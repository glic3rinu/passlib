"""passlib.handler - code for implementing handlers, and global registry for handlers"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import inspect
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.utils import abstractmethod, abstractclassmethod, classproperty, h64, \
    getrandstr, rng, Undef, is_crypt_handler
#pkg
#local
__all__ = [

    #framework for implementing handlers
    'BaseHandler',
    'PlainHandler',
]

###==========================================================
###base interface for all the crypt algorithm implementations
###==========================================================
##class CryptHandler(object):
##    """helper class for implementing a password algorithm using class methods"""
##
##    #=========================================================
##    #class attrs
##    #=========================================================
##
##    name = None #globally unique name to identify algorithm. should be lower case and hyphens only
##    context_kwds = () #tuple of additional kwds required for any encrypt / verify operations; eg "realm" or "user"
##    setting_kwds = () #tuple of additional kwds that encrypt accepts for configuration algorithm; eg "salt" or "rounds"
##
##    #=========================================================
##    #primary interface - primary methods implemented by each handler
##    #=========================================================
##
##    @abstractclassmethod
##    def genhash(cls, secret, config, **context):
##        """encrypt secret to hash"""
##
##    @classmethod
##    def genconfig(cls, **settings):
##        """return configuration string encoding settings for hash generation"""
##        #NOTE: this implements a default method which is suitable ONLY for classes with no configuration.
##        if cls.setting_kwds:
##            raise NotImplementedError, "classes with config kwds must implement genconfig()"
##        if settings:
##            raise TypeError, "%s has no configuration options" % (cls,)
##        return None
##
##    #=========================================================
##    #secondary interface - more useful interface for user,
##    # frequently implemented more efficiently by specific handlers
##    #=========================================================
##
##    @classmethod
##    def identify(cls, hash):
##        """identify if a hash string belongs to this algorithm."""
##        #NOTE: this default method is going to be *really* slow for most implementations,
##        #they should override it. but if genhash() conforms to the specification, this will do.
##        if cls.context_kwds:
##            raise NotImplementedError, "classes with context kwds must implement identify()"
##        if not hash:
##            return False
##        try:
##            cls.genhash("stub", hash)
##        except ValueError:
##            return False
##        return True
##
##    @classmethod
##    def encrypt(cls, secret, **kwds):
##        """encrypt secret, returning resulting hash string."""
##        if cls.context_kwds:
##            context = dict(
##                (k,kwds.pop(k))
##                for k in cls.context_kwds
##                if k in kwds
##            )
##            config = cls.genconfig(**kwds)
##            return cls.genhash(secret, config, **context)
##        else:
##            config = cls.genconfig(**kwds)
##            return cls.genhash(secret, config)
##
##    @classmethod
##    def verify(cls, secret, hash, **context):
##        """verify a secret against an existing hash."""
##        #NOTE: methods whose hashes have multiple encodings should override this,
##        # as the hash will need to be normalized before comparing via string equality.
##        # alternately, the ExtCryptHandler class provides a more flexible framework.
##
##        #ensure hash was specified - genhash() won't throw error for this
##        if not hash:
##            raise ValueError, "no hash specified"
##
##        #the genhash() implementation for most setting-less algorithms
##        #simply ignores the config string provided; whereas most
##        #algorithms with settings have to inspect and validate it.
##        #therefore, we do this quick check IFF it's setting-less
##        if not cls.setting_kwds and not cls.identify(hash):
##            raise ValueError, "not a %s hash" % (cls.name,)
##
##        #do simple string comparison
##        return hash == cls.genhash(secret, hash, **context)
##
##    #=========================================================
##    #eoc
##    #=========================================================

#=========================================================
# BaseHandler
#   rounds+salt+xtra    phpass, sha256_crypt, sha512_crypt
#   rounds+salt         bcrypt, ext_des_crypt, sha1_crypt, sun_md5_crypt
#   salt only           apr_md5_crypt, des_crypt, md5_crypt
#=========================================================
class BaseHandler(object):
    """helper class for implementing hash schemes

    hash implementations should fill out the following:
        * all required class attributes
            - name, setting_kwds
            - max_salt_chars, min_salt_chars, etc - only if salt is used
            - max_rounds, min_rounds, default_roudns - only if rounds are used
        * classmethod from_string()
        * instancemethod to_string()
        * instancemethod calc_checksum()

    many implementations will want to override the following:
        * classmethod identify() can usually be done more efficiently
        * checksum_charset, checksum_chars attributes may prove helpful for validation

    most implementations can use defaults for the following:
        * genconfig(), genhash(), encrypt(), verify(), etc
        * norm_checksum() usually only needs overriding if checksum has multiple encodings

    note this class does not support context kwds of any type,
    since that is a rare enough requirement inside passlib.

    implemented subclasses may call cls.validate_class() to check attribute consistency
    (usually only required in unittests, etc)
    """

    #=========================================================
    #class attributes
    #=========================================================

    #----------------------------------------------
    #password hash api - required attributes
    #----------------------------------------------
    name = None #required by BaseHandler
    setting_kwds = None #required by BaseHandler
    context_kwds = ()

    #----------------------------------------------
    #checksum information
    #----------------------------------------------
    checksum_charset = None #if specified, norm_checksum() will validate this
    checksum_chars = None #if specified, norm_checksum will require this length

    #----------------------------------------------
    #salt information
    #----------------------------------------------
    max_salt_chars = None #required by BaseHandler.norm_salt()

    @classproperty
    def min_salt_chars(cls):
        "min salt chars (defaults to max_salt_chars if not specified by subclass)"
        return cls.max_salt_chars

    @classproperty
    def default_salt_chars(cls):
        "default salt chars (defaults to max_salt_chars if not specified by subclass)"
        return cls.max_salt_chars

    salt_charset = h64.CHARS

    @classproperty
    def default_salt_charset(cls):
        return cls.salt_charset

    #----------------------------------------------
    #rounds information
    #----------------------------------------------
    min_rounds = 0
    max_rounds = None #required by BaseHandler.norm_rounds()
    default_rounds = None #if not specified, BaseHandler.norm_rounds() will require explicit rounds value every time
    rounds_cost = "linear" #common case


    #----------------------------------------------
    #misc BaseHandler configuration
    #----------------------------------------------
    _strict_rounds_bounds = False #if true, always raises error if specified rounds values out of range - required by spec for some hashes
    _extra_init_settings = () #settings that BaseHandler.__init__ should handle by calling norm_<key>()

    #=========================================================
    #instance attributes
    #=========================================================
    checksum = None
    salt = None
    rounds = None

    #=========================================================
    #init
    #=========================================================
    #XXX: rename strict kwd to _strict ?
    def __init__(self, checksum=None, salt=None, rounds=None, strict=False, **kwds):
        self.checksum = self.norm_checksum(checksum, strict=strict)
        self.salt = self.norm_salt(salt, strict=strict)
        self.rounds = self.norm_rounds(rounds, strict=strict)
        extra = self._extra_init_settings
        if extra:
            for key in extra:
                value = kwds.pop(key, None)
                norm = getattr(self, "norm_" + key)
                value = norm(value, strict=strict)
                setattr(self, key, value)
        super(BaseHandler, self).__init__(**kwds)

    @classmethod
    def validate_class(cls):
        "helper to ensure class is configured property"
        if not cls.name:
            raise AssertionError, "class must have .name attribute set"

        if cls.setting_kwds is None:
            raise AssertionError, "class must have .setting_kwds attribute set"

        if any(k not in cls.setting_kwds for k in cls._extra_init_settings):
            raise AssertionError, "_extra_init_settings must be subset of setting_kwds"

        if 'salt' in cls.setting_kwds:

            if cls.min_salt_chars > cls.max_salt_chars:
                raise AssertionError, "min salt chars too large"

            if cls.default_salt_chars < cls.min_salt_chars:
                raise AssertionError, "default salt chars too small"
            if cls.default_salt_chars > cls.max_salt_chars:
                raise AssertionError, "default salt chars too large"

            if any(c not in cls.salt_charset for c in cls.default_salt_charset):
                raise AssertionError, "default salt charset not subset of salt charset"

        if 'rounds' in cls.setting_kwds:

            if cls.max_rounds is None:
                raise AssertionError, "max rounds not specified"

            if cls.min_rounds > cls.max_rounds:
                raise AssertionError, "min rounds too large"

            if cls.default_rounds is not None:
                if cls.default_rounds < cls.min_rounds:
                    raise AssertionError, "default rounds too small"
                if cls.default_rounds > cls.max_rounds:
                    raise AssertionError, "default rounds too large"

            if cls.rounds_cost not in ("linear", "log2"):
                raise AssertionError, "unknown rounds cost function"

    #=========================================================
    #helpers
    #=========================================================
    @classmethod
    def norm_checksum(cls, checksum, strict=False):
        if checksum is None:
            return None
        cc = cls.checksum_chars
        if cc and len(checksum) != cc:
            raise ValueError, "%s checksum must be %d characters" % (cls.name, cc)
        cs = cls.checksum_charset
        if cs and any(c not in cs for c in checksum):
            raise ValueError, "invalid characters in %s checksum" % (cls.name,)
        return checksum

    @classproperty
    def _has_salt(cls):
        "attr for checking if salts are supported, optimizes itself on first use"
        if cls is BaseHandler:
            raise RuntimeError, "not allowed for BaseHandler directly"
        value = cls._has_salt = 'salt' in cls.setting_kwds
        return value

    @classmethod
    def norm_salt(cls, salt, strict=False):
        "helper to normalize salt string; strict flag causes error even for correctable errors"
        if not cls._has_salt:
            if salt is not None:
                raise ValueError, "%s does not support ``salt``" % (cls.name,)
            return None

        if salt is None:
            if strict:
                raise ValueError, "no salt specified"
            return getrandstr(rng, cls.default_salt_charset, cls.default_salt_chars)

        #TODO: run salt_charset tests

        mn = cls.min_salt_chars
        if mn and len(salt) < mn:
            raise ValueError, "%s salt string must be >= %d characters" % (cls.name, mn)

        mx = cls.max_salt_chars
        if len(salt) > mx:
            if strict:
                raise ValueError, "%s salt string must be <= %d characters" % (cls.name, mx)
            salt = salt[:mx]

        return salt

    @classproperty
    def _has_rounds(cls):
        "attr for checking if variable are supported, optimizes itself on first use"
        if cls is BaseHandler:
            raise RuntimeError, "not allowed for BaseHandler directly"
        value = cls._has_rounds = 'rounds' in cls.setting_kwds
        return value

    @classmethod
    def norm_rounds(cls, rounds, strict=False):
        "helper to normalize rounds value; strict flag causes error even for correctable errors"
        if not cls._has_rounds:
            if rounds is not None:
                raise ValueError, "%s does not support ``rounds``" % (cls.name,)
            return None

        if rounds is None:
            if strict:
                raise ValueError, "no rounds specified"
            rounds = cls.default_rounds
            if rounds is None:
                raise ValueError, "%s requires an explicitly-specified rounds value" % (cls.name,)
            return rounds

        if cls._strict_rounds_bounds:
            strict = True

        mn = cls.min_rounds
        if rounds < mn:
            if strict:
                raise ValueError, "%s rounds must be >= %d" % (cls.name, mn)
            rounds = mn

        mx = cls.max_rounds
        if rounds > mx:
            if strict:
                raise ValueError, "%s rounds must be <= %d" % (cls.name, mx)
            rounds = mx

        return rounds

    #=========================================================
    #password hash api - primary interface (default implementation)
    #=========================================================
    @classmethod
    def genconfig(cls, **settings):
        return cls(**settings).to_string()

    @classmethod
    def genhash(cls, secret, config):
        self = cls.from_string(config)
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    def calc_checksum(self, secret):
        "given secret; calcuate and return encoded checksum portion of hash string, taking config from object state"
        raise NotImplementedError, "%s must implement calc_checksum()" % (cls,)

    #=========================================================
    #password hash api - secondary interface (default implementation)
    #=========================================================
    @classmethod
    def identify(cls, hash):
        #NOTE: subclasses may wish to use faster / simpler identify,
        # and raise value errors only when an invalid (but identifiable) string is parsed
        if not hash:
            return False
        try:
            cls.from_string(hash)
            return True
        except ValueError:
            return False

    @classmethod
    def encrypt(cls, secret, **settings):
        self = cls(**settings)
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    @classmethod
    def verify(cls, secret, hash):
        #NOTE: classes with multiple checksum encodings (rare)
        # may wish to either override this, or override norm_checksum
        # to normalize any checksums provided by from_string()
        self = cls.from_string(hash)
        return self.checksum == self.calc_checksum(secret)

    #=========================================================
    #password hash api - parsing interface
    #=========================================================
    @classmethod
    def from_string(cls, hash):
        "return parsed instance from hash/configuration string; raising ValueError on invalid inputs"
        raise NotImplementedError, "%s must implement from_string()" % (cls,)

    def to_string(self):
        "render instance to hash or configuration string (depending on if checksum attr is set)"
        raise NotImplementedError, "%s must implement from_string()" % (type(self),)

    def to_config_string(self):
        "helper for generating configuration string (ignoring hash)"
        chk = self.checksum
        if chk:
            try:
                self.checksum = None
                return self.to_string()
            finally:
                self.checksum = chk
        else:
            return self.to_string()

    #=========================================================
    #
    #=========================================================

#=========================================================
#plain - mysql_323, mysql_41, nthash, postgres_md5
#=========================================================
#XXX: rename this? StaticHandler? NoSettingHandler? and give this name to WrapperHandler
class PlainHandler(object):
    """helper class optimized for implementing hash schemes which have NO settings whatsoever"""
    #=========================================================
    #password hash api - required attributes
    #=========================================================
    name = None #required
    setting_kwds = ()
    context_kwds = ()

    #=========================================================
    #helpers for norm checksum
    #=========================================================
    checksum_charset = None #if specified, norm_checksum() will validate this
    checksum_chars = None #if specified, norm_checksum will require this length

    #=========================================================
    #init
    #=========================================================
    def __init__(self, checksum=None, strict=False, **kwds):
        self.checksum = self.norm_checksum(checksum, strict=strict)
        super(PlainHandler, self).__init__(**kwds)

    @classmethod
    def validate_class(cls):
        "helper to validate that class has been configured properly"
        if not cls.name:
            raise AssertionError, "class must have .name attribute set"

    #=========================================================
    #helpers
    #=========================================================
    norm_checksum = BaseHandler.norm_checksum.im_func

    #=========================================================
    #primary interface
    #=========================================================
    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, config, **context):
        #NOTE: config is ignored
        self = cls()
        self.checksum = self.calc_checksum(secret, **context)
        return self.to_string()

    calc_checksum = BaseHandler.calc_checksum.im_func

    #=========================================================
    #secondary interface
    #=========================================================
    @classmethod
    def identify(cls, hash):
        #NOTE: subclasses may wish to use faster / simpler identify,
        # and raise value errors only when an invalid (but identifiable) string is parsed
        if not hash:
            return False
        try:
            cls.from_string(hash)
            return True
        except ValueError:
            return False

    @classmethod
    def encrypt(cls, secret, **context):
        return cls.genhash(secret, None, **context)

    @classmethod
    def verify(cls, secret, hash, **context):
        #NOTE: classes may wish to override this
        self = cls.from_string(hash)
        return self.checksum == self.calc_checksum(secret, **context)

    #=========================================================
    #parser interface
    #=========================================================
    @classmethod
    def from_string(cls, hash):
        raise NotImplementedError, "implement in subclass"

    def to_string(cls):
        raise NotImplementedError, "implement in subclass"

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#wrapper
#=========================================================
class WrapperHandler(object):
    "helper for implementing wrapper of crypt-like interface, only required genconfig & genhash"

    #=====================================================
    #required attributes
    #=====================================================
    name = None
    setting_kwds = None
    context_kwds = ()

    #=====================================================
    #formatting (usually subclassed)
    #=====================================================
    @classmethod
    def identify(cls, hash):
        #NOTE: this relys on genhash throwing error for invalid hashes.
        # this approach is bad because genhash may take a long time on valid hashes,
        # so subclasses *really* should override this.
        try:
            cls.genhash('stub', hash)
            return True
        except ValueError:
            return False

    #=====================================================
    #primary interface (must be subclassed)
    #=====================================================
    @classmethod
    def genconfig(cls, **settings):
        if cls.setting_kwds:
            raise NotImplementedError, "%s subclass must implement genconfig()" % (cls,)
        else:
            if settings:
                raise TypeError, "%s genconfig takes no kwds" % (cls.name,)
            return None

    @classmethod
    def genhash(cls, secret, config):
        raise NotImplementedError, "%s subclass must implement genhash()" % (cls,)

    #=====================================================
    #secondary interface (rarely subclassed)
    #=====================================================
    @classmethod
    def encrypt(cls, secret, **settings):
        config = cls.genconfig(**settings)
        return cls.genhash(secret, config)

    @classmethod
    def verify(cls, secret, hash):
        if not hash:
            raise ValueError, "no hash specified"
        return hash == cls.genhash(secret, hash)

    #=====================================================
    #eoc
    #=====================================================

#=========================================================
#
#=========================================================
class BackendMixin(object):

    #NOTE: subclass must provide:
    #   * attr 'backends' containing list of known backends (top priority backend first)
    #   * attr '_has_backend_xxx' for each backend 'xxx', indicating if backend is available on system
    #   * attr '_calc_checksum_xxx' for each backend 'xxx', containing calc_checksum implementation using that backend

    _backend = None

    @classmethod
    def get_backend(cls):
        "return name of active backend"
        return cls._backend or cls.set_backend()

    @classmethod
    def has_backend(cls, name):
        "check if specified class can be loaded"
        return getattr(cls, "_has_backend_" + name)

    @classmethod
    def set_backend(cls, name=None):
        "change class to use specified backend"
        if not name or name == "default":
            if not name:
                name = cls._backend
                if name:
                    return name
            for name in cls.backends:
                if cls.has_backend(name):
                    cls.calc_checksum = getattr(cls, "_calc_checksum_" + name)
                    cls._backend = name
                    return name
            raise EnvironmentError, "no %s backends available" % (cls.name,)
        else:
            ##if name not in cls.backends:
            ##    raise ValueError, "unknown %s backend: %r" % (cls.name, name)
            if not cls.has_backend(name):
                raise ValueError, "%s backend not available: %r" % (cls.name, name)
            cls.calc_checksum = getattr(cls, "_calc_checksum_" + name)
            cls._backend = name
            return name

    def calc_checksum(self, secret):
        "stub for calc_checksum(), default backend will be selected first time stub is called"
        #backend not loaded - run detection and call replacement
        assert not self._backend, "set_backend() failed to replace lazy loader"
        self.set_backend()
        assert self._backend, "set_backend() failed to load a default backend"
        return self.calc_checksum(secret)

class BackendBaseHandler(BackendMixin, BaseHandler):
    pass

class BackendPlainHandler(BackendMixin, PlainHandler):
    pass

#=========================================================
# eof
#=========================================================
