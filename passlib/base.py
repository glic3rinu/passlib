"""passlib - implementation of various password hashing functions

Context options

    schemes - list of names or handler instances which should be recognized by context
    deprecated - list names of handlers which should context should only use to validate *old* hashes
    default - optional name of handler to use for encrypting new hashes.

Many schemes support their own options, such as min/max/default rounds.

"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from ConfigParser import ConfigParser
import inspect
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
from warnings import warn
#site
#libs
import passlib.hash as _hmod
from passlib.utils import abstractclassmethod, Undef, is_crypt_handler, splitcomma
#pkg
#local
__all__ = [
    #global registry
    'register_crypt_handler',
    'get_crypt_handler',
    'list_crypt_handlers'

    #contexts
    'CryptContext',
]

#=========================================================
#global registry
#=========================================================

#list of builtin hashes (for list_crypt_handlers, to work around lazy loading)
#XXX: could write some code in setup.py that generates this from package listing.
_builtin_names = set([
    "apr_md5_crypt", "bcrypt", "des_crypt", "ext_des_crypt",
    "md5_crypt", "mysql_323", "mysql_41", "postgres_md5",
    "sha256_crypt", "sha512_crypt", "sun_md5_crypt",
    ])

def register_crypt_handler(obj, force=False):
    "register CryptHandler handler"
    global _hmod

    #validate obj
    if not is_crypt_handler(obj):
        raise TypeError, "object does not appear to be a CryptHandler: %r" % (obj,)
    assert obj, "CryptHandlers must be boolean True: %r" % (obj,)

    #validate name
    name = obj.name
    if not name:
        raise ValueError, "name is null: %r" % (name,)
    if name.lower() != name:
        raise ValueError, "name must be lower-case: %r" % (name,)
    if re.search("[^_a-z0-9]",name):
        raise ValueError, "invalid characters in name (only underscore, a-z, 0-9 allowed): %r" % (name,)

    #check for existing handler
    other = getattr(_hmod, name, None)
    if other:
        if other is obj:
            return #already registered
        if force:
            log.warning("overriding previous handler registered to name %r: %r", name, other)
        else:
            raise ValueError, "handler already registered for name %r: %r" % (name, other)

    #put handler into hash module
    setattr(_hmod, name, obj)
    log.info("registered crypt handler %r: %r", name, obj)

def get_crypt_handler(name, default=Undef):
    "resolve crypt algorithm name"
    global _hmod

    #normalize name
    alt = name.replace("-","_").lower()
    if alt != name:
        warn("handler names be lower-case, and use underscores instead of hyphens: %r => %r" % (name, alt))
        name = alt

    #check if handler loaded
    handler = getattr(_hmod, name, None)
    if handler:
        return handler

    #try to lazy load from passlib.hash.xxx
    try:
        mod = __import__("passlib.hash." + name, None, None, ['dummy'], 0)
    except ImportError, err:
        #make sure we don't hide failure to import dependancy
        if str(err) != "No module named " + name:
            raise
    else:
        #<mod> should now be value store in _hmod.name,
        #we call register_crypt_handler() as sanity check to be sure.
        #(will raise ValueError/TypeError if something went wrong)
        register_crypt_handler(mod)
        return mod

    #fail!
    if default is Undef:
        raise KeyError, "no crypt handler found for algorithm: %r" % (name,)
    else:
        return default

def list_crypt_handlers():
    "return sorted list of all known crypt algorithm names"
    global _hmod, _builtin_names
    return sorted(_builtin_names.union(x for x in dir(_hmod) if not x.startswith("_")))

#=========================================================
#policy
#=========================================================
"""

context file format -

config ini

[passlib]
allow = des-crypt, md5-crypt, sha256-crypt, sha512-crypt
default = sha512-crypt
deprecate = des-crypt, md5-crypt

sha256_crypt/min_rounds = 10000
sha256_crypt/default_rounds = 40000

admin/sha256_crypt/default_rounds = 50000

CryptContext(
    allow=["des-crypt", "md5-crypt", "sha256-crypt", "sha512-crypt"],
    default="sha512-crypt",
    deprecate=["des-crypt", "md5-crypt"],
    sha256_crypt__default_rounds = 40000,
)
"""

#=========================================================
#
#=========================================================
class CryptContext(object):
    """Helper for encrypting passwords using different algorithms.

    Different storage contexts (eg: linux shadow files vs openbsd shadow files)
    may use different sets and subsets of the available algorithms.
    This class encapsulates such distinctions: it represents an ordered
    list of algorithms, each with a unique name. It contains methods
    to verify against existing algorithms in the context,
    and still encrypt using new algorithms as they are added.

    Because of all of this, it's basically just a list object.
    However, it contains some dictionary-like features
    such as looking up algorithms by name, and it's restriction
    that no two algorithms in a list share the same name
    causes it to act more like an "ordered set" than a list.

    In general use, none of this matters.
    The typical use case is as follows::

        >>> from passlib import hash
        >>> #create a new context that only understands Md5Crypt & BCrypt
        >>> myctx = hash.CryptContext([ hash.Md5Crypt, hash.BCrypt ])

        >>> #the last one in the list will be used as the default for encrypting...
        >>> hash1 = myctx.encrypt("too many secrets")
        >>> hash1
        '$2a$11$RvViwGZL./LkWfdGKTrgeO4khL/PDXKe0TayeVObQdoew7TFwhNFy'

        >>> #choose algorithm explicitly
        >>> hash2 = myctx.encrypt("too many secrets", alg="md5-crypt")
        >>> hash2
        '$1$E1g0/BY.$gS9XZ4W2Ea.U7jMueBRVA.'

        >>> #verification will autodetect the right hash
        >>> myctx.verify("too many secrets", hash1)
        True
        >>> myctx.verify("too many secrets", hash2)
        True
        >>> myctx.verify("too many socks", hash2)
        False

        >>> #you can also have it identify the algorithm in use
        >>> myctx.identify(hash1)
        'bcrypt'
        >>> #or just return the CryptHandler instance directly
        >>> myctx.identify(hash1, resolve=True)
        <passlib.BCrypt object, name="bcrypt">

        >>> #you can get a list of algs...
        >>> myctx.keys()
        [ 'md5-crypt', 'bcrypt' ]

        >>> #and get the CryptHandler object by name
        >>> bc = myctx['bcrypt']
        >>> bc
        <passlib.BCrypt object, name="bcrypt">
    """
    #===================================================================
    #instance attrs
    #===================================================================
    _handlers = None #list of password hash handlers instances.
    _default = None #default handler
    _hmap = None #dict mapping handler.name -> handler for all handlers in _handlers
    _dset = None #set of all handlers which have been deprecated
    _config = None #dict mapping handler.name -> options for norm_handler_settings

    #===================================================================
    #init
    #===================================================================
    def __init__(self, schemes, **kwds):
        self.set_config(schemes, **kwds)

    def __repr__(self):
        names = [ handler.name for handler in self._handlers ]
        return "CryptContext(%r)" % (names,)

    #===================================================================
    #setting policy configuration
    #===================================================================
    def _add_scheme(self, scheme):
        "helper to add scheme to internal config"
        #resolve & validate handler
        if is_crypt_handler(scheme):
            handler = scheme
        else:
            handler = get_crypt_handler(scheme)
        name = handler.name
        if not name:
            raise KeyError, "handler lacks name: %r" % (handler,)

        #check name->handler mapping
        hmap = self._hmap
        other = hmap.get(name)
        if other:
            if other is handler: #quit if already added to config
                return handler
            raise KeyError, "multiple handlers with same name: %r" % (handler, other)
        hmap[name] = handler

        #add to handler list
        self._handlers.append(handler)

        return handler

    def set_config(self, schemes, deprecated=None, default=None, **kwds):
        "set configuration from dictionary of options"

        #init handler state
        self._handlers = []
        self._hmap = {}

        #parse scheme list
        if not schemes:
            raise ValueError, "no schemes defined"
        if isinstance(schemes, str):
            schemes = splitcomma(schemes)
        for scheme in reversed(schemes): #NOTE: reversed() just so last entry is used as default, and is checked first.
            self._add_scheme(scheme)

        #parse deprecated set
        dset = self._dset = set()
        if deprecated:
            if isinstance(deprecated, str):
                deprecated = splitcomma(deprecated)
            for scheme in deprecated:
                handler = self._add_scheme(scheme)
                dset.add(handler)

        #take care of default
        if default:
            self._default = self._add_scheme(default)
        else:
            self._default = self._handlers[0]

        #all other keywords should take form "name__param" or "name/param",
        #where name is a handler name, and param is a parameter for settings name's policy behavior.
        config = self._config = {}
        hmap = self._hmap
        for key, value in kwds.iteritems():
            if '__' in key:
                name, param = key.split("__")
            elif '/' in key:
                name, param = key.split("/")
            else:
                raise KeyError, "unknown keyword: %r" % (key,)
            if name not in hmap:
                raise KeyError, "unknown scheme: %r" % (scheme,)
            if name in config:
                opts = config[name]
            else:
                opts = config[name] = {}
            opts[param] = value

    def load_config_from_file(self, path, section="passlib"):
        "load context configuration from section of ConfigParser file"
        p = ConfigParser()
        if not p.read([path]):
            raise EnvironmentError, "failed to read path"
        self.set_config(**dict(p.items(section)))

    #===================================================================
    #exporting policy configuration
    #===================================================================
    def get_config(self):
        "get configuration as dictionary"
        out = {}
        out['schemes'] =[
            handler.name if get_crypt_handler(handler.name,None) is handler else handler
            for handler in self._handlers
        ]
        if self._dset:
            out['deprecated'] = [h.name for h in self._dset]
        if self._default is not self._handlers[0]:
            out['default'] = self._default.name
        for name, opts in self._config:
            for k,v in opts.iteritems():
                out["%s__%s" % (name, k)] = v
        return out

    def write_config_to_file(self, path, section="passlib"):
        "save context configuration to section of ConfigParser file"
        p = ConfigParser()
        if os.path.exists(path):
            if not p.read([path]):
                raise EnvironmentError, "failed to read config file"
            p.remove_section(section)
        for k,v in self.get_config().items():
            if k == "schemes":
                if any(hasattr(h,"name") for h in v):
                    raise ValueError, "can't write to config file, unregistered handlers in use"
            if k in ["schemes", "deprecated"]:
                v = ", ".join(v)
            k = k.replace("__", "/")
            p.set(k, v)
        fh = file(path, "w")
        p.write(fh)
        fh.close()

    #===================================================================
    #examining policy configuratio
    #===================================================================
    def lookup(self, name=None, required=False):
        """given an algorithm name, return CryptHandler instance which manages it.
        if no match is found, returns None.

        if name is None, will return default algorithm
        """
        if name and name != "default":
            for handler in self._handlers:
                if handler.name == name:
                    return handler
        else:
            assert self._default
            return self._default
        if required:
            raise KeyError, "no crypt algorithm by that name in context: %r" % (name,)
        return None

    def get_handler_settings(self, handler):
        "return context-specific default settings for handler or handler name"
        return self._config.get(handler.name) or {}

    def norm_handler_settings(self, handler, **settings):
        "normalize settings for handler according to context configuration"
        #check for config
        opts = self._config.get(handler.name)
        if not opts:
            return settings

        #load in default values
        for k in handler.setting_kwds:
            if k not in settings and k in opts:
                settings[k] = opts[k]

        #check context-specified limits

        return settings

    #===================================================================
    #
    #===================================================================

    def genconfig(self, scheme=None, **settings):
        """Call genconfig() for specified handler"""
        handler = self.lookup(scheme, required=True)
        settings = self.norm_handler_settings(handler, **settings)
        return handler.genconfig(**settings)

    def genhash(self, config, scheme=None, **context):
        """Call genhash() for specified handler"""
        if scheme:
            handler = self.lookup(scheme, required=True)
        else:
            handler = self.identify(config, required=True)
        return handler.genhash(config, **context)

    def identify(self, hash, name=False, required=False):
        """Attempt to identify which algorithm hash belongs to w/in this context.

        :arg hash:
            The hash string to test.

        :param name:
            If true, returns the name of the handler
            instead of the handler itself.

        All registered algorithms will be checked in from last to first,
        and whichever one claims the hash first will be returned.

        :returns:
            The handler which first identifies the hash,
            or ``None`` if none of the algorithms identify the hash.
        """
        if hash is None:
            if required:
                raise ValueError, "no hash specified"
            return None
        for handler in self._handlers:
            if handler.identify(hash):
                if name:
                    return handler.name
                else:
                    return handler
        if required:
            raise ValueError, "hash could not be identified"
        return None

    def encrypt(self, secret, scheme=None, **kwds):
        """encrypt secret, returning resulting hash.

        :arg secret:
            String containing the secret to encrypt

        :param scheme:
            Optionally specify the name of the algorithm to use.
            If no algorithm is specified, an attempt is made
            to guess from the hash string. If no hash string
            is specified, the last algorithm in the list is used.

        :param **kwds:
            All other keyword options are passed to the algorithm's encrypt method.
            The two most common ones are "keep_salt" and "rounds".

        :returns:
            The secret as encoded by the specified algorithm and options.
        """
        if not self:
            raise ValueError, "no algorithms registered"
        handler = self.lookup(scheme, required=True)
        kwds = self.norm_handler_settings(handler, **kwds)
        return handler.encrypt(secret, **kwds)

    def verify(self, secret, hash, scheme=None, **context):
        """verify secret against specified hash

        :arg secret:
            the secret to encrypt
        :arg hash:
            hash string to compare to
        :param scheme:
            optional force context to use specfic scheme (must be allowed by context)
        """
        #quick checks
        if not self:
            raise ValueError, "no crypt schemes registered"
        if hash is None:
            return False

        #locate handler
        if scheme:
            handler = self.lookup(scheme, required=True)
        else:
            handler = self.identify(hash, required=True)

        #strip context kwds if scheme doesn't use them
        ##for k in context.keys():
        ##    if k not in handler.context_kwds:
        ##        del context[k]

        #use handler to verify secret
        return handler.verify(secret, hash, **context)

    #=========================================================
    #policy variants
    #=========================================================
    def verify_and_update(self, secret, hash, **context):
        """verify secret against specified hash, and re-encrypt secret if needed"""
        ok = self.verify(secret, hash, **context)
        if ok and self.needs_update(hash):
            return True, self.encrypt(secret, **context)
        else:
            return ok, None

    def needs_update(self, hash):
        """check if hash is allowed by current policy, or should be re-encrypted"""
        handler = self.identify(hash, required=True)
        if handler in self._dset:
            return True
        #TODO: check specific policy for hash.
        #need to work up protocol here.
        #probably want to hand off settings to handler.
        return False

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
# eof
#=========================================================
