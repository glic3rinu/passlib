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
from passlib.utils import abstract_class_method, classproperty, H64_CHARS, getrandstr, rng, Undef
#pkg
#local
__all__ = [
    #global registry
    'register_crypt_handler',
    'get_crypt_handler',
    'list_crypt_handlers'

    'is_crypt_handler',
    'is_ext_crypt_handler',

    #framework for implementing handlers
    'CryptHandler',
    'ExtCryptHandler',
]

#=========================================================
#global registry
#=========================================================
_handler_map = {} #dict mapping names & aliases -> crypt algorithm instances
_name_set = set() #list of keys in _handler_map which are names not aliases

def register_crypt_handler(obj):
    "register CryptHandler handler"
    global _handler_map, _name_set

    if not is_crypt_handler(obj):
        raise TypeError, "object does not appear to be CryptHandler handler: %r" % (obj,)

    name = obj.name
    _validate_name(name)

    if name in _name_set:
        log.warning("overriding previous handler registered to name %r: %r", name, _handler_map[name])
##        raise ValueError, "handler already registered for name %r: %r" % (name, _handler_map[name])

    _handler_map[name] = obj
    _name_set.add(name)

    for alias in obj.aliases:
        _validate_name(alias)
        if alias not in _name_set:
            _handler_map[alias] = obj

    log.info("registered crypt handler: obj=%r name=%r aliases=%r", obj, obj.name, obj.aliases)

def _validate_name(name):
    "validate crypt algorithm name"
    if not name:
        raise ValueError, "name/alias empty: %r" % (name,)
    if name.lower() != name:
        raise ValueError, "name/alias must be lower-case: %r" %(name,)
    if re.search("[^-a-zA-Z0-9]",name):
        raise ValueError, "names & aliases must consist of a-z, 0-9, A-Z: %r" % (name,)
    return True

def get_crypt_handler(name, default=Undef):
    "resolve crypt algorithm name / alias"
    global _handler_map
    if default is Undef:
        return _handler_map[name]
    else:
        return _handler_map.get(name, default)

def list_crypt_handlerss():
    "return sorted list of all known crypt algorithm names"
    global _name_set
    return sorted(_name_set)

#==========================================================
#other helpers
#==========================================================
def is_crypt_handler(obj):
    "check if obj following CryptHandler protocol"
    #NOTE: this isn't an exhaustive check of all required attrs,
    #just a quick check of the most uniquely identifying ones
    return all(hasattr(obj, name) for name in (
        "name", "verify", "encrypt", "identify",
        ))

def is_ext_crypt_handler(obj):
    "check if obj following ExtCryptHandler protocol"
    #NOTE: this isn't an exhaustive check of all required attrs,
    #just a quick check of the most uniquely identifying ones
    return all(hasattr(obj, name) for name in (
        "name", "verify", "encrypt", "identify", "parse", "render"
        ))

#==========================================================
#base interface for all the crypt algorithm implementations
#==========================================================
class CryptHandler(object):
    """base class for implementing a password algorithm.

    The following should be filled out for all crypt algorithm subclasses.
    Additional methods, attributes, and features may vary.

    Informational Attributes
    ========================
    .. attribute:: name

        This should be a globally unique name to identify
        the hash algorithm with.

    .. attribute:: salt_bytes

        This is a purely informational attribute
        listing how many bytes are in the salt your algorithm uses.

    .. attribute:: hash_bytes

        This is a purely informational attribute
        listing how many bytes are in the cheksum part of your algorithm's hash.

    .. note::

        Note that all the bit counts should measure
        the number of bits of entropy, not the number of bits
        a given encoding takes up.

    .. attribute:: has_salt

        This is a virtual attribute,
        calculated based on the value of the salt_bytes attribute.
        It returns ``True`` if the algorithm contains any salt bytes,
        else ``False``.

    .. attribute:: secret_chars

        Number of characters in secret which are used.
        If ``None`` (the default), all chars are used.
        BCrypt, for example, only uses the first 55 chars.

    .. attribute:: has_rounds

        This is a purely informational attribute
        listing whether the algorithm can be scaled
        by increasing the number of rounds it contains.
        It is not required (defaults to False).

    .. attribute:: has_named_rounds

        If this flag is true, then the algorithm's
        encrypt method supports a ``rounds`` keyword
        which (at the very least) accepts the following
        strings as possible values:

            * ``fast`` -- number of rounds will be selected
                to provide adequate security for most user accounts.
                This is retuned perodically to take around .25 seconds.

            * ``medium`` -- number of rounds will be selected
                to provide adequate security for most root/administrative accounts
                This is retuned perodically to take around .75 seconds.

            * ``slow`` -- number of rounds will be selected
                to require a large amount of calculation time.
                This is retuned perodically to take around 1.5 seconds.

        .. note::
            Last retuning of the default round sizes was done
            on 2009-07-06 using a 2ghz system.

    Common Methods
    ==============
    .. automethod:: identify

    .. automethod:: encrypt

    .. automethod:: verify

    Implementing a new crypt algorithm
    ==================================
    Subclass this class, and implement :meth:`identify`
    and :meth:`encrypt` so that they implement your
    algorithm according to it's documentation
    and the specifications of the methods themselves.
    You must also specify :attr:``name``.
    Optionally, you may override :meth:`verify`
    and set various informational attributes.

    """

    #=========================================================
    #class attrs
    #=========================================================

    #---------------------------------------------------------
    #registry
    #---------------------------------------------------------
    name = None #globally unique name to identify algorithm. should be lower case and hyphens only
    aliases = () #optional list of aliases (other names) this hash should be recognized by
    context_kwds = () #tuple of additional kwds required for any encrypt / verify operations; eg "realm" or "user"
    setting_kwds = () #tuple of additional kwds that encrypt accepts for configuration algorithm; eg "salt" or "rounds"

    #---------------------------------------------------------
    #optional informational attributes
    #---------------------------------------------------------
    secret_chars = -1 #max number of chars of secret that are used in hash. -1 if all chars used.
    salt_bytes = 0 #number of effective bytes in salt - 0 if doesn't use salt, max salt bytes if variable-length salt supported
    checksum_bytes = 0 #number of effective bits in hash

    #---------------------------------------------------------
    #algorithm rounds information - only required if alg supports rounds
    #---------------------------------------------------------
    default_rounds = None #default number of rounds to use if none specified (can be name of a preset)
    min_rounds = None #minimum number of rounds (smaller values silently ignored)
    max_rounds = None #maximum number of rounds (larger values silently ignored)

    #=========================================================
    #frontend interface
    #=========================================================

    @abstract_class_method
    def identify(cls, hash):
        """identify if a hash string belongs to this algorithm.

        :arg hash:
            the hash string to check

        :returns:
            ``True`` if provided hash string is handled by
            this class, otherwise ``False``.
            If hash is ``None``, should return ``False``.
        """

    @abstract_class_method
    def encrypt(cls, secret, **context_and_settings):
        """encrypt secret, returning resulting hash string.

        :arg secret:
            A string containing the secret to encode.
            Unicode behavior is specified on a per-hash basis,
            but the common case is to encode into utf-8
            before processing.

        :param context_and_settings:
            All other keywords are algorithm-specified,
            and should be listed in :attr:`setting_kwds`
            and :attr:`context_kwds`.

            Common keywords include ``salt`` and ``rounds``.

        :raises ValueError:
            * if settings are invalid and not correctable.
              (eg: provided salt contains invalid characters / length).

            * if a context kwd contains an invalid value, or was required
              but omitted.

            * if secret contains forbidden characters (e.g: des-crypt forbids null characters).
              this should rarely occur, since most modern algorithms have no limitations
              on the types of characters.

        :returns:
            Hash encoded in algorithm-specified format.
        """

    @abstract_class_method
    def verify(cls, secret, hash, **context):
        """verify a secret against an existing hash.

        This checks if a secret matches against the one stored
        inside the specified hash.

        :param secret:
            A string containing the secret to check.
        :param hash:
            A string containing the hash to check against.

        :param context:
            Any additional keywords will be passed to the encrypt
            method. These should be limited to those listed
            in :attr:`context_kwds`.

        :raises ValueError:
            if the hash is omitted or does not belong to this algorithm.

        :returns:
            ``True`` if the secret matches, otherwise ``False``.
            If hash is ``None``, should return ``False``.
        """

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#
#=========================================================
class ExtCryptHandler(CryptHandler):
    """class providing an extended handler interface,
    allowing manipulation of hash & config strings.

    About
    -----
    this extended interface adds methods for parsing and rendering
    a hash or config string to / from a dictionary of components.

    this interface is generally easier to use when *implementing* hash
    algorithms, and as such is used through passlib. it's kept separate
    from :class:`CryptHandler` itself, since it's features are not typically
    required for user-facing purposes.

    Usage
    -----
    when implementing a hash algorithm...

    subclasses must implement:

        * parse()
        * render()
        * encrypt()

    subclasses may optionally implement more efficient versions of
    these functions, though the defaults should be sufficient:

        * identify()
        * verify()

    subclasses may also use the following helper functions
    when implementing encrypt():

        * render()
        * _norm_rounds() for normalizing rounds values.
        * _norm_salt() for normalizing / generating salt
          (requires filling in some class attrs, read _norm_salt doc for details)
    """

    #=========================================================
    #class attrs
    #=========================================================

    #---------------------------------------------------------
    #helper to auto-specify setting_kwds for common cases
    #---------------------------------------------------------
    @classproperty
    def setting_kwds(cls):
        "auto-calculates setting_kwds for the 3 most common cases, autodetecting via other informational attributes"
        if cls.salt_bytes > 0:
            if cls.default_rounds:
                return ("salt", "rounds")
            return ("salt",)
        elif cls.default_rounds:
            return ("rounds",)
        else:
            return ()

    #---------------------------------------------------------
    # _norm_salt() configuration
    #---------------------------------------------------------

    salt_chars = None #fill in with (maxium) number of salt chars required, and _norm_salt() will handle truncating etc
    salt_charset = H64_CHARS #helper used when generating salt

    #override only if minimum number of salt chars is different from salt_chars
    @classproperty
    def min_salt_chars(cls):
        return cls.salt_chars

    #=========================================================
    #parsing routines
    #=========================================================
    @abstract_class_method
    def parse(cls, hash):
        """parse hash or config into dictionary.

        :arg hash: the hash/config string to parse

        :raises ValueError:
            If hash/config string is empty,
            or not recognized as belonging to this algorithm

        :returns:
            dictionary containing a subset of the keys
            specified in :attr:`setting_kwds`.

            commonly used keys are ``salt``, ``rounds``.

            If and only if the string is a hash, the dict should also contain
            the key ``checksum``, mapping to the checksum portion of the hash.

        .. note::
            Specific implementations may perform anywhere from none to full
            validation of input string; the primary goal of this method
            is to parse settings from single string into kwds
            which will be recognized by :meth:`render` and :meth:`encrypt`.

            :meth:`encrypt` is where validation of inputs *must* be performed.
        """

    @abstract_class_method
    def render(cls, checksum, **settings):
        """render hash from checksum & settings (as returned by :meth:`parse`).

        :param checksum:
            Encoded checksum portion of hash.

        :param settings:
            All other keywords are algorithm-specified,
            and should be listed in :attr:`setting_kwds`.

        :raises ValueError:
            If any values are not encodeable into hash.

        :raises NotImplementedError:
            If checksum is omitted and the algorithm
            doesn't have any settings (:attr:`setting_kwds` is empty),
            or doesn't support generating "salt strings"
            which contain all configuration except for the
            checksum itself.

        :returns:
            if checksum is specified, this should return a fully-formed hash.
            otherwise, it should return a config string containing
            the specified inputs.

        .. note::
            Specific implementations may perform anywhere from none to full
            validation of inputs; the primary goal of this method
            is to render the settings into a single string
            which will be recognized by :meth:`parse`.

            :meth:`encrypt` is where validation of inputs *must* be performed.
        """

    #=========================================================
    #frontend
    #=========================================================

    @classmethod
    def identify(cls, hash):
        #NOTE: this is a default identify() implementation provided
        # by ExtCryptAlgorithm, which should work for most classes.
        try:
            cls.parse(hash)
        except ValueError:
            return False
        return True

    #NOTE: subclasses must still implement encrypt() directly,
    # though _norm_salt(), _norm_rounds(), and render()
    # are generally helpful when writing an encrypt() method.

    @classmethod
    def verify(cls, secret, hash, **context):
        #NOTE: this is a default verify() implementation provided
        # by ExtCryptAlgorithm, which should work for most classes,
        # provided that comparing the checksums as returned by parse()
        # is a valid way of comparing the two hashes.
        #
        # simple string comparison of 'hash == other' was not used
        # as the default behavior, since some algorithms have multiple possible
        # encodings for the same hash (eg: case insensitivity, zero-padding
        # of numeric options, etc)
        assert all(key in cls.context_kwds for key in context), "one the following not a valid context kwd: %r" % (context,)
        settings = cls.parse(hash)
        settings.pop("checksum", None)
        settings.update(context)
        other = cls.encrypt(secret, **settings)
        return hash == other

    #=========================================================
    #configuration helpers
    #=========================================================
    @classmethod
    def _norm_rounds(cls, rounds):
        """helper routine for normalizing rounds

        * falls back to default_rounds
        * clips to min_rounds / max_rounds
        """
        if not rounds:
            rounds = cls.default_rounds
            if not rounds:
                raise ValueError, "rounds must be specified explicitly"
        mx = cls.max_rounds
        if mx and rounds > mx:
            warn("%s algorithm does not allow more than %d rounds: %d", mx, rounds)
            rounds = mx
        mn = cls.min_rounds
        if mn and rounds < mn:
            warn("%s algorithm does not allow less than %d rounds: %d", mn, rounds)
            rounds = mn
        return rounds

    @classmethod
    def _gen_salt(cls):
        """helper routine to generate salt, used by _norm_salt"""
        return getrandstr(rng, cls.salt_charset, cls.salt_chars)

    @classmethod
    def _norm_salt(cls, salt):
        """helper routine for normalizing salt

        required salt_charset & salt_chars attrs to be filled in,
        along with optional min_salt_chars attr (defaults to salt_chars).

        * generates salt if none provided
        * clips salt to maximum length of salt_chars

        :raises ValueError:
            * if salt contains chars that aren't in salt_charset.
            * if salt contains less than min_salt_chars characters.

        :returns:
            resulting or generated salt
        """
        if not salt:
            return cls._gen_salt()

        cs = cls.salt_charset
        for c in salt:
            if c not in cs:
                raise ValueError, "invalid character in %s salt: %r"  % (cls.name, c)

        mn = cls.min_salt_chars
        assert mn, "cls.min_salt_chars not set"
        if len(salt) < mn:
            raise ValueError, "%s salt must be at least %d chars" % (cls.name, mn)

        mx = cls.salt_chars
        assert mx, "cls.salt_chars not set"
        if len(salt) > mx:
            #automatically clip things to specified number of chars
            return salt[:mx]
        else:
            return salt
    #=========================================================
    #eoc
    #=========================================================

#=========================================================
# eof
#=========================================================
