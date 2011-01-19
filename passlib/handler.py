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
from passlib.utils import abstract_class_method, classproperty
#pkg
#local
__all__ = [
    #global registry
    'register_crypt_handler',
    'get_crypt_handler',
    'list_crypt_handlers'

    'is_crypt_handler',

    #framework for implementing handlers
    'CryptHandler',
    'CryptHandlerHelper',
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

    log.info("registered crypt algorithm: cls=%r name=%r aliases=%r", obj, obj.name, obj.aliases)

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

def is_crypt_handler(obj):
    "check if obj following CryptHandler protocol"
    #NOTE: this isn't an exhaustive check of all required attrs,
    #just a quick check of the most uniquely identifying ones
    return all(hasattr(obj, name) for name in (
        "name", "verify", "encrypt", "identify",
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
    salt_bytes = 0 #number of effective bytes in salt
    checksum_bytes = 0 #number of effective bits in hash

    #---------------------------------------------------------
    #algorithm rounds information
    #---------------------------------------------------------
    default_rounds = None #default number of rounds to use if none specified (can be name of a preset)
    min_rounds = None #minimum number of rounds (smaller values silently ignored)
    max_rounds = None #maximum number of rounds (larger values silently ignored)

    #=========================================================
    #subclass-provided methods
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
    def encrypt(self, secret):
        """encrypt secret, returning resulting hash string.

        :arg secret:
            A string containing the secret to encode.
            Unicode behavior is specified on a per-hash basis,
            but the common case is to encode into utf-8
            before processing.

        .. note::
            Various password algorithms may accept addition keyword
            arguments, usually to override default configuration parameters.
            For example, most has_rounds algorithms will have a ``rounds`` keyword.
            Such details vary on a per-algorithm basis, consult their encrypt method
            for details.

        .. note::
            In general, if an option was specified both as a kwd
            and encoded within the ``hash`` parameter,
            the kwd value should be given preference (eg, the ``rounds`` kwds).

        :returns:
            The encoded hash string, with any chrome and identifiers.
            All values returned by this function should
            pass ``identify(hash) -> True``
            and ``verify(secret,hash) -> True``.

        Usage Example::

            >>> from passlib.md5_crypt import Md5Crypt
            >>> #encrypt a secret, creating a new hash
            >>> hash = Md5Crypt.encrypt("it's a secret")
            >>> hash
            '$1$2xYRz6ta$IWpg/auAdyc8.CyZ0K6QK/'
            >>> #verify our secret
            >>> Md5Crypt.verify("fluffy bunnies", hash)
            False
            >>> Md5Crypt.verify("it's a secret", hash)
            True
            >>> #encrypting again should generate a new salt,
            >>> #even if we pass in the old one
            >>> crypt.encrypt("it's a secret", hash)
            '$1$ZS9HCWrt$dRT5Q5R9YRoc5/SLA.WkD/'
            >>> _ == hash
            False
        """

    @abstract_class_method
    def verify(cls, secret, hash):
        """verify a secret against an existing hash.

        This checks if a secret matches against the one stored
        inside the specified hash. By default this uses :meth:`encrypt`
        to re-crypt the secret, and compares it to the provided hash;
        though some algorithms may implement this in a more efficient manner.

        :param secret:
            A string containing the secret to check.
        :param hash:
            A string containing the hash to check against.

        :returns:
            ``True`` if the secret matches, otherwise ``False``.
            If hash is ``None``, should return ``False``.

        See :meth:`encrypt` for a usage example.

        .. note::
            The default implementation works most of the time,
            but may give false negatives
            if the hash algorithm has encoding quirks,
            such as multiple possible encodings for the same
            salt + secret.
        """

    #=========================================================
    #
    #=========================================================

    #def parse(cls, hash):
    #  optional method which parses hash into components, or raises ValueError

    #def render(cls, **parse_kwds):
    #  optional inverse of parse()

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#helpers
#=========================================================
class CryptHandlerHelper(CryptHandler):
    "class providing some helpful methods for implementing a crypt algorithm"

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

    @classmethod
    def _norm_rounds(cls, rounds):
        "provide default rounds if needed, and clip rounds to boundary"
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

#=========================================================
# eof
#=========================================================
