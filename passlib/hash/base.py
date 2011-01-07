"""passlib.hash - implementation of various password hashing functions"""
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
from passlib.util import classproperty, abstractmethod, is_seq, srandom, H64
#pkg
#local
__all__ = [
    #crypt algorithms
    'CryptAlgorithm',

    #crypt context
    'CryptContext',
]

#=========================================================
#common helper funcs for passwords
#=========================================================

class HashInfo(object):
    "helper used by various CryptAlgorithms to store parsed hash information"
    alg = None #name or alias identifying algorithm
    salt = None #salt portion of hash
    chk = None #checksum (result of hashing salt & password according to alg)
    rounds = None #number of rounds, if known & applicable
    source = None #source above information was parsed from, if available

    def __init__(self, alg, salt, chk=None, rounds=None, source=None):
        self.alg = alg
        self.salt = salt
        self.chk = chk
        self.rounds = rounds
        self.source = source

#==========================================================
#base interface for all the crypt algorithm implementations
#==========================================================
class CryptAlgorithm(object):
    """base class for holding information about password algorithm.

    The following should be filled out for all crypt algorithm subclasses.
    Additional methods, attributes, and features may vary.

    Informational Attributes
    ========================
    .. attribute:: name

        This should be a globally unique name to identify
        the hash algorithm with.

    .. attribute:: salt_bits

        This is a purely informational attribute
        listing how many bits are in the salt your algorithm uses.
        (defaults to ``None`` if information is not available).

    .. attribute:: hash_bits

        This is a purely informational attribute
        listing how many bits are in the cheksum part of your algorithm's hash.
        (defaults to ``None`` if information is not available).

    .. note::

        Note that all the bit counts should measure
        the number of bits of entropy, not the number of bits
        a given encoding takes up.

    .. attribute:: has_salt

        This is a virtual attribute,
        calculated based on the value of the salt_bits attribute.
        It returns ``True`` if the algorithm contains any salt bits,
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

    .. note::
        It is recommended to use ``from passlib.util import srandom``
        as your random number generator, since it should (hopefully)
        be the strongest rng passlib can find on your system.

    """

    #=========================================================
    #informational attrs
    #=========================================================
    name = None #globally unique name to identify algorithm
    salt_bits = None #number of effective bits in salt
    hash_bits = None #number of effective bits in hash
    secret_chars = None #max number of chars of secret that are used in hash. None if all chars used.

    has_rounds = False #supports variable number of rounds via rounds kwd
    has_named_rounds = False #round kwd supports 'fast', 'medium', 'slow' presets

    @classproperty
    def has_salt(self):
        "helper to determine if hash has a salt"
        if self.salt_bits is None:
            return None
        return self.salt_bits > 0

    #=========================================================
    #class config
    #=========================================================
    #keywords which will be set by constructor
    init_attrs = ("name", "salt_bits", "hash_bits", "has_rounds",
        "identify", "encrypt", "verify",
        )

    #=========================================================
    #init & internal methods
    #=========================================================
    def __init__(self, **kwds):
        #XXX: can probably do away with this, nothing uses it.
        #but should add in checksum / salt / source / ident kwds from HashInfo
        #load in kwds, letting options be overridden on a per-instance basis
        for key in self.init_attrs:
            if key in kwds:
                setattr(self, key, kwds.pop(key))
        super(CryptAlgorithm, self).__init__(**kwds)
        self._validate()

    def _validate(self):
        #make sure instance has everything defined
        if not self.name:
            raise ValueError, "no name specified"

    def __repr__(self):
        c = self.__class__
        return '<%s.%s object, name=%r>' % (c.__module__, c.__name__, self.name)

##    def __repr__(self):
##        c = self.__class__
##        tail = ''
##        for key in ("name",):
##            if key in self.__dict__:
##                tail += "%s=%r, " % (key, getattr(self, key))
##        if tail:
##            tail = tail[:-2]
##        return "%s.%s(%s)" % (c.__module__,c.__name__, tail)

    #=========================================================
    #subclass-provided methods
    #=========================================================

    @abstractmethod
    def identify(self, hash):
        """identify if a hash string belongs to this algorithm.

        :arg hash:
            the hash string to check
            
        :returns:
            ``True`` if provided hash string is handled by
            this class, otherwise ``False``.
            If hash is ``None``, should return ``False``.
        """

    @abstractmethod
    def encrypt(self, secret, hash=None, keep_salt=False):
        """encrypt secret, returning resulting hash string.

        :arg secret:
            A string containing the secret to encode.
            Unicode behavior is specified on a per-hash basis,
            but the common case is to encode into utf-8
            before processing.

        :arg hash:
            Optional hash string, containing a salt and other
            configuration parameters (rounds, etc). If a salt is not specified,
            a new salt should be generated with default configuration
            parameters set.

        :type keep_salt: bool
        :param keep_salt:
            *This option is rarely needed by end users,
            you can safely ignore it if you are not writing a hash algorithm.*

            By default (``keep_salt=False``), a new salt will
            be generated for each call to encrypt, for added security.
            If a salt string is provided, only the configuration
            parameters (number of rounds, etc) should be preserved.

            However, it is sometimes useful to preserve the original salt
            bytes, instead of generating new ones (such as when verifying
            the hash of an existing password). In that case,
            set ``keep_salt=True``. Note that most end-users will want
            to call ``self.verify(secret,hash)`` instead of using this flag.

        .. note::
            Various password algorithms may accept addition keyword
            arguments, usually to override default configuration parameters.
            For example, most has_rounds algorithms will have a *rounds* keyword.
            Such details vary on a per-algorithm basis, consult their encrypt method
            for details.

        :returns:
            The encoded hash string, with any chrome and identifiers.
            All values returned by this function should
            pass ``identify(hash) -> True``
            and ``verify(secret,hash) -> True``.

        Usage Example::

            >>> from passlib.pwhash import Md5Crypt
            >>> crypt = Md5Crypt()
            >>> #encrypt a secret, creating a new hash
            >>> hash = crypt.encrypt("it's a secret")
            >>> hash
            '$1$2xYRz6ta$IWpg/auAdyc8.CyZ0K6QK/'
            >>> #verify our secret
            >>> crypt.verify("fluffy bunnies", hash)
            False
            >>> crypt.verify("it's a secret", hash)
            True
            >>> #encrypting again should generate a new salt,
            >>> #even if we pass in the old one
            >>> crypt.encrypt("it's a secret", hash)
            '$1$ZS9HCWrt$dRT5Q5R9YRoc5/SLA.WkD/'
            >>> _ == hash
            False
        """

    @classmethod
    def verify(self, secret, hash):
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
        """
        #NOTE: this implementation works most of the time,
        # but if hash algorithm is funky, or input hash
        # is not in the proper normalized form that encrypt returns,
        # there will be false negatives.
        if hash is None:
            return False
        return hash == self.encrypt(secret, hash, keep_salt=True)

    #=========================================================
    #eoc
    #=========================================================

def is_crypt_alg(obj):
    "check if obj following CryptAlgorithm protocol"
    #NOTE: this isn't an exhaustive check of all required attrs,
    #just a quick check of the most uniquely identifying ones
    return all(hasattr(obj, name) for name in (
        "name", "verify", "encrypt", "identify",
        ))

#=========================================================
#
#=========================================================
class CryptContext(list):
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
        >>> #or just return the CryptAlgorithm instance directly
        >>> myctx.identify(hash1, resolve=True)
        <passlib.hash.BCrypt object, name="bcrypt">

        >>> #you can get a list of algs...
        >>> myctx.keys()
        [ 'md5-crypt', 'bcrypt' ]

        >>> #and get the CryptAlgorithm object by name
        >>> bc = myctx['bcrypt']
        >>> bc
        <passlib.hash.BCrypt object, name="bcrypt">
    """
    #=========================================================
    #init
    #=========================================================
    def __init__(self, source=None):
        list.__init__(self)
        if source:
            self.extend(source)

    #=========================================================
    #wrapped list methods
    #=========================================================

    #---------------------------------------------------------
    #misc
    #---------------------------------------------------------
    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, list.__repr__(self))

    #---------------------------------------------------------
    #readers
    #---------------------------------------------------------
    def keys(self):
        "return list of names of all algorithms in context"
        return [ alg.name for alg in self ]

    def get(self, name, default=None):
        return self.resolve(name) or default

    def __getitem__(self, value):
        "look up algorithm by index or by name"
        if isinstance(value, str):
            #look up by string
            return self.must_resolve(value)
        else:
            #look up by index
            return list.__getitem__(self, value)

    def __contains__(self, value):
        "check for algorithm's presence by name or instance"
        return self.index(value) > -1

    def index(self, value):
        """find location of algorithm by name or instance"""
        if isinstance(value, str):
            #hunt for element by alg name
            for idx, crypt in enumerate(self):
                if crypt.name == value:
                    return idx
            return -1
##        elif isinstance(value, type):
##            #hunt for element by alg class
##            for idx, crypt in enumerate(self):
##                if isinstance(crypt, value):
##                    return idx
##            return -1
        else:
            #else should be an alg instance
            for idx, crypt in enumerate(self):
                if crypt == value:
                    return idx
            return -1

    #---------------------------------------------------------
    #adding
    #---------------------------------------------------------
    #XXX: prevent duplicates?

    def _norm_alg(self, value):
        "makes sure all elements of list are CryptAlgorithm instances"
        if not is_crypt_alg(value):
            raise ValueError, "value must be CryptAlgorithm class or instance: %r" % (value,)
        if isinstance(value, type):
            value = value()
        if not value.name:
            raise ValueError, "algorithm instance lacks name: %r" % (value,)
        return value

    def __setitem__(self, idx, value):
        "override algorithm at specified location"
        if idx < 0:
            idx += len(self)
        value = self._norm_alg(value)
        old = self.index(value.name)
        if old > -1 and old != idx:
            raise KeyError, "algorithm named %r already present in context" % (value.name,)
        list.__setitem__(self, idx, value)

    def append(self, value):
        "add another algorithm to end of list"
        value = self._norm_alg(value)
        if value.name in self:
            raise KeyError, "algorithm named %r already present in context" % (value.name,)
        list.append(self, value)

    def insert(self, idx, value):
        value = self._norm_alg(value)
        if value.name in self:
            raise KeyError, "algorithm named %r already present in context" % (value.name,)
        list.insert(self, idx, value)

    #---------------------------------------------------------
    #composition
    #---------------------------------------------------------
    def __add__(self, other):
        c = CryptContext()
        c.extend(self)
        c.extend(other)
        return c

    def __iadd__(self, other):
        self.extend(other)
        return self

    def extend(self, values, include=None, exclude=None):
        "add more algorithms from another list, optionally filtering by name"
        if include:
            values = (e for e in values if e.name in include)
        if exclude:
            values = (e for e in values if e.name not in exclude)
        for value in values:
            self.append(value)

    #---------------------------------------------------------
    #removing
    #---------------------------------------------------------
    def remove(self, value):
        if isinstance(value, str):
            value = self[value]
        list.remove(self, value)

    def discard(self, value):
        if isinstance(value, str):
            try:
                self.remove(value)
                return True
            except KeyError:
                return False
        else:
            try:
                self.remove(value)
                return True
            except ValueError:
                return False

    #=========================================================
    #CryptAlgorithm workalikes
    #=========================================================
    #TODO: recode default to be explicitly settable, not just using first one.
    #TODO: simplify interface as much as possible.

    def resolve(self, name=None, default=None):
        """given an algorithm name, return CryptAlgorithm instance which manages it.
        if no match is found, returns None.

        resolve() without arguments will return default algorithm
        """
        if name is None:
            #return default algorithm
            if self:
                return self[-1]
        elif is_seq(name):
            #pick last hit from list of names
            for elem in reversed(self):
                if elem.name in name:
                    return elem
        else:
            #pick name
            for elem in reversed(self):
                if elem.name == name:
                    return elem
        return default

    def must_resolve(self, name):
        "helper which raises error if alg can't be found"
        crypt = self.resolve(name)
        if crypt is None:
            raise KeyError, "algorithm not found: %r" % (name,)
        else:
            return crypt

    def identify(self, hash, resolve=False):
        """Attempt to identify which algorithm hash belongs to w/in this context.

        :arg hash:
            The hash string to test.
        :param resolve:
            If ``True``, the actual algorithm object is returned.
            If ``False`` (the default), only the name of the algorithm is returned.

        All registered algorithms will be checked in from last to first,
        and whichever one claims the hash first will be returned.

        :returns:
            The first algorithm instance that identifies the hash,
            or ``None`` if none of the algorithms claims the hash.
        """
        if hash is None:
            return None
        for alg in reversed(self):
            if alg.identify(hash):
                if resolve:
                    return alg
                else:
                    return alg.name
        return None

    def must_identify(self, hash, **kwds):
        "helper which raises error if hash can't be identified"
        alg = self.identify(hash, **kwds)
        if alg is None:
            raise ValueError, "hash could not be identified"
        else:
            return alg

    def encrypt(self, secret, hash=None, alg=None, **kwds):
        """encrypt secret, returning resulting hash.

        :arg secret:
            String containing the secret to encrypt

        :arg hash:
            Optional hash string previously returned by encrypt (or compatible source).
            If specified, this string will be used to provide default
            value for the salt, rounds, or other algorithm-specific options.

        :param alg:
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
        if alg:
            crypt = self.must_resolve(alg)
        elif hash:
            crypt = self.must_identify(hash, resolve=True)
        else:
            crypt = self[-1]
        return crypt.encrypt(secret, hash, **kwds)

    def verify(self, secret, hash, alg=None, **kwds):
        """verify secret against specified hash

        :arg secret:
            the secret to encrypt
        :arg hash:
            hash string to compare to
        :param alg:
            optionally specify which algorithm(s) should be considered.
        """
        if not self:
            raise ValueError, "no algorithms registered"
        if hash is None: #for convience, so apps can pass in user_account.hash field w/o worrying if it was set
            return False
        if alg:
            crypt = self.must_resolve(alg)
        else:
            crypt = self.must_identify(hash, resolve=True)
        #NOTE: passing additional keywords for algorithms such as PostgresMd5Crypt
        return crypt.verify(secret, hash, **kwds)

    #=========================================================
    #eof
    #=========================================================

def is_crypt_context(obj):
    "check if obj following CryptContext protocol"
    #NOTE: this isn't an exhaustive check of all required attrs,
    #just a quick check of the most uniquely identifying ones
    return all(hasattr(obj, name) for name in (
        "resolve", "verify", "encrypt", "identify",
        ))

#=========================================================
# eof
#=========================================================
