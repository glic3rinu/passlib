"""bps.security.pwhash - implementation of various password hashing functions"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import inspect
import re
import hashlib
import time
import os
#site
#libs
from bps import *
from bps.basic import enum_slice
from bps.rng import srandom
from passlib.util import classproperty, abstractmethod, is_seq

try:
    #try stdlib module, which is only present under posix
    from crypt import crypt as unix_crypt
    #XXX: might want to reconcile our implementation's behavior
    # with the posix behavior so error types/messages and limitations
    # are reliable
except ImportError:
    from bps.security._unix_crypt import crypt as unix_crypt

try:
    #try importing py-bcrypt, it's much faster
    import bcrypt
except ImportError:
    #fall back to our slow pure-python implementation
    import bps.security._bcrypt as bcrypt

#pkg
#local
__all__ = [
    #crypt algorithms
    'CryptAlgorithm',
        'UnixCrypt',
        'Md5Crypt',
        'Sha256Crypt',
        'Sha512Crypt',
        'BCrypt',

    #crypt context
    'CryptContext',
        'default_context',
        'linux_context',
        'bsd_context',

    #quick helpers
    'identify_secret',
    'encrypt_secret',
    'verify_secret',

]

#=========================================================
#common helper funcs for passwords
#=========================================================
#charmap for "hash64" encoding
#most unix hash algorithms use this mapping (though bcrypt put it's numerals at the end)
CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
CHARIDX = dict( (c,i) for i,c in enumerate(CHARS))

def _enc64(value, offset=0, num=False):
    if num:
        x, y, z = value[offset], value[offset+1], value[offset+2]
    else:
        x, y, z = ord(value[offset]), ord(value[offset+1]), ord(value[offset+2])
    #xxxxxx xxyyyy yyyyzz zzzzzz
    #aaaaaa bbbbbb cccccc dddddd
    a = (x >> 2) # x [8..3]
    b = ((x & 0x3) << 4) + (y>>4) # x[2..1] + y [8..5]
    c = ((y & 0xf) << 2) + (z>>6) #y[4..1] + d[8..7]
    d = z & 0x3f
    return CHARS[a] + CHARS[b] + CHARS[c] + CHARS[d]

def _dec64(value, offset=0, num=False):
    a, b, c, d = CHARIDX[value[offset]], CHARIDX[value[offset+1]], \
        CHARIDX[value[offset+2]], CHARIDX[value[offset+3]]
    #aaaaaabb bbbbcccc ccdddddd
    #xxxxxxxx yyyyyyyy zzzzzzzz
    x = (a<<2) + (b >> 4) #a[6..1] + b[6..5]
    y = ((b & 0xf) << 4) + (c >> 2) #b[4..1] + c[6..3]
    z = ((c & 0x3) << 6) + d #c[2..1] + d[6..1]
    if num:
        return x, y, z
    return chr(x) + chr(y) + chr(z)

def h64_encode(value, pad=False, num=False):
    "encode string of bytes into hash64 format"
    if num:
        value = list(value)
    #pad value to align w/ 3 byte chunks
    x = len(value) % 3
    if x == 2:
        if num:
            value += [0]
        else:
            value += "\x00"
        p = 1
    elif x == 1:
        if num:
            value += [0, 0]
        else:
            value += "\x00\x00"
        p = 2
    else:
        p = 0
    assert len(value) % 3 == 0
    out = "".join( _enc64(value, offset, num=num) for offset in xrange(0, len(value), 3))
    assert len(out) % 4 == 0
    if p:
        if pad:
            out = out[:-p] + "=" * p
        else:
            out = out[:-p]
    return out

def h64_decode(value, pad=False, num=False):
    "decode string of bytes from hash64 format"
    if value.endswith("="):
        assert len(value) % 4 == 0, value
        if value.endswith('=='):
            p = 2
            value = value[:-2] + '..'
        else:
            p = 1
            value = value[:-1] + '.'
    else:
        #else add padding if needed
        x = len(value) % 4
        if x == 0:
            p = 0
        elif pad:
            raise ValueError, "size must be multiple of 4"
        elif x == 3:
            p = 1
            value += "."
        elif x == 2:
            p = 2
            value += ".."
        elif x == 1:
            p = 3
            value += "..."
    assert len(value) % 4 == 0, value
    if num:
        out = []
        for offset in xrange(0, len(value), 4):
            out.extend(_dec64(value, offset, num=True))
    else:
        out = "".join( _dec64(value, offset) for offset in xrange(0, len(value), 4))
    assert len(out) % 3 == 0
    if p: #strip out garbage chars
        out = out[:-p]
    return out

def _enc64b(a, b, c, n=4):
    "std hash64 bit encoding"
    v = (ord(a) << 16) + (ord(b) << 8) + ord(c)
    return "".join(
        CHARS[(v >> (i*6)) & 0x3F]
        for i in range(n)
        )

def _enc64b1(buffer, a):
    "do 64bit encode of single element of a buffer"
    return _enc64b('\x00', '\x00', buffer[a], 2)

def _enc64b2(buffer, a, b):
    "do 64bit encode of 2 elements of a buffer"
    return _enc64b('\x00', buffer[a], buffer[b], 3)

def _enc64b3(buffer, a, b, c):
    "do 64bit encode of 3 elements of a buffer"
    return _enc64b(buffer[a], buffer[b], buffer[c], 4)

def h64_gen_salt(size, pad=False):
    "generate hash64 salt of arbitrary length"
    srandom.reseed()
    out = ''.join(
        srandom.choice(CHARS)
        for idx in xrange(size)
        )
    if pad and size % 4:
        out += "=" * (-size % 4)
    return out

class UnixHash(object):
    "helper used by various hash algorithm utilities"
    alg = None
    salt = None
    chk = None
    rounds = None
    source = None

    def __init__(self, alg, salt, chk=None, rounds=None, source=None):
        self.alg = alg
        self.salt = salt
        self.chk = chk
        self.rounds = rounds
        self.source = source

#==========================================================
#base interface for all the crypt algorithm implementations
#==========================================================
class CryptAlgorithm(BaseClass):
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
        It is recommended to use ``from bps.rng import srandom``
        as your random number generator, since it should (hopefully)
        be the strongest rng BPS can find on your system.
        To help this, you should call ``srandom.reseed()``
        before generating your salt.

    """

    #=========================================================
    #informational attrs
    #=========================================================
    name = None #globally unique name to identify algorithm
    salt_bits = None #number of bits in salt
    hash_bits = None #number of bits in hash
    secret_chars = None #number of chars in secret that are used. None if all chars used.
    has_rounds = False #has_rounds (via rounds, etc) as computers get more powerful
    has_named_rounds = False #supports round aliases

    @classproperty
    def has_salt(self):
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
        #load in kwds, letting options be overridden on a per-instance basis
        for key in self.init_attrs:
            if key in kwds:
                setattr(self, key, kwds.pop(key))
        self.__super.__init__(**kwds)
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

        .. note::
            For some of the simplist algorithms (eg plaintext),
            there is no globally unambiguous way to identify
            a given hash. In this case, identify() should
            at the very least be able to distinguish
            it's hashes from the other algorithms
            in use within a given context.
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

            >>> from bps.security.pwhash import Md5Crypt
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

        See :meth:`encrypt` for a usage example.
        """
        #NOTE: this implementation works most of the time,
        # but if hash algorithm is funky, or input hash
        # is not in the proper normalized form that encrypt returns,
        # there will be false negatives.
        if hash is None:
            return False
        return hash == self.encrypt(secret, hash, keep_salt=True)

##    def decrypt(self, hash):
##        """decrypt hash, recovering original password.
##
##        Most (good) password algorithms will not be recoverable.
##        For those, this will raise a NotImplementedError.
##        For the few which are weak enough, or can be recovered
##        with the aid of external information such as a private key,
##        this method should be overridden to provide an implementation.
##
##        Subclasses may add arbitrary options (external keys, etc)
##        to aid with decryption.
##
##        If decrypt is implemented, but does not succeed in the end,
##        it should raise a ValueError.
##        """
##        raise NotImplementedError, "this algorithm does not support decryption"

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
#sql database hashes
#=========================================================
class Mysql10Crypt(CryptAlgorithm):
    """This implements Mysql's OLD_PASSWORD algorithm, used prior to version 4.1.

    See :class:`Mysql41Crypt` for the new algorithm was put in place in version 4.1

    This function is known to be very insecure,
    and should only be used to verify existing password hashes.

    """
    name = "mysql-1.0-crypt"
    salt_bits = 0
    hash_bits = 16*16

    _pat = re.compile(r"^[0-9a-f]{16}$", re.I)

    def identify(self, hash):
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    def encrypt(self, secret, hash=None, keep_salt=False):
        nr1 = 1345345333
        nr2 = 0x12345671
        add = 7
        for c in secret:
            if c in ' \t':
                continue
            tmp = ord(c)
            nr1 ^= ((((nr1 & 63)+add)*tmp) + (nr1 << 8)) & 0xffffffff
            nr2 = (nr2+((nr2 << 8) ^ nr1)) & 0xffffffff
            add = (add+tmp) & 0xffffffff
        return "%08x%08x" % (nr1 & 0x7fffffff, nr2 & 0x7fffffff)

    def verify(self, secret, hash):
        if hash is None:
            return False
        return hash.lower() == self.encrypt(secret)

class Mysql41Crypt(CryptAlgorithm):
    """This implements Mysql new PASSWORD algorithm, introduced in version 4.1.

    This function is unsalted, and therefore not very secure against rainbow attacks.
    It should only be used when dealing with mysql passwords,
    for all other purposes, you should use a salted hash function.

    Description taken from http://dev.mysql.com/doc/refman/6.0/en/password-hashing.html
    """
    name = "mysql-4.1-crypt"
    salt_bits = 0
    hash_bits = 16*40

    _pat = re.compile(r"^\*[0-9A-F]{40}$", re.I)

    def identify(self, hash):
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    def encrypt(self, secret, hash=None, keep_salt=False):
        return '*' + hashlib.sha1(hashlib.sha1(secret).digest()).hexdigest().upper()

    def verify(self, secret, hash):
        if hash is None:
            return False
        return hash.upper() == self.encrypt(secret)

class PostgresMd5Crypt(CryptAlgorithm):
    """This implements the md5-based hash algorithm used by Postgres to store
    passwords in the pg_shadow table.

    This algorithm shouldn't be used for any purpose besides Postgres interaction,
    it's a weak unsalted algorithm which could easily be attacked with a rainbow table.

    .. warning::
        This algorithm is slightly different from most of the others,
        in that both encrypt() and verify() require you pass in
        the name of the user account via the required 'user' keyword,
        since postgres uses this in place of a salt :(

    Usage Example::

        >>> from bps.security import pwhash
        >>> crypt = pwhash.PostgresMd5Crypt()
        >>> crypt.encrypt("mypass", user="postgres")
        'md55fba2ea04fd36069d2574ea71c8efe9d'
        >>> crypt.verify("mypass", 'md55fba2ea04fd36069d2574ea71c8efe9d', user="postgres")
        True
    """
    name = "postgres-md5-crypt"
    salt_bits = 0
    hash_bits = 16*32

    _pat = re.compile(r"^md5[0-9a-f]{32}$")

    def identify(self, hash):
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    def encrypt(self, secret, hash=None, keep_salt=False, user=None):
        if isinstance(secret, tuple):
            if user:
                raise TypeError, "user specified in secret & in kwd"
            secret, user = secret
        if not user:
            raise ValueError, "user keyword must be specified for this algorithm"
        return "md5" + hashlib.md5(secret + user).hexdigest().lower()

    def verify(self, secret, hash, user=None):
        if hash is None:
            return False
        return hash == self.encrypt(secret, user=user)

#=========================================================
#old unix crypt
#=========================================================
class UnixCrypt(CryptAlgorithm):
    """Old Unix-Crypt Algorithm, as originally used on unix before md5-crypt arrived.
    This implementation uses the builtin ``crypt`` module when available,
    but contains a pure-python fallback so that this algorithm can always be used.
    """
    name = "unix-crypt"
    salt_bits = 6*2
    hash_bits = 6*11
    has_rounds = False
    secret_chars = 8

    _pat = re.compile(r"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<hash>[./a-z0-9]{11})
        $""", re.X|re.I)

    def identify(self, hash):
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    def encrypt(self, secret, hash=None, keep_salt=False):
        if hash and keep_salt:
            salt = hash[:2]
        else:
            salt = h64_gen_salt(2)
        return unix_crypt(secret, salt)

    #default verify used

#=========================================================
#id 1 -- md5
#=========================================================

#TODO: never seen it, but read references to a Sun-specific
# md5-crypt which supports rounds, format supposedly something like
# "$md5,rounds=XXX$salt$chk" , could add support under SunMd5Crypt()

class Md5Crypt(CryptAlgorithm):
    """This provides the MD5-crypt algorithm, used in many 1990's era unix systems.
    It should be byte compatible with unix shadow hashes beginning with ``$1$``.
    """
    name = 'md5-crypt'
    salt_bits = 48
    hash_bits = 96
    has_rounds = False

    def _md5_crypt_raw(self, secret, salt):
        #init salt
        if not salt:
            salt = h64_gen_salt(8)
        assert len(salt) == 8

        h = hashlib.md5()
        assert h.digestsize == 16
        h.update(secret)
        h.update(salt)
        h.update(secret)
        tmp_digest = h.digest()

        h = hashlib.md5()
        h.update(secret)
        h.update("$1$")
        h.update(salt)

        idx = len(secret)
        while idx > 0:
            h.update(tmp_digest[0:min(16, idx)])
            idx -= 16

        idx = len(secret)
        while idx > 0:
            if idx & 1:
                h.update('\x00')
            else:
                h.update(secret[0])
            idx >>= 1

        hash = h.digest()
        for idx in xrange(1000):
            assert len(hash) == 16
            h = hashlib.md5()
            if idx & 1:
                h.update(secret)
            else:
                h.update(hash)
            if idx % 3:
                h.update(salt)
            if idx % 7:
                h.update(secret)
            if idx & 1:
                h.update(hash)
            else:
                h.update(secret)
            hash = h.digest()

        out = ''.join(
            _enc64b3(hash,
                idx,
                idx+6,
                idx+12 if idx < 4 else 5,
            )
            for idx in xrange(5)
            ) + _enc64b1(hash, 11)
        return UnixHash('1', salt, out)

    _pat = re.compile(r"""
        ^
        \$(?P<alg>1)
        \$(?P<salt>[A-Za-z0-9./]+)
        (\$(?P<chk>[A-Za-z0-9./]+))?
        $
        """, re.X)

    def identify(self, hash):
        "identify md5-crypt hash"
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    def parse(self, hash):
        "parse an md5-crypt hash"
        m = self._pat.match(hash)
        if not m:
            raise ValueError, "invalid md5 salt"
        return UnixHash(m.group("alg"), m.group("salt"), m.group("chk"))

    def encrypt(self, secret, salt=None, keep_salt=False):
        "encrypt an md5-crypt hash"
        real_salt = None
        if salt:
            rec = self.parse(salt)
            if keep_salt:
                real_salt = rec.salt
        rec = self._md5_crypt_raw(secret, real_salt)
        return "$1$%s$%s" % (rec.salt, rec.chk)

    def verify(self, secret, hash):
        "verify an md5-crypt hash"
        if hash is None:
            return False
        rec = self.parse(hash)
        other = self._md5_crypt_raw(secret, rec.salt)
        return other.chk == rec.chk

#=========================================================
#ids 5,6 -- sha
#algorithm defined on this page:
#   http://people.redhat.com/drepper/SHA-crypt.txt
#=========================================================
class _ShaCrypt(CryptAlgorithm):
    "this is the base class used by SHA-256 & SHA-512. don't use directly."
    #=========================================================
    #algorithm info
    #=========================================================
    #hash_bits, name filled in for subclass
    salt_bits = 96
    has_rounds = True
    has_named_rounds = True

    #tuning the round aliases
    rounds_per_second = 156000 #last tuned 2009-7-6 on a 2gz system
    fast_rounds = int(rounds_per_second * .25)
    medium_rounds = int(rounds_per_second * .75)
    slow_rounds = int(rounds_per_second * 1.5)

    #=========================================================
    #internals required from subclass
    #=========================================================
    _key = None #alg id (5, 6) of specific sha alg
    _hash = None #callable to use for hashing
    _chunk_size = None #bytes at a time to input secret
    _hash_size = None #bytes in hash
    _pat = None #regexp for sha variant

    @abstractmethod
    def _encode(self, result):
        "encode raw result into h64 style"

    #=========================================================
    #core sha crypt algorithm
    #=========================================================
    def _sha_crypt_raw(self, rounds, salt, secret):
        "perform sha crypt, returning just the checksum"
        #setup alg-specific parameters
        hash = self._hash
        chunk_size = self._chunk_size

        #init salt
        if salt is None:
            salt = h64_gen_salt(16)
        elif len(salt) > 16:
            salt = salt[:16] #spec says to use up to first chars 16 only

        #init rounds
        if rounds == -1:
            real_rounds = 5000
        else:
            if rounds < 1000:
                rounds = 1000
            if rounds > 999999999:
                rounds = 999999999
            real_rounds = rounds

        def extend(source, size_ref):
            size = len(size_ref)
            return source * int(size/chunk_size) + source[:size % chunk_size]

        #calc digest B
        b = hash()
        b.update(secret)
        b.update(salt)
        b.update(secret)
        b_result = b.digest()
        b_extend = extend(b_result, secret)

        #begin digest A
        a = hash()
        a.update(secret)
        a.update(salt)
        a.update(b_extend)

        #for each bit in slen, add B or SECRET
        value = len(secret)
        while value > 0:
            if value % 2:
                a.update(b_result)
            else:
                a.update(secret)
            value >>= 1

        #finish A
        a_result = a.digest()

        #calc DP
        dp = hash()
        dp.update(secret * len(secret))
        dp_result = extend(dp.digest(), secret)

        #calc DS
        ds = hash()
        for i in xrange(0, 16+ord(a_result[0])):
            ds.update(salt)
        ds_result = extend(ds.digest(), salt) #aka 'S'

        #calc digest C
        last_result = a_result
        for i in xrange(0, real_rounds):
            c = hash()
            if i % 2:
                c.update(dp_result)
            else:
                c.update(last_result)
            if i % 3:
                c.update(ds_result)
            if i % 7:
                c.update(dp_result)
            if i % 2:
                c.update(last_result)
            else:
                c.update(dp_result)
            last_result = c.digest()

        #encode result using 256/512 specific func
        out = self._encode(last_result)
        assert len(out) == self._hash_size, "wrong length: %r" % (out,)
        return UnixHash(self._key, salt, out, rounds=rounds)

    def _sha_crypt(self, rounds, salt, secret):
        rec = self._sha_crypt_raw(rounds, salt, secret)
        if rec.rounds == -1:
            return "$%s$%s$%s" % (rec.alg, rec.salt, rec.chk)
        else:
            return "$%s$rounds=%d$%s$%s" % (rec.alg, rec.rounds, rec.salt, rec.chk)

    #=========================================================
    #frontend helpers
    #=========================================================
    def identify(self, hash):
        "identify bcrypt hash"
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    def parse(self, hash):
        "parse bcrypt hash"
        m = self._pat.match(hash)
        if not m:
            raise ValueError, "invalid sha hash/salt"
        alg, rounds, salt, chk = m.group("alg", "rounds", "salt", "chk")
        if rounds is None:
            rounds = -1 #indicate we're using the default mode
        else:
            rounds = int(rounds)
        assert alg == self._key
        return UnixHash(alg, salt, chk, rounds=rounds, source=hash)

    def encrypt(self, secret, hash=None, rounds=None, keep_salt=False):
        """encrypt using sha256/512-crypt.

        In addition to the normal options that :meth:`CryptAlgorithm.encrypt` takes,
        this function also accepts the following:

        :param rounds:
            Optionally specify the number of rounds to use.
            This can be one of "fast", "medium", "slow",
            or an integer in the range 1000...999999999.

            See :attr:`CryptAlgorithm.has_named_rounds` for details
            on the meaning of "fast", "medium" and "slow".
        """
        salt = None
        if hash:
            rec = self.parse(hash)
            if keep_salt:
                salt = rec.salt
            if rounds is None:
                rounds = rec.rounds
        rounds = self._norm_rounds(rounds)
        return self._sha_crypt(rounds, salt, secret)

    def _norm_rounds(self, rounds):
        if isinstance(rounds, int):
            return rounds
        elif rounds == "fast" or rounds is None:
            return self.fast_rounds
        elif rounds == "slow":
            return self.slow_rounds
        else:
            if rounds != "medium":
                log.warning("unknown rounds alias %r, using 'medium'", rounds)
            return self.medium_rounds

    def verify(self, secret, hash):
        if hash is None:
            return False
        rec = self.parse(hash)
        other = self._sha_crypt_raw(rec.rounds, rec.salt, secret)
        return other.chk == rec.chk

    #=========================================================
    #eoc
    #=========================================================

class Sha256Crypt(_ShaCrypt):
    """This class implements the SHA-256 Crypt Algorithm,
    according to the specification at `<http://people.redhat.com/drepper/SHA-crypt.txt>`_.
    It should be byte-compatible with unix shadow hashes beginning with ``$5$``.

    See Sha512Crypt for usage examples and details.
    """
    #=========================================================
    #algorithm info
    #=========================================================
    name='sha256-crypt'
    hash_bits = 256

    #=========================================================
    #internals
    #=========================================================
    _hash = hashlib.sha256
    _key = '5'
    _chunk_size = 32
    _hash_size = 43

    def _encode(self, result):
        out = ''
        a, b, c = [0, 10, 20]
        while a < 30:
            out += _enc64b3(result, a, b, c)
            a, b, c = c+1, a+1, b+1
        assert a == 30, "loop to far: %r" % (a,)
        out += _enc64b2(result, 31, 30)
        return out

    #=========================================================
    #frontend
    #=========================================================
    _pat = re.compile(r"""
        ^
        \$(?P<alg>5)
        (\$rounds=(?P<rounds>\d+))?
        \$(?P<salt>[A-Za-z0-9./]+)
        (\$(?P<chk>[A-Za-z0-9./]+))?
        $
        """, re.X)

    #=========================================================
    #eof
    #=========================================================

class Sha512Crypt(_ShaCrypt):
    """This class implements the SHA-512 Crypt Algorithm,
    according to the specification at `http://people.redhat.com/drepper/SHA-crypt.txt`_.
    It should be byte-compatible with unix shadow hashes beginning with ``$6$``.

    This implementation is based on a pure-python translation
    of the original specification.

    .. note::
        This is *not* just the raw SHA-512 hash of the password,
        which is sometimes incorrectly referred to as sha512-crypt.
        This is a variable-round descendant of md5-crypt,
        and is comparable in strength to bcrypt.

    Usage Example::

        >>> from bps.security.pwhash import Sha512Crypt
        >>> crypt = Sha512Crypt()
        >>> #to encrypt a new secret with this algorithm
        >>> hash = crypt.encrypt("forget me not")
        >>> hash
        '$6$rounds=11949$KkBupsnnII6YXqgT$O8qAEcEgDyJlMC4UB3buST8vE1PsPPABA.0lQIUARTNnlLPZyBRVXAvqqynVByGRLTRMIorkcR0bsVQS5i3Xw1'
        >>> #to verify an existing secret
        >>> crypt.verify("forget me not", hash)
        True
        >>> crypt.verify("i forgot it", hash)
        False

    .. automethod:: encrypt
    """
    #=========================================================
    #algorithm info
    #=========================================================

    name='sha512-crypt'
    hash_bits = 512

    #=========================================================
    #internals
    #=========================================================
    _hash = hashlib.sha512
    _key = '6'
    _chunk_size = 64
    _hash_size = 86

    def _encode(self, result):
        out = ''
        a, b, c = [0, 21, 42]
        while c < 63:
            out += _enc64b3(result, a, b, c)
            a, b, c = b+1, c+1, a+1
        assert c == 63, "loop to far: %r" % (c,)
        out += _enc64b1(result, 63)
        return out

    #=========================================================
    #frontend
    #=========================================================

    _pat = re.compile(r"""
        ^
        \$(?P<alg>6)
        (\$rounds=(?P<rounds>\d+))?
        \$(?P<salt>[A-Za-z0-9./]+)
        (\$(?P<chk>[A-Za-z0-9./]+))?
        $
        """, re.X)

    #=========================================================
    #eof
    #=========================================================

#=========================================================
#OpenBSD's BCrypt
#=========================================================
class BCrypt(CryptAlgorithm):
    """Implementation of OpenBSD's BCrypt algorithm.

    BPS will use the py-bcrypt package if it is available,
    otherwise it will fall back to a slower pure-python implementation
    that is builtin.

    .. automethod:: encrypt
    """
    #=========================================================
    #algorithm info
    #=========================================================
    name = "bcrypt"
    salt_bits = 128
    hash_bits = 192
    secret_chars = 55
    has_rounds = True
    has_named_rounds = True

    #current recommended default rounds for blowfish
    # last updated 2009-7-6 on a 2ghz system
    fast_rounds = 11 # ~0.25s
    medium_rounds = 13 # ~0.82s
    slow_rounds = 14 # ~ 1.58s

    #=========================================================
    #frontend
    #=========================================================
    _pat = re.compile(r"""
        ^
        \$(?P<alg>2[a]?)
        \$(?P<rounds>\d+)
        \$(?P<salt>[A-Za-z0-9./]{22})
        (?P<chk>[A-Za-z0-9./]{31})?
        $
        """, re.X)

    def identify(self, hash):
        "identify bcrypt hash"
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    def parse(self, hash):
        "parse bcrypt hash"
        m = self._pat.match(hash)
        if not m:
            raise ValueError, "invalid bcrypt hash/salt"
        alg, rounds, salt, chk = m.group("alg", "rounds", "salt", "chk")
        return UnixHash(alg, salt, chk, rounds=int(rounds), source=hash)

    def encrypt(self, secret, hash=None, keep_salt=False, rounds=None):
        """encrypt using bcrypt.

        In addition to the normal options that :meth:`CryptAlgorithm.encrypt` takes,
        this function also accepts the following:

        :param rounds:
            Optionally specify the number of rounds to use
            (technically, bcrypt will actually use ``2**rounds``).
            This can be one of "fast", "medium", "slow",
            or an integer in the range 4..31.

            See :attr:`CryptAlgorithm.has_named_rounds` for details
            on the meaning of "fast", "medium" and "slow".
        """
        #validate salt
        if hash:
            rec = self.parse(hash)
            if rounds is None:
                rounds = rec.rounds
        #generate new salt
        if hash and keep_salt:
            salt = hash
        else:
            rounds = self._norm_rounds(rounds)
            salt = bcrypt.gensalt(rounds)
        #encrypt secret
        return bcrypt.hashpw(secret, salt)

    def _norm_rounds(self, rounds):
        if isinstance(rounds, int):
            return rounds
        elif rounds == "fast" or rounds is None:
            return self.fast_rounds
        elif rounds == "slow":
            return self.slow_rounds
        else:
            if rounds != "medium":
                log.warning("unknown rounds alias %r, using 'medium'", rounds)
            return self.medium_rounds

    def verify(self, secret, hash):
        "verify bcrypt hash"
        return bcrypt.hashpw(secret, hash) == hash

    #=========================================================
    #eoc
    #=========================================================

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

        >>> from bps.security import pwhash
        >>> #create a new context that only understands Md5Crypt & BCrypt
        >>> myctx = pwhash.CryptContext([ pwhash.Md5Crypt, pwhash.BCrypt ])

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
        <bps.security.pwhash.BCrypt object, name="bcrypt">

        >>> #you can get a list of algs...
        >>> myctx.keys()
        [ 'md5-crypt', 'bcrypt' ]

        >>> #and get the CryptAlgorithm object by name
        >>> bc = myctx['bcrypt']
        >>> bc
        <bps.security.pwhash.BCrypt object, name="bcrypt">
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

    def index(self, value, start=None, stop=None):
        """find location of algorithm by name or instance"""
        if isinstance(value, str):
            #hunt for element by alg name
            for idx, crypt in enum_slice(self, start, stop):
                if crypt.name == value:
                    return idx
            return -1
##        elif isinstance(value, type):
##            #hunt for element by alg class
##            for idx, crypt in enum_slice(self, start, stop):
##                if isinstance(crypt, value):
##                    return idx
##            return -1
        else:
            #else should be an alg instance
            for idx, crypt in enum_slice(self, start, stop):
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
#build up the standard context objects
#=========================================================

#default context for quick use.. recognizes all known algorithms,
#   currently uses SHA-512 as default
default_context = CryptContext([ UnixCrypt, Md5Crypt, BCrypt, Sha256Crypt, Sha512Crypt ])

def identify(hash, resolve=False):
    """Identify algorithm which generated a password hash.

    :arg hash:
        The hash string to identify.
    :param resolve:
        If ``True``, this function will return a :class:`CryptAlgorithm`
        instance which can handle the hash.
        If ``False`` (the default), then only the name of the hash algorithm
        will be returned.

    The following algorithms are currently recognized:

        =================== ================================================
        Name                Description
        ------------------- ------------------------------------------------
        ``"unix-crypt"``    the historic unix-crypt algorithm

        ``"md5-crypt"``     the md5-crypt algorithm, usually identified
                            by the prefix ``$1$`` in unix shadow files.

        ``"bcrypt"``        the openbsd blowfish-crypt algorithm,
                            usually identified by the prefixes ``$2$`` or ``$2a$``
                            in unix shadow files.

        ``"sha256-crypt"``  the 256-bit version of the sha-crypt algorithm,
                            usually identified by the prefix ``$5$``
                            in unix shadow files.

        ``"sha512-crypt"``  the 512-bit version of the sha-crypt algorithm,
                            usually identified by the prefix ``$6$``
                            in unix shadow files.
        =================== ================================================

    :returns:
        The name of the hash, or ``None`` if the hash could not be identified.
        (The return may be altered by the *resolve* keyword).

    .. note::
        This is a convience wrapper for ``pwhash.default_context.identify(hash)``.
    """
    return default_context.identify(hash, resolve=resolve)

def encrypt(secret, hash=None, alg=None, **kwds):
    """Encrypt secret using a password hash algorithm.

    :type secret: str
    :arg secret:
        String containing the secret to encrypt

    :type hash: str|None
    :arg hash:
        Optional previously existing hash string which
        will be used to provide default value for the salt, rounds,
        or other algorithm-specific options.
        If not specified, algorithm-chosen defaults will be used.

    :type alg: str|None
    :param alg:
        Optionally specify the name of the algorithm to use.
        If no algorithm is specified, an attempt is made
        to guess from the hash string. If no hash string
        is specified, sha512-crypt will be used.
        See :func:`identify` for a list of algorithm names.

    All other keywords are passed on to the specific password algorithm
    being used to encrypt the secret.

    :type keep_salt: bool
    :param keep_salt:
        This option is accepted by all of the builtin algorithms.

        By default, a new salt value generated each time
        a secret is encrypted. However, if this keyword
        is set to ``True``, and a previous hash string is provided,
        the salt from that string will be used instead.

        .. note::
            This is generally only useful when verifying an existing hash
            (see :func:`verify`). Other than that, this option should be
            avoided, as re-using a salt will needlessly decrease security.

    :type rounds: int
    :param rounds:
        For the sha256-crypt and sha512-crypt algorithms,
        this option lets you specify the number of rounds
        of encryption to use. For the bcrypt algorithm,
        this option lets you specify the log-base-2 of
        the number of rounds of encryption to use.

        For all three of these algorithms, you can either
        specify a positive integer, or one of the strings
        "fast", "medium", "slow" to choose a preset number
        of rounds corresponding to an appropriate level
        of encryption.

    :returns:
        The secret as encoded by the specified algorithm and options.
    """
    return default_context.encrypt(secret, hash=hash, alg=alg, **kwds)

def verify(secret, hash, alg=None):
    """verify a secret against an existing hash.

    This checks if a secret matches against the one stored
    inside the specified hash. By default this uses :func:`encrypt`
    to re-crypt the secret, and compares it to the provided hash;
    though some algorithms may implement this in a more efficient manner.

    :type secret: str
    :arg secret:
        A string containing the secret to check.

    :type hash: str
    :param hash:
        A string containing the hash to check against.

    :type alg: str|None
    :param alg:
        Optionally specify the name of the algorithm to use.
        If no algorithm is specified, an attempt is made
        to guess from the hash string. If it can't be
        identified, a ValueError will be raised.
        See :func:`identify` for a list of algorithm names.

    :returns:
        ``True`` if the secret matches, otherwise ``False``.
    """
    return default_context.verify(secret, hash, alg=alg)

#some general os-context helpers (these may not match your os policy exactly)
linux_context = CryptContext([ UnixCrypt, Md5Crypt, Sha256Crypt, Sha512Crypt ])
bsd_context = CryptContext([ UnixCrypt, Md5Crypt, BCrypt ])

#some sql db context helpers
mysql40_context = CryptContext([Mysql10Crypt])
mysql_context = CryptContext([Mysql10Crypt, Mysql41Crypt])
postgres_context = CryptContext([PostgresMd5Crypt])

#=========================================================
#deprecated function names
#=========================================================
from bps.warndep import relocated_function
identify_secret = relocated_function("identify_secret", identify)
encrypt_secret = relocated_function("encrypt_secret", encrypt)
verify_secret = relocated_function("verify_secret", verify)

#=========================================================
# eof
#=========================================================
