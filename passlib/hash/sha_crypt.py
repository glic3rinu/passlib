"""passlib.hash.sha_crypt - implements SHA-256-Crypt & SHA-512-Crypt

Implementation written based on specification at `<http://www.akkadia.org/drepper/SHA-crypt.txt>`_.
It should be byte-compatible with unix shadow hashes beginning with ``$5$`` and ``$6%``.
More details about specification at `<http://www.akkadia.org/drepper/sha-crypt.html>`_.

XXX: spec says salt can be variable (8-16 chars), but implementation currently always generates 16 chars.
    should at least make sure it can accept <16 chars properly

NOTE: the spec says nothing about unicode, so we handle it by converting to utf-8
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.hash.base import CryptAlgorithm, register_crypt_algorithm
from passlib.util import classproperty, abstractmethod, is_seq, srandom, \
    HashInfo, h64_gensalt, h64_encode_3_offsets, h64_encode_2_offsets
#pkg
#local
__all__ = [
    'Sha256Crypt',
    'Sha512Crypt',
]

#=========================================================
#ids 5,6 -- sha
#algorithm defined on this page:
#   http://people.redhat.com/drepper/SHA-crypt.txt
#=========================================================
class _ShaCrypt(CryptAlgorithm):
    "common code for used by Sha(256|512)Crypt Classes"
    #=========================================================
    #algorithm info
    #=========================================================
    #hash_bytes & name filled in for subclass
    salt_bytes = 12
    has_rounds = True

    #tuning the round aliases
    default_rounds = "medium"
    _rounds_per_second = 156000 #last tuned 2009-7-6 on a 2gz system
    round_presets = dict(
        fast = int(_rounds_per_second * .25),
        medium = int(_rounds_per_second * .75),
        slow = int(_rounds_per_second * 1.5),
    )

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
    @classmethod
    def _sha_crypt_raw(self, rounds, salt, secret):
        "perform sha crypt, returning just the checksum"
        #setup alg-specific parameters
        hash = self._hash
        chunk_size = self._chunk_size

        #init salt
        if salt is None:
            salt = h64_gensalt(16)
        elif len(salt) > 16:
            salt = salt[:16] #spec says to use up to first chars 16 only

        #handle unicode
        #FIXME: can't find definitive policy on how sha-crypt handles non-ascii.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")

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
        return HashInfo(self._key, salt, out, rounds=rounds)

    @classmethod
    def _sha_crypt(self, rounds, salt, secret):
        rec = self._sha_crypt_raw(rounds, salt, secret)
        if rec.rounds == -1:
            return "$%s$%s$%s" % (rec.ident, rec.salt, rec.checksum)
        else:
            return "$%s$rounds=%d$%s$%s" % (rec.ident, rec.rounds, rec.salt, rec.checksum)

    #=========================================================
    #frontend helpers
    #=========================================================
    @classmethod
    def identify(self, hash):
        "identify bcrypt hash"
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    @classmethod
    def _parse(self, hash):
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
        return HashInfo(alg, salt, chk, rounds=rounds, source=hash)

    @classmethod
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
            rec = self._parse(hash)
            if keep_salt:
                salt = rec.salt
            if rounds is None:
                rounds = rec.rounds
        rounds = self._resolve_preset_rounds(rounds)
        return self._sha_crypt(rounds, salt, secret)

    @classmethod
    def verify(self, secret, hash):
        if hash is None:
            return False
        rec = self._parse(hash)
        other = self._sha_crypt_raw(rec.rounds, rec.salt, secret)
        return other.checksum == rec.checksum

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
    name='sha-256-crypt'
    hash_bytes = 32

    #=========================================================
    #internals
    #=========================================================
    _hash = hashlib.sha256
    _key = '5'
    _chunk_size = 32
    _hash_size = 43

    @classmethod
    def _encode(self, result):
        out = ''
        a, b, c = 0, 10, 20
        while a < 30:
            out += h64_encode_3_offsets(result, c, b, a)
            a, b, c = c+1, a+1, b+1
        assert a == 30, "loop went to far: %r" % (a,)
        out += h64_encode_2_offsets(result, 30, 31)
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

register_crypt_algorithm(Sha256Crypt)

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

        >>> from passlib.hash import Sha512Crypt
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
    name='sha-512-crypt'
    hash_bytes = 64

    #=========================================================
    #internals
    #=========================================================
    _hash = hashlib.sha512
    _key = '6'
    _chunk_size = 64
    _hash_size = 86

    @classmethod
    def _encode(self, result):
        out = ''
        a, b, c = 0, 21, 42
        while c < 63:
            out += h64_encode_3_offsets(result, c, b, a)
            a, b, c = b+1, c+1, a+1
        assert c == 63, "loop to far: %r" % (c,)
        out += h64_encode_1_offset(result, 63)
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

register_crypt_algorithm(Sha512Crypt)

#=========================================================
# eof
#=========================================================
