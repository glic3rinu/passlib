"""passlib.sha_crypt - implements SHA-256-Crypt & SHA-512-Crypt

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
from passlib.handler import ExtCryptHandler, register_crypt_handler
from passlib.utils import abstract_class_method, \
    h64_encode_3_offsets, h64_encode_2_offsets, h64_encode_1_offset
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
class _ShaCrypt(ExtCryptHandler):
    "common code for used by Sha(256|512)Crypt Classes"
    #=========================================================
    #crypt info
    #=========================================================

    #name - provided by subclass
    setting_kwds = ("salt", "rounds")

    secret_chars = -1
    salt_bytes = 12
    #checksum_bytes - provided by subclass

    #NOTE: spec seems to allow shorter salts. not sure *how* short
    min_salt_chars = 1
    salt_chars = 16

    default_rounds = 40000
    min_rounds = 1000
    max_rounds = 999999999

    #=========================================================
    #backend
    #=========================================================

    #------------------------------------------------
    #provided by subclass
    #------------------------------------------------
    _hash = None #callable to use for hashing
    _chunk_size = None #bytes at a time to input secret
    _hash_size = None #bytes in hash
    _pat = None #regexp for sha variant
    _ident = None #identifier for specific subclass

    @abstract_class_method
    def _encode(cls, result):
        "encode raw result into h64 style"

    #------------------------------------------------
    #common code
    #------------------------------------------------
    @classmethod
    def _raw_encrypt(cls, secret, salt, rounds):
        "perform sha crypt, returning just the checksum"
        #setup alg-specific parameters
        hash = cls._hash
        chunk_size = cls._chunk_size

        #handle unicode
        #FIXME: can't find definitive policy on how sha-crypt handles non-ascii.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")

        #init rounds
        if rounds < 1000:
            rounds = 1000
        if rounds > 999999999:
            rounds = 999999999

        if len(salt) > 16:
            salt = salt[:16]

        def extend(source, size_ref):
            size = len(size_ref)
            return source * int(size/chunk_size) + source[:size % chunk_size]

        #calc digest B
        b = hash(secret)
        a = b.copy()
        b.update(salt)
        b.update(secret)
        b_result = b.digest()
        b_extend = extend(b_result, secret)

        #begin digest A
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
        dp = hash(secret * len(secret))
        dp_result = extend(dp.digest(), secret)

        #calc DS
        ds = hash()
        for i in xrange(0, 16+ord(a_result[0])):
            ds.update(salt)
        ds_result = extend(ds.digest(), salt) #aka 'S'

        #calc digest C
        last_result = a_result
        for i in xrange(0, rounds):
            if i % 2:
                c = hash(dp_result)
            else:
                c = hash(last_result)
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
        return cls._encode(last_result), salt, rounds

    @classmethod
    def parse_config(cls, config):
        "parse partial hash containing just salt+rounds, with salt potentially too large"
        if not config:
            raise ValueError, "invalid sha hash/salt"
        m = re.search(r"""
            ^
            \$(?P<ident>""" + cls._ident + r""")
            (\$rounds=(?P<rounds>\d+))?
            \$(?P<salt>[A-Za-z0-9./]+)
            $
            """, config, re.X)
        if not m:
            raise ValueError, "invalid sha hash/salt"
        ident, rounds, salt = m.group("ident", "rounds", "salt")
        return dict(
            implicit_rounds = not rounds,
            ident = ident,
            rounds = int(rounds) if rounds else 5000,
            salt = salt,
        )

    #=========================================================
    #frontend helpers
    #=========================================================
    @classmethod
    def identify(cls, hash):
        "identify bcrypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def parse(cls, hash):
        "parse bcrypt hash"
        if not hash:
            raise ValueError, "invalid sha hash/salt"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sha hash/salt"
        rounds, salt, chk = m.group("rounds", "salt", "chk")
        assert m.group("ident") == cls._ident
        return dict(
            implicit_rounds = not rounds,
            rounds = int(rounds) if rounds else 5000,
            salt=salt,
            checksum=chk,
        )

    @classmethod
    def render(cls, rounds, salt, checksum=None, implicit_rounds=False):
        if rounds == 5000 and implicit_rounds:
            out = "$%s$%s" % (cls._ident, salt)
        else:
            out = "$%s$rounds=%d$%s" % (cls._ident, rounds, salt)
        if checksum is not None:
            out += "$" + checksum
        return out

    @classmethod
    def encrypt(cls, secret, salt=None, rounds=None, implicit_rounds=False):
        """encrypt using sha256/512-crypt.

        In addition to the normal options that :meth:`CryptHandler.encrypt` takes,
        this function also accepts the following:

        :param rounds:
            Optionally specify the number of rounds to use.
            This can be one of "fast", "medium", "slow",
            or an integer in the range 1000...999999999.

            See :attr:`CryptHandler.has_named_rounds` for details
            on the meaning of "fast", "medium" and "slow".
        """
        salt = cls._norm_salt(salt)
        rounds = cls._norm_rounds(rounds)
        checksum, salt, rounds = cls._raw_encrypt(secret, salt, rounds)
        return cls.render(rounds, salt, checksum, implicit_rounds)

    @classmethod
    def verify(cls, secret, hash):
        info = cls.parse(hash)
        checksum, _, _ = cls._raw_encrypt(secret, info['salt'], info['rounds'])
        return checksum == info['checksum']

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
    checksum_bytes = 32

    #=========================================================
    #backend
    #=========================================================
    _ident = '5'
    _hash = hashlib.sha256
    _chunk_size = 32

    _pat = re.compile(r"""
        ^
        \$(?P<ident>5)
        (\$rounds=(?P<rounds>\d+))?
        \$(?P<salt>[A-Za-z0-9./]{1,16})
        \$(?P<chk>[A-Za-z0-9./]{43})
        $
        """, re.X)

    @classmethod
    def _encode(self, result):
        out = ''
        a, b, c = 0, 10, 20
        while a < 30:
            out += h64_encode_3_offsets(result, c, b, a)
            a, b, c = c+1, a+1, b+1
        assert a == 30, "loop went to far: %r" % (a,)
        out += h64_encode_2_offsets(result, 30, 31)
        assert len(out) == 43, "wrong length: %r" % (out,)
        return out

    #=========================================================
    #eof
    #=========================================================

register_crypt_handler(Sha256Crypt)

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

        >>> from passlib import Sha512Crypt
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
    #crypt info
    #=========================================================
    name='sha512-crypt'
    checksum_bytes = 64

    #=========================================================
    #backend
    #=========================================================
    _ident = '6'
    _hash = hashlib.sha512
    _chunk_size = 64

    _pat = re.compile(r"""
        ^
        \$(?P<ident>6)
        (\$rounds=(?P<rounds>\d+))?
        \$(?P<salt>[A-Za-z0-9./]{1,16})
        \$(?P<chk>[A-Za-z0-9./]{86})
        $
        """, re.X)

    @classmethod
    def _encode(self, result):
        out = ''
        a, b, c = 0, 21, 42
        while c < 63:
            out += h64_encode_3_offsets(result, c, b, a)
            a, b, c = b+1, c+1, a+1
        assert c == 63, "loop to far: %r" % (c,)
        out += h64_encode_1_offset(result, 63)
        assert len(out) == 86, "wrong length: %r" % (out,)
        return out

    #=========================================================
    #eof
    #=========================================================

register_crypt_handler(Sha512Crypt)

#=========================================================
# eof
#=========================================================
