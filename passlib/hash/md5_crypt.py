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
from passlib.util import classproperty, abstractmethod, is_seq, srandom, \
    HashInfo, h64_gensalt, h64_encode_3_offsets, h64_encode_1_offset
from passlib.hash.base import CryptAlgorithm
#pkg
#local
__all__ = [
    'Md5Crypt',
]

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
    salt_bytes = 6
    hash_bytes = 12
    has_rounds = False

    #=========================================================
    #backend
    #=========================================================
    @classmethod
    def _md5_crypt_raw(self, secret, salt):
        #init salt
        if not salt:
            salt = h64_gensalt(8)
        assert len(salt) == 8

        #handle unicode
        #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")

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
            h64_encode_3_offsets(hash,
                idx+12 if idx < 4 else 5,
                idx+6,
                idx,
            )
            for idx in xrange(5)
            ) + h64_encode_1_offset(hash, 11)
        return HashInfo('1', salt, out)

    _pat = re.compile(r"""
        ^
        \$(?P<alg>1)
        \$(?P<salt>[A-Za-z0-9./]+)
        (\$(?P<chk>[A-Za-z0-9./]+))?
        $
        """, re.X)

    @classmethod
    def identify(self, hash):
        "identify md5-crypt hash"
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    @classmethod
    def _parse(self, hash):
        "parse an md5-crypt hash"
        m = self._pat.match(hash)
        if not m:
            raise ValueError, "invalid md5 salt"
        return HashInfo(m.group("alg"), m.group("salt"), m.group("chk"))

    @classmethod
    def encrypt(self, secret, salt=None, keep_salt=False):
        "encrypt an md5-crypt hash"
        real_salt = None
        if salt:
            rec = self._parse(salt)
            if keep_salt:
                real_salt = rec.salt
        rec = self._md5_crypt_raw(secret, real_salt)
        return "$1$%s$%s" % (rec.salt, rec.checksum)

    @classmethod
    def verify(self, secret, hash):
        "verify an md5-crypt hash"
        if hash is None:
            return False
        rec = self._parse(hash)
        other = self._md5_crypt_raw(secret, rec.salt)
        return other.checksum == rec.checksum

#=========================================================
# eof
#=========================================================
