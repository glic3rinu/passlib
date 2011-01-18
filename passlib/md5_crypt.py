"""passlib - implementation of various password hashing functions

http://unix.derkeiler.com/Newsgroups/comp.unix.solaris/2004-04/0199.html
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import inspect
import re
from hashlib import md5
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.util import classproperty, abstractmethod, is_seq, srandom, \
    HashInfo, h64_gensalt, h64_encode_3_offsets, h64_encode_1_offset, generate_h64_salt, validate_h64_salt
from passlib.base import CryptAlgorithmHelper, register_crypt_handler
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

class Md5Crypt(CryptAlgorithmHelper):
    """This provides the MD5-crypt algorithm, used in many 1990's era unix systems.
    It should be byte compatible with unix shadow hashes beginning with ``$1$``.
    """
    #=========================================================
    #crypt info
    #=========================================================
    name = 'md5-crypt'
    
    setting_kwds = ("salt",)

    secret_chars = -1
    salt_bytes = 6
    checksum_bytes = 12

    #=========================================================
    #backend
    #=========================================================
    @classmethod
    def _raw_encrypt(cls, secret, salt):
        "given secret & salt, return encoded md5-crypt checksum"
        assert len(salt) == 8, "invalid salt length: %r" % (salt,)

        #handle unicode
        #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")

        h = md5(secret)
        t = h.copy()
        t.update(salt)
        t.update(secret)
        hash = t.digest()

        h.update("$1$")
        h.update(salt)

        idx = len(secret)
        while idx > 0:
            h.update(hash[0:min(16, idx)])
            idx -= 16

        idx = len(secret)
        while idx > 0:
            if idx & 1:
                h.update('\x00')
            else:
                h.update(secret[0])
            idx >>= 1
        hash = h.digest()

        hs = md5(secret)
        for idx in xrange(1000):
            if idx & 1:
                h = hs.copy()
            else:
                h = md5(hash)
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
        return out

    _pat = re.compile(r"""
        ^
        \$(?P<ident>1)
        \$(?P<salt>[A-Za-z0-9./]+)
        (\$(?P<chk>[A-Za-z0-9./]+))?
        $
        """, re.X)

    #=========================================================
    #frontend
    #=========================================================
    @classmethod
    def identify(cls, hash):
        "identify md5-crypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def parse(cls, hash):
        "parse an md5-crypt hash"
        if not hash:
            raise ValueError, "invalid md5-crypt hash"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid md5-crypt hash"
        salt, chk = m.group("salt", "chk")
        return dict(
            salt=salt,
            checksum=chk,
        )

    @classmethod
    def encrypt(cls, secret, salt=None):
        "encrypt an md5-crypt hash"
        if salt:
            validate_h64_salt(salt, 8)
        else:
            salt = generate_h64_salt(8)
        checksum = cls._raw_encrypt(secret, salt)
        return "$1$%s$%s" % (salt, checksum)

    @classmethod
    def verify(cls, secret, hash):
        "verify an md5-crypt hash"
        info = cls.parse(hash)
        checksum = cls._raw_encrypt(secret, info['salt'])
        return checksum == info['checksum']

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(Md5Crypt)

#=========================================================
# eof
#=========================================================
