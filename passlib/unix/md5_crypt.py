"""passlib - implementation of various password hashing functions
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
from passlib.utils import h64_encode_3_offsets, h64_encode_1_offset
from passlib.handler import ExtCryptHandler, register_crypt_handler
#pkg
#local
__all__ = [
    'Md5Crypt',
]

#=========================================================
#default backend
#=========================================================
def raw_md5_crypt(secret, salt, apr=False):
    "perform raw md5 encryption"
    #NOTE: regarding 'apr' format: really, apache? you had to invent a whole new "$apr1$" format,
    # when all you did was change the ident incorporated into the hash?
    # would love to find webpage explaining why just using a portable
    # implementation of $1$ wasn't sufficient.

    #validate secret
    #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #validate salt
    if len(salt) > 8:
        salt = salt[:8]

    #primary hash = secret+id+salt+...
    h = md5(secret)
    h.update("$apr1$" if apr else "$1$")
    h.update(salt)

    # primary hash - add len(secret) chars of tmp hash,
    # where temp hash is md5(secret+salt+secret)
    tmp = md5(secret + salt + secret).digest()
    assert len(tmp) == 16
    slen = len(secret)
    h.update(tmp * (slen//16) + tmp[:slen % 16])

    # primary hash - add null chars & first char of secret !?!
    #
    # this may have historically been a bug,
    # where they meant to use tmp[0] instead of '\x00',
    # but the code memclear'ed the buffer,
    # and now all implementations have to use this.
    #
    # sha-crypt replaced this step with
    # something more useful, anyways
    idx = len(secret)
    evenchar = secret[0]
    while idx > 0:
        h.update('\x00' if idx & 1 else evenchar)
        idx >>= 1
    result = h.digest()

    # do 1000 rounds of md5 to make things harder.
    # each round formed from...
    #   idx % 2 => secret else result
    #   idx % 3 => salt
    #   idx % 7 => secret
    #   idx % 2 => result else secret
    # first we pre-compute some strings and hashes to speed up calculation
    secret_secret = secret*2
    salt_secret = salt+secret
    salt_secret_secret = salt + secret*2
    secret_hash = md5(secret).copy
    secret_secret_hash = md5(secret*2).copy
    secret_salt_hash = md5(secret+salt).copy
    secret_salt_secret_hash = md5(secret+salt+secret).copy
    for idx in xrange(1000):
        if idx & 1:
            if idx % 3:
                if idx % 7:
                    h = secret_salt_secret_hash()
                else:
                    h = secret_salt_hash()
            elif idx % 7:
                h = secret_secret_hash()
            else:
                h = secret_hash()
            h.update(result)
        else:
            h = md5(result)
            if idx % 3:
                if idx % 7:
                    h.update(salt_secret_secret)
                else:
                    h.update(salt_secret)
            elif idx % 7:
                h.update(secret_secret)
            else:
                h.update(secret)
        result = h.digest()

    #encode resulting hash
    out = ''.join(
        h64_encode_3_offsets(result,
            idx+12 if idx < 4 else 5,
            idx+6,
            idx,
        )
        for idx in xrange(5)
        ) + h64_encode_1_offset(result, 11)

    return out

#=========================================================
#choose backend for md5-crypt
#=========================================================

#fallback to default backend (defined above)
backend = "builtin"

#check if stdlib crypt is available, and if so, if OS supports $1$
#XXX: is this test expensive enough it should be delayed
#until md5-crypt is requested?

try:
    from crypt import crypt
except ImportError:
    crypt = None
else:
    if crypt("test", "$1$test") == '$1$test$pi/xDtU5WFVRqYS6BMU8X/':
        backend = "stdlib"
    else:
        crypt = None

#TODO: could check for libssl support (openssl passwd -1)

#=========================================================
#id 1 -- md5
#=========================================================
class Md5Crypt(ExtCryptHandler):
    """This provides the MD5-crypt algorithm, used in many 1990's era unix systems.
    It should be byte compatible with unix shadow hashes beginning with ``$1$``.
    """
    #=========================================================
    #crypt info
    #=========================================================
    name = 'md5-crypt'
    #stats: 96 bit checksum, 48 bit salt

    setting_kwds = ("salt",)

    salt_chars = 8
    min_salt_chars = 0

    #=========================================================
    #helpers
    #=========================================================
    _ident = "1"

    _pat = re.compile(r"""
        ^
        \$1
        \$(?P<salt>[A-Za-z0-9./]{,8})
        \$(?P<chk>[A-Za-z0-9./]{22})
        $
        """, re.X)

    @classmethod
    def parse(cls, hash):
        "parse an md5-crypt hash or config string"
        if not hash:
            raise ValueError, "no %s hash specified" % (cls.name,)
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid %s hash" % (cls.name,)
        salt, chk = m.group("salt", "chk")
        return dict(
            salt=salt,
            checksum=chk,
        )

    @classmethod
    def render(cls, salt, checksum=None):
        "render md5-crypt hash or config string"
        return "$%s$%s$%s" % (cls._ident, salt, checksum or '')

    #=========================================================
    #1.4 frontend
    #=========================================================
    @classmethod
    def identify(cls, hash):
        "identify md5-crypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def genconfig(cls, salt=None):
        salt = cls._norm_salt(salt)
        return cls.render(salt)

    @classmethod
    def genhash(cls, secret, config):
        if crypt:
            #use OS's crypt(), should be faster than builtin backend
            config = cls._norm_config(config)
            if isinstance(secret, unicode):
                secret = secret.encode("utf-8")
            return crypt(secret, config)
        else:
            #fallback to builtin backend
            info = cls._parse_norm_config(config)
            checksum = raw_md5_crypt(secret, info['salt'])
            return cls.render(checksum=checksum, **info)

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(Md5Crypt)

#=========================================================
#apache variant of md5 crypt
#=========================================================
class AprMd5Crypt(Md5Crypt):
    "Apache variant of md5-crypt, used in htpasswd files"

    name = "apr-md5-crypt"

    _ident = "apr1"

    _pat = re.compile(r"""
        ^
        \$apr1
        \$(?P<salt>[A-Za-z0-9./]{,8})
        \$(?P<chk>[A-Za-z0-9./]{22})
        $
        """, re.X)

    @classmethod
    def genhash(cls, secret, config):
        #TODO: could check for libssl support (openssl passwd -apr)
        info = cls._parse_norm_config(config)
        checksum = raw_md5_crypt(secret, info['salt'], apr=True)
        return cls.render(checksum=checksum, **info)

register_crypt_handler(AprMd5Crypt)

#=========================================================
# eof
#=========================================================
