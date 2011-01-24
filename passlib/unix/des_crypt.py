"""passlib - implementation of various password hashing functions

http://www.phpbuilder.com/manual/function.crypt.php

http://dropsafe.crypticide.com/article/1389
"""
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
#pkg
from passlib.utils import H64_CHARS
from passlib.handler import ExtCryptHandler, register_crypt_handler
#local
__all__ = [
    'DesCrypt',
    'ExtDesCrypt',
]

#=========================================================
#load unix crypt backend
#=========================================================
try:
    #try stdlib module, which is only present under posix
    from crypt import crypt as _crypt

    #NOTE: we're wrapping the builtin crypt with some checks due to deficiencies in it's base implementation.
    #   1. given an empty salt, it returns '' instead of raising an error. the wrapper raises an error.
    #   2. given a single letter salt, it returns a hash with the original salt doubled,
    #       but appears to calculate the hash based on the letter + "G" as the second byte.
    #       this results in a hash that won't validate, which is DEFINITELY wrong.
    #       the wrapper raises an error.
    #   3. given salt chars outside of H64_CHARS range, it does something unknown internally,
    #       but reports the hashes correctly. until this alg gets fixed in builtin crypt or stdlib crypt,
    #       wrapper raises an error for bad salts.
    #   4. it tries to encode unicode -> ascii, unlike most hashes. the wrapper encodes to utf-8.
    def crypt(key, salt):
        "wrapper around stdlib's crypt"
        if '\x00' in key:
            raise ValueError, "null char in key"
        if isinstance(key, unicode):
            key = key.encode("utf-8")
        if not salt:
            raise ValueError, "no salt specified"
        if len(salt) < 2:
            raise ValueError, "salt must have 2 chars"
        elif len(salt) > 2:
            salt = salt[:2]
        for c in salt:
            if c not in H64_CHARS:
                raise ValueError, "invalid char in salt"
        return _crypt(key, salt)

    backend = "stdlib"
except ImportError:
    #XXX: could check for openssl passwd -des support in libssl


    #TODO: need to reconcile our implementation's behavior
    # with the stdlib's behavior so error types, messages, and limitations
    # are the same. (eg: handling of None and unicode chars)
    from passlib.utils._slow_des_crypt import crypt
    backend = "builtin"

from passlib.utils._slow_des_crypt import raw_ext_crypt, b64_decode_int24, b64_encode_int24

#=========================================================
#old unix crypt
#=========================================================
class DesCrypt(ExtCryptHandler):
    """Old Unix-Crypt Algorithm, as originally used on unix before md5-crypt arrived.
    This implementation uses the builtin ``crypt`` module when available,
    but contains a pure-python fallback so that this algorithm can always be used.
    """
    #=========================================================
    #crypt information
    #=========================================================
    name = "des-crypt"
    aliases = ("unix-crypt",)

    setting_kwds = ("salt")

    salt_bytes = 6*2/8.0
    checksum_bytes = 6*11/8.0
    secret_chars = 8

    salt_chars = 2

    #=========================================================
    #frontend
    #=========================================================

    #FORMAT: 2 chars of H64-encoded salt + 11 chars of H64-encoded checksum
    _pat = re.compile(r"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>[./a-z0-9]{11})
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def parse(cls, hash):
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "not a des-crypt hash"
        return dict(
            salt=m.group("salt"),
            checksum=m.group("chk")
        )

    @classmethod
    def render(cls, salt, checksum=None):
        if len(salt) < 2:
            raise ValueError, "invalid salt"
        return "%s%s" % (salt[:2], checksum or '')

    @classmethod
    def encrypt(cls, secret, salt=None):
        salt = cls._norm_salt(salt)
        return crypt(secret, salt)

    @classmethod
    def verify(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError, "not a des-crypt hash"
        return hash == crypt(secret, hash)

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(DesCrypt)

#=========================================================
#extended des crypt
#=========================================================
#refs -
# http://fuse4bsd.creo.hu/localcgi/man-cgi.cgi?crypt+3
# http://search.cpan.org/dist/Authen-Passphrase/lib/Authen/Passphrase/DESCrypt.pm

class ExtDesCrypt(ExtCryptHandler):
    """Extended BSDi DES Crypt

    this algorithm was used on some systems
    during the time between the original crypt()
    and the development of md5-crypt and the modular crypt format.

    thus, it doesn't follow the normal format,
    but it does enhance the crypt algorithm to include
    all chars, and adds a rounds parameter.
    """

    #=========================================================
    #crypt information
    #=========================================================
    name = "ext-des-crypt"

    setting_kwds = ("salt", "rounds")

    salt_bytes = 6*4/8.0
    checksum_bytes = 6*11/8.0
    secret_chars = -1

    salt_chars = 4

    #NOTE: this has variable rounds, but it's so old we just max them out by default
    #if this is ever used, since it's so weak to begin with
    default_rounds = 1000
    default_rounds_range = 64
    min_rounds = 25
    max_rounds = 4095

    #=========================================================
    #frontend
    #=========================================================

    #FORMAT: 2 chars of H64-encoded salt + 11 chars of H64-encoded checksum
    _pat = re.compile(r"""
        ^
        _
        (?P<rounds>[./a-z0-9]{4})
        (?P<salt>[./a-z0-9]{4})
        (?P<chk>[./a-z0-9]{11})
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def parse(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "not a ext-des-crypt hash"
        return dict(
            rounds=b64_decode_int24(m.group("rounds")),
            salt=m.group("salt"),
            checksum=m.group("chk")
        )

    @classmethod
    def render(cls, checksum, salt, rounds):
        if len(salt) != 4:
            raise ValueError, "invalid salt"
        if len(checksum) != 11:
            raise ValueError, "invalid checksum"
        return "_%s%s%s" % (b64_encode_int24(rounds), salt, checksum)

    @classmethod
    def encrypt(cls, secret, salt=None, rounds=None):
        salt = cls._norm_salt(salt)
        rounds = cls._norm_rounds(rounds)
        chk = raw_ext_crypt(secret, salt, rounds)
        return cls.render(chk, salt, rounds)

    @classmethod
    def verify(cls, secret, hash):
        info = cls.parse(hash)
        return info['checksum'] == raw_ext_crypt(secret, info['salt'], info['rounds'])

register_crypt_handler(ExtDesCrypt)
#=========================================================
# eof
#=========================================================
