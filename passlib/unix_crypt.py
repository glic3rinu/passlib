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
from passlib.base import CryptAlgorithmHelper, register_crypt_handler
from passlib.util import classproperty, abstractmethod, is_seq, srandom, validate_h64_salt, generate_h64_salt
#local
__all__ = [
    'UnixCrypt',
##    'crypt', 'backend'
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
        if not salt or len(salt) < 2:
            raise ValueError, "invalid salt"
        elif not h64_validate(salt):
            raise ValueError, "invalid salt"
        return _crypt(key, salt)

    backend = "stdlib"
except ImportError:
    #TODO: need to reconcile our implementation's behavior
    # with the stdlib's behavior so error types, messages, and limitations
    # are the same. (eg: handling of None and unicode chars)
    from passlib._slow_unix_crypt import crypt
    backend = "builtin"

#=========================================================
#old unix crypt
#=========================================================
class UnixCrypt(CryptAlgorithmHelper):
    """Old Unix-Crypt Algorithm, as originally used on unix before md5-crypt arrived.
    This implementation uses the builtin ``crypt`` module when available,
    but contains a pure-python fallback so that this algorithm can always be used.
    """
    #=========================================================
    #crypt information
    #=========================================================
    name = "unix-crypt"

    setting_kwds = ()

    salt_bytes = 6*2/8.0
    checksum_bytes = 6*11/8.0
    secret_chars = 8

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
            raise ValueError, "not a unix-crypt hash"
        return dict(
            salt=m.group("salt"),
            checksum=m.group("chk")
        )

    @classmethod
    def encrypt(cls, secret, salt=None):
        if salt:
            validate_h64_salt(salt, 2)
        else:
            salt = generate_h64_salt(2)
        return crypt(secret, salt)

    @classmethod
    def verify(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError, "not a unix-crypt hash"
        return hash == crypt(secret, hash)

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(UnixCrypt)

#=========================================================
# eof
#=========================================================
