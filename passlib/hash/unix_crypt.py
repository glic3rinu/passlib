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
try:
    #try stdlib module, which is only present under posix
    from crypt import crypt as _crypt

    #NOTE: we're wrapping the builtin crypt with some checks due to deficiencies in it's base implementation.
    #   1. given an empty salt, it returns '' instead of raising an error. the wrapper raises an error.
    #   2. given a single letter salt, it returns a hash with the original salt doubled,
    #       but appears to calculate the hash based on the letter + "G" as the second byte.
    #       this results in a hash that won't validate, which is DEFINITELY wrong.
    #       the wrapper raises an error.
    #   3. given salt chars outside of H64.CHARS range, it does something unknown internally,
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
        elif salt[0] not in H64.CHARS or salt[1] not in H64.CHARS:
            raise ValueError, "invalid salt"
        return _crypt(key, salt)

    backend = "stdlib"
except ImportError:
    #TODO: need to reconcile our implementation's behavior
    # with the stdlib's behavior so error types, messages, and limitations
    # are the same. (eg: handling of None and unicode chars)
    from passlib._unix_crypt import crypt
    backend = "builtin"
#site
#pkg
from passlib.hash.base import CryptAlgorithm, HashInfo
from passlib.util import classproperty, abstractmethod, is_seq, srandom, H64
#local
__all__ = [
    'UnixCrypt',
    'crypt',
]

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

    #FORMAT: 2 chars of H64-encoded salt + 11 chars of H64-encoded checksum
    _pat = re.compile(r"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<hash>[./a-z0-9]{11})
        $""", re.X|re.I)

    @classmethod
    def identify(self, hash):
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    @classmethod
    def encrypt(self, secret, hash=None, keep_salt=False):
        if hash and keep_salt:
            salt = hash[:2]
        else:
            salt = H64.randstr(2)
        return crypt(secret, salt)

    #default verify used

#=========================================================
# eof
#=========================================================
