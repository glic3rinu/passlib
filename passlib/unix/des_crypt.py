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
    #TODO: need to reconcile our implementation's behavior
    # with the stdlib's behavior so error types, messages, and limitations
    # are the same. (eg: handling of None and unicode chars)
    from passlib.utils._slow_des_crypt import crypt
    backend = "builtin"

##from passlib.utils._slow_des_crypt import raw_ext_crypt

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

    setting_kwds = ()

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
#
#=========================================================
#TODO: find a source for this algorithm, and convert it to python.
# also need to find some test sources.

##class ExtDesCrypt(CryptHandlerHelper):
##    """extended des crypt (3des based)
##
##    this algorithm was used on some systems
##    during the time between the original crypt()
##    and the development of md5-crypt and the modular crypt format.
##
##    thus, it doesn't follow the normal format.
##    """
##
##    #=========================================================
##    #crypt information
##    #=========================================================
##    name = "ext-des-crypt"
##
##    setting_kwds = ()
##
##    salt_bytes = 6*8/8.0
##    checksum_bytes = 6*11/8.0
##    secret_chars = -1 # ???
##
##    salt_chars = 8
##
##    #=========================================================
##    #frontend
##    #=========================================================
##
##    #FORMAT: 2 chars of H64-encoded salt + 11 chars of H64-encoded checksum
##    _pat = re.compile(r"""
##        ^
##        _
##        (?P<salt>[./a-z0-9]{8})
##        (?P<chk>[./a-z0-9]{11})
##        $""", re.X|re.I)
##
##    @classmethod
##    def identify(cls, hash):
##        return bool(hash and cls._pat.match(hash))
##
##    @classmethod
##    def parse(cls, hash):
##        m = cls._pat.match(hash)
##        if not m:
##            raise ValueError, "not a ext-des-crypt hash"
##        return dict(
##            salt=m.group("salt"),
##            checksum=m.group("chk")
##        )
##
##    @classmethod
##    def encrypt(cls, secret, salt=None):
##        salt = cls._norm_salt(salt)
##        return ext_crypt(secret, salt)
##
##    @classmethod
##    def verify(cls, secret, hash):
##        info = cls.parse(hash)
##        return info['checksum'] == raw_ext_crypt(secret, info['salt'])

#=========================================================
# eof
#=========================================================
