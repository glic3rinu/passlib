"""passlib - implementation of various password hashing functions"""
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
from passlib.context import CryptContext
from passlib.handler import CryptHandlerHelper, register_crypt_handler
#pkg
#local
__all__ = [
    'Mysql10Crypt',
    'Mysql41Crypt',

    'mysql10_context',
    'mysql_context',
]

#=========================================================
#sql database hashes
#=========================================================
class Mysql10Crypt(CryptHandlerHelper):
    """This implements Mysql's OLD_PASSWORD algorithm, used prior to version 4.1.

    See :class:`Mysql41Crypt` for the new algorithm was put in place in version 4.1

    This function is known to be very insecure,
    and should only be used to verify existing password hashes.

    """
    #=========================================================
    #crypt information
    #=========================================================
    name = "mysql-10"

    setting_kwds = ()

    checksum_bytes = 32

    #=========================================================
    #frontend
    #=========================================================
    _pat = re.compile(r"^[0-9a-f]{16}$", re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def encrypt(cls, secret):
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

    @classmethod
    def verify(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError, "not a mysql-10 hash"
        return hash.lower() == cls.encrypt(secret)

    #=========================================================
    #eoc
    #=========================================================
register_crypt_handler(Mysql10Crypt)

class Mysql41Crypt(CryptHandlerHelper):
    """This implements Mysql new PASSWORD algorithm, introduced in version 4.1.

    This function is unsalted, and therefore not very secure against rainbow attacks.
    It should only be used when dealing with mysql passwords,
    for all other purposes, you should use a salted hash function.

    Description taken from http://dev.mysql.com/doc/refman/6.0/en/password-hashing.html
    """
    #=========================================================
    #crypt information
    #=========================================================
    name = "mysql-41"
    setting_kwds = ()
    checksum_bytes = 80

    #=========================================================
    #frontend
    #=========================================================
    _pat = re.compile(r"^\*[0-9A-F]{40}$", re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def encrypt(cls, secret):
        return '*' + hashlib.sha1(hashlib.sha1(secret).digest()).hexdigest().upper()

    @classmethod
    def verify(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError, "not a mysql-41 hash"
        return hash.upper() == cls.encrypt(secret)

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(Mysql41Crypt)

#=========================================================
#some db context helpers
#=========================================================
mysql10_context = CryptContext([Mysql10Crypt])
mysql_context = CryptContext([Mysql10Crypt, Mysql41Crypt])

#=========================================================
# eof
#=========================================================
