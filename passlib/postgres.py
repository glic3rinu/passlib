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
from passlib.handler import CryptHandler, register_crypt_handler
#pkg
#local
__all__ = [
    'PostgresMd5Crypt',
]
#=========================================================
#sql database hashes
#=========================================================
class PostgresMd5Crypt(CryptHandler):
    """This implements the md5-based hash algorithm used by Postgres to store
    passwords in the pg_shadow table.

    This algorithm shouldn't be used for any purpose besides Postgres interaction,
    it's a weak unsalted algorithm which could easily be attacked with a rainbow table.

    .. warning::
        This algorithm is slightly different from most of the others,
        in that both encrypt() and verify() require you pass in
        the name of the user account via the required 'user' keyword,
        since postgres uses this in place of a salt :(

    Usage Example::

        >>> from passlib import hash
        >>> crypt = hash.PostgresMd5Crypt()
        >>> crypt.encrypt("mypass", user="postgres")
        'md55fba2ea04fd36069d2574ea71c8efe9d'
        >>> crypt.verify("mypass", 'md55fba2ea04fd36069d2574ea71c8efe9d', user="postgres")
        True
    """
    #=========================================================
    #crypt information
    #=========================================================
    name = "postgres-md5"

    setting_kwds = ()
    context_kwds = ("user",)

    checksum_bytes = 64

    #=========================================================
    #frontend
    #=========================================================
    _pat = re.compile(r"^md5[0-9a-f]{32}$")

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def encrypt(cls, secret, user):
        if not user:
            raise ValueError, "user keyword must be specified for this algorithm"
        return "md5" + hashlib.md5(secret + user).hexdigest().lower()

    @classmethod
    def verify(cls, secret, hash, user):
        if not cls.identify(hash):
            raise ValueError, "invalid postgres-md5 hash"
        return hash == cls.encrypt(secret, user)

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(PostgresMd5Crypt)

#=========================================================
#db contexts
#=========================================================
postgres_context = CryptContext([PostgresMd5Crypt])

#=========================================================
# eof
#=========================================================
