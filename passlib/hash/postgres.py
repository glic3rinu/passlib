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
from passlib.util import classproperty, abstractmethod, is_seq, srandom
from passlib.hash.base import CryptAlgorithm, CryptContext
#pkg
#local
__all__ = [
    'PostgresMd5Crypt',
]
#=========================================================
#sql database hashes
#=========================================================
class PostgresMd5Crypt(CryptAlgorithm):
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
    name = "postgres-md5-crypt"
    hash_bytes = 64
    context_kwds = ("user",)

    _pat = re.compile(r"^md5[0-9a-f]{32}$")

    @classmethod
    def identify(self, hash):
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    @classmethod
    def encrypt(self, secret, hash=None, keep_salt=False, user=None):
        if isinstance(secret, tuple):
            if user:
                raise TypeError, "user specified in secret & in kwd"
            secret, user = secret
        if not user:
            raise ValueError, "user keyword must be specified for this algorithm"
        return "md5" + hashlib.md5(secret + user).hexdigest().lower()

    @classmethod
    def verify(self, secret, hash, user=None):
        if hash is None:
            return False
        return hash == self.encrypt(secret, user=user)

#=========================================================
#db contexts
#=========================================================
postgres_context = CryptContext([PostgresMd5Crypt])

#=========================================================
# eof
#=========================================================
