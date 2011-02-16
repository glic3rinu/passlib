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
from passlib.hash import postgres_md5, mysql_323, mysql_41
from passlib.base import CryptContext, register_crypt_handler
from passlib.utils.handlers import CryptHandler
#pkg
#local
__all__ = [
    #postgres
    'postgres_md5',
    'postgres_context',

    #mysql
    'mysql_323',
    'mysql_41',
    'mysql3_context',
    'mysql_context'
]

#=========================================================
#helpers
#=========================================================
class PostgresPlaintextHandler(CryptHandler):
    "fake password hash which recognizes ALL hashes, and assumes they encode the password in plain-text"
    name = "postgres_plaintext"

    context_kwds = ("user",)

    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, config, user=None):
        return secret

    @classmethod
    def identify(cls, hash):
        return bool(hash)

    @classmethod
    def verify(cls, secret, hash, user=None):
        return secret == hash

register_crypt_handler(PostgresPlainTextHandler)

#=========================================================
#postgres
#=========================================================
postgres_context = CryptContext([PostgresPlainTextHandler, postgres_md5])

#=========================================================
#mysql
#=========================================================
mysql3_context = CryptContext([mysql_323])
mysql_context = CryptContext([mysql_323, mysql_41])

#=========================================================
#TODO:
#=========================================================
#oracle - http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/

#=========================================================
# eof
#=========================================================
