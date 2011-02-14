"""passlib.hash.mysql_41 - MySQL NEW_PASSWORD

This implements Mysql new PASSWORD algorithm, introduced in version 4.1.

This function is unsalted, and therefore not very secure against rainbow attacks.
It should only be used when dealing with mysql passwords,
for all other purposes, you should use a salted hash function.

Description taken from http://dev.mysql.com/doc/refman/6.0/en/password-hashing.html
"""
#=========================================================
#imports
#=========================================================
#core
from hashlib import sha1
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
#pkg
from passlib.base import register_crypt_handler
from passlib.utils import autodocument
from passlib.utils.handlers import WrapperHandler
#local
__all__ = [
    "MySQL_41",
]

#=========================================================
#handler
#=========================================================
class MySQL_41(WrapperHandler):
    #=========================================================
    #algorithm information
    #=========================================================
    name = "mysql_41"
    setting_kwds = ()

    #=========================================================
    #formatting
    #=========================================================
    _pat = re.compile(r"^\*[0-9A-F]{40}$", re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    #=========================================================
    #backend
    #=========================================================
    #NOTE: using default genconfig() method

    @classmethod
    def genhash(cls, secret, config):
        if config and not cls.identify(config):
            raise ValueError, "not a mysql-41 hash"
        #FIXME: no idea if mysql has a policy about handling unicode passwords
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return '*' + sha1(sha1(secret).digest()).hexdigest().upper()

    #=========================================================
    #helpers
    #=========================================================
    #NOTE: using default encrypt() method

    @classmethod
    def verify(cls, secret, hash):
        if not hash:
            raise ValueError, "no hash specified"
        return hash.upper() == cls.genhash(secret, hash)

    #=========================================================
    #eoc
    #=========================================================

autodocument(MySQL_41)
register_crypt_handler(MySQL_41)
#=========================================================
#eof
#=========================================================
