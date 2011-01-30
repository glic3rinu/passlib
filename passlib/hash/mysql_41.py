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
#local
__all__ = [
    "genhash",
    "genconfig",
    "encrypt",
    "identify",
    "verify",
]

#=========================================================
#backend
#=========================================================

#=========================================================
#algorithm information
#=========================================================
name = "mysql_41"
#stats: 160 bit checksum, no salt

setting_kwds = ()
context_kwds = ()

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"^\*[0-9A-F]{40}$", re.I)

#=========================================================
#primary interface
#=========================================================
def genconfig():
    return None

def genhash(secret, config):
    if config and not identify(config):
        raise ValueError, "not a mysql-41 hash"
    return '*' + sha1(sha1(secret).digest()).hexdigest().upper()

#=========================================================
#secondary interface
#=========================================================
def encrypt(secret, **settings):
    return genhash(secret, genconfig(**settings))

def verify(secret, hash):
    if not hash:
        raise ValueError, "no hash specified"
    return hash.upper() == genhash(secret, hash)

def identify(hash):
    return bool(hash and _pat.match(hash))

#=========================================================
#eof
#=========================================================
