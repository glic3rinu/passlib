"""passlib.hash.postgres_md5 - MD5-based algorithm used by Postgres for pg_shadow table

This implements the md5-based hash algorithm used by Postgres to store
passwords in the pg_shadow table.

This algorithm shouldn't be used for any purpose besides Postgres interaction,
it's a weak unsalted algorithm which could be attacked with a rainbow table
built against common user names.

.. warning::
    This algorithm is slightly different from most of the others,
    in that both encrypt() and verify() require you pass in
    the name of the user account via the required 'user' keyword,
    since postgres uses this in place of a salt :(

Usage Example::

    >>> from passlib.hash import postgres_md5 as pm
    >>> pm.encrypt("mypass", user="postgres")
    'md55fba2ea04fd36069d2574ea71c8efe9d'
    >>> pm.verify("mypass", 'md55fba2ea04fd36069d2574ea71c8efe9d', user="postgres")
    True
"""
#=========================================================
#imports
#=========================================================
#core
from hashlib import md5
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
name = "postgres-md5"
#stats: 512 bit checksum, username used as salt

setting_kwds = ()
context_kwds = ("user",)

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"^md5[0-9a-f]{32}$")

#=========================================================
#primary interface
#=========================================================
def genconfig():
    return None

def genhash(secret, config, user):
    if config and not identify(config):
        raise ValueError, "not a postgres-md5 hash"
    if not user:
        raise ValueError, "user keyword must be specified for this algorithm"
    return "md5" + md5(secret + user).hexdigest().lower()

#=========================================================
#secondary interface
#=========================================================
def encrypt(secret, user, **settings):
    return genhash(secret, genconfig(**settings), user)

def verify(secret, hash, user):
    if not hash:
        raise ValueError, "no hash specified"
    return hash.lower() == genhash(secret, hash, user)

def identify(hash):
    return bool(hash and _pat.match(hash))

#=========================================================
#eof
#=========================================================
