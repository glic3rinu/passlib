"""passlib.hash.postgres_md5 - MD5-based algorithm used by Postgres for pg_shadow table"""
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
from passlib.utils import autodocument
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
name = "postgres_md5"
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

autodocument(globals(), context_doc="""\
:param user: string containing name of postgres user account this password is associated with.
""")
#=========================================================
#eof
#=========================================================
