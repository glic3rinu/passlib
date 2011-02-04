"""passlib.hash.mysql_323 - MySQL OLD_PASSWORD

This implements Mysql's OLD_PASSWORD algorithm, introduced in version 3.2.3, deprecated in version 4.1.

See :mod:`passlib.hash.mysql_41` for the new algorithm was put in place in version 4.1

This algorithm is known to be very insecure, and should only be used to verify existing password hashes.

http://djangosnippets.org/snippets/1508/
"""
#=========================================================
#imports
#=========================================================
#core
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
name = "mysql_323"
#stats: 62 bit checksum, no salt

setting_kwds = ()
context_kwds = ()

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"^[0-9a-f]{16}$", re.I)

#=========================================================
#primary interface
#=========================================================
def genconfig():
    return None

def genhash(secret, config):
    if config and not identify(config):
        raise ValueError, "not a mysql-323 hash"

    MASK_32 = 0xffffffff
    MASK_31 = 0x7fffffff

    nr1 = 0x50305735
    nr2 = 0x12345671
    add = 7
    for c in secret:
        if c in ' \t':
            continue
        tmp = ord(c)
        nr1 ^= ((((nr1 & 63)+add)*tmp) + (nr1 << 8)) & MASK_32
        nr2 = (nr2+((nr2 << 8) ^ nr1)) & MASK_32
        add = (add+tmp) & MASK_32
    return "%08x%08x" % (nr1 & MASK_31, nr2 & MASK_31)

#=========================================================
#secondary interface
#=========================================================
def encrypt(secret, **settings):
    return genhash(secret, genconfig(**settings))

def verify(secret, hash):
    if not hash:
        raise ValueError, "no hash specified"
    return hash.lower() == genhash(secret, hash)

def identify(hash):
    return bool(hash and _pat.match(hash))

autodocument(globals())
#=========================================================
#eof
#=========================================================
