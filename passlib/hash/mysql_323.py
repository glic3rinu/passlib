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
from passlib.base import register_crypt_handler
from passlib.utils import autodocument
from passlib.utils.handlers import PlainHandler
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
class MySQL_323(PlainHandler):

    #=========================================================
    #class attrs
    #=========================================================
    name = "mysql_323"

    #=========================================================
    #init
    #=========================================================
    @classmethod
    def norm_checksum(cls, chk, strict=False):
        if chk:
            return chk.lower() #to make upper-case strings verify properly
        return None

    #=========================================================
    #formatting
    #=========================================================
    _pat = re.compile(r"^[0-9a-f]{16}$", re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "not a recognized mysql-323 hash"
        return cls(checksum=hash)

    def to_string(self):
        return self.checksum

    #=========================================================
    #backend
    #=========================================================
    def calc_checksum(self, secret):
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
    #eoc
    #=========================================================

autodocument(MySQL_323)
register_crypt_handler(MySQL_323)
#=========================================================
#eof
#=========================================================
