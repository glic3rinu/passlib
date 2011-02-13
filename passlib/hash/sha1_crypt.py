"""passlib.hash.sha1_crypt
"""

#=========================================================
#imports
#=========================================================
from __future__ import with_statement, absolute_import
#core
from hmac import new as hmac
from hashlib import sha1
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
try:
    from M2Crypto import EVP as _EVP
except ImportError:
    _EVP = None
#libs
from passlib.utils import norm_rounds, norm_salt, autodocument, h64
from passlib.utils.handlers import BaseHandler
from passlib.base import register_crypt_handler
#pkg
#local
__all__ = [
]

#=========================================================
#backend
#=========================================================
def hmac_sha1(key, msg):
    return hmac(key, msg, sha1).digest()

if _EVP:
    try:
        result = _EVP.hmac('x','y') #default *should* be sha1, which saves us a wrapper, but might as well check.
    except ValueError:
        pass
    else:
        if result == ',\x1cb\xe0H\xa5\x82M\xfb>\xd6\x98\xef\x8e\xf9oQ\x85\xa3i':
            hmac_sha1 = _EVP.hmac

#TODO: should test for crypt support (NetBSD only)

#=========================================================
#sha1-crypt
#=========================================================
class Sha1Crypt(BaseHandler):

    #=========================================================
    #class attrs
    #=========================================================
    name = "sha1_crypt"
    setting_kwds = ("salt", "rounds")

    default_salt_chars = 8
    min_salt_chars = 0
    max_salt_chars = 64

    default_rounds = 40000 #current passlib default
    min_rounds = 1 #really, this should be higher.
    max_rounds = 4294967295 # 32-bit integer limit
    rounds_cost = "linear"

    #=========================================================
    #formatting
    #=========================================================
    @classmethod
    def identify(cls, hash):
        return bool(hash) and hash.startswith("$sha1$")

    _pat = re.compile(r"""
        ^
        \$sha1
        \$(?P<rounds>\d+)
        \$(?P<salt>[A-Za-z0-9./]{0,64})
        (\$(?P<chk>[A-Za-z0-9./]{28})?)?
        $
        """, re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sha1_crypt hash"
        rounds, salt, chk = m.group("rounds", "salt", "chk")
        if rounds.startswith("0"):
            raise ValueError, "invalid sha1-crypt hash (zero-padded rounds)"
        return cls(
            rounds=int(rounds),
            salt=salt,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self):
        out = "$sha1$%d$%s" % (self.rounds, self.salt)
        if self.checksum:
            out += "$" + self.checksum
        return out

    #=========================================================
    #backend
    #=========================================================
    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        rounds = self.rounds
        result = "%s$sha1$%s" % (self.salt, rounds)
        r = 0
        while r < rounds:
            result = hmac_sha1(secret, result)
            r += 1
        return h64.encode_transposed_bytes(result, self._chk_offsets)

    _chk_offsets = [
        2,1,0,
        5,4,3,
        8,7,6,
        11,10,9,
        14,13,12,
        17,16,15,
        0,19,18,
    ]

    #=========================================================
    #eoc
    #=========================================================

autodocument(Sha1Crypt)
register_crypt_handler(Sha1Crypt)
#=========================================================
#eof
#=========================================================
