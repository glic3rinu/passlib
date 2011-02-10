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
        result = _EVP.hmac('x','y') #default *should* be sha1, which saves us a wrapper
    except ValueError:
        pass
    else:
        if result == ',\x1cb\xe0H\xa5\x82M\xfb>\xd6\x98\xef\x8e\xf9oQ\x85\xa3i':
            hmac_sha1 = _EVP.hmac

#TODO: should test for crypt support (NetBSD only)

#=========================================================
#algorithm information
#=========================================================
name = "sha1_crypt"
#stats: ?? bit checksum, ?? bit salt, 2**(4..31) rounds

setting_kwds = ("salt", "rounds")
context_kwds = ()

default_salt_chars = 8
min_salt_chars = 0
max_salt_chars = 64

default_rounds = 40000 #current passlib default
    #todo: vary default value by some % down
min_rounds = 1 #really, this should be higher.
max_rounds = 4294967295 # 32-bit integer limit
rounds_cost = "linear"

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$sha1
    \$(?P<rounds>\d+)
    \$(?P<salt>[A-Za-z0-9./]{0,64})
    (\$(?P<chk>[A-Za-z0-9./]{28}))?
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid sha1_crypt hash"
    rounds, salt, chk = m.group("rounds", "salt", "chk")
    if rounds.startswith("0"):
        raise ValueError, "invalid sha1-crypt hash: zero-padded rounds"
    return dict(
        rounds=int(rounds),
        salt=salt,
        checksum=chk,
    )

def render(rounds, salt, checksum=None):
    out = "$sha1$%d$%s" % (rounds, salt)
    if checksum:
        out += "$" + checksum
    return out

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None):
    salt = norm_salt(salt, min_salt_chars, max_salt_chars, default_salt_chars, name=name)
    rounds = norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name=name)
    return render(rounds, salt, None)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)
    info = parse(config)
    rounds, salt = info['rounds'], info['salt']

    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    result = salt + "$sha1$" + str(rounds)
    r = 0
    while r < rounds:
        result = hmac_sha1(secret, result)
        r += 1
    chk = h64.encode_transposed_bytes(result, _chk_offsets)
    return render(rounds, salt, chk)

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
#secondary interface
#=========================================================
def encrypt(secret, **settings):
    return genhash(secret, genconfig(**settings))

def verify(secret, hash):
    return hash == genhash(secret, hash)

def identify(hash):
    return bool(hash and _pat.match(hash))

autodocument(globals())
#=========================================================
#eof
#=========================================================
