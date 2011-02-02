"""passlib.bcrypt

Implementation of OpenBSD's BCrypt algorithm.

Passlib will use the py-bcrypt package if it is available,
otherwise it will fall back to a slower builtin pure-python implementation.

Note that rounds must be >= 10 or an error will be returned.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement, absolute_import
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import norm_rounds, norm_salt, autodocument
#pkg
#local
__all__ = [
    "BCrypt",
##    "bcrypt", "backend",
]

#=========================================================
#backend
#=========================================================
#fall back to our much slower pure-python implementation
from passlib.utils._slow_bcrypt import hashpw as bcrypt
backend = "builtin"

try:
    #try importing py-bcrypt, it's much faster
    from bcrypt import hashpw as bcrypt
    backend = "pybcrypt"
except ImportError:
    #check for OS crypt support before falling back to pure python version
    try:
        from crypt import crypt
    except ImportError:
        pass
    else:
        if (
            crypt("test", "$2a$04$......................") == '$2a$04$......................qiOQjkB8hxU8OzRhS.GhRMa4VUnkPty'
            and
            crypt("test", "$2$04$......................") == '$2$04$......................1O4gOrCYaqBG3o/4LnT2ykQUt1wbyju'
        ):
            def bcrypt(secret, config):
                if isinstance(secret, unicode):
                    secret = secret.encode("utf-8")
                hash = crypt(secret, config)
                if not hash.startswith("$2a$") and not hash.startswith("$2$"):
                    #means config was wrong
                    raise ValueError, "not a bcrypt hash"
                return hash
            backend = "os-crypt"

#XXX: should issue warning when _slow_bcrypt is first used.

#=========================================================
#algorithm information
#=========================================================
name = "bcrypt"
#stats: 192 bit checksum, 128 bit salt, 2**(4..31) rounds, max 72 chars of secret

setting_kwds = ("salt", "rounds")
context_kwds = ()

min_salt_chars = max_salt_chars = 22

default_rounds = 12 #current passlib default
min_rounds = 4 # bcrypt spec specified minimum
max_rounds = 31 # 32-bit integer limit (real_rounds=1<<rounds)

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$(?P<ident>2a?)
    \$(?P<rounds>\d{2})
    \$(?P<salt>[A-Za-z0-9./]{22})
    (?P<chk>[A-Za-z0-9./]{31})?
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid bcrypt hash"
    ident, rounds, salt, chk = m.group("ident", "rounds", "salt", "chk")
    out = dict(
        rounds=int(rounds),
        salt=salt,
        checksum=chk,
    )
    if ident == '2':
        out['omit_null_suffix'] = True
    return out

def render(rounds, salt, checksum=None, omit_null_suffix=False):
    if omit_null_suffix:
        out = "$2$%02d$%s" % (rounds, salt)
    else:
        out = "$2a$%02d$%s" % (rounds, salt)
    if checksum is not None:
        out += "$" + checksum
    return out

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None, omit_null_suffix=False):
    ##"""generate bcrypt configuration string
    ##
    ##:param salt:
    ##    optional salt string to use.
    ##
    ##    if omitted, one will be automatically generated (recommended).
    ##
    ##    length must be 22 characters.
    ##    characters must be in range ``A-Za-z0-9./``.
    ##
    ##:param rounds:
    ##
    ##    optional number of rounds, must be between 4 and 31 inclusive.
    ##
    ##    unlike most algorithms, bcrypt's rounds value is logarithmic,
    ##    each increase of +1 will double the actual number of rounds used.
    ##
    ##:returns:
    ##    bcrypt configuration string.
    ##"""
    salt = norm_salt(salt, min_salt_chars, max_salt_chars, name=name)
    rounds = norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name=name)
    return render(rounds, salt, None, omit_null_suffix)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)

    #run through chosen backend
    return bcrypt(secret, config)

#=========================================================
#secondary interface
#=========================================================
def encrypt(secret, **settings):
    return genhash(secret, genconfig(**settings))

def verify(secret, hash):
    return hash == genhash(secret, hash)

def identify(hash):
    return bool(hash and _pat.match(hash))

autodocument(globals(), log_rounds=True)
#=========================================================
#eof
#=========================================================
