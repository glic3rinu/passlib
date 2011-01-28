"""passlib.hash._skel - skeleton file for creating new hash modules
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
from passlib.utils import norm_rounds, norm_salt
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
name = "xxx"
#stats: ??? bit checksum, ??? bit salt, ??? rounds, max ??? chars of secret

setting_kwds = ("salt", "rounds")
context_kwds = ()

default_rounds = None #current passlib default
min_rounds = 1
max_rounds = 1

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$xxx
    \$(?P<rounds>\d+)
    \$(?P<salt>[A-Za-z0-9./]{xxx})
    (\$(?P<chk>[A-Za-z0-9./]{xxx})?)?
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid xxx hash"
    rounds, salt, chk = m.group("rounds", "salt", "chk")
    return dict(
        rounds=int(rounds),
        salt=salt,
        checksum=chk,
    )

def render(rounds, salt, checksum=None):
    return "$xxx$%d$%s$%s" % (rounds, salt, checksum or '')

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None):
    """generate xxx configuration string

    :param salt:
        optional salt string to use.

        if omitted, one will be automatically generated (recommended).

        length must be XXX characters.
        characters must be in range ``A-Za-z0-9./``.

    :param rounds:

        optional number of rounds, must be between XXX and XXX inclusive.

    :returns:
        xxx configuration string.
    """
    salt = norm_salt(salt, 22, name=name)
    rounds = norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name=name)
    return render(rounds, salt, None)

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

#=========================================================
#eof
#=========================================================
