"""passlib.hash.sha512_crypt - SHA512-CRYPT

This algorithm is identical to :mod:`sha256-crypt <passlib.hash.sha256_crypt>`,
except that it uses SHA-512 instead of SHA-256. See that module
for any handler specific details.
"""
#=========================================================
#imports
#=========================================================
#core
from hashlib import sha256
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import norm_rounds, norm_salt, h64
from passlib.hash.sha256_crypt import raw_sha512_crypt
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
#choose backend
#=========================================================

#fallback to default backend (defined above)
backend = "builtin"

#check if stdlib crypt is available, and if so, if OS supports $5$ and $6$
#XXX: is this test expensive enough it should be delayed
#until sha-crypt is requested?

try:
    from crypt import crypt
except ImportError:
    crypt = None
else:
    if crypt("test", "$6$rounds=1000$test") == "$6$rounds=1000$test$2M/Lx6MtobqjLjobw0Wmo4Q5OFx5nVLJvmgseatA6oMnyWeBdRDx4DU.1H3eGmse6pgsOgDisWBGI5c7TZauS0":
        backend = "os-crypt"
    else:
        crypt = None

#=========================================================
#algorithm information
#=========================================================
name = "sha512_crypt"
#stats: 512 bit checksum, 96 bit salt, 1000..10e8-1 rounds

setting_kwds = ("salt", "rounds")
context_kwds = ()

default_rounds = 40000 #current passlib default
min_rounds = 1000
max_rounds = 999999999

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$6
    (\$rounds=(?P<rounds>\d+))?
    \$
    (
        (?P<salt1>[^:$]*)
        |
        (?P<salt2>[^:$]{0,16})
        \$
        (?P<chk>[A-Za-z0-9./]{86})?
    )
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid sha512-crypt hash"
    rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
    return dict(
        implicit_rounds = not rounds,
        rounds=int(rounds) if rounds else 5000,
        salt=salt1 or salt2,
        checksum=chk,
    )

def render(rounds, salt, checksum=None, implicit_rounds=True):
    assert '$' not in salt
    if rounds == 5000 and implicit_rounds:
        return "$6$%s$%s" % (salt, checksum or '')
    else:
        return "$6$rounds=%d$%s$%s" % (rounds, salt, checksum or '')

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None, implicit_rounds=True):
    """generate sha512-crypt configuration string

    :param salt:
        optional salt string to use.

        if omitted, one will be automatically generated (recommended).

        length must be 0 .. 16 characters inclusive.
        characters must be in range ``A-Za-z0-9./``.

    :param rounds:

        optional number of rounds, must be between 1000 and 999999999 inclusive.

    :param implicit_rounds:

        this is an internal option which generally doesn't need to be touched.

    :returns:
        sha512-crypt configuration string.
    """
    #TODO: allow salt charset 0-255 except for "\x00\n:$"
    salt = norm_salt(salt, 0, 16, name=name)
    rounds = norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name=name)
    return render(rounds, salt, None, implicit_rounds)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)

    #run through chosen backend
    if crypt:
        #using system's crypt routine.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return crypt(secret, config)
    else:
        #using builtin routine
        info = parse(config)
        checksum, salt, rounds = raw_sha512_crypt(secret, info['salt'], info['rounds'])
        return render(rounds, salt, checksum, info['implicit_rounds'])

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
