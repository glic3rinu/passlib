"""passlib.hash.nthash - unix-crypt compatible nthash passwords"""
#=========================================================
#imports
#=========================================================
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils.md4 import md4
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
def raw_nthash(secret, hex=False):
    "encode password using md4-based NTHASH algorithm; returns string of raw bytes"
    hash = md4(secret.encode("utf-16le"))
    return hash.hexdigest() if hex else hash.digest()

#=========================================================
#algorithm information
#=========================================================
name = "nthash"
#stats: 128 bit checksum, no salt

setting_kwds = ()
context_kwds = ()

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$(?P<ident>3\$\$|NT\$)
    (?P<chk>[a-f0-9]{32})
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid nthash"
    ident, chk = m.group("ident", "chk")
    out = dict(
        checksum=chk,
        )
    ident=ident.strip("$")
    if ident != "3":
        out['ident'] = ident
    return out

def render(checksum, ident=None):
    if not ident or ident == "3":
        return "$3$$" + checksum
    elif ident == "NT":
        return "$NT$" + checksum
    else:
        raise ValueError, "invalid ident"

#=========================================================
#primary interface
#=========================================================
def genconfig(ident=None):
    return render("0" * 32, ident)

def genhash(secret, config):
    info = parse(config)
    if secret is None:
        raise TypeError, "secret must be a string"
    chk = raw_nthash(secret, hex=True)
    return render(chk, info.get('ident'))

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
