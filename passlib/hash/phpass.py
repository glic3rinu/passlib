"""passlib.hash.phpass - PHPass Portable Crypt

phppass located - http://www.openwall.com/phpass/
algorithm described - http://www.openwall.com/articles/PHP-Users-Passwords

phpass context - blowfish, ext_des_crypt, phpass
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
from passlib.utils import norm_rounds, norm_salt, h64
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
#algorithm information
#=========================================================
name = "phpass"
#stats: 128 bit checksum, 24 bit salt

setting_kwds = ("salt", "rounds")
context_kwds = ()

default_rounds = 9
min_rounds = 7
max_rounds = 30

#=========================================================
#internal helpers
#=========================================================
#$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0
# $P$ 9 IQRaTwmf eRo7ud9Fh4E2PdI0S3r.L0

_pat = re.compile(r"""
    ^
    \$
    (?P<ident>[PH])
    \$
    (?P<rounds>[A-Za-z0-9./])
    (?P<salt>[A-Za-z0-9./]{8})
    (?P<chk>[A-Za-z0-9./]{22})?
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid phpass portable hash"
    ident, rounds, salt, chk = m.group("ident", "rounds", "salt", "chk")
    out = dict(
        rounds=h64.decode_6bit(rounds),
        salt=salt,
        checksum=chk,
    )
    if ident != "P":
        out['ident'] = ident
    return out

def render(rounds, salt, checksum=None, ident="P"):
    if rounds < 0 or rounds > 31:
        raise ValueError, "invalid rounds"
    return "$%s$%s%s%s" % (ident, h64.encode_6bit(rounds), salt, checksum or '')

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None, ident="P"):
    """generate md5-crypt configuration string

    :param salt:
        optional salt string to use.

        if omitted, one will be automatically generated (recommended).

        length must be between 8 characters.
        characters must be in range ``A-Za-z0-9./``.

    :param rounds:
        optional rounds parameter.

        like bcrypt's rounds value, phpass' rounds value is logarithmic,
        each increase of +1 will double the actual number of rounds used.

    :param ident:

        phpBB3 uses ``H`` instead of ``P`` for it's identifier.
        this may be set to ``H`` in order to generate phpBB3 compatible hashes.

    :returns:
        phpass configuration string.
    """
    if ident not in ("P", "H"):
        raise ValueError, "invalid ident: %r" % (ident,)
    salt = norm_salt(salt, 8, name=name)
    if rounds is None:
        rounds = default_rounds
    if rounds < 7 or rounds > 30:
        #NOTE: PHPass raises error when encrypting if rounds are outside these bounds.
        raise ValueError, "rounds must be between 7..30 inclusive"
    return render(rounds, salt, None, ident)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)
    info = parse(config)
    ident, rounds, salt = info.get("ident","P"), info['rounds'], info['salt']

    #FIXME: can't find definitive policy on how phpass handles non-ascii.
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    real_rounds = 1<<rounds
    result = md5(salt + secret).digest()
    r = 0
    while r < real_rounds:
        result = md5(result + secret).digest()
        r += 1

    checksum = h64.encode_bytes(result)
    return render(rounds, salt, checksum, ident)

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
