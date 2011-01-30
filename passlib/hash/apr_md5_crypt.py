"""passlib.hash.apr_md5_crypt - Apache variant of md5-crypt algorithm

This format is primarily used by Apache in htpasswd files.

.. note::
    This format would be identical to md5-crypt,
    except for two things: it uses ``$apr1$`` as it's prefix
    when encoded, and inserts that constant into the hash calculation
    where md5-crypt would insert ``$1$``.
    Thus, the formats aren't compatible, nor the checksums they contain.
    Other than that, they have identical levels of security.
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
from passlib.hash.md5_crypt import raw_md5_crypt
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

#TODO: could check for libssl support (openssl passwd -apr1)

#=========================================================
#algorithm information
#=========================================================
name = "apr_md5_crypt"
#stats: 96 bit checksum, 48 bit salt

setting_kwds = ("salt",)
context_kwds = ()

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$apr1
    \$(?P<salt>[A-Za-z0-9./]{,8})
    (\$(?P<chk>[A-Za-z0-9./]{22})?)?
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid apr-md5-crypt hash"
    salt, chk = m.group("salt", "chk")
    return dict(
        salt=salt,
        checksum=chk,
    )

def render(salt, checksum=None):
    return "$apr1$%s$%s" % (salt, checksum or '')

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None):
    """generate apr-md5-crypt configuration string

    :param salt:
        optional salt string to use.

        if omitted, one will be automatically generated (recommended).

        length must be between 0 and 8 characters inclusive.
        characters must be in range ``A-Za-z0-9./``.

    :returns:
        md5-crypt configuration string.
    """
    salt = norm_salt(salt, 0, 8, name=name)
    return render(salt, None)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    #FIXME: could eliminate an extra render+parse call here
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)
    info = parse(config)

    #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #run through chosen backend
    salt = info['salt']
    checksum = raw_md5_crypt(secret, salt, apr=True)
    return render(salt, checksum)

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
