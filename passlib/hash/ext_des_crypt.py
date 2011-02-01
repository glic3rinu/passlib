"""passlib.hash.ext_des_crypt - extended BSDi unix (DES) crypt"""
#=========================================================
#imports
#=========================================================
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import norm_rounds, norm_salt, h64
from passlib.utils.des import mdes_encrypt_int_block
from passlib.hash.des_crypt import _crypt_secret_to_key
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
def raw_ext_crypt(secret, rounds, salt):
    "ext_crypt() helper which returns checksum only"

    #decode salt
    try:
        salt_value = h64.decode_int24(salt)
    except ValueError:
        raise ValueError, "invalid salt"

    #validate secret
    if '\x00' in secret:
        #builtin linux crypt doesn't like this, so we don't either
        #XXX: would make more sense to raise ValueError, but want to be compatible w/ stdlib crypt
        raise ValueError, "secret must be string without null bytes"

    #XXX: doesn't match stdlib, but just to useful to not add in
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #convert secret string into an integer
    key_value = _crypt_secret_to_key(secret)
    while len(secret) > 8:
        secret = secret[8:]
        key_value = mdes_encrypt_int_block(key_value, key_value, salt=0, rounds=1)
        for i,c in enumerate(secret[:8]):
            key_value ^= (ord(c)&0x7f)<<(57-8*i)

    #run data through des using input of 0
    result = mdes_encrypt_int_block(key_value, 0, salt=salt_value, rounds=rounds)

    #run h64 encode on result
    return h64.encode_int64(result)

#TODO: check if crypt supports ext-des-crypt.

#=========================================================
#algorithm information
#=========================================================
name = "ext_des_crypt"
#stats: 64 bit checksum, 24 bit salt, 0..(1<<24)-1 rounds

setting_kwds = ("salt", "rounds")
context_kwds = ()

default_rounds = 10000
min_rounds = 0
max_rounds = 16777215 # (1<<24)-1

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    _
    (?P<rounds>[./a-z0-9]{4})
    (?P<salt>[./a-z0-9]{4})
    (?P<chk>[./a-z0-9]{11})?
    $""", re.X|re.I)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid ext-des-crypt hash"
    rounds, salt, chk = m.group("rounds", "salt", "chk")
    return dict(
        rounds=h64.decode_int24(rounds),
        salt=salt,
        checksum=chk,
    )

def render(rounds, salt, checksum=None):
    if rounds < 0:
        raise ValueError, "invalid rounds"
    if len(salt) != 4:
        raise ValueError, "invalid salt"
    if checksum and len(checksum) != 11:
        raise ValueError, "invalid checksum"
    return "_%s%s%s" % (h64.encode_int24(rounds), salt, checksum or '')

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None):
    """generate xxx configuration string

    :param salt:
        optional salt string to use.

        if omitted, one will be automatically generated (recommended).

        length must be 4 characters.
        characters must be in range ``A-Za-z0-9./``.

    :param rounds:

        optional number of rounds, must be between 0 and 16777215 inclusive.

    :returns:
        xxx configuration string.
    """
    salt = norm_salt(salt, 4, name=name)
    rounds = norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name=name)
    return render(rounds, salt, None)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    #TODO: could *easily* optimize this to skip excess render/parse
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)
    info = parse(config)
    rounds, salt = info['rounds'], info['salt']

    #run through chosen backend
    checksum = raw_ext_crypt(secret, rounds, salt)
    return render(rounds, salt, checksum)

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
