"""passlib.hash.des_crypt - traditional unix (DES) crypt"""

#=========================================================
#imports
#=========================================================
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.base import register_crypt_handler
from passlib.utils import norm_salt, h64, autodocument
from passlib.utils.handlers import BaseHandler
from passlib.utils.des import mdes_encrypt_int_block
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
#pure-python backend
#=========================================================
def _crypt_secret_to_key(secret):
    "crypt helper which converts lower 7 bits of first 8 chars of secret -> 56-bit des key"
    key_value = 0
    for i, c in enumerate(secret[:8]):
        key_value |= (ord(c)&0x7f) << (57-8*i)
    return key_value

def raw_crypt(secret, salt):
    "pure-python fallback if stdlib support not present"
    assert len(salt) == 2

    #NOTE: technically might be able to use
    #fewer salt chars, not sure what standard behavior is,
    #so forbidding it for handler.

    try:
        salt_value = h64.decode_int12(salt)
    except ValueError:
        raise ValueError, "invalid chars in salt"
    #FIXME: ^ this will throws error if bad salt chars are used
    # whereas linux crypt does something (inexplicable) with it

    #convert secret string into an integer
    key_value = _crypt_secret_to_key(secret)

    #run data through des using input of 0
    result = mdes_encrypt_int_block(key_value, 0, salt_value, 25)

    #run h64 encode on result
    return h64.encode_dc_int64(result)

#=========================================================
#choose backend
#=========================================================
backend = "builtin"

try:
    #try stdlib module, which is only present under posix
    from crypt import crypt
    if crypt("test", "ab") == 'abgOeLfPimXQo':
        backend = "os-crypt"
    else:
        #shouldn't be any unix os which has crypt but doesn't support this format.
        warn("crypt() failed runtime test for DES-CRYPT support")
        crypt = None
except ImportError:
    #XXX: could check for openssl passwd -des support in libssl

    #TODO: need to reconcile our implementation's behavior
    # with the stdlib's behavior so error types, messages, and limitations
    # are the same. (eg: handling of None and unicode chars)
    crypt = None

#=========================================================
#handler
#=========================================================
class DesCrypt(BaseHandler):
    #=========================================================
    #class attrs
    #=========================================================
    name = "des_crypt"
    setting_kwds = ("salt",)
    min_salt_chars = max_salt_chars = 2

    #=========================================================
    #formatting
    #=========================================================
    #FORMAT: 2 chars of H64-encoded salt + 11 chars of H64-encoded checksum

    _pat = re.compile(r"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>[./a-z0-9]{11})?
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid des-crypt hash"
        salt, chk = m.group("salt", "chk")
        return cls(salt=salt, checksum=chk, strict=bool(chk))

    def to_string(self):
        return "%s%s" % (self.salt, self.checksum or '')

    #=========================================================
    #backend
    #=========================================================
    def calc_checksum(self, secret):
        #forbidding nul chars because linux crypt (and most C implementations) won't accept it either.
        if '\x00' in secret:
            raise ValueError, "null char in secret"

        #XXX: des-crypt predates unicode, not sure if there's an official policy for handing it.
        #for now, just coercing to utf-8.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")

        #run through chosen backend
        if crypt:
            #XXX: given a single letter salt, linux crypt returns a hash with the original salt doubled,
            #     but appears to calculate the hash based on the letter + "G" as the second byte.
            #     this results in a hash that won't validate, which is DEFINITELY wrong.
            #     need to find out it's underlying logic, and if it's part of spec,
            #     or just weirdness that should actually be an error.
            #     until then, passlib raises an error in genconfig()

            #XXX: given salt chars outside of h64.CHARS range, linux crypt
            #     does something unknown when decoding salt to 12 bit int,
            #     successfully creates a hash, but reports the original salt.
            #     need to find out it's underlying logic, and if it's part of spec,
            #     or just weirdness that should actually be an error.
            #     until then, passlib raises an error for bad salt chars.
            return self.from_string(crypt(secret, self.to_string())).checksum
        else:
            return raw_crypt(secret, self.salt)

    #=========================================================
    #eoc
    #=========================================================

autodocument(DesCrypt)
register_crypt_handler(DesCrypt)
#=========================================================
#eof
#=========================================================
