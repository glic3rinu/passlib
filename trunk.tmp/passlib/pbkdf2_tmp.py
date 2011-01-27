"""passlib.pbkdf2 - PBKDF2 support

"""
#=================================================================================
#imports
#=================================================================================
#core
from binascii import unhexlify
from cStringIO import StringIO
import hashlib
import hmac
import logging; log = logging.getLogger(__name__)
import re
from struct import pack
#site
try:
    from M2Crypto import EVP as _EVP
except ImportError:
    _EVP = None
#pkg
from passlib.util import xor_bytes, h64_gensalt, h64_validate
#local
__all__ = [
    "pbkdf2",
]

#=================================================================================
#crypt implementation
#=================================================================================

def b64encode(data):
    return data.encode('base64').replace("\n","").replace("+",".").strip("=")

class P5K2Crypt(CryptAlgorithm):
    "pbkdf2-based password hash compatible with ???'s PBKDF2.py module"
    name = "p5k2-crypt"
    aliases = ("p5k2","pbkdf2")
    salt_bytes = 6
    hash_bytes = 24
    has_rounds = True
    default_rounds = 1000

    _pat_re = re.compile(r"^\$p5k2\$(?P<rounds>[0-9a-fA-F]*)\$(?P<salt>[a-zA-Z0-9./]+)(\$(?P<chk>[a-zA-Z0-9./]+))?$")

    @classmethod
    def identify(cls, hash):
        return bool(hash & cls._pat_re.match(hash))

    @classmethod
    def encrypt(cls, secret, hash=None, keep_salt=False, rounds=None):
        salt = None
        if hash:
            m = _pat_re.match(hash)
            if not m:
                raise ValueError, "invalid hash"
            r,s,c = m.groups("rounds", "salt", "chk")
            if keep_salt:
                salt = s
                if isinstance(salt, unicode):
                    salt = salt.encode("us-ascii")
                if not h64_validate(salt):
                    raise ValueError, "invalid characters in salt: %r" % (salt,)
            if rounds is None:
                rounds = int(r,16) if r else 400
        rounds = cls._resolve_round_preset(rounds)
        if not salt:
            salt = h64_gensalt(8)
        if rounds == 400:
            prefix = "$p5k2$$" + salt
        else:
            prefix = "$p5k2$%x$%s" % (rounds, salt)
        checksum = b64encode(pbkdf2(secret, prefix, rounds, 24))
        return prefix + "$" + checksum

def test_pbkdf2():
    """Module self-test"""
    from binascii import a2b_hex

    #
    # Test vectors from RFC 3962
    #

    def assertEqual(result, expected):
        if result != expected:
            raise RuntimeError, 'test failed: %r %r' % (result, expected)

    #
    # crypt() test vectors
    #

    # crypt 1
    result = crypt("cloadm", "exec")
    expected = '$p5k2$$exec$r1EWMCMk7Rlv3L/RNcFXviDefYa0hlql'
    assertEqual(result, expected)

    # crypt 2
    result = crypt("gnu", '$p5k2$c$u9HvcT4d$.....')
    expected = '$p5k2$c$u9HvcT4d$Sd1gwSVCLZYAuqZ25piRnbBEoAesaa/g'
    assertEqual(result, expected)

    # crypt 3
    result = crypt("dcl", "tUsch7fU", rounds=13)
    expected = "$p5k2$d$tUsch7fU$nqDkaxMDOFBeJsTSfABsyn.PYUXilHwL"
    assertEqual(result, expected)

    # crypt 4 (unicode)
    result = crypt(u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
        '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ')
    expected = '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ'
    assertEqual(result, expected)

if __name__ == '__main__':
    test_pbkdf2()

#=================================================================================
#eof
#=================================================================================
