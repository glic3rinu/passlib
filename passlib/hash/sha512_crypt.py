"""passlib.hash.sha512_crypt - SHA512-CRYPT

This algorithm is identical to :mod:`sha256-crypt <passlib.hash.sha256_crypt>`,
except that it uses SHA-512 instead of SHA-256. See that module
for any handler specific details.
"""
#=========================================================
#imports
#=========================================================
#core
from hashlib import sha512
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import h64, autodocument, classproperty, os_crypt
from passlib.hash.sha256_crypt import raw_sha_crypt
from passlib.utils.handlers import BackendBaseHandler
from passlib.base import register_crypt_handler
#pkg
#local
__all__ = [
    "Sha512Crypt",
]

#=========================================================
#builtin backend
#=========================================================
def raw_sha512_crypt(secret, salt, rounds):
    "perform raw sha512-crypt; returns encoded checksum, normalized salt & rounds"
    #run common crypt routine
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, sha512)

    ###encode result
    out = h64.encode_transposed_bytes(result, _512_offsets)
    assert len(out) == 86, "wrong length: %r" % (out,)
    return out, salt, rounds

_512_offsets = (
    42, 21, 0,
    1,  43, 22,
    23, 2,  44,
    45, 24, 3,
    4,  46, 25,
    26, 5,  47,
    48, 27, 6,
    7,  49, 28,
    29, 8,  50,
    51, 30, 9,
    10, 52, 31,
    32, 11, 53,
    54, 33, 12,
    13, 55, 34,
    35, 14, 56,
    57, 36, 15,
    16, 58, 37,
    38, 17, 59,
    60, 39, 18,
    19, 61, 40,
    41, 20, 62,
    63,
)

#=========================================================
#sha 512 crypt
#=========================================================
class Sha512Crypt(BackendBaseHandler):

    #=========================================================
    #algorithm information
    #=========================================================
    name = "sha512_crypt"

    setting_kwds = ("salt", "rounds", "implicit_rounds")

    min_salt_chars = 0
    max_salt_chars = 16
    #TODO: allow salt charset 0-255 except for "\x00\n:$"

    default_rounds = 40000 #current passlib default
    min_rounds = 1000
    max_rounds = 999999999
    rounds_cost = "linear"

    #=========================================================
    #init
    #=========================================================
    def __init__(self, implicit_rounds=None, **kwds):
        if implicit_rounds is None:
            implicit_rounds = True
        self.implicit_rounds = implicit_rounds
        super(SHA512Crypt, self).__init__(**kwds)

    #=========================================================
    #parsing
    #=========================================================
    @classmethod
    def identify(cls, hash):
        return bool(hash) and hash.startswith("$6$")

    #: regexp used to parse hashes
    _pat = re.compile(r"""
        ^
        \$6
        (\$rounds=(?P<rounds>\d+))?
        \$
        (
            (?P<salt1>[^:$\n]*)
            |
            (?P<salt2>[^:$\n]{0,16})
            (
                \$
                (?P<chk>[A-Za-z0-9./]{86})?
            )?
        )
        $
        """, re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        #TODO: write non-regexp based parser,
        # and rely on norm_salt etc to handle more of the validation.
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sha512-crypt hash"
        rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
        if rounds and rounds.startswith("0"):
            raise ValueError, "invalid sha512-crypt hash (zero-padded rounds)"
        return cls(
            implicit_rounds = not rounds,
            rounds=int(rounds) if rounds else 5000,
            salt=salt1 or salt2,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self):
        if self.rounds == 5000 and self.implicit_rounds:
            return "$6$%s$%s" % (self.salt, self.checksum or '')
        else:
            return "$6$rounds=%d$%s$%s" % (self.rounds, self.salt, self.checksum or '')

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        return bool(
            os_crypt and
            os_crypt("test", "$6$rounds=1000$test") ==
            "$6$rounds=1000$test$2M/Lx6MtobqjLjobw0Wmo4Q5OFx5nVLJvmgseatA6oMnyWeBdRDx4DU.1H3eGmse6pgsOgDisWBGI5c7TZauS0"
            )

    def _calc_checksum_builtin(self, secret):
        checksum, salt, rounds = raw_sha512_crypt(secret, self.salt, self.rounds)
        assert salt == self.salt, "class doesn't agree w/ builtin backend"
        assert rounds == self.rounds, "class doesn't agree w/ builtin backend"
        return checksum

    def _calc_checksum_os_crypt(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        #NOTE: avoiding full parsing routine via from_string().checksum,
        # and just extracting the bit we need.
        result = os_crypt(secret, self.to_string())
        assert result.startswith("$6$")
        chk = result[-86:]
        assert '$' not in chk
        return chk

    #=========================================================
    #eoc
    #=========================================================

autodocument(Shas512Crypt, settings_doc="""
:param implicit_rounds:
    this is an internal option which generally doesn't need to be touched.

    this flag determines whether the hash should omit the rounds parameter
    when encoding it to a string; this is only permitted by the spec for rounds=5000,
    and the flag is ignored otherwise. the spec requires the two different
    encodings be preserved as they are, instead of normalizing them.
""")
register_crypt_handler(Sha512Crypt)
#=========================================================
#eof
#=========================================================
