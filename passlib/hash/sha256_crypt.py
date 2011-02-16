"""passlib.hash.sha256_crypt - SHA256-CRYPT"""
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
from passlib.base import register_crypt_handler
from passlib.utils import h64, classproperty, autodocument, os_crypt
from passlib.utils.handlers import BackendExtHandler
#pkg
#local
__all__ = [
    "SHA256Crypt",
]

#=========================================================
#pure-python backend (shared between sha256-crypt & sha512-crypt)
#=========================================================
def raw_sha_crypt(secret, salt, rounds, hash):
    """perform raw sha crypt

    :arg secret: password to encode (if unicode, encoded to utf-8)
    :arg salt: salt string to use (required)
    :arg rounds: int rounds
    :arg hash: hash constructor function for 256/512 variant

    :returns:
        Returns tuple of ``(unencoded checksum, normalized salt, normalized rounds)``.

    """
    #validate secret
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #validate rounds
    if rounds < 1000:
        rounds = 1000
    if rounds > 999999999:
        rounds = 999999999

    #validate salt
    if any(c in salt for c in '\x00$'):
        raise ValueError, "invalid chars in salt"
    if len(salt) > 16:
        salt = salt[:16]

    #init helpers
    def extend(source, size_ref):
        "helper which repeats <source> digest string until it's the same length as <size_ref> string"
        assert len(source) == chunk_size
        size = len(size_ref)
        return source * int(size/chunk_size) + source[:size % chunk_size]

    #calc digest B
    b = hash(secret)
    chunk_size = b.digest_size #grab this once hash is created
    b.update(salt)
    a = b.copy() #make a copy to save a little time later
    b.update(secret)
    b_result = b.digest()
    b_extend = extend(b_result, secret)

    #begin digest A
    #a = hash(secret) <- performed above
    #a.update(salt) <- performed above
    a.update(b_extend)

    #for each bit in slen, add B or SECRET
    value = len(secret)
    while value > 0:
        if value % 2:
            a.update(b_result)
        else:
            a.update(secret)
        value >>= 1

    #finish A
    a_result = a.digest()

    #calc DP - hash of password, extended to size of password
    dp = hash(secret * len(secret))
    dp_result = extend(dp.digest(), secret)

    #calc DS - hash of salt, extended to size of salt
    ds = hash(salt * (16+ord(a_result[0])))
    ds_result = extend(ds.digest(), salt) #aka 'S'

    #
    #calc digest C
    #NOTE: this has been contorted a little to allow pre-computing
    #some of the hashes. the original algorithm was that
    #each round generates digest composed of:
    #   if round%2>0 => dp else lr
    #   if round%3>0 => ds
    #   if round%7>0 => dp
    #   if round%2>0 => lr else dp
    #where lr is digest of the last round's hash (initially = a_result)
    #

    #pre-calculate some digests to speed up odd rounds
    dp_hash = hash(dp_result).copy
    dp_ds_hash = hash(dp_result + ds_result).copy
    dp_dp_hash = hash(dp_result * 2).copy
    dp_ds_dp_hash = hash(dp_result + ds_result + dp_result).copy

    #pre-calculate some strings to speed up even rounds
    ds_dp_result = ds_result + dp_result
    dp_dp_result = dp_result * 2
    ds_dp_dp_result = ds_result + dp_dp_result

    #run through rounds
    last_result = a_result
    i = 0
    while i < rounds:
        if i % 2:
            if i % 3:
                if i % 7:
                    c = dp_ds_dp_hash()
                else:
                    c = dp_ds_hash()
            elif i % 7:
                c = dp_dp_hash()
            else:
                c = dp_hash()
            c.update(last_result)
        else:
            c = hash(last_result)
            if i % 3:
                if i % 7:
                    c.update(ds_dp_dp_result)
                else:
                    c.update(ds_dp_result)
            elif i % 7:
                c.update(dp_dp_result)
            else:
                c.update(dp_result)
        last_result = c.digest()
        i += 1

    #return unencoded result, along w/ normalized config values
    return last_result, salt, rounds

def raw_sha256_crypt(secret, salt, rounds):
    "perform raw sha256-crypt; returns encoded checksum, normalized salt & rounds"
    #run common crypt routine
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, sha256)
    out = h64.encode_transposed_bytes(result, _256_offsets)
    assert len(out) == 43, "wrong length: %r" % (out,)
    return out, salt, rounds

_256_offsets = (
    20, 10, 0,
    11, 1,  21,
    2,  22, 12,
    23, 13, 3,
    14, 4,  24,
    5,  25, 15,
    26, 16, 6,
    17, 7,  27,
    8,  28, 18,
    29, 19, 9,
    30, 31,
)

#=========================================================
#handler
#=========================================================
class SHA256Crypt(BackendExtHandler):

    #=========================================================
    #algorithm information
    #=========================================================
    name = "sha256_crypt"

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
        return bool(hash) and hash.startswith("$5$")

    #: regexp used to parse hashes
    _pat = re.compile(r"""
        ^
        \$5
        (\$rounds=(?P<rounds>\d+))?
        \$
        (
            (?P<salt1>[^:$]*)
            |
            (?P<salt2>[^:$]{0,16})
            \$
            (?P<chk>[A-Za-z0-9./]{43})?
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
            raise ValueError, "invalid sha256-crypt hash"
        rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
        if rounds and rounds.startswith("0"):
            raise ValueError, "invalid sha256-crypt hash (zero-padded rounds)"
        return cls(
            implicit_rounds = not rounds,
            rounds=int(rounds) if rounds else 5000,
            salt=salt1 or salt2,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self):
        if self.rounds == 5000 and self.implicit_rounds:
            return "$5$%s$%s" % (self.salt, self.checksum or '')
        else:
            return "$5$rounds=%d$%s$%s" % (self.rounds, self.salt, self.checksum or '')

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        return bool(
            os_crypt and
            os_crypt("test", "$5$rounds=1000$test") ==
            "$5$rounds=1000$test$QmQADEXMG8POI5WDsaeho0P36yK3Tcrgboabng6bkb/"
            )

    def _calc_checksum_builtin(self, secret):
        checksum, salt, rounds = raw_sha256_crypt(secret, self.salt, self.rounds)
        assert salt == self.salt, "class doesn't agree w/ builtin backend"
        assert rounds == self.rounds, "class doesn't agree w/ builtin backend"
        return checksum

    def _calc_checksum_os_crypt(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        #NOTE: avoiding full parsing routine via from_string().checksum,
        # and just extracting the bit we need.
        result = os_crypt(secret, self.to_string())
        assert result.startswith("$5$")
        chk = result[-43:]
        assert '$' not in chk
        return chk

    #=========================================================
    #eoc
    #=========================================================

autodocument(SHA256Crypt, settings_doc="""
:param implicit_rounds:
    this is an internal option which generally doesn't need to be touched.

    this flag determines whether the hash should omit the rounds parameter
    when encoding it to a string; this is only permitted by the spec for rounds=5000,
    and the flag is ignored otherwise. the spec requires the two different
    encodings be preserved as they are, instead of normalizing them.
""")
register_crypt_handler(SHA256Crypt)
#=========================================================
#eof
#=========================================================
