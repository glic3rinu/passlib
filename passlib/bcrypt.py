"""passlib.bcrypt"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement, absolute_import
#core
import re
import logging; log = logging.getLogger(__name__)
#site
#libs
from passlib.util import HashInfo, h64_gensalt
from passlib.base import CryptAlgorithm, register_crypt_algorithm
#pkg
#local
__all__ = [
    "BCrypt",
##    "bcrypt", "backend",
]

#=========================================================
#load bcrypt backend
#=========================================================
try:
    #try importing py-bcrypt, it's much faster
    import bcrypt
    backend = "pybcrypt"
except ImportError:
    #fall back to our much slower pure-python implementation
    import passlib._slow_bcrypt as bcrypt
    backend = "builtin"

#=========================================================
#OpenBSD's BCrypt
#=========================================================
class BCrypt(CryptAlgorithm):
    """Implementation of OpenBSD's BCrypt algorithm.

    Passlib will use the py-bcrypt package if it is available,
    otherwise it will fall back to a slower builtin pure-python implementation.

    Note that rounds must be >= 10 or an error will be returned.

    .. automethod:: encrypt
    """
    #=========================================================
    #algorithm info
    #=========================================================
    name = "bcrypt"
    salt_bytes = 16
    hash_bytes = 24
##    secret_chars = 55

    has_rounds = True
    default_rounds = "medium"

    #current recommended default rounds for blowfish
    # last updated 2009-7-6 on a 2ghz system
    round_presets = dict(
        fast = 12, # ~0.25s
        medium = 13, # ~0.82s
        slow = 14, # ~ 1.58s
    )

    #=========================================================
    #helpers
    #=========================================================
    _pat = re.compile(r"""
        ^
        \$(?P<ident>2a?)
        \$(?P<rounds>\d+)
        \$(?P<salt>[A-Za-z0-9./]{22})
        (?P<chk>[A-Za-z0-9./]{31})
        $
        """, re.X)

    @classmethod
    def _parse(cls, hash):
        "helper used to parse bcrypt hash into HashInfo object"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid bcrypt hash"
        ident, rounds, salt, chk = m.group("ident", "rounds", "salt", "chk")
        return HashInfo(ident, salt, chk, rounds=int(rounds), source=hash)

    #=========================================================
    #frontend
    #=========================================================

    @classmethod
    def identify(cls, hash):
        "identify bcrypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def encrypt(cls, secret, hash=None, keep_salt=False, rounds=None):
        """encrypt using bcrypt.

        In addition to the normal options that :meth:`CryptAlgorithm.encrypt` takes,
        this function also accepts the following:

        :param rounds:
            Optionally specify the number of rounds to use
            (technically, bcrypt will actually use ``2**rounds``).
            This can be one of "fast", "medium", "slow",
            or an integer in the range 4..31.

            See :attr:`CryptAlgorithm.has_named_rounds` for details
            on the meaning of "fast", "medium" and "slow".
        """
        salt = None
        if hash:
            info = cls._parse(hash)
            if rounds is None:
                rounds = info.rounds
            if keep_salt:
                salt = info.salt
        rounds = cls._resolve_preset_rounds(rounds)
        if not salt:
            salt = h64_gensalt(22)
        enc_salt = "$2a$%d$%s" % (rounds, salt)
        return bcrypt.hashpw(secret, enc_salt)

    @classmethod
    def verify(cls, secret, hash):
        "verify bcrypt hash"
        return bool(hash) and bcrypt.hashpw(secret, hash) == hash

    #=========================================================
    #eoc
    #=========================================================

register_crypt_algorithm(BCrypt)

#=========================================================
# eof
#=========================================================
