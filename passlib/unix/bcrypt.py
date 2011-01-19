"""passlib.bcrypt"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement, absolute_import
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.handler import CryptHandlerHelper, register_crypt_handler
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
    import passlib.utils._slow_bcrypt as bcrypt
    backend = "builtin"

#XXX: should issue warning when _slow_bcrypt is first used.

#=========================================================
#OpenBSD's BCrypt
#=========================================================
class BCrypt(CryptHandlerHelper):
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

    setting_kwds = ("salt", "rounds")

    salt_bytes = 16
    checksum_bytes = 24
    secret_chars = 72

    salt_chars = 22

    default_rounds = 12
    min_rounds = 4 # pybcrypt won't take less than this
    max_rounds = 31 # 32-bit limitation on 1<<rounds

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

    #=========================================================
    #frontend
    #=========================================================

    @classmethod
    def identify(cls, hash):
        "identify bcrypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def parse(cls, hash):
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid bcrypt hash"
        ident, rounds, salt, chk = m.group("ident", "rounds", "salt", "chk")
        return dict(
            ident=ident,
            rounds=int(rounds),
            salt=salt,
            checksum=chk,
        )

    @classmethod
    def encrypt(cls, secret, salt=None, rounds=None):
        """encrypt using bcrypt.

        In addition to the normal options that :meth:`CryptHandler.encrypt` takes,
        this function also accepts the following:

        :param rounds:
            Optionally specify the number of rounds to use
            (technically, bcrypt will actually use ``2**rounds``).
            This can be one of "fast", "medium", "slow",
            or an integer in the range 4..31.

            See :attr:`CryptHandler.has_named_rounds` for details
            on the meaning of "fast", "medium" and "slow".
        """
        salt = cls._norm_salt(salt)
        rounds = cls._norm_rounds(rounds)
        config = "$2a$%d$%s" % (rounds, salt)
        return bcrypt.hashpw(secret, config)

    @classmethod
    def verify(cls, secret, hash):
        "verify bcrypt hash"
        if not cls.identify(hash):
            raise ValueError, "not a bcrypt hash"
        return bcrypt.hashpw(secret, hash) == hash

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(BCrypt)

#=========================================================
# eof
#=========================================================
