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
from passlib.handler import ExtCryptHandler, register_crypt_handler
#pkg
#local
__all__ = [
    "BCrypt",
##    "bcrypt", "backend",
]

#=========================================================
#load bcrypt backend
#=========================================================
#fall back to our much slower pure-python implementation
from passlib.utils._slow_bcrypt import hashpw as bcrypt
backend = "builtin"

try:
    #try importing py-bcrypt, it's much faster
    from bcrypt import hashpw as bcrypt
    backend = "pybcrypt"
except ImportError:
    #check for OS crypt support before falling back to pure python version
    try:
        from crypt import crypt
    except ImportError:
        pass
    else:
        if (
            crypt("test", "$2a$04$......................") == '$2a$04$......................qiOQjkB8hxU8OzRhS.GhRMa4VUnkPty'
            and
            crypt("test", "$2$04$......................") == '$2$04$......................1O4gOrCYaqBG3o/4LnT2ykQUt1wbyju'
        ):
            def bcrypt(secret, config):
                if isinstance(secret, unicode):
                    secret = secret.encode("utf-8")
                hash = crypt(secret, config)
                if not hash.startswith("$2a$") and not hash.startswith("$2$"):
                    #means config was wrong
                    raise ValueError, "not a bcrypt hash"
                return hash
            backend = "stdlib"

#XXX: should issue warning when _slow_bcrypt is first used.

#=========================================================
#OpenBSD's BCrypt
#=========================================================
class BCrypt(ExtCryptHandler):
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
    #stats: 192 bit checksum, 128 bit salt, 2**(4..31) rounds, max 72 chars of secret

    setting_kwds = ("salt", "rounds")

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
        (?P<chk>[A-Za-z0-9./]{31})?
        $
        """, re.X)

    @classmethod
    def parse(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid bcrypt hash"
        ident, rounds, salt, chk = m.group("ident", "rounds", "salt", "chk")
        out = dict(
            rounds=int(rounds),
            salt=salt,
            checksum=chk,
        )
        if ident == '2':
            out['omit_null_suffix'] = True
        return out

    @classmethod
    def render(cls, rounds, salt, checksum=None, omit_null_suffix=False):
        if omit_null_suffix:
            out = "$2$%d$%s" % (rounds, salt)
        else:
            out = "$2a$%d$%s" % (rounds, salt)
        if checksum is not None:
            out += "$" + checksum
        return out

    #=========================================================
    #frontend
    #=========================================================
    @classmethod
    def identify(cls, hash):
        "identify bcrypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def genconfig(cls, salt=None, rounds=None, omit_null_suffix=False):
        salt = cls._norm_salt(salt)
        rounds = cls._norm_rounds(rounds)
        return cls.render(rounds, salt, None, omit_null_suffix)

    @classmethod
    def genhash(cls, secret, config):
        config = cls._norm_config(config)
        return bcrypt(secret, config)

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(BCrypt)

#=========================================================
# eof
#=========================================================
