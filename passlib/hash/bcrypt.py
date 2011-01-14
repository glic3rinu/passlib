"""passlib.hash.bcrypt"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement, absolute_import
#core
import inspect
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.util import classproperty, abstractmethod, is_seq, srandom, H64, HashInfo
from passlib.hash.base import CryptAlgorithm
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
    #fall back to our slow pure-python implementation
    import passlib.hash._slow_bcrypt as bcrypt
    backend = "builtin"

#=========================================================
#OpenBSD's BCrypt
#=========================================================
class BCrypt(CryptAlgorithm):
    """Implementation of OpenBSD's BCrypt algorithm.

    BPS will use the py-bcrypt package if it is available,
    otherwise it will fall back to a slower pure-python implementation
    that is builtin.

    .. automethod:: encrypt
    """
    #=========================================================
    #algorithm info
    #=========================================================
    name = "bcrypt"
    salt_bytes = 16
    hash_bytes = 24
    secret_chars = 55

    has_rounds = True

    #current recommended default rounds for blowfish
    # last updated 2009-7-6 on a 2ghz system
    default_rounds = "medium"
    round_presets = dict(
        fast = 12, # ~0.25s
        medium = 13, # ~0.82s
        slow = 14, # ~ 1.58s
    )

    #=========================================================
    #frontend
    #=========================================================
    _pat = re.compile(r"""
        ^
        \$(?P<alg>2[a]?)
        \$(?P<rounds>\d+)
        \$(?P<salt>[A-Za-z0-9./]{22})
        (?P<chk>[A-Za-z0-9./]{31})?
        $
        """, re.X)

    @classmethod
    def identify(self, hash):
        "identify bcrypt hash"
        if hash is None:
            return False
        return self._pat.match(hash) is not None

    @classmethod
    def _parse(self, hash):
        "parse bcrypt hash"
        m = self._pat.match(hash)
        if not m:
            raise ValueError, "invalid bcrypt hash/salt"
        alg, rounds, salt, chk = m.group("alg", "rounds", "salt", "chk")
        return HashInfo(alg, salt, chk, rounds=int(rounds), source=hash)

    @classmethod
    def encrypt(self, secret, hash=None, keep_salt=False, rounds=None):
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
        #XXX: could probably remove a bunch of this.
        #validate salt
        if hash:
            rec = self._parse(hash)
            if rounds is None:
                rounds = rec.rounds
        #generate new salt
        if hash and keep_salt:
            salt = hash
        else:
            rounds = self._resolve_preset_rounds(rounds)
            salt = bcrypt.gensalt(rounds)
        #encrypt secret
        return bcrypt.hashpw(secret, salt)

    @classmethod
    def verify(self, secret, hash):
        "verify bcrypt hash"
        return bcrypt.hashpw(secret, hash) == hash

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
# eof
#=========================================================
