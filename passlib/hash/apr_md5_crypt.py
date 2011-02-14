"""passlib.hash.apr_md5_crypt - Apache variant of md5-crypt algorithm"""
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
from passlib.utils import autodocument
#pkg
from passlib.hash.md5_crypt import Md5Crypt, raw_md5_crypt
#local
__all__ = [
    "AprMd5Crypt",
]

class AprMd5Crypt(Md5Crypt):
    #NOTE: this shares *everything* with md5 crypt, except a minor changes.

    name = "apr_md5_crypt"

    _pat = re.compile(r"""
        ^
        \$apr1
        \$(?P<salt>[A-Za-z0-9./]{,8})
        (\$(?P<chk>[A-Za-z0-9./]{22})?)?
        $
        """, re.X)

    @classmethod
    def identify(cls, hash):
        return bool(hash) and hash.startswith("$apr1$")

    def to_string(self):
        return "$apr1$%s$%s" % (self.salt, self.checksum or '')

    #NOTE: this doesn't need the backend framework at all,
    # but md5_crypt does, and we subclass it.

    backends = ("builtin",)
    _has_backend_os_crypt = False

    def _calc_checksum_builtin(self, secret):
        #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return raw_md5_crypt(secret, self.salt, apr=True)

autodocument(AprMd5Crypt)
register_crypt_handler(AprMd5Crypt)
#=========================================================
#eof
#=========================================================
