"""passlib.unix
"""
from passlib.base import CryptContext, register_crypt_handler
from passlib.utils.handlers import CryptHandler
#=========================================================
#helpers
#=========================================================
class DisabledHandler(CryptHandler):
    """fake crypt handler which handles special (non-hash) strings found in /etc/shadow

    unix shadow files sometimes have "!" or "*" characters indicating logins are disabled.
    linux also prepends "!" to valid hashes to indicate a password is disabled.

    this is a fake password hash, designed to recognize those values,
    and return False for all verify attempts.
    """
    name = "disabled"
    setting_kwds = ()
    context_kwds = ()

    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, config):
        return "!"

    @classmethod
    def identify(cls, hash):
        return not hash or hash == "*" or hash.startswith("!")

    @classmethod
    def verify(cls, hash):
        return False

register_crypt_handler(DisabledHandler)

#TODO: UnknownCryptHandler - given hash, detect if system crypt recognizes it,
# allowing for pass-through for unknown ones.

#=========================================================
#build default context objects
#=========================================================

#default context for quick use.. recognizes common algorithms, uses SHA-512 as default
#er... should we promote bcrypt as default
default_context = CryptContext(["disabled", "des_crypt", "md5_crypt", "bcrypt", "sha256_crypt", "sha512_crypt"])

#=========================================================
#some general os-context helpers (these may not match your os policy exactly, but are generally useful)
#=========================================================

#referencing source via -http://fxr.googlebit.com
# freebsd 6,7,8 - des, md5, bcrypt, nthash
# netbsd - des, ext, md5, bcrypt, sha1 (TODO)
# openbsd - des, ext, md5, bcrypt

#referencing linux shadow...
# linux - des,md5, sha256, sha512

linux_context = CryptContext([ "disabled", "des_crypt", "md5_crypt", "sha256_crypt", "sha512_crypt" ])
freebsd_context = CryptContext([ "disabled",  "des_crypt", "nthash", "md5_crypt", "bcrypt"])
openbsd_context = CryptContext([ "disabled",  "des_crypt", "ext_des_crypt", "md5_crypt", "bcrypt"])
netbsd_context = CryptContext([ "disabled",  "des_crypt", "ext_des_crypt", "md5_crypt", "bcrypt"])

#=========================================================
#eof
#=========================================================
