"""passlib.unix
"""
#=========================================================
#import standard hash algorithms
#=========================================================
##import passlib.unix.des_crypt #registers "des-crypt", "ext-des-crypt" handlers
##
###XXX: passlib.unix.sun_md5 is working, but hasn't been tested much,
### so isn't imported by default.
##
###TODO: Mac OSX salted sha1 hashes  - need reference
###http://www.dribin.org/dave/blog/archives/2006/04/28/os_x_passwords_2/
##
##import passlib.unix.md5_crypt #registers "md5-crypt" handler
##import passlib.unix.bcrypt #registers "bcrypt" handler
##import passlib.unix.sha_crypt #registers "sha256-crypt" and "sha512-crypt" handlers

#other recognizers for shadow - NullHandler for empty string (always verify) and "*" (never verify)
#also, a UnknownCryptHandler - given hash, detect if system crypt recognizes it,
# allowing for pass-through for unknown ones.

#=========================================================
#build default context objects
#=========================================================
from passlib.context import CryptContext

#default context for quick use.. recognizes common algorithms, uses SHA-512 as default
default_context = CryptContext(["des-crypt", "md5-crypt", "bcrypt", "sha256-crypt", "sha512-crypt"], lazy=True)

#some general os-context helpers (these may not match your os policy exactly, but are generally useful)
linux_context = CryptContext([ "des-crypt", "md5-crypt", "sha256-crypt", "sha512-crypt" ], lazy=True)
bsd_context = CryptContext([ "des-crypt", "md5-crypt", "bcrypt" ], lazy=True)

#=========================================================
#eof
#=========================================================
