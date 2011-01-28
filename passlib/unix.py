"""passlib.unix
"""
#=========================================================
#import standard hash algorithms
#=========================================================
from passlib.hash import des_crypt, md5_crypt, bcrypt, sha256_crypt, sha512_crypt

#other recognizers for shadow - NullHandler for empty string (always verify) and "*" (never verify)
#also, a UnknownCryptHandler - given hash, detect if system crypt recognizes it,
# allowing for pass-through for unknown ones.

#=========================================================
#build default context objects
#=========================================================
from passlib.context import CryptContext

#default context for quick use.. recognizes common algorithms, uses SHA-512 as default
default_context = CryptContext([des_crypt, md5_crypt, bcrypt, sha256_crypt, sha512_crypt])

#some general os-context helpers (these may not match your os policy exactly, but are generally useful)
linux_context = CryptContext([ des_crypt, md5_crypt, sha256_crypt, sha512_crypt ])
bsd_context = CryptContext([ des_crypt, md5_crypt, bcrypt ])

#=========================================================
#eof
#=========================================================
