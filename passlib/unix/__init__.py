"""passlib.unix
"""
#=========================================================
#import standard hash algorithms
#=========================================================
import passlib.unix.des_crypt #registers "des-crypt", "ext-des-crypt" handlers

#TODO: support sun-md5-crypt, precursor to md5_crypt
# http://dropsafe.crypticide.com/article/1389
# http://www.cuddletech.com/blog/pivot/entry.php?id=778

#TODO: Mac OSX salted sha1 hashes  - need reference

import passlib.unix.md5_crypt #registers "md5-crypt" handler
import passlib.unix.bcrypt #registers "bcrypt" handler
import passlib.unix.sha_crypt #registers "sha256-crypt" and "sha512-crypt" handlers

#=========================================================
#build default context objects
#=========================================================
from passlib.context import CryptContext

#default context for quick use.. recognizes common algorithms, uses SHA-512 as default
default_context = CryptContext(["des-crypt", "md5-crypt", "bcrypt", "sha256-crypt", "sha512-crypt"])

#some general os-context helpers (these may not match your os policy exactly, but are generally useful)
linux_context = CryptContext([ "des-crypt", "md5-crypt", "sha256-crypt", "sha512-crypt" ])
bsd_context = CryptContext([ "des-crypt", "md5-crypt", "bcrypt" ])

#=========================================================
#eof
#=========================================================
