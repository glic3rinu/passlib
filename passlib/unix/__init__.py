"""passlib.unix
"""
#=========================================================
#import standard hash algorithms
#=========================================================
import passlib.unix.des_crypt #registers "des-crypt" handler
import passlib.unix.md5_crypt #registers "md5-crypt" handler
import passlib.unix.bcrypt #registers "bcrypt" handler
import passlib.unix.sha_crypt #registers "sha256-crypt" and "sha512-crypt" handlers

#=========================================================
#build default context objects
#=========================================================

#=========================================================
#eof
#=========================================================
