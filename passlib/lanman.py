"""

lanman

macintosh
D47F 3AF8 27A4 8F7D FA4F 2C1F 12D6 8CD6

08460EB13C5CA0C4CA9516712F7FED95

ntlm


lanman

C234 13A8 A1E7 665f
AAD3 B435 B514 04EE
welcome
"""
from binascii import hexlify
from bps.numeric import int_to_base
from passlib.utils._slow_des_crypt import des_encrypt_block

LM_MAGIC = "KGS!@#$%"

def lmhash(secret):
    #XXX: encoding should be oem ascii
    ns = secret.upper()[:14] + "\x00" * (14-len(secret))
    return hexlify(des_encrypt_block(expand_des_key(ns[:7]), LM_MAGIC) + des_encrypt_block(expand_des_key(ns[7:]), LM_MAGIC))

for secret, hash in [
    #hashes from http://msdn.microsoft.com/en-us/library/cc245828(v=prot.10).aspx
    ("OLDPASSWORD", "c9b81d939d6fd80cd408e6b105741864"),
    ("NEWPASSWORD", '09eeab5aa415d6e4d408e6b105741864'),
    ("welcome", "c23413a8a1e7665faad3b435b51404ee"),
    ]:

    print secret, lmhash(secret), hash == lmhash(secret)
