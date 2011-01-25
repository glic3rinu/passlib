"""passlib._slow_unix_crypt -- fallback pure-python unix crypt() implementation

This module is mainly meant as a fallback when stdlib does not supply a ``crypt`` implementation,
such as on windows systems. As such, it attempts to have a public interface
which is compatible with stdlib, so it can be used as a drop-in replacement.
"""
#=========================================================
#imports
#=========================================================
#pkg
from passlib.utils import H64_CHARS
from passlib.utils.des import mdes_encrypt_int_block
#local
__all__ = [
    "crypt",
    "raw_ext_crypt",
    "ext_crypt",
]

#=========================================================
#crypt-style base64 encoding / decoding
#=========================================================

#base64 char sequence
b64_encode_6bit = H64_CHARS.__getitem__ # int -> char

#inverse map (char->value)
CHARIDX = dict( (c,i) for i,c in enumerate(H64_CHARS))
b64_decode_6bit = CHARIDX.__getitem__ # char -> int

##def b64_to_int(value):
##    "decode hash-64 format used by crypt into integer"
##    #FORMAT: little-endian, each char contributes 6 bits,
##    # char value = index in H64_CHARS string
##    try:
##        out = 0
##        for c in reversed(value):
##                out = (out<<6) + b64_decode_6bit(c)
##        return out
##    except KeyError:
##        raise ValueError, "invalid character in string"

def b64_decode_int12(value):
    "decode 2 chars of hash-64 format used by crypt, returning 12-bit integer"
    try:
        return (b64_decode_6bit(value[1])<<6)+b64_decode_6bit(value[0])
    except KeyError:
        raise ValueError, "invalid character"

def b64_decode_int24(value):
    "decode 4 chars of hash-64 format used by crypt, returning 24-bit integer"
    try:
        return  b64_decode_6bit(value[0]) +\
                (b64_decode_6bit(value[1])<<6)+\
                (b64_decode_6bit(value[3])<<18)+\
                (b64_decode_6bit(value[2])<<12)
    except KeyError:
        raise ValueError, "invalid character"

def b64_encode_int24(value):
    "decode 2 chars of hash-64 format used by crypt, returning 12-bit integer"
    return  b64_encode_6bit(value & 0x3f) + \
            b64_encode_6bit((value>>6) & 0x3f) + \
            b64_encode_6bit((value>>12) & 0x3f) + \
            b64_encode_6bit((value>>18) & 0x3f)

def b64_encode_int64(value):
    "encode 64-bit integer to hash-64 format used by crypt, returning 11 chars"
    out = [None] * 10 + [ b64_encode_6bit((value<<2)&0x3f) ]
    value >>= 4
    for i in RR9_1:
        out[i] = b64_encode_6bit(value&0x3f)
        value >>= 6
    return "".join(out)

#=========================================================
#crypt frontend
#=========================================================
def _crypt_secret_to_key(secret):
    key_value = 0
    for i, c in enumerate(secret[:8]):
        key_value |= (ord(c)&0x7f) << (57-8*i)
    return key_value

def crypt(secret, config):
    "encrypt string using unix-crypt (des) algorithm"
    #parse config
    if not config or len(config) < 2:
        raise ValueError, "invalid salt"

    salt = config[:2]
    try:
        salt_value = b64_decode_int12(salt)
    except ValueError:
        raise ValueError, "invalid chars in salt"
    #FIXME: ^ this will throws error if bad salt chars are used
    # whereas linux crypt does something (inexplicable) with it

    #validate secret
    if '\x00' in secret:
        #builtin linux crypt doesn't like this, so we don't either
        #XXX: would make more sense to raise ValueError, but want to be compatible w/ stdlib crypt
        raise ValueError, "secret must be string without null bytes"

    #XXX: doesn't match stdlib, but just to useful to not add in
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #convert secret string into an integer
    key_value = _crypt_secret_to_key(secret)

    #run data through des using input of 0
    result = mdes_encrypt_int_rounds(key_value, 0, salt=salt_value, rounds=25)

    #run h64 encode on result
    return salt + b64_encode_int64(result)

#=========================================================
#ext crypt frontend
#=========================================================
def raw_ext_crypt(secret, salt, rounds):
    "ext_crypt() helper which returns checksum only"

    #decode salt
    try:
        salt_value = b64_decode_int24(salt)
    except ValueError:
        raise ValueError, "invalid salt"

    #validate secret
    if '\x00' in secret:
        #builtin linux crypt doesn't like this, so we don't either
        #XXX: would make more sense to raise ValueError, but want to be compatible w/ stdlib crypt
        raise ValueError, "secret must be string without null bytes"

    #XXX: doesn't match stdlib, but just to useful to not add in
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #convert secret string into an integer
    key_value = _crypt_secret_to_key(secret)
    while len(secret) > 8:
        secret = secret[8:]
        key_value = mdes_encrypt_rounds(key_value, key_value, salt=0, rounds=1)
        for i,c in enumerate(secret[:8]):
            key_value ^= (ord(c)&0x7f)<<(57-8*i)

    #run data through des using input of 0
    result = mdes_encrypt_int_rounds(key_value, 0, salt=salt_value, rounds=rounds)

    #run h64 encode on result
    return b64_encode_int64(result)

def ext_crypt(secret, config):
    "perform extended unix crypt (BSDi's 3DES modification of crypt)"
    if not config or len(config) < 5 or not config.startswith("_"):
        raise ValueError, "invalid config string"
    try:
        rounds = b64_decode_int24(config[1:5])
    except ValueError:
        raise ValueError, "invalid rounds specification"
    salt = config[5:9]
    return config[:9] + raw_ext_crypt(secret, salt, rounds)

#=========================================================
#eof
#=========================================================
