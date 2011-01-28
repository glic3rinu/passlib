"""passlib.utils.h64 - hash64 encoding helpers

many of the password hash algorithms in passlib
use a encoding scheme very similar to, but not compatible with,
the standard base64 encoding scheme. the main differences are that
it uses ``.`` instead of ``+``, and assigns the
characters *completely* different numeric values.

this encoding system appears to have originated with des-crypt hash,
but is used by md5-crypt, sha-256-crypt, and others.
within passlib, this encoding is referred as ``hash64`` encoding,
and this module contains various utilities functions for encoding
and decoding strings in that format.

.. note::
    It may *look* like bcrypt uses this scheme,
    when in fact bcrypt uses the standard base64 encoding scheme,
    but with ``+`` replaced with ``.``.
"""
#=================================================================================
#imports
#=================================================================================
#core
import logging; log = logging.getLogger(__name__)
#site
#pkg
#local
__all__ = [
    "CHARS",

    "decode_6bit",  "encode_6bit",

                    "encode_3_offsets",
                    "encode_2_offsets",
                    "encode_1_offset",

    "decode_int12",
    "decode_int24", "encode_int24",
                    "encode_int64",

]

#=================================================================================
#6 bit value <-> char mapping
#=================================================================================
CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#base64 char sequence
encode_6bit = CHARS.__getitem__ # int -> char

#inverse map (char->value)
_CHARIDX = dict( (c,i) for i,c in enumerate(CHARS))
decode_6bit = _CHARIDX.__getitem__ # char -> int

#=================================================================================
#encode offsets from buffer - used by md5_crypt, sha_crypt, et al
#=================================================================================
def encode_3_offsets(buffer, o1, o2, o3):
    "do hash64 encode of three bytes at specified offsets in buffer; returns 4 chars"
    #how 4 char output corresponds to 3 byte input:
    #
    #1st character: the six low bits of the first byte (0x3F)
    #
    #2nd character: four low bits from the second byte (0x0F) shift left 2
    #               the two high bits of the first byte (0xC0) shift right 6
    #
    #3rd character: the two low bits from the third byte (0x03) shift left 4
    #               the four high bits from the second byte (0xF0) shift right 4
    #
    #4th character: the six high bits from the third byte (0xFC) shift right 2
    v1 = ord(buffer[o1])
    v2 = ord(buffer[o2])
    v3 = ord(buffer[o3])
    return  encode_6bit(v1&0x3F) + \
            encode_6bit(((v2&0x0F)<<2) + (v1>>6)) + \
            encode_6bit(((v3&0x03)<<4) + (v2>>4)) + \
            encode_6bit(v3>>2)

def encode_2_offsets(buffer, o1, o2):
    "do hash64 encode of two bytes at specified offsets in buffer; 2 missing msg set null; returns 3 chars"
    v1 = ord(buffer[o1])
    v2 = ord(buffer[o2])
    return  encode_6bit(v1&0x3F) + \
            encode_6bit(((v2&0x0F)<<2) + (v1>>6)) + \
            encode_6bit((v2>>4))

def encode_1_offset(buffer, o1):
    "do hash64 encode of single byte at specified offset in buffer; 4 missing msb set null; returns 2 chars"
    v1 = ord(buffer[o1])
    return encode_6bit(v1&0x3F) + encode_6bit(v1>>6)

#=================================================================================
# int <-> b64 string, used by des_crypt, ext_des_crypt
#=================================================================================

##def decode_int(value):
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

def decode_int12(value):
    "decode 2 chars of hash-64 format used by crypt, returning 12-bit integer"
    try:
        return (decode_6bit(value[1])<<6)+decode_6bit(value[0])
    except KeyError:
        raise ValueError, "invalid character"

def decode_int24(value):
    "decode 4 chars of hash-64 format used by crypt, returning 24-bit integer"
    try:
        return  decode_6bit(value[0]) +\
                (decode_6bit(value[1])<<6)+\
                (decode_6bit(value[3])<<18)+\
                (decode_6bit(value[2])<<12)
    except KeyError:
        raise ValueError, "invalid character"

def encode_int24(value):
    "decode 2 chars of hash-64 format used by crypt, returning 12-bit integer"
    return  encode_6bit(value & 0x3f) + \
            encode_6bit((value>>6) & 0x3f) + \
            encode_6bit((value>>12) & 0x3f) + \
            encode_6bit((value>>18) & 0x3f)

_RR9_1 = range(9,-1,-1)

def encode_int64(value):
    "encode 64-bit integer to hash-64 format used by crypt, returning 11 chars"
    out = [None] * 10 + [ encode_6bit((value<<2)&0x3f) ]
    value >>= 4
    for i in _RR9_1:
        out[i] = encode_6bit(value&0x3f)
        value >>= 6
    return "".join(out)

#=================================================================================
#eof
#=================================================================================
