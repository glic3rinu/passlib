"""passlib.utils.h64 - hash64 encoding helpers"""
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

                    "encode_bytes",
                    "encode_3_offsets",
                    "encode_2_offsets",
                    "encode_1_offset",

    "decode_int6",  "encode_int6",
    "decode_int12", "encode_int12"
    "decode_int24", "encode_int24",
    "decode_int64", "encode_int64",
    "decode_int",
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

def encode_bytes(source):
    "encode byte string to h64 format"
    #FIXME: do something much more efficient here.
    out = ''
    end = len(source)
    idx = 0
    while idx <= end-3:
        out += encode_3_offsets(source, idx, idx+1, idx+2)
        idx += 3
    if end % 3 == 1:
        out += encode_1_offset(source, idx)
        idx += 1
    elif end % 3 == 2:
        out += encode_2_offset(source, idx, idx+1)
        idx += 2
    assert idx == end
    return out

#=================================================================================
# int <-> b64 string, used by des_crypt, ext_des_crypt
#=================================================================================

def encode_int6(value):
    "encode 6 bit integer to single char of hash-64 format"
    return encode_6bit(value)

def decode_int6(value):
    "decode 1 char of hash-64 format, returning 6-bit integer"
    return decode_6bit(value)

#---------------------------------------------------------------------

def decode_int12(value):
    "decode 2 chars of hash-64 format used by crypt, returning 12-bit integer"
    try:
        return (decode_6bit(value[1])<<6)+decode_6bit(value[0])
    except KeyError:
        raise ValueError, "invalid character"

def encode_int12(value):
    "encode 2 chars of hash-64 format from a 12-bit integer"
    return  encode_6bit(value & 0x3f) + encode_6bit((value>>6) & 0x3f)

#---------------------------------------------------------------------

def decode_int24(value):
    "decode 4 chars of hash-64 format, returning 24-bit integer"
    try:
        return  decode_6bit(value[0]) +\
                (decode_6bit(value[1])<<6)+\
                (decode_6bit(value[3])<<18)+\
                (decode_6bit(value[2])<<12)
    except KeyError:
        raise ValueError, "invalid character"

def encode_int24(value):
    "encode 4 chars of hash-64 format from a 24-bit integer"
    return  encode_6bit(value & 0x3f) + \
            encode_6bit((value>>6) & 0x3f) + \
            encode_6bit((value>>12) & 0x3f) + \
            encode_6bit((value>>18) & 0x3f)

#---------------------------------------------------------------------

_RR9_1 = range(9,-1,-1)

def decode_int64(value):
    "decode 64-bit integer from 11 chars of hash-64 format"
    return decode_int(value)

def encode_int64(value):
    "encode 64-bit integer to hash-64 format, returning 11 chars"
    out = [None] * 10 + [ encode_6bit((value<<2)&0x3f) ]
    value >>= 4
    for i in _RR9_1:
        out[i] = encode_6bit(value&0x3f)
        value >>= 6
    return "".join(out)

#---------------------------------------------------------------------

def decode_int(value):
    "decode hash-64 format used by crypt into integer"
    #FORMAT: little-endian, each char contributes 6 bits,
    # char value = index in H64_CHARS string
    try:
        out = 0
        for c in reversed(value):
                out = (out<<6) + b64_decode_6bit(c)
        return out
    except KeyError:
        raise ValueError, "invalid character in string"

## def encode_int(value):

#=================================================================================
#eof
#=================================================================================
