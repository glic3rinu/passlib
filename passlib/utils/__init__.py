"""passlib utility functions"""
#=================================================================================
#imports
#=================================================================================
#core
from functools import update_wrapper
from hashlib import sha256
import logging; log = logging.getLogger(__name__)
import os
import sys
import random
import time
import warnings
#site
#pkg
#local
__all__ = [
    #decorators
    "classproperty",
    "abstractmethod",
    "abstract_class_property",

    #byte manipulation
    "bytes_to_list",
    "list_to_bytes",
    "xor_bytes",

    #hash64 encoding
    'h64_validate',
]
#=================================================================================
#decorators
#=================================================================================
class classproperty(object):
    """Decorator which acts like a combination of classmethod+property (limited to read-only)"""

    def __init__(self, func):
        self.im_func = func

    def __get__(self, obj, cls):
        return self.im_func(cls)

def abstractmethod(func):
    """Method decorator which indicates this is a placeholder method which
    should be overridden by subclass.

    If called directly, this method will raise an :exc:`NotImplementedError`.
    """
    msg = "object %(self)r method %(name)r is abstract, and must be subclassed"
    def wrapper(self, *args, **kwds):
        text = msg % dict(self=self, name=wrapper.__name__)
        raise NotImplementedError(text)
    update_wrapper(wrapper, func)
    return wrapper

def abstract_class_method(func):
    """Class Method decorator which indicates this is a placeholder method which
    should be overridden by subclass.

    If called directly, this method will raise an :exc:`NotImplementedError`.
    """
    msg = "class %(cls)r method %(name)r is abstract, and must be subclassed"
    def wrapper(cls, *args, **kwds):
        text = msg % dict(cls=cls, name=wrapper.__name__)
        raise NotImplementedError(text)
    update_wrapper(wrapper, func)
    return classmethod(wrapper)

Undef = object() #singleton used as default kwd value in some functions

#=================================================================================
#numeric helpers
#=================================================================================

#XXX: rename 'bytes' kwd for py30 compat purposes

def list_to_bytes(value, bytes=None, order="big"):
    """Returns a multi-character string corresponding to a list of byte values.

    This is similar to :func:`int_to_bytes`, except that this a list of integers
    instead of a single encoded integer.

    :arg value:
        The list of integers to encode.
        It must be true that ``all(elem in range(0,256)) for elem in value``,
        or a ValueError will be raised.

    :param bytes:
        Optionally, the number of bytes to encode to.
        If specified, this will be the length of the returned string.

    :param order:
        Byte ordering: "big", "little", "native".
        The default is "big", since this the common network ordering,
        and "native" as the default would present poor cross-platform predictability.

    :returns:
        The number encoded into a string, according to the options.

    Usage Example::

        >>> from passlib.util import list_to_bytes, bytes_to_list
        >>> list_to_bytes([4, 210], 4)
        '\\x00\\x00\\x04\\xd2'

        >>> list_to_bytes([4, 210], 4, order="little")
        '\\xd2\\x04\\x00\\x00'

        >>> bytes_to_list('\\x00\\x00\\x04\\xd2')
        [4, 210]
    """
    #make sure all elements have valid values
    if any( elem < 0 or elem > 255 for elem in value):
        raise ValueError, "value must be list of integers in range(0,256): %r" % (value,)

    #validate bytes / upper
    if bytes is None:
        bytes = len(value)
        if bytes == 0:
            raise ValueError, "empty list not allowed"
    else:
        if bytes < 1:
            raise ValueError, "bytes must be None or >= 1: %r" % (bytes,)
        if len(value) > bytes:
            raise ValueError, "list too large for number of bytes: bytes=%r len=%r" % (bytes, len(value))

    #encode list in big endian mode
    out = ''.join( chr(elem) for elem in value )
    pad = bytes-len(out)

    #pad/reverse as needed for endianess
    if order == "native":
        order = sys.byteorder
    if order == "big":
        if pad:
            out = ('\x00' * pad) + out
    else:
        assert order == "little"
        if pad:
            out = out[::-1] + ('\x00' * pad)
        else:
            out = out[::-1]
    return out

def bytes_to_list(value, order="big"):
    """decode a string into a list of numeric values representing each of it's bytes.

    This is similar to :func:`bytes_to_int`, the options and results
    are effectively the same, except that this function
    returns a list of numbers representing each byte in sequence,
    with most significant byte listed first.

    :arg value:
        The string to decode.
    :param order:
        The byte ordering, defaults to "big".
        See :func:`int_to_bytes` for more details.

    :returns:
        The decoded list of byte values.
    """
    if order == "native":
        order = sys.byteorder
    if order == "big":
        return [ ord(c) for c in value ]
    else:
        assert order == "little"
        return [ ord(c) for c in reversed(value) ]

_join = "".join
def xor_bytes(left, right):
    "bitwise-xor two byte-strings together"
    return _join(chr(ord(l) ^ ord(r)) for l, r in zip(left, right))

#=================================================================================
#misc
#=================================================================================
def norm_rounds(value, default, presets):
    """helper for validating & normalizing hash 'rounds' parameter
    """
    assert isinstance(default, int)
    if isinstance(value, int):
        return value
    if value is not None:
        if value in presets:
            return presets[value]
        log.warning("unknown preset round name: %r", value)
    return default

#=================================================================================
#randomness
#=================================================================================

#-----------------------------------------------------------------------
# setup rng for generating salts
#-----------------------------------------------------------------------

#NOTE:
# generating salts (eg h64_gensalt, below) doesn't require cryptographically
# strong randomness. it just requires enough range of possible outputs
# that making a rainbow table is too costly.
# so python's builtin merseen twister prng is used, but seeded each time
# this module is imported, using a couple of minor entropy sources.

try:
    os.urandom(1)
    has_urandom = True
except NotImplementedError:
    has_urandom = False

def genseed(value=None):
    "generate prng seed value from system resources"
    text = "%s %s %s %.15f %s" % (
        value,
            #if user specified a seed value (eg current rng state), mix it in

        os.getpid(),
            #add current process id

        id(object()),
            #id of a freshly created object.
            #(at least 2 bytes of which are hard to predict)

        time.time(),
            #the current time, to whatever precision os uses

        os.urandom(16) if has_urandom else 0,
            #if urandom available, might as well mix some bytes in.
        )
    #hash it all up and return it as int
    return long(sha256(text).hexdigest(), 16)

rng = random.Random(genseed())

#NOTE: to reseed rng: rng.seed(genseed(rng.getrandbits(32*8)))

#-----------------------------------------------------------------------
# some rng helpers
#-----------------------------------------------------------------------

def getrandbytes(rng, count):
    """return string of *count* number of random bytes, using specified rng"""
    #NOTE: would be nice if this was present in stdlib Random class

    ###just in case rng provides this (eg our SystemRandom subclass above)...
    ##meth = getattr(rng, "getrandbytes", None)
    ##if meth:
    ##    return meth(count)

    #XXX: break into chunks for large number of bits?
    value = rng.getrandbits(count<<3)
    buf = StringIO()
    for i in xrange(count):
        buf.write(chr(value & 0xff))
        value //= 0xff
    return buf.getvalue()

def getrandstr(rng, alphabet, count):
    """return string of *size* number of chars, whose elements are drawn from specified alphabet"""
    #check alphabet & count
    if count < 0:
        raise ValueError, "count must be >= 0"
    letters = len(alphabet)
    if letters == 0:
        raise ValueError, "alphabet must not be empty"
    if letters == 1:
        return alphabet * count

    #get random value, and write out to buffer
    #XXX: break into chunks for large number of letters?
    value = rng.randrange(0, letters**count)
    buf = StringIO()
    for i in xrange(count):
        buf.write(alphabet[value % letters])
        value //= letters
    assert value == 0
    return buf.getvalue()

#=================================================================================
# "hash64" encoding helpers
#
# many of the password hash algorithms in this module
# use a encoding that maps chunks of 3 bytes ->
# chunks of 4 characters, in a manner similar (but not compatible with) base64.
#
# this encoding system appears to have originated with unix-crypt,
# but is used by md5-crypt, sha-xxx-crypt, and others.
# this encoded is referred to (within passlib) as hash64 encoding,
# due to it's use of a strict set of 64 ascii characters.
#
# notably, bcrypt uses the same scheme, but with a different
# ordering of the characters. bcrypt hashes cannot be decoded properly
# with the following rountines (though h64_gensalt & h64_validate work fine)
#
#=================================================================================

H64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def generate_h64_salt(count):
    "return base64 salt containing specified number of characters"
    return getrandstr(rng, H64_CHARS, count)

def validate_h64_salt(value, count):
    "validate base64 encoded salt is of right size & charset"
    if not value:
        raise ValueError, "no salt specified"
    if len(value) != count:
        raise ValueError, "salt must have %d chars: %r" % (count, value)
    for c in value:
        if c not in H64_CHARS:
            raise ValueError, "invalid %r character in salt: %r" % (c, value)
    return True

##def norm_h64_salt(value, count):
##    "validate salt if provided, generate one if not provided"
##    if value:
##        validate_h64_salt(value, count)
##        return value
##    return generate_h64_salt(count)

def h64_encode_3_offsets(buffer, o1, o2, o3):
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
    return  H64_CHARS[v1&0x3F] + \
            H64_CHARS[((v2&0x0F)<<2) + (v1>>6)] + \
            H64_CHARS[((v3&0x03)<<4) + (v2>>4)] + \
            H64_CHARS[v3>>2]

def h64_encode_2_offsets(buffer, o1, o2):
    "do hash64 encode of two bytes at specified offsets in buffer; 2 missing msg set null; returns 3 chars"
    v1 = ord(buffer[o1])
    v2 = ord(buffer[o2])
    return  H64_CHARS[v1&0x3F] + \
            H64_CHARS[((v2&0x0F)<<2) + (v1>>6)] + \
            H64_CHARS[(v2>>4)]

def h64_encode_1_offset(buffer, o1):
    "do hash64 encode of single byte at specified offset in buffer; 4 missing msb set null; returns 2 chars"
    v1 = ord(buffer[o1])
    return H64_CHARS[v1&0x3F] + H64_CHARS[v1>>6]

#old code, not used anymore...
###reverse map of char -> value
##CHARIDX = dict( (c,i) for i,c in enumerate(CHARS))
##def _enc64(value, offset=0, num=False):
##    if num:
##        x, y, z = value[offset], value[offset+1], value[offset+2]
##    else:
##        x, y, z = ord(value[offset]), ord(value[offset+1]), ord(value[offset+2])
##    #xxxxxx xxyyyy yyyyzz zzzzzz
##    #aaaaaa bbbbbb cccccc dddddd
##    a = (x >> 2) # x [8..3]
##    b = ((x & 0x3) << 4) + (y>>4) # x[2..1] + y [8..5]
##    c = ((y & 0xf) << 2) + (z>>6) #y[4..1] + d[8..7]
##    d = z & 0x3f
##    return CHARS[a] + CHARS[b] + CHARS[c] + CHARS[d]
##
##def _dec64(value, offset=0, num=False):
##    a, b, c, d = CHARIDX[value[offset]], CHARIDX[value[offset+1]], \
##        CHARIDX[value[offset+2]], CHARIDX[value[offset+3]]
##    #aaaaaabb bbbbcccc ccdddddd
##    #xxxxxxxx yyyyyyyy zzzzzzzz
##    x = (a<<2) + (b >> 4) #a[6..1] + b[6..5]
##    y = ((b & 0xf) << 4) + (c >> 2) #b[4..1] + c[6..3]
##    z = ((c & 0x3) << 6) + d #c[2..1] + d[6..1]
##    if num:
##        return x, y, z
##    return chr(x) + chr(y) + chr(z)
##
##def h64_encode(value, pad=False, num=False):
##    "encode string of bytes into hash64 format"
##    if num:
##        value = list(value)
##    #pad value to align w/ 3 byte chunks
##    x = len(value) % 3
##    if x == 2:
##        if num:
##            value += [0]
##        else:
##            value += "\x00"
##        p = 1
##    elif x == 1:
##        if num:
##            value += [0, 0]
##        else:
##            value += "\x00\x00"
##        p = 2
##    else:
##        p = 0
##    assert len(value) % 3 == 0
##    out = "".join( _enc64(value, offset, num=num) for offset in xrange(0, len(value), 3))
##    assert len(out) % 4 == 0
##    if p:
##        if pad:
##            out = out[:-p] + "=" * p
##        else:
##            out = out[:-p]
##    return out
##
##def h64_decode(value, pad=False, num=False):
##    "decode string of bytes from hash64 format"
##    if value.endswith("="):
##        assert len(value) % 4 == 0, value
##        if value.endswith('=='):
##            p = 2
##            value = value[:-2] + '..'
##        else:
##            p = 1
##            value = value[:-1] + '.'
##    else:
##        #else add padding if needed
##        x = len(value) % 4
##        if x == 0:
##            p = 0
##        elif pad:
##            raise ValueError, "size must be multiple of 4"
##        elif x == 3:
##            p = 1
##            value += "."
##        elif x == 2:
##            p = 2
##            value += ".."
##        elif x == 1:
##            p = 3
##            value += "..."
##    assert len(value) % 4 == 0, value
##    if num:
##        out = []
##        for offset in xrange(0, len(value), 4):
##            out.extend(_dec64(value, offset, num=True))
##    else:
##        out = "".join( _dec64(value, offset) for offset in xrange(0, len(value), 4))
##    assert len(out) % 3 == 0
##    if p: #strip out garbage chars
##        out = out[:-p]
##    return out

#=================================================================================
#eof
#=================================================================================
