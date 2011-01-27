"""passlib utility functions"""
#=================================================================================
#imports
#=================================================================================
#core
from cStringIO import StringIO
from functools import update_wrapper
from hashlib import sha256
import logging; log = logging.getLogger(__name__)
import os
import sys
import random
import time
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
    'generate_h64_salt',
    'validate_h64_salt',
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

##def int_to_bytes(value, count=None, order="big"):
##    """encode a integer into a string of bytes
##
##    :arg value: the integer
##    :arg count: optional number of bytes to expose, uses minimum needed if count not specified
##    :param order: the byte ordering; "big" (the default), "little", or "native"
##
##    :raises ValueError:
##        * if count specified and integer too large to fit.
##        * if integer is negative
##
##    :returns:
##        bytes encoding integer
##    """
##
##
##def bytes_to_int(value, order="big"):
##    """decode a byte string into an integer representation of it's binary value.
##
##    :arg value: the string to decode.
##    :param order: the byte ordering; "big" (the default), "little", or "native"
##
##    :returns: the decoded positive integer.
##    """
##    if not value:
##        return 0
##    if order == "native":
##        order = sys.byteorder
##    if order == "little":
##        value = reversed(value)
##    out = 0
##    for v in value:
##        out = (out<<8) | ord(v)
##    return out

def bytes_to_int(value):
    "decode bytes as single big-endian integer"
    out = 0
    for v in value:
        out = (out<<8) | ord(v)
    return out

def int_to_bytes(value, count):
    "encode integer into single big-endian byte string"
    assert value < (1<<(8*count)), "value too large for %d bytes: %d" % (count, value)
    return ''.join(
        chr((value>>s) & 0xff)
        for s in xrange(8*count-8,-8,-8)
    )

#TODO: rename 'bytes' kwd for py30 compat purposes
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

#=================================================================================
#eof
#=================================================================================
