"""passlib utility functions"""
#=================================================================================
#imports
#=================================================================================
#core
from functools import update_wrapper
import logging; log = logging.getLogger(__name__)
import sys
import random
import warnings
#site
#pkg
#local
__all__ = [
    #decorators
    "classproperty",
    "abstractmethod",

    #tests
    "is_seq",
    "is_num",

    #byte manipulation
    "bytes_to_list",
    "list_to_bytes",

    #random helpers
    'srandom',
    'getrandbytes',
    'weighted_choice',
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

##def abstract_class_method

#=================================================================================
#tests
#=================================================================================
SequenceTypes = (list,tuple,set)
def is_seq(obj):
    "tests if *obj* is a known heterogenous sequence type"
    return isinstance(obj, SequenceTypes)

NumericTypes = (int, float, long) #XXX: add decimal?
def is_num(obj):
    "tests if *obj* is a known numeric type"
    return isinstance(obj, NumericTypes)

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


#=================================================================================
#pick strongest rng (SystemRandom, if available), and store in srandom
#=================================================================================
srandom = random.SystemRandom()

try:
    srandom.getrandbits(8)
    has_urandom = True
except NotImplementedError:
    warnings.warn("Your system lacks urandom support, passlib's output will be predictable")
    #XXX: should this be a critical error that halts importing?
    # for now, just providing fallback...
    # we could at least provide a way to help add some entropy for systems that need it
    srandom = random
    has_urandom = False

#=================================================================================
#random number helpers
#=================================================================================
def getrandbytes(rng, size):
    """return string of *size* number of random bytes, using specified rng"""
    #NOTE: would be nice if this was present in stdlib Random class
    #TODO: make this faster?
    bits = size<<3
    value = rng.getrandbits(bits)
    return ''.join(
        chr((value >> offset) & 0xff)
        for offset in xrange(0, bits, 8)
        )

def weighted_choice(rng, source):
    """pick randomly from a weighted list of choices.

    The list can be specified in a number of formats (see below),
    but in essence, provides a list of choices, each with
    an attached (non-negative) numeric weight. The probability of a given choice
    being selected is ``w/tw``, where ``w`` is the weight
    attached to that choice, and ``tw`` is the sum of all weighted
    in the list.

    :param source:
        weighted list of choices to select from.

        * source can be dict mapping choice -> weight.
        * source can be sequence of ``(choice,weight)`` pairs
        * source can be sequence of weights, in which case
          a given index in the sequence will be chosen based on the weight
          (equivalent too ``enumerate(source)``).

    :returns:
        The selected choice.

    .. note::
        * Choices with a weight of ``0`` will NEVER be chosen.
        * Weights should never be negative
        * If the total weight is 0, an error will be raised.
    """
    if not source:
        raise IndexError, "no choices"
    if hasattr(source, "items"):
        #assume it's a map of choice=>weight
        total = sum(source.itervalues())
        if total == 0:
            raise ValueError, "zero sum weights"
        pik = 1+rng.randrange(0, total)
        cur = 0
        for choice, weight in source.iteritems():
            cur += weight
            if cur >= pik:
                return choice
        else:
            raise RuntimeError, "failed to sum weights correctly"
        source = source.items()
    elif isinstance(source[0], (int, float, long)):
        #assume it's a sequence of weights, they just want the index
        total = sum(source)
        if total == 0:
            raise ValueError, "zero sum weights"
        pik = 1+rng.randrange(0, total)
        cur = 0
        for idx, weight in enumerate(source):
            cur += weight
            if cur >= pik:
                return idx
        else:
            raise RuntimeError, "failed to sum weights correctly"
    else:
        #assume it's a sequence of (choice,weight) pairs
        total = sum(elem[1] for elem in source)
        if total == 0:
            raise ValueError, "zero sum weights"
        pik = 1+rng.randrange(0, total)
        cur = 0
        for choice, weight in source:
            cur += weight
            if cur >= pik:
                return choice
        else:
            raise RuntimeError, "failed to sum weights correctly"

#=================================================================================
# "hash64" encoding
#=================================================================================

class H64:
    """hash64 encoding helpers.

    many of the password hash algorithms in this module
    use a encoding that maps chunks of 3 bytes ->
    chunks of 4 characters, in a manner similar (but not compatible with) base64.

    this encoding system appears to have originated with unix-crypt,
    but is used by md5-crypt, sha-xxx-crypt, and others.
    this encoded is referred to (within passlib) as hash64 encoding,
    due to it's use of a strict set of 64 ascii characters.

    notably, bcrypt uses the same scheme, but with a different
    ordering of the characters. bcrypt hashes cannot be decoded properly
    with the H64 class.
    """

    #string of all h64 chars; position in string corresponds to value encoded
    CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    @classmethod
    def randstr(cls, count, rng=srandom):
        "generate random hash64 string containing specified # of chars; usually used as salt"
        CHARS = cls.CHARS
        return ''.join(rng.choice(CHARS) for idx in xrange(count))

    @classmethod
    def encode_3_offsets(cls, buffer, o1, o2, o3):
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
        CHARS = cls.CHARS
        v1 = ord(buffer[o1])
        v2 = ord(buffer[o2])
        v3 = ord(buffer[o3])
        return  CHARS[v1&0x3F] + \
                CHARS[((v2&0x0F)<<2) + (v1>>6)] + \
                CHARS[((v3&0x03)<<4) + (v2>>4)] + \
                CHARS[v3>>2]

    @classmethod
    def encode_2_offsets(cls, buffer, o1, o2):
        "do hash64 encode of two bytes at specified offsets in buffer; 2 missing msg set null; returns 3 chars"
        CHARS = cls.CHARS
        v1 = ord(buffer[o1])
        v2 = ord(buffer[o2])
        return  CHARS[v1&0x3F] + \
                CHARS[((v2&0x0F)<<2) + (v1>>6)] + \
                CHARS[(v2>>4)]

    @classmethod
    def encode_1_offset(cls, buffer, o1):
        "do hash64 encode of single byte at specified offset in buffer; 4 missing msb set null; returns 2 chars"
        CHARS = cls.CHARS
        v1 = ord(buffer[o1])
        return CHARS[v1&0x3F] + CHARS[v1>>6]

    #old code, never used...
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
