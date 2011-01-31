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
from warnings import warn
#site
#pkg
import passlib.utils.h64
#local
__all__ = [
    #decorators
    "classproperty",
    "abstractmethod",
    "abstractclassmethod",

    #byte manipulation
    "bytes_to_list",
    "list_to_bytes",
    "xor_bytes",

    #misc helpers
    'gen_salt',
    'norm_salt',
    'norm_rounds',
]
#=================================================================================
#decorators
#=================================================================================
class classproperty(object):
    """Function decorator which acts like a combination of classmethod+property (limited to read-only properties)"""

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

def abstractclassmethod(func):
    """Class Method decorator which indicates this is a placeholder method which
    should be overridden by subclass, and must be a classmethod.

    If called directly, this method will raise an :exc:`NotImplementedError`.
    """
    msg = "class %(cls)r method %(name)r is abstract, and must be subclassed"
    def wrapper(cls, *args, **kwds):
        text = msg % dict(cls=cls, name=wrapper.__name__)
        raise NotImplementedError(text)
    update_wrapper(wrapper, func)
    return classmethod(wrapper)

Undef = object() #singleton used as default kwd value in some functions

#==========================================================
#protocol helpers
#==========================================================
def is_crypt_handler(obj):
    "check if object follows the :ref:`crypt handler api <crypt-handler-api>`"
    return all(hasattr(obj, name) for name in (
        "name",
        "setting_kwds", "context_kwds",
        "genconfig", "genhash",
        "verify", "encrypt", "identify",
        ))

##def is_crypt_context(obj):
##    "check if obj follows CryptContext api"
##    #NOTE: this isn't an exhaustive check of all required attrs,
##    #just a quick check of the most uniquely identifying ones
##    return all(hasattr(obj, name) for name in (
##        "lookup", "verify", "encrypt", "identify",
##        ))

#=================================================================================
#string helpers
#=================================================================================
def splitcomma(source):
    "split comma separated string into list elements, stripping whitespace and empty elements"
    return [
        elem.strip()
        for elem in source.split(",")
        if elem.strip()
    ]

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
    "decode string of bytes as single big-endian integer"
    out = 0
    for v in value:
        out = (out<<8) | ord(v)
    return out

def int_to_bytes(value, count):
    "encodes integer into single big-endian byte string"
    assert value < (1<<(8*count)), "value too large for %d bytes: %d" % (count, value)
    return ''.join(
        chr((value>>s) & 0xff)
        for s in xrange(8*count-8,-8,-8)
    )

#TODO: rename 'bytes' kwd for py30 compat purposes
def list_to_bytes(value, bytes=None, order="big"):
    """Returns a multi-character string corresponding to a list of byte values.

    This is similar to :func:`int_to_bytes`, except that this returns a list
    of integers, where each integer corresponds to a single byte of the input.

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

        >>> from passlib.utils import list_to_bytes, bytes_to_list
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
    "perform bitwise-xor of two byte-strings"
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
    """return byte-string containing *count* number of randomly generated bytes, using specified rng"""
    #NOTE: would be nice if this was present in stdlib Random class

    ###just in case rng provides this...
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

def getrandstr(rng, charset, count):
    """return character string containg *count* number of chars, whose elements are drawn from specified charset, using specified rng"""
    #check alphabet & count
    if count < 0:
        raise ValueError, "count must be >= 0"
    letters = len(charset)
    if letters == 0:
        raise ValueError, "alphabet must not be empty"
    if letters == 1:
        return charset * count

    #get random value, and write out to buffer
    #XXX: break into chunks for large number of letters?
    value = rng.randrange(0, letters**count)
    buf = StringIO()
    for i in xrange(count):
        buf.write(charset[value % letters])
        value //= letters
    assert value == 0
    return buf.getvalue()

#=================================================================================
#misc helpers
#=================================================================================
def norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name="this crypt"):
    """helper routine for normalizing rounds

    * falls back to :attr:`default_rounds`
    * raises ValueError if no fallback
    * clips to min_rounds / max_rounds
    * issues warnings if rounds exists min/max

    :returns: normalized rounds value
    """
    if rounds is None:
        rounds = default_rounds
        if rounds is None:
            raise ValueError, "rounds must be specified explicitly"

    if rounds > max_rounds:
        warn("%s algorithm does not allow more than %d rounds: %d" % (name, max_rounds, rounds))
        rounds = max_rounds

    if rounds < min_rounds:
        warn("%s algorithm does not allow less than %d rounds: %d" % (name, min_rounds, rounds))
        rounds = min_rounds

    return rounds

def gen_salt(count, charset=h64.CHARS):
    "generate salt string of *count* chars using specified *charset*"
    global rng
    return getrandstr(rng, charset, count)

def norm_salt(salt, min_chars, max_chars=None, charset=h64.CHARS, gen_charset=None, name="specified"):
    """helper to normalize & validate user-provided salt string

    required salt_charset & salt_chars attrs to be filled in,
    along with optional min_salt_chars attr (defaults to salt_chars).

    * generates salt if none provided
    * clips salt to maximum length of salt_chars

    :arg salt: user-provided salt
    :arg min_chars: minimum number of chars in salt
    :arg max_chars: maximum number of chars in salt (if omitted, same as min_chars)
    :param charset: character set that salt MUST be subset of (defaults to :)
    :param gen_charset: optional character set to restrict to when generating new salts (defaults to charset)
    :param name: optional name of handler, for inserting into error messages

    :raises ValueError:

        * if salt contains chars that aren't in salt_charset.
        * if salt contains less than min_salt_chars characters.

    :returns:
        resulting or generated salt
    """
    #generate one if needed
    if salt is None:
        return gen_salt(max_chars or min_chars, gen_charset or charset)

    #check character set
    for c in salt:
        if c not in charset:
            raise ValueError, "invalid character in %s salt: %r"  % (name, c)

    #check min size
    if len(salt) < min_chars:
        raise ValueError, "%s salt must be at least %d chars" % (name, min_chars)

    if max_chars is None:
        max_chars = min_chars
    if len(salt) > max_chars:
        #automatically clip things to specified number of chars
        return salt[:max_chars]
    else:
        return salt

#=================================================================================
#eof
#=================================================================================
