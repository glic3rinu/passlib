"""bps.numeric -- numeric extensions for bps3.

this is mainly an extension of the 'math' library.
"""
#=========================================================
#imports
#=========================================================
#core
from __builtin__ import pow as intpow
import sys
from decimal import Decimal
from itertools import izip
trunc = int #clobbered by real implementation under py26+
from math import * #NOTE: we import everything from math so this module can act as a drop-in replacement
#pkg
from bps.meta import isnum, isseq
from bps.rng import random, srandom
#local
__all__ = [

    #numeric format conversions
    'int_to_base',
##    'base_to_int',

    'float_to_base',
##    'base_to_float',

    'int_to_roman',
    'roman_to_int',

    #byte strings
    'int_to_bytes', 'bytes_to_int',
    'list_to_bytes', 'bytes_to_list',
    'xor_bytes', 'and_bytes', 'or_bytes', 'neg_bytes', 'binop_bytes',

    #numthy
    'gcd', 'lcm', 'factors',

    #prime
    'is_prime', 'get_factors',
    'next_prime', 'prev_prime', 'iter_primes',

    #misc
    'sdivmod', 'splitfrac',
    'limit', 'avgsd', 'digits',

]

#calc bits-per-float... (usually 53)
BPF = 0
while (1+2**-BPF) > 1:
    BPF += 1

EMPTY_BYTES = ""

#=========================================================
#misc
#=========================================================
def sdivmod(x,y):
    """divmod variant which preserves sign of remainder"""
    d,r = divmod(x,y)
    if x < 0 and r > 0: #NOTE: r < 0 if x is negative Decimal instance
        d += 1
        r -= y
    return d,r

def splitfrac(v):
    "split number into integer portion and fractional portion; returns ``(int_part as int, frac_part as original type)``"
    #NOTE: this reason this is present instead of various other solutions:
    #   modf(v) - always returns (float,float); whereas it's frequently needed for int part to be integer.
    #       also, modf coerces Decimal to float, this preserves Decimal in the fractional portion
    #   divmod(v,1) or v%1 - doesn't handle negative values correctly, and int part is not integer
    #   sdivmod(v,1) - int part is not integer, and too more complex for common case
    if isinstance(v, (int,long)):
        return v, 0
    else:
        ip = trunc(v)
        return ip, v - ip

def limit(value, lower, upper):
    """constraints value to specified range.

    :arg value: value to clamp
    :arg lower: smallest value allowed
    :arg upper: largest value allowed

    :returns:
        value, if it's between lower & upper.
        otherwise returns the appropriate limit;

    Usage Example::

        >>> from bps.numeric import limit
        >>> limit(-1,0,1)
        0
        >>> limit(.5,0,1)
        .5
        >>> limit(100,0,1)
        1
    """
    if lower > upper:
        raise ValueError, "lower must be <= upper"
    if value < lower:
        return lower
    if value > upper:
        return upper
    return value

def digits(value, base=10):
    """Returns minimum number of digits required to represent value under a given base.

    :arg value: integer value to check.
    :arg base: base to count the digits for (defaults to base 10).

    :returns:
        Returns minimum number of digits needed under specified base.
        Negative numbers will be converted to positive.
        ``0`` is special-cased to always return ``1``.
        Thus this will always return a value >= 1.

    Usage Example::

        >>> from bps.numeric import digits
        >>> digits(99,10)
        2
        >>> digits(100,10)
        3
        >>> digits(7,2)
        3
        >>> digits(8,2)
        4
        >>> digits(255,16)
        2
    """
    if value == 0:
        return 1
    if value < 0: #ignore the minus sign
        value = -value
    return int(ceil(log(value+1, base)))

def avgsd(args, sample=False):
  "calc avg & std deviation of a sequence of numbers"
  if not hasattr(args, "__len__"):
      args = list(iter(args))
  if not args:
    raise IndexError, "empty list passed in"
  num = len(args)
  avg = sum(args) / float(num)
  if sample and num > 1:
      num -= 1
  sigma = sqrt(sum((x - avg)**2 for x in args) / num)
  return avg, sigma

#===================================================
#number theory functions
#===================================================
def gcd(a, b):
    """returns the greatest common divisor of the integers *a* and *b*."""
    if b < 0:
        b = -b
    while b:
        a, b = b, (a % b)
    return a

def lcm(a, b):
    """returns least common multiple of the integers *a* and *b*"""
    # lcm = abs(a*b) / gcd(a,b)
    if a == 0 and b == 0:
        return 0
    ab = a*b
    if ab < 0:
        ab = -ab
    g = gcd(a, b)
    assert ab % g == 0
    return ab//g

def factors(value):
    """return list of factor of integer *value*

    :arg value:
        The integer to factor.
        This can be negative, 0, or positive.

    :returns:
        This will return a list of prime & exponent pairs.
        For example, ``factors(48)`` would return ``[(2,4),(3,1)])``,
        signifying that ``(2**4) * (3**1) == 48``.

        Invariants:

            * All factors will be listed in ascending order,
            * All exponents will be > 0.

        Special Cases:
            * If the value is prime, a single entry will be returned,
              being ``[(value,1)]``.
            * Negative values will be made positive first.
            * The numbers 0 and 1 will return empty lists.

    Usage Example::

        >>> from bps.numeric import factors
        >>> #factors for a prime are just itself
        >>> factors(5) # 5**1
        [(5, 1)]
        >>> #factors for a larger number...
        >>> factors(104) # 2**3 * 13**1
        [(2, 3), (13, 1)]
        >>> #factors for a negative act just like the positive
        >>> factors(-10)
        [(2, 1), (5, 1)]
    """
    #TODO: find more efficient factoring algorithm

    if value < 0:
        value = -value
    if value < 2:
        return []

    #check if prime (should be quick)
    if is_prime(value):
        return [ (value, 1) ]

    #pull off prime factors as we find them
    out = []
    for prime in iter_primes():
        count = 0
        while value % prime == 0:
            value //= prime
            count += 1
        if count:
            out.append((prime, count))
            if value == 1:
                return out

#===================================================
#prime iteration
#===================================================

#the first 64 primes, for quick testing.
_small_primes = [
    2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,
    59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,
    137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,
    227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,
    ]

#---------------------------------------------------
#primality testing
#---------------------------------------------------
def is_mr_prime(value, rounds=None):
    """tests for primality using the miller-rabin test.

    :arg value:
        The value to test for primality
    :param rounds:
        The number of rounds to use.
        The chances of a false positive are ``1/(4**rounds)``.

        By default, the number of rounds will be chosen
        such that the chances of a false positive are ``1/(value**2)``,
        so the larger the prime, the more certain you can be :)

    :returns:
        ``False`` if the number is confirmed composite.
        ``True`` if the number is probably prime (w/in bounds
        set by number of rounds).
    """
    #boundary cases
    if value < 2:
        return False
    elif value == 2 or value == 3:
        return True
    elif value & 1 == 0:
        return False

    #determine number of rounds
    if rounds is None:
        #pick default number of rounds based on size of value.
        #add 2 rounds for every bit in number...
        #since prob of false positive is 4**(-rounds),
        #prob of false positive for n is 4**(-log(n,2)),
        #or (n**-2).
        rounds=max(256, int(log(value,2)))
##    max_rounds = value//4+1
##    if rounds > max_rounds:
##        rounds = max_rounds
    if rounds >= value-10:
        #run through all witnesses [2..value-1]
        rounds = value-2
        rounds_mode = 1
    else:
        #randomly pick witnesses
        rounds_mode = 0

    #find positive ints s & d s.t.
    #   (2**s)*d == value-1, with d % 2 == 1
    vone = value-1
    assert vone & 1 == 0
    s = 0
    d = vone
    while d & 1 == 0:
        d >>= 1
        s += 1
    assert d & 1
    assert s > 0
    assert (1<<s)*d == vone
    r_range = xrange(1, s)

    #test some candidates
    #TODO: prevent repetitions? deal w/ small modulus?
    randrange = random.randrange
    for i in xrange(rounds):
        #generate random candidate
        if rounds_mode == 0:
            a = randrange(2, vone)
        else:
            assert rounds_mode == 1
            a = i+2

        #check if a**d = 1 or -1 mod value
        x = intpow(a, d, value)
        if x == 1 or x == vone:
            #satisfied condition for primality witness,
            #it's not a composite witness
            #try another one
            continue

##        #just to save some speed, run fermat primality test first
##        #   if a**vone is not 1, then a**(d*2**r) will never be 1 OR -1 for any r,
##        #   so there's no point in doing mr loop, and intpow is cheaper
##        if intpow(a, vone, value) != 1:
##            return False
##        #...so now we only let primes & carmichael numbers through

        #check if a**(2**r*d) for 0<=r<=s-1, but above check already done for r=0
        for r in r_range:
            x = intpow(x, 2, value)
            if x == 1:
                #no chance it'll ever be -1, it's a composite witness
                return False
            if x == vone:
                #satisfied condition for primality witness,
                #it's not a composite witness
                #try another one
                break #break 'r' loop; continue 'i' loop
        else:
            #no chance it'll ever be -1, it's a composite witness
            return False

    #probably prime, change we're wrong is 1/4**rounds
    return True

def is_prime(value):
    """Test if integer is prime.

    .. note::
        Implementation wise, this does a quick check
        against some smaller primes, and then falls
        back to the miller-rabin test.
    """
    if value < 2:
        return False
    #do quick check for the small ones
    for prime in _small_primes:
        if value % prime == 0:
            return value == prime
    #anything up to square of last prime in list has to be prime
    if value <= prime*prime:
        return True
    #fallback to miller-rabin
    return is_mr_prime(value)

#---------------------------------------------------
#prime iteration
#---------------------------------------------------

###don't use, not cryptographically useful
##def rand_prime(bits, is_prime=is_prime, rng=srandom):
##    """generate a random prime.
##
##    :param bits:
##        the minimum number of bits,
##        s.t. ``log(prime,2) >= bits``
##
##    """
##    rng.reseed()
##    #generate odd number between 1<<(bits-1) and 1<<bits
##    cur = (rng.getrandbits(bits-1)<<1) + 1
##    while True:
##        if is_prime(cur):
##            return cur
##        cur += 2

def iter_primes(start=0, stop=None, count=None, rounds=None):
    """generator which returns sequential primes.

    :param start:
        Starting point for generating primes.
        The first value generates will be the smallest
        prime which is greater than or equal to *start*.
        This defaults to ``0``, which means
        all primes starting with ``2`` will be genereated in order.

    :param stop:
        If specified, the generator will stop
        after yeilding the largested prime which is
        strictly less than *stop*.

    :param count:
        If specified, the generator will stop
        after yielding *count* prime numbers.
        If a *stop* is also specified,
        the generator will halt on whichever
        condition is reached first.

    :param rounds:
        Optionally lock the number of rounds
        used by the Miller-Rabin test.
        This is generally not needed.

    :returns:
        A generator which will yield ascending prime numbers
        according to the parameters above.
    """
    if stop or count:
        #wrap ourselves with a counter
        idx = 0
        for prime in iter_primes(start, rounds=rounds):
            if stop and prime >= stop:
                return
            yield prime
            idx += 1
            if count and idx >= count:
                return

    #yield from small primes list to get things started
    global _small_primes
    top = _small_primes[-1]
    if start <= top:
        for prime in _small_primes:
            if prime < start:
                continue
            yield prime
        cur = prime+2
    else:
        cur = start|1
    #iterate one by one, using modified is_prime() to test
    assert cur > top
    assert cur & 1 == 1
    while True:
        for prime in _small_primes:
            if cur % prime == 0:
                break
        else:
            if is_mr_prime(cur, rounds=rounds):
                yield cur
        cur += 2

def next_prime(value, rounds=None):
    "return the smallest prime strictly greater than the specified value"
    #pick from small primes list
    top = _small_primes[-1]
    if value <= top:
        for prime in _small_primes:
            if prime <= value:
                continue
            return prime
        value = prime+2
    elif value & 1:
        value += 2
    else:
        value += 1
    #iteratoe one by one, using modified is_prime to test
    assert value > top
    assert value & 1
    while True:
        for prime in _small_primes:
            if value % prime == 0:
                break
        else:
            if is_mr_prime(value, rounds=rounds):
                return value
        value += 2

def prev_prime(value, rounds=None):
    "return the largest prime strictly less than the specified value, or ``None``"
    top = _small_primes[-1]

    #pick from small primes list
    if value <= top:
        for prime in reversed(_small_primes):
            if prime >= value:
                continue
            return prime
        assert value <= 2
        return None

    #step value down to next candidate
    if value & 1:
        value -= 2
    else:
        value -= 1
    assert value & 1
    assert value >= top

    #iteratoe one by one, until we reach top of preset list
    while value > top:
        for prime in _small_primes:
            if value % prime == 0:
                break
        else:
            if is_mr_prime(value, rounds=rounds):
                return value
        value -= 2
    return top

#=========================================================
#int <-> binary encoded string
#=========================================================
def _log256_ceil(value):
    "helper for mchr & mord"
    #FIXME: probably a nice clever way to do this w/ integer / bitshifting
    if value < 0:
        return 0
    return int(ceil(log(value, 256)))

def int_to_bytes(num, bytes=None, upper=None, order="big"):
    """Returns a multi-character string corresponding to the ordinal *num*.

    Bit String Encoding:
    This is the multi-character equivalent of :func:`chr`, with some additional features.
    It takes in a positive integer, and returns a string representation,
    packed into a specified number of bytes.

    :arg num:
        The positive integer to encode.
    :param bytes:
        Optionally, the number of bytes to encode integer into.
        If specified, this will be the length of the returned string.
        If not specified, this will default to the minimum number
        required to encode the number.
    :param upper:
        Upper bound allowed for the number.
        If not specified, but *bytes* is, upper will default
        to the largest number representable by that number of bytes.
        If num is equal to or larger than upper, a ValueError will be raised.
    :param order:
        Byte ordering: "big", "little", "native".
        The default is "big", since this the common network ordering,
        and "native" as the default would present poor cross-platform predictability.

    :returns:
        The number encoded into a string, according to the options.

    Usage Example::

        >>> from bps.numeric import bytes_to_int, int_to_bytes
        >>> int_to_bytes(1234, bytes=4)
        '\\x00\\x00\\x04\\xd2'

        >>> int_to_bytes(1234, bytes=4, order="little")
        '\\xd2\\x04\\x00\\x00'

        >>> bytes_to_int('\\x00\\x00\\x04\\xd2')
        1234
    """
    #TODO: would a "bits" keyword be useful?
    if bytes is not None:
        #encode in specified number of bytes
        if bytes < 1:
            raise ValueError, "bytes must be None or >= 1: %r" % (bytes,)
        bupper = 256**bytes
        if upper is None:
            upper = bupper
        elif upper > bupper:
            raise ValueError, "upper bound too large for number of bytes: bytes=%r upper=%r" % (bytes, upper)
    else:
        if upper is None:
            upper = num+1
        bytes = _log256_ceil(upper)
    if upper < 0:
        raise ValueError, "top must be >= 0: %r" % (upper,)
    if num < 0 or num >= upper:
        raise ValueError, "expected number between 0 and %d: %d" % (upper-1, num)
    if order == "native":
        order = sys.byteorder
    if order == "big": #encode bytes-1 byte first, 0 byte last
        itr = xrange(bytes*8-8, -8, -8)
    else: #encode 0 byte first, bytes-1 byte last
        assert order == "little"
        itr = xrange(0, bytes*8, 8)
    return EMPTY_BYTES.join(
        chr((num >> offset) & 255)
        for offset in itr
        )

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

        >>> from bps.numeric import list_to_bytes, bytes_to_list
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

def bytes_to_int(value, order="big"):
    """decode a string into an integer representation of it's binary values.

    Bit String Decoding:
    This returns a positive integer, as decoded from the string.
    This is the inverse of the :func:`int_to_bytes` function.

    :arg value:
        The string to decode.
    :param order:
        The byte ordering, defaults to "big".
        See :func:`int_to_bytes` for more details.

    :returns:
        The decoded positive integer.
    """
    if not value:
        return 0
    upper = len(value) #upper bound in bytes
    if order == "native":
        order = sys.byteorder
    if order == "big":
        itr = xrange(upper*8-8, -8, -8)
    else:
        assert order == "little"
        itr = xrange(0, upper*8, 8)
    return sum(
        ord(value[idx]) << offset
        for idx, offset in enumerate(itr)
        )

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

def _bytes_align(left, right, order):
    "helper used by xor_bytes, and_bytes, etc. to align strings"
    l = len(left)
    r = len(right)
    if l != r:
        if order is None:
            raise ValueError, "strings are not same size: %r %r" % (l, r)
        if order == "native":
            order = sys.byteorder
        if order == "big":
            #right-align strings by padding left with nulls
            if l < r:
                left = ("\x00" * (r-l)) + left
            else:
                right = ("\x00" * (l-r)) + right
        else:
            assert order == "little"
            #left-align strings by padding right with nulls
            if l < r:
                left += ("\x00" * (r-l))
            else:
                right += ("\x00" * (l-r))
        assert len(left) == len(right)
    return left, right

def binop_bytes(left, right, op, order=None):
    """perform arbitrary bit-wise logical operation on two bit strings.

    :arg left:
        left bit string
    :arg right:
        right bit string
    :arg op:
        This should be a callable with the syntax ``op(left_value,right_value) -> result_value``.
        It will be called for every byte in the two strings,
        and will be passed each byte as an integer.
        It should then return the resulting byte.

    :param order:
        This sets the byte ordering of the strings,
        which only really effects how the function deals
        with strings of different sizes.

        =============== =====================================================
        Value           Action
        --------------- -----------------------------------------------------
        ``None``        No byte ordering is specified (the default).
                        The strings must be exactly the same size,
                        or a :exc:`ValueError` will be raised.

        ``"big"``       Big-endian byte ordering.
                        If the two strings are of unequal lengths,
                        the smaller one will be right-aligned,
                        so that the least significant digits line up.
                        The resulting string will be as long as the
                        long of the two inputs.

        ``"little"``    Little-endian byte ordering.
                        If the two strings are of unequal lengths,
                        the smaller one will be left-aligned,
                        so that the least significant digits line up.
                        The resulting string will be as long as the
                        long of the two inputs.

        ``"native"``    The native byte ordering (``"little"`` or ``"big"``)
                        will be used.
        =============== =====================================================

    :returns:
        The resulting bit string
    """
    left, right = _bytes_align(left, right, order)
    return "".join(
        chr(op(ord(a), ord(b)))
        for a, b in izip(left, right)
    )

#bytes_xor
def xor_bytes(left, right, order=None):
    """XOR two bit strings together.

    This is the equivalent of ``int_to_bytes(bytes_to_int(left) ^ bytes_to_int(right))``.

    :arg left:
        The first bit string to perform the operation on.
    :arg right:
        The second bit string to perform the operation on.
    :param order:
        The byte ordering to for aligning
        strings of different sizes.
        See :func:`binop_bytes` for details.
    """
    left, right = _bytes_align(left, right, order)
    return "".join(
        chr(ord(a) ^ ord(b))
        for a, b in izip(left, right)
    )

#bytes_and
def and_bytes(left, right, order=None):
    """AND two bit strings together.

    This is the equivalent of ``int_to_bytes(bytes_to_int(left) & bytes_to_int(right))``.

    :arg left:
        The first bit string to perform the operation on.
    :arg right:
        The second bit string to perform the operation on.
    :param order:
        The byte ordering to for aligning
        strings of different sizes.
        See :func:`binop_bytes` for details.
    """
    left, right = _bytes_align(left, right, order)
    return "".join(
        chr(ord(a) & ord(b))
        for a, b in izip(left, right)
    )

#bytes_or
def or_bytes(left, right, order=None):
    """OR two bit strings together.

    This is the equivalent of ``int_to_bytes(bytes_to_int(left) | bytes_to_int(right))``.

    :arg left:
        The first bit string to perform the operation on.
    :arg right:
        The second bit string to perform the operation on.
    :param order:
        The byte ordering to for aligning
        strings of different sizes.
        See :func:`binop_bytes` for details.
    """
    left, right = _bytes_align(left, right, order)
    return "".join(
        chr(ord(a) | ord(b))
        for a, b in izip(left, right)
    )

#bytes_neg
def invert_bytes(value):
    """invert a bit string (1->0, 0->1)

    This is the equivalent of ``int_to_bytes(~bytes_to_int(value))``.
    """
    return "".join( chr(256+~ord(a)) for a in value)

#=========================================================
#counting systems
#=========================================================

#set of chars used by int_to_base()
_chars = "0123456789abcdefghijklmnopqrstuvwxyz"

def int_to_base(value, base=10, pad=0):
    """convert integer to specified base.

    The builtin python function :func:`int`
    has the option for converting integers from string
    format using a variety of bases.

    This is the inverse, which converts an integer
    into a string of the specified base.

    :arg value:
        The integer to convert
    :arg base:
        The base to use. Must be between 2 and 36, inclusive.
    :param pad:
        Optionally add zeros to left of number until string is at least ``pad``
        characters long.

    It should always be true that ``int(to_base(n,b),b) == n``.

    Usage Example::

        >>> from bps.numeric import int_to_base
        >>> int_to_base(123456789,32)
        '3lnj8l'
        >>> int('3lnj8l',32)
        123456789
        >>> int_to_base(123456789,16)
        '75bcd15'
        >>> 0x75bcd15
        123456789
    """
    if base < 2 or base > 36 or int(base) != base:
        raise ValueError, "base must be between 2 and 36, inclusive: %r" % (base,)
    if value == 0:
        return "0"
    if value < 0:
        neg = True
        value = -value
    else:
        neg = False
    out = ""
    while value > 0:
        out = _chars[ value % base ] + out
        value = int(value/base)
    if pad and len(out) < pad:
        out = ('0' * (pad-len(out))) + out
    if neg:
        out = "-" + out
    return out

base_to_int = int #convience alias for reverse of int_to_base

def float_to_base(value, base, fsize=-1, ftrim=True):
    """convert float to specified base"""
    if base < 2 or base > 36 or int(base) != base:
        raise ValueError, "base must be between 2 and 36, inclusive: %r" % (base,)
    #split into int & frac parts
    fp, ip = modf(value)
    assert int(ip) == ip
    #format int part
    text = int_to_base(int(ip), base)
    if fsize == 0:
        return text
    text += "."

    #determine default fsize
    if fsize == -1: ##or fsize == -2:
        #show digits to max system precision
        bits = BPF
        if ip:
            bits -= 1+int(floor(log(abs(ip), 2))) #account for integer bits
        if bits < 0:
            fsize = 0
        else:
            fsize = int(ceil(log(1<<bits, base))) #num digits under base
        #TODO: under fsize==-1 + ftrim,
        # could implement "pick shortest repr" algorithm
        # from py3.1
    elif fsize < -1:
        raise ValueError, "fsize must be >= -1: %r" % (fsize,)

    #scale fp up to fsize, and round it
    r, m = modf(abs(fp) * (base**fsize))
    m = int(m)
    if r >= .5:
        m += 1

    #render in reverse order
    out = ''
    for d in xrange(fsize):
        out += _chars[m % base]
        m //= base

    #trim the zeroes, reverse, and return
    if ftrim:
        out = out.lstrip("0")
        if not out:
            out = "0"
    return text + out[::-1]

#todo: base_to_float

#=========================================================
#roman numerals
#=========================================================

##def int_to_barred_roman(value):
##    """convert integer to parsed list of roman numerals,
##    suitable for rendering with overscores via post-processing.
##    """
##    #return tuple of roman numerals s.t.
##    #last string in list should have no overscore,
##    #2nd from last should have 1 overscore,
##    #3rd from last should have 2 overscores, etc.
##    out = []
##    def helper(value, bars):
##        if value >= 4000:
##            #more than 4000, got to invoke special rules
##            if value % 10000 < 4000:
##                #put the thousands w/ current bar level, since <4000
##                x = value//1000
##                helper(x - (x%10), bars+1)
##                value %= 10000
##            else:
##                #else put the thosands w/ next bar level, since >=4000
##                helper(value//1000, bars+1)
##                value %= 1000
##        if value > 0:
##            temp = int_to_roman(value)
##            out.append((temp, bars))
##    helper(value, 0)
##    return out

_roman_level = "IVXLCDM"
_roman_decimal = "IXCM"
_roman_values = dict(I=1, V=5, X=10, L=50, C=100, D=500, M=1000)
_roman_standard = [
    ('M', 1000),    ('CM', 900),    ('D', 500), ('CD', 400),
    ('C', 100),     ('XC', 90),     ('L', 50),  ('XL', 40),
    ('X', 10),      ('IX', 9),      ('V', 5),   ('IV', 4),
    ('I', 1),
    ]
_roman_additive = [
    ('M', 1000),    ('D', 500),    ('C', 100),     ('L', 50),
    ('X', 10),      ('V', 5),       ('I', 1),
    ]

def int_to_roman(value, dialect="standard"): ##, bar="~"):
    "convert integer to roman numerals"
    #disable till there's a need, and a parser...
##    if mode == "barred":
##        return "".join(
##            "".join(
##                (bar * count) + c
##                for c in elem
##            )
##            for elem, count in int_to_barred_roman(value)
##            )
    if dialect == "additive":
        pairs = _roman_additive
        max_mult = 4
    else:
        assert dialect == "standard"
        pairs = _roman_standard
        max_mult = 3
    max_value = 4*pairs[0][1]
    if value < 1:
        raise ValueError, "value too small: %r" % (value,)
    if value >= max_value:
        raise ValueError, "value too large: %r >= %r" % (value, max_value)
    out = ''
    for char, mag in pairs:
        if value >= mag:
            mult = value//mag
            assert 1 <= mult <= max_mult
                #^ thanks to 9/5/4 pairs, we shouldn't ever have mults larger
            assert mult == 1 or char in _roman_decimal
                #^ thanks to 1 pairs, 9/5/4 pairs shouldn only have 0/1 mult
            out += char * mult
            value -= mag * mult
    assert value == 0
    return out

def roman_to_int(value, strict=False):
    """convert roman numerals to integer.

    This function accepts all properly formed roman numerals (eg ``"xiv"``),
    but will also attempt grammatically incorrect strings (eg ``"iiiiv"``),
    but will reject ones which aren't interpretable as a valid positive integer (eg ``"vvx"``).
    Such invalid values will result in a ValueError.

    :param strict:
        If this is set to ``True``, the input must a a proper roman numeral.
        That is to say, the subtraction only allows for
        a single "I" before a "V" or "X", a single "X" before a "L" or "C",
        and a single "C" before a "D" or "M", and all additive letters
        must occur in decreasing value if they occur at all.
        Under strict mode, any violations of this rule will cause a ValueError.
    """
    orig = value
    value = value.strip().upper()
    if not value:
        raise ValueError, "invalid literal for int_from_roman: %r" % (orig,)
    if any(c not in _roman_level for c in value):
        raise ValueError, "invalid literal for int_from_roman: %r" % (orig,)
    if strict:
        return _strict_parse_roman(orig, value)
    else:
        return _parse_roman(orig, value, len(value)-1, 999)[1]

def _strict_parse_roman(orig, value):
    "parser used by int_from_roman"
    out = 0
    for char, mag in _roman_standard:
        if char in _roman_decimal: #only IXCM are allowed to repeat
            count = 0
            while value.startswith(char):
                if count == 4:
                    #max of 4 repetitions is allowed to permit additive style,
                    #5 is just plain too many
                    raise ValueError, "invalid synatax for int_from_roman: %r" % (orig,)
                out += mag
                value = value[len(char):]
                count += 1
        elif value.startswith(char): # VLD and the subtractive pairs can occur only once
            out += mag
            value = value[len(char):]
    if value:
        raise ValueError, "invalid syntax for int_from_roman: %r" % (orig,)
    return out

def _parse_roman(orig, value, idx, stop_level):
    "parser used by int_from_roman()"
    out = 0
    cur_level = -1
    while idx > -1:
        char = value[idx]
        level = _roman_level.find(char)
        if level >= stop_level:
            #if we hit higher level, return value and cursor
            return idx, out
        if level < cur_level:
            #if dropped down from last level, this is beginning of a substraction stanza,
            #which will last for all chars from to the left of idx (including idx),
            #until (but excluding) the first char w/ the same level as cur_level
            idx, diff = _parse_roman(orig, value, idx, cur_level)
            out -= diff
            if out < 1:
                raise ValueError, "invalid syntax for int_from_roman: %r" % (orig,)
        else:
            #else we're at old level or better
            out += _roman_values[char]
            cur_level = level
            idx -= 1
    return -1, out

#=========================================================
#misc
#=========================================================

##def iter_fibonacci():
##    yield 1
##    yield 1
##    last = 1
##    cur = 1
##    while True:
##        last, cur = cur, last+cur
##        yield cur


##def seqsum(*seqs):
##    """generate a list that contains the element-wise sum of all the sequences passed in.
##    the result will be as long as the longest sequence passed in,
##    and any shorter input sequences will be implicitly right-padded with zeros.
##    """
####    if len(seqs) == 1 and isseq(seqs[0]):
####        seqs = seqs[0]
##    if not seqs:
##        return []
##    if isnum(seqs[0]):
##        assert len(seqs) % 2 == 0
##        #assume it's a sequence of [weight1, seq1, weight2, seq2 ... ],
##        size = max(len(seq) for seq in seqs[1::2])
##        return [
##            sum(
##                seqs[col] * (
##                    seqs[col+1][idx] if idx < len(seqs[col+1]) else 0
##                )
##                for col in xrange(0, len(seqs), 2)
##            )
##            for idx in xrange(size)
##            ]
##    elif isseq(seqs[0]) and len(seqs[0]) == 2 and isseq(seqs[0][1]):
##        #assume it's a sequence of [ (weight1, seq1), (weight2, seq2) ... ],
##        size = max(len(row[1]) for row in seqs)
##        return [
##            sum(
##                weight * (seq[idx] if idx < len(seq) else 0)
##                for weight, seq in seqs
##            )
##            for idx in xrange(size)
##            ]
##    else:
##        #assume it's a sequence of [seq1, seq2...]
##        if len(seqs) == 1:
##            return list(seqs[0])
##        size = max(len(seq) for seq in seqs)
##        return [
##            sum((seq[idx] if idx < len(seq) else 0) for seq in seqs)
##            for idx in xrange(size)
##            ]

#=========================================================
#eof
#=========================================================
