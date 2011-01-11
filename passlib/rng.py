"""passlib.rng - custom helpers building on top of stdlib's random

this provides a proxy object named "srandom" which is initialized
to point to system random if possible, falling back to python's prng.
a proxy object is used so applications can provide an alternate
randomness source, and all functions in passlib will use that source instead
(see :func:`set_srandom_rng`)

this module also provides some utility functions for generating random strings
(:func:`getrandstr` and :func:`getrandbytes`).
"""
#=================================================================================
#imports
#=================================================================================
#core
from binascii import hexlify as _hexlify
from cStringIO import StringIO
import logging; log = logging.getLogger(__name__)
import math
import os
import random as _random
from warnings import warn
#site
#pkg
#local
__all__ = [
    # random proxy used by passlib
    'srandom',
    'set_srandom_rng',
    
    #helper for creating Rng sources
    'StreamRandom',
##    'SystemRandom',
##    'has_urandom',
 
    #utils not part of stdlib random object   
    'getrandbytes',
    'getrandstr',
    'weighted_choice',    
]
    
#=================================================================================
#helper class for implementation other random sources (eg: SSLRandom, below)
#=================================================================================
_BYTES_PER_FLOAT = int((_random.BPF+7)//8) #number of bytes needed to generate new float
_UNUSED_BITS_PER_FLOAT = _BYTES_PER_FLOAT*8 - _random.BPF #exta bits to discard when generating float
_RECIP_BPF = _random.RECIP_BPF

class StreamRandom(_random.Random):
    """helper which provides Random subclass that pulls all data from single abstract method: getrandbytes()"""
    #NOTE: this basically clones the fallback _random.SystemRandom implementation,
    #but calls self.getrandbytes() instead of a _urandom global

    def __init__(self, getrandbytes=None):
        if getrandbytes:
            if hasattr(getrandbytes, "read"):
                getrandbytes = getrandbytes
            self.getrandbytes = getrandbytes
        super(StreamRandom, self).__init__()
    
    def getrandbytes(self, count):
        "return string containing specified number of random bytes"
        raise NotImplementedError, "getrandbytes() must be implemented by subclass or instance constructor"

    def random(self):
        """Get the next random number in the range [0.0, 1.0)."""
        #NOTE: this is just optimized version of getrandbits(_random.BPF) * _random.RECIP_BPF
        return (long(_hexlify(self.getrandbytes(_BYTES_PER_FLOAT)), 16) >> _UNUSED_BITS_PER_FLOAT) * _RECIP_BPF

    def getrandbits(self, k):
        """getrandbits(k) -> x.  Generates a long int with k random bits."""
        if k <= 0:
            raise ValueError('number of bits must be greater than zero')
        if k != int(k):
            raise TypeError('number of bits should be an integer')
        bytes = (k + 7) // 8                    # bits / 8 and rounded up
        x = long(_hexlify(self.getrandbytes(bytes)), 16)
        return x >> (bytes * 8 - k)             # trim excess bits
    
    def _notimplemented(self, *args, **kwds):
        "subclasses may implement these if they wish"
        raise NotImplementedError('%s entropy source does not have state.' % (self.__class__.__name__,))
    getstate = setstate = _notimplemented

#=================================================================================
#system random helper class
#=================================================================================

#NOTE: this is done mainly to speed up :func:`getrandbytes` calls
class SystemRandom(_random.SystemRandom):
    "subclass of random.SystemRandom which implements getrandbytes as urandom call"    
    def getrandbytes(self, count):
        return os.urandom(count)

#check if os.urandom is available
try:
    os.urandom(1)
except NotImplementedError:
    has_urandom = False
else:
    has_urandom = True
    
#=================================================================================
#setup proxy for chosen strong random source
#=================================================================================
class RandomProxy(object):
    "proxy object for RNG instances"
    def __init__(self, name, rng=None):
        self.__name = name
        self.__rng = None
        if rng:
            self.set_rng(rng)

    def __getattr__(self, attr):
        rng = self.__rng
        if rng is None:
            raise AttributeError, "attribute not found (no RNG specified for proxy %r)" % (self.__name)
        return getattr(rng, attr)
        
    def get_rng(self):
        "return rng instance currently used by this proxy object"
        return self.__rng

    def set_rng(self, source):
        """change rng source which this proxy object uses
        
        :arg source:
            replacement RNG. can be one of the following:
            
            * class or instance of :class:`random.Random` or a subclass.
            * callable which takes in byte count and returns random bytes (eg :func:``os.urandom``)
            * a stream which contains an unending source of random bytes (eg: file("/dev/urandom") on unix))
            * predefined constant "system", which uses SystemRandom - raises EnvironmentError if urandom not available
            * predefined constant "default", which resets the proxy to the rng passlib would use by default.
        """
        if isinstance(source, (str,unicode)):
            if source == "system":
                if not has_urandom:
                    raise EnvironmentError, "urandom support not available"
                source = SystemRandom
            elif source == "default":
                source = get_default_rng()
            else:
                raise ValueError, "unknown preset random source: %r" % (source,)
        if hasattr(source, "randrange"): #random class or instance
            if callable(source):
                source = source()
        elif hasattr(source, "read") or callable(source):
            source = StreamRandom(source)
        else:
            raise TypeError, "unknown random source type: %r" % (source,)
        self.__rng = source
        return source
        
    def __repr__(self):
        return "<RandomProxy %r target=%r>" % (self.__name, self.__rng)

def get_default_rng():
    "return default rng class for passlib to use"
    if has_urandom:
        return SystemRandom
    warnings.warn("Your system lacks urandom support, passlib's output will be predictable")
    #XXX: should this be a critical error that halts importing?
    # for now, just providing fallback...
    # we could at least provide a way to help add some entropy for systems that need it
    return random.Random

#proxy for whichever RNG has been selected for passlib routines to use.    
srandom = RandomProxy(name="strong random", rng="default")    

#=================================================================================
#random number helpers
#=================================================================================
def getrandbytes(rng, count):
    """return string of *count* number of random bytes, using specified rng"""
    #NOTE: would be nice if this was present in stdlib Random class
    
    #just in case rng provides this (eg our SystemRandom subclass above)...
    meth = getattr(rng, "getrandbytes", None)
    if meth:
        return meth(count)
    
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
    #XXX: break into chunks for large number of bits?
    value = rng.randrange(0, letters**count)
    buf = StringIO()
    for i in xrange(count):        
        buf.write(alphabet[value % letters])
        value //= letters
    assert value == 0
    return buf.getvalue()

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
          (equivalent to ``weighted_choice(enumerate(source))``).

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
#eof
#=================================================================================

