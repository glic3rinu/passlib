"""bps.rng - random generators"""
#================================================================
#imports
#================================================================
#core
from hashlib import sha512
import logging; log = logging.getLogger(__name__)
import os
import random as _random
#site
try:
    bytes
except NameError:
    bytes = str
#local
__all__ = [
    'random',
    'srandom',
    'drandom',
]

#check if we have urandom support
try:
    os.urandom(1)
    has_urandom = True
except NotImplementedError:
    has_urandom = False

#calibrate the precision of the host's time
##    tick = time.time()
##    #FIXME: ~ 1/10 chance we'll miss last digit this way, 1/100 the 2nd to last, etc
##    # would love a way to properly interrogate the time (or sys) module for this info.
##    mag = 1
##    while tick != int(tick):
##        mag *= 2
##        tick *= 2
##    #NOTE: log(mag,2) gives precision in bits


#================================================================
#more random methods
#================================================================
class BaseRandom(_random.Random):
    """enhances builtin PRNG with extra features"""
##    state_bits = 19937 #approx bits of state in generator

    #================================================================
    #prng enhancements
    #================================================================
    def reseed(self):
        """attempt to scramble PRNG state by adding in entropy from time & other sources"""
        self.jumpahead(self.genseed())

    def genseed(self):
        """generate a good random seed value from a number of entropy sources.

        .. note:
            While this function returns 64 byte integer,
            the sources it draws from have maybe 32-42 bits worth of new entropy.
            Since python's prng has 19937 bits worth of state,
            this is probably barely enough to reseed with effective randomness,
            and really, more sources should be found.
        """
        #want to scramble the prng as best as possible...
        #do this by gathering together all the entropy we can,
        #ordering the least-predictable information first,
        #and then run it through sha512.

        t = threading.current_thread()
        #NOTE: entropy estimated below are relative to an attacker
        # who is on the same system, with another process running,
        # but who is not able to access the internal state of _this_ process.
        # this is all very heuristic and ugly, but you don't have urandom,
        # do you? so we going to do our best...
        #
        #NOTE: characters are put in string w/ most predictabile chars at start,
        # then string is reversed and digested
        text = "%x\x00%s\x00%x\x00%s\x00%x\x00%.15f" % (
                    os.getpid(),
                        #the current pid, for the heck of it

                    t.name,
                    id(t),
                        #id and name of current thread, for thread-uniqueness

                    self.getrandbytes(32),
                        #feed a little from existing generator
                        #just added to help mix things up.

                    id(object()),
                        #id of a freshly created object, to make timing attacks
                        #just a little harder
                        #at least 16 bits of useful entropy

                    time.time(),
                        #the current time, for some tasty entropy.
                        #about 16 bits of useful entropy
                    )
##        print repr(text)
        return int(sha512(text[::-1]).hexdigest(), 16) # 64 byte long, < 4 bytes new entropy :(

    #================================================================
    #extra methods usuable by all rngs
    #================================================================
    def getrandbytes(self, size):
        """return string of *size* number of random bytes"""
        #TODO: make this faster?
        bits = size<<3
        value = self.getrandbits(bits)
        return ''.join(
            chr((value >> offset) & 0xff)
            for offset in xrange(0, bits, 8)
            )

    def weighted_choice(self, source):
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
            pik = 1+self.randrange(0, total)
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
            pik = 1+self.randrange(0, total)
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
            pik = 1+self.randrange(0, total)
            cur = 0
            for choice, weight in source:
                cur += weight
                if cur >= pik:
                    return choice
            else:
                raise RuntimeError, "failed to sum weights correctly"

    #================================================================
    #eof
    #================================================================

#================================================================
#custom randoms
#================================================================
class SystemRandom(_random.SystemRandom, BaseRandom):
    "new SystemRandom with additional methods mixed in"
    reseed = _random.SystemRandom._stub

class DeadRandom(BaseRandom):
    "rng with no external entropy sources besides seed(), useful for predicatable unittests"
    def reseed(self):
        pass

#================================================================
#
#================================================================

#pseudo random with entropic seeding
random = BaseRandom()

#strongest random (system random if available, else prandom)
if has_urandom:
    srandom = SystemRandom()
else:
    srandom = random

#entropy-free prng for testing purposes
drandom = DeadRandom()

#================================================================
#
#================================================================
