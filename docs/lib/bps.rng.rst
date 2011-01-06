=================================================
:mod:`bps.rng` -- Random Number Generation
=================================================

.. module:: bps.rng
    :synopsis: random number generation

This module is essentially just a wrapper for stdlib's
random module. It provides a few additional
methods for managing & getting random numbers,
but also provides a more useful interface
for the *type* of randomness you want.

Random Number Generators
========================
The following random number generator
instances are always available from this module:

.. data:: random

    This will be an instance of the best pseudo random number generator
    available (currently the python builtin prng), with as good
    an entropic source as is available for seeding via
    the seed() and reseed() methods.
    Use this for most non-cryptographic purposes.

.. data:: srandom

    This will be an instance of the strongest random number generator
    available on your system. It will use python's SystemRandom
    if os.urandom support is available, otherwise it will fall back
    to the same generator as prandom. This should be used
    for cryptographic purposes over the normal prng.

    .. warning::
        If urandom is present, this is dependant on the strength
        of your system's urandom implementation. If urandom is missing,
        the fallback (normal) may not have enough entropy to defend
        from attackers. To help this somewhat, it is recommended
        to call ``strong.reseed()`` before calls which will consume
        randomness for critical purposes, just to help scramble things
        as best as possible (reseed is a no-op if urandom is being used).

.. data:: drandom

    This is a variant of the *random* generator,
    except that all outside entropic
    sources are disabled, so that it's state is completely
    deteremined by the value passed into seed().

    This is mainly useful in unitests, when you need
    to reliably repeat the same results over an over.

Extra Methods
=============
In addition to the methods provided by stdlib's random module,
all the above rngs will contain the following extra methods:

.. function:: reseed()

    Unlike seed(), which attempts to set the random number generator's
    state explicitly, this method attempts to pull in outside
    entropy sources (current rng state, time, etc) to help
    randomize the state of your prng as much as possible.

    .. todo::
        In the future, need a way for app to add entropy to the system.

.. function:: getrandbytes()

.. function:: weightedchoice()
