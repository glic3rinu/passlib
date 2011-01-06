=================================================
:mod:`bps.numeric` -- Numeric Tools
=================================================

.. module:: bps.numeric
    :synopsis: mathematical and numeric tools

Number Theory
=============
.. autofunction:: factors
.. autofunction:: gcd
.. autofunction:: lcm

Primality Testing
=================
.. autofunction:: is_prime
.. autofunction:: next_prime
.. autofunction:: prev_prime
.. autofunction:: iter_primes

Numeric Formats
===============
.. autofunction:: int_to_base
.. autofunction:: float_to_base
.. autofunction:: int_to_roman
.. autofunction:: roman_to_int

Miscellaneous Functions
=======================
.. autofunction:: sdivmod
.. autofunction:: splitfrac
.. autofunction:: avgsd
.. autofunction:: digits
.. autofunction:: limit

Bytes Strings
=============
The following functions manipulate strings
as if they were binary data, not characters.
They allow for doing bit-wise boolean operations
on strings, converting them to integers, etc.

.. note::
    When this module is converted to Python 3.0,
    these will all be operations on ``bytes``, not ``str``.

.. autofunction:: int_to_bytes
.. autofunction:: bytes_to_int
.. autofunction:: list_to_bytes
.. autofunction:: bytes_to_list
.. autofunction:: xor_bytes
.. autofunction:: or_bytes
.. autofunction:: and_bytes
.. autofunction:: invert_bytes
.. autofunction:: binop_bytes
