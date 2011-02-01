================================================
:mod:`passlib.utils.h64` - Hash-64 Codec helpers
================================================

.. module:: passlib.utils.h64
    :synopsis: Hash-64 Codec helpers

Many of the password hash algorithms in passlib
use a encoding scheme very similar to (but not compatible with)
the standard base64 encoding scheme. the main differences are that
it assigns the characters *completely* different numeric values compared
to base64, as well as using ``.`` instead of ``+`` in it's character set.

This encoding system appears to have originated with des-crypt hash,
but is used by md5-crypt, sha-256-crypt, and others.
within passlib, this encoding is referred as ``hash64`` encoding,
and this module contains various utilities functions for encoding
and decoding strings in that format.

.. note::
    It may *look* like bcrypt uses this scheme,
    when in fact bcrypt uses the standard base64 encoding scheme,
    but with ``+`` replaced with ``.``.

.. data:: CHARS

    The character set used by the Hash-64 format.
    A character's index in CHARS denotes it's corresponding 6-bit integer value.

.. autofunction:: encode_3_offsets
.. autofunction:: encode_2_offsets
.. autofunction:: encode_1_offset

.. autofunction:: decode_int12
.. autofunction:: encode_int12

.. autofunction:: decode_int24
.. autofunction:: encode_int24

.. autofunction:: decode_int64
.. autofunction:: encode_int64
