=============================================================
:mod:`passlib.utils.pbkdf2` - PBKDF2 key derivation algorithm
=============================================================

.. module:: passlib.utils.pbkdf2
    :synopsis: PBKDF2 key derivation algorithm

This module provides a single function, :func:`pbkdf2`,
which provides the ability to generate an arbitrary
length key using the PBKDF2 key derivation algorithm,
as specified in `rfc 2898 <http://tools.ietf.org/html/rfc2898>`_.
This function can be helpful in creating password hashes
using schemes which have been based around the pbkdf2 algorithm.

.. autofunction:: pbkdf2
