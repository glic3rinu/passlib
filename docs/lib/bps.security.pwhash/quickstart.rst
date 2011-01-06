========================================
:mod:`bps.security.pwhash` - Quick Start
========================================

.. currentmodule:: bps.security.pwhash

Usage Example
=============
In order to get off the ground quickly, here's an
example of how to quickly encrypt and verify passwords
without having to delve too deeply into this module::

    >>> from bps.security import pwhash

    >>> #encrypt password using strongest algorithm defined by this module
    >>> hash = pwhash.encrypt("too many secrets")
    >>> hash
    $6$rounds=39000$DNnCxm85LEP1WXUh$IVkALQeSuhr2hcUV90Tv8forzli3K.XwX.1JzPjgwltgvCAgllN3x1jNpG9E1C8IQPm0gEIesqATDyKh/nEnh0'

    >>> #verify password against hash
    >>> pwhash.verify("mypass", hash)
    False
    >>> pwhash.verify("too many secrets", hash)
    True

    >>> #identify the algorithm used in a hash
    >>> pwhash.identify(hash)
    'sha512-crypt'

    >>> #choose a specific algorithm to use (instead of the default)
    >>> hash2 = pwhash.encrypt("too many secrets", alg="bcrypt")
    '$2a$11$unZuTsMEjeo5mqFX6rmRduQPBDx9t3djd2voi9W.oFhUDQu1NNMcW'

    >>> #check if we used right algorithm
    >>> pwhash.identify(hash2)
    'bcrypt'

    >>> #the hash type is autodetected by verify
    >>> pwhash.verify("too many secrets", hash2)
    True

Frontend Functions
==================
.. autofunction:: encrypt
.. autofunction:: verify
.. autofunction:: identify
