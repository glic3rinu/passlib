=================================================================================
:mod:`passlib.hash.ext_des_crypt` - BSDi Extended DES Crypt password hash
=================================================================================

.. module:: passlib.hash.ext_des_crypt
    :synopsis: BSDi Extended Unix (DES) Crypt

This algorithm was developed by BSDi for their BSD/OS distribution.
It's based on :mod:`~passlib.hash.des_crypt`, contains many modern improvements.
Nonetheless, since it's based on DES, and still shared many of des-crypt's flaws,
it should not be used in new applications.

Usage
=====
Aside from a slight

Functions
=========

Format
======

Algorithm
=========

Deviations
==========

References
==========

but uses twice the salt bits,
a variable number of rounds, and includes all  Nonetheless, by modern standards, it's not very secure,
and should not be used in new applications.

This scheme does not follow the :ref:`modular-crypt-format`, instead
is distinguished from des-crypt and other hashes by the fact that it begins
with ``_``.

Implementation
==============
Passlib contains a pure-python implemented of this algorithm,
based on the description found at `http://fuse4bsd.creo.hu/localcgi/man-cgi.cgi?crypt+3`_,
as well as the documentation at `http://search.cpan.org/dist/Authen-Passphrase/lib/Authen/Passphrase/DESCrypt.pm`_.

.. todo::

    write documentation
