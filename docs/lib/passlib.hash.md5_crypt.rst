==================================================================
:mod:`passlib.hash.md5_crypt` - MD5 Crypt
==================================================================

.. module:: passlib.hash.md5_crypt
    :synopsis: MD5-Crypt

Also known as BSD-MD5-Crypt,
this algorithm was developed to replace the aging des-crypt crypt.
It is supported by a wide variety of unix flavors, and is found
in other contexts as well.

Security-wise, MD5-Crypt lacks newer features,
such as a variable number of rounds. Futhermore, the MD5 message digest
algorithm which it's based around is considered broken,
though pre-image attacks are currently only theoretical.
Despite this, MD5-Crypt itself is not considered broken,
and is still considered ok to use, though new applications
should use a strong scheme if feasible.

Usage
=====
.. todo::

    write usage instructions

Functions
=========
.. autofunction:: genconfig
.. autofunction:: genhash
.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

Format
======
This algorithm was created in parallel with
the :ref:`modular-crypt-format`, and so it uses
the identifier ``$1$`` for all of it's hashes.

An md5-crypt hash string has length 26-34, with the format ``$1$<salt>$<checksum>``;
where ``<salt>`` is 0-8 characters drawn from ``[0-9a-zA-Z./]``,
and ``<checksum>`` is 22 characters drawn from the same set.

An example hash (of ``password``) is ``$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0``.

Algorithm
=========
The algorithm used by MD5-Crypt is convoluted,
and is best described by examining the BSD implementation
linked to below.

It uses the MD5 message digest algorithm to generate
various intermediate digests based on combinations
of the secret, the salt, and some fixed constant strings.

It then performs a fixed 1000 rounds of recursive digests,
combining the secret, salt, and last digest in varying orders.

The resulting checksum is a convoluted form of
the last resulting digest, encoded in hash64.

Deviations
==========
This implementation of md5-crypt differs from others in a few ways:

* While the underlying algorithm technically allows salt strings
  to contain any possible byte value besides ``\x00`` and ``$``,
  this would conflict with many uses of md5-crypt, such as within
  unix ``/etc/shadow`` files. Futhermore, most unix systems
  will only generate salts using the standard 64 characters listed above.
  This implementation follows along with that, by strictly limiting
  salt strings to the known-good set, until counter-examples are found.

* Unicode strings are encoded using UTF-8 before being passed into the algorithm.
  While the algorithm accepts passwords containing any 8-bit value
  except for ``\x00``, as of this writing, the authors
  know of no specification defining the official behavior that should be used
  for unicode strings.

References
==========
* `<http://www.freebsd.org/cgi/cvsweb.cgi/~checkout~/src/lib/libcrypt/crypt.c?rev=1.2>` - primary reference used for information & implementation
