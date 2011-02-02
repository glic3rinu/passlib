==================================================================
:mod:`passlib.hash.phpass` - PHPass Portable Hash
==================================================================

.. module:: passlib.hash.phpass
    :synopsis: PHPass Portable Hash

This algorithm is used primarily by PHP software
which uses the `PHPass <http://www.openwall.com/phpass/>`_ library,
a PHP library similar to PassLib. The PHPass Portable Hash
is a custom password hash used by PHPass as a fallback
when none of it's other hashes are available. It's hashes
can be identified by the :ref:`modular-crypt-format` prefix
``$P$`` (or ``$H$`` in phpBB3 databases).
Due to it's reliance on MD5, and the simplistic implementation,
other hash algorithms should be used if possible.

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

Format & Algorithm
==================
An phpass portable hash string has length 34, with the format ``$P$<rounds><salt><checksum>``;
where ``<rounds>`` is a single character encoding a 6-bit integer,
``<salt>`` is an eight-character salt, and ``<checksum>`` is an encoding
of the 128 bit checksum. All values are encoded using :mod:`hash64 <passlib.utils.h64>`.

An example hash (of ``password``) is ``$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1``;
the rounds are encoded in ``8``, the salt is ``ohUJ.1sd``,
and the checksum is ``Fw09/bMaAQPTGDNi2BIUt1``.

PHPass uses a straightforward algorithm to calculate the checksum:

* an initial result is generated from the MD5 digest of the salt string + the secret.
* for ``2**rounds`` repetitions, a new result is created from the MD5 digest of the last result + the secret.
* the last result is then encoded according to the format described above.

Deviations
==========
This implementation of phpass differs from the specification:

* Unicode strings are encoded using UTF-8 before being passed into the algorithm.
  While the original code accepts passwords containing any 8-bit value,
  it has no specific policy for dealing with unicode.

References
==========
* `<http://www.openwall.com/phpass/>`_ - PHPass homepage, which describes the algorithm
