===================================================================
:mod:`passlib.hash.sha512_crypt` - SHA-512 Crypt password hash
===================================================================

.. module:: passlib.hash.sha512_crypt
    :synopsis: SHA-512 Crypt

This scheme is identical to :mod:`~passlib.hash.sha256_crypt` in almost every way,
they are defined by the same specification and have the same design and structure,
except the following differences:

* it uses the prefix ``$6$`` where the SHA-256 Crypt uses ``$5$``.
* it uses SHA-512 as it's internal hash function instead of SHA-256.
* it's output hash is correspondingly larger.

For details about this module, see :mod:`~passlib.hash.sha256_crypt`.
