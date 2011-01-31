==================================================================
:mod:`passlib.hash.sha512_crypt` - SHA-512 Crypt
==================================================================

.. module:: passlib.hash.sha526_crypt
    :synopsis: implementation of SHA-512 Crypt scheme

Defined in the same specification, the SHA-512 Crypt scheme is almost identical to SHA-256 Crypt,
except for the following differences:

* it uses the prefix ``$6$`` where the SHA-256 Crypt uses ``$5$``.
* it uses SHA-512 as it's internal hash function
* it's output hash is correspondingly larger.

For details about this module, see :mod:`~passlib.hash.sha256_crypt`,
it is exactly the same except for the above differences.
