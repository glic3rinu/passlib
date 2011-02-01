==================================================================
:mod:`passlib.hash.nthash` - Windows NT-HASH for Unix
==================================================================

.. module:: passlib.hash.nthash
    :synopsis: Windows NT-HASH for Unix

.. warning::

    This scheme is notoriously weak (since it's based on :mod:`~passlib.utils.md4`).
    Online tables exist for quickly performing pre-image attacks on this scheme.
    **Do not use** in new code.

This handler implements the Windows NT-HASH algorithm,
encoded in a format compatible with the :ref:`modular-crypt-format`.
It is found on some unix systems where the administrator has decided
to store user passwords in a manner compatible with the SMB/CIFS protocol.

It supports two identifiers, ``$3$`` and ``$NT$``, though it defaults to ``$3$``.

In addition to the normal password hash api, this module also exposes
the following method:

.. function:: raw_nthash(secret, hex=False)

    perform raw nthash calculation, returning either
    raw digest, or as lower-case hexidecimal characters.
