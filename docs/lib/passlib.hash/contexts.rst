=============================================
:mod:`passlib` - Crypt Contexts
=============================================

.. currentmodule:: passlib

For more complex deployment scenarios than
the frontend functions described in :doc:`Quick Start <quickstart>`,
the CryptContext class exists...

.. autoclass:: CryptContext

Predefined Contexts
===================
The following context objects are predefined by BPS:

.. data:: default_context

    This context object contains all the algorithms
    supported by BPS, listed (mostly) in order of strength.
    :func:`identify`, :func:`verify`, and :func:`encrypt`
    are all merely wrappers for this object's methods
    of the same name.

.. data:: linux_context

    This context object contains only the algorithms
    in use on modern linux systems (namely:
    unix-crypt, md5-crypt, sha512-crypt).

.. data:: bsd_context

    This context object contains only the algorithms
    in use on modern BSD systems (namely:
    unix-crypt, md5-crypt, bcrypt).
