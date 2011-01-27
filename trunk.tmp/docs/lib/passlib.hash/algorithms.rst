=============================================
:mod:`passlib` - Crypt Algorithms
=============================================

.. currentmodule:: passlib

All of the crypt algorithms must inherit from :class:`CryptAlgorithm`,
which defines a common interface all algorithms must support.
You may use the algorithms directly, by creating
an instance and calling it as described in :doc:`Implementing a Crypt Algorithm <implementation>`.
However, you will normally will not need to deal with the internals of the algorithms
directly, but rather take advantage of one of the predefined algorithms,
through the :doc:`frontend functions <quickstart>` or a
custom :doc:`crypt context <contexts>`.

Standard Algorithms
===================
The following algorithms are all standard password hashing algorithms
used by various Posix operating systems over the years.

.. note::
    BPS tries to use external accelaration for these classes when possible,
    but provides a pure-python fallback so that these algorithms will
    ALWAYS be available for use.

.. autoclass:: UnixCrypt
.. autoclass:: Md5Crypt
.. autoclass:: Sha256Crypt
.. autoclass:: Sha512Crypt
.. autoclass:: BCrypt

Database Algorithms
===================
BPS also provides implementations of the hash
algorithms used by MySql and PostgreSQL.

.. autoclass:: Mysql10Crypt
.. autoclass:: Mysql41Crypt
.. autoclass:: PostgresMd5Crypt

.. data:: mysql_context

    This context object contains the algorithms used by MySql 4.1 and newer
    for storing user passwords.

.. data:: postgres_context

    This context object should be able to read/write/verify
    the values found in the password field of the pg_shadow table in Postgres.
