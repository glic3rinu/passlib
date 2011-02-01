============================================
:mod:`passlib.hash` - Password Hash Schemes
============================================

.. module:: passlib.hash
    :synopsis: package containing all builtin password hashes

This subpackage contains handlers for all the password hashes built into
passlib. As well, any third-party handlers registered using :func:`register_crypt_handler`
will be inserted into this package.

Each module within this package implements a single password hashing scheme,
and follows passlib's :ref:`password-hash-api`.
While many applications may find it easier to use a :class:`CryptContext`
instance, or retreive handlers via :func:`get_crypt_handler`, they can
also be imported and used directly from this package:

    >>> from passlib.hash import md5_crypt
    >>> hash = md5_crypt.encrypt("password")

Passlib contains the following builtin password algorithms:

Standard Unix Schemes
---------------------
All these schemes are/were used by various unix flavors to store user passwords.
Because of this, all these schemes (except des-crypt and ext-des-crypt) follow
the :ref:`modular crypt format <modular-crypt-format>`.

..
    * :mod:`~passlib.hash.des_crypt` - Legacy DES-based unix crypt() algorithm.
    * :mod:`~passlib.hash.ext_des_crypt` - Legacy BSDi extension of des-crypt which adds more salt and variable rounds.
    * :mod:`~passlib.hash.md5_crypt` - MD5-based descendant of des-crypt.
    * :mod:`~passlib.hash.bcrypt` - Blowfish-based replacement for md5-crypt, used mostly on BSD systems.
    * :mod:`~passlib.hash.sha256_crypt` - SHA-256 based descendant of MD5 crypt, used mostly on Linux systems.
    * :mod:`~passlib.hash.sha512_crypt` - SHA-512 based descendant of MD5 crypt, used mostly on Linux systems.

.. toctree::
    :maxdepth: 1

    passlib.hash.des_crypt
    passlib.hash.ext_des_crypt
    passlib.hash.md5_crypt
    passlib.hash.bcrypt
    passlib.hash.sha256_crypt
    passlib.hash.sha512_crypt

Non-Standard Unix-Compatible Schemes
------------------------------------
While most of these schemes are rarely used by any unix flavor to store user passwords,
these are compatible with the :ref:`modular crypt format <modular-crypt-format>`, and can be
used in contexts which support them, in parallel with the others following
the modular crypt format.

..
    * :mod:`~passlib.hash.apr_md5_crypt` - Apache-specific variant of md5-crypt, used in htpasswd files
    * :mod:`~passlib.hash.nthash` - Windows NT-Hash password hashApache-specific variant of md5-crypt, used in htpasswd files

.. toctree::
    :maxdepth: 1

    passlib.hash.apr_md5_crypt
    passlib.hash.nthash

.. todo::

    These aren't fully implemented / tested yet:

    * :mod:`~passlib.hash.nthash` - modular-crypt-format encoding of legacy NTHASH algorithm
    * :mod:`~passlib.hash.sun_md5_crypt` - MD5-based crypt descendant used by Solaris 10 (NOT related to md5-crypt above).

Other Schemes
-------------
The following schemes are used in very specified contexts,
and have encoding schemes and other requirements
not seen outside those specific contexts:

.. toctree::
    :maxdepth: 1

    passlib.hash.mysql_323
    passlib.hash.mysql_41
    passlib.hash.postgres_md5

..
    * :mod:`~passlib.hash.mysql_323` - Legacy scheme used by MySQL 3.2.3+ to store user passwords
    * :mod:`~passlib.hash.mysql_41` - Current scheme used by MySQL 4.1+ to store user passwords
    * :mod:`~passlib.hash.postgres_md5` - Current scheme used by PostgreSQL to store user passwords
