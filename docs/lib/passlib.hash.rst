============================================
:mod:`passlib.hash` - Password Hash Schemes
============================================

.. module:: passlib.hash
    :synopsis: package containing handlers for all builtin password hash schemes

Overview
========
This package contains handlers for all the password hash schemes built into
passlib. All modules within this package implement a single scheme,
and follow the :ref:`crypt-handler-api`. They can be imported
and used directly, eg::

    >>> from passlib.hash import md5_crypt
    >>> hash = md5_crypt.encrypt("password")

As well, any third-party handlers registered with passlib via :func:`register_crypt_handler`
will be inserted into this package.

Note that many applications may find it easier to use a :class:`CryptContext`
instance, or retreive handlers via :func:`get_crypt_handler`, rather than
import directly from this module.

Contents
========
Passlib contains the following builtin password algorithms:

Standard Unix Schemes
---------------------
All these schemes are/were used by various unix flavors to store user passwords.
Because of this, all these schemes (except des-crypt and ext-des-crypt) follow
the :ref:`modular crypt format <modular-crypt-format>`.

* :mod:`~passlib.hash.des_crypt` - Legacy DES-based unix crypt() algorithm.
* :mod:`~passlib.hash.ext_des_crypt` - Legacy BSDi extension of des-crypt which adds more salt and variable rounds.
* :mod:`~passlib.hash.md5_crypt` - MD5-based descendant of des-crypt.
* :mod:`~passlib.hash.bcrypt` - Blowfish-based replacement for md5-crypt, used mostly on BSD systems.
* :mod:`~passlib.hash.sha256_crypt` - SHA-256 based descendant of MD5 crypt, used mostly on Linux systems.
* :mod:`~passlib.hash.sha512_crypt` - SHA-512 based descendant of MD5 crypt, used mostly on Linux systems.

Non-Standard Unix-Compatible Schemes
------------------------------------
While few of these schemes were ever used by unix flavors to store user passwords,
these are compatible with the :ref:`modular crypt format <modular-crypt-format>`, and can be
used in contexts which support them in parallel with the others following
the same format.

* :mod:`~passlib.hash.apr_md5_crypt` - Apache-specific variant of md5-crypt, used in htpasswd files

.. todo::

    These aren't fully implemented / tested yet:

    * :mod:`~passlib.hash.nthash` - modular-crypt-format encoding of legacy NTHASH algorithm
    * :mod:`~passlib.hash.sun_md5_crypt` - MD5-based crypt descendant used by Solaris 10 (NOT related to md5-crypt above).

Other Schemes
-------------
The following schemes are used in very specified contexts,
and have encoding schemes and other requirements
not seen outside those specific contexts:

* :mod:`~passlib.hash.mysql_323` - Legacy scheme used by MySQL 3.2.3+ to store user passwords
* :mod:`~passlib.hash.mysql_41` - Current scheme used by MySQL 4.1+ to store user passwords
* :mod:`~passlib.hash.postgres_md5` - Current scheme used by PostgreSQL to store user passwords
