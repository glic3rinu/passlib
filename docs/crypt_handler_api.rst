.. _crypt-handler-api:

======================
api for crypt handlers
======================

Motivation
==========
Passlib supports many different password hashing schemes.
A majority of them were originally designed to be used on a unix
system, follow some variant of the unix ``crypt()`` api,
and have are encoded using the Extended Crypt Format.
Others were designed for use specific contexts only,
such as PostgreSQL.

Passlib was designed to provide a uniform interface to implementations
of all these schemes, as well as hide away as much of the implementation
detail as possible; both in order to make it easier to integrate password hashing
into new and existing applications. Because of these goals, some of the methods
required by the crypt handler api tend to overlap slightly,
in order to accomodate a wide variety of application requirements,
and other parts have been kept intentionally non-commital, in order to allow
flexibility of implementation.

All of the schemes built into passlib implement this interface;
most them as modules within the :mod:`passlib.hash` package.

Overview
========
A CryptHandler object may be a module, class, or instance.
The only requirement is that it expose (at least) the following attributes
and functions (for classes, the following functions must be static or class methods).

CryptHandlers have the following three attributes:

    * ``name`` - unique identifier used to distinguish scheme within
    * ``setting_kwds`` - list of settings recognized by ``genconfig()`` and ``encrypt()``.
    * ``context_kwds`` - list of context specified keywords required by algorithm

CryptHandlers have the following five methods:

    * ``genconfig(**settings) -> configuration string`` - used for generating configuration strings.
    * ``genhash(secret, config, **context) -> hash`` - used for encrypting secret using configuration string or existing hash
    * ``encrypt(secret, **context_and_settings) -> hash`` - used for encrypting secret using specified options
    * ``identify(hash) -> True|False`` - used for identifying hash belonging to this algorithm
    * ``verify(secret, hash, **context)`` - used for verifying a secret against an existing hash

Usage Examples
==============

.. todo::

    show some quick examples using bcrypt.

Informational Attributes
========================
.. attribute:: name

    A unique name used to identify
    the particular algorithm this handler implements.

    These names should consist only of lowercase a-z, the digits 0-9, and hyphens.

    .. note::

        All handlers built into passlib are implemented as modules
        whose path corresponds to the name, with an underscore replacing the hyphen.
        For example, ``des-crypt`` is stored as the module ``passlib.hash.des_crypt``.

.. attribute:: setting_kwds

    If the algorithm supports per-hash configuration
    (such as salts, variable rounds, etc), this attribute
    should contain a tuple of keywords corresponding
    to each of those configuration options.

    This should correspond with the keywords accepted
    by :func:`genconfig`, see that method for details.

    If no settings are supported, this attribute
    is an empty tuple.

.. attribute:: context_kwds

    Some algorithms require external contextual information
    in order to generate a checksum for a password.
    An example of this is Postgres' md5 algorithm,
    which requires the username to be provided
    (which it uses as a salt).

    This attribute should contain a tuple of keywords
    which should be passed into :func:`encrypt`, :func:`verify`,
    and :func:`genhash` in order to encrypt a password.

    Since most password hashes require no external information,
    this tuple will usually be empty.

Primary Interface
=================
The ``encrypt()``, ``identify()``, and ``verify()`` methods are designed
to provide an easy interface for applications to encrypt new passwords
and verify existing passwords, without having to deal with details such
as salt formats.

.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

Secondary Interface
===================
While the primary interface is generally the most useful when integrating
password support into an application, those methods are for the most part
built on top of the secondary interface, which is somewhat simpler
for *implementing* new password schemes. It also happens to match
the tradition unix crypt interface, and consists of two functions:
``genconfig()`` and ``genhash``.

.. autofunction:: genconfig
.. autofunction:: genhash

Other Methods
=============
Some of the CryptHandlers in passlib expose some additional function and attributes,
which may be useful, but whose behavior varies between handlers (if present at all),
and may not conform exactly to the following summary:

.. autofunction:: parse

    This method usually takes in a hash or configuration string
    belonging to the scheme, and parses it into a dictionary
    whose keys should match :attr:`setting_kwds`,
    as well as the key ``checksum``, which is either ``None`` or
    the encoded checksum portion of the string (ie, the hash itself).

    It should raise :exc:`ValueError` in the same cases that :func:`genhash` would.

    Most implementations of ``parse()`` do very little sanity checking,
    leaving that job to ``genconfig``.

.. autofunction:: render

    This method is the inverse of :func:`parse`:
    it takes in a dictionary such as returned by :func:`parse`,
    and renders a hash or configuration string.

    Most implementations of ``render()`` do very little sanity checking,
    and may be willing to form strings which are malformed.

For schemes which support a variable number of rounds,
the following attributes are usually exposed:

.. attribute:: default_rounds

    The default number of rounds that will be used if not
    explicitly set when calling :func:`encrypt` or :func:`genconfig`.

.. attribute:: min_rounds

    The minimum number of rounds the scheme allows.
    Specifying values below this will generally result
    in a warning, and ``min_rounds`` will be used instead.

.. attribute:: max_rounds

    The maximum number of rounds the scheme allows.
    Specifying values above this will generally result
    in a warning, and ``max_rounds`` will be used instead.
