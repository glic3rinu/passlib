==================================================================
:mod:`passlib.hash.postgres_md5` - Postgres MD5 password hash
==================================================================

.. module:: passlib.hash.postgres_md5
    :synopsis: Postgres MD5 password hash

Stats: 512 bit checksum, username used as salt

This implements the md5-based hash algorithm used by Postgres to store
passwords in the pg_shadow table.

This algorithm shouldn't be used for any purpose besides Postgres interaction,
it's a weak unsalted algorithm which could be attacked with a rainbow table
built against common user names.

.. warning::
    This algorithm is slightly different from most of the others,
    in that both encrypt() and verify() require you pass in
    the name of the user account via the required 'user' keyword,
    since postgres uses this in place of a salt :(

Usage Example::

    >>> from passlib.hash import postgres_md5 as pm
    >>> pm.encrypt("mypass", user="postgres")
    'md55fba2ea04fd36069d2574ea71c8efe9d'
    >>> pm.verify("mypass", 'md55fba2ea04fd36069d2574ea71c8efe9d', user="postgres")
    True

.. todo::

    find references
