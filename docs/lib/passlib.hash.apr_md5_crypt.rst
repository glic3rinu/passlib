=============================================================
:mod:`passlib.hash.apr_md5_crypt` - Apache MD5-Crypt Variant
=============================================================

.. module:: passlib.hash.apr_md5_crypt
    :synopsis: Apache MD5 Crypt

Stats: 96 bit checksum, 48 bit salt, :ref:`modular-crypt-format` compatible.

This format is a variation of :mod:`~passlib.hash.md5_crypt`,
primarily used by the Apache webserver in ``htpasswd`` files.

This format is identical to md5-crypt, except for two things:
it uses ``$apr1$`` as a prefix where md5-crypt uses ``$1$``,
and inserts ``$apr1$`` where md5-crypt inserts ``$1$`` into
it's internal hash calculation. Thus, this algorithm is just
as strong as md5-crypt, but the formats (and their contained checksums)
are in no way compatible with eachother.

Implementation
==============
PassLib contains a builtin pure-python implementation of apr-md5-crypt,
based of the specification at `http://httpd.apache.org/docs/2.2/misc/password_encryptions.html`,
but code shared with :mod:`~passlib.hash.md5_crypt`.
