=====================
Copyrights & Licenses
=====================

Copyright
=========
The BPS library is (c) 2004-2009 `Assurance Technologies, LLC <http://www.assurancetechnologies.com>`_,
excepting any code noted below as taken from :ref:`third party sources <third-party-software>`.
Such portions are copyright their respective owners.

License
=======
This library is released under the BSD license; we hope you find it useful.

::

    The BPS Python Library

    Copyright (c) 2004-2009 Assurance Technologies, LLC

    Permission to use, copy, modify, and distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

.. _third-party-software:

Third Party Software
====================
BPS contains some code taken from various third-party sources, which have their
own licenses (all of which, it should be noted, are BSD-compatible).
The following is a list of these sources, their owners, licenses, and the parts
of BPS derived from them.

GPW
---
The class :class:`bps.security.pwgen.GpwGenerator`
is a python implementation of Tom Van Vleck's phonetic
password algorithm `GPW <http://www.multicians.org/thvv/gpw.html>`_.
It's released under informally worded BSD-like terms.

jBcrypt
-------
`jBCrypt <http://www.mindrot.org/projects/jBCrypt/>`_ is a pure-java
implementation of OpenBSD's BCrypt algorithm, written by Damien Miller,
and released under a BSD license.

:mod:`bps.security._bcrypt` is a python translation of this code,
which is used as a fallback backend for :class:`bps.security.pwhash.BCrypt`
when the external python library `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_
is not available.

This is the license and copyright for jBCrypt::

    Copyright (c) 2006 Damien Miller <djm@mindrot.org>

    Permission to use, copy, modify, and distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

MD5-Crypt
---------
The class :class:`bps.security.pwgen.Md5Crypt` is a pure-python
implementation of the md5-crypt password hashing algorithm.
It's derived from the FreeBSD md5-crypt implementation `<http://www.freebsd.org/cgi/cvsweb.cgi/~checkout~/src/lib/libcrypt/crypt.c?rev=1.2>`_,
which was released under the following license::

    "THE BEER-WARE LICENSE" (Revision 42):
    <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
    can do whatever you want with this stuff. If we meet some day, and you think
    this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp

PEP 3101
--------
:pep:`3101` defines a new string templating system
via the method ``string.format()``, which is built-in
to Python 2.6 and higher. :mod:`bps.text._string_format` is a pure-python
implementation of PEP 3101, used by BPS to backport this feature
to Python 2.5 (see :mod:`bps.text` for usage).

While the current implementation has been rewritten drastically
(to pass the python 2.6 format() unittests), it was originally
based on the one created by Patrick Maupin and Eric V. Smith, as found in
the PEP 3101 sandbox at `<http://svn.python.org/view/sandbox/trunk/pep3101/>`_.
While no license was attached, it is assumed to have been released
under an equivalent license to the `Python source code`_.

Python Source Code
------------------
BPS contains many small fragments taken from the Python 2.6.2 source code,
mainly for the purpose of backporting 2.6 features to python 2.5:

    * :mod:`bps.text._string_format`, contains a modified copy of
      Python 2.6's :class:`string.Formatter`, as part of BPS's
      Python 2.6-compatible PEP3101 implementation for Python 2.5.

    * :class:`bps.types.namedtuple` is a adaptation of
      the Python 2.6 namedtuple class, for use with Python 2.5.

The Python 2.6.2 source code is licensed under the
`Python Software Foundation License, Version 2 <http://www.python.org/download/releases/2.6.2/license/>`_.

UnixCrypt.java
--------------
`UnixCrypt.java <http://www.dynamic.net.au/christos/crypt/UnixCrypt2.txt>`_
is a pure-java implementation of the historic unix-crypt password hash algorithm.
Originally written by Aki Yoshida, and modified by others,
it was released under a BSD-like license.

:mod:`bps.security._unix_crypt` is a python translation of this code,
which is used as a fallback backend for :class:`bps.security.pwhash.UnixCrypt`
for platforms where stdlib's :mod:`crypt` is not available.

This is the license and copyright for UnixCrypt.java::

    UnixCrypt.java	0.9 96/11/25
    Copyright (c) 1996 Aki Yoshida. All rights reserved.
    Permission to use, copy, modify and distribute this software
    for non-commercial or commercial purposes and without fee is
    hereby granted provided that this copyright notice appears in
    all copies.

    modified April 2001
    by Iris Van den Broeke, Daniel Deville

    modified Aug 2005
    by Greg Wilkins (gregw)
