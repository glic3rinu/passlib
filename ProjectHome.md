# Welcome #
**PassLib** is a password hashing library for Python, which provides cross-platform
implementations of over 30 password hashing algorithms; as well as a framework for managing and migrating existing password hashes.

It's designed to be useful for any task from quickly verifying a hash found in a unix system's _/etc/shadow_ file, to providing full-strength password hashing for multi-user application.

# News #

**2013-12-26** - **Attention: Passlib 1.7 will drop support for Python 2.5.** Too many core tools (such as Setuptools, Pip, and Tox) no longer support it, making testing increasingly burdensome.

**2013-12-26** - Passlib 1.6.2 released. This fixes a few minor compatibility bugs and other issues - see the [release notes](http://pythonhosted.org/passlib/history.html) for details.

**2012-08-02** - Passlib 1.6.1 released. This fixes a few minor bugs.

_[old news](http://code.google.com/p/passlib/wiki/News)_

# Documentation #
Documentation of the latest release of Passlib can always be found at http://pythonhosted.org/passlib.

Additional questions about usage or features? Feel free to post on our [mailinglist](https://groups.google.com/group/passlib-users).

# Downloads #

The latest release of Passlib is always available at [PyPI](http://pypi.python.org/pypi/passlib). All downloads are signed with the GPG key [4CE1ED31](http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x4D8592DF4CE1ED31).

For the latest development edition, see our [mercurial repository](https://code.google.com/p/passlib/source).

# Usage #
A quick example of using passlib to integrate into a new application:

```
>>> #import the context under an app-specific name (so it can easily be replaced later)
>>> from passlib.apps import custom_app_context as pwd_context

>>> #encrypting a password...
>>> hash = pwd_context.encrypt("somepass")
>>> hash
'$6$rounds=36122$kzMjVFTjgSVuPoS.$zx2RoZ2TYRHoKn71Y60MFmyqNPxbNnTZdwYD8y2atgoRIp923WJSbcbQc6Af3osdW96MRfwb5Hk7FymOM6D7J1'

>>> #verifying a password...
>>> ok = pwd_context.verify("somepass", hash)
True
>>> ok = pwd_context.verify("letmein", hash)
False

```

For more details and an extended set of examples, see the  [full documentation](http://pythonhosted.org/passlib); This example barely touches on the range of features available.

# Development #

For the latest development edition, see our [mercurial repository](https://code.google.com/p/passlib/source). See the [roadmap](https://code.google.com/p/passlib/wiki/Roadmap) for an overview of development plans.

If you have bugs, questions, or code to contribute, please contact us on the passlib [mailinglist](https://groups.google.com/group/passlib-users).

PassLib is actively being developed, and we are interested in feedback, as well as enhancing passlib's architecture to support a broad range of use-cases and algorithms.