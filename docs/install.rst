============
Installation
============

Requirements
============
BPS tries to use pure-python implementations of things whereever possible,
and have as few dependancies as possible. The current set of requirements is:

    * Python 2.5 or better is required (Python 2.6 is supported).

        * BPS is no longer tested for Python 2.4.x or earlier,
          no guarantees are made about whether BPS will work with them.

        * Python 3.0 has **not** been assessed for compatibility. It probably won't work.

    * The `pywin32 <http://sourceforge.net/projects/pywin32/>`_ package is required
      when running under windows.

The following libraries will be used if present, but they are not required:

    * If installed, `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ will be
      used instead of BPS's slower pure-python bcrypt implementation.
      (see :class:`bps.security.pwhash.BCrypt`).

Installing
==========
BPS can be installed with easy_install, linked/copied into sys.path directly
from it's source directory, or installed using "setup.py".
BPS is pure python, there is nothing to compile or configure.

Testing
=======
BPS contains a number of unittests (sadly, coverage is not yet complete).
all of which are contained within the :mod:`bps.tests` module,
and are designed to be run use the `nose <http://somethingaboutorange.com/mrl/projects/nose>`_ library.
Once BPS and nose have been installed, you may run the following commands::

    #to run the full bps test suite
    nosetests bps.tests

    #the full suite with some extra longer-running tests
    export BPS_DEV_TESTS=true
    nosetests bps.tests

Documentation
=============
BPS uses Sphinx to generate it's documentation.
To create your own copy, make sure you have Sphinx 0.6.3 or better installed,
as well as BPS, and run ``python $SOURCE/docs/make.py clean html``,
where ``$SOURCE`` is the path to the BPS source directory.
Once this completes, point a browser to the file at ``$SOURCE/docs/_build/html/index.html``
to access the BPS documentation.
