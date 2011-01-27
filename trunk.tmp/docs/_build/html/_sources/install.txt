============
Installation
============

Requirements
============
PassLib tries to use pure-python implementations of things whereever possible,
and have as few dependancies as possible. The current set of requirements is:

    * Python 2.5 or better is required (Python 2.6 is supported).

        * PassLib is no longer tested for Python 2.4.x or earlier,
          no guarantees are made about whether PassLib will work with them.

        * Python 3.0 has **not** been assessed for compatibility. It probably won't work.

The following libraries will be used if present, but they are not required:

    * If installed, `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ will be
      used instead of PassLib's slower pure-python bcrypt implementation.
      (see :class:`passlib.hash.BCrypt`).

Installing
==========
PassLib can be installed with easy_install, linked/copied into sys.path directly
from it's source directory, or installed using ``$SOURCE/setup.py install``,
where ``$SOURCE`` is the path to the PassLib source directory.
PassLib is pure python, there is nothing to compile or configure.

Testing
=======
PassLib contains a number of unittests (sadly, coverage is not yet complete).
all of which are contained within the :mod:`passlib.tests` module,
and are designed to be run use the `nose <http://somethingaboutorange.com/mrl/projects/nose>`_ library.
Once PassLib and nose have been installed, you may run the following commands::

    #to run the standard passlib test suite:
    nosetests passlib/tests

    #to run the standard suite + some additional longer-running tests:
    export PASSLIB_DEV_TESTS=true
    nosetests passlib/tests

Documentation
=============
PassLib uses Sphinx to generate it's documentation.
To create your own copy, make sure you have Sphinx 1.0 or better installed,
as well as PassLib, and run ``python $SOURCE/docs/make.py clean html``,
where ``$SOURCE`` is the path to the PassLib source directory.
Once this completes, point a browser to the file at ``$SOURCE/docs/_build/html/index.html``
to access the PassLib documentation in html.
