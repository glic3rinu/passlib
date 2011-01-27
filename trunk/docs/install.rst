============
Installation
============

Requirements
============
PassLib tries to use pure-python implementations of things whereever possible,
and have as few dependancies as possible. The current set of requirements is:

    * Python 2.5 or better is required.

        * PassLib has not been tested with Python 2.4 or earlier,
          and no guarantees are made about whether PassLib will work with them.

        * Python 3.x has **not** been assessed for compatibility.
          It probably won't work just yet.

The following libraries will be used if present, but they are not required:

    * If installed, `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ will be
      used instead of PassLib's slower pure-python bcrypt implementation.
      (see :class:`passlib.BCrypt`).

Installing
==========
PassLib can be installed with easy_install, linked/copied into sys.path directly
from it's source directory, or installed using ``$SOURCE/setup.py install``,
where ``$SOURCE`` is the path to the PassLib source directory.
PassLib is pure python, there is nothing to compile or configure.

Testing
=======
PassLib contains a number of unittests (sadly, coverage is not yet complete).
all of which are contained within the :mod:`passlib.tests` package,
and are designed to be run using the `nose <http://somethingaboutorange.com/mrl/projects/nose>`_ unit testing library.
Once PassLib and nose have been installed, you may run the following commands::

    #to run the basic passlib test suite:
    nosetests passlib/tests

    #to run the extended passlib test suite, including some longer running tests:
    export PASSLIB_TESTS=all
    nosetests passlib/tests

Documentation
=============
The latest copy of this documentation should always be available 
at the `PassLib homepage <http://www.assurancetechnologies.com/software/passlib>`_.

If you wish to generate your own copy of the documentation,
you will need to install `Sphinx <http://sphinx.pocoo.org/>`_ (1.0 or better)
as well `astdoc <http://www.assurancetechnologies.com/software/astdoc>`_ (a bundle of custom sphinx themes & extensions
used by Assurance Technologies). Next, download the PassLib source,
and run ``python $SOURCE/docs/make.py clean html`` (where ``$SOURCE`` is the path to the PassLib source directory).
Once Sphinx completes it's run, point a web browser to the file at ``$SOURCE/docs/_build/html/index.html``
to access the PassLib documentation in html format.
