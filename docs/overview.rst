================
Library Overview
================

BPS started life in 2003 as an in-house collection of small functions
and tools which were frequently needed by the programmers at
`Assurance Technologies <http://www.assurancetechnologies.com>`_.
Over the years, it has accumlated a more small functions,
but it has also acquired some modules which provide major
new features that go above and beyond simple utility functions.
Since we have benefited greatly from open source software,
this library was released publically in 2009, in order
to fill a few niches for which there is a need (password hashing,
desktop interaction), as well as to simply give something
back to the community.

.. module:: bps
    :synopsis: Root of all BPS modules

Organization
============
Everything in BPS falls into two main categories:
There are modules which contain interconnected
functions dealing with a specific topic (the `service modules`_),
and there are the modules which contain smaller utility
functions which aren't really connected to eachother,
but which are grouped together for convience based on a common
subject (the `utility modules`_). You may read through
the entirety of the documentation to find any functions
which might be useful, or jump directly to a submodule
whose services you already know you need.

Service Modules
===============
The following modules contain tightly-knit sets of interconnected functions,
and each module provides a unique set of services which would not be possible
without all the functions it contains:

    :mod:`bps.fs`

        This provides a "magic" filepath object, as well as some other filesystem
        related helpers. The magic filepath object is a string subclass
        which allows you to manipulate filepaths (and interact with the filesystem)
        in an object oriented manner.
        *Warning: use of this module can be incredibly addictive.*

    :mod:`bps.host`

        This provides a wide array of functions for detecting host resource
        paths, managing processes, and interacting with the desktop,
        all in a os-neutral manner.

    :mod:`bps.logs`

        This module contains a number of helper utilties
        for using python's builting logging module:

        * an easier-to-use logging config format for ini files.
        * a more programmatic interface for configuring the logging system.
        * ability to capture & redirect stdio, and the warnings module.

    :mod:`bps.security`

        This module contains a sophisticated system for creating & verifying
        password hashes, supporting all the major unix password hashing schemes
        (in native python no less).

Utility Modules
===============
Unlike the service modules, the remaining modules in bps
are collections of smaller standalone functions, grouped
together by common theme:

    :mod:`bps.basic`

        Utility functions for manipulating
        common python data structures, such as helpers
        for manipulated dicts, sets, and others.

    :mod:`bps.cache`

        Decorators and helpers
        for doing memoization and related activities.

    :mod:`bps.error.types`

        Assorted Exceptions classes which are used by BPS
        or which may be generally useful.

    :mod:`bps.meta`

        Introspection tools,
        decorators for meta-level activities (eg abstract methods),
        and monkeypatching.

    :mod:`bps.numeric`

        Numeric related helpers,
        mainly as an extension to stdlib's math module.

    :mod:`bps.refs`

        Weak reference helpers and proxy objects.

    :mod:`bps.security`

        Security tools, mainly password hashing and generation.

    :mod:`bps.stream`

        Buffer and stream related tools.

    :mod:`bps.text`

        Tool for manipulating text strings,
        and other language related operations. This includes a noun
        pluralization function, a function for sanitizing user-provided
        filenames, ``asbool``, and more.
        *For Python 2.5 users, this also provides a backport of Python 2.6's
        "str.format()" system.*

    :mod:`bps.types`

        A collection of assorted classes which are frequently helpful
        in programming, such as `bps.types.BaseClass`, which provides
        automatic super() support.

    :mod:`bps.warndep`

        Decorators for easily raises deprecation warnings
        when you move / relocate functions, methods, and properties
        in your application.

    :mod:`bps.misc`
        This module contains any tools which don't fit into one of the other
        categories.

The things left out...
===========================
One other module exists which is purposely not documented:

    :mod:`bps.unstable`
        This module contains functions
        which have been added to BPS by the developers, but aren't officially
        included and documented for any number of reasons...

            * too application specific
            * not developed long enough
            * not tested enough much
            * look neat, but don't have any real world use-cases yet

        Use them if you dare, they may be removed or recoded on the spur
        of the moment. The same goes for some of the other
        present-but-undocumented functions you may find in the BPS source.
