====================================
:mod:`bps.fs` -- The filepath object
====================================

.. module:: bps.fs
    :synopsis: filesystem interaction

Overview
========

This module provides a clean object-oriented interface
to the host filesystem, in the form of the :class:`FilePath` object.
Objects of this class act just like strings (they are in fact a subclass),
but they contain additional attributes and methods for manipulating
them as paths and interacting with the local filesystem.
The methods and attributes wrap functionality available in the :mod:`os`,
:mod:`os.path`, and :mod:`shutils` modules, and while the full contents
of those modules is not directly available, the common ones are,
and more are added frequently.

Usage
=====

Usage is very simple, just call the :func:`filepath` function
with a string, and a new :class:`FilePath` object
will be returned which will act exactly like the original
string, but with additional methods for manipulating the filesystem.

Some examples using the filepath object::

    >>> #this imports the default bps3 objects,
    >>> #you can alternately use "from bps.fs import filepath"
    >>> from bps import *
    >>> #this example code assumes the current directory is the bps3 source dir
    >>> path = filepath(".")
    >>> path #it looks like a string
        '.'
    >>> type(path) #but it's not
        <class 'bps.fs.FilePath'>
    >>> #get the absolute path (your exact path will vary)
    >>> path.abspath
        '/home/elic/dev/libs/bps'
    >>> #get a directory listing
    >>> path.listdir()
        [ '.svn', 'bps', 'docs', 'tests', 'setup.cfg', 'setup.py', 'bps.e4p' ]
    >>> #join paths together, equivalent of os.path.join...
    >>> #note that this will always use the host-specific path separator
    >>> docs = path / "docs" / "_static"
    >>> docs
        './docs/_static'
    >>> #note that under windows, this would appear as '.\\docs\\_static'
    >>> #get the absolute version of the path (your result will vary)
    >>> docs.abspath
        '/home/elic/dev/libs/bps/docs/_static'
    >>> #check the filetype of a path
    >>> docs.ftype
        'dir'
    >>> #touch a path (updating it's mtime & atime)
    >>> docs.touch()


Creating Filepaths
==================
.. autofunction:: filepath

Using Filepaths
===============
.. autoclass:: FilePath

    .. warning::

        Relative paths will always be relative to the current working directory
        *at the time of the method call*, so changing the cwd will usually
        result in a different outcome when the instance in question
        references a relative path.

.. note::

    :class:`FilePath` will probably *never* be extended to include urls
    and other similar resources: that was tried in an earlier iteration
    of this library, and it was determined there was so little
    commonality between the two (filepaths and urls), both in terms
    of interface, code, and use cases, that tieing them together
    would confusing and without much benefit. A similar-but-separate
    UrlPath may be added in the future, however.

.. todo::

    :class:`FilePath` needs to support unicode.
    Currently waiting for the Python 3.x design team to provide
    some guidance-by-example on how to handle differing OS encoding policies.
