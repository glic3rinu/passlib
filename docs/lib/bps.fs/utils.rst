===========================================
:mod:`bps.fs` -- Other Filesystem Utilities
===========================================

.. currentmodule:: bps.fs

In addition to :func:`filepath`, this module also provides
some additional utility functions for manipulating the filesystem.

Permissions
===========
The following functions deal with file access permissions
(mainly unix-centric, though they are functional under windows).
While they are ostensibly wrappers for similar functions
available under :mod:`os`, these versions provide some enhanced capabilities:

.. autofunction:: chmod
.. autofunction:: setumask
.. autofunction:: getumask

Mode Parsing
------------
To help manipulate symbolic mode strings,
the following helper functions are available:

.. autofunction:: parse_mode_mask
.. autofunction:: repr_mode_mask

Other Functions
===============
This module provides some additional functions for interacting with the filesystem:

.. autofunction:: is_filepath
.. autofunction:: posix_to_local
.. autofunction:: local_to_posix
.. autofunction:: splitsep
.. autofunction:: is_shortcut
.. autofunction:: read_shortcut

.. data:: os_has_symlinks

    This is a module-level constant set to ``True`` if the os supports symlinks.

.. data:: os_has_shortcuts

    This is a module-level constant set to ``True`` if the os supports windows shortcuts (aka LNK files).
    This will only be true under windows, though :func:`read_shortcut` will work cross-platform.
