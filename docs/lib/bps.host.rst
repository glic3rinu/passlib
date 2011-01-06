==========================================
:mod:`bps.host` -- Locating Host Resources
==========================================

.. module:: bps.host
    :synopsis: host resource discovery & desktop interaction


This package provides methods for accessing various host resources,
much like stdlib's ``os`` package. In fact, this package
mainly exists to provide routines which ``os`` does not provide,
for one reason or another.

The this module is broken into the following sections:

* `Process Management`_ -- OS-agnostic signaling & pid management
* `System Interaction`_ -- finding installed applications
* `Desktop Interaction`_ -- opening, printing, executing files via desktop environment
* `Resource Paths`_ -- helpers for locating home dir, desktop, user config directory, and more.
* `User Accounts`_ -- retrieve basic information about the user accounts on the host system.

.. toctree::
    :maxdepth: 2

    bps.host.posix
    bps.host.windows
    bps.host.utils

.. note::

    The main two reasons many of these functions probably are not included in the stdlib
    is that this module relies on `pywin32 <http://sourceforge.net/projects/pywin32/>`_ under Windows,
    and the fact that this module makes some arbitrary decisions
    about path locations which work 90% of cases, but not the 100% that the stdlib requires.

Usage
=====
The typical use of this module's core functions is to import ``bps.host`` into
your package, and then access it's various methods from the imported object::

    >>> #note that while this example was written under linux, the host module interface
    >>> #is designed to be uniform, so that you can use the *exact same calls*
    >>> #to acheive the same effect under windows, without changing your code.
    >>> from bps import host
    >>>
    >>> #check what desktop environment you're running under
    >>> host.get_desktop_name()
        'gnome'
    >>>
    >>> #find location of an executable
    >>> host.find_exe("meld")
        '/usr/bin/meld'
    >>>
    >>> #tell desktop to open a file
    >>> host.desktop_open("myfile.txt")
    >>>
    >>> #get current pid
    >>> host.get_pid()
        12984
    >>>
    >>> #check if a pid is running
    >>> host.has_pid(12984)
        True
    >>>
    >>> #kill a pid
    >>> host.term_pid(12984)
    >>>

Process Management
==================

.. function:: get_pid

    Returns current PID.
    Alias for ``os.getpid()``, included just for symmetry with the other pid functions.

.. autofunction:: has_pid
.. autofunction:: term_pid
.. autofunction:: kill_pid

System Interaction
==================
.. autofunction:: find_exe

.. attribute:: exe_exts

    This should be a tuple of all the extensions that will be searched
    when trying to find an exe. For example, under posix, the list will be ``('',)``,
    but under windows the tuple will contain ``('.exe','.bat')``.

.. todo::
    Would like to add database for detecting & locating applications via windows registry,
    or other methods.

Desktop Interaction
===================

.. autofunction:: get_desktop_name
.. autofunction:: desktop_open
.. autofunction:: desktop_compose_email

Resource Paths
==============
All the resource path functions are designed to quickly
locate the directories that are important to a cross-platform
desktop application, without having to know os-specific details...

.. autofunction:: get_env_path

.. autoclass:: EnvPaths

----

The following functions return a :class:`ProgPaths` instance,
with various resource paths chosen according to the default conventions
of the OS you are currently running on, allowing quick and easy
creation of applications which store their config in the right place
no matter what OS you run them on...

.. autofunction:: get_app_path
.. autofunction:: get_service_path
.. autoclass:: ProgPaths

User Accounts
=============
.. autofunction:: find_user

.. autoclass:: UserProfile
