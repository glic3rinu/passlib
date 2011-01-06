======================================================
:mod:`bps.host.windows` -- Windows-specific Utilities
======================================================

.. module:: bps.host.windows
    :platform: nt
    :synopsis: windows-specific utilities

This contains a number of windows-specific helper functions.
They are either very windows-specific, or simply haven't
been rolled into a common function in :mod:`bps.host`
along with compatriots from other OS modules...

.. autofunction:: regpath

.. autoclass:: RegistryPath

.. autofunction:: reghandle

.. autoclass:: RegistryHandle

.. autofunction:: detect_office_app

