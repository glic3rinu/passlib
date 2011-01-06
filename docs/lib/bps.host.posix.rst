=================================================
:mod:`bps.host.posix` -- Posix-specific Utilties
=================================================

.. module:: bps.host.posix
    :platform: posix
    :synopsis: posix-specific utilities

This contains a number of posix-specific helper functions.
They are either very posix-specific, or simply haven't
been rolled into a common function in :mod:`bps.host`
along with compatriots from other OS modules...

.. autofunction:: resolve_uid

.. autofunction:: resolve_gid

.. autofunction:: resolve_user

.. autofunction:: resolve_group

.. autofunction:: chown

