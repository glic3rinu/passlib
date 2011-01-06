=============================================
:mod:`bps.error.utils` -- BPS Error Utilities
=============================================

.. module:: bps.error.utils
    :synopsis: Utilties for dealing with errors

This module contains a few utilties used by BPS
for handling errors. :func:`format_exception` in particular
is used by the :class:`bps.logs.formatters.FancyFormatter` to print tracebacks.

.. autofunction:: format_exception
.. autofunction:: get_sysexit_rc

.. seealso::
    :func:`bps.develop.trap`

