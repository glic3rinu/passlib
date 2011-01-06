===========================================
:mod:`bps.host.utils` -- General  Utilties
===========================================

.. module:: bps.host.utils

Signals
=======
The signal functions provide a enhanced interface
to stdlib's :mod:`signal` module. Much like :mod:`atexit`
enhances the ``sys.exitfunc``, these utilties
allow multiple handlers to be chained to a given unix signal.

.. autofunction:: has_signal

.. autofunction:: add_signal_handler

.. autofunction:: remove_signal_handler

.. autofunction:: adapt_sig_term
