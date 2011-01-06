===============================================
:mod:`bps.stream` -- Stream & Buffer Utilities
===============================================

.. module:: bps.stream
    :synopsis: stream (file, StringIO) helpers

This module contain various stream & buffer related utilities.

Non-Blocking Reads
==================

.. autofunction:: nb_read
.. autofunction:: nb_readline_iter
.. autoclass:: nb_readline_list

Other Functions
===============
.. autofunction:: get_stream_size

..
    not listing this one till it's heuristic or use-case is better defined:

    .. autofunction:: get_input_type
