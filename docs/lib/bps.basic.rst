========================================================
:mod:`bps.basic` -- Manipulation of basic Python objects
========================================================

.. module:: bps.basic
    :synopsis: tools for manipulating basic python datatypes

This module contains utilities for manipulating the basic python
datatypes, like :class:`dict` or :class:`list`. It also
contains functions such as would be found in :mod:`functools`
and :mod:`itertools`, under the rationale that functions
and generators can also be considered basic python objects.

Dictionary Helpers
==================
.. autofunction:: invert_dict
.. autofunction:: zip_dict
.. autofunction:: unzip_dict
.. autofunction:: pop_from_dict
.. autofunction:: update_dict_defaults
.. autofunction:: prefix_from_dict

Iterator and Functional Helpers
===============================
.. autofunction:: iter_unique
.. autofunction:: unique

Set and Sequence Helpers
========================
.. autofunction:: intersects
.. autofunction:: sameset

..
    not documented:
        .. autofunction:: revpartial
