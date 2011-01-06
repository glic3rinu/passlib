=================================
:mod:`bps.cache` -- Caching Tools
=================================

.. module:: bps.cache
    :synopsis: caching tools

This module defines a number of function decorators,
most of which come in function- and method- specific
variants, and aid in caching.

Caching Decorators
==================
These decorators allow for quick "memoization" of a function.

.. autofunction:: cached_function
.. autofunction:: cached_method

Stateful Decorators
===================
These decorators allow for quick and easy setup of callbacks,
allowing the decorated method to alert listeners that a value has changed.

.. autofunction:: stateful_function
.. autofunction:: stateful_method
.. autofunction:: is_stateful
