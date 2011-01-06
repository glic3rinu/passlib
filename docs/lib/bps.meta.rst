===============================================================
:mod:`bps.meta` -- Introspection & Monkeypatching
===============================================================

.. module:: bps.meta
    :synopsis: introspection & monkeypatching

This module contains various utilities introspection
utilities, to enhance what is already provided through
python's :mod:`inspect` module,

Interface Tests
===============
.. autofunction:: is_class
.. autofunction:: is_num
.. autofunction:: is_seq
.. autofunction:: is_oseq
.. autofunction:: is_str

Class Inspection
================
.. autofunction:: is_overridden
.. autofunction:: find_attribute

Module Inspection
=================
.. autofunction:: get_module_exports

Decorators
===========
.. autofunction:: abstractmethod
.. autofunction:: decorate_per_instance

Autosuper
=========
.. autofunction:: instrument_super

Monkeypatching
==============
.. autofunction:: monkeypatch
.. autofunction:: monkeypatch_mixin

