=======================================================
:mod:`bps.warndep` -- Warning and deprecation Utilities
=======================================================

.. module:: bps.warndep
    :synopsis: warning & deprecation utilities

This module contains some helpful functions for
issuing deprecation warnings about methods,
functions, and properties which are about to
be relocated or removed entirely.

Deprecation Decorators
======================
These decorators automatically issue
a deprecation warning when the decorated
object is accessed:

.. autofunction:: deprecated_function
.. autofunction:: deprecated_method

Deprecation Constructors
========================
These functions create an entirely new object,
usually wrapping the old object in some manner.

.. autofunction:: deprecated_property
.. autofunction:: relocated_function

