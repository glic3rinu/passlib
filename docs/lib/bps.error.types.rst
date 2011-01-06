===========================================
:mod:`bps.error.types` -- BPS Error Classes
===========================================

.. module:: bps.error.types
    :synopsis: All the BPS Error Classes

This modules contains all the exceptions classes which BPS
defines, stored in one location for easy access.
Some of these are errors raised by various parts of BPS,
while others are helpers designed to be used inside your own code.
Many of them exist mainly to act as pretty-printed helpers
for specific cases of more generic Python exceptions.

Attribute Errors
=========================
Helpers for creating explicit :exc:`AttributeError` messages.

.. autoexception:: MissingAttributeError
.. autoexception:: ReadonlyAttributeError
.. autoexception:: PermanentAttributeError
.. autoexception:: UnsetAttributeError

Function Errors
===============
These errors are useful when implementing complicated
python functions.

.. autoexception:: ParamError
.. autoexception:: NormError
.. autoexception:: RangeError

.. note::
    BPS 3.x used to define an :exc:`InvariantError` which could be raised
    when an internal invariant was violated in an application.
    However, the common Python practice seems to be
    to raise :exc:`AssertionError`.
    Unlike ``assert`` statements, raising this error
    directly will not be disabling when in optimized mode.
    This, ``InvariantError`` was removed, in favor of :exc:`AssertionError`.

Reference Errors
================
These errors will be raised by the :mod:`bps.refs` module.

.. autoexception:: ProxyEmptyError
.. autoexception:: ProxyNestError

Meta Errors
===========

.. autoexception:: AbstractMethodError

..
	Command Line Errors:

        These errors are useful when implemented code that's
        acting as a command line frontend. They are designed
        to integrate well with the :mod:`bps.app.command` framework,
        see it for more details.

        .. autoexception:: CommandError
        .. autoexception:: ParseError
        .. autoexception:: InputError


	Command Class Errors:

        These errors are useful mainly for :mod:`bps.app.command`,
        and will not be needed otherwise.

        .. autoexception:: DistTypeError
        .. autoexception:: EnvTypeError
