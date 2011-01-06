=================================================
:mod:`bps.types` -- Useful Classes and Types
=================================================

.. module:: bps.types
    :synopsis: useful classes and types

This module contains most of the classes defined by BPS:

    * `base classes`_
    * `simple data structures`_
    * `dictionary classes`_
    * `other classes`_

Base Classes
============
.. autoclass:: BaseClass
.. autoclass:: BaseMetaClass

Simple Data Structures
======================
.. autoclass:: stub

.. class:: namedtuple

    Returns a new subclass with named tuple fields

    This class is just a backport from Python 2.6.
    When BPS is loaded under 2.6 or higher,
    the native implementation will be used instead.

Dictionary Classes
==================
.. autoclass:: CustomDict
.. autoclass:: OrderedDict

Other Classes
=============
.. autoclass:: CloseableClass

