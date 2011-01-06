=================================================
:mod:`bps.text` -- Text parsing & formatting
=================================================

.. module:: bps.text
    :synopsis: text parsing & formatting

This module provides various methods for manipulating
various types of strings. It includes helpers
for cleaning user input, inflecting english words,
and some other features.

String Parsing
===============

.. autofunction:: asbool
.. autofunction:: condense
.. autofunction:: split_condense

Filename Sanitizing
===================
.. autofunction:: clean_filename

Extending :func:`clean_filename`
--------------------------------
The clean_filename function is designed to be extended
to suite your own requirements, and yet still perform
optimally. If you have a preset configuration
which you frequently use, simply create an instance
of :class:`FileCleaner`, passing in the appropriate
options for your preset, or clone an existing preset
using ``preset.copy()``. These instances can be called
directly, just like the `clean_filename` function proper.
Or, you may insert it into ``bps3.text.cfg_presets``
under a custom name, so that it will be globally available
through :func:`clean_filename`. See the source code for more.

Language Inflection
===================
BPS implements a language inflector class based off of
the one implemented in Ruby On Rails. Current only English
is supported (but see note below). While the system
is class based, the following public functions
are offered up for easy access:

.. autofunction:: pluralize
.. autofunction:: singularize
.. autofunction:: countof
.. autofunction:: oneof
.. autofunction:: ordinal

.. note::
    Currently, there only exists an (American) English language inflector,
    but if and when more Inflector subclasses are written for other languages,
    this system will be expanded as the use cases require.

..
	Variable Renaming
	=================
	BPS has only the beginnings of support for variable name mangling,
	such as converting from ``CamelCase`` to ``lower_case_with_underlines``.
	This will hopefully be fleshed out more in the future.

	.. autofunction:: lu_to_cc

Format String Backport
======================
Python 2.6 introduced a new formatting system.
BPS contains a pure-python implementation of this system,
so that it is available to Python 2.5 deployments.
Thus, the following methods are aliases for the native
python implementations when available; otherwise
they are backed by a pure-python implementation.

.. autofunction:: render_format
.. autofunction:: format
.. autoclass:: Formatter

.. note::
    For Python 2.5 users who *really* want to have ``str.format()``
    available to them directly, they may import :mod:`bps.text.patch_format`
    somewhere in their application. By importing this module,
    the native strings types of Python 2.5 will be monkeypatched to include
    a format method which should be a compatible with the real thing.
    This is not imported by default, as it's a somewhat evil thing to do.

Format String Parsing
=====================
The following functions are available for examining
format strings. They are rarely needed,
but occasionally code has the need to inspect a format string template:

.. autofunction:: fmt_has_field
.. autofunction:: get_fmt_fields

..
    these are present, but not documented yet
    .. autofunction:: parse_fmt_string
    .. autofunction:: parse_fmt_field


..
    agent string parsing:
        .. autofunction:: parse_agent_string
        .. autofunction:: agent_string_has_product
