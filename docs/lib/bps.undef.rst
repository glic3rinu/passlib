==========================================
:mod:`bps.undef` -- The "Undefined" Object
==========================================

.. module:: bps.undef
    :synopsis: provides an "Undef" singleton (ala Javascript)

Other languages like javascript (and frequently other python libraries)
have the recurring need for a "undefined" singleton, representing
that a value is not specified; this is opposed to ``None``
which technically represents "no value present", but does double duty
as meaning "undefined" as well. But sometimes, that double duty just doesn't
cut it. BPS provides the following Undef object.

.. data:: Undef

    The Undef object signals that the value is not defined.
    It has the unique property that is it never equal to anything (in a boolean sense),
    including itself, much like the sql "NULL" object.

.. function:: defined(value)

    Helper for checking if a value is or is not the :data:`Undef` object.
    This just for completeness, it's equivalent to ``value is not Undef``,
    which is typically faster.

.. function:: undefined(value)

    Inverse of :func:`defined`.

.. caution::
    Mako's "Undefined" and peak's "NOT_GIVEN" objects are other examples
    of this singleton. Hopefully a way will be found to unify these objects
    before it becomes a problem. Because of this, it's generally
    useful to use Undef as an internal value inside your code,
    usually as a default value for a function keyword,
    and never use it as a return value.
