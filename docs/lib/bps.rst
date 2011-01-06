==============
Global Exports
==============

This page deals lists the objects that are imported
when using the command ``from bps import *``.

While the BPS package is generally accessed by importing
one one of the submodules, it does offer a limited list
of exports, which are designed to be dropped into your
module's global namespace directly.

Since populating the global namespace like this usually
causes havoc due to it's implict nature, the objects
exported by default have been limited only to ones
which the BPS authors felt day in and day out were
going to be needed so often, and so unpredictably,
that it would be nice if they were available almost like builtins.
Thus, much of our code begins with the stanza::

    >>> #import from the bps global namespace
    >>> from bps import *

This ensures a number of very useful objects
are always available. But since this import can be abused,
objects are very rarely added to this list.

Exported Objects
================
The following objects will be exported by ``from bps import *``.
While they are documented more fully elsewhere, here is a quick description:

    :func:`abstractmethod() <bps.meta.abstractmethod>`

        This is a very useful decorator to have around if you do a lot
        of interface-style class creation.

        .. note::
            A native version has been introduced
            in Python 2.6, but that is not yet used by BPS.

    :class:`BaseClass <bps.types.BaseClass>`

        This class can be used as a drop-in replacement for ``object``,
        it provides features such as an intelligent ``self.__super`` method,
        and a ``cls.__initsubclass__`` method for performing actions
        based on the created of inherited classes.

    :func:`filepath() <bps.fs.filepath>`

        This is the constructor for BPS's all-singing-all-dancing filepath object.
        It's so useful, this was the first global export added.
        Never use `os.path` again!

    :func:`log <bps.logs.log>`

        This is a magic logger object.
        Import it into your module and call it,
        and through introspection, it will act just like ``logging.getLogger(__name__)``,
        and log all messages to the name of the module it was called from.

    :func:`partial`
        This is an export of stdlib's `functools.partial <http://docs.python.org/library/functools.html#functools.partial>`_,
        since it is used a lot (at least, by the BPS developers it is).
        An implementation of this has been exported by BPS since it's inception,
        it was only when Python 2.5 was set as a minimum requirement
        that BPS started using the stdlib version.

    :data:`Undef <bps.types.Undef>`

        A companion to ``None`` which represents an undefined/missing value.
        Same as javascript's "undefined".

    :func:`warn`

        This is an export of stdlib's `warnings.warn <http://docs.python.org/library/warnings.html#warnings.warn>`_.
        Warnings should be used much more often then they are,
        and that would be encouraged if not for the inconvience
        of having to add an import stanza at the top.
