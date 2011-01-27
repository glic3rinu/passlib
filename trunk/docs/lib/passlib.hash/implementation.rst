===================================================================
:mod:`passlib` - Implementing a Custom Crypt Algorithm
===================================================================

.. currentmodule:: passlib

New password algorithms can be implemented
by subclassing :class:`CryptHandler`,
which provides the underlying framework used
for all the password algorithms.

To create a new one,
you simple subclass CryptHandler,
and implement the identify, encrypt, and verify methods
(at the very least).

.. autoclass:: CryptHandler
