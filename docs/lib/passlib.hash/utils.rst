=============================================
:mod:`passlib` - Helper Functions
=============================================

.. currentmodule:: passlib

A couple of utility functions are available,
mainly useful when writing custom password hash algorithms.
The ``h64_*`` series of functions all provide
utilities for encoding & decoding strings
under the modified base64 system used by most
of the standard unix hash algorithms.

.. autofunction:: h64_encode
.. autofunction:: h64_decode
.. autofunction:: h64_gen_salt

.. autofunction:: is_crypt_context
.. autofunction:: is_crypt_handler
