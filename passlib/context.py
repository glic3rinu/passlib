"""passlib - implementation of various password hashing functions"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import inspect
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.utils import abstract_class_method, Undef
from passlib.handler import get_crypt_handler, is_crypt_handler
#pkg
#local
__all__ = [
    'CryptContext',
    "is_crypt_context",
]

#=========================================================
#
#=========================================================
class CryptContext(object):
    """Helper for encrypting passwords using different algorithms.

    Different storage contexts (eg: linux shadow files vs openbsd shadow files)
    may use different sets and subsets of the available algorithms.
    This class encapsulates such distinctions: it represents an ordered
    list of algorithms, each with a unique name. It contains methods
    to verify against existing algorithms in the context,
    and still encrypt using new algorithms as they are added.

    Because of all of this, it's basically just a list object.
    However, it contains some dictionary-like features
    such as looking up algorithms by name, and it's restriction
    that no two algorithms in a list share the same name
    causes it to act more like an "ordered set" than a list.

    In general use, none of this matters.
    The typical use case is as follows::

        >>> from passlib import hash
        >>> #create a new context that only understands Md5Crypt & BCrypt
        >>> myctx = hash.CryptContext([ hash.Md5Crypt, hash.BCrypt ])

        >>> #the last one in the list will be used as the default for encrypting...
        >>> hash1 = myctx.encrypt("too many secrets")
        >>> hash1
        '$2a$11$RvViwGZL./LkWfdGKTrgeO4khL/PDXKe0TayeVObQdoew7TFwhNFy'

        >>> #choose algorithm explicitly
        >>> hash2 = myctx.encrypt("too many secrets", alg="md5-crypt")
        >>> hash2
        '$1$E1g0/BY.$gS9XZ4W2Ea.U7jMueBRVA.'

        >>> #verification will autodetect the right hash
        >>> myctx.verify("too many secrets", hash1)
        True
        >>> myctx.verify("too many secrets", hash2)
        True
        >>> myctx.verify("too many socks", hash2)
        False

        >>> #you can also have it identify the algorithm in use
        >>> myctx.identify(hash1)
        'bcrypt'
        >>> #or just return the CryptHandler instance directly
        >>> myctx.identify(hash1, resolve=True)
        <passlib.BCrypt object, name="bcrypt">

        >>> #you can get a list of algs...
        >>> myctx.keys()
        [ 'md5-crypt', 'bcrypt' ]

        >>> #and get the CryptHandler object by name
        >>> bc = myctx['bcrypt']
        >>> bc
        <passlib.BCrypt object, name="bcrypt">
    """
    _lazy = False
    _handlers = None

    def __init__(self, handlers, lazy=False):
        if lazy:
            self._lazy = True
            self._handlers = list(handlers)
        else:
            self._handlers = h = map(self._norm_handler, handlers)

    def _norm_handler(self, handler):
        if isinstance(handler, str):
            handler = get_crypt_handler(handler)
        if not is_crypt_handler(handler):
            raise TypeError, "handler must be CryptHandler class or name: %r" % (handler,)
        return handler

    def _get_handlers(self):
        "helper which handles lazy-loading"
        h = self._handlers
        if self._lazy:
            self._handlers = h = map(self._norm_handler, h)
            self._lazy = False
        return h

    def __repr__(self):
        names = [ handler.name or handler for handler in self._get_handlers() ]
        return "CryptContext(%r)" % (names,)

    def lookup(self, name=None, required=False):
        """given an algorithm name, return CryptHandler instance which manages it.
        if no match is found, returns None.

        if name is None, will return default algorithm
        """
        handlers = self._get_handlers()
        if not handlers:
            if required:
                raise KeyError, "no crypt algorithms registered with context"
            return None
        if name and name != "default":
            for handler in handlers:
                if handler.name == name:
                    return handler
            for handler in handlers:
                if name in handler.aliases:
                    return handler
        else:
            return handlers[-1]
        if required:
            raise KeyError, "no crypt algorithm by that name in context: %r" % (name,)
        return None

    def identify(self, hash, name=False, required=False):
        """Attempt to identify which algorithm hash belongs to w/in this context.

        :arg hash:
            The hash string to test.

        :param name:
            If true, returns the name of the handler
            instead of the handler itself.

        All registered algorithms will be checked in from last to first,
        and whichever one claims the hash first will be returned.

        :returns:
            The handler which first identifies the hash,
            or ``None`` if none of the algorithms identify the hash.
        """
        if hash is None:
            if required:
                raise ValueError, "no hash specified"
            return None
        #NOTE: going in reverse order so default handler gets checked first,
        # also so if handler 0 is a legacy "plaintext" handler or some such,
        # it doesn't match *everything* that's passed into this function.
        for handler in self._get_handlers():
            if handler.identify(hash):
                if name:
                    return handler.name
                else:
                    return handler
        if required:
            raise ValueError, "hash could not be identified"
        return None

    def encrypt(self, secret, alg=None, **kwds):
        """encrypt secret, returning resulting hash.

        :arg secret:
            String containing the secret to encrypt

        :param alg:
            Optionally specify the name of the algorithm to use.
            If no algorithm is specified, an attempt is made
            to guess from the hash string. If no hash string
            is specified, the last algorithm in the list is used.

        :param **kwds:
            All other keyword options are passed to the algorithm's encrypt method.
            The two most common ones are "keep_salt" and "rounds".

        :returns:
            The secret as encoded by the specified algorithm and options.
        """
        if not self:
            raise ValueError, "no algorithms registered"
        handler = self.lookup(alg, required=True)
        return handler.encrypt(secret, **kwds)

    def verify(self, secret, hash, alg=None, **kwds):
        """verify secret against specified hash

        :arg secret:
            the secret to encrypt
        :arg hash:
            hash string to compare to
        :param alg:
            optionally specify which algorithm(s) should be considered.
        """
        if not self:
            raise ValueError, "no algorithms registered"
        if hash is None:
            return False
        if alg:
            handler = self.lookup(alg, required=True)
        else:
            handler = self.identify(hash, required=True)
        return handler.verify(secret, hash, **kwds)

def is_crypt_context(obj):
    "check if obj following CryptContext protocol"
    #NOTE: this isn't an exhaustive check of all required attrs,
    #just a quick check of the most uniquely identifying ones
    return all(hasattr(obj, name) for name in (
        "lookup", "verify", "encrypt", "identify",
        ))

#=========================================================
# eof
#=========================================================
