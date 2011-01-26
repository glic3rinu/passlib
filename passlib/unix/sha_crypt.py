"""passlib.unix.sha_crypt - implements SHA-256-Crypt & SHA-512-Crypt

This implementation is based on Ulrich Drepper's
``sha-crypt specification <http://www.akkadia.org/drepper/sha-crypt.txt>``.
It should be byte-compatible with unix shadow hashes beginning with ``$5$`` and ``$6%``.

About
=====
This implementation is based on Ulrich Drepper's
``sha-crypt specification <http://www.akkadia.org/drepper/sha-crypt.txt>``.
It should be byte-compatible with unix shadow hashes beginning with ``$5$`` and ``$6%``.

This module is not intended to be used directly,
but merely as a backend for :mod:`passlib.unix.sha_crypt`
when native sha crypt support is not available.

Deviations from the Specification
=================================

Unicode
-------
The sha-crypt specification makes no statement regarding
the unicode support, it merely takes in a series of bytes.

In order to support non-ascii passwords and :class:`unicode` class,
this implementation makes the arbitrary decision to encode all unicode passwords
to ``utf-8`` before passing it into the encryption function.

Salt Length
-----------
The sha-crypt specification allows salt strings of length 0-16 inclusive.
However, most implementations (including this one) will only
generate salts of length 16, though they allow the full range.

Salt Characters
---------------
The charset used by salt strings is poorly defined for sha-crypt.

The sha-crypt spec does not make any statements about the allowable
salt charset, one way or the other. Furthermore, the reference implementation
within the spec, and linux implementation, cheerfully allow
all 8-bit values besides ``\x00`` and ``$``, and excluding
those not by choice, but due to implementation details.
Thus the argument could be made that all other characters should be allowed.

However, allowing the characters ``:`` and ``\n`` would cause
problems for the most common application of this algorithm,
storage in ``/etc/shadow``. As well, the most unix shadow suites
only generate salts using the chars ``./0-9A-Za-z``.

Thus, as a compromise, this implementation of sha-crypt
will allow all salt characters except for ``\x00\n:$``,
in order to support as much of the specification as feasible;
but it will only generate salts using the chars ``./0-9A-Za-z``,
in order to remain compatible with the majority of hashes
out there, in case other tools have made different assumptions.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.handler import ExtCryptHandler, register_crypt_handler
from passlib.utils import abstract_class_method, \
    h64_encode_3_offsets, h64_encode_2_offsets, h64_encode_1_offset
#pkg
#local
__all__ = [
    'Sha256Crypt',
    'Sha512Crypt',
]

#=========================================================
#pure-python backend
#=========================================================
def raw_sha_crypt(secret, salt, rounds, hash):
    """perform raw sha crypt

    :arg secret: password to encode (if unicode, encoded to utf-8)
    :arg salt: salt string to use (required)
    :arg rounds: int rounds
    :arg hash: hash constructor function for 256/512 variant

    :returns:
        Returns tuple of ``(unencoded checksum, normalized salt, normalized rounds)``.

    """
    #validate secret
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #validate rounds
    if rounds < 1000:
        rounds = 1000
    if rounds > 999999999:
        rounds = 999999999

    #validate salt
    if any(c in salt for c in '\x00$'):
        raise ValueError, "invalid chars in salt"
    if len(salt) > 16:
        salt = salt[:16]

    #init helpers
    def extend(source, size_ref):
        "helper which repeats <source> digest string until it's the same length as <size_ref> string"
        assert len(source) == chunk_size
        size = len(size_ref)
        return source * int(size/chunk_size) + source[:size % chunk_size]

    #calc digest B
    b = hash(secret)
    chunk_size = b.digest_size #grab this once hash is created
    b.update(salt)
    a = b.copy() #make a copy to save a little time later
    b.update(secret)
    b_result = b.digest()
    b_extend = extend(b_result, secret)

    #begin digest A
    #a = hash(secret) <- performed above
    #a.update(salt) <- performed above
    a.update(b_extend)

    #for each bit in slen, add B or SECRET
    value = len(secret)
    while value > 0:
        if value % 2:
            a.update(b_result)
        else:
            a.update(secret)
        value >>= 1

    #finish A
    a_result = a.digest()

    #calc DP - hash of password, extended to size of password
    dp = hash(secret * len(secret))
    dp_result = extend(dp.digest(), secret)

    #calc DS - hash of salt, extended to size of salt
    ds = hash(salt * (16+ord(a_result[0])))
    ds_result = extend(ds.digest(), salt) #aka 'S'

    #
    #calc digest C
    #NOTE: this has been contorted a little to allow pre-computing
    #some of the hashes. the original algorithm was that
    #each round generates digest composed of:
    #   if round%2>0 => dp else lr
    #   if round%3>0 => ds
    #   if round%7>0 => dp
    #   if round%2>0 => lr else dp
    #where lr is digest of the last round's hash (initially = a_result)
    #

    #pre-calculate some digests to speed up odd rounds
    dp_hash = hash(dp_result).copy
    dp_ds_hash = hash(dp_result + ds_result).copy
    dp_dp_hash = hash(dp_result * 2).copy
    dp_ds_dp_hash = hash(dp_result + ds_result + dp_result).copy

    #pre-calculate some strings to speed up even rounds
    ds_dp_result = ds_result + dp_result
    dp_dp_result = dp_result * 2
    ds_dp_dp_result = ds_result + dp_dp_result

    #run through rounds
    last_result = a_result
    i = 0
    while i < rounds:
        if i % 2:
            if i % 3:
                if i % 7:
                    c = dp_ds_dp_hash()
                else:
                    c = dp_ds_hash()
            elif i % 7:
                c = dp_dp_hash()
            else:
                c = dp_hash()
            c.update(last_result)
        else:
            c = hash(last_result)
            if i % 3:
                if i % 7:
                    c.update(ds_dp_dp_result)
                else:
                    c.update(ds_dp_result)
            elif i % 7:
                c.update(dp_dp_result)
            else:
                c.update(dp_result)
        last_result = c.digest()
        i += 1

    #return unencoded result, along w/ normalized config values
    return last_result, salt, rounds

def raw_sha256_crypt(secret, salt, rounds):
    "perform raw sha256-crypt; returns encoded checksum, normalized salt & rounds"
    #run common crypt routine
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, hashlib.sha256)

    #encode result
    out = ''
    a, b, c = 0, 10, 20
    while a < 30:
        out += h64_encode_3_offsets(result, c, b, a)
        a, b, c = c+1, a+1, b+1
    assert a == 30, "loop went to far: %r" % (a,)
    out += h64_encode_2_offsets(result, 30, 31)
    assert len(out) == 43, "wrong length: %r" % (out,)
    return out, salt, rounds

def raw_sha512_crypt(secret, salt, rounds):
    "perform raw sha512-crypt; returns encoded checksum, normalized salt & rounds"
    #run common crypt routine
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, hashlib.sha512)

    #encode result
    out = ''
    a, b, c = 0, 21, 42
    while c < 63:
        out += h64_encode_3_offsets(result, c, b, a)
        a, b, c = b+1, c+1, a+1
    assert c == 63, "loop to far: %r" % (c,)
    out += h64_encode_1_offset(result, 63)
    assert len(out) == 86, "wrong length: %r" % (out,)
    return out, salt, rounds

#=========================================================
#choose backend
#=========================================================

#fallback to default backend (defined above)
backend = "builtin"

#check if stdlib crypt is available, and if so, if OS supports $5$ and $6$
#XXX: is this test expensive enough it should be delayed
#until sha-crypt is requested?

try:
    from crypt import crypt
except ImportError:
    crypt = None
else:
    if (
        crypt("test", "$5$rounds=1000$test") == "$5$rounds=1000$test$QmQADEXMG8POI5WDsaeho0P36yK3Tcrgboabng6bkb/"
        and
        crypt("test", "$6$rounds=1000$test") == "$6$rounds=1000$test$2M/Lx6MtobqjLjobw0Wmo4Q5OFx5nVLJvmgseatA6oMnyWeBdRDx4DU.1H3eGmse6pgsOgDisWBGI5c7TZauS0"
        ):
        backend = "stdlib"
    else:
        crypt = None

#=========================================================
#ids 5,6 -- sha
#algorithm defined on this page:
#   http://people.redhat.com/drepper/SHA-crypt.txt
#=========================================================
class _ShaCrypt(ExtCryptHandler):
    "common code for used by Sha(256|512)Crypt Classes"
    #=========================================================
    #crypt info
    #=========================================================

    #name - provided by subclass
    setting_kwds = ("salt", "rounds")

    secret_chars = -1

    min_salt_chars = 0
    salt_chars = 16

    default_rounds = 40000
    min_rounds = 1000
    max_rounds = 999999999

    #=========================================================
    #backend backend
    #=========================================================
    _pat = None #regexp for hash string - provided by subclass
    _ident = None #identifier hash string - provided by subclass
    _raw_crypt = None #corresponding crypt func from builtin backend - provided by subclass

    @classmethod
    def _validate_salt_chars(cls, salt):
        #see documentation in _sha_crypt with regards to why we allow
        #all chars except the following...
        if any(c in salt for c in '\x00\n:$'):
            raise ValueError, "invalid %s salt: '\\x00', '\\n', ':', and '$' chars forbidden" % (cls.name,)
        return salt

    #TODO: merge this into parse()
    @classmethod
    def parse_config(cls, config):
        "parse partial hash containing just salt+rounds, with salt potentially too large"
        if not config:
            raise ValueError, "invalid sha hash/salt"
        m = re.search(r"""
            ^
            \$""" + cls._ident + r"""
            (\$rounds=(?P<rounds>\d+))?
            \$(?P<salt>[^:$]*)
            $
            """, config, re.X)
        if not m:
            raise ValueError, "invalid sha hash/salt"
        rounds, salt = m.group("rounds", "salt")
        return dict(
            implicit_rounds = not rounds,
            rounds = int(rounds) if rounds else 5000,
            salt = salt,
        )

    #=========================================================
    #frontend helpers
    #=========================================================
    @classmethod
    def identify(cls, hash):
        "identify bcrypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def parse(cls, hash):
        "parse bcrypt hash"
        if not hash:
            raise ValueError, "invalid sha hash/salt"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sha hash/salt"
        rounds, salt, chk = m.group("rounds", "salt", "chk")
        return dict(
            implicit_rounds = not rounds,
            rounds = int(rounds) if rounds else 5000,
            salt=salt,
            checksum=chk,
        )

    @classmethod
    def render(cls, rounds, salt, checksum=None, implicit_rounds=True):
        assert '$' not in salt
        if rounds == 5000 and implicit_rounds:
            out = "$%s$%s" % (cls._ident, salt)
        else:
            out = "$%s$rounds=%d$%s" % (cls._ident, rounds, salt)
        if checksum:
            out += "$" + checksum
        return out

    @classmethod
    def genconfig(cls, salt=None, rounds=None, implicit_rounds=True):
        salt = cls._norm_salt(salt)
        rounds = cls._norm_rounds(rounds)
        return cls.render(rounds, salt, None, implicit_rounds)

    @classmethod
    def genhash(cls, secret, config=None):
        config = cls._prepare_config(config)
        if crypt:
            #using system's crypt routine.
            if isinstance(secret, unicode):
                secret = secret.encode("utf-8")
            return crypt(secret, config)
        else:
            #using builtin routine
            info = cls.parse(config)
            checksum, salt, rounds = cls._raw_crypt(secret, info['salt'], info['rounds'])
            return cls.render(rounds, salt, checksum, info['implicit_rounds'])

    #=========================================================
    #eoc
    #=========================================================

class Sha256Crypt(_ShaCrypt):
    """This class implements the SHA-256 Crypt Algorithm,
    according to the specification at `<http://people.redhat.com/drepper/SHA-crypt.txt>`_.
    It should be byte-compatible with unix shadow hashes beginning with ``$5$``.

    See Sha512Crypt for usage examples and details.
    """
    #=========================================================
    #algorithm info
    #=========================================================
    name='sha256-crypt'
    #stats: 256 bit checksum, 96 bit salt, 1000..10e8-1 rounds

    #=========================================================
    #backend
    #=========================================================
    _ident = '5'

    _pat = re.compile(r"""
        ^
        \$(?P<ident>5)
        (\$rounds=(?P<rounds>\d+))?
        \$(?P<salt>[^:$]{0,16})
        \$(?P<chk>[A-Za-z0-9./]{43})
        $
        """, re.X)

    _raw_crypt = raw_sha256_crypt

    #=========================================================
    #eof
    #=========================================================

register_crypt_handler(Sha256Crypt)

class Sha512Crypt(_ShaCrypt):
    """This class implements the SHA-512 Crypt Algorithm,
    according to the specification at `http://people.redhat.com/drepper/SHA-crypt.txt`_.
    It should be byte-compatible with unix shadow hashes beginning with ``$6$``.

    This implementation is based on a pure-python translation
    of the original specification.

    .. note::
        This is *not* just the raw SHA-512 hash of the password,
        which is sometimes incorrectly referred to as sha512-crypt.
        This is a variable-round descendant of md5-crypt,
        and is comparable in strength to bcrypt.

    Usage Example::

        >>> from passlib import Sha512Crypt
        >>> crypt = Sha512Crypt()
        >>> #to encrypt a new secret with this algorithm
        >>> hash = crypt.encrypt("forget me not")
        >>> hash
        '$6$rounds=11949$KkBupsnnII6YXqgT$O8qAEcEgDyJlMC4UB3buST8vE1PsPPABA.0lQIUARTNnlLPZyBRVXAvqqynVByGRLTRMIorkcR0bsVQS5i3Xw1'
        >>> #to verify an existing secret
        >>> crypt.verify("forget me not", hash)
        True
        >>> crypt.verify("i forgot it", hash)
        False

    .. automethod:: encrypt
    """
    #=========================================================
    #crypt info
    #=========================================================
    name='sha512-crypt'
    #stats: 512 bit checksum, 96 bit salt, 1000..10e8-1 rounds

    #=========================================================
    #backend
    #=========================================================
    _ident = '6'

    _pat = re.compile(r"""
        ^
        \$(?P<ident>6)
        (\$rounds=(?P<rounds>\d+))?
        \$(?P<salt>[^:$]{0,16})
        \$(?P<chk>[A-Za-z0-9./]{86})
        $
        """, re.X)

    _raw_crypt = raw_sha512_crypt

    #=========================================================
    #eof
    #=========================================================

register_crypt_handler(Sha512Crypt)

#=========================================================
# eof
#=========================================================
