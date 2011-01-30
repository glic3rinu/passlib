"""passlib.hash.sha256_crypt - SHA256-CRYPT

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
#core
from hashlib import sha256, sha512
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import norm_rounds, norm_salt, h64
#pkg
#local
__all__ = [
    "genhash",
    "genconfig",
    "encrypt",
    "identify",
    "verify",
]

#=========================================================
#pure-python backend (shared between sha256-crypt & sha512-crypt)
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
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, sha256)

    #encode result
    out = ''
    a, b, c = 0, 10, 20
    while a < 30:
        out += h64.encode_3_offsets(result, c, b, a)
        a, b, c = c+1, a+1, b+1
    assert a == 30, "loop went to far: %r" % (a,)
    out += h64.encode_2_offsets(result, 30, 31)
    assert len(out) == 43, "wrong length: %r" % (out,)
    return out, salt, rounds

def raw_sha512_crypt(secret, salt, rounds):
    "perform raw sha512-crypt; returns encoded checksum, normalized salt & rounds"
    #run common crypt routine
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, sha512)

    #encode result
    out = ''
    a, b, c = 0, 21, 42
    while c < 63:
        out += h64.encode_3_offsets(result, c, b, a)
        a, b, c = b+1, c+1, a+1
    assert c == 63, "loop to far: %r" % (c,)
    out += h64.encode_1_offset(result, 63)
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
    if crypt("test", "$5$rounds=1000$test") == "$5$rounds=1000$test$QmQADEXMG8POI5WDsaeho0P36yK3Tcrgboabng6bkb/":
        backend = "os-crypt"
    else:
        crypt = None

#=========================================================
#algorithm information
#=========================================================
name = "sha256_crypt"
#stats: 256 bit checksum, 96 bit salt, 1000..10e8-1 rounds

setting_kwds = ("salt", "rounds")
context_kwds = ()

default_rounds = 40000 #current passlib default
min_rounds = 1000
max_rounds = 999999999

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$5
    (\$rounds=(?P<rounds>\d+))?
    \$
    (
        (?P<salt1>[^:$]*)
        |
        (?P<salt2>[^:$]{0,16})
        \$
        (?P<chk>[A-Za-z0-9./]{43})?
    )
    $
    """, re.X)

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid sha256-crypt hash"
    rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
    return dict(
        implicit_rounds = not rounds,
        rounds=int(rounds) if rounds else 5000,
        salt=salt1 or salt2,
        checksum=chk,
    )

def render(rounds, salt, checksum=None, implicit_rounds=True):
    assert '$' not in salt
    if rounds == 5000 and implicit_rounds:
        return "$5$%s$%s" % (salt, checksum or '')
    else:
        return "$5$rounds=%d$%s$%s" % (rounds, salt, checksum or '')

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None, implicit_rounds=True):
    """generate sha256-crypt configuration string

    :param salt:
        optional salt string to use.

        if omitted, one will be automatically generated (recommended).

        length must be 0 .. 16 characters inclusive.
        characters must be in range ``A-Za-z0-9./``.

    :param rounds:

        optional number of rounds, must be between 1000 and 999999999 inclusive.

    :param implicit_rounds:

        this is an internal option which generally doesn't need to be touched.

    :returns:
        sha256-crypt configuration string.
    """
    #TODO: allow salt charset 0-255 except for "\x00\n:$"
    salt = norm_salt(salt, 0, 16, name=name)
    rounds = norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name=name)
    return render(rounds, salt, None, implicit_rounds)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)

    #run through chosen backend
    if crypt:
        #using system's crypt routine.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return crypt(secret, config)
    else:
        #using builtin routine
        info = parse(config)
        checksum, salt, rounds = raw_sha256_crypt(secret, info['salt'], info['rounds'])
        return render(rounds, salt, checksum, info['implicit_rounds'])

#=========================================================
#secondary interface
#=========================================================
def encrypt(secret, **settings):
    return genhash(secret, genconfig(**settings))

def verify(secret, hash):
    return hash == genhash(secret, hash)

def identify(hash):
    return bool(hash and _pat.match(hash))

#=========================================================
#eof
#=========================================================
