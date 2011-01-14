"""passlib.pbkdf2 - PBKDF2 support

"""
#=================================================================================
#imports
#=================================================================================
#core
from binascii import unhexlify
from cStringIO import StringIO
import hashlib
import hmac
import logging; log = logging.getLogger(__name__)
import re
from struct import pack
#site
try:
    from M2Crypto import EVP as _EVP
except ImportError:
    _EVP = None
#pkg
from passlib.util import xor_bytes
#local
__all__ = [
    "pbkdf2",
]

#=================================================================================
#backend
#=================================================================================
MAX_BLOCKS = 0xffffffffL #2**32-1

def pbkdf2(secret, salt, rounds, keylen, digest="sha1", hmac_const=hmac.new):
    """pkcs#5 password-based key derivation v2.0

    :arg secret: passphrase to use to generate key
    :arg salt: salt string to use when generating key
    :param rounds: number of rounds to use to generate key
    :arg keylen: number of bytes to generate
    :param digest:
        hash function to use with HMAC.
        should be a string (eg "sha1", "sha256", etc)
        which is recognized by :func:`M2Crypto.EVP.hmac` (if present),
        or :func:`hashlib.new`.
        can also be a hash module (eg ``sha``) or hash constructor
        (eg ``hashlib.sha256``).

    This function attempts to use M2Crypto as a backend
    if available and if the digest is a string supported
    by M2Crypto. Otherwise it falls back to a software implementation.

    :returns:
        raw bytes of generated key
    """

    #prepare secret
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")
    elif not isinstance(secret, str):
        raise TypeError("secret must be str or unicode")

    #prepare salt
    if isinstance(salt, unicode):
        salt = salt.encode("utf-8")
    elif not isinstance(salt, str):
        raise TypeError("salt must be str or unicode")

    #preprare rounds
    if not isinstance(rounds, (int, long)):
        raise TypeError("rounds must be an integer")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    #setup prf (may be overridden when digest is parsed)
    def prf(key, msg):
        return hmac_const(key, msg, digest_const).digest()

    #parse digest into digest_const & digest_size
    digest_const = None
    if isinstance(digest, str):
        #check if m2crypto is installed
        if _EVP:
            #can do this directly from m2crypto
            if digest == "sha1":
                try:
                    return _EVP.pbkdf2(secret, salt, rounds, keylen)
                except OverflowError:
                    raise ValueError, "key length too long"
            #check if _EVP.hmac supports specified algorithm
            try:
                result = _EVP.hmac('x', 'y', digest)
            except ValueError:
                pass
            else:
                #it does. so use M2Crypto's hmac & digest code
                hmac_const = _EVP.hmac
                digest_const = True #signal that this is not needed
                digest_size = len(result)
                def prf(key, msg):
                    return hmac_const(key, msg, digest)

        #fallback to hashlib & hmac
        if not digest_const:
            digest_const = getattr(hashlib, digest, None)
            if not digest_const:
                raise ValueError, "unknown digest: %r" % (digest,)
            digest_size = digest_const().digest_size

    elif hasattr(digest, "new"):
        #it's a module, eg "sha"
        digest_const = digest.new
        digest_size = digest.digest_size

    else:
        #it's a constructor, eg "hashlib.sha1" or "sha.new"
        digest_const = digest
        digest_size = digest_const().digest_size

    #figure out how many blocks we'll need
    bcount = (keylen+digest_size-1)//digest_size
    if bcount > MAX_BLOCKS:
        raise ValueError, "key length to long"

    #build up key from blocks
    out = StringIO()
    write = out.write
    for i in xrange(1,bcount+1):
        block = tmp = prf(secret, salt + pack(">L", i))
        #NOTE: could potentially unroll this loop somewhat for speed,
        # or find some faster way to accumulate & xor tmp values together
        for j in xrange(rounds-1):
            tmp = prf(secret, tmp)
            block = xor_bytes(block, tmp)
        write(block)
    #and done
    return out.getvalue()[:keylen]

#=================================================================================
#eof
#=================================================================================
