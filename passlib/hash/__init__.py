from passlib.hash.base import CryptContext
from passlib.hash.unix_crypt import UnixCrypt
from passlib.hash.md5_crypt import Md5Crypt
from passlib.hash.sha_crypt import Sha256Crypt, Sha512Crypt
from passlib.hash.bcrypt import BCrypt

#=========================================================
#build up the standard context objects
#=========================================================

#default context for quick use.. recognizes all known algorithms,
#   currently uses SHA-512 as default
default_context = CryptContext([ UnixCrypt, Md5Crypt, BCrypt, Sha256Crypt, Sha512Crypt ])

def identify(hash, resolve=False):
    """Identify algorithm which generated a password hash.

    :arg hash:
        The hash string to identify.
    :param resolve:
        If ``True``, this function will return a :class:`CryptAlgorithm`
        instance which can handle the hash.
        If ``False`` (the default), then only the name of the hash algorithm
        will be returned.

    The following algorithms are currently recognized:

        =================== ================================================
        Name                Description
        ------------------- ------------------------------------------------
        ``"unix-crypt"``    the historical unix-crypt algorithm

        ``"md5-crypt"``     the md5-crypt algorithm, usually identified
                            by the prefix ``$1$`` in unix shadow files.

        ``"bcrypt"``        the openbsd blowfish-crypt algorithm,
                            usually identified by the prefixes ``$2$`` or ``$2a$``
                            in unix shadow files.

        ``"sha256-crypt"``  the 256-bit version of the sha-crypt algorithm,
                            usually identified by the prefix ``$5$``
                            in unix shadow files.

        ``"sha512-crypt"``  the 512-bit version of the sha-crypt algorithm,
                            usually identified by the prefix ``$6$``
                            in unix shadow files.
        =================== ================================================

    :returns:
        The name of the hash, or ``None`` if the hash could not be identified.
        (The return may be altered by the *resolve* keyword).

    .. note::
        This is a convience wrapper for ``pwhash.default_context.identify(hash)``.
    """
    return default_context.identify(hash, resolve=resolve)

def encrypt(secret, hash=None, alg=None, **kwds):
    """Encrypt secret using a password hash algorithm.

    :type secret: str
    :arg secret:
        String containing the secret to encrypt

    :type hash: str|None
    :arg hash:
        Optional previously existing hash string which
        will be used to provide default value for the salt, rounds,
        or other algorithm-specific options.
        If not specified, algorithm-chosen defaults will be used.

    :type alg: str|None
    :param alg:
        Optionally specify the name of the algorithm to use.
        If no algorithm is specified, an attempt is made
        to guess from the hash string. If no hash string
        is specified, sha512-crypt will be used.
        See :func:`identify` for a list of algorithm names.

    All other keywords are passed on to the specific password algorithm
    being used to encrypt the secret.

    :type keep_salt: bool
    :param keep_salt:
        This option is accepted by all of the builtin algorithms.

        By default, a new salt value generated each time
        a secret is encrypted. However, if this keyword
        is set to ``True``, and a previous hash string is provided,
        the salt from that string will be used instead.

        .. note::
            This is generally only useful when verifying an existing hash
            (see :func:`verify`). Other than that, this option should be
            avoided, as re-using a salt will needlessly decrease security.

    :type rounds: int
    :param rounds:
        For the sha256-crypt and sha512-crypt algorithms,
        this option lets you specify the number of rounds
        of encryption to use. For the bcrypt algorithm,
        this option lets you specify the log-base-2 of
        the number of rounds of encryption to use.

        For all three of these algorithms, you can either
        specify a positive integer, or one of the strings
        "fast", "medium", "slow" to choose a preset number
        of rounds corresponding to an appropriate level
        of encryption.

    :returns:
        The secret as encoded by the specified algorithm and options.
    """
    return default_context.encrypt(secret, hash=hash, alg=alg, **kwds)

def verify(secret, hash, alg=None):
    """verify a secret against an existing hash.

    This checks if a secret matches against the one stored
    inside the specified hash. By default this uses :func:`encrypt`
    to re-crypt the secret, and compares it to the provided hash;
    though some algorithms may implement this in a more efficient manner.

    :type secret: str
    :arg secret:
        A string containing the secret to check.

    :type hash: str
    :param hash:
        A string containing the hash to check against.

    :type alg: str|None
    :param alg:
        Optionally specify the name of the algorithm to use.
        If no algorithm is specified, an attempt is made
        to guess from the hash string. If it can't be
        identified, a ValueError will be raised.
        See :func:`identify` for a list of algorithm names.

    :returns:
        ``True`` if the secret matches, otherwise ``False``.
    """
    return default_context.verify(secret, hash, alg=alg)

#some general os-context helpers (these may not match your os policy exactly, but are generally useful)
linux_context = CryptContext([ UnixCrypt, Md5Crypt, Sha256Crypt, Sha512Crypt ])
bsd_context = CryptContext([ UnixCrypt, Md5Crypt, BCrypt ])

#=========================================================
#eof
#=========================================================
