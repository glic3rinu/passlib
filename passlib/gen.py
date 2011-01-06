"""bps.security.pwhash - password hashing tools"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import inspect
import hashlib
import logging; log = logging.getLogger(__name__)
import os
import re
import time
#site
#libs
#pkg
from bps.rng import srandom
from passlib._gpw_data import get_gpw_data as _get_gpw_data
#local
__all__ = [
    #frontend
    'generate_secret',

    #base classes
    'PasswordGenerator',
    'PhoneticGenerator',

    #algorithms
    'RandomGenerator',
    'CvcGenerator',
    'GpwGenerator',

]

#=========================================================
#base generation classes
#=========================================================
class PasswordGenerator(BaseClass):
    size = 16 #default password size
    padding = 0 #padding being added (used by phonetic algs)

    def __init__(self, size=None, **kwds):
        self.__super.__init__(**kwds)
        if size is not None:
            self.size = size

    def get_size(self):
        size = self.size
        if isinstance(size, tuple):
            start, end = size
            return srandom.randrange(start, end)-self.padding
        else:
            return size-self.padding

    def get_size_range(self):
        if isinstance(self.size, tuple):
            min_size, max_size = self.size
        else:
            min_size = max_size = self.size
        return min_size-self.padding, max_size-self.padding

    def __call__(self, count=None):
        srandom.reseed() #shake the prng before generating passwords
        if count == "iter": #mild hack to return an iterator
            return self
        elif count is None:
            return self.next()
        else:
            next = self.next
            return [ next() for i in xrange(count) ]

    def __iter__(self):
        srandom.reseed() #shake the prng before generating passwords
        return self

    @abstractmethod
    def next(self):
        "generate and return a new password"

class PhoneticGenerator(PasswordGenerator):
    size = (10, 13) #default password size for phonetic generators
    numeric_head = 0
    numeric_tail = 0

    def __init__(self, numeric_head=None, numeric_tail=None, **kwds):
        self.__super.__init__(**kwds)
        if numeric_head > 0:
            self.numeric_head = numeric_head
        if numeric_tail > 0:
            self.numeric_tail = numeric_tail
        self.padding = self.numeric_head + self.numeric_tail

    def pad_secret(self, secret):
        if self.numeric_head:
            secret = self.gen_digits(self.numeric_head) + secret
        if self.numeric_tail:
            secret += self.gen_digits(self.numeric_tail)
        return secret

    def gen_digits(self, size):
        return ("%0" + str(size) + "d") % srandom.randrange(0, 10**size)


#=========================================================
#hex & alphanumeric dialect helpers
#=========================================================
_alphanum_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_other_chars = "!@#$%^&*()_+-=[]{}\\|/?\"';:,.<>"
class RandomGenerator(PasswordGenerator):
    "generate for generating random passwords from an alphabet"
    charsets = dict(
        hex="0123456789abcdef",
        alphanum=_alphanum_chars,
        ascii=_alphanum_chars + _other_chars,
    )
    def __init__(self, charset=None, alphabet=None, **kwds):
        self.__super.__init__(**kwds)
        if alphabet:
            self.alphabet = alphabet
        else:
            self.alphabet = self.charsets[charset.lower()]

    def next(self):
        size = self.get_size()
        return ''.join(srandom.choice(self.alphabet) for x in xrange(size))

#=========================================================
#cvc dialect helpers
#=========================================================
class CvcGenerator(PhoneticGenerator):
    #FIXME: like to support non-english groups here too
    patterns = dict(cv=25, cvv=10) ##, dv=4, dvv=1)
    consonants = "bcdfghjklmnprstvwxyz"
    doubled = "bdfglmprst"
    start_vowel = .05
    end_cons = .4
    vowels = "aeiou"

    def next(self):
        #NOTE: we ignore size, and work it out ourselves
        min_size, max_size = self.get_size_range()
        min_size = srandom.randrange(min_size, max_size+1)
        out = ""
        if srandom.random() < self.start_vowel:
            out += srandom.choice(self.vowels)
        while True:
            choice = srandom.weighted_choice(self.patterns)
            if not out and choice.startswith("d"):
                continue
            i = 0
            m = len(choice)-1
            while i < len(choice):
                s = choice[i]
                if s == "c":
                    buf = srandom.choice(self.consonants)
                    #make sure u follows q
                    if buf == "q":
                        if i < m and choice[i+1] == "v": #check for quV
                            buf += "u"
                            if i+1 < m and choice[i+2] == "v": #prevent quVV
                                i += 1
                        else: #else don't put q and end of syllable
                            continue
                elif s == "d":
                    buf = srandom.choice(self.doubled) * 2
                else:
                    buf = srandom.choice(self.vowels)
                out += buf
                i += 1
            if len(out) >= min_size:
                out = out[:max_size]
                if srandom.random() < self.end_cons:
                    c = srandom.choice(self.consonants)
                    if len(out) == max_size:
                        out = out[:-1] + c
                    else:
                        out += c
                return self.pad_secret(out)

#=========================================================
#gpw dialect helpers
#this algorithm (and probabilty table) taken from www.multicians.org/thvv/gpw.html
#=========================================================

class GpwGenerator(PhoneticGenerator):
    def __init__(self, language=None, **kwds):
        self.__super.__init__(**kwds)
        data = _get_gpw_data(language)
        self.alphabet = data['alphabet']
        self.tris = data['tris']
        self.tris_total = data['tris_total']

    def next(self):
        size = self.get_size()
        while True:
            secret = self.next_word(size)
            if secret is not None:
                break
        return self.pad_secret(secret)

    def pick_start(self):
        pik = 1+srandom.randrange(0, self.tris_total)
        cur = 0
        for c1, r1 in enumerate(self.tris):
            for c2, r2 in enumerate(r1):
                for c3, w in enumerate(r2):
                    cur += w
                    if cur >= pik:
                        return c1, c2, c3
        raise RuntimeError, "sigma < sum of weights!"

    def next_word(self, size):
        alphabet = self.alphabet
        tris = self.tris

        #pick random starting point, weighted by char occurrence
        c1, c2, c3 = self.pick_start()
        out = alphabet[c1]+alphabet[c2]+alphabet[c3]
        num = 3

        #do random walk
        while num < size:
            #find current weight row
            row = tris[c1][c2]

            #pick random point in weight range
            total = sum(row)
            if total == 0:
                #no chars follow this sequence, give up and try again
                return None
            pik = 1+srandom.randrange(0, total)

            #use first char > that weighted choice
            cur = 0
            for c3, weight in enumerate(row):
                cur += weight
                if cur >= pik:
                    break
            else:
                raise RuntimeError, "pick out of bounds"

            #add c3 and advance
            out += alphabet[c3]
            num += 1
            c1 = c2
            c2 = c3
        return out

#=========================================================
#frontend
#=========================================================

#dictionary which maps algorithm names to driver class,
#used by generate_secret
_gs_algs = dict(
    random=RandomGenerator,
    cvc=CvcGenerator,
    gpw=GpwGenerator,
    )

#set name of generate secret's default algorithm
_gs_default = "alphanum"

#dict containing all presets for generate_secret
_gs_presets = dict(
    #global presets
    human=dict(alg="cvc", size=(10, 13)),
    strong=dict(alg="random", charset="ascii", size=16),

    #hex presets
    hex=dict(alg="random", charset="hex"),
    alphanum=dict(alg="random", charset="alphanum"),
    ascii=dict(alg="random", charset="ascii"),
)

def generate_secret(alg=None, count=None, **kwds):
    """Generate a random password.

    *count* lets you generate multiple passwords at once.
    If count is not specified, a single string is returned.
    Otherwise, a list of *count* passwords will be returned.

    *alg* lets you select the algorithm used when generating the password.
    This value may be either the name of a preset, or the name of an actual algorithm
    (see the list of presets and algorithms below).

    Any additional keywords will be passed to the algorithm implementation.

    Examples
    ========
    The follow are some usages examples (your results may vary,
    depending on the random number state)::

        >>> from bps.security.pwgen import generate_secret

        >>> # generate a bunch of passwords using the  gpw algorithm
        >>> generate_secret(count=10, alg="gpw")
        ['preatioc',
         'mirenencet',
         'blackessse',
         'shantesita',
         'sonsimena',
         'mestongesho',
         'amilitterl',
         'lonisantr',
         'onsesenone',
         'astensult']

        >>> # generate a single alphanumeric password
        >>> generate_secret(alg="alphanum")
        'l9u09f3N8Squ23q2'

        >>> # generate a single password using default algorithm
        >>> generate_secret()
        'bablistre'

        >>> #generate a strong password
        >>> generate_secret("strong")
        "g_)'sP?Z'Zhi]6hL"

    Presets
    =======
    This function defines a number of presets, which can be passed
    in as the *alg* string, and will load the most appropriate underlying algorithm,
    as well as various presets:

        ``alphanum`` (the default)
            Generates a random sequence of mixed-case letters, and numbers.
            This was chosen as the default because it's reasonably strong
            for average purposes, to lessen the security risk if users
            just call ``generate_secret()`` without options.
            If you want a more memorable (and therefore weaker) password,
            you have to explicitly chose another preset. As a matter
            of balance, this is not the *strongest* algorithm available,
            just one that's reasonably strong for most uses.

        ``hex``
            Generates a random sequence of 16 hexidecimal digits.

        ``ascii``
            This algorithm uses a wide range of 92 ascii characters (letters, numbers, punctuation).

        ``human``
            This generates a medium-strength phonetic password,
            which should be (relatively) easy to remember,
            yet reasonably unlikely to be guessed.

            Currently this uses the ``cvc`` algorithm with a size of 9-12,
            but if stronger-yet-memorable algorithm is found,
            this preset will be changed to refer to that algorithm instead.

        ``strong``
            This generates a password that's as strong enough to be unguessable.

            This is currently an alias for the ``ascii`` preset, which creates a
            16  character password made up of all possible ascii characters.
            The odds of this password being guessed / generated again are 1 in 2e31,
            making it reasonably strong for most purposes.
            As computers get more powerful, this preset's nature may be upped
            as needed to keep it strong.

    Algorithms
    ==========
    The following algorithms are available:

        ``random``
            This generates a random password from a specified alphabet.
            You can specify a *charset* of ``hex``, ``alphanum``, or ``ascii``,
            or specifiy an *alphabet* string directly.

        ``cvc``
            This implements a simple phonetic algorithm which generates
            sequences of letters using some basic english syllable patterns.
            While not as frequently pronouncable as the ``gpw`` algorithm's results,
            this algorithm has a much larger effective key space,
            and so it a much better choice for phonetic password generation.

        ``gpw``
            This is a complex phonetic algorithm, which attempts to generate
            pronouncable words via a markov walk using a compiled dictionary
            of 3-order letter frequencies. This is a python implementation of
            Tom Van Vleck's phonetic password algorithm, found at http://www.multicians.org/thvv/gpw.html.

            .. warning::
                While more memorable, it's probablistic nature severely constrains
                the effective keyspace, so this should not be used where
                strong passwords are needed, especially if the attacker
                knows you have used this algorithm and can brute force their attack.

                For size=10, this will generate a duplicate 1 out of 20,000 times.

            This algorithm accepts a *language* keyword, letting you specify
            the dictionary to load from. The following languages are implemented:

                en_US (the default)
                    uses a dictionary built from Ubuntu's american-english word list.
                en_UK
                    uses a dictionary built from Ubuntu's british-english word list.
                gpw
                    uses the original dictionary from Tom Van Vleck's implementation.

            .. note::

                Due to keyspace issues, the en_US and en_UK tables have been removed for now.

    Additional Keywords
    ===================
    The following keywords are recognized by all algorithms:

        size
            This lets you explicitly set the size of the generated password.
            If the size is not specified, a algorithm-dependant default is used.
            If size is a tuple of two integers, a random size is used with the
            specified range.

        reshake
            If true (the default), the random number generator will be

    The following keywords are recognized by the phonetic algorithms (cvc,gpw):

        numeric_head
            If set to a positive integer, that many digits will be added to the start
            of the generated password.

        numeric_tail
            If set to a positive integer, that many digits will be added to the end
            of the generated password.
    """

    if 'dialect' in kwds:
        alg = kwds.pop("dialect")
        warnings.warn("generate_password(): 'dialect' kwd is deprecated, use 'alg' instead")

    #load preset
    if not alg or alg == "default":
        alg = _gs_default
    if alg in _gs_presets:
        preset = _gs_presets[alg]
        alg = preset['alg']
        for k in preset:
            if k not in kwds:
                kwds[k] = preset[k]

    #create generator
    if alg in _gs_algs:
        cls = _gs_algs[alg]
    else:
        raise ValueError, "unknown algorithm or preset: %r" % (alg,)
    gen = cls(**kwds)
    return gen(count)

#=========================================================
# eof
#=========================================================
