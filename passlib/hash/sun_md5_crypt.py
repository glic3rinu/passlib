"""passlib.hash.sun_md5_crypt - Sun's Md5 Crypt used on Solaris

.. note::
    Outside of being based on the md5 hash function,
    this algorithm has almost nothing to do with the
    bsd md5-crypt format.

.. note::

    This implementation has not been fully tested
    (particularly on an actual Solaris system)
    and so may not match the real implementation.
    it still needs work, and in particular,
    test cases to run against.
"""

#NOTE: sun-md5-crypt algorithm internals mostly described
#   http://dropsafe.crypticide.com/article/1389
#   http://www.cuddletech.com/blog/pivot/entry.php?id=778
#   and scattered messages around the web,
#   though no official specification seems to exist.
#this code was written from notes made from those sources,
#combined with trial and error based on a single known sunmd5 hash,
# "passwd" => "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"
#which was the only one I could find on the web
#(not having a Solaris install handy).

#=========================================================
#imports
#=========================================================
#core
from hashlib import md5
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
#backend
#=========================================================
#=========================================================
#backend
#=========================================================
#constant data used by alg - Hamlet act 3 scene 1 + null char
# exact bytes as in http://www.ibiblio.org/pub/docs/books/gutenberg/etext98/2ws2610.txt
# from Project Gutenberg.

MAGIC_HAMLET = (
    "To be, or not to be,--that is the question:--\n"
    "Whether 'tis nobler in the mind to suffer\n"
    "The slings and arrows of outrageous fortune\n"
    "Or to take arms against a sea of troubles,\n"
    "And by opposing end them?--To die,--to sleep,--\n"
    "No more; and by a sleep to say we end\n"
    "The heartache, and the thousand natural shocks\n"
    "That flesh is heir to,--'tis a consummation\n"
    "Devoutly to be wish'd. To die,--to sleep;--\n"
    "To sleep! perchance to dream:--ay, there's the rub;\n"
    "For in that sleep of death what dreams may come,\n"
    "When we have shuffled off this mortal coil,\n"
    "Must give us pause: there's the respect\n"
    "That makes calamity of so long life;\n"
    "For who would bear the whips and scorns of time,\n"
    "The oppressor's wrong, the proud man's contumely,\n"
    "The pangs of despis'd love, the law's delay,\n"
    "The insolence of office, and the spurns\n"
    "That patient merit of the unworthy takes,\n"
    "When he himself might his quietus make\n"
    "With a bare bodkin? who would these fardels bear,\n"
    "To grunt and sweat under a weary life,\n"
    "But that the dread of something after death,--\n"
    "The undiscover'd country, from whose bourn\n"
    "No traveller returns,--puzzles the will,\n"
    "And makes us rather bear those ills we have\n"
    "Than fly to others that we know not of?\n"
    "Thus conscience does make cowards of us all;\n"
    "And thus the native hue of resolution\n"
    "Is sicklied o'er with the pale cast of thought;\n"
    "And enterprises of great pith and moment,\n"
    "With this regard, their currents turn awry,\n"
    "And lose the name of action.--Soft you now!\n"
    "The fair Ophelia!--Nymph, in thy orisons\n"
    "Be all my sins remember'd.\n\x00" #<- apparently null at end of C string is included (test vector won't pass otherwise)
)

def raw_sun_md5_crypt(secret, rounds, salt):
    "given secret & salt, return encoded sun-md5-crypt checksum"
    global MAGIC_HAMLET

    #validate secret
    #FIXME: no definitive information about how it handles unicode,
    # so using this as a fallback...
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #validate salt
    if len(salt) > 8:
        salt = salt[:8]

    #validate rounds
    if rounds <= 0:
        rounds = 0
    real_rounds = 4096 + rounds
    #NOTE: spec seems to imply max 'rounds' is 2**32-1

    #generate initial digest to start off round 0.
    #NOTE: algorithm includes prefix & rounds in salt as well.
    #FIXME: seen in various forms around web, some of which
    # have "$" instead of "," as md5/rounds separator.
    # code will currently normalize that away,
    # but that might be in opposition to spec behavior.
    # lacking a real spec for this algorithm, not sure.
    if rounds:
        prefix = "$md5,rounds=%d$" % (rounds,)
    else:
        prefix = "$md5$"
    result = md5(secret + prefix + salt).digest()
    assert len(result) == 16

    #prepare constants for the per-round operations
    ROUND_ITER = [
        (i,i+3,i+8,(i+11)%16)
        for i in xrange(8)
    ]
    cdata = MAGIC_HAMLET

    #NOTE: many things have been inlined to speed up the loop
    # as much as possible. eg: the getbit routine - (rval[bit//8] >> (bit%8)) & 1

    round = 0
    while round < real_rounds:
        #convert last result byte string to list of byte-ints for easy access
        rval = [ ord(c) for c in result ]
        #XXX: could speed things up more by inlining rval[xxx] w/ g=rval.__getitem__ ... g(xxx)

        #build up two 8-bit ints (x & y) to use as bit offsets for 'coin flip'
        x = y = 0
        for i,i3,i8,i11 in ROUND_ITER:
            #use oa'th bit of last result as i'th bit of x
            bit = ((rval[(rval[i] >> (rval[i3] % 5)) & 0x0f]) >> ((rval[i3] >> (rval[i] % 8)) & 1)) & 0x7F
            x |= ((rval[bit//8] >> (bit%8)) & 1) << i

            #use ob'th bit of last result as i'th bit of y
            bit = ((rval[(rval[i8] >> (rval[i11] % 5)) & 0x0f]) >> ((rval[i11] >> (rval[i8] % 8)) & 1)) & 0x7F
            y |= ((rval[bit//8] >> (bit%8)) & 1) << i

        #based on round, pick high 7 bits or low 7 bits to use as actual offset
        #(md5 digest contains exactly 128 bits)
        x = (x >> ((rval[(round%128)//8] >> (round%8)) & 1)) & 0x7f
        y = (y >> ((rval[((round+64)%128)//8] >> (round%8)) & 1)) & 0x7f

        #extract x'th and y'th bit, xoring them together to yeild "coin flip"
        coin = ((rval[x//8] >> (x%8)) ^ (rval[y//8] >> (y%8))) & 1

        #construct hash for this round
        h = md5(result)
        if coin:
            h.update(cdata)
        h.update(str(round))
        result = h.digest()

        round += 1

    #encode output
    #NOTE: appears to use same output encoding as md5-crypt
    out = ''.join(
        h64.encode_3_offsets(result,
            idx+12 if idx < 4 else 5,
            idx+6,
            idx,
        )
        for idx in xrange(5)
        ) + h64.encode_1_offset(result, 11)
    return out

#=========================================================
#algorithm information
#=========================================================
name = "sun-md5-crypt"
#stats: 128 bit checksum, 48 bit salt, 0..2**32-4095 rounds

setting_kwds = ("salt", "rounds")
context_kwds = ()

default_rounds = 5000 #current passlib default
min_rounds = 0
max_rounds = 4294963199 ##2**32-1-4096

#=========================================================
#internal helpers
#=========================================================
_pat = re.compile(r"""
    ^
    \$md5
    ([$,]rounds=(?P<rounds>\d+))?
    \$(?P<salt>[A-Za-z0-9./]{0,8})
    (\$(?P<chk>[A-Za-z0-9./]{22})?)?
    $
    """, re.X)

#NOTE: trailing "$" is supposed to be part of config string,
# supposed to take both, but render with "$"
#NOTE: seen examples with both "," or "$" as md5/rounds separator,
# not sure what official format is.
# taking both, rendering ","

def parse(hash):
    if not hash:
        raise ValueError, "no hash specified"
    m = _pat.match(hash)
    if not m:
        raise ValueError, "invalid sun-md5-crypt hash"
    rounds, salt, chk = m.group("rounds", "salt", "chk")
    #NOTE: this is *additional* rounds added to base 4096 specified by spec.
    #XXX: should we note whether "$" or "," was used as rounds separator?
    # not sure if that affects anything
    return dict(
        rounds=int(rounds) if rounds else 0,
        salt=salt,
        checksum=chk,
    )

def render(rounds, salt, checksum=None):
    "render a sun-md5-crypt hash or config string"
    if rounds > 0:
        return "$md5,rounds=%d$%s$%s" % (rounds, salt, checksum or '')
    else:
        return "$md5$%s$%s" % (salt, checksum or '')

#=========================================================
#primary interface
#=========================================================
def genconfig(salt=None, rounds=None):
    """generate xxx configuration string

    :param salt:
        optional salt string to use.

        if omitted, one will be automatically generated (recommended).

        length must be 0 to 8 characters inclusive.
        characters must be in range ``A-Za-z0-9./``.

    :param rounds:

        optional number of rounds, must be between 0 and 4294963199 inclusive.

    :returns:
        sun-md5-crypt configuration string.
    """
    salt = norm_salt(salt, 0, 8, name=name)
    rounds = norm_rounds(rounds, default_rounds, min_rounds, max_rounds, name=name)
    return render(rounds, salt, None)

def genhash(secret, config):
    #parse and run through genconfig to validate configuration
    #FIXME: could eliminate uneeded render/parse call
    info = parse(config)
    info.pop("checksum")
    config = genconfig(**info)
    info = parse(config)
    rounds, salt = info['rounds'], info['salt']

    #run through builtin backend
    checksum = raw_sun_md5_crypt(secret, rounds, salt)
    return render(rounds, salt, checksum)

#=========================================================
#secondary interface
#=========================================================
def encrypt(secret, **settings):
    return genhash(secret, genconfig(**settings))

def verify(secret, hash):
    #normalize hash format so strings compare
    if hash and hash.startswith("$md5$rounds="):
        hash = "$md5,rounds=" + hash[12:]
    return hash == genhash(secret, hash)

def identify(hash):
    return bool(hash and _pat.match(hash))

#=========================================================
#eof
#=========================================================
