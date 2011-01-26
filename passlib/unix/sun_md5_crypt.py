"""passlib - implementation of various password hashing functions

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
from __future__ import with_statement
#core
import inspect
import re
from hashlib import md5
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.utils import h64_encode_3_offsets, h64_encode_1_offset
from passlib.handler import ExtCryptHandler, register_crypt_handler
#pkg
#local
__all__ = [
    'SunMd5Crypt',
]

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

def raw_sun_md5_crypt(secret, salt, rounds):
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
    last_result = md5(secret + prefix + salt).digest()
    assert len(last_result) == 16

    #prepare constants for the per-round operations
    ROUND_ITER = [
        (i,i+3,i+8,(i+11)%16)
        for i in xrange(8)
    ]
    cdata = MAGIC_HAMLET

    #NOTE: many things have been inlined to speed up the loop
    # as much as possible. eg: the getbit routine - (last_bytes[bit//8] >> (bit%8)) & 1

    round = 0
    while round < real_rounds:
        #convert last result byte string to list of byte-ints for easy access
        last_bytes = [ ord(c) for c in last_result ]
        #XXX: could speed things up more by inlining last_bytes[xxx] w/ g=last_bytes.__getitem__ ... g(xxx)

        #build up two 8-bit ints (x & y) to use as bit offsets for 'coin flip'
        x = y = 0
        for i,i3,i8,i11 in ROUND_ITER:
            #use oa'th bit of last result as i'th bit of x
            bit = ((last_bytes[(last_bytes[i] >> (last_bytes[i3] % 5)) & 0x0f]) >> ((last_bytes[i3] >> (last_bytes[i] % 8)) & 1)) & 0x7F
            x |= ((last_bytes[bit//8] >> (bit%8)) & 1) << i

            #use ob'th bit of last result as i'th bit of y
            bit = ((last_bytes[(last_bytes[i8] >> (last_bytes[i11] % 5)) & 0x0f]) >> ((last_bytes[i11] >> (last_bytes[i8] % 8)) & 1)) & 0x7F
            y |= ((last_bytes[bit//8] >> (bit%8)) & 1) << i

        #based on round, pick high 7 bits or low 7 bits to use as actual offset
        #(md5 digest contains exactly 128 bits)
        x = (x >> ((last_bytes[(round%128)//8] >> (round%8)) & 1)) & 0x7f
        y = (y >> ((last_bytes[((round+64)%128)//8] >> (round%8)) & 1)) & 0x7f

        #extract x'th and y'th bit, xoring them together to yeild "coin flip"
        coin = ((last_bytes[x//8] >> (x%8)) ^ (last_bytes[y//8] >> (y%8))) & 1

        #construct hash for this round
        h = md5(last_result)
        if coin:
            h.update(cdata)
        h.update(str(round))
        last_result = h.digest()

        round += 1

    #encode output
    #NOTE: appears to use same output encoding as md5-crypt
    out = ''.join(
        h64_encode_3_offsets(last_result,
            idx+12 if idx < 4 else 5,
            idx+6,
            idx,
        )
        for idx in xrange(5)
        ) + h64_encode_1_offset(last_result, 11)
    return out

#=========================================================
#
#=========================================================
class SunMd5Crypt(ExtCryptHandler):
    #=========================================================
    #crypt info
    #=========================================================
    name = 'sun-md5-crypt'
    #stats: 128 bit checksum, 48 bit salt, 0..2**32-4095 rounds

    setting_kwds = ("salt","rounds")

    secret_chars = -1

    salt_chars = 8
    min_salt_chars = 0

    default_rounds = 5000
    min_rounds = 0
    max_rounds = 4294963199 ##2**32-1-4096

    #=========================================================
    #helpers
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

    @classmethod
    def parse(cls, hash):
        "parse a sun-md5-crypt hash or config string"
        if not hash:
            raise ValueError, "no sun-md5-crypt hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sun-md5-crypt hash"
        salt, chk, rounds = m.group("salt", "chk", "rounds")
        #NOTE: this is *additional* rounds added to base 4096 specified by spec.
        #XXX: should we note whether "$" or "," was used as rounds separator?
        # not sure if that affects anything
        return dict(
            salt=salt,
            checksum=chk,
            rounds=int(rounds) if rounds else 0,
        )

    @classmethod
    def render(cls, salt, rounds=0, checksum=None):
        "render a sun-md5-crypt hash or config string"
        if not checksum:
            checksum = ''
        if rounds:
            return "$md5,rounds=%d$%s$%s" % (rounds, salt, checksum)
        else:
            return "$md5$%s$%s" % (salt, checksum)

    #=========================================================
    #frontend
    #=========================================================
    @classmethod
    def identify(cls, hash):
        "identify sun-md5-crypt hash"
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def genconfig(cls, salt=None, rounds=None):
        salt = cls._norm_salt(salt)
        rounds = cls._norm_rounds(rounds)
        return cls.render(salt, rounds)

    @classmethod
    def genhash(cls, secret, config):
        info = cls._prepare_parsed_config(config)
        checksum = raw_sun_md5_crypt(secret, info['salt'], info['rounds'])
        return cls.render(checksum=checksum, **info)

    @classmethod
    def norm_hash(cls, hash):
        if hash.startswith("$md5$"):
            return "$md5," + hash[5:]
        return hash

    #=========================================================
    #eoc
    #=========================================================

register_crypt_handler(SunMd5Crypt)

#=========================================================
# eof
#=========================================================
