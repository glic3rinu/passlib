"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import re
import hashlib
from logging import getLogger
#site
#pkg
from passlib.handler import CryptHandler
from passlib.tests.handler_utils import _HandlerTestCase
from passlib.utils import generate_h64_salt
#module
log = getLogger(__name__)

#=========================================================
#sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib
#=========================================================
class UnsaltedHash(CryptHandler):
    "example algorithm which lacks a salt [REALLY INSECURE - DO NOT USE]"
    name = "unsalted-example"
    checksum_bytes = 20

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^[0-9a-f]{40}$", hash))

    @classmethod
    def encrypt(cls, secret):
        return hashlib.sha1("boblious" + secret).hexdigest()

    @classmethod
    def verify(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError, "not an unsalted-example hash"
        return hash == cls.encrypt(secret)

class SaltedHash(CryptHandler):
    "example algorithm with a salt [REALLY INSECURE - DO NOT USE]"
    name = "salted-example"
    setting_kwds = ("salt",)
    salt_bytes = 6*2/8.0
    checksum_bytes = 20

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^@salt[0-9a-zA-Z./]{2}[0-9a-f]{40}$", hash))

    @classmethod
    def parse(cls, hash):
        if not cls.identify(hash):
            raise ValueError, "not unsalted-example hash"
        return dict(
            salt=hash[5:7],
            checksum=hash[7:],
        )

    @classmethod
    def encrypt(cls, secret, salt=None):
        if not salt:
            salt = generate_h64_salt(2)
        assert len(salt) == 2
        checksum = hashlib.sha1(salt+secret).hexdigest()
        return "@salt%s%s" % (salt, checksum)

    @classmethod
    def verify(cls, secret, hash):
        info = cls.parse(hash)
        return hash == cls.encrypt(secret, salt=info['salt'])

#=========================================================
#test sample algorithms
#=========================================================

#TODO: provide data samples for algorithms
# (positive knowns, negative knowns, invalid identify)

class UnsaltedHashTest(_HandlerTestCase):
    handler = UnsaltedHash

class SaltedHashTest(_HandlerTestCase):
    handler = SaltedHash

#=========================================================
#
#=========================================================

#TODO: test registry system

#=========================================================
#EOF
#=========================================================
