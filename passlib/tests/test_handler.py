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
from passlib.utils import gen_salt
#module
log = getLogger(__name__)

#=========================================================
#sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib. they shouldn't be used as actual password schemes.
#=========================================================
class UnsaltedHash(CryptHandler):
    "example algorithm which lacks a salt"
    name = "unsalted_example"
    #stats: 160 bit checksum, no salt

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^[0-9a-f]{40}$", hash))

    @classmethod
    def genhash(cls, secret, config):
        return hashlib.sha1("boblious" + secret).hexdigest()

class SaltedHash(CryptHandler):
    "example algorithm with a salt"
    name = "salted_example"
    #stats: 160 bit checksum, 12 bit salt

    setting_kwds = ("salt",)

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^@salt[0-9a-zA-Z./]{2}[0-9a-f]{40}$", hash))

    @classmethod
    def parse(cls, hash):
        if not cls.identify(hash):
            raise ValueError, "not a salted-example hash"
        return dict(
            salt=hash[5:7],
            checksum=hash[7:],
        )

    @classmethod
    def render(cls, salt, checksum):
        assert len(salt) == 2
        assert len(checksum) == 40
        return "@salt%s%s" % (salt, checksum)

    @classmethod
    def genconfig(cls, salt=None):
        if not salt:
            salt = gen_salt(2)
        return cls.render(salt[:2], '0' * 40)

    @classmethod
    def genhash(cls, secret, config):
        salt = cls.parse(config)['salt']
        checksum = hashlib.sha1(salt + secret + salt).hexdigest()
        return cls.render(salt, checksum)

#=========================================================
#test sample algorithms - really a self-test of _HandlerTestCase
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
