"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
import warnings
from logging import getLogger
#site
#pkg
from passlib import hash as pwhash
from passlib.tests.utils import TestCase, enable_suite
from passlib.util import H64
from passlib.tests.test_hash_base import _CryptTestCase as CryptTestCase
import passlib.hash.mysql as mod
#module
log = getLogger(__name__)

#=========================================================
#database hashes
#=========================================================
class Mysql10CryptTest(CryptTestCase):
    alg = mod.Mysql10Crypt

    #remove single space from secrets
    secrets = [ x for x in CryptTestCase.secrets if x != ' ' ]

    positive_knowns = (
        ('mypass', '6f8c114b58f2ce9e'),
    )
    invalid_identify = (
        #bad char in otherwise correct hash
        '6z8c114b58f2ce9e',
    )
    negative_identify = (
        #other hashes
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'
        )

    def test_whitespace(self):
        "check whitespace is ignored properly"
        h = self.do_encrypt("mypass")
        h2 = self.do_encrypt("my pass")
        self.assertEqual(h, h2)

class Mysql41CryptTest(CryptTestCase):
    alg = mod.Mysql41Crypt
    positive_knowns = (
        ('mypass', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4'),
    )
    invalid_identify = (
        #bad char in otherwise correct hash
        '*6Z8989366EAF75BB670AD8EA7A7FC1176A95CEF4',
    )
    negative_identify = (
        #other hashes
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'
        '6f8c114b58f2ce9e',
        )

#=========================================================
#EOF
#=========================================================
