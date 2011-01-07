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
from passlib.tests.utils import TestCase
#module
log = getLogger(__name__)

#=========================================================
#pull crypt tests
#=========================================================
#this test suite uses info stored in the specific hash algs' test suites,
#so we have to import them here.
from passlib.tests.test_hash_sha_crypt import Sha256CryptTest, Sha512CryptTest
from passlib.tests.test_hash_unix_crypt import UnixCryptTest
from passlib.tests.test_hash_bcrypt import BCryptTest
from passlib.tests.test_hash_md5_crypt import Md5CryptTest

#=========================================================
#quick access functions
#=========================================================
class QuickAccessTest(TestCase):
    "test quick access functions"

    crypt_cases = [ UnixCryptTest, Md5CryptTest, Sha256CryptTest]
    if BCryptTest:
        crypt_cases.append(BCryptTest)
    crypt_cases.extend([ Sha512CryptTest ])

    def test_00_identify(self):
        "test pwhash.identify()"
        identify = pwhash.identify
        for cc in self.crypt_cases:
            name = cc.alg.name
            for _, hash in cc.positive_knowns:
                self.assertEqual(identify(hash), name)
            for _, hash in cc.negative_knowns:
                self.assertEqual(identify(hash), name)
            for hash in cc.negative_identify:
                self.assertNotEqual(identify(hash), name)
            for hash in cc.invalid_identify:
                self.assertEqual(identify(hash), None)

    def test_01_verify(self):
        "test pwhash.verify()"
        verify = pwhash.verify
        for cc in self.crypt_cases:
            name = cc.alg.name
            for secret, hash in cc.positive_knowns[:3]:
                self.assert_(verify(secret, hash))
                self.assert_(verify(secret, hash, alg=name))
            for secret, hash in cc.negative_knowns[:3]:
                self.assert_(not verify(secret, hash))
                self.assert_(not verify(secret, hash, alg=name))
            for hash in cc.invalid_identify[:3]:
                #context should raise ValueError because can't be identified
                self.assertRaises(ValueError, verify, secret, hash)

    def test_02_encrypt(self):
        "test pwhash.encrypt()"
        identify = pwhash.identify
        verify = pwhash.verify
        encrypt = pwhash.encrypt
        for cc in self.crypt_cases:
            alg = cc.alg.name
            s = 'test'
            h = encrypt(s, alg=alg)
            self.assertEqual(identify(h), alg)
            self.assertEqual(verify(s, h), True)
            h2 = encrypt(s, h)
            self.assertEqual(identify(h2), alg)
            self.assertEqual(verify(s, h2, alg=alg), True)

    def test_04_default_context(self):
        "test pwhash.default_context contents"
        dc = pwhash.default_context
        for case in self.crypt_cases:
            self.assert_(case.alg.name in dc)

        last = 'sha-512-crypt'
        self.assertEqual(dc.keys()[-1], last)
        h = dc.encrypt("test")
        self.assertEqual(dc.identify(h), last)
        self.assertEqual(dc.verify('test', h, alg=last), True)

#=========================================================
#EOF
#=========================================================
