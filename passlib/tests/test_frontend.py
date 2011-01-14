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
import passlib as mod
from passlib.tests.utils import TestCase
#module
log = getLogger(__name__)

#=========================================================
#pull crypt tests
#=========================================================
def get_crypt_cases():

    #this test suite uses info stored in the specific hash algs' test suites,
    #so we have to import them here.
    from passlib.tests.test_sha_crypt import Sha256CryptTest, Sha512CryptTest
    from passlib.tests.test_unix_crypt import UnixCryptTest
    from passlib.tests.test_bcrypt import BCryptTest
    from passlib.tests.test_md5_crypt import Md5CryptTest

    crypt_cases = [ UnixCryptTest, Md5CryptTest, Sha256CryptTest]
    if BCryptTest:
        crypt_cases.append(BCryptTest)
    crypt_cases.extend([ Sha512CryptTest ])

    return crypt_cases

#=========================================================
#quick access functions
#=========================================================
class QuickAccessTest(TestCase):
    "test quick access functions"

    crypt_cases = get_crypt_cases()

    def test_00_identify(self):
        "test pwhash.identify()"
        identify = mod.identify
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
        verify = mod.verify
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
        identify = mod.identify
        verify = mod.verify
        encrypt = mod.encrypt
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
        dc = mod.default_context
        for case in self.crypt_cases:
            self.assert_(dc.lookup(case.alg.name) is case.alg)

        last = 'sha512-crypt'
        self.assertEqual(dc.lookup().name, last)
        h = dc.encrypt("test")
        self.assertEqual(dc.identify(h).name, last)
        self.assertEqual(dc.verify('test', h, alg=last), True)

#=========================================================
#EOF
#=========================================================
