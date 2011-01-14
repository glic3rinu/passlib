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
from passlib.hash.base import CryptAlgorithm
from passlib.tests.utils import TestCase, enable_suite
from passlib.util import H64
#module
log = getLogger(__name__)

#=========================================================
#helper password algorithms - these serve both as simple
# examples, and are used in the unittests
#=========================================================
class UnsaltedAlg(CryptAlgorithm):
    "example algorithm usuing constant-salt hash"
    name = "unsalted"

    @classmethod
    def identify(self, hash):
        if hash is None:
            return False
        if len(hash) != 40:
            return False
        try:
            int(hash, 16)
        except ValueError:
            return False
        return True

    @classmethod
    def encrypt(self, secret, salt=None, keep_salt=False):
        #NOTE: that salt / _keep_salt are simply ignored
        return hashlib.sha1("boblious" + secret).hexdigest()

class SaltedAlg(CryptAlgorithm):
    """example naive salted algorithm which never obeys keep_salt
    (note that the default verify() is implemented in this case)
    """
    name = "salted"
    salt_bytes = 6*2/8.0

    @classmethod
    def identify(self, hash):
        if hash is None:
            return False
        return hash.startswith("@salt")

    @classmethod
    def _raw(self, secret, salt):
        return "@salt%s%s" % (salt, hashlib.sha1(salt+secret).hexdigest())

    @classmethod
    def encrypt(self, secret, salt=None, keep_salt=False):
##        warn("keep_salt not supported by this algorithm")
        real_salt = H64.randstr(2)
        return self._raw(secret, real_salt)

    @classmethod
    def verify(self, secret, hash):
        if hash is None:
            return False
        salt = hash[5:7]
        return self._raw(secret, salt) == hash

class SampleAlg(CryptAlgorithm):
    "example salted algorithm w/ keep_salt support"
    name = "sample"
    salt_bytes = 6*2/8.0

    @classmethod
    def identify(self, hash):
        if hash is None:
            return False
        return hash.startswith("@sam")

    @classmethod
    def encrypt(self, secret, salt=None, keep_salt=False):
        if salt and keep_salt:
            real_salt = salt[4:6]
        else:
            real_salt = H64.randstr(2)
        return "@sam%s%s" % (real_salt, hashlib.sha1(real_salt+secret).hexdigest())

#=========================================================
#other unittest helpers
#=========================================================

#list of various distinct secrets that all algs are tested with
SECRETS = [
    '',
    ' ',
    'test',
    'testtest',
    'test test',
    'test bcdef',
    'Compl3X AlphaNu3meric',
    '4lpHa N|_|M3r1K W/ Cur51|\\|g: #$%(*)(*%#',
    'Really Long Password (tm), which is all the rage nowadays with the cool kids',
##    u'test with unic\u00D6de', #<- note, not all codecs can handle unicode yet.
    ]

class _CryptTestCase(TestCase):
    "base class for CryptAlgorithm subclass testing"

    #=========================================================
    #subclass attrs
    #=========================================================
    alg = None #plugin for class
    positive_knowns = () #list of (secret,hash) pairs to verify they do match
    negative_knowns = () #list of (secret,hash) pairs to verify they don't match
    negative_identify = () # list of hashses that shouldn't identify as this one
    invalid_identify = () # list of this alg's hashes w/ typo

    def case_prefix(self):
        return self.alg.name

    secrets = SECRETS #list of default secrets to check

    #=========================================================
    #identify
    #=========================================================
    def test_01_identify_positive_knowns(self):
        "test identify() against known correct algorithm hashes"
        for _, hash in self.positive_knowns:
            self.assertEqual(self.do_identify(hash), True)
        for _, hash in self.negative_knowns:
            self.assertEqual(self.do_identify(hash), True)

    def test_02_identify_negative_knowns(self):
        "test identify() against known wrong algorithm hashes"
        for hash in self.negative_identify:
            self.assertEqual(self.do_identify(hash), False)

    def test_03_identify_invalid_knowns(self):
        "test identify() against known invalid algorithm hashes"
        for hash in self.invalid_identify:
            self.assertEqual(self.do_identify(hash), False)

    def test_04_identify_none(self):
        "test identify() reports hash=None as False"
        self.assertEqual(self.do_identify(None), False)

    #=========================================================
    #verify
    #=========================================================
    def test_10_verify_positive_knowns(self):
        "test verify() against algorithm-specific known positive matches"
        for secret, hash in self.positive_knowns:
            self.assertEqual(self.do_verify(secret, hash), True)

    def test_11_verify_negative_knowns(self):
        "test verify() against algorithm-specific known negative matches"
        for secret, hash in self.negative_knowns:
            self.assertEqual(self.do_verify(secret, hash), False)

    def test_12_verify_derived_negative_knowns(self):
        "test verify() against algorithm-specific deliberate negative matches"
        for secret, hash in self.positive_knowns:
            self.assertEqual(self.do_verify(self.do_concat(secret,'x'), hash), False)

#XXX: haven't decided if this should be part of protocol
##    def test_13_verify_secret_none(self):
##        "test verify() accepts secret=None and reports False"
##        for _, hash in self.positive_knowns:
##            self.assert_(not self.do_verify(None, hash))

    def test_14_verify_hash_none(self):
        "test verify() reports hash=None as not matching"
        for secret in (None, "", "xxx"):
            self.assert_(not self.do_verify(secret, None))

    #=========================================================
    #encrypt
    #=========================================================
    def test_30_encrypt(self):
        "test encrypt() against standard secrets"
        for secret in self.secrets:
            self.check_encrypt(secret)
        for secret, _ in self.positive_knowns:
            self.check_encrypt(secret)
        for secret, _ in self.negative_knowns:
            self.check_encrypt(secret)

    def test_31_encrypt_gen_salt(self):
        "test encrypt() generates new salt each time"
        if not self.alg.has_salt:
            return
        for secret, hash in self.positive_knowns:
            hash2 = self.do_encrypt(secret, hash)
            self.assertNotEqual(hash, hash2)

    def test_31_encrypt_keep_salt(self):
        "test encrypt() honors keep_salt keyword"
        if not self.alg.has_salt:
            return
        for secret, hash in self.positive_knowns:
            hash2 = self.do_encrypt(secret, hash, keep_salt=True)
            self.assertEqual(hash, hash2)

    def check_encrypt(self, secret):
        "check encrypt() behavior for a given secret"
        #hash the secret
        hash = self.do_encrypt(secret)

        #test identification
        self.assertEqual(self.do_identify(hash), True)

        #test positive verification
        self.assertEqual(self.do_verify(secret, hash), True)

        #test negative verification
        for other in ['', 'test', self.do_concat(secret,'x')]:
            if other != secret:
                self.assertEqual(self.do_verify(other, hash), False,
                    "hash collision: %r and %r => %r" % (secret, other, hash))

    def test_32_secret_chars(self):
        "test secret_chars limitation"
        #hash a really long secret
        secret = "too many secrets" * 16
        tail = "my socrates note" * 8
        hash = self.do_encrypt(secret)

        sc = self.alg.secret_chars
        if sc > 0:
            #bcrypt, unixcrypt
            assert sc < len(secret), "need to increase test secret size"
            self.assert_(self.do_verify(secret[:sc], hash))
            self.assert_(self.do_verify(secret + tail, hash))
            self.assert_(not self.do_verify(secret[:sc-1], hash))
        else:
            #if no limit, secret+tail shouldn't verify
            self.assertEquals(sc, -1)
            self.assert_(not self.do_verify(secret[:16], hash))
            self.assert_(not self.do_verify(secret+tail, hash))

    def test_33_encrypt_none(self):
        "test encrypt() refused secret=None"
        self.assertRaises(TypeError, self.do_encrypt, None)

    #=========================================================
    #alg interface
    #=========================================================
    def do_concat(self, secret, prefix):
        return prefix + secret

    def do_encrypt(self, *args, **kwds):
        return self.alg().encrypt(*args, **kwds)

    def do_verify(self, secret, hash):
        return self.alg().verify(secret, hash)

    def do_identify(self, hash):
        return self.alg().identify(hash)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#dummy algorithms
#=========================================================
#this tests the dummy algorithms defined above,
#to make sure creating custom algorithms works properly.

class UnsaltedDummyAlgTest(_CryptTestCase):
    alg = UnsaltedAlg

class SaltedDummyAlgTest(_CryptTestCase):
    alg = SaltedAlg

class SampleDummyAlgTest(_CryptTestCase):
    alg = SampleAlg

#=========================================================
#utils
#=========================================================
class UtilsTest(TestCase):
    "test util funcs and core class behavior"

    def test_has_salt(self):
        "check CryptAlgorithm.has_salt property works"

        #make sure property function works at class level, not instance level
        self.assertEqual(UnsaltedAlg.has_salt, False)
        self.assertEqual(SaltedAlg.has_salt, True)

        #make sure property function works at instance level too
        self.assertEqual(UnsaltedAlg().has_salt, False)
        self.assertEqual(SaltedAlg().has_salt, True)

#=========================================================
#EOF
#=========================================================
