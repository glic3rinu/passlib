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
#module
log = getLogger(__name__)

#=========================================================
#helper password algorithms - these serve both as simple
# examples, and are used in the unittests
#=========================================================
class UnsaltedAlg(pwhash.CryptAlgorithm):
    "example algorithm usuing constant-salt hash"
    name = "unsalted"
    salt_bits = 0

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
        #NOTE: that salt / keep_salted are simply ignored
        return hashlib.sha1("boblious" + secret).hexdigest()

class SaltedAlg(pwhash.CryptAlgorithm):
    """example naive salted algorithm which never obeys keep_salt
    (note that the default verify() is implemented in this case)
    """
    name = "salted"
    salt_bits = 6*2

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

class SampleAlg(pwhash.CryptAlgorithm):
    "example salted algorithm w/ keep_salt support"
    name = "sample"
    salt_bits = 6*2

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
    'Really Long Password (tm), which is all the rage nowadays with the cool kids'
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
        if sc:
            #bcrypt, unixcrypt
            assert sc < len(secret), "need to increase test secret size"
            self.assert_(self.do_verify(secret[:sc], hash))
            self.assert_(self.do_verify(secret + tail, hash))
            self.assert_(not self.do_verify(secret[:sc-1], hash))
        else:
            #if no limit, secret+tail shouldn't verify
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
#database hashes
#=========================================================
class Mysql10CryptTest(_CryptTestCase):
    alg = pwhash.Mysql10Crypt

    #remove single space from secrets
    secrets = [ x for x in _CryptTestCase.secrets if x != ' ' ]

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

class Mysql41CryptTest(_CryptTestCase):
    alg = pwhash.Mysql41Crypt
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

class PostgresMd5CryptTest(_CryptTestCase):
    alg = pwhash.PostgresMd5Crypt
    positive_knowns = (
        # ((secret,user),hash)
        (('mypass', 'postgres'), 'md55fba2ea04fd36069d2574ea71c8efe9d'),
        (('mypass', 'root'), 'md540c31989b20437833f697e485811254b'),
        (("testpassword",'testuser'), 'md5d4fc5129cc2c25465a5370113ae9835f'),
    )
    invalid_identify = (
        #bad char in otherwise correct hash
        'md54zc31989b20437833f697e485811254b',
    )
    negative_identify = (
        #other hashes
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'
        '6f8c114b58f2ce9e',
        )

    def test_tuple_mode(self):
        "check tuple mode works for encrypt/verify"
        self.assertEquals(self.alg().encrypt(('mypass', 'postgres')),
            'md55fba2ea04fd36069d2574ea71c8efe9d')
        self.assertEquals(self.alg().verify(('mypass', 'postgres'),
            'md55fba2ea04fd36069d2574ea71c8efe9d'), True)

    def test_user(self):
        "check user kwd is required for encrypt/verify"
        self.assertRaises(ValueError, self.alg().encrypt, 'mypass')
        self.assertRaises(ValueError, self.alg().verify, 'mypass', 'md55fba2ea04fd36069d2574ea71c8efe9d')

    def do_concat(self, secret, prefix):
        if isinstance(secret, tuple):
            secret, user = secret
            secret = prefix + secret
            return secret, user
        else:
            return prefix + secret

    def do_encrypt(self, secret, *args, **kwds):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        assert 'user' not in kwds
        kwds['user'] = user
        return self.alg().encrypt(secret, *args, **kwds)

    def do_verify(self, secret, hash):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        return self.alg().verify(secret, hash, user=user)

#=========================================================
#Md5Crypt
#=========================================================
class Md5CryptTest(_CryptTestCase):
    alg = pwhash.Md5Crypt
    positive_knowns = (
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        )
    invalid_identify = (
        #bad char in otherwise correct hash
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        )
    negative_identify = (
        #other hashes
        '!gAwTx2l6NADI',
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
        )

#=========================================================
#BCrypt
#=========================================================
if enable_suite("bcrypt"):
    class BCryptTest(_CryptTestCase):
        alg = pwhash.BCrypt
        positive_knowns = (
            #test cases taken from bcrypt spec
            ('', '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
            ('', '$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye'),
            ('', '$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW'),
            ('', '$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO'),
            ('a', '$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe'),
            ('a', '$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.'),
            ('a', '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
            ('a', '$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS'),
            ('abc', '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'),
            ('abc', '$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm'),
            ('abc', '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
            ('abc', '$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q'),
            ('abcdefghijklmnopqrstuvwxyz', '$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC'),
            ('abcdefghijklmnopqrstuvwxyz', '$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.'),
            ('abcdefghijklmnopqrstuvwxyz', '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
            ('abcdefghijklmnopqrstuvwxyz', '$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG'),
            ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO'),
            ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW'),
            ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
            ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC'),
            )
        negative_identify = (
            #other hashes
            '!gAwTx2l6NADI',
            '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
            '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6ox',
            )
        invalid_identify = (
            #unsupported version
            "$2b$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
            #bad char in otherwise correct hash
            "$2a$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
            )

    #NOTE: BCrypt backend tests stored in test_security_bcrypt
else:
    BCryptTest = None

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
