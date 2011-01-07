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
        real_salt = pwhash.h64_gen_salt(2)
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
            real_salt = pwhash.h64_gen_salt(2)
        return "@sam%s%s" % (real_salt, hashlib.sha1(real_salt+secret).hexdigest())

#=========================================================
#other unittest helpers
#=========================================================

#list of various distinct secrets that all algs are tested with
SECRETS = [
    '',
    ' ',
    'test',
    'testa',
    'test test',
    'test bcdef',
    'testq'
    'testtest',
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

    def message_prefix(self):
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
#UnixCrypt
#=========================================================

class UnixCryptTest(_CryptTestCase):
    "test UnixCrypt algorithm"
    alg = pwhash.UnixCrypt
    positive_knowns = (
        #secret, example hash which matches secret
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),
        )
    invalid_identify = (
        #bad char in otherwise correctly formatted hash
        '!gAwTx2l6NADI',
        )
    negative_identify = (
        #hashes using other algs, which shouldn't match this algorithm
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'
        )

class UnixCryptBackendTest(TestCase):
    "test builtin unix crypt backend"
    unix_crypt = pwhash.unix_crypt

    positive_knowns = UnixCryptTest.positive_knowns

    def test_knowns(self):
        "test lowlevel unix_crypt function"
        unix_crypt = self.unix_crypt
        for secret, result in self.positive_knowns:
            #make sure crypt verifies using salt
            out = unix_crypt(secret, result[:2])
            self.assertEqual(out, result)
            #make sure crypt verifies using partial hash
            out = unix_crypt(secret, result[:6])
            self.assertEqual(out, result)
            #make sure crypt verifies using whole hash
            out = unix_crypt(secret, result)
            self.assertEqual(out, result)

    #TODO: deal with border cases where host crypt & bps crypt differ
    # (none of which should impact the normal use cases)
    #border cases:
    #   no salt given, empty salt given, 1 char salt
    #   salt w/ non-b64 chars (linux crypt handles this _somehow_)
    #test that \x00 is NOT allowed
    #test that other chars _are_ allowed

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
#test raw sha-crypt functions
#=========================================================
class Sha256CryptTest(_CryptTestCase):
    alg = pwhash.Sha256Crypt
    positive_knowns = (
        ('', '$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3'),
        (' ', '$5$rounds=10376$I5lNtXtRmf.OoMd8$Ko3AI1VvTANdyKhBPavaRjJzNpSatKU6QVN9uwS9MH.'),
        ('test', '$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1'),
        ('Compl3X AlphaNu3meric', '$5$rounds=10350$o.pwkySLCzwTdmQX$nCMVsnF3TXWcBPOympBUUSQi6LGGloZoOsVJMGJ09UB'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$5$rounds=11944$9dhlu07dQMRWvTId$LyUI5VWkGFwASlzntk1RLurxX54LUhgAcJZIt0pYGT7'),
        )
    invalid_identify = (
        #bad char in otherwise correct hash
        '$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe!ZGsGx2aBvxTvDFI613c3'
        )
    negative_identify = (
        #other hashes
        '!gAwTx2l6NADI',
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6ox',
        )

class Sha512CryptTest(_CryptTestCase):
    alg = pwhash.Sha512Crypt
    positive_knowns = (
        ('', '$6$rounds=11021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1'),
        (' ', '$6$rounds=11104$ED9SA4qGmd57Fq2m$q/.PqACDM/JpAHKmr86nkPzzuR5.YpYa8ZJJvI8Zd89ZPUYTJExsFEIuTYbM7gAGcQtTkCEhBKmp1S1QZwaXx0'),
        ('test', '$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1'),
        ('Compl3X AlphaNu3meric', '$6$rounds=10787$wakX8nGKEzgJ4Scy$X78uqaX1wYXcSCtS4BVYw2trWkvpa8p7lkAtS9O/6045fK4UB2/Jia0Uy/KzCpODlfVxVNZzCCoV9s2hoLfDs/'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$6$rounds=11065$5KXQoE1bztkY5IZr$Jf6krQSUKKOlKca4hSW07MSerFFzVIZt/N3rOTsUgKqp7cUdHrwV8MoIVNCk9q9WL3ZRMsdbwNXpVk0gVxKtz1'),
        )
    negative_identify = (
        #other hashes
        '!gAwTx2l6NADI',
         '$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3',
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6ox',
        )
    invalid_identify = (
        #bad char in otherwise correct hash
        '$6$rounds=11021$KsvQipYPWpr9!wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1',
        )

class Sha512BackendTest(TestCase):
    "test sha512-crypt backend against specification unittest"
    cases512 = [
        #salt-hash, secret, result -- taken from alg definition page
        ("$6$saltstring", "Hello world!",
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
        "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1" ),

      ( "$6$rounds=10000$saltstringsaltstring", "Hello world!",
        "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
        "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." ),

      ( "$6$rounds=5000$toolongsaltstring", "This is just a test",
        "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
        "zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0" ),

      ( "$6$rounds=1400$anotherlongsaltstring",
        "a very much longer text to encrypt.  This one even stretches over more"
        "than one line.",
        "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
        "vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1" ),

      ( "$6$rounds=77777$short",
        "we have a short salt string but not a short password",
        "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
        "ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0" ),

      ( "$6$rounds=123456$asaltof16chars..", "a short string",
        "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
        "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1" ),

      ( "$6$rounds=10$roundstoolow", "the minimum number is still observed",
        "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
        "hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX." ),
    ]
    def test512(self):
        crypt = pwhash.Sha512Crypt()
        for hash, secret, result in self.cases512:
            rec = crypt._parse(hash)
            self.assertEqual(rec.alg, '6')
            out = crypt.encrypt(secret, hash, keep_salt=True)
            rec2 = crypt._parse(hash)
            self.assertEqual(rec2.salt, rec.salt, "hash=%r secret=%r" % (hash, secret))
            self.assertEqual(rec2.chk, rec.chk, "hash=%r secret=%r" % (hash, secret))
            self.assertEqual(out, result, "hash=%r secret=%r" % (hash, secret))

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
#CryptContext
#=========================================================

CryptContext = pwhash.CryptContext

class CryptContextTest(TestCase):
    "test CryptContext object's behavior"

    #=========================================================
    #0 constructor
    #=========================================================
    def test_00_constructor(self):
        "test CryptContext constructor using classes"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])

        #parse
        a, b, c = cc
        self.assertIsInstance(a, UnsaltedAlg)
        self.assertIsInstance(b, SaltedAlg)
        self.assertIsInstance(c, SampleAlg)

    def test_01_constructor(self):
        "test CryptContext constructor using instances"
        #create crypt context
        a = UnsaltedAlg()
        b = SaltedAlg()
        c = SampleAlg()
        cc = CryptContext([a,b,c])

        #verify elements
        self.assertEquals(list(cc), [a, b, c])

    #=========================================================
    #1 list getters
    #=========================================================
    def test_10_getitem(self):
        "test CryptContext.__getitem__[idx]"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        #verify len
        self.assertEquals(len(cc), 3)

        #verify getitem
        self.assertEquals(cc[0], a)
        self.assertEquals(cc[1], b)
        self.assertEquals(cc[2], c)
        self.assertEquals(cc[-1], c)
        self.assertRaises(IndexError, cc.__getitem__, 3)

    def test_11_index(self):
        "test CryptContext.index(elem)"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc
        d = SampleAlg()

        self.assertEquals(cc.index(a), 0)
        self.assertEquals(cc.index(b), 1)
        self.assertEquals(cc.index(c), 2)
        self.assertEquals(cc.index(d), -1)

    def test_12_contains(self):
        "test CryptContext.__contains__(elem)"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc
        d = SampleAlg()

        self.assertEquals(a in cc, True)
        self.assertEquals(b in cc, True)
        self.assertEquals(c in cc, True)
        self.assertEquals(d in cc, False)

    #=========================================================
    #2 list setters
    #=========================================================
    def test_20_setitem(self):
        "test CryptContext.__setitem__"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc
        d = SampleAlg()
        self.assertIsNot(c, d)
        e = pwhash.Md5Crypt()

        #check baseline
        self.assertEquals(list(cc), [a, b, c])

        #replace 0 w/ d should raise error (SampleAlg already in list)
        self.assertRaises(KeyError, cc.__setitem__, 0, d)
        self.assertEquals(list(cc), [a, b, c])

        #replace 0 w/ e
        cc[0] = e
        self.assertEquals(list(cc), [e, b, c])

        #replace 2 w/ d
        cc[2] = d
        self.assertEquals(list(cc), [e, b, d])

        #replace -1 w/ c
        cc[-1] = c
        self.assertEquals(list(cc), [e, b, c])

        #replace -2 w/ d should raise error
        self.assertRaises(KeyError, cc.__setitem__, -2, d)
        self.assertEquals(list(cc), [e, b, c])

    def test_21_append(self):
        "test CryptContext.__setitem__"
        cc = CryptContext([UnsaltedAlg])
        a, = cc
        b = SaltedAlg()
        c = SampleAlg()
        d = SampleAlg()

        self.assertEquals(list(cc), [a])

        #try append
        cc.append(b)
        self.assertEquals(list(cc), [a, b])

        #and again
        cc.append(c)
        self.assertEquals(list(cc), [a, b, c])

        #try append dup
        self.assertRaises(KeyError, cc.append, d)
        self.assertEquals(list(cc), [a, b, c])

    def test_20_insert(self):
        "test CryptContext.insert"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc
        d = SampleAlg()
        self.assertIsNot(c, d)
        e = pwhash.Md5Crypt()
        f = pwhash.Sha512Crypt()
        g = pwhash.UnixCrypt()

        #check baseline
        self.assertEquals(list(cc), [a, b, c])

        #inserting d at 0 should raise error (SampleAlg already in list)
        self.assertRaises(KeyError, cc.insert, 0, d)
        self.assertEquals(list(cc), [a, b, c])

        #insert e at start
        cc.insert(0, e)
        self.assertEquals(list(cc), [e, a, b, c])

        #insert f at end
        cc.insert(-1, f)
        self.assertEquals(list(cc), [e, a, b, f, c])

        #insert g at end
        cc.insert(5, g)
        self.assertEquals(list(cc), [e, a, b, f, c, g])

    #=========================================================
    #3 list dellers
    #=========================================================
    def test_30_remove(self):
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc
        d = SampleAlg()
        self.assertIsNot(c, d)

        self.assertEquals(list(cc), [a, b, c])

        self.assertRaises(ValueError, cc.remove, d)
        self.assertEquals(list(cc), [a, b, c])

        cc.remove(a)
        self.assertEquals(list(cc), [b, c])

        self.assertRaises(ValueError, cc.remove, a)
        self.assertEquals(list(cc), [b, c])

    def test_31_discard(self):
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc
        d = SampleAlg()
        self.assertIsNot(c, d)

        self.assertEquals(list(cc), [a, b, c])

        self.assertEquals(cc.discard(d), False)
        self.assertEquals(list(cc), [a, b, c])

        self.assertEquals(cc.discard(a), True)
        self.assertEquals(list(cc), [b, c])

        self.assertEquals(cc.discard(a), False)
        self.assertEquals(list(cc), [b, c])

    #=========================================================
    #4 list composition
    #=========================================================

    def test_40_add(self, lsc=False):
        "test CryptContext + list"
        #build and join cc to list
        a = UnsaltedAlg()
        b = SaltedAlg()
        c = SampleAlg()
        cc = CryptContext([a, b, c])
        ls = [pwhash.Md5Crypt, pwhash.Sha512Crypt]
        if lsc:
            ls = CryptContext(ls)
        cc2 = cc + ls

        #verify types
        self.assertIsInstance(cc, CryptContext)
        self.assertIsInstance(cc2, CryptContext)
        self.assertIsInstance(ls, CryptContext if lsc else list)

        #verify elements
        self.assertIsNot(cc, ls)
        self.assertIsNot(cc, cc2)
        self.assertIsNot(ls, cc2)

        #verify cc
        a, b, c = cc
        self.assertIsInstance(a, UnsaltedAlg)
        self.assertIsInstance(b, SaltedAlg)
        self.assertIsInstance(c, SampleAlg)

        #verify ls
        d, e = ls
        if lsc:
            self.assertIsInstance(d, pwhash.Md5Crypt)
            self.assertIsInstance(e, pwhash.Sha512Crypt)
        else:
            self.assertIs(d, pwhash.Md5Crypt)
            self.assertIs(e, pwhash.Sha512Crypt)

        #verify cc2
        a2, b2, c2, d2, e2 = cc2
        self.assertIs(a2, a)
        self.assertIs(b2, b)
        self.assertIs(c2, c)
        if lsc:
            self.assertIs(d2, d)
            self.assertIs(e2, e)
        else:
            self.assertIsInstance(d2, pwhash.Md5Crypt)
            self.assertIsInstance(e2, pwhash.Sha512Crypt)

    def test_41_add(self):
        "test CryptContext + CryptContext"
        self.test_40_add(lsc=True)

    def test_42_iadd(self, lsc=False):
        "test CryptContext += list"
        #build and join cc to list
        a = UnsaltedAlg()
        b = SaltedAlg()
        c = SampleAlg()
        cc = CryptContext([a, b, c])
        ls = [pwhash.Md5Crypt, pwhash.Sha512Crypt]
        if lsc:
            ls = CryptContext(ls)

        #baseline
        self.assertEquals(list(cc), [a, b, c])
        self.assertIsInstance(cc, CryptContext)
        self.assertIsInstance(ls, CryptContext if lsc else list)
        if lsc:
            d, e = ls
            self.assertIsInstance(d, pwhash.Md5Crypt)
            self.assertIsInstance(e, pwhash.Sha512Crypt)

        #add
        cc += ls

        #verify types
        self.assertIsInstance(cc, CryptContext)
        self.assertIsInstance(ls, CryptContext if lsc else list)

        #verify elements
        self.assertIsNot(cc, ls)

        #verify cc
        a2, b2, c2, d2, e2 = cc
        self.assertIs(a2, a)
        self.assertIs(b2, b)
        self.assertIs(c2, c)
        if lsc:
            self.assertIs(d2, d)
            self.assertIs(e2, e)
        else:
            self.assertIsInstance(d2, pwhash.Md5Crypt)
            self.assertIsInstance(e2, pwhash.Sha512Crypt)

        #verify ls
        d, e = ls
        if lsc:
            self.assertIsInstance(d, pwhash.Md5Crypt)
            self.assertIsInstance(e, pwhash.Sha512Crypt)
        else:
            self.assertIs(d, pwhash.Md5Crypt)
            self.assertIs(e, pwhash.Sha512Crypt)

    def test_43_iadd(self):
        "test CryptContext += CryptContext"
        self.test_42_iadd(lsc=True)

    def test_44_extend(self):
        a = UnsaltedAlg()
        b = SaltedAlg()
        c = SampleAlg()
        cc = CryptContext([a, b, c])
        ls = [pwhash.Md5Crypt, pwhash.Sha512Crypt]

        cc.extend(ls)

        a2, b2, c2, d2, e2 = cc
        self.assertIs(a2, a)
        self.assertIs(b2, b)
        self.assertIs(c2, c)
        self.assertIsInstance(d2, pwhash.Md5Crypt)
        self.assertIsInstance(e2, pwhash.Sha512Crypt)

        self.assertRaises(KeyError, cc.extend, [pwhash.Sha512Crypt ])
        self.assertRaises(KeyError, cc.extend, [pwhash.Sha512Crypt() ])

    #=========================================================
    #5 basic crypt interface
    #=========================================================
    def test_50_resolve(self):
        "test CryptContext.resolve()"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        self.assertEquals(cc.resolve('unsalted'), a)
        self.assertEquals(cc.resolve('salted'), b)
        self.assertEquals(cc.resolve('sample'), c)
        self.assertEquals(cc.resolve('md5-crypt'), None)

        self.assertEquals(cc.resolve(['unsalted']), a)
        self.assertEquals(cc.resolve(['md5-crypt']), None)
        self.assertEquals(cc.resolve(['unsalted', 'salted', 'md5-crypt']), b)

    def test_51_identify(self):
        "test CryptContext.identify"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        for crypt in (a, b, c):
            h = crypt.encrypt("test")
            self.assertEquals(cc.identify(h, resolve=True), crypt)
            self.assertEquals(cc.identify(h), crypt.name)

        self.assertEquals(cc.identify('$1$232323123$1287319827', resolve=True), None)
        self.assertEquals(cc.identify('$1$232323123$1287319827'), None)

        #make sure "None" is accepted
        self.assertEquals(cc.identify(None), None)

    def test_52_encrypt_and_verify(self):
        "test CryptContext.encrypt & verify"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        #check encrypt/id/verify pass for all algs
        for crypt in (a, b, c):
            h = cc.encrypt("test", alg=crypt.name)
            self.assertEquals(cc.identify(h, resolve=True), crypt)
            self.assertEquals(cc.verify('test', h), True)
            self.assertEquals(cc.verify('notest', h), False)

        #check default alg
        h = cc.encrypt("test")
        self.assertEquals(cc.identify(h, resolve=True), c)

        #check verify using algs
        self.assertEquals(cc.verify('test', h, alg='sample'), True)
        self.assertEquals(cc.verify('test', h, alg='salted'), False)

    def test_53_encrypt_salting(self):
        "test CryptContext.encrypt salting options"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc
        self.assert_(c.has_salt)

        h = cc.encrypt("test")
        self.assertEquals(cc.identify(h, resolve=True), c)

        h2 = cc.encrypt("test", h)
        self.assertEquals(cc.identify(h2, resolve=True), c)
        self.assertNotEquals(h2, h)

        h3 = cc.encrypt("test", h, keep_salt=True)
        self.assertEquals(cc.identify(h3, resolve=True), c)
        self.assertEquals(h3, h)

    def test_54_verify_empty(self):
        "test CryptContext.verify allows hash=None"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        self.assertEquals(cc.verify('xxx', None), False)
        for crypt in cc:
            self.assertEquals(cc.verify('xxx', None, alg=crypt.name), False)

#XXX: haven't decided if this should be part of protocol
##    def test_55_verify_empty_secret(self):
##        "test CryptContext.verify allows secret=None"
##        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
##        h = cc.encrypt("test")
##        self.assertEquals(cc.verify(None,h), False)

    #=========================================================
    #6 crypt-enhanced list interface
    #=========================================================
    def test_60_getitem(self):
        "test CryptContext.__getitem__[algname]"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        #verify getitem
        self.assertEquals(cc['unsalted'], a)
        self.assertEquals(cc['salted'], b)
        self.assertEquals(cc['sample'], c)
        self.assertRaises(KeyError, cc.__getitem__, 'md5-crypt')

    def test_61_get(self):
        "test CryptContext.get(algname)"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        #verify getitem
        self.assertEquals(cc.get('unsalted'), a)
        self.assertEquals(cc.get('salted'), b)
        self.assertEquals(cc.get('sample'), c)
        self.assertEquals(cc.get('md5-crypt'), None)

    def test_62_index(self):
        "test CryptContext.index(algname)"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])

        #verify getitem
        self.assertEquals(cc.index('unsalted'), 0)
        self.assertEquals(cc.index('salted'), 1)
        self.assertEquals(cc.index('sample'), 2)
        self.assertEquals(cc.index('md5-crypt'), -1)

    def test_63_contains(self):
        "test CryptContext.__contains__(algname)"
        #create crypt context
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        self.assertEquals('salted' in cc, True)
        self.assertEquals('unsalted' in cc, True)
        self.assertEquals('sample' in cc, True)
        self.assertEquals('md5-crypt' in cc, False)

    def test_64_keys(self):
        "test CryptContext.keys()"
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        self.assertEquals(cc.keys(), ['unsalted', 'salted', 'sample'])

    def test_65_remove(self):
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        self.assertEquals(list(cc), [a, b, c])

        self.assertRaises(KeyError, cc.remove, 'md5-crypt')
        self.assertEquals(list(cc), [a, b, c])

        cc.remove('unsalted')
        self.assertEquals(list(cc), [b, c])

        self.assertRaises(KeyError, cc.remove, 'unsalted')
        self.assertEquals(list(cc), [b, c])

    def test_66_discard(self):
        cc = CryptContext([UnsaltedAlg, SaltedAlg, SampleAlg])
        a, b, c = cc

        self.assertEquals(list(cc), [a, b, c])

        self.assertEquals(cc.discard('md5-crypt'), False)
        self.assertEquals(list(cc), [a, b, c])

        self.assertEquals(cc.discard('unsalted'), True)
        self.assertEquals(list(cc), [b, c])

        self.assertEquals(cc.discard('unsalted'), False)
        self.assertEquals(list(cc), [b, c])
    #=========================================================
    #eoc
    #=========================================================

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

        last = 'sha512-crypt'
        self.assertEqual(dc.keys()[-1], last)
        h = dc.encrypt("test")
        self.assertEqual(dc.identify(h), last)
        self.assertEqual(dc.verify('test', h, alg=last), True)

#=========================================================
#EOF
#=========================================================
