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
from passlib.tests.test_hash_base import _CryptTestCase as CryptTestCase
import passlib.hash.postgres as mod
#module
log = getLogger(__name__)

#=========================================================
#database hashes
#=========================================================
class PostgresMd5CryptTest(CryptTestCase):
    alg = mod.PostgresMd5Crypt
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
#EOF
#=========================================================
