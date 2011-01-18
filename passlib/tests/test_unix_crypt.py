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
from passlib.tests.utils import TestCase, enable_suite
from passlib._slow_unix_crypt import crypt as builtin_crypt
import passlib.unix_crypt as mod
from passlib.tests.test_base import _CryptTestCase as CryptTestCase
from passlib.hash import unix_crypt as uc
#module
log = getLogger(__name__)

#=========================================================
#test frontend class
#=========================================================
class UnixCryptTest(CryptTestCase):
    "test UnixCrypt algorithm"
    alg = uc
    positive_knowns = (
        #secret, example hash which matches secret
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),
        (u'hell\u00D6', 'saykDgk3BPZ9E'),
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

#=========================================================
#test activate backend (stored in mod._crypt)
#=========================================================
class UnixCryptBackendTest(TestCase):
    "test builtin unix crypt backend"
    case_prefix = "builtin crypt() backend"

    def get_crypt(self):
        return builtin_crypt

    positive_knowns = UnixCryptTest.positive_knowns

    def test_knowns(self):
        "test known crypt results"
        crypt = self.get_crypt()
        for secret, result in self.positive_knowns:

            #make sure crypt verifies preserving just salt
            out = crypt(secret, result[:2])
            self.assertEqual(out, result)

            #make sure crypt verifies preseving salt + fragment of known hash
            out = crypt(secret, result[:6])
            self.assertEqual(out, result)

            #make sure crypt verifies using whole known hash
            out = crypt(secret, result)
            self.assertEqual(out, result)

    #TODO: deal with border cases where host crypt & bps crypt differ
    # (none of which should impact the normal use cases)
    #border cases:
    #   no salt given, empty salt given, 1 char salt
    #   salt w/ non-b64 chars (linux crypt handles this _somehow_)
    #test that \x00 is NOT allowed
    #test that other chars _are_ allowed

    def test_null_in_key(self):
        "test null chars in secret"
        crypt = self.get_crypt()
        #NOTE: this is done to match stdlib crypt behavior.
        # would raise ValueError if otherwise had free choice
        self.assertRaises(ValueError, crypt, "hello\x00world", "ab")

    def test_invalid_salt(self):
        "test invalid salts"
        crypt = self.get_crypt()

        #NOTE: stdlib crypt's behavior is to return "" in this case.
        # passlib wraps stdlib crypt so it raises ValueError
        self.assertRaises(ValueError, crypt, "fooey","")

        #NOTE: stdlib crypt's behavior is rather bizarre in this case
        # (see wrapper in passlib.unix_crypt).
        # passlib wraps stdlib crypt so it raises ValueError
        self.assertRaises(ValueError, crypt, "fooey","f")

        #FIXME: stdlib crypt does something unpredictable
        #if passed salt chars outside of H64.CHARS range.
        #not sure *what* it's algorithm is. should figure that out.
        # until then, passlib wraps stdlib crypt so this causes ValueError
        self.assertRaises(ValueError, crypt, "fooey", "a@")

if mod.backend != "builtin":
    #NOTE: this will generally be the stdlib implementation,
    #which of course is correct, so doing this more to detect deviations in builtin implementation
    class ActiveUnixCryptBackendTest(UnixCryptBackendTest):
        "test active unix crypt backend"
        case_prefix = mod.backend + " crypt() backend"

        def get_crypt(self):
            return mod.crypt

#=========================================================
#EOF
#=========================================================
