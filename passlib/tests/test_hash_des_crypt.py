"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
from logging import getLogger
#site
#pkg
from passlib.tests.utils import TestCase, enable_option
from passlib.tests.handler_utils import _HandlerTestCase
import passlib.hash.des_crypt as mod
import passlib.hash.ext_des_crypt as mod2
#module
log = getLogger(__name__)

#=========================================================
#test frontend class
#=========================================================
class DesCryptTest(_HandlerTestCase):
    "test DesCrypt algorithm"
    handler = mod
    secret_chars = 8

    #TODO: test

    known_correct = (
        #secret, example hash which matches secret
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),
        (u'hell\u00D6', 'saykDgk3BPZ9E'),
        )
    known_invalid = (
        #bad char in otherwise correctly formatted hash
        '!gAwTx2l6NADI',
        )

if mod.backend != "builtin" and enable_option("all-backends"):

    #monkeypatch des-crypt mod so it uses builtin backend

    class BuiltinDesCryptTest(DesCryptTest):
        case_prefix = "des-crypt (builtin backend)"

        def setUp(self):
            self.tmp = mod.crypt
            mod.crypt = None

        def cleanUp(self):
            mod.crypt = self.tmp

class ExtDesCryptTest(_HandlerTestCase):
    "test ExtDesCrypt algorithm"
    handler = mod2
    known_correct = (
        (" ", "_K1..crsmZxOLzfJH8iw"),
        ("my", '_KR/.crsmykRplHbAvwA'), #<- to detect old 12-bit rounds bug
        ("my socra", "_K1..crsmf/9NzZr1fLM"),
        ("my socrates", '_K1..crsmOv1rbde9A9o'),
        ("my socrates note", "_K1..crsm/2qeAhdISMA"),
    )
    known_invalid = (
        #bad char in otherwise correctly formatted hash
       "_K1.!crsmZxOLzfJH8iw"
    )

#=========================================================
#test activate backend (stored in mod._crypt)
#=========================================================
#TODO: make these tests work again, or merge them into above.
##class _DesCryptBackendTest(TestCase):
##    "test builtin unix crypt backend"
##
##    def get_crypt(self):
##        raise NotImplementedError
##
##    known_correct = DesCryptTest.known_correct
##
##    def test_knowns(self):
##        "test known crypt results"
##        crypt = self.get_crypt()
##        for secret, result in self.known_correct:
##
##            #make sure crypt verifies preserving just salt
##            out = crypt(secret, result[:2])
##            self.assertEqual(out, result, "secret=%r using salt alone:" % (secret,))
##
##            #make sure crypt verifies preseving salt + fragment of known hash
##            out = crypt(secret, result[:6])
##            self.assertEqual(out, result, "secret=%r using salt + fragment:" % (secret,))
##
##            #make sure crypt verifies using whole known hash
##            out = crypt(secret, result)
##            self.assertEqual(out, result, "secret=%r using whole hash:" % (secret,))
##
##    #TODO: deal with border cases where host crypt & bps crypt differ
##    # (none of which should impact the normal use cases)
##    #border cases:
##    #   no salt given, empty salt given, 1 char salt
##    #   salt w/ non-b64 chars (linux crypt handles this _somehow_)
##    #test that \x00 is NOT allowed
##    #test that other chars _are_ allowed
##
##    def test_null_in_key(self):
##        "test null chars in secret"
##        crypt = self.get_crypt()
##        #NOTE: this is done to match stdlib crypt behavior.
##        # would raise ValueError if otherwise had free choice
##        self.assertRaises(ValueError, crypt, "hello\x00world", "ab")
##
##    def test_invalid_salt(self):
##        "test invalid salts"
##        crypt = self.get_crypt()
##
##        #NOTE: stdlib crypt's behavior is to return "" in this case.
##        # passlib wraps stdlib crypt so it raises ValueError
##        self.assertRaises(ValueError, crypt, "fooey","")
##
##        #NOTE: stdlib crypt's behavior is rather bizarre in this case
##        # (see wrapper in passlib.unix_crypt).
##        # passlib wraps stdlib crypt so it raises ValueError
##        self.assertRaises(ValueError, crypt, "fooey","f")
##
##        #FIXME: stdlib crypt does something unpredictable
##        #if passed salt chars outside of H64.CHARS range.
##        #not sure *what* it's algorithm is. should figure that out.
##        # until then, passlib wraps stdlib crypt so this causes ValueError
##        self.assertRaises(ValueError, crypt, "fooey", "a@")
##
##if mod.backend != "builtin" and enable_option("fallback-backend"):
##    class BuiltinDesCryptBackendTest(_DesCryptBackendTest):
##        "test builtin des-crypt backend"
##        case_prefix = "builtin des-crypt() backend"
##
##        def get_crypt(self):
##            return builtin_crypt
##
##if enable_option("backends"):
##    #NOTE: this will generally be the stdlib implementation,
##    #which of course is correct, so doing this more to detect deviations in builtin implementation
##    class ActiveDesCryptBackendTest(_DesCryptBackendTest):
##        "test active des-crypt backend"
##        case_prefix = mod.backend + " des-crypt() backend"
##
##        def get_crypt(self):
##            return mod.crypt

#=========================================================
#EOF
#=========================================================
