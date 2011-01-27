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
from passlib.tests.utils import TestCase, enable_test
from passlib.tests.handler_utils import _HandlerTestCase
from passlib.utils._slow_des_crypt import crypt as builtin_crypt
import passlib.unix.des_crypt as mod
#module
log = getLogger(__name__)

#=========================================================
#test frontend class
#=========================================================
class DesCryptTest(_HandlerTestCase):
    "test DesCrypt algorithm"
    handler = mod.DesCrypt
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

class ExtDesCryptTest(_HandlerTestCase):
    "test ExtDesCrypt algorithm"
    handler = mod.ExtDesCrypt
    known_correct = (
        (" ", "_K1..crsmZxOLzfJH8iw"),
        ("my", "_K1..crsmjChSwFUvdpw"),
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
class _DesCryptBackendTest(TestCase):
    "test builtin unix crypt backend"

    def get_crypt(self):
        raise NotImplementedError

    known_correct = DesCryptTest.known_correct

    def test_knowns(self):
        "test known crypt results"
        crypt = self.get_crypt()
        for secret, result in self.known_correct:

            #make sure crypt verifies preserving just salt
            out = crypt(secret, result[:2])
            self.assertEqual(out, result, "secret=%r using salt alone:" % (secret,))

            #make sure crypt verifies preseving salt + fragment of known hash
            out = crypt(secret, result[:6])
            self.assertEqual(out, result, "secret=%r using salt + fragment:" % (secret,))

            #make sure crypt verifies using whole known hash
            out = crypt(secret, result)
            self.assertEqual(out, result, "secret=%r using whole hash:" % (secret,))

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

if mod.backend != "builtin" and enable_test("fallback-backend"):
    class BuiltinDesCryptBackendTest(_DesCryptBackendTest):
        "test builtin des-crypt backend"
        case_prefix = "builtin des-crypt() backend"

        def get_crypt(self):
            return builtin_crypt

if enable_test("backends"):
    #NOTE: this will generally be the stdlib implementation,
    #which of course is correct, so doing this more to detect deviations in builtin implementation
    class ActiveDesCryptBackendTest(_DesCryptBackendTest):
        "test active des-crypt backend"
        case_prefix = mod.backend + " des-crypt() backend"

        def get_crypt(self):
            return mod.crypt


class DesTest(TestCase):

    #test vectors taken from http://www.skepticfiles.org/faq/testdes.htm

    #(key, plaintext, ciphertext) all as 64 bit
    test_des_vectors = [
        (int(line[4:21],16), int(line[21:38],16), int(line[38:],16))
        for line in
 """    0000000000000000 0000000000000000 8CA64DE9C1B123A7
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF 7359B2163E4EDC58
    3000000000000000 1000000000000001 958E6E627A05557B
    1111111111111111 1111111111111111 F40379AB9E0EC533
    0123456789ABCDEF 1111111111111111 17668DFC7292532D
    1111111111111111 0123456789ABCDEF 8A5AE1F81AB8F2DD
    0000000000000000 0000000000000000 8CA64DE9C1B123A7
    FEDCBA9876543210 0123456789ABCDEF ED39D950FA74BCC4
    7CA110454A1A6E57 01A1D6D039776742 690F5B0D9A26939B
    0131D9619DC1376E 5CD54CA83DEF57DA 7A389D10354BD271
    07A1133E4A0B2686 0248D43806F67172 868EBB51CAB4599A
    3849674C2602319E 51454B582DDF440A 7178876E01F19B2A
    04B915BA43FEB5B6 42FD443059577FA2 AF37FB421F8C4095
    0113B970FD34F2CE 059B5E0851CF143A 86A560F10EC6D85B
    0170F175468FB5E6 0756D8E0774761D2 0CD3DA020021DC09
    43297FAD38E373FE 762514B829BF486A EA676B2CB7DB2B7A
    07A7137045DA2A16 3BDD119049372802 DFD64A815CAF1A0F
    04689104C2FD3B2F 26955F6835AF609A 5C513C9C4886C088
    37D06BB516CB7546 164D5E404F275232 0A2AEEAE3FF4AB77
    1F08260D1AC2465E 6B056E18759F5CCA EF1BF03E5DFA575A
    584023641ABA6176 004BD6EF09176062 88BF0DB6D70DEE56
    025816164629B007 480D39006EE762F2 A1F9915541020B56
    49793EBC79B3258F 437540C8698F3CFA 6FBF1CAFCFFD0556
    4FB05E1515AB73A7 072D43A077075292 2F22E49BAB7CA1AC
    49E95D6D4CA229BF 02FE55778117F12A 5A6B612CC26CCE4A
    018310DC409B26D6 1D9D5C5018F728C2 5F4C038ED12B2E41
    1C587F1C13924FEF 305532286D6F295A 63FAC0D034D9F793
    0101010101010101 0123456789ABCDEF 617B3A0CE8F07100
    1F1F1F1F0E0E0E0E 0123456789ABCDEF DB958605F8C8C606
    E0FEE0FEF1FEF1FE 0123456789ABCDEF EDBFD1C66C29CCC7
    0000000000000000 FFFFFFFFFFFFFFFF 355550B2150E2451
    FFFFFFFFFFFFFFFF 0000000000000000 CAAAAF4DEAF1DBAE
    0123456789ABCDEF 0000000000000000 D5D44FF720683D0D
    FEDCBA9876543210 FFFFFFFFFFFFFFFF 2A2BB008DF97C2F2
    """.split("\n") if line.strip()
    ]

    def test_des_encrypt_int_block(self):
        from passlib.utils._slow_des_crypt import des_encrypt_int_block
        for k,p,c in self.test_des_vectors:
            result = des_encrypt_int_block(k,p)
            self.assertEqual(result, c, "key=%r p=%r:" % (k,p))

#=========================================================
#EOF
#=========================================================
