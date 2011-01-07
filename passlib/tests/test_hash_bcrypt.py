"""passlib._bcrypt unitests (and parallel test for pybcrypt)

The BaseTest class was adapted from the jBcrypt unitests,
released under the following license:

    // Permission to use, copy, modify, and distribute this software for any
    // purpose with or without fee is hereby granted, provided that the above
    // copyright notice and this permission notice appear in all copies.
    //
    // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
#=========================================================
#imports
#=========================================================
#site
try:
    import bcrypt as pybcrypt
except ImportError:
    pybcrypt = None
#pkg
from passlib.tests.utils import TestCase, enable_suite
from passlib.hash import _slow_bcrypt as slow_bcrypt
from passlib.tests.test_hash_base import _CryptTestCase as CryptTestCase
import passlib.hash.bcrypt as mod

#=========================================================
#test slow_bcrypt backend
#=========================================================
class UtilTest(TestCase):
    "test slow_bcrypt's utility funcs"

    def test_encode64(self):
        encode = slow_bcrypt.encode_base64
        self.assertFunctionResults(encode, [
            ('', ''),
            ('..', '\x00'),
            ('...', '\x00\x00'),
            ('....', '\x00\x00\x00'),
            ('9u', '\xff'),
            ('996', '\xff\xff'),
            ('9999', '\xff\xff\xff'),
            ])

    def test_decode64(self):
        decode = slow_bcrypt.decode_base64
        self.assertFunctionResults(decode, [
            ('', ''),
            ('\x00', '..'),
            ('\x00\x00', '...'),
            ('\x00\x00\x00', '....'),
            ('\xff', '9u', ),
            ('\xff\xff','996'),
            ('\xff\xff\xff','9999'),
            ])

class _BcryptTestBase(TestCase):
    mod = None

    #XXX: where did these test vectors come from? jBCrypt?
    test_vectors = [
        [ "",
        "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
        "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." ],
        [ "",
        "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
        "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" ],
        [ "",
        "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
        "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" ],
        [ "",
        "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
        "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" ],
        [ "a",
        "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
        "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" ],
        [ "a",
        "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
        "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." ],
        [ "a",
        "$2a$10$k87L/MF28Q673VKh8/cPi.",
        "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" ],
        [ "a",
        "$2a$12$8NJH3LsPrANStV6XtBakCe",
        "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" ],
        [ "abc",
        "$2a$06$If6bvum7DFjUnE9p2uDeDu",
        "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" ],
        [ "abc",
        "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
        "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" ],
        [ "abc",
        "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
        "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" ],
        [ "abc",
        "$2a$12$EXRkfkdmXn2gzds2SSitu.",
        "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" ],
        [ "abcdefghijklmnopqrstuvwxyz",
        "$2a$06$.rCVZVOThsIa97pEDOxvGu",
        "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" ],
        [ "abcdefghijklmnopqrstuvwxyz",
        "$2a$08$aTsUwsyowQuzRrDqFflhge",
        "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." ],
        [ "abcdefghijklmnopqrstuvwxyz",
        "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
        "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" ],
        [ "abcdefghijklmnopqrstuvwxyz",
        "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
        "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" ],
        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
        "$2a$06$fPIsBO8qRqkjj273rfaOI.",
        "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" ],
        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
        "$2a$08$Eq2r4G/76Wv39MzSX262hu",
        "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" ],
        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
        "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
        "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" ],
        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
        "$2a$12$WApznUOJfkEGSmYRfnkrPO",
        "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" ],
        ]

    def test_00_hashpw(self):
        "test hashpw() generates expected result for a given plaintext & salt"
        hashpw = self.mod.hashpw
        for plain, salt, expected in self.test_vectors:
            hashed = hashpw(plain, salt)
            self.assertEquals(hashed, expected)

    def test_01_hashpw_success(self):
        "test hashpw() verifies knowns correctly"
        hashpw = self.mod.hashpw
        for plain, _, expected in self.test_vectors:
            hash = hashpw(plain, expected)
            self.assertEquals(hash, expected)

    def test_02_hashpw_failure(self):
        "test hashpw() negatively verifies incorrect knowns"
        hashpw = self.mod.hashpw
        for plain, _, expected in self.test_vectors:
            hash = hashpw(plain + 'number 15', expected)
            self.assertNotEquals(hash, expected)

    def test_03_gensalt(self):
        "test new salts verifies correctly"
        hashpw = self.mod.hashpw
        gensalt = self.mod.gensalt
        seen = set()
        for plain, _, _ in self.test_vectors:
            if plain in seen:
                continue
            seen.add(plain)

            #create salt
            salt = gensalt()

            #hash it
            hashed1 = hashpw(plain, salt)

            #run check again
            hashed2 = hashpw(plain, hashed1)

            #hashes shouldn't have changed
            self.assertEquals(hashed1, hashed2)

    def test_04_gensalt(self):
        "test gensalt options"
        hashpw = self.mod.hashpw
        gensalt = self.mod.gensalt
        seen = set()
        for plain, _, _ in self.test_vectors:
            if plain in seen:
                continue
            seen.add(plain)

            #create salt
            salt = gensalt(4)

            #hash it
            hashed1 = hashpw(plain, salt)

            #run check again
            hashed2 = hashpw(plain, hashed1)

            #hashes shouldn't have changed
            self.assertEquals(hashed1, hashed2)

    #=========================================================
    #eoc
    #=========================================================

if enable_suite("slow_bcrypt"):
    class SlowBcryptTest(_BcryptTestBase):
        "test slow bcrypt module"
        mod = slow_bcrypt

if pybcrypt and enable_suite("bcrypt"):
    #if pybcrypt is installed, run our unitest on them too,
    #just to ensure slow_bcrypt's interface is compatible.
    class PyBcryptTest(_BCryptTestBase):
        "make sure slow_bcrypt is compatible w/ pybcrypt"
        mod = pybcrypt

#=========================================================
#test frontend bcrypt algorithm
#=========================================================
if enable_suite("bcrypt"):
    class BCryptTest(CryptTestCase):
        alg = mod.BCrypt
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
#eof
#=========================================================
