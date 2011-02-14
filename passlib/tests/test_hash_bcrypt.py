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
from passlib.tests.utils import TestCase, enable_option
from passlib.utils import _slow_bcrypt as slow_bcrypt
from passlib.tests.handler_utils import _HandlerTestCase, create_backend_case
from passlib.hash.bcrypt import BCrypt

#=========================================================
#utils
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

#=========================================================
#test frontend bcrypt algorithm
#=========================================================

#XXX: do we really need all these test vectors?
##    test_vectors = [
##        [ "",
##        "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
##        "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." ],
##        [ "",
##        "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
##        "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" ],
##        [ "",
##        "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
##        "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" ],
##        [ "",
##        "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
##        "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" ],
##
##        [ "a",
##        "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
##        "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" ],
##        [ "a",
##        "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
##        "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." ],
##        [ "a",
##        "$2a$10$k87L/MF28Q673VKh8/cPi.",
##        "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" ],
##        [ "a",
##        "$2a$12$8NJH3LsPrANStV6XtBakCe",
##        "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" ],
##
##        [ "abc",
##        "$2a$06$If6bvum7DFjUnE9p2uDeDu",
##        "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" ],
##        [ "abc",
##        "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
##        "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" ],
##        [ "abc",
##        "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
##        "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" ],
##        [ "abc",
##        "$2a$12$EXRkfkdmXn2gzds2SSitu.",
##        "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" ],
##
##        [ "abcdefghijklmnopqrstuvwxyz",
##        "$2a$06$.rCVZVOThsIa97pEDOxvGu",
##        "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" ],
##        [ "abcdefghijklmnopqrstuvwxyz",
##        "$2a$08$aTsUwsyowQuzRrDqFflhge",
##        "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." ],
##        [ "abcdefghijklmnopqrstuvwxyz",
##        "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
##        "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" ],
##        [ "abcdefghijklmnopqrstuvwxyz",
##        "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
##        "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" ],
##
##        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
##        "$2a$06$fPIsBO8qRqkjj273rfaOI.",
##        "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" ],
##        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
##        "$2a$08$Eq2r4G/76Wv39MzSX262hu",
##        "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" ],
##        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
##        "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
##        "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" ],
##        [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
##        "$2a$12$WApznUOJfkEGSmYRfnkrPO",
##        "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" ],
##        ]

class BCryptTest(_HandlerTestCase):
    handler = BCrypt
    secret_chars = 72

    known_correct = (
        #selected subset of backend test vectors (see above)
        ('', '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
        ('a', '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
        ('abc', '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
        ('abcdefghijklmnopqrstuvwxyz', '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
        ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
        )

    known_invalid = [
        #unsupported version
        "$2b$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
    ]

    known_identified_invalid = [
        #bad char in otherwise correct hash
        "$2a$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
        #rounds not zero-padded (pybcrypt rejects this, so so do we)
        '$2a$6$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'
        ]

#NOTE: pybcrypt backend will be chosen as primary if possible,
#so just check for os crypt and builtin
OsCrypt_BCryptTest = create_backend_case(BCryptTest, "os_crypt")
Builtin_BCryptTest = create_backend_case(BCryptTest, "builtin") if enable_option("slow") else None

#=========================================================
#eof
#=========================================================
