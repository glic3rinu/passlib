"""
test_bps3 -- bps3 unittest script -- (c) Assurance Technologies 2003-2006

defines unit tests for bps lib.

NOTE: this module should import bps3 modules
relative to sys.path, not locally, since it may be run in another location.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import sys
from itertools import islice
from decimal import Decimal
#site
#pkg
from bps import numeric as num
from bps.rng import random
from bps.meta import Params as ak
#module
from bps.tests.utils import TestCase
native = sys.byteorder
#=========================================================
#number theory funcs
#=========================================================
class NumberTheoryTest(TestCase):
    #TODO: test gcd, lcm

    composites = [
        4, 8, 12, 7*6, 108, 641**5 * 431**2 * 449
    ]
    factors = {
        -1: [],
        0: [],
        1: [],
        2: [(2, 1)],
        8:[(2, 3)],
        -10:[(2, 1), (5, 1)],
        }
    def test_factors(self):
        "run factors() against simple & border test cases"
        for value, factors in self.factors.iteritems():
            self.assertEqual(num.factors(value), factors)
        for value in PrimeTest.primes:
            f = num.factors(value)
            self.assert_(f == [(value, 1)], "prime %r has wrong factors: %r" % (value, f))
        for value in self.composites:
            f = num.factors(value)
            self.assert_(len(f) > 1 or (f[0][0] < value and f[0][1] > 1),
                "composite %r has wrong factors: %r" % (value, f))

    def test_random_factors(self):
        "run factors() against randomly generated composites"
        primes = PrimeTest.primes
        for r in xrange(25):
            c = random.randrange(1, 9)
            out = set()
            while len(out) < c:
                out.add(random.choice(primes))
            f = [
                (p, random.randrange(1, 7))
                for p in sorted(out)
                ]
            n = 1
            for p, e in f:
                n *= (p**e)
            result = num.factors(n)
            self.assertEqual(result, f)

    def test_gcd(self):
        self.check_function_results(num.gcd, [
            #test zero behavior
            (0, 0, 0),
            (100, 100, 0),
            (100, 0, 100),

            #test 1 behavior
            (1, 1, 10),
            (1, 1, 2),
            (1, 1, 3),

            #test prime behavior
            (1, 5, 7),

            #test various composites
            (5, 10, 15),

            #test negatives
            (2, 10, 4),
            (2, -10, 4),
            (2, 10, -4),
            (2, -10, -4),
            ])

    def test_lcm(self):
        self.check_function_results(num.lcm, [
            (40, 10, 8),
            (120, 15, 40),
            (45, 15, 45),
            ])

#=========================================================
#primality funcs
#=========================================================
class PrimeTest(TestCase):
    "test primality/factorization"
    #the first 128 primes (that's 64 more than is stored internally,
    # so that we test both modes of operations
    primes = [
        #prime 0
        2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,
        59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,
        137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,
        227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,

        #^ end of bps.numeric._small_primes

        #prime 64
        313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,
        419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,
        509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,
        617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,

        #prime 128
        727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827,
        829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
        947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
        1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,

        #prime 192
        1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
        1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
        1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
        1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,

        #^ prime 255
        ]

    big_primes = [


    ]

    def test_is_prime(self):
        primes = set(self.primes)
        for value in xrange(-10, max(primes)):
            self.assertEqual(num.is_prime(value), value in primes)

    def test_is_mr_prime(self):
        primes = set(self.primes)
        for value in xrange(-10, max(primes)):
            self.assertEqual(num.is_mr_prime(value), value in primes)

    def test_iter_primes(self):
        #test the list matches
        primes = list(islice(num.iter_primes(), len(self.primes)))
        self.assertEqual(primes, self.primes)

        #what if we start real low
        primes = list(islice(num.iter_primes(-100), len(self.primes)))
        self.assertEqual(primes, self.primes)

        #in middle of small primes
        primes = list(islice(num.iter_primes(53), len(self.primes)-15))
        self.assertEqual(primes, self.primes[15:])

        #at end of small primes
        primes = list(islice(num.iter_primes(310), len(self.primes)-63))
        self.assertEqual(primes, self.primes[63:])

        #at end of small primes 2
        primes = list(islice(num.iter_primes(311), len(self.primes)-63))
        self.assertEqual(primes, self.primes[63:])

        #at end of small primes 3
        primes = list(islice(num.iter_primes(313), len(self.primes)-64))
        self.assertEqual(primes, self.primes[64:])

        #test 'stop' kwd
        primes = list(num.iter_primes(313, 419))
        self.assertEqual(primes, self.primes[64:64+16])

        primes = list(num.iter_primes(312, 419))
        self.assertEqual(primes, self.primes[64:64+16])

        #test 'count' kwd
        primes = list(num.iter_primes(313, count=16))
        self.assertEqual(primes, self.primes[64:64+16])

        #test stop < count
        primes = list(num.iter_primes(313, 419, count=32))
        self.assertEqual(primes, self.primes[64:64+16])

        #test stop > count
        primes = list(num.iter_primes(313, 900, count=16))
        self.assertEqual(primes, self.primes[64:64+16])

    def test_np_prime(self):
        "test next_prime & prev_prime"
        #before first prime
        for value in xrange(-10, 2):
            self.assertEqual(num.next_prime(value), 2)
            self.assertEqual(num.prev_prime(value), None)

        #test 2
        self.assertEqual(num.next_prime(2), 3)
        self.assertEqual(num.prev_prime(2), None)

        #over first 128 primes (avoiding 2 & last one)
        for idx, value in enumerate(self.primes[1:-1]):
            idx += 1
            assert self.primes[idx] == value

            #prev
            prev = self.primes[idx-1]
            self.assertEqual(num.prev_prime(value+2), value)
            self.assertEqual(num.prev_prime(value+1), value)
            self.assertEqual(num.prev_prime(value), prev, "value: %r" % value)
            if prev == value-1:
                assert value == 3
                self.assertEqual(num.prev_prime(value-1), None)
                self.assertEqual(num.prev_prime(value-2), None)
            elif prev == value-2:
                self.assertEqual(num.prev_prime(value-1), prev)
                self.assert_(num.prev_prime(value-2) < prev)
            else:
                self.assertEqual(num.prev_prime(value-1), prev)
                self.assertEqual(num.prev_prime(value-2), prev)

            #next
            next = self.primes[idx+1]
            if value == 3:
                self.assertEqual(num.next_prime(value-2), 2)
            else:
                self.assertEqual(num.next_prime(value-2), value)
            self.assertEqual(num.next_prime(value-1), value)
            self.assertEqual(num.next_prime(value), next)
            self.assertEqual(num.next_prime(value+1), next)
            if next == value+2:
                self.assert_(num.next_prime(value+2) > next, "v=%r nv+2=%r n=%r" % (value, num.next_prime(value+2), next))
            else:
                self.assertEqual(num.next_prime(value+2), next)

#=========================================================
#bit string funcs
#=========================================================
class BytesTest(TestCase):

    def test_list_to_bytes(self):
        self.check_function_results(num.list_to_bytes, [
            #standard big endian
            ak('\x00', [0], 1),
            ak('\x01', [1], 1),
            ak('\x00\x01', [1], 2),
            ak('\x00\x01', [0, 1], 2),
            ak('\x00\x00\x01', [1], 3),
            ak('\x00\x00\x00\x00', [0], 4),
            ak('\x00\x00\x00\x01', [1], 4),
            ak('\x00\x00\x00\xff', [255], 4),
            ak('\x00\x00\x01\xff', [1, 255], 4),
            ak('\x04\x03\x02\x01', [4, 3, 2, 1], 4),

            #standard little endian
            ak('\x00', [0], 1, order="little"),
            ak('\x01', [1], 1, order="little"),
            ak('\x01\x00', [1], 2, order="little"),
            ak('\x01\x00', [0, 1], 2, order="little"),
            ak('\x01\x00\x00', [1], 3, order="little"),
            ak('\x00\x00\x00\x00', [0], 4, order="little"),
            ak('\x01\x00\x00\x00', [1], 4, order="little"),
            ak('\xff\x00\x00\x00', [255], 4, order="little"),
            ak('\xff\x01\x00\x00', [1, 255], 4, order="little"),
            ak('\x01\x02\x03\x04', [4, 3, 2, 1], 4, order="little"),

            ])

        #check bytes size check
        self.assertRaises(ValueError, num.list_to_bytes, [])
        self.assertRaises(ValueError, num.list_to_bytes, [0, 0], bytes=1)

        #check bytes bound check
        self.assertRaises(ValueError, num.list_to_bytes, [256], bytes=1)

        #quick check native mode works right
        if native == "little":
            self.assertEqual(num.list_to_bytes([1], 3, order="native"), '\x01\x00\x00')
        else:
            self.assertEqual(num.list_to_bytes([1], 3, order="native"), '\x00\x00\x01')

    def test_bytes_to_list(self):
        self.check_function_results(num.bytes_to_list, [

            #standard big endian
            ak([1], '\x01'),
            ak([0, 1], '\x00\x01'),
            ak([0, 0, 1], '\x00\x00\x01'),
            ak([0, 0, 0, 0],'\x00\x00\x00\x00'),
            ak([0, 0, 0, 1],'\x00\x00\x00\x01'),
            ak([0, 0, 0, 255],'\x00\x00\x00\xff'),
            ak([0, 0, 1, 0],'\x00\x00\x01\x00'),
            ak([4, 3, 2, 1],'\x04\x03\x02\x01'),

            #standard little endian
            ak([1], '\x01', order="little"),
            ak([0, 1], '\x01\x00', order="little"),
            ak([0, 0, 1], '\x01\x00\x00', order="little"),
            ak([0, 0, 0, 0], '\x00\x00\x00\x00', order="little"),
            ak([0, 0, 0, 1], '\x01\x00\x00\x00', order="little"),
            ak([0, 0, 0, 255], '\xff\x00\x00\x00', order="little"),
            ak([0, 0, 1, 0], '\x00\x01\x00\x00', order="little"),
            ak([4, 3, 2, 1],'\x01\x02\x03\x04', order="little"),

            ])

        #quick check native mode works right
        if native == "little":
            self.assertEqual(num.bytes_to_list('\x01\x00\x00', order="native"), [0, 0, 1])
        else:
            self.assertEqual(num.bytes_to_list('\x00\x00\x01', order="native"), [0, 0, 1])

    def test_int_to_bytes(self):
        self.check_function_results(num.int_to_bytes, [
            #standard big endian
            ak('\x00', 0, 1),
            ak('\x01', 1, 1),
            ak('\x00\x01', 1, 2),
            ak('\x00\x00\x01', 1, 3),
            ak('\x00\x00\x00\x00', 0, 4),
            ak('\x00\x00\x00\x01', 1, 4),
            ak('\x00\x00\x00\xff', 255, 4),
            ak('\x00\x00\x01\x00', 256, 4),
            ak('\x04\x03\x02\x01', 0x04030201, 4),

            #standard little endian
            ak('\x00', 0, 1, order="little"),
            ak('\x01', 1, 1, order="little"),
            ak('\x01\x00', 1, 2, order="little"),
            ak('\x01\x00\x00', 1, 3, order="little"),
            ak('\x00\x00\x00\x00', 0, 4, order="little"),
            ak('\x01\x00\x00\x00', 1, 4, order="little"),
            ak('\xff\x00\x00\x00', 255, 4, order="little"),
            ak('\x00\x01\x00\x00', 256, 4, order="little"),
            ak('\x01\x02\x03\x04', 0x04030201, 4, order="little"),

            ])

        #check bytes bound check
        self.assertRaises(ValueError, num.int_to_bytes, 256, bytes=1)

        #check upper bound check
        self.assertRaises(ValueError, num.int_to_bytes, 129, upper=128)

        #check bytes/upper check
        self.assertRaises(ValueError, num.int_to_bytes, 1, bytes=1, upper=512)

        #quick check native mode works right
        if native == "little":
            self.assertEqual(num.int_to_bytes(1, 3, order="native"), '\x01\x00\x00')
        else:
            self.assertEqual(num.int_to_bytes(1, 3, order="native"), '\x00\x00\x01')

    def test_bytes_to_int(self):
        self.check_function_results(num.bytes_to_int, [
            #standard big endian
            ak(1, '\x01'),
            ak(1, '\x00\x01'),
            ak(1, '\x00\x00\x01'),
            ak(0,'\x00\x00\x00\x00'),
            ak(1,'\x00\x00\x00\x01'),
            ak(255,'\x00\x00\x00\xff'),
            ak(256,'\x00\x00\x01\x00'),
            ak(0x04030201,'\x04\x03\x02\x01'),

            #standard little endian
            ak(1, '\x01', order="little"),
            ak(1, '\x01\x00', order="little"),
            ak(1, '\x01\x00\x00', order="little"),
            ak(0, '\x00\x00\x00\x00', order="little"),
            ak(1, '\x01\x00\x00\x00', order="little"),
            ak(255, '\xff\x00\x00\x00', order="little"),
            ak(256, '\x00\x01\x00\x00', order="little"),
            ak(0x04030201,'\x01\x02\x03\x04', order="little"),

            ])

        #quick check native mode works right
        if native == "little":
            self.assertEqual(num.bytes_to_int('\x01\x00\x00', order="native"), 1)
        else:
            self.assertEqual(num.int_to_bytes('\x00\x00\x01', order="native"), 1)

    def test_xor_bytes(self):
        self.check_function_results(num.xor_bytes, [
            #result, left, right
            ak('\x00\x00\x00\x00', '\x00\x00\x00\x00', '\x00\x00\x00\x00'),
            ak('\x00\x00\xff\x00', '\xff\x00\xff\x00', '\xff\x00\x00\x00'),
            ak('\x00\x00\x00\x00', '\xff\x00\xff\x00', '\xff\x00\xff\x00'),
            ak('\x00\x44\x03\x02', '\x08\x04\x02\x03', '\x08\x40\x01\x01')
            ])
        self.check_bs_func(num.xor_bytes, lambda a, b: a^b)

    def test_align_bytes(self):
        #since xor_bytes/and/etc all use the same alignment func,
        #we're just quickly testing xor_bytes

        self.assertRaises(ValueError, num.xor_bytes, '\x00', '\x00\x21')
        self.assertRaises(ValueError, num.xor_bytes, '\x00', '\x00\x21', order=None)

        self.assertEqual(num.xor_bytes('\x01', '\x00\x21', order="big"), '\x00\x20')
            #^ same as '\x00\x21' \x00\x01'
        self.assertEqual(num.xor_bytes('\x01', '\x00\x21', order="little"), '\x01\x21')
            #^ same as '\x00\x21' \x01\x00'

    def test_and_bytes(self):
        self.check_function_results(num.and_bytes, [
            #result, left, right
            ak('\x00\x00\x00\x00', '\x00\x00\x00\x00', '\x00\x00\x00\x00'),
            ak('\xff\x00\x00\x00', '\xff\x00\xff\x00', '\xff\x00\x00\x00'),
            ak('\xff\x00\xff\x00', '\xff\x00\xff\x00', '\xff\x00\xff\x00'),
            ak('\x08\x00\x00\x01', '\x08\x04\x02\x03', '\x08\x40\x01\x01')
            ])
        self.check_bs_func(num.and_bytes, lambda a, b: a&b)

    def test_or_bytes(self):
        self.check_function_results(num.or_bytes, [
            #result, left, right
            ak('\x00\x00\x00\x00', '\x00\x00\x00\x00', '\x00\x00\x00\x00'),
            ak('\xff\x00\xff\x00', '\xff\x00\xff\x00', '\xff\x00\x00\x00'),
            ak('\xff\x00\xff\x00', '\xff\x00\xff\x00', '\xff\x00\xff\x00'),
            ak('\x08\x44\x03\x03', '\x08\x04\x02\x03', '\x08\x40\x01\x01')
            ])
        self.check_bs_func(num.or_bytes, lambda a, b: a|b)

    def test_binop_bytes(self):
        #note: this also checks some python invariants, just to be safe,
        #as well as some internal bits of bs_op.
        #under the guise of that, we test using bs_op to perform NAND
        assert -1 % 256 == 255
        assert 255 % 256 == 255
        def nand(a, b):
            assert a % 256 == a
            assert b % 256 == b
            c = 256 + ~ (a & b)
            assert c % 256 == c
            return c
        self.check_function_results(num.binop_bytes, [
            #result, left, right
            ak('\xff\xff\xff\xff', '\x00\x00\x00\x00', '\x00\x00\x00\x00', nand),
            ak('\x00\xff\xff\xff', '\xff\x00\xff\x00', '\xff\x00\x00\x00', nand),
            ak('\x00\xff\x00\xff', '\xff\x00\xff\x00', '\xff\x00\xff\x00', nand),
            ak('\xf7\xff\xff\xfe', '\x08\x04\x02\x03', '\x08\x40\x01\x01', nand)
            ])

    def test_invert_bytes(self):
        self.check_function_results(num.invert_bytes, [
            ak('\x00\xff', '\xff\x00'),
            ak('\x84\x21\x00', '\x7b\xde\xff'),
            ])

    def check_bs_func(self, func, op):
        "check bool operation over random bytes"
        for r in xrange(1000):
            al = random.randrange(1, 9)
            bl = random.randrange(1, 9)
            a = random.getrandbytes(al)
            b = random.getrandbytes(bl)

            #do big-endian
            av = num.bytes_to_int(a)
            bv = num.bytes_to_int(b)
            cv = op(av, bv)
            c = num.int_to_bytes(cv, max(al, bl))
            self.assertEqual(func(a, b, order="big"), c)

            #do little-endian
            av = num.bytes_to_int(a, order="little")
            bv = num.bytes_to_int(b, order="little")
            cv = op(av, bv)
            c = num.int_to_bytes(cv, max(al, bl), order="little")
            self.assertEqual(func(a, b, order="little"), c)

#=========================================================
#roman numeral funcs
#=========================================================
class RomanTest(TestCase):
    #   I   V   X   L   C   D   M
    #   1   5   10  50  100 500 1000

    roman_pairs = [
        #pairs tests forward and backward
('i', 1),   ('ii', 2),  ('iii', 3), ('iv', 4),
('v', 5),   ('vi', 6),  ('vii', 7), ('viii', 8),
('ix', 9),  ('x', 10),  ('xi', 11), ('xii', 12),
('xiii', 13),   ('xiv', 14),    ('xv', 15),
('xlv', 45),    ('xlvi', 46),   ('xlvii', 47),  ('xlviii', 48),
('xlix', 49),   ('l', 50), ('li', 51),
('xcix', 99), ('c', 100), ('ci', 101),
('cxcix', 199),   ('cc', 200),    ('cci', 201),
('cccxcix', 399), ('cd', 400),    ('cdi', 401),
('cmxcix', 999),   ('m', 1000),    ('mi', 1001),
('mcmxcviii', 1998),    ('mcmxcix', 1999),  ('mm', 2000),   ('mmi', 2001),
('mmmcmxcix', 3999),
        ]

    ns_roman_pairs = [
        #non-standard roman -- not allowed in strict mode

        #duplicate elements
        ('xxxxxx', 60),
        ('mmmmm', 5000),

        #duplicate stanzas
        ('iviv', 8),
        ('ivivx', 2),

        #over-large substraction stanzas
        ('iiiiv', 1),
        ('vix', 4),
        ]

    invalid_roman = [
        #grammatically incorrect (encodes a negative w/in a subtraction stanza)
        "vvx", "iiiiiv", "iviviix",
        #wrong literals
        "", "axcv",
        ]

    def test_int_to_roman(self):
        for roman, arabic in self.roman_pairs:
            self.assertEqual(num.int_to_roman(arabic), roman.upper())
        self.assertRaises(ValueError, num.int_to_roman, -1)
        self.assertRaises(ValueError, num.int_to_roman, 0)
        self.assertRaises(ValueError, num.int_to_roman, 4001)

        #test dialects
        self.assertEqual(num.int_to_roman(99), "xcix".upper())
        self.assertEqual(num.int_to_roman(99, dialect="standard"), "xcix".upper())
        self.assertEqual(num.int_to_roman(99, dialect="additive"), "lxxxxviiii".upper())

        #test some invariants...
        #2. the powers of ten should never occur >3 times
        for i in xrange(1, 3999):
            r = num.int_to_roman(i)
            #the non-powers of ten should never occur twice in a row
            for c in "VLD":
                self.assert_((c*2) not in r)
            for c in "IXCM":
                self.assert_((c*4) not in r)

    def test_roman_to_int(self):
        #test std pairs
        for roman, arabic in self.roman_pairs:
            self.assertEqual(num.roman_to_int(roman), arabic)

        #run all numbers through and back
        for i in xrange(1, 3999):
            self.assertEqual(num.roman_to_int(num.int_to_roman(i)), i)

        #check for some non-standard but correct ones
        for roman, arabic in self.ns_roman_pairs:
            self.assertEqual(num.roman_to_int(roman), arabic)
            self.assertRaises(ValueError, num.roman_to_int, roman, strict=True)

        #check invalid romans
        for roman in self.invalid_roman:
            self.assertRaises(ValueError, num.roman_to_int, roman)

#=========================================================
#base conversions
#=========================================================

# int_to_base
# int_from_base -- int
# float_to_base
# float_from_base
    # test float_to_base(1<<BPF,2) - was throwing error

#=========================================================
#misc
#=========================================================

class MiscTest(TestCase):

    def test_sdivmod(self):
        sdivmod = num.sdivmod

        def ts(x,y,cd,cr):
            rd,rr = sdivmod(x,y)
            if isinstance(x, Decimal):
                self.assertIsInstance(rr, Decimal)
            elif isinstance(x, float):
                self.assertIsInstance(rr, float)
            self.assertEquals(rd, cd)
            self.assertEquals(rr, cr)

        ts(12,5, 2,2)
        ts(-12,5, -2,-2)

        ts(12.5,5, 2, 2.5)
        ts(-12.5,5, -2, -2.5)

        ts(Decimal("12.5"), 5, 2, Decimal("2.5"))
        ts(Decimal("-12.5"), 5, -2, Decimal("-2.5"))

    def test_splitfrac(self):
        def ts(v, ci, cf):
            ri, rf = num.splitfrac(v)
            if isinstance(v, long):
                self.assertIsInstance(ri, long)
                self.assertIsInstance(rf, int) #could make this a long for symetry, but it's not worth it
            elif isinstance(v, int):
                self.assertIsInstance(ri, int)
                self.assertIsInstance(rf, int)
            elif isinstance(v, float):
                self.assertIsInstance(ri, int)
                self.assertIsInstance(rf, float)
            elif isinstance(v, Decimal):
                self.assertIsInstance(ri, int)
                self.assertIsInstance(rf, Decimal)
            else:
                raise TypeError
            self.assertEquals(ri, ci)
            self.assertEquals(rf, cf)

        #float w/ frac portion
        ts(-10.75, -10, -.75)
        ts(-1.25, -1, -.25)
        ts(0.25, 0, .25)
        ts(1.25, 1, .25)
        ts(10.25, 10, .25)

        #float w/o frac portion
        ts(-12.0, -12, 0)
        ts(-1.0, -1, 0)
        ts(0.0, 0, 0)
        ts(1.0, 1, 0)
        ts(12.0, 12, 0)

        #decimal w/ frac portion
        ts(Decimal("-10.1"), -10, Decimal("-.1"))
        ts(Decimal("-1.1"), -1, Decimal("-.1"))
        ts(Decimal("-.1"), 0, Decimal("-.1"))
        ts(Decimal(".1"), 0, Decimal(".1"))
        ts(Decimal("1.1"), 1, Decimal(".1"))
        ts(Decimal("12.1"), 12, Decimal(".1"))

        #decimal w/o frac portion
        ts(Decimal("-10.0"), -10, Decimal("0"))
        ts(Decimal("-1.0"), -1, Decimal("0"))
        ts(Decimal("0.0"), 0, Decimal("0"))
        ts(Decimal("1.0"), 1, Decimal("0"))
        ts(Decimal("12.0"), 12, Decimal("0"))

        #ints
        ts(-10, -10, 0)
        ts(0,0,0)
        ts(1, 1, 0)
        ts(10, 10, 0)

        #longs
        ts(1L, 1L, 0)

        #TODO: Decimal support

    def test_int_to_base(self):
        self.check_function_results(num.int_to_base, [
            #check base 2
            ak('0', 0, 2),
            ak('11', 3, 2),
            ak('1000', 8, 2),

            #check 10 in various bases
            ak('1010', 10, 2),
            ak('101', 10, 3),
            ak('10', 10, 10),

            #check 16 in various bases
            ak('16', 16, 10),
            ak('f', 15, 16),
            ak('10', 16, 16),
            ak('23', 35, 16),

            #check 35 in various bases
            ak('35', 35, 10),
            ak('z', 35, 36),
            ak('10', 36, 36),
            ak('zz', 1295, 36),

            #check negatives
            ak('-110', -(4+2), 2),
            ak('-1f', -0x1F, 16),

            #check pad kwd
            ak('1010', 8+2, 2, pad=0),
            ak('1010', 8+2, 2, pad=4),
            ak('01010', 8+2, 2, pad=5),
            ak('00001101', 8+4+1, 2, pad=8),
            ak('00101101', 32+8+4+1, 2, pad=8),

            #check pad + negative
            ak('-00001101', -(8+4+1), 2, pad=8),
            ])
        self.assertRaises(ValueError, num.int_to_base, 0, -1)
        self.assertRaises(ValueError, num.int_to_base, 0, 0)
        self.assertRaises(ValueError, num.int_to_base, 0, 1)
        self.assertRaises(ValueError, num.int_to_base, 0, 37)
        self.assertRaises(ValueError, num.int_to_base, 0, 1000)
        for r in xrange(1000):
            b = random.randrange(2, 37)
            n = random.randrange(-2**32, 2**32+1)
            v = num.int_to_base(n, b)
            self.assertEqual(int(v, b), n)

    def test_limit(self):
        self.check_function_results(num.limit, [
            # result, value, lower, upper
            ak(5, 5, 0, 10),
            ak(0, -5, 0, 10),
            ak(10, 15, 0, 10),

            ak(0, -1.5, 0, 1),
            ak(.5, .5, 0, 1),
            ak(1, 1.5, 0, 1),

            ak(5, -10, 5, 5),
            ])
        #check it won't let lower > upper
        self.assertRaises(ValueError, num.limit, 0, 10, 5)

    def test_avgsd(self):
        self.assertEqual(num.avgsd([0, 1, 1, 2]), (1.0, 0.70710678118654757))

    def test_digits(self):
        self.check_function_results(num.digits, [
            # result, value, [digits]
            ak(2, 99),

            ak(2, 99, 10),
            ak(3, 100, 10),
            ak(3, 7, 2),
            ak(4, 8, 2),
            ak(2, 255, 16),

            ak(2, -99, 10),
            ak(1, 0, 10),

            ])

##    seqsum_cases = [
##        (
##            ak([179,50,74,51], [0,126,41,4], [93,99,109]),
##                [272, 275, 224, 55],
##        ),
##        (
##            ak(1, [179,50,74,51], 1, [0,126,41,4], 1, [93,99,109]),
##                [272, 275, 224, 55],
##        ),
##        (
##            ak((1, [179,50,74,51]), (1, [0,126,41,4]), (1, [93,99,109])),
##                [272, 275, 224, 55],
##        ),
##    ]
##    def test_seqsum(self):
##        for i,o in self.seqsum_cases:
##            r = seqsum(*i.args, **i.kwds)
##            self.assertEqual(r, o, "case %r: got %r, expected %r" % (i, r, o))
#=========================================================
#EOF
#=========================================================
