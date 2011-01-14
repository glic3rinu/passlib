"""tests for passlib.util"""
#=========================================================
#imports
#=========================================================
#core
import sys
import random
#site
#pkg
#module
from passlib import util
from passlib.tests.utils import TestCase, Params as ak
#=========================================================
#byte funcs
#=========================================================
class BytesTest(TestCase):

    def test_list_to_bytes(self):
        self.assertFunctionResults(util.list_to_bytes, [
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
        self.assertRaises(ValueError, util.list_to_bytes, [])
        self.assertRaises(ValueError, util.list_to_bytes, [0, 0], bytes=1)

        #check bytes bound check
        self.assertRaises(ValueError, util.list_to_bytes, [256], bytes=1)

        #quick check native mode works right
        if sys.byteorder == "little":
            self.assertEqual(util.list_to_bytes([1], 3, order="native"), '\x01\x00\x00')
        else:
            self.assertEqual(util.list_to_bytes([1], 3, order="native"), '\x00\x00\x01')

    def test_bytes_to_list(self):
        self.assertFunctionResults(util.bytes_to_list, [

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
        if sys.byteorder == "little":
            self.assertEqual(util.bytes_to_list('\x01\x00\x00', order="native"), [0, 0, 1])
        else:
            self.assertEqual(util.bytes_to_list('\x00\x00\x01', order="native"), [0, 0, 1])

#=========================================================
#hash64
#=========================================================
class Test_H64(TestCase):
    "test H64 codec functions"
    case_prefix = "H64 codec"

    def test_encode_1_offset(self):
        self.assertFunctionResults(util.H64.encode_1_offset,[
            ("z1", "\xff", 0),
            ("..", "\x00", 0),
        ])

    def test_encode_2_offsets(self):
        self.assertFunctionResults(util.H64.encode_2_offsets,[
            (".wD", "\x00\xff", 0, 1),
            ("z1.", "\xff\x00", 0, 1),
            ("z1.", "\x00\xff", 1, 0),
        ])

    def test_encode_3_offsets(self):
        self.assertFunctionResults(util.H64.encode_3_offsets,[
            #move through each byte, keep offsets
            ("..kz", "\x00\x00\xff", 0, 1, 2),
            (".wD.", "\x00\xff\x00", 0, 1, 2),
            ("z1..", "\xff\x00\x00", 0, 1, 2),

            #move through each offset, keep bytes
            (".wD.", "\x00\x00\xff", 0, 2, 1),
            ("z1..", "\x00\x00\xff", 2, 0, 1),
        ])

    ##def test_randstr(self):
    ##    #override default rng so we can get predictable values
    ##    rng = random.Random()
    ##    def wrapper(*a, **k):
    ##        rng.seed(1234)
    ##        k['rng'] = rng
    ##        return util.H64.randstr(*a, **k)
    ##    self.assertFunctionResults(wrapper,[
    ##        ("", 0),
    ##        ("x", 1),
    ##        ("xQ", 2),
    ##        ("xQ.uwZe3lD/mKbb7", 16),
    ##        ("xQ.uwZe3lD/mKbb795.Tx2WRa3ZFXdSK", 32),
    ##    ])


#=========================================================
#EOF
#=========================================================
