"""tests for passlib.util"""
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
from passlib import util
from passlib.tests.utils import TestCase
#=========================================================
#byte funcs
#=========================================================
class BytesTest(TestCase):

    def test_list_to_bytes(self):
        self.check_function_results(util.list_to_bytes, [
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
        self.check_function_results(util.bytes_to_list, [

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
#EOF
#=========================================================
