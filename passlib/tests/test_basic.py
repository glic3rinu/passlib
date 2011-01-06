"""tests for bps.text -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from array import array
import os.path
#site
#pkg
from bps.basic import *
from bps.meta import Params as ak
#module
from bps.tests.utils import TestCase
#=========================================================
#
#=========================================================
from bps.unstable import smart_list_iter
class SmartListIterTest(TestCase):
    def test_basic(self):
        source=[5,6,100,2,3,40,8]
        target=list(source)
        out = []
        itr = smart_list_iter(target)
        for elem in itr:
            out.append(elem)
        self.assertEquals(out, source)
        self.assertEquals(target, source)

    def test_enum(self):
        source=[5,6,100,2,3,40,8]
        target=list(source)
        out = []
        itr = smart_list_iter(target, enum=True)
        for elem in itr:
            out.append(elem)
        self.assertEquals(out, list(enumerate(source)))
        self.assertEquals(target, source)

    def test_delete(self):
        source=[5,6,100,2,3,40,8]
        target=list(source)
        out = []
        itr = smart_list_iter(target)
        for elem in itr:
            out.append(elem)
            if elem > 30:
                itr.delete()
        self.assertEquals(out, source)
        self.assertEquals(target, [5, 6, 2, 3, 8])

    def test_double_delete(self):
        source=[5,6,100,2,3,40,8]
        target=list(source)
        out = []
        itr = smart_list_iter(target)
        for elem in itr:
            out.append(elem)
            if elem > 30:
                itr.delete()
                itr.delete()
        self.assertEquals(out, [5, 6, 100, 3, 40])
        self.assertEquals(target, [5, 6, 3])

    def test_insert(self):
        source=[5,6,100,2,3,40,8]
        target=list(source)
        out = []
        itr = smart_list_iter(target)
        for elem in itr:
            out.append(elem)
            if elem == 6:
                itr.delete()
                itr.insert(0, 666)
            elif elem == 100:
                itr.delete()
                itr.insert(0, 111, relative=True)
            elif elem == 2:
                itr.insert(2, 222)
                itr.insert(2, 2221, relative=True)
            elif elem == 3:
                itr.insert(1, 333, relative=True)
        self.assertEquals(out, [5, 6, 100, 111, 2, 3, 333, 2221, 40, 8])
        self.assertEquals(target, [666, 5, 222, 111, 2, 3, 333, 2221, 40, 8])

    def test_eol_delete(self):
        source=[5,6,100,2,3,40,8]
        target=list(source)
        out = []
        itr = smart_list_iter(target)
        for elem in itr:
            out.append(elem)
            if elem == 8:
                itr.delete()
                self.assertRaises(IndexError, itr.delete)
        self.assertEquals(out, source)
        self.assertEquals(target, [5, 6, 100, 2, 3, 40])

    #TODO: test various other insert/pop code
    #TODO: test next_pos, __length__

from bps.unstable import filter_in_place

class FilterInPlaceTest(TestCase):

    def test_list(self):
        def ff(elem):
            return elem in (3,9,7)

        #test empty
        a = []
        filter_in_place(ff, a)
        self.assertEquals(a,[])

        #test all removed
        a = [1,5,13,11]
        filter_in_place(ff, a)
        self.assertEquals(a,[])

        #test none removed
        a = [3,7,9]
        filter_in_place(ff, a)
        self.assertEquals(a,[3,7,9])

        #test some removed
        a = [1,3,5,7,9,11]
        filter_in_place(ff, a)
        self.assertEquals(a,[3,7,9])

        #test some removed + invert
        a = [1,3,5,7,9,11]
        filter_in_place(ff, a, invert=True)
        self.assertEquals(a,[1,5,11])

    def test_array(self):
        def ff(elem):
            return elem in ("3","9","7")

        #test empty
        a = array('c')
        filter_in_place(ff, a)
        self.assertEquals(a.tostring(),'')

        #test all removed
        a = array('c','158')
        filter_in_place(ff, a)
        self.assertEquals(a.tostring(),'')

        #test none removed
        a = array('c','379')
        filter_in_place(ff, a)
        self.assertEquals(a.tostring(),'379')

        #test some removed
        a = array('c','135987')
        filter_in_place(ff, a)
        self.assertEquals(a.tostring(),'397')

        #test some removed + invert
        a = array('c','135987')
        filter_in_place(ff, a, invert=True)
        self.assertEquals(a.tostring(),'158')

    def test_set(self):
        def ff(elem):
            return elem in (3,9,7)

        #test empty
        a = set()
        filter_in_place(ff, a)
        self.assertEquals(a,set())

        #test all removed
        a = set([1,5,13,11])
        filter_in_place(ff, a)
        self.assertEquals(a,set())

        #test none removed
        a = set([3,7,9])
        filter_in_place(ff, a)
        self.assertEquals(a,set([3,7,9]))

        #test some removed
        a = set([1,3,5,7,9,11])
        filter_in_place(ff, a)
        self.assertEquals(a,set([3,7,9]))

        #test some removed + invert
        a = set([1,3,5,7,9,11])
        filter_in_place(ff, a, invert=True)
        self.assertEquals(a,set([1,5,11]))

    def test_dict(self):
        def ff(elem):
            return elem in (3,9,7)

        #test empty
        a = {}
        filter_in_place(ff, a)
        self.assertEquals(a,{})

        #test all removed
        a = {1:2, 5:6, 13:8, 11:12}
        filter_in_place(ff, a)
        self.assertEquals(a,{})

        #test none removed
        a = {3:2, 7:6, 9:8}
        filter_in_place(ff, a)
        self.assertEquals(a,{3:2, 7:6, 9:8})

        #test some removed
        a = {1:2, 5:6, 13:8, 11:12, 3:2, 7:6, 9:8}
        filter_in_place(ff, a)
        self.assertEquals(a,{3:2, 7:6, 9:8})

        #test some removed + invert
        a = {1:2, 5:6, 13:8, 11:12, 3:2, 7:6, 9:8}
        filter_in_place(ff, a, invert=True)
        self.assertEquals(a,{1:2, 5:6, 13:8, 11:12})

    def test_bad_types(self):
        def ff(elem):
            return elem in (3,9,7)
        a = [1,3,6]
        self.assertRaises(TypeError, filter_in_place, ff, iter(a))
        self.assertRaises(TypeError, filter_in_place, ff, (1,3,5,7))
        self.assertRaises(TypeError, filter_in_place, ff, "1357")
        self.assertRaises(TypeError, filter_in_place, ff, frozenset((1,3,5,7)))

class MiscTest(TestCase):
    intersect_cases = [
        ([],[],False),
        ([],[1],False),
        ([1],[2],False),
        ([1,3,5],[2,4,6],False),
        ([1,3,7],[2,3,1],True),
        ([1,2,3],[3,2,1],True),
        ([1,3,3],[2,3,4],True),
    ]
    intersect_classes = [ list, tuple, set, frozenset ]

    def test_intersects(self):
        "test intersects() helper"
        from bps.basic import intersects
        for a,b,real in self.intersect_cases:
            for ac in self.intersect_classes:
                ao = ac(a)
                for bc in self.intersect_classes:
                    bo = bc(b)
                    result = intersects(ao,bo)
                    self.assertEquals(result, real, "intersects(%r, %r):" % (ao,bo))

    def test_enum_slice(self):
        from bps.basic import enum_slice
        def func(*a, **k):
            return list(enum_slice(*a, **k))
        self.check_function_results(func, [
            #without arguments
            ak([],''),
            ak([(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')],
                'abcdef'),

            #with stop
            ak([],
                'abcdef', 0),
            ak([(0, 'a')],
                'abcdef', 1),
            ak([(0, 'a'), (1, 'b')],
                'abcdef', 2),
            ak([(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd')],
                'abcdef', -2),

            #with start+no stop
            ak([(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')],
                'abcdef', None, None),
            ak([(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')],
                'abcdef', 0, None),
            ak([(1, 'b'), (2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')],
                'abcdef', 1, None),
            ak([(2, 'c'), (3, 'd'), (4, 'e'), (5, 'f')],
                'abcdef', 2, None),
            ak([(4, 'e'), (5, 'f')],
                'abcdef', -2, None),

            #with start+stop
            ak([(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd'), (4, 'e')],
                'abcdef', 0, -1),
            ak([(1, 'b'), (2, 'c'), (3, 'd')],
                'abcdef', 1, 4),
            ak([(2, 'c'), (3, 'd'), (4, 'e')],
                'abcdef', 2, 5),
            ak([(2, 'c'), (3, 'd')],
                'abcdef', -4, 4),

            #with postive step
            ak([(1, 'b'), (3, 'd'), (5, 'f')],
                'abcdef', 1, None, 2),

            #with negative step
            ak([],
                'abcdef', 2, -1, -1),
            ak([],
                'abcdef', 2, 3, -1),
            ak([(2, 'c'), (1, 'b'), (0, 'a')],
                'abcdef', 2, None, -1),
            ak([(4, 'e'), (3, 'd'), (2, 'c'), (1, 'b'), (0, 'a')],
                'abcdef', 4, None, -1),
            ak([(4, 'e'), (3, 'd'), (2, 'c'), (1, 'b')],
                'abcdef', 4, 0, -1),
            ak([(4, 'e'), (2, 'c'), (0, 'a')],
                'abcdef', 4, None, -2),
            ak([(4, 'e'), (2, 'c')],
                'abcdef', 4, 0, -2),
            ])

#=========================================================
#EOF
#=========================================================
