"""bps.types unittest script -- (c) 2004-2009 Assurance Technologies 2003-2006"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os
import warnings
import gc
#site
#pkg
from bps.tests.utils import TestCase
#module
#=========================================================
#baseclass
#=========================================================
from bps.types import BaseClass
class BaseClassTest(TestCase):

    def test_multisuper(self):
        "test MultipleSuperProperty handler for BaseClass"
        buffer = []
        class Core(BaseClass):
            def bob(self):
                buffer.append("core")

        class Test(Core):
            "test 1"
            def bob(self):
                buffer.append("test1")
                self.__super.bob()
        Test1 = Test

        class Test(Test):
            "test 2"
            def bob(self):
                buffer.append("test2")
                self.__super.bob()
        Test2 = Test

        #check core
        del buffer[:]
        test0 = Core()
        test0.bob()
        self.assertEqual(buffer, ['core'])

        #check single-class call
        del buffer[:]
        test1 = Test1()
        test1.bob()
        self.assertEqual(buffer, ['test1', 'core'])

        #check multi-class call
        #if MultipleSuperProperty fails, we'll have dups of test1 or test2 in buffer.
        del buffer[:]
        test2 = Test2()
        test2.bob()
        self.assertEqual(buffer, ['test2', 'test1', 'core'])

#=========================================================
#closeableclass
#=========================================================
from bps.types import CloseableClass
class CloseableClassTest(TestCase):

    def test_closed_property(self):
        #check init state
        c = CloseableClass()
        self.assert_(not c.closed)

        #make sure it changes
        c.close()
        self.assert_(c.closed)

        #make sure double call is NOOP
        c.close()
        self.assert_(c.closed)

    def test_close_on_del(self):
        #NOTE: since this relies on GC flushing, and implicitly calling del
        #(which CPython doesn't guarantee will happen), this test may fail.
        #should write better way to test things.
        d = [False]
        def setter():
            d[0] = True
        c = CloseableClass()
        c.on_close(setter)
        del c
        gc.collect()
        self.assert_(d[0])

    def test_cleanup(self):
        class Test(CloseableClass):
            x = 1

            def _cleanup(self):
                self.x += 1

        #check init state
        c = Test()
        self.assertEquals(c.x, 1)

        #make sure it's called right
        c.close()
        self.assertEquals(c.x, 2)

        #make sure it's not double-called
        c.close()
        self.assertEquals(c.x, 2)

    #NOTE: 'close' method not explicitly tested,
    #as at least one of the other tests should fail
    #if something was wrong with it

    def test_close(self):

        #test init state
        c = CloseableClass()
        self.assert_(not c.closed)

        #test 'close' returns true on success
        self.assert_(c.close())
        self.assert_(c.closed)

        #test 'close' returns false if already closed
        self.assert_(not c.close())
        self.assert_(c.closed)

    def test_recursive_close(self):
        c = CloseableClass()
        c._in_closer = False

        def closer():
            self.assert_(not c._in_closer)
            c._in_closer = True
            try:
                #NOTE: policy is to simply ignore recursive calls, might revise in future
                self.assert_(not c.closed)
                r = c.close()
                self.assert_(not c.closed)
                self.assertIs(r, None)
            finally:
                c._in_closer = False
        c.on_close(closer)

        r = c.close()
        self.assert_(r)
        self.assert_(c.closed)

    #TODO: should decide on / test policy for what happens if on_close() / delete_on_close()
    # is called AFTER class has been closed!

    def test_on_close_func(self):
        c = CloseableClass()

        #prepare & register callback
        d = []
        def func():
            d.append(1)
        c.on_close(func)
        self.assertEquals(d,[])

        #make sure it's called right
        c.close()
        self.assertEquals(d,[1])

        #make sure it's not double-called
        c.close()
        self.assertEquals(d,[1])

    def test_on_close_multi_func(self):
        c = CloseableClass()

        #prepare & register two callbacks
        d = []
        c.on_close(d.append, 1)
        c.on_close(d.append, 2)
        self.assertEquals(d,[])

        #make sure they're calling in LIFO order
        c.close()
        self.assertEquals(d,[2,1])

        #make sure they're not double-called
        c.close()
        self.assertEquals(d,[2,1])

    #XXX: if there's cyclic ref in kwds, GC will have loop

    def test_on_close_func_kwds(self):
        c = CloseableClass()

        #prepare & register callback
        d = []
        def func(value=1):
            d.append(value)
        c.on_close(func, value=5)
        self.assertEquals(d,[])

        #make sure it's called right
        c.close()
        self.assertEquals(d,[5])

        #make sure it's not double-called
        c.close()
        self.assertEquals(d,[5])

    def test_delete_on_close(self):
        c = CloseableClass()

        #prepare & register attrs to purge
        c.x = 1
        c.y = 2
        c.z = 3
        c.delete_on_close('x','y')

        #check attrs kept
        self.assertEquals(c.x, 1)
        self.assertEquals(c.y, 2)
        self.assertEquals(c.z, 3)

        #check purge works
        c.close()
        self.assertIs(c.x, None)
        self.assertIs(c.y, None)
        self.assertEquals(c.z, 3)

        #check purge doesn't get called again (though I guess it could)
        c.x = 5
        c.y = 10
        c.close()
        self.assertEquals(c.x, 5)
        self.assertEquals(c.y, 10)
        self.assertEquals(c.z, 3)

    def test_callback_order(self):
        #delete_on_close & on_close calls should share same LIFO stack
        #_cleanup() should be called last

        class Test(CloseableClass):
            x = 1
            y = 2

            def __init__(self):
                self.buf = []

            def _cleanup(self):
                self.buf.append("cleanup")

        #prepare test to check ordering of events
        c = Test()
        def read_x():
            c.buf.append(c.x)
        def read_y():
            c.buf.append(c.y)

        #_cleanup - fourth
        c.on_close(read_x) #third
        c.delete_on_close('x','y') #second
        c.on_close(read_y) #first

        #check init state
        self.assertEquals(c.buf, [])
        self.assertEquals(c.x, 1)
        self.assertEquals(c.y, 2)

        #call
        c.close()
        self.assertEquals(c.buf, [2,None,"cleanup"])
        self.assertIs(c.x, None)
        self.assertIs(c.y, None)

    #=========================================================
    #EOC
    #=========================================================
#=========================================================
#EOF
#=========================================================
