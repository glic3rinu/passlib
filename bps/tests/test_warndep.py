"""tests for bps.warnup -- (c) Assurance Technologies 2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from unittest import __file__ as ut_file
#site
#pkg
from bps import warndep, filepath
from bps.error.types import ParamError
#module
from bps.tests.utils import TestCase, catch_warnings, __file__ as util_file

def print_warnings(msgs):
    print "warning list: %r warnings" % len(msgs)
    for idx, msg in enumerate(msgs):
        print "\t%d: %s" % (idx,msg)
    print

#=========================================================
#dep func
#=========================================================
class DepFuncTest(TestCase):
    "test deprecated_function decorator"

    # use, name, msg, removal

    def test_plain(self):
        "test basic depfunc call"
        @warndep.deprecated_function()
        def myfunc(a,b=2):
            return a*b
        with catch_warnings(record=True) as msgs:
            #make sure func can be called in various ways
            self.assertEquals(myfunc(3), 6)
            self.assertEquals(myfunc(2.5,b=3), 7.5)
            #and fails if not called correctly
            self.assertRaises(TypeError, myfunc)
##        print_warnings(msgs)
        x = "bps.tests.test_warndep: function 'myfunc' is deprecated"
        self.assert_warning(msgs.pop(0), message=x, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x, category=DeprecationWarning, filename=util_file)
        self.assert_(not msgs)

    def test_removal(self):
        "test depfunc removal kwd"
        @warndep.deprecated_function(removal=True)
        def myfunc1():
            return 1
        @warndep.deprecated_function(removal="2009-10-1")
        def myfunc2():
            return 2
        with catch_warnings(record=True) as msgs:
            myfunc1()
            myfunc2()
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'myfunc1' is deprecated; it will be removed in the future"
        x2 = "bps.tests.test_warndep: function 'myfunc2' is deprecated; it will be removed after 2009-10-1"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x2, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_use(self):
        "test depfunc use kwd"
        @warndep.deprecated_function(use="otherfunc")
        def myfunc():
            return 1
        with catch_warnings(record=True) as msgs:
            myfunc()
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'myfunc' is deprecated, use 'otherfunc' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_use_old(self):
        "test depfunc use kwd"
        @warndep.deprecated_function(use="otherfunc")
        def myfunc():
            return 1
        with catch_warnings(record=True) as msgs:
            myfunc()
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'myfunc' is deprecated, use 'otherfunc' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_name(self):
        "test depfunc name kwd"
        @warndep.deprecated_function(name="otherfunc")
        def myfunc():
            return 1
        with catch_warnings(record=True) as msgs:
            myfunc()
        x1 = "bps.tests.test_warndep: function 'otherfunc' is deprecated"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_name_old(self):
        "test depfunc name kwd"
        @warndep.deprecated_function(name="otherfunc")
        def myfunc():
            return 1
        with catch_warnings(record=True) as msgs:
            myfunc()
        x1 = "bps.tests.test_warndep: function 'otherfunc' is deprecated"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_msg(self):
        "test depfunc msg kwd"
        @warndep.deprecated_function(msg="help me, %(name)s")
        def myfunc():
            return 1
        with catch_warnings(record=True) as msgs:
            myfunc()
        x1 = "bps.tests.test_warndep: help me, myfunc"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_msg2(self):
        "test depfunc msg kwd 2"
        @warndep.deprecated_function(msg="help me, %(mod)s.%(name)s")
        def myfunc():
            return 1
        with catch_warnings(record=True) as msgs:
            myfunc()
        x1 = "help me, bps.tests.test_warndep.myfunc"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

def rf_01(x=1,y=2):
    return (x,y)

#NOTE: this is wrong, "name" and "use" are flipped,
# used for unittest
rf_02 = warndep.relocated_function("rf_01", "rf_02")

class RelFuncTest(TestCase):
    "test relocated function proxy-maker"

    def test_basic_00(self):
        "basic operation w/ explicit module path"
        b = warndep.relocated_function("b", __name__ + ".rf_01")
        self.assertEquals(b.__name__, "b")
        with catch_warnings(record=True) as msgs:
            self.assertEqual(b(5,y=3), (5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'b' is deprecated, use 'bps.tests.test_warndep.rf_01' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_basic_01(self):
        "basic operation w/ explicit module path 2"
        b = warndep.relocated_function("b", __name__ + ":rf_01")
        self.assertEquals(b.__name__, "b")
        with catch_warnings(record=True) as msgs:
            self.assertEqual(b(5,y=3), (5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'b' is deprecated, use 'bps.tests.test_warndep.rf_01' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_basic_02(self):
        "basic operation w/in module"
        b = warndep.relocated_function("b", "rf_01")
        self.assertEquals(b.__name__, "b")
        with catch_warnings(record=True) as msgs:
            self.assertEqual(b(5,y=3), (5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'b' is deprecated, use 'bps.tests.test_warndep.rf_01' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_basic_03(self):
        "basic operation w/callable"
        b = warndep.relocated_function("b", rf_01)
        self.assertEquals(b.__name__, "b")
        with catch_warnings(record=True) as msgs:
            self.assertEqual(b(5,y=3), (5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'b' is deprecated, use 'bps.tests.test_warndep.rf_01' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_nonlazy(self):
        "basic operation w/in module"
        #FIXME: do something harser to test for sure, such as contained module.
        b = warndep.relocated_function("b", "rf_01", lazy=False)
        with catch_warnings(record=True) as msgs:
            self.assertEqual(b(5,y=3), (5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'b' is deprecated, use 'bps.tests.test_warndep.rf_01' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_removal(self):
        "test depfunc removal kwd"
        f1 = warndep.relocated_function("b1", "rf_01", removal=True)
        f2 = warndep.relocated_function("b2", "rf_01", removal="2009-10-1")
        self.assertEquals(f1.__name__, "b1")
        self.assertEquals(f2.__name__, "b2")
        with catch_warnings(record=True) as msgs:
            f1()
            f2()
        x1 = "bps.tests.test_warndep: function 'b1' is deprecated, use 'bps.tests.test_warndep.rf_01' instead; it will be removed in the future"
        x2 = "bps.tests.test_warndep: function 'b2' is deprecated, use 'bps.tests.test_warndep.rf_01' instead; it will be removed after 2009-10-1"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x2, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_mistake_00_reversed(self):
        with catch_warnings(record=True) as msgs:
            self.assertRaises(ParamError,rf_02)
            #^ "name and use parameters reversed"
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'rf_01' is deprecated, use 'bps.tests.test_warndep.rf_02' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=util_file)
        self.assert_(not msgs)

    def test_mistake_01_missing_module(self):
        b = warndep.relocated_function("b", __name__ + "_xxx.rf_01")
        with catch_warnings(record=True) as msgs:
            self.assertRaises(ImportError,b)
            #^ no such module test_warndepxxx
        x1 = "bps.tests.test_warndep: function 'b' is deprecated, use 'bps.tests.test_warndep_xxx.rf_01' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=util_file)
        self.assert_(not msgs)

    def test_mistake_02_missing_func(self):
        b = warndep.relocated_function("b", __name__ + ".rf_xxx")
        with catch_warnings(record=True) as msgs:
            self.assertRaises(AttributeError,b)
            #^ module has no such attr rf_xxx
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep: function 'b' is deprecated, use 'bps.tests.test_warndep.rf_xxx' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=util_file)
        self.assert_(not msgs)

    def test_mistake_03_missing_nonlazy(self):
        self.assertRaises(AttributeError, warndep.relocated_function, "b", __name__ + ".rf_xxx", lazy=False)
        self.assertRaises(ImportError, warndep.relocated_function, "b", __name__ + "_xxx.rf_01", lazy=False)

#=========================================================
#dep meth
#=========================================================
class DepMethTest(TestCase):
    "test deprecated_method decorator"

    def test_plain(self):
        "test basic depmeth call"
        class Test:
            @warndep.deprecated_method()
            def myfunc(self,a,b=2):
                return self,a,b
        with catch_warnings(record=True) as msgs:
            t = Test()
            #make sure func can be called in various ways
            self.assertEquals(t.myfunc(3), (t,3,2))
            self.assertEquals(t.myfunc(2.5,b=3), (t,2.5,3))
            #and fails if not called correctly
            self.assertRaises(TypeError, t.myfunc)
##        print_warnings(msgs)
        x = "bps.tests.test_warndep.Test: method 'myfunc' is deprecated"
        self.assert_warning(msgs.pop(0), message=x, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x, category=DeprecationWarning, filename=util_file)
        self.assert_(not msgs)

    def test_removal(self):
        "test depmeth removal kwd"
        class Test:
            @warndep.deprecated_method(removal=True)
            def myfunc1(self):
                return 1
            @warndep.deprecated_method(removal="2009-10-1")
            def myfunc2(self):
                return 2
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.myfunc1()
            t.myfunc2()
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'myfunc1' is deprecated; it will be removed in the future"
        x2 = "bps.tests.test_warndep.Test: method 'myfunc2' is deprecated; it will be removed after 2009-10-1"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x2, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_use(self):
        "test depmeth use kwd"
        class Test:
            @warndep.deprecated_method(use="otherfunc")
            def myfunc(self):
                return 1
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.myfunc()
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'myfunc' is deprecated, use 'otherfunc' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_use_old(self):
        "test depmeth use kwd"
        class Test:
            @warndep.deprecated_method(use="otherfunc")
            def myfunc(self):
                return 1
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.myfunc()
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'myfunc' is deprecated, use 'otherfunc' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_name(self):
        "test depmeth name kwd"
        class Test:
            @warndep.deprecated_method(name="otherfunc")
            def myfunc(self):
                return 1
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.myfunc()
        x1 = "bps.tests.test_warndep.Test: method 'otherfunc' is deprecated"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_name_old(self):
        "test depmeth name kwd"
        class Test:
            @warndep.deprecated_method(name="otherfunc")
            def myfunc(self):
                return 1
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.myfunc()
        x1 = "bps.tests.test_warndep.Test: method 'otherfunc' is deprecated"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_msg(self):
        "test depmeth msg kwd"
        class Test:
            @warndep.deprecated_method(msg="help me, %(name)s")
            def myfunc(self):
                return 1
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.myfunc()
        x1 = "bps.tests.test_warndep.Test: help me, myfunc"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_msg2(self):
        "test depmeth msg kwd"
        class Test:
            @warndep.deprecated_method(msg="help me, %(mod)s.%(cls)s:%(name)s")
            def myfunc(self):
                return 1
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.myfunc()
        x1 = "help me, bps.tests.test_warndep.Test:myfunc"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

class RelMethTest(TestCase):
    "test relocated method proxy-maker"

    def test_basic_00(self):
        "basic operation w/ method name"
        class Test:
            def a(self,x=1,y=2):
                return (self,x,y)
            b = warndep.relocated_method("b","a")
        self.assertEquals(Test.b.__name__, "b")
        with catch_warnings(record=True) as msgs:
            t = Test()
            self.assertEqual(t.b(5,y=3), (t,5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'b' is deprecated, use 'a' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_basic_01(self):
        "basic operation w/ method callable"
        class Test:
            def a(self,x=1,y=2):
                return (self,x,y)
            b = warndep.relocated_method("b", a)
        self.assertEquals(Test.b.__name__, "b")
        with catch_warnings(record=True) as msgs:
            t = Test()
            self.assertEqual(t.b(5,y=3), (t,5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'b' is deprecated, use 'a' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_name_detect(self):
        "basic operation w/ name not specified"
        class Test:
            def a(self,x=1,y=2):
                return (self,x,y)
            b = warndep.relocated_method(None, "a")
        self.assertEquals(Test.b.__name__, "<deprecated alias for 'a'>")
        with catch_warnings(record=True) as msgs:
            t = Test()
            self.assertEqual(t.b(5,y=3), (t,5,3))
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'b' is deprecated, use 'a' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_removal(self):
        "test depfunc removal kwd"
        class Test:
            def a(self,x=1,y=2):
                return (self,x,y)
            f1 = warndep.relocated_method("b1", "a", removal=True)
            f2 = warndep.relocated_method("b2", "a", removal="2009-10-1")
        self.assertEquals(Test.f1.__name__, "b1")
        self.assertEquals(Test.f2.__name__, "b2")
        with catch_warnings(record=True) as msgs:
            t = Test()
            t.f1()
            t.f2()
        x1 = "bps.tests.test_warndep.Test: method 'b1' is deprecated, use 'a' instead; it will be removed in the future"
        x2 = "bps.tests.test_warndep.Test: method 'b2' is deprecated, use 'a' instead; it will be removed after 2009-10-1"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=__file__)
        self.assert_warning(msgs.pop(0), message=x2, category=DeprecationWarning, filename=__file__)
        self.assert_(not msgs)

    def test_mistake_00_reversed(self):
        class Test:
            def a(self,x=1,y=2):
                return (self,x,y)
            b = warndep.relocated_method("a", "b")
        self.assertEquals(Test.b.__name__,"a")
        self.assertEquals(Test.a.__name__,"a")
        with catch_warnings(record=True) as msgs:
            t = Test()
            self.assertRaises(ParamError, t.b)
            #^ "name and use parameters reversed"
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'a' is deprecated, use 'b' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=util_file)
        self.assert_(not msgs)

    def test_mistake_01_missing_attr(self):
        class Test:
            b = warndep.relocated_method("b", "a")
        self.assertEquals(Test.b.__name__,"b")
        with catch_warnings(record=True) as msgs:
            t = Test()
            self.assertRaises(AttributeError,t.b)
            #^ module has no such attr rf_xxx
##        print_warnings(msgs)
        x1 = "bps.tests.test_warndep.Test: method 'b' is deprecated, use 'a' instead"
        self.assert_warning(msgs.pop(0), message=x1, category=DeprecationWarning, filename=util_file)
        self.assert_(not msgs)

    def test_mistake_02_no_use(self):
        self.assertRaises(ValueError, warndep.relocated_method,"a",None)

#=========================================================
#dep attr
#=========================================================
#TODO: deprecated_property -
# test basic functionality,
# test options,
# test that deprecated_method wrapped funcs are unwrapped via ._deprecated_func

#=========================================================
#eof
#=========================================================
