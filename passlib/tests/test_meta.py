"""bps.meta unittest script"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import sys
import time
import os.path
#package
from bps import meta
ak = Params = meta.Params
#local
from bps.tests.utils import TestCase
#=========================================================
#
#=========================================================
##
##    #interfaces
##    'isseq', 'isnum', 'isstr',
##
##    #introspection & monkeypatching
##    'is_overridden',
##    'find_attribute',
####    'get_module',
####    'get_module_exports',
##    'instrument_super',
##
##    #other decorators
##    'abstract_method', 'abstract_property', 'AbstractMethodError',
##    'decorate_per_instance',

class MonkeypatchTest(TestCase):

    def test_monkeypatch_class(self):
        "test monkeypatch against a class"
        #create test class
        target = [0]
        class Testum(object):
            def abc(self, x):
                target[0] = x
                return x

            xyz = abc

        t = Testum()

        #reset target
        target[0] = 1
        self.assertEqual(target[0], 1)

        #test base method
        self.assertEqual(t.abc(5), 5)
        self.assertEqual(target[0], 5)

        #reset target
        target[0] = 1
        self.assertEqual(target[0], 1)

        #patch the class
        @meta.monkeypatch(Testum)
        def abc(self, x):
            target[0] = 2*x
            return 3*x

        #check patch worked
        self.assertEqual(t.abc(10), 30)
        self.assertEqual(target[0], 20)

        #reset target
        target[0] = 1
        self.assertEqual(target[0], 1)

        #try patch with wrapping
        @meta.monkeypatch(Testum, wrap=True)
        def xyz(orig, self, x):
            return 30*orig(self, 10*x)

        #check patch worked
        self.assertEqual(t.xyz(10), 3000)
        self.assertEqual(target[0], 100)

    def test_monkeypatch_object(self):
        "test monkeypatch against an object"
        #create test object
        target = [0]
        class Testum(object):
            def abc(self, x):
                target[0] = x
                return x

            xyz = abc

            v = 1

        t = Testum()
        s = Testum()

        #reset target
        target[0] = 1
        self.assertEqual(target[0], 1)

        #test base method
        self.assertEqual(t.abc(5), 5)
        self.assertEqual(target[0], 5)

        #reset target
        target[0] = 1
        self.assertEqual(target[0], 1)

        #patch the class
        @meta.monkeypatch(t)
        def abc(x):
            target[0] = 2*x
            return 3*x

        #check patch worked
        self.assertEqual(t.abc(10), 30)
        self.assertEqual(target[0], 20)

        #reset target
        target[0] = 1
        self.assertEqual(target[0], 1)

        #try patch with wrapping
        @meta.monkeypatch(t, wrap=True)
        def xyz(orig, x):
            return 30*orig(10*x)

        #check patch worked
        self.assertEqual(t.xyz(10), 3000)
        self.assertEqual(target[0], 100)

        #-------------------------
        #check patching didn't affect class or other instances

        #reset target
        target[0] = 1
        self.assertEqual(target[0], 1)

        #test base method
        self.assertEqual(s.abc(5), 5)
        self.assertEqual(target[0], 5)

    def test_monkeypatch_attr(self):
        #check patching a attribute (non-decorator mode)
        class Testum(object):
            v = 1
        t = Testum()
        s = Testum()
        self.assertEqual(t.v, 1)
        meta.monkeypatch(t, 'v')(2)
        self.assertEqual(t.v, 2)
        self.assertEqual(s.v, 1)

    def test_monkeypatch_clobber(self):
        class Testum(object):
            def f(self):
                pass
        f = Testum.__dict__['f']

        def g():
            pass

        meta.monkeypatch(Testum, clobber=False)(g)
        self.assertIs(Testum.__dict__['g'], g)

        self.assertRaises(AttributeError, meta.monkeypatch(Testum, attr="f", clobber=False), g)
        self.assertIs(Testum.__dict__['f'], f)

class MonkeypatchMixinTest(TestCase):

    def test_separate_class(self):
        "test monkeypatch of external mixin"

        # A --+--> B
        #     |
        # M --/
        #
        # M should be shadowed by A and B

        class A(object):
            x = 'a' #shadowed by B
            y = 'a' #not shadowed by B

        class B(A):
            x = 'b'

        self.assertEqual(B.x, 'b')
        self.assertEqual(B.y, 'a')
        self.assertEqual(getattr(B,'m',None), None)

        class M(object):
            x = 'm' #shadowed by A,B
            y = 'm' #shadowed by A
            m = 'm'

        r = meta.monkeypatch_mixin(B)(M)
        self.assertIs(r, M)

        self.assertEqual(B.x, 'b')
        self.assertEqual(B.y, 'a')
        self.assertEqual(B.m, 'm')

    def test_separate_class_first(self):
        "test monkeypatch of external mixin"

        # M --+--> B
        #     |
        # A --/
        #
        # M should shadow A, be shadowed by B

        class A(object):
            x = 'a' #shadowed by M,B
            y = 'a' #shadowed by M

        class B(A):
            x = 'b'

        self.assertEqual(B.x, 'b')
        self.assertEqual(B.y, 'a')
        self.assertEqual(getattr(B,'m',None), None)

        class M(object):
            x = 'm' #shadowed by A,B
            y = 'm' #shadowed by A
            m = 'm'

        r = meta.monkeypatch_mixin(B, first=True)(M)
        self.assertIs(r, M)

        self.assertEqual(B.x, 'b')
        self.assertEqual(B.y, 'm')
        self.assertEqual(B.m, 'm')

    def test_subclass(self):
        "if patching subclass, should be noop"

        # A -->  M --> B

        class A(object):
            x = 'a' #shadowed by B
            y = 'a' #not shadowed

        class M(A):
            x = 'm'
            y = 'm'
            m = 'm'

        class B(M):
            x = 'b'

        self.assertEqual(B.x, 'b')
        self.assertEqual(B.y, 'm')
        self.assertEqual(B.m, 'm')

        r = meta.monkeypatch_mixin(B)(M)
        self.assertIs(r, M)

        self.assertEqual(B.x, 'b')
        self.assertEqual(B.y, 'm')
        self.assertEqual(B.m, 'm')

    def test_wrong_subclass(self):
        "patching parent should be error"

        # A --> B --> M

        class A(object):
            x = 'a' #shadowed by B
            y = 'a' #not shadowed

        class B(A):
            x = 'b'

        self.assertEqual(B.x, 'b')
        self.assertEqual(B.y, 'a')
        self.assertEqual(getattr(B,'m',None), None)

        class M(B):
            x = 'm'
            y = 'm'
            m = 'm'

        self.assertRaises(TypeError, meta.monkeypatch_mixin(B), M)

class ParamsTest(TestCase):
    "test bps.meta.Params class"

    def test_misc(self):
        self.assertEqual(repr(Params(1, 2, x=1)), "Params(1, 2, x=1)")

    def test_constructor(self):
        "test Params()"
        #test constructor
        p1 = Params()
        self.assertEqual(p1.args, [])
        self.assertEqual(p1.kwds, {})

        p2 = Params(1, 2)
        self.assertEqual(p2.args, [1, 2])
        self.assertEqual(p2.kwds, {})

        p3 = Params(1, 2, x=1, y=2)
        self.assertEqual(p3.args, [1, 2])
        self.assertEqual(p3.kwds, dict(x=1, y=2))

        p4 = Params(x=1, y=2)
        self.assertEqual(p4.args, [])
        self.assertEqual(p4.kwds, dict(x=1, y=2))

    def test_clone(self):
        p1 = Params(1,2, x=1, y=2)

        p2 = p1.clone()
        self.assertIsNot(p2.args, p1.args)
        self.assertEquals(p1.args, [1,2])
        self.assertEquals(p2.args, [1,2])

        self.assertIsNot(p2.kwds, p1.kwds)
        self.assertEquals(p1.kwds, dict(x=1,y=2))
        self.assertEquals(p2.kwds, dict(x=1,y=2))

    def test_clone_mutate(self):
        p1 = Params(1,2, x=1, y=2)

        p2 = p1.clone(3,y=3,z=4)
        self.assertIsNot(p2.args, p1.args)
        self.assertEquals(p1.args, [1,2])
        self.assertEquals(p2.args, [1,2,3])

        self.assertIsNot(p2.kwds, p1.kwds)
        self.assertEquals(p1.kwds, dict(x=1,y=2))
        self.assertEquals(p2.kwds, dict(x=1,y=3,z=4))

    def test_clear(self):
        p1 = Params(1, 2, x=1, y=2)

        a = p1.args
        k = p1.kwds
        self.assertEqual(a, [1,2])
        self.assertEqual(k, dict(x=1,y=2))

        p1.clear()
        self.assertIs(p1.args, a)
        self.assertIs(p1.kwds, k)
        self.assertEqual(a, [])
        self.assertEqual(k, dict())

    def test_eq(self):
        p1 = Params(1, 2, x=1, y=2)

        p2 = Params(1, 2, x=1, y=2)
        self.assertIsNot(p2, p1)
        self.assertEqual(p2, p1)

        p3 = Params(1, 2, x=1)
        p4 = Params(1, 2, x=1, y=3)
        p5 = Params(1, x=1, y=2)
        p6 = Params(1, 3, x=1, y=2)
        choices = [p1, p3, p4, p5, p6]
        for c1 in choices:
            for c2 in choices:
                if c1 is c2:
                    self.assertEqual(c1, c2)
                else:
                    self.assertNotEqual(c1, c2)

        self.assertNotEqual(None, p1)

    def test_parse(self):
        "test Params.parse() constructor"
        self.check_function_results(Params.parse, [
            ak(Params(),            ""),
            ak(Params(1, 2),        "1,2"),
            ak(Params(1, 2),        "(1,2)"),
            ak(Params((1, 2)),      "(1,2),"),
            ak(Params((1, 5), 5),   "(1,y),y", scope=dict(y=5)),
            ak(Params(1, 2),        "(x,2)", scope=dict(x=1)),
            ak(Params((1, 2), z=3), "(1,2),z=3"),
            ak(Params((1, 2), z=3), "(1,2),z=3,"),
            ak(Params(a=1, b=2),    "a=1,b=2"),
            ak(Params(1, a=2, b=3), "1,a=2,b=3"),
            ])

    #TODO: test evil scope behavior, see if we can lock it down somehow.
    #except restricted-python seems to be a frequently attempted pipedream,
    #so fixing it would probably require waiting.
    #we _could_ add a "safe" flag to parse,
    #which simply prevents any syntaxes (eg complex exprs) that we can't lock down.

    def test_render(self):
        results = [
            ak("",              Params()),
            ak("1, 2",          Params(1, 2)),
            ak("(1, 2)",        Params((1, 2))),
            ak("(1, 5), 5",     Params((1, 5), 5)),
            ak("(1, 2), z=3",   Params((1, 2), z=3)),
            ak("a=1, b=2",      Params(a=1, b=2)),
            ak("1, a=2, b=3",   Params(1, a=2, b=3)),
            ]
        self.check_function_results(lambda x: x.render(), results)
        self.check_function_results(lambda x: str(x), results)

    def test_render_offset(self):
        results = [
            ak("2",          Params(1, 2)),
            ak("",        Params((1, 2))),
            ak("5",     Params((1, 5), 5)),
            ak("z=3",   Params((1, 2), z=3)),
            ak("a=2, b=3",   Params(1, a=2, b=3)),

            #NOTE: it hasn't been decided as to whether offsets
            # which goes past end of positional args should be allowed to implicitly return empty tuple,
            # or raise an error (the former behavior is what we currently have)
            ak("",              Params()),
            ak("a=1, b=2",      Params(a=1, b=2)),
            ]
        self.check_function_results(lambda x: x.render(1), results)

    def test_render_class(self):
        class Test(object):
            pass
        cls = meta.SingleSuperProperty
        obj = cls(Test)

        p = Params()
        self.assertEquals(p.render_class(cls),"bps.meta.SingleSuperProperty()")

        p = Params(1,2,a='a')
        self.assertEquals(p.render_class(cls),"bps.meta.SingleSuperProperty(1, 2, a='a')")
        self.assertEquals(p.render_class(obj),"bps.meta.SingleSuperProperty(1, 2, a='a')")


    #   check x.args is list, and can be edited directly
    #   check x.kwds is dict, and can be edited directly
    #   check x.normalize
    #   check x[int] and x[str]

    def test_append(self):
        p = Params(1,2,3,a='a',b='b')

        p.append()
        self.assertEqual(p.args,[1,2,3])
        self.assertEqual(p.kwds,dict(a='a',b='b'))

        p.append(b='bb',c='c')
        self.assertEqual(p.args,[1,2,3])
        self.assertEqual(p.kwds,dict(a='a',b='bb',c='c'))

        p.append(4,c='cc')
        self.assertEqual(p.args,[1,2,3,4])
        self.assertEqual(p.kwds,dict(a='a',b='bb',c='cc'))

        p.append(5,1,3)
        self.assertEqual(p.args,[1,2,3,4,5,1,3])
        self.assertEqual(p.kwds,dict(a='a',b='bb',c='cc'))

        p.append(c='c2',d=None)
        self.assertEqual(p.args,[1,2,3,4,5,1,3])
        self.assertEqual(p.kwds,dict(a='a',b='bb',c='c2',d=None))

    def test_append_modified(self):
        p = Params(1,2,3,a='a',b='b')

        p.append_modified({})
        self.assertEqual(p.args,[1,2,3])
        self.assertEqual(p.kwds,dict(a='a',b='b'))

        p.append_modified(dict(c=1,d=None))
        self.assertEqual(p.args,[1,2,3])
        self.assertEqual(p.kwds,dict(a='a',b='b',c=1))

        p.append_modified(dict(c=2,d=None), default=2)
        self.assertEqual(p.args,[1,2,3])
        self.assertEqual(p.kwds,dict(a='a',b='b',c=1,d=None))

    def test_insert(self):
        p = Params(1,2,3,a='a',b='b')

        p.insert(2)
        self.assertEqual(p.args,[1,2,3])
        self.assertEqual(p.kwds,dict(a='a',b='b'))

        p.insert(2,b='bb',c='c')
        self.assertEqual(p.args,[1,2,3])
        self.assertEqual(p.kwds,dict(a='a',b='bb',c='c'))

        p.insert(2,4,c='cc')
        self.assertEqual(p.args,[1,2,4,3])
        self.assertEqual(p.kwds,dict(a='a',b='bb',c='cc'))

        p.insert(4,5,1,3)
        self.assertEqual(p.args,[1,2,4,3,5,1,3])
        self.assertEqual(p.kwds,dict(a='a',b='bb',c='cc'))

class MiscTest(TestCase):

    def test_lookup_module_files(self):
        "test lookup_module() against known py files"
        lookup_module = meta.lookup_module
        import bps
        for module in (os, meta):
            path = module.__file__
            self.assertEquals(lookup_module(path), module)
            self.assertEquals(lookup_module(path, name=True), module.__name__)

    def test_lookup_module_packages(self):
        "test lookup_module() against known packages"
        lookup_module = meta.lookup_module
        import bps as module
        path = module.__file__
        dir = os.path.dirname(path)
        self.assertEquals(lookup_module(path), module)
        self.assertEquals(lookup_module(path, name=True), module.__name__)
        self.assertEquals(lookup_module(dir), module)
        self.assertEquals(lookup_module(dir, name=True), module.__name__)

    if os.name in ("posix", "nt"):
        def test_lookup_module_compiled(self):
            "test lookup_module() against a compiled extension"
            lookup_module = meta.lookup_module

            if os.name == "nt":
                name = "select" #known to be a .pyd under nt
            else:
                assert os.name == "posix"
                name = "audioop" #known to be a .so under linux

            #test module isn't already in use, allowing us to remove it at will
            #TODO: could remember & restore state
            self.assert_(name not in sys.modules)

            #import module & test compiled-module handling
            module = __import__(name)
            path = module.__file__
            self.assert_(os.path.splitext(path)[1] in meta._cmod_exts)
            self.assertEquals(lookup_module(path), module)
            self.assertEquals(lookup_module(path, name=True), name)

            #now test no detection if module not loaded
            del sys.modules[name]
            self.assertEquals(lookup_module(path), None)
            self.assertEquals(lookup_module(path, name=True), None)

    def test_func_accepts_key(self):
        def check(f, k, r=True):
            self.assertEqual(meta.func_accepts_key(f, k), r)

        #check normal func
        def f(a, b):
            pass
        check(f, 'a')
        check(f, 'b')
        check(f, 'c', False)
        check(f, ['a', 'b'])
        check(f, ['a', 'c'], False)


        #check normal func
        def f(a=None, b=None):
            pass
        check(f, 'a')
        check(f, 'b')
        check(f, 'c', False)
        check(f, ['a', 'b'])
        check(f, ['a', 'c'], False)

        #check kwd func
        def f(**k):
            pass
        check(f, 'a')
        check(f, 'b')
        check(f, 'c')
        check(f, ['a', 'b'])
        check(f, ['a', 'c'])

        #check class
        class f(object):
            def __init__(self, a, b=None):
                pass
        check(f, "self", False) #first arg shouldn't count
        check(f, 'a')
        check(f, 'b')
        check(f, 'c', False)
        check(f, ['a', 'b'])
        check(f, ['a', 'c'], False)

class FallbackMethodTest(TestCase):
    "tests class_property, fallback_method, fallback_property"

    def test_class_property(self):
        class Test:

            @meta.class_property
            def test(*a, **k):
                return 1, a, k
        self.assertEquals(Test.test, (1, (Test,),{}))
        test = Test()
        self.assertEquals(test.test, (1, (Test,),{}))

    def test_fallback_property(self):
        class Test:

            @meta.fallback_property
            def test(*a, **k):
                return 1, a, k
        self.assertEquals(Test.test, (1, (None, Test),{}))
        test = Test()
        self.assertEquals(test.test, (1, (test, Test),{}))

    if meta._classobj:
        def test_classobj(self):
            class Test:

                @meta.fallback_method
                def test(*a, **k):
                    return a,k

            self.assert_(isinstance(Test, meta._classobj))

            func = Test.__dict__['test'].im_func

            a = Test.test
            self.assertIs(a.im_self, None)
            self.assertIs(a.im_class, Test)
            self.assertIs(a.im_func, func)

            self.assertIsNot(Test.test, a)

            self.assertEquals(a(), ((None, Test),{}))
            self.assertEquals(a(1,2), ((None, Test,1,2),{}))
            self.assertEquals(a(1,2,x=1), ((None, Test,1,2),{'x':1}))

            self._check_instance(Test)

    def test_class(self):
        class Test(object):

            @meta.fallback_method
            def test(*a, **k):
                return a,k

        func = Test.__dict__['test'].im_func

        a = Test.test
        self.assertIs(a.im_self, None)
        self.assertIs(a.im_class, Test)
        self.assertIs(a.im_func, func)

        self.assertIs(Test.test, a)

        self.assertEquals(a(), ((None, Test),{}))
        self.assertEquals(a(1,2), ((None, Test,1,2),{}))
        self.assertEquals(a(1,2,x=1), ((None, Test,1,2),{'x':1}))

        self._check_instance(Test)

    def _check_instance(self, Test):
        func = Test.__dict__['test'].im_func
        test = Test()
        a = test.test

        self.assertIs(a.im_self, test)
        self.assertIs(a.im_class, Test)
        self.assertIs(a.im_func, func)

        self.assertIs(test.test, a)
        self.assertIs(test.__dict__['test'], a)

        self.assertEquals(a(), ((test, Test),{}))
        self.assertEquals(a(1,2), ((test, Test,1,2),{}))
        self.assertEquals(a(1,2,x=1), ((test, Test,1,2),{'x':1}))

#=========================================================
#eof
#=========================================================
