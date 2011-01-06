"""tests for bps.text._string_format.

Most of these tests are adapted from the python source,
to make sure our custom implementation passes all the
tests the real format() has to pass.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import sys
from functools import partial
#site
#pkg
import bps.text.patch_format
import bps.text._string_format as tsf
#module
from bps.types import stub
from bps.meta import Params as ak
from bps.tests.utils import TestCase
#=========================================================
#
#=========================================================

string = stub(Formatter=tsf.Formatter)

#=========================================================
#custom string.format tests
#=========================================================
class BaseClassTest(TestCase):
    def setUp(self):
        self.formatter = tsf.Formatter()

    def test_formatter(self, format=None):
        if format is None:
            format = self.formatter.format
        self.check_function_results(format, [
            ak("1",
                "{a}", a=1),
            ak("1 2",
                "{0} {a}", 1, a=2),
            ak("This is a test of } 3e8 hex 3 a 200000{",
                "This is a test of }} {0:x} {x} {y[2]} {2[2]} {1:5n}{{",
                1000, 200000, 'grag', x='hex', y=[1,2,3]),
            ak("5  5 5 +5", "{0:n} {0: n} {0:-n} {0:+n}", 5),
            ak("-5 -5 -5 -5", "{0:n} {0: n} {0:-n} {0:+n}", -5),
            ])

    if sys.version_info >= (2, 6):
        def test_formatter_test(self):
            "run test cases through python's builtin format, errors here mean test itself is wrong"
            def wrapper(s, *a, **k):
                return s.format(*a, **k)
            self.test_formatter(wrapper)

class StdlibTest(TestCase):
    "this is a copy of Python 2.6.2's Formatter tests"

    #from Lib/test/test_builtin line 1368
    def test_format_builtin(self):
        # Test the basic machinery of the format() builtin.  Don't test
        #  the specifics of the various formatters
        self.assertEqual(format(3, ''), '3')

        # Returns some classes to use for various tests.  There's
        #  an old-style version, and a new-style version
        def classes_new():
            class A(object):
                def __init__(self, x):
                    self.x = x
                def __format__(self, format_spec):
                    return str(self.x) + format_spec
            class DerivedFromA(A):
                pass

            class Simple(object): pass
            class DerivedFromSimple(Simple):
                def __init__(self, x):
                    self.x = x
                def __format__(self, format_spec):
                    return str(self.x) + format_spec
            class DerivedFromSimple2(DerivedFromSimple): pass
            return A, DerivedFromA, DerivedFromSimple, DerivedFromSimple2

        # In 3.0, classes_classic has the same meaning as classes_new
        def classes_classic():
            class A:
                def __init__(self, x):
                    self.x = x
                def __format__(self, format_spec):
                    return str(self.x) + format_spec
            class DerivedFromA(A):
                pass

            class Simple: pass
            class DerivedFromSimple(Simple):
                def __init__(self, x):
                    self.x = x
                def __format__(self, format_spec):
                    return str(self.x) + format_spec
            class DerivedFromSimple2(DerivedFromSimple): pass
            return A, DerivedFromA, DerivedFromSimple, DerivedFromSimple2

        def class_test(A, DerivedFromA, DerivedFromSimple, DerivedFromSimple2):
            self.assertEqual(format(A(3), 'spec'), '3spec')
            self.assertEqual(format(DerivedFromA(4), 'spec'), '4spec')
            self.assertEqual(format(DerivedFromSimple(5), 'abc'), '5abc')
            self.assertEqual(format(DerivedFromSimple2(10), 'abcdef'),
                             '10abcdef')

        class_test(*classes_new())
        class_test(*classes_classic())

        def empty_format_spec(value):
            # test that:
            #  format(x, '') == str(x)
            #  format(x) == str(x)
            self.assertEqual(format(value, ""), str(value))
            self.assertEqual(format(value), str(value))

        # for builtin types, format(x, "") == str(x)
        empty_format_spec(17**13)
        empty_format_spec(1.0)
        empty_format_spec(3.1415e104)
        empty_format_spec(-3.1415e104)
        empty_format_spec(3.1415e-104)
        empty_format_spec(-3.1415e-104)
        empty_format_spec(object)
        empty_format_spec(None)

        # TypeError because self.__format__ returns the wrong type
        class BadFormatResult:
            def __format__(self, format_spec):
                return 1.0
        self.assertRaises(TypeError, format, BadFormatResult(), "")

        # TypeError because format_spec is not unicode or str
        self.assertRaises(TypeError, format, object(), 4)
        self.assertRaises(TypeError, format, object(), object())

        # tests for object.__format__ really belong elsewhere, but
        #  there's no good place to put them
        #JEC -- replaced below ##x = object().__format__('')
        x = tsf.object_format(object(), '')
        self.assert_(x.startswith('<object object at'))

        # first argument to object.__format__ must be string
        self.assertRaises(TypeError, partial(tsf.object_format, object()), 3)
        self.assertRaises(TypeError, partial(tsf.object_format, object()), object())
        self.assertRaises(TypeError, partial(tsf.object_format, object()), None)

        # make sure we can take a subclass of str as a format spec
        class DerivedFromStr(str): pass
        self.assertEqual(format(0, DerivedFromStr('10')), '         0')

    # Lib/test/test_datetime, line 860
##    def test_format_date(self):
##        dt = self.theclass(2007, 9, 10)
##        self.assertEqual(dt.__format__(''), str(dt))
##
##        # check that a derived class's __str__() gets called
##        class A(self.theclass):
##            def __str__(self):
##                return 'A'
##        a = A(2007, 9, 10)
##        self.assertEqual(a.__format__(''), 'A')
##
##        # check that a derived class's strftime gets called
##        class B(self.theclass):
##            def strftime(self, format_spec):
##                return 'B'
##        b = B(2007, 9, 10)
##        self.assertEqual(b.__format__(''), str(dt))
##
##        for fmt in ["m:%m d:%d y:%y",
##                    "m:%m d:%d y:%y H:%H M:%M S:%S",
##                    "%z %Z",
##                    ]:
##            self.assertEqual(dt.__format__(fmt), dt.strftime(fmt))
##            self.assertEqual(a.__format__(fmt), dt.strftime(fmt))
##            self.assertEqual(b.__format__(fmt), 'B')

    # Lib/test/test_datetime, line 1169
##    def test_format_datetime(self):
##        dt = self.theclass(2007, 9, 10, 4, 5, 1, 123)
##        self.assertEqual(dt.__format__(''), str(dt))
##
##        # check that a derived class's __str__() gets called
##        class A(self.theclass):
##            def __str__(self):
##                return 'A'
##        a = A(2007, 9, 10, 4, 5, 1, 123)
##        self.assertEqual(a.__format__(''), 'A')
##
##        # check that a derived class's strftime gets called
##        class B(self.theclass):
##            def strftime(self, format_spec):
##                return 'B'
##        b = B(2007, 9, 10, 4, 5, 1, 123)
##        self.assertEqual(b.__format__(''), str(dt))
##
##        for fmt in ["m:%m d:%d y:%y",
##                    "m:%m d:%d y:%y H:%H M:%M S:%S",
##                    "%z %Z",
##                    ]:
##            self.assertEqual(dt.__format__(fmt), dt.strftime(fmt))
##            self.assertEqual(a.__format__(fmt), dt.strftime(fmt))
##            self.assertEqual(b.__format__(fmt), 'B')

        # Lib/test/test_datetime, line 1827
##    def test_format(self):
##        t = self.theclass(1, 2, 3, 4)
##        self.assertEqual(t.__format__(''), str(t))
##
##        # check that a derived class's __str__() gets called
##        class A(self.theclass):
##            def __str__(self):
##                return 'A'
##        a = A(1, 2, 3, 4)
##        self.assertEqual(a.__format__(''), 'A')
##
##        # check that a derived class's strftime gets called
##        class B(self.theclass):
##            def strftime(self, format_spec):
##                return 'B'
##        b = B(1, 2, 3, 4)
##        self.assertEqual(b.__format__(''), str(t))
##
##        for fmt in ['%H %M %S',
##                    ]:
##            self.assertEqual(t.__format__(fmt), t.strftime(fmt))
##            self.assertEqual(a.__format__(fmt), t.strftime(fmt))
##            self.assertEqual(b.__format__(fmt), 'B')


    #from Lib/test/test_string line 109
    def test_formatter_class(self):
        fmt = string.Formatter()
        self.assertEqual(fmt.format("foo"), "foo")

        self.assertEqual(fmt.format("foo{0}", "bar"), "foobar")
        self.assertEqual(fmt.format("foo{1}{0}-{1}", "bar", 6), "foo6bar-6")
        self.assertEqual(fmt.format("-{arg!r}-", arg='test'), "-'test'-")

        # override get_value ############################################
        class NamespaceFormatter(string.Formatter):
            def __init__(self, namespace={}):
                string.Formatter.__init__(self)
                self.namespace = namespace

            def get_value(self, key, args, kwds):
                if isinstance(key, str):
                    try:
                        # Check explicitly passed arguments first
                        return kwds[key]
                    except KeyError:
                        return self.namespace[key]
                else:
                    string.Formatter.get_value(key, args, kwds)

        fmt = NamespaceFormatter({'greeting':'hello'})
        self.assertEqual(fmt.format("{greeting}, world!"), 'hello, world!')


        # override format_field #########################################
        class CallFormatter(string.Formatter):
            def format_field(self, value, format_spec):
                return format(value(), format_spec)

        fmt = CallFormatter()
        self.assertEqual(fmt.format('*{0}*', lambda : 'result'), '*result*')


        # override convert_field ########################################
        class XFormatter(string.Formatter):
            def convert_field(self, value, conversion):
                if conversion == 'x':
                    return None
                return super(XFormatter, self).convert_field(value, conversion)

        fmt = XFormatter()
        self.assertEqual(fmt.format("{0!r}:{0!x}", 'foo', 'foo'), "'foo':None")


        # override parse ################################################
        class BarFormatter(string.Formatter):
            # returns an iterable that contains tuples of the form:
            # (literal_text, field_name, format_spec, conversion)
            def parse(self, format_string):
                for field in format_string.split('|'):
                    if field[0] == '+':
                        # it's markup
                        field_name, _, format_spec = field[1:].partition(':')
                        yield '', field_name, format_spec, None
                    else:
                        yield field, None, None, None

        fmt = BarFormatter()
        self.assertEqual(fmt.format('*|+0:^10s|*', 'foo'), '*   foo    *')

        # test all parameters used
        class CheckAllUsedFormatter(string.Formatter):
            def check_unused_args(self, used_args, args, kwargs):
                # Track which arguments actuallly got used
                unused_args = set(kwargs.keys())
                unused_args.update(range(0, len(args)))

                for arg in used_args:
                    unused_args.remove(arg)

                if unused_args:
                    raise ValueError("unused arguments")

        fmt = CheckAllUsedFormatter()
        self.assertEqual(fmt.format("{0}", 10), "10")
        self.assertEqual(fmt.format("{0}{i}", 10, i=100), "10100")
        self.assertEqual(fmt.format("{0}{i}{1}", 10, 20, i=100), "1010020")
        self.assertRaises(ValueError, fmt.format, "{0}{i}{1}", 10, 20, i=100, j=0)
        self.assertRaises(ValueError, fmt.format, "{0}", 10, 20)
        self.assertRaises(ValueError, fmt.format, "{0}", 10, 20, i=100)
        self.assertRaises(ValueError, fmt.format, "{i}", 10, 20, i=100)

        # Alternate formatting is not supported
        self.assertRaises(ValueError, format, '', '#')
        self.assertRaises(ValueError, format, '', '#20')

    #from Lib/test/test_str, line 141
    def test_format(self):
        self.assertEqual(''.format(), '')
        self.assertEqual('a'.format(), 'a')
        self.assertEqual('ab'.format(), 'ab')
        self.assertEqual('a{{'.format(), 'a{')
        self.assertEqual('a}}'.format(), 'a}')
        self.assertEqual('{{b'.format(), '{b')
        self.assertEqual('}}b'.format(), '}b')
        self.assertEqual('a{{b'.format(), 'a{b')

        # examples from the PEP:
        import datetime
        self.assertEqual("My name is {0}".format('Fred'), "My name is Fred")
        self.assertEqual("My name is {0[name]}".format(dict(name='Fred')),
                         "My name is Fred")
        self.assertEqual("My name is {0} :-{{}}".format('Fred'),
                         "My name is Fred :-{}")

        d = datetime.date(2007, 8, 18)
        self.assertEqual("The year is {0.year}".format(d),
                         "The year is 2007")

        # classes we'll use for testing
        class C:
            def __init__(self, x=100):
                self._x = x
            def __format__(self, spec):
                return spec

        class D:
            def __init__(self, x):
                self.x = x
            def __format__(self, spec):
                return str(self.x)

        # class with __str__, but no __format__
        class E:
            def __init__(self, x):
                self.x = x
            def __str__(self):
                return 'E(' + self.x + ')'

        # class with __repr__, but no __format__ or __str__
        class F:
            def __init__(self, x):
                self.x = x
            def __repr__(self):
                return 'F(' + self.x + ')'

        # class with __format__ that forwards to string, for some format_spec's
        class G:
            def __init__(self, x):
                self.x = x
            def __str__(self):
                return "string is " + self.x
            def __format__(self, format_spec):
                if format_spec == 'd':
                    return 'G(' + self.x + ')'
                #jec - replaced below
                return tsf.object_format(self, format_spec)

        # class that returns a bad type from __format__
        class H:
            def __format__(self, format_spec):
                return 1.0

        class I(datetime.date):
            def __format__(self, format_spec):
                return self.strftime(format_spec)

        class J(int):
            def __format__(self, format_spec):
                #jec -- replaced below
                return tsf.int_format(self * 2, format_spec)


        self.assertEqual(''.format(), '')
        self.assertEqual('abc'.format(), 'abc')
        self.assertEqual('{0}'.format('abc'), 'abc')
        self.assertEqual('{0:}'.format('abc'), 'abc')
        self.assertEqual('X{0}'.format('abc'), 'Xabc')
        self.assertEqual('{0}X'.format('abc'), 'abcX')
        self.assertEqual('X{0}Y'.format('abc'), 'XabcY')
        self.assertEqual('{1}'.format(1, 'abc'), 'abc')
        self.assertEqual('X{1}'.format(1, 'abc'), 'Xabc')
        self.assertEqual('{1}X'.format(1, 'abc'), 'abcX')
        self.assertEqual('X{1}Y'.format(1, 'abc'), 'XabcY')
        self.assertEqual('{0}'.format(-15), '-15')
        self.assertEqual('{0}{1}'.format(-15, 'abc'), '-15abc')
        self.assertEqual('{0}X{1}'.format(-15, 'abc'), '-15Xabc')
        self.assertEqual('{{'.format(), '{')
        self.assertEqual('}}'.format(), '}')
        self.assertEqual('{{}}'.format(), '{}')
        self.assertEqual('{{x}}'.format(), '{x}')
        self.assertEqual('{{{0}}}'.format(123), '{123}')
        self.assertEqual('{{{{0}}}}'.format(), '{{0}}')
        self.assertEqual('}}{{'.format(), '}{')
        self.assertEqual('}}x{{'.format(), '}x{')

        # weird field names
        self.assertEqual("{0[foo-bar]}".format({'foo-bar':'baz'}), 'baz')
        self.assertEqual("{0[foo bar]}".format({'foo bar':'baz'}), 'baz')
        self.assertEqual("{0[ ]}".format({' ':3}), '3')

        self.assertEqual('{foo._x}'.format(foo=C(20)), '20')
        self.assertEqual('{1}{0}'.format(D(10), D(20)), '2010')
        self.assertEqual('{0._x.x}'.format(C(D('abc'))), 'abc')
        self.assertEqual('{0[0]}'.format(['abc', 'def']), 'abc')
        self.assertEqual('{0[1]}'.format(['abc', 'def']), 'def')
        self.assertEqual('{0[1][0]}'.format(['abc', ['def']]), 'def')
        self.assertEqual('{0[1][0].x}'.format(['abc', [D('def')]]), 'def')

        # strings
        self.assertEqual('{0:.3s}'.format('abc'), 'abc')
        self.assertEqual('{0:.3s}'.format('ab'), 'ab')
        self.assertEqual('{0:.3s}'.format('abcdef'), 'abc')
        self.assertEqual('{0:.0s}'.format('abcdef'), '')
        self.assertEqual('{0:3.3s}'.format('abc'), 'abc')
        self.assertEqual('{0:2.3s}'.format('abc'), 'abc')
        self.assertEqual('{0:2.2s}'.format('abc'), 'ab')
        self.assertEqual('{0:3.2s}'.format('abc'), 'ab ')
        self.assertEqual('{0:x<0s}'.format('result'), 'result')
        self.assertEqual('{0:x<5s}'.format('result'), 'result')
        self.assertEqual('{0:x<6s}'.format('result'), 'result')
        self.assertEqual('{0:x<7s}'.format('result'), 'resultx')
        self.assertEqual('{0:x<8s}'.format('result'), 'resultxx')
        self.assertEqual('{0: <7s}'.format('result'), 'result ')
        self.assertEqual('{0:<7s}'.format('result'), 'result ')
        self.assertEqual('{0:>7s}'.format('result'), ' result')
        self.assertEqual('{0:>8s}'.format('result'), '  result')
        self.assertEqual('{0:^8s}'.format('result'), ' result ')
        self.assertEqual('{0:^9s}'.format('result'), ' result  ')
        self.assertEqual('{0:^10s}'.format('result'), '  result  ')
        self.assertEqual('{0:10000}'.format('a'), 'a' + ' ' * 9999)
        self.assertEqual('{0:10000}'.format(''), ' ' * 10000)
        self.assertEqual('{0:10000000}'.format(''), ' ' * 10000000)

        # format specifiers for user defined type
        self.assertEqual('{0:abc}'.format(C()), 'abc')

        # !r and !s coersions
        self.assertEqual('{0!s}'.format('Hello'), 'Hello')
        self.assertEqual('{0!s:}'.format('Hello'), 'Hello')
        self.assertEqual('{0!s:15}'.format('Hello'), 'Hello          ')
        self.assertEqual('{0!s:15s}'.format('Hello'), 'Hello          ')
        self.assertEqual('{0!r}'.format('Hello'), "'Hello'")
        self.assertEqual('{0!r:}'.format('Hello'), "'Hello'")
        self.assertEqual('{0!r}'.format(F('Hello')), 'F(Hello)')

        # test fallback to object.__format__
        self.assertEqual('{0}'.format({}), '{}')
        self.assertEqual('{0}'.format([]), '[]')
        self.assertEqual('{0}'.format([1]), '[1]')
        self.assertEqual('{0}'.format(E('data')), 'E(data)')
        self.assertEqual('{0:^10}'.format(E('data')), ' E(data)  ')
        self.assertEqual('{0:^10s}'.format(E('data')), ' E(data)  ')
        self.assertEqual('{0:d}'.format(G('data')), 'G(data)')
        self.assertEqual('{0:>15s}'.format(G('data')), ' string is data')
        self.assertEqual('{0!s}'.format(G('data')), 'string is data')

        self.assertEqual("{0:date: %Y-%m-%d}".format(I(year=2007,
                                                       month=8,
                                                       day=27)),
                         "date: 2007-08-27")

        # test deriving from a builtin type and overriding __format__
        self.assertEqual("{0}".format(J(10)), "20")


        # string format specifiers
        self.assertEqual('{0:}'.format('a'), 'a')

        # computed format specifiers
        self.assertEqual("{0:.{1}}".format('hello world', 5), 'hello')
        self.assertEqual("{0:.{1}s}".format('hello world', 5), 'hello')
        self.assertEqual("{0:.{precision}s}".format('hello world', precision=5), 'hello')
        self.assertEqual("{0:{width}.{precision}s}".format('hello world', width=10, precision=5), 'hello     ')
        self.assertEqual("{0:{width}.{precision}s}".format('hello world', width='10', precision='5'), 'hello     ')

        # test various errors
        self.assertRaises(ValueError, '{'.format)
        self.assertRaises(ValueError, '}'.format)
        self.assertRaises(ValueError, 'a{'.format)
        self.assertRaises(ValueError, 'a}'.format)
        self.assertRaises(ValueError, '{a'.format)
        self.assertRaises(ValueError, '}a'.format)
        self.assertRaises(IndexError, '{0}'.format)
        self.assertRaises(IndexError, '{1}'.format, 'abc')
        self.assertRaises(KeyError,   '{x}'.format)
        self.assertRaises(ValueError, "}{".format)
        self.assertRaises(ValueError, "{".format)
        self.assertRaises(ValueError, "}".format)
        self.assertRaises(ValueError, "abc{0:{}".format)
        self.assertRaises(ValueError, "{0".format)
        self.assertRaises(IndexError, "{0.}".format)
        self.assertRaises(ValueError, "{0.}".format, 0)
        self.assertRaises(IndexError, "{0[}".format)
        self.assertRaises(ValueError, "{0[}".format, [])
        self.assertRaises(KeyError,   "{0]}".format)
        self.assertRaises(ValueError, "{0.[]}".format, 0)
        self.assertRaises(ValueError, "{0..foo}".format, 0)
        self.assertRaises(ValueError, "{0[0}".format, 0)
        self.assertRaises(ValueError, "{0[0:foo}".format, 0)
        self.assertRaises(KeyError,   "{c]}".format)
        self.assertRaises(ValueError, "{{ {{{0}}".format, 0)
        self.assertRaises(ValueError, "{0}}".format, 0)
        self.assertRaises(KeyError,   "{foo}".format, bar=3)
        self.assertRaises(ValueError, "{0!x}".format, 3)
        self.assertRaises(ValueError, "{0!}".format, 0)
        self.assertRaises(ValueError, "{0!rs}".format, 0)
        self.assertRaises(ValueError, "{!}".format)
        self.assertRaises(ValueError, "{:}".format)
        self.assertRaises(ValueError, "{:s}".format)
        self.assertRaises(ValueError, "{}".format)

        # can't have a replacement on the field name portion
        self.assertRaises(TypeError, '{0[{1}]}'.format, 'abcdefg', 4)

        # exceed maximum recursion depth
        self.assertRaises(ValueError, "{0:{1:{2}}}".format, 'abc', 's', '')
        self.assertRaises(ValueError, "{0:{1:{2:{3:{4:{5:{6}}}}}}}".format,
                          0, 1, 2, 3, 4, 5, 6, 7)

        # string format spec errors
        self.assertRaises(ValueError, "{0:-s}".format, '')
        self.assertRaises(ValueError, format, "", "-")
        self.assertRaises(ValueError, "{0:=s}".format, '')

    # Lib/test/test_types, line 93
    def test_float_to_string(self):
        def test(f, result):
            self.assertEqual(tsf.float_format(f,'e'), result)
            self.assertEqual('%e' % f, result)

        # test all 2 digit exponents, both with __format__ and with
        #  '%' formatting
        for i in range(-99, 100):
            test(float('1.5e'+str(i)), '1.500000e{0:+03d}'.format(i))

        # test some 3 digit exponents
        self.assertEqual(tsf.float_format(1.5e100, 'e'), '1.500000e+100')
        self.assertEqual('%e' % 1.5e100, '1.500000e+100')

        self.assertEqual(tsf.float_format(1.5e101, 'e'), '1.500000e+101')
        self.assertEqual('%e' % 1.5e101, '1.500000e+101')

        self.assertEqual(tsf.float_format(1.5e-100, 'e'), '1.500000e-100')
        self.assertEqual('%e' % 1.5e-100, '1.500000e-100')

        self.assertEqual(tsf.float_format(1.5e-101, 'e'), '1.500000e-101')
        self.assertEqual('%e' % 1.5e-101, '1.500000e-101')

    # Lib/test/test_unicode, line 880
    def test_format_unicode(self):
        self.assertEqual(u''.format(), u'')
        self.assertEqual(u'a'.format(), u'a')
        self.assertEqual(u'ab'.format(), u'ab')
        self.assertEqual(u'a{{'.format(), u'a{')
        self.assertEqual(u'a}}'.format(), u'a}')
        self.assertEqual(u'{{b'.format(), u'{b')
        self.assertEqual(u'}}b'.format(), u'}b')
        self.assertEqual(u'a{{b'.format(), u'a{b')

        # examples from the PEP:
        import datetime
        self.assertEqual(u"My name is {0}".format(u'Fred'), u"My name is Fred")
        self.assertEqual(u"My name is {0[name]}".format(dict(name=u'Fred')),
                         u"My name is Fred")
        self.assertEqual(u"My name is {0} :-{{}}".format(u'Fred'),
                         u"My name is Fred :-{}")

        # datetime.__format__ doesn't work with unicode
        #d = datetime.date(2007, 8, 18)
        #self.assertEqual("The year is {0.year}".format(d),
        #                 "The year is 2007")

        # classes we'll use for testing
        class C:
            def __init__(self, x=100):
                self._x = x
            def __format__(self, spec):
                return spec

        class D:
            def __init__(self, x):
                self.x = x
            def __format__(self, spec):
                return str(self.x)

        # class with __str__, but no __format__
        class E:
            def __init__(self, x):
                self.x = x
            def __str__(self):
                return u'E(' + self.x + u')'

        # class with __repr__, but no __format__ or __str__
        class F:
            def __init__(self, x):
                self.x = x
            def __repr__(self):
                return u'F(' + self.x + u')'

        # class with __format__ that forwards to string, for some format_spec's
        class G:
            def __init__(self, x):
                self.x = x
            def __str__(self):
                return u"string is " + self.x
            def __format__(self, format_spec):
                if format_spec == 'd':
                    return u'G(' + self.x + u')'
                return tsf.object_format(self, format_spec)

        # class that returns a bad type from __format__
        class H:
            def __format__(self, format_spec):
                return 1.0

        class I(datetime.date):
            def __format__(self, format_spec):
                return self.strftime(format_spec)

        class J(int):
            def __format__(self, format_spec):
                return tsf.int_format(self * 2, format_spec)


        self.assertEqual(u''.format(), u'')
        self.assertEqual(u'abc'.format(), u'abc')
        self.assertEqual(u'{0}'.format(u'abc'), u'abc')
        self.assertEqual(u'{0:}'.format(u'abc'), u'abc')
        self.assertEqual(u'X{0}'.format(u'abc'), u'Xabc')
        self.assertEqual(u'{0}X'.format(u'abc'), u'abcX')
        self.assertEqual(u'X{0}Y'.format(u'abc'), u'XabcY')
        self.assertEqual(u'{1}'.format(1, u'abc'), u'abc')
        self.assertEqual(u'X{1}'.format(1, u'abc'), u'Xabc')
        self.assertEqual(u'{1}X'.format(1, u'abc'), u'abcX')
        self.assertEqual(u'X{1}Y'.format(1, u'abc'), u'XabcY')
        self.assertEqual(u'{0}'.format(-15), u'-15')
        self.assertEqual(u'{0}{1}'.format(-15, u'abc'), u'-15abc')
        self.assertEqual(u'{0}X{1}'.format(-15, u'abc'), u'-15Xabc')
        self.assertEqual(u'{{'.format(), u'{')
        self.assertEqual(u'}}'.format(), u'}')
        self.assertEqual(u'{{}}'.format(), u'{}')
        self.assertEqual(u'{{x}}'.format(), u'{x}')
        self.assertEqual(u'{{{0}}}'.format(123), u'{123}')
        self.assertEqual(u'{{{{0}}}}'.format(), u'{{0}}')
        self.assertEqual(u'}}{{'.format(), u'}{')
        self.assertEqual(u'}}x{{'.format(), u'}x{')

        # weird field names
        self.assertEqual(u"{0[foo-bar]}".format({u'foo-bar':u'baz'}), u'baz')
        self.assertEqual(u"{0[foo bar]}".format({u'foo bar':u'baz'}), u'baz')
        self.assertEqual(u"{0[ ]}".format({u' ':3}), u'3')

        self.assertEqual(u'{foo._x}'.format(foo=C(20)), u'20')
        self.assertEqual(u'{1}{0}'.format(D(10), D(20)), u'2010')
        self.assertEqual(u'{0._x.x}'.format(C(D(u'abc'))), u'abc')
        self.assertEqual(u'{0[0]}'.format([u'abc', u'def']), u'abc')
        self.assertEqual(u'{0[1]}'.format([u'abc', u'def']), u'def')
        self.assertEqual(u'{0[1][0]}'.format([u'abc', [u'def']]), u'def')
        self.assertEqual(u'{0[1][0].x}'.format(['abc', [D(u'def')]]), u'def')

        # strings
        self.assertEqual(u'{0:.3s}'.format(u'abc'), u'abc')
        self.assertEqual(u'{0:.3s}'.format(u'ab'), u'ab')
        self.assertEqual(u'{0:.3s}'.format(u'abcdef'), u'abc')
        self.assertEqual(u'{0:.0s}'.format(u'abcdef'), u'')
        self.assertEqual(u'{0:3.3s}'.format(u'abc'), u'abc')
        self.assertEqual(u'{0:2.3s}'.format(u'abc'), u'abc')
        self.assertEqual(u'{0:2.2s}'.format(u'abc'), u'ab')
        self.assertEqual(u'{0:3.2s}'.format(u'abc'), u'ab ')
        self.assertEqual(u'{0:x<0s}'.format(u'result'), u'result')
        self.assertEqual(u'{0:x<5s}'.format(u'result'), u'result')
        self.assertEqual(u'{0:x<6s}'.format(u'result'), u'result')
        self.assertEqual(u'{0:x<7s}'.format(u'result'), u'resultx')
        self.assertEqual(u'{0:x<8s}'.format(u'result'), u'resultxx')
        self.assertEqual(u'{0: <7s}'.format(u'result'), u'result ')
        self.assertEqual(u'{0:<7s}'.format(u'result'), u'result ')
        self.assertEqual(u'{0:>7s}'.format(u'result'), u' result')
        self.assertEqual(u'{0:>8s}'.format(u'result'), u'  result')
        self.assertEqual(u'{0:^8s}'.format(u'result'), u' result ')
        self.assertEqual(u'{0:^9s}'.format(u'result'), u' result  ')
        self.assertEqual(u'{0:^10s}'.format(u'result'), u'  result  ')
        self.assertEqual(u'{0:10000}'.format(u'a'), u'a' + u' ' * 9999)
        self.assertEqual(u'{0:10000}'.format(u''), u' ' * 10000)
        self.assertEqual(u'{0:10000000}'.format(u''), u' ' * 10000000)

        # format specifiers for user defined type
        self.assertEqual(u'{0:abc}'.format(C()), u'abc')

        # !r and !s coersions
        self.assertEqual(u'{0!s}'.format(u'Hello'), u'Hello')
        self.assertEqual(u'{0!s:}'.format(u'Hello'), u'Hello')
        self.assertEqual(u'{0!s:15}'.format(u'Hello'), u'Hello          ')
        self.assertEqual(u'{0!s:15s}'.format(u'Hello'), u'Hello          ')
        self.assertEqual(u'{0!r}'.format(u'Hello'), u"u'Hello'")
        self.assertEqual(u'{0!r:}'.format(u'Hello'), u"u'Hello'")
        self.assertEqual(u'{0!r}'.format(F(u'Hello')), u'F(Hello)')

        # test fallback to object.__format__
        self.assertEqual(u'{0}'.format({}), u'{}')
        self.assertEqual(u'{0}'.format([]), u'[]')
        self.assertEqual(u'{0}'.format([1]), u'[1]')
        self.assertEqual(u'{0}'.format(E(u'data')), u'E(data)')
        self.assertEqual(u'{0:^10}'.format(E(u'data')), u' E(data)  ')
        self.assertEqual(u'{0:^10s}'.format(E(u'data')), u' E(data)  ')
        self.assertEqual(u'{0:d}'.format(G(u'data')), u'G(data)')
        self.assertEqual(u'{0:>15s}'.format(G(u'data')), u' string is data')
        self.assertEqual(u'{0!s}'.format(G(u'data')), u'string is data')

        self.assertEqual("{0:date: %Y-%m-%d}".format(I(year=2007,
                                                       month=8,
                                                       day=27)),
                         "date: 2007-08-27")

        # test deriving from a builtin type and overriding __format__
        self.assertEqual("{0}".format(J(10)), "20")


        # string format specifiers
        self.assertEqual('{0:}'.format('a'), 'a')

        # computed format specifiers
        self.assertEqual("{0:.{1}}".format('hello world', 5), 'hello')
        self.assertEqual("{0:.{1}s}".format('hello world', 5), 'hello')
        self.assertEqual("{0:.{precision}s}".format('hello world', precision=5), 'hello')
        self.assertEqual("{0:{width}.{precision}s}".format('hello world', width=10, precision=5), 'hello     ')
        self.assertEqual("{0:{width}.{precision}s}".format('hello world', width='10', precision='5'), 'hello     ')

        # test various errors
        self.assertRaises(ValueError, '{'.format)
        self.assertRaises(ValueError, '}'.format)
        self.assertRaises(ValueError, 'a{'.format)
        self.assertRaises(ValueError, 'a}'.format)
        self.assertRaises(ValueError, '{a'.format)
        self.assertRaises(ValueError, '}a'.format)
        self.assertRaises(IndexError, '{0}'.format)
        self.assertRaises(IndexError, '{1}'.format, 'abc')
        self.assertRaises(KeyError,   '{x}'.format)
        self.assertRaises(ValueError, "}{".format)
        self.assertRaises(ValueError, "{".format)
        self.assertRaises(ValueError, "}".format)
        self.assertRaises(ValueError, "abc{0:{}".format)
        self.assertRaises(ValueError, "{0".format)
        self.assertRaises(IndexError, "{0.}".format)
        self.assertRaises(ValueError, "{0.}".format, 0)
        self.assertRaises(IndexError, "{0[}".format)
        self.assertRaises(ValueError, "{0[}".format, [])
        self.assertRaises(KeyError,   "{0]}".format)
        self.assertRaises(ValueError, "{0.[]}".format, 0)
        self.assertRaises(ValueError, "{0..foo}".format, 0)
        self.assertRaises(ValueError, "{0[0}".format, 0)
        self.assertRaises(ValueError, "{0[0:foo}".format, 0)
        self.assertRaises(KeyError,   "{c]}".format)
        self.assertRaises(ValueError, "{{ {{{0}}".format, 0)
        self.assertRaises(ValueError, "{0}}".format, 0)
        self.assertRaises(KeyError,   "{foo}".format, bar=3)
        self.assertRaises(ValueError, "{0!x}".format, 3)
        self.assertRaises(ValueError, "{0!}".format, 0)
        self.assertRaises(ValueError, "{0!rs}".format, 0)
        self.assertRaises(ValueError, "{!}".format)
        self.assertRaises(ValueError, "{:}".format)
        self.assertRaises(ValueError, "{:s}".format)
        self.assertRaises(ValueError, "{}".format)

        # can't have a replacement on the field name portion
        self.assertRaises(TypeError, '{0[{1}]}'.format, 'abcdefg', 4)

        # exceed maximum recursion depth
        self.assertRaises(ValueError, "{0:{1:{2}}}".format, 'abc', 's', '')
        self.assertRaises(ValueError, "{0:{1:{2:{3:{4:{5:{6}}}}}}}".format,
                          0, 1, 2, 3, 4, 5, 6, 7)

        # string format spec errors
        self.assertRaises(ValueError, "{0:-s}".format, '')
        self.assertRaises(ValueError, format, "", "-")
        self.assertRaises(ValueError, "{0:=s}".format, '')

        # test combining string and unicode
        self.assertEqual(u"foo{0}".format('bar'), u'foobar')
        # This will try to convert the argument from unicode to str, which
        #  will succeed
        self.assertEqual("foo{0}".format(u'bar'), 'foobar')
        # This will try to convert the argument from unicode to str, which
        #  will fail
        self.assertRaises(UnicodeEncodeError, "foo{0}".format, u'\u1000bar')


#=========================================================
# Lib/test/test_format.py, in it's entirety
#=========================================================

import sys
verbose = False
have_unicode = True
TestFailed = AssertionError
##from test.test_support import verbose, have_unicode, TestFailed
##import test.test_support as test_support
import unittest

##maxsize = test_support.MAX_Py_ssize_t
maxsize = 1<<32

# test string formatting operator (I am not sure if this is being tested
# elsewhere but, surely, some of the given cases are *not* tested because
# they crash python)
# test on unicode strings as well

overflowok = 1
overflowrequired = 0

def checkformat(formatstr, args, output=None, limit=None):
    if verbose:
        if output:
            print "%s %% %s =? %s ..." %\
                (repr(formatstr), repr(args), repr(output)),
        else:
            print "%s %% %s works? ..." % (repr(formatstr), repr(args)),
    try:
        result = formatstr % args
    except OverflowError:
        if not overflowok:
            raise
        if verbose:
            print 'overflow (this is fine)'
    else:
        if overflowrequired:
            if verbose:
                print 'no'
            print "overflow expected on %s %% %s" % \
                  (repr(formatstr), repr(args))
        elif output and limit is None and result != output:
            if verbose:
                print 'no'
            print "%s %% %s == %s != %s" % \
                  (repr(formatstr), repr(args), repr(result), repr(output))
        # when 'limit' is specified, it determines how many characters
        # must match exactly; lengths must always match.
        # ex: limit=5, '12345678' matches '12345___'
        # (mainly for floating point format tests for which an exact match
        # can't be guaranteed due to rounding and representation errors)
        elif output and limit is not None and (
                len(result)!=len(output) or result[:limit]!=output[:limit]):
            if verbose:
                print 'no'
            print "%s %% %s == %s != %s" % \
                  (repr(formatstr), repr(args), repr(result), repr(output))
        else:
            if verbose:
                print 'yes'

def checkboth(formatstr, *args):
    checkformat(formatstr, *args)
    if have_unicode:
        checkformat(unicode(formatstr), *args)

class FormatTest(unittest.TestCase):
    def test_format(self):
        checkboth("%.1d", (1,), "1")
        checkboth("%.*d", (sys.maxint,1))  # expect overflow
        checkboth("%.100d", (1,), '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001')
        checkboth("%#.117x", (1,), '0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001')
        checkboth("%#.118x", (1,), '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001')

        checkboth("%f", (1.0,), "1.000000")
        # these are trying to test the limits of the internal magic-number-length
        # formatting buffer, if that number changes then these tests are less
        # effective
        checkboth("%#.*g", (109, -1.e+49/3.))
        checkboth("%#.*g", (110, -1.e+49/3.))
        checkboth("%#.*g", (110, -1.e+100/3.))

        # test some ridiculously large precision, expect overflow
        checkboth('%12.*f', (123456, 1.0))

        # check for internal overflow validation on length of precision
        overflowrequired = 1
        checkboth("%#.*g", (110, -1.e+100/3.))
        checkboth("%#.*G", (110, -1.e+100/3.))
        checkboth("%#.*f", (110, -1.e+100/3.))
        checkboth("%#.*F", (110, -1.e+100/3.))
        overflowrequired = 0

        # Formatting of long integers. Overflow is not ok
        overflowok = 0
        checkboth("%x", 10L, "a")
        checkboth("%x", 100000000000L, "174876e800")
        checkboth("%o", 10L, "12")
        checkboth("%o", 100000000000L, "1351035564000")
        checkboth("%d", 10L, "10")
        checkboth("%d", 100000000000L, "100000000000")

        big = 123456789012345678901234567890L
        checkboth("%d", big, "123456789012345678901234567890")
        checkboth("%d", -big, "-123456789012345678901234567890")
        checkboth("%5d", -big, "-123456789012345678901234567890")
        checkboth("%31d", -big, "-123456789012345678901234567890")
        checkboth("%32d", -big, " -123456789012345678901234567890")
        checkboth("%-32d", -big, "-123456789012345678901234567890 ")
        checkboth("%032d", -big, "-0123456789012345678901234567890")
        checkboth("%-032d", -big, "-123456789012345678901234567890 ")
        checkboth("%034d", -big, "-000123456789012345678901234567890")
        checkboth("%034d", big, "0000123456789012345678901234567890")
        checkboth("%0+34d", big, "+000123456789012345678901234567890")
        checkboth("%+34d", big, "   +123456789012345678901234567890")
        checkboth("%34d", big, "    123456789012345678901234567890")
        checkboth("%.2d", big, "123456789012345678901234567890")
        checkboth("%.30d", big, "123456789012345678901234567890")
        checkboth("%.31d", big, "0123456789012345678901234567890")
        checkboth("%32.31d", big, " 0123456789012345678901234567890")
        #python 2.5 chokes on this...
##        checkboth("%d", float(big), "123456________________________", 6)

        big = 0x1234567890abcdef12345L  # 21 hex digits
        checkboth("%x", big, "1234567890abcdef12345")
        checkboth("%x", -big, "-1234567890abcdef12345")
        checkboth("%5x", -big, "-1234567890abcdef12345")
        checkboth("%22x", -big, "-1234567890abcdef12345")
        checkboth("%23x", -big, " -1234567890abcdef12345")
        checkboth("%-23x", -big, "-1234567890abcdef12345 ")
        checkboth("%023x", -big, "-01234567890abcdef12345")
        checkboth("%-023x", -big, "-1234567890abcdef12345 ")
        checkboth("%025x", -big, "-0001234567890abcdef12345")
        checkboth("%025x", big, "00001234567890abcdef12345")
        checkboth("%0+25x", big, "+0001234567890abcdef12345")
        checkboth("%+25x", big, "   +1234567890abcdef12345")
        checkboth("%25x", big, "    1234567890abcdef12345")
        checkboth("%.2x", big, "1234567890abcdef12345")
        checkboth("%.21x", big, "1234567890abcdef12345")
        checkboth("%.22x", big, "01234567890abcdef12345")
        checkboth("%23.22x", big, " 01234567890abcdef12345")
        checkboth("%-23.22x", big, "01234567890abcdef12345 ")
        checkboth("%X", big, "1234567890ABCDEF12345")
        checkboth("%#X", big, "0X1234567890ABCDEF12345")
        checkboth("%#x", big, "0x1234567890abcdef12345")
        checkboth("%#x", -big, "-0x1234567890abcdef12345")
        checkboth("%#.23x", -big, "-0x001234567890abcdef12345")
        checkboth("%#+.23x", big, "+0x001234567890abcdef12345")
        checkboth("%# .23x", big, " 0x001234567890abcdef12345")
        checkboth("%#+.23X", big, "+0X001234567890ABCDEF12345")
        checkboth("%#-+.23X", big, "+0X001234567890ABCDEF12345")
        checkboth("%#-+26.23X", big, "+0X001234567890ABCDEF12345")
        checkboth("%#-+27.23X", big, "+0X001234567890ABCDEF12345 ")
        checkboth("%#+27.23X", big, " +0X001234567890ABCDEF12345")
        # next one gets two leading zeroes from precision, and another from the
        # 0 flag and the width
        checkboth("%#+027.23X", big, "+0X0001234567890ABCDEF12345")
        # same, except no 0 flag
        checkboth("%#+27.23X", big, " +0X001234567890ABCDEF12345")
        #python 2.5 chokes on this...
##        checkboth("%x", float(big), "123456_______________", 6)

        big = 012345670123456701234567012345670L  # 32 octal digits
        checkboth("%o", big, "12345670123456701234567012345670")
        checkboth("%o", -big, "-12345670123456701234567012345670")
        checkboth("%5o", -big, "-12345670123456701234567012345670")
        checkboth("%33o", -big, "-12345670123456701234567012345670")
        checkboth("%34o", -big, " -12345670123456701234567012345670")
        checkboth("%-34o", -big, "-12345670123456701234567012345670 ")
        checkboth("%034o", -big, "-012345670123456701234567012345670")
        checkboth("%-034o", -big, "-12345670123456701234567012345670 ")
        checkboth("%036o", -big, "-00012345670123456701234567012345670")
        checkboth("%036o", big, "000012345670123456701234567012345670")
        checkboth("%0+36o", big, "+00012345670123456701234567012345670")
        checkboth("%+36o", big, "   +12345670123456701234567012345670")
        checkboth("%36o", big, "    12345670123456701234567012345670")
        checkboth("%.2o", big, "12345670123456701234567012345670")
        checkboth("%.32o", big, "12345670123456701234567012345670")
        checkboth("%.33o", big, "012345670123456701234567012345670")
        checkboth("%34.33o", big, " 012345670123456701234567012345670")
        checkboth("%-34.33o", big, "012345670123456701234567012345670 ")
        checkboth("%o", big, "12345670123456701234567012345670")
        checkboth("%#o", big, "012345670123456701234567012345670")
        checkboth("%#o", -big, "-012345670123456701234567012345670")
        checkboth("%#.34o", -big, "-0012345670123456701234567012345670")
        checkboth("%#+.34o", big, "+0012345670123456701234567012345670")
        checkboth("%# .34o", big, " 0012345670123456701234567012345670")
        checkboth("%#+.34o", big, "+0012345670123456701234567012345670")
        checkboth("%#-+.34o", big, "+0012345670123456701234567012345670")
        checkboth("%#-+37.34o", big, "+0012345670123456701234567012345670  ")
        checkboth("%#+37.34o", big, "  +0012345670123456701234567012345670")
        # next one gets one leading zero from precision
        checkboth("%.33o", big, "012345670123456701234567012345670")
        # base marker shouldn't change that, since "0" is redundant
        checkboth("%#.33o", big, "012345670123456701234567012345670")
        # but reduce precision, and base marker should add a zero
        checkboth("%#.32o", big, "012345670123456701234567012345670")
        # one leading zero from precision, and another from "0" flag & width
        checkboth("%034.33o", big, "0012345670123456701234567012345670")
        # base marker shouldn't change that
        checkboth("%0#34.33o", big, "0012345670123456701234567012345670")
        #python 2.5 chokes on this...
##        checkboth("%o", float(big), "123456__________________________", 6)

        # Some small ints, in both Python int and long flavors).
        checkboth("%d", 42, "42")
        checkboth("%d", -42, "-42")
        checkboth("%d", 42L, "42")
        checkboth("%d", -42L, "-42")
        checkboth("%d", 42.0, "42")
        checkboth("%#x", 1, "0x1")
        checkboth("%#x", 1L, "0x1")
        checkboth("%#X", 1, "0X1")
        checkboth("%#X", 1L, "0X1")
        checkboth("%#x", 1.0, "0x1")
        checkboth("%#o", 1, "01")
        checkboth("%#o", 1L, "01")
        checkboth("%#o", 0, "0")
        checkboth("%#o", 0L, "0")
        checkboth("%o", 0, "0")
        checkboth("%o", 0L, "0")
        checkboth("%d", 0, "0")
        checkboth("%d", 0L, "0")
        checkboth("%#x", 0, "0x0")
        checkboth("%#x", 0L, "0x0")
        checkboth("%#X", 0, "0X0")
        checkboth("%#X", 0L, "0X0")

        checkboth("%x", 0x42, "42")
        checkboth("%x", -0x42, "-42")
        checkboth("%x", 0x42L, "42")
        checkboth("%x", -0x42L, "-42")
        checkboth("%x", float(0x42), "42")

        checkboth("%o", 042, "42")
        checkboth("%o", -042, "-42")
        checkboth("%o", 042L, "42")
        checkboth("%o", -042L, "-42")
        checkboth("%o", float(042), "42")

        # Test exception for unknown format characters
        if verbose:
            print 'Testing exceptions'

        def test_exc(formatstr, args, exception, excmsg):
            try:
                checkformat(formatstr, args)
            except exception, exc:
                if str(exc) == excmsg:
                    if verbose:
                        print "yes"
                else:
                    if verbose: print 'no'
                    print 'Unexpected ', exception, ':', repr(str(exc))
            except:
                if verbose: print 'no'
                print 'Unexpected exception'
                raise
            else:
                raise TestFailed, 'did not get expected exception: %s' % excmsg

        test_exc('abc %a', 1, ValueError,
                 "unsupported format character 'a' (0x61) at index 5")
        if have_unicode:
            test_exc(unicode('abc %\u3000','raw-unicode-escape'), 1, ValueError,
                     "unsupported format character '?' (0x3000) at index 5")

        test_exc('%d', '1', TypeError, "int argument required") ##"%d format: a number is required, not str")
        test_exc('%g', '1', TypeError, "float argument required") ##", not str")
        test_exc('no format', '1', TypeError,
                 "not all arguments converted during string formatting")
        test_exc('no format', u'1', TypeError,
                 "not all arguments converted during string formatting")
        test_exc(u'no format', '1', TypeError,
                 "not all arguments converted during string formatting")
        test_exc(u'no format', u'1', TypeError,
                 "not all arguments converted during string formatting")

        class Foobar(long):
            def __oct__(self):
                # Returning a non-string should not blow up.
                return self + 1

        test_exc('%o', Foobar(), TypeError,
                 "expected string or Unicode object, long found")

        if maxsize == 2**31-1:
            # crashes 2.2.1 and earlier:
            try:
                "%*d"%(maxsize, -127)
            except MemoryError:
                pass
            else:
                raise TestFailed, '"%*d"%(maxsize, -127) should fail'

#=========================================================
#EOF
#=========================================================
