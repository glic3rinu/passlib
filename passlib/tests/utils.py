"""helpers for bps unittests"""
#=========================================================
#imports
#=========================================================
#core
import warnings
import os
import atexit
import tempfile
import unittest
import sys
from logging import getLogger; log = getLogger(__name__)
from cStringIO import StringIO
import logging
#pkg
from bps.fs import filepath
from bps.meta import Params, is_oseq, is_iter
from bps.logs import config_logging
from bps.logs.handlers import purge_handlers
#local
__all__ = [
            'ak'
   'TestCase',
    'get_tmp_path', 'enable_suite',
    'catch_warnings', 'capture_logger',
]

class Params(object):
    "helper to represent params for function call"
    def __init__(self, *args, **kwds):
        self.args = args
        self.kwds = kwds

    def render(self, offset=0):
        """render parenthesized parameters.

        ``Params.parse(p.render())`` should always return
        a params object equal to the one you started with.

        ``p.render(1)`` is useful for method arguments,
        when you want to exclude the first argument
        from being displayed.
        """
        txt = ''
        for a in self.args[offset:]:
            txt += "%r, " % (a,)
        kwds = self.kwds
        for k in sorted(kwds):
            txt += "%s=%r, " % (k, kwds[k])
        if txt.endswith(", "):
            txt = txt[:-2]
        return txt

#=========================================================
#custom test base
#=========================================================
class TestCase(unittest.TestCase):
    "bps-specific test case class, mainly contains messaging enhancements"

    _prefix = None

    def __init__(self, *a, **k):
        #set the doc strings to begin w/ prefix
        #yes, this is incredibly hacked
        prefix = self._prefix
        if prefix:
            if callable(prefix):
                prefix = prefix()
            for attr in dir(self):
                if not attr.startswith("test_"):
                    continue
                v = getattr(self, attr)
                d = v.im_func.__doc__ or v.im_func.__name__
                idx = d.find(": ")
                if idx > -1:
                    d = d[idx+1:]
                v.im_func.__doc__ = d = "%s: %s" % (prefix, d.lstrip())
                assert v.__doc__ == d
        unittest.TestCase.__init__(self, *a, **k)

    def assertEquals(self, real, correct, msg=None):
        #NOTE: overriding this to get msg formatting capability
        msg = self._format_msg(msg, "got %r, expected would equal %r", real, correct)
        return self.assert_(real == correct, msg)

##    assert_equals = assertEquals

    def assertEqual(self, *a, **k):
        return self.assertEquals(*a, **k)

    def assertElementsEqual(self, real, correct, msg=None):
        "test that two objects have same set of elements"
        real = set(real)
        correct = set(correct)
        msg = self._format_msg(msg, "got %r, expected would have same elements as %r", sorted(real), sorted(correct))
        return self.assert_(real == correct, msg)
    assert_sets_equal = assertElementsEqual #deprecated
    assert_same_set = assertElementsEqual #preferred

    def assert_same_order(self, real, correct, msg=None):
        "test that two objects are sequences w/ same elements in same order"
        real = list(real)
        correct = list(correct)
        msg = self._format_msg(msg, "got %r, expected would have same elements, in same order, as %r", real, correct)
        return self.assert_(real == correct, msg)

    def assertNotEquals(self, real, correct, msg=None):
        #NOTE: overriding this to get msg formatting capability
        msg = self._format_msg(msg, "got %r, expected would equal %r", real, correct)
        return self.assert_(real != correct, msg)
##    assert_not_equals = assertNotEquals

    def assertNotEqual(self, *a, **k):
        return self.assertNotEquals(*a, **k)

    def assertIs(self, real, correct, msg=None):
        msg = self._format_msg(msg, "got %r, expected would be %r", real, correct)
        return self.assert_(real is correct, msg)

    def assertIsNot(self, real, correct, msg=None):
        msg = self._format_msg(msg, "expected would not be %r", real)
        return self.assert_(real is not correct, msg)

    def assertIsInstance(self, obj, klass, msg=None):
        msg = self._format_msg(msg, "got %r, expected instance of %r", obj, klass)
        return self.assert_(isinstance(obj, klass), msg)

    def assertRaises(self, type, func, *args, **kwds):
        msg = kwds.pop("__msg__", None)
        err = None
        try:
            result = func(*args, **kwds)
        except Exception, err:
            pass
        if err is None:
            msg = self._format_msg(msg, "function returned %r, expected it to raise %r", result, type)
            raise AssertionError(msg)
        elif not isinstance(err, type):
            msg = self._format_msg(msg, "function raised %r, expected %r", err, type)
            raise AssertionError(msg)

    def assertAttrRaises(self, excClass, obj, attr):
        #XXX: default msg?
        self.assertRaises(excClass, getattr, obj, attr)

    def assertWarningEquals(self, warning, **kwds):
        "check if WarningMessage instance matches parameters"
        for key in ("message", "category", "filename", "lineno", "file", "line"):
            if key not in kwds:
                continue
            real = getattr(warning, key)
            if key == "message":
                real = str(real) #usually a UserWarning(value), etc
            value = kwds[key]
            if key == "filename":
                if value.endswith(".pyc") or value.endswith(".pyo"):
                    value = value[:-1]
            if real != value:
                raise AssertionError("warning %s doesn't match pattern %r" % (warning, kwds))

    assert_warning = assertWarningEquals

    def check_function_results(self, func, cases):
        "helper for running through function call cases"
        #cases should be list of ak objects,
        #whose first element is the function's return value
        for elem in cases:
##            elem = Params.normalize(elem)
            correct = elem.args[0]
            result = func(*elem.args[1:], **elem.kwds)
            self.assertEqual(result, correct,
                    "error for case %s: got %r, expected would equal %r" % (elem.render(1), result, correct)
                    )

    def check_function_rtype(self, func, retval=None, rtype=None, ordered=False):
        """helper for testing functions that allow return type to be specified via rtype kwd.

        :arg func: function (w/ parameters bound via partial)
        :arg retval: expected result (can be set, list, etc)
        :arg rtype: default rtype
        :param ordered: if order must match retval when rtype is ordered
        """
        #NOTE: 'self' should be test case
        has_retval = (retval is not None)

        #check default rtype is correct
        result = func()
        if rtype is None:
            pass
        elif rtype is iter:
            self.assert_(is_iter(result))
        else:
            self.assertIsInstance(result, rtype)
        if has_retval:
            if ordered and (is_oseq(result) or is_iter(result)):
                self.assert_same_order(result, retval)
            else:
                self.assert_same_set(result, retval)

        #check unordered types work
        for t in (set, frozenset):
            result = func(rtype=t)
            self.assertIsInstance(result,t)
            if has_retval:
                self.assert_same_set(result, retval)

        #check ordered types work
        for t in (list, tuple):
            result = func(rtype=t)
            self.assertIsInstance(result,t)
            if has_retval:
                if ordered:
                    self.assert_same_order(result, retval)
                else:
                    self.assert_same_set(result, retval)

        #check rtype=iter works
        result = func(rtype=iter)
        self.assert_(is_iter(result))
        if has_retval:
            if ordered:
                self.assert_same_order(result, retval)
            else:
                self.assert_same_set(result, retval)

    def _format_msg(self, msg, template, *args, **kwds):
        if msg and not msg.endswith(":"):
            return msg
        if args:
            template %= args
        if kwds:
            template %= kwds
        if msg:
            return msg + " " + template
        return template

#=========================================================
#helper funcs
#=========================================================

def enable_suite(name):
    """check if a given test should be included based on the env var.

    test flags:
        bcrypt          enable basic bcrypt tests
        slow_bcrypt     enable extra check for slow bcrypt implementation
        pwgen_dups      enable duplication rate checks for pwgen
    """
    _flags = [ v.strip()
              for v
              in os.environ.get("BPS_TEST_SUITE", "").lower().split(",")
              ]
    if 'all' in _flags:
        return True
    if name in _flags:
        return True
    return False

#=========================================================
#python backports
#=========================================================

#this was copied from the python 2.6.2 warnings.py file,
#so it would always be available for unit-tests
try:
    from warnings import catch_warnings, WarningMessage
except ImportError:
    class WarningMessage(object):

        """Holds the result of a single showwarning() call."""

        _WARNING_DETAILS = ("message", "category", "filename", "lineno", "file",
                            "line")

        def __init__(self, message, category, filename, lineno, file=None,
                        line=None):
            local_values = locals()
            for attr in self._WARNING_DETAILS:
                setattr(self, attr, local_values[attr])
            self._category_name = category.__name__ if category else None

        def __str__(self):
            return ("{message : %r, category : %r, filename : %r, lineno : %s, "
                        "line : %r}" % (self.message, self._category_name,
                                        self.filename, self.lineno, self.line))

    class catch_warnings(object):

        """A context manager that copies and restores the warnings filter upon
        exiting the context.

        The 'record' argument specifies whether warnings should be captured by a
        custom implementation of warnings.showwarning() and be appended to a list
        returned by the context manager. Otherwise None is returned by the context
        manager. The objects appended to the list are arguments whose attributes
        mirror the arguments to showwarning().

        The 'module' argument is to specify an alternative module to the module
        named 'warnings' and imported under that name. This argument is only useful
        when testing the warnings module itself.

        """

        def __init__(self, record=False, module=None):
            """Specify whether to record warnings and if an alternative module
            should be used other than sys.modules['warnings'].

            For compatibility with Python 3.0, please consider all arguments to be
            keyword-only.

            """
            self._record = record
            self._module = sys.modules['warnings'] if module is None else module
            self._entered = False

        def __repr__(self):
            args = []
            if self._record:
                args.append("record=True")
            if self._module is not sys.modules['warnings']:
                args.append("module=%r" % self._module)
            name = type(self).__name__
            return "%s(%s)" % (name, ", ".join(args))

        def __enter__(self):
            if self._entered:
                raise RuntimeError("Cannot enter %r twice" % self)
            self._entered = True
            self._filters = self._module.filters
            self._module.filters = self._filters[:]
            self._showwarning = self._module.showwarning
            if self._record:
                log = []
                def showwarning(*args, **kwargs):
                    log.append(WarningMessage(*args, **kwargs))
                self._module.showwarning = showwarning
                return log
            else:
                return None

        def __exit__(self, *exc_info):
            if not self._entered:
                raise RuntimeError("Cannot exit %r without entering first" % self)
            self._module.filters = self._filters
            self._module.showwarning = self._showwarning

class catch_all_warnings(catch_warnings):
    "wrap which ensures all warnings are logged to buffer"
    def __init__(self):
        self.__super = super(catch_all_warnings,self)
        self.__super.__init__(record=True)
    def __enter__(self):
        log = self.__super.__enter__()
        warnings.filterwarnings("always")
        return log

#=========================================================
#capture logging output
#=========================================================

class capture_logger(object):
    "capture output of logger, returning StringIO buffer output is written to"

    def __init__(self, name=""):
        self.log = getLogger(name)

    def __enter__(self):
        #remove handlers but don't delete them (we'll restore later)
        self.propagate = self.log.propagate
        self.handlers = purge_handlers(self.log, close=False)

        #create new handler
        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        handler.formatter = logging.Formatter("%(name)s: %(levelname)s: %(message)s")
        self.log.addHandler(handler)
        self.log.propagate = False
        return buffer

    def __exit__(self, *exc_info):
        #remove handler we added
        purge_handlers(self.log)

        #restore original list of handlers
        self.log.handlers[:] = self.handlers
        self.log.propagate = self.propagate

#=========================================================
#EOF
#=========================================================
