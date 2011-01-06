"""helpers for bps unittests"""
#=========================================================
#imports
#=========================================================
#core
import os
import unittest
import logging; log = logging.getLogger(__name__)
#pkg
#local
__all__ = [
    'TestCase',
    'Param',
    'enable_suite',
]

#=========================================================
#helper for assertFunctionResults() method
#=========================================================
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
    """passlib-specific test case class
    
    this class mainly overriddes many of the common assert methods
    so to give a default message which includes the values
    as well as the class-specific message_prefix string.
    this latter bit makes the output of various test cases
    easier to distinguish from eachother.    
    """

    message_prefix = None

    def __init__(self, *a, **k):
        #set the doc strings for all test messages to begin w/ message_prefix
        #yes, this is incredibly hacked.
        prefix = self.message_prefix
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
    
    def assertEqual(self, *a, **k):
        return self.assertEquals(*a, **k)

    def assertNotEquals(self, real, correct, msg=None):
        #NOTE: overriding this to get msg formatting capability
        msg = self._format_msg(msg, "got %r, expected would equal %r", real, correct)
        return self.assert_(real != correct, msg)

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

    def assertFunctionResults(self, func, cases):
        """helper for running through function calls.
        
        func should be the function to call.
        cases should be list of Param instances,
        where first position argument is expected return value,
        and remaining args and kwds are passed to function.
        """
        for elem in cases:
            correct = elem.args[0]
            result = func(*elem.args[1:], **elem.kwds)
            self.assertEqual(result, correct,
                    "error for case %s: got %r, expected would equal %r" % (elem.render(1), result, correct)
                    )

    def _format_msg(self, msg, template, *args, **kwds):
        "helper for generating default message"
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
#EOF
#=========================================================
