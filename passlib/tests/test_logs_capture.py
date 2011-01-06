"""
bps.logs.capture unittest script -- (c) Assurance Technologies 2003-2006
defines unit tests for bps's stdio redirection package
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os
import sys
from logging import getLogger
import logging
from cStringIO import StringIO
from warnings import warn
import warnings
#site
#pkg
from bps.fs import filepath
from bps.logs import config as lc, handlers as lh, capture as cp, config_logging, add_handler
from bps.logs.handlers import WatchedFileHandler, purge_handlers
from bps.error import types as errors
#lib
from bps.tests.utils import get_tmp_path as get_tmp_file, TestCase
#module
log = getLogger(__name__)

#=========================================================
#capture tests
#=========================================================
class _StdCaptureTest(TestCase):
    name = None

    def setUp(self):
        #make sure capturing was never on
        orig_stream, cp_proxy, cp_orig = self.get3()
        if cp_orig:
            raise RuntimeError, "stream capturing has been enabled by test harness"
        if cp_proxy:
            #code doesn't want this cleared normally, but we do
            setattr(cp, "_proxy_" + self.name, None)

        #setup the logger & a buffer for it
        self.log = getLogger("sys." + self.name)
        self.log.propagate = 0
        purge_handlers(self.log)
        self.log.setLevel(1)
        self.log_buffer = StringIO()
        h = logging.StreamHandler(self.log_buffer)
        h.formatter = logging.Formatter("[%(name)s %(levelname)s] %(message)s")
        self.raw_prefix = "[sys.%s RAW] " % self.name
        self.debug_prefix = "[sys.%s DEBUG] " % self.name
        self.log.addHandler(h)

        #intercept sys stream
        self.orig_stream = self.get()
        self.buffer = StringIO()
        self.set(self.buffer)

    def tearDown(self):
        purge_handlers(self.log)
        self.set(self.orig_stream)

    def get(self):
        return getattr(sys, self.name)

    def get3(self):
        return self.get(), getattr(cp, "_proxy_" + self.name), getattr(cp, "_orig_" + self.name)

    def set(self, value):
        setattr(sys, self.name, value)

    def test_logger(self):
        "test that basic logger setup works"
        self.check_empty()
        self.log.debug("TESTING")
        self.check_and_empty("", self.debug_prefix + "TESTING\n")

    def test_capture_release(self):
        "test capture/release cycle with some writing"
        #test capture & write
        self.capture(True)
        self.wt()

        #test release & write
        self.release()
        self.wt2()

        #test re-capturing & write
        self.capture(False)
        self.wt()

        #release
        self.release()

    def capture(self, first):
        "enable capturing"
        #check it's not being captured
        self.assert_(not getattr(cp, "check_" + self.name)())

        #verify buffers
        c, p, o = self.get3()
        self.assertEqual(c, self.buffer)
        if first:
            self.assertEqual(p, None)
        else:
            self.assertTrue(isinstance(p, cp.StreamWrapper))
            self.assertEqual(p.name, "sys." + self.name)
        self.assertEqual(o, None)

        #enable capturing
        config_logging(**{"capture_" + self.name: True})

        #check it's being captured
        self.assert_(getattr(cp, "check_" + self.name)())

        #recheck streams
        c, p, o = self.get3()
        self.assertEqual(c, p)
        self.assertTrue(isinstance(p, cp.StreamWrapper))
        self.assertEqual(o, self.buffer)

    def release(self):
        "release capturing"
        #check it's being captured
        self.assert_(getattr(cp, "check_" + self.name)())

        #check streams
        c, p, o = self.get3()
        self.assertEqual(c, p)
        self.assertTrue(isinstance(p, cp.StreamWrapper))
        self.assertEqual(o, self.buffer)

        #release streams
        config_logging(**{"capture_" + self.name: False})

        #check release
        self.assert_(not getattr(cp, "check_" + self.name)())

        #check buffers
        c, p, o = self.get3()
        self.assertEqual(c, self.buffer)
        self.assertTrue(isinstance(p, cp.StreamWrapper))
        self.assertEqual(o, None)

    def wt(self):
        "test that writes are being captured"
        buf = self.get() #stdout, using proxy
        self.check_empty()

        #try a flushed write...
        buf.write("ABCDEF\n")
        cp.flush_buffers()
        self.check_and_empty("", self.raw_prefix + "unmanaged logging output:\nABCDEF\n\n\n")

        #try a flush forced by logging
        buf.write("QRSTVUVE\n")
        self.log.debug("XXX")
        self.check_and_empty("", self.raw_prefix +
            "unmanaged logging output:\nQRSTVUVE\n\n\n" + self.debug_prefix + "XXX\n")

    def wt2(self):
        "test that we're writing to buffer, not being captured"
        self.check_empty()
        self.get().write("ABC\n")
        self.check_and_empty("ABC\n", "")

    def check_and_empty(self, buffer, log_buffer):
        self.assertEqual(self.buffer.getvalue(), buffer)
        if buffer:
            self.buffer.reset(); self.buffer.truncate()

        self.assertEqual(self.log_buffer.getvalue(), log_buffer)
        if log_buffer:
            self.log_buffer.reset(); self.log_buffer.truncate()

        self.check_empty()

    def check_empty(self):
        self.assertEqual(self.buffer.getvalue(), "")
        self.assertEqual(self.log_buffer.getvalue(), "")

class StdOutCaptureTest(_StdCaptureTest):
    _prefix = "capture stdout"
    name = "stdout"

class StdErrCaptureTest(_StdCaptureTest):
    _prefix = "capture stderr"
    name = "stderr"

class WarningCaptureTest(TestCase):
    _prefix = "capture warnings"

    def setUp(self):
        if cp._orig_showwarning:
            raise RuntimeError, "capture warnings enabled"
        self.orig_stderr = sys.stderr
        self.orig_format = warnings.formatwarning
        def fmt(message, category, filename, lineno, line=None):
            filename = filepath(filename)
            return "[%s %s] %s" % (filename.root, category.__name__, message)
        warnings.formatwarning = fmt

        sys.stderr = self.err_buffer = StringIO()

        #setup the logger & a buffer for it
        self.log_buffer = StringIO()
        self.log = getLogger("sys.warnings")
        self.log.setLevel(1)
        add_handler(self.log.name,
            klass='StreamHandler',
            args=(self.log_buffer,),
            formatter=dict(fmt="[%(name)s %(levelname)s] %(message)s"),
            propagate=False, add=False,
        )
##        self.log.propagate = 0
##        purge_handlers(self.log)
##        h = logging.StreamHandler(self.log_buffer)
##        h.formatter = logging.Formatter("[%(name)s %(levelname)s] %(message)s")
##        self.log.addHandler(h)

        self.warning_path = filepath(__file__).abspath

    def tearDown(self):
        sys.stderr = self.orig_stderr
        warnings.formatwarning = self.orig_format
        cp.release_warnings()
        purge_handlers(self.log)

    def test_logger(self):
        "test basic logger behavior"
        self.check_empty()
        self.log.debug("TESTING")
        self.check_and_empty("", "[sys.warnings DEBUG] TESTING\n")

    def test_capture_release(self):
        modname = __name__.rsplit(".", 1)[1]
        wp = "[" + modname + " UserWarning] "
        lp = "[sys.warnings WARNING] UserWarning:\n\tmessage: "

        #check before capture
        self.check_empty()
        warn("XXX YYY")
        self.check_and_empty(wp + "XXX YYY", "")

        #check w/ capture
        self.capture()
        warn("ABDDEF")
        self.check_and_empty("", lp + "ABDDEF\n")

        #check after release
        self.release()
        warn("QRSIUT")
        self.check_and_empty(wp + "QRSIUT", "")

        #check re-capture
        self.capture()
        warn("ASIDUAASDADS")
        self.check_and_empty("",lp + "ASIDUAASDADS\n")

        #check re-release
        self.release()
        warn("XXXXXXX")
        self.check_and_empty(wp + "XXXXXXX", "")

    def capture(self):
        self.assert_(not cp.check_warnings())
        self.check_empty()
        self.assertEqual(cp._orig_showwarning, None)
        config_logging(
            capture_warnings=True,
            warning_target="sys.warnings",  #override normal redirection so we see it
            warning_fmt = "%(category)s:\n\tmessage: %(message)s" #override normal format so we can test for it
            )
        self.assert_(cp.check_warnings())
        self.assertNotEqual(cp._orig_showwarning, None)
        self.check_empty()

    def release(self):
        self.assert_(cp.check_warnings())
        self.check_empty()
        self.assertNotEqual(cp._orig_showwarning, None)
        config_logging(
            capture_warnings=False,
            )
        self.assertEqual(cp._orig_showwarning, None)
        self.check_empty()
        self.assert_(not cp.check_warnings())

    def check_and_empty(self, err_buffer, buffer):
        self.assertEqual(self.log_buffer.getvalue(), buffer, "capture buffer:")
        if buffer:
            self.log_buffer.reset(); self.log_buffer.truncate()

        self.assertEqual(self.err_buffer.getvalue(), err_buffer, "stderr buffer:")
        if err_buffer:
            self.err_buffer.reset(); self.err_buffer.truncate()
        self.check_empty()

    def check_empty(self):
        self.assertEqual(self.log_buffer.getvalue(), "", "capture buffer:")
        self.assertEqual(self.err_buffer.getvalue(), "", "stderr buffer:")

#=========================================================
#EOF
#=========================================================
