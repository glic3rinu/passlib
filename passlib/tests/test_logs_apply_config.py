"""
bps.logs.config unittest script -- (c) Assurance Technologies 2003-2006
defines unit tests for the execution half of bps's logging config handling
"""

#=========================================================
#imports
#=========================================================
#core
import logging
import warnings
import sys
import time
from cStringIO import StringIO
#pkg
from bps.error import types as errors
from bps.logs import config_logging
from bps.logs.loggers import get_logger
from bps.logs.config import LoggingConfig
from bps.logs.handlers import purge_handlers
from bps.meta import Params as ak
#lib
from bps.tests.utils import TestCase, get_tmp_path
#local

#=========================================================
#
#=========================================================

#=========================================================
#
#=========================================================
class ConfigTest(TestCase):

    def tearDown(self):
        #make sure to release any captures that were set
        config_logging(capture_stderr=False, capture_stdout=False, capture_warnings=False)

    def test_missing_file(self):
        "test config_logging() handles missing path"
        log_path = get_tmp_path()
        self.assert_(config_logging(log_path) is False)
        self.assertRaises(errors.MissingPathError, config_logging, log_path, errors="raise")

    def test_placeholder(self):
        "test reset_loggers doesn't choke on placeholders"
        #NOTE: this was an observed bug...
        # we reset once, add a logger which ensures a placeholder ('xxx') is created,
        # and then make sure reset_loggers doesn't choke on the placeholder.
        log_path = get_tmp_path()
        config_logging(
            reset_loggers=True,
            levels="xxx.yyy=DEBUG",
        )
        config_logging(
            reset_loggers=True,
        )

    def test_sample1(self):
        #configure logging system
        log_path = get_tmp_path()
        config_logging(
            level="WARNING",
            levels="bps.tests.test_logs_fake=DEBUG; bps.tests.test_logs=INFO",
            default_handler=dict(
                klass="FileHandler",
                args=(log_path, ),
                formatter="std-file",
                startup_msg=True,
            ),
            capture_stderr=True,
        )

##        h = logging.StreamHandler(self.log_buffer)
##        h.formatter = logging.Formatter("[%(name)s %(levelname)s] %(message)s")

        #log some messages
        cur = time.strftime("%Y-%m-%d %H:%M:%S")
        get_logger().warning("test message")
        get_logger("myapp").info("can't see me")
        get_logger("myapp").warning("can see me")
        get_logger("bps.tests.test_logs").debug("shouldn't display")
        get_logger("bps.tests.test_logs").info("should display")
        sys.stderr.write("hello stderr!\n")
        sys.stderr.flush()

        #detach the handler
        root = get_logger()
        for h in root.handlers[:]:
            if getattr(h, "baseFilename", None) == log_path:
                root.removeHandler(h)
                h.flush()
                h.close()

        #now check what was written
        self.assertEqual(log_path.get(), """\
[%(cur)s INF ] --- LOGGING STARTED %(cur)s ---
[%(cur)s WRN root] test message
[%(cur)s WRN myapp] can see me
[%(cur)s INF bps.tests.test_logs] should display
[%(cur)s RAW sys.stderr] unmanaged logging output:
   hello stderr!
   \n   \n\n""" % dict(cur=cur))

    def test_sample2(self):
        name = __name__ + ".test_logger"
        log = get_logger(name)
        log.setLevel(99)
        buffer = StringIO()
        #NOTE: this makes sure outputs:handlers works
        config_logging(
            levels={name:"WARNING"},
            outputs={name: dict(handlers=['custom'], propagate=False)},
            handlers=dict(custom=dict(klass='StreamHandler', args=(buffer,), formatter='custom')),
            formatters=dict(custom=dict(format="%(name)s: %(levelname)s: %(message)s")),
            )
        log.warning("test")
        self.assertEqual(buffer.getvalue(), name + ": WARNING: test\n")

    def test_sample3(self):
        name = __name__ + ".test_logger"
        log = get_logger(name)
        log.setLevel(99)
        buffer = StringIO()
        #NOTE: this makes sure outputs:handlers works
        config_logging(
            loggers={name: dict(level="WARNING", outputs=['custom'], propagate=False)},
            handlers=dict(custom=dict(klass='StreamHandler', args=(buffer,), formatter='custom')),
            formatters=dict(custom=dict(format="%(name)s: %(levelname)s: %(message)s")),
            )
        log.warning("test")
        self.assertEqual(buffer.getvalue(), name + ": WARNING: test\n")

#=========================================================
#eof
#=========================================================

"""

config logging use cases found in the wild...
=============================================

medicred
--------
logs.config_logging(path)
    medicred.cfg
    debug.cfg

logging.cfg files found in the wild...
======================================
[logging:levels]
##<root> = DEBUG
<root> = WARNING
##thumbs = DEBUG
##thumbs.common = DEBUG
thumbs.zoom = DEBUG

---------------
[logging:options]
capture_warnings = True
warning_fmt = %(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s

[logging:levels]
<root> = WARNING
------------
[medicred:debug]
site=cgmcn

[logging:levels]
<root> = WARNING
imports = DEBUG
bps3.base = DEBUG
##sqlalchemy.engine = INFO
##gwrap.windows.stack = DEBUG

##automigrate = DEBUG
medicred.migration = DEBUG
##uif.list_control = DEBUG
##gwrap.simple_dialogs.select_dialogs = DEBUG
uif.mailclient = DEBUG

gwrap.misc.simple_list_model = DEBUG

medicred.client.report_dialog = DEBUG
reporting = DEBUG

medicred.build_client = INFO
medicred.build_backend = INFO

"""
