"""
bps.logs unittest script -- (c) Assurance Technologies 2003-2006
defines unit tests for bps's logging package
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os
import sys
import logging
from cStringIO import StringIO
from warnings import warn
import warnings
#site
#pkg
from bps.fs import filepath
from bps.logs import config as lc, handlers as lh, capture as cp, config_logging, add_handler
from bps.logs.loggers import get_logger, parse_level_name, get_level_name
from bps.logs.handlers import WatchedFileHandler, purge_handlers
from bps.logs import proxy_logger
from bps.error import types as errors
#lib
from bps.tests.utils import ak, get_tmp_path as get_tmp_file, TestCase, capture_logger
#module

LS = os.linesep

#=========================================================
#utilities
#=========================================================
class HelperTest(TestCase):

    def test_get_logger(self):
        gl = logging.getLogger

        #test root
        root = gl()
        self.assertIs(get_logger(), root)
        self.assertIs(get_logger(None), root)
        self.assertIs(get_logger(""), root)
        self.assertIs(get_logger("<root>"), root)

        #test this mod
        self.assertIs(get_logger("bps"), gl("bps"))

        #test logger resolution
        l = gl("xxx")
        self.assertIs(get_logger(l), l)

    def test_parse_level_name(self):
        #test a few of the levels
        self.check_function_results(parse_level_name, [
            ak(0, "NOTSET"),
            ak(0, "notset"),
            ak(0, "0"),
            ak(0, 0),

            ak(30, "WARNING"),
            ak(30, "warning"),
            ak(30, "Warn"),
            ak(30, "30"),
            ak(30, 30),

            ak(99, "99"),
            ak(99, 99),
            ])

        self.assertRaises(ValueError, parse_level_name, "NotALevel")

    def test_get_level_name(self):
        self.check_function_results(get_level_name, [
            ak("NOTSET", "NOTSET"),
            ak("NOTSET", "notset"),
            ak("NOTSET", "0"),
            ak("NOTSET", 0),

            ak("WARNING", "WARNING"),
            ak("WARNING", "warning"),
            ak("WARNING", "Warn"),
            ak("WARNING", "30"),
            ak("WARNING", 30),

            ak("99", "99"),
            ak("99", 99),
            ])

        self.assertRaises(ValueError, get_level_name, "NotALevel")

#=========================================================
#handler tests (startup_msg etc)
#=========================================================

#---------------------------------------------------
#watched file handler
#---------------------------------------------------
class WatchedFileHandlerTest(TestCase):
    "test WatchFileHandler"
    def setUp(self):
        #get logger, ensure it's free of handlers, and that it will log debug msgs
        self.log = get_logger(__name__ + ".LogsTest.test_file_handler")
        purge_handlers(self.log)
        self.log.setLevel(1)
        #get a tmp file path to work with
        self.path = get_tmp_file()

    def tearDown(self):
        purge_handlers(self.log, close=True)

    def test_logging(self):
        #NOTE: only because we're reading a file create in 'w' mode
        # do we have to care about os.linesep (aka global var LS).
        # the rest of the logging system uses \n.

        #make sure file is created after handler
        h = lh.WatchedFileHandler(self.path)

        self.assertTrue(self.path.exists, "log path missing")
        self.assertEquals(self.path.get(), "", "log path not empty")

        self.log.addHandler(h)

        #make sure lines are flushed immediately
        self.log.debug("AAA")
        self.assertEqual(self.path.get(), "AAA" + LS)

        self.log.debug("BBB\n")
        self.assertEqual(self.path.get(), "AAA" + LS + "BBB" + LS + LS)

        #try truncating file
        s = h.stream
        self.path.set("")
        self.log.debug("CCC\n")
        self.assertNotEqual(h.stream, s, "handler didn't reopen stream")
        self.assertEqual(self.path.get(), "CCC" + LS + LS)

        #try deleting file
        if os.name == "nt":
            #under windows, handler's lock prevents removal
            self.assertRaises(errors.PathInUseError, self.path.remove)
            h.stream.close()
        self.path.remove()
        s = h.stream
        self.log.debug("QQQ\n")
        self.assertNotEqual(h.stream, s, "handler didn't reopen stream")
        self.assertEqual(self.path.get(), "QQQ" + LS + LS)

        #try moving file
        p2 = get_tmp_file()
        assert p2.ismissing
        if os.name == "nt":
            #under windows, handler's lock prevents moving it
            self.assertRaises(errors.PathInUseError, self.path.move_to, p2)
            h.stream.close()
        assert p2.ismissing #todo: perm glitch in move_to's try/except of os.rename allowing p2 to exist after failed move
        self.path.move_to(p2)
        self.assertTrue(self.path.ismissing, "path not moved")
        self.assertEqual(p2.get(), "QQQ" + LS + LS, "move mismatch")

        #check for reopen
        s = h.stream
        self.log.debug("SSS")
        self.assertNotEqual(h.stream, s, "handler didn't reopen stream")
        self.assertEqual(p2.get(), "QQQ" + LS + LS, "old path touched")
        self.assertEqual(self.path.get(), "SSS" + LS, "new path not written")

##    def test_single_shared(self):
##        h = lh.WatchFileHandler(self.path)
##        self.log.addHandler(h)
##
##    def test_single_solo(self):
##        h = lh.WatchFileHandler(self.path, shared=False)
##        self.log.addHandler(h)

##    def test_double_shared(self):
##        h1 = lh.WatchFileHandler(self.path)
##        self.log.addHandler(h1)
##
##        h2 = lh.WatchFileHandler(self.path)
##        self.log.addHandler(h2)
##
##    def test_double_solo(self):
##        h1 = lh.WatchFileHandler(self.path, shared=False)
##        self.log.addHandler(h1)
##
##        h2 = lh.WatchFileHandler(self.path, shared=False)
##        self.log.addHandler(h2)

#=========================================================
#formatter tests
#=========================================================

#=========================================================
#proxy tests
#=========================================================
mod_log = get_logger(__name__)
log = alog = proxy_logger.log
mlog = proxy_logger.multilog

class ProxyLoggerTest(TestCase):
    _prefix = "bps.logs.proxy_logger"

    def setUp(self):
        global log
        log = proxy_logger.log

    def test_00_vars(self):
        "verify initial state is correct"

        #test globals
        g = globals()
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], proxy_logger.log)
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

        #test base logger
        with capture_logger(__name__) as logbuf:
            mod_log.warning("this is a test")
        self.assertEqual(logbuf.getvalue(), "bps.tests.test_logs: WARNING: this is a test\n")

        #test nothing changed
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], proxy_logger.log)
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

    def test_01_alog(self):
        "test accessing log under alias"

        #test globals
        g = globals()
        g['log'] = None #just to check w/o target to replace
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], None)
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

        #test base logger
        with capture_logger(__name__) as logbuf:
            alog.warning("this is a test")
        self.assertEqual(logbuf.getvalue(), "bps.tests.test_logs: WARNING: this is a test\n")

        #test nothing changed
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], None) #should have still replaced itself
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

        #put log back
        g['log'] = proxy_logger.log

        #test base logger
        with capture_logger(__name__) as logbuf:
            alog.warning("this is a test")
        self.assertEqual(logbuf.getvalue(), "bps.tests.test_logs: WARNING: this is a test\n")

        #test log replaced itself
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], get_logger(__name__)) #should have still replaced itself
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

    def test_02_alog(self):
        "test accessing log with replacment behavior"

        #test globals
        g = globals()
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], proxy_logger.log)
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

        #test base logger
        with capture_logger(__name__) as logbuf:
            log.warning("this is a test")
        self.assertEqual(logbuf.getvalue(), "bps.tests.test_logs: WARNING: this is a test\n")

        #test 'log' replaced itself
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], get_logger(__name__)) #should have replaced itself
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

    def test_03_mlog(self):
        "test accessing multilog"

        #test globals
        g = globals()
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], proxy_logger.log)
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

        #test base logger
        with capture_logger(__name__) as logbuf:
            mlog.warning("this is a test")
        self.assertEqual(logbuf.getvalue(), "bps.tests.test_logs: WARNING: this is a test\n")

        #test nothing changed
        self.assertIs(g['mod_log'], get_logger(__name__))
        self.assertIs(g['log'], proxy_logger.log) #should have replaced itself
        self.assertIs(g['alog'], proxy_logger.log)
        self.assertIs(g['mlog'], proxy_logger.multilog)

#=========================================================
#EOF
#=========================================================
