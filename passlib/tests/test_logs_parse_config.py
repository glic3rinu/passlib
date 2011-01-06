"""
bps.logs.config unittest script -- (c) Assurance Technologies 2003-2006
defines unit tests for the parsing half of bps's logging config handling
"""
from __future__ import with_statement
#=========================================================
#imports
#=========================================================
import logging
import warnings
import sys
from bps.fs import filepath
from bps.logs import config
from bps.meta import Params
ak = Params
from bps.logs.config import LoggingConfig
from bps.tests.utils import TestCase, catch_warnings, capture_logger
from bps.error.types import MissingPathError, InputError

#=========================================================
#
#=========================================================
class HelperTest(TestCase):

    def test_parse_output_value(self):
        self.check_function_results(config.parse_output_value, [
            ak(dict(outputs=[]),                            ""),
            ak(dict(outputs=[]),                            ",|"),
            ak(dict(outputs=['a', 'b']),                    "a,b"),
            ak(dict(outputs=['a', 'b'], add=True),          "a,b|add=True"),
            ak(dict(outputs=['a', 'b'], propagate=True),    "a,b|propagate=True"),
            ak(dict(outputs=['a', 'b'], propagate=False),   "a,b|propagate=False"),
        ])

    def test_parse_dict_string(self):
        self.check_function_results(config.parse_dict_string, [
            ak(dict(a="1", b="2"),          "a=1;b=2", ";"),
            ak(dict(a="1", d="2"),          "a=1 #blah\nd=2\n\n\n#blah","\n", strip_comments=True),
            ak(dict(a="1", b="2"),          "a=1,b=2", ","),
            ak(dict(a="1", b="2 #comment"), "  a=1 , b  = 2 #comment", ","),
            ak(dict(a="1", b="2; 3=4"),     "a=  1,b  =  2; 3=4", ","),
        ])
        self.assertRaises(ValueError, config.parse_dict_string, "a=1 #blah\nd=2\n\n\n#blah","\n")
            #ValueError: unexpected element in string
            #   caused by "#blah" element

    def test_splitcomma(self):
        self.check_function_results(config.splitcomma, [
            ak(['a', 'b'],              "a,b"),
            ak(['a', 'b'],              "a, b"),
            ak(['a', 'b'],              " a, b"),
            ak(['a', 'b'],              "a,, b ,,, , , , "),
            ak(['a', 'b'],              "a,, \n b ,,, , , , "),
            ak(['a', 'b', ';'],         "a,, \n b ,,, ; , , , "),
        ])

#=========================================================
#parsing tests
#=========================================================
class ParseConfigTest(TestCase):

    #=========================================================
    #test failures
    #=========================================================
    def test_missing_file(self):
        "test parse_config()'s missing file behavior"

        #test file-not-found w/ errors='log'
        path = self.sample1_path + "_file_does_not_exist.ini"
        with capture_logger("bps.logs.config") as logbuf:
            result = config.parse_config(path)
        self.assertIs(result, None)
        self.assertEqual(logbuf.getvalue(), """\
bps.logs.config: ERROR: config file not found: filename=%r
""" % path)

        #test file-not-found w/ errors='raise'
        self.assertRaises(MissingPathError, config.parse_config, path, errors="raise")
            #error: no such file or directory

    def test_empty_data(self):

        with capture_logger("bps.logs.config") as logbuf:
            result = config.parse_config("\n")
        self.assertIs(result, None)
        self.assertEqual(logbuf.getvalue(), """\
bps.logs.config: WARNING: couldn't determine logging config format: stype='raw'
""")

        self.assertRaises(InputError, config.parse_config, "", errors="raise")

    #=========================================================
    #samples
    #=========================================================
    sample1 = r"""[logging:options]
capture_warnings = True
warning_fmt = %(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s
reset_loggers = True
not_an_option = ignored options should be ignored

[logging:levels]
<root> = WARNING
"""
    sample1_path = filepath(__file__, "..", "_logs_parse_config_sample1.ini").abspath

    def test_sample1(self, data=None):
        """test small compact-ini sample"""
        if data is None:
            data = self.sample1

        #check it parses correctly (and emits warning about not_an_option)
        with catch_warnings(record=True) as log:
            warnings.filterwarnings("always")
            c = config.parse_config(data)
        self.assertEquals(len(log), 1)
        self.assertWarningEquals(log[0],
                message="unknown logging:options key encountered: 'not_an_option'",
                filename=__file__,
                )

        self.assertConfigEquals(c, dict(
            loggers={"":dict(level=30)},
            options=dict(
                capture_warnings=True,
                reset_loggers=True,
                warning_fmt='%(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s'
                ),
            ))

        #examine w/ readers
        self.assert_(c.get_option("capture_warnings"))
        self.assert_(c.get_option("reset_loggers"))
        self.assert_(c.get_option("reset_handlers"))

        #change it
        c.set_level('x', "DEBUG")
        c.set_level('y', "NotSET")
        del c.options['reset_loggers']

        #try reparsing
        c2 = config.parse_config(c)

        #should be diff objects
        assert c2 is not c
        assert c2.loggers is not c.loggers

        #but values should have parsed properly
        self.assertConfigEquals(c2, dict(
            loggers={"":dict(level=30), "x":dict(level=10), "y":dict(level=0)},
            options=dict(
                capture_warnings=True,
                warning_fmt='%(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s'
                ),
            ))

        #examine w/ readers
        self.assert_(c.get_option("capture_warnings"))
        self.assert_(not c.get_option("reset_loggers"))
        self.assert_(not c.get_option("reset_handlers"))

    def test_sample1a(self):
        self.test_sample1(self.sample1_path)

    #------------------------------------------------
    #
    #------------------------------------------------
    def test_sample2(self):
        "test large compact-ini sample"
        data = r"""

[logging:options]
capture_stdout = false
capture_warnings = true
warning_fmt = %(category)s: %(message)s

[logging:levels]
<root> = INFO
myapp = DEBUG
pylons = WARNING

[logging:output]
<root> = console | add=True

[logging:outputs]
myapp = syslog | propagate=False
mylib = syslog

[logging:handler:console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic
startup_msg = True

[logging:handler:syslog]
class=handlers.SysLogHandler
level=ERROR
formatter=generic
args=(('localhost', handlers.SYSLOG_UDP_PORT), handlers.SysLogHandler.LOG_USER)

[logging:handler:syslog2]
class=handlers.SysLogHandler
level=ERROR
formatter=generic
args=(('localhost', handlers.SYSLOG_UDP_PORT), level=handlers.SysLogHandler.LOG_USER)

[logging:formatter:generic]
format = %(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s
datefmt =    %H:%M:%S #simple date format

"""
        #check it parses correctly
        with catch_warnings(record=True) as log:
            warnings.filterwarnings("always")
            c = config.parse_config(data)
        self.assertEquals(len(log), 1)
        self.assertWarningEquals(log[0],
                message=r"'logging:output' is deprecated, use 'logging:outputs' instead",
                filename=__file__,
                )

        self.assertConfigEquals(c, dict(
            loggers={
                "": dict(level=20,
                        outputs=['console'],
                        add=True,
                        propagate=True,
                    ),
                "myapp": dict(
                        level=10,
                        outputs=['syslog'],
                        propagate=False,
                    ),
                'pylons': dict(level=30),
                'mylib': dict(
                        outputs=['syslog'],
                        propagate=True,
                ),
                },
            formatters={
                "generic": dict(
                    format="%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s",
                    datefmt="%H:%M:%S #simple date format",
                    ),
                },
            handlers={
                "console": dict(
                    klass=logging.StreamHandler,
                    args=Params(sys.stderr),
                    level="NOTSET",
                    formatter="generic",
                    startup_msg=True,
                    ),
                "syslog": dict(
                    klass=logging.handlers.SysLogHandler,
                    level="ERROR",
                    formatter="generic",
                    args=Params(('localhost', logging.handlers.SYSLOG_UDP_PORT), logging.handlers.SysLogHandler.LOG_USER),
                    ),
                "syslog2": dict(
                    klass=logging.handlers.SysLogHandler,
                    level="ERROR",
                    formatter="generic",
                    args=Params(('localhost', logging.handlers.SYSLOG_UDP_PORT),
                            level=logging.handlers.SysLogHandler.LOG_USER
                            ),
                    ),
                },
            options=dict(
                capture_warnings=True,
                capture_stdout=False,
                warning_fmt='%(category)s: %(message)s',
                ),
            ))

    #------------------------------------------------
    #
    #------------------------------------------------
    def test_sample3(self):
        "test large stdlib-ini sample"
        data = r"""

[loggers]
keys=root,my_app,mylib,pylons

[handlers]
keys=console,syslog

[formatters]
keys=generic

[logger_root]
level = INFO
handlers = console

[logger_my_app]
level = DEBUG
qualname=myapp
handlers = syslog
propagate = 0

[logger_mylib]
handlers = syslog
qualname = mylib

[logger_pylons]
level = WARNING
qualname = pylons

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic
startup_msg = True

[handler_syslog]
class=handlers.SysLogHandler
level=ERROR
formatter=generic
args=(('localhost', handlers.SYSLOG_UDP_PORT), handlers.SysLogHandler.LOG_USER)

[formatter_generic]
format = %(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s
datefmt =    %H:%M:%S #simple date format

"""
        #check it parses correctly
        c = config.parse_config(data)
        self.assertConfigEquals(c, dict(
            loggers={
                "": dict(level=20,
                        outputs=['console'],
                    ),
                "myapp": dict(
                        level=10,
                        outputs=['syslog'],
                        propagate=False,
                    ),
                'pylons': dict(level=30, outputs=[], propagate=True),
                'mylib': dict(
                        outputs=['syslog'],
                        propagate=True,
                ),
                },
            formatters={
                "generic": dict(
                    format="%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s",
                    datefmt="%H:%M:%S #simple date format",
                    ),
                },
            handlers={
                "console": dict(
                    klass=logging.StreamHandler,
                    args=Params(sys.stderr),
                    level="NOTSET",
                    formatter="generic",
                    ),
                "syslog": dict(
                    klass=logging.handlers.SysLogHandler,
                    level="ERROR",
                    formatter="generic",
                    args=Params(('localhost', logging.handlers.SYSLOG_UDP_PORT), logging.handlers.SysLogHandler.LOG_USER),
                    ),
                },
            options=dict(disable_existing_loggers=True),
            ))

    #------------------------------------------------
    #
    #------------------------------------------------
    def test_sample4(self):
        data = dict(
            levels="<root>=WARNING; myapp=DEBUG",
            capture_warnings=True,
            warning_fmt='%(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s',
            default_handler="console",
        )

        #check it parses correctly
        c = config.parse_config(**data)
        self.assertConfigEquals(c, dict(
            loggers={"":dict(level=30, outputs=['console']),  "myapp": dict(level=10)},
            options=dict(
                capture_warnings=True,
                warning_fmt='%(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s',
                ),
            ))

    #------------------------------------------------
    #
    #------------------------------------------------
    def test_sample5(self):
        data = dict(
            levels="<root>=WARNING #my comment \n #another comment \n myapp=DEBUG",
            capture_warnings=True,
            warning_fmt='%(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s',
            default_handler=dict(klass=logging.StreamHandler),
            handlers=dict(
                console=dict(
                    klass='StreamHandler',
                    args='sys.stderr,',
                    level="NOTSET",
                    formatter="generic",
                    startup_msg=True,
                ),
##                console="""
##class = StreamHandler
##args = (sys.stderr,)
##level = NOTSET
##formatter = generic
##startup_msg = True
##""",
                syslog=dict(
                 klass="handlers.SysLogHandler",
                 level="ERROR",
                 formatter="generic",
                args=(('localhost', logging.handlers.SYSLOG_UDP_PORT), logging.handlers.SysLogHandler.LOG_USER),
                ),
            ),
            formatters=dict(
                generic=dict(
                    format="%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s",
                    datefmt="%H:%M:%S",
                    ),
##                generic="""
##format = %(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s
##datefmt =    %H:%M:%S
##""",
                alt=dict(
                    fmt = "%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s",
                    datefmt = "%H:%M:%S",
                )
            )
        )

        #check it parses correctly
        c = config.parse_config(**data)
        self.assertConfigEquals(c, dict(
            loggers={
              "":dict(level=30, outputs=[LoggingConfig.DEFAULT_HANDLER_NAME]),
              "myapp":dict(level=10),
            },
            options=dict(
                capture_warnings=True,
                warning_fmt='%(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s',
            ),
            handlers={
                LoggingConfig.DEFAULT_HANDLER_NAME: {"klass": logging.StreamHandler},
                "console": dict(
                    klass=logging.StreamHandler,
                    args=Params(sys.stderr,),
                    level="NOTSET",
                    formatter="generic",
                    startup_msg=True,
                    ),
                "syslog": dict(
                    klass=logging.handlers.SysLogHandler,
                    level="ERROR",
                    formatter="generic",
                    args=Params(('localhost', logging.handlers.SYSLOG_UDP_PORT), logging.handlers.SysLogHandler.LOG_USER),
                    ),
            },
            formatters={
                "generic": dict(
                    format="%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s",
                    datefmt="%H:%M:%S",
                    ),
                "alt": dict(
                    fmt="%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s",
                    datefmt="%H:%M:%S",
                    ),
                },
            ))

    #------------------------------------------------
    #
    #------------------------------------------------
    def test_sample6(self):
        name = __name__ + ".test_logger"
        buffer = sys.stderr
        c = config.parse_config(
            levels={name:"WARNING"},
            outputs={name: dict(handlers=['custom'], propagate=False)},
            handlers=dict(custom=dict(klass='StreamHandler', args=(buffer,), formatter='custom')),
            formatters=dict(custom=dict(format="%(name)s: %(levelname)s: %(message)s")),
            )

        self.assertConfigEquals(c, dict(
            loggers={
                name: dict(
                    level=30,
                    outputs=['custom'],
                    propagate=False,
                    )
            },
            handlers=dict(
                custom=dict(
                    klass=logging.StreamHandler,
                    args=Params(buffer),
                    formatter='custom',
                    ),
            ),
            formatters=dict(
                custom=dict(
                    format="%(name)s: %(levelname)s: %(message)s"
                    ),
            ),
        ))

    #=========================================================
    #helpers
    #=========================================================
    def assertConfigEquals(self, config, test):
        assert isinstance(config, LoggingConfig)
        for k in ("options", "loggers", "formatters", "handlers"):
            msg = k + ":"
            real = getattr(config, k)
            correct = test.setdefault(k, {})
            if real == correct:
                continue
            if set(real.keys()) != set(correct.keys()):
                self.assertEqual(real, correct, msg) #force error
            for sk in real:
                left = real.get(sk)
                right = correct.get(sk)
                if left != right:
                    self.assertEqual(left, right, "%s[%r]:" % (k, sk, ))
            raise RuntimeError

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
