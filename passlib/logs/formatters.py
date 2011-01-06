"""This module provides additional logging Formatter classes."""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import atexit
from cStringIO import StringIO
import sys
import os
import logging
from logging import getLogger,  Formatter
from time import time as get_time
import threading
#site
#pkg
from bps.cache import cached_method
from bps.logs.loggers import RAW
from bps.meta import is_class
from bps.error.utils import format_exception
#local
log = getLogger(__name__)
__all__ = [
    #formatter helper funcs
    'is_formatter',

    #custom formatters
    "FancyFormatter",
    "StdFormatter"
    "DevFormatter",
]

#=========================================================
#formatter factory, used by config_logging
#=========================================================
def is_formatter(value, instance=None):
    "returns True if value is Formatter object or class"
    #XXX: really formatTime etc aren't required, should use a negative test to distinguish it
    if instance is not None and not is_class(value) ^ instance:
        return False
    return all(hasattr(value,  attr) for attr in ("formatTime",  "formatException", "format"))

#=========================================================
#standard formatter
#=========================================================
class FancyFormatter(Formatter):
    """
    Logging formatter with a couple of bells and whistles:
        * sanely recovers from errors which occur during formatted
            - eg, when a logger is passed an invalid format string
        * can specially format multiline log messages
        * can add ANSI color coding to output
        * can adapt logging format based on error level
        * more detailed exception traceback information, using `format_exception.formatException`

    FancyFormatter does not take a "fmt" option.
    Instead, it's display format is assembled via
    a "header" format, the log message itself,
    and a series of conditionally present "footer" formats.
    This allows for colorization, and some other features.

    FancyFormatter defines a few additional LogRecord attributes
    which can be used:
        %(shortlevelname)s
            fixed 3-digit form of logging level name.
            If a name is not defined in cls.short_level_names,
            the default level name is used.

        %(multiline_header)s
            If a multiline log message is detected,
            and multiline formatting is enabled,
            This will contain the first line of the message
            ONLY if it appears to be a header line (see `detect_header`),
            else this will be an empty string.

        %(multiline_content)s
            If a multiline log message is detected,
            and multiline formatting is enabled,
            This will contain the all of the message
            not included in %(multiline_header)s,
            else this will be an empty string.

    :Parameters:
        header_fmt
            [optional]
            The format string of the header written before the message proper.
            If None, the class default is used.

        date_fmt
            [optional]
            This behaves the same as Formatter's ``datefmt``,
            except for the fact that the default value can be specified
            at the class level. If None or "iso", you get the ISO8601 format.

        error_fmt
            [optional]
            This specified the format of the footer added after %(message)s
            for all log levels of ERROR or higher. By default this is None,
            but see HumanFormatter for a usage example.

        multiline_fmt
            [optional]
            Formatting used for %(multiline_message)s,
            The default will normally be the desired format,
            but other formats may be used, or it may be set
            to False, which disables multiline detection entirely.

        colorize
            [optional]
            Enables the used of ANSI color codes (or html, if overridden),
            which are used to format the various parts of the log message.
            Setting colorize=True will enable them.

        header_color
            [optional]
            If colorize=True, this string will be inserted before the header_fmt,
            as well as before the error_fmt.

        message_color
            [optional]
            If colorize=True, this string will be inserted after the header_fmt.

        exception_color
            [optional]
            If colorize=True, this string will be inserted before printing the exc_info.

        multiline_color
            [optional]
            If colorize=True, this string will be inserted before printing the multiline_content.

        reset_color
            [optional]
            If colorize=True, this string will be inserted at the end of the log message.

    TODO
        * document this formatters options.
        * make the per-level error message creation more flexible.
    """
    #=========================================================
    #class/instance attrs
    #=========================================================

    #formats
    header_fmt = "[%(asctime)s:%(shortlevelname)s:%(name)s] "
    date_fmt = None
    error_fmt = None
    multiline_fmt = "\n%(multiline_content)s\n"

    #color codes
    colorize = False
    header_color = "\x1B[0m"
    header_color_dbg = "\x1B[1;34m"
    header_color_inf = "\x1B[1;32m"
    header_color_wrn = "\x1B[1;33m"
    header_color_err = "\x1B[1;31m" #covers warning, error and critical
    message_color = "\x1B[0m"
    message_color_dbg = "\x1B[1;30m"
    exception_color = "\x1B[1;31m"
    multiline_color = "\x1B[32m"
    reset_color = "\x1B[0m"

    #DOS color code reference
    #   "\x1B[1;%dm" - %d values as follows
    # 29 : bright white
    # 30 : grey
    # 31 : red
    # 32 : green
    # 33 : yellow
    # 34 : blue
    # 35 : pink
    # 36 : aqua

    # grey w/blue background - "\x1B[7m" - classic dos look; kindof stands out
    # blue w/grey background - "\x1B[7m" - really stands out; hard to miss

    #misc options
    error_msg = "[message not logged: a %(name)s error ocurred during formatting]"
    multiline_tab = '   ' #: char to replace tabs w/ in multiline content
    multiline_pad = '   ' #: padding to add to lines of multiline content

    #dictionary mapping std level names to short form
    short_level_names = {
        "DEBUG": "DBG",
        "INFO": "INF",
        "WARNING": "WRN",
        "ERROR": "ERR",
        "CRITICAL": "CRI",
        }

    #=========================================================
    #init
    #=========================================================
    def __init__(self,
            header_fmt=None, date_fmt=None,  error_fmt=None,  multiline_fmt=None,
            colorize=None,
                header_color=None,  message_color=None,
                exception_color=None, multiline_color=None,
                reset_color=None,
            ):
        #set options
        if header_fmt is not None:
            self.header_fmt = header_fmt
        if date_fmt is not None:
            self.date_fmt = date_fmt
        if error_fmt is not None:
            self.error_fmt = error_fmt
        if multiline_fmt is not None:
            self.multiline_fmt = multiline_fmt
        if colorize is not None:
            self.colorize = colorize
        if header_color is not None:
            self.header_color = header_color
        if message_color is not None:
            self.message_color = message_color
        if exception_color is not None:
            self.exception_color = exception_color
        if multiline_color is not None:
            self.multiline_color = multiline_color
        if reset_color is not None:
            self.reset_color = reset_color
        #send date_fmt -> Formatter.datefmt
        df= self.date_fmt
        if df == "iso":
            df = None
        Formatter.__init__(self, fmt=None, datefmt=df)

    #=========================================================
    #format
    #=========================================================
    #NOTE: moved format out of attr and to func param, in case
    # this formatter got called recursively (it happened!)
    _err_nest = 0

    def format(self, record):
        "wrapper which catches any renderRecord() errors"

        #trap any errors when formatting (typically, msg/args mismatch)
        try:
            fmt = self.prepareRecord(record)
            return self.renderRecord(fmt, record)
        except Exception, err:
            #something in logging system failed, so log info to this module's log.
            #FIXME: add threading lock around this?
            #in case error is occurring recursively, just let things
            #fail if we recurse too much (2 is arbitrary)
            #NOTE: if we just let this go, recursion error would hide real error
            if self._err_nest > 2:
                raise
            try:
                self._err_nest += 1
                self.logFormatError(err, record)
            finally:
                self._err_nest -=1

            #return a generic message
            try:
                return self.error_msg % dict(name=type(err).__name__)
            except:
                return "[message not logged: an error ocurred during formatting]"

    def prepareRecord(self, record):
        "prepare record & calculated attributes"
        #NOTE: this code was adapted from python 2.5.2 Formatter.format
        record.message = record.getMessage()
        self._prepareMultiline(record)
        fmt = self.getFormat(record)
        if "%(shortlevelname)" in fmt:
            record.shortlevelname = self.short_level_names.get(record.levelname, record.levelname)
        if "%(asctime)" in fmt:
            record.asctime = self.formatTime(record, self.datefmt) #NOTE: this reads datefmt not date_fmt
        if record.exc_info:
            # Cache the traceback text to avoid converting it multiple times
            # (it's constant anyway)
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        return fmt

    def _prepareMultiline(self,  record):
        "helper for prepareRecord, sets the multiline support attrs"
        record.multiline_content = ''
        if not self.multiline_fmt:
            return
        message = record.message
        if '\n' not in message:
            return
        lines = message.replace("\t",self.multiline_tab).split("\n")
        if detect_header(lines[0]):
            record.multiline_header = lines.pop(0).rstrip()
        else:
            record.multiline_header = ''
        record.multiline_content = '\n'.join(
            self.multiline_pad + line.rstrip() for line in lines)

    def renderRecord(self, fmt, record):
        "takes care of actually rendering record, after all attrs are prepared"
        #NOTE: this code was adapted from python 2.5.2 Formatter.format
        s = fmt % record.__dict__
        if record.exc_text:
            if not s.endswith("\n"):
                s += "\n"
            if self.colorize:
                s += self.exception_color
            s += record.exc_text + "\n"
        if self.colorize:
            s += self.reset_color
        return s

    def logFormatError(self, err, record):
        #build message text ourselves, to isolate any more internal failures
        try:
            text = (
                "error formatting log record:\n"
                "  record: %r\n"
                "     msg: %r\n"
                "    args: %r\n"
                "  lineno: %r\n"
                "filename: %r"
            ) % (
                record,
                getattr(record, "msg", None),
                getattr(record, "args", None),
                getattr(record, "lineno", None),
                getattr(record, "filename", None),
            )
        except Exception, err:
            #we've already failed once, let's not try to log this error
            text = "error formatting log record:\n<%s error formatting info about error formatting!>" % (type(err).__name__)

        #now try to log it
        log.critical(text, exc_info=True)

    #=========================================================
    #generate log format
    #=========================================================
##    def kf_getFormat(record):
##        return (
##            bool(record.multiline_content),
##            bool(record.exc_info),
##            bool(record.levelno),
##            )
##
##    @cached_method(key=kf_getFormat)
    def getFormat(self, record):
        "builds format string according to formatter options and record attrs"
        fmt = StringIO()
        write = fmt.write
        colorize = self.colorize
        multiline = bool(record.multiline_content and self.multiline_fmt)
        if colorize:
            if record.levelname == "DEBUG":
                col = self.header_color_dbg
            elif record.levelname == "INFO":
                col = self.header_color_inf
            elif record.levelname == "WARNING":
                col = self.header_color_wrn
            elif record.levelname in ("ERROR", "CRITICAL"):
                col = self.header_color_err
            else:
                col = self.header_color
            write(col)
        write(self.header_fmt)
        if colorize:
            if record.levelname == "DEBUG":
                col = self.message_color_dbg
            #elif record.levelname == "INFO":
            #    col = self.header_color_inf
            elif record.levelname == "WARNING":
                col = self.header_color_wrn
            elif record.levelname in ("ERROR", "CRITICAL"):
                col = self.header_color_err
            else:
                col = self.message_color
            write(col)
        if multiline:
            write("%(multiline_header)s")
        else:
            write("%(message)s")
        if self.error_fmt and (record.exc_info or (record.levelno != RAW and record.levelno >= logging.ERROR)):
            if colorize:
                write(self.header_color)
            write(self.error_fmt)
        if multiline:
            if colorize:
                write(self.multiline_color)
            write(self.multiline_fmt)
        #NOTE: reset_color added by formatRecord method
        return fmt.getvalue()

    #=========================================================
    #format exceptions
    #=========================================================
    def formatException(self, exc_info):
        return format_exception(exc_info)

    #=========================================================
    #EOC
    #=========================================================

def detect_header(first):
    "helper for detecting 'header' line in multiline content"
    first = first.rstrip()
    return first == '' or first.endswith(":") or first.endswith("...")

#=========================================================
#debugging
#=========================================================
class FileFormatter(FancyFormatter):
    """helpful preset containin a easily parseable format"""
    header_fmt = "[%(asctime)s %(shortlevelname)s %(name)s] "
    error_fmt = " [%(module)s %(lineno)d %(funcName)s]"
    date_fmt = "%Y-%m-%d %H:%M:%S"

class StdFormatter(FancyFormatter):
    """helpful preset containing a more human-readable format"""
    header_fmt = "<%(asctime)s> %(shortlevelname)s %(name)s: "
    error_fmt = " [Module %(module)r, line %(lineno)d, in %(funcName)s]"
    date_fmt = "%Y:%m:%d %H:%M:%S"

class DevFormatter(StdFormatter):
    """helpful preset for when doing debugging on the cmd line, and logging via stderr.
    
    .. note::
        This formatter embeds ansi escape codes.
        It is recommended to use it with :class:`bps.logs.handlers.ConsoleHandler`,
        which processes them appropriately for the platform & terminal. 
    """
    date_fmt = "%H:%M:%S"
    colorize = True

#=========================================================
#eof
#=========================================================
