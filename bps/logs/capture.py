"""
This module contains functions for capturing various information sources,
and rerouting them through the logging system.

sys.stderr
==========
By calling the `captureStdErr` function,
the default ``sys.stderr`` stream can be replaced with a `Stream_Wrapper`
instance which will collect anything written to stderr,
and redirect it to a logger named ``stderr``.

If logging is to done to stderr, `captureStdErr` should be called
AFTER the logging handlers have been set up, so that the handlers
are attached to the original sys.stderr.

NOTE:
    As it stands now, once invoked, the redirection is permanent for
    the life of the process, but no known technical reason is stopping the code
    from being extended to remedy this.

sys.stdout
===========
Like stderr, by calling the `captureStdOut` function,
the default ``sys.stdout`` can be replaced
with a `Stream_Wrapper` instance which will collect anything written to stdout,
and redirect it to a logger named ``stdout``.

This is a niche function, mainly useful only on win32 graphical applications,
whose libraries may try to print things via ``print`` etc.
In this case, developers may wish to see this output in the log files.

NOTE:
    As it stands now, once invoked, the redirection is permanent for
    the life of the process, but no known technical reason is stopping the code
    from being extended to remedy this.

Warnings
=======
By calling `captureWarnings`, any warnings issued by the `warnings` module
will be redirected to display via the logger named "warnings".
This may be undone by calling `releaseWarnings`.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import atexit
from cStringIO import StringIO
import sys
import os
import inspect
import logging
from time import time as get_time
import threading
import warnings
#site
#pkg
from bps.logs.loggers import RAW, parse_level_name as parse_level
from bps.cache import cached_function
from bps.logs import loggers as logger_module
from bps.meta import lookup_module
#local
log = logging.getLogger(__name__)
__all__ = [
    "capture_stdout", "release_stdout", "check_stdout",
    "capture_stderr", "release_stderr", "check_stderr",
    "capture_warnings", "release_warnings", "check_warnings",
    "flush_buffers",
]

#=========================================================
#HACK to flush stdout/stderr buffers whenever something is logged
#this has the effect of keeping stdout/stderr writes grouped together naturally,
#while still ordering them correctly with other log events.
#=========================================================
_flush_streams = set() #set of streams that need flushing before certain events (logging, etc)
_flush_lock = threading.RLock()
def flush_buffers():
    """thread-safe helper to flush all capture buffers...
    called by BpsLogger before any message is logged,
    but can be called pretty much anywhere.
    """
    if _flush_lock.acquire(False):
        for stream in _flush_streams:
            stream.flush(force=True)
        _flush_lock.release()
logger_module.flush_buffers = flush_buffers

#=========================================================
#stream wrapper
#=========================================================
class StreamWrapper(object):
    """stream like object which proxies all it's writes to a specified logger.
    TODO: need to document & clean up the buffering logic.
    """
    #=========================================================
    #instance constants
    #=========================================================
    name = None #: name of stream to use when logging
    header = "unmanaged logging output:" #: header to preface all writes with
    flush_threshold = 10 #number of seconds between flush calls before autoflushing
    write_threshold = 1 #max write delay to disable autoflush

    #=========================================================
    #instance attrs
    #=========================================================
    buf = None #buffer
    last_write = 0
    last_flush = 0

    broken = False
        #set when flush was forced to break on a non-linebreak character
        #cleared by write when it adds content to the (now empty) buffer,
        #along with a '...' indicating this was a continuation

    #=========================================================
    #init
    #=========================================================
    def __init__(self, name=None):
        self.name = name or source_attr
        assert isinstance(self.flush_threshold, (int,float))
        assert isinstance(self.write_threshold, (int,float))
        self.log = logging.getLogger(self.name)
        self.broken = False
        self.last_write = 0
        self.last_flush = 0
        self.buf = StringIO()

    #=========================================================
    #flushing
    #=========================================================
    def flush(self, force=False):
        "flush any complete lines out of buffer"
        #XXX: should capturing honor os.linesep? or assume it's always "\n",
        # using universal-newline style?

        #NOTE: it's important for recursion purposes that _write() be called after buffer state is set
        #read buffer
        self.last_flush = get_time()
        buf = self.buf
        content = buf.getvalue()
        #check if we're empty
        if content == '':
            return None
##        assert not self.broken, "if there's content, write() should have cleared broken flag"
        #check if we have a complete line
        if content[-1] == '\n':
            buf.reset()
            buf.truncate()
            self._write(content)
            return True
        #check if we have to force a flush
        if force:
            buf.reset()
            buf.truncate()
            self.broken = True
            self._write(content + "...\n")
            return True
        #just flush to end of last complete line
        idx = content.rfind('\n')+1
        if idx == 0:
            return False
        buf.reset()
        buf.truncate()
        buf.write(content[idx:])
        self._write(content[:idx])
        return True

    def _write(self, content):
        "backend method controlling where output goes... always receives full lines of some type"
        self.log.log(RAW, "%s\n%s\n", self.header, content)

    #=========================================================
    #writing
    #=========================================================
    def write(self, chunk):
        #autoflush if we haven't since last write, and last write was long enough ago...
##        self._write(chunk)
##        return len(chunk)
        cur = get_time()
        if self._calc_autoflush(cur):
            self.flush()
        self.last_write = cur
        if not chunk:
            return 0
        if self.broken:
            self.buf.write("...")
            self.broken = False
        return self.buf.write(chunk)

    def _calc_autoflush(self, cur):
        #if we had a write w/in write_threshold time,
        #assume they're grouped together, and don't autoflush yet.
        if self.last_write + self.write_threshold >= cur:
            return False
        #make sure we've flushed w/in flush_threshold time...
        if self.last_flush + self.flush_threshold < cur:
            return True
        #else we flushed recently enough
        return False

    #=========================================================
    #EOF
    #=========================================================

#=========================================================
#sys.stderr capturing
#=========================================================
_orig_stderr = None
_proxy_stderr = None

def capture_stderr():
    "reroute sys.stderr to logging system, see module documentation for details"
    global _orig_stderr, _proxy_stderr, _flush_streams, _flush_lock
    if _orig_stderr is None:
        _flush_lock.acquire()
        try:
            if _proxy_stderr is None:
                _proxy_stderr = StreamWrapper(name="sys.stderr")
                #would like to just call flush_buffers() at exit, but it's config is gone when atexit runs :(
                atexit.register(_proxy_stderr.flush, force=True)
            _flush_streams.add(_proxy_stderr)
            _orig_stderr = sys.stderr
            sys.stderr = _proxy_stderr
        finally:
            _flush_lock.release()

def release_stderr():
    "stop capturing of stderr"
    global _orig_stderr,  _proxy_stderr
    if _orig_stderr:
        _flush_lock.acquire()
        try:
            assert _proxy_stderr
            if sys.stderr is not _proxy_stderr:
                raise RuntimeError, "can't release: sys.stderr was modified since it was captured"
            _proxy_stderr.flush(force=True)
            sys.stderr = _orig_stderr
            _orig_stderr = None
            _flush_streams.discard(_proxy_stderr)
            #NOTE: would like to undo the atexit call
        finally:
            _flush_lock.release()

def check_stderr():
    "return True if stdout is begin captured"
    global _orig_stderr
    return _orig_stderr is not None

#=========================================================
#sys.stdout capturing
#=========================================================
#TODO: could use a stacked proxy object, so once orig is captured,
# we can release/capture again w/o conflicting with subsequent overrides
# from other apps.

_orig_stdout = None
_proxy_stdout = None

def capture_stdout():
    "reroute sys.stdout to logging system, see module documentation for details"
    global _orig_stdout, _proxy_stdout, _flush_streams, _flush_lock
    if _orig_stdout is None:
        _flush_lock.acquire()
        try:
            if _proxy_stdout is None:
                _proxy_stdout = StreamWrapper(name="sys.stdout")
                #would like to just call flush_buffers() at exit, but it's config is gone when atexit runs :(
                atexit.register(_proxy_stdout.flush, force=True)
            _flush_streams.add(_proxy_stdout)
            _orig_stdout = sys.stdout
            sys.stdout = _proxy_stdout
        finally:
            _flush_lock.release()

def release_stdout():
    "stop capturing of stdout"
    global _orig_stdout, _proxy_stdout
    if _orig_stdout:
        _flush_lock.acquire()
        try:
            assert _proxy_stdout
            if sys.stdout is not _proxy_stdout:
                raise RuntimeError, "can't release: sys.stdout was modified since it was captured"
            _proxy_stdout.flush(force=True)
            sys.stdout = _orig_stdout
            _orig_stdout = None
            _flush_streams.discard(_proxy_stdout)
            #NOTE: would like to undo the atexit call
        finally:
            _flush_lock.release()

def check_stdout():
    "return True if stdout is begin captured"
    global _orig_stdout
    return _orig_stdout is not None

#=========================================================
#python warnings system
#=========================================================
warning_target = "%(source)s"
warning_fmt = "%(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s"

_inspect_filename = False
_orig_showwarning = None #: original warnings.showwarning stored if captureWarnings enabled.

def capture_warnings(fmt=None,  target=None):
    """redirect all warnings through logging system via logger named 'warnings'.

    :Parameters:
        fmt
            format string controlling how warnings are printed out.
            the default simulates the original warning.formatwarning().
            format string should use the "%(keyword)s" format,
            available keywords are described below.

            For example, this string mimics the style of ``warnings.formatwarning``:
                "%(filename)s:%(lineno)s: %(category)s: %(message)s"

            By default this uses a multiline format.

        target
            Format string defining name of logger to send message to.
            this uses the same keywords as 'fmt'. This can also be a callable,
            which will be passed in all the same keywords, and should
            return the name of the logger to use.

            For example, this string sends all warnings to the warnings module:
                "warnings"

            By default, the following string is used,
            which uses a logger named after the module:
                "%(source)s"

    ``fmt`` and ``target`` strings will have the following keywords defined:

        message
            content of warning text, from the warning object.
        category
            __name__ of warning object's class
        filename
            filepath of module warning was issued in
        lineno
            line number in file where warning was issued
        modulepath
            full path of module (package + module name),
            or empty string if not derivable from filename
        modulename
            just the module name of the module
        source
            same as module name,
            but returns "warnings" instead of empty string.
            This keyword is probably a little more useful as a logger target
            than module is.
    """
    global _orig_showwarning,  warning_fmt,  warning_target,  _inspect_filename
    if _orig_showwarning is None:
        _orig_showwarning = warnings.showwarning
        warnings.showwarning = _showWarning
    if fmt is not None:
        warning_fmt = fmt
    if target is not None:
        warning_target = target
    #check if we need to inspect the filename
    if callable(warning_target):
        _inspect_filename = True
    else:
        _inspect_filename = any(
            any(
                "%%(%s)" % key in fmt
                for key in ("modulepath",  "modulename",  "source")
            )
            for fmt in (warning_fmt,  warning_target)
            )

whl = (sys.version_info >= (2, 6)) #warnings-has-line? introduced in py26

def _showWarning(message, category, filename, lineno, file=None, line=None):
    #NOTE: 'line' added in py26
    global warning_fmt,  warning_target,  _inspect_filename
    if file is not None:
        #use old version if writing to a file somewhere, can't use logging system for this
        if whl:
            #fixme: what if incompatible app patched this before us?
            return _orig_showwarning(message, category, filename, lineno, file, line)
        else:
            return _orig_showwarning(message, category, filename, lineno, file)
    #TODO: fill in default for 'line' like 26's showwarning does
    kwds = dict(
            message=message,
            category=category.__name__,
            filename=filename,
            lineno=lineno,
            line=line,
            )
    if _inspect_filename:
        path = _guess_module_from_path(filename)
        if path:
            if '.' in path:
                name = path.rsplit(".", 1)[1]
            else:
                name = path
            kwds.update(
                modulepath=path,
                modulename=name,
                source=path,
            )
        else:
            kwds.update(
                modulepath='',
                modulename='',
                source='sys.warnings',
            )
    text = warning_fmt % kwds
    if callable(warning_target):
        name = warning_target(**kwds)
    else:
        name = warning_target % kwds
    logging.getLogger(name).warning(text)

@cached_function(args=1)
def _guess_module_from_path(path):
    "guess full module name (w/ package) from filepath"
    return lookup_module(path, name=True)

def release_warnings():
    global _orig_showwarning
    if _orig_showwarning is None:
        return
    if warnings.showwarning != _showWarning:
        log.error("releaseWarnings() failed, another application has overridden warnings.showwarning")
        return
    warnings.showwarning = _orig_showwarning
    _orig_showwarning = None

def check_warnings():
    "return True if stdout is begin captured"
    global _orig_showwarning
    return _orig_showwarning is not None

#=========================================================
#eof
#=========================================================
