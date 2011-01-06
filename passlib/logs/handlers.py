"""This module provides additional logging Handler classes."""
#=========================================================
#imports
#=========================================================
#core
try:
    import codecs
except ImportError:
    codecs = None
import os.path
import logging
from logging import StreamHandler
import os
import time
#site
#pkg
from bps.meta import is_class
#local
log = logging.getLogger(__name__)
__all__ = [
    #handle utilities
    'set_startup_msg',
    'is_handler',
    'purge_handlers',
    'has_default_handler',

    #custom handlers
   'WatchedFileHandler',
   'NullHandler',
]

#=========================================================
#handler helpers
#=========================================================
def set_startup_msg(handler,  msg=True,  delay=True):
    """
    Modifies a handler so it emits a message
    indicating when the logging system started up,
    but ONLY when it is first called by the logging system
    to log something.
    """
    #prepare the message text
    if msg is True:
        msg = "--- LOGGING STARTED %(asctime)s ---"
    msg %= dict(
        asctime = time.strftime("%Y-%m-%d %H:%M:%S")
        )
    #create the record we're going to emit
    startup_record = logging.LogRecord("", logging.INFO, "__main__", 0, msg, (), None)

    if not delay:
        handler.emit(startup_record)
        return

    #wrap the handler's emit func with a onetime wrapper
    #that will remove itself after being called
    orig_emit = handler.emit
    def emit_wrapper(record):
        #remove our hook
        handler.emit = orig_emit
        #emit startup record - note we bypass all filters, so this message always gets through
        orig_emit(startup_record)
        #emit real record
        return orig_emit(record)
    handler.emit = emit_wrapper

def is_handler(value, instance=None):
    "returns True if value is Handler object or class"
    if instance is not None and not is_class(value) ^ instance:
        return False
    #TODO: make this more comprehensive,
    #but for now these attrs should be good enough though
    return all(hasattr(value,  attr)
               for attr in ("setLevel",  "format", "handle",  "setFormatter"))

def purge_handlers(logger, close=True):
    "remove all handlers attached to logger, returns list of handlers removed"
    #FIXME: this assumes handlers aren't bound to 2+ loggers.
    # probably safe to assume, but could bite us in the future.
    if isinstance(logger, str):
        logger = logging.getLogger(logger)
    handlers = logger.handlers[:]
    for h in handlers:
        #remove handler from logger
        if close:
            h.acquire()
            try:
                logger.removeHandler(h)
                h.flush()
                h.close() #close resources, remove from logging tracker
            finally:
                h.release()
        else:
            logger.removeHandler(h)
    return handlers #WARNING: if 'close' is True, all these handlers are inoperative (unless .shared is True)

def has_default_handler():
    "check if a handler has been attached to the root logger"
    return len(logging.getLogger("").handlers) > 0

#=========================================================
#WatchedFileHandler
#=========================================================
#NOTE: as of py26, there is a core handler that provides this, and has the same name!
#it would be useful to load that one instead, unless it lacks some feature of this one (doubtful)

class WatchedFileHandler(StreamHandler):
    """
    This is a re-implemenation of the core FileHandler,
    which has the added ability to detect if the file it's writing
    to has been clobbered (eg, by logrotate), and reopen it before logging.

    It would inherit from the original FileHandler,
    but too many things needed rearranging

    """
    def __init__(self, filename, mode='a', encoding=None, shared=True):
        """
        Open the specified file and use it as the stream for logging.
        """
        if codecs is None:
            encoding = None
        self.encoding = encoding
        self.mode = mode
        self.shared = shared #if True, assume multiple writers to file, if False, assume this should be only one.
        self.filename = os.path.abspath(filename)
        self.stream = None #file handle
        self.stat = None #stat() of last time we flushed
        self.prepare() #go ahead and open the stream, so we can pass it to StreamHandler
        StreamHandler.__init__(self, self.stream)

    def check(self):
        """
        Check if stream needs to be (re)opened.
        """
        #make sure file exists and stream is open
        if not self.stream or self.stream.closed:
            return True
        if not os.path.exists(self.filename):
            return True
        cur = os.stat(self.filename)
        orig = self.stat

        #check if file has been truncated
        if self.shared and cur.st_size < orig.st_size:
            return True
        elif cur.st_size != orig.st_size:
            return True

        #check if ctime has changed
        if cur.st_ctime != orig.st_ctime:
            return True

        #check if file has been replaced
        if cur.st_dev != orig.st_dev:
            return True
        if cur.st_ino != orig.st_ino:
            return True

        #NOTE: if ctime was faked, and size was restored to EXACTLY what it was, we might be fooled.
        return False

    def prepare(self):
        """
        Opens the stream if closed,
        and Reopens the stream if the file has been clobbered.
        """
        if self.check():
            if self.stream:
                self.stream.close()
            self.stream = file(self.filename, self.mode)
            #flush to make sure file is created, and update self.stat
            self.flush()

    def flush(self):
        try:
            StreamHandler.flush(self)
        except ValueError, err:
            #only ever seen under windows
            if os.name == "nt" and str(err) == "I/O operation on closed file":
                return
            raise
        #now that we've flushed, save the latest stat info to check next time
        if self.stream and not self.stream.closed:
            self.stat = os.fstat(self.stream.fileno())

    def emit(self, record):
        self.prepare() #reopen stream if needed
        return StreamHandler.emit(self, record)

    def close(self):
        """
        Closes the stream.
        """
        self.flush()
        self.stream.close()
        StreamHandler.close(self)

#=========================================================
#
#=========================================================

from bps.unstable.ansi import AnsiStripper
if os.name == "nt":
    from bps.unstable.winconsole import AnsiConsoleWriter
    def _create_ansi_wrapper(stream):
        if not ( hasattr(stream,"isatty") and stream.isatty() ):
            return AnsiStripper(stream)
        else:
            return AnsiConsoleWriter(stream)
else:
    def _create_ansi_wrapper(stream):
        #if not a tty, assume it has no capabilities
        if not ( hasattr(stream,"isatty") and stream.isatty() ):
            return AnsiStripper(stream)
        #XXX: we could use curses if available to check terminfo
        #otherwise assume it's ansi capable
        return stream

class ConsoleHandler(StreamHandler):
    """
    This stream handler should be used when writing to a console (such as stderr).
    It can handle ANSI escape codes (such as emitted by DevFormatter),
    and does one of three things:
        * [nt] use the windows api to colorize the display appropriately
        * [posix] pass ansi codes on through if target stream looks capable.
        * otherwise ansi codes are stripped out
    """
    def __init__(self, *a, **k):
        StreamHandler.__init__(self, *a, **k)
        #NOTE: all the work is done by the platform-specific AnsiWriter class
        self.stream = _create_ansi_wrapper(self.stream)

#=========================================================
#null handler for discarding records
#=========================================================

class NullHandler(logging.Handler):
    shared = False #flag used to indicate handler should never be closed.

    def __init__(self, shared=False):
        self.shared = shared
        logging.Handler.__init__(self)

    def emit(self, record):
        pass

    def close(self):
        if not self.shared:
            logging.Handler.close(self)

#singleton use by setup_lib_logging() among others
null_handler = NullHandler(shared=True)

#=========================================================
#eof
#=========================================================
