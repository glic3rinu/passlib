"""
This module installs a custom logger class,
which enhances the default logger class.
features include:
    * setLogLevel() supports strings as well as numeric levels
    * logger object can be used in comparisions w/ string & int levels
      to check if it would log a message. eg::
        if logger > "warning":
            logger.warn("foo")
    * integration with bps.logs.capture to help keep stdout/stderr flushed correctly.
This module is automatically imported by bps.logs,
so there is no real reason to import it manually.
"""
#=========================================================
#imports
#=========================================================
#core
import logging
#site
#pkg
flush_buffers = None #NOTE: to prevent a cyclic import, this is filled in by the capture module
#local
__all__ = [
    'is_logger',
    'get_logger',
##    'will_log_level',
    'parse_level_name',
    'get_level_name',
]

ROOT = "<root>" #special alias for root logger

#=========================================================
#register special log level that capture module uses
#   to display captured output
#=========================================================
RAW=45
logging.addLevelName(RAW, "RAW")

#=========================================================
#helpers
#=========================================================
def is_logger(obj):
    "test if object appears to be a logger"
    #NOTE: not all attrs tested for, just enough to identify it
    return all(
        hasattr(obj, attr)
        for attr in ("name", "getEffectiveLevel", "addHandler", "log", "warn")
        )

def get_logger(value=None):
    """return logger object.

    unlike logging.getLogger(),
    this can be passed a logger object or a name,
    for easily normalizing to a logger object.
    """
    if is_logger(value):
        value = value.name
    elif value == ROOT:
        value = ""
    return logging.getLogger(value)

def get_managed_loggers(resolve=True):
    """returns name of all loggers which have been referenced up to this point.

    this is mainly useful for code which wants to inspect
    the existing logging configuration, as any loggers
    not returned have not been references, so can't have any special configuration.

    :param resolve: if ``False``, returns logger names instead of Logger objects.
    """
    #NOTE: this is poking into the logging module's internals.
    # any changes to that module will require updating here.
    # this mainly exists to isolate such nosiness to single function.
    logging._acquireLock()
    try:
        #ld maps logging name -> Logger or PlaceHolder,
        # the latter of which lacks a ".handlers" attr
        ld = logging.root.manager.loggerDict
        return [
            logger if resolve else name
            for name, logger in ld.iteritems()
            if hasattr(logger, "handlers")
        ]
    finally:
        logging._releaseLock()

##def purge_all_handlers():
##    """purge all handlers in system"""
##    for logger in get_managed_loggers():
##        if logger.handlers:
##            purge_handlers(logger.name) #removed handlers from logger, calls close
##        logger.propagate = 1
##        logger.disabled = 0
##
##def reset_all_loggers():
##    "reset all logger levels, handlers, and settings"
##    #FIXME: would be good to track libs that called setup_lib_logging(), and preserve those
##    for logger in get_managed_loggers():
##        if logger.handlers:
##            purge_handlers(logger)
##        logger.level = logging.NOTSET
##        logger.propagate = 1
##        logger.disabled = 0

##def is_logger_managed(name):
##    """check if logger has been previously referenced"""
##    #NOTE: this is poking into the logging module's internals.
##    # any changes to that module will require updating here.
##    # this mainly exists to isolate such nosiness to single function.
##    logging._acquireLock()
##    try:
##        logger = logging.root.manager.loggingDict.get(name)
##        return logger and hasattr(logger, "handlers")
##    except:
##        logging._releaseLock()

##def will_log_level(name, level):
##    "return ``True`` if specified logger would log info at a given level or above."
##    #FIXME: this won't work for proxy logger.
##    #should resolve it via inspect?
##    logger = get_logger(name)
##    level = parse_level_name(level)
##    return logger.getEffectiveLevel() <= level

def parse_level_name(value):
    """parse logging level string.

    Given a string containing an int log level or a log level name,
    returns the corresponding integer log level.

    Integer passed in will be returned unchanged.
    Unlike the logging package, this function is case-insensitive.

    raises ValueError if value can't be parsed.

    Usage Example::

        >>> from bps import logs
        >>> logs.parse_level_name("NOTSET")
        0
        >>> logs.parse_level_name("INFO")
        20
        >>> logs.parse_level_name("debug")
        10
        >>> logs.parse_level_name("35")
        35
        >>> logs.parse_level_name(20)
        20
        >>> logs.parse_level_name("BADVALUE")
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
        ValueError: unknown logging level value: 'BADVALUE'
    """
    #check for int
    try:
        return int(value)
    except (ValueError, TypeError):
        pass
    #check for registered level name
    result = logging.getLevelName(value.upper())
    if isinstance(result, int):
        return result
    #give up
    raise ValueError, "unknown logging level value: %r" % (value,)

def get_level_name(value):
    """reverse of parse_level; returns registered name of logging level.

    Usage Example::

        >>> from bps import logs
        >>> logs.get_level_name(0)
        'NOTSET'
        >>> logs.get_level_name(10)
        "DEBUG"
        >>> logs.get_level_name("info")
        "INFO"
        >>> logs.get_level_name("BADVALUE")
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
        ValueError: unknown logging level value: 'BADVALUE'
    """
    value = parse_level_name(value)
    name = logging.getLevelName(value)
    if name.startswith('Level ') and name[6:].isdigit():
        #just return number as string
        return str(value)
    return name

#=========================================================
#patch logger class
#=========================================================
_OldLogger = logging.getLoggerClass()

class BpsLogger(_OldLogger):
    "helper class bps creates from original logger class to flush captured streams"
    def handle(self, record):
        flush_buffers() #call bps.logs.capture's flush hook
        return _OldLogger.handle(self, record)

##    def getLogger(self):
##        #NOTE: right now, this is merely a helper for the proxy loggers
##        #but in future, could add logger resolution ala absimport
##        return self

##    def setLevel(self, value):
##        v = _OldLogger.setLevel(self, parse_level(value))
##        _trigger_callbacks(self.name)
##        return v

    def __cmp__(self, other):
        if isinstance(other, int):
            return cmp(self.getEffectiveLevel(), other)
        elif isinstance(other, str):
            return cmp(self.getEffectiveLevel(), parse_level_name(other))
        else:
            #do this so __eq__ works correctly
            return cmp(id(self), id(other))

    def __hash__(self):
        return id(self)

logging.setLoggerClass(BpsLogger)

#=========================================================
#
#=========================================================
#NOTE: experimental hook for notifying apps when logging level changes
#
##_callbacks = {}
##
##def _trigger_callbacks(name):
##    global _callbacks
##    chain = _callbacks.get(name)
##    if chain:
##        for func in chain:
##            func()
##
##def on_level_change(name, func):
##    "register a callback called when logger changes level"
##    #XXX: this is an attempted callback system, not finalized at all
##    if hasattr(name, "name"):
##        name = name.name
##    global _callbacks
##    chain = _callbacks.get(name)
##    if name in _callbacks:
##        chain = _callbacks[name]
##    else:
##        chain = _callbacks[name] = []
##    chain.append(func)

#=========================================================
#eof
#=========================================================
