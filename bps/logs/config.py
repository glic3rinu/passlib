"""bps.logs.config -- configuration parsing"""
#=========================================================
#imports
#=========================================================
#core
from warnings import warn
import os
import logging
import ConfigParser
#site
#lib
from bps.undef import Undef
from bps.error.types import ParseError, InputError, ParamError, MissingPathError
from bps.meta import is_str, is_seq, is_oseq, Params
from bps.parsing.config import read_into_parser, parser_get_section, unescape_string
from bps.stream import get_input_type
from bps.text import asbool
from bps.types import BaseClass
#pkg
from bps.logs import capture
from bps.logs.formatters import is_formatter
from bps.logs.handlers import set_startup_msg, null_handler, \
        has_default_handler, purge_handlers, is_handler
from bps.logs.loggers import parse_level_name, ROOT, is_logger, get_managed_loggers
#local
log = logging.getLogger(__name__)
__all__ = [
    #main frontends
    'setup_lib_logging',
    'setup_std_logging',
    'config_logging',
    'add_handler',
    'parse_config',

##    #helpers
##    'patch_paste',
]

#=========================================================
#misc
#=========================================================
#disabled till we figure out a way to call it before .ini loads :(
##def patch_paste():
##    """monkeypatch Paste to use config_logging() instead of default logging system.
##    this lets you use BPS style logging config directives,
##    while still (hopefully) retaining backward compatibility with
##    the old format.
##    """
##    from bps.meta import monkeypatch
##    from paste.script.command import Command
##    @monkeypatch(Command)
##    def logging_file_config(self, config_file):
##        config_logging(config_file)

#=========================================================
#config frontends
#=========================================================
def setup_lib_logging(name):
    """Suppress "No handler cound be found" message
    by telling the logging system to silently ignore unhandled
    messages for the specified logger.

    This is done by attaching a null handler to the specified logger.
    This handler will not prevent any messages from being passed
    to other handlers, it merely prevents any messages passing through
    the named logger from appearing as "unhandled".

    It is recommended to call this function at the top
    of the root module of a library, so that any messages
    that are logged while the library is loading will not result
    in annoying error messages.
    """
    logging.getLogger(name).addHandler(null_handler)

def setup_std_logging(force=True, level=None, dev=False):
    """Quickly set up stderr logging for your application.

    This is mainly for setting up logging at the beginning of a command line script,
    before verbosity, levels, or handlers have been loaded.

    :Parameters:
        force
            If True (the default), clear out any existing default handlers,
            and set up our own. If False, aborts if a default handler exists.
        level
            The default logging level to set for the logging system.
            If not specified, defaults to "ERROR" (though see dev mode below).
        dev
            If devel mode is set, default level is upped to "WARNING",
            and a colorized formatter is used, both to aid in software development.

            If not set (the default), a uncolorized (and hence machine parseable) formatter
            is used, and the default level is set to "ERROR".

    This is essentially a stripped down version of :func:`logging.basicConfig`,
    designed to do the one core job efficiently. For more complex
    logging configuration, call :func:`config_logging`
    directly, it is a much more powerful function than this or basicConfig.
    If this is the case for you, see the source code for this function
    as a starting point, it's only 16 lines long.
    """
    if not force and has_default_handler():
        return None
    if dev:
        handler = "dev-console"
        if level is None:
            level = "WARNING"
    else:
        handler = "std-console"
        if level is None:
            level = "ERROR"
    config_logging(
        level=level,
        capture_warnings=True,
        default_handler=handler,
        stacklevel=2,
        )
    return True

def config_logging(source=None, source_format=None, stacklevel=1, **kwds):
    config = parse_config(source=source, source_format=source_format, stacklevel=stacklevel+1, **kwds)
    if config is None:
        return False
    else:
        config.apply()
        return True #xxx: could return False is config is noop

def add_handler(logger="<root>", propagate=None, add=True, **kwds):
    "add handler to logger by description"
    config = LoggingConfig(stacklevel=2)
    if isinstance(kwds.get("formatter"), dict):
        config.set_formatter("custom-fmt", **config.parse_formatter_desc(kwds['formatter']))
        kwds['formatter'] = "custom-fmt"
    config.set_handler("custom-hnd", **config.parse_handler_desc(kwds))
    config.set_propagate(logger, propagate)
    if add:
        config.add_outputs(logger, ['custom-hnd'])
    else:
        config.set_outputs(logger, ['custom-hnd'])
    config.apply()

#=========================================================
#parser frontend
#=========================================================
def parse_config(
        #source input
        source=None, source_format=None, source_scope=None,

        #controls
##        restrict=None,
        errors="log",
        stacklevel=1,

        #kwd input
        **kwds):
    """parse logging configuration from file, string, or dictionary

    :param errors:
        Policy for dealing with errors.

        * ``"raise"`` -- all errors are raised
        * ``"log"`` -- the default, causes errors to be logged internally, and ``None`` returned

    :returns:
        This returns an instance of the :class:`LoggingConfig` subclass
        which handles parsing whichever input format the configuration
        was provided in.

        If ``errors='log'`` and an error occurrs, returns ``None``.
    """
    #parse / normalize source
    if source is None:
        config = LoggingConfig(scope=source_scope, stacklevel=stacklevel+1)
    elif isinstance(source, LoggingConfig):
        config = LoggingConfig(scope=source_scope, stacklevel=stacklevel+1)
        config.add_kwds(source.__dict__)
    else:
        try:
            config = _parse_from_source(source, source_format, source_scope, errors, stacklevel+1)
        except (ParseError, InputError), err:
            if errors == "raise":
                raise
            log.warning(str(err))
            return None
        if config is None:
            return None

    #merge kwds
    if kwds:
        config.add_kwds(kwds)

    #done!
    return config

def _parse_from_source(source, source_format, scope, errors, stacklevel):
    #detect what type of input 'source' is...
    stype = get_input_type(source)
    assert stype in ("path", "raw", "stream")
    if stype == "path":
        if not os.path.exists(source):
            if errors == "raise":
                raise MissingPathError(filename=source)
            else:
                log.error("config file not found: filename=%r", source)
                return None

    #detect what format 'source' is...
    if source_format is None:
        source_format = _detect_source_format(source, stype)

    #dispatch to format-specific parser
    if source_format == "standard":
        return StandardConfig(source, stacklevel=stacklevel+1)
    elif source_format == "compact":
        return CompactConfig(source, scope=scope, stacklevel=stacklevel+1)
    else:
        raise InputError("unknown logging config format: %r" % format)

def _detect_source_format(source, stype):
    "helper for parse_config... tries to guess format used by source"
    #try to load as ini file
    try:
        parser = read_into_parser(source, errors="log", reset=True)
    except ConfigParser.MissingSectionHeaderError:
        parser = None
    if parser:
        if CompactConfig.detect_cp(parser):
            return "compact"
        if StandardConfig.detect_cp(parser):
            return "standard"
    #give up
    if stype == "path":
        txt = "couldn't determine logging config format: filename=%r" % (source,)
    else:
        txt = "couldn't determine logging config format: stype=%r" % (stype,)
    raise InputError(txt)

#=========================================================
#logging config object - represents a parsed logging config snippet
#=========================================================
class LoggingConfig(BaseClass):
    """class which represents a parsed logging config file.

    it's mainly used as a framework for building up a parsed configured
    via the subclasses later in this file.
    """
    #=========================================================
    #class constants
    #=========================================================

    #default handler presets defined for all configurations
    default_handlers = {
        'console': dict(
            klass="StreamHandler",
            args="(sys.stderr,)",
            #XXX: would like to auto-detect if console is interactive, and choose formatter accordingly
            formatter="std-console",
            ),

        'dev-console': dict(
            klass="bps.logs.handlers.ConsoleHandler",
            args="(sys.stderr,)",
            formatter="dev-console",
            ),

        'std-console': dict(
            klass="StreamHandler",
            args="(sys.stderr,)",
            formatter="std-console",
            ),

        'null': dict(
            klass='bps.logs.handlers.NullHandler'
            ),
    }

    #list of prefixes to try when resolving handler names
    handler_prefixes = ['logging', 'logging.handlers', 'bps.logs.handlers']

    #default formatter presets defined for all configurations.
    default_formatters = {
        'dev-console': dict(
            klass="bps.logs.formatters.DevFormatter",
            ),
        'std-console': dict(
            klass="bps.logs.formatters.StdFormatter",
            ),
        'std-file': dict(
            klass="bps.logs.formatters.FileFormatter",
            ),
    }

    #list of module prefixes which will be searched when
    # resolving formatter class names
    formatter_prefixes = [ 'logging', 'bps.logs.formatters' ]

    #name used by add_default_handler
    DEFAULT_HANDLER_NAME = "__default_handler__"

    #global options which are boolean
    BOOL_OPTIONS = ("disable_existing_loggers",
        "reset_handlers", "reset_loggers",
        "capture_stdout", "capture_stderr", "capture_warnings")

    #all global options
    ALL_OPTIONS = ("warning_fmt", "warning_target") + BOOL_OPTIONS

    #=========================================================
    #init
    #=========================================================
    def __init__(self, scope=None, stacklevel=1):
        self.stacklevel = stacklevel #stacklevel for warnings
        self.options = {}
        self.loggers = {}
        self.formatters = {}
        self.handlers = {}
        self.scope = vars(logging)
        if scope:
            self.scope.update(scope)

    #=========================================================
    #global options
    #=========================================================
    options = None # option name -> option value

    def set_option(self, name, value):
        assert name in self.ALL_OPTIONS, "unknown option: %r" % (name, )
        self.options[name] = value

    def get_option(self, name):
        value = self.options.get(name)
        if name == "reset_handlers":
            if not value and self.get_option("reset_loggers"):
                value = True
        elif name == "reset_loggers":
            if not value and self.get_option("disable_existing_loggers"):
                value = True
        return value

    #=========================================================
    #logger configuration
    #=========================================================
    loggers = None #dict mapping logger name -> dict of logger options.
        #optional keys in logger options dict:
        #   propagate - True/False - change value of propagate flag
        #   level - string/int - change current log level
        #   outputs - list of handler names / instances
        #   add - if True, handlers should be added, not replacing existing.
        #NOTE: if handlers is not None and add is not True, existing handlers are purged.

    def get_logger_config(self, name, default=Undef, create=False):
        "retrieve dict with config for specified logger"
        name = parse_logger_name(name)
        if name in self.loggers:
            return self.loggers[name]
        elif create:
            self.loggers[name] = config = {}
            return config
        elif default is Undef:
            raise KeyError, "logger config not found: %r" % (name,)
        else:
            return default

    def set_level(self, name, level):
        "set a given logging level"
        level = parse_level_name(level)
        config = self.get_logger_config(name, create=True)
        config['level'] = level

    def set_propagate(self, name, value):
        "set propagate flag for logger"
        if value is None:
            return
        config = self.get_logger_config(name, create=True)
        config['propagate'] = value

    def _check_outputs(self, handlers):
        "validate outputs list"
        if not all(
                   is_str(h) or is_handler(h)
                   for h in handlers
                   ):
            raise ValueError, "output list must contain handler names or instances: %r" % (handlers,)

    def set_outputs(self, name, handlers):
        "set list of handlers for logger, replacing existing ones"
        self._check_outputs(handlers)
        config = self.get_logger_config(name, create=True)
        config['outputs'] = list(handlers)
        if 'add' in config:
            del config['add']

    def add_outputs(self, name, handlers):
        "add list of handlers to logger, appending to existing ones"
        self._check_outputs(handlers)
        if not handlers:
            return
        config = self.get_logger_config(name, create=True)
        if 'outputs' in config:
            config['outputs'].extend(handlers)
            #keep existing mode flag
        else:
            config['outputs'] = list(handlers)
            config['add'] = True

    def clear_outputs(self, name):
        "remove all handlers from logger"
        config = self.get_logger_config(name, create=True)
        config['outputs'] = []
        if 'add' in config:
            del config['add']

    def validate_loggers(self):
        "make sure output names all exist"
        for name, config in self.loggers.iteritems():
            if 'outputs' in config:
                for hname in config['outputs']:
                    if self.get_handler_config(hname, None) is None:
                        raise ValueError, "%s: unknown handler %r" % (name, hname)

    #=========================================================
    #handlers
    #=========================================================
    handlers = None #map of handler name -> handler constructor kwds
    scope = None #dict used as global scope for evaluating various strings

    def get_handler_config(self, name, default=Undef):
        "return dict w/ config for handler, or raise KeyError"
        name = parse_handler_name(name)
        if name in self.handlers:
            return self.handlers[name]
        elif name in self.default_handlers:
            config = self.parse_handler_desc(self.default_handlers[name])
            self._check_handler_config(config)
            return config
        elif default is Undef:
            raise KeyError, "no handler named %r" % name
        else:
            return default

    def _check_handler_config(self, kwds):
        "validate handler config dict"
        klass = kwds["klass"]
        if not is_handler(klass, False):
            raise ValueError, "%s: class keyword not a handler class: %r" % (name, klass,)
        if 'args' in kwds:
            kwds['args'] = Params.normalize(kwds['args'])
        if 'formatter' in kwds:
            f = kwds.get("formatter")
            if not is_str(f) and not is_formatter(f, True):
                raise ValueError, "%s: formatter keyword not formatter instance or name: %r" % (name, f)
        #XXX: validate any more keys?
        #XXX: raise error if unknown keys found?
        #   everything here is eventually passed to create_handler()

    def set_handler(self, name, **kwds):
        "add a handler configuration"
        name = parse_handler_name(name)
        #TODO: parse 'level' kwd?
        resolve_class_aliases(kwds)
        self._check_handler_config(kwds)
        self.handlers[name] = kwds

    def validate_handlers(self):
        "make sure formatter & target names all exist"
        for name, config in self.handlers.iteritems():
            f = config.get("formatter")
            if is_str(f) and self.get_formatter_config(f, None) is None:
                raise ValueError, "%s: unknown formatter %r" % (name, f)
            t = config.get("target")
            if t and self.get_handler_config(t, None) is None:
                raise ValueError, "%s: unknown target handler %r" % (name, t)

    #=========================================================
    #formatters
    #=========================================================
    formatters = None  #map of formatter name -> formatter constructor kwds

    def get_formatter_config(self, name, default=Undef):
        "return dict w/ config for formatter, or raise KeyError"
        if name in self.formatters:
            return self.formatters[name]
        if name in self.default_formatters:
            config = self.parse_formatter_desc(self.default_formatters[name])
            self._check_formatter_config(config)
            return config
        if default is Undef:
            raise KeyError, "no formatter named %r" % name
        else:
            return default

    def _check_formatter_config(self, kwds):
        klass = kwds.get("klass")
        if klass and not is_formatter(klass, False):
            raise ValueError, "%s: class keyword not a formatter class: %r" % (name, klass)
        #all other kwds passed to constructor ("format" passed as first positional arg if present)

    def set_formatter(self, name, **kwds):
        "add a formatter configuration"
        name = parse_formatter_name(name)
        #TODO: parse 'level' kwd?
        resolve_class_aliases(kwds)
        self._check_formatter_config(kwds)
        self.formatters[name] = kwds

    #=========================================================
    #applying configuration to logging system
    #=========================================================
    def validate(self):
        self.validate_loggers()
        self.validate_handlers()

    def apply(self):
        "apply configuration to logging system"
        self._handlers = {}
        self._formatters = {}

        #lock logging module while we're doing all this
        logging._acquireLock()
        try:
            self.raw_apply()
        finally:
            logging._releaseLock()

    def raw_apply(self):
        #load option flags
        root = logging.getLogger("")
        dxl = self.get_option("disable_existing_loggers")
        rl = self.get_option("reset_loggers") #reset all loggers to default state?
        rh = self.get_option("reset_handlers") #purge all handlers?
        if rl and not rh:
            #NOTE: get_option() should prevent this from ever happening.
            raise NotImplementedError, "reset_loggers w/o reset_handlers is not supported"

        #TODO: reimplement most of this using util functions
        #   eg purge_all_handlers(), reset_all_loggers()

        #grab list of existing loggers
        if rh or rl or dxl:
            existing = get_managed_loggers()

        #do global purge of all handlers
        if rh or rl:
            for logger in existing:
                if rh and logger.handlers:
                    purge_handlers(logger) #removed handlers from logger, calls close
                if rl:
                    logger.setLevel(logging.NOTSET)
                logger.propagate = 1
                logger.disabled = 0

        #update logger's levels, etc
        for name, config in self.loggers.iteritems():
            self.raw_apply_logger(name, **config)

        #replicate fileConfig()'s disable_existing_loggers behavior.
        #to replicate fileConfig w/ disable_existing_loggers, set reset_handlers=True
        if dxl:
            #since dxl implies rl + rh, we've already reset the level,prop,and disabled flags.
            #so all we have to do is set disabled=1 for any loggers with no configured parents.
            configured = self.loggers.keys()
            for logger in existing:
                name = logger.name
                if name in configured:
                    continue
                for test in configured:
                    if name.startswith(test + "."):
                        break
                else:
                    logger.disabled = 1

        #update capture options, but AFTER we've added our handlers
        self.raw_apply_capture_options()

    def raw_apply_logger(self, name, level=None, propagate=None, outputs=None, add=None):
        "apply any configuration changes to logger object"
        logger = logging.getLogger(name)
        if level is not None:
            logger.setLevel(level)
        if propagate is not None:
            logger.propagate = int(propagate)
        if outputs is not None:
            if not add:
                purge_handlers(logger)
            for name in outputs:
                if is_handler(name, True):
                    handler = name
                else:
                    handler = self.get_handler(name)
                logger.addHandler(handler)
        logger.disabled = 0

    def raw_apply_capture_options(self):
        "apply bps.logs.capture configuration changes"
        kwds = self.options

        value = kwds.get('capture_warnings')
        if value is True:
            fmt = kwds.get("warning_fmt")
            target = kwds.get("warning_target")
            capture.capture_warnings(fmt=fmt, target=target)
        elif value is False:
            capture.release_warnings()

        #check capture_stderr
        value = kwds.get("capture_stderr")
        if value is True:
            capture.capture_stderr()
        elif value is False:
            capture.release_stderr()

        #check capture_stdout
        value = kwds.get("capture_stdout")
        if value is True:
            capture.capture_stdout()
        elif value is False:
            capture.release_stdout()

    #=========================================================
    #handler creation
    #=========================================================
    _handlers = None #dict of handler name -> instance used by apply_handlers

    def get_handler(self, name):
        "get handler, creating if needed"
        if name not in self._handlers:
            config = self.get_handler_config(name)
            self._handlers[name] = self.create_handler(**config)
        return self._handlers[name]

    def create_handler(self,
                #constructor options
                klass=None, args=None,
                #configuration options
                level=None,
                formatter=None,
                target=None,
                startup_msg=None, delay_startup_msg=True,
                ):
        """create handler from options.

        .. note::
            This function relies on set_handler/get_handler_config
            to take care of all normalization and type-checking
            of it's inputs.

        :param klass:
            Handler class.

        :param args:
            Arguments to pass to handler constructor, in form of a Params object.

        :param level:
            Optional logging level for handler, interpreted via :func:`parse_level_name`

        :param startup_msg:
            Optional flag indicating handler should emit a "logging started" message
            when it runs. if not a boolean (True/False), assumed to contain a custom startup msg.

        :param delay_startup_msg:
            Optional flag to control whether startup_msg should be delayed
            until handler actually emits something, or be printed right away.
            Defaults to True (delayed until first message is logged).

        :param formatter:
            Optional formatter instance or name of formatter.

        :param target:
            Optionally specifies the name of another handler
            which should be retrieved and passed to this handler's setTarget() method.

        :Returns:
            a handler instance
        """
        #create handler
        if args is None:
            handler = klass()
        else:
            handler = klass(*args.args, **args.kwds)

        #set level
        if level is not None:
            handler.setLevel(parse_level_name(level))

        #set formatter
        if formatter:
            if isinstance(formatter, str):
                formatter = self.get_formatter(formatter)
            elif not is_formatter(formatter, True):
                raise TypeError, "formatter param must be str, or Formatter: %r" % (formatter,)
            handler.setFormatter(formatter)

        #set startup msg
        if startup_msg:
            set_startup_msg(handler, startup_msg, delay=delay_startup_msg)

        #set/register target
        if target is not None:
            if hasattr(handler, "setTarget"):
                target = self.get_handler(target)
                handler.setTarget(target)
            else:
                log.warning("ignoring target for handler: handler=%r target=%r",  handler,  target)

        #done
        return handler

    #=========================================================
    #formatter creation
    #=========================================================
    _formatters = None

    def get_formatter(self, name):
        "get formatter, creating if needed"
        if name not in self._formatters:
            config = self.get_formatter_config(name)
            #TODO: could fallback to trying name as class path?
            self._formatters[name] = self.create_formatter(**config)
        return self._formatters[name]

    def create_formatter(self, **kwds):
        klass = kwds.pop("klass", logging.Formatter)
        if 'format' in kwds:
            format = kwds.pop("format")
            return klass(format, **kwds)
        else:
            return klass(**kwds)

    #=========================================================
    #parse logging config from keywords
    #=========================================================
    def add_kwds(self, source):
        """parse logging config from kwd arguments,
    ala the direct config_logging() style.

    This is mainly used as the base class for parsing
    the various supporting logging config formats,
    but it can also be used to parse programmatic input
    in the form of keywords passed into the constructor.

    In this second mode, the following keywords are recognized:

        level
            This specifies the master logging level used by the root logger.
            This is a shortcut for setting the root logger via the levels keyword.

        levels
            This should be a dictionary mapping logger names to logging levels.

        formatters
            This should be a dictionary mapping formatter names to dicts of formatter options,
            to be passed to compile_formatter(). The names may be referred to by the handlers.

        handlers
            This should be a dictionary mapping handlers names to dicts of handlers options,
            to be passed to compile_handler(). The names may be referred to be the output section.

        outputs
            This should be a dictionary mapping loggers to dictionary
            of handler options. One option is "handlers",
            which should be a list of handler names or handler objects.
            There is also the "propagate" boolean keyword,
            and the "replace" boolean keyword.

        default_handler
            This is a shortcut, which lets you specifiy the kwds for a single handler,
            which will be set up as the ONLY handler for the root logger.
            ``default_handler=dict(XXX)`` is the same as
            ``output="<root>=default only",handlers=dict(default=dict(XXX))``,
            but is run before ``outputs`` and ``handlers`` are processed.

    .. note::

        If changes are made to an already-existing instance,
        call ``self.reparse()`` to re-run internal syntactic validation
        and parsing routines.
        """
        #
        #parse options first
        #
        if 'options' in source:
            opts = source['options']
        else:
            opts = source
        for name in self.ALL_OPTIONS:
            if name in opts:
                self.set_option(name, opts[name])

        #
        #parse kwds that could be user-provided OR
        #being passed back in from LoggingConfig object
        #

        #formatters
        if 'formatters' in source:
            for name, desc in source['formatters'].iteritems():
                config = self.parse_formatter_desc(desc)
                self.set_formatter(name, **config)

        #handlers
        if 'handlers' in source:
            for name, desc in source['handlers'].iteritems():
                config = self.parse_handler_desc(desc)
                self.set_handler(name, **config)

        #loggers
        if 'loggers' in source:
            for name, desc in source['loggers'].iteritems():
                self.add_output_desc(name, desc)

        #
        #parse user-provided programmatic input
        #

        #check for master level
        if 'level' in source:
            self.set_level(ROOT, source['level'])

        #check for level dict, parse values to levels
        if 'levels' in source:
            levels = source['levels']
            if is_str(levels):
                levels = parse_dict_string(levels, "\n,;", strip_comments=True)
            for name, level in levels.iteritems():
                self.set_level(name, level)

        #check for default handler
        if 'default_handler' in source:
            self.set_default_handler(source['default_handler'])

        #check for output dict
        if 'outputs' in source:
            for name, desc in source['outputs'].iteritems():
                #desc should be a dict or list
                if is_seq(desc):
                    desc = dict(outputs=desc)
                self.add_output_desc(name, desc, outputs=True)

    def add_output_desc(self, name, desc, outputs=False):
        if not outputs:
            if 'level' in desc:
                self.set_level(name, desc['level'])
        if 'propagate' in desc:
            self.set_propagate(name, desc['propagate'])
        if not outputs and 'outputs' in desc:
            out = desc['outputs']
        elif outputs and 'handlers' in desc:
            out = desc['handlers']
        else:
            out = None
        if out is not None:
            if is_str(out):
                out = splitcomma(out)
            if desc.get('add'):
                self.add_outputs(name, out)
            else:
                self.set_outputs(name, out)

    def parse_handler_desc(self, config):
        "parse programmatic-input format for handler config dict"
        #NOTE: used internally by get_handler_config & also by KwdConfig
        config = config.copy()
        resolve_class_aliases(config)
        klass = config['klass']
        if not is_handler(klass, False):
            klass = resolve_class_path(klass, self.handler_prefixes)
        config['klass'] = klass
        if 'kwds' in config:
            warn("'kwds' option deprecated for handler desc, used args instead", stacklevel=self.stacklevel+2) #relative to add_kwds call
            if 'args' in config:
                raise ValueError, "args and kwds both specified"
            config['args'] = config.pop("kwds")
        if 'args' in config and is_str(config['args']):
            config['args'] = Params.parse(config['args'], scope=self.scope)
        return config

    def parse_formatter_desc(self, config):
        "parse programmatic-input format for formatter config dict"
        #NOTE: used internally by get_formatter_config & also by KwdConfig
        config = config.copy()
        resolve_class_aliases(config)
        if 'klass' in config:
            klass = config.get('klass')
            if not is_formatter(klass, False):
                klass = resolve_class_path(klass, self.formatter_prefixes)
            config['klass'] = klass
        return config

    def set_default_handler(self, handler):
        "register the default handler"
        #this function provides a useful shorthand
        #for adding a handler to the root logger.

        if is_str(handler) or is_handler(handler, True):
            self.set_outputs(ROOT, [handler])
        elif isinstance(handler, dict):
            config = self.parse_handler_desc(handler)
            name = self.DEFAULT_HANDLER_NAME
            self.set_handler(name, **config)
            self.set_outputs(ROOT, [name])
        else:
            #TODO: accept handler instances?
            raise TypeError, "default_handler must be dict/str: %r" % (handler,)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#compact format (see bps documentation for spec)
#=========================================================
class CompactConfig(LoggingConfig):
    """parse compact logging config format, returning LoggingConfig object.

    :arg source:
        String, stream, or filepath containing
        an standard logging config ini file.

    :returns:
        Config in parsed form, as a LoggingConfig object.

    .. note::
        This merely creates a valid LoggingConfig object,
        it doesn't actually make any changes to the logging system
        (you must call the LoggingCofnig.apply() method for that).
    """
    #=========================================================
    #class constants
    #=========================================================
    OPTIONS_SECTION = "logging:options"
    LEVEL_SECTION = "logging:levels"
    OLD_OUTPUT_SECTION = "logging:output" #deprecated section name, don't use
    OUTPUT_SECTION = "logging:outputs"
    HANDLER_SECTION = "logging:handler"
    FORMAT_SECTION = "logging:formatter"

    #HACK: have to use 'raw' mode for these keys,
    #since ConfigParser has no way to escape '%' options
    RAW_FORMATTER_KEYS = [ 'format', 'fmt', 'datefmt' ]
    RAW_OPTIONS = ESCAPE_OPTIONS = [ 'warning_fmt', 'warning_target' ]

    #=========================================================
    #detect
    #=========================================================
    @classmethod
    def detect_cp(cls, parser):
        "detect format from config-parser object"
        for name in (cls.OPTIONS_SECTION, cls.LEVEL_SECTION, cls.OUTPUT_SECTION,
                     cls.OLD_OUTPUT_SECTION):
            if parser.has_section(name):
                return True
        return False

    #=========================================================
    #parse
    #=========================================================
    def __init__(self, source, **kwds):
        "create new config from ini source"
        self.__super.__init__(**kwds)
        self.stacklevel += 1
        self.init_parser(source)
        self.parse_options()
        self.parse_levels()
        self.parse_outputs()
        self.parse_formatters()
        self.parse_handlers()

    def init_parser(self, source):
        #parse the file
        cp = self.cp = ConfigParser.ConfigParser()
        try:
            read_into_parser(source, parser=cp)
        except ValueError, err:
            raise InputError(str(err))

        #purge defaults (if this section is part of a larger ini file, eg pylons,
        #the defaults will add spurious logger names...
        #FIXME: really, we just want to purge defaults when getting options list,
        # could leave defaults alone when reading values.
        cp._defaults.clear()

    def parse_options(self):
        "parse logging:options section"
        cp = self.cp

        #parse options
        if cp.has_section(self.OPTIONS_SECTION):
            for key in cp.options(self.OPTIONS_SECTION):
                if key not in self.ALL_OPTIONS:
                    warn("unknown logging:options key encountered: %r" %(key, ), stacklevel=self.stacklevel+1)
                    continue
                raw = (key in self.RAW_OPTIONS)
                value = cp.get(self.OPTIONS_SECTION, key, raw)
                self.parse_option(key, value)

    def parse_option(self, key, value):
        if key in self.ESCAPE_OPTIONS:
            value = unescape_string(value)
        if key in self.BOOL_OPTIONS:
            value = asbool(value)
        self.set_option(key, value)

    def parse_levels(self):
        "parse logging:levels section"
        cp = self.cp
        """
        spec defines format as:

            [logging:levels]
            lname = level
            lname = level #comment

        lname can be name of a logger, or <root>
        level can be name of level or number (NOTSET included).
        """
        if cp.has_section(self.LEVEL_SECTION):
            for lname in cp.options(self.LEVEL_SECTION):
                value = cp.get(self.LEVEL_SECTION, lname)
                self.set_level(lname, stripcomment(value))

    def parse_outputs(self):
        "parse logging:outputs section"
        cp = self.cp

        #parse *old* logger:output section
        #TODO: support for this section name should be removed after 2009-08-01
        if cp.has_section(self.OLD_OUTPUT_SECTION):
            warn("'logging:output' is deprecated, use 'logging:outputs' instead", DeprecationWarning, stacklevel=self.stacklevel+1)
            #each value is a comma-sep list of handler names, but that's accepted by set_logging_outputs()
            for lname in cp.options(self.OLD_OUTPUT_SECTION):
                value = cp.get(self.OLD_OUTPUT_SECTION, lname)
                self.parse_output(lname, value)

        #parse new logger:outputs section
        """
        spec defines format as:

            [logging:outputs]
            lname = handler_a, handler_b #comment
            lname = #this would purge all handlers
            lname = handler_a | propagate=True, add=True #keywords appended to end.
        """
        if cp.has_section(self.OUTPUT_SECTION):
            #each value is a comma-sep list of handler names, but that's accepted by set_logging_outputs()
            for lname in cp.options(self.OUTPUT_SECTION):
                value = cp.get(self.OUTPUT_SECTION, lname)
                self.parse_output(lname, value)

    def parse_output(self, lname, value):
        "parse logging:outputs line"
        value = stripcomment(value)
        kwds = parse_output_value(value)
        if 'propagate' in kwds:
            self.set_propagate(lname, asbool(kwds.pop('propagate')))
        else:
            self.set_propagate(lname, True)
        if 'add' in kwds:
            add = asbool(kwds.pop("add"))
        else:
            add = False
        outputs = kwds.pop("outputs")
        if kwds:
            warn("ignoring unknown flags in logging:outputs section: %r = %r" % (lname, kwds))
        if add:
            self.add_outputs(lname, outputs)
        else:
            self.set_outputs(lname, outputs)

    def parse_formatters(self):
        "parse logging:formatter:xxx sections"
        cp = self.cp

        """
        spec assumes the following...

            [logging:formatter:a]
            class = zzz #optional, defaults to 'logging.Formatter', resolved as class path
            format = zzz #optional, raw - first positional arg to formatter if specified.
            #all other keys taken as kwd arguments to pass constructor.
            #if key ends with "format" or "fmt" it will be read raw.
            #note that inline comments are NOT supported here.
        """

        prefix = self.FORMAT_SECTION + ":"
        for section in cp.sections():
            if section.startswith(prefix):
                fname = section[len(prefix):]
                self.parse_formatter(section, fname)

    def parse_formatter(self, section, fname):
        cp = self.cp
        opts = cp.options(section)
        kwds = {}
        #XXX: what if user uses 'klass' instead?
        if 'class' in opts:
            kwds['klass'] = resolve_class_path(cp.get(section, 'class'), self.formatter_prefixes)
            opts.remove('class')
        for key in opts:
            #XXX: could create logging:options flag for setting additional raw kwds
            raw = (key in self.RAW_FORMATTER_KEYS)
            kwds[key] = cp.get(section, key, raw)
        self.set_formatter(fname, **kwds)

    def parse_handlers(self):
        "parse logging:handler:xxx sections"

        """
        spec assumes the following...

            [logging:handler:a]
            class = xxx #required, should be class path
            args = zzz #optional, should eval to tuple or fcall under vars(logging) context

            #all other kwds are sent to handler constructor.
            #common ones...
            formatter = yyy #optional
            level = xxx #optional
            target = yyy #optional, defaults to '' but only for MemoryHandler subclasses

            #note that inline comments are NOT supported here.
        """
        cp = self.cp
        prefix = self.HANDLER_SECTION + ":"
        for section in cp.sections():
            if section.startswith(prefix):
                hname = section[len(prefix):]
                self.parse_handler(section, hname)

    def parse_handler(self, section, hname):
        cp = self.cp
        opts = cp.options(section)
        kwds = {}
        #XXX: what if user uses 'klass' instead?
        klass = cp.get(section, "class")
        kwds['klass'] = resolve_class_path(klass, self.handler_prefixes)
        opts.remove("class")
        if 'args' in opts:
            args = cp.get(section, "args")
            opts.remove("args")
            kwds['args'] = Params.parse(args, scope=self.scope)
        for key in opts:
            kwds[key] = cp.get(section, key)
        if 'startup_msg' in kwds:
            try:
                kwds['startup_msg'] = asbool(kwds['startup_msg'])
            except ValueError:
                pass
        if 'delay_startup_msg' in kwds:
            kwds['delay_startup_msg'] = asbool(kwds['delay_startup_msg'])
        self.set_handler(hname, **kwds)

#=========================================================
#std format (from original logging module)
#=========================================================
class StandardConfig(LoggingConfig):
    """parse standard logging config format, returning LoggingConfig object.

    :arg source:
        String, stream, or filepath containing
        an standard logging config ini file.

    :returns:
        Config in parsed form, as a LoggingConfig object.

    .. note::
        This merely creates a valid LoggingConfig object,
        it doesn't actually make any changes to the logging system
        (you must call the LoggingCofnig.apply() method for that).

    .. note::
        This function attempts to replicate the semantics of the original parser
        as closely as possible, any deviations are probably a bug.
    """

    @classmethod
    def detect_cp(cls, parser):
        """detect ini file contains standard logging config format"""
        return parser.has_section("loggers") and parser.has_section("logger_root")

    def __init__(self, source, **kwds):
        "create new config from ini source"

        self.__super.__init__(**kwds)

        #parse the file
        cp = ConfigParser.ConfigParser()
        try:
            read_into_parser(source, parser=cp)
        except ValueError, err:
            raise InputError(str(err))

        #parse logger declarations
        """
        std format assumes the following...

            [loggers] #required
            keys = a,b,c  #required
            #all other opts ignored

            [logger_root] #required
            level = xxx #optional
            handlers = a,b,c #optional
            #handlers purged regardless of lists's presence
            #all other opts ignored

            [logger_a]
            qualname = yyy #required
            propagate = 1|0 #optional, defaults to 1
            level = xxx #optional
            handlers = a,b,c #optional
            #handlers purged regardless of list's presence
            #all other opts ignored
        """
        snames = splitcomma(cp.get("loggers", "keys"))
        if 'root' not in snames:
            snames.append("root")
        for sname in snames:
            section = "logger_" + sname
            opts = cp.options(section)
            if sname == "root":
                lname = ROOT
            else:
                lname = cp.get(section, "qualname")
            if 'level' in opts:
                self.set_level(lname, cp.get(section, 'level'))
            if sname != "root":
                if 'propagate' in opts:
                    self.set_propagate(lname, asbool(cp.getint(section, 'propagate')))
                else:
                    self.set_propagate(lname, True)
            if 'handlers' in opts:
                self.set_outputs(lname, splitcomma(cp.get(section, 'handlers')))
            else:
                self.clear_outputs(lname)

        #parse formatters
        """
        std format assumes the following...

            [formatters] #required
            keys = a,b,c #required

            [formatter_a] #required
            format = xxx #optional, raw, defaults to None
            datefmt = yyy #optional, raw, defaults to None
            class = zzz #optional, defaults to 'logging.Formatter', resolved as class path
            #all other opts ignored
        """
        snames = splitcomma(cp.get("formatters", "keys"))
        for sname in snames:
            section = "formatter_" + sname
            opts = cp.options(section)
            kwds = {}
            if 'format' in opts:
                kwds['format'] = cp.get(section, "format", 1)
            if 'datefmt' in opts:
                kwds['datefmt'] = cp.get(section, "datefmt", 1)
            if 'class' in opts:
                kwds['klass'] = resolve_class_path(cp.get(section, "class"))
            self.set_formatter(sname, **kwds)

        #parse handlers
        """
        std format assumes the following...

            [handlers] #required
            keys = a,b,c #required

            [handler_a] #required
            class = xxx #required, should eval to class undef vars(logging) context OR be class path
            args = zzz #required, should eval to tuple under vars(logging) context
            formatter = yyy #optional, defaults to ''
            level = xxx #optional
            target = yyy #optional, defaults to '' but only for MemoryHandler subclasses
        """
        snames = splitcomma(cp.get("handlers", "keys"))
        for sname in snames:
            section = "handler_" + sname
            opts = cp.options(section)
            kwds = {}
            klass = cp.get(section, "class")
            try:
                kwds['klass'] = eval(klass, self.scope)
            except (AttributeError, NameError):
                kwds['klass'] = resolve_class(klass)
            args = cp.get(section, "args")
            kwds['args'] = eval(args, self.scope)
            for k in ("formatter", 'level', 'target'):
                if k in opts:
                    kwds[k] = cp.get(section, k)
            self.set_handler(sname, **kwds)

        #set option to replicate fileConfig()'s behavior.
        self.set_option("disable_existing_loggers", True)

#=========================================================
#private helpers
#=========================================================
BAD_CHARS = "<>[]=#,|"

def parse_logger_name(value):
    """bps restricts logger names to not contain certain chars"""
    if value == ROOT: #resolve the alias
        return ""
    if value:
        for c in BAD_CHARS:
            if c in value:
                raise ValueError, "invalid logger name: %r" % (value,)
    return value

def parse_formatter_name(name):
    """bps restricts formatter names to not contain certain chars"""
    for c in BAD_CHARS:
        if c in name:
            raise ValueError, "invalid formatter name: %r" % (name,)
    return name

def parse_handler_name(name):
    """bps restricts handler names to not contain certain chars"""
    for c in BAD_CHARS:
        if c in name:
            raise ValueError, "invalid handler name: %r" % (name,)
    return name

def parse_output_value(value):
    """parse line from compact format's logging:outputs section.

    :arg value: string containig logger's output config

    :returns:
        dict containing:
            outputs - list of handler names
            and any other flags which were set
    """
    kwds = {}
    idx = value.find("|")
    if idx > -1:
        flags = value[idx+1:]
        #should be string of "a=b, c=d" etc
        #NOTE: we use parse_param_string to coerce add/propagate to bool.
        #could use other method.
        ##flags = parse_dict_string(flags, ",")
        flags = Params.parse(flags)
        if flags.args:
            raise ValueError, "positional arguments not allowed"
        flags = flags.kwds

        #should now be dict of dict(a="b",c="d")
        kwds.update(flags)
        #strip from end
        value = value[:idx]
    if value.lower().endswith(" only"):
        #TODO: support for this flag should be removed after 2009-08-01
        warn("'only' suffix is ignored", DeprecationWarning)
        #this used to be an uglier way to signal propagate=False + add=False
        #but as of 4.1, add=False by default,
        #and most of the places "only" was used, propgate=False didn't matter
        value = value[:-5]
    kwds['outputs'] = splitcomma(value)
    return kwds

def resolve_class_aliases(kwds):
    "resolve aliases for class keyword, allowing easier data-entry"
    if 'class' in kwds:
        warn("'klass' kwd is preferred over 'class' kwd: %r" % (kwds,))
        kwds['klass'] = kwds.pop("class")
    if 'class_' in kwds:
        warn("'klass' kwd is preferred over 'class_' kwd: %r" % (kwds,))
        kwds['klass'] = kwds.pop("class_")
    return kwds

#=========================================================
#generic helpers
#=========================================================

def parse_dict_string(source, sep, strip_comments=False):
    """parses and returns a string->string dictionary from various formats.

    This is used by parse_config and friends to parse
    level & output description blocks, among other things.

    :arg source:
        The input string, may be any of the following:

        * a string containing a single ``"k=v"`` element
        * a string of ``"k=v"`` elements separated by the separator.
        * a string of ``"k=v #comment"`` or ``"k=v"`` elements separated by the separator
          (this only applies if strip_comments set to True).

    :arg seps:
        A sequence of potential separator strings to try.
        If more than one, all will be tried in turn.

    :param strip_comments:
        If True, inline comments starting with "#" will be stripped
        from the end of each value.

    :returns:
        A dictionary containing all the k->v pairs in the source,
        after all whitespace, blank elements, and comments have been stripped out.

    :raises ValueError: if it encounters a non-empty element that's not "k=v #comment"
    :raises TypeError: if list contains something besides strings and (k,v) pairs.

    Usage Examples::
        >>> from bps.logs.config import parse_dict_string
        >>> parse_dict_string("a=1;b=2",";")
        { a="1", b="2" }
        >>> parse_dict_string("a=1 #blah\nd=2\n\n\n#blah","\n", strip_comments=True)
        { a="1", d="2" }
    """
    assert is_str(source)

    #split apart string into elements if needed
    for s in sep:
        if s in source:
            parts = source.split(s)
            break
    else:
        parts = [ source ]

    #break apart k=v pairs in list
    #assume it's a list of "k=v #comment" elements and (k,v) pairs
    kwds = {}
    for elem in parts:
        if strip_comments:
            idx = elem.find("#")
            if idx > -1:
                elem = elem[:idx]
        idx = elem.find("=")
        if idx > -1:
            k = elem[:idx].strip()
            v = elem[idx+1:].strip()
            kwds[k] = v
        elif elem.strip():
            raise ValueError, "unexpected element in string %r: %r" % (source, elem)

    return kwds

def splitcomma(value):
    "split a string on the commas, striping out whitespace and empty sections"
    return [ a.strip() for a in value.split(",") if a.strip() ]

def stripcomment(value):
    "strip inline comment from string"
    idx = value.find("#")
    if idx > -1:
        value = value[:idx]
    return value.strip()

def _try_import_module(name):
    "helper for resolve_class_path"
    try:
        return __import__(name)
    except ImportError, err:
        if str(err) == "No module named " + name:
          return None
        if '.' in name:
          if str(err) == "No module named " + name[name.rfind(".")+1:]:
             return None
        raise

def _try_import_data(name):
    "helper for resolve_class_path"
    name = name.split('.')
    used = name.pop(0)
    found = _try_import_module(used)
    if found is None:
        return None
    for n in name:
        used = used + '.' + n
        try:
            found = getattr(found, n)
        except AttributeError:
            if _try_import_module(used) is None:
                return None
            found = getattr(found, n)
    return found

#XXX: would this be generally useful enough to add to bps.meta ?
def resolve_class_path(name, prefixes=[]):
    "resolve class path, trying various prefixes"
    if '.' in name:
        cls = _try_import_data(name)
        if cls is not None:
            return cls
    for prefix in prefixes:
        cls = _try_import_data(prefix + "." + name)
        if cls is not None:
            return cls
    raise ImportError, "No object path named %s" % (name,)

#=========================================================
#EOF
#=========================================================
