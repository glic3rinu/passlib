"""bps.parsing.config -- ConfigParser helpers"""
#=========================================================
#imports
#=========================================================
#core
from cStringIO import StringIO
import re
from logging import getLogger; log = getLogger(__name__)
import ConfigParser
import os.path
#site
#pkg
from bps.stream import get_input_type
#local
__all__ = [
##    "unescape_string",
##    "section_to_dict",
##    "no_parser_defaults",
]

#=========================================================
#parser object helpers
#=========================================================
def read_into_parser(source, parser=None, errors="strict", reset=False, source_type=None):
    """load input into parser instance

    This is a helper for loading inputs into a ConfigParser instance,
    since it's provider read() method is somewhat annoying.

    :param source:
        The source to load data from.
        This may be any of:

            * a path to a local file
            * a string containing the raw data
            * an open stream (file, buffer) object

        Which one of these it is will be autodetected,
        and the appropriate parser methods invoked.

    :param parser:
        The parser to load data into.
        If not specified, a new :class:`ConfigParser.ConfigParser` instance
        is created, populated, and returned.

    :param errors:
        What to do when errors occur:

        ============    =============================================
        Value           Action
        ------------    ---------------------------------------------
        ``"strict"``    errors are raised; this is the default
        ``"ignore"``    errors are silently ignored and ``None`` is returned
        ``"log"``       errors are logged and ``None`` is returned
        ============    =============================================

    :param reset:
        If true, and source is a stream,
        it will be reset back to it's current location
        after the data has been loaded.
        This is useful when you want to "peek" at the data in the stream.

    :raises ValueError:
        if file coudn't be parsed as a cfg/ini file

    :returns:
        parser object on success, ``None`` if errors occurred but were ignored.
    """
    if parser is None:
        parser = ConfigParser.ConfigParser()
    t = get_input_type(source, source_type=source_type)
    if t == "raw":
        parser.readfp(StringIO(source))
    elif t == "stream":
        if reset:
            pos = source.tell()
        parser.readfp(source)
        if reset:
            source.seek(pos, 0)
    else:
        assert t == "path"
        if not os.path.exists(source):
            if errors == "ignore":
                return None
            elif errors == "log":
                log.error("ini file not found: %r", source)
                return None
            else:
                raise ValueError, "ini file not found: %r" % (source,)
        if not parser.read([source]):
            if errors == "ignore":
                return None
            elif errors == "log":
                log.error("failed to read ini file: %r", source)
                return None
            else:
                raise ValueError, "failed to read ini file: %r" % (source,)
    return parser

def parser_get_section(parser, section, raw=None):
    "convert section of ConfigParser to a dict"
    #TODO: document this better
    out = {}
    for key in parser.options(section):
        out[key] = parser.get(section, key, raw=(raw and (raw is True or key in raw)))
    return out

#=========================================================
#helpers
#=========================================================
def unescape_string(value):
    """if a value is defined in the ini using '\n' etc, the backslashes will be
    returned literally. this takes in such a string, and lets python eval
    all the backslash-escapes in the string"""
    if value is None: return value
    #Escape any double-quote chars with an EVEN number of preceding backslashes,
    #so eval() can't be exploited by malicious input; but DONT escape any
    #double-quote chars with an ODD number of preceding backslashes,
    #those are already properly escaped. I think that covers it :)
    value = re.sub(r'(^|[^\\])((\\\\)*)"', r'\1\2\\"', value)
    return eval('"%s"' % (value,))

#=========================================================
#unused
#=========================================================
##
###XXX: is this worth keeping in the long run?

#NOTE: just "path,section" currently used, rest can be redesigned
#should expand to load whole file if possible
def read_to_dict(path, section, cls=ConfigParser.ConfigParser, defaults=None, raw=None):
    "load specified section from file and convert to dict"
    p = cls()
    read_into_parser(path, p)
    if defaults:
        p.defaults().update(defaults)
    if section == "DEFAULT":
        #XXX: what about RAW here?
        return p.defaults()
    else:
        return parser_get_section(p, section, raw=raw)

##class no_parser_defaults(object):
##    """context manager that disables ConfigParser defaults
##    for the duration it's scope.
##    value returned by manager is the defaults we're ignoring
##        (please treat as readonly!!!)
##    FIXME: this currently isn't threadsafe!!!
##        would have to put a lock inside parser object, say.
##
##    :Parameters:
##        parser
##            parser to act on
##        keep
##            optional list of keys whose defaults should be kept
##    """
##    "with-statement manager that disables parser's defaults"
##    def __init__(self, parser, keep=None):
##        if hasattr(parser,  "cfg"): #hack for ConfigDict
##            parser = parser.cfg
##        self.parser = parser
##        self.keep = keep
##
##    def __enter__(self):
##        self.defaults = self.parser._defaults
##        self.parser._defaults = {}
##        if self.keep:
##            for k in self.keep:
##                if k in self.defaults:
##                    self.parser._defaults[k] = self.defaults[k]
##        return self.defaults
##
##    def __exit__(self, *exc_info):
##        self.parser._defaults = self.defaults

#=========================================================
#EOF
#=========================================================
