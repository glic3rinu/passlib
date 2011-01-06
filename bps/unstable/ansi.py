"""ansi (aka vt100) control code handling

this module contains some attempts at ANSI control code parsing,
with a focus on the color control codes. It also contains
some ctypes code for rendering said color codes onto windows consoles.
"""
#=========================================================
#imports
#=========================================================
#core
import sys
import os
import re
#pkg
from bps.logs.proxy_logger import log
from bps.meta import Params
#local
__all__ = [
    'AnsiCode', 'is_ansi_code',
    'parse_ansi_string',
    'len_ansi_string',
]

#=========================================================
#constants
#=========================================================
colors = ("black","red","green","yellow", "blue","magenta","cyan","white","default")

def write_test_text(stream=sys.stdout):
    "helper which writes some text to test ansi escape code handling"
    def write(msg, *a, **k):
        if a: msg %= a
        if k: msg %= k
        stream.write(msg)

    r8 = range(8) + [9]
    hs = 16
    hfmt = "\x1b[0m%16s: "
    fmt = "%-8s " * 8
    x = "-" * 7 + " "

    write("\x1b[2J\x1b[9999;9999H\x1b[3DBR\x1b[H")

    write("COLOR/STYLE CODES...\n")
    write(" " * hs + "  ")
    for c in colors:
        if not c:
            continue
        write("%-8s", c)
    write("\n")

    write("-" * (hs+1) + " " + x * 9 + "\n")

    def write_row(name, seq):
        write(hfmt % name)
        for v in seq:
            write("\x1b[%smTEST    \x1b[0m",v)
        write("\n")

    write_row("fg", ("3%s" % i for i in r8))
    #NOTE: 37 should basically be ignored

    write("\n")
    write_row("unbold", ("1;3%s;22" % i for i in r8))
    write_row("bold", ("1;3%s" % i for i in r8))

##    write("\n")
##    write_row("unitalic", ("3;3%s;23" % i for i in r8))
##    write_row("italic", ("3;3%s" % i for i in r8))

    #4/24 - underlined

    write("\n")
    write_row("bg", ("4%s" % i for i in r8))
    write_row("bg+bold", ("1;4%s" % i for i in r8))
#    write("\n")
#    write_row("under", ("4;3%s" % i for i in r8))

    write("\n")
    write_row("unblink", ("6;3%s;25" % i for i in r8))
    write_row("blink", ("5;3%s" % i for i in r8))
    write_row("blink+bold", ("6;1;3%s" % i for i in r8))

    write("\n")
    write_row("normal", ("7;3%s;27" % i for i in r8))
    write_row("reverse", ("7;3%s" % i for i in r8))
    write_row("bold+reverse", ("1;7;3%s" % i for i in r8)) #effective fg should be bold
    write_row("blink+reverse", ("5;7;3%s" % i for i in r8))

    write("\n")
    write_row("visible", ("8;3%s;28" % i for i in r8))
    write_row("conceal", ("8;3%s" % i for i in r8)) #should display as solid BG block

    write("-" * (hs+1) + " " + x * 9 + "\n")

    write("\nCURSOR CONTROL CODES...\n")
    write("1. UP->       <--\n")
    write("  ERROR\x1b[1ATEST-UP\n2.     ^     ^\n")
    write("3. RIGHT ------\\/        \\/\n")
    write("4. \x1b[13CTEST-RIGHT\n")
    write("5. LEFT---->    ERROR<--\x1b[12DTEST-LEFT\n")
    write("6. DOWN----\\/       \\/\n7.\n  ERROR     \x1b[2A\x1b[1BTEST-DOWN\n8.         /\\       /\\\n")
    write("9. Far Right... \x1b[999C\x1b[13DTEST-FAR-RIGHT\nERROR\x1b[999D\x1b[1AA.\nB.    \n")

#=========================================================
#main classes
#=========================================================
#XXX: could remove the "CODESET." prefix from everything
class CODESET:
    #the 'c0' set
    #NOTE: this library ignores 0x09, 0x0A, 0x0D, and handles 0x1B specially
    #   xxx: could make this a special policy
    C0 = "c0"
        #range(0x00,0x20)
        #identified by ESC + 0x21 + 0x40

    #the 'c1' set
    #NOTE: until CSTR support is added, this will parse CSTRs incorrectly
    C1 = "c1"
    #    #ESC + range(0x40,0x60)
    #    #identified by ESC + 0x26 0x40
    #    #8bit: 7bit identified by ESC + 0x20 + 0x46
    #    #8bit: raw bytes in range(0x80,0xA0)
    #    #8bit: identified by ESC + 0x22 0x46

    #control sequences
    CSEQ = "cseq"
        #ESC + 0x5b + P=range(0x30,0x40)? + I=range(0x20,0x30)? + F=range(0x40,0x7F)
        #   note F=range(0x70,0x7F) reserved for private/experimental use
        #8bit: 0x9b instead of ESC + 0x5b

    #indep control funcs
    ICF = "icf"
        #ESC + range(0x60,0x7F)

    #code currently doesn't support parsing these,
    ###control strings - meaning dependant on sender & receiver
    ##CSTR = "cstr"
    ##    #startr + cstr + end + ST
    ##    #start: APC, DCS, OSC, PM, SOS - all defined in C1
    ##    #cstr: (range(0x08,0x0D)|range(0x20,0x7F))?
    ##    #   or any bitseq but SOS / ST

    values = (C0, C1, CSEQ, ICF)

class AnsiError(ValueError):
    "base for all ansi parsing errors"

class AnsiParseError(AnsiError):
    "error raised when parsing an incorrectly structured ansi control code"

class AnsiCommandError(AnsiError):
    "error raised when command contains invalid arguments"

class AnsiCode(object):
    "base class representing a vt100 control code"
    #=========================================================
    #instance attrs
    #=========================================================

    #general
    malformed = None #flag set if code is malformed: None if not malformed; if malformed, non-empty string containing error message
    source = None #source string if set explicitly - use 'source' property
    codeset = None #codeset this belongs to (one of CODESET.values)
        #NOTE: this will be None for an instance IFF it's a "malformed" code
    code = None #always contains code string w/ CODESET specific prefix & params removed
        #see also <{codeset}_code>

    argstr = None #raw parameter string for CSEQ codes (empty string if no parms)

    #command specific attrs
    args = None #generic tuple of parsed args
    mode = None #used by some cseq commands which have a "mode" parameter
    offset = None #used by some cseq commands which encode a single relative offset
    row = None #used by some cseq commands which encode a absolute row
    col = None #used by some cseq commands which encode a absolute col

    #=========================================================
    #init
    #=========================================================
    def __init__(self, codeset, code, argstr=None, source=None, malformed=None):
        if codeset is None:
            assert code is None
            assert argstr is None
        else:
            if codeset not in CODESET.values:
                raise ValueError, "invalid codeset: %r" % (codeset,)
            if not code:
                raise ValueError, "code must be specified"
        if malformed is True:
            malformed = "<unknown reason>"
        if malformed:
            assert source
            assert isinstance(malformed,str),"bad value: %r" % (malformed,)
        self.malformed = malformed
        self.codeset = codeset
        self.code = code
        self.source = source
        if argstr is None and codeset == CODESET.CSEQ:
            argstr = ""
        self.argstr = argstr

        #run code-specific init func if present
        if code:
            func = self._get_init_func()
            #XXX: not sure about this policy
            if malformed:
                try:
                    func()
                except AnsiError, err:
                    self.malformed = "%s; %s" % (self.malformed, str(err))
            else:
                func()

    def _get_init_func(self):
        "retrieve code-specific init function"
        codeset, code = self.codeset, self.code
        name = "init_" + codeset + "_" + "_".join(
            c if c.isalnum()
              else "%02x" % (ord(c),)
            for c in code
            )
        func = getattr(self, name, None)
        if func:
            return func
        name = "init_" + codeset + "_default"
        func = getattr(self, name, None)
        if func:
            return func
        return self.init_default

    @classmethod
    def try_parse(cls, source):
        "wrapper for :meth:`parse` which catches AnsiErrors"
        try:
            return True, cls.parse(source)
        except AnsiError, err:
            return False, err

    #XXX: flag controlling if argstr-related errors should be raised vs ignored vs turned into malformed?

    @classmethod
    def parse(cls, source):
        "parse control sequence; raises ValueError if format isn't right"
        if not source:
            raise AnsiParseError, "empty string is not a code"
        elif source.startswith("\x1b"):
            if len(source) < 2:
                raise AnsiParseError, "too few characters in control code"
            s1 = source[1]
            if s1  == "[":
                #parse cseq
                if len(source) < 3:
                    raise AnsiParseError, "too few characters in control sequence"
                code = source[-1]
                if code < '\x40' or code >= '\x7F':
                    raise AnsiParseError, "invalid final character in control sequence"
                idx = len(source)-2
                while idx > 1 and '\x20' <= source[idx] < '\x30':
                    idx -= 1
                code = source[idx+1:-1] + code
                argstr = source[2:idx+1]
                return cls(codeset=CODESET.CSEQ, code=code,
                           argstr=argstr, source=source)
            elif s1 < '\x40':
                #non-standard, but some legacy codes exist.
                #TODO: should have init_c1_default issue warning
                ##raise ValueError, "invalid control code"
                if len(source) > 2:
                    #TODO: could be cstr instead
                    raise AnsiParseError, "too many characters in (c1) control code"
                return cls(codeset=CODESET.C1, code=s1, source=source)
            elif s1 < '\x60':
                #parse c1
                if len(source) > 2:
                    #TODO: could be cstr instead
                    raise AnsiParseError, "too many characters in (c1) control code"
                return cls(codeset=CODESET.C1, code=s1, source=source)
            elif s1 < '\x7F':
                #parse icf
                if len(source) > 2:
                    raise AnsiParseError, "too many characters in (icf) control code"
                return cls(codeset=CODESET.ICF, code=s1, source=source)
            else:
                raise AnsiParseError, "invalid control code"
        elif len(source) == 1 and source < '\x20':
            return cls(codeset=CODESET.C0, code=source, source=source)
        else:
            raise AnsiParseError, "unknown control code"

    #=========================================================
    #python protocol
    #=========================================================
    def __str__(self):
        "use source code came from, or render it as ansi string"
        if self.source is None:
            return self.render()
        else:
            return self.source

    def render(self):
        "render string from components"
        cs = self.codeset
        if cs == CODESET.CSEQ:
            return "\x1b[" + self.argstr + self.code
        elif self.codeset == CODESET.C1 or self.codeset == CODESET.ICF:
            return "\x1b" + self.code
        elif not self.codeset:
            return ""
        else:
            assert self.codeset == CODESET.C0
            return self.code

    def __repr__(self):
        p = Params(self.codeset, self.code)
        if self.codeset == CODESET.CSEQ and self.argstr:
            p.append(self.argstr)
        if self.source is not None and self.source != self.render():
            p.append(source=self.source)
        malformed = self.malformed
        if malformed:
            ##if ';' in malformed:
            ##    #strip out init_xxx level errors that were added
            ##    malformed = malformed[:malformed.index(";")]
            p.append(malformed=malformed)
        return "AnsiCode(%s)" % p

    def __eq__(self, other):
        if is_ansi_code(other):
            #XXX: deal w/ malformed - probably should compare 'source' attrs
            return self.codeset == other.codeset and \
                self.code == other.code and self.argstr == other.argstr
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    #=========================================================
    #malformed helpers
    #=========================================================
    @classmethod
    def create_malformed(cls, source, reason=None):
        "helper to create a MalformedAnsiCode"
        return cls(None, None, malformed=reason or True, source=source)

    def is_malformed(self):
        return bool(self.malformed)

    def get_malformed_reasons(self):
        if self.malformed:
            return (self.malformed,)
##            return self.malformed.split(";")
        else:
            return ()

    #=========================================================
    #codeset & code examination
    #=========================================================
    def get_c0_code(self):
        return self.code if self.codeset == CODESET.C0 else None
    c0_code = property(get_c0_code)

    def get_c1_code(self):
        return self.code if self.codeset == CODESET.C1 else None
    c1_code = property(get_c1_code)

    def get_cseq_code(self):
        return self.code if self.codeset == CODESET.CSEQ else None
    cseq_code = property(get_cseq_code)

    def get_icf_code(self):
        return self.code if self.codeset == CODESET.ICF else None
    icf_code = property(get_icf_code)

    ##def get_cstr_code(self):
    ##    return self.code if self.codeset == CODESET.CSTR else None
    ##cstr_code = property(get_cstr_code)

    #=========================================================
    #argstr parsing
    #=========================================================
    def parse_cseq_int_args(self):
        "return argstr as ints separated by semicolons ala CSEQ"
        if not self.argstr:
            return ()
        def cast_int(x):
            try:
                return int(x)
            except ValueError:
                raise AnsiParseError("argstr contains non-integer: %r" % (self.argstr,))
        return tuple(cast_int(x) for x in self.argstr.split(";"))

    def _tma_error(self):
        return AnsiCommandError("too many arguments for command sequence: %r" % (str(self),))

    def _wna_error(self):
        return AnsiCommandError("wrong number of arguments for command sequence: %r" % (str(self),))

    #=========================================================
    #c0, c1 init helpers
    #=========================================================
    def init_default(self):
        #generic fallback
        pass

    def init_c0_1b(self):
        #forbidden, since this signals start of c1, icf, or cseq
        raise AnsiParseError, "raw 'ESC' is not a valid control code"

    def init_c1_5b(self):
        #forbidden, since this signals start of cseq
        raise AnsiParseError, "raw 'ESC' + '[' is not a valid control code"

    #=========================================================
    #cseq init helpers
    #=========================================================
    def init_cseq_default(self):
        #by default, parse argstr as ints (if present at all)
        self.args = self.parse_cseq_int_args()

    def init_cseq_A(self):
        args = self.args = self.parse_cseq_int_args()
        if not args:
            self.offset = 1
        elif len(args) == 1:
            self.offset, = args
        else:
            raise self._tma_error()
    init_cseq_D = init_cseq_C = init_cseq_B = init_cseq_A

    def init_cseq_f(self):
        self.code = "H"
        self.init_cseq_H()

    def init_cseq_H(self):
        #TODO: support row or col being None
        args = self.args = self.parse_cseq_int_args()
        if not args:
            self.col = self.row = 0
        elif len(args) == 2:
            self.col, self.row = args
        else:
            raise self._wna_error()

    def init_cseq_J(self):
        args = self.args = self.parse_cseq_int_args()
        if not args:
            self.mode = 0
        elif len(args) == 1:
            self.mode, = args
            ##if not (0 <= self.mode < 3):
            ##    raise AnsiCommandError, "unknown clear-line mode: %r" % (str(self),)
        else:
            raise self._tma_error()

    def init_cseq_K(self):
        args = self.args = self.parse_cseq_int_args()
        if not args:
            self.mode = 0
        elif len(args) == 1:
            self.mode, = args
            ##if not (0 <= self.mode < 3):
            ##    raise AnsiCommandError, "unknown clear-screen mode: %r" % (str(self),)
        else:
            raise self._tma_error()

    def init_cseq_m(self):
        #ensure args are parseable
        args = self.args = self.parse_cseq_int_args()
        ##if not args:
        ##    raise AnsiCommandError, "no styles listed: %r" % (str(self),)
        ##if any(x < 0 or x > 100 for x in args):
        ##    raise AnsiCommandError, "style value out of bounds: %r" % (str(self),)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#utilities
#=========================================================

def is_ansi_code(obj):
    "check if object is a AnsiCode object"
    return hasattr(obj,"codeset") and hasattr(obj,"code")

def is_malformed_ansi_code(obj):
    return is_ansi_code(obj) and obj.is_malformed()

def len_ansi_string(source):
    """return effective text length of a ansi string.

    .. todo::
        decide on whether cursor control codes should result in error,
        warning, or be ignored. for now, naively counting chars.
    """
    count = 0
    for elem in parse_ansi_string(source, rtype=iter):
        if not is_ansi_code(elem):
            count += len(elem)
    return count

def strip_ansi_string(source):
    "strip ansi escape codes out of string"
    return "".join(
        elem
        for elem in parse_ansi_string(source, rtype=iter,
                                      malformed_codes="parse")
        if not is_ansi_code(elem)
        )

def parse_ansi_string(source, rtype=list, malformed_codes="ignore"):
    """parse string, yeilding chunks of raw text and ansi control codes.

    :arg source:
        source string to parse

    :param rtype:
        optionally you can specify the return type of this function;
        the common values are ``list``, and ``iter``.

    :param malformed_codes:
        this sets the policy for how this function
        handles malformed command codes.

        * ``ignore`` (the default) -- malformed codes are ignored, and kept as literal text.
        * ``parse`` -- malformed codes are parsed and returned
          in :class:`AnsiCode` instances which have no code or codeset specified.
        * ``strip`` -- malformed codes are removed entirely.
        * ``raise`` -- malformed codes cause a ValueError to be raised.

    :returns:
        this returns a list of 1 or more elements,
        which are either raw strings, or :class:`AnsiCode` instances.

    """
    assert malformed_codes in ("ignore","parse","strip","raise")
    if malformed_codes == "strip":
        result = (
            elem
            for elem in _parse_ansi_helper(source, "parse")
            if not is_malformed_ansi_code(elem)
        )
    else:
        result = _parse_ansi_helper(source, malformed_codes)
    if rtype is iter:
        return result
    else:
        return rtype(result)

def _parse_ansi_helper(source, malformed_codes):
    if not source:
        yield ""
        return
    if malformed_codes == "raise":
        def create_bad(source, reason):
            raise ValueError, "%s: %r" % (reason, source)
        create = AnsiCode.parse
    elif malformed_codes == "ignore":
        def create_bad(source,reason):
            log.warning("ignoring malformed control code: %r: %r", reason, source)
            return source
        def create(source):
            ok, result = AnsiCode.try_parse(source)
            if ok:
                return result
            else:
                log.warning("ignoring malformed control code: %r: %r", result, source)
                return source
    else:
        assert malformed_codes == "parse"
        create_bad = AnsiCode.create_malformed
        def create(source):
            ok, result = AnsiCode.try_parse(source)
            if ok:
                return result
            else:
                result = str(result)
                log.warning("encounterd malformed control code: %r: %r", result, source)
                return create_bad(source, result)
    state = 0
        #0 - scanning raw text into buffer
        #1 - saw ESC -- looking for next char
        #2 - saw ESC+[ -- scanning cseq into buffer
    buf = ""
    for c in source:
        if state == 1:
            #parsing escape code
            assert buf == "\x1b"
            if c == '[':
                #it's a cseq
                buf += c
                state = 2
                continue
            else:
                #assume it's a 2 char escape code (c1, icf)
                buf += c
                yield create(buf)
                state = 0
                buf = ""
                continue

        elif state == 2:
            assert buf.startswith("\x1b[")

            if '\x20' <= c < '\x40':
                #parse cseq param or intermediate byte
                buf += c
                continue
            elif '\x40' <= c < '\x7F':
                #parse cseq final byte
                buf += c
                yield create(buf)
                buf = ""
                state = 0
                continue
            else:
                #cseq should contain no other bytes,
                #so something's invalid here
                yield create_bad("\x1b[" + buf, "string contains unterminated control code")
                #fall through to state 0, below
                state = 0

        #this is down here in case a higher state finishes early
        if state == 0:
            #parsing raw text
            if c < '\x20':
                #it's a c0 code...
                if c == "\x1b":
                    #jump to escape handling (c1,icf,cseq)
                    if buf:
                        yield buf
                    buf = c
                    state = 1
                    continue
                elif c in '\r\n\t':
                    #treat these codes like regular characters.
                    #XXX: should caller be able to set policy?
                    buf +=c
                    continue
                else:
                    #all others, yeild c0 code
                    if buf:
                        yield buf
                        buf = ""
                    yield create(c)
                    continue
            else:
                buf += c
                continue

    if state == 0:
        if buf:
            yield buf
    else:
        yield create_bad(buf, "string ends with unterminated control code")

#=========================================================
#streams
#=========================================================
class AnsiStripper(object):
    "wraps another stream, removes ansi escape codes before writing to original stream"
    stream = None

    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

    def write(self, text):
        write = self.stream.write
        for elem in parse_ansi_string(text, rtype=iter, malformed_codes="parse"):
            if not is_ansi_code(elem):
                write(elem)

    def writelines(self, seq):
        for elem in seq:
            self.write(seq)

#=========================================================
#eof
#=========================================================
