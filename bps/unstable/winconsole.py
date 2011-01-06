"""collection of ctypes-based helpers for accessing the windows console.

References
==========
* Windows API Reference -- http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winprog/winprog/windows_api_reference.asp
* recipe to set color attr -- http://code.activestate.com/recipes/496901/
* recipe to get color attr -- http://code.activestate.com/recipes/440694/
"""
#=========================================================
#imports
#=========================================================
#core
from logging import getLogger; log = getLogger(__name__)
import sys
import os
import re
if os.name == "nt":
    #do thing conditionally so full docs can still be built under posix
    import msvcrt
    from ctypes import *
    kernel32 = windll.kernel32
else:
    kernel32 = None
#pkg
from bps import *
from bps.numeric import limit
from bps.unstable import ansi
#local
__all__ = [
    'print_ansi_string',
]

#=========================================================
#misc constants
#=========================================================
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000

#=========================================================
#constants from wincon.h
#=========================================================
##STD_INPUT_HANDLE = -10
##STD_OUTPUT_HANDLE= -11
##STD_ERROR_HANDLE = -12

FOREGROUND_BLUE = 0x01 # text color contains blue.
FOREGROUND_GREEN= 0x02 # text color contains green.
FOREGROUND_RED  = 0x04 # text color contains red.
FOREGROUND_INTENSITY = 0x08 # text color is intensified.

BACKGROUND_BLUE = 0x10 # background color contains blue.
BACKGROUND_GREEN= 0x20 # background color contains green.
BACKGROUND_RED  = 0x40 # background color contains red.
BACKGROUND_INTENSITY = 0x80 # background color is intensified.

class SMALL_RECT(Structure):
    _fields_ = [("Left", c_short),
                ("Top", c_short),
                ("Right", c_short),
                ("Bottom", c_short)]

class COORD(Structure):
    _fields_ = [("X", c_short),
                ("Y", c_short)]

class CONSOLE_SCREEN_BUFFER_INFO(Structure):
    _fields_ = [("dwSize", COORD),
                ("dwCursorPosition", COORD),
                ("wAttributes", c_short),
                ("srWindow", SMALL_RECT),
                ("dwMaximumWindowSize", COORD)]

#non-standard derived constants
FOREGROUND_WHITE = 0x07
BACKGROUND_WHITE = 0x70
FOREGROUND_ALL = 0x0F
BACKGROUND_ALL = 0xF0
ALL_WHITE = 0x77

#map of ansi -> dos color values
# (dos flips R & B bits)
ansi_to_dos = [0,4,2,6,1,5,3,7]

#=========================================================
#
#=========================================================
def _get_hnd(stream):
    return msvcrt.get_osfhandle(stream.fileno())

##def get_console_size(file=sys.stdout):
##    "get size of console attached to stream"
##    info = CONSOLE_SCREEN_BUFFER_INFO()
##    status = kernel32.GetConsoleScreenBufferInfo(hnd, byref(info))
##

def write_ansi_string(source, stream=sys.stdout):
    "print string w/ embedded ansi escape codes to dos console"
    return AnsiConsoleWriter(stream).write(source)

def _clear_bits(attr, bits):
    "clear specified bits in bitmask"
    return (attr|bits)^bits

def _swap_bgfg(attr):
    "swap fg and bg color bits"
    fg = (attr & FOREGROUND_WHITE)
    bg = (attr & BACKGROUND_WHITE)
    return (attr-fg-bg) | (bg>>4) |(fg<<4)

def _pp_get_last_error():
    code = GetLastError() #ctypes wrapper for kernel32.GetLastError
    if code < 1:
        return None
    else:
        msg = FormatError(code) #ctypes wrapper for kernel32.FormatMessage
        return "[%d] %s" % (code, msg)

class AnsiConsoleWriter(object):
    """wraps a stream attached to a windows console,
    extracting any ansi escape codes, and implementing
    them using the Windows Console API where possible.

    :arg stream:
        open handle to console (usualy stdout / stderr).
        by default, this writes to sys.stdout.

    .. note::
        Right now, only ansi text styles (code "m") are supported.
        All others are ignored. In the future, there are plans
        to support the cursor movement codes.

    .. warning::
        This will raise an EnvironmentError if the stream is not
        attached to a console. Use :meth:`wrap` for a graceful
        fallback if the stream is not a tty.

    .. warning::
        Reverse Video and Concealed Text styles utilitize
        per-Writer state, which may not work with concurrent
        changes to styles while either mode is enabled.
    """
    #=========================================================
    #instance attrs
    #=========================================================
    stream = None #stream we're wrapping
    _hnd = None #windows fhandle for stream
    _attrs = None #last attr state we read from console
    _reverse = False #flag if reverse video is enabled
    _conceal = None #flag bg if concealed text is enabled
    _conceal_fg = None

    #=========================================================
    #init
    #=========================================================

    #XXX: classmethod such as "has_console(stream)" if isatty() isn't sufficient?

    def __init__(self, stream=None):
        if stream is None:
            stream = sys.stdout
        if not stream.isatty():
            raise ValueError, "stream is not attached to a tty"
        self._hnd = _get_hnd(stream)
        assert isinstance(self._hnd, int)
        self.stream = stream

    #=========================================================
    #state management
    #=========================================================
    def _get_info(self):
        info = CONSOLE_SCREEN_BUFFER_INFO()
        ok = kernel32.GetConsoleScreenBufferInfo(self._hnd, byref(info))
        if ok:
            return info
        else:
            log.error("failed to read screen buffer info: stream=%r error=%r", self.stream, _pp_get_last_error())
            return None

    def _update_state(self):
        "update internal state from console"
        info = self._get_info()
        if info:
            self._attrs = info.wAttributes
        else:
            self._attrs = FOREGROUND_WHITE

    def _apply_code(self, code):
        "apply change requested by AnsiCode instance"
        if code.cseq_code == "m":
            self._apply_styles(code.args)
        elif code.cseq_code == "A":
            self._move_cursor(0, -code.offset)
        elif code.cseq_code == "B":
            self._move_cursor(0, code.offset)
        elif code.cseq_code == "C":
            self._move_cursor(code.offset,0)
        elif code.cseq_code == "D":
            self._move_cursor(-code.offset,0)
        elif code.cseq_code == "H":
            self._set_cursor(code.col, code.row)
        #TODO: support abs vert & horiz csr movement codes
        elif code.cseq_code == "J":
            self._do_clear_screen(code.mode)
        ##elif code.cseq_code == "K":
        ##    self._do_clear_line(code.mode)
        else:
            #TODO: we could support the cursor repositioning commands
            log.debug("discarding unsupported ansi escape code: %r", code)

    def _do_clear_screen(self, mode):
        if mode == 0:
            #clear line -> bottom
            info = self._get_info()
            if not info:
                return
            cpos = info.dwCursorPosition
            cx, cy = cpos.X, cpos.Y
            c = COORD(0,cy)
            d = c_short()
            s = info.dwSize.X * (info.dwSize.Y-cy+1)
            ok = kernel32.FillConsoleOutputCharacterA(self._hnd, 32, s, c, byref(d) )
            if not ok:
                log.error("failed to clear screen: stream=%r error=%r", self.stream, _pp_get_last_error())
        elif mode == 1:
            #clear top -> line
            info = self._get_info()
            if not info:
                return
            cpos = info.dwCursorPosition
            cx, cy = cpos.X, cpos.Y
            c = COORD(0,0)
            d = c_short()
            s = info.dwSize.X * (info.dwSize.Y-cy+1)
            ok = kernel32.FillConsoleOutputCharacterA(self._hnd, 32, s, c, byref(d) )
            if not ok:
                log.error("failed to clear screen: stream=%r error=%r", self.stream, _pp_get_last_error())
        elif mode == 2:
            #clear all
            info = self._get_info()
            if not info:
                return
            c = COORD(0,0)
            d = c_short()
            s = info.dwSize.X * info.dwSize.Y
            ok = kernel32.FillConsoleOutputCharacterA(self._hnd, 32, s, c, byref(d) )
            if not ok:
                log.error("failed to clear screen: stream=%r error=%r", self.stream, _pp_get_last_error())
        else:
            log.debug("unsupported J mode: %r", num)

    def _set_cursor(self, cx, cy):
        info = self._get_info()
        if not info:
            return
        bsize = info.dwSize
        bx, by = bsize.X, bsize.Y
        #FIXME: is windows relative to 0,0 or 1,1? cause H codes is 1,1
        #TODO: support single-dim movement when cx / cy is None
        cx = limit(cx,0,bx-1)
        cy = limit(cy,0,by-1)
        #get csr position
        cpos = COORD(cx,cy)
        ok = kernel32.SetConsoleCursorPosition(self._hnd, cpos)
        if not ok:
            log.error("failed to set cursor position: stream=%r error=%r", self.stream, _pp_get_last_error())

    def _move_cursor(self, rx, ry):
        info = self._get_info()
        if not info:
            return
        cpos = info.dwCursorPosition
        cx, cy = cpos.X, cpos.Y
        bsize = info.dwSize
        bx, by = bsize.X, bsize.Y
        cx = limit(cx+rx,0,bx-1)
        cy = limit(cy+ry,0,by-1)
        #get csr position
        cpos = COORD(cx,cy)
        ok = kernel32.SetConsoleCursorPosition(self._hnd, cpos)
        if not ok:
            log.error("failed to set cursor position: stream=%r error=%r", self.stream, _pp_get_last_error())

        ##bufx = info.dwSize.X
        ##bufy = into.dwSize.Y
        ##curx = info.dwCursorPosition.X
        ##cury = info.dwCursorPosition.Y
        ##win = info.srWindow
        ##l,t,r,b = win.Left, win.Top, win.Right, win.Bottom
        ##ws = info.dwMaximumWindowSize
        ##mx, my = ws.X, ws.Y
        ##sizex = r-l+1
        ##sizey = b-t+1

    def _apply_styles(self, values):
        "apply values attached to ansi 'm' code"
        clear = _clear_bits

        #load attrs, rearrange based on flags
        attr = self._attrs
        rev = self._reverse
        if rev: #undo attr swap if reversed
            attr = _swap_bgfg(attr)
        conceal = self._conceal
        if conceal: #restore orig bg color if concealed
            attr = attr-(attr & FOREGROUND_ALL) + self._conceal_fg

        #make changes
        for value in values:
            if value == 0:
                #reset all
                attr = FOREGROUND_WHITE
                rev = conceal = False
            elif value == 1:
                #enable bold
                attr |= FOREGROUND_INTENSITY
            #4,21 - underline
            elif value == 5 or value == 6:
                #enable blink (as background highlight)
                attr |= BACKGROUND_INTENSITY
            elif value == 7:
                #reverse text mode
                rev = True
            elif value == 8:
                #concealed text mode
                conceal = True

            elif value == 22:
                #disable bold
                attr = clear(attr, FOREGROUND_INTENSITY)
            elif value == 25:
                #disable blink
                attr = clear(attr, BACKGROUND_INTENSITY)
            #24 - undo underline
            elif value == 27:
                #undo reverse text mode
                rev = False
            elif value == 28:
                #undo concealed mode
                conceal = False

            elif 30 <= value < 38 or value == 39:
                #set fg color
                if value == 39: #treat white as default
                    value = 37
                attr = clear(attr, FOREGROUND_WHITE) | ansi_to_dos[value-30]
            elif 40 <= value < 48 or value == 49:
                #set bg color
                if value == 49: #treat black as default
                    value = 40
                attr = clear(attr, BACKGROUND_WHITE) | (ansi_to_dos[value-40]<<4)
            else:
                #we ignore all other attr codes
                log.debug("ignoring unsupported ansi style attr: %r", value)
                continue

        #rearrange attr based on flags
        if conceal:
            old = self._conceal_fg = attr & FOREGROUND_ALL
            new = (attr&BACKGROUND_ALL)>>4
            attr = attr-old+new
        if rev: #swap colors if reversed
            attr = _swap_bgfg(attr)

        #now that we're done, try to update
        assert isinstance(attr, int)
        ok = kernel32.SetConsoleTextAttribute(self._hnd, attr)
        if ok:
            self._attrs = attr
            self._reverse = rev
            self._conceal = conceal
        else:
            log.error("failed to write attrstate to console: stream=%r error=%r", self.stream, _pp_get_last_error())

    #=========================================================
    #methods to proxy real stream
    #=========================================================
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

    def write(self, text):
        self._update_state()
        raw_write = self.stream.write
        apply_code = self._apply_code
        for elem in ansi.parse_ansi_string(text, rtype=iter, malformed_codes="ignore"):
            if hasattr(elem, "code"):
                apply_code(elem)
            else:
                raw_write(elem)

    def writelines(self, seq):
        self._update_state()
        raw_write = self.stream.write
        apply_code = self._apply_code
        for text in seq:
            for elem in ansi.parse_ansi_string(text, rtype=iter, malformed_codes="ignore"):
                if hasattr(elem, "code"):
                    apply_code(elem)
                else:
                    raw_write(elem)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
