"""utility functions used by bps.host"""
#==================================================================================
#imports
#==================================================================================
#core
import os
import re
import stat
import signal as sigmod
import sys
#pkg
from bps.fs import filepath
from bps.cache import cached_function
from bps.warndep import relocated_function, deprecated_function
#local
__all__ = [
    #chmod wrappers
    'compile_mode', 'compile_mode_mask', 'repr_mode', 'chmod',

    #umask wrappers
    'setumask', 'getumask',

    #signal wrappers
    'has_signal', 'add_signal_handler', 'remove_signal_handler',
        'adapt_sig_term',
]
#==================================================================================
#mode parsing utilities
#==================================================================================

#TODO: this should be moved to fs.py

#---------------------------------------------------------------------
#constants used for parsing & validating modes
#---------------------------------------------------------------------

###short-lived custom format
##rwx_str = "( r -{0,2} | -? w -? | -{0,2} x | rw -? | -? wx | r -? x | rwx | -{1,3} )"
##_line_re = re.compile(r"""
##    ^ \s*
##    (
##        (?P<special> u -? | -? g | ug | -{{1,2}} )
##        \s+
##    )?
##    (?P<u> {rwx}) \s+
##    (?P<g> {rwx}) \s+
##    (?P<o> {rwx})
##    \s* $
##""".format(rwx=rwx_str), re.X)

#note: this doesn't support chmod's 'X' and 't' bits, or some other bits of it's grammar
_sym_re = re.compile(r"""
    ^ \s*
    (
        [ugoa]*
        [+-=]
        ( [rwxs]* | [ugo] )
        (\s*,\s* | \s+ | \s*(,\s*)? $)
    )*
    $
    """, re.X)

_sym_elem_re = re.compile(r"""
    \s*
    (?P<scope>[ugoa]*)
    (?P<action>[+-=])
    (?P<flags> [rwxs]* | [ugo] )
    (\s*,\s* | \s+ | \s*(,\s*)? $)
    """, re.X)

#NOTE: under windows, only IRUSR and IWUSR are applied
PERM_BITLIST = (
    #scope char, rbit, wbit, xbit, sbit
    ('u', stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR, stat.S_ISUID),
    ('g', stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP, stat.S_ISGID),
    ('o', stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH, 0),
    )

#NOTE: this _should_ be all the bits specified by stat module.
PERM_BITMASK = 07777

PERM_CHARLIST = [
    #scope char, ('r',rbit), ('w',wbit), ('x',xbit), ('s',sbit)
    [row[0]] + zip("rwxs", row[1:])
    for row in PERM_BITLIST
    ]

#---------------------------------------------------------------------
#recognizers
#---------------------------------------------------------------------
@deprecated_function("bps.fs.is_mode_mask", removal="2009-10-01")
def is_mode_mask(value):
    return (
        isinstance(value, (list, tuple)) and
        len(value) == 2 and
        isinstance(value[0], int) and (0 <= v <= PERM_BITMASK) and
        isinstance(value[1], int) and (0 <= v <= PERM_BITMASK) and
        (v[0] & v[1] == 0) #'bits' that are set shouldn't be allowed in 'mask'
        )

def _is_mode_mask_type(value):
    return (
        isinstance(value, (list, tuple)) and
        len(value) == 2 and
        isinstance(value[0], int) and
        isinstance(value[1], int)
        )

@deprecated_function("bps.fs.is_mode_int", removal="2009-10-01")
def is_mode_int(value):
    return isinstance(value, (int, long)) and (0 <= v <= PERM_BITMASK)

#---------------------------------------------------------------------
#converting -> int form
#---------------------------------------------------------------------
@deprecated_function("bps.fs.parse_mode_mask()[0]", removal="2009-10-01")
def compile_mode(mode):
    """Compile a symbolic mode string into a mode integer,
    build out of ``stat.S_Ixxx`` bits *or*\ ed together.

    The input string is of the format accepted by gnu's *chmod* implementation.

    ``repr_mode(bits)`` is the inverse of this function.
    """
    return compile_mode_mask(mode)[0]

@deprecated_function("bps.fs.parse_mode_mask", removal="2009-10-01")
def compile_mode_mask(mode):
    """version of compile_mode which returns ``(bits,mask)``
    where *bits* is the bits which are to be set in the final mode,
    and *mask* is the bits which are to be preserved from the current mode
    set on the file. This is needed to accurately reproduce mode strings
    such as "u-rw", which requires knowledge of the previous mode.

    The final mode is determined by the formula ``bits | (oldbits & mask)``,
    where *oldbits* is the previous mode set on the file, as returned by ``os.stat(path).st_mode``.
    Note that any bits not set in *bits* or *mask* will be set to 0.
    Note also that if *mask* is 0, the original *oldbits* do not need to be retrieved.
    """
    if isinstance(mode, int):
        if not is_mode_int(mode):
            raise ValueError, "mode integer out of range" % (mode,)
        return value
    if _is_mode_mask_type(mode):
        if not is_mode_mask(mode):
            raise ValueError, "mode pair out of range/invalid: %r" % (mode,)
        return mode
    if not isinstance(mode, str):
        raise TypeError, "mode must be int, pair of ints, or string: %r" % (mode,)
    value = mode

##    #check for solid permission format
##    m = _line_re.match(value)
##    if m:
##        pos = 0
##        value = m.group("special") or ''
##        if 'u' in value:
##            pos |= stat.S_ISUID
##        if 'g' in value:
##            pos |= stat.S_ISGID
##        for row in PERM_CHARLIST:
##            flags = m.group(row[0]) #'u', 'g', or 'o' => rwxs string
##            for pchar, pbit in row[1:]:
##                if pchar in flags:
##                    pos |= pbit
##        return pos, 0

    #detect chmod-style symbolic string
    if _sym_re.match(value.replace(",", " ")):
        pos = 0  #bits set
        used = 0 #bits set or cleared
        for m in _sym_elem_re.finditer(value.replace(",", " ")):
            scope, action, flags = m.group("scope","action","flags")
            if not scope:
                scope = "ugo"
                #XXX: under correct chmod behavior, bits set in umask aren't affected in this case
            elif 'a' in scope:
                scope = "ugo"
            if len(flags) == 1 and flags in "ugo":
                #TODO: supporting this feature would require introspection of the file perm,
                #making our compiled return value more complicated.
                #unless this becomes needed, not going to bother.
                raise NotImplementedError, "[+-=]ugo is not supported"
            for row in PERM_CHARLIST:
                if row[0] in scope:
                    pairs = row[1:]
                    if action == "+":
                        for pchar, pbit in pairs:
                            if pchar in flags:
                                pos |= pbit
                                used |= pbit
                    elif action == "-":
                        for pchar, pbit in pairs:
                            if pchar in flags:
                                pos = (pos|pbit) ^ pbit
                                used |= pbit
                    else:
                        assert action == "="
                        for pchar, pbit in pairs:
                            if pchar in flags:
                                pos |= pbit
                            else:
                                pos = (pos|pbit) ^ pbit
                            used |= pbit
        return pos, PERM_BITMASK ^ used

    #todo: detect octal-mode format

    #can't parse format
    raise ValueError, "can't parse mode string: %r" % (mode,)

#---------------------------------------------------------------------
#converting -> symbolic form
#---------------------------------------------------------------------
@deprecated_function("bps.fs.repr_mode_mask", removal="2009-10-01")
def repr_mode(mode):
    """given mode int (made of bits from :mod:``stat``), returns symbolic representation
    in string form, ala gnu chmod's symbolic format.

    ``compile_mode(mode_string)`` is the inverse of this function.
    """
    if _is_mode_mask_type(mode):
        #FIXME: would like to have this work with mask bits
        mode, mask = mode
    else:
        mask = 0
    if isinstance(mode, int):
        out = []
        for row in PERM_CHARLIST:
            #row: [ ugoa str, (pchar, pbit), ... ]
            start = True
            part = ''.join(
                pchar
                for pchar, pbit in row[1:]
                if pbit and (mode & pbit)
                )
            if part:
                out.append("%s=%s" % (row[0], part))
        return ",".join(out)
    raise TypeError, "unexpected value for mode: %r" % (mode,)

#---------------------------------------------------------------------
#helpers for using (bits,mask) version of mode.
#---------------------------------------------------------------------
def _compile_mode_func(mode):
    "helper used by chmod, returns function that modifying path's mode according to directive"
    if not mode:
        return lambda path: None
    bits, mask = compile_mode_mask(mode)
    if mask:
        def setmode(path):
            cur = os.stat(path).st_mode
            os.chmod(path, bits|(cur & mask))
    else:
        def setmode(path):
            os.chmod(path, bits)
    return setmode

##def _setmode(path, bits, mask):
##    if mask:
##        cur = os.stat(path).st_mode
##        os.chmod(path, bits|(cur&mask))
##    else:
##        os.chmod(path, bits)

#==================================================================================
#chmod & umask
#==================================================================================

@deprecated_function("bps.fs.chmod (note call syntax change)", removal="2009-10-01")
def chmod(target, mode, recursive=False):
    """set file permissions, using a syntax that's mostly compatible with GNU chmod.

    *source* may be either a path, or a sequence of paths.

    If *recursive* is True, *source* (or any path listed in it)
    which is a directory will be recursively tranversed,
    and the mode applied to all of it's contents in turn.

    *mode* must be a string containing a comma-separated series
    of symbolic permission operations. Each operation
    is of the form ``[ugoa]?[+-=]r?w?x?s?``.

    .. todo::

        Given some usuage examples of the various mode formats.

    *mode* may also be a dict, which specifies
    different modes depending on the type of file.
    This allows setting a different mode for dirs and for files,
    and in the following example::

        >> chmod("/home/user/tmp", dict(file="=rw", dir="=rwx"), recursive=True)

    *mode* may also be a callable, in which case,
    the callable should have the prototype ``mode_func(absolute_path) -> mode string``.
    This allows for much greater customization of security policies.

    .. todo::

        Fix symbolic link behavior (followlinks, etc)
    """
    if isinstance(mode, (str, int)):
        setdir = setfile = _compile_mode_func(mode)
    elif isinstance(mode, dict):
        allmode = (mode.get("all") or "") + ","
        setfile = _compile_mode_func(allmode + (mode.get("file") or ""))
        setdir = _compile_mode_func(allmode + (mode.get("dir") or ""))
    else:
        def setfile(path):
            value = mode(path)
            if value:
                bits, mask = compile_mode_mask(value)
                if mask:
                    os.chmod(path, bits|(os.stat(path).st_mode&mask))
                else:
                    os.chmod(path, bits)
        setdir = setfile

    #run through loop
    for root in _norm_path_list(target):
        if root.isfile:
            setfile(root)
        elif recursive:
            for base, dirnames, filenames in os.walk(root.abspath, topdown=True):
                setdir(base)
                for name in filenames:
                    setfile(os.path.join(base, name))
        else:
            assert root.isdir
            setdir(root)

def _norm_path_list(source):
    "helper for chmod/chown"
    if isinstance(source, (tuple, list)):
        return [ filepath(path).abspath for path in source ]
    else:
        return [ filepath(source).abspath ]

@deprecated_function("bps.fs.setumask (note format change)", removal="2010-04-01")
def setumask(mode, format="sym"):
    "like os.umask, but accepts symbolic mode strings"
    from bps.fs import parse_mode_mask, repr_mode_mask
    bits, mask = parse_mode_mask(mode)
    #XXX: _wish_ this was atomic
    old = os.umask(bits)
    if mask:
        os.umask(bits | (old & mask))
    if format == 'symbolic':
        return repr_mode_mask(old)
    return old

@deprecated_function("bps.fs.getumask (note format change)", removal="2010-04-01")
def getumask(format="sym"):
    #XXX: _wish_ this was atomic, or that we could read umask easily
    from bps.fs import repr_mode_mask
    old = os.umask(0022)
    os.umask(old)
    if format == "sym":
        return repr_mode_mask(old)
    else:
        return old

#==================================================================================
#signals
#==================================================================================
#TODO: where should this be moved? misc?

#TODO: would like to raise error when trying to attach handler to SIGTERM under nt,
# since it can't actually be caught.

def _resolve_signum(signum):
    "resolve signal name to os-specific value, raises ValueError if name is unknown"
    if isinstance(signum, str):
        try:
            return int(signum)
        except ValueError:
            try:
                signum = getattr(sigmod, signum.upper())
            except AttributeError:
                raise ValueError, "unknown signal name: %r" % (signum,)
    if not isinstance(signum, int):
        raise TypeError, "signum must be int"
    return signum

def has_signal(name):
    "check if specific signal is available for OS"
##    if not sigmod:
##        warning("`signal` module not available, can't check for signal", RuntimeWarning)
##        return False
    return hasattr(sigmod, name.upper())

_master_signal_handlers = {} #map of signum -> master handler func
def _get_master_handler(signum, create=True):
    "helper which returns master handler function, with chain stored as attr, for specified signal"
    global _master_signal_handlers
    assert isinstance(signum, int)
    if signum in _master_signal_handlers:
        return _master_signal_handlers[signum]
    if not create:
        return None
    chain = []
    def master(s, f):
        assert s == signum, "handler attached to wrong signal!"
        exc_info = None
        for handler in chain:
            #XXX: could have a signal to trap errors?
            #but decided trapping all by default is bad policy
##            try:
            handler(s, f)
            #XXX: could have True result => don't call any more handlers
##            except SystemExit:
##                exc_info = sys.exc_info()
##            except:
##                import traceback
##                print >> sys.stderr, "Error in signal handler: signum=%r handler=%r"  % (signum, handler)
##                traceback.print_exc()
##                exc_info = sys.exc_info()
##        if exc_info is not None:
##            raise exc_info[0], exc_info[1], exc_info[2]
    master.chain = chain
    _master_signal_handlers[signum] = master
    return master

def add_signal_handler(signal, handler, prepend=False):
    """attach a new handler to the specified signal.

    when the signal is raised, all handlers are called
    in the order they were attached, until one of them
    returns ``True``, at which point, the signal is assumed
    to be handled, and no other handlers are called.

    :Parameters:
        signal
            Signal name (resolve from signal module), or number.
        handler
            A callback, with the prototype ``handler(signum,frame) -> bool success``.
            If it returns ``True``, no more handlers will be called.
            Otherwise, it may returns ``None`` or ``False``.
        prepend
            if True, handler will be put first in line to be called,
            instead of last in line.

    .. note::

        If another signal handler has been attached directly when this function
        is called, that handler will be removed, and automatically placed on the chain
        before your handler is added.
    """
##    if not sigmod:
##        warning("`signal` module not available, can't attach signal handler", RuntimeWarning)
##        return
    signum = _resolve_signum(signal)

    #attach master handler
    master = _get_master_handler(signum)
    cur = sigmod.getsignal(signum)
    if cur is not master:
        if not isinstance(cur, int): #disregarding SIG_DFL SIG_IGN
            master.chain.append(cur)
        sigmod.signal(signum, master)

    #add our handler
    if prepend:
        master.chain.insert(0, handler)
    else:
        master.chain.append(handler)
    return True
register_signal_handler = relocated_function("register_signal_handler", add_signal_handler)

def remove_signal_handler(signal, handler):
    """remove a handler attached to the specified signal.

    * Returns True if handler successfully removed.
    * Returns None if :mod:`signal` module not present.
    * Raises a :exc:`KeyError` if the handler isn't attached to the signal,
      either directly, or in a chain.
    """
##    if not sigmod:
##        warning("`signal` module not available, can't remove signal handler", RuntimeWarning)
##        return
    signum = _resolve_signum(signal)

    #check if handler is attached to master
    master = _get_master_handler(signum, create=False)
    if master and handler in master.chain:
        master.chain.remove(handler)
        if not master.chain: #remove master once chain is empty
            cur = sigmod.getsignal(signum)
            if cur is master:
                sigmod.signal(signum, sigmod.SIG_DFL)
        return True

    #check if handler is attached directly
    cur = sigmod.getsignal(signum)
    if handler is cur:
        if master and master.chain: #re-attach master if it's active
            sigmod.signal(signum, master)
        else:
            sigmod.signal(signum, sigmod.SIG_DFL)
        return True

    #give up
    raise KeyError, "handler not attached to signal!"

_adapted = False
def adapt_sig_term(value=1):
    """This attaches a handler to SIGTERM which adapts it into a ``SystemExit(1)`` error,
    so that atexit functions properly when SIGTERM is sent to the process.
    The optional value keyword lets you override the exit code used.

    .. note::

        If SIGTERM is not defined for the OS, this function will silently perform a NOOP.
    """
    if not has_signal("SIGTERM") or os.name == "nt":
        #NOTE: nt's SIGTERM cannot be caught
        return False
    def handler(signum, frame):
        raise SystemExit(value)
    add_signal_handler("SIGTERM", handler)
    return True

#==================================================================================
#EOF
#==================================================================================
