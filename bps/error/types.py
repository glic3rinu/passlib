"""
bps.error.types -- Exception classes & utilities
"""
#===================================================
#imports
#===================================================
from warnings import warn
from bps.undef import Undef
import errno as _errno
import os
__all__ = [

    #func errors
    "ParamError",
    "NormError",
    "RangeError",

    #command invariants
    'EnvTypeError',
    'DistTypeError',

    #command arg errors
    'CommandError',
    'ParseError',
    'InputError',

    #bps.fs:
    'MissingPathError',
    'PathExistsError',
    'ExpectedDirError',
##    'ExpectedFileError',
    'DirNotEmptyError',
    'PathInUseError',

    #bps.reference:
    'ProxyEmptyError',
    'ProxyNestError',

    #bps.meta
    'AbstractMethodError',

    #attribute errors
    'MissingAttributeError',
        'UnsetAttributeError',
    'ReadonlyAttributeError',
    'PermanentAttributeError',

]

#===================================================
#function errors
#===================================================
class ParamError(TypeError):
    """This error should be raised to indicated invalid parameters were passed to function.

    For example:
        * missing required arguments or keywords
        * mutually exclusive keywords specified
        * some other combination of the above

    It should *not* be used for:
        * incorrect type for a parameter (use :exc:`TypeError`).
        * incorrect value for a parameter (use :exc:`ValueError`).

    This is a subclass of :exc:`TypeError`, in order to be compatible
    with Python's normal behavior.
    """

class NormError(ValueError):
    """raised to indicate function was passed value that can't be normalized.

    This error is typically raised by normalization functions,
    whose job is to convert a value to it's canonical form if it's in some domain
    (such as converting a date in string form to a date type).

    This is a helper for raising an more informative :exc:`ValueError`
    in the case where the provided value cannot be normalized / decoded / parsed.
    It is a subclass of :exc:`ValueError`.

    :arg msg:
        Optional traceback message.
        If not specified, a sensible default will be chosen
        based on the other provided values.
        The result (default or not) is available via ``err.msg`` or ``err.args[0]``.

    :param value:
        This is the most common keyword to use with this exception.
        It specifies the actual value which is the cause of the error.
        It is accessible via ``err.value``, and will be integrated
        into the default message.

    :param key:
        If the error is related to a particular key (such as a dictionary,
        object attribute, etc), it may optionally be specified using
        this keyword. It's value is accessible via ``err.key``,
        and will be integrated into the default message.

    :param pretty:
        Optional "pretty printed" message,
        suitable for display to the end user.
        By default, this is the same as *text*,
        and is accessible via ``err.pretty`` or ``str(err)``.
        This is present for the cases where the default text
        is more informative for debugging purposes,
        but a more concise message is appropriate for displaying
        to the user.

    Usage Example::

        >>> from bps.error.types import NormError
        >>> def naive_bool(value):
        >>>     if value == 'true':
        >>>         return True
        >>>     if value == 'false':
        >>>         return False
        >>>     raise NormError(value=value)
        >>> naive_bool("foo") #will raise a NormError
    """

    msg = None
    text = None #NOTE: this is a deprecated name for msg
    pretty = None
    key = None
    value = None

    def __init__(self, msg=None, pretty=None, key=None, value=Undef, text=None):
        self.key = key
        if value is not Undef:
            self.value = value
        if text:
            warn("text kwd is deprecated, use msg kwd instead")
            msg = text
        if msg is None:
            msg = self._default_msg()
        self.msg = self.text = msg
        self.pretty = pretty or msg
        if value is not Undef:
            ValueError.__init__(self, msg, value)
        else:
            ValueError.__init__(self, msg)

    def _default_msg(self):
        "called to create default message"
        msg = "Invalid value"
        if self.key is not None:
            msg += " for key %r" % (self.key,)
        if value is not Undef:
            msg += ": %r" % (self.value,)
        return msg

    def __str__(self):
        return self.pretty

class RangeError(NormError):
    """raised to indicate function was passed value that can't be normalized because it was out of range.

    This is a subclass of :exc:`NormError`, which offers a more appropriate
    error message for when the reason a value couldn't be normalized
    was because it was outside some supported range (eg: a date contains month 13).

    In addition to all the parameters :exc:`NormError` supports,
    this class adds two additional parameters:

    :param lower:
        Optional lower bound of range, will be integrated into default message.
    :param upper:
        Optional upper bound of range, will be integrated into default message.

    If possible, lower should be inclusive and upper should be exclusive,
    following the python slice protocol.
    """
    lower = None
    upper = None

    def __init__(self, msg=None, pretty=None, key=None, value=Undef, lower=None, upper=None, text=None):
        self.lower = lower
        self.upper = upper
        NormError.__init__(self, msg=msg, pretty=pretty, key=key, value=value, text=text)

    def _default_msg(self):
        msg = NormError._default_msg(self)
        if self.lower is not None:
            if self.upper is not None:
                msg += ", must be within %r and %r" % (self.lower, self.upper)
            else:
                msg += ", must be at or above %r" % (self.lower,)
        elif self.upper is not None:
            msg += ", must be below %r" % (self.upper,)
        return msg

#===================================================
#command invariant errors
#===================================================
class EnvTypeError(AssertionError):
    """raised by subclasses of :class:`bps.app.command.Command` when they encounter an unexpected env_type value.

    This is a rather common case when writing a code
    which supports multiple env_types in a Command subclass.
    This error can be raised when a value is encountered
    that the code is not prepared for.

    If you are not using the Command class, you can ignore this exception.

    .. note::
        Since env_type values are generally internal to a program,
        this indicates a violation of an internal invariant,
        thus this subclasses :exc:`AssertionError`, not :exc:`ValueError`.
    """
    def __init__(self, value):
        if hasattr(value, "env_type"): #allow us to pass in commands, etc
            value = value.env_type
        self.value = value
        AssertionError.__init__(self, "unexpected environment type: %r" % self.value)

class DistTypeError(AssertionError):
    """raised by subclasses of :class:`bps.app.command.Command` when they encounter an unexpected env_type value.

    This is similar to :exc:`UnexpectedEnvTypeError`, see it for details.
    """
    def __init__(self, value):
        if hasattr(value, "dist_type"): #allow us to pass in commands, etc
            value = value.dist_type
        self.value = value
        AssertionError.__init__(self,"unexpected distribution type: %r" % self.value)

#===================================================
#user input errors
#===================================================
class CommandError(Exception):
    "base for errors to be raised by code processing sys.argv input"

    @classmethod
    def format(cls, template, *args, **kwds):
        warn("this method has been deprecated!", DeprecationWarning)
        from bps.text import render_format
        msg = render_format(template, *args, **kwds)
        return cls(msg)

class ParseError(CommandError):
    "syntax error when parsing command line arguments (unknown / contradictory options, etc)"
    #NOTE: this will cause Command to print out it's usage

class InputError(CommandError):
    "semantic error when parsing command line arguments (file not found, etc)"

#===================================================
#bps.reference
#===================================================
class ProxyEmptyError(TypeError):
    """error raised when :class:`bps.refs.ProxyObject` is accessed without a proxy target"""

class ProxyNestError(AssertionError):
    """error raised when targets are removed from :class:`bps.refs.ProxyObject` in wrong order"""

#===================================================
#bps.meta
#===================================================
class AbstractMethodError(NotImplementedError):
    """error class raised by :func:`bps.meta.abstractmethod` decorator when
    an abstract method is invoked."""
    def __init__(self, msg="this method must be implemented in a subclass"):
        NotImplementedError.__init__(self, msg)

#===================================================
#attribute error helpers
#===================================================
class PrettyAttributeError(AttributeError):
    msg = None
    obj = None #stores object for instance
    attr = None #stores attr for instance

    verb = None #verb to append to default message

    def __init__(self, obj=None, attr=None, msg=None):
        self.attr = attr
        self.obj = obj
        if msg is None:
            if attr:
                if obj:
                    msg = "%(obj)r: attribute %(attr)r %(verb)s"
                else:
                    msg = "attribute %(attr)r %(verb)s"
            else:
                if obj:
                    msg = "%(obj)r: attribute %(verb)s"
                else:
                    msg = "attribute %(verb)s"
        msg %= dict(obj=obj, attr=attr, verb=self.verb)
        self.msg = msg
        AttributeError.__init__(self, msg)

class MissingAttributeError(PrettyAttributeError):
    """helper for quickly raising an error when getattr fails.

    :param obj:
        Optionally provide reference to object code was trying to access.
        Will be integrated into default message.
        Stored in ``obj`` attribute of error.

    :param attr:
        Optionally provide name of attribute being read.
        Will be integrated into default message.
        Stored in ``attr`` attribute of error.

    :param msg:
        Override the default message.
        Can be retreived via ``str(err)``

    Usage Example::

        >>> from bps.error.types import MissingAttributeError
        >>> # .. in code somewhere ...
        >>> raise MissingAttributeError(self,attr)
    """
    verb = "not found"

class ReadonlyAttributeError(PrettyAttributeError):
    "helper for raising error when setattr fails, used just like MissingAttributeError"
    verb = "is read-only"

class PermanentAttributeError(PrettyAttributeError):
    "helper for raising error when delattr fails, used just like MissingAttributeError"
    verb = "cannot be deleted"

class UnsetAttributeError(MissingAttributeError):
    """helper for raising error when descriptor managing an attribute wishes
    to indicate it has no defined value to return"""
    verb = "has no set value"

#===================================================
#filesystem errors - used by bps.fs.FilePath
#===================================================

#---------------------------------------------------
#internal wrapper backends
#---------------------------------------------------
#NOTE: internal inheritance may change in the future,
# the only guarantee is that all these errors will be OSError subclasses
# (and also WindowsError subclasses, where appropriate).

class _OSErrorHelper(OSError):
    "helper used by errors which wrap a specific OSError errno"
    errno = None
    #NOTE: order of kwds is different from OSError, mainly to aid in creation of instances
    # with more helpful messages
    def __init__(self, strerror=None, filename=None, errno=None):
##        if isinstance(errno, str) and strerror is None:
##            errno, strerror = None, errno
        if errno is None:
            errno = self.errno
        if strerror is None and errno:
            strerror = os.strerror(errno)
        OSError.__init__(self, errno, strerror, filename)

if os.name == "nt":
    assert WindowsError
    #NOTE: order of kwds is different from WindowsError, mainly to aid in creation of instances
    # with more helpful messages
    class _WindowsErrorHelper(WindowsError):
        "helper used by errors which wrap a specific WindowsError winerror"
        winerror = None
        strerror = None
        #errno autocalculated
        def __init__(self, strerror=None, filename=None, winerror=None):
            if winerror is None:
                winerror = self.winerror
            if strerror is None:
                strerror = self.strerror
                if streror is None and errno:
                    strerror = os.strerror(errno)
            WindowsError.__init__(self, winerror, strerror, filename)

        def __str__(self):
            out = "[WinError %r] " % self.winerror
            if self.errno:
                out += "[Errno %r] " % self.errno
            if self.strerror:
                out += self.strerror
            if self.filename:
                out += ": %r" % (self.filename,)
            return out

else:
    WindowsError = None
    _WindowsErrorHelper = _OSErrorHelper
    #under non-nt, the _WindowsErrorHelper errors shouldn't be raised,
    #but we define them anyway so any use-cases don't have to deal w/ them vanishing.
    #so, we use _OSErrorHelper to provide a base class.

#---------------------------------------------------
#filepath errors
#---------------------------------------------------

class MissingPathError(_OSErrorHelper):
    """Indicates a filepath that was expected to exist could not be found.

    This is a wrapper for ``OSError(errno.ENOENT)`` raised by :class:`bps.fs.FilePath`.
    """
    errno = _errno.ENOENT

class PathExistsError(_OSErrorHelper):
    """Indicates a filepath exists on the filesystem when it was expected to be empty.

    This is a wrapper for ``OSError(errno.EEXIST)`` raised by :class:`bps.fs.FilePath`.
    """
    errno = _errno.EEXIST

class ExpectedDirError(_OSErrorHelper):
    """Indicates filepath was expected to be a directory, but was found to be another filetype.

    This is a wrapper for ``OSError(errno.ENOTDIR)`` raised by :class:`bps.fs.FilePath`.
    """
    errno = _errno.ENOTDIR

class DirNotEmptyError(_OSErrorHelper):
    """Indicated directory should have been empty, but wasn't (mainly caused by rmdir)

    This is a wrapper for ``OSError(errno.ENOTEMPTY)`` raised by :class:`bps.fs.FilePath`.
    """
    errno = _errno.ENOTEMPTY

##class ExpectedFileError(WrongPathTypeError):
##    errno = _errno.EISDIR

##PathPermissionError(_OSErrorHelper) - _errno.EACCES, should be parent of PathInUseError

class PathInUseError(_WindowsErrorHelper):
    """Indicates the filepath is currently locked by another process, and cannot be moved/opened/etc.

    This is a wrapper for ``WindowsError(32)`` raised by :class:`bps.fs.FilePath`.
    It will currently only be raised under Windows.
    """
    errno = _errno.EACCES
    winerror = 32
    strerror = "The process cannot access the file because it is being used by another process"

#------------------------------------------
#aliases based on errno id's
#------------------------------------------
ENOENT_Error = MissingPathError
EEXIST_Error = PathExistsError
##EISDIR_Error = ExpectedFileError
ENOTDIR_Error = ExpectedDirError
ENOTEMPTY_Error = DirNotEmptyError

#------------------------------------------
#adapt os errors to one of BPS's subclasses
#------------------------------------------
if WindowsError:
    _win_err_map = {
        32: PathInUseError,
    }

_os_err_map = { #dict mapping errno to oserror subclass
    _errno.ENOENT: ENOENT_Error,
    _errno.EEXIST: EEXIST_Error,
##    _errno.EISDIR: EISDIR_Error,
    _errno.ENOTDIR: ENOTDIR_Error,
    _errno.ENOTEMPTY: ENOTEMPTY_Error,
}

def adapt_os_errors(func, *args, **kwds):
    "wraps function call, trapping & adapting os errors into BPS errors"
    try:
        return func(*args, **kwds)
    except OSError, err:
        new_err = translate_os_error(err)
        if new_err:
            raise new_err
        log.warning("unmanaged os error: %r", err)
        raise

def translate_os_error(err):
    "adapt a plain os error into one of BPS's OSError subclasses"
    global _os_err_map, _win_err_map

    #for debugging/development
##    if True:
##        from bps.error.utils import format_exception
##        from logging import getLogger
##        getLogger("bps.error.types").critical(format_exception(err))

    #check if we've already wrapped it, or if it's not an OSError
    if isinstance(err, (_OSErrorHelper, _WindowsErrorHelper)):
        return None

    #check for WindowsErrors (since WindowsError subclass of OSError)
    #NOTE: <py2.5, .errno contained the windows error value, not the errno value!
    elif WindowsError and isinstance(err, WindowsError) and err.winerror in _win_err_map:
        cls = _win_err_map[err.winerror]
        return cls(err.strerror, err.filename, err.winerror)

    #else it should be an OS Error
    elif isinstance(err, OSError) and err.errno in _os_err_map:
        #XXX: what if this _is_ a WindowsError? should we do something?
        cls = _os_err_map[err.errno]
        return cls(err.strerror, err.filename, err.errno)

    #don't handle the rest
    return None

#===================================================
#eof
#===================================================
