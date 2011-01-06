"""bps.error.utils -- error utility functions"""
#========================================================
#imports
#========================================================
#core
import sys
import traceback
from cStringIO import StringIO
from bps.undef import Undef
#local
__all__ = [
    #display
    'format_exception'

    #helpers
    'get_sysexit_rc',
]
#========================================================
#format an exception
#========================================================
EXC_ATTRS = ("errno", "filename", "winerror") #common exc attributes to display if present
EXC_HEADER  = "@@@@@@@@@@@@@@@@@@@@_exception_@@@@@@@@@@@@@@@@@@@@@\n"
EXC_DIVIDER = "----------------------------------------------------\n"
EXC_FOOTER  = "@@@@@@@@@@@@@@@@@@@@^^^^^^^^^^^@@@@@@@@@@@@@@@@@@@@@\n"

def format_exception(exc_info=True, limit=None): ##, depth=0):
    """An enhanced version of traceback.format_exception

    This function prints out the specified exception info,
    but tries to given additional information about the exception,
    which is frequently useful when debugging unknown errors from a log file.

    :param exc_info:
        The exc info tuple to format.
        If this is set to ``True`` (the default), :func:`sys.exc_info()`
        will be called to get the real exc info tuple.

        This can also be an error instance, in which case
        the error will be treated the same as the exc_info tuple ``(type(err),err,None)``.

    :param limit:
        Limit on how far from the original caller
        that the traceback should go.

    """
##    :param depth:
##        If set, the first *depth* frames will be skipped.
##        This is useful for displaying tracebacks that occur
##        inside an interactive shell, so that the top frames
##        can be ignored.

    #get exc info
    if exc_info is True:
        exc_info = sys.exc_info()
    if exc_info:
        if isinstance(exc_info, BaseException):
            exc_type, exc_value, exc_trace = type(exc_info), exc_info, None
        else:
            exc_type, exc_value, exc_trace = exc_info
    else:
        return EXC_HEADER + "     exc_info: None\n" + EXC_FOOTER

    #
    #prepare output buffer, write header
    #
    out = StringIO()
    write = out.write
    write(EXC_HEADER)

    #
    #write exc value info
    #
    write("     exc_type: %s\n" % (_safe_repr(exc_type),))
    write("    exc_value: %s\n" % (_safe_repr(exc_value),))

    #show the err's args one by one
    if hasattr(exc_value, "args") and isinstance(exc_value.args,(tuple,list)):
        for i,arg in enumerate(exc_value.args):
            write("      args[%d]: %s\n" % (i,_safe_repr(arg)))
    for attr in EXC_ATTRS:
        if hasattr(exc_value, attr):
            value = getattr(exc_value, attr)
            write("%13s: %s\n" % (attr, _safe_repr(value)))

    #
    #write traceback
    #
    write(EXC_DIVIDER)
##    while exc_trace and depth > 0:
##        exc_trace = exc_trace.tb_next
##        depth -= 1
    if exc_trace:
        stack = traceback.extract_tb(exc_trace, limit=limit)
        if stack:
            write("    traceback:\n")
            traceback.print_list(stack, out)

    #
    #write the error text
    #
    write(EXC_DIVIDER)
    lines = traceback.format_exception_only(exc_type, exc_value)
    if lines: #should always be >0, usually ==1
        for line in lines:
            write(line)
            #should always end in \n

    #
    #write the footer
    #
    write(EXC_FOOTER)

    #
    #return
    #
    del exc_type, exc_value, exc_trace
    return out.getvalue()

def _safe_repr(value):
    try:
        return repr(value)
    except Exception:
        return '<unrepresentable %s object>' % type(value).__name__

#===================================================
#helpers
#===================================================
def get_sysexit_rc(err):
    "get int return code from SystemExit instance"
    code = err.code
    if isinstance(code, int):
        return code
    elif code:
        return 1
    else:
        return 0

#========================================================
#eof
#========================================================
