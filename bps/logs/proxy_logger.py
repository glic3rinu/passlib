"""proxy logger"""
#=========================================================
#imports
#=========================================================
#core
import inspect
from logging import getLogger
#site
#lib
#pkg
#local
__all__ = [
    'log', 'multilog', 'classlog',
]
#=========================================================
#
#=========================================================

#TODO: needs unittests

#TODO: should detect any environments (jython?) under which
# our globals hack won't work, and make ProxyLogger alias
# MultiProxyLogger instead for those cases.

class ProxyLogger(object):
    """
    FIXME: explain what this does much more clearly, give examples.

    This class is for the lazy programmer who doesn't want to create a new
    logger class for every module, but still get the benefits of having logging
    messages mapped to the module name.

    The single instance of this class, ``log``, determines the ``__name__``
    of the module which called the instance's method, and proxies the
    logger returned by getLogger(__name__) on a per-call basis.

    Additionally, when first called from a module,
    it will replace itself in the module's globals with the actual logger,
    to speed up future calls.

    By my count this is 3 ugly hacks rammed together.
    But the behavior makes logging kinda nice :)
    """
    def __getattribute__(self, attr):
        globals = inspect.currentframe(1).f_globals
        name = globals.get("__name__", "unnamed-module")
        log = getLogger(name)
        if globals.get("log") is self:
            globals['log'] = log
        return getattr(log, attr)

class MultiProxyLogger(object):
    """
    This class is just like ProxyLogger,
    except it doesn't magically replace itself in the global scope
    when it's first invoked.

    This is useful when importing a log object that's going to be
    imported again from other contexts (eg: pylons base.py -> controllers)
    """
    def __getattribute__(self, attr):
        globals = inspect.currentframe(1).f_globals
        name = globals.get("__name__", "unnamed-module")
        log = getLogger(name)
        return getattr(log, attr)

class ClassLogger(object):
    """
    This is a property object which proxies a logger
    with the full module path and name of the class
    it's invoked for.
    """
    def __get__(self, obj, cls):
        return getLogger(cls.__module__ + "." + cls.__name__)

#=========================================================
#create the single instance anyone will ever need
#=========================================================
log = ProxyLogger()
multilog = MultiProxyLogger()
classlog = ClassLogger()
#=========================================================
#eof
#=========================================================
