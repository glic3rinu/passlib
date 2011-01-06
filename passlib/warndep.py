"""bps.warndep -- warning and deprecation utilities"""
#===================================================
#imports
#===================================================
#core
import inspect
from functools import update_wrapper
from warnings import warn
#needed imports
#legacy imports
from bps.undef import Undef
from bps.meta import isstr, find_attribute
from bps.error.types import ParamError

__all__ = [
    #deprecation decorators
    'deprecated_function',
    'deprecated_method',

    #deprecation constructors
    'deprecated_property',
    'relocated_function',
    'relocated_class',
]

#=========================================================
#deprecation decorators
#=========================================================
def deprecated_function(use=None, name=None, removal=None, msg=None, **kwds):
    #TODO: once positional version deprecated, move "name" -> after removal, remove kwds
    """Used to indicate a function has been deprecated,
    and issues a warning telling user where to find the recommended replacement (if any)

    :type use: str|None
    :param use:
        [optional]
        name of replacement function.
        if provided, the default message will indicate this function
        should be used instead. if not provided, the default
        message will indicate the function is scheduled for removal.

    :type name: str|None
    :param name:
        [optional]
        Overrides name of original function
        (else derived from function that's being wrapped).

    :type removal: str|True|None
    :param removal:
        [optional]
        A string containing information about when this function
        will be removed. Typically, this will either be a date
        or a version number. It is inserted
        into the default message by appending the phrase:

            ``"and will be removed after %(removal)s"``

    :type msg: str|None
    :param msg:
        [optional]
        Overrides default warning message.
        This message will be passed through ``msg % opts``, where
        opts is a dictionary containing the following keys:

            name
                deprecated function name: ``name`` keyword, or name of original function
            mod
                name of module old function came from.
            use
                replacement name (``use`` keyword, or ``None``).
            removal
                value of ``removal`` keyword, or ``None``.

    .. todo:: give usage example for depfunc

    .. note::

        all options should be specified as kwd args
    """
    #XXX: should we expose stacklevel for weird invocation cases?

    #handle deprecated kwds
    if 'new_name' in kwds:
        warn("'new_name' deprecated, use 'use' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        use = kwds.pop("new_name")
    if 'old_name' in kwds:
        warn("'old_name' deprecated, use 'name' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        name = kwds.pop("old_name")
    if kwds:
        raise TypeError, "unknown kwds: %r" % (kwds,)

    #create default msg
    if not msg:
        msg = "function %(name)r is deprecated"
        if use:
            msg += ", use %(use)r instead"
        if removal:
            if removal is True:
                msg += "; it will be removed in the future"
            else:
                msg += "; it will be removed after %(removal)s"
    if '%(mod)' not in msg: #just to make sure user is oriented about warning
        msg = "%(mod)s: " + msg

    #decorator-builder
    def builder(func):
        #FIXME: old_mod currently points to *new* module,
        # which is usually the same, but not always
        text = msg % dict(
            mod=func.__module__,
            name=name or func.__name__,
            use=use,
            removal=removal,
            )
        def wrapper(*args, **kwds):
            warn(text, DeprecationWarning, stacklevel=2)
            return func(*args, **kwds)
        update_wrapper(wrapper, func)
        return wrapper
    return builder

def deprecated_method(use=None, name=None, removal=None, msg=None, **kwds):
    """Used to indicate a method has been deprecated, and displays msg w/ recommended replacement.

    Aside from decorating a method instead of a function,
    this is exactly the same as :func:`deprecated_function`,
    except for the additionl of the following extra keywords
    available for formatting inside *msg*:

        cls
            name of class the deprecated function is stored inside.
    """
    #XXX: should we expose stacklevel for weird invocation cases?

    #handle deprecated kwds
    if 'new_name' in kwds:
        warn("'new_name' deprecated, use 'use' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        use = kwds.pop("new_name")
    if 'old_name' in kwds:
        warn("'old_name' deprecated, use 'name' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        name = kwds.pop("old_name")
    if kwds:
        raise TypeError, "unknown kwds: %r" % (kwds,)

    #create default msg
    if not msg:
        msg = "method %(name)r is deprecated"
        if use:
            msg += ", use %(use)r instead"
        if removal:
            if removal is True:
                msg += "; it will be removed in the future"
            else:
                msg += "; it will be removed after %(removal)s"
    if '%(mod)' not in msg: #just to make sure user is oriented about warning
        msg = "%(mod)s.%(cls)s: " + msg

    #decorator-builder
    def builder(func):
        state = dict(
            use=use,
            name=name or func.__name__,
            removal=removal,
            #params filled in when bound to class...
            mod=None,
            cls=None,
            text=None,
            )
        def wrapper(self, *args, **kwds):
            text = state['text']
            if not text:
                cls = self.__class__
                state.update(mod=cls.__module__,  cls=cls.__name__)
                text = state['text'] = msg % state
            warn(text, DeprecationWarning, stacklevel=2)
            return func(self, *args, **kwds)
        wrapper._deprecated_func = func #used to let deprecated_property strip this off
        update_wrapper(wrapper, func)
        return wrapper
    return builder

def deprecated_property(fget=None, fset=None, fdel=None, doc=None,
                        new_name=None, old_name=None, msg=None, removal=None):
    """replacement for property() which issues deprecation warning when property is used.

    :arg fget:
        get function, same as for :func:`property()`
    :arg fset:
        set function, same as for :func:`property()`
    :arg fdel:
        delete function, same as for :func:`property()`
    :arg doc:
        alternate docstring, same as for :func:`property()`

    :param new_name:
        Name of alternate attribute that should be used.
        If not set, default message will indicate this property
        is deprecated without any alternatives.

    :param old_name:
        Name of the attribute this property will be stored in.
        If not specified, an attempt will be made to derive
        it from the name of the fget / fset methods.
        If that fails, a ParamError will be raised.

    :param removal:
        [optional]
        A string containing information about when this function
        will be removed. Typically, this will either be a date
        or a version number. It is inserted
        into the default message by appending the phrase:

            ``"and will be removed after %(removal)s"``

    :param msg:
        If this is specified, it overrides the default warning message.
        All message strings will be passed through ``msg % vars``,
        where *vars* is a dictionary containing the following keys:

            new_name
                value of new_name parameter passed into constructor

            old_name
                value of old_name parameter passed into constructor

            old_cls
                name of class that attribute is part of

            old_mod
                name of module that old_class belongs to
    """
    if not msg:
        msg = "attribute %(old_name)r is deprecated"
        if removal:
            if removal is True:
                msg += ", and will be removed in the future"
            else:
                msg += ", and will be removed after %(removal)s"
        if new_name:
            msg += ", use %(new_name)r instead"
    if '%(old_mod)' not in msg:
        msg = "%(old_mod)s.%(old_cls)s: " + msg
    if old_name is None:
        #try to guess it from fget
        assert fget
        name = fget.__name__.lstrip("_")
        if name.startswith("get"):
            old_name = name[3:]
        elif fset:
            #try to guess from fset
            name = fset.__name__.lstrip("_")
            if name.startswith("set"):
                old_name = name[3:]
            else:
                raise ParamError, "old_name must be specified, can't guess from fget/fset"
    state = dict(
        new_name=new_name,
        old_name=old_name,
        removal=removal,
        )
    def builder(func):
        if func is None:
            return None
        if hasattr(func, "_deprecated_func"): #set by deprecated_method, so we don't do a double warning
            func = func._deprecated_func
        def wrapper(self, *args, **kwds):
            if 'text' not in state:
                cls = self.__class__
                state.update(old_mod=cls.__module__,  old_cls=cls.__name__)
                state['text'] = msg % state
            warn(state['text'], DeprecationWarning, stacklevel=2)
            return func(self, *args, **kwds)
        update_wrapper(wrapper, func)
        return wrapper
    return property(builder(fget), builder(fset), builder(fdel), doc)

#=========================================================
#func/class generators
#=========================================================
#TODO: rename "new_func" to "handler", and swap locations with "new_name",
# which should now be required (see relocated-method)
def relocated_function(name, use, removal=None, lazy=True, msg=None, **kwds):
    #detect swapped params
    """Used to indicate a function has been deprecated:
    this generates and returns a wrapper function which acts as a proxy
    for the replacement, after issuing a suitable warning.

    The replacement can either be passed in directly,
    or lazily imported when needed.

    :type name: str
    :arg name:
        [required]
        name of old (deprecated) function we're creating a wrapper for

    :type use: str|callable
    :arg use:
        [required]
        new function to use, or string containing absolute module path + name func for importing

    :type msg: str|None
    :param msg:
        [optional, kwd only]
        overrides the entire string displayed in the warning message.

    :type lazy: bool
    :param lazy:
        If ``True`` (the default), the import of *new_func* is delayed until needed.
        If False, the new function is imported immediately.

    Usage examples ::

        >>> from bps.warndep import relocated_function

        >>> #function 'old_func' has been renamed to 'new_func' with the same module
        >>> old_func = relocated_function("old_func", new_func)

        >>> #function 'old_func' has been moved to another module,
        >>> #and must be specified by name only (it will be lazily imported)
        >>> old_func = relocated_function("old_func", "othermod.new_func")

        >>> #this function is basically a helpful wrapper for deprecated_function,
        >>> #the equivalent usage of which would be the following...
        >>> from bps.warndep import deprecated_function
        >>> from othermod import new_func
        >>> @deprecated_function(new_func.__name__)
        >>> def old_func(*a,**k):
        >>>     return new_func(*a,**k)
        >>> #... but relocated_function offers lazy imports
        >>> # plus handles creating a stub function automatically

    """
    #handle deprecated kwds
    if 'new_name' in kwds:
        warn("'new_name' deprecated, use 'use' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        use = kwds.pop("new_name")
    if 'new_func' in kwds:
        warn("'new_func' deprecated, use 'use' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        use = kwds.pop("new_func")
    if 'old_name' in kwds:
        warn("'old_name' deprecated, use 'name' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        name = kwds.pop("old_name")
    if kwds:
        raise TypeError, "unknown kwds: %r" % (kwds,)

    #inspect caller to determine current module
    mod = inspect.currentframe(1).f_globals.get("__name__", "???")

    #parse 'use' into use_mod, use_name, handler
    if isinstance(use, str):
        if ':' in use:
            #assume they used "a.b.c:func" syntax
            idx = use.rindex(":")
        elif '.' in use:
            #assume they used "a.b.c.func" syntax
            idx = use.rindex(".")
        else:
            #assume in this module
            use = mod + "." + use
            idx = use.rindex(".")
        use_mod = use[:idx]
        use_name = use[idx+1:]
        handler = None
    elif callable(use):
        use_mod = use.__module__
        use_name = use.__name__
        handler = use
    else:
        raise ValueError, "new function path or instance must be specified ('use' kwd)"

    #fill in some defaults
    if name is None:
        if mod == use_mod:
            raise ValueError, "old function name must be specified ('name' kwd)"
        name = use_name
    old_path = mod + "." + name
    use_path = use_mod + "." + use_name

    #create default msg
    if not msg:
        #TODO: have this use name only if w/in same module.
        #   this will require better test_warndep code, using external modules,
        #   as well as changing the text of test_security_pwhash's legacy warnings
        ##if mod == use_mod:
        ##    msg = "function %(name)r is deprecated, use %(use_name)r instead"
        ##else:
        msg = "function %(name)r is deprecated, use %(use_path)r instead"
        if removal:
            if removal is True:
                msg += "; it will be removed in the future"
            else:
                msg += "; it will be removed after %(removal)s"
    if '%(mod)' not in msg: #just to make sure user is oriented about warning
        msg = "%(mod)s: " + msg

    #render warning message
    text = msg % dict(
        mod=mod,
        name=name,
        use_path=use_path,
        use_name=use_name,
        removal=removal,
        )

    #resolve handler
    wrapper = None
    def resolve():
        module = __import__(use_mod, fromlist=[use_name])
        try:
            value = getattr(module, use_name)
        except AttributeError:
            raise AttributeError("module %r has no attribute %r" % (use_mod, use_name))
        if value is wrapper:
            raise ParamError, "relocated_function(%r,%r): 'name' & 'use' parameters reversed" % (old_path,use_path,)
        return value
    if handler is None and not lazy:
        handler = resolve()
        assert handler

    #create appropriate wrapper
    if handler:
        #direct wrapper
        def wrapper(*args, **kwds):
            warn(text, DeprecationWarning, stacklevel=2)
            return handler(*args, **kwds)
        update_wrapper(wrapper, handler)
    else:
        #delayed importing wrapper
        cache = [None]
        def wrapper(*args, **kwds):
            warn(text, DeprecationWarning, stacklevel=2)
            func = cache[0]
            if func is None:
                func = cache[0] = resolve()
                update_wrapper(wrapper, func)
            return func(*args, **kwds)
        wrapper.__doc__ = "relocated_function wrapper for %r" % use
    wrapper.__name__ = name
    return wrapper

#TODO: work out way for this to operate on class & static methods
def relocated_method(name=None, use=None, removal=None, msg=None, **kwds):
    """Companion to deprecated_method(): This actually returns a function
    which proxies the replacement method after issuing a deprecation warning.

    :type name: str|None
    :arg name:
        name of old (deprecated) method we're creating a function for.
        (If ``None``, name will be autodetected when method is first used).

    :type use: str|callable
    :arg use:
        [required]
        name of new method which should be used in this method's place.

    :type msg: str|None
    :param msg:
        optionally override the deprecation message displayed.

    :type removal: str|None
    :param removal:
        optional indicate date or release this will be removed in.
    """
    #handle deprecated kwds
    if 'new_name' in kwds:
        warn("'new_name' deprecated, use 'use' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        use = kwds.pop("new_name")
    if 'old_name' in kwds:
        warn("'old_name' deprecated, use 'name' instead; to be removed soon", DeprecationWarning, stacklevel=2)
        name = kwds.pop("old_name")
    if kwds:
        raise TypeError, "unknown kwds: %r" % (kwds,)

    #
    #validate inputs (let deprecated_method catch other cases)
    #
    if not use:
        raise ValueError, "new method name to use must be specified ('use' kwd)"

    if callable(use):
        handler = use
        use = handler.__name__
    else:
        handler = None

    #
    #build msg
    #
    if not msg:
        msg = "method %(name)r is deprecated, use %(use)r instead"
        if removal:
            if removal is True:
                msg += "; it will be removed in the future"
            else:
                msg += "; it will be removed after %(removal)s"
    if '%(mod)' not in msg: #just to make sure user is oriented about warning
        msg = "%(mod)s.%(cls)s: " + msg

    #
    #build wrapped handler
    #
    state = dict(
        #from constructor
        use=use,
        name=name,
        removal=removal,

        #filled in after being bound to class
        text=None,
        mod=None,
        cls=None,
        handler=None,
        )
    def wrapper(self, *a, **k):
        #FIXME: this text optimization doesn't work if 2+ subclasses call relocated method of parent.
        #   remove optimization & add a unit test
        ##text = state['text']
        ##handler = state['handler']
        ##if text:
        ##    warn(text, DeprecationWarning, stacklevel=2)
        ##else:
            cls = self.__class__
            if not state['name']:
                state['name'] = find_attribute(cls, wrapper, required=True)
            state.update(
                mod=cls.__module__,
                cls=cls.__name__,
                )
            #TODO: detect old_name here
            text = state['text'] = msg % state
            warn(text, DeprecationWarning, stacklevel=2)
            handler = state['handler'] = getattr(cls, use)
            if getattr(handler,"im_func",None) is wrapper:
                raise ParamError, "%r: relocated_method(%r,%r): 'name' & 'use' parameters reversed" % (cls, name, use)
            return handler(self, *a, **k)
    wrapper.__name__ = name or "<deprecated alias for %r>" % (use,)
    return wrapper

#XXX: this func hasn't been documented yet, because it doesn't work right yet
def relocated_class(old_name, new_class=None, new_name=None, msg=None, lazy=True, inheritable=True):
    """equivalent to relocated_function() for classes.

    :param subclass:
        If ``False``, the stub this returns will not be suitable for subclassing.
        This allows a cheaper implementation to be used.

    .. todo::
        Right now this doesn't actually do anything
        besides return the named class, and just acts as a placeholder
        till a proper implementation is devised.

        Such an implementation must:
            * issue a warning when the class is first imported OR instantiated/subclassed
            * still act like just the real class as far as inheritance goes.
    """
    if not inheritable:
        #TODO: work up better msg
        return relocated_function(old_name, new_class, new_name, msg, lazy)

    #FIXME:
    if not old_name:
        raise ValueError, "old function name must be specified"
    if not new_class:
        #new_func stored in old_name,
        #and proper old_name should be derived
        #from end of new_func
        new_class = old_name
        assert isinstance(new_class, str)
        assert '.' in new_class or ':' in new_class
        old_name = None
    if isinstance(new_class, str):
        #assume this is a full path name,
        #which will be imported lazily w/in the wrapper
        if ':' in new_class:
            #assume they used "a.b.c:func" syntax
            idx = new_class.rindex(":")
        else:
            #assume they used "a.b.c.func" syntax
            idx = new_class.rindex(".")
        new_mod = new_class[:idx]
        new_class = new_class[idx+1:]

    #and now the hack.. we resolve & return new_class
    if isinstance(new_class, str):
        mod = __import__(new_mod, fromlist=[new_class])
        return getattr(mod, new_class)
    else:
        return new_class

#=========================================================
#
#=========================================================
