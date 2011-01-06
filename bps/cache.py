"""bps.cache -- caching tools"""
#===================================================
#imports
#===================================================
#core
import inspect
from functools import update_wrapper
import time
from warnings import warn
#needed imports
#legacy imports
from bps.undef import Undef
from bps.meta import find_attribute, decorate_per_instance, instancemethod
#XXX: bps3.misc.finalmethod?
#TODO: bps3.misc.AbstractMethodError - here or in bps.exc?

__all__ = [
    #cached decorators
    'cached_function',
    'cached_method',

    #stateful decorators
    'stateful_function',
    'stateful_method',
    'is_stateful',
]

#=========================================================
#function caching decorator
#=========================================================

def cached_function(key=None, args=None, lifetime=None, tick=time.time):
    """decorator that caches a function's output.

    This decorator creates an dictionary which caches the return values
    of the wrapped function, so that successive calls hit the cache
    rather than calling the function itself. This decorator
    supports numerous features, including time-limited caching,
    and customization how the cache key is calculated.

    :param key:
        This should be a function which takes the wrapper func's inputs,
        and maps them to a hashable value to identify inputs for caching purposes.
        If ``key(*args,**kwds)`` returns the ``NotImplemented`` singleton, caching will be bypassed.

    :param args:
        Alternately, instead of specifying a `key`, this option can be used
        to specify the number of positional arguments expected, which will be formed into a tuple,
        and used as the cache key. This option is mutually exlusive with *key*.

    :param lifetime:
        Amount of time (as measured by `tick` function)
        before cached values should expire.
        If lifetime is ``None`` (the default), cached values will never expire,
        unless ``func.clear()`` is explicitly called by your application.

    :param tick:
        Function returning arbitrary objects for timestamping,
        used by `lifetime`. By default, this uses ``time.time()``

    The resulting decorated function object will have a some extra attributes:
        ``func.key(*args,**kwds)``
            Calling this with a set of the function's arguments
            will return the key used to cache the result for those parameters.

        ``func.clear(keys=None)``
            Calling this will clear the internal cache of function results.
            If *keys* is specified, only those cache keys will be cleared.

        ``func.set(key,value)``
            Allows writing to the function cache directly.

        ``func.cache``
            This is an exposed reference to the actual cache dictionary.
            Please use this only if you *really* have to.

            .. caution::
                If your code does access the dictionary, be aware that the
                ``lifetime`` option will change the organization of the dict from
                ``key -> result`` to ``key -> (mtime,result)``.

    A simple usage example::

        >>> import time
        >>> from bps.cache import cached_function
        >>> #an example which has an expiring cache
        >>> @cached_function(args=1, lifetime=2)
        >>> def myfunc(value):
        >>>     print "myfunc called:", value
        >>>     return value*2
        >>> #the first call won't be cached
        >>> print "result:", myfunc(2)
            myfunc called: 2
            result: 4
        >>> #but the next one will
        >>> print "result:", myfunc(2)
            result: 4
        >>> #if we wait a bit and try again, the cache will expire
        >>> time.sleep(2)
        >>> print "result:", myfunc(2)
            myfunc called: 2
            result: 4
        >>> #or we can manually flush the entire cache
        >>> myfunc.clear()
        >>> print "result:", myfunc(2)
            myfunc called: 2
            result: 4

    .. seealso::
        :func:`cached_method`
        :func:`stateful_function`
    """
    if key is None:
        if args is None:
            warn("one of `key` or `args` will be required for cached_function() in the future, the bare version is deprecated", DeprecationWarning, stacklevel=3)
            def key():
                return None
        elif args == 0:
            def key():
                return None
        elif args == 1:
            def key(value):
                return value
        else:
            def key(*a):
                if len(a) != args:
                    raise ValueError, "expected exactly %s arguments: %r" % (args, a)
                return a
    else:
        assert args is None, "args and key() function are mutually exlusive"
    assert callable(key), "key() function must be callable"
    def builder(func):
        #validate the function
        if hasattr(func, "on_changed"):
            warn("cached_function() is wrapping a function that was wrapped with stateful_function()... the opposite wrapping order is recommended for correct behavior", stacklevel=1)
            #NOTE: why the warning?
            # because stateful's changed() can call clear_cache(),
            # but cache_func will hide any state changes which occur.
            # so you want to decorator your function the other way around.

        #init locals
        cache = {}

        #create wrapper...
        if lifetime is None:
            #...with no expiration
            def wrapper(*args, **kwds):
                value = key(*args, **kwds)
                if value is NotImplemented:
                    return func(*args, **kwds)
                elif value in cache:
                    return cache[value]
                result = cache[value] = func(*args, **kwds)
                return result
            wrapper.set = cache.__setitem__ #for easy overriding of cache

        else:
            #...with predefined expiration
            def wrapper(*args, **kwds):
                value = key(*args, **kwds)
                if value is NotImplemented:
                    return func(*args, **kwds)
                now = tick()
                if value in cache:
                    expires, result = cache[value]
                    if expires > now:
                        return result
                result = func(*args, **kwds)
                cache[value] = (now+lifetime, result)
                return result

            def set(key, value, expires=None):
                if expires is None:
                    expires = tick() + lifetime
                cache[key] = (expires, value)
            wrapper.set = set #for easy overriding of cache
            wrapper.tick = tick #in case it's useful

        #fill in common attributes
        def clear(keys=None):
            if keys:
                for key in keys:
                    if key in cache:
                        del cache[key]
            else:
                cache.clear()
        wrapper.expire = clear #legacy ref, do not use
        wrapper.clear = clear
        wrapper.key = key #expose the key func
        wrapper.cache = cache #for times when you really need direct cache access

        #return wrapper
        update_wrapper(wrapper, func)
        return wrapper

    return builder

def cached_method(key=None, args=None, lifetime=None, tick=time.time):
    """decorator that created instance-level cached functions.

    This a wrapper for :func:`cached_function`, which is designed
    to wrap methods, not functions, by providing a per-instance
    caching dictionary.

    The options for this are the same as :func:`cached_function`.

    .. note::

        By default, the *self* argument will not be present in the arguments
        passed to the key function. That can be fixed if needed,
        but it simplifies the current internal implementation.
    """
    #TODO: we use "method" binding so the .clear() etc attributes are instance specific.
    # so "function" binding can't be used.
    # but we could expose a bind="function" to fake things,
    # and artificially insert *self* into the key func's arguments.
    builder = cached_function(key=key, args=args, lifetime=lifetime, tick=tick)
    return decorate_per_instance(builder, bind="method")

#=========================================================
#stateful decorators
#=========================================================

def stateful_function(func=None):
    """decorator which adds methods to function allows callbacks
    to be attached to detect when it changes it's output.

    This decorator is primarily useful for functions
    which consistently return the same value when called
    called multiple times, but occasionally change
    what the value is due to some internal event.
    Examples of this include functions returning
    filesystem listings, or in gui programming.

    This decorator adds a simple callback / signalling system
    by instrumenting the function object with the following methods:

        ``func.changed()``
            Your program should call this method after a resource has changed
            which would alter what the function would returned.
            It will cause all registered callbacks to be fired.

        ``func.on_change(callback, data=Undef, tag=None) -> tag``
            This attached a callback to the function,
            Callback are called in FIFO order when ``func.changed()`` is invoked.
            *on_change* will return a unique tag object to identify the registration
            of your callback, for use with ``func.forget_callbacks``.

            *callback*
                This should be a function with the prototype ``callback()``,
                or ``callback(data)`` if the *data* parameter is set.
            *data*
                This is an optional value passed as a positional parameter
                to your callback.
            *tag*
                Optional value specifying custom tag object to use.
                If not specified, an anonymous object will be created.
                This option allows you to gang a bunch of callbacks
                together on one tag, for mass-removal.
                No restrictions are placed on the nature of the object you provide.

        ``func.forget_callbacks(*tags)``
            Remove all callbacks attached to this function using any
            of the specified tags. Any tags that aren't found will be silently ignored.

    Usage example::

        >>> from bps.cache import stateful_function
        >>> #stateful functions typically have no arguments, but they can if they want
        >>> @stateful_function
        >>> def getpi():
        >>>     print "getpi called"
        >>>     return 3.14159
        >>> getpi()
            getpi called
            3.14159
        >>> #say we want to attach a callback
        >>> def hook():
        >>>     print "divide by cucumber error, please reboot universe"
        >>>     print "pi is now:", getpi()
        >>> getpi.on_change(hook)
        >>> #and say pi changes value for some reason, our hook will be called..
        >>> getpi.changed()
            divide by cucumber error, please reboot universe
            pi is now: 3.14159

    """
    #
    #just return prepared builder if function isn't present
    #
    if func is None:
        return stateful_function

    if isinstance(func, instancemethod):
        #instance methods have read-only attributes,
        #so we have to create a wrapper whose attributes we _can_ set
        orig = func
        def func(*args, **kwds):
            return orig(*args, **kwds)
        update_wrapper(func, orig)

    #
    #state
    #
    hooks = [] #list of (tag, hook, data) callbacks

    #
    #methods
    #
    def on_change(hook, data=Undef, tag=None):
        "mattaching a callback to be invoked when function state changes"
        if tag is None: tag = object()
        entry = (tag, hook, data)
        hooks.append(entry)
        return tag
    func.on_change = on_change

    #clear_cache provides integration with cachemethod() above,
    #but cachemethod MUST BE CALLED FIRST
    clear_cache = getattr(func, "clear", None)

    ##func.changing = False
    def changed():
        "signal that function's state has changed, triggering callbacks"
        if clear_cache: clear_cache()
        ##func.changing = True
        ##try:
        for tag, hook, data in hooks:
            if data is Undef: hook()
            else: hook(data)
        ##finally:
        ##    func.changing = False
    func.changed = changed

    def forget_callbacks(*tags):
        "remove specified callbacks hooks"
        pos = 0
        while pos < len(hooks):
            if hooks[pos][0] in tags:
                del hooks[pos]
            else:
                pos += 1
    func.forget_callbacks = forget_callbacks

    #return func
    return func

def stateful_method(func=None):
    """Per-instance version of :func:`stateful_function`.

    Unlike stateful_function, all callbacks / triggers will be unique per-instance,
    rather than shared globally. See stateful_function for more details.
    """
    decorator = decorate_per_instance(stateful_function, bind="method")
    if func:
        return decorator(func)
    else:
        return decorator

def is_stateful(func):
    """returns ``True`` if function has been instrumentated by @stateful_function or compatible protocol"""
    return (
        hasattr(func, "changed")
        and hasattr(func, "on_change")
        and hasattr(func, "forget_callbacks")
    )

#=========================================================
#
#=========================================================
