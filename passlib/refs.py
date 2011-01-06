"""bps.refs -- weak reference objects and proxy objects"""
#=========================================================
#imports
#=========================================================
#core
from contextlib import contextmanager
from sys import getrefcount
import thread
from time import time as cur_time
from weakref import ref as make_weakref
from warnings import warn
#pkg
from bps.undef import Undef
from bps.error.types import ProxyNestError, ProxyEmptyError
from bps.types import CustomDict
#local
__all__ = [
    #decorators
    'weakref_property',

    #weak ref classes
    'WeakSet',
    'SoftValueDict',

    #proxy objects
    'ProxyObject',
    'proxy_using_object',
    'is_proxy_active',
]
#=========================================================
#decorators
#=========================================================
class weakref_property(object):
    """descriptor which provides transparent access to stored object via weakref.

    A common need is to store a weak reference in a attribute,
    and then resolve it before using it.
    This property takes care of that, by storing a weak reference
    to any value passed to it inside another (hidden) attribute,
    thus the attribute acts like a proxy for whatever is referenced.
    ``None`` is returned if no reference is present,
    and if ``None`` is stored, any weak references will be purged.

    :param attr:
        This allows specifying the attribute that will be used
        to store the weak reference. By default, a random one
        based on the property's id will be chosen.
    """
    #XXX: really should be called 'weakref_attribute'
    name = None #: the attribute we'll store the weakref in

    def __init__(self, attr=None):
        if attr is None:
            #FIXME: will this cause problems for, say, pickling?
            # shouldn't be pickling weakrefs, but could anything
            # be relying on the attr name only to have it shift
            # when the id changes?
            self.attr = "_weakref_property__%d" % (id(self),)
        else:
            self.attr = attr

    def __get__(self, instance, owner):
        if instance is None:
            return self
        else:
            ref = getattr(instance, self.attr, None)
            if ref:
                return ref()
            else:
                return None

    def __set__(self, instance, value):
        if value is None:
            setattr(instance, self.attr, None)
        else:
            setattr(instance, self.attr, make_weakref(value))

    def __delete__(self, instance):
        delattr(instance, self.attr)

#=========================================================
#constructors
#=========================================================

#=========================================================
#classes
#=========================================================
try:
    #introduced in py27
    from weakref import WeakSet
except ImportError:
    #TODO: make sure this conforms to py27 weakset
    #esp ensure non-standard methods like iterrefs() match whatever py27 has (if available)
    
    class WeakSet(object):
        """A :class:`set` compatible object which stored weak references
        to all of it's elements.
    
        .. warning::
            This class is not fully fleshed out, has some implementation
            issues, and may need development work for all but the simplest
            use-cases. Many of these issues can be fixed if the need arises.
    
            * the | & ^ operators haven't been implemented (yet).
            * there may be some glitches in some methods (needs UTs)
            * this class doesn't derive from :class:`set`, but it should
    
        all standard set methods should be present and act the same,
        with the minor change that ones which previously returned
        a set() instance now return a WeakSet() instance.
            
        this class provides one additional method not found in the normal
        set class:
        
        .. automethod:: iterrefs
        
        """
        #TODO: inherit from set ?
        #TODO: implement the other set methods correctly
        #TODO: implement __or__, __and__, etc
    
        def __init__(self, source=None):
            data = self.data = set() #contains weakrefs to real data
            
            #when weakref goes away, this callback will be called,
            #which takes care of updating set.
            def remove(elem, dref=make_weakref(data)):
                data = dref()
                if data is not None:
                    data.discard(elem)
            self._remove = remove
            
            #load initial data
            if source:
                self.update(source)
    
        def __contains__(self, elem):
            try:
                r = make_weakref(elem)
            except TypeError: #elem not weakref'able
                return False
            #NOTE: this relies on weakrefs being comparable based on obj's __eq__ method
            return r in self.data
    
        # __and__
        # __eq__
        # __iand__
        # __ior__
        # __ixor__
    
        def __iter__(self):
            for ref in self.data:
                elem = ref()
                if elem is not None:
                    yield elem
    
        def __len__(self):
            c = 0
            for ref in self.data:
                if ref() is not None:
                    c += 1
            return c
    
        # __ne__
    
        def __nonzero__(self):
            for ref in self.data:
                if ref() is not None:
                    return True
            return False
        
        # __or__
        # __rand__
        # __ror__
        # __rxor__
        # __xor__
        
        def add(self, elem):
            self.data.add(make_weakref(elem, self._remove))
    
        def clear(self):
            self.data.clear()
    
        def copy(self):
            return WeakSet(self)
        
        def difference(self, other):
            "return new weakset containing elements in ``self`` which are also in ``other``"
            return WeakSet(elem for elem in other if elem not in self)
        
        def difference_update(self, other):
            "remove elements from ``self`` which are also in ``other``"
            discard = self.data.discard
            for elem in other:
                try:
                    ref = make_weakref(elem)
                except TypeError:
                    continue
                discard(ref)
    
        def discard(self, elem):
            try:
                ref = make_weakref(elem)
            except TypeError:
                return
            self.data.discard(ref)
    
        def flush(self, force=True):
            #NOTE: this is holdover from old implementation
            # which didn't use weakref callback hook to clean unused refs.
            warn("WeakSet.flush is deprecated & now a noop, it longer needs to be called", DeprecationWarning, 2)
    
        def intersection(self, other):
            return WeakSet(elem for elem in other if elem in self)
        
        def intersection_update(self, other):
            "remove elements from ``self`` which are not in ``other``"
            #FIXME: probably have error since we're modifying set as we iterate it.
            #might be better to use difference & different update
            discard = self.data.discard
            for ref in self.data:
                elem = ref()
                if elem is not None and elem not in other:
                    discard(ref)
    
        #NOTE: this was introduced in py26, should we expose it for py25?
        def isdisjoint(self, other):
            "true if two sets have NO elements in common"
            for elem in other:
                if elem in self:
                    return False
            return True
                
        def issubset(self, other):
            "whether other contains all elements of self"
            if not hasattr(other, "__contains__"):
                other = set(other)
            return all(elem in other for elem in self)
            
        def issuperset(self, other):
            "whether self contains all elements of other"
            return all(elem in self for elem in other)
        
        def iterrefs(self):
            "iterate through all weakrefs [not part of set standard]"
            return iter(self.data)
        
        def pop(self):
            pop = self.data.pop
            while True:
                ref = pop() #raises KeyError when underlying set is empty
                elem = ref()
                if elem is not None:
                    return elem
    
        def remove(self, elem):
            try:
                ref = make_weakref(elem)
            except TypeError:
                #raise KeyError since this could never be a key
                raise KeyError, elem
            try:
                self.data.remove(ref)
            except KeyError:
                raise KeyError, elem
    
        def symmetric_difference(self, other):
            "return elems in self OR in other, but not both"
            out = self.copy()
            out.symmetric_difference_update(other)
            return out
            
        def symmetric_difference_update(self, other):
            add, remove = self.add, self.remove
            for elem in other:
                if elem in self:
                    remove(elem)
                else:
                    add(elem)
        
        def union(self, other):
            target = self.copy()
            target.update(other)
            return target
        
        def update(self, other):
            add = self.data.add
            remove = self._remove
            for elem in other:
                add(make_weakref(elem,remove))

#TODO: this will need much more work before it's publically used
class SoftValueDict(CustomDict):
    """This dict operates much like :class:`weakref.WeakValueDictionary`,
    except that it attempts to provide something similar to java's soft references
    (which are real references, but purged if memory is needed).

    Currently, the implementation does not rely on memory at all,
    but rather uses a somewhat inefficient cache / timed expiration,
    so that infrequently accessed references will be dropped.

    In order for this to work, ``self.flush()`` must be called occasionally,
    it order to flush stale references.

    .. todo::
        * The main use of this class is by :class:`bps.fs.filepath`,
          so the class may not be as useful in other places.
        * Document this better
        * Work up a better soft-reference algorithm.

    .. warning::

        This uses a pretty ugly reference counting hack internally,
        it's almost guaranteed to break for someone... but the break
        will (at worst) mean it this dict acts like a strong reference dict.

    :param expire:
        Number of seconds a key can remain unreferenced
        for it's deemed "stale" and cleared on the next flush cycle.
    :param flush:
        How many seconds between flush cycles.
        Unless ``self.flush(force=True)`` is used,
        called ``self.flush()`` will only cause a flush to occur
        every *flush* seconds, allowing this function to be
        safely called *a lot*.
    """
    #=================================================
    #init
    #=================================================
    def __init__(self, expire=300, flush=150):
        self.expire = expire
        self.flush_delay = flush
        self.next_flush = 0
        CustomDict.__init__(self)

    def flush(self, force=False):
        "flush expired entries"
        #TODO: could "amortize" the cost of the flush over all the calls?
        cur = cur_time()
        if not force and cur > self.next_flush:
            return
        self.next_flush = cur + self.flush_delay
        cutoff = cur - self.expire
        purge = [
            key
            for key, (atime, value) in dict.iteritems(self)
            if getrefcount(value) <= 4 and atime < cutoff
                #4 refs held by: self, ``value`` in current frame, getrefcount frame, and iteritems frame
            ]
        print "DelayedValueDict: purging keys: %r" % (purge,)
        for key in purge:
            del self[key]

    #=================================================
    #first level
    #=================================================
    def __getitem__(self, key):
        entry = CustomDict.__getitem__(self, key)
        entry[0] = cur_time() #fresh access time
        return entry[1]

    def __setitem__(self, key, value):
        return CustomDict.__setitem__(self, key, [cur_time(), value])

    #__delitem__ left alone

    #=================================================
    #EOC
    #=================================================

#=========================================================
#proxy objects
#=========================================================
#TODO: a potential use-case involves global default values
# which can then be overridden on a per-thread basis.
#
import threading

#TODO: definitely need ProxyObject unittests

class ProxyObject(object):
    """This is a global proxy object.

    Once an instance is created, proxy targets are pushed onto the stack.
    Any attribute access will be proxied to the last target object pushed on to the stack.
    Targets must be removed in LIFO order from the stack.

    This is mainly useful for when you absolutely have to have
    a global object, but need to import it before the object itself exists.

    :param name:
        Optional unique name to give the proxy instance you're created.
        This will be reported in the text of any raised errors,
        and via ``repr()``.

    :param default:
        Optional object which will be used as default target
        when the stack is empty.

    :param threaded:
        If ``True``, the instance will maintain a unique stack of targets
        for each thread. If ``False`` (the default), a single stack will
        be shared across all threads in the process.

    .. automethod:: _current_obj
    .. automethod:: _pop_object
    .. automethod:: _push_object

    .. note::
        This class tries to adhere to the interface used by
        `Paste's StackObjectProxy <http://pythonpaste.org/modules/registry.html#paste.registry.StackedObjectProxy>`_,
        which it was directly inspired by.

    """
    #=========================================================
    #init
    #=========================================================
    def __init__(self, name=None, default=Undef, threaded=False):
        self.__dict__['_BpsProxyObject_name'] = name or ("Unnamed 0x%x" % id(self))
        self.__dict__['_BpsProxyObject_default'] = default
        self.__dict__['_BpsProxyObject_threaded'] = threaded
        if threaded:
            self.__dict__['_BpsProxyObject_local'] = threading.local()
        else:
            self.__dict__['_BpsProxyObject_stack'] = []

    #=========================================================
    #stack management
    #=========================================================
    def _current_obj(self):
        """Returns object on top of proxy stack.

        If the stack is empty, the default object will be used.
        If there is no default object, :exc:`bps.error.types.ProxyEmptyError` will be raised.
        """
        threaded = self.__dict__['_BpsProxyObject_threaded']
        if threaded:
            stack = getattr(self.__dict__['_BpsProxyObject_local'], "stack", None)
        else:
            stack = self.__dict__['_BpsProxyObject_stack']
        if stack:
            return stack[-1]
        default = self.__dict__['_BpsProxyObject_default']
        if default is Undef:
            raise ProxyEmptyError(
                'No object registered for global proxy %r'
                % self.__dict__['_BpsProxyObject_name'])
        else:
            return default

    def _push_object(self, obj):
        """push another object onto the proxy stack"""
        threaded = self.__dict__['_BpsProxyObject_threaded']
        if threaded:
            local = self.__dict__['_BpsProxyObject_local']
            if hasattr(local, "stack"):
                stack = local.stack
            else:
                stack = local.stack = []
        else:
            stack = self.__dict__['_BpsProxyObject_stack']
        stack.append(obj)

    def _pop_object(self, obj=Undef):
        """pop top object off proxy stack, and return it.

        If the stack is empty, an :exc:`IndexError` will be raised.

        Objects are popped off in LIFO order.

        If the parameter *obj* is specified, it will be checked against
        the removed object, and if it does not match, :exc:`bps.error.types.ProxyNestError` will be raised.
        """
        threaded = self.__dict__['_BpsProxyObject_threaded']
        if threaded:
            local = self.__dict__['_BpsProxyObject_local']
            if hasattr(local, "stack"):
                stack = local.stack
            else:
                stack = local.stack = []
        else:
            stack = self.__dict__['_BpsProxyObject_stack']
        cur = stack.pop()
        if obj is not Undef:
            if obj is not cur:
                raise ProxyNestError(
                    "Unexpected object popped from %s proxy %r: popped %r, but expected %r"
                    % (
                       ["global","thread"][threaded],
                       self.__dict__['_BpsProxyObject_name'],
                       cur, obj)
                       )
        return cur

    def _object_stack(self):
        """return copy of current object stack as a list"""
        threaded = self.__dict__['_BpsProxyObject_threaded']
        if threaded:
            local = self.__dict__['_BpsProxyObject_local']
            if hasattr(local, "stack"):
                return local.stack[:]
            else:
                return []
        else:
            return self.__dict__["_BpsProxyObject_stack"][:]

    #=========================================================
    #methods that have to be overridden for proxying to work
    #=========================================================

    #proxy attribute access
    def __getattr__(self, attr):
        "proxy all attribute reads to the proxy target"
        return getattr(self._current_obj(), attr)

    def __setattr__(self, attr, value):
        "proxy all attribute writes to the proxy target"
        setattr(self._current_obj(), attr, value)

    def __delattr__(self, attr):
        "proxy all attribute deletes to the proxy target"
        delattr(self._current_obj(), attr)

    #=========================================================
    #special attributes
    #   exposing these attributes speeds things up, but more
    #   importantly, Python performs various "capability" checks
    #   (eg is an object callable) by looking at the class dict,
    #   so __getattr__ is never hit. Thus, if we don't expose
    #   these, Python won't detect them.
    #=========================================================

    #NOTE: only going to uncomment these after testing
    # that _all_ are need for the above behavior.
    # confirmed for __call__, but need unittests

    #proxy item access
    ##def __getitem__(self, key):
    ##    return self._current_obj()[key]
    ##
    ##def __setitem__(self, key, value):
    ##    self._current_obj()[key] = value
    ##
    ##def __delitem__(self, key):
    ##    del self._current_obj()[key]

    #proxy 'in' operator
    ##def __contains__(self, key):
    ##    return key in self._current_obj()

    ###proxy the special methods
    ##def __len__(self):
    ##    return len(self._current_obj())

    def __call__(self, *args, **kw):
        return self._current_obj()(*args, **kw)

    ##def __iter__(self):
    ##    return iter(self._current_obj())
    ##
    ##def __nonzero__(self):
    ##    return bool(self._current_obj())

    #=========================================================
    #methods that expose some information about the proxy
    #=========================================================
    def __dir__(self):
        "reports list of all of proxy object's attrs as well as target object's attributes (if any)"
        attrs = set(dir(self.__class__))
        attrs.update(self.__dict__)
        try:
            obj = self._current_obj()
        except ProxyEmptyError:
            pass
        else:
            attrs.update(dir(obj))
        return sorted(attrs)

    def __repr__(self):
        "tries to report target's repr, falls back to proxy object id"
        try:
            obj = self._current_obj()
        except (ProxyEmptyError, AttributeError):
            #NOTE: AttributeError caught in case repr() was called
            #   before object created or after partly torn down.
            return object.__repr__(self)
        else:
            return repr(obj)

    #=========================================================
    #eoc
    #=========================================================

#TODO: alter_proxy_config()
# which can change from threads->non-threaded, change name & default

def is_proxy_active(proxy):
    """checks if a proxy object currently has a target set.

    :arg proxy: the proxy object to test.

    :returns:
        ``True`` if proxy object has a target (whether by default, or added).
        ``False`` if proxy object has no target (reading it will result in :exc:`ProxyEmptyError`).
    """
    #TODO: make this work w/ Paste proxies?
    #TODO: add default=False to exclude default from check, somehow?
    try:
        proxy._current_obj()
        return True
    except ProxyEmptyError:
        return False

@contextmanager
def proxy_using_object(proxy, obj):
    """context-manager for proxy objects, manages adding & removing object for you.

    Usage Example::

        >>> from bps.refs import ProxyObject, proxy_using_object
        >>> app = ProxyObject()
        >>> obj = object()
        >>> with proxy_using_object(app,obj):
        >>>     #during this context, 'app' will proxy 'obj',
        >>>     #and it will stop proxying 'obj' when the context ends

    :param proxy:
        The proxy instance
    :param obj:
        The object it should proxy for the during of the context.

    :returns:
        Returns the original proxy object,
        after having *obj* pushed onto it's stack.
    """
    proxy._push_object(obj)
    try:
        yield proxy
    finally:
        proxy._pop_object(obj)

#TODO: ProxyBinding, for pushing/popping from a group of proxies at once

#=========================================================
#EOF
#=========================================================
