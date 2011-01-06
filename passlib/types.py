"""bps.types -- helper datatypes
"""
#=========================================================
#imports
#=========================================================
#core
import sys
import time
from logging import getLogger; log = getLogger(__name__)
#pkg
from bps.meta import instrument_super, is_str
from bps.undef import Undef
from bps.warndep import deprecated_method, relocated_function
#local
__all__ = [
    'BaseMetaClass', 'BaseClass',
    'stub',
    'namedtuple',
    'CustomDict', 'OrderedDict',
]

#provide a 'bytes' alias for 2.5 (2.6 already has one)
try:
    bytes
except NameError:
    bytes = str

#=========================================================
#BaseClass
#=========================================================
class BaseMetaClass(type):
    """meta class which provides some useful class behaviors.
    see `BaseClass` for details.
    """
    def __init__(self, name, bases, kwds):
        #init parent stuff
        type.__init__(self,name,bases, kwds)

        #fill in __super descriptor
        instrument_super(self)

        #call __initclass__ if defined
        if '__initclass__' in kwds:
            kwds['__initclass__'](self)

        #does this class defined __initsubclass__?
        if '__initsubclass__' in kwds:
            #make sure it's stored as a classmethod
            value = kwds['__initsubclass__']
            if not isinstance(value, classmethod):
                self.__initsubclass__ = classmethod(value)
            #now call parent's __initsubclass__ if any
            parent = super(self,self)
            if hasattr(parent, "__initsubclass__"):
                parent.__initsubclass__()
        #else check if any of this class's parents defined __initsubclass__
        elif hasattr(self, '__initsubclass__'):
            self.__initsubclass__()

##    def __repr__(self):
##        return "<class '%s.%s' id=%r>" % (self.__module__, self.__name__, id(self))


class BaseClass(object):
    """Useful base class to inherit from, as a replacement for :class:`object`.

    Inheriting from this class provides three peices of magic behavior,
    courtesy of the metaclass :class:`BaseMetaClass`:

        * every subclass of BaseClass is provided with a ``self.__super`` attribute which can take
          the place of having to call super(cls,self) all the time.

        * the method ``cls.__initclass__()`` method will be invoked (if present) after a
          class is created, for doing additional runtime initialization.

        * the method ``cls.__initsubclass__()`` method will be invoked (if present)
            for every subclass of cls which is created.

          .. note::
            NOTE: __super.__initsubclass__ must be called to invoke a parent's
            __initsubclass__ method, if it has one, they will not be chained.

    .. todo::
        Some usage examples, especially to illustrate __initsubclass__.
    """
    #=========================================================
    #class attrs
    #=========================================================
    __metaclass__ = BaseMetaClass
    __extraneous_policy = "log" #XXX: may change default policy soon, now that non-conforming apps have this option
    __super = None

    if sys.version_info >= (2, 6):
        #HACK:
        #   We were hit hard by 2.6's requirement that object.__init__()
        #   never get passed arguments. This is a stopgap until our
        #   code finally gets in compliance.
        #   (though it may be left available as a optional flag in the future)

        def __init__(self, *args, **kwds):
            if args or kwds:
                #check if we're last before object
                if self.__class__.__mro__[-2] is BaseClass:
                    assert self.__class__.__mro__[-1] is object
                    #and if so, discard args and kwds
                    #these really are a sign of bad code
                    policy = self.__extraneous_policy
                    if policy == "log":
                        log.error("extraneous arguments passed to BaseClass: cls=%r args=%r kwds=%r",
                                  self.__class__, args, kwds)
                        self.__super.__init__()
                        return
                    elif policy == "ignore":
                        self.__super.__init__()
                        return
                    elif policy != "preserve":
                        raise ValueError, "bad _BaseClass__extraneous_policy value for %r: %r" % (self, policy)
            self.__super.__init__(*args, **kwds)

    #=========================================================
    #EOC BaseClass
    #=========================================================

#=========================================================
#closeable
#=========================================================
class CloseableClass(BaseClass):
    """Represents an object which has resources that will need freeing when it's closed.

    This class provides a closed attribute, a close method,
    and methods for attaching callbacks which will be invoked
    when close is called. This is especially useful for objects
    which representing a external resource which needs to be freed
    at a certain time.

    .. todo::
        Document methods & examples
    """
    #=========================================================
    #instance attrs
    #=========================================================
    __closed = False #private flag indicating object has been "closed"
    __closing = False #private flag indicating close() method is working
    __closehooks = None #callbacks, stored as list of (func,args,kwds) tuples

    #=========================================================
    #internals
    #=========================================================

    def __del__(self):
        #when object is GC'd, make sure to close it.
        #FIXME: if attached hooks are methods of object,
        # we'll never get here due to cyclic problem :(
        self.close()

    #simulate a ".closed" attribute by proxying __closed
    class _Closed_Property(object):
        """Indicates whether this :meth:`closed` has been called for this object.

        This is a readonly boolean property.
        """
        def __get__(self, obj, cls):
            if obj is None: return self
            else: return obj._CloseableClass__closed

        def __set__(self, obj, value):
            raise AttributeError, "'closed' attribute is read-only"
    closed = _Closed_Property()

    def __purge_helper(self, *attrs):
        "helper used by delete_on_close"
        for attr in attrs:
            #XXX: should we use hasattr/delattr?
            setattr(self, attr, None)

    #=========================================================
    #shared methods
    #=========================================================
    def _cleanup(self):
        "subclass this to add cleanup functions w/o using on_close()"
        pass

    #=========================================================
    #public methods
    #=========================================================
    def close(self):
        """close this object, and any attached resources."""
        if self.__closed:
            return False
        if self.__closing:
            log.warning("ignoring recursive call to CloseableClass.close()")
            return None
        self.__closing = True
        try:
            if self.__closehooks:
                #XXX: might make things more resilient to purge callbacks as they're run
                for func,args,kwds in self.__closehooks:
                    assert callable(func)
                    func(*args,**kwds)
                self.__closehooks = None
            self._cleanup()
        finally:
            self.__closing = False
        self.__closed = True
        return True

    def on_close(self, func, *args, **kwds):
        """register a callback to invoke at cleanup time.

        ``func`` should be a callable, and will be invoked as ``func(*args, **kwds)``.

        Callbacks are run in LIFO order.

        Exceptions raised by ``func`` will not be caught,
        and it's return value will be ignored.
        """
        assert not self.__closed
        if self.__closehooks is None:
            self.__closehooks = []
        assert callable(func)
        self.__closehooks.insert(0,(func,args,kwds))

    def delete_on_close(self, *attrs):
        """
        on close, set the specified attrs to ``None`` to free any references
        """
        #NOTE: this uses a callback so that attrs are deleted in order
        # along with any callbacks, in case class relies on exact ordering.
        assert not self.__closed
        if len(attrs) == 0:
            return
        if self.__closehooks is None:
            self.__closehooks = []
        self.__closehooks.insert(0,(self.__purge_helper,attrs, {}))

    purge_on_close = deprecated_method("purge_on_close", delete_on_close)

    #=========================================================
    #EOC
    #=========================================================

#=========================================================
#helper classes
#=========================================================
class stub(BaseClass):
    """create an anonymous object:

    * Any kwds passed to constructor are set as attributes.
    * All attribute are read-write.
    * There are no default attributes.

    For when even namedtuple isn't quick-n-dirty enough.
    """
    def __init__(self, **kwds):
        for k,v in kwds.iteritems():
            setattr(self, k, v)
        self.__super.__init__()

    __repr = None
    def __repr__(self):
        value = self.__repr
        if value is None:
            return object.__repr__(self)
        elif is_str(value):
            return value
        else:
            return unicode(value)

    __str = None
    def __str__(self):
        value = self.__str
        if value is None:
            return object.__str__(self)
        elif is_str(value):
            return value
        else:
            return unicode(value)

#=========================================================
#backports
#=========================================================
try:
    from collections import namedtuple #use native version if available
except ImportError:
    #
    # this class taken directly from the Python 2.6.2 source
    #
    from keyword import iskeyword as _iskeyword
    from operator import itemgetter as _itemgetter
    import sys as _sys
    def namedtuple(typename, field_names, verbose=False):
        """Returns a new subclass of tuple with named fields.
        [backported from python 2.6.2]

        >>> Point = namedtuple('Point', 'x y')
        >>> Point.__doc__                   # docstring for the new class
        'Point(x, y)'
        >>> p = Point(11, y=22)             # instantiate with positional args or keywords
        >>> p[0] + p[1]                     # indexable like a plain tuple
        33
        >>> x, y = p                        # unpack like a regular tuple
        >>> x, y
        (11, 22)
        >>> p.x + p.y                       # fields also accessable by name
        33
        >>> d = p._asdict()                 # convert to a dictionary
        >>> d['x']
        11
        >>> Point(**d)                      # convert from a dictionary
        Point(x=11, y=22)
        >>> p._replace(x=100)               # _replace() is like str.replace() but targets named fields
        Point(x=100, y=22)

        """

        # Parse and validate the field names.  Validation serves two purposes,
        # generating informative error messages and preventing template injection attacks.
        if isinstance(field_names, basestring):
            field_names = field_names.replace(',', ' ').split() # names separated by whitespace and/or commas
        field_names = tuple(map(str, field_names))
        for name in (typename,) + field_names:
            if not all(c.isalnum() or c=='_' for c in name):
                raise ValueError('Type names and field names can only contain alphanumeric characters and underscores: %r' % name)
            if _iskeyword(name):
                raise ValueError('Type names and field names cannot be a keyword: %r' % name)
            if name[0].isdigit():
                raise ValueError('Type names and field names cannot start with a number: %r' % name)
        seen_names = set()
        for name in field_names:
            if name.startswith('_'):
                raise ValueError('Field names cannot start with an underscore: %r' % name)
            if name in seen_names:
                raise ValueError('Encountered duplicate field name: %r' % name)
            seen_names.add(name)

        # Create and fill-in the class template
        numfields = len(field_names)
        argtxt = repr(field_names).replace("'", "")[1:-1]   # tuple repr without parens or quotes
        reprtxt = ', '.join('%s=%%r' % name for name in field_names)
        dicttxt = ', '.join('%r: t[%d]' % (name, pos) for pos, name in enumerate(field_names))
        template = '''class %(typename)s(tuple):
            '%(typename)s(%(argtxt)s)' \n
            __slots__ = () \n
            _fields = %(field_names)r \n
            def __new__(cls, %(argtxt)s):
                return tuple.__new__(cls, (%(argtxt)s)) \n
            @classmethod
            def _make(cls, iterable, new=tuple.__new__, len=len):
                'Make a new %(typename)s object from a sequence or iterable'
                result = new(cls, iterable)
                if len(result) != %(numfields)d:
                    raise TypeError('Expected %(numfields)d arguments, got %%d' %% len(result))
                return result \n
            def __repr__(self):
                return '%(typename)s(%(reprtxt)s)' %% self \n
            def _asdict(t):
                'Return a new dict which maps field names to their values'
                return {%(dicttxt)s} \n
            def _replace(self, **kwds):
                'Return a new %(typename)s object replacing specified fields with new values'
                result = self._make(map(kwds.pop, %(field_names)r, self))
                if kwds:
                    raise ValueError('Got unexpected field names: %%r' %% kwds.keys())
                return result \n
            def __getnewargs__(self):
                return tuple(self) \n\n''' % locals()
        for i, name in enumerate(field_names):
            template += '            %s = property(itemgetter(%d))\n' % (name, i)
        if verbose:
            print template

        # Execute the template string in a temporary namespace and
        # support tracing utilities by setting a value for frame.f_globals['__name__']
        namespace = dict(itemgetter=_itemgetter, __name__='namedtuple_%s' % typename)
        try:
            exec template in namespace
        except SyntaxError, e:
            raise SyntaxError(str(e) + ':\n' + template)
        result = namespace[typename]

        # For pickling to work, the __module__ variable needs to be set to the frame
        # where the named tuple is created.  Bypass this step in enviroments where
        # sys._getframe is not defined (Jython for example).
        if hasattr(_sys, '_getframe'):
            result.__module__ = _sys._getframe(1).f_globals.get('__name__', '__main__')

        return result

#=========================================================
#CustomDict
#=========================================================
#TODO: would like to clean this up a lot more before exposing it

class CustomDict(dict):
    """This is basically a lift of the DictMixin code,
    but inheriting from dict itself, so that object is
    a newstyle class.

    It attempts to provide an easy
    framework for creating custom dict objects with
    arbitrary behavior, by providing useful defaults
    for most of the dictionary methods such that
    only a few methods need to be overidden.

    .. todo::
        * document the layers system, what methods
          are required, may be overridden, and probably shouldn't be.
          currently all of that is in the source code.
    """
    #=========================================================
    #init
    #=========================================================
    def __init__(self, *args, **kwds):
##        #use underlying dict's clear method if __delitem__ isn't overridden
##        #and neither is clear()
##        if (
##            (getattr(self.__delitem__, "im_func", None) == dict.__delitem__)
##            and
##            (getattr(self.clear, "im_func", None) == CustomDict.clear)
##            ):
##            self.clear = self.__raw_clear
        #init object - we pass everything through update() so that
        # custom update / setitem calls get to handle everything.
        dict.__init__(self)
        if args or kwds:
            self.update(*args, **kwds)


    #=========================================================
    #item methods [layer 1]
    #   dict defaults can be used,
    #   but you'll probably want to override them
    #=========================================================

    #def __getitem__(self, key):
    #def __setitem__(self, key, value):
    #def __delitem__(self, key):
    #def __contains__(self, key):

    #=========================================================
    #length methods [layer 2]
    #   either leave them alone,
    #   or overide both of them.
    #=========================================================
    #def __iter__(self):
    #def keys(self):

    #TODO: could auto-detect override of single, and patch

    #=========================================================
    #basic iterators [layer 3]
    #   you can override these one-by-one if your
    #   subclass could do one of them more efficiently,
    #   but the defaults are usually sufficient.
    #   (the dict default methods are shadowed since
    #   these will respect whatever you do to the item methods)
    #=========================================================
    def iteritems(self):
        for k in self:
            yield (k, self[k])

    def items(self):
        return [ (k, self[k]) for k in self ]

    def itervalues(self):
        for k in self:
            yield self[k]

    def values(self):
        return [ self[k] for k in self ]

    def clear(self):
        for key in self.keys():
            del self[key]

    #=========================================================
    #other methods [layer 4]
    #   you may override these one-by-one if like,
    #   but for almost all use-cases, the provided
    #   defaults will allow efficient behavior
    #   using the implementations of the lower layers
    #=========================================================
    def iterkeys(self):
        return self.__iter__()

    def has_key(self, key):
        return self.__contains__(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def setdefault(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            self[key] = default
            return default

    def pop(self, key, *args):
        if len(args) > 1:
            raise TypeError, "pop expected at most 2 arguments, got %d" % (1+len(args),)
        try:
            value = self[key]
        except KeyError:
            if args: return args[0]
            else: raise
        del self[key]
        return value

    def popitem(self):
        try:
            k, v = self.iteritems().next()
        except StopIteration:
            raise KeyError, 'container is empty'
        del self[k]
        return (k, v)

    def update(self, *args, **kwds):
        if args:
            if len (args) > 1:
                raise ValueError, "update expected at most 1 positional argument, got %d" % (len(args),)
            other = args[0]
            # Make progressively weaker assumptions about "other"
            if hasattr(other, 'iteritems'):  # iteritems saves memory and lookups
                for k, v in other.iteritems():
                    self[k] = v
            elif hasattr(other, 'keys'):
                for k in other.keys():
                    self[k] = other[k]
            else:
                for k, v in other:
                    self[k] = v
        if kwds:
            for k,v in kwds.iteritems():
                self[k] = v

##    def __repr__(self):
##        return repr(dict(self.iteritems()))

##    def __cmp__(self, other):
##        if other is None:
##            return 1
##        if isinstance(other, DictMixin):
##            other = dict(other.iteritems())
##        return cmp(dict(self.iteritems()), other)

    def __len__(self):
        return len(self.keys())

    #=========================================================
    #some helpers for use by subclasses
    #=========================================================
    def _raw_get(self, key, value=None):
        "return value of underlying dictionary"
        if value is Undef:
            return dict.__getitem__(self, key)
        else:
            try:
                return dict.__getitem__(self, key)
            except KeyError:
                return value

    def _raw_set(self, key, value):
        "set value of underlying dictionary"
        return dict.__setitem__(self, key, value)

    def _raw_del(self, key):
        "delete value of underlying dictionary"
        return dict.__delitem__(self, key)

    def _raw_clear(self):
        "clear underlying dictionary"
        return dict.clear(self)

    #=========================================================
    #EOC
    #=========================================================

#=========================================================
#ordered dictionary
#=========================================================
class OrderedDict(CustomDict):
    """dictionary that preserves order of keys.

    .. todo::
        * Document this better
        * implement reorder() method
        * compare to python's new ordereddict, implement any missing features
    """
    #=========================================================
    #instance attrs
    #=========================================================
    __keys = None #internal list object storing canonical ordering of keys

    #=========================================================
    #init
    #=========================================================
    def __init__(self, *args, **kwds):
        #TODO: support initial key order from inputs
        self.__keys = [] #list containing key ordering
        CustomDict.__init__(self, *args, **kwds)

    #=========================================================
    #first level
    #=========================================================
    #getitem - we can just use default

    def __setitem__(self, key, value):
        retval = CustomDict.__setitem__(self,key,value)
        if key not in self.__keys:
            self.__keys.append(key)
        return retval

    def __delitem__(self, key):
        retval = CustomDict.__delitem__(self,key)
        if key in self.__keys: #should always be true
            self.__keys.remove(key)
        return retval

    #=========================================================
    #second level
    #=========================================================
    def __iter__(self): return iter(self.__keys)
    def keys(self): return list(self.__keys)

    #=========================================================
    #custom
    #=========================================================
    #TODO: a "reorder" method for rearranging keys

    def insert(self, pos, key, value=Undef):
        """insert a key in a particular position.
        if value is Undef, the key must already
            be present, and will simple be relocated.
            else a keyerror will be throw
        if value is present, key will be added and the value set.
        """
        if value is Undef:
            if key in self.__keys:
                self.__keys.remove(key)
                self.__keys.insert(pos,key)
            else:
                raise KeyError, "key not found: %r" % (key,)
        else:
            if key in self.__keys:
                self.__keys.remove(key)
            self.__keys.insert(pos,key)
            self[key] = value
    #=========================================================
    #EOC
    #=========================================================

#=========================================================
#insensitive dictionary
#=========================================================
#this probably works, just hasn't been tested/used
##class InsensitiveDict(CustomDict):
##    """dictionary that allows only strings for keys, and is case-insensitive-but-preserving"""
##    #CAUTION: this class hasn't been fully tested yet
##
##    #=========================================================
##    #init
##    #=========================================================
##    def __init__(self, *args, **kwds):
##        self.__keys = {} #dict mapping lower-case key to currently preserved key
##        CustomDict.__init__(self, *args, **kwds)
##
##    def normkey(self, key):
##        if not isinstance(key, str):
##            raise ValueError, "key must be a str: %r" % (key,)
##        return key.lower()
##
##    #=========================================================
##    #first level
##    #=========================================================
##    def __getitem__(self, key):
##        nkey = self.normkey(key)
##        if CustomDict.__contains__(self, nkey):
##            return dict.__getitem__(self,nkey)
##        else:
##            raise KeyError, "key not found: %r" % (key,)
##
##    def __setitem__(self, key, value):
##        nkey = self.normkey(key)
##        self.__keys.setdefault(nkey, key)
##        return CustomDict.__setitem__(self,nkey,value)
##
##    def __delitem__(self, key):
##        nkey = self.normkey(key)
##        retval = CustomDict.__delitem__(self,nkey)
##        del self.__keys[nkey]
##        return retval
##
##    def __contains__(self, key):
##        nkey = self.normkey(key)
##        return CustomDict.__contains__(self, nkey)
##
##    #=========================================================
##    #second level
##    #=========================================================
##    def __iter__(self): return self.__keys.itervalues()
##    def keys(self): return self.__keys.values()
##
##    #=========================================================
##    #third level
##    #=========================================================
##    def iteritems(self):
##        for nk, k in self.__keys.iteritems():
##            yield k, CustomDict.__getitem__(self, nk)
##
##    def items(self):
##        return [
##            (k, CustomDict.__getitem__(self, nk))
##            for nk, k in self.__keys.iteritems()
##            ]
##
##    #=========================================================
##    #EOC
##    #=========================================================

#=========================================================
#deprecated - to be removed 2010-04-01
#=========================================================
defined = relocated_function("defined", "bps.undef.defined", removal="2010-04-01")
undefined = relocated_function("undefined", "bps.undef.undefined", removal="2010-04-01")

#=========================================================
#EOF
#=========================================================
