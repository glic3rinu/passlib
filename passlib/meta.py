"""bps.meta - introspection utilities"""
#===================================================
#imports
#===================================================
from __future__ import absolute_import
#core
import os.path
import inspect
from functools import update_wrapper, partial
from logging import getLogger; log = getLogger(__name__)
import time
import sys
from warnings import warn
from weakref import WeakKeyDictionary
import types #python module, NOT bps.types
#needed imports
#legacy imports
from bps.undef import Undef
from bps.error.types import AbstractMethodError

__all__ = [
    #interfaces
    'isseq', 'isnum', 'isstr',

    #introspection & monkeypatching
    'is_overridden',
    'find_attribute',
##    'get_module',
##    'get_module_exports',
    'monkeypatch',
    'monkeypatch_mixin',
    'instrument_super',

    #other decorators
    'abstract_method', 'abstract_property', 'AbstractMethodError',
    'decorate_per_instance',
]

#=========================================================
#interface tests
#=========================================================
#XXX: should these groups be moved into bps.types?
# which place would new users expect them to be located?

#XXX: should we standardize on is_xxx or isxxx; or support both?
# these funcs are so lightweight, isxxx is probably better

NumericTypes = (int, float, long) #XXX: add decimal?
SequenceTypes = (list, tuple, set) #heterogenous sequence types (ie, sequences excluding string)
OrderedTypes = (list, tuple) #heterogenous ordered sequences types
if sys.version >= (3, 0):
    StringTypes = (str,)
    ClassTypes = (type,)
    _classobj = None
else:
    StringTypes = types.StringTypes
    _classobj = types.ClassType
    ClassTypes = (types.ClassType, types.TypeType)

def is_seq(obj):
    "tests if *obj* is a known heterogenous sequence type"
    return isinstance(obj, SequenceTypes)
isseq = is_seq

def is_oseq(obj):
    "tests if *obj* is a known ordered heterogenous sequence"
    return isinstance(obj, OrderedTypes)
isoseq = is_oseq

def is_num(obj):
    "tests if *obj* is a known numeric type"
    return isinstance(obj, NumericTypes)
isnum = is_num

#add is_integral / is_real ?

def is_str(obj):
    "tests if *obj* is a known string type"
    return isinstance(obj, StringTypes)
isstr = is_str

def is_class(obj):
    "test if *obj* is old or new style class object"
    return isinstance(obj, ClassTypes)
isclass = is_class

def is_pair(obj):
    "check if object is an ordered pair"
    return is_oseq(obj) and len(obj) == 2
ispair = is_pair

def is_iter(obj):
    "check if object is an iterator/generator"
    return hasattr(obj,"next") and hasattr(obj,"__iter__")

def hasattrs(obj, include=None, exclude=None):
    "helper for testing if object matches expected protocol by checking for whole sets of attrs"
    return (not include or all(hasattr(obj, attr) for attr in include)) \
        and not (exclude and any(hasattr(obj,attr) for attr in exclude))

#=========================================================
#class inspection
#=========================================================
def is_overridden(attr, owner, parent):
    """check if a method has been shadowed.

    :arg attr:
        the method name to check
    :arg owner:
        the object (instance or class) to check
    :param parent:
        parent class to compare against.
    :returns:
        returns ``True`` if *attr*, as defined by *parent*,
        is overridden by *owner* or any class between it and parent.
        Otherwise, returns ``False``.
    """
    #TODO: this currently only deals with methods, could extend if needed
    #TODO: could make parent default to immediate parent of owner
    new = getattr(owner, attr)
    old = getattr(parent, attr)
    return getattr(new, "im_func", None) is not old.im_func

def find_attribute(owner, target, first=True, required=False):
    """search class hierarchy of *owner* to find which attribute *target*
    is being stored under.

    Given a *target* object, and an *owner* object to search (either the class or an instance),
    try to determine what attribute of the class the property is stored under.
    By default this will return the first attribute the target object is found at.
    If it is not found, ``None`` will be returned.

    This is useful for property constructors which need to introspect
    and find what attribute they have been stored under at runtime (see example below).

    :Parameters:
        owner
            The object which should be scanned for the property.
            This may be an instance or a class.

        target
            The property (or other object such as a function) to search
            through the attrs of the class hierarchy for.

        first : bool
            If set to ``False``, *all* attributes the match
            will be returned as a list. Otherwise only
            the first match will be returned.

        required : bool
            If true, a RuntimeError will be raised if the target cannot be found.

    An example of how to use this in a property class::

        >>> class LazyConstructor(object):
        >>>     def __init__(self, func):
        >>>         self.func = func
        >>>         self.name = None
        >>>     def __get__(self, obj, cls):
        >>>     if obj is None:
        >>>         return self
        >>>     if self.name is None: #cache result for later
        >>>         self.name = find_attribute(cls, self, required=True)
        >>>     assert self.name not in obj.__dict__
        >>>     value = obj.__dict__[self.name] = self.func()
        >>>     #we should never get called again for this object
        >>>     return value

    """
    #resolve instances to their class type if needed
    if not isinstance(owner, ClassTypes):
        owner = type(owner)
    if hasattr(owner, "__mro__"):
        mro = owner.__mro__[:-1] #remove 'object' cause we don't need to search it
    elif hasattr(owner, "__bases__"):
        assert isinstance(owner, types.ClassType)
        mro = inspect.getmro(owner)
    else:
        raise RuntimeError, "unknown object type: %r" % (owner,)
    #traverse class dicts using MRO, bypassing getattr & property code
    if not first:
        out = []
    for cls in mro:
        for k,v in cls.__dict__.iteritems():
            if v is target:
                if first:
                    return k
                else:
                    out.append(k)
    if first:
        log.warning("find_attribute failed: owner=%r target=%r", owner, target)
        if not required:
            return None
    else:
        if out or not required:
            return out
    raise RuntimeError, "object %r does not appear in the class dictionary of %r" % (target, owner)

def get_cls_kwds(cls):
    """Return list of keyword arguments accepted by the specified class's constructor.

    This performs it's job by recursively examining
    the __init__ methods in the specified class and it's bases.

    .. todo::
        Could look for a class attribute such as "__kwds__" or something,
        but should survey if any major projects have set up a de facto standard first.
    """
    kwds = set() #set of kwds we've seen
    self_kwds = set() #set of kwds used by class as 'self' argument (usually just contains 'self')

    #for each class in MRO, read arguments of it's init method
    for c in cls.__mro__:
        f = c.__dict__.get("__init__")
        if not isinstance(f, types.FunctionType):
            continue
        #only if it's a function object do we check
        #list of names, and **kwds slot.
        names, _, varkwds, _ = inspect.getargspec(f)
        if not names:
            continue
        self_name = names[0]
        if self_name not in kwds:
            #only store a function's "self" argument
            #if that kwd wasn't being shadowed by a higher-level
            #__init__ method... that way, when we remove all self-names
            #below, we don't remove shadowed self-names
            self_kwds.add(self_name)
        kwds.update(names)
        if not varkwds:
            #if it doesn't support varkwds,
            #assume we don't need to go higher up class hierarchy.
            break
    #remove all kwds being used for "self"
    kwds.difference_update(self_kwds)
    return list(kwds)

##def get_func_kwds(func):
##    """Return list of legal kwd args for the given function"""
##    return inspect.getargspec(func)[0]

def func_accepts_key(func, key):
    """test if function accepts a given kwd parameter.

    :arg func:
        function or class object.
        (if a class, the __init__ method is examined).
    :arg key:
        the key (or list of keys) which must be accepted.

    :returns:
        ``True`` if the keyword is accepted, else ``False``.
    """
    #check this is a class
    method = False
    if isclass(func):
        #TODO: make use get_cls_kwds, but need to make sure nothing
        #relies on this function's **kwds behavior.
##        return key in get_cls_kwds(func)
        func = func.__init__.im_func
        method = True
    elif isinstance(func, partial):
        while isinstance(func, partial):
            func = func.func
    args, varargs, varkw, defaults = inspect.getargspec(func)
    if bool(varkw):
        #XXX: is there some de facto protocol to check for this?
        #  for now, just assume it accepts everything
        return True
    if method:
        args = args[1:]
    if is_seq(key):
        return all(k in args for k in key)
    else:
        return key in args

#=========================================================
#module inspection
#=========================================================
def get_module(name):
    "return module by absolute name"
    return __import__(name, None, None, ['dummy'], 0)

def get_module_exports(module):
    """return list of attrs exported from module by default.

    This is the same as ``list(module.__all__)`` IF the module defined that variable.
    Otherwise, this returns a list approximating the default python behavior.
    """
    if is_str(module):
        module = get_module(module)
    try:
        return list(module.__all__)
    except AttributeError:
        return [n for n in dir(module) if not n.startswith("_")]

_script_exts = set([".py", ".pyc", ".pyo"])
if os.name == "posix":
    _cmod_exts = set([".so"])
elif os.name == "nt":
    _cmod_exts = set([".pyd"])
    _script_exts.add(".pyw")
else:
    #TODO: what do other os's use?
    _cmod_exts = set()

def lookup_module(path, name=False):
    """find loaded module given path it came from.

    given a path to a .py file or a package directory,
    this attempts to find the loaded module that was derived
    from the file. this attempts to be the reverse of ``module.__path``,
    using inspection of ``sys.modules``. it's not perfect,
    but there's no analog in the inspect module.

    :arg path:
        path to python file or package directory.

    :param name:
        optionally this function can return the full name
        of the module, rather than the module itself.

    :returns:
        name or module instance (see name flag) if
        a loaded module was found which matches path.

        if no corresponding module has been loaded yet,
        or the path does not correspond to a python module,
        returns ``None``.
    """
    global _script_exts, _cmod_exts
    #FIXME: gotta be a better way to figure this info out,
    #inspect doesn't seem to have the right func for the job.

    if os.path.isfile(path):
        #figure out what type of file this is
        root, ext = os.path.splitext(path)
        root = os.path.abspath(root)
        if ext in _script_exts:
            #if it's a script, search for all known script extensions
            targets = set(root + ext for ext in _script_exts)
        elif ext in _cmod_exts:
            #if it's a compiled module, search for all known compiled module extensions
            targets = set(root + ext for ext in _cmod_exts)
        else:
            #no idea what to do
            log.warning("lookup_module(): path has unknown extension: %r", path)
            return None
        test = targets.__contains__
    elif os.path.isdir(path):
        #assume it's a package dir, and set root to be the init file inside the directory
        root = os.path.abspath(os.path.join(path, "__init__"))
        targets = set(root + ext for ext in _script_exts)
        test = targets.__contains__
    elif not os.path.exists(path):
        log.warning("lookup_module(): path doesn't exist: %r", path)
        return None
    else:
        log.warning("lookup_module(): unsupported file type: %r", path)
        return None

    #try and find target in loaded modules
    #NOTE: would like to use iteritems(), but dict changes size on us :(
    #FIXME: there may be multiple matches (eg: posixpath and os.path),
    #   and this just returns the first one it finds. we could do better,
    #   say returning all of them if requested, or preferring one
    #   whose name matches the pathname (ie, original over aliases)
    for mod_name, module in sys.modules.items():
        mod_file = getattr(module, "__file__", None)
        #XXX: do we need to run mod_path through abspath ?
        if mod_file and test(mod_file):
            log.debug("lookup_module(): resolved path to module: %r => %r", path, mod_name)
            if name:
                return mod_name
            else:
                return module

    #give up
    log.warning("lookup_module(): can't resolve path to loaded module: %r",  path)
    return None

#=========================================================
#class manipulation
#=========================================================
##def get_private_attr(obj, attr, default=Undef, name=Undef):
##    if name is Undef:
##        if isinstance(obj,type):
##            name = obj.__name__
##        else:
##            name = obj.__class__.__name__
##    if name[0] == "_":
##        attr = "%s__%s" % (name,attr)
##    else:
##        astr = "_%s__%s" % (name,attr)
##    if default is Undef:
##        return getattr(obj,astr)
##    else:
##        return getattr(obj,astr,default)
##
##def set_private_attr(obj, attr, value, name=Undef):
##    if name is Undef:
##        if isinstance(obj,type):
##            name = obj.__name__
##        else:
##            name = obj.__class__.__name__
##    if name[0] == "_":
##        attr = "%s__%s" % (name,attr)
##    else:
##        astr = "_%s__%s" % (name,attr)
##    return getattr(obj,astr,value)

#=========================================================
#monkeypatching
#=========================================================
def monkeypatch(target, attr=None, wrap=False, clobber=True):
    """Decorator to aid in monkeypatching.

    The decorated function will be patched into `target`
    under the attribute same name as the wrapped function.
    The attribute can be overriden via the `attr` kwd.

    This was posted by GVR somewhere on the internet.
    *It's not just evil, it's easy-to-use evil!*
    Pretend this isn't here unless you really need it.

    :Parameters:
        target
            the target object which we're replacing an attribute of
        attr
            [optional]
            attribute to be replaced. if not specified,
            taken from the name of the function this decorates.
        wrap
            if true, original value will be passed in as first positional argument,
            if false (the default), it will be discarded.
        clobber
            By default, this function will overwrite any existing
            value stored in the target attribute. If this is set
            to ``False``, an error will be raised if the attribute
            contains data.

    Usage::

        >>> from bps.meta import monkeypatch
        >>> #say we have a class...
        >>> class MyClass(object):
        >>>     def a(self, x=10):
        >>>         return x+1
        >>> m = MyClass()
        >>> m.a()
            11
        >>> #and later we want to patch method 'a'
        >>> @monkeypatch(MyClass)
        >>> def a(self, x=10):
            return x*2
        >>> m.a()
            20
        >>> #say we want to patch it (again) while calling previous copy
        >>> @monkeypatch(MyClass, wrap=True)
        >>> def a(orig, self, x=10):
        >>>     return orig(self,x)+5
        >>> m.a()
            25
    """
    def builder(func):
        name = attr or func.__name__
        if not clobber and getattr(target, name, None):
            raise AttributeError, "monkeypatch target already exists: target=%r attr=%r" % (target, name)
        if wrap:
            orig = getattr(target, name)
            if isinstance(target, type):
                #can't use partial since it's going in a class
                def wrapper(*a, **k):
                    return func(orig, *a, **k)
                update_wrapper(wrapper, orig)
                setattr(target, name, wrapper)
                return
            func = partial(func, orig)
        setattr(target, name, func)
    return builder

def monkeypatch_mixin(target, first=False):
    """Modify a class by appending another class to it's list of bases.
    This is mainly useful for monkeypatching a mixin class.

    :arg target: class to be patched
    :param first: if mixin should be placed at beginning of bases, not end

    Usage::

        >>> from bps.meta import monkeypatch_mixin
        >>> #say you have a class...
        >>> class MyClass(object):
        >>>     pass
        >>> MyClass.__bases__
            (object,)
        >>> #and somewhere else, you want to patch one in
        >>> class OtherClass(object):
        >>>     pass
        >>> monkeypatch_mixin(MyClass)(OtherClass)
        >>> MyClass.__bases__
            (object,OtherClass)

    .. note::
        If target is subclass of mixin,
        this function will silently do nothing.
    """
    def builder(mixin):
        #check if it's already merged in
        if issubclass(target, mixin):
            return mixin

        #check if we can't due to circular ref
        if issubclass(mixin, target):
            raise TypeError, "mixin %r cannot derive from target %r" % (mixin, target)

        #TODO: figure out greatest common ancestor,
        # and (if it's in target.__bases__, just replace it w/ mixin)
        if first:
            target.__bases__ = (mixin,) + target.__bases__
        else:
            target.__bases__ += (mixin,)

        return mixin

    return builder

#=========================================================
#source code inspection
#=========================================================
_cache = {} #FIXME: make weakkeyref?
def get_class_range(cls):
    """given a class, returns a tuple of ``(path,first,last)``, defined as follows:

        path
            filepath that class was defined in (may not exist, just used for identification)

        first
            smallest firstlineno of any method defined in the class

        last
            largest firstlineno of any method defined in the class

    .. note::
        This function is mainly used by :func:`init_super_property`.
        It may have some strange behaviors related to that use-case,
        which may need to be cleared up when other use-cases are found.
    """
    global _cache
    if cls in _cache:
        return _cache[cls]

    #first, figure out path of class
    path = getattr(sys.modules.get(cls.__module__), "__file__", None)
    if path is None:
        #builtin, return fake info
        log.debug("get_class_range(%r): <builtin>", cls)
        return None, None, None
    npath = _get_base_path(path)

    #find largest & smallest firstlineno of all of class's methods
    #which are defined in class path
    first = None
    last = None
    for k, v in cls.__dict__.iteritems():
        if hasattr(v, "__get__") and not isinstance(v, (MultipleSuperProperty, SingleSuperProperty)):
            v = v.__get__(None, cls)
        if hasattr(v, "im_func"):
            c = v.im_func.func_code
        elif hasattr(v, "func_code"):
            c = v.func_code
        else:
            continue
        if _get_base_path(c.co_filename) != npath:
            continue
        if first is None or c.co_firstlineno < first:
            first = c.co_firstlineno
        if last is None or c.co_firstlineno > last:
            last = c.co_firstlineno
    log.debug("get_class_range(%r): path=%r start=%r end=%r", cls, path, first, last)
    return path, first, last

def _get_base_path(path):
    """helper func used to normalize filepaths
    returned by getfile(cls) and func.co_filename paths"
    """
    return os.path.splitext(os.path.abspath(path))[0]

#=========================================================
#super descriptor
#=========================================================
class SingleSuperProperty(object):
    """helper for init_super_property() which provides
    a __super attribute for a single class."""
    __thisclass__ = None #class super() should resolve relative to

    def __init__(self, cls):
        self.__thisclass__ = cls

    def __get__(self, obj, cls):
        if obj is None: obj=cls
        return super(self.__thisclass__, obj)

    def __delete__(self, obj):
        raise ValueError, "__super attributes are read-only"

    def __set__(self, obj, value):
        raise ValueError, "__super attributes are read-only"

class MultipleSuperProperty(object):
    """helper for init_super_property() which provides
    a __super attribute which uses different __thisclass__ values
    depending on which class accesses the attribute.

    it takes as input the class name it's managing __$NAME__super for,
    and (via stack inspection), picks the class with that name which seems
    to contain the calling code. the algorithm works reliably for most cases,
    including multiple classes in the same file, sharing the same name.

    however, situtations such as explicitly accessing the private namespace
    from code which lies outside the class are not handled, as there seems
    to be no "best" behavior in such a situation. this case is pretty rare,
    however.

    another drawback is this is a rather complicated and expensive algorithm.
    luckily, init_super_property() only uses this property
    when multiple classes are sharing the same private namespace.
    """
    name = None #: name of classes whose shared namespace this manages __super for

    def __init__(self, name):
        self.name = name

    def __get__(self, obj, cls):
        #get list of all parent classes with the desired name
        name = self.name
        choices = [
            c for c in cls.__mro__
            if c.__name__ == name
            ]
        if len(choices) == 0:
            raise RuntimeError, "no classes named %r found in mro of %r" % (name, cls)
        elif len(choices) == 1:
            thisclass = choices[0]
        else:
            #remove candidates with different module path
            frame = inspect.currentframe(1)
            path = frame.f_globals.get("__file__")
            choices = [
                c for c in choices if
                getattr(sys.modules.get(c.__module__), "__file__", None) == path
                ]
            if len(choices) == 0:
                raise RuntimeError, "no classes named %r from file %r found in mro of %r" % (name, path, cls)
            elif len(choices) == 1:
                thisclass = choices[0]
            else:
                #now the unreliable part:
                #try and guess which class defined the frame's code,
                #based on the line numbers used by the candidates's methods.
                target = frame.f_code.co_firstlineno
                def match_class(cls):
                    _path, first, last = get_class_range(cls)
                    assert _path == path, "class unexpected changed path"
                    if first is None:
                        return True #XXX: discard cls if we have no info?
                    return first <= target and last >= target
                choices = [
                    c for c in choices
                    if match_class(c)
                    ]
                if len(choices) == 0:
                    raise RuntimeError, "no classes named %r from file %r including line %r found in mro of %r" % (name, path, target, cls)
                elif len(choices) == 1:
                    thisclass = choices[0]
                else:
                    #FIXME: what do we do now?
                    #multiple classes in same file, seemingly both including target lineno.
                    #kinda weird.
                    log.warning("multiple matches for thisclass: name=%r path=%r line=%r choices=%r", name, path, target, choices)
                    #only case i can think of where this could occur is two nested classes w/ same name,
                    #so for now, we pick the one w/ largest starting lineno
                    #FIXME: what about case where one of choices had first=None?
                    thisclass = choices[0]
                    first = get_class_range(thisclass)[1]
                    for choice in choices[1:]:
                        v = get_class_range(choice)[1]
                        if v > first:
                            thisclass = choice
                            first = v

        #ok, thisclass has been chosen, so generate super()
        if obj is None:
            obj = cls
        return super(thisclass, obj)

    def __delete__(self, obj, cls):
        raise ValueError, "__super attributes are read-only"

    def __set__(self, obj, value):
        raise ValueError, "__super attributes are read-only"

def instrument_super(cls, optimize=True):
    """Sets up a ``__super`` descriptor in the private namespace of the specified class.

    This function should be able to instrument any class which inherits from :class:`object`.

    :param optimize:
        Setting this to ``False`` disables the fast __super implementation,
        when normally, the choice will be autodetected.
        This is mainly a helper for when autodetection fails.

    Usage Example::

        >>> class MyClass(object):
        >>>     def __init__(self, **kwds):
        >>>         self.__super.__init__(**kwds)
        >>> init_super_property(MyClass) #calling this makes self.__super work, above.

    .. note::
        This is not needed if you are inheriting from :class:`bps.types.BaseClass`,
        as that class takes care of calling this function for all subclasses.

    .. note::
        Since this method of automatic ``super()`` support relies on the class's
        private namespace being unique, two classes in the mro with the same
        name will have to share a single attribute. The code behind this function
        attempts to compensate for this case, but occasionally may get confused.

    .. warning::
        This function assumes it will be called on a parent
        class before it's child classes, or never called for the parent classes.
        The remaining case (where it's called to instrument a parent class
        AFTER it's been called on a child class) messes up the autodetection algorithm.

    """
    attr = "_%s__super" % cls.__name__.lstrip("_")
    #check to see if another class using the same namespace already has __super defined...
    #if so, we have to use the less desirable _MultipleSuperProperty()
    #XXX: this check fails to detect if parent __super is initialized AFTER child __super
    if not optimize or (hasattr(cls, attr) and attr not in cls.__dict__):
        value = MultipleSuperProperty(cls.__name__)
    else:
        value = SingleSuperProperty(cls)
    #set new __super property
    setattr(cls, attr, value)

#=========================================================
#other decorators
#=========================================================
def abstract_method(func):
    """Method decorator which indicates this is a placeholder method which
    should be overridden by subclass.

    This is mainly useful when defining framework classes that must be
    subclassed before they will be useful.

    If called directly, this method will raise an :exc:`AbstractMethodError`
    (which is a subclass of :exc:`NotImplementedError`).
    """
    msg = "object %(self)r method %(name)r is abstract, and cannot be called"
    def wrapper(self, *args, **kwds):
        text = msg % dict(self=self, name=wrapper.__name__)
        raise AbstractMethodError(text)
    update_wrapper(wrapper, func)
    return wrapper

abstractmethod = abstract_method #for compat with python syntax

class class_property(object):
    """Decorator which acts like a combination of classmethod+property (limited to read-only)"""

    def __init__(self, func):
        self.im_func = func

    def __get__(self, obj, cls):
        return self.im_func(cls)

class fallback_property(object):
    """Decorator which acts like a combination of classmethod+fallback_method (limited to read-only)"""
    def __init__(self, func):
        self.im_func = func

    def __get__(self, obj, cls):
        return self.im_func(obj, cls)

class fallback_method(object):
    """Decorator which lets method act like a class OR instance method.

    function will be called with prototype ``func(obj,cls,*args,**kwds)``,
    where ``obj`` is ``None`` if invoked from a class.
    """
    def __init__(self, func):
        self.im_func = func
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__
        self._cache = WeakKeyDictionary()

    def _bind_func(self, obj, cls):
        func = self.im_func
        def method(*a, **k):
            return func(obj, cls, *a, **k)
        update_wrapper(method, func)
        ##if obj is None:
        ##    method.__repr__ = lambda : "<fallback_method %s.%s; bound to class>" % (cls.__name__, func.__name__)
        ##else:
        ##    method.__repr__ = lambda : "<fallback_method %s.%s; bound to instance %r>" % (cls.__name__, func.__name__, obj)
        method.__name__ = "<fallback_method_wrapper>" #NOTE: would like to implement repr() above, but can't.

        method.im_func = func
        method.im_self = obj
        method.im_class = cls
        return method

    def __get__(self, obj, cls):
        if obj is not None:
            #create method and store in object, so next access calls it directly (shadowing this descriptor)
            method = self._bind_func(obj, cls)
            setattr(obj, self.__name__, method)
            return method

        #old style classes can't do weakrefs, so can't cache our result
        elif _classobj and isinstance(cls, _classobj):
            return self._bind_func(None, cls)

        #can't shadow ourselves in subclass, so using internal cache for methods
        else:
            cache = self._cache
            method = cache.get(cls)
            if method is None:
                method = cache[cls] = self._bind_func(None, cls)
            return method

def abstract_property(name, doc=None):
    """Property constructor which indicates this is a placeholder attribute which
    should be overridden by subclass.

    This is mainly useful when defining framework classes that must be
    subclassed before they will be useful.

    If read or written from an instance, this method will raise an :exc:`AbstractMethodError`
    (which is a subclass of :exc:`NotImplementedError`).
    """
    if not name:
        raise ValueError, "property name must be specified"
    if not doc:
        doc = "abstract property %r" % (name,)
    msg = "object %(self)r attribute %(name)r is abstract, and must be implemented by a subclass"
    def helper(self, *args, **kwds):
        text = msg % dict(self=self, name=name)
        raise AbstractMethodError(text)
    return property(helper, helper, helper, doc)

def decorate_per_instance(decorator, attr=True, bind="function"):
    """creates a decorator to be applied per-instance to the instance method.

    .. note::
        What this function does may be considered "slightly deep magic",
        at least by those who don't normally traffic in such things.
        It performs some python trickery which (if it's not the trickery you need)
        can safely be ignored.

    This is a decorator-decorator: that is, instead of wrapping an
    already decorated function, it's designed to wrap the decorator itself.

    What is returned is in fact a descriptor object,
    which lazily uses the provided decorator to wrap
    the function on a per-instance basis, rather than
    wrap it a single time for underlying function,
    which is what a unmodified decorator does.

    This allows decorators such as :func:`cached_method` have
    separate scopes for each instance, instead of one shared
    scope for the entire function (such as :func:`cached_function`).

    :param decorator:
        This should be a decorator function. It will be called
        for every instance of the class whose method we are decorating.

    :param attr:
        If attr is ``True`` (the default), the name of
        the decorated function will be assumed to be the final name
        of the attribute. If attr is ``None``, an attempt
        will be made to determine the attr at runtime.
        Otherwise, attr should be a string which will override
        the assumed attr.

    :param bind:
        This controls how the decorator will be attached to the instance.
        There are currently two possible values:

            ``function``
                The default behavior:

                The decorator will be passed the underlying function,
                and it's return value passed to python to create the bound method.
                This mode has the following properties:

                * The local scope of the decorator will be per-instance,
                  not per function. This is what distinguishes this meta decorator
                  from simply decorating the original function directly.

                * If your decorator stores any state in ``func.__dict__``,
                  it will have to share that dict between all object instances.
                  If this is not desirable, consider using ``method`` mode, below.

                * Like a normal function, *self* will always be the first argument
                  when your decorated function is called.

            ``method``
                The decorator will be passed a bound instance method
                instead of the original function, and it's return value
                will be returned as if it were the desired method.
                This has the following properties:

                * The decorator scope will still be per-instance like function mode.

                * ``func.__dict__`` will unique per instance, since the function
                  provided will in fact be a instancemethod object that is unique
                  per instance, as opposed to function mode.

                * Since this mode occurs after *self* has been bound into the method,
                  *self* will NOT be present as the first argument in your decorator
                  (though it can be accessed via the instancemethod object's im_self).

    :returns:
        This returns a decorator which
        (when passed a function), will return
        an :class:`instance_decorating_descriptor` object
        that will lazyily bind the method on a per-instance
        basis.

    A usage example::
        >>> from bps.cache import cached_function
        >>> from bps.meta import decorate_per_instance
        >>> class MyClass(object):
        >>>     #this is essentially how cached_method() is implemented...
        >>>     @decorate_per_instance(cached_function(args=1))
        >>>     def myfunc(self, value):
        >>>         return value*2

    .. caution::

        The current implementation of this function violates normal decorator
        behavior, because the result of it's constructor is not a callable function,
        but a descriptor object. Because of this, should wrapping the topmost (outermost)
        decorator applied to a function, since most decorators will not be
        able to handle a descriptor object.
    """
    def instance_decorator(func):
        return instance_decorating_descriptor(func, decorator, attr=attr, bind=bind)
    return instance_decorator

class instance_decorating_descriptor(object):
    """property which decorates methods on a per-instance basis.

    this is the backend for :func:`decorate_per_instance`,
    see that function for details.
    """
    def __init__(self, func, decorator, attr=True, bind="function"):
        assert func
        self.func = func
        if attr is True:
            self.attr = func.__name__
        else:
            self.attr = attr #none or a string
        # we could also clone func's docstring / other things update_wrapper does
        assert decorator
        self.decorator = decorator
        if bind == "function":
            self.create = self.create_function
        elif bind == "method":
            self.create = self.create_method
        else:
            raise ValueError, "unknown bind mode: %r" % (bind,)

    create = None #filled in by init

    def create_function(self, obj, cls):
        "create() implementation using func mode binding"
        func = self.decorator(self.func)
        return instancemethod(func, obj, cls)

    def create_method(self, obj, cls):
        "create() implementation using meth mode binding"
        meth = instancemethod(self.func, obj, cls)
        return self.decorator(meth)

    def __get__(self, obj, cls):
        #take first opportunity to figure out what attribute we're stored in
        if self.attr is None:
            self.attr = find_attribute(cls, self, required=True)
        #deal with class-level access
        if obj is None:
            #XXX: could return a decorated but unbound instance
            #XXX: could do some clever alternate attribute storage for class methods
            return self
        #create decorated method, and put it in object's dictionary
        #   to shadow this descriptor, so we won't get called again
        wrapped_method = obj.__dict__[self.attr] = self.create(obj, cls)
        return wrapped_method

#hack to get function which creates method instances.
#instance_decorating_descriptor was chosen just because it was there,
#this type can be gonna from any method.
instancemethod = type(instance_decorating_descriptor.__get__)

#=========================================================
#functional stuff
#=========================================================
class Params(object):
    """object which represents set of args and kwds.

    Like partial() but without the function.

    The args attribute will contain the args tuple.
    The kwds attribute will contains the kwds dict.
    """

    @classmethod
    def normalize(cls, value):
        "given tuple, dict, or Params object, return a Params object"
        if hasattr(value, "args") and hasattr(value, "kwds"):
            #assume it's already a Params objs
            return value
        elif hasattr(value, "keys"):
            #assume it's a dict
            return cls(**value)
        #XXX: if is_str, call parse?
        else:
            #assume it's a sequence / iterable of positional args
            return cls(*value)

    @classmethod
    def parse(cls, source, kwds=True, scope=None):
        """parse params string, returning Params object.

        :arg source: the source string to parse
        :arg kwds: whether kwd arguments should be accepted (defaults to True)
        :param scope: optional dictionary to use as global scope when evaluating string.

        :returns:
            Params object containing the parsed args and kwds.

        :raises ValueError: if string can't be parsed into Params.

        Usage Example::

            >>> from bps.meta import Params
            >>> x = Params.parse("1,2,'a',t=5")
            >>> x
            Params(1,2,'a',t=5)
            >>> x.args
            (1, 2)
            >>> x.kwds
            { 't': 5 }

        .. warning::
            This currently uses 'eval', so it shouldn't be considered secure.
            In the future, a simpler parser may be written for safety.
        """
        assert is_str(source), "expected string: %r" % (source,)
        if not source.strip():
            return cls()
        if kwds:
            grab = cls
        else:
            def grab(*a):
                return cls(*a)
        if scope:
            g = scope.copy()
        else:
            g = {}
        g['__grab'] = grab
        try: #assume it's already parenthesized
            result = eval("__grab " + source, g)
            if isinstance(result, cls):
                return result
            #else probably had format of "(1,2),3", so wrong value was returned.
        except SyntaxError:
            pass
        #try wrapping with parens
        try:
            result = eval("__grab (" + source + ")", g)
        except SyntaxError:
            raise ValueError, "bad params string: %r" % (source,)
        if isinstance(result, cls):
           return result
        raise ValueError, "bad params string: %r" % (source,)

    def __init__(self, *args, **kwds):
        "create new params object from args"
        self.args = list(args)
        self.kwds = kwds

    def __getitem__(self, key):
        if isinstance(key, int):
            #it's an argument
            return self.args[key]
        else:
            #it's a keyword
            return self.kwds[key]

    #XXX: could do a get() method, __contains__ method, etc
    #XXX: could have __iter__ yield the ints then kwds for use with __getitem__

    def append_modified(self, kwds, default=None):
        "append all specified kwds, but only if value doesn't match default"
        target = self.kwds
        for k,v in kwds.iteritems():
            if v != default:
                target[k] = v

    def append(self, *args, **kwds):
        "append positional parameters, update kwd parameters"
        if args:
            self.args.extend(args)
        if kwds:
            self.kwds.update(kwds)

    def insert(self, pos, *args, **kwds):
        "insert positional parameters, update kwd parameters"
        if args:
            self.args[pos:pos] = args
        if kwds:
            self.kwds.update(kwds)

##    def apply(self, func):
##        return func(*self.args, **self.kwds)

    def clone(self, *args, **kwds):
        "create new params object with args appended to existing args"
        other = Params(*self.args, **self.kwds)
        if args:
            other.args.extend(args)
        if kwds:
            other.kwds.update(kwds)
        return other

    def clear(self):
        del self.args[:]
        self.kwds.clear()

    def render(self, offset=0):
        """render parenthesized parameters.

        ``Params.parse(p.render())`` should always return
        a params object equal to the one you started with.

        ``p.render(1)`` is useful for method arguments,
        when you want to exclude the first argument
        from being displayed.
        """
        txt = ''
        for a in self.args[offset:]:
            txt += "%r, " % (a,)
        kwds = self.kwds
        for k in sorted(kwds):
            txt += "%s=%r, " % (k, kwds[k])
        if txt.endswith(", "):
            txt = txt[:-2]
        return txt

    def render_class(self, class_):
        "render a nice repr for the class using the current parameters"
        if not hasattr(class_,"__bases__"): #allow obj to be passed in for convience
            class_ = class_.__class__
        return "%s.%s(%s)" % (class_.__module__,class_.__name__, self)

    def __str__(self):
        return self.render()

    def __repr__(self):
        return "Params(%s)" % self.render()

    def __eq__(self, other):
        if hasattr(other, "args") and hasattr(other, "kwds"):
            return self.args == other.args and self.kwds == other.kwds
##        if is_oseq(other) and not self.kwds:
##            return self.args == other
##        if isinstance(other, dict) and not self.args:
##            return self.kwds == other
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

#=========================================================
#
#=========================================================
