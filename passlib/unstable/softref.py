"""
soft reference implementation

this module implements something similar to Java's soft references.
these are normal python references, but use reference count introspection
to remove the reference only no other references to the final object
are left, AND the object has not been used in a long enough time
to warrant removing the object.

this is mainly useful when maintaining a cache of objects
which can be regenerated, but only through a (cpu) costly process.
it's generally useful to keep such objects around in a cache,
in case they are needed again, but for memory reasons,
long running processes will generally want to free unused
objects up after a time.

this class provides ``softref()`` which provides access-time tracking,
allowing the reference to be freed up after it's remained unused
for an (application specified) amount of time.

it also contains platform-specific code for detecting low memory conditions,
and freeing up softrefs more aggressively in this case,
in the hopes of staving off out-of-memory conditions.
"""
#=================================================================================
#imports
#=================================================================================
from __future__ import with_statement
#core
import logging
import sys
import threading
from itertools import count as itercount
from time import time as cur_time
import logging; log = logging.getLogger(__name__)
import UserDict
from weakref import ref as make_weakref
from warnings import warn
#site
#pkg
#local
log = logging.getLogger(__name__)
__all__ = [
    #main entry point
    "softref",

    #collector control & configuration
    "collect", "enable", "disable", "is_enabled",
    "get_config", "set_config",

    #introspection
    "get_softref_count",
    "get_softrefs",

    #other helpers
    'SoftValueDict',
##    'KeyedSoftRef',
#   'get_memory_usage',
]

#=================================================================================
#platform specific code for detecting memory levels
#=================================================================================

#NOTE: this is mainly used a helper for the collector to detect low memory conditions.

if sys.platform == "linux2":
    #use /proc/meminfo
    import re

    _memtotal_re = re.compile("^MemTotal:\s+(\d+)\s*kb$", re.I|re.M)
    _memfree_re = re.compile("^MemFree:\s+(\d+)\s*kb$", re.I|re.M)
    _buffers_re = re.compile("^Buffers:\s+(\d+)\s*kb$", re.I|re.M)
    _cached_re = re.compile("^Cached:\s+(\d+)\s*kb$", re.I|re.M)

    def get_memory_usage():
        try:
            with file("/proc/meminfo") as fh:
                data = fh.read()
            memtotal = int(_memtotal_re.search(data).group(1))
            memfree = int(_memfree_re.search(data).group(1))
            buffers = int(_buffers_re.search(data).group(1))
            cached = int(_cached_re.search(data).group(1))
            avail = memfree + buffers + cached
            assert 0 <= avail <= memtotal
            return memtotal, avail
        except:
            #this is a sign something has gone wrong :|
            log.error("error reading /proc/meminfo", exc_info=True)
            return (-1, -1)

elif sys.platform == "win32":
    #implementation taken from http://code.activestate.com/recipes/511491/
    #TODO: check if this will work with cygwin platform
    import ctypes
    kernel32 = ctypes.windll.kernel32
    c_ulong = ctypes.c_ulong
    class MEMORYSTATUS(ctypes.Structure):
        _fields_ = [
            ('dwLength', c_ulong),
            ('dwMemoryLoad', c_ulong),
            ('dwTotalPhys', c_ulong),
            ('dwAvailPhys', c_ulong),
            ('dwTotalPageFile', c_ulong),
            ('dwAvailPageFile', c_ulong),
            ('dwTotalVirtual', c_ulong),
            ('dwAvailVirtual', c_ulong)
        ]
    def get_memory_usage():
        memoryStatus = MEMORYSTATUS()
        memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUS)
        kernel32.GlobalMemoryStatus(ctypes.byref(memoryStatus))
        #XXX: does availphy correspond properly to linux's free-buffers-cache ?
        return (memoryStatus.dwTotalPhys//1024, memoryStatus.dwAvailPhys//1024)
else:
    #TODO: would like to support more platforms (esp OS X)
    warn("disabled low memory detection, not implemented for " + sys.platform + " platform")
    def get_memory_usage():
        return (-1,-1)

get_memory_usage.__doc__ = """return memory usage

Return current memory usage as tuple
``(total physical memory, available physical memory)``.

All measurments in kilobytes.

Available physical memory counts
os buffers & cache as "available",
where possible for the implementation.

Currently supports linux & win32 platforms,
if run on other platforms, will return
tuple where all values are -1.

If an error occurs on a supported platform,
it will be logged, and a tuple of -1 values will be returned.
"""

#=================================================================================
#soft ref collector - implemented as singleton of private class
#=================================================================================

#log used by collector
clog = logging.getLogger(__name__ + ".collector")

#NOTE: design of this module attempts to put as much work in the collector,
# and as little work in the creation & access of the softrefs,
# since the collector is designed to run in another thread anyways.

class _SoftRefCollector(object):
    """tracks softref objects, handles collecting them when needed"""
    #=================================================================================
    #instance attrs
    #=================================================================================

    #--------------------------------------------------------------------
    #configuration
    #--------------------------------------------------------------------
    default_min_age = 600 #default delay from last access time before a softref can be released
    default_max_age = -1 #default delay from last access time before softref will be released even w/o lowmem condition

    collect_frequency = 300 #how often collector should run

    lowmem_abs = 25 * 1024 #lowmem level in kilobytes
    lowmem_pct = .05 #lowmem level as % of total mem
        #low memory is calculated as max(lowmem_abs, physmem * lowmem_pct)
        #this way there's a floor to the lowmem level for low memory systems (eg <512mb),
        #but it scales so lowmem doesn't get hit as often for systems with more memory (eg 4gb)
        #values may need tuning

    #--------------------------------------------------------------------
    #softref state
    #--------------------------------------------------------------------
    targetmap = None #map of id(target) -> [ weakref(softref(target)) ... ]
        #since id will only be re-used once target is dereferenced,
        #and that won't happen as long as softrefs exist,
        #ids should never conflict
    last_collect = 0 #timestamp of last time collect() ran

    #--------------------------------------------------------------------
    #threading
    #--------------------------------------------------------------------
    lock = None #threading lock for instance state
    thread = None #thread collector uses to run in the background
    thread_stop = None #Event used to signal collector thread that it should halt

    #=================================================================================
    #init
    #=================================================================================
    def __init__(self):
        self.targetmap = {}
        self.lock = threading.Lock() #lock for changes
            #XXX: if softref's onrelease tried to create a new softref,
            # it'll block on this lock.. in that case, this should be made to an RLock.
            # if this happens, could either do it permanently, or make an use_rlock() method
        self.thread_stop = threading.Event()

    #=================================================================================
    #softref interface
    #=================================================================================
    def add(self, sref):
        "add a new softref instance"
        #NOTE: instances *must* be compatible with softref type,
        # namely its' _target _atime min_age attrs

        #TODO: some target types (eg: int, str, bool, None) should never have softref expire,
        # and we shouldn't even bother tracking them. should find nice way to have fallback in that case.
        # bucket system would be good, could just never add them to initial bucket.

        target_id = id(sref._target)
        sref_wr = make_weakref(sref)
        targetmap = self.targetmap
        with self.lock:
            srlist = targetmap.get(target_id)
            if srlist is None:
                targetmap[target_id] = [ sref_wr ]
            else:
                srlist.append(sref_wr)

    #=================================================================================
    #introspection
    #=================================================================================
    @property
    def next_collect(self):
        "time next collection is scheduled"
        return self.last_collect + self.collect_frequency

    def count(self, target):
        with self.lock:
            srlist = self.targetmap.get(id(target))
            count = 0
            if srlist:
                for sref_wr in srlist:
                    if sref_wr():
                        count += 1
            return count

    def refs(self, target):
        with self.lock:
            srlist = self.targetmap.get(id(target))
            out = []
            if srlist:
                for sref_wr in srlist:
                    sref = sref_wr()
                    if sref:
                        out.append(sref)
            return out

    #=================================================================================
    #collector
    #=================================================================================
    def collect(self):
        #TODO: rework this scan into using generational buckets (ala gc module),
        # keyed off of target id, that way long-lived ones don't have to be scanned as often.
        with self.lock:
            targetmap = self.targetmap
            lowmem = self._check_lowmem()
            clog.info("collecting soft refs... targets=%d lowmem=%r", len(targetmap), lowmem)
            purge_keys = set()
            cur = cur_time()
            #call collect_entry for all of targetmap
            helper = self._collect_entry
            for target_id, srlist in targetmap.iteritems():
                if helper(target_id, srlist, cur, lowmem):
                    purge_keys.add(target_id)
            #purge any keys we identified previously, just to free up even more memory
            for target_id in purge_keys:
                del targetmap[target_id]
            self.last_collect = cur
            count = len(purge_keys)
            clog.info("released %d targets", count)
            return count

    def _check_lowmem(self):
        "check if we're running in low memory condition"
        #TOOD:
        #   - sliding scale, doing more as lowmem approaches? ie, freeing only some eligible softrefs
        #   - have collector prefer softrefs w/ older atimes in that case
        #   - weighting for different instances / types, allowing "heavy" classes to be preferred to be freed?
        #   - generational buckets
        #   - other schemes?
        total, free = get_memory_usage()
        if total == -1: #not available or error occurred
            clog.debug("disabling lowmem check")
            #just to stop spamming, let's not call get mem again
            self._check_lowmem = lambda : False
            return False
        threshold = int(max(self.lowmem_abs, total * self.lowmem_pct))
        clog.debug("system memory: total=%r lowmem_threshold=%r free=%r", total, threshold, free)
        return free <= threshold

    def _collect_entry(self, target_id, srlist, cur, lowmem):
        "run collect algorithm for specified entry, return True if it needs removing"

        #NOTE: could consolidate min_age, max_age (and maybe atime)
        #into a single record stored w/in collector,
        #instead of storing separately in each softref.

        #scan existing softrefs, working out latest atime & softrefcount
        atime = 0
        min_age = self.default_min_age
        max_age = self.default_max_age
        srefs = [] #accumulate hard refs to sref objects, so weakrefs don't vanish while in this loop
        for sref_wr in srlist:
            sref = sref_wr()
            if sref is None:
                #TODO: could purge sref_wr here for extra mem,
                #but probably efficient enough for most cases
                #to just purge whole targetmap entry once target_wr is gone
                continue
            srefs.append(sref)
            if sref._atime > atime:
                atime = sref._atime
            if sref.min_age > min_age:
                min_age = sref.min_age
            if sref.max_age is not None and (max_age == -1 or sref.max_age < max_age):
                max_age = sref.max_age

        #check if any softrefs is still around
        if not srefs:
            #all references to softref objects dropped before they were purged
            clog.debug("softrefs vanished: %r", target_id)
            return True

        #decide if this one should be released yet
        age = cur-atime
        if age <= min_age:
            return False
        if not lowmem and (max_age == -1 or age < max_age):
            return False

        #sanity check on target
        assert all(id(sref._target) == target_id for sref in srefs), "targetmap corrupted: target=%r srefs=%r" % (target_id, srefs)
        target = srefs[0]._target

        #now check how many hardrefs are out there,
        #after ignoring the following hard refs:
        #   +1 reference in this frame's 'target' var
        #   +1 reference in getrefcount() call
        #   +N references held by '_target' attr of srefs
        #   any more, and it's external.
        #   any less, and it's runtimeerror, cause one of the above was missing.
        offset = 2+len(srefs)
        rc = sys.getrefcount(target)
        if rc < offset:
            raise RuntimeError, "too few references to target: %r rc=%r offset=%r" % (target, rc, offset)
        if rc > offset:
            #(rc-offset) hardrefs still out there, so don't purge softref
            return False

        #ok, time to release softref
        clog.info("releasing softrefs: %r", target)
        for sref in reversed(srefs): #NOTE: reversed so handlers called LIFO, same as weakref module
            sref._target = None #just so existing softrefs return None
            h = sref._onrelease
            if h is not None:
                try:
                    h(sref)
                except:
                    clog.error("error in softref onrelease callback: %r %r", target, onrelease)
                    sys.excepthook(*sys.exc_info())

        #schedule whole entry for removal
        return True

    #=================================================================================
    #collector thread
    #=================================================================================
    def is_enabled(self):
        "return true if collector thread is running, else false"
        if not self.thread or not self.thread.isAlive():
            return False
        if self.thread_stop.isSet():
            return None #special value indicating thread is still running but will stop soon. call disable() to ensure it's stopped.
        return True

    def enable(self):
        "start collector thread if not running"
        if self.thread and self.thread.isAlive():
            if not self.thread_stop.isSet():
                return True
            #wait til thread has exited
            self.thread.join()
        self.thread_stop.clear()
        thread = threading.Thread(target=self._collector_loop, name="[softref collector]")
        thread.setDaemon(True)
        clog.debug("softref collector thread launched")
        thread.run()

    def _collector_loop(self):
        "main loop used by collector thread"
        clog.info("softref collector thread started")
        #XXX: should we check for errors and have a cooldown period before trying again?
        while True:
            #wait for stop event OR time for next collection
            delay = max(.05, self.next_collect - cur_time())
            self.thread_stop.wait(delay)

            #check if we've been signalled to stop
            if self.thread_stop.isSet():
                clog.info("softref collector thread stopped")
                return

            #run collector
            clog.info("collecting softrefs")
            self.collect()

    def disable(self):
        "stop collector thread if running"
        #NOTE: this shouldn't be called if self.lock is held,
        #otherwise might deadlock if we join while
        #other thread is trying to acquire lock.

        #signal thread should stop
        self.thread_stop.set()

        #then join til it does
        if self.thread and self.thread.isAlive():
            self.thread.join()
        self.thread = None

    #=================================================================================
    #eoc
    #=================================================================================

#=================================================================================
#single collector and public interface to it
#=================================================================================

_collector = _SoftRefCollector()

#----------------------------------------------------------------------
#configuration collector
#----------------------------------------------------------------------
def set_config(default_max_age=None, default_min_age=None, collect_frequency=None,
                lowmem_pct=None, lowmem_abs=None):
    """update various collector config options.

    :kwd default_min_age:
        change minimum age (seconds since last access)
        before a softref is eligible to be released
        by the collector.

        softrefs can specify this per-instance.

        defaults to 10 minutes.

    :kwd default_max_age:
        change maximum age (seconds since last access)
        before a softref will be purged by collector
        even if there isn't a low memory condition.

        softrefs can specify this per-instance.

        defaults to -1 minutes,
        which indicates there is no max age.

    :kwd collect_frequency:
        how often collector thread calls collect(),
        measured in seconds.

        defaults to every 5 minutes.

    :kwd lowmem_pct:
        if free memory drops below this amount (as percent of total memory),
        the collector considers the system to be low on memory,
        and becomes agressive in purging softrefs.

        the actual low memory threshold is ``max(lowmem_abs, phymem * lowmem_pct)``,
        providing a floor to the lowmem threshold so it will function acceptably
        on systems with a small amount of physical memory.

        defaults to .05 percent (~100 Mb on a 2Gb system).

    :kwd lowmem_abs:
        minimum free memory threshold (in kilobytes).
        see lowmem_pct for more details.

        defaults to 25 Mb (~.05 percent on a 512 Mb system).

    .. note::
        default values subject to change as internal algorithm
        is being refined (currently doesn't account for system memory usage, etc)

    most changes will take affect the next time collect() runs,
    with the exception of collect_frequency, which will take effect
    next time the collector thread wakes up.
    """
    global _collector
    if default_max_age is not None:
        if default_max_age <= 0 and default_max_age != -1:
            raise ValueError, "default_max_age must be -1 or positive value"
        _collector.default_max_age = default_max_age
    if default_min_age is not None:
        if default_min_age < 0:
            raise ValueError, "default_min_age must be >= 0"
        _collector.default_min_age = default_min_age
    if collect_frequency is not None:
        if collector_frequency <= 0:
            raise ValueError, "collector frequency must be > 0"
        _collector.collect_frequency = collect_frequency
    if lowmem_pct is not None:
        if lowmem_pct < 0 or lowmem_pct >= 1:
            raise ValueError, "lowmem_pct must be between [0.0,1.0)"
        _collector.lowmem_pct = lowmem_pct
    if lowmem_abs is not None:
        if lowmem_abs < 0:
            raise ValueError, "lowmem_abs must be >= 0"
        _collector.lowmem_abs = lowmem_abs

def get_config():
    "return dict of current collector config options, corresponding to :func:`set_config` kwds"
    global _collector
    return dict(
        (k,getattr(_collector,k))
        for k in ["default_min_age", "default_max_age", "collect_frequency",
                  "lowmem_pct", "lowmem_abs"]
    )

#----------------------------------------------------------------------
#running collector
#----------------------------------------------------------------------
def is_enabled():
    "check if softref collector thread is running"
    return _collector.is_enabled()

def enable():
    "ensure softref collector thread is running"
    return _collector.enable()

def disable():
    "ensure softref collector thread is not running (will block until thread terminates)"
    return _collector.disable()

def collect():
    "force a run of the softref collector immediately"
    return _collector.collect()

#----------------------------------------------------------------------
#introspection of softref information
#----------------------------------------------------------------------
def get_softref_count(target):
    "return number of soft refs attached to target"
    return _collector.count(target)

def get_softrefs(target):
    "return all softref instances attached to target"
    return _collector.refs(target)

def get_hardref_count(target):
    "return number of hard refs attached to target (include 1 ref for this function call)"
    rc = sys.getrefcount(target)
    sc = get_softref_count(target)
    return rc-sc-1

#=================================================================================
#softref constructor
#=================================================================================
class softref(object):
    """create a softref to another object

    :arg target: object this should hold softref to
    :arg onrelease:
        optional callback to invoke ``onrelease(sref)``
        if softref to target is released before this object
        is dereferenced.
    :arg min_age:
        override default min_age for this target
    :arg max_age:
        override default max_age for this target

    :returns:
        a new softref instance.
        calling it will return original target, or ``None``,
        same as a weakref.
    """

    #TODO: provide hook which can prevent softref from being freed
    #(eg if object shouldn't be freed if it's in a certain state, etc)

    #=================================================================================
    #instance attrs
    #=================================================================================
    __slots__ = ["__weakref__", "_target", "_atime", "_onrelease", "min_age", "max_age"]

    #store quick links to collector
    _collector_lock = _collector.lock
    _collector_add = _collector.add

    #=================================================================================
    #instance methods
    #=================================================================================
    #TODO: could override __new__ for cls=softref and only 'target' param,
    # let it cache things for us.

    def __init__(self, target, onrelease=None, min_age=None, max_age=None):
        self._target = target
        self._onrelease = onrelease
        self.min_age = min_age
        self.max_age = max_age
        self._atime = cur_time()
        self._collector_add(self) #register new softref with collector

    ##@property
    ##def atime(self): return self._atime

    ##def touch(self):
    ##    self._atime = cur_time()

    def __call__(self):
        self._atime = cur_time() #NOTE: doing this outside lock cause it can't hurt, and might catch collector in it's tracks

        #NOTE: have to lock collector while we're creating new hardref,
        #or collector might see N hard refs, this thread creates hard ref N+1,
        #and then collector purges softref, causing this thread
        #to have a hard ref after softref was purged (which is against
        #how this module wants softrefs to behave)
        with self._collector_lock:
            return self._target

    def __repr__(self):
        target = self._target
        if target is None:
            return "<softref at 0x%x; dead>"%  (id(self),)
        else:
            return "<softref at 0x%x; to '%s' at 0x%x>" % (id(self), type(target).__name__, id(target))

    def __eq__(self, other):
        return self._target == other

    def __ne__(self, other):
        return self._target != other

    #=================================================================================
    #eoc
    #=================================================================================

#=================================================================================
#soft value dict
#=================================================================================
#NOTE: this is cloned from py26 weakref.WeakValueDict, and adapted for softrefs...

class SoftValueDictionary(UserDict.UserDict):
    """Mapping class that references values using softref.

    Entries in the dictionary will be discarded when no strong
    reference to the value exists anymore
    """
    # We inherit the constructor without worrying about the input
    # dictionary; since it uses our .update() method, we get the right
    # checks (if the other dictionary is a WeakValueDictionary,
    # objects are unwrapped on the way out, and we always wrap on the
    # way in).

    min_age = None
    max_age = None

    def __init__(self, source=None, min_age=None, max_age=None):
        if min_age:
            self.min_age = min_age
        if max_age:
            self.max_age = max_age
        def remove(sr, selfref=make_weakref(self)):
            self = selfref()
            if self is not None:
                del self.data[sr.key]
        self._remove = remove
        if source is None:
            args = ()
        else:
            args = (source,)
        UserDict.UserDict.__init__(self, *args)

    ##def touch(self, key):
    ##    "helper to update softref atime for value attached to key"
    ##    self.data[key].touch()

    def __getitem__(self, key):
        o = self.data[key]()
        if o is None:
            raise KeyError, key
        else:
            return o

    def __contains__(self, key):
        try:
            o = self.data[key]()
        except KeyError:
            return False
        return o is not None

    def has_key(self, key):
        try:
            o = self.data[key]()
        except KeyError:
            return False
        return o is not None

    def __repr__(self):
        return "<SoftValueDictionary at %s>" % id(self)

    def __setitem__(self, key, value):
        self.data[key] = KeyedSoftRef(key, value, self._remove, self.min_age, self.max_age)

    def copy(self):
        new = SoftValueDictionary()
        new.min_age = self.min_age
        new.max_age = self.max_age
        for key, sr in self.data.items():
            o = sr()
            if o is not None:
                new[key] = o
        return new

    def get(self, key, default=None):
        try:
            sr = self.data[key]
        except KeyError:
            return default
        else:
            o = sr()
            if o is None:
                # This should only happen
                return default
            else:
                return o

    def items(self):
        L = []
        for key, sr in self.data.items():
            o = sr()
            if o is not None:
                L.append((key, o))
        return L

    def iteritems(self):
        for sr in self.data.itervalues():
            value = ws()
            if value is not None:
                yield ws.key, value

    def iterkeys(self):
        return self.data.iterkeys()

    def __iter__(self):
        return self.data.iterkeys()

    def itervaluerefs(self):
        """Return an iterator that yields the weak references to the values.

        The references are not guaranteed to be 'live' at the time
        they are used, so the result of calling the references needs
        to be checked before being used.  This can be used to avoid
        creating references that will cause the garbage collector to
        keep the values around longer than needed.

        """
        return self.data.itervalues()

    def itervalues(self):
        for wr in self.data.itervalues():
            obj = wr()
            if obj is not None:
                yield obj

    def popitem(self):
        while 1:
            key, wr = self.data.popitem()
            o = wr()
            if o is not None:
                return key, o

    def pop(self, key, *args):
        try:
            o = self.data.pop(key)()
        except KeyError:
            if args:
                return args[0]
            raise
        if o is None:
            raise KeyError, key
        else:
            return o

    def setdefault(self, key, default=None):
        try:
            wr = self.data[key]
        except KeyError:
            self.data[key] = KeyedSoftRef(key, default, self._remove, self.min_age, self.max_age)
            return default
        else:
            return wr()

    def update(self, dict=None, **kwargs):
        d = self.data
        if dict is not None:
            if not hasattr(dict, "items"):
                dict = type({})(dict)
            for key, o in dict.items():
                d[key] = KeyedSoftRef(key, o, self._remove, self.min_age, self.max_age)
        if len(kwargs):
            self.update(kwargs)

    def valuerefs(self):
        """Return a list of weak references to the values.

        The references are not guaranteed to be 'live' at the time
        they are used, so the result of calling the references needs
        to be checked before being used.  This can be used to avoid
        creating references that will cause the garbage collector to
        keep the values around longer than needed.

        """
        return self.data.values()

    def values(self):
        L = []
        for wr in self.data.values():
            o = wr()
            if o is not None:
                L.append(o)
        return L

class KeyedSoftRef(softref):
    """Specialized reference that includes a key corresponding to the value.

    This is used in the SoftValueDictionary to avoid having to create
    a function object for each key stored in the mapping.  A shared
    callback object can use the 'key' attribute of a KeyedSoftRef instead
    of getting a reference to the key from an enclosing scope.

    """

    __slots__ = "key",

    def __new__(cls, key, target, onrelease=None, min_age=None, max_age=None):
        self = softref.__new__(cls, target, onrelease, min_age, max_age)
        self.key = key
        return self

    def __init__(self, key, target, onrelease=None, min_age=None, max_age=None):
        super(KeyedSoftRef, self).__init__(target, onrelease, min_age, max_age)

#=================================================================================
#eof
#=================================================================================
