"""bps.basic -- tools for manipulating basic python datatypes"""
#=========================================================
#imports
#=========================================================
#core
from itertools import islice
from sys import version_info as pyver
#pkg
from bps.error.types import ParamError
#local
__all__ = [
    #dict utilities
    'zip_dict',
    'unzip_dict',
    'pop_from_dict',
##    'extract_from_dict',
    'set_dict_defaults',

    #sequence utilities
    'intersects', 'sameset',
    'unique',
    'iter_unique',
    'is_unique',
    'enum_slice',

    #functional
    ##'partial' - used to be provided until 2.5 added their implementation
##    'revpartial',
]

#=========================================================
#dictionary helpers
#=========================================================

def invert_dict(source, dups="error"):
    """invert dictionary.

    Given a dict mapping key -> value,
    this returns a new dictionary mapping value -> key.

    :arg source: the source dictionary to invert
    :param dups:
        Sets the policy when two keys map to the same value.
        * By default this is ``"error"``, which raises a ValueError
        * Set to "ignore", one key will be chosen (the last one returned by iteritems).

    :raises ValueError: if the source dictionary maps two keys to the same value

    Usage Example::

        >>> from bps.basic import invert_dict
        >>> invert_dict({1:2, 3:4, 5:6})
            { 2:1, 4:3, 6:5 }
    """
    if dups == "error":
        out = {}
        for k, v in source.iteritems():
            if v in out:
                raise ValueError, "dictionary not invertible: value=%r key1=%r key2=%r" % (v, out[v], k)
            out[v] = k
        return out
    else:
        assert dups == "ignore"
        return dict( (v, k) for k, v in source.iteritems())

def update_dict_defaults(target, *args, **kwds):
    """cross between dict.update and dict.setdefault, which updates only the keys which aren't already present.

    Usage Examples::

        >>> from bps.basic import update_dict_defaults
        >>> a = dict(x=1,y=2)
        >>> update_dict_defaults(a, x=100, z=3)
        >>> a
        { 'x': 1, 'y': 2, 'z': 3 }
        >>> update_dict_defaults(a, { 'z': 100, 's': 20 })
        >>> a
        { 'x': 1, 'y': 2, 'z': 3, 's': 20 }
    """
    if args:
        if len(args) > 1:
            raise TypeError, "at most one positional argument is allowed"
        source = args[0]
        for k,v in source.iteritems():
            if k not in target:
                target[k] = v
    if kwds:
        for k,v in kwds.iteritems():
            if k not in target:
                target[k] = v

set_dict_defaults = update_dict_defaults #XXX: deprecate this name?

#---------------------------------------
# (keys, values) <-> dict
#---------------------------------------
def zip_dict(keys, values):
    "converts list of keys, list of values to dict"
    return dict(zip(keys, values))

def unzip_dict(data):
    "converts dict to list of keys and list of values"
    if data is None: #special case
        return [],[]
    else:
        keys = []
        values = []
        for k,v in data.iteritems():
            keys.append(k)
            values.append(v)
        return keys,values

#---------------------------------------
#extract one dict from another
#---------------------------------------
def pop_from_dict(source, keys, target=None):
    """for all keys in <keys>, extract any from <source> dict,
    and return them in new dictionary (or place in <target> dict)
    """
    if target is None:
        target = {}
    for k in keys:
        if k in source:
            target[k] = source.pop(k)
    return target

##def filter_dict(func, source, target=None):
##    """filter dictionary. ``func(k,v) -> bool``"""
##    if target is None:
##        target = {}
##    for k, v in source.iteritems():
##        if func(k, v):
##            target[k] = v
##    return target

def prefix_from_dict(source, prefix, target=None):
    """For all keys in *source* dict with the specified *prefix*,
    strip the prefix, and copy the k/v pair to the *target* dict.

    If target is specified, it will be used as the dictionary
    that any matching k/v pairs are inserted into.
    Otherwise, a new dictionary will be created as the target.

    :Returns:
        This always returns the target dict,
        whether passed-in or created.

    Usage Example::

        >>> from bps.basic import strip_from_dict
        >>> prefix_from_dict({"abc":1, "def": 2, "abxyz": 3}, "ab")
            { "c": 1, "xyz": 3 }

    """
    if target is None:
        target = {}
    for key in source:
        if key.startswith(prefix):
            target[key[len(prefix):]] = source[key]
    return target

#works, but near useless probably
##def extract_from_dict(source, keys, target=None):
##    """extract specified keys from dictionary.
##
##    returns a new dictionary, unless target is specified.
##    if target is a dict, keys are placed in target.
##    if target is ``list`` or ``tuple``, the corresponding class
##    will be returned.
##    """
##    if target is list:
##        return [ source[k] for k in keys ]
##    elif target is tuple:
##        return tuple(source[k] for k in keys)
##    elif target is None:
##        return dict( (k,source[k]) for k in keys)
##    else:
##        for k in keys:
##            target[k] = source[k]
##        return target

#=========================================================
#set helpers
#=========================================================

#xxx: would enable this, but could use more intelligent return values
##def intersection(list1, list2):
##    "returns list containing all elements shared by two sequences / iterables"
##    return list(set(list1).intersection(list2))
##

#TODO: write unittests
if pyver < (2,6):
    def intersects(list1, list2):
        "returns True if two sequences / iterables have any elements in common"
        #TODO: would like a more efficient way of doing this for large sets
        return bool(set(list1).intersection(list2))
else:
    def intersects(list1, list2):
        "returns True if two sequences / iterables have any elements in common"
        return not set(list1).isdisjoint(list2)

def sameset(list1, list2):
    "returns True if the two sequences contain exactly the same elements, else False"
    if not isinstance(list1, set):
        list1 = set(list1)
    if not isinstance(list2, set):
        list2 = set(list2)
    return list1 == list2

#=========================================================
#iteration & functional helpers
#=========================================================

#this works, but not used
##def revpartial(func, *args, **kwds):
##    "like partial(), but args & kwds are appended to end"
##    #TODO: given this 'func', 'args' and 'kwds' attrs like functools.partial
##    return lambda *p, **n:\
##                    func(*p + args, **dict(kw.items() + n.items()))

def iter_unique(seq):
    """iterate through sequence, yielding only unique values.
    values will be returned in order of first occurrence.

    Example Usage::
        >>> from bps.basic import iter_unique
        >>> for x in iter_unique([1,3,2,1,2,3]):
        >>>     print x
            1
            3
            2
    """
    seen = set()
    cont = seen.__contains__
    add = seen.add
    for val in seq:
        if not cont(val):
            add(val)
            yield val

def unique(seq):
    """return list containing only unique elements in sequence,
    in order of first occurrence.

    Example Usage::
        >>> from bps.basic import unique
        >>> unique([1,3,2,1,2,3])
            [1,3,2]
    """
    return list(iter_unique(seq))

def is_unique(seq):
    "check if sequence/iterator contains only unique values; returns False after first duplicate is found"
    if isinstance(seq, (set,frozenset)):
        return True
    #XXX: is there a faster way?
    seen = set()
    cont = seen.__contains__
    add = seen.add
    for elem in seq:
        if cont(elem):
            return False
        add(elem)
    return True

def enum_slice(seq, *args):
    """enumslice(iterable, [start,] stop [, step])

    Combination of enumerate & islice which reports original index values.
    Equivalent to ``islice(enumerate(seq), start, stop, step)``,
    but without creation of intermediate sequence.

    Usage::

        >>> from bps.basic import enum_slice
        >>> for idx, value in enum_slice("abcdef", 2, 5):
        >>>     print idx, value
        2 c
        3 d
        4 e
    """
    #NOTE: we calc start/stop/step ourselves,
    #so we can handle negative indices (since islice doesn't).
    #if islice did, this would be a much simpler function.

    #handle simple case
    ac = len(args)
    if ac == 0:
        for idx, value in enumerate(seq):
            yield idx, value
        return

    #figure out params
    elif ac == 1:
        start = 0
        stop, = args
        step = 1
    elif ac == 2:
        start, stop = args
        step = 1
    elif ac == 3:
        start, stop, step = args
    else:
        raise ParamError, "too many arguments"

    #normalize inputs
    if start is None:
        start = 0
    elif start < 0:
        #FIXME: error if passed an iterator (works for lists/strings)
        start += len(seq)
    if stop is None:
        pass
    elif stop < 0:
        #FIXME: error if passed an iterator (works for lists/strings)
        stop += len(seq)
    if step is None:
        step = 1

    #run
    if step < 0:
        #islice doesn't support negative ints.
        #FIXME: error if passed an iterator (works for lists/strings)
        offset = start
        if stop is None:
            stop = -1
        while offset > stop:
            yield offset, seq[offset]
            offset += step
    else:
        offset = start
        for value in islice(seq, start, stop, step):
            yield offset, value
            offset += step

#=========================================================
#EOF
#=========================================================
