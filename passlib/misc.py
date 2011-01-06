"""bps.misc -- assorted functions that dont fit in another category"""
#===================================================
#imports
#===================================================
#core
from functools import update_wrapper
import time
import re
#pkg
from bps.types import Undef
from bps.meta import find_attribute
#local
__all__ = [
    #property constructors
    'indirect_property',
    'constructor_property',

    #http
    'parse_agent_string',
    'agent_string_has_product',

    #other
    'stepped_delay',
]

#=========================================================
#property constructors
#=========================================================
class indirect_property(object):
    """descriptor which acts like property(), but resolves methods at instance time.

    One of the drawbacks of the builtin :func:``property`` is that it stored
    the functions directly. Thus, if a subclass overrides the method
    which is also being used by a property's fget,
    the property object will still use the original function.

    This is a drop-in replacement for property which takes in
    attribute names instead of actual functions. It does
    runtime resolution of the attributes, so that the named
    methods can be safely overridden (even on a per-instance basis)
    and still have the properties use the correct code.

    .. note::
        Due to the repeated additional lookup, this is slower
        than a normal property, so use it only if you have to.
    """
    #TODO: need to make this work right for various border cases (missing fget/fset)
    #TODO: default doc based on attr names

    def __init__(self, fget=None, fset=None, fdel=None, doc=None):
        self.fget = fget
        self.fset = fset
        self.fdel = fdel
        if doc:
            self.__doc__ = doc

    def __get__(self, obj, cls):
        if obj is None:
            return self
        else:
            return getattr(obj, self.fget)()

    def __set__(self, obj, value):
        if self.fset:
            getattr(obj, self.fset)(value)
        else:
            raise AttributeError("readonly attribute")

    def __delete__(self, obj):
        if self.fdel:
            getattr(obj, self.fdel)(value)
        else:
            raise AttributeError("can't delete attribute")

class constructor_property(object):
    """lazy-initialized attribute.

    This is a class property,
    which takes in a constructor func, and uses that function
    to fill in the instance attribute when it's first accessed.

    usage::
        >>> from bps.misc import constructor_property
        >>> #create a custom class
        >>> class Example(object):
        >>>    a = constructor_property(dict)
        >>> e = Example()
        >>> #initially nothing is stored in 'a'
        >>> e.__dict__.get("a")
            None
        >>> #but when it's first accessed, dict() is called, and the value is stored/returned
        >>> e.a
            {}
        >>> #from then on, that's the value that will be returned for .a, until ``del e.a`` is called
        >>> e.__dict__.get("a")
            {}

    :arg func:
        function / class to call when attribute is first accessed for an instance
    :arg name:
        optionally let object know which attribute it's stored under
        (will be autodiscovered later)
    :param passref:
        if True, func will be called with instance as first argument (eg ``func(self)``)
        rather than without arguments (eg ``func()``)
    """
    def __init__(self, func, name=None, passref=False):
        self.func = func
        self.name = name
        self.passref = passref

    def __get__(self, obj, cls):
        if obj is None:
            return self
        if self.name is None:
            self.name = find_attribute(cls, self, required=True)
        assert self.name not in obj.__dict__
        if self.passref:
            value = self.func(obj)
        else:
            value = self.func()
        obj.__dict__[self.name] = value
        #we should never get called again for this object
        return value

class class_property(object):
    "classmethod+readonly property"
    #TODO: document this
    def __init__(self, fget):
        self.fget = fget
    def __get__(self, owner, cls):
        return self.fget(cls)

#=========================================================
#
#=========================================================
def _iter_decay(lower, upper, half):
    "helper for stepped_delay"
    #default delay loop using "lower" "upper" and "half"
    #equation: delay[idx] = upper - (upper-lower) * (decay ** idx)
    #such that:
    #    delay[0] == lower
    #    delay[half] = (upper+lower)/2
    #    delay[idx] < upper
    #
    #this means decay = (1/2)**(1/half)
    #
    if half:
        decay = .5**(1.0/half)
    else:
        decay = .9 ## approx ~ half=7
    value = upper-lower
    while True:
        yield upper-value
        value *= decay

def stepped_delay(timeout=None, count=None,  steps=None, lower=.1, upper=90, half=None):
    """generate a stepped delay loop; useful when polling a resource repeatedly.

    This function provides a delay loop
    for such things as polling a filesystem for changes, etc.
    It provides an initially short delay which slowly backs off.
    It's designed to be used an iterator, so that all logic
    stays within your application.

    You can either specify a custom sequence of delay values via *steps*,
    or use the default exponential decay algorithm, which
    begans with a delay of *lower*, and slowly increases,
    approaching a delay time of *upper*.

    :param timeout:
        If specified, the loop will stop after *timeout* seconds
        have passed, no matter how many repetitions have been run.

    :param count:
        If specified, the loop will stop after *count* repetitions.

    :param steps:
        If specified, this should be a sequence
        of delay values to use. When the sequence runs
        out, the last delay value will be repeated.
        If *steps* is not used, a default exponential
        decay algorithm will be used.

    :param lower:
        [ignored if *steps* is specified]
        This specifies the starting delay.
        The first delay will be this length,
        the next a little more, and so on.

    :param upper:
        [ignored if *steps* is specified]
        This specifies the upper bound on the delay.
        Each time the iterator sleeps, the delay
        will increase, asymptotically approaching
        the *upper* bound.

    :param half:
        [optional, ignored if *steps* is specified]
        If specified, adjusts the rate of the exponential delay
        increase such that it will take exactly *half*
        rounds through the iterator before the delay
        is at the half-way mark between *lower* and *upper*.

    :Returns:
        This loop yields tuples of ``(index,delay)``,
        where *index* is the number of passes that have been made,
        and *delay* is the amount of time it slept before
        yielding the last tuple. It will increase the delay
        used each time before it yeilds a new tuple,
        in accordance with the configuration above.
        If the loop ends due to *timeout* or *count*,
        the iterator will raise :exc:`StopIteration`.

    Usage Example::

        >>> import time
        >>> from bps.misc import stepped_delay
        >>> for i,d in stepped_delay(count=10, lower=.1, upper=10):
        >>>     print i,d,time.time()
        >>>     #... do stuff, calling break if done with loop
        >>> else:
        >>>     print "loop exit w/o success"
            0 0 1244648293.01
            1 0.1 1244648293.11
            2 1.09 1244648294.2
            3 1.981 1244648296.19
            4 2.7829 1244648298.97
            5 3.50461 1244648302.48
            6 4.154149 1244648306.64
            7 4.7387341 1244648311.38
            8 5.26486069 1244648316.65
            9 5.738374621 1244648322.39
            loop exit w/o success

    .. todo::
        Could allow delay to be reset to initial value
        by sending ``"reset"`` back to the yield statement.
    """

    #run first round without any delay
    yield 0, 0

    #prepare delay value generator
    if steps:
        #ignore 'lower', 'upper', and 'half'
        def loopgen():
            for value in steps:
                yield value
            while True: #repeat last value
                yield value
        loop = loopgen()
    else:
        if upper <= lower: #allow us to set really small 'upper' and auto-scale lower
            lower = .1 * upper
        loop = _iter_decay(lower, upper, half)

    #run main delay loop
    if timeout:
        end = time.time() + timeout
    for idx, delay in enumerate(loop):
        time.sleep(delay)
        yield idx+1, delay
        #check if it's time to abort
        if count and idx+2 >= count:
            return
        if timeout and time.time() >= end:
            return

#=========================================================
#http agent string
#=========================================================
_clean_re = re.compile(r"\s+")

_agent_re = re.compile(
    r"""
    ^
    \s*
    (
        (?P<product>
            (?P<name>
                [^\s()/]+ # technically this should only be TOKEN chars
            )
            (
                /
                (?P<version>
                    [^\s()]+ #XXX: what _is_ allowed here? TOKEN?
                )
            )?
        )
    |
        (
            \(
            (?P<comment>
                [^)]+ #technically this should only be TOKEN chars
            )
            \)
        )
    )
    \s*
    """, re.I|re.X)

def parse_agent_string(value, normalize=True):
    """parse a HTTP user agent string.

    This parses an HTTP User Agent string,
    returning a list of agents identified in the string, in order.


    :type value: str
    :param value:
        The agent string to parse

    :type normalize: bool
    :param normalize:
        This flag (enabled by default)
        turns on any special-case heuristics for known
        atypical user agent strings, as well
        as converting the string to lower case.
        It can be disabled to get the unmangled results.

    :returns:
        A list of dictionaries, one for each product found.
        The first dictionary is usually considered the primary.
        This code assumes comments will always *follow* the product description
        they are attached to, but if this rule is violated,
        a "blank" product entry will be inserted, where all relevant keys
        except "comment" will be ``None``. Other than that case,
        the following keys should be filled out for each dictionary:

            product
                This will contain the raw product name, eg "Mozilla/5.0".
            name
                This will contain just the name of the product
                (assuming it has the format "name/version").
                If the product couldn't be parsed this way, name's contents are undefined.
            version
                This will contain the version of the product,
                (assuming it has the format "name/version").
                If the product couldn't be parsed this way, version's contents are undefined.
            comment
                This is present if a comment stanza followed
                the product definition. This will be a list of strings,
                as read from the comment and separated by semicolons.
                If no comment is present, the key will not be included.

    Usage Example::

        >>> from bps.misc import parse_agent_string
        >>> parse_agent_string("Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.11) Gecko/2009060309 Ubuntu/9.04 (jaunty) Firefox/3.0.11")
            [
                {   'name': 'Mozilla', 'version': '5.0',
                    'product': 'Mozilla/5.0',
                    'comments': ['X11', 'U', 'Linux x86_64',
                        'en-US', 'rv:1.9.0.11'],
                    },
                {   'name': 'Gecko', 'product': 'Gecko/2009060309',
                    'version': '2009060309'
                    },
                {   'name': 'Ubuntu', 'version': '9.04',
                    'product': 'Ubuntu/9.04',
                    'comments': ['jaunty'],
                  },
                {   'name': 'Firefox', 'version': '3.0.11',
                    'product': 'Firefox/3.0.11',
                    }
            ]

    .. seealso:

        :rfc:`2068` is the authoritative agent string format spec.
    """
    #NOTE: this code makes the assumption
    #that a comment will always be FOLLOWING (and is associated with) the preceding product.
    #this goes against the grammar of RFC2068, but is the de facto case.
    #thus, if a unexpected comment is encountered, a empty product entry will be created.
    orig = value
    value = _clean_re.sub(" ", value).strip()
    if normalize:
        value = value.lower()
    out = []
    while value:
        m = _agent_re.match(value)
        if m:
            comment = m.group("comment")
            if comment:
                comments = [ elem.strip() for elem in comment.split(";") ]
                if out and isinstance(out[-1], dict) and 'comments' not in out[-1]:
                    out[-1]['comments'] = comments
                else:
                    log.warning("unexpected comment segment in agent: %r %r", comment, orig)
                    out.append(dict(product=None, name=None, version=None, comments=comments))
            else:
                product, name, version = m.group("product", "name", "version")
                out.append(dict(product=product, name=name, version=version))
            value = value[m.end():]
        else:
            #can this _ever_ happen?
            log.warning("failed to parse agent segment: %r of %r", value, orig)
            value = ''
##    if not normalize:
##        return out
    #TODO: detect the "+http://homepage" elements add end of comment list,
    # move out to "url" kwd
    #TODO: detect platform info
    #TODO: detect firefox, opera, konq, safari, chrome,
    # and move their products to the front
##    #now we apply various bits of UA-specific knowledge to normalize things
##    #TODO: could pull out 'MSIE' etc
##    for entry in out:
##        if not entry['product'] or not entry['comments']:
##            continue
##        #could parse out site urls
    return out

def _parse_agent_version(value):
    if value is None:
        return None
    #XXX: use a real version parser here.
    if isinstance(value, str):
        try:
            return tuple(int(x) for x in value.split("."))
        except ValueError:
            return None
    elif isinstance(value, int):
        return tuple(value)
    #should be tuple of ints.
    return value

def agent_string_has_product(agent, name, min_version=None):
    """tests if agent string references a product name.

    This wrapper for :func:`parse_agent_string`
    checks if a given product is found in the provided string.
    This is a simple function, more complex cases may require
    rolling your own test function.

    :param agent:
        The raw agent string, OR the output of parse_agent_string.
    :param name:
        The name of the product to check for.
    :param min_version:
        Optional minimum version.
        For this to work, min_version must be an integer,
        tuple of integers, or a period-separated string.

    :returns:
        Returns ``True`` if a match is found,
        ``False`` if a match is not found.
    """
    name = name.lower()
    min_version = _parse_agent_version(min_version)
    if isinstance(agent, str):
        agent = parse_agent_string(agent)
    for entry in agent:
        if entry['name'] == name:
            if not min_version or min_version <= _parse_agent_version(entry['version']):
                return True
        #TODO: IE detect here or in extended?
    return False

#=========================================================
#code scraps
#=========================================================

#need to clean this up a little, but might be useful
##def formatFuncStr(fname, *args, **kwds):
##    if isinstance(fname, str):
##        pass##    elif callable(fname):
##        fname = fname.__name__
##    else:
##        fname = str(fname)
##
##    body = ""
##    if args:
##        for a in args:
##            if body != "": body += ","
##            body += repr(a)
##    if kwds:
##        for k,v in kwds.items():
##            if body != "": body += ","
##            body += "%s=%r" % (k,v)
##    return "%s(%s)" % (fname,body)

#=========================================================
#
#=========================================================
