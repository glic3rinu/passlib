"""bps.unstable -- new, undocumented, and still developing additions to bps
"""
#=========================================================
#imports
#=========================================================
#core
import contextlib
import os
from logging import getLogger; log = getLogger(__name__)
import os.path
from warnings import warn
import re
#pkg
from bps.fs import getcwd, filepath
from bps.text import condense
from bps.meta import isstr, is_iter, get_module
from bps.basic import enum_slice
#local
__all__ = [
    'smart_list_iter',
    'ellipsize',
    'protected_env',
]

#=========================================================
#iteration
#=========================================================
##class BufferedIter(object):
##    "return iterator which can be walked back, ala ungetch"
##    def __init__(self, source):
##        self._source = source
##        self._itr = iter(source)
##        self._buffer = []
##
##    def next(self):
##        if self._buffer:
##            return self._buffer.pop()
##        return self._itr.next()
##
##    def pushnext(self, value):
##        self._buffer.append(value)


##def pairs(obj):
##    "an attempt at a Lua-like pairs() iterator."
##    if hasattr(obj, "iteritems"):
##        return obj.iteritems()
##    elif hasattr(obj, "__len__") and hasattr(obj,"__getitem__"):
        ##if hasattr(obj, "_asdict") and hasattr(obj, "_fields"):
        ##    #probably a namedtuple...
        ##    return (
        ##        (k,getattr(obj,k))
        ##        for k in obj._fields
        ##    )
        ##return enumerate(obj)
##    else:
##        return (
##            (k,getattr(obj,k))
##            for k in dir(obj)
##            if not k.startswith("_")
##        )
##TODO: maybe also an ipairs()

def filter_in_place(func, target, invert=False):
    "perform in-place filtering on a list, removing elements if they don't pass filter func"
    #NOTE: length check delayed til after type identified,
    # so that type errors won't get hidden for empty instances
    # of unsupported types.
    if not hasattr(target, "__len__"):
        #target is iter, or something more obscure
        raise TypeError, "cannot support types without length: %r" % (type(target),)
    if not hasattr(target, "__iter__"):
        #not sure what types could get here. but code relies on iteration
        raise TypeError, "cannot support non-iterable types: %r" % (type(target),)
    if hasattr(target, "__getitem__"):
        if not hasattr(target, "__delitem__"):
            #target is frozenset, str, tuple, etc
            raise TypeError, "cannot support types without del: %r" % (type(target),)
        if hasattr(target, "keys"): #xxx: is there better way to identifier mapping?
            #target is dict-like
            #NOTE: we build set of keys to delete rather than deleting
            #as we go, since that set will always be smaller than set of all keys
            pos = not invert
            remove = set(
                key for key in target
                if pos ^ func(key) #NOTE: operates on key, not value
            )
            for key in remove:
                del target[key]
            return
        else:
            #target is list-like (eg: list, array)
            #FIXME: this assumes __len__ + __getitem__ - keys implies int indexes.
            #   might need better check of this assumption ('index' is reliable for list & array)
            end = len(target)
            if not end:
                return
            pos = 0
            while pos < end:
                if invert ^ func(target[pos]):
                    pos += 1
                else:
                    del target[pos]
                    end -= 1
            return
    elif hasattr(target, "difference_update"):
        #assume it's a set
        pos = not invert
        remove = set(
            elem for elem in target
            if pos ^ func(elem)
        )
        if remove:
            target.difference_update(remove)
        return
    else:
        #probably a frozenset
        raise TypeError, "unsupported type: %r" % (type(target),)

#rename to mutable_list_iter ? also, might be too complex, when filter_in_place might be better
class smart_list_iter(object):
    """list iterator which handles certain list operations without disrupting iteration.

    The typical usage of this class is when you need to iterate
    over a list, and delete selected elements as you go.

    The reason this is in unstable is that other use-cases may require
    reworking the class, the delete() case is the only one
    this class is currently being used for.

    Usage example::

        >>> from bps.unstable import smart_list_iter
        >>> a=[5,6,100,2,3,40,8] #given a list
        >>> itr = smart_list_iter(a) #create the iterator
        >>> for elem in itr: #iterate over it as normal
        >>>     print elem
        >>>     if elem > 30: #remove all elements over 30
        >>>         itr.delete() #delete via the iterator, allowing it to continue w/o losing sync
        >>> #all elements will be scanned
        5
        6
        100
        2
        3
        40
        8
        >>> a #but all ones called for delete will be replaced
        [5,6,2,3,8]

    Public Attributes
    =================

    .. attribute:: pos

        Current position in list (-1 before iterator starts)

    .. attribute:: next_pos

        Next position in list (may be equal to len of list)

    .. attrbite:: target

        The list we're iterating over.

    Public Methods
    ==============

    .. automethod:: delete

    .. automethod:: pop

    .. automethod:: append

    .. automethod:: insert
    """
    def __init__(self, target, enum=False):
        #XXX: reverse option?
        self.target = target
        self._enum = enum
        self.pos = -1
        self._deleted = False #flag that current element was deleted

    def _get_next_pos(self):
        pos = self.pos
        if not self._deleted:
            pos += 1
        return max(pos, len(self.target))
    next_pos = property(_get_next_pos)

    def __iter__(self):
        return self

    def __length__(self):
        pos = self.pos
        if not self._deleted:
            pos += 1
        return max(0, len(self.target)-pos)

    def next(self):
        "return next item"
        pos, deleted = self.pos, self._deleted
        if not deleted:
            pos += 1
        assert pos >= 0
        end = len(self.target)
        if pos >= end:
            raise StopIteration
        if deleted:
            self._deleted = False
        else:
            self.pos = pos
        if self._enum:
            return pos, self.target[pos]
        else:
            return self.target[pos]

    def delete(self):
        "delete current entry"
        pos = self.pos
        if pos == -1:
            raise IndexError, "not currently pointing to an element"
        del self.target[pos]
        self._deleted = True

    def pop(self, idx, relative=False):
        "pop entry from list. if index not specified, pops current entry in iterator"
        pos = self.pos
        if relative:
            idx += pos
        elif idx < 0:
            idx += len(self.target)
        if idx < 0:
            raise IndexError, "index too small"
        value = self.target.pop(idx)
        if idx < pos:
            self.pos = pos-1
        elif idx == pos:
            self._deleted = True
        return value

    def append(self, value):
        "quickly append to list"
        return self.insert(len(self.target), value)

    def insert(self, idx, value, relative=False):
        "insert entry into list. if relative=True, pos is relative to current entry in iterator"
        pos = self.pos
        if relative:
            idx += pos
        elif idx < 0:
            idx += len(self.target)
        if idx < 0:
            raise IndexError, "index too small"
        self.target.insert(idx, value)
        if idx < pos:
            self.pos = pos+1
        return idx

#=========================================================
#text related
#=========================================================
def get_textblock_size(text, rstrip=False):
    "return rows & cols used by text block"
    if not text:
        return 0,0
    textlines = text.split("\n")
    rows = len(textlines)
    if rstrip:
        cols = max(len(line.rstrip()) for line in textlines)
    else:
        cols = max(len(line) for line in textlines)
    return rows, cols

def ellipsize(text, width, align=">", ellipsis="...", mode="plain", window=None):
    """attempt to ellipsize text.

    :arg text: the string to ellipsize
    :arg width: the maximum allowed width
    :param align:
        Where the ellipsis should be inserted.

        ==============  ============================================
        Value           Location
        --------------  --------------------------------------------
        "<", "left"     ellipsis inserted at left side of text
        "^", "center"   ellipsis inserted in center of text
        ">", "right"    ellipsis inserted at right side of text
                        (the default).
        ==============  ============================================

    :param mode:
        Select which algorithm is used to ellipsize.
        Defaults to "smart".

        ==============  ================================================
        Value           Behavior
        --------------  ------------------------------------------------
        "plain"         Text will be clipped as needed,
                        regardless of spaces or other boundaries,
                        and the text will otherwise be left alone.
        "smart"         This function will attempt to remove extraneous
                        spaces and similar characters from the string,
                        and if ellipsis are needed, will prefer splitting
                        text at a space.
        "filepath"      Variant of the smart algorithm, this assumes
                        it's working with a local filepath,
                        and attempts to break on directory boundaries.
        ==============  ================================================

    :param window:
        For smart / filepath modes, this specifies
        the maximum number of characters to search for a good break point
        before giving up.

    :param ellipsis:
        Optionally overide the text used as the ellipsis.

    Usage Example::

        >>> from bps.text import ellipsize
        >>> ellipsize("abc", 6) #this does nothing
        'abc'
        >>> ellipsize("abcdefghi", 8) #suddenly, ellipsized
        'abcde...'
        >>> ellipsize("abcdefghi", 8, "<") #other side
        '...efghi'
    """
    #XXX: write code to break up string into atomic parts,
    #and override len() to handle them,
    #so this can deal with VT100 codes and HTML

    #convert to string
    if not isstr(text):
        text = str(text)

    #pre-process string
    if mode == "smart":
        #smart mode will ALWAYS try to shrink
        text = condense(text, " \t")

    #check if string fits w/in alloted space
    tsize = len(text)
    if tsize <= width:
        return text

    #figure out how much we can keep
    chars = width-len(ellipsis)
    if chars < 0:
        raise ValueError, "width must be larger than ellipsis!"
    elif chars == 0:
        return ellipsis

    #select boundary finder function
    if mode in ("smart", "filepath"):
        if mode == "smart":
            bc = " \t"
            if window is None:
                window = 8
        else:
            assert mode == "filepath"
            bc = os.path.sep
            if window is None:
                window = 32
        def find_boundary(start, fwd):
            "locate next boundary character in string"
            #nested vars: 'text', 'tsize', 'bc', and 'window'
            if fwd:
                if window == -1:
                    end = None
                else:
                    end = min(start+window, tsize)
                last = None
                for idx, c in enum_slice(text, start, end):
                    if c in bc:
                        last = idx
                    elif last is not None:
                        return last
                return last
            else:
                if window == -1:
                    end = None
                else:
                    end = start-window-1
                    if end < 0:
                        end = None
                log.debug("find_boundary rev: %r %r %r", text, start, end)
                last = None
                for idx, c in enum_slice(text, start, end, -1):
                    log.debug("checking %r %r last=%r", idx, c, last)
                    if c in bc:
                        last = idx
                    elif last is not None:
                        return last
                return last
    else:
        def find_boundary(start, fwd):
            return None

    #chop according to alignment
    if align == "<" or align == "left":
        #put ellipsis on left side, so pick at most {chars}
        #characters from the right side of the string.
        left = tsize-chars
        b = find_boundary(left, True)
        if b is not None:
            left = b #want text[left] to be the boundary char
        result = ellipsis + text[left:]

    elif align == "^" or align == "center":
        #'left' is left end-point
        #'right' is right start-point
        #result is [0:left] ... [right:tsize]
        if mode == "plain":
            #quick simple centering
            left = chars//2
            right = tsize-chars+left
        else:
            #much more tricky... start in center of string,
            #and move left/right until boundaries are large enough.
            left = center = tsize//2
            right = center-1
            left_active = right_active = True
            first = True
            diff = tsize+2-chars
            while left_active and right_active:
                #move left to next boundary
                if left_active:
                    assert left > 0
                    b = find_boundary(left-1, False)
                    if b is None:
                        left_active = False
                    else:
                        left = b
                        left_active = (left > 0)
                #check if we're done
                if not first and right-left<diff:
                   break
                #move right to next boundary
                if right_active:
                    assert right < tsize-1
                    b = find_boundary(right+1, True)
                    if b is None:
                        right_active = False
                    else:
                        right = b
                        right_active = (right < tsize-1)
                #check if we're done
                if right-left < diff:
                    break
                #move boundaries outward again
                first = False
            #check if we failed.
            if right-left < diff:
                #moved out to best boundary we could find,
                #and nothing doing. so fall back to
                #quick simple centering
                left = chars//2
                right = tsize-chars+left
            else:
                left += 1 #so we include left char
        assert left>=0 and left < tsize
        assert right>left and right <= tsize
        assert left+tsize-right <= chars
        result = text[:left] + ellipsis + text[right:]

    #TODO: could have "edge"/"<>" alignment, where center is kept
    else:
        assert align == ">" or align == "right"
        right = chars-1
        b = find_boundary(right, False)
        log.debug("text=%r right=%r b=%r", text, right, b)
        if b is not None:
            right = b
        result = text[:right+1] + ellipsis

    #just a final check
    assert len(result) <= width
    return result

#=========================================================
#text - email
#=========================================================

#regexp for strict checking of local part
#TODO: support backslash escapes, quoted mode
_re_email_local = re.compile(r"""
    ^(
        (
        \w | [-!#$%&'*+/=?^`{|}~.]
        )+
    )$
    """, re.X|re.U)

#regexp for strict checking of domain part
#TODO: support ipv6 in quotes too
_re_email_domain = re.compile(r"""
    ^(
        ## match ip address within brackets (rare but in std)
        \[ [0-2]?\d\d \. [0-2]?\d\d \. [0-2]?\d\d \. [0-2]?\d\d \]
    |
        ## match domain name
        (
            [.-]
            |
            ## note: since \w matches underscore along with alphanum,
            ## we have to use neg-lookahead to prevent underscore from matching
            (?!_) \w
        )+
    )$
    """, re.X|re.U)

_dws_re = re.compile(r"\s{2,}")

def parse_email_addr(value, strict=True, strip=True, allow_empty=False, unquote_name=True, clarify=False):
    """parse email address into constituent parts.

    This function takes a provided email address,
    and splits it into the display name, the local name, and the domain name.
    While this function has a lot of options for controlling precisely
    how it parses email addresses, the basic usage is::

        >>> from bps.unstable import parse_email_addr
        >>> parse_email_addr("joe@bob.com")
        (None, 'joe', 'bob.com')
        >>> parse_email_addr("Joe Smith <joe@bob.com>")
        ('Joe Smith','joe','bob.com')
        >>> parse_email_addr("joe@")
        ValueError: domain part of email address must not be empty: 'joe@'

    :arg value:
        This should be a string containing the email address to be parsed.
        Extranous spaces around the address will be automatically stripped.

    :param strict:
        By default this function is strict, and raises :exc:`ValueError`
        if the local name or domain name violates various email address rules
        (see :func:`validate_email_parts`).

        If ``strict=False``, this function will only throw as :exc:`ValueError`
        only for mismatched ``<>`` around an email, or if the ``@`` is missing.

    :param strip:
        By default, extraneous white space is stripped from the address
        before parsing, and from the parts after they have been parsed,
        to help normalize unpredictable user input. Set ``strip=False`` to disable.

    :param allow_empty:
        By default, an empty string is considered an invalid email.
        If ``allow_empty=True``, passing in an empty string
        will result in the tuple ``(None,None,None)`` being returned.
        This can be detected easily because in all other cases,
        the domain part will be a non-empty string.

    :param unquote_name:
        A common convention is to surround display names in quotes
        (eg ``"John Doe" <jdoe@foo.com>``). By default, this function
        will strip the quotes out, and report the raw name.
        To disable this, set ``unquote_name=False``,
        and the raw name string will be returned.

    :param clarify:
        If enabled via ``clarify=True``, and the address cannot be parsed
        as provided, parse_email_addr will search for obfuscated email address
        features, such as ``@`` being written as ``(at)``, and attempt
        to restore and parse the original address. This is particularly useful
        when standardizing user input.

        This feature is disabled by default, since it may not always
        return the right results.

    :returns:
        This returns a tuple ``(name, local, domain)``:

        * ``name`` contains the display name, or ``None`` if the display name was empty / missing.
        * ``local`` contains the local part of the address (or ``None`` if allow_empty is ``True``).
        * ``domain`` contains the domain part of the address (or ``None`` if allow_empty is ``True``).

    :raises ValueError:
        if the address cannot be parsed as an email address,
        or if the components of the address violate rfc specs
        (see the ``strict`` parameter for more).

    .. note::
        This function (mostly) complies with the relevant rfcs, such as http://tools.ietf.org/html/rfc3696.
        Deviations include:

        * it doesn't support quoted local names (eg ``"John Doe"@foo.com``)
        * it doesn't support backslash escaping in the local name (eg ``User\<\>Name@foo.com``).
        * it allows any alphanumeric unicode/locale defined character, not just a-z, 0-9.

    """
    #initial setup
    if value is None:
        if allow_empty:
            return (None,None,None)
        else:
            raise ValueError, "not a valid email address: %r" % (value,)
    if strip:
        addr = value.strip()
    else:
        addr = value

    #extract name part
    if '<' in addr:
        if addr[-1] != '>':
            raise ValueError, "malformed braces in email address: %r" % (value,)
        name, addr = addr[:-1].rsplit("<",1)
        if strip:
            name = name.strip()
        elif name[-1] == ' ': #at least strip right most space
            name = name[:-1]
        if unquote_name:
            if name.startswith('"') and name.endswith('"'):
                name = name[1:-1]
                if strip:
                    name = name.strip()
            elif name.startswith("'") and name.endswith("'"):
                name = name[1:-1]
                if strip:
                    name = name.strip()
        if not name:
            name = None
        elif strip and '  ' in name:
            name = _dws_re.sub(" ", name)
        if strip:
            addr = addr.strip()
    elif '>' in addr:
        raise ValueError, "malformed braces in email address: %r" % (value,)
    else:
        name = None

    #split local & domain parts
    if not addr and allow_empty:
        return None, None, None
    elif '@' in addr:
        local, domain = addr.rsplit('@',1)
        if strip:
            local = local.rstrip()
            domain = domain.lstrip()
    elif clarify:
        #let's try some alternates
        def helper(addr):
            try:
                result = parse_email_addr(addr, strict=False, strip=True, clarify=False)
                return result[1:3]
            except ValueError:
                return None, None
        while True:
            if '(at)' in addr:
                tmp = re.sub(r"\s*\(at\)\s*","@",addr)
                tmp = re.sub(r"\s*\(dot\)\s*",".",tmp)
                local, domain = helper(tmp)
                if domain:
                    break
            if '[at]' in addr:
                tmp = re.sub(r"\s*\[at\]\s*","@",addr)
                tmp = re.sub(r"\s*\[dot\]\s*",".",tmp)
                local, domain = helper(tmp)
                if domain:
                    break
            if ' at ' in addr:
                tmp = re.sub(r"\s* at \s*","@",addr)
                tmp = re.sub(r"\s* dot \s*",".",tmp)
                local, domain = helper(tmp)
                if domain:
                    break
            raise ValueError, "not a valid email address: %r" % (value,)
    else:
        raise ValueError, "not a valid email address: %r" % (value,)

    #validate parts and return
    validate_email_parts(name, local, domain, strict=strict, _value=value)
    return name, local, domain

def validate_email_parts(name, local, domain, strict=True, _value=None):
    """validates the three components of an email address (``Name <local @ domain>``).

    :arg name: the display name component, or ``None``.
    :arg local: the local part component
    :arg domain: the domain part component

    :param strict:
        By default, this function checks that the parts conform to the rfc,
        and don't contain any forbidden characters or character sequences.

        By default this function is strict, and raises :exc:`ValueError`
        if the local name or domain name contain invalid characters;
        contain invalid character sequences (such as ".."); or
        if the address violates various email part size rules.

        If ``strict=False``, the only checks made are that local & domain
        are non-empty strings.

    :param _value:
        Override the value that's displayed in error messages.
        This is mainly used internally by :func:`parse_email_address`.

    :returns:
        ``True`` on success; raises ValueError upon failure.
    """
    if _value is None:
        _value = (name,local,domain)

    if not local:
        raise ValueError, "empty local part in email address: %r" % (_value,)
    if not domain:
        raise ValueError, "empty domain part in email address: %r" % (_value,)
    if not strict:
        return True

    if not _re_email_local.match(local):
        raise ValueError, "invalid characters in local part of email address: %r" % (_value,)
    if '..' in local or local[0] == '.' or local[-1] == '.':
        raise ValueError, "invalid periods in local part of email address: %r" %(_value,)

    #XXX: split into is_valid_hostname?
    if not _re_email_domain.match(domain):
        raise ValueError, "invalid characters in domain part of email address: %r" % (_value,)
    if '..' in domain or domain[0] == '.':
        raise ValueError, "invalid periods in domain part of email address: %r" %(_value,)
    if domain[0] == '-' or domain[-1] == '-' or '-.' in domain or '.-' in domain:
        raise ValueError, "invalid hyphens in domain part of email address: %r" %(_value,)
    ##if len(domain) < (3 if domain[-1] == '.' else 2):
    ##    raise ValueError, "domain part of email address is too small: %r" % (value,)

    if len(local) > 64:
        raise ValueError, "local part of email address is too long: %r" % (_value,)
    if len(domain) > 255:
        raise ValueError, "domain part of email address is too long: %r" % (_value,)

    return True

def compile_email_addr(name, local, domain, strict=True, quote_name=True):
    """return formatted email address.

    this function takes the components of an email address,
    and formats them correctly into a single string,
    after validating them.

    :arg name: the display name component, or ``None``.
    :arg local: the local part component
    :arg domain: the domain part component

    :param strict:
        whether strict validation is enabled
        (see :func:`validate_email_parts`)

    :param quote_name:
        whether the name part is automatically
        put inside double-quotes when formatting.

    :returns:
        email address as single string.
    """
    validate_email_parts(name, local, domain, strict=strict)
    if name:
        if quote_name:
            ##if '"' in name:
            ##    name = name.replace('"',"'")
            return '"%s" <%s@%s>' % (name,local,domain)
        else:
            return '%s <%s@%s>' % (name,local,domain)
    else:
        return '%s@%s' % (local,domain)

def norm_email_addr(value, strict=True, allow_empty=False, quote_name=True, clarify=False):
    """normalize email address string.

    This uses :func:`parse_email_addr` and :func:`compile_email_addr`
    in order to parse, validate, normalize, and reassemble
    any email address passed into it.

    :arg value: raw email address
    :param strict:
        whether strict checking of email format is enabled
        (see :func:`validate_email_parts`).
    :param allow_empty:
        By default, empty strings will cause a :exc:`ValueError`.
        If ``True``, empty strings will be returned as ``None``.
    :param quote_name:
        By default, the name portion will have double-quotes
        added around it if they are missing.
        Set to ``False`` to preserve original name.

    :returns:
        normalized email address, with extraneous spaces removed;
        or raises ValueError if address was invalid.
    """
    n,l,d = parse_email_addr(value,
                strict=strict,
                strip=True,
                allow_empty=allow_empty,
                unquote_name=quote_name,
                clarify=clarify,
                )
    if d is None:
        assert allow_empty
        return None
    return compile_email_addr(n,l,d, strict=False, quote_name=quote_name)

#=========================================================
#functional code
#=========================================================

##class compose(object):
##    """
##    function composition
##
##    usage:
##        fc = compose(f0, f1, ... fn)
##        assert fc(*a,**k) == f0(f1(...fn(*a,**k))
##    """
##    def __new__(cls, *funcs):
##        #calc true content from funcs
##        assert isinstance(funcs, tuple)
##        content = []
##        for func in funcs:
##            assert callable(func)
##            if func == IdentityFunc:
##                #this one should be ignored.
##                continue
##            if isinstance(compose):
##                content += compose.func_seq
##            else:
##                content.append(func)
##        #return appropiate object based on content
##        if len(content) == 0:
##            return IdentityFunc
##        elif len(content) == 1:
##            #no need to compose
##            return content[0]
##        else:
##            #build compose object
##            self = object.__new__(cls)
##            content.reverse()
##            self.func_seq = tuple(content)
##            return self
##
##    def __call__(self, *args, **kwds):
##        gen = iter(self.func_seq)
##        result = gen.next()(*args,**kwds)
##        for fn in gen:
##            result = fn(result)
##        return result

##_NameCount = {}
##def composeClass(bases, name=Undef, kwds=None):
##    """
##    returns a new class built out of the bases provided.
##    given bases = [b1, b2, b3],
##    the resulting class expects arguments in the form of...
##
##    cls( a1, a2, a3)
##        where aN are all tuples, dicts, or ArgKwds.
##        only the first contructor b1.__new__(*args,**kwds) from a1
##        each bN.__new__(*args,**kwds) from aN
##
##    xxx: not done with this!
##    """
##    global _NameCount
##
##    initseq = []
##    for pos, base in enumerate(bases):
##        for i, cls in initseq:
##            if issubclass(base,cls):
##                break
##        else:
##            initseq.append((pos,base))
##
##    def newfn(cls, *aks):
##        return cls.__bases__[0].__new__(aks[0])
##
##    def initfn(self, *aks):
##        for pos, cls in initseq:
##            if pos > len(aks):
##                args = []
##                kwds = {}
##            else:
##                ak = aks[pos]
##                if isinstance(ak, tuple):
##                    args = ak
##                    kwds = {}
##                elif isinstance(ak, dict):
##                    args = []
##                    kwds = ak
##                else:
##                    args, kwds = ak.args, ak.kwds
##            cls.__init__(*args, **kwds)
##    outkwds = {"__new__":newfn, "__init__": initfn}
##    if kwds:
##        outkwds.update(kwds)
##
##    if name is Undef:
##        name = "_comp_".join([cls.__name__ for cls in bases])
##    count = _NameCount[name] = _NameCount.get(name,0)+1
##    if count > 1:
##        name += "_%d" % (count,)
##
##    return type(name,bases,outkwds)

#=========================================================
#fs/env related
#=========================================================
@contextlib.contextmanager
def protected_env(*keys, **opts):
    "context manager which restores cwd & specified environment keys"
    cwd = opts.pop("cwd", False)
    if opts:
        raise TypeError, "unknown kwd options: %r" % (opts,)
    if cwd:
        c = getcwd()
        assert c.isabs
    if keys:
        env = os.environ
        o = dict((k,env.get(k)) for k in keys)
    f = [] #list of files to purge
    try:
        yield f
    finally:
        for name in f:
            filepath(name).discard()
        if cwd:
            c.chdir()
        if keys:
            for k, v in o.iteritems():
                if v is None:
                    if k in env:
                        del env[k]
                else:
                    env[k] = v

#=========================================================
#unused fs code that might be useful in the future
#=========================================================

##def getDir(path, separator="\x00"):
##  return join(separator, os.path.listdir(path))

##def getDirHash(path):
##  return sha.new(getDir(path)).digest()

##def getUrl(url, **kwds):
##  """getUrl(url, **kwds) -> str
##  wrapper for urllib, behaves like getFile.
##  keyword args translated to cgi params.
##  uses 'post' method.
##  xxx: swallows all exceptions
##  """
##  try:
##      if len(kwds):
##          fh = urllib.urlopen(url, urllib.urlencode(kwds))
##      else:
##          fh = urllib.urlopen(url)
##  except:
##      return None
##  try:
##      return fh.read()
##  finally:
##      fh.close()

##def getModUrl(srcUrl, tick=None, rawDate=False, dateFmt="%a, %d %b %Y %H:%M:%S %Z"):
##  """
##  ok, data, tick = getModUrl(url,tick=None)
##  """
##  print srcUrl, tick
##  if tick is None:
##      fh = urllib2.urlopen(srcUrl)
##  else:
##      if isinstance(tick, (int,float,long)):
##          tick = time.strftime(dateFmt,time.gmtime(tick))
##      try:
##          fh = urllib2.urlopen(
##              urllib2.Request(srcUrl,None,{'If-Modified-Since': tick})
##              )
##      except urllib2.HTTPError, e:
##          if e.code == 304: # not modified
##              return False, None, tick
##          else:
##              raise e
##  data = fh.read()
##  tick = fh.headers['Last-Modified']
##  if not rawDate:
##      tick = time.mktime(time.strptime(tick, dateFmt))
##  fh.close()
##  return True, data, tick

#=========================================================
#version string parsing - stopgap until PEP386 verlib is in stdlib
#=========================================================
FINAL_MARKER = ('f',)

VERSION_RE = re.compile(r'''
    ^
    (?P<release>
        (?P<version>\d+\.\d+)          # minimum 'N.N'
        (?P<extraversion>(?:\.\d+)*)   # any number of extra '.N' segments
    )
    (?:
        (?P<prerel>[abc]|rc)       # 'a'=alpha, 'b'=beta, 'c'=release candidate
                                   # 'rc'= alias for release candidate
        (?P<prerelversion>\d+(?:\.\d+)*)
    )?
    (?P<postdev>
        (?: \.post (?P<post>\d+) )?
        (?: \.dev (?P<dev>\d+) )?
    )?
    $''', re.VERBOSE)

def main_version(verstr, str=False):
    "return version as ``(major,minor)`` tuple"
    version = parse_version(verstr)[0][:2]
    if str:
        return "%d.%d" % version
    else:
        return version

def release_version(verstr, str=False):
    "return version+extraversion as ``(major,minor,...)`` tuple"
    version = parse_version(verstr)[0]
    if str:
        return ".".join(str(n) for n in version)
    else:
        return version

def get_module_release(modname, str=False):
   "return release version given module name"
   mod = get_module(modname)
   return release_version(mod.__version__, str=str)

def parse_version(verstr):
    "parse version into parts per PEP386"
    match = VERSION_RE.search(verstr)
    if not match:
        raise ValueError, "version string doesn't conform to PEP386: %r" % (verstr,)
    groups = match.groupdict()

    def parse_numdots(s, minsize=0):
        assert minsize >= 0
        nums = []
        for n in s.split("."):
            if len(n) > 1 and n.startswith("0"):
                raise ValueError("cannot have leading zero in version string segment: %r in %r" % (n, verstr))
            nums.append(int(n))
        if len(nums) > minsize:
            while len(nums) > minsize and nums[-1] == 0:
                nums.pop()
        elif len(nums) < minsize:
            nums.extend([0] * (minsize-len(nums)))
        assert len(nums) >= minsize
        return nums

    # main version
    block = tuple(parse_numdots(groups['release'], 2))
    parts = [block]

    # prerelease
    prerel = groups.get('prerel')
    if prerel:
        block = [prerel] + parse_numdots(groups['prerelversion'], 1)
        parts.append(tuple(block))
    else:
        parts.append(FINAL_MARKER)

    # postdev
    if groups.get('postdev'):
        post = groups.get('post')
        dev = groups.get('dev')
        postdev = []
        if post:
            postdev.extend(FINAL_MARKER)
            postdev.extend(['post', int(post)])
            if dev:
                postdev.extend(FINAL_MARKER)
        if dev:
            postdev.extend(['dev', int(dev)])
        parts.append(tuple(postdev))
    else:
        parts.append(FINAL_MARKER)
    return tuple(parts)

#=========================================================
#eof
#=========================================================
