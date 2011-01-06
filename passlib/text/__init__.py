"""bps.text -- useful text manipulation funcs -- (c) Assurance Technologies 2003-2006
"""
#=========================================================
#imports
#=========================================================
#core
import sys
import os.path
import re
from warnings import warn
import logging; log = logging.getLogger(__name__)
#pkg
from bps.types import BaseClass, namedtuple
from bps.meta import abstractmethod, isstr
#local
__all__ = [
    #misc string manipulation
    'condense', 'split_condense',
    'split_at',
    'asbool',

    #inflection helpers
    'countof', 'oneof',
    'pluralize',
    'singularize',

    #capitalization converters
    'lu_to_cc',

    #aliased exports
    "isstr",
]

#some constants used various places
EMPTY = ""
DOT = "."
SPACE = " "
WSCHARS = " \t\n\r"

#=========================================================
#cleaning up input strings
#=========================================================
_cleaner_re = re.compile("\s+")
_re_cache = {} #cache of regexps we've compiled for various char sets

def condense(value, chars=None):
    """Strips leading & trailing whitespace, reduces internal whitespace chunks to a single space.

    This function is an enhanced version of ``str.strip()``,
    which takes care of reducing duplicate internal whitespace as well.
    This is primarily useful when normalizing user input.

    :arg value: the string to strip whitespace from
    :param chars:
        String containing characters that should be stripped.
        Internal occurences of any combination of these characters
        will be replaced with the first character in the string.
        If not specified, this defaults to ``" \\t\\n\\r"``.

    :returns: the resulting string

    Some examples::

        >>> from bps.text import condense
        >>> #a simple example, removing whitespace from a provided name
        >>> condense(" john   smithson   jr \\n the third  \\t")
            "john smithson jr the third"
        >>> #a example showing a custom character set
        >>> condense(" 123-465 -0000- 43526  ", " -")
            "123 465 0000 43526"

    """
    global _re_cache, _cleaner_re

    if value is None:
        return None
    elif chars:
        #cache the regexp so we don't have to recompile it next time
        pat = _re_cache.get(chars)
        if pat is None:
            pat = _re_cache[chars] = re.compile("[" + re.escape(chars) + "]+")
        return pat.sub(chars[0], value.strip(chars))
    else:
        #common case is to strip all whitespace, equiv to chars=" \t\r\n"
        return _cleaner_re.sub(SPACE,value.strip())

def split_condense(value, sep=",", empty="keep", chars=None):
    """Split string into list based on separator, and then run :func:`condense` on each element.

    This function is commonly used when parsing user input,
    and a list of values is provided in string form,
    using a predefined separator. The string will be broken
    along the separator, and then any whitespace removed from the elements.

    :arg value: The string to split.
    :param sep:
        The separator to split by.
        this can either be a single string,
        or a list of strings, in which case
        the all elements of the list will
        be considered as possible separators.
    :param empty:
        The policy for empty elements.
        By default, when the string has been split,
        any empty elements will be returned (``empty="keep"``).
        Frequently, the need arises to strip out
        any empty elements (such as happens with a trailing separator).
        To do this, set ``empty="strip"``.
    :param chars:
        This is the list of whitespace characters to strip.
        See :func:`condense` for details of it's behavior.

    :returns: a list of the resulting elements (may be empty)

    Some examples::

        >>> from bps.text import split_condense
        >>> split_condense("a, b,c  , d")
            [ 'a', 'b', 'c', 'd' ]
        >>> split_condense("123; ; 456 ; ", sep=";")
            [ '123', '', '456', '' ]
        >>> split_condense("123; 456 ; ", sep=";", empty="strip")
            [ '123', '456' ]
    """
    assert empty in ("keep", "strip")
    if value is None:
        return [] #XXX: what None policy should we use? treat like ""?

    #NOTE: it would be faster to do the condense first, and .strip() later,
    # but for the case where sep chars are in the strip char list,
    # separators are stripped out too early.

    if isstr(sep):
        result = value.split(sep)
    else:
        #seq of split characters, ala java's split method
        result = [ value ]
        for s in sep:
            source = result
            result = []
            for v in source:
               result.extend(v.split(s))
    if empty == "keep":
        return [ condense(value, chars) for value in result ]
    else:
        assert empty == "strip"
        itr = ( condense(value, chars) for value in result )
        def ff(elem):
            return bool(elem)
        return filter(ff, itr)

def split_at(s, *indexes):
    """split a sequence at an arbitrary number of specified pointers.

    :arg s: string to split
    :arg indexes: list of indexes to act as split points

    Example Usage::
        >>> from bps.text import split_at
        >>> split_at('abc', 1)
            [ 'a', 'bc' ]
        >>> split_at('abcdef', 2, 5)
            ['ab', 'cde', 'f']
    """
    count = len(indexes)
    if count == 0:
        return [ s ]
    elif count == 1:
        return [ s[0:index], s[index:] ]
    else:
        out = []
        last = 0
        for idx in indexes:
            out.append(s[last:idx])
            idx = last
        out.append(s[last:])
        return out

#clean_string - could put all kinds of fancier things here
#   cleaning up names, detecting/cleaning up urls,
#   fixing typos, ???

#=========================================================
#clean_filename - sanitize those filthy external inputs :)
#=========================================================
_dos_path_re = re.compile(r"^[A-Z]+:\\.*?([^\\]*)$", re.I)
_dosnet_path_re = re.compile(r"\\\\.*?([^\\]*)$", re.I)
_posix_path_re = re.compile("^/.*?([^/]*)$")
_badset = set([ EMPTY, SPACE, DOT, '..' ]) #filenames we simply don't allow, ever

def _compile_safe_char(unsafe_chars, safe_char):
    """compile safe_char description into a function which replaces safe chars.

    this function first validates the safe_char input
    so that no unsafe_chars are listed in safe char.
    then, given the format of safe_char, it generates
    a function of the form ``cleaner(unsafe_char) -> safe_replacement_char``.
    """
    #empty string would already work, None would just be too much
##    if safe_char is None:
##        #if safe char is None, we replace unsafe char 'c' with empty string
##        return lambda c: EMPTY
    if isinstance(safe_char, str):
        #if safe char is a str, use it as the replacement (assuming it's safe)
        if safe_char and safe_char in unsafe_chars:
            log.warning("safe_char %r is unsafe: %r", safe_char, unsafe_chars)
            safe_char = EMPTY
        return lambda c: safe_char
    #this option is just too ornate to live...
##    elif isinstance(safe_char, (list, tuple)):
##        #if it's a list, assume it's made of (unsafe_list, replacement_char) elements,
##        #the initial element may be a single string, used as the default element.
##        if not safe_char:
##            return lambda c: EMPTY
##        if isinstance(safe_char[0], str):
##            default = safe_char[0]
##            safe_char = safe_char[1:]
##            if default in unsafe_chars:
##                log.warning("default safe_char %r is unsafe: %r", default, unsafe_chars)
##                default = EMPTY
##        else:
##            default = EMPTY
##        out = {}
##        for chars, alt in safe_char:
##            if alt and alt in unsafe_chars:
##                log.warning("safe_char %r for %r is unsafe: %r", alt, chars, unsafe_chars)
##                continue
##            for c in chars:
##                out[c] = alt
##        return lambda c: out.get(c, default)
    #this option, while not as ornate, disabled until it's needed
    elif isinstance(safe_char, dict):
        #safe_char is a dict mapping unsafe chars to their replacement.
        #the 'default' key (if present) is used for all unsafe chars not found in dict
        if not safe_char:
            return lambda c: EMPTY
        default = safe_char.get("default", EMPTY)
        if default and default in unsafe_chars:
            log.warning("default safe_char %r is unsafe: %r", default, unsafe_chars)
            default = EMPTY
        out = {}
        for chars, alt in safe_char.iteritems():
            if chars == "default":
                continue
            if alt and alt in unsafe_chars:
                log.warning("safe_char %r for %r is unsafe: %r", alt, chars, unsafe_chars)
                continue
            for c in chars:
                out[c] = alt
        return lambda c: out.get(c, default)
    elif callable(safe_char):
        #safe char is a callable which is used directly (with validation that unsafe chars can't slip through)
        def wrapper(c):
            alt = safe_char(c)
            if alt in unsafe_chars:
                log.warning("safe_char %r for %r is unsafe: %r", alt, c, unsafe_chars)
                return EMPTY
            return alt
        return wrapper
    else:
        raise ValueError, "invalid safe_char: %r" % (safe_char,)

def _compile_ext_list(default_filename, ext_list):
    "normalize ext_list, integrating default's extension"
    if ext_list is None:
        return None
    elif isinstance(ext_list, str):
        #parse into list
        ext_list = os.path.normcase(ext_list)
        if ';' in ext_list:
            ext_list = ext_list.split(";")
        elif ':' in ext_list:
            ext_list = ext_list.split(":")
        else:
            ext_list = [ext_list] #assume a single extension
    elif isinstance(ext_list, (list, tuple)):
        ext_list = [ os.path.normcase(elem) for elem in ext_list ]
    else:
        raise ValueError, "invalid ext_list: %r" % (ext_list,)
    assert all(ext == EMPTY or ext.startswith(DOT) for ext in ext_list)
    #put default_filename's ext at beginning, if it's valid at all.
    if default_filename:
        idx = default_filename.rfind(".", 1)
        if idx > -1:
            ext = os.path.normcase(default_filename[idx:])
            if ext in ext_list:
                if ext != ext_list[0]:
                    ext_list.remove(ext)
                    ext_list.insert(0, ext)
            else:
                log.info("default filename's extension not in ext_list: default=%r ext_list=%r",
                    default_filename, ext_list)
    return ext_list

class FileCleaner(BaseClass):
    """Base class implementing routines for cleaning up a filename, used by :func:`clean_filename`.

    Instances of this class will sanitize any filename passed into their ``clean()`` method,
    according to the configuration of the instance.

    New instances may be created from the class, or from existing instances using the ``copy()`` method.

    See :func:`clean_filename` for the details on the various options:
    each of it's keywords corresponds directly to an attribute in this class.
    """
    #=========================================================
    #instance attrs
    #=========================================================
    default_filename = None #default filename to use if the original filename has to be scrapped
    ext_list = None #optional list of extensions which file is limited to,
        #first one is used as the default

    strip_dos_paths = True #remove dir-part of absolute dos paths if detected?
    strip_posix_paths = True #remove dir-part of absolute posix paths if detected?

    unsafe_chars = '\r\n\'"`~!#$&%^*|\\:;<>?/'
        #list of characters considers "unsafe"
        #the default set contains all the common chars which could be
        #potentially dangerous, as they have special meaning in some OS.
    safe_char = "_" #character/dict used to replace any unsafe chars found

    allow_hidden = False #allow hidden files?

    space_char = None #if defined, all spaces are replaced with this character

    #get_safe_char - filled in by init
    #=========================================================
    #framework
    #=========================================================
    def __init__(self, _copy=None, **kwds):
        if _copy:
            self.__dict__.update(_copy.__dict__)
        self.__dict__.update(kwds)
        if not _copy or 'safe_char' in kwds or 'unsafe_chars' in kwds:
            self.get_safe_char = _compile_safe_char(self.unsafe_chars or EMPTY, self.safe_char)
        if not _copy or 'ext_list' in kwds or 'default_filename' in kwds:
            self.ext_list = _compile_ext_list(self.default_filename, self.ext_list)
        if not _copy or 'space_char' in kwds:
            if self.space_char is None:
                self.space_char = SPACE
        if not _copy or 'default_filename' in kwds:
            if self.default_filename:
                self.default_filename = self.clean_extension(self.default_filename)

    def copy(self, **kwds):
        "make a (possibly mutated) copy"
        return FileCleaner(_copy=self, **kwds)

    def __call__(self, filename, **kwds):
        "main frontend"
        if kwds:
            self = self.copy(**kwds)
        return self.clean(filename)

    #=========================================================
    #cleaning
    #=========================================================
    def clean(self, filename):
        "main frontend which is used to clean a filename"
        if not filename:
            return self.default_filename

        #remove absolute paths
        #NOTE: we strip these paths since it's common
        #for them to be present in (for example) cgi form submissions,
        #where they aren't even part of the intended name.
        filename, path_type = self.strip_paths(filename)

        #remove any unsafe characters
        get_safe_char = self.get_safe_char
        for c in self.unsafe_chars:
            if c in filename:
                alt = get_safe_char(c)
                filename = filename.replace(c, alt)

        #replace space_char with SPACE for condense()
        space_char = self.space_char
        if space_char not in (EMPTY, SPACE):
            filename = filename.replace(space_char, SPACE)

        #condense spaces
        hidden = self.allow_hidden and filename.startswith(DOT)
        filename = condense(filename).strip(" .")

        #condense space around path elements
        #FIXME: would like to this path stuff recursively, near strip_paths call
        if path_type == "dos":
            filename = "\\".join(elem.strip() for elem in filename.split("\\"))
            while "\\\\" in filename:
                filename = filename.replace("\\\\", "\\")
        elif path_type == "posix":
            filename = "/".join(elem.strip() for elem in filename.split("/"))
            while "//" in filename:
                filename = filename.replace("//", "/")

        #replace SPACE with space_char
        if space_char != SPACE:
            filename = filename.replace(SPACE, space_char)

        #restore hidden file status if it got stripped
        if hidden and not filename.startswith(DOT):
            filename = DOT + filename

        #don't let forbidden names sneak through
        if filename in _badset:
            return self.default_filename

        #allow only permitted extensions
        return self.clean_extension(filename)

    def strip_paths(self, filename):
        "strip any path-like prefixes if asked, return (filename,detected)"
        m = _dos_path_re.match(filename)
        if m:
            if self.strip_dos_paths:
                filename = m.group(1)
                return filename, None #return 'None' since path is no longer there
            else:
                return filename, "dos"
        m = _dosnet_path_re.match(filename)
        if m:
            if self.strip_dos_paths:
                filename = m.group(1)
                return filename, None #return 'None' since path is no longer there
            else:
                return filename, "dos"
        m = _posix_path_re.match(filename)
        if m:
            if self.strip_posix_paths:
                filename = m.group(1)
                return filename, None
            else:
                return filename, "posix"
        return filename, None

    def clean_extension(self, filename):
        "make sure extension is valid, replacing with alternate if it isn't"
        assert filename

        #check if we have anything to do
        ext_list = self.ext_list
        if ext_list is None:
            return filename

        #check if extension is acceptable
        idx = filename.rfind(".", 1)
        if idx > -1:
            ext = os.path.normcase(filename[idx:])
        else:
            idx = len(filename)
            ext = ""
        if ext in ext_list:
            return filename

        #return filename w/ default extension
        if ext_list:
            return filename[:idx] + ext_list[0]
        else:
            return filename[:idx]

    #=========================================================
    #EOC
    #=========================================================

def _init_cfn_presets():
    "setup initial presets for clean_filename"
    default = FileCleaner()
    return {
        "safe": default,
        "clean": default.copy(
            safe_char=SPACE,
            ),
        "minimal": default.copy(
            unsafe_chars='\r\n\$%\\:;/',
            ),
        "paranoid": default.copy(
            unsafe_chars=default.unsafe_chars + "\x00@()[]{},",
            safe_char=EMPTY,
            space_char="_",
            ),
        #this should work, just commented out 'til usecase is presented
##        "local_path": default.copy(
##            unsafe_chars=default.unsafe_chars.replace(os.path.sep, ""),
##            strip_dos_paths=(os.name != "nt"),
##            strip_posix_paths=(os.name == "nt"),
##            ),
##        "posix_path": default.copy(
##            unsafe_chars=default.unsafe_chars.replace("/", ""),
##            strip_posix_paths=False,
##            ),
        "excel_sheet": default.copy(
            unsafe_chars=default.unsafe_chars + "[]",
            ),
        }
cfn_presets = _init_cfn_presets()

def clean_filename(
        #positional arguments
        filename, default_filename=None, ext_list=None,

        #kwd only arguments
        preset="safe",
        unsafe_chars=None,
        safe_char=None,
        space_char=None,
        allow_hidden=None,
        ):
    """Sanitize the provided filename.

    This function takes in a (unsanitized) filename, and does the following:
        * unsafe characters (such as "&", ":", etc) are removed
        * duplicate whitespace is condensed/stripped
        * special files ("..", ".") are detected and removed entirely
        * file extensions are restricted (optional)
        * ... and more

    Note that this does not operate on file *paths*, only the filename after the separator.
    In particular, it is designed to *remove* any separators, such as when sanitizing
    user-provided filenames in a webform.

    This function is *highly* configurable, with a large number of options.
    However, it is designed to be usable in it's default state, or
    via one of the many presets (see next section). All arguments
    except the filename itself are optional.

    :type filename: str | None
    :arg filename:
            [required, can be positional]
            String containing the potentially filename that should be sanitized.
            ``None`` is treated the same as an empty string.

    :type default_filename: str | None
    :arg default_filename:
            [can be positional]
            String containing the default filename which should be used
            if the provide filename has to be scrapped entirely.

            This is ``None`` by default.

    :type ext_list: str | seq of str | None
    :arg ext_list:
            [can be positional]
            This specifies a list of the validate extensions (case-insensitive)
            which will be allowed for the file. If not specified,
            all extensions will be allowed. If the file's extension
            is not in the list, the first extension in the list will be used.

            All extensions must be specified with a leading dot,
            except for the empty string, which is used to indicate 'no extension'.
            This can be a string containing a single extension, a series of colon/semi-colon separated extensions,
            or a list/tuple containing the extensions. Any inputs
            will be converted to lower-case before use.

            This is ``None`` by default.

    :type preset: str
    :param preset:
            Specifies which preset to load.
            A KeyError will be raised if an unknown preset is specified.

    :type unsafe_chars: str
    :param unsafe_chars:
            This should be a list of characters to consider unsafe,
            and replace with *safe_char*. If all should be considered safe,
            use an empty string.

            The default for this varies between presets.

    :type safe_char: str
    :param safe_char:
            This should be a character that will be used in place of any unsafe characters.
            To remove unsafe characters entirely, specify an empty string.
            This can also be a callable, of the form ``safe_char(c) -> r``,
            which will be called with an unsafe character *c*,
            and should return a string *r* to replace it with.
            This is useful, for example, to escape unsafe characters as hex codes, for recovery.

            This defaults to an underscore.

    :type space_char: str
    :param space_char:
            This will replace all spaces with the specified character.
            By default, this is ``None``, which is the same as keeping
            the normal space character.

    :type allow_hidden: bool
    :param allow_hidden:
            If ``True``, hidden files (those beginning with ``.``) will be allowed.
            Otherwise any leading dots will be stripped (this is the default behavior).

    This function defines a number of preset configurations,
    which can be selected via the ``preset`` keyword. Any additional
    options which are specified will override those set by the preset,
    which merely provides defaults.

    The following presets are available:

        ``safe``
            This is the default preset, which attempts to keep
            as much of the original filename's structure intact,
            while preventing any unsafe characters from getting through.

            To this end, it removes any characters  known to be dangerous
            under Windows, Posix, or MacOS.

            Unsafe characters are replaced by an underscore.

        ``clean``
            This basically the same as the default preset,
            except that unsafe characters are replaced with spaces.
            The result looks much prettier, but the original structure
            of the filename is not preserved, thus making it much harder
            to tell someone was trying to pass in malicious paths
            (hence why this is not the default preset)

        ``paranoid``
            This allows pretty much nothing besides alphanumeric characters,
            removing any unsafe characters entirely, and replacing all spaces
            with underscores.

        ``minimal``
            This leaves most characters alone, except for certain ones
            which are almost guaranteed to cause problems under (at least one of)
            windows or posix, in particular: ``\\/;:$%``.

        ``excel_sheet``
            A special preset designed to allow through only filenames
            which are valid names for an Excel spreadsheet.

    Some Usage Examples::

        >>> from bps.text import clean_filename
        >>> #the default preset is designed to preserve the original name,
        >>> #to make detected hackers easier
        >>> clean_filename("../../../usr/bin/rm -rf")
            "_.._.._usr_bin_rm -rf"
        >>> #but if you just want to get a good clean name...
        >>> clean_filename("../../../usr/bin/rm -rf", preset="clean")
            "usr bin rm -rf"
        >>> #for those who want to feel _really_ safe
        >>> clean_filename("../../../usr/bin/rm -rf &; wget http://hack.tgz", preset="paranoid")
            "usrbinrm_-rf_wget_httphack.tgz"
    """
    #group back into kwds #NOTE: did it like this just for easy param reference in function
    kwds = {}
    if default_filename is not None:
        kwds['default_filename'] = default_filename
    if ext_list is not None:
        kwds['ext_list'] = ext_list
    if unsafe_chars is not None:
        kwds['unsafe_chars'] = unsafe_chars
    if safe_char is not None:
        kwds['safe_char'] = safe_char
    if space_char is not None:
        kwds['space_char'] = space_char
    if allow_hidden is not None:
        kwds['allow_hidden'] = allow_hidden

    #load & run cleaner
    cleaner = cfn_presets[preset]
    return cleaner(filename, **kwds)

#=========================================================
#displaying strings
#=========================================================
#TODO: ellipsize() -- like to do this intelligently
#TODO: ellipsize_block() -- take from medicred.backend.utils, does multiline version
#TODO: might want medicred.backend.utils:decimal_format

#=========================================================
#shell
#=========================================================

#=========================================================
#html utilties
#=========================================================
def html_escape(data):
    "helper function for escaping html strings"
    instr = str(data)
    out = ''
    for c in instr:
        val = ord(c)
        if c == "<":
            out += "&lt;"
        elif c == ">":
            out += "&gt;"
        elif c == "&":
            out += "&amp;"
        elif c in ["\n","\t"]:
            out += c
        elif (val < 32 or val > 127):
            out += "%%%02x" % val
        else:
            out += c
    return out

#=========================================================
#boolean coercion
#=========================================================
basestr = str.__bases__[0]
true_set = set([ 'true', 't', 'yes', 'y', 'on', '1', 'enable'])
false_set = set([ 'false', 'f', 'no', 'n', 'off', '0', 'disable'])
none_set = set([ 'none', 'null', '', 'noval', 'novalue' ])

def asbool(obj, default=None):
    """convert boolean string to boolean value.

    If the input object is a string, it will be coerced
    to one of ``True``, ``False``, or ``None`` based on preset recognized strings...
    spaces & case are ignored.

    If the input object is any other type, it is converted to
    one of ``True`` or False`` via ``bool()``.

    If the resulting value is ``None``, the default value will be
    returned if specified. This allows asbool to chain the default
    of other input source, with ``"none"`` and the like acting
    as a "use the default" option.

    :arg obj: the object to convert to boolean
    :param default: the default value to return if ``obj`` evalutes to ``None``.
    """
    if isinstance(obj, basestr):
        obj = obj.strip().lower()
        if obj in true_set: return True
        if obj in false_set: return False
        if obj in none_set: return default
        raise ValueError, "string is no a recognized boolean constant: %r" % (obj,)
    elif obj is None:
        return default
    else:
        return bool(obj)

#=========================================================
#inflector - inspired by RoR's inflector
#=========================================================
class Inflector(BaseClass):
    "base inflector class, inspired by RoR's inflector, but not as complete"
    #=========================================================
    #subclass attrs
    #=========================================================
    uncountable_words = None #list of uncountable words
    irregular_plurals = None #dict of irregular singular => plural pairs
    irregular_indefinites = None #dict of words w/ irregular indefinite articles

    plural_rules = None #list of (re-pat, re-sub) strings for pluralization
    singular_rules = None #list of (re-pat, re-sub) strings for singularization
    indefinite_rules = None #list of (re-pat, re-sub) strings for indefinite articles

    #the following are (re)built by compile()
    _uncountable_words = None #frozenset of uncountable_words
    _irregular_singulars = None #reverse map of irregular_plurals
    _plural_rules = None #list of re's from irregular_plurals & plural_rules
    _singular_rules = None #list of re's from irregular_plurals & singular_rules

    #=========================================================
    #init
    #=========================================================
    def __init__(self, **kwds):
        self.__super.__init__(**kwds)
        self.compile()

    #=========================================================
    #registry
    #=========================================================
    def compile(self):
        #build set of uncountables
        self._uncountable_words = frozenset(self.uncountable_words)

        #build reverse map for irregular_words
        self._irregular_singulars = dict(
            (v, k) for k, v in self.irregular_plurals.iteritems()
            )

        #compile plural rules
        self._plural_rules = [
            self.compile_rule(source)
            for source in self.plural_rules
            ]

        #compile singular rules
        self._singular_rules = [
            self.compile_rule(source)
            for source in self.singular_rules
            ]

        #compile indefinite rules
        self._indefinite_rules = [
            self.compile_rule(source)
            for source in self.indefinite_rules
            ]

    def compile_rule(self, (pat, sub)):
        pat = re.compile(pat, re.IGNORECASE)
        return pat, sub

    #=========================================================
    #inflectors
    #=========================================================
    def _normalize_word(self, word):
        if word.rstrip() != word:
            raise ValueError, "trailing whitespace not supported"
        word = word.lstrip().lower()
        #strip out everything to left of rightmost separator
        idx = max(word.rfind(sep) for sep in " _-")
        if idx:
            word = word[idx+1:]
        return word

    def is_uncountable(self, noun):
        "test if noun is a known uncountable noun (eg, 'information')"
        return self._normalize_word(noun) in self._uncountable_words

    def countof(self, count, noun, zero="0"):
        """Returns a string representation of a counted number of a given noun (eg "3 cows").

        :param count: the number of *noun* objects
        :param noun: a (countable) noun in singular form.
        :key zero:
            optional keyword to override text
            when count is 0. for example,
            ``countof(0,"goats", zero="no")`` would
            display "no goats" instead of "0 goats".

        :returns: an inflected string

        Some usage examples::

            >>> from bps.text import countof
            >>> countof(3,"cow")
                "3 cows"
            >> countof(1,"larch tree")
                "1 larch tree"
            >> countof(0,"goats")
                "0 goats"
            >> countof(-1,"goats") + " (uhoh!)"
                "-1 goats (uhoh!)"
        """
        if self.is_uncountable(noun):
            warn("countof() called with known uncountable noun: %r" % (noun,))
        if count == 0:
            return "%s %s" % (zero, self.pluralize(noun))
        elif count == 1:
            #NOTE: we assume the singular form was provided
            return "1 " + noun
        else:
            return "%s %s" % (count, self.pluralize(noun))

    @abstractmethod
    def ordinal(self, number, long=False):
        """return ordinal form of number (1st, 2nd, etc).

        :arg number: number to render
        :param long: if true, returns 'first' instead of '1st'
        """

    def oneof(self, noun):
        """returns indefinite article followed by noun (eg: "an allosaur").

        :arg noun: the noun to add the article to.
        :returns: noun with prepending article.

        Some examples::

            >>> from bps.text import oneof
            >>> oneof("cow")
                "a cow"
            >>> oneof("allosaur")
                "an allosaur"

        .. note::
            The english language a/an rules regarding the letter "h"
            are a little hazy, and implemented according to what
            "sounds right" to the BPS programmers.
        """
        if self.is_uncountable(noun):
            warn("oneof() called with known uncountable noun: %r" % (noun,))
            #we'll do this, but it doesn't make much sense, at least in english.
        test = noun.lstrip().lower()
        if not test:
            return ''

        #check for irregular indefinites, preserve case of first letter only
        #NOTE: this is pretty english-specific, as it provides suffixes only
        if test in self.irregular_indefinites:
            return self.irregular_indefinites[test] + " " + noun

        for pat, prefix in self._indefinite_rules:
            match = pat.search(test)
            if match:
                return prefix + " " + noun

        #if no rules matches, use the last prefix
        warn("no rules matches oneof(): %r" % (noun,))
        return self._indefinite_rules[-1][1] + " " + noun

    def pluralize(self, word):
        """Return plural form of singular noun.

        Some examples::

            >>> from bps.text import pluralize
            >>> pluralize("cow")
                "cows"
            >>> pluralize("horse fly")
                "horse flies"

        .. note::
            While it would be nice for this function to be idempotent,
            so that ``pluralize("cows")`` returned ``"cows"``, the english
            language rules are too complex for this to work in a context-free manner.
            It may work for some words, but don't rely on it.
        """
        if not word:
            return ''
        test = self._normalize_word(word)

        #check for uncountable words
        if test in self._uncountable_words:
            return word

        #check for irregular plurals, preserve case of first letter only
        if test in self.irregular_plurals:
            return word[:-len(test)+1] + self.irregular_plurals[test][1:]

        #apply normal plurality rules
        for pat, sub in self._plural_rules:
            match = pat.search(test)
            if match:
                groups = match.groups()
                for k in xrange(len(groups)):
                    #remove any unmatched groups from pattern
                    if groups[k] is None:
                        sub = sub.replace('\\'+str(k+1), '')
                return pat.sub(sub, word)

        #assume it's plural
        return word

    def singularize(self, word):
        """Return single form of plural noun.

        Some examples::

            >>> from bps.text import singularize
            >>> singularize("cows")
                "cow"
            >>> singularize("horse flies")
                "horse fly"

        .. note::
            While it would be nice for this function to be idempotent,
            so that ``singularize("cow")`` returned ``"cow"``, the english
            language rules are too complex for this to work in a context-free manner.
            It may work for some words, but don't rely on it.
        """
        if not word:
            return ''
        test = self._normalize_word(word)

        #check for uncountable words
        if test in self._uncountable_words:
            return word

        #check for irregular singulars, preserve case of first letter only
        if test in self.irregular_plurals:
            return word
        if test in self._irregular_singulars:
            return word[:-len(test)+1] + self._irregular_singulars[test][1:]

        #apply normal plurality rules
        for pat, sub in self._singular_rules:
            match = pat.search(test)
            if match:
                groups = match.groups()
                for k in xrange(len(groups)):
                    #remove any unmatched groups from pattern
                    if groups[k] is None:
                        sub = sub.replace('\\'+str(k+1), '')
                return pat.sub(sub, word)

        #assume it's plural
        return word

    #=========================================================
    #EOC
    #=========================================================

class EnglishInflector(Inflector):
    #XXX: this information was gotten from a source
    #which probably didn't do a very thourough job.
    #should study http://www.csse.monash.edu.au/~damian/papers/HTML/Plurals.html
    #for a replacement

    uncountable_words =  [
        'equipment', 'fish', 'information',
        'money', 'rice',
        'series', 'sheep', 'species',
        'pez',
        ]

    irregular_plurals = {
        'fez': 'fezzes',
        'child' : 'children',
        'goose': 'geese',
        'louse': 'lice',
        'mouse': 'mice',
        'move' : 'moves',
        'ox': 'oxen',
        'quiz': 'quizzes',
        'sex' : 'sexes',
        'woman': 'women',
        'fetus': 'fetuses',
        'loaf': 'loaves',
        }

    plural_rules = [
        ['(person)$', 'people' ], #irregular root
        ['(man)$', 'men' ], #irregular root
        ['(matr|vert|ind)ix|ex$' , '\\1ices'],
        ['(x|ch|ss|sh)$' , '\\1es'],
##        ['([^aeiouy]|qu)ies$' , '\\1y'], #does this belong here?
        ['([^aeiouy]|qu)y$' , '\\1ies'],
        ['(hive)$' , '\\1s'],
        ['([^f])fe$', '\\1ves'],
        ['([lr])f$', '\\1ves'],
        ['sis$' , 'ses'],
        ['([ti])um$' , '\\1a'],
        ['(buffal|tomat)o$' , '\\1oes'],
        ['(bu)s$' , '\\1ses'],
        ['(alias|status)$' , '\\1es'],
        ['(octop|vir)us$' , '\\1i'],
        ['(ax|test)is$' , '\\1es'],
        ['s$' , 's'],
        ['$' , 's']
    ]

    singular_rules = [
        ['(people)$', 'person' ], #irregular root
        ['(men)$', 'man' ], #irregular root
        ['(matr)ices$' , '\\1ix'],
        ['(vert|ind)ices$' , '\\1ex'],
        ['(alias|status)es$' , '\\1'],
        ['([octop|vir])i$' , '\\1us'],
        ['(cris|ax|test)es$' , '\\1is'],
        ['(shoe)s$' , '\\1'],
        ['(o)es$' , '\\1'],
        ['(bus)es$' , '\\1'],
        ['([ml])ice$' , '\\1ouse'],
        ['(x|ch|ss|sh)es$' , '\\1'],
        ['(m)ovies$' , '\\1ovie'],
        ['(s)eries$' , '\\1eries'],
        ['([^aeiouy]|qu)ies$' , '\\1y'],
        ['([lr])ves$' , '\\1f'],
        ['(tive)s$' , '\\1'],
        ['(hive)s$' , '\\1'],
        ['([^f])ves$' , '\\1fe'],
        ['(^|\W)(analy)ses$', '\\1\\2sis'],
        ['((a)naly|(b)a|(d)iagno|(p)arenthe|(p)rogno|(s)ynop|(t)he)ses$' , '\\1\\2sis'],
        ['([ti])a$' , '\\1um'],
        ['(n)ews$' , '\\1ews'],
        ['s$' , ''],
    ]

    irregular_indefinites = {}
    indefinite_rules = [
        #general rule.. all vowels + 'h', unless the vowel/h is soft
        ['^hour', 'an'],  #soft H (the exception) uses an
        ['^h', 'a'],  #the basic h rule uses 'a'
        ['^uni',      'a'], #soft vowel exceptions use 'a' not 'an'
        ['^[aeiuo]',    'an'], #the basic vowel rule uses 'an'
        ['.',           'a'], #the catchall for everything else uses 'a'
        ]

    _ord_map = {
        0: "th",
        1: "st",         2: "nd",         3: "rd",
        4: "th",         5: "th",         6: "th",
        7: "th",         8: "th",         9: "th",
        }
    def ordinal(self, number, long=False):
        if number < 1:
            raise ValueError, "ordinal numbers must be >= 1: %r" % (number,)
        if long:
            raise NotImplementedError, "should get to this someday"
        return "%d%s" % (number, self._ord_map[number % 10])
    ordinal.__doc__ = Inflector.ordinal.__doc__

#---------------------------------------------------
#build a default inflector for easy shortcuts
#---------------------------------------------------
#TODO: have a way to specify language etc

default_inflector = EnglishInflector()

def pluralize(word):
    return default_inflector.pluralize(word)
pluralize.__doc__ = default_inflector.pluralize.__doc__

def singularize(word):
    return default_inflector.singularize(word)
singularize.__doc__ = default_inflector.singularize.__doc__

def countof(count, noun, zero="0"):
    return default_inflector.countof(count,noun,zero=zero)
countof.__doc__ = default_inflector.countof.__doc__

def oneof(noun):
    return default_inflector.oneof(noun)
oneof.__doc__ = default_inflector.oneof.__doc__

def ordinal(noun):
    return default_inflector.ordinal(noun)
ordinal.__doc__ = default_inflector.ordinal.__doc__

#=========================================================
#other inflection-related stuff
#=========================================================
#TODO: this could be made MUCH more flexible,
# much more reliable, etc.

_lu_re = re.compile("(^|_)(.)")
def lu_to_cc(value):
    """convert variable lowercase w/ underscore (lu) -> camel case (cc).

    :raises ValueError: when input is not in lu format.

    for example::
        >>> from bps.text import lu_to_cc
        >>> lu_to_cc("my_variable_name")
            "MyVariableName"
    """
    if value.lower() != value:
        raise ValueError, "input value is not in LU format: %r" % (value,)
    def rf(m):
        return m.group(2).upper()
    return _lu_re.sub(rf, value)

#TODO: cc_to_lu()

#FIXME: _really_ wish the re module has a lower-case and upper-case wildcard
_cc_re = re.compile("(^|[a-z0-9])([A-Z])")
def cc_to_lu(value):
    #FIXME: this is a quick hack, probably fails in some cases.
    def func(m):
        a, b = m.group(1, 2)
        if a:
            return "%s_%s" % (a, b.lower())
        else:
            return b.lower()
    return _cc_re.sub(func, value)

#=========================================================
#string format examination
#=========================================================

FormatElement = namedtuple('TemplateElement','text field spec conv')

#----------------------------------------------------
#bps has a pure-python implementation of PEP3101,
#which should be used only if native isn't available.
#
#this imports the native or backport versions of "format"
#and "Formatter" if possible.
#
#also, this defines a publically visible set of functions
#for parsing fmt strings.
#----------------------------------------------------
if sys.version_info > (2, 6):
    #running under >= py26, can use native support

    from __builtin__ import format
    from string import Formatter

    def render_format(format_string, *a, **k):
        return format_string.format(*a, **k)

    def parse_fmt_string(format_string):
        #TODO: support resolution of embedded templates?
        for elem in format_string._formatter_parser():
            yield FormatElement(*elem)

    def parse_fmt_field(field_name):
        return field_name._formatter_field_name_split()

    def _get_field_head(field_name):
        return field_name._formatter_field_name_split()[0]

else:
    #use pure-python implementation
    from bps.text._string_format import format, Formatter, \
        _parse_template, _parse_field_name, _formatter

    def render_format(format_string, *args, **kwds):
        return _formatter.format(format_string, *args, **kwds)

    def parse_fmt_string(format_string):
        #TODO: support resolution of embedded templates?
        for elem in _parse_template(format_string):
            yield FormatElement(*elem)

    def parse_fmt_field(field_name):
        #TODO: support resolution of embedded templates?
        return _parse_field_name(field_name)

    def _get_field_head(field_name):
        return _parse_field_name(field_name)[0]

render_format.__doc__ = """renders a format string.

This uses the native string format method if available.
"""

parse_fmt_string.__doc__ = """iterates over the elements
of a {} format template.

Each element returned by the iterator will be a namedtuple of the form::

    (text, field, spec, conv)

Where the elements are defined as follows:

    text
        This will be a (possible empty) string
        containing all the text which came before
        the format directive.

    field
        This will be the name of the field, containing
        any item or attribute accessors. This can
        be parsed by :func:`parse_fmt_field`.
        If the format string has trailing text,
        the last element returned will have ``None`` for the field.

    spec
        The format specifier for the field,
        suitable for passing into the :func:`format` function.
        This is a (possibly empty) string.
        If the format string has trailing text,
        the last element returned will have ``None`` for the spec.

    conv
        Option conversion specifier ("r" or "s"),
        ``None`` if not present.

If any parsing errors occur, a :exc:`ValueError` will be raised.

.. note::
    This function is simply a wrapper for native implementation (if available),
    but under Python 2.5 a pure-python implementation is provided.
"""

parse_fmt_field.__doc__ = """Parses field name as returned by :func:`parse_fmt_string`.

The return value will be a tuple of ``(head, tail)``
where ``head`` is the int / string of the template argument / key to start with,
and ``tail`` is a list of ``(is_attr,value)`` tuples.

.. note::
    *value* may contain embedded template strings.
"""

#----------------------------------------------------
#quick testing
#----------------------------------------------------
def _iter_fmt_fields(format_string):
    stack = [format_string]
    while stack:
        fmt = stack.pop()
        if not fmt:
            continue
        for elem in parse_fmt_string(fmt):
            #XXX: detect and handle "{} {} {}" style fields
            #XXX: should this honor & raise recursion error when >2 deep?
            if elem.field:
                head, tail = parse_fmt_field(elem.field)
                yield head
                for attr, name in tail:
                    if name:
                        stack.append(name) #for nested fields
            if elem.spec:
                stack.append(elem.spec) #for nested fields

def fmt_has_field(format_string, key):
    "check if string references specified field name"
    return any(key == elem for elem in _iter_fmt_fields(format_string))

def get_fmt_fields(format_string):
    "return set of position arguments and keywords referenced in format string"
    return set(_iter_fmt_fields(format_string))

#=========================================================
#EOF
#=========================================================
