"""bps3.fs -- filesystem interaction -- (c) Assurance Technologies 2003-2009

See bps documentation for information about this module.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from collections import deque
import codecs
##import mmap
import stat
import errno as _errno
import os, sys, time
from os.path import curdir as _CURDIR, pardir as _PARDIR, \
    sep as _SEP #cause we access these A LOT
import struct
import sys
import logging
log = logging.getLogger(__name__)
import shutil
import threading
from warnings import warn
import hashlib
#pkg
from bps.meta import is_seq
from bps.types import Undef
from bps.refs import SoftValueDict
from bps.warndep import deprecated_method, deprecated_function, relocated_function, deprecated_property
from bps.error import types as errors
#module

__all__ = [
    #filepath
    "filepath",
    "is_filepath",
    "getcwd", "setcwd",

        #deprecated
        "getFile", "setFile",
        "curpath",

    #perms
    'parse_mode_mask', 'repr_mode_mask',
    'chmod',
    'setumask', 'getumask',

    #shortcuts
    'is_shortcut', 'read_shortcut',

    #misc
    'posix_to_local', 'local_to_posix',

    #constants
    'os_has_symlinks',
    'os_has_shortcuts',

]

#some quick constants
os_has_symlinks = hasattr(os, "symlink")
os_has_shortcuts = (os.name == "nt") #note that bps can resolve shortcuts under any os

#all known filetypes ('link' only returned by path.lfiletype, not path.filetype)
ALL_FILETYPES = [ 'missing', 'link', 'file', 'dir', 'char', 'block', 'fifo', 'socket', 'unknown']

#all filetypes we can set perms on
PERM_FILESTYPES = ['file', 'dir', 'char', 'block', 'fifo', 'socket']

#=========================================================
#dry run support
#=========================================================

#TODO: implement dry run support via a global context manager,
# such that a single flag in this module can disable all filepath operations.
_wet_run = True

#=========================================================
#main functions
#=========================================================
_fp_cache = SoftValueDict(expire=300, flush=150) #cache of existing filepaths, keyed by str
_fp_lock = threading.Lock() #lock for cache access

def filepath(src, *parts):
    """Return :class:`FilePath` instance representing a local file path.

    Input can be any number of positional arguments,
    made of a mix of strings and :class:`FilePath` instances.
    They will all be joined together using the local path separator,
    and then a :class:`FilePath` instance returned representing that path.

    This function maintains an internal cache, so that successive calls
    for the same path should result in the same object. Thus, this is
    the preferred way to create :class:`FilePath` instances.

    Usage::

        >>> from bps3 import *
        >>> #simple example
        >>> path = filepath("/home")
        >>> filepath("/home") is path #multiple calls should return same object
        True
        >>> path.isabs
        True
        >>> path.listdir()
        [ 'joe', 'bob', 'sue', 'ftp', 'elic' ]
        >>> #example with multiple arguments
        >>> path = filepath(path, "elic", "dev")
        >>> path
        '/home/elic/dev'

    .. note::
        the ``None`` value is treated as a special case,
        such that ``filepath(None)`` will return ``None`` unchanged.

    .. seealso::
        :func:`is_filepath`
        :class:`FilePath`
    """
    #join all args together...
    if parts:
        src = os.path.join(src, *parts)

    #just return unchanged None or any FilePath instances
    if src is None or isinstance(src, FilePath):
        return src

    #coerce to string
    #FIXME: treat unicode right!
    if not isinstance(src, str):
        src = str(src)

    #get instance from cache, or create new one
    global _fp_cache, _fp_lock
    _fp_lock.acquire()
    try:
        cache = _fp_cache
        if src in cache:
            return cache[src]
        cache.flush() #HACK: forget about old instances so memory doesn't get too big
        obj = cache[src] = FilePath(src)
        return obj
    finally:
        _fp_lock.release()

#=========================================================
#main class -- should only be called via filepath() function
#=========================================================
class FilePath(str):
    """Instances of this class represent a path on the host filesystem.

    This class wraps the :class:`str`, and instances of this class should
    be usable everywhere a string would be. Without breaking compatibility
    with the string object, this class provides a wide variety of methods
    and attributes for interacting with the local filesystem.

    Instances should not be created directly from this class,
    but through the :func:`filepath` constructor function.
    See that function for more usage examples.

    Unless otherwise noted, attributes which one might expect to return
    strings will always return :class:`FilePath` instances.

    What follows is all the methods and attributes of this class,
    grouped by category:

        * :ref:`Path Properties <bps-fs-filepath-path-properties>`
        * :ref:`Path Components <bps-fs-filepath-path-components>`
        * :ref:`Derived Paths <bps-fs-filepath-derived-paths>`
        * :ref:`Filesystem Properties <bps-fs-filepath-filesystem-properties>`
        * :ref:`Filesystem Manipulation <bps-fs-filepath-filesystem-manipulation>`
        * :ref:`Symlink Manipulation <bps-fs-filepath-symlink-manipulation>`
        * :ref:`Directory Manipulation <bps-fs-filepath-directory-manipulation>`
        * :ref:`File Manipulation <bps-fs-filepath-file-manipulation>`

    ..
        Also, most attributes can be accessed via a method of the same
        name as the attribute, just with a "get" prefix, eg ``path.getdir()``
        instead of ``path.dir``. For attributes which are writeable,
        there should also be a corresponding ``path.setdir

    Path Properties
    ===============

    .. attribute:: isnorm

        ``True`` if path is already normalized, otherwise ``False``.
        This is equivalent to ``path == path.normpath``, but faster.
        See :func:`os.path.normpath` for details of what normalization entails.

    .. attribute:: isabs

        ``True`` if path is absolute, otherwise ``False`` for relative paths.
        This wraps :func:`os.path.isabs`.

    .. attribute:: isrel

        ``True`` if path is relative (to current working directory),
        otherwise ``False``. This will always be the opposite of ``path.isabs``.
        This wraps :func:`os.path.isabs`.

    .. attribute:: iscanon

        ``True`` if path is the canonical path to a resource, otherwise ``False``.
        See :attr:`canonpath` for details.

    Path Components
    ===============

    Every filepath is composed of a number of parts, and the following
    attributes allow quick access to the desired part of a path's anatomy.
    A simple diagram of the parts of a path::

          path = "/home/eric/test.png"
                  \________/x\______/
                  |  dir     | name |        path.dir  == "/home/eric"
                  |          |      |        # x -- separator not included in dir *or* name
                  |          |      |        path.name == "test.png"
                  |          \__/\__/
                  |          root ext        path.root == "test"
                  |             |            path.ext  == ".png"
                  \_____________/
                       base                  path.base == "/home/eric/test"

    .. attribute:: dir

        This returns all of the filepath up
        to (but not including) the last path separator.
        For example, ``filepath("/home/eric/test.png").dir`` would return ``'/home/eric'``.

    .. attribute:: name

        This returns all the filepath *after* the last path separator.
        For example, ``filepath("/home/eric/test.png").dir`` would return ``'test.png'``.
        It should always be true that ``filepath(dir_part,name_part)`` returns the original path.

    .. attribute:: ext

        This returns the filetype extension portion of the *name*.
        For example, ``filepath("/home/eric/test.png").dir`` would return ``'.png'``.

    .. attribute:: root

        This returns the root part of the *name*, excluding the extension.
        For example, ``filepath("/home/eric/test.png").root`` would return ``'test'``.
        It should always be true that ``root_part + ext_part`` returns the original name attribute.

    .. attribute:: base

        This returns the *dir* plus the *root* of the filename.
        In other words, it returns the full path, but without the file extension (if any).
        For example, ``filepath("/home/eric/test.png").base`` would return ``'/home/eric/test'``.

    Derived Paths
    =============

    The following paths can be derived from a given filepath,
    via common attributes and methods:

    .. autoattribute:: parentpath
    .. autoattribute:: normpath
    .. autoattribute:: abspath
    .. autoattribute:: canonpath

    .. automethod:: getabspath
    .. automethod:: getrelpath
    .. automethod:: expand
    .. automethod:: samepath

    Filesystem Properties
    =====================
    .. autoattribute:: exists
    .. autoattribute:: isfile
    .. autoattribute:: isdir
    .. autoattribute:: islink
    .. autoattribute:: ismissing
    .. autoattribute:: ismount

    .. autoattribute:: filetype
    .. automethod:: getfiletype

    .. autoattribute:: atime
    .. autoattribute:: ctime
    .. autoattribute:: mtime
    .. autoattribute:: size
    .. autoattribute:: linecount
    .. autoattribute:: dircount

    Filesystem Manipulation
    =======================
    .. automethod:: chdir
    .. automethod:: touch

    .. automethod:: remove
    .. automethod:: discard
    .. automethod:: clear

    .. automethod:: copy_to
    .. automethod:: move_to

    Symlink Manipulation
    ======================
    .. autoattribute:: lexists
    .. autoattribute:: ltarget
    .. automethod:: mklink
    .. seealso::
            :attr:`islink`

    Directory Manipulation
    ======================
    .. automethod:: listdir
    .. automethod:: iterdir

    .. automethod:: mkdir
    .. automethod:: makedirs
    .. automethod:: ensuredirs
    .. automethod:: removedirs

    File Manipulation
    =================
    .. automethod:: open
    .. automethod:: get
    .. automethod:: set

    .. todo::

        others part of object that aren't officially added yet:

        .. autoattribute:: joinsep
        .. autoattribute:: splitdir
        .. autoattribute:: splitext

        .. autoattribute:: md5

        .. autoattribute:: mode
        .. autoattribute:: modestr

    """
    #=========================================================
    #init
    #=========================================================

    def __init__(self, path):
        #init attrs
        str.__init__(self)
        self._path = path

        #set invariant components
        self._dir, self._name = os.path.split(self)
        self._root = os.path.splitext(self._name)[0]
        self._base, self._ext = os.path.splitext(self)
        self._normpath = os.path.normpath(self)

        #set invariant properties
        #TODO: should lock these so they can't be changed publically
        self.isnorm = (self == self._normpath)
        self.isabs = os.path.isabs(self)
        self.isrel = not self.isabs

    def __str__(self):
        return self._path

    #=========================================================
    #path properties
    #=========================================================
    #NOTE: all these are filled in by the __init__ method
    #FIXME: these should really be readonly
    _path = None
    isnorm = None
    isabs = None
    isrel = None

    #is path relative to cwd?
    def getisrel(self): return self.isrel

    #is path relative to host?
    def getisabs(self): return self.isabs

    #is path normalized?
    def getisnorm(self): return self.isnorm

    #is path canonical?
    def getiscanon(self): return self == self.canonpath
    iscanon = property(getiscanon)

    #=========================================================
    #posix/url <-> local separator convention
    #=========================================================
    #NOTE: these should only be used for relative paths,
    #since abs paths may have drive prefix, etc, which won't be translated correctly
    #commented out until needed
##    if os.path.sep == '/':
##        def posix_to_local(self):
##            return self
##        def local_to_posix(self): #not strictly a "path" anymore
##            return self
##    else:
##        def posix_to_local(self):
##            return filepath(self.replace("/", os.path.sep))
##        def local_to_posix(self): #not strictly a "path" anymore
##            return filepath(self.replace(os.path.sep,"/"))

##    if os.path.sep == '/':
##        def to_posix(self):
##            "Returns filepath as a posix-style string"
##            return self._path
##    else:
##        def to_posix(self):
##            "Returns filepath as a posix-style string"
##            return self._path.replace(os.path.sep, "/")

    #=========================================================
    #path components
    #=========================================================

    #directory component of path
    def getdir(self): return filepath(self._dir)
    dir = property(getdir)

    #name of path inside parent directory
    def getname(self): return filepath(self._name)
    name = property(getname)

    #file extension of path
    def getext(self): return filepath(self._ext)
    ext = property(getext)

    #root of pathname -- ie, full path sans the file extension
    def getbase(self): return filepath(self._base)
    base = property(getbase)

    #root of filename -- ie, basename sans the file extension
    def getroot(self): return filepath(self._root)
    root = property(getroot)

    #=========================================================
    #derived paths
    #=========================================================

    #parent directory of path
    #XXX: should this be renamed to parpath / parentpath?
    def getparentpath(self):
        """Returns this path's normalized parent directory.

        Unlike the *dir* attribute,   which returns the literal
        portion of the specified path, this attribute attempts
        to always return a valid path indicating the parent directory,
        even in cases where that information is not explicitly coded
        into the path.
        """
        path = self._path
        if not path:
            return _CURDIR #special case the empty string
        #just add PARDIR to end and normalize
        return filepath(os.path.normpath(os.path.join(self._path, _PARDIR)))
    parentpath = property(getparentpath)

    def _getparent(self):
        return self.getparentpath()
    parent = deprecated_property(_getparent, new_name="parentpath")

    #normalized for of path
    def getnormpath(self):
        """Returns a normalized version of the path.

        Redundant parts will be consolidated. This function
        should be idempotent. If the original path is relative,
        the result should remain relative.

        This is a wrapper for :func:`os.path.normpath`.
        """
        return filepath(self._normpath)
    normpath = property(getnormpath)

    #normalized for case
    #XXX: should this be shown publically?
    # it's not really used for much besides canonpath
    if os.name == "nt":
        def getnormcase(self):
            return filepath(os.path.normcase(self))
    else:
        def getnormcase(self):
            return self
    normcase = property(getnormcase)

    def expand(self, user=None, vars=None, shortcuts=None, symlinks=None, all=False):
        """expand various substitutions found in filepath, returning the result.

        :param user:
            Set to ``True`` to expand user home directory refs (``~/``).
            This option calls :func:`os.path.expanduser`.

        :param vars:
            Set to ``True`` to expand environmental variables.
            This option calls :func:`os.path.expandvars`.

        :param shortcuts:
            Set to ``True`` to resolve windows shortcut (.lnk) files.
            This options calls :func:`read_shortcut`.

        :param symlinks:
            Set to ``True`` to expand symlinks.
            Note that currently this just calls ``self.abspath``,
            whereas a proper implementation should probably
            respect ``self.isrel`` when possible.

        :param all:
            If set to ``True``, all other options
            which aren't explictly set to ``False``
            will be enabled. This why the default
            value for the above keywords is ``None``,
            allowing for inclusive or exclusive masking.
        """
        if all:
            if user is None:
                user = True
            if vars is None:
                vars = True
            if shortcuts is None:
                shortcuts = True
            if symlinks is None:
                symlinks = True
        path = self
        if vars:
            path = os.path.expandvars(path)
        if user:
            path = os.path.expanduser(path)
        if shortcuts and os_has_shortcuts:
            #XXX: shortcuts won't make sense unless under nt,
            #   but we might be running via cygwin or something.
            #   hmm.
            path = self._expand_shortcuts(path)
        if symlinks and os_has_symlinks:
            #we could use realpath() since we're probably under posix,
            #but realpath won't preserve contents, which we'd like
            ##path=os.path.realpath(path)
            path = self._expand_symlinks(path)
        return filepath(path)

    @staticmethod
    def _expand_shortcuts(path):
        "helper for expand()"
        parts = splitsep(path)
        path = parts.pop(0)
        while True:
            target = read_shortcut(path)
            if target:
                #XXX: can user/vars ever be inside target?
                #insert target parts and restart hunt
                parts = splitsep(target) + parts
                path = parts.pop(0)
            elif parts:
                #not shortcut, move on to next part
                path = os.path.join(path, parts.pop(0))
            else:
                #nothing more to check
                return path

    @staticmethod
    def _expand_symlinks(path):
        "helper for expand()"
        parts = splitsep(path)
        path = parts.pop(0)
        while True:
            if os.path.islink(path):
                #insert target parts and restart hunt
                parts = splitsep(os.readlink(path)) + parts
                path = parts.pop(0)
            elif parts:
                #not shortcut, move on to next part
                path = os.path.join(path, parts.pop(0))
            else:
                #nothing more to check
                return path

    def getabspath(self, start=None):
        """This is the function form of :attr:`abspath`.

        Without arguments, it behaves exactly like the *abspath* attribute.
        However, it also accepts a single argument, *start*, which
        specifies an alternate working directory to prepend
        if the path is relative.
        """
        if self.isabs:
            #even if technically absolute, it might not be normalized
            if self.isnorm:
                return self
            else:
                return self.normpath
        elif start is None:
            #NOTE: output changes relative to CWD
            return filepath(os.path.abspath(self))
        else:
            #NOTE: we wrap in abspath in case base is relative
            return filepath(os.path.abspath(os.path.join(start, self)))
    abspath = property(getabspath, None, None,"""
        This attribute returns a normalized path relative
        to the root of the filesystem.""")

    #XXX: should this do a hasattr(os.path,"realpath") test instead?
    #path in host-relative form with all symlinks resolved
    if os.name == "nt":
        def getcanonpath(self):
            "Return absolute & normalized path, but with symlinks unresolved"
            #no 'realpath' available, so just do our best
            #NOTE: have to normcase AFTER, in case abspath has mixed-case
            return filepath(os.path.normcase(os.path.abspath(self)))
    else:
        def getcanonpath(self):
            "Return absolute & normalized path, but with symlinks unresolved"
            return filepath(os.path.realpath(self))
    canonpath = property(getcanonpath, None, None, """Returns canonical form of path.

        This attribute returns a normalized path, relative
        to the root of the filesystem, and attempts to
        normalize for case (if appropriate), resolve symlinks,
        and in general return a single "canonical" path.

        .. note::

            If attempting to determine if two paths point
            to the same resource, use :meth:`sameas` instead,
            since that function can frequently perform such a check
            in a more robust and efficient manner.

        .. warning::

            Internally this uses :func:`os.path.realpath` if available.
            But on platforms where is missing (windows), BPS uses
            a custom approximation, which may sometimes be fooled by
            complex cases. Haven't seen it fail, but no guarantees.

        """)

    def getrelpath(self, start=None, strict=False):
        """Return path relative to specified base (the inverse of abspath).

        This function acts as the inverse of :func:`getabspath`.
        It returns the path as it would be relative to given directory
        (which defaults to the current working directory).

        :param start:
            Directory that result should be relative to.
            If not specified, the current working directory is used.

        :param strict:
            If ``True``, *self* must be a subpath of the *start* directory,
            not rooted in some other directory. If it is not, an error will be raised.
            When this option is enabled, ``".."`` will never be used
            when building a relative path.
        """
        #TODO: under >=py2.6, we should use os.path.relpath()
        assert len(os.path.sep) == 1
        if start is None:
            base = curpath()
        else:
            base = filepath(start)
        if base[-1] == os.path.sep:
            base = filepath(base[1:])
        #accelarate some common cases, before the heavy lifter
        if self == base:
            #assume self is a dir, since base is a dir
            return filepath(_CURDIR)
        if self.startswith(base):
            offset = len(base)
            suffix = self[offset:]
            if suffix[0] == os.path.sep:
                return filepath(suffix[1:])
        #XXX: the algorithm this uses needs more testing,
        # there may be glitches in it
        sp = splitsep(self.canonpath)
        bp = splitsep(base.canonpath)
        common = []
        while sp and bp:
            if sp[0] == bp[0]:
                common.append(sp.pop(0))
                bp.pop(0)
            else:
                break
        #NOTE: 'common' should now contain largest common ancestor of the two
        if bp:
            if strict:
                raise ValueError, "path %r not child of base path %r" % (self, base)
            if os.name == "nt":
                if not common:
                    #under windows, they may have different drive letters,
                    #at which point there's no relative path...
                    #guess we can just fall back on an absolute path
                    log.warning("no common ancestor between paths: %r %r", self, base)
                    return self
                #else there should be at least a drive letter in common
                assert common[0].endswith(":")
            else:
                #under posix, common should always be at least '/'
                assert common and common[0] == '/'
            #parts of bp & sp were left over, sp is not a child of base,
            #so we have to add '..' to move back to closest common ancestor
            sp = [ _PARDIR ] * len(bp) + sp
            return filepath(os.path.join(*sp))
        elif sp:
            #only sp was left over, that part should be relative to basepath
            return filepath(os.path.join(*sp))
        else:
            #paths were the same
            #NOTE: since base is assumed to be a dir,
            # and they compared the same, we assume self is a dir as well.
            return filepath(_CURDIR)

##    def get_common_path(self, other):
##        "return the large common path shared with other"

    def contained_in_path(self, other, strict=False):
        """Check if the path *self* is contained within the path *other*.

        :param other:
            Candidate parent path.

        :param strict:
            If ``True``, strict containment is assumed,
            and the case of self being the same path as other returns ``False``.
            By default, loose containment is assumed,
            and this function will report a path as containing itself.

        :returns:
            Returns ``True`` if the path *self* is a file or directory
            contained with the directory structure of the path *other*.


        This is equivalent to ``shutil.dstinsrc(other,self)``
        """
        cur = self.canonpath._path
        if not cur.endswith(_SEP):
            cur += _SEP
        other = filepath(other).canonpath._path
        if not other.endswith(_SEP):
            other += _SEP
        if other == cur:
            return not strict
        return cur.startswith(other)

    #XXX: should this be renamed same_as_path() to match contained_in_path()?
    if os.name == "nt":
        def samepath(self, other):
            if other is None:
                return False
            return self.canonpath == filepath(other).canonpath
    else:
        def samepath(self, other):
            if other is None:
                return False
            other = filepath(other)
            if self.exists and other.exists:
                return os.path.samefile(self, other)
            else: #samefile doesn't work if paths don't exist
                #NOTE: this hopes that realpath() will resolve what symlinks it can
                warn("path.samepath may not be reliable if paths don't exist", RuntimeWarning)
                return self.canonpath == other.canonpath
    samepath.__doc__ = """compare if two paths refer to the same resource (ie, same canonical path).

        This function performs a similar role to :func:`os.samefile`,
        and is also similar to comparing ``self.canonpath == other.canonpath``,
        but attempts this function to work around any cases where those two options
        would not give correct results (for example, samefile
        cannot handle non-existent paths).
        """

    #=========================================================
    #split path into various pairs
    #=========================================================
    #NOTE: this aren't officially listing in documentation yet, still deciding about them

    #would have named this "split", but that's reserved for str.split()
    #XXX: would splitsep be a better name?
    def splitdir(self, full=False):
        if full:
            #they want a list of ALL the parts
            return [ filepath(elem) for elem in splitsep(self) ]
        else:
            #they just want topmost name split off
            return self.dir, self.name

##    @deprecated_method("splitsep")
##    def splitdir(self, *a, **k):
##        return self.splitsep(*a, **k)

    def splitext(self): return self.base, self.ext

    if os.name == "nt":
        def splitdrive(self):
            drive, tail = os.path.splitdrive(self)
            return filepath(drive), filepath(tail)
    else:
        def splitdrive(self): return filepath(""), self

    if os.name == "nt":
        def splitunc(self):
            unc, tail = os.path.splitunc(self)
            return filepath(unc), filepath(tail)
    else:
        def splitunc(self): return filepath(""), self


    #=========================================================
    #path tree traversal
    #=========================================================
    #path joining via separator

    #would have named this "join", but that's reserved for str.join()
    def joinsep(self, *paths):
        """Returns a new path made of this path joined with the additional *paths*

        This is the method called by the division operator.
        """
        if not paths:
            return self
        return filepath(os.path.join(self, *paths))

    def joinfmt(self, txt, *args):
        if isinstance(txt, (list,tuple)):
            txt = os.path.join(*txt)
        return filepath(os.path.join(self, txt % args))
    #TODO: should this be deprecated?
    #TODO: should __mod__ be implemented?

    #divison is the same as a joinsep
    def __div__(self, other):
        if isinstance(other, (list,tuple)):
            if len(other) == 0:
                return self
            return filepath(os.path.join(self, *other))
        else:
            return filepath(os.path.join(self, other))

    __truediv__ = __div__

    #addition is the same as a norm str add
    def __add__(self, other):
        if other is None:
            return self
        elif isinstance(other, PathType):
            return filepath(self._path + other._path)
        elif isinstance(other, str):
            return filepath(self._path + other)
        else:
            return str.__add__(self, other)

    #addition is the same as a norm str add
    def __radd__(self, other):
        if other is None:
            return self
        elif isinstance(other, PathType):
            return filepath(other._path + self._path)
        elif isinstance(other, str):
            return filepath(other + self._path)
        else:
            return str.__radd__(self, other)

##    def getischdir(self):
##        "does this point to the current working directory?"
##        return self.samepath(os.getcwd())
##    ischdir = property(getischdir)


    #=========================================================
    #filesystem properties
    #=========================================================

    def getexists(self):
        "return ``True`` if path exists"
        return os.path.exists(self)
    exists = property(getexists)

    def getismissing(self):
        "return ``True`` if path does not exist, otherwise ``False``"
        return not os.path.exists(self)
    ismissing = property(getismissing)

    ##def getisbroken(self): return self.ismissing and self.islink

    def getisfile(self):
        "return ``True`` if path is a file, otherwise ``False``"
        return os.path.isfile(self)
    isfile = property(getisfile)

    def getisdir(self):
        "return ``True`` if path is a directory, otherwise ``False``"
        return os.path.isdir(self)
    isdir = property(getisdir)

    def getislink(self):
        "return ``True`` if path is a symbolic link, otherwise ``False``"
        return os.path.islink(self)
    islink = property(getislink)

    #is path a mountpoint?
    def getismount(self):
        """``True`` if path is a mountpoint, otherwise ``False``.
        This wraps :func:`os.path.ismount`.
        """
        return os.path.ismount(self)
    ismount = property(getismount)

    def getfiletype(self, followlinks=True):
        """return a string identifying the type of the file.

        :param followlinks:
            If ``True`` (the default), symlinks will be dereferenced,
            and the filetype of their target will be reported.
            If ``False``, symlinks will be reported as links,
            and not dereferenced.

        The possible values that may be returned:

        ============    =====================================================
        Value           Meaning
        ------------    -----------------------------------------------------
        link            [Only if ``followlinks=False``] Path is a symlink (whether broken or not).

        missing         Path doesn't exist. (Or ``followlinks=True`` and path is a broken symlink).

        file            Path is a regular file.

        dir             Path is a directory.

        char            [POSIX only] Path is a character device.

        block           [POSIX only] Path is block device.

        fifo            [POSIX only] Path is a FIFO device (aka named pipe).

        socket          [POSIX only] Path is a socket file.

        unknown         Can't recognize type of file this path points to.
                        This should generally never happen, probably means
                        BPS lacks tests for some type of file on your OS.
        ============    =====================================================
        """
        if not followlinks and self.islink:
            return "link"
        #NOTE: for efficiency, this bypassing os.path.isxxx() tests and reads st_mode directly
        try:
            mode = os.stat(self).st_mode
        except OSError, err:
            if err.errno == 2: #no such file/dir
                return "missing"
            raise
        if stat.S_ISDIR(mode):
            return "dir"
        elif stat.S_ISREG(mode):
            return "file"
        elif stat.S_ISCHR(mode): #posix character device (usually found in /dev)
            return "char"
        elif stat.S_ISBLK(mode): #posix block device (usually found in /dev)
            return "block"
        elif stat.S_ISFIFO(mode): #posix fifo device (named pipe)
            return "fifo"
        elif stat.S_ISSOCK(mode): #unix socket
            return "socket"
        else:
            #FIXME: this is probably a sign that the code missed testing for something,
            # any occurrences should be remedied...
            log.critical("unknown filetype encountered: path=%r st_mode=%r", self, mode)
            return "unknown"

    filetype = property(getfiletype, None, None,
        """Indicates the type of resource located at path (file, dir, etc),
        after symlinks have be dereferenced. (See :meth:`getfiletype` for possible values)""")

    def getlfiletype(self):
        return self.getfiletype(followlinks=False)
    lfiletype = property(getlfiletype, None, None,
        """Indicates the type of resource located at path (file, dir, etc),
        does *not* dereference symbolic links.""")

    #creation time
    def getctime(self):
        "returns the time when file was created"
        return errors.adapt_os_errors(os.path.getctime, self)
    ctime = property(getctime)

    #last modify time -- not used for nt dirs
    def getmtime(self):
        "returns the time when file was last modified"
        return errors.adapt_os_errors(os.path.getmtime, self)
    def setmtime(self, time):
        return os.utime(self,(self.atime, time))
    mtime = property(getmtime, setmtime, None,
        "returns time when file was last modified, can be written to override")

    #last accessed time
    def getatime(self):
        "returns the time when file was last accessed"
        return errors.adapt_os_errors(os.path.getatime, self)
    def setatime(self, time): return os.utime(self,(time, self.mtime))
    atime = property(getatime, setatime, None,
        "returns the time when file was last accessed, can be written to override")

    #get size in bytes (only for applies to files)
    def getsize(self):
        "returns the size of the file located at path, in bytes"
        #FIXME: if self.filetype == "block", getsize reports 0, we have to open/seek(0,2)/tell/close to get real size
        return errors.adapt_os_errors(os.path.getsize, self)
    size = property(getsize)

    #=========================================================
    #filesystem manipulation
    #=========================================================

    #XXX: rename to setcwd() or something more explicit?
    def chdir(self):
        "set this path as the current working directory"
        os.chdir(self)

    def touch(self, value=None):
        """update atime and mtime to current time, equivalent to unix ``touch`` command.

        :param value:
            This may be ``None``, in which case atime & mtime are set to the current time.
            This may be a single number, in which case atime & mtime will both be set to that value.
            This may be a pair of numbers, in which case it's interpreted as ``(atime,mtime)``.

        If you want to set atime or mtime alone, just write to the respective filepath attribute,
        using either ``None`` or a numeric value.
        """
        if isinstance(value, (int, float)):
            os.utime(self, (value, value))
        else:
            #assume it's a None, or an (atime,mtime) pair
            os.utime(self, value)

    #XXX: naming this 'truncate' would fit unix better, but 'clear' fits python better
    def clear(self):
        """empties directories, truncates files, raises error if missing or not file/dir.

        Unlike :meth:`remove`, this will leave directory / file which it was called on,
        it will only delete the contents.

        .. warning::
            This will recursively delete all of a directory's contents, no questions asked.
            So be warned, it will do what you told it to do.
        """
        if self.isdir:
            #purge everything from directory, but leave dir itself
            for root, dirs, files in os.walk(self, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
        elif self.isfile:
            #open file and wipe it
            fh = self.open("wb")
            fh.close()
        elif self.ismissing:
            raise errors.MissingPathError(filename=self)
        else:
            raise NotImplementedError, "filetype not supported: %r" % (self.filetype,)

    def remove(self, recursive=True, parents=False, ensure=False):
        """remove file or directory if it exists, raise error if missing.

        if passed a directory, contents will be recursively removed first.

        if path is missing, ``OSError(2,"No such file or directory")`` will be raised.

        :param recursive:
            If set to ``False``, this will stop being recursive,
            and act just like :func:`os.remove` or :func:`os.rmdir`.

        :param parents:
            If set to ``True``, removes any intermediate directories
            up to and including highest directory in path,
            or highest non-empty directory, whichever comes first.

        :param ensure:
            By default, :exc:`bps.error.types.MissingPathError` will be raised
            if the path does not exist. However, if ensure is set to ``True``,
            this function will silently return without errors.

        .. warning::
            This will recursively delete the directory and all it's contents,
            no questions asked. So be warned, it will do what you told it to do.

        Filesystem calls this can replace:

            * ``os.remove()``, ``os.unlink()``, ``os.rmdir()`` can be replaced with ``path.remove(recursive=False)``.
            * ``shutil.rmtree()`` can be replaced with ``path.remove()``.
            * ``os.removedirs()`` can be replaced with ``path.remove(recursive=False, parents=True)``.

        """
        #TODO: could support onerror="raise", "ignore", callable() around each remove all
        try:
            if ensure and not self.lexists:
                if parents:
                    self._remove_parents()
                return False
            if self.islink or not self.isdir:
                os.remove(self)
            else:
                if recursive:
                    for root, dirs, files in os.walk(self, topdown=False):
                        for name in files:
                            os.remove(os.path.join(root, name))
                        for name in dirs:
                            os.rmdir(os.path.join(root, name))
                os.rmdir(self)
            if parents:
                self._remove_parents()
            return True
        except OSError, err:
            new_err = errors.translate_os_error(err)
            if new_err:
                raise new_err
            log.warning("unmanaged os error: %r", err)
            raise

    def _remove_parents(self):
        "helper to remove all non-empty components of parent path"
        path = self.dir
        while path:
            if path.exists:
                try:
                    os.rmdir(path)
                except OSError, err:
                    if err.errno == _errno.ENOTEMPTY:
                        break
                    raise
            path = path.dir

    def discard(self, recursive=True, parents=False):
        "call :meth:`remove` and returns True if path exists, does nothing if path is missing"
        return self.remove(recursive=recursive, parents=parents, ensure=True)

    #=========================================================
    #symlink manipulation
    #=========================================================
    def getlexists(self):
        "return ``True`` if path exists, *after* resolving any symlinks"
        return os.path.lexists(self)
    lexists = property(getlexists)

    def mklink(self, target, force=False, relative=None):
        """create a symbolic link at *self*, which points to *target*.

        ``os.symlink(src,dst)`` can be replaced by ``dst.mklink(src)``
        """
        #TODO: could add a "hard=True" option for making a hard link
        if force and self.lexists:
            self.remove()
        if relative:
            target = filepath(target).getrelpath(self.parentpath)
        return os.symlink(target, self)

    def getltarget(self):
        if self.islink:
            return os.readlink(self)
    def setltarget(self, target):
        if self.islink: #this lets ltarget behave like a writable attr
            self.remove()
        self.mklink(target)
    ltarget = property(getltarget, setltarget, None,
        """Returns target if path is a symlink, else ``None``.

        If written to, creates symlink at path, pointing to target.
        """)

    #=========================================================
    #directory manipulation
    #=========================================================
    def listdir(self, full=False, hidden=True):
        """return listing of directory.

        By default, this returns a list containing
        the names of the individual files in the directory,
        *without* the directory path prepended.

        :param full: if ``True``, the directory path will be prepended.
        :param hidden: if ``False``, any hidden files will be filtered from the list.

        For large directories, consider using :meth:`iterdir` instead.

        Example usage::

            >>> filepath("/home").listdir()
                [ 'joe', 'sue', 'ftp', 'elic' ]
            >>> filepath("/home").listdir(full=True)
                [ '/home/joe', '/home/sue', '/home/ftp', '/home/elic' ]

        .. note::
            To get a sorted list, use ``sorted(path.iterdir())``.

        .. seealso::
            :meth:`iterdir`
            :attr:`dircount`
        """
        if full or not hidden:
            #use the complicated loop for all other choices...
            return [
                filepath(os.path.join(self, child)) if full else filepath(child)
                for child in os.listdir(self)
                if hidden or not child.startswith(".")
                ]
        else:
            #names only, with hidden files...
            return [
                filepath(child)
                for child in os.listdir(self)
                ]

    def iterdir(self, full=False, hidden=True):
        """returns an iterator of the directory contents.

        This function is just like listdir(), but returns an iterator
        instead of a list.

        This is mainly offerred for large directories, where
        building a list would be prohibitively expensive.

        Otherwise, it's interface should be exactly the same as :meth:`listdir`.

        Example usage::

            >>> for x in filepath("/home").iterdir()
            >>>     print x
                joe
                sue
                ftp
                elic

        .. note::

            Currently python does not natively offer iterative directory access.
            To get around that, BPS will try the following options:

                * for posix: libc's opendir, via ctypes
                * for windows: win32all's win32file module
                * fallback to os.listdir()

            If you plan to iterate over very large directories,
            os.listdir may have a serious performance hit,
            you may want to verify one of the more efficient options
            is being used, by checking the ``bps3.fs.iterdir_version`` attribute.
        """
        if full or not hidden:
            #use the complicated loop for all other choices...
            return (
                filepath(os.path.join(self, child)) if full else filepath(child)
                for child in iterdir(self)
                if hidden or not child.startswith(".")
                )
        else:
            #names only, with hidden files...
            return (
                filepath(child)
                for child in iterdir(self)
                )

    def mkdir(self, mode=None, parents=False, ensure=False, force=False):
        if (force or ensure) and self.isdir:
            #TODO: set mode iff it's not None
            return False
        if self.lexists:
            if force:
                self.remove()
            else:
                raise errors.PathExistsError(strerror="Make Dir: target path already exists (found %s)" % self.lfiletype, filename=self)
        if mode is None:
            mode = 0777
        #TODO: add support for symbolic modes (see bps3.host.utils)
        if parents:
            os.makedirs(self, mode)
        else:
            os.mkdir(self, mode)
        return True

    #XXX: not sure about deprecating these two,
    # they're so commonly used in their own right
##    @deprecated_method("self.mkdir(parents=True)")
    def makedirs(self, mode=0777):
        self.mkdir(mode=mode, parents=True)

##    @deprecated_method("self.mkdir(parents=True, ensure=True)")
    def ensuredirs(self):
        "ensure full directory path is present, creating it if needed"
        return self.mkdir(parents=True, ensure=True)

    def getdircount(self):
        "return number of entries in directory"
        if self.ismissing:
            raise errors.MissingPathError(filename=self)
        elif not self.isdir:
            raise errors.ExpectedDirError(filename=self)
        return countdir(self) #this is part of iterdir backend system
    dircount = property(getdircount, None, None, """
        Returns the number of files in the immediate directory.

        This is the equivalent of ``len(self.listdir())``,
        except performed much more efficiently where possible.
    """)

    def walk(self, relroot=False, topdown=True, followlinks=False, onerror=None): ##, dirfilter=None, filefilter=None, pathfilter=None):
        "wrapper for os.walk"
        #TODO: document relroot
        if not self.isdir:
            raise errors.ExpectedDirError("can't walk over a %s" % self.filetype, filename=self)
        if relroot:
            root_prefix = self._path
            if not root_prefix.endswith(_SEP):
                root_prefix += _SEP
            root_prefix_len = len(root_prefix)
        if sys.version_info < (2, 6):
            if followlinks:
                raise NotImplementedError, "os.walk for python < 2.6 doesn't support followlinks, and BPS doesn't have a custom implementation (yet)"
            walker = os.walk(self, topdown=topdown, onerror=onerror)
        else:
            walker = os.walk(self, topdown=topdown, followlinks=followlinks, onerror=onerror)
        for root, dirs, files in walker:
            if relroot:
                if root == self._path:
                    root = _CURDIR
                else:
                    assert root.startswith(root_prefix)
                    root = root[root_prefix_len:]
            root = filepath(root)
            yield root, dirs, files

##    def itertree(self, followlinks=False, dirfilter=None, filefilter=None, pathfilter=None):
##        """walk over tree rooted at this path, yielding every entry in top-down manner.
##
##        .. todo::
##
##            * document this function's behavior, usage, comparison to os.walk
##            * enhance filter options to accept globs, regexps?
##            * a non-iterative version?
##            * bottom-up mode?
##            * onerror support?
##        """
##        #XXX: would like to expose this publically, but is design sound?
##        #compared to os.walk approach...
##        #   pro: can handle large dirs iteratively, better for scanning
##        #       pro: can be aborted faster
##        #   con: doesn't present useful dir/file lists to user, or root directory
##        #       fix: could have "relative" mode where child paths are returned relative to base.
##        if not self.isdir:
##            raise errors.ExpectedDirError("must walk over a directory, not a %s" % self.filetype, filename=self)
####        if followlinks or dirfilter or filefilter or pathfilter:
##        stack = deque([self])
##        while stack:
##            path = stack.popleft()
##            for child in path.iterdir(full=True):
##                if filefilter and not filefilter(child.name):
##                    continue
##                if pathfilter and not pathfilter(child):
##                    continue
##                yield child
##                if child.isdir and (followlinks or not child.islink):
##                    if dirfilter and not dirfilter(child):
##                        continue
##                    stack.append(child)
####        else:
####            #accel the common case of no filters and not followlinks
####            stack = deque([self])
####            while stack:
####                path = stack.popleft()
####                for child in path.iterdir(full=True):
####                    yield child
####                    if child.isdir and not child.islink:
####                        stack.append(child)

    #=========================================================
    #reading/writing files
    #=========================================================
    #2009-02-24: 'form' option was removed from open(), it was probably NEVER used

    def open(self, mode="rb", encoding=None):
        "wrapper for builtin file() method, additionally supports optional encoding"
        #XXX: should add 'errors' kwd to pass to codecs.open
        #XXX: should add 'buffering' kwd to pass to both open calls.
        if encoding:
            return codecs.open(self._path, mode, encoding)
        else:
            return file(self._path, mode)

##    def mmap(self, mode="rb"):
##        #NOTE: we could allow rwb / wb+ as well
##        if mode not in ["rb", "wb"]:
##            raise ValueError, "mode not supported: %r" % (mode,)
##        fh = self.open(mode)
##        try:
##            if mode == 'rb':
##                access = mmap.ACCESS_READ
##            elif mode == 'wb':
##                access = mmap.ACCESS_READ | mmap.ACCESS_WRITE
##            return mmap.mmap(fh.fileno(), 0, access=access)
##        finally:
##            fh.close()

    def get(self, default=Undef, encoding=None, text=False):
        """Helper to quickly get contents of a file as a single string.

        :param default:
            optional default value if file does not exist.
            if not set, missing files will cause an IO Error.

        :param text:
            Set to ``True`` to indicate file should be decoded as text,
            using universal newline support. Otherwise, binary mode is used.

        :param encoding:
            Optionally decode contents using specified codec.
            Automatically enables ``text=True``.
        """
        #XXX: what encoding should be used if text=True and encoding=None?
#            If path is a directory, a ``\n`` separated list of the directory
#            contents will be returned.
##        if self.isdir:
##            return "\n".join(self.listdir())

        #TODO: rewrite to use open's encoding kwd (make sure newline works right)
        if encoding:
            text = True
        if text:
            fh = self.open("rU")
        else:
            fh = self.open("rb")
        try:
            try:
                content = fh.read()
            except IOError:
                if default is Undef:
                    raise
                else:
                    log.warning("supressed error while reading file: %r", self, exc_info=True)
                    return default
        finally:
            fh.close()
        if encoding:
            content = content.decode(encoding)
        return content

    def getmd5(self):
        "return md5 hex digest of file"
        return hashlib.md5(self.get()).hexdigest()
    md5 = property(getmd5)

##    def getsha1(self):
##        "return sha1 hex digest of file"
##        return hashlib.sha1(self.get()).hexdigest()
##    sha1 = property(getsha1)

##    def getsha256(self):
##        "return sha256 hex digest of file"
##        return hashlib.sha256(self.get()).hexdigest()
##    sha256 = property(getsha256)

    def set(self, value, encoding=None):
        """quickly set the contents of a file from a string.

        :param value: string to write to file
        :param encoding: optional encoding to pass string through
        """
        #FIXME: if value is None, do we write empty file, remove it, or error?
        if value is None:
            value = ''
        #TODO: rewrite to use open's encoding kwd
        if encoding:
            value = value.encode(encoding)
            fh = self.open("w", encoding=encoding)
        else:
            fh = self.open("wb")
        try:
            return fh.write(value)
        finally:
            fh.close()

    #NOTE: this is experimental, may remove it in future
    def getlinecount(self, newline=None):
        "return number of lines in file"
        if self.isdir:
            warn("you should use .dircount for directories, using .linecount for directories is deprecated!", DeprecationWarning, stacklevel=2)
            return self.dircount
        if newline is None:
            #count all possible newlines
            #XXX: is there a more efficient way to do this?
            try:
                fh = self.open("rU")
            except IOError, err:
                if err.errno == _errno.ENOENT:
                    raise errors.MissingPathError(_errno.ENOENT, filename=self)
                raise
            try:
                count = 0
                for row in fh:
                    count += 1
                return count
            finally:
                fh.close()
        else:
            #count just the newline type specified
            assert newline in ("\n", "\r", "\r\n")
            #XXX: is there a more efficient way to do this?
            return self.get().count(newline)

    linecount = property(getlinecount, None, None, """
        Returns the number of lines in the file.

        This function the file was to be opened in text mode,
        with universal newlines enabled.
    """)

    #=========================================================
    #shell utils
    #=========================================================

    def _norm_cm_target(self, prefix, target, mode, force):
        "helper used by copy_to / move_to"

        #validate mode
        if mode not in ("exact", "child", "smart"):
            raise ValueError, "unknown %s_to mode: %r" % (prefix.lower(), mode,)

        #check source is present (include broken links)
        if not self.lexists:
            raise errors.MissingPathError(strerror=prefix + " File: Source path not found", filename=self)
        target = filepath(target)

        #detect if we're copying/moving source INTO target dir
        if mode == "child" or mode == "smart":
            if target.ismissing:
                if mode == "child":
                    raise errors.MissingPathError(strerror=prefix + " File: Target directory not found", filename=target)
                else:
                    assert mode == "smart"
                    mode = "exact"
            elif target.isdir:
                target = target / self.name
                mode = "exact"
            elif mode == "smart":
                mode = "exact"
            else:
                raise errors.ExpectedDirError(strerror=prefix + " File: Target path is not a directory (found %s)" % target.filetype, filename=target)

        #we should now be in "exact" mode, check that target is missing, but parent dir exists
        assert mode == "exact"
        if target.lexists and not force:
            raise errors.PathExistsError(strerror=prefix + " File: Target path already exists (found %s)" % target.lfiletype, filename=target)
        pt = target.parentpath.filetype
        if pt == "missing":
            #XXX: could have flag to create parents if needed
            raise errors.MissingPathError(strerror=prefix + " File: Target path's parent directory not found", filename=target)
        elif pt != "dir":
            raise errors.ExpectedDirError(strerror=prefix + " File: Target path's parent not a directory (found %s)" % pt, filename=target)

        return target

    def _copy_helper(self, target, preserve, followlinks, root=None, force=False):
        "helper for copy_to / move_to which copies self -> target directly"
##        log.debug("copy helper: %r => %r", self, target)
        if self.islink:
            if not followlinks:
                target.mklink(self.ltarget, force=force)
                return
            elif self.ismissing:
                log.warning("not copying broken link: %r => %r", self, target)
                return #we were probably called recursively, just skip this broken link
        if self.isdir:
            target.mkdir(ensure=True, force=force)
            for name in self.iterdir():
                if root and target.samepath(root): #in case we're copying into source directory
                    continue
                (self/name)._copy_helper(target/name, preserve, followlinks, root, force)
        elif force:
            try:
                shutil.copyfile(self, target)
            except IOError, err:
                log.debug("got IOError copying file, removing target first (self=%r target=%r)", self, target, exc_info=True)
                target.remove()
                shutil.copyfile(self, target)
        else:
            if target.lexists: #shouldn't really get here if force=False
                raise errors.PathExistsError(strerror="Target path already exists (a %s)" % target.lfiletype, filename=target)
            shutil.copyfile(self, target)
        if preserve:
            if preserve == "mode":
                shutil.copymode(self, target)
            else:
                assert preserve == "all"
                shutil.copystat(self, target)

    #TODO: update=True kwd to cause cp --update mode,
    # copies when dest is missing or older mtime
    def copy_to(self, target, mode="exact", preserve=None, followlinks=False, force=False):
        """Copy file/dir to a different location.

        This function wraps the :mod:`shutil` copy methods (copyfile, copy, etc),
        and attempts to unify their behavior under one function.

        :arg self: source path to copy from

        :arg target: target path we're copying to (affected by copy mode, above)

        :param mode:
            The mode controls how *self* and *target* are interpreted when performing the copy operation.
            The following values are accepted:

            =============== ====================================================
            mode            description
            --------------- ----------------------------------------------------
            ``"exact"``     By default, a copy of *self* will be made
                            located exactly at the path named *target*,
                            not as a child of *target* or any other heuristic
                            method. (Directories will be copied
                            recursively).

            ``"child"``     In this case, target must be an (existing)
                            directory, and self will be copied to
                            ``target / self.name``.
                            (Directories will be copied recursively).

            ``"smart"``     This enables a heuristic algorithm which attempts to
                            "do the right thing" based on whether self and
                            target exist, and what type of path they point to.
                            The exact behavior of this mode is detailed in the
                            next table.
            =============== ====================================================

            Under smart mode, the decision about what should be copied will be
            made according to the filetype of *self* and *target*,
            as listed in the following table:

            =============   =============== ========================================
            self.filetype   target.filetype resulting action
            -------------   --------------- ----------------------------------------
            dir             missing         target is created as dir,
                                            and contents are copied from self
                                            into target.

            dir             file            :exc:`bps.error.types.PathExistsError`
                                            raised.

            dir             dir             contents of self are copied into target.

            file            missing         target is created as file inside
                                            the directory ``target.parentpath``.

            file            file            :exc:`bps.error.types.PathExistsError`
                                            raised.

            file            dir             file named ``target/self.name``
                                            is created.
            =============   =============== ========================================

        :param preserve:
                * If set to ``None`` (the default), no metadata is preserved.
                * If set to ``"mode"``, only the permission mode will be preserved.
                * If set to ``True``, the file timestamps, ownership, and mode
                  will be preserved.
                * If set to ``"all"``, all possible metadata will be preserved.
                  This is currently the same as ``True``, but may include
                  other metadata in the future. (the goal is to eventually
                  match the unix cp command).

        :type preserve: bool or str

        :param followlinks:
                Boolean flag controlling whether symlinks should be deferenced.
                If ``False`` (the default), symlinks will be copied directly.
                If ``True``, symlinks will be dereferenced, and their contents copied.

        :param force:
            If set to ``True``, and the target exists, it will be removed if it can't be opened.
            This operation is not atomic (except when the target is a file).
            By default (``False``), a :exc:`bps.error.types.PathExistsError` will usually be raised
            if the target already exists.
        """
        #TODO: support more of the unix cp command's options, such as the backup behaviors.
        #TODO: support more of cp command's "preserve" options.
        if preserve is True: #equiv to cp -p ... mode,ownership,timestamps
            preserve = "all" #whereas 'all' may one day encompass some other things
        ##elif preserve is False or preserve == '':
        ##    preserve = None
        if preserve not in (None, "all", "mode"):
            raise ValueError, "unknown preserve value: %r" % (preserve,)
        target = filepath(target)

        #check copy semantics
        if self.samepath(target):
            raise ValueError, "Copy File: cannot copy path %r to self %r" % (self, target)
        elif target.contained_in_path(self):
            root = target
        else:
            root = None

        #normalize target & validate inputs based on options
        target = self._norm_cm_target("Copy", target, mode, force)

        #check copy semantics again (in case mode caused target to change)
        if self.samepath(target):
            raise ValueError, "Copy File: cannot copy path %r to self %r" % (self, target)

        target.parentpath.mkdir(parents=True, ensure=True)
        self._copy_helper(target, preserve=preserve, followlinks=followlinks, root=root, force=force)

    def move_to(self, target, mode="exact", force=False):
        """Move file/dir to a different location.

        This function wraps the :mod:`shutil` move method,
        and attempts to provide an interface similar to :meth:`copy_to`.

        :param self: source path to move from

        :param target: target path we're moving to (affected by move mode, above)

        :type mode: str
        :param mode:
            The mode controls how *self* and *target* are interpreted when
            performing the move operation.
            The following values are accepted:

            =============== ====================================================
            mode            description
            --------------- ----------------------------------------------------
            ``"exact"``     By default, *self* will be moved to exactly
                            the path named *target*, not as a child of *target*
                            or any other heuristic method.

            ``"child"``     In this case, target must be an (existing)
                            directory, and self will be moved to
                            ``target / self.name``.

            ``"smart"``     This enables a heuristic algorithm which attempts to
                            "do the right thing" based on whether self and
                            target exist, and what type of path they point to.
                            The exact behavior of this mode is detailed in the
                            next table.
            =============== ====================================================

            Under smart mode, the decision about where self should be moved will
            be made according to the path type of *self* and *target*,
            as listed in the following table:

            =============   =============== ========================================
            self.filetype   target.filetype resulting action
            -------------   --------------- ----------------------------------------
            dir             missing         self is moved to a path exactly matching
                                            the target.

            dir             file            :exc:`bps.error.types.PathExistsError`
                                            is raised (see *force*)

            dir             dir             dir named ``target/self.name`` is
                                            created.

            file            missing         self is moved to a path exactly matching
                                            the target.

            file            file            :exc:`bps.error.types.PathExistsError`
                                            is raised (see *force*)

            file            dir             file named ``target/self.name``
                                            is created.
            =============   =============== ========================================

        :param force:
            If set to ``True``, and the target exists, it will be removed first.
            This operation is not atomic (except under unix, when the target is a file).
            By default (``False``), a :exc:`bps.error.types.PathExistsError` will usually be raised
            if the target already exists.

        Filesystem calls this can replace:

            * ``os.rename(src,dst)`` can be approximated with ``src.move_to(dst)``,
              except that this version is willing to move across filesystems,
              and doesn't have varying semantics across OSes.

            * ``shutil.move(src,dst)`` is equivalent to ``src.move_to(dst, mode="smart")``.
        """
        #TODO: what about group file moves?

        #catch this early
        if self.samepath(target):
            raise ValueError, "Move File: cannot move directory %r to itself %r" % (self, target)

        #normalize target & validate inputs based on options
        target = self._norm_cm_target("Move", target, mode, force)

        #check directory movement semantics
        if self.isdir and target.contained_in_path(self):
            raise ValueError, "Move File: cannot move directory %r into itself %r" % (self, target)

        #try using os.rename
        if target.lexists and not (target.isfile and os.name == "posix"):
            #unix rename allows target to be a file,
            #and takes care of clobbering it for us.
            target.remove()
        try:
            os.rename(self, target)
            return
        except OSError:
            #probably an error renaming across filesystems, but we could check
            log.debug("move_to(): os.rename returned error, using fallback (self=%r target=%r)", self, target, exc_info=True)
            pass

        #else fall back to software implementation using shutil
        target.discard()
        self._copy_helper(target, preserve="all", followlinks=False)
        self.remove()

    #=========================================================
    #mode / ownership
    #=========================================================
    def getmode(self):
        "get permission mode for file, as integer bitmask"
        #NOTE: we & PERM_BITMASK to strip off the filetype part of 'mode'
        st = errors.adapt_os_errors(os.stat, self)
        return st.st_mode & PERM_BITMASK

    def getmodestr(self):
        "get permission mode for file, rendered to symbolic string"
        return repr_mode_mask(self.getmode())

    def setmode(self, value):
        "set permission mode int for file/dir"
        mode = parse_mode_mask(value)
        errors.adapt_os_errors(self._apply_mode_mask, mode)

    mode = property(getmode, setmode)
    modestr = property(getmodestr, setmode)

    def _apply_mode_mask(self, mode):
        "helper for chmod function, and setmode method"
        bits, preserve = mode
        if preserve:
            if preserve == PERM_BITMASK:
                return
            bits |= os.stat(self).st_mode & preserve
        os.chmod(self, bits)

    #=========================================================
    #deprecated methods, scheduled for removal 2010-04-01
    #=========================================================
    x = "2010-04-01"

    @deprecated_method("self.walk()", removal=x)
    def walktree(self, *a, **k):
       return self.walk(*a, **k)

    @deprecated_method("getabspath", removal=x)
    def geteffpath(self):
        "Return absolute & normalized path, but with symlinks unresolved"
        #NOTE: this used to ensure even absolute paths were normalized,
        # but now .abspath takes care of that.
        if self.isabs:
            return self.normpath
        else:
            #changes relative to get_cwd()
            return filepath(os.path.normpath(os.path.abspath(self)))
    effpath = deprecated_property(geteffpath, new_name="abspath", removal=x)

    @deprecated_method("path.getfiletype(dereference=False)", removal=x)
    def getftype(self, follow=False):
        return self.getfiletype(symlinks=not follow)
    ftype = property(getftype)

    #renamed to discard(), to mimic python's set type
    @deprecated_method("path.discard()", removal=x)
    def remove_if_exists(self):
        return self.discard()

    @deprecated_method("path.remove()", removal=x)
    def rmfile(self, *args, **kwds): return os.remove(self, *args, **kwds)

    @deprecated_method("path.remove(recursive=False)", removal=x)
    def rmdir(self): return os.rmdir(self)

    @deprecated_method("path.remove(recursive=False, parents=True)", removal=x)
    def removedirs(self):
##        return os.removedirs(self)
        return self.remove(recursive=False, parents=True)

    @deprecated_method("path.move_to(target, mode='smart')", removal=x)
    def move(self, dst):
        return self.move_to(dst, mode="smart")

    #NOTE: might not want to ever remove this, just so users don't get suprised by no rename()
    @deprecated_method("move_to(target)", removal=x)
    def rename(self, dst):
        return self.move_to(dst)

    symlink = mklink #deprecate this name?

    del x
    #=========================================================
    #eoc
    #=========================================================

PathType = FilePath #deprecated name for class, scheduled for removal 2009-8-8

#=========================================================
#other functions
#=========================================================
def is_filepath(path):
    """test if an object is a FilePath or compatible.

    This is preferred over isinstance (at least until python 3.0's
    abstract base classes) because it tests for a protocol,
    not inheritance.

    Example usage::

        >>> from bps.fs import filepath, is_filepath
        >>> path = filepath("/home")
        >>> is_filepath(path)
            True
        >>> is_filepath("/home")
            False

    .. todo::

        This doesn't test for the entire interface,
        just a couple of attributes that are likely
        indicators.
    """
    return hasattr(path, "ext") and hasattr(path, "isabs")

isfilepath = relocated_function("isfilepath", is_filepath) #XXX: which of these should we deprecate?

#XXX: rename to getcwd() / setcwd()?
@deprecated_function(removal="2009-10-01")
def curpath(path=Undef):
    "return current directory as filepath"
    if path is not Undef:
        os.chdir(path)
    return filepath(os.getcwd())

def getcwd():
    "return current directory as filepath object (wraps os.getcwd)"
    return filepath(os.getcwd())

def setcwd(path):
    "set current direct (alias for os.chdir, for symetry)"
    path = filepath(path)
    if path.ismissing:
        raise errors.MissingPathError(sterror="directory does not exist", filename=path)
    if not path.isdir:
        raise errors.ExpectedDirError(strerror="path is a %s, not a directory" % path.filetype, filename=path)
    os.chdir(path)

if os.path.sep == '/':
    def posix_to_local(path):
        ""
        return filepath(path)
    def local_to_posix(path):
        return str(path)
else:
    def posix_to_local(path):
        if path is None: return path
        return path.replace('/', os.path.sep)
    def local_to_posix(path):
        if path is None: return path
        return path.replace(os.path.sep, '/')
posix_to_local.__doc__ = """Convert a relative path using posix separators (``/``) to local separators.

This function is merely a quick helper to allow strings stored in configuration files
to be stored using the posix separator, but quickly localized. It takes in a string,
and returns a :class:`FilePath` instance.
"""

local_to_posix.__doc__ = """Convert a relative local path to one using posix separators (``/``).

This function is merely a quick helper to allow local filepaths to be converted
to use posix separator, such as when storing in a portable config file.
It takes in a string or :class:`FilePath` instance, and returns a string.
"""

def splitsep(path):
    """split path into it's component parts.

    This acts like a repeated :func:`os.path.split` call,
    returning a list of all elements in the path,
    split by any separators present.

    Windows Example::

        >> splitsep(r"c:\Documents and Settings\Administrator\Desktop")
            [ 'c:\', 'Documents and Settings', 'Administrator', 'Desktop' ]

    .. note::

        Since the general use of this is to examine the individual peices
        of a path, and not typically to immediate use them as a relative path
        on the filesystem, this function returns a list of strings,
        *not* :class:`FilePath` instances.

    """
    out = []
    while True:
        path, tail = os.path.split(path)
        if tail:
            out.insert(0, tail)
        else:
            out.insert(0, path)
            return out

@deprecated_function("use filepath(path).get()", removal="2010-04-01")
def getFile(path, default=Undef):
    "get contents of file as string"
    return filepath(path).get(default=default)

@deprecated_function("use filepath(path).set(value)", removal="2010-04-01")
def setFile(path, value):
    "set contents of file from string"
    return filepath(path).set(value)

#=========================================================
#iterdir
#=========================================================
#python doesn't have a native iterdir, so we try our best to provide one

#first, the fallback and common docstring
def iterdir(path):
    return iter(os.listdir(path))
def countdir(path):
    return len(os.listdir(path))
iterdir_version = "os.listdir"

if os.name == "nt":
    #see if we can use the pywin32 backend
    try:
        import win32file
    except ImportError:
        pass
    else:
        import pywintypes
        def iterdir(path):
            try:
                for entry in win32file.FindFilesIterator(os.path.join(path, "*")):
                    #NOTE: entry contains lots of useful stuff... ctimes, mtimes, ???
                    name = entry[8]
                    if name not in (".", ".."):
                        yield name
            except pywintypes.error, err:
                if err.args and err.args[0] == 3:
                    #(3, 'FindFirstFileW', 'The system cannot find the path specified.')
                    raise errors.MissingPathError(filename=path)
                raise

        def countdir(path):
            #xxx: is there a better way to do this?
            c = -2
            try:
                for entry in win32file.FindFilesIterator(os.path.join(path, "*")):
                    c += 1
                assert c>=0
                return c
            except pywintypes.error, err:
                if err.args and err.args[0] == 3:
                    #(3, 'FindFirstFileW', 'The system cannot find the path specified.')
                    raise errors.MissingPathError(filename=path)
                raise
        iterdir_version = "win32file.FindFilesIterator"

#NOTE: commented this out until it can get more testing...
#XXX: could have this enable-able via a env var flag, and run a quick test of bps directory.
# if we get the shape of 'struct dirent' wrong for a host, this won't work at all.
##elif os.name == "posix":
##    #use ctypes to access posix's opendir suite
##
##    #TODO: research how much dirent structure varies
##    # across platforms. so we're gonna be paranoid,
##    # and only support linux2 / 32 and 64bit,
##    # and hope that's enough
##
##    dirent = libc = None
##    if sys.platform == "linux2":
##        from ctypes import *
##        #derived from /usr/include/bits/dirent.h
##        class dirent(Structure):
##            _fields_ = [
##                ('d_ino', c_ulong),
##                ('d_off', c_ulong),
##                ('d_reclen', c_ushort),
##                ('d_type', c_char),
##                ('d_name', c_char * 256),
##                ]
##        try:
##            libc = cdll.LoadLibrary("libc.so.6")
##        except OSError:
##            pass
##
##    if dirent and libc:
##        dir_p = c_void_p #pointer to a dir handle
##        dirent_p = POINTER(dirent) #pointer to struct dirent
##
##        opendir = libc.opendir
##        opendir.argtypes = [ c_char_p ]
##        opendir.restype = dir_p
##
##        readdir = libc.readdir
##        readdir.argtypes = [ dir_p ]
##        readdir.restype = dirent_p
##
##        closedir = libc.closedir
##        closedir.argtypes = [ dir_p ]
##        closedir.restype = c_int
##
##        def iterdir(path):
##            dh = opendir(path)
##            if dh is None:
##                raise IOError, "couldn't open dir"
##            try:
##                while True:
##                    entry = readdir(dh)
##                    if not entry:
##                        return
##                    name = entry.contents.d_name
##                    if name not in (".", ".."):
##                        yield name
##            finally:
##                closedir(dh)
##        def countdir(path):
##            dh = opendir(path)
##            if dh is None:
##                raise IOError, "couldn't open dir"
##            try:
##                c = -2 #to account for "." and ".."
##                while True:
##                    entry = readdir(dh)
##                    if not entry:
##                        assert c >= 0
##                        return c
##                    c += 1
##            finally:
##                closedir(dh)
##        iterdir_version = "libc.readdir"

iterdir.__doc__ = """iterate over a directory.

    This iterates over a directory, returning the raw strings
    contained in the directory. See :meth:`FilePath.iterdir`
    for a more fully-featured function.

    Since python has no native iterdir, BPS tries to use
    various alternate means to implement this function efficiently,
    falling back on wrapping os.listdir().
    """
countdir.__doc__ = """return directory count as efficiently as possible"""

#=========================================================
#windows shortcut handling
#=========================================================
LNK_MAGIC = "\x4C\0\0\0\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
#NOTE: this code also assumes all windows shortcuts will end in .lnk

def is_shortcut(path):
    "check if file is a windows shortcut"
    if not path.lower().endswith(".lnk"):
        return False
    with file(path, "rb") as fh:
        return fh.read(20) == LNK_MAGIC
    #XXX: could do more validatation if magic fits

def read_shortcut(path):
    "return target of windows shortcut, or None if not a shortcut"
    if not path.lower().endswith(".lnk"):
        return None
    with file(path, "rb") as fh:
        if fh.read(20) != LNK_MAGIC:
            #wrong hlen or guid
            return None
        fh.seek(0)
        data = fh.read()
    def read_long(idx):
        return struct.unpack("L", data[idx:idx+4])[0]
    def read_short(idx):
        return struct.unpack("H", data[idx:idx+2])[0]
    flags = read_long(0x14)
    if not (flags & 2):
        #doesn't point to a file or directory!
        #just going to pretend this isn't a shortcut
        return None
    offset = 76
    if flags & 1:
        #skip id list
        offset += 2+read_short(offset)
    #offset now marks beginning of FileLocationInfo
    tflags = read_long(offset+0x8)
    if tflags & 1:
        #local path
        bp = offset+read_long(offset+0x10)
        end = data.index("\x00", bp)
        root = data[bp:end]
    elif tflags & 2:
        #network path
        bp = offset+0x14+read_long(offset+0x14)
        end = data.index("\x00", bp)
        root = data[bp:end]
    else:
        raise NotImplementedError, "unexpected FileLocationInfo flags: %r" % tflags
    rp = offset+read_long(offset+0x18)
    end = data.index('\x00', rp)
    tail = data[rp:end]
    if tail:
        root += "\\" + tail
    #NOTE: this ignored any arguments added to the shortcut
    return root

##def parse_shortcut(path):
##    "hacked code used to learn basics of shortcut file, might be useful for expanding in future"
##    path = filepath(path)
##    d = path.get()
##
##    #header
##    clen = 4+16+4+4+8*3+4+4+4+4+4+4
##    assert clen == 76
##    out = struct.unpack("L16sLL8s8s8sLLLLLL",d[:clen])
##    d = d[clen:]
##
##    c1, guid, flags, fattrs, t1, t2, t3, flen, icon, shownd, hotkey, c2, c3 = out
##    assert c1 == 76 and c2 == 0 and c3 == 0
##    assert guid == '\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F'
##    opts = {}
##
##    #flags
##    source = flags
##    flags = set()
##    if source & (1<<0):
##        flags.add("has_id_list")
##    if source & (1<<1):
##        flags.add("target_fd")
##    if source & (1<<2):
##        flags.add("has_desc")
##    if source & (1<<3):
##        flags.add("has_relpath")
##    if source & (1<<4):
##        flags.add("has_wd")
##    if source & (1<<5):
##        flags.add("has_args")
##    if source & (1<<6):
##        flags.add("has_icon")
##    if source & (1<<7):
##        flags.add("has_unicode")
##    #1<<8 means what?
##    m = (1<<8)-1
##    if source > m:
##        flags.add((source|m)^m)
##
##    #fattrs
##    source = fattrs
##    fattrs = set()
##    if source & (1<<4):
##        fattrs.add("is_dir")
##        source -= 1<<4
##    if source:
##        fattrs.add(source)
##
##    #t1,t2,t3 - ctime,mtime,atime
##
##    #id list
##    if 'has_id_list' in flags:
##        clen, = struct.unpack("H", d[:2])
##        assert clen >= 2 and clen <= len(d)
##        source = d[2:2+clen]
##        print repr(source)
##        d = d[2+clen:]
##
##        opts['id_list'] = out = []
##        while source:
##            assert len(source) >= 2
##            clen, = struct.unpack("H", source[:2])
##            if clen == 0:
##                source = source[2:]
##                break
##            assert clen >= 2 and len(source) >= clen
##            out.append(source[2:clen])
##            print repr(out[-1])
##            source = source[clen:]
##        assert not source
##        assert clen == 0
##
##    #target info
##    if 'target_fd' in flags:
##        clen, = struct.unpack("L", d[:4])
##        assert clen >= 4 and clen <= len(d)
##        source = d[:clen]
##        d = d[clen:]
##        ##opts['target_fd'] = source
##        first_offset, tflags, o_lvm, o_bp, o_nvi, o_pth = struct.unpack("6L", source[4:4*7])
##        assert first_offset == 0x1C, "strange first offset"
##        x = tflags
##        tflags = set()
##        if x & 1:
##            tflags.add("local") #o_lvm, o_bp are valid
##            x-=1
##        if x & 2:
##            tflags.add("network") #o_nvi is valid
##            x-=2
##        if x:
##            raise ValueError, "unknown tflag: %r" % (x,)
##        if 'local' in tflags:
####            #read the lvm
####            clen, = struct.unpack("H", source[o_bp:o_bp+2])
####            #NOTE: skipping 2-16, which contains some volume info
####            #16..clen contains the actual name
####            volume_name = source[o_bp+16:o_bp+clen]
####            assert root_name.endswith("\x00")
####            volumn_name = volume_name[:-1]
##
##            #read the bp
##            end = source.index("\x00", o_bp)
##            root_path = source[o_bp:end]
##        elif 'network' in x:
##            raise NotImplementedError
##        else:
##            raise ValueError, "missing local & network"
##        end = source.index('\x00', o_pth)
##        tail_path = source[o_pth:end]
##        opts['target'] = dict(
##            source=source,
##            tflags=sorted(tflags),
##            o_lvm=o_lvm,
##            o_bp=o_bp,
##            o_nvi=o_nvi,
##            o_pth=o_pth,
##            root_path=root_path,
##            tail_path=tail_path,
##            )
##
##    x = dict(
##        flags=sorted(flags),
##        fattrs=sorted(fattrs),
##        t1=t1, t2=t2, t3=t3,
##        flen=flen,
##        icon=icon,
##        shownd=shownd,
##        hotkey=hotkey,
##        tail=d,
##    )
##    x.update(opts)
##    return x

#=========================================================
#permission mode parsing
#=========================================================

#constants
PERM_SCOPES = "ugoa"
PERM_FLAGS = "rwxst"
PERM_OPS = "+-="

#NOTE: this _should_ be all the bits specified by stat module.
PERM_BITMASK = 07777

#mapping of scope name -> bits involved in that scope
PERM_SCOPE_BITS = dict(
        u=stat.S_IRWXU | stat.S_ISUID,
        g=stat.S_IRWXG | stat.S_ISGID,
        o=stat.S_IRWXO | stat.S_ISVTX,
        a=PERM_BITMASK,

        o_rwx=stat.S_IRWXO,
        implicit=PERM_BITMASK ^ (stat.S_IWGRP|stat.S_IWOTH), #special "implict" scope, same as "a" but w/o write for g & o
        )
#mapping of flag name -> bits involved with the flag
PERM_FLAG_BITS = dict(
        r=stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
        w=stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH,
        x=stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
        s=stat.S_ISUID | stat.S_ISGID,
        t=stat.S_ISVTX,
        )

def is_mode_mask(value, valid=True):
    "check if object looks like mode,mask tuple, optionally validating range"
    if not (
        isinstance(value, (list, tuple)) and len(value) == 2 and
        isinstance(value[0], int) and
        isinstance(value[1], int)
        ):
            return False
    return (not valid) or (
        (0 <= value[0] <= PERM_BITMASK) and
        (0 <= value[1] <= PERM_BITMASK) and
        (value[0] & value[1] == 0) #'bits' that are set shouldn't be allowed in 'mask'
        )

def is_mode_int(value, valid=True):
    "check if object looks like mode integer, optionally validating range"
    return isinstance(value, (int, long)) and ((not valid) or (0 <= value <= PERM_BITMASK))

#XXX: cache this for speed?
def parse_mode_mask(value):
    """parse unix-chmod-style symbolic mode string, returning ``(mode_bits,preserve_mask)``.

    :arg value:
        The mode mask to parse. Can be any of the following:

        * string containing octal mode, left-padding with zeros till it's four
          chars long (ex: ``"77"``, ``"0644"``), will be parsed into bits with
          mask of 0.
        * string containing symbolic mode operations to perform (ex: ``"u+r,g+w,-x"``),
          which will be parsed into appropriate bits and mask.

        * integer mode, returned as ``(mode, 0)``.
        * mode and mask tuple, will be returned unchanged.

    :raises ValueError:
        If any of the input string are improperly formatted,
        or input integers are out of range.

    :returns:
        This parses the various mode symbolic strings recognized by unix chmod,
        and returns a tuple ``(mode_bits, preserve_mask)``, where mode_bits is
        the mode bits that should be set in the new mode, and preserve_mask
        is the bits which should be kept from the path's current mode (if this is 0,
        the previous mode can be ignored).

    Symbolic mode format
    --------------------
    The symbolic mode format is a string describing a set of operations
    for setting and clearing a file's mode bits. For example:

    * ``"u+r,g-x,o="`` would add 'read' permission for the owning user,
      remove executable permission for the owning group, and remove
      all permissions for anyone else.

    The syntax of the symbolic mode format is as follows:

    .. productionlist::
        mode: `group` [ "," `group` ]* [ "," ]
        group: `scope`* `operator` `flag`*
        scope: "u" | "g" | "o" | "a"
        operator: "+" | "-" | "="
        flag: "r" | "w" | "x" | "s" | "t"

    .. note::
        The format this function accepts attempts to be compatible with the
        unix chmod command's format, with the exception that (for simplicity)
        this does _not_ support chmod's "g=u" style mode strings.
    """
    #get the easy inputs out of the way
    if value is None: #simulate "preserve all"
        return (0, PERM_BITMASK)
    if isinstance(value, int):
        if not is_mode_int(value):
            raise ValueError("invalid mode integer: %r" % value)
        return (value, 0)
    elif is_mode_mask(value, valid=False):
        if not is_mode_mask(value):
            raise ValueError("invalid mode,mask tuple: %r" % (value,))
        return value
    elif not isinstance(value, str):
        raise TypeError, "unexpected type for mode mask: %r" % (value,)
    #check for octal mode
    if value.isdigit():
        try:
            bits = int(value, 8)
        except ValueError:
            pass
        else:
            if 0 <= bits <= PERM_BITMASK:
                return bits
        raise ValueError("invalid mode: %r" % value)
    #time for state machine to parse symbolic mode
    SEPS = ","
    state = 0 #current state of state machine
        # 0 - not in group, expecting start of group (scope,op) or whitespace
        # 1 - saw scope, waiting for op
        # 2 - saw operator (+,-,=), waiting for flags, op, or end of group
    scope = 0 #bits enabled for group by state=1
    op = None #operator (+,-,=) used by state=2
    bits = 0 #bits we're setting to 1
    used = 0 #bits we're flipping one way or the other.
    for c in value:
        if state == 0:
            #expecting scope or operator
            if c in SEPS:
                continue
            if c in PERM_SCOPES:
                state = 1
                scope = PERM_SCOPE_BITS[c]
                continue
            if c in PERM_OPS:
                state = 2
                op = c
                scope = PERM_SCOPE_BITS['implicit']
                if op == "=": #clear bits for = op
                    bits = (bits|scope) ^ scope
                    used |= scope
                continue
            raise ValueError, "invalid mode string: %r" % (value,)
        elif state == 1:
            #expecting more scope or operator
            if c in PERM_SCOPES:
                scope |= PERM_SCOPE_BITS[c]
                continue
            if c in PERM_OPS:
                state = 2
                op = c
                if op == "=": #clear bits for = op
                    bits = (bits|scope) ^ scope
                    used |= scope
                continue
            raise ValueError, "invalid mode string: %r" % (value,)
        else:
            assert state == 2
            #expecting end-of-group, new op, or flag
            if c in SEPS:
                state = 0
                continue
            if c in PERM_OPS:
                op = c
                if op == "=": #clear bits for = op
                    bits = (bits|scope) ^ scope
                    used |= scope
                continue
            if c in PERM_FLAGS:
                v = PERM_FLAG_BITS[c] & scope
                bits |= v
                used |= v
                if op == "-":
                    bits ^= v
                continue
            raise ValueError, "invalid mode string: %r" % (value,)
    if state == 1:
        raise ValueError, "invalid mode string: %r" % (value,)
    return bits, (PERM_BITMASK ^ used)

def repr_mode_mask(value, octal='never'):
    """represent mode mask as symbolic string.

    :arg value:
        * mode integer
        * (mode bits, preserver bits) tuple

    :param octal:
        Controls when octal format will be output instead
        of symbolic output.

        * 'never' - always use symbolic format
        * 'always' - always use octal format, raising error if mask can't be represented
        * 'prefer' - use octal when possible, falling back to symbolic.

    :returns:
        mode as symbolic string, such as is accepted by unix chmod
        as well as :func:`parse_mode_mask`.
    """
    #parse into (bits,used)
    if isinstance(value, int):
        if not is_mode_int(value):
            raise ValueError("invalid mode integer: %r" % value)
        bits, used = value, PERM_BITMASK
    elif is_mode_mask(value, valid=False):
        if not is_mode_mask(value):
            raise ValueError("invalid mode,mask tuple: %r" % (value,))
        bits, preserved = value
        used = PERM_BITMASK ^ preserved
    elif isinstance(value, str):
        #normalize any string if passed in
        bits, preserved = parse_mode_mask(value)
        used = PERM_BITMASK ^ preserved
    else:
        raise TypeError, "unexpected type for mode mask: %r" % (value,)
    #try to render as octal
    if octal != "never":
        if used == PERM_BITMASK:
            return "%04o" % bits
        if octal == "always":
            raise ValueError, "can't represent mask as octal string: %r" % (value,)
    #
    #render as symbolic string
    #

    #XXX: this could probably be done much faster, simpler,
    # and with more compact output. but this function isn't _that_ important

    #render each section
    def render_scope(s):
        scope_mask = PERM_SCOPE_BITS[s]
        scope_used = scope_mask & used
        if scope_used == 0:
            return ""
        scope_bits = bits & scope_used
        if scope_bits == 0:
            if scope_used == scope_mask:
                return "="
            #render minus op
            out = '-'
            for flag in PERM_FLAGS:
                flag_mask = PERM_FLAG_BITS[flag]
                if flag_mask & scope_used and not flag_mask & scope_bits:
                    out += flag
            return out
        elif scope_used == scope_mask:
            #render eq op
            out = "="
            for flag in PERM_FLAGS:
                flag_mask = PERM_FLAG_BITS[flag]
                if flag_mask & scope_bits:
                    assert flag_mask & scope_used
                    out += flag
            return out
        elif scope_bits == scope_used:
            #render plus op
            out = "+"
            for flag in PERM_FLAGS:
                flag_mask = PERM_FLAG_BITS[flag]
                if flag_mask & scope_bits:
                    assert flag_mask & scope_used
                    out += flag
            return out
        else:
            #render plus op and minus op
            outp = "+"
            outm = "-"
            for flag in PERM_FLAGS:
                flag_mask = PERM_FLAG_BITS[flag]
                if flag_mask & scope_used:
                    if flag_mask & scope_bits:
                        outp += flag
                    else:
                        outm += flag
            return outp + outm

    us, ut = "u", render_scope("u")
    gs, gt = "g", render_scope("g")
    os, ot = "o", render_scope("o_rwx")

    #combine like scopes
    if ut and gt == ut:
        gs = us+gs
        ut = ""
    if ut and ot == ut:
        os = us+os
        ut = ""
    elif gt and ot == gt:
        os = gs+os
        gt = ""
    if os == "ugo":
        assert not ut and not gt
        os = "a"

    #now add stick bit
    st = ""
    if used & stat.S_ISVTX:
        s = bits & stat.S_ISVTX
        if s:
            if not ot or ot.startswith("-"):
                st = "+t"
            elif '-' in ot:
                assert ot.startswith("+")
                idx = ot.index("-")
                assert idx > 1
                ot = ot[:idx] + "t" + ot[idx:]
            else:
                assert ot.startswith("=") or ot.startswith("+")
                ot += "t"
        else:
            if '-' in ot:
                ot += "t"
            elif ot.startswith("="):
                pass
            else:
                st = "-t"

    #create output string
    if ut:
        out = us + ut
    else:
        out = ""
    if gt:
        if out:
            out += ","
        out += gs + gt
    if ot:
        if out:
            out += ","
        out += os + ot
    if st:
        if out:
            out += ","
        out += st
    return out

def _is_empty_mode_mask(mask):
    "check if mask leaves original mode unchanged"
    return mask[1] == PERM_BITMASK

def _concat_mode_mask(left, right):
    "concatenate two mode masks together"
    left_bits, left_preserve = left
    right_bits, right_preserve = right
    out_bits = (left_bits & right_preserve) | right_bits
    out_preserve = left_preserve & right_preserve
    return out_bits, out_preserve

##def _compile_mode_func(source):
##    "given mode value provided to chmod, return function which sets mode for path"
##    if isinstance(source, dict):
##        allmode = parse_mode_mask(source.get("all"))
##        target = {}
##        if _is_empty_mode_mask(allmode):
##            for k in PERM_FILETYPES:
##                if k in source:
##                    target[k] = parse_mode_mask(source[k])
##        else:
##            for k in PERM_FILETYPES:
##                if k in source:
##                    target[k] = _concat_mode_mask(allmode, parse_mode_mask(source[k]))
##        def setmode(path):
##            value = target.get(path.filetype)
##            if value:
##               if value[1]:
##                  os.chmod(path, value[0]|(os.stat(path).st_mode & value[1]))
##               else:
##                   os.chmod(path, value[0])
##    elif callable(source):
##        def setmode(path):
##            value = source(path)
##            if value:
##                bits, mask = parse_mode_mask(value)
##                if mask:
##                    os.chmod(path, bits|(os.stat(path).st_mode & mask))
##                else:
##                    os.chmod(path, bits)
##    else:
##        bits, mask = parse_mode_mask(mode)
##        if mask:
##            def setmode(path):
##                os.chmod(path, bits|(os.stat(path).st_mode & mask))
##        else:
##            def setmode(path):
##                os.chmod(path, bits)
##    return setmode

def chmod(targets, mode=None, dirmode=None, filemode=None, recursive=False, followlinks=False):
    """set file permissions, using a syntax that's mostly compatible with GNU chmod.

    :arg targets:
        This may be either a single path to update the mode for,
        or a sequence of paths. The paths may be either a string or filepath object,
        and they may be absolute, or relative to the cwd.

    :arg mode:
        [optional]
        The mode to apply to all targets.
        This can be an integer, symbolic mode string,
        or anything accepted by :func:`parse_mode_mask`.

    :param dirmode:
        [optional]
        The mode to apply to directories only.
        (Applied after primary *mode*).
        This can be an integer, symbolic mode string,
        or anything accepted by :func:`parse_mode_mask`.

    :param filemode:
        [optional]
        The mode to apply to files only.
        (Applied after primary *mode*).
        This can be an integer, symbolic mode string,
        or anything accepted by :func:`parse_mode_mask`.

    :param recursive:
        If ``True``, any targets which are directories
        will be traversed top-down, and all the above
        permission policies will be applied to their contents as well.

    :param followlinks:
        By default, links will not be followed when recursively
        traversing a target. Set this to ``True`` to follow links.
    """
    mode = parse_mode_mask(mode)
    dirmode = _concat_mode_mask(mode, parse_mode_mask(dirmode))
    filemode = _concat_mode_mask(mode, parse_mode_mask(filemode))
    if _is_empty_mode_mask(dirmode) and _is_empty_mode_mask(filemode):
        return
    if is_seq(targets):
        targets = (filepath(path).abspath for path in targets)
    else:
        targets = [ filepath(targets).abspath ]
    for target in targets:
        if target.isdir:
            target._apply_mode_mask(dirmode)
            if recursive:
                #NOTE: 'target' should be first root returned by walk,
                # but double setting mode shouldn't hurt, right?
                for root, dirnames, filenames in target.walk(followlinks=followlinks):
                    root._apply_mode_mask(dirmode)
                    for name in filenames:
                        (root/name)._apply_mode_mask(filemode)
        else:
            target._apply_mode_mask(filemode)

def setumask(mode, format="int"):
    """set/modify current umask.

    :arg mode:
        New mode to use as umask, or modify existing umask.
        Can be a int, or any string accepted by :func:`parse_mode_mask`.
    :param format:
        Format old mask is reported in (see :func:`getumask`).

    :returns:
        the previous umask.

    This is just a wrapper for :func:`os.umask`,
    except that it accepts symbolic mode masks
    in the format handled by :func:`parse_mode_mask`.
    """
    assert format in ("sym", "int")
    bits, preserve = parse_mode_mask(mode)
    old = os.umask(bits)
    if preserve:
        os.umask(bits | (old & prevserve))
    if format == 'sym':
        return repr_mode_mask(old)
    else:
        return old

def getumask(format="int"):
    """read current umask without changing it.

    :param format:
        Format that umask should be reported in.
        "int" (the default) returns the integer mask.
        "sym" returns the symbolic mask.

    .. warning::
        This is not currently an atomic operation!
    """
    assert format in ("sym", "int")
    #XXX: _wish_ this was atomic, or that we could read umask easily
    old = os.umask(0022)
    os.umask(old)
    if format == "sym":
        return repr_mode_mask(old)
    else:
        return old

#=========================================================
#eof
#=========================================================
