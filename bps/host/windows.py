"""windows backend"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from logging import getLogger
import os.path
import subprocess
import sys
from warnings import warn
try:
    import _winreg as winreg
except ImportError:
    winreg = None #doing this so docs can be built from linux
from contextlib import contextmanager
import threading
#pkg
from bps.types import BaseClass, Undef
from bps.refs import SoftValueDict
from bps.fs import filepath, posix_to_local
from bps.host.base import BaseBackend, UserProfile
#local
log = getLogger(__name__)

if hasattr(winreg, "ExpandEnvironmentStrings"): #added in py26
    _ExpandEnvironmentStrings = winreg.ExpandEnvironmentStrings
else:
    _ExpandEnvironmentStrings = os.path.expandvars

#=========================================================
#nt
#=========================================================
#TODO: should implement a CygWin backend, and have NT_Backend check for it
#TODO: kde4 can run under windows, should check for it.

class WindowsBackend(BaseBackend):

    #=========================================================
    #instance attrs
    #=========================================================
    profile = None #profile name (nt, 95) determining resource path locations

    #resource discovery
    env_user = None #environ_user info

    wine = False #are we running under wine?

    #=========================================================
    #init
    #=========================================================
    def __init__(self, **kwds):
        self.__super.__init__(**kwds)

        #check for wine
##        #this might not be a reliable test...
##        try: #keeping this protected till regpath gets more testing
##            if regpath("/local_machine/software/wine/drives").exists:
##                self.wine = True
##                log.info("WINE detected")
##        except:
##            log.error("error in regpath:", exc_info=True)
        #TODO: if wine _is_ present, would like to choose user's real home dir / config dir etc

        # need to check if cygwin sets same key,
        # and it might be cleared anyways
##        pwd = os.environ.get("PWD")
##        if pwd and pwd.startswith("/"):
##            #best guess, we're probably running under wine
##            pass


        #determine profile
        major, minor, build, platform, text = version = sys.getwindowsversion()
        if platform == 2: #nt/2k/xp
            self.profile = "nt"
        elif platform == 1: #windows 95/98/ME
            self.profile = "95"
        else:
            #FIXME: don't have access to 3.1(platform=0) or CE(platform=3) for testing
            raise EnvironmentError, "unsupported windows version: %r" % (version,)

        #load custom exe_exts...
        #first, load PATHEXT if present...
        #';' separated list of extensions (eg: ".EXE;.BAT") which will be searched for by cmd.exe
        exts = os.environ.get("PATHEXT")
        if exts:
            self.exe_exts = tuple(exts.split(os.path.pathsep))

    #=========================================================
    #process management
    #=========================================================
    def terminate_pid(self, pid, retry, kill, timeout):
        #FIXME: would like to try _something_ for _termiante_pid()
        #SEE: http://www.ddj.com/windows/184416547 for ideas about how
        warn("stub: terminate_pid() not implemented for win32, using kill_pid()", RuntimeWarning)
        return self.kill_pid(pid, retry, timeout)

    def _kill_pid(self, pid):
        #FIXME: need to pass sig in
        #os.kill isn't available for win32, so use win32api
        import win32api
        handle = win32api.OpenProcess(1, 0, pid)
        #TODO: log an error/warning if terminate fails, maybe even figure out why
        #XXX: make sure this returns 'True' if signal sent, and 'False' if process not found

        if win32api.TerminateProcess(handle, 0) == 0:
            #XXX: MS sez check GetLastError() to find out why.
            return False #could check, but assuming the signal failed to be sent cause proc was gone.
        else: #assume it was sent
            return True

    def has_pid(self, pid):
        #found at http://mail.python.org/pipermail/spambayes-checkins/2003-December/002383.html
        import win32process
        import win32con
        try:
            rc = win32process.GetExitCodeProcess(pid)
            return rc == win32con.STILL_ACTIVE
        except win32process.error:
            return False

    #=========================================================
    #shell integration
    #=========================================================
    exe_exts = (".com", ".exe",  ".bat",)

    #TODO: find_exe() - saw something that said windows will only
    # consider exact match if extension is specified (eg "app.exe", "app.bat"),
    # but will look at all exe_exts if no extension is present.
    # need to verify this, as well as what "foo.bar" would do

    #=========================================================
    #desktop interaction
    #=========================================================
    def detect_desktop(self):
        #XXX: use orig when kde detection is integrated
        return "windows"

    def desktop_open(self, path,  action,  mimetype):
        #XXX: if desktop not windows, need to use alt handler
        #TODO: have code hunt down available actions in registry, for better choosing
        waction = {
            "open": "open", #duh
            "view": "open", #view never really registered
            "edit": "open", #edit never really registered
            #print - rare
            #exec - not seen
            "browse": "explore",
            }.get(action,  action)
        if waction == "exec":
            log.warning("'exec' action has not been tested much on win32")
        try:
            os.startfile(path,  waction)
        except WindowsError,  err:
            if err.args[0] == 1155: # No application is associated with the specified file for this operation
                if action is not None:
                    #fallback to default action
                    log.warning("no handler for action: action=%r path=%r", action, path)
                    os.startfile(path)
                    #FIXME: what if startfile fails again?
                    #     should we raise special error, or just return false?
                    #     _can_ it ever raise an error in this context?
                    return
            raise

    #=========================================================
    #resource discovery
    #=========================================================
    def load_resources(self):
        self.__super.load_resources()
        if self.profile == "nt":
            self.load_nt_resources()
        else:
            assert self.profile == "95"
            self.load_95_resources()

    def load_95_resources(self):
        #FIXME: don't have this OS available for testing.
        #where is everyting, with or w/o user profiles?
        #provided a cheap guess here
        WinDir = filepath(os.environ.get("WINDIR",None))
        if not WinDir or WinDir.ismissing:
            raise EnvironmentError, "can't find windows install"
        profile = self.env
        profile.state_dir = WinDir / "Application Data"
        if profile.state_dir.ismissing:
            profile.state_dir.makedirs()
        profile.home_dir = WinDir #FIXME: could do better than this, even under win95

    def load_nt_resources(self):
        profile = self.env
        get = os.environ.get
        profile.login = get("USERNAME") #XXX: could guess defaults based on login

        #find home directory... store in HomePath
        while True:
            #check for user profile
            HomePath = filepath(get("USERPROFILE"))
            if HomePath and HomePath.exists:
                break
            #check for HomeDrive  / HomePath
            drive = get("HOMEDRIVE")
            path = get("HOMEPATH")
            if drive and path:
                HomePath = filepath(drive, path)
                if HomePath.exists:
                    break
            #give up
            raise EnvironmentError, "can't find user's home directory"
        profile.home_dir = HomePath

        #check for appdata...
        AppDataPath = filepath(get("APPDATA"))
        if AppDataPath and AppDataPath.exists:
            profile.state_dir = AppDataPath
        else:
            #TODO: like to try something else before we fall back to pre-nt behavior...
            profile.state_dir = HomePath / "Application Data"
            if profile.state_dir.ismissing:
                profile.state_dir.makedirs()

        self._fill_user_info(profile, is_env=True)

    #-----------------------------------------------
    #user related info
    #-----------------------------------------------
    def user_by_login(self, login, missing):
        "return UserInfo for user w/ matching login"
        raise NotImplementedError, "implement me!"

    def user_by_uid(self, uid, missing):
        "return UserInfo for user w/ matching uid"
        if missing == "error":
            raise KeyError, "UIDs are not assigned by windows: %r" % uid
        else:
            warn("UIDs are not assigned by windows, so no match is possible: %r" % uid)
            return None

    def _fill_user_info(self, info, is_env=False):
        "fill out common dirs in user info"
        #NOTE: if is_env
        HomePath = info.home_dir

        if self.profile == "nt":
            #XXX: we could check reg if not is_env

            #check for documents
            for docs in (
                    filepath(os.environ.get("Documents",None)), #non-standard, used by LiteStep
                    #FIXME: like to get path from windows registry at this point.
                    HomePath / "My Documents",
                    ):
                if docs and docs.exists:
                    info.docs_dir = docs
                    break

            #XXX: we could check reg if not is_env

            #check for desktop
            for desktop in (
                    filepath(os.environ.get("Desktop", None)), #non-standard, used by LiteStep
                    #FIXME: like to get path from windows registry at this point
                    HomePath / "Desktop",
                    ):
                if desktop and desktop.exists:
                    info.desktop_dir = desktop
                    break

            #XXX: fill state_dir w/ app data?
        return info

    #-----------------------------------------------
    #program related resources
    #-----------------------------------------------
    def get_service_paths(self, name, login, home):
        raise NotImplementError, "no preset paths available for windows services"

    #=========================================================
    #EOC
    #=========================================================

#some code I saw for searching through windows processes by name
##cmd = os.popen('query process')
##x = cmd.readlines()
##for y in x:
##   p = y.find('openoffice')
##   if p >= 0: # process running

#=========================================================
#registry helpers
#=========================================================
#build map of hkey name -> value
_hkey_values = {}
_hkey_names = {}
def _build_hkey_maps():
    for k in dir(winreg):
        if k.startswith("HKEY_"):
            s = k[5:].lower()
            v = getattr(winreg, k)
            _hkey_values[s] = v
            _hkey_names[v] = s
_build_hkey_maps()

_rp_cache_lock = threading.Lock()
_rp_cache = SoftValueDict(expire=300, flush=150) #cache of existing regpaths, keyed by str

def regpath(path, format=None):
    """\
    given a registry path, returns an object which wraps the registry path,
    and allows easy introspection of it, in much the same way the :func:`bps.fs.filepath` works.

    This attempts to wrap the windows registry path convention
    using a normalized unix-path style, just to make it easier
    to refer to and compare various registry paths.
    The normalized path format is:

        ``[//{system}]/{root}/...``

    Where *system* is the name of the system being connected to,
    and *root* is the ``HKEY_XXX`` constant, but *without* the ``HKEY_`` prefix,
    e.g. ``local_machine`` instead of ``HKEY_LOCAL_MACHINE``.

    .. warning::

        This function, and the RegPath object, are still a design experiment.
        The interface and methods are subject to change or be removed.
    """
    #basically this is just a wrapper for RegistryPath,
    #except it caches old instances based on the *path*
    #this isn't required by the class itself,
    #it just saves time & memory
    global _rp_cache, _rp_cache_lock
    if isinstance(path, RegistryPath) or path is None:
        return path
    if format == "ms":
        #assume it's a backslash separated string, beginning with hkey_xxx
        #(ie, the format return by RegistryPath.raw_path)
        assert '/' not in path, "not sure how to normalize path with / in name: %r" % (path,)
        path = path.replace("\\", "/")
        #when presented in this format, we'll allow strings to start with hkey_xxx instead of slash
        temp = path.lower()
        if not temp.startswith("hkey_"):
            raise ValueError, "ms format reg paths must start with HKEY constant: %r" % (path,)
        if temp[5:temp.find("/")] not in _hkey_values:
            raise ValueError, "ms format reg paths must start with known hkey constant: %r" % (path,)
        path = "/" + path
    elif format and format != "bps":
        raise ValueError, "unknown format: %r" % (format,)
    _rp_cache_lock.acquire()
    try:
        if path in _rp_cache:
            return _rp_cache[path]
        _rp_cache.flush()
        obj = _rp_cache[path] = RegistryPath(path)
        return obj
    finally:
        _rp_cache_lock.release()

class RegistryPath(BaseClass):
    """this represents a path in the registry.


    This class attempts to mimic the interface for filepaths
    provided by :mod:`bps.fs`.

    .. note::

        This does *not* represent a handle to the registry
        (see :class:`RegistryHandle` for that), but it's
        various methods may open them.
    """
    #=========================================================
    #instance attrs
    #=========================================================
    host = None #name of host, or None if local system

    root = None #name of root key, always defined (lower case - local_machine, current_user, etc)
    raw_root = None #name of root key, always defined (upper case with hkey - HKEY_LOCAL_MACHINE, etc)
    raw_root_value = None #int value of winreg.HKEY_XXX for root

    subpath = None #subpath relative to root, using "/" as separator
    raw_subpath = None #subpath relative to root, using "\\" as separator

    raw_path = None #full path "HKEY_XXX\..." in windows style.

    _rootstr = None #root+host portion of path as a string
    _str = None #normalized string of path, returned by __str__

    #=========================================================
    #init
    #=========================================================
    def __init__(self, path):
        #normalize path
        orig = path
        path = path.lower()

        #parse host
        if path.startswith("//"):
            idx = path.find("/", 2)
            if idx == -1:
                host = path[2:]
                path = "/local_machine"
            else:
                host = path[2:idx]
                path = path[idx:]
            if host.lower() == "localhost":
                host = None
        else:
            host = None
        self.host = host

        #parse root
        if path.startswith("/"):
            parts = path[1:].split("/")
            if not parts:
                raise ValueError, "no registry root specified in path: %r" % (orig,)
            root = parts.pop(0)
        else:
            raise NotImplementedError, "relative paths not supported: %r" % orig
        if root.startswith("hkey_"):
            root = root[5:]
        if root not in _hkey_values:
            raise ValueError, "unknown registry root in path: %r" % orig
        self.root = root
        self.raw_root = "HKEY_" + root.upper()
        self.raw_root_value = _hkey_values[root]

        #parse remaining path
        while '' in parts:
            parts.remove('')
        self.subpath = "/".join(parts)
        self.raw_subpath = "\\".join(parts)

        #build full path
        if parts:
            self.raw_path = self.raw_root + "\\" + self.raw_subpath
        else:
            self.raw_path = self.raw_root

        #build string
        out = ""
        if self.host:
            out += "//" + self.host
        out += "/"  + self.root
        self._rootstr = out
        if parts:
            out += "/" + self.subpath
        self._str = out

    def __str__(self):
        return self._str

    def __repr__(self):
        return "regpath(%r)" % self._str

    def __eq__(self, other):
        if isinstance(other, RegistryPath):
            return self._str == other._str
        elif isinstance(other, (str, unicode)):
            try:
                other = regpath(other)
            except NotImplementedError, ValueError:
                return False
            return self._str == other._str
        else:
            return False

    #=========================================================
    #construction
    #=========================================================
    def __div__(self, other):
        if isinstance(other, (list,tuple)):
            if len(other) == 0:
                return self
            other = "/".join(other)
        elif not other:
            return self
        return regpath(self._str + "/" + other)

    __truediv__ = __div__

    #'root' stored directly as attribute

    def _getparent(self):
        path = self.subpath
        if path:
            idx = path.rfind("/")
            if idx == -1:
                return regpath(self._rootstr)
            else:
                return regpath(self._rootstr + "/" + path[:idx])
        else:
            #XXX: return 'self' instead?
            return None
    parent = property(_getparent)

    def _getname(self):
        path = self.subpath
        if path:
            idx = path.rfind("/")
            if idx == -1:
                return path
            else:
                return path[idx+1:]
        else:
            return self.root
    name = property(_getname)

    #=========================================================
    #registry tree navigation
    #=========================================================
    def _getexists(self):
        h = self.open(missing='ignore')
        if h is None:
            return False
        else:
            h.close()
            return True
    exists = property(_getexists)

    def _getismissing(self):
        return not self.exists
    ismissing = property(_getismissing)

    #--------------------------------------------------------
    #proxied from RegHandle object
    #--------------------------------------------------------
    def iterdir(self, full=False):
        #NOTE: we have to proxy iterator so handle stays open
        with self.open() as handle:
            for elem in handle.iterdir(full=full):
                yield elem

    def listdir(self, full=False):
        with self.open() as handle:
            return handle.listdir(full=full)

    def _getmtime(self):
        with self.open() as handle:
            return handle.mtime
    mtime = property(_getmtime)

    #TODO: remove() discard()
##    def remove(self, recursive=True):
            ##winreg.DeleteKey()
##    def discard(self, **kwds):
##        if self.exists:
##            self.remove(**kwds)

    #=========================================================
    #registry values
    #=========================================================

    #--------------------------------------------------------
    #proxied from RegHandle object
    #--------------------------------------------------------
    def iterkeys(self):
        #NOTE: we have to proxy iterator so handle stays open
        with self.open() as handle:
            for key in handle:
                yield key

    def keys(self):
        with self.open() as handle:
            return handle.keys()

    def get(self, key, default=None, missing="ignore", expand=False):
        with self.open() as handle:
            return handle.get(key, default, missing=missing, expand=expand)

    def get_as_path(self, key, default=None, missing="ignore", expand=True):
        with self.open() as handle:
            return handle.get_as_path(key, default, missing=missing, expand=expand)

    #=========================================================
    #lowlevel access
    #=========================================================
    def open(self, mode="r", missing='error'):
        "return a raw winreg handle"
        try:
            return reghandle(self, mode)
        except WindowsError, err:
            if missing == 'ignore' and err.args[0] == 2: #cannot find file specified
                return None
            else:
                raise

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#registry handle (winreg.HKEYType replacement)
#=========================================================
def reghandle(path, mode="r"):
    """given a registry path, as accepted by :func:`regpath`, return a handle
    to it opened with the specified mode.
    """
    return RegistryHandle(path, mode)

class RegistryHandle(BaseClass):
    """replacment for winreg.HKEYType.

    * uses close() instead of Close(), etc
    * provides context manager support
    * provides regpath attribute to retreive original path
    * provides closed attribute

    * supports file()-like mode strings in addition to registry constants.

        =======     ==================================================
        Mode        Description
        -------     --------------------------------------------------
        ``r``       all read perms, equivalent to KEY_READ

        ``w``       all write perms, equivalent to KEY_WRITE

        ``rw``      all read & write permissions

        ``*``       all permissions, equivlanet to KEY_ALL_ACCESS.
                    for most uses, ``rw`` will be sufficient
        =======     ==================================================
    """
    #XXX: if there was a way to close a detached handle int,
    # we wouldn't have to keep _hkey around and proxy it
    _hkey = None #internal HKey we're using
    _rkey = None #key to root of remote registry, if host is defined and subpath exists

    def __init__(self, path, mode="r"):
        self.path = path = regpath(path)
        if not mode:
            mode = "r"
        if isinstance(mode, int): #allow user to pass in raw winreg.KEY_* values
            self.mode = self.mode_value = mode
        elif isinstance(mode, str):
            if any(c not in "*rw" for c in mode):
                raise ValueError, "unknown characters in mode: %r" % (mode,)
            mstr = ''
            mval = 0
            if '*' in mode:
                mstr = '*'
                mval = winreg.KEY_ALL_ACCESS
            else:
                if 'r' in mode:
                    mstr += 'r'
                    mval |= winreg.KEY_READ
                if 'w' in mode:
                    mstr += 'w'
                    mval |= winreg.KEY_WRITE
            if not mval:
                raise ValueError, "no mode specified: %r" (mode,)
            self.mode = mstr
            self.mode_value = mval
        else:
            raise TypeError, "mode must be str or int: %r" % (mode,)
        log.debug("opening registry key: path=%r mode=%r", path, self.mode or self.mode_value)
        if path.host:
            #would probably want to keep a cache of the registry connections,
            #so that we can re-use them
            h = winreg.ConnectRegistry(path.host, path.raw_root_value)
            if path.raw_subpath:
                try:
                    self._hkey = winreg.OpenKey(h, path.raw_subpath, 0, self.mode_value)
                finally:
                    h.Close() #FIXME: is this right? haven't tested this far
            else:
                self._hkey = h
        else:
            self._hkey = winreg.OpenKey(path.raw_root_value, path.raw_subpath, 0, self.mode_value)

    def detach(self):
        return self._hkey.Detach()
    Detach = detach #for backwards compat

    def close(self):
        return self._hkey.Close()
    Close = close #for backwards compat

    def _gethandle(self):
        return self._hkey.handle
    handle = property(_gethandle)

    def _getclosed(self):
        return self._hkey.handle == 0
    closed = property(_getclosed)

    def __enter__(self):
        return self

    def __exit__(self, v, c, t):
        self.close()

    def iterdir(self, full=False):
        h = self.handle
        idx = 0
        try:
            while True:
                child = winreg.EnumKey(h, idx)
                if full:
                    yield self.path / child
                else:
                    yield child
                idx += 1
        except WindowsError, err:
            if err.args[0] == 259: #no more data available
                return
            raise

    def listdir(self, **kwds):
        return list(self.iterdir(**kwds))

    def __iter__(self):
        return self.iterkeys()

    def iterkeys(self):
        "iterate through all keys under this path"
        h = self.handle
        idx = 0
        try:
            while True:
                yield winreg.EnumValue(h, idx)[0]
                idx += 1
        except WindowsError, err:
            if err.args[0] == 259: #no more data available
                return
            raise

    def keys(self):
        return list(self.iterkeys())

    def iteritems(self):
        for key in self:
            yield key, self.get(key)

    def items(self):
        return list(self.iteritems())

    def __contains__(self, key):
        try:
            winreg.QueryValueEx(self.handle, key)
            return True
        except WindowsError, err:
            if err.args[0] == 2: #file not found
                return False
            raise

    def __getitem__(self, key):
        return self.get(key, missing="error")

    def __setitem__(self, key, value):
        return self.set(key, value)

    def __delitem__(self, key):
        try:
            winreg.DeleteValue(self, key)
        except WindowsError, err:
            if err.args[0] == 2: #file not found
                raise KeyError, "key not found: %r" % key
            raise

    def set(self, key, value, type=None):
        #NOTE: this is not final call syntax
        if type is None:
            #TODO: this auto-type detection code could be more intelligent
            if value is None:
                type = winreg.REG_NONE
            elif isinstance(value, (int, long)):
                type = winreg.REG_DWORD
                #XXX: we _could_ check previous stored type
            elif isinstance(value, (str, unicode)):
                if '\x00' in value:
                    type = winreg.REG_BINARY
                else:
                    type = winreg.REG_SZ
            else:
                raise TypeError, "can't guess type from value: %r" % (value,)
        #XXX: should we add some sanity checking here to make sure values match?
        winreg.SetValueEx(self.handle, key, None, type, value)

    def raw_get(self, key, default=None, missing="ignore"):
        "raw get: returns ``(value,dt)`` or ``(default,None)`` if key is missing"
        assert missing in ("ignore", "error")
        #NOTE: this is not final call syntax
        try:
            return winreg.QueryValueEx(self.handle, key)
        except WindowsError, err:
            if err.args[0] == 2: #file not found
                if missing == "ignore":
                    return default, None
                else:
                    raise KeyError, "key not found in registry: path=%r key=%r" % (self.path, key)
            raise

    def get(self, key, default=None, missing="ignore", expand=False):
        value, dt = self.raw_get(key, missing=missing)
        if dt is None:
            return default
        if dt in (winreg.REG_SZ, winreg.REG_BINARY):
            assert isinstance(value, (str, unicode)), value
            return value
        elif dt == winreg.REG_EXPAND_SZ:
            assert isinstance(value, (str, unicode)), value
            if expand and value:
                value = _ExpandEnvironmentStrings(value)
            return value
        elif dt in (winreg.REG_DWORD, winreg.REG_DWORD_BIG_ENDIAN,
            winreg.REG_DWORD_LITTLE_ENDIAN):
                assert isinstance(value, (int, long)), value
                return value
        elif dt == winreg.REG_NONE:
            #err, is that what this means?
            assert value is None, value
            return None
        else:
            #LINK, MULTI_SZ are the known ones we haven't implemented
            raise NotImplementedError, "registry type not implemented: %r %r" % (value, dt)

    def get_as_path(self, key, default=None, expand=True, **kwds):
        value = self.get(key, default, expand=expand, **kwds)
        return filepath(value)

    def get_as_pathlist(self, key, default=None, expand=True, **kwds):
        value = self.get(key, default, expand=expand, **kwds)
        if value:
            return [ filepath(elem) for elem in value.split(os.path.pathsep)]
        else:
            return []

    def _getmtime(self):
        subfiles, subkeys, wmtime = winreg.QueryInfoKey(self.handle)
        if not wmtime:
            return 0
        #wmtime - int of 100s of nanoseconds since Jan 1, 1600
        #this converts to epoch... constant at end is ~ 369.24 years,
        #derived by setting reg key, and comparing mtime to time.time() when call returned.
        return wmtime * 1.0e-7 - 11644473600
    mtime = property(_getmtime)

#=========================================================
#ms office helpers
#=========================================================
def _hid():
    "attempt at a host id"
    return regpath("/local_machine/software/microsoft/windows/currentversion").get("ProductId")

def detect_outlook():
    "detect outlook version & root"
    return detect_office_app("outlook")

def detect_outlook_express():
    "detect outlook express version & root"
    if regpath("/local_machine").ismissing:
        log.warning("couldn't connect to windows registry")
        return None
    outlook = regpath("/local_machine/software/microsoft/outlook express")
    if outlook.ismissing:
        log.info("microsoft outlook express not found in registry")
        return None
    path = outlook.get_as_path("InstallRoot")
    if not path:
        log.warning("outlook express %r has bad InstallRoot")
        return None
    if path.ismissing:
        log.info("outlook express install path missing: %r", path)
        return None
    vstr = outlook.get("MediaVer")
    if vstr:
        version=tuple(int(v) for v in vstr.split(","))
    else:
        version = None
    return dict(
        vstr=vstr,
        version=version,
        path=path,
    )

def detect_office_app(app):
    """detect ms office application, returning path to exe of newest version.

    *app* should be one of ``outlook``, ``word``, ``excel``... er, what others?

    .. note::

        Whatever happens to the registry interface code,
        this function's interface should remain constant.

    .. todo::

        This could probably be expanded to return a lot more of the info it can gather.
    """
    #make sure registry is there...
    if regpath("/local_machine").ismissing:
        log.warning("couldn't connect to windows registry")
        return None
    #check for office...
    office = regpath("/local_machine/software/microsoft/office")
    if office.ismissing:
        log.info("microsoft office not found in registry")
        return None
    best = None #best we're found
    for vstr in office.iterdir():
        try:
            version = float(vstr)
        except ValueError:
            #dir should contain just office version numbers,
            #but also contains some dirs named "Common" and "Dispatch"
            continue
            log.debug("found microsoft office version %r", vstr)
        if best and version < best['version']: #skip older versions
            continue
        install = office / vstr / app / "installroot"
        if install.ismissing:
            log.debug("%s %r not installed", app, vstr)
            continue
        path = install.get_as_path("path")
        if not path:
            log.warning("%s %r has bad InstallRoot", app, vstr)
        if path.ismissing:
            log.info("%s %r install path missing: %r", app, vstr, path)
            continue
        best = dict(version=version, vstr=vstr, path=path)
        log.info("%s %r found at %r", app, vstr, path)
    return best

#=========================================================
#EOC
#=========================================================
