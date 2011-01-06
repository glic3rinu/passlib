"""bps.host.base -- template for all bps.host implementations.

This module provides the template for all bps.host implementations,
specifying abstract / default implementations for all the functions
they should provide, as well as internal helper methods.

TODO: under unix, if we're run as root or as user w/o home dir, should probably store state in /var
TODO: find_exe needs to deal w/ CWD
"""
#=========================================================
#imports
#=========================================================
#core
from logging import getLogger
import os
import subprocess
import sys
from warnings import warn
import time
#pkg
from bps.types import BaseClass
from bps.fs import filepath,  posix_to_local
from bps.host.const import DESKTOPS
from bps.meta import abstractmethod
from bps.warndep import deprecated_method
#local
log = getLogger(__name__)

#=========================================================
#primary interface
#=========================================================
class BackendInterface(BaseClass):
    """this is minimum interface that all backend implementations must adhere to.
    the names correspond to the ``bps3.host`` functions, and are documented there.
    """
    #=========================================================
    #creation
    #=========================================================
    @classmethod
    def create(cls):
        "create new backend handler"
        #NOTE: this is provided so backend classes can return
        #an instance of another backend class if they wish
        #(such as PosixBackend detecting and returning a CygywinBackend)
        return cls()

    #=========================================================
    #process management
    #=========================================================
    def get_pid(self):
        "wrapper for os.getpid, for symetry"
        return os.getpid()

    @abstractmethod
    def terminate_pid(self, pid, retry, kill, timeout):
        """send hard-kill signal to *pid*,
        repeating every *retry* seconds if retry defined,
        handing off to kill_pid after *kill* seconds if defined,
        and giving up returning False after *timeout* seconds if timeout defined.
        """

    @abstractmethod
    def kill_pid(self, pid, retry, timeout):
        """send hard-kill signal to *pid*,
        repeating every *retry* seconds if retry defined,
        and giving up returning False after *timeout* seconds if timeout defined
        """

    @abstractmethod
    def has_pid(self, pid):
        "Return True if the process id *pid* exits, False if it doesn't."
        #TODO: would like to detect process status (running, waiting, zombie, etc)
        # as return richer info on request

    #=========================================================
    #shell interaction
    #=========================================================
    exe_exts = None #list of exe extensions used by host

    @abstractmethod
    def find_exe(self, name, extra_paths, paths=None):
        "find exe by name in PATH, or return None"

    #=========================================================
    #desktop interaction
    #=========================================================
    def get_desktop_name(self):
        "return name of desktop environment, one of the DESKTOP_TYPE strings"

    def desktop_open(self, path, action, mimetype):
        "attempt to open file using specified action via desktop environment"

    #=========================================================
    #resource discovery
    #=========================================================
    @abstractmethod
    def user_by_login(self, login):
        "return UserInfo for user w/ matching login"

    @abstractmethod
    def user_by_uid(self, uid):
        "return UserInfo for user w/ matching uid"

    @abstractmethod
    def get_env_paths(self):
        "return UserInfo built from current environment"

    @abstractmethod
    def get_app_paths(self, name):
        "return ProgPaths for application"

    @abstractmethod
    def get_service_paths(self, name, login, home):
        "return ProgPaths for service"

    #=========================================================
    #EOC
    #=========================================================

#=========================================================
#helper classes
#=========================================================
class _Info(BaseClass):
    def __init__(self, **kwds):
        for k, v in kwds.iteritems():
            if k.endswith("_file") or k.endswith("_dir") or k.endswith("_path"):
                v = filepath(v)
            setattr(self, k, v)

class UserProfile(_Info):
    """This class represents all the information about a given user account,
    as returned by :func:`find_user`.

    All :class:`UserProfile<>` instances will have the following attributes:

        .. attribute:: login

            The login name of the user.

        .. attribute:: name

            The display name of the user, as a string.

        .. attribute:: home_dir

            Path to the user's home directory.
            Should always be defined & exist.

        .. attribute:: desktop_dir

            Path to the user's desktop. Will be defined IFF it exists.

        .. attribute:: docs_dir

            Path to user's documents directory. Will be defined IFF it exists.

            .. NOTE::
                The logic of this directory's selection is currently a little hackneyed.

        .. attribute:: start_dir

            Chosen from one of the above, this should always be a good directory
            to open a file browser into.

        .. attribute:: state_dir

            Directory applications should use to store persistent application state.
            This uses ``APPDATA`` under windows, and ``~/.config`` under posix.

    These attributes will only be defined under a ``posix`` environment,
    they will be set to ``None`` for all others:

        .. attribute:: uid

            Integer uid assigned to account.

        .. attribute:: gid

            Integer gid assigned to account's primary group.

        .. attribute:: shell_file

            Path to user's default shell.
    """
    #=========================================================
    #os independant
    #=========================================================

    #-----------------------------------------------
    #user stats
    #-----------------------------------------------
    name = None #display name of user
    login = None #login name of user

    #-----------------------------------------------
    #resource paths
    #-----------------------------------------------
    home_dir = None #path to home directory (should always be defined & exist)
    desktop_dir = None #path to desktop directory (should always be defined IF exists)
    docs_dir = None #path to user's documents (should always be defined IF exists)

    #path filebrowsers should start in (should always be defined)
    def _get_start_dir(self):
        return self.desktop_dir or self.home_dir
    start_dir = property(_get_start_dir)

    #-----------------------------------------------
    #app info helpers
    #-----------------------------------------------
    #XXX: could list some desktop stuff here
    state_dir = None #path where apps should store config (AppData under win32, .config under posix)

    #=========================================================
    #posix
    #=========================================================
    uid = None #uid of user
    gid = None #uid of user's primary group

    shell_file = None #path to user's default shell

    #=========================================================
    #win32
    #=========================================================

    #=========================================================
    #EOC
    #=========================================================

class EnvPaths(_Info):
    """This class represents all the information about the current environment's
    resource paths, as returned by :func:`get_env_paths`. It should not be instantiated directly.
    Any values not defined under the current environment will be set to `None`.

    All :class:`EnvPaths<>` instances will have the following attributes:

        .. attribute:: login

            The login name of the user account we were run from.
            May not always be defined.

        .. attribute:: home_dir

            Path to the user's home directory.
            Will always be present, unless your script is being run from ``/etc/init.d``.

        .. attribute:: desktop_dir

            Path to the user's desktop.
            Will be defined if and only if it exists.

        .. attribute:: docs_dir

            Path to user's documents directory.
            Will be defined if and only if it exists.

            .. warning::
                The logic of this directory's selection is currently a little hackneyed
                under posix.

        .. attribute:: start_dir

            Chosen from one of the above, this should always be a good directory
            to open a file browser into.

        .. attribute:: state_dir

            Directory applications should use to store configuration.
            This uses ``%APPDATA%`` under windows, and ``~/.config`` under posix.

    The following attributes will only be defined for posix,
    they will be set to ``None`` for all all other OSes:

        .. attribute:: shell_file

            Path to the shell we were run under.

    .. note::

        This class contains a subset of same attributes as :class:`UserProfile`,
        but the contents of this class are derived from ``os.environ``, whereas
        the contents of that class are derived from the host's user account database.
        Thus, while they will frequently be in agreement, this is not a guarantee.
    """
    #=========================================================
    #os independant
    #=========================================================

    #-----------------------------------------------
    #user stats
    #-----------------------------------------------
    login = None #login name of user

    #-----------------------------------------------
    #resource paths
    #-----------------------------------------------
    home_dir = None #path to home directory (should always be defined & exist)
    desktop_dir = None #path to desktop directory (should always be defined IF exists)
    docs_dir = None #path to user's documents (should always be defined IF exists)

    #path filebrowsers should start in (should always be defined)
    def _get_start_dir(self):
        return self.desktop_dir or self.home_dir
    start_dir = property(_get_start_dir)

    #-----------------------------------------------
    #app info helpers
    #-----------------------------------------------
    #XXX: could list some desktop stuff here
    state_dir = None #path where apps should store config (AppData under win32, .config under posix)

    #=========================================================
    #posix
    #=========================================================
    shell_file = None #path to user's default shell

    #=========================================================
    #win32
    #=========================================================

    #=========================================================
    #EOC
    #=========================================================

class ProgPaths(_Info):
    """This class is used to hold the results of a :func:`get_app_paths` call.
    See that function for more details.

    Each :class:`ProgInfo<>` object contains the following attributes:

        .. attribute:: name

            The name of the application, as passed into :func:`get_app_paths`,
            after being normalized for host naming conventions.

        .. attribute:: state_dir

            The application may use this directory to store any persistent data
            which should be kept between invocations of the application,
            and should survive system reboots, etc.

            Under windows, this will point to the ``%APPDATA%/{name}`` directory,
            and under posix, this will point to ``~/.config/{name}``

            .. note::
                For services, this will generally be a read-only directory, eg ``/etc``

        .. attribute:: run_dir

            The application may use this directory to store any data
            which does not need to persist past the current invocation of the program.
            Normally, this is set to the same value as ``state_dir``.

        .. attribute:: cache_dir

            Directory to stored cached data. Usually defaults to ``{state_dir}/cache``.

        .. attribute:: lock_file

            Recommending location for application's lock file.
            Usually defaults to ``{run_dir}/{name}.lock``

    For profiles generated by :func:`get_service_paths`, the following
    attributes will also be set:

        .. attribute:: config_dir

            This should point to (usually read-only) default configuration
            for the service. Eg, this is ``/etc/{name}`` under posix.

        .. attribute:: log_file

            Suggested log file for service.
    """
    name = None #name of application (used to fill in some paths)
    first_name = None

    state_dir = None #path to persistent state directory
    run_dir = None #path to run-time state directory
    cache_dir = None #path to cache directory (usually state_dir / cache)
    lock_file = None #path to lock file (usually run_dir / pid.lock)

    config_dir = None #path to config directory
    log_file = None #path to log file

#=========================================================
#base backend class
#=========================================================
class BaseBackend(BackendInterface):
    "base backend class which provides helpers needed by most implementations"
    #=========================================================
    #class attrs
    #=========================================================
    pid_check_refresh = .1 #delay in terminate/kill_pid loop

    #=========================================================
    #instance attrs
    #=========================================================

    #desktop interaction attrs
    desktop_loaded = False #set to True when desktop discover run
    desktop_name = None #desktop name when loaded

    #resource discovery attrs
    resources_loaded = False
    env = None #EnvProfile filled out by load_resources

    #=========================================================
    #creation
    #=========================================================

    def __init__(self,  **kwds):
        self.__super.__init__(**kwds)
        if not isinstance(self.exe_exts, tuple):
            self.exe_exts = tuple(self.exe_exts)

    #=========================================================
    #process management
    #=========================================================
    def terminate_pid(self, pid, retry, kill, timeout):
        """wraps _terminate_pid() and provides the complex behavior host.terminate_pid requires"""
        if not self._terminate_pid(pid):
            return True
        now = time.time()
        retry_after = now + retry if retry else None
        kill_after = now + kill if kill else None
        timeout_after = now + timeout if timeout and timeout > kill else None
        delay = self.pid_check_refresh
        while True:
            time.sleep(delay)
            if not self.has_pid(pid):
                return True
            now = time.time()
            if retry_after and retry_after <= now:
                if not self._terminate_pid(pid):
                    return True
                retry_after = now + retry
            if kill_after and kill_after <= now:
                #NOTE: we decrease timeout since it measures TOTAL amount of time spent signalling.
                if timeout:
                    if timeout > kill:
                        timeout -= kill
                    else:
                        log.warning("terminate_pid(): timeout window less than kill window: %r vs %r", timeout, kill)
                        timeout = 30
                return self.kill_pid(pid, retry, timeout)
            if timeout_after and timeout_after <= now:
                return False

    def kill_pid(self, pid, retry, timeout):
        """wraps _kill_pid() and provides the complex behavior host.kill_pid requires"""
        if not self._kill_pid(pid):
            return True
        now = time.time()
        retry_after = now + retry if retry else None
        timeout_after = now + timeout if timeout else None
        delay = self.pid_check_refresh
        while True:
            time.sleep(delay)
            if not self.has_pid(pid):
                return True
            now = time.time()
            if retry_after and retry_after <= now:
                if not self._kill_pid(pid):
                    return True
                retry_after = now + retry
            if timeout_after and timeout_after <= now:
                return False

    #---------------------------------------------------------
    #subclass interface
    #---------------------------------------------------------
    @abstractmethod
    def _terminate_pid(self, pid):
        "helper to terminate specified process"
        #returns True if signal sent, False if pid not found (ala has_pid)

    @abstractmethod
    def _kill_pid(self, pid):
        "helper to kill specified process"
        #returns True if signal sent, False if pid not found (ala has_pid)

    #=========================================================
    #shell interaction
    #=========================================================
    def find_exe(self, name, extra_paths=None, paths=None):
        "scan host os's exe path for binary with specified name"
        #NOTE: for most OS's, this won't need to be overridden.
        if paths is None:
            paths = self.get_exe_paths()
        elif extra_paths:
            paths = list(paths) #don't let extra paths modify original
        if extra_paths:
            paths.extend(extra_paths)
        #FIXME: should CWD be included?
        for prefix in paths:
            #XXX: will expandvars work right under nt?
            prefix = os.path.expanduser(os.path.expandvars(prefix))
            for ext in self.exe_exts:
                path = os.path.join(prefix, "%s%s" % (name,  ext))
                if os.path.exists(path):
                    return filepath(path)
        return None

    def get_exe_paths(self):
        "[find_exe helper] return list of paths to check"
        #XXX: this strips null directories out... should they be treated as '.', or ignored?
        return [ path for path in os.environ["PATH"].split(os.path.pathsep) if path ]

    #=========================================================
    #desktop interaction
    #=========================================================

    #---------------------------------------------------------
    #desktop discovery helpers
    #---------------------------------------------------------
    def init_desktop(self):
        "delays desktop discovery if needed"
        if not self.desktop_loaded:
            self.load_desktop()
            assert self.desktop_name in DESKTOPS
            self.desktop_loaded = True

    def load_desktop(self):
        self.desktop_name = self.detect_desktop()

    def detect_desktop(self):
        "helper to detect what type of desktop environment is in use, returning id string or None"
        get = os.environ.get
        has = os.environ.__contains__

        #check for windows desktop
        if os.name == "nt" or os.name == "ce":
            return "windows"

        #check for osx
        if os.name == "osx":
            return "osx"

        #check for X11 environments
        if os.environ.get("DISPLAY"):
            ds = get("DESKTOP_SESSION")

            #check for kde
            #XXX: we could check for kde4 before windows/macosx
            if ds == "kde" or has('KDE_SESSION_UID') or has('KDE_FULL_SESSION'):
                #XXX: distinguish kde3 / kde4?
                return "kde"

            #check for gnome
            if ds == "gnome" or has('GNOME_SESSION_ID'):
                return "gnome"

            #check for xfce
            if self.find_exe("xprop"):
                #XXX: is there a easier way to detect xfce?
                p = subprocess.Popen(['xprop',  '-root',  '_DT_SAVE_MODE'],  stdout=subprocess.PIPE)
                p.wait()
                v = p.stdout.read().strip()
                if v == '_DT_SAVE_MODE(STRING) = "xfce4"':
                    return "xfce"

        #give up
        return None

    #---------------------------------------------------------
    #interface helpers
    #---------------------------------------------------------
    def get_desktop_name(self):
        #subclasses shouldn't need to override this (tweak detect_desktop instead)
        self.init_desktop()
        return self.desktop_name

    def desktop_open(self, path, action, mimetype):
        #subclasses will want to override this, thus is just a stub
        #they will also want to call self.init_desktop()
        return self.stub_open(path, action, mimetype)

    def stub_open(self, path, action, mimetype):
        "stub for when no opener is available"
        warn("stub desktop open(): file not opened: path=%r action=%r mimetype=%r" %
             (path, action, mimetype))
        return None

    #=========================================================
    #resource discovery
    #=========================================================
    #NOTE: this code assumed env profile is built up once, and used by other bits

    def init_resources(self):
        if not self.resources_loaded:
            self.load_resources()
            self.resources_loaded = True

    def load_resources(self):
        self.env = EnvPaths()

    def get_env_paths(self):
        "return EnvPaths instance"
        self.init_resources()
        return self.env

    def norm_prog_name(self, name):
        "helper for normalized program names"
        name = name.replace(" ", "-")
        if '/' in name:
            tail = name.rsplit("/", 1)[1]
            name = posix_to_local(name)
        else:
            tail = name
        return name, tail

    def get_app_paths(self, name):
        "standard app path creator, works for windows and posix"
        env = self.get_env_paths()
        name, tail = self.norm_prog_name(name)
        state_dir = run_dir = env.state_dir / name
        return ProgPaths(
            name=name, first_name=tail,
            state_dir=state_dir,
            run_dir=run_dir,
            cache_dir=state_dir / "cache",
            lock_file=run_dir / (tail + ".pid"),
            )

    #=========================================================
    #EOC
    #=========================================================

#=========================================================
#EOC
#=========================================================
