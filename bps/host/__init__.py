"""bps.host -- Uniform access to host resources"""
#=========================================================
#imports
#=========================================================
#core
from logging import getLogger; log = getLogger(__name__)
import os.path
import subprocess
import sys
from warnings import warn
#pkg
from bps.fs import filepath, posix_to_local
from bps.types import BaseClass
from bps.warndep import relocated_function, deprecated_function
#module
from bps.host.base import UserProfile, EnvPaths, ProgPaths
from bps.host.const import DESKTOPS, ACTIONS
#local
__all__ = [
    #process management
    'get_pid', 'has_pid', 'terminate_pid', 'kill_pid',

    #desktop interaction
    "get_desktop_name", "desktop_open", "desktop_compose_email",

    #shell interaction
    "find_exe",

    #application resources
   ]

#=========================================================
#choose backend class, create backend singleton
#=========================================================
_backend = None
def _set_backend(cls):
    global _backend, exe_exts
    _backend = cls.create()
    exe_exts = _backend.exe_exts

#=========================================================
#process management
#=========================================================
get_pid = os.getpid #just for symetry

def has_pid(pid):
    """Check if the specified process *pid* exists: returns ``True`` if found, ``False`` it not"""
    if pid is None:
        raise ValueError, "no pid specified"
    return _backend.has_pid(pid)
    #TODO: would like to detect process status (running, waiting, zombie, etc) as return richer info on request

def term_pid(pid, retry=None, kill=30, timeout=60):
    """Send a signal to process *pid* to shut itself down and exit cleanly.

    :Parameters:
        pid
            The id of the process to be terminated.

        retry
            If not set, only one termination signal will be sent.

            If set to a positive number, a new termination signal
            will be sent every *retry* seconds, unless the process exits first.

        kill
            If set to a positive number, :func:`kill_pid` will be used
            to send a kill signal if the process hasn't exited within
            *kill* seconds of when the first termination signal was sent.

            If set to ``None``, :func:`kill_pid` will never be called.

        timeout
            If set to a positive number, the attempt to terminate or kill the
            process will timeout after *timeout* seconds, and this function
            will give up and return ``False``.

            If set to None, this function will wait forever or until the process exits.

    This is the preferred way to end a process,
    as :func:`kill_pid` doesn't give the process
    a chance to shut down cleanly.

    Under ``posix``, this uses the SIGTERM signal.
    Under windows, a more complicated system is used,
    involving ``ExitProcess`` and ``WM_CLOSE``.
    """
    if pid is None:
        raise ValueError, "no pid specified"
    if retry is not None and retry < 0:
        raise ValueError, "timeout must be None, or number > 0: %r" % (retry,)
    if kill is not None and kill < 0:
        raise ValueError, "timeout must be None, or number > 0: %r" % (kill,)
    if timeout is not None and timeout < 0:
        raise ValueError, "timeout must be None, or number > 0: %r" % (timeout,)
    if timeout and kill and timeout <= kill:
        raise ValueError, "timeout threshold must be > kill threshold: k=%r t=%r" % (kill, timeout)
    t = kill or timeout
    if t and retry and retry >= t:
        log.warning("terminate_pid(): retry value larger than timeout/kill threshold"
            ", will never fire: r=%r kt=%r", retry, t)
        retry = None
    return _backend.terminate_pid(pid, retry, kill, timeout)

terminate_pid = term_pid #alias

def kill_pid(pid, retry=None, timeout=30):
    """Send a signal to process *pid* to shut itself down **immediately**, without cleaning up first.

    :Parameters:
        pid
            The id of the process to be terminated.

        retry
            If not set, only one kill signal will be sent.

            If set to a positive number, a new kill signal
            will be sent every *retry* seconds, unless the process exits first.

        timeout
            If set to a positive number, the attempt to kill the
            process will timeout after *timeout* seconds, and this function
            will give up and return ``False``.

            If set to ``None``, this function will wait forever or until the process exits.

    This method of killing the process is more reliable,
    since the process cannot stop it from happening,
    but not as clean, since the process cannot shut down first.
    If you must, it is recommended to use :func:`term_pid` with the
    ``kill`` option set, so that the program gets a chance to exit cleanly first.

    Under ``posix``, this uses the SIGKILL signal.
    Under windows, this calls ``TerminateProc()``.
    """
    if pid is None:
        raise ValueError, "no pid specified"
    if retry is not None and retry < 0:
        raise ValueError, "timeout must be None, or number > 0: %r" % (retry,)
    if timeout is not None and timeout < 0:
        raise ValueError, "timeout must be None, or number > 0: %r" % (timeout,)
    if timeout and retry and retry >= t:
        log.warning("terminate_pid(): retry value larger than timeout threshold"
            ", will never fire: r=%r t=%r", retry, timeout)
        retry = None
    return _backend.kill_pid(pid, retry, timeout)

#reload_pid ? ala SIGHUP? is there any remotely equiv thing under windows?

#=========================================================
#shell interaction
#=========================================================
exe_exts = None #filled in by _set_backend()

def find_exe(name, extra_paths=None, paths=None):
    """
    Returns path to file which would have been executed if the command *name* was run in a shell,
    by locating it in host's command search path. Returned path will be absolute.
    If no command of that name can be found, returns ``None``.

    :Parameters:
        name
            The name of the command to search for, *without* any executable suffix
            added (e.g. ``.exe`` under windows). All known :attr:`exe_exts` will
            be checked in turn, for every directory in the command search path.
        extra_paths
            Optionally, a list of custom paths to be checked if the command
            can't be found in the host's command search path. This will
            be appended to the default search path.
        paths
            Optionally, a list of paths which will be used *in place of* the default
            executable search path.

    The environmental variable ``PATH`` is used as the command search path
    for both windows and posix. This command is the equivalent of the bash ``where`` command.

    For example, under a windows system with python installed::

        >>> #try finding notepad under windows
        >>> host.find_exe("notepad")
        'c:\\windows\\notepad.exe'

        >>> #try finding something not in standard search path
        >>> host.find_exe("myscript")
        None

        >>> #try finding something with help of a non-standard extra path
        >>> host.find_exe("myscript", extra_paths=["c:\\Program Files\\My App"])
        'c:\\Program Files\\My App\\myscript.bat'
    """
    if isinstance(extra_paths, (str, unicode)):
        extra_paths = extra_paths.split(os.path.pathsep)
    if isinstance(paths, (str, unicode)):
        paths = paths.split(os.path.pathsep)
    return _backend.find_exe(name, extra_paths, paths)

#TODO: would a find_lib be useful?

#=========================================================
#desktop interaction
#=========================================================
def get_desktop_name():
    """
    Return name of desktop environment currently in use.
    Will be one of ``windows``, ``osx``, ``kde``, ``gnome``, ``xfce``, or None.
    """
    value = _backend.get_desktop_name()
    assert value in DESKTOPS
    return value

def desktop_open(path,  action=None, mimetype=None):
    """
    Attempt to open file for user using program chosen by host.
    this attempts to provide os.startfile-like behavior on other oses.

    :Parameters:
        path
            Path to file that should be opened.
            If missing, an error is raised.

        action
            Specifies the *action* that should be taken to file.
            Valid values are listed in the table below.

        mimetype
            Optionally, a mime type may be specified,
            which may act as a hint to the desktop,
            if it can to use it.

    The following actions are generally available,
    but not supported under all environments:

        =========== ============================================================================

        Action      Description

        ----------- ----------------------------------------------------------------------------

        ``open``    Desktop will open file in viewer/editor, chosen at it's discretion.
                    This action is the default, and the one that will be used
                    as a fallback if the specified action isn't supported by the desktop.
                    This action should be supported for all desktops detectable.

        ``view``    Desktop will open file in a viewer if possible, else fall back to an editor.
                    Currently, most desktops will treat this the same as ``open``.

        ``edit``    Desktop will open file in editor if possible, else fall back to a viewer.
                    Currently, most desktops will treat this the same as ``open``.

        ``print``   Desktop will open a print dialog directly if possible, else fall back to a
                    viewer. Currently, this won't work for ANY desktops, and will be treated
                    the same as ``open``.

        ``exec``    Desktop will execute the file using a registered assistant.
                    While this is supported by most desktops, for files where this doesn't make
                    sense, the default is usually to treat it like ``open``.

        ``browse``  Desktop should open a file browser to this path (usually a dir).
                    This is supported by few desktops.

        =========== ============================================================================

    ..
        TODO: document exactly which desktops support which actions
    """
    orig = path
    path = filepath(orig).abspath
    if not path.exists:
        raise ValueError, "path not found: %r" % (orig,)
    if not action:
        action = "open"
    if action not in ACTIONS:
        raise ValueError,  "unknown action: %r" % (action, )
    return _backend.desktop_open(path, action, mimetype)

import mailclient
mailclient.find_exe = find_exe
def desktop_compose_email(*args, **kwds):
    """tell currently configured email client to open a new "compose email" window,
    with the specified fields automatically filled in.

    :Parameters:
        to
            list of email addrs, or string containing semicolon separated email addrs.
        cc
            same format as 'to', but for 'cc' field
        bcc
            same format as 'to', but for 'bcc' field
        subject
            optional subject text
        body
            optional body text (for now, should be text/plain)
        attachments
            not implemented: would like to support list of filepaths,
            as well as dict mapping names => buffers (or filepaths)

    .. note::

        This is merely an alias for :func:`bps.host.mailclient.compose_email`,
        see that function and it's module for additional features,
        such as the ability to examine the detected email clients,
        and setting the preferred email client.

    .. note::

        The mailclient module current supports Thunderbird and Outlook,
        but uses a driver system which should allow for easy registration
        of new client drivers, whether internal or external.
    """
    return mailclient.compose_email(*args, **kwds)

#=========================================================
#resource discovery
#=========================================================
def get_env_path(path):
    """Locates various environment-defined paths in an OS-agnostic fashion.

    *path* should specify which one of the pre-defined host resource paths
    should be returned, for example, ``home_dir`` will return the current
    user's home directory. For a full list of the predefined path names available,
    see the documentation for :class:`EnvPaths`.

    These paths are derived from ``os.environ`` and OS-specific conventions.
    The special path ``all_paths`` will return the :class:`EnvPaths` instance itself,
    for easier access to multiple paths.

    Example usage::
        >>> from bps import host

        >>> #locate home directory
        >>> host.get_env_path("home_dir")
        'c:\\Documents and Settings\\James'

        >>> #locate user's desktop
        >>> host.get_env_path("desktop_dir")
        'c:\\Documents and Settings\\James\\Desktop'

        >>> #get env path object to examine later
        >>> ep = host.get_env_path("all_paths")
        >>> print ep.home_dir
        'c:\\Documents and Settings\\James'
        >>> print ep.docs_dir
        'c:\\Documents and Settings\\James\\My Documents'

    .. seealso:: :class:`EnvPaths`
    """
    ep = _backend.get_env_paths()
    if path == "all_paths":
        return ep
    else:
        return getattr(ep, path)

# get_env_info() - have this return EnvInfo (rename from paths)
#   instead of all_paths option

def find_user(login=None, uid=None, missing="ignore"):
    """Given either a *login* or a posix *uid*,
    returns a :class:`UserInfo` object for the specified user,
    or None if no match was found.

    If *login* begins with a "#", as in ``#101``,
    this will be treated as an encoded uid, ala apache's ``User`` directive.
    """
    assert missing in ["ignore", "error"]
    if login and uid:
        raise ValueError, "can't specified login & uid at the same time"
    if login and login.startswith("#"):
        uid = int(login[1:])
    if login:
        return _backend.user_by_login(login, missing)
    elif uid:
        return _backend.user_by_uid(uid, missing)
    elif missing == "error":
        raise ValueError, "must specify one of login or uid"
    else:
        return None

def get_app_path(name, path):
    """Returns the default resource paths for given application.

    Given the *name* of your application, this returns a :class:`ProgPaths` instance
    populated with the default resource paths the application should use,
    per local OS conventions.

    The returned :class:`ProgPaths` will be fully populated with paths relevant
    to an application being run by a user (as opposed to :func:`get_service_path`).
    This paths are only a recommendation based on local host conventions.

    For OSes such as posix, you may wish to do something completely different.
    """
    #XXX: support desktop-environment specific paths (eg, kde vs gnome locations?)
    pp = _backend.get_app_paths(name)
    if path == "all_paths":
        return pp
    else:
        return getattr(pp, path)

# get_app_info() - have this return AppInfo (rename from paths)
#   instead of all_paths option

def get_service_path(name, path, login=None, home=None):
    """Returns the default resource paths for given service.

    Given the *name* of your service, this returns a :class:`ProgPaths` instance
    populated with the default resource paths the service should use,
    per local OS conventions.

    The returned :class:`ProgPaths` will be fully populated with paths relevant
    to a service being launched by the operating system (as opposed to :func:`get_app_path`).
    This paths are only a recommendation based on local host conventions.

    If *login* is specified, it is assumed to be the name of a login account
    assigned to the service itself, and the service's paths will be subdirs
    of that account's home directory.

    If *home* is specified, it will act like the home directory of a user
    assigned via *login*.

    For OSes such as posix, you may wish to do something completely different.

    .. warning::

        This function is relatively new, and has been tested
        under few real-world use cases, so the current behavior may
        leave much to be desired, and thus it may be tweaked in the future.
    """
    pp = _backend.get_service_paths(name, login, home)
    if path == "all_paths":
        return pp
    else:
        return getattr(pp, path)

# get_service_info() - have this return ServiceInfo (rename from paths)
#   instead of all_paths option

#=========================================================
#load correct backend implementation
#=========================================================
#NOTE: a singleton object instance was chosen over the
# "from xxx import *" solution that the os module uses
# for the reason that inheritance w/ a single scope
# is simply not available w/ the module based solution,
# and inheritance greatly increased the common code's utility.
if os.name == "nt" or os.name == "ce":
    #NOTE: we might want to check for wine here, at least so user info would be correct
    #NOTE: combining ce & nt here, but that's just a guess
    # that it'll behave the same for our purposes
    from bps.host.windows import WindowsBackend as _Backend
elif os.name == "posix":
    #NOTE: we might want to check for wine here, at least so user info would be correct
    #NOTE: we might want to check for cygwin/mingw here.
    from bps.host.posix import PosixBackend as _Backend
else:
    #TODO: would really like to support more, just don't have access to them.
    # esp would like Mac OS X support!
    raise ImportError, "no OS specific bps.host module found: %r" % (os.name,)
_set_backend(_Backend)

#=========================================================
#deprecated functions, to be removed in the future
#=========================================================
def _grp(key):
    """return a specified resource path.
    keys that are always present... and EnvironmentError will be raised if they can't be configured:
        home - location of user's home directory
        state - base path for storing application configuration (see getStatePath)
        start - preferred starting path for file browsing
    keys that may be present (will return None if missing)...
        docs - location of user's documents directory
            on windows, this will usually be the user's "My Documents" directory.
        desktop - location of user's desktop directory
    """
    if key in ("home", "state", "start", "docs", "desktop"):
        return get_env_path(key + "_dir")
    raise ValueError, "unknown key: %r" % (key,)
getResourcePath = relocated_function("getResourcePath", _grp, "get_env_path()")
get_resource_path = relocated_function("get_resource_path", _grp, "get_env_path()")

def _gsp(CfgName):
    """
    given an application prefix,
    returns a place to store user-specific application state.
    .. note::
        if you want to specify subdirectories, such as
        mycompany / myapp, use forward slashes only,
        they will be translated.
    """
    if '/' in CfgName:
        if os.path.sep != '/':
            CfgName = CfgName.replace("/", os.path.sep)
        CfgName, tail = os.path.split(CfgName)
    else:
        tail = None
    path = get_app_path(CfgName, "state_dir")
    if tail:
        path /= tail
    return path
getStatePath = relocated_function("getStatePath", _gsp, "get_app_path('state_dir')/xxx or get_service_path('state_dir')/xxx")
get_state_path = relocated_function("get_state_path", _gsp, "get_app_path('state_dir') or get_service_path('state_dir')")

desktop_name = relocated_function("desktop_name", get_desktop_name)

#deprecated proxy for accessing host info
class _BackendProxy(object):
    def __getattr__(self, attr):
        warn("bps.host.Host.%s() is deprecated, use bps.host.%s() instead" % (attr, attr), DeprecationWarning)
        if attr == "find_exe":
            return find_exe
        #NOTE: no other attrs were ever used.
        raise AttributeError, "Host.%s not supported" % attr
Host = _BackendProxy() #helper which proxies currently backend, useful for importing

@deprecated_function("bps.host")
def get_backend():
    """this creates (if needed) and returns the
    single backend instance appropriate for the host"""
    return _backend

#=========================================================
#EOC
#=========================================================
