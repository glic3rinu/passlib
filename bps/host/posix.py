"""
bps.host - functions for discovering host resources.

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
import errno
import signal as sigmod
import time
import re
import stat
#pkg
from bps.meta import is_seq
from bps.types import Undef, BaseClass
from bps.fs import filepath,  posix_to_local
from bps.host.base import BaseBackend, UserProfile, ProgPaths
#local
log = getLogger(__name__)
#=========================================================
#posix
#=========================================================
class PosixBackend(BaseBackend):
    #=========================================================
    #options
    #=========================================================
    prefer_xdg = False #: if true, xdg will be used over kde/gnome
    kde_prefer_exec = True #: if true, kfmclient's "exec" mode will be used instead of "openURL"
        #this gives better behavior, but the safety/semantics seem to be under debate

    #=========================================================
    #instance attrs
    #=========================================================
    _default_open = None #preferred desktop opener, set by load_desktop()

    #=========================================================
    #process management
    #=========================================================
    def _terminate_pid(self, pid):
        return _send_signal(pid, sigmod.SIGTERM)

    def _kill_pid(self, pid):
        return _send_signal(pid, sigmod.SIGKILL)

    def has_pid(self, pid):
        "check if process exists - true if yes, false if no"
        try:
            os.kill(pid, 0)
        except os.error, detail:
            #FIXME: this may raise errno.EPERM if we don't have perm to signal proc.
            #might be better to check for "/proc" first
            if detail.errno == errno.ESRCH: #no such process
                return False
            else:
                raise
        return True

    #=========================================================
    #shell interaction
    #=========================================================
    exe_exts = ("",)

    #=========================================================
    #desktop interaction
    #=========================================================
    def load_desktop(self):
        self.__super.load_desktop()
        self._default_open = self.choose_default_opener()

    def choose_default_opener(self):
        if self.prefer_xdg and self.has_xdg_open():
            return self.xdg_open
        if self.desktop_name == "kde" and self.has_kde_open():
            return self.kde_open
        if self.desktop_name == "gnome" and self.has_gnome_open():
            return self.gnome_open
        if not self.prefer_xdg and self.has_xdg_open():
            return self.xdg_open
        return self.stub_open

    def desktop_open(self, *args):
        "launch file using specified action"
        self.init_desktop()
        return self._default_open(*args)

    #-----------------------------------------------
    #kde
    #-----------------------------------------------
    def has_kde_open(self):
        return bool(self.find_exe("kfmclient"))

    def kde_open(self,  path,  action,  mimetype):
        #kfmclient only supports two of this library's actions,
        #   "openURL" (which acts sort like view/open)
        #   and "exec" (which acts more like exec/edit)
        if action == "exec":
            kaction = "exec"
        elif action == "browse":
            kaction = "openURL"
        elif self.kde_prefer_exec:
            kaction = "exec"
        else:
            kaction = "openURL"
        args = [ 'kfmclient',  kaction,  path]
        if kaction == "openURL" and mimetype:
            args.append(mimetype)
        log.debug("launching opener: %r",  args)
        subprocess.Popen(args)

    #-----------------------------------------------
    #gnome
    #-----------------------------------------------
    def has_gnome_open(self):
        return bool(self.find_exe("gnome-open"))

    def gnome_open(self,  path,  action,  mimetype):
        subprocess.Popen(['gnome-open',  path])

    #-----------------------------------------------
    #xdg
    #-----------------------------------------------
    def has_xdg_open(self):
        return bool(self.find_exe("xdg-open"))

    def xdg_open(self,  path,  action,  mimetype):
        subprocess.Popen(['xdg-open',  path])

    #=========================================================
    #resource discovery
    #=========================================================
    def load_resources(self):
        self.__super.load_resources()
        env = self.env
        get = os.environ.get

        #FIXME: if there's an APPDATA, we're probably running under mingw / cygwin, might wanna deal w/ that

        #detect if we're running under a user
        home_dir = filepath(get("HOME"))
        if home_dir and home_dir.exists:
            env.login = get("USER") #XXX: is this the right one? USERNAME also defined.
            env.shell_file=filepath(get("SHELL"))
            env.home_dir=home_dir
            env.mode = "user"
            self._fill_user_info(env, is_env=True)
            return

        #check if we're running under initd
        #XXX: should be a more reliable way
        if 'HOME' not in os.environ and os.getuid() == 0:
            #we're probably launched from an initd script,
            #or a similarly restricted environment.
            #so assume we're using root's home dir.
            env.mode = "initd"
            return

        raise NotImplementedError, "bps3.host doesn't understand environment"

    #-----------------------------------------------
    #user related info
    #-----------------------------------------------
    def user_by_login(self, login, missing):
        for info in iter_user_info():
            if info['name'] == login:
                return self._build_user_info(info)
        if missing == "ignore":
            return None
        else:
            raise KeyError, "no user with login: %r" % login

    def user_by_uid(self, uid, missing):
        for info in iter_user_info():
            if info['uid'] == uid:
                return self._build_user_info(info)
        if missing == "ignore":
            return None
        else:
            raise KeyError, "no user with uid: %r" % uid

    def _build_user_info(info):
        "build user info out of passwd info"
        stats = info['stats']
        user = UserProfile(
            login=info['name'],
            name=stats.split(',', 1)[0].strip() if ',' in stats else stats, #XXX: is this right?
            uid=info['uid'],
            gid=info['gid'],
            shell_file=info['shell_file'],
            home_dir=info['home_dir'],
            )
        self._fill_user_info(user)
        return user

    def _fill_user_info(self, info, is_env=False):
        "fill out common dirs in user info"
        #find desktop...
        for name in ("Desktop", "DESKTOP"):
            path = info.home_dir / name
            if path.exists:
                info.desktop_dir = path
                break

        #find documents...
        for name in ("docs", "Docs", "documents", "Documents", "My Documents"):
            path = info.home_dir / name
            if path.exists:
                info.docs_dir = path
                break

        info.state_dir = info.home_dir / ".config"
        return info

    #-----------------------------------------------
    #program related resources
    #-----------------------------------------------
    def get_app_paths(self, name):
        self.init_resources()
        if self.env.mode == "initd":
            raise RuntimeError, "applications should not be run from init.d"
        return self.__super.get_app_paths(name)

    def get_service_paths(self, name, login, home):
        env = self.get_env_paths()
        name, tail = self.norm_prog_name(name)
        if login:
            #if a login account has been assigned to service, use it's home directory
            for info in iter_user_info():
                if info['user'] == login:
                    home = info['home']
                    break
            else:
                raise KeyError, "user not found: %r" % (login,)
        if home:
            home = filepath(home)
            state_dir = run_dir = home / "state" #XXX: don't like this name
            return ProgPaths(
                name=name, first_name=tail,
                state_dir=state_dir,
                run_dir=run_dir,
                cache_dir=home / "cache",
                lock_file=run_dir / (tail + ".pid"),
                config_dir=home / "etc",
                log_file=home / "log" / (tail + ".log"),
                )
        state_dir = filepath("/var/lib", name)
        run_dir = filepath("/var/run", name)
        return ServiceProfile(
            name=name, first_name=tail,
            state_dir=state_dir,
            run_dir=run_dir,
            cache_dir=filepath("/var/cache",name),
            lock_file=run_dir / (tail + ".pid"),
            config_dir=filepath("/etc", name),
            log_file=filepath("/var/log", name + ".log"),
            )

    #=========================================================
    #EOC
    #=========================================================

#=========================================================
#posix-specific helper functions
#=========================================================
DEFAULT_PASSWD = "/etc/passwd"
DEFAULT_SHADOW = "/etc/shadow"
PASSWD_COLS = [ "name", None, "uid", "gid", "stats", "home", "shell" ]
SHADOW_COLS = [ "name", "hash", "last_changed", "must_change", "warn_expire", "disabled_after", "disabled", None]
    #ex: "root:!:14251:0:99999:7:::"
    # xxx: see 'man shadow' for details on fields
    #invalid hash (eg * or !) means no login permitted

def _parse_passwd_row(row):
    info = dict(entry for entry in zip(PASSWD_COLS, row.split(":")) if entry[0])
    #FIXME: 'stats' contains name,phone, some other stuff, separated by ','
    info['uid'] = int(info['uid'])
    info['gid'] = int(info['gid'])
    info['home'] = filepath(info['home'])
    info['shell'] = filepath(info['shell'])
    return info

def iter_user_info(passwd=DEFAULT_PASSWD, shadow=DEFAULT_SHADOW):
    "iterate through unix-style passwd & shadow files, returning rows as dict"
    try:
        ph = file(passwd, "r")
    except IOError, err:
        if err.errno == 2: #no such file/dir
            log.warning("no such passwd file: %r", passwd)
            return
        raise
    try:
##        sh = None
##        if shadow:
##            try:
##                sh = file(passwd, "r")
##            except IOError, err:
##                if err.errno == 2: #no such file/dir
##                    log.warning("no such shadow file: %r", shadow)
##                elif err.errno == 13: #perm denied
##                    log.debug("not permitted to open shadow file: %r", shadow)
##                else:
##                    raise
        for row in ph:
            if row:
                yield _parse_passwd_row(row.rstrip())
    finally:
        ph.close()

DEFAULT_GROUP = "/etc/group"
GROUP_COLS = ['name', None, 'gid', 'members']

def _parse_group_row(row):
    info = dict(entry for entry in zip(GROUP_COLS, row.split(":")) if entry[0])
    #FIXME: 'stats' contains name,phone, some other stuff, separated by ','
    info['gid'] = int(info['gid'])
    info['members'] = [ m.strip() for m in info['members'].split(",") if m.strip() ]
    return info

def iter_group_info(group=DEFAULT_GROUP):
    "iterate through unix-style group files, returning rows as dict"
    try:
        ph = file(group, "r")
    except IOError, err:
        if err.errno == 2: #no such file/dir
            log.warning("no such group file: %r", group)
            return
        raise
    try:
##        sh = None
##        if shadow:
##            try:
##                sh = file(passwd, "r")
##            except IOError, err:
##                if err.errno == 2: #no such file/dir
##                    log.warning("no such shadow file: %r", shadow)
##                elif err.errno == 13: #perm denied
##                    log.debug("not permitted to open shadow file: %r", shadow)
##                else:
##                    raise
        for row in ph:
            if row:
                yield _parse_group_row(row.rstrip())
    finally:
        ph.close()

def resolve_uid(value, default=Undef, validate=True):
    "given a user login string, or string containing a uid, returns matching uid as integer"
    def helper():
        for info in iter_user_info():
            yield info['name'], info['uid']
    return _resolve_id("user", helper, value, default=default, validate=validate)

def resolve_gid(value, default=Undef, validate=True):
    "given a group name as a string, or string containing a gid, returns matching gid as integer"
    def helper():
        for info in iter_group_info():
            yield info['name'], info['gid']
    return _resolve_id("group", helper, value, default=default, validate=validate)

def _resolve_id(name, helper, value, default=Undef, validate=True):
    if validate:
        def vf(value):
            for n, v in helper():
                if v == value:
                    return value
            if default is Undef:
                raise KeyError, "unknown %s id: %r" % (name, value)
            else:
                return default
    else:
        def vf(value):
            return value
    if value is None or value == -1:
        return -1
    elif isinstance(value, int):
        return vf(value)
    elif isinstance(value, str):
        if value.startswith("#"):
            return vf(int(value[1:]))
        else:
            for n, v in helper():
                if n == value:
                    return v
            if default is Undef:
                raise KeyError, "unknown %s name: %r" % (name, value)
            else:
                return default
    else:
        raise TypeError, "%s name/id must be None, int, or string: %r" % (name, value)

def resolve_user(value, default=Undef):
    "given a uid, return user login string"
    def helper():
        for info in iter_user_info():
            yield info['uid'], info['name']
    return _resolve_name("user", helper, value, default=default)

def resolve_group(value, default=Undef):
    "given a gid, return group string"
    def helper():
        for info in iter_group_info():
            yield info['gid'], info['name']
    return _resolve_name("group", helper, value, default=default)

def _resolve_name(name, helper, value, default=Undef):
    if value is None or value == -1:
        return None
    if isinstance(value, str):
        try:
            if value.startswith("#"):
                value = int(value[1:])
            else:
                value = int(value)
        except ValueError:
            #try to resolve name
            for i, n in helper():
                if n == value:
                    return n
            if default is Undef:
                raise KeyError, "unknown %s id: %r" % (name, value)
            else:
                return default
        #else it's now an int
    if isinstance(value, int):
        for i, n in helper():
            if i == value:
                return n
        if default is Undef:
            raise KeyError, "unknown %s id: %r" % (name, value)
        else:
            return default
    else:
        raise TypeError, "%s name/id must be None, int, or string: %r" % (name, value)


#=========================================================
#
#=========================================================

#TODO: move this to fs.py ?
def chown(targets, user=None, group=None, recursive=False):
    "set permissions for an entire tree"
    uid = resolve_uid(user)
    gid = resolve_gid(group)
    if uid == -1 and gid == -1:
        return
    if is_seq(targets):
        targets = (filepath(path).abspath for path in targets)
    else:
        targets = [ filepath(targets).abspath ]
    for root in targets:
        if root.isdir and recursive:
            for base, dirnames, filenames in root.walk():
                os.chown(base, uid, gid)
                for name in filenames:
                    os.chown(base / name, uid, gid)
        else:
            os.chown(root, uid, gid)

#=========================================================
#signals
#=========================================================
##try:
##    import signal as sigmod
##except ImportError:
##    sigmod = None

def _send_signal(pid, signal):
    "helper for sending a signal, checking if it was received"
    try:
        os.kill(pid, signal)
    except os.error, detail:
        if detail.errno == errno.ESRCH: #no such process
            return False
        else:
            raise
    return True

##def send_signal(pid, signal, check, retry=None, timeout=None):
##    """helper for sending signals, with retry & timeout ability.
##
##    :Parameters:
##        pid
##            pid to send signal to
##        signal
##            name / value of signal
##        check
##            function to check if signal was received.
##            prototype is ``check(pid,signal) -> bool``, should
##            return True if loop should continue trying to send the signal.
##            ``host.has_pid`` is used here.
##        retry
##            number of seconds between send attempts,
##            or None if only 1 try.
##        timeout
##            number of seconds before giving up.
##
##    :Returns:
##        Returns True if signal was received,
##        False if timeout occurred.
##
##    XXX: this is an experimental func, it may be removed in the future.
##    """
##    #NOTE: this code is borrowed straight from BaseBackend.kill_pid
##    signal = _resolve_signum(signal)
##    _send_signal(pid, signal)
##    now = time.time()
##    retry_after = now + retry if retry else None
##    timeout_after = now + timeout if timeout else None
##    delay = .1
##    while True:
##        time.sleep(delay)
##        if not check(pid, signal):
##            return True
##        now = time.time()
##        if retry_after and retry_after <= now:
##            _send_signal(pid, signal)
##            retry_after = now + retry
##        if timeout_after and timeout_after <= now:
##            return False

#=========================================================
#EOF
#=========================================================
