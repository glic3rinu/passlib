"""bps3.hosts unittest script.

.. warning::
    In order to test the host detection properly,
    this module does some heavy monkeypatching to the ``os`` module.
    If something goes wrong, it may leave the ``os`` module seriously
    messed up for the rest of the process' lifetime.
    By seriously, I mean ``os.name`` reporting ``nt`` when under ``posix`` :)

FIXME: should rewrite this to just run an os-specific set of checks
for whatever os it's being run under.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os.path
import sys
from unittest import TestCase
from logging import getLogger
from warnings import warn
import warnings
#site
#pkg
from bps.fs import filepath
from bps.tests.utils import get_tmp_path, catch_warnings
#module
log = getLogger(__name__)

#=========================================================
#
#=========================================================
class EnvPathTest(TestCase):
    "test of bps3.host.get_env_path()"
    def setUp(self):
        unload_host()
        self.tmp_dir = get_tmp_path()
        self.backup = {}

    def tearDown(self):
        unpatch_modules(self.backup)

    if os.name == "nt":
        def test_nt(self):
            #===============
            #FIXME: patching os module is a really horrible way to make this test happen.
            # should just implement tests which run only on the correct os,
            # and fake the dir structure, etc... that way we don't have to worry about fileops going wrong.
            #===============

            #create nt environ in temp dir
            home = self.tmp_dir / "Documents and Settings" / "User"
            home.ensuredirs()
            (home / "Desktop").ensuredirs()
            (home / "My Documents").ensuredirs()
            config = home / "Application Data"
            config.ensuredirs()
            env = dict(
                USERPROFILE=str(home),
                PATH="c:\\Windows",
                APPDATA=str(config),
                PATHEXT=".wys;.wyg",
            )
            def winver():
                return (0, 0, 0, 2, 0)
            patch_modules(self.backup, **{
                "os": dict(name="nt", environ=env),
                "os.path": dict(pathsep=";", sep="\\"),
                "sys": dict(getwindowsversion=winver),
                })
            self.assertEqual(os.name, "nt")

            #import host, check backend
            from bps import host
            from bps.host.windows import WindowsBackend
            self.assertTrue(isinstance(host._backend, WindowsBackend))
            self.assertEqual(host._backend.profile, "nt")
            self.assertEqual(host.exe_exts, ('.wys', '.wyg'))

            #check env paths
            paths = host.get_env_path("all_paths")
            self.assertEqual(paths.home_dir, home)
            self.assertEqual(paths.state_dir, config)
            self.assertEqual(paths.desktop_dir, home / "Desktop")
            self.assertEqual(paths.docs_dir, home / "My Documents")
            self.assertEqual(paths.start_dir, home / "Desktop")

            #check app paths
            paths = host.get_app_path("xxx", "all_paths")
            self.assertEqual(paths.state_dir, config / "xxx")
            self.assertEqual(paths.cache_dir, config / "xxx" / "cache")
            self.assertEqual(paths.lock_file, config / "xxx" / "xxx.pid")

            #check app paths
            paths = host.get_app_path("xxx/yyy", "all_paths")
            self.assertEqual(paths.state_dir, config / "xxx" / "yyy")
            self.assertEqual(paths.cache_dir, config / "xxx" / "yyy" / "cache")
            self.assertEqual(paths.lock_file, config / "xxx" / "yyy" / "yyy.pid")

            #test legacy funcs
##                message=r"bps\.host: function 'get(Resource|State)Path' is deprecated, use .*",
##                module=r"bps\.tests\.test_host",
            with catch_warnings(record=True) as wmsgs:
                self.assertEqual(host.getResourcePath("home"), home)
                self.assertEqual(host.getResourcePath("desktop"), home / "Desktop")
                self.assertEqual(host.getResourcePath("docs"), home / "My Documents")
                self.assertEqual(host.getResourcePath("start"), home / "Desktop")
                self.assertEqual(host.getStatePath("xxx/yyy.txt"), config / "xxx" / "yyy.txt")
                #TODO: verify we get the right warning msgs back.
            #should be 4 deprecation warnings for getResourcePath,
            #   and 1 for getStatePath
            self.assertEqual(len(wmsgs), 5, str(", ".join(str(w) for w in wmsgs)))

#=========================================================
#helpers
#=========================================================
def unload_host():
    if 'bps.host' in sys.modules:
        del sys.modules['bps.host']

def patch_modules(backup, **kwds):
    for name, attrs in kwds.iteritems():
        mod = __import__(name, fromlist=['dummy'])
        if name in backup:
            orig = backup[name]
        else:
            orig = backup[name] = {}
        for k, v in attrs.iteritems():
            if k not in orig:
                orig[k] = getattr(mod, k, None)
            setattr(mod, k, v)

def unpatch_modules(backup):
    for name, orig in backup.iteritems():
        mod = __import__(name, fromlist=['dummy'])
        for k, v in orig.iteritems():
            setattr(mod, k, v)

#=========================================================
#EOF
#=========================================================
