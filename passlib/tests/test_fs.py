"""bps3.fs unittest script"""

#TODO: test filesystem property methods
#TODO: test file manipulation methods
#TODO: test dir manipulation methods
#TODO: test symlink manipulation methods
#TODO: test expand() method & shortcut functions

#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import time
import os.path
import stat
from functools import partial
SEP = os.path.sep
PAR = os.path.pardir
CUR = os.path.curdir
#package
from bps.error import types as errors
from bps.fs import filepath, FilePath, is_filepath, os_has_symlinks, parse_mode_mask, repr_mode_mask, chmod
from bps.tests.utils import TestCase, get_tmp_path, ak
#local
if SEP == "/":
    def local(path):
        return path
else:
    def local(path):
        return path.replace("/", SEP)

#=========================================================
#filepath function
#=========================================================
class ConstructorTest(TestCase):
    "test filepath() constructor"
    def test_none(self):
        "test None behavior"
        self.assertIs(filepath(None), None)

    various_data = [
        #arg1 [ arg2 ... ] result

        #single element
        ("", ""),
        ("a", "a"),
        (CUR, CUR),
        (PAR, PAR),

        #multiple element
        ("a", "a", "a" + SEP + "a"),
        ("a", "b", "c", "a" + SEP + "b" + SEP + "c"),

        #elements containing seps
        ("a" + SEP + "b", "c", "a" + SEP + "b" + SEP + "c"),
        ("a" + SEP + "b" + SEP, "c", "a" + SEP + "b" + SEP + "c"),

    ]

    def test_various(self):
        "test assorted inputs"
        for row in self.various_data:
            path = filepath(*row[:-1])
            self.assert_(isinstance(path, FilePath))
            self.assert_(is_filepath(path))
            self.assertEqual(path, row[-1])

    def test_duplicate(self):
        "test filepath caching"
        for row in self.various_data:
            self.assertIs(filepath(*row[:-1]), filepath(*row[:-1]))

#=========================================================
#test path composition
#=========================================================

#we need somewhere to use as a base for the abspath tests
cwd = os.path.abspath(os.getcwd())
if os.name == "nt":
    cwdcan = os.path.normcase(cwd)
    abase = "c:\\dev"
else:
    cwdcan = os.path.realpath(cwd)
    abase = "/testing"
assert os.path.isdir(cwd)
assert not cwd.endswith(SEP)

class PathTest(TestCase):
    "test filesystem-independant FilePath methods"

    #=========================================================
    #test filepath component attrs
    #=========================================================
    component_data = [
        # path = dir + name = root + ext
        # name = base + ext

        #paths w/o dir part
        dict(source=["a"], dir="",
            name="a", base="a", ext="", root="a"),
        dict(source=["a.jpg"], dir="",
            name="a.jpg", base="a", ext=".jpg", root="a"),
        dict(source=[".private"], dir="",
            name=".private", base=".private", ext="", root=".private"),
        dict(source=[".private.png"],
            dir="", name=".private.png", base=".private", ext=".png", root=".private"),

        #paths w/ dir part
        dict(source=["aaa","bbb",".private.png"],
            path="aaa" + SEP + "bbb" + SEP + ".private.png",
            dir="aaa" + SEP + "bbb",
            name=".private.png",
            base="aaa" + SEP + "bbb" + SEP + ".private",
            ext=".png",
            root=".private"),
    ]

    def test_components(self):
        "test parsing of path components"
        self._run_attr_test(self.component_data)

    #=========================================================
    #test normpath & parentpath
    #=========================================================
    np_data = [
        dict(source=['aaa', 'bbb', '.private.png'],
             parentpath="aaa" + SEP + "bbb",
             normpath="aaa" + SEP + "bbb" + SEP + ".private.png",
             ),

        dict(source=[PAR, 'aaa', 'bbb'],
             parentpath=PAR + SEP + 'aaa',
             normpath=PAR + SEP + 'aaa' + SEP + 'bbb'
             ),

        dict(source=['aaa', PAR, 'bbb'],
            parentpath=CUR,
            normpath='bbb',
            ),

        dict(source=[''], #empty path - poorly defined what this is.
            #can't open it as a file anywhere.
            #windows treats it as a dir(can list, norm=CUR) ,
            #unix leaves it alone (norm='', no list or open).
            #until overriding reason is found to force one behavior,
            #just going w/ os-specific here
             parentpath=CUR,
             normpath=CUR,
             dir='', name='', ext='', root='', base='',
             ),

        dict(source=[CUR], #cur dir - should return parent dir
             parentpath=PAR,
             normpath=CUR,
             dir='', name=CUR, ext='', root=CUR, base=CUR,
             ),

        dict(source=[PAR], #par dir - should return parent / parent
             parentpath=PAR + SEP + PAR,
             normpath=PAR,
             dir='', name=PAR, ext='', root=PAR, base=PAR,
             ),

        dict(source=[PAR, 'xxx'], #par dir - should return parent / parent
             parentpath=PAR,
             normpath=PAR + SEP + 'xxx',
             dir=PAR, name='xxx', ext='', root='xxx', base=PAR + SEP + 'xxx',
             ),
    ]

    def test_np(self):
        "test normpath & parentpath"
        self._run_attr_test(self.np_data)

    def test_contained_in_path(self):
        "test filepath.contained_in_path()"
        source = filepath("x", "y")
        target = source / "z"
        self.assert_(target.contained_in_path(source))
        self.assert_(target.contained_in_path(source, strict=True))

        self.assert_(target.contained_in_path(target))
        self.assert_(not target.contained_in_path(target, strict=True))

        self.assert_(not source.contained_in_path(target))
        self.assert_(not source.contained_in_path(target, strict=True))

    #=========================================================
    #test derived path attrs
    #=========================================================
    derived_data = [
        dict(source=["a"],
             normpath="a",
             abspath=cwd + SEP + "a",
             parentpath=CUR,
             canonpath=cwdcan + SEP + "a",
             ),

        #CUR/PAR combinations
        dict(source="", normpath=CUR, parentpath=CUR, abspath=cwd), #XXX: this treats "" like a file. is that right?
        dict(source=[CUR], normpath=CUR, parentpath=PAR),
        dict(source=[PAR], normpath=PAR, parentpath=PAR + SEP + PAR),
        dict(source=[PAR, CUR], normpath=PAR, parentpath=PAR + SEP + PAR),
        ]
    def test_derived(self):
        "test derived paths"
        os.chdir(cwd) #so abspath will work
        self._run_attr_test(self.derived_data)

    gap_data = [
        ("a", None, cwd + SEP + "a"),
        ("a", cwd, cwd + SEP + "a"),
        ("a", "xxx", cwd + SEP + 'xxx' + SEP + "a"),
        (abase, None, abase),
        (abase, "xxx", abase),
    ]

    def test_getabspath(self):
        for source, start, value in self.gap_data:
            result = filepath(source).getabspath(start)
            self.assertEqual(result, value, "source=%r start=%r:" % (source, start))

    def test_getrelpath(self):
        "test filepath.getrelpath()"
        for path, start, result in [
            (['a', 'b'],            ['a'],              ['b']),
            (['a', 'b'],            ['a', 'd'],         [PAR, 'b']),
            (['a', 'b', 'c'],       ['a', 'd', 'e'],    [PAR, PAR, 'b', 'c']),
            (['a', 'b', 'c'],       ['x', 'y', 'z'],    [PAR, PAR, PAR, 'a', 'b', 'c']),
            (['a', 'b', 'c'],       ['x', 'y', 'z', 'q'],    [PAR, PAR, PAR, PAR, 'a', 'b', 'c']),
            ]:

            path = SEP.join(path)
            start = SEP.join(start)
            result = SEP.join(result)
            out = filepath(path).getrelpath(start)
            print [path, start, out, result]
            self.assertEqual(out, result, "path=%r start=%r:"%  (path, start))

    def test_samepath(self):
        #TODO: write real test for samepath
        filepath(cwd).samepath(cwd)
        filepath(cwd).samepath(cwd + SEP + "xxx")

    #=========================================================
    #expand tests
    #=========================================================
    def test_expand(self):
        #TODO: write real test for expand

        path = filepath(cwd)
        #just make sure this doesn't throw errors for now
        new = path.expand(all=True)

    #=========================================================
    #test string & joining operators
    #=========================================================
    def test_stringop(self):
        "test string operations"
        ax = "ax"
        ab = "a" + SEP + "b"
        abx = "a" + SEP + "bx"

        #test __add__
        self.assert_(isinstance(filepath("a") + "x", FilePath))
        self.assertEqual(filepath("a") + "x", ax)

        self.assertEqual(filepath("a") / "b" + "x", abx)

        #test __radd__
        self.assert_(isinstance("x" + filepath("a"), FilePath))
        self.assertEqual("x" + filepath("a"), "xa")

    def test_joiners(self):
        "test div and joinXXX operations"
        ab = "a" + SEP + "b"
        abc = "a" + SEP + "b" + SEP + "c"

        #test __div__
        self.assertEqual(filepath("a") / "b", ab)
        self.assertEqual(filepath("a") / ("b", "c"), abc)

        #test __div__ w/ strings & filepaths mixed
        self.assertEqual(filepath("a") / filepath("b"), ab)
        self.assertEqual(filepath("a") / (filepath("b"), "c"), abc)

        #test chained div
        self.assertEqual(filepath("a") / filepath("b") / filepath("c"), abc)
        self.assertEqual(filepath("a") / "b" / filepath("c"), abc)

        #test joinsep .. since it's called by __div__, don't need much separate testing.
        self.assertEqual(filepath("a").joinsep("b"), ab)
        self.assertEqual(filepath("a").joinsep("b", "c"), abc)

    #=========================================================
    #helpers
    #=========================================================

    def _run_attr_test(self, data):
        "helper for test_derived / test_components etc"
        for row in data:
            source = row['source']
            if isinstance(source, (list, tuple)):
                path = filepath(*source)
            else:
                path = filepath(source)
            for key in row:
                if key == "path":
                    self.assertEqual(path, row[key])
                elif key != "source":
                    value = getattr(path, key)
                    real = row[key]
                    self.assertEqual(value, real, "source=%r attr=%r ... got=%r expected=%r" % (source, key, value, real))

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#fs interaction
#=========================================================
class _InteractionTest(TestCase):
    "base class for fs interaction tests"
    #=========================================================
    #setup/teardown - create a tmp path for each test to use if needed
    #=========================================================
    def setUp(self):
        self._paths = []

    def tearDown(self):
        for path in self._paths:
            path.discard()

    #=========================================================
    #path creation funcs
    #=========================================================
    def create_path(self):
        """create new path whose parent dir exists, but it doesn't.
        automatically cleaned up after test completes"""
        path = get_tmp_path()
        assert not path.lexists
        assert path.parentpath.isdir
        self._paths.append(path)
        return path

    def create_noparent(self):
        "return path whose parent doesn't exist"
        base = self.create_path()
        self.assert_(base.ismissing)
        path = base / "notapath"
        self.assert_(path.ismissing)
        return path

    def create_missing(self):
        "return path whose parentdir exists, but path doesn't"
        path = self.create_path()
        self.assert_(path.parentpath.isdir)
        return path

    def create_file(self, content="qwerty"):
        "return path which is a file"
        path = self.create_path()
        path.set(content)
        self.assert_(path.isfile and path.get() == content)
        return path

    def create_parentfile(self):
        "return path whose parent is a file"
        base = self.create_file()
        path = base / "notpath"
        self.assert_(path.ismissing)
        return path

    def create_dir(self):
        "create path which is a dir"
        path = self.create_path()
        path.mkdir()
        self.assert_(path.isdir)
        return path

    #=========================================================
    #preset creation & testing funcs (used by move/copy)
    #=========================================================
    def create_file_style1(self):
        return self.create_file("qwerty")

    def check_file_style1(self, path):
        self.check_file(path, "qwerty", 1)

    def create_dir_style1(self):
        "create path which is a dir and has content (1 file and 1 dir)"
        # path/
        #   test.file: qwerty
        #   test.dir/
        #       test.txt: hello world
        #       test.link> test.txt
        #       broken.link> ../notafile.notthere
        path = self.create_path()
        path.mkdir()
        self.assert_(path.isdir)
        (path / "test.file").set("qwerty")
        (path / "test.dir").mkdir()
        (path / "test.dir" / "test.txt").set("hello world")
        if os_has_symlinks:
            (path / "test.dir" / "test.link").mklink("../test.file")
            (path / "test.dir" / "broken.link").mklink("../notafile.notthere")
        return path

    def check_dir_style1(self, path, copy_symlinks=True):
        self.check_dir(path, ['test.file', 'test.dir'])
        self.check_file(path / "test.file", 'qwerty')
        if os_has_symlinks:
            if copy_symlinks:
                self.check_dir(path / 'test.dir', ['test.txt', 'test.link', 'broken.link'])
                self.check_file_link(path / 'test.dir' / 'test.link', '../test.file', 'qwerty')
                self.check_link(path / "test.dir" / "broken.link", "../notafile.notthere", broken=True)
            else:
                self.check_dir(path / 'test.dir', ['test.txt', 'test.link'])
                self.check_file(path / 'test.dir' / 'test.link', 'qwerty')
        else:
            self.check_dir(path / 'test.dir', ['test.txt'])
        self.check_file(path / 'test.dir' / 'test.txt', 'hello world')

    #=========================================================
    #check funcs - verify properties are reported correctly
    #   for various types of files
    #=========================================================

    #-----------------------------------------------
    #missing
    #-----------------------------------------------
    def check_missing(self, path, link=False):
        "check missing path properties"
        self.assertEqual(path.filetype, "missing")
        self.assertEqual(path.lfiletype, "link" if link else "missing")
        self.assertEqual(path.exists, False)
        self.assertEqual(path.lexists, link)
        self.assertEqual(path.isdir, False)
        self.assertEqual(path.isfile, False)
        self.assertEqual(path.islink, link)
        self.assertEqual(path.ismissing, True)
        self.assertEqual(path.ismount, False)
        self.assertAttrRaises(errors.MissingPathError, path, "atime")
        self.assertAttrRaises(errors.MissingPathError, path, "ctime")
        self.assertAttrRaises(errors.MissingPathError, path, "mtime")
        self.assertAttrRaises(errors.MissingPathError, path, "size")
        self.assertAttrRaises(errors.MissingPathError, path, "linecount")
        self.assertAttrRaises(errors.MissingPathError, path, "dircount")

    #-----------------------------------------------
    #dir
    #-----------------------------------------------
    def check_empty_dir(self, path, **kwds):
        self.check_dir(path, [], **kwds)

    def check_dir(self, path, content=None, created=None, link=False):
        "check various dir-readers, given directory path and (correct) contents"

        #check filetypes
        self.assertEqual(path.filetype, "dir")
        self.assertEqual(path.lfiletype, "link" if link else "dir")
        self.assertEqual(path.exists, True)
        self.assertEqual(path.lexists, True)
        self.assertEqual(path.isdir, True)
        self.assertEqual(path.isfile, False)
        self.assertEqual(path.islink, link)
        self.assertEqual(path.ismissing, False)
        self.assertEqual(path.ismount, False)

        #check times
        path.atime #just make sure it works, can't be sure it'll be honored
        path.ctime
        path.mtime
        if created:
            tick_start, tick_stop = created
            self.assert_(tick_start <= path.ctime <= tick_stop)
            self.assert_(tick_start <= path.mtime <= tick_stop)

        #check relative listdir
        if content is not None:
            self.assertElementsEqual(path.listdir(), content)
            self.assertElementsEqual(list(path.iterdir()), content)

        #check full listdir
        if content is not None:
            content = [ path / elem for elem in content ]
            self.assertElementsEqual(path.listdir(full=True), content)
            self.assertElementsEqual(list(path.iterdir(full=True)), content)

        #check other
        path.size #what should this report for various OSes?
        if content is not None:
            self.assertEqual(path.dircount, len(content))
        else:
            self.assert_(path.dircount >= 0)
        path.linecount #NOTE: in future, should raise ExpectedFileError

    #-----------------------------------------------
    #file
    #-----------------------------------------------
    def check_file(self, path, content=None, lines=None, created=None, link=False):
        "check file properties"

        #check filetypes
        self.assertEqual(path.filetype, "file")
        self.assertEqual(path.lfiletype, "link" if link else "file")
        self.assertEqual(path.exists, True)
        self.assertEqual(path.lexists, True)
        self.assertEqual(path.isdir, False)
        self.assertEqual(path.isfile, True)
        self.assertEqual(path.islink, link)
        self.assertEqual(path.ismissing, False)
        self.assertEqual(path.ismount, False)

        #check times
        path.atime #just make sure it works, can't be sure it'll be honored
        path.ctime
        path.mtime
        if created:
            tick_start, tick_stop = created
            self.assert_(tick_start <= path.ctime <= tick_stop)
            self.assert_(tick_start <= path.mtime <= tick_stop)

        #check other
        if content is None:
            self.assert_(path.size >= 0)
        else:
            self.assertEqual(path.size, len(content))
        self.assertAttrRaises(errors.ExpectedDirError, path, "dircount")
        if lines is not None:
            self.assertEqual(path.linecount, lines)
        else:
            self.assert_(path.linecount >= 0)

        #check content
        if content is not None:
            self.assertEqual(path.get(), content)

    #-----------------------------------------------
    #links
    #-----------------------------------------------
    def check_link(self, path, target=None, broken=None):
        self.assert_(path.lexists)
        self.assertEqual(path.lfiletype, "link")
        if broken:
            self.assertEqual(path.filetype, "missing")
            self.assert_(path.ismissing)
        elif broken is False:
            self.assertNotEqual(path.filetype, "missing")
            self.assert_(path.exists)

        if broken is False:
            path.atime
            path.ctime
            path.mtime
            if path.isdir:
                path.dircount
            elif path.isfile:
                path.linecount

        if target is not None:
            self.assertEqual(path.ltarget, target)

    def check_file_link(self, path, target, content=None, broken=None):
        self.check_link(path, target, broken=broken)
        self.check_file(path, content, link=True)

    #=========================================================
    #eoc
    #=========================================================

#TODO: test filepath.walk() - esp followlinks behavior (since it's not available under py25)
#TODO: test filepath.mode, filepath.modestr

class _MoveCopyTest(_InteractionTest):
    "common tests used by both move_to and copy_to"
    copy = False
    copy_symlinks = True

    def gf(self, path):
        if self.copy:
            if not self.copy_symlinks:
                return partial(path.copy_to, followlinks=True)
            else:
                return path.copy_to
        else:
            return path.move_to

    def check_output_dir_style1(self, *a, **k):
        if not self.copy_symlinks:
            k['copy_symlinks'] = False
        return self.check_dir_style1(*a, **k)

    #=========================================================
    #test boundary cases
    #=========================================================
    def test_bad_mode(self):
        "test invalid mode value"
        source = self.create_file()
        target = self.create_path()
        self.assertRaises(ValueError, self.gf(source), target, mode="not a mode")


    #=========================================================
    #test source/target errors common to all modes
    #=========================================================
    def test_source_missing(self):
        "test handling of missing source, for all target types and move modes"
        source = self.create_missing()
        for target in (self.create_noparent(), self.create_missing(), self.create_file(), self.create_dir()):
            for mode in ("exact", "child", "smart"):
                self.assertRaises(errors.MissingPathError, self.gf(source), target, mode=mode)

    def test_target_noparent(self):
        "test handling of target's parent dir being missing, for all source types and move modes"
        target = self.create_noparent()
        for source in (self.create_file(), self.create_dir(), self.create_dir_style1()):
            for mode in ("exact", "child", "smart"):
                self.assertRaises(errors.MissingPathError, self.gf(source), target, mode=mode)

    def test_target_file(self):
        "test handling of file located as target, for all source types and move modes (except child)"
        for mode in ("exact", "smart"):
            for source in (self.create_file(), self.create_dir(), self.create_dir_style1()):
                target = self.create_file()
                #move should raise error
                self.assertRaises(errors.PathExistsError, self.gf(source), target, mode=mode,
                                __msg__="source=%r mode=%r:" % (source.filetype, mode))
                #but this one should be successful
                st = source.filetype
                self.gf(source)(target, mode=mode, force=True)
                if self.copy:
                    self.assertEqual(source.filetype, st)
                else:
                    self.assertEqual(source.filetype, "missing")
                self.assertEqual(target.filetype, st)

    def test_child_target_file(self):
        "test handling of file located as target, for child mode"
        for source in (self.create_file(), self.create_dir(), self.create_dir_style1()):
            target = self.create_file()
            self.assertRaises(errors.ExpectedDirError, self.gf(source), target, mode="child",
                            __msg__="source=%r:" % (source.filetype, ))

    #=========================================================
    #exact mode
    #=========================================================
    #source: file, (full) dir
    #target: missing, dir

    def test_exact_file_missing(self):
        source = self.create_file_style1()
        target = self.create_missing()

        self.gf(source)(target)
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(target)

    def test_exact_file_dir(self):
        source = self.create_file_style1()
        target = self.create_dir()

        self.assertRaises(errors.PathExistsError, self.gf(source), target)
        self.check_file_style1(source)
        self.check_dir(target, [])

        self.gf(source)(target, force=True)
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(target)

    def test_exact_dir_missing(self):
        source = self.create_dir_style1()
        target = self.create_missing()

        self.gf(source)(target)
        if self.copy:
            self.check_dir_style1(source)
        else:
            self.check_missing(source)
        self.check_output_dir_style1(target)

    def test_exact_dir_dir(self):
        source = self.create_dir_style1()
        target = self.create_dir()
        temp = target / 'xxx'
        temp.set("yyy")

        self.assertRaises(errors.PathExistsError, self.gf(source), target)
        self.check_dir_style1(source)
        self.check_dir(target, ['xxx'])

        self.gf(source)(target, force=True)
        if self.copy:
            self.check_dir_style1(source)
            self.check_file(temp, 'yyy'); temp.remove()
        else:
            self.check_missing(source)
        self.check_output_dir_style1(target)

    #=========================================================
    #child mode
    #=========================================================
    #source: file, (full) dir
    #target: missing, dir, dir with source in the way

    def test_child_file_missing(self):
        source = self.create_file_style1()
        target = self.create_missing()

        self.assertRaises(errors.MissingPathError, self.gf(source), target, mode="child")
        self.check_file_style1(source)
        self.check_missing(target)

    def test_child_file_dir(self):
        source = self.create_file_style1()
        target = self.create_dir()
        result = target / source.name

        self.gf(source)(target, mode="child")
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(result)

    def test_child_file_dir_occupied_file(self):
        source = self.create_file_style1()
        target = self.create_dir()
        result = target / source.name
        result.set("xxx")

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="child")
        self.check_file_style1(source)
        self.check_dir(target, [source.name])
        self.check_file(result, 'xxx')

        self.gf(source)(target, mode="child", force=True)
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(result)

    def test_child_file_dir_occupied_dir(self):
        source = self.create_file_style1()
        target = self.create_dir()
        result = target / source.name
        result.mkdir()
        temp = result / 'xxx'
        temp.set('yyy')

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="child")
        self.check_file_style1(source)
        self.check_dir(target, [source.name])
        self.check_dir(result, ['xxx'])
        self.check_file(temp, 'yyy')

        self.gf(source)(target, mode="child", force=True)
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(result)

    def test_child_dir_missing(self):
        source = self.create_dir_style1()
        target = self.create_missing()

        self.assertRaises(errors.MissingPathError, self.gf(source), target, mode="child")
        self.check_dir_style1(source)
        self.check_missing(target)

    def test_child_dir_dir(self):
        source = self.create_dir_style1()
        target = self.create_dir()
        result = target / source.name

        self.gf(source)(target, mode="child")
        if self.copy:
            self.check_dir_style1(source)
        else:
            self.check_missing(source)
        self.check_output_dir_style1(result)

    def test_child_dir_dir_occupied_file(self):
        source = self.create_dir_style1()
        target = self.create_dir()
        result = target / source.name
        result.set('xxx')

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="child")
        self.check_dir_style1(source)
        self.check_dir(target, [source.name])
        self.check_file(result, 'xxx')

        self.gf(source)(target, mode="child", force=True)
        if self.copy:
            self.check_dir_style1(source)
        else:
            self.check_missing(source)
        self.check_output_dir_style1(result)

    def test_child_dir_dir_occupied_dir(self):
        source = self.create_dir_style1()
        target = self.create_dir()
        result = target / source.name
        result.mkdir()
        temp = result / 'xxx'
        temp.set('yyy')

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="child")
        self.check_dir_style1(source)
        self.check_dir(target, [source.name])
        self.check_dir(result, ['xxx'])
        self.check_file(temp, 'yyy')

        self.gf(source)(target, mode="child", force=True)
        if self.copy:
            self.check_dir_style1(source)
            self.check_file(temp, 'yyy'); temp.remove()
        else:
            self.check_missing(source)
        self.check_output_dir_style1(result)

    #=========================================================
    #smart mode
    #=========================================================
    #source: file, (full) dir
    #target: missing, dir, dir with source in the way

    def test_smart_file_missing(self):
        source = self.create_file_style1()
        target = self.create_missing()

        self.gf(source)(target, mode="smart")
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(target)

    def test_smart_file_dir(self):
        source = self.create_file_style1()
        target = self.create_dir()
        result = target / source.name

        self.gf(source)(target, mode="smart")
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(result)

    def test_smart_file_dir_occupied_file(self):
        source = self.create_file_style1()
        target = self.create_dir()
        result = target / source.name
        result.set("xxx")

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="smart")
        self.check_file_style1(source)
        self.check_dir(target, [source.name])
        self.check_file(result, 'xxx')

        self.gf(source)(target, mode="smart", force=True)
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(result)

    def test_smart_file_dir_occupied_dir(self):
        source = self.create_file_style1()
        target = self.create_dir()
        result = target / source.name
        result.mkdir()
        temp = result / 'xxx'
        temp.set('yyy')

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="smart")
        self.check_file_style1(source)
        self.check_dir(target, [source.name])
        self.check_dir(result, ['xxx'])
        self.check_file(temp, 'yyy')

        self.gf(source)(target, mode="smart", force=True)
        if self.copy:
            self.check_file_style1(source)
        else:
            self.check_missing(source)
        self.check_file_style1(result)

    def test_smart_dir_missing(self):
        source = self.create_dir_style1()
        target = self.create_missing()

        self.gf(source)(target, mode="smart")
        if self.copy:
            self.check_dir_style1(source)
        else:
            self.check_missing(source)
        self.check_output_dir_style1(target)

    def test_smart_dir_dir(self):
        source = self.create_dir_style1()
        target = self.create_dir()
        result = target / source.name

        self.gf(source)(target, mode="smart")
        if self.copy:
            self.check_dir_style1(source)
        else:
            self.check_missing(source)
        self.check_output_dir_style1(result)

    def test_smart_dir_dir_occupied_file(self):
        source = self.create_dir_style1()
        target = self.create_dir()
        result = target / source.name
        result.set('xxx')

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="smart")
        self.check_dir_style1(source)
        self.check_dir(target, [source.name])
        self.check_file(result, 'xxx')

        self.gf(source)(target, mode="smart", force=True)
        if self.copy:
            self.check_dir_style1(source)
        else:
            self.check_missing(source)
        self.check_output_dir_style1(result)

    def test_smart_dir_dir_occupied_dir(self):
        source = self.create_dir_style1()
        target = self.create_dir()
        result = target / source.name
        result.mkdir()
        temp = result / 'xxx'
        temp.set('yyy')

        self.assertRaises(errors.PathExistsError, self.gf(source), target, mode="smart")
        self.check_dir_style1(source)
        self.check_dir(target, [source.name])
        self.check_dir(result, ['xxx'])
        self.check_file(temp, 'yyy')

        self.gf(source)(target, mode="smart", force=True)
        if self.copy:
            self.check_dir_style1(source)
            self.check_file(temp, 'yyy'); temp.remove()
        else:
            self.check_missing(source)
        self.check_output_dir_style1(result)

    #=========================================================
    #eoc
    #=========================================================

class MoveTest(_MoveCopyTest):
    """test PathType.move_to():

    for each mode, behavior should be checked for all combinations
    of source over the range of values:
        missing - source missing
        dir - source is a dir
        file - source is a file
    and for target over the range of values:
        pfile - target is missing, parent is not a dir
        noparent - target & parent dir missing
        missing - target missing, parent dir exists
        file - target is file
        dir - target is dir

    exact mode:
                    noparent,   missing    file        dir
                    pfile

        missing     error       error       error       error

        file        error       success     error       error

        dir         error       success     error       error

    child mode:
                    noparent,   missing    file        dir
                    pfile

        missing     error       error       error       error

        file        error       error       error       success

        dir         error       error       error       success

    smart mode:
                    noparent,   missing    file        dir
                    pfile

        missing     error       error       error       error

        file        error       success     error       success

        dir         error       success     error       success

    Thus source missing, target noparent, and target file should always raise an error.
    The others are dependant on the mode.
    Each test is thus named "test_{mode}_{source type}_{target type}"
    """
    _prefix = "PathType.move_to()"
    copy = False

    def test_target_in_source(self):
        "test target in source detection"
        source = self.create_dir()
        target = source / "z"
        self.assertRaises(ValueError, self.gf(source), target)
        self.assertRaises(ValueError, self.gf(source), source)

class CopyTest(_MoveCopyTest):
    #MoveTest class handles copy_test as well, copy=True flag makes it change behavior
    _prefix = "path.copy_to()"
    copy = True
    copy_symlinks = False

    def test_target_in_source(self):
        "test target in source"
        source = self.create_dir()
        self.assertRaises(ValueError, self.gf(source), source)

        target = source / "z"
        self.gf(source)(target)
        self.check_dir(source, ['z'])
        self.check_dir(target, [])

    def test_force_recursion(self):
        #make sure force flag is preserved during recursion (bug fixed r7192)
        source = self.create_dir_style2()
        target = self.create_dir_style2a()
        source.copy_to(target, force=True)
        self.check_dir_style2(source)
        self.check_dir_style2(target)

    def create_dir_style2(self, content='xxx'):
        "dir structure used by test_force_recursion to detect deep failure of force kwd"
        source = self.create_dir()
        stemp = source / 'test.dir' / 'really'
        stemp.mkdir(parents=True)
        stemp2 = stemp / 'test.txt'
        stemp2.set(content)
        return source

    def check_dir_style2(self,path,content='xxx'):
        self.check_dir(path,['test.dir'])
        self.check_dir(path / 'test.dir',['really'])
        self.check_dir(path / 'test.dir' / 'really',['test.txt'])
        self.check_file(path / 'test.dir' / 'really' / 'test.txt',content)

    def create_dir_style2a(self):
        return self.create_dir_style2(content='yyy')

    def check_dir_style2a(self, path):
        self.check_dir_style2(path,content='yyy')

class CopySymTest(_MoveCopyTest):
    _prefix = "path.copy_to(symlinks=True)"
    copy = True

#=========================================================
#scripts
#=========================================================
class ScriptTest(_InteractionTest):
    "composite fs interaction tests"

    def test_00_script(self):
        "run through some file creation tests"
        base = get_tmp_path()
        self.check_missing(base)
        self._paths.append(base)

        #--------------------------------------------------------------
        #make a directory
        #--------------------------------------------------------------
        assert base.parentpath.isdir, "parent directory missing"
        tick_start = int(time.time())
        base.mkdir()
        tick_stop = max(tick_start+1, int(time.time()))

        #check fs properties of a directory
        self.check_empty_dir(base, created=[tick_start, tick_stop])
        orig_mtime = base.mtime
        time.sleep(1) #wait a second, so file's mtime will be different

        #--------------------------------------------------------------
        #make a file
        #--------------------------------------------------------------
        fname = "imafile.txt"
        fpath = base / fname
        self.assertEqual(fpath, base + SEP + fname)
        self.assertEqual(fpath.filetype, "missing")
        tick_start = int(time.time())
        with fpath.open(mode="wb") as fh:
            fh.write("123\x00")
        tick_stop = max(tick_start+1, int(time.time()))

        #check we can read it
        self.check_file(fpath, "123\x00", 1, created=[tick_start, tick_stop])

        #check dir properties
        self.assert_(base.mtime > orig_mtime) #xxx: only true if os honors dir_mtime
        self.check_dir(base, [fname])

        #--------------------------------------------------------------
        #truncate a file
        #--------------------------------------------------------------
        fpath.clear()
        self.check_file(fpath, '')

        #--------------------------------------------------------------
        #test get/set
        #--------------------------------------------------------------
        fpath.set("a\r\nb\nc")
        self.assertEqual(fpath.get(text=True), "a\nb\nc")
        self.assertEqual(fpath.get(), "a\r\nb\nc")

        #--------------------------------------------------------------
        #test remove
        #--------------------------------------------------------------
        self.assert_(fpath.exists)
        fpath.remove()
        self.check_missing(fpath)
        self.assertRaises(errors.MissingPathError, fpath.remove)

        #TODO: test removing a symlink to a dir removes just the link

        #test discard w/o path
        fpath.discard()

        #test discard w/ path
        fpath.set("")
        self.assert_(fpath.exists)
        fpath.discard()

        #--------------------------------------------------------------
        #test dir's clear
        #--------------------------------------------------------------
        fpath.set("")
        self.check_dir(base, [fname])
        base.clear()
        self.check_dir(base, [])
        base.clear()

        #--------------------------------------------------------------
        #remove base dir
        #--------------------------------------------------------------
        base.remove()
        self.assertEqual(base.filetype, "missing")
        self.assertRaises(errors.MissingPathError, base.remove)
        base.mkdir()
        self.assertEqual(base.filetype, "dir")
        base.discard()
        self.assertEqual(base.filetype, "missing")
        base.discard()

#=========================================================
#
#=========================================================
class ModeTest(TestCase):
    """test chmod support"""
    #TODO: chmod testing
    #    mode, mode+dirmode, mode+filemode
    #    followlinks
    #called on file, called on dir


    def test_parse_mode_mask(self):
        for value in [
            -1,
            1+07777,
            (1+07777, 0),
            (0, 1+07777),
            (457, 3639),
            "x", "u",
            "v=",
            "u=q", "u=g",
            "a+r,o",
            ]:
            self.assertRaises(ValueError, parse_mode_mask, value, __msg__="%r:" % (value, ))

        for input, bits, preserve in [
            #integers
            ((0, 0), 0, 0),
            ((0, 123), 0, 123),
            (456, 456, 0),

            #simple
            ("", 0, 07777),
            ("a+", 0, 07777),
            ("a-", 0, 07777),

            ("a=", 0, 0),
            ("u=,g=,o=", 0, 0),
            ("ugo=", 0, 0),

            #random ones
            ("u+r,g=w,o=t", 784, 2240),
            ("u+tr,g=w,o=t", 784, 2240),
            ]:
            result = parse_mode_mask(input)
            self.assertEqual(result, (bits, preserve), "%r:" % (input, ))

    def test_repr_mode_mask(self):
        self.check_function_results(repr_mode_mask, [
            ak("u=w,g=rw", "ug=w,g+r"),
            ak("u=rw,g=r", "ug=rw,g-wx"),
            ak("ug+r,o+r-x", "a+r,o-x"),
            ak("ug=rwx,o=r", "u=rwx,g=rwx,o=r"),
            ak("a=w", "u=w,g=w,o=rwx,a-rx"),
            ak("", ""),
            ak("a=", "a="),

            ak("0444", "a=r", octal="prefer"),
            ak("0444", "a=r", octal="always"),
            ak("a+r", "a+r", octal="prefer"),

            #real cases
            ak("u=rw,g=r,o=", "u=rw,g=r,o="),
            ak("ug+x", "ug+x"),
            ak("ug=rw,o=", "ug=rw,o="),
            ak("u+x,g+xs", "u+x,g+xs"),
            ])
        self.assertRaises(ValueError, repr_mode_mask, "a+r", octal="always")

##
##    chmod(target, dict(all=all_mode, file=file_mode, dir=dir_mode), recursive=True)
##
##        #config - app_group can read, root is real owner
##        #NOTE: could make sure parent dirs of home have o+rx
##        prepare(
##            target=[cfg.config_dir, cfg.home_dir],
##            user=root_user, group=app_group,
##            all_mode="u=rw,g=r,o=", dir_mode="ug+x",
##            )
##
##        #state_dir, cache_dir - app user only!
##        paths = [cfg.state_dir, cfg.run_dir, cfg.cache_dir, log_dir]
##        prepare(paths, app_user, app_group, all_mode="ug=rw,o=", dir_mode="ug+x")
##
##        #mail dir - owned by app user, but let share_group rw it as well (used by external apps)
##        prepare(cfg.mail_dir, app_user, share_group, all_mode="ug=rw,o=", dir_mode="ug+x,g+s")

def ChangeModeTest(_InteractionTest):

        # path/
        #   test.file: qwerty
        #   test.dir/
        #       test.txt: hello world
        #       test.link> test.txt
        #       broken.link> ../notafile.notthere

    def assert_mode(self, path, mode):
        self.assertEqual(path.modestr, mode)

    def reset_mode(self, path):
        chmod(path, "a=", recursive=True)

    def assert_clear_style1(self, path, reset=False):
        if reset:
            self.clear_mode(path)
        am = self.assert_mode
        am(path, "a=")
        am(path / 'test.file', "a=")
        am(path / 'test.dir', 'a=')
        am(path / 'test.dir' / 'test.txt', 'a=')
        if os_has_symlinks:
            am(path / 'test.dir' / 'test.link', 'a=')

    def assert_style1(self, path, dm, fm):
        am = self.assert_mode
        am(path, dm)
        am(path / 'test.file', fm)
        am(path / 'test.dir', dm)
        am(path / 'test.dir' / 'test.txt', fm)
        if os_has_symlinks:
            am(path / 'test.dir' / 'test.link', fm)

    def test_script1(self):
        am = self.assert_mode

        #create dir to test
        path = self.create_dir_style1()
        self.assert_clear_style1(path, True)

        #call chmod with some weird params, but no recursion
        chmod(path, mode="ug+r,u+w", dirmode="+x", filemode="o+r")
        dm = "u=rwx,g=rx,o=rx"
        fm = "u=rw,g=r,o=rx"
        self.assert_mode(path, dm)
        path.mode = "a="
        self.assert_clear_style1(path)

        #call chmod with some weird params and recursion
        self.assert_clear_style1(path, True)
        chmod(path, mode="ug+r,u+w", dirmode="+x", filemode="o+r", recursive=True)
        self.assert_style1(path, dm, fm)

        #test removal
        chmod(path, mode="og-x+w", recursive=True)
        dm = "u=rwx,go=rw"
        fm = "u=rw,go=rw"
        self.assert_style1(path, dm, fm)

#=========================================================
#eof
#=========================================================
