"""passlib setup script"""
#=========================================================
#init script env - ensure cwd = root of source dir
#=========================================================
import os
root_dir = os.path.abspath(os.path.join(__file__,".."))
os.chdir(root_dir)

#=========================================================
#imports
#=========================================================
import re
import sys
py3k = (sys.version_info[0] >= 3)

try:
    from setuptools import setup
    has_distribute = True
except ImportError:
    from distutils import setup
    has_distribute = False

from distutils.command.build_ext import build_ext
from distutils.errors import CCompilerError, DistutilsExecError, DistutilsPlatformError
from setuptools import Extension, Feature

#=========================================================
#patch distutils so build extension errors aren't fatal
#=========================================================
build_errors = [CCompilerError, DistutilsExecError, DistutilsPlatformError]

class BuildFailed(Exception):
    "custom error raised when optional extension fails to build"

class build_optional_ext(build_ext):

    def run(self):
        try:
            build_ext.run(self)
        except DistutilsPlatformError, err:
            raise BuildFailed()

    def build_extension(self, ext):
        try:
            build_ext.build_extension(self, ext)
        except build_errors, err:
            raise BuildFailed()

#=========================================================
#monkeypatch preprocessor into 2to3, and enable 2to3
#=========================================================
cmdclass = {}
opts = {}

if py3k:
    from passlib.setup.cond2to3 import patch2to3
    patch2to3()
    
    if has_distribute:
        opts['use_2to3'] = True
    else:
        #if we can't use distribute's "use_2to3" flag,
        #have to override build_py command
        from distutils.command.build_py import build_py_2to3 as build_py
        cmdclass['build_py'] = build_py

#=========================================================
#version string
#=========================================================
vh = open(os.path.join(root_dir, "passlib", "__init__.py"))
VERSION = re.search(r'^__version__\s*=\s*"(.*?)"\s*$', vh.read(), re.M).group(1)
vh.close()

#=========================================================
#static text
#=========================================================
SUMMARY = "comprehensive password hashing framework supporting over 20 schemes"

DESCRIPTION = """\
PassLib is a password hash library, which provides cross-platform
implementations of over 20 password hashing algorithms; as well as a framework for managing
and migrating existing password hashes. It's designed to be useful
for any task from quickly verifying a hash found in /etc/shadow,
to providing full-strength password hashing for multi-user applications.

* See the `online documentation <http://packages.python.org/passlib>`_ for details and examples.

* See the `passlib homepage <http://passlib.googlecode.com>`_ for the latest news, more information, and additional downloads. 

* See the `changelog <http://packages.python.org/passlib/history.html>`_ for list of what's new in passlib.

All releases are signed with the gpg key `4CE1ED31 <http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x4D8592DF4CE1ED31>`_.
"""

KEYWORDS = "password secret hash security crypt md5-crypt sha256-crypt sha512-crypt bcrypt apache htpasswd htdigest pbkdf2 ntlm"

#=========================================================
#config C extensions
#=========================================================
names = [ "speedup", "des", "h64", "md5crypt" ]
sources = [ 'src/%s.c' % n for n in names ] + [ "src/sha512_crypt.c", "src/sha256_crypt.c" ]
depends = [ 'src/%s.h' % n for n in names ]
cflags = [ '--std=c99' ] #FIXME: this assumes gcc!

speedup = Feature(
    "optional C speedup module for passlib",
    standard=True,
    ext_modules = [
        Extension("passlib.utils._speedup",
                  sources=sources,
                  depends=depends,
                  libraries=["ssl"],
                  extra_compile_args=cflags,
                  ),
    ],
)

#=========================================================
#config setup
#=========================================================
config = dict(
    #package info
    packages = [
        "passlib",
            "passlib.handlers",
            "passlib.setup",
            "passlib.tests",
            "passlib.utils",
        ],
    package_data = { "passlib": ["*.cfg"] },
    features = { "speedup": speedup },
    zip_safe=True,

    #metadata
    name = "passlib",
    version = VERSION,
    author = "Eli Collins",
    author_email = "elic@assurancetechnologies.com",
    license = "BSD",

    url = "http://passlib.googlecode.com",
    download_url = "http://passlib.googlecode.com/files/passlib-" + VERSION + ".tar.gz",

    description = SUMMARY,
    long_description = DESCRIPTION,
    keywords = KEYWORDS,
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],

    tests_require = 'nose >= 1.0',
    test_suite = 'nose.collector',

    #extra opts
    cmdclass=cmdclass,
    **opts
)
#=========================================================
#build
#=========================================================
try:
    setup(**config)
except BuildFailed:
    HEADER = "*" * 80
    MSG = "WARNING: The C speedup library could not be compiled"
    print HEADER
    print MSG
    print "Retrying to build without C speedups enabled"
    print HEADER
    del config['features']['speedup']
    setup(**config)
    print HEADER
    print MSG
    print "Pure-Python build suceeded"
    print HEADER

#=========================================================
#EOF
#=========================================================
