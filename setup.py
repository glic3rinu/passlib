"""passlib setup script"""
#=========================================================
#init script env
#=========================================================
import os
os.chdir(os.path.abspath(os.path.join(__file__,"..")))
#=========================================================
#imports
#=========================================================
from distutils.command.build_ext import build_ext
from distutils.errors import CCompilerError, DistutilsExecError, DistutilsPlatformError
from setuptools import setup, find_packages, Extension, Feature
from passlib import __version__ as version
import sys
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
#setup config
#=========================================================
speedup = Feature(
    "optional C speedup module for passlib",
    standard=True,
    ext_modules = [
        Extension("passlib.utils._speedup", ["src/speedup.c"]),
    ],
)

config = dict(
    #package info
    packages = find_packages(),
    package_data = { "passlib": ["*.cfg"] },
    features = { "speedup": speedup },

    # metadata
    name = "passlib",
    version = version,
    author = "Eli Collins",
    author_email = "elic@assurancetechnologies.com",
    license = "BSD",

    url = "http://code.google.com/p/passlib/",
    download_url = "http://code.google.com/p/passlib/downloads/list",

    description = "comprehensive password hashing framework supporting over 20 schemes",
    long_description = """\
PassLib is a password hash library, which provides cross-platform
implementations of over 20 password hashing algorithms; as well as a framework for managing
and migrating existing password hashes. It's designed to be useful
for any task from quickly verifying a hash found in /etc/shadow,
to providing full-strength password hashing for multi-user application.
""",

    keywords = "password secret hash security crypt md5-crypt sha256-crypt sha512-crypt bcrypt htpasswd htdigest pbkdf2",
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
    zip_safe=True,

    test_suite = 'nose.collector',

    cmdclass={'build_ext': build_optional_ext}
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
