"""
bps setup script
"""
#=========================================================
#init app env
#=========================================================
import sys,os
from os.path import abspath, join
root_path = abspath(join(__file__, ".."))
os.chdir(root_path)
lib_path = '.'
##lib_path = abspath(join(root_path,""))
##if lib_path not in sys.path:
##    sys.path.insert(0, lib_path)
#=========================================================
#imports
#=========================================================
from setuptools import setup, find_packages
from bps import __version__ as version
#=========================================================
#setup
#=========================================================
setup(
    #package info
    packages = find_packages(where=lib_path),
##    package_data = {},
##    package_dir= { '':  lib_path },

    # metadata
    name = "bps",
    version = version,
    author = "Eli Collins",
    author_email = "elic@astllc.org",
    description = "a package of helper routines for python apps",
    license = "BSD",
    keywords = "ast",
    url = "http://www.astllc.org",
    # could also include long_description, download_url, classifiers, etc.
    zip_safe=True,
)
#=========================================================
#EOF
#=========================================================
