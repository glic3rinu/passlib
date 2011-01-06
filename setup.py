"""
passlib setup script
"""
#=========================================================
#init app env
#=========================================================
import sys,os
from os.path import abspath, join
root_path = abspath(join(__file__, ".."))
os.chdir(root_path)
#=========================================================
#imports
#=========================================================
from setuptools import setup, find_packages
from passlib import __version__ as version
#=========================================================
#setup
#=========================================================
setup(
    #package info
    packages = find_packages(),

    # metadata
    name = "passlib",
    version = version,
    author = "Eli Collins",
    author_email = "elic@astllc.org",
    description = "utilities for password generation & hashing",
    license = "BSD",
    keywords = "password hash generation secret security sha md5 bcrypt crypt",
    url = "http://www.astllc.org/software/passlib",
    # could also include long_description, download_url, classifiers, etc.
    zip_safe=True,
)
#=========================================================
#EOF
#=========================================================
