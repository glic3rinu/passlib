"""passlib setup script"""
#=========================================================
#init script env
#=========================================================
import os
os.chdir(os.path.abspath(os.path.join(__file__,"..")))
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
