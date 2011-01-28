"""passlib - implementation of various password hashing functions"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import inspect
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
#site
#libs
from passlib.hash import postgres_md5
from passlib.context import CryptContext
#pkg
#local
__all__ = [
    'postgres_md5',
    'postgres_context',
]

#=========================================================
#db contexts
#=========================================================
postgres_context = CryptContext([postgres_md5])

#=========================================================
# eof
#=========================================================
