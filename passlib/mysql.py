"""passlib - implementation of various password hashing functions"""
#=========================================================
#imports
#=========================================================
#core
import logging; log = logging.getLogger(__name__)
#site
#libs
from passlib.hash import mysql_323, mysql_41
from passlib.context import CryptContext
#pkg
#local
__all__ = [
    #helpful imports of handlers
    'mysql_10',
    'mysql_41',

    #contexts
    'mysql10_context',
    'mysql_context',
]

#=========================================================
#some db context helpers
#=========================================================
mysql3_context = CryptContext([mysql_323])
mysql4_context = CryptContext([mysql_323, mysql_41])

#=========================================================
# eof
#=========================================================
