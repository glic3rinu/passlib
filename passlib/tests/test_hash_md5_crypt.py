"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
import warnings
from logging import getLogger
#site
#pkg
from passlib import hash as pwhash
from passlib.tests.utils import TestCase, enable_suite
from passlib.util import H64
from passlib.tests.test_hash_base import _CryptTestCase as CryptTestCase
import passlib.hash.md5_crypt as mod
#module
log = getLogger(__name__)

#=========================================================
#hash alg
#=========================================================
class Md5CryptTest(CryptTestCase):
    alg = mod.Md5Crypt
    positive_knowns = (
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        )
    invalid_identify = (
        #bad char in otherwise correct hash
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        )
    negative_identify = (
        #other hashes
        '!gAwTx2l6NADI',
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc',
        )

#=========================================================
#EOF
#=========================================================
