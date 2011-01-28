"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
from logging import getLogger
#site
#pkg
from passlib.tests.handler_utils import _HandlerTestCase
from passlib.tests.utils import enable_option
import passlib.hash.md5_crypt as mod
import passlib.hash.apr_md5_crypt as apr
#module
log = getLogger(__name__)

#=========================================================
#md5 crypt
#=========================================================
class Md5CryptTest(_HandlerTestCase):
    handler = mod

    known_correct = (
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        )

    known_invalid = (
        #bad char in otherwise correct hash
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        )

if mod.backend != "builtin" and enable_option("all-backends"):

    #monkeypatch md5-crypt mod so it uses builtin backend

    class BuiltinMd5CryptTest(Md5CryptTest):
        case_prefix = "md5-crypt (builtin backend)"

        def setUp(self):
            self.tmp = mod.crypt
            mod.crypt = None

        def cleanUp(self):
            mod.crypt = self.tmp

#=========================================================
#apr md5 crypt
#=========================================================
class AprMd5CryptTest(_HandlerTestCase):
    handler = apr

    #values taken from http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
    known_correct = (
        ('myPassword', '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/'),
        )

    known_invalid = (
        #bad char in otherwise correct hash
        '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA!'
        )

#=========================================================
#EOF
#=========================================================
