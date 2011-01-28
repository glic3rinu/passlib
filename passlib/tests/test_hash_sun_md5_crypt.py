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
import passlib.hash.sun_md5_crypt as mod
#module
log = getLogger(__name__)

#=========================================================
#hash alg
#=========================================================
class SunMd5CryptTest(_HandlerTestCase):
    handler = mod

    known_correct = [
        ("passwd", "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"),
        ]

    known_invalid = (
        #bad char in otherwise correct hash
        "$md5$RPgL!6IJ$WTvAlUJ7MqH5xak2FMEwS/"
        )

#=========================================================
#EOF
#=========================================================
