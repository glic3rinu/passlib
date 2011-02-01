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
import passlib.hash.phpass as mod
#module
log = getLogger(__name__)

#=========================================================
#md5 crypt
#=========================================================
class PHPassTest(_HandlerTestCase):
    handler = mod

    known_correct = (
        ('', '$P$7JaFQsPzJSuenezefD/3jHgt5hVfNH0'),
        ('compL3X!', '$P$FiS0N5L672xzQx1rt1vgdJQRYKnQM9/'),
        ('test12345', '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0'), #from the source
        )

    known_invalid = (
        #bad char in otherwise correct hash
        '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r!L0',
        )

#=========================================================
#EOF
#=========================================================
