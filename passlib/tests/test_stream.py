"""tests for bps.stream -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os.path
#site
#pkg
from bps import stream
from bps.stream import BT
from bps.meta import Params as ak
#module
from bps.tests.utils import TestCase

#=========================================================
#
#=========================================================

#TODO: test MUCH MORE of stream
class SourceTypeTest(TestCase):

    def test_get_source_type(self):
        self.check_function_results(stream.get_input_type, [
            ak(BT.RAW, ""),

            #TODO: many more test cases!

            ])

#=========================================================
#EOF
#=========================================================
