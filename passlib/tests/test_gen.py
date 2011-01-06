"""passlib tests"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os
from unittest import TestCase
import hashlib
import warnings
import random
from logging import getLogger
#site
#pkg
from passlib import gen as pwgen
from passlib.util import srandom
from passlib.tests.utils import enable_suite
#module
log = getLogger(__name__)

#=========================================================
#
#=========================================================
if enable_suite("pwgen_dups"):

    class DupTest(TestCase):
        "Test the rate of duplicate generation for various algorithms"
        rounds = 10**5
        duplicates = [
            #check random engine, mainly as a sanity check
            dict(alg='hex', size=7, dups=25),

            #check cvc engine
            dict(alg="cvc", size=8, dups=10),
            dict(alg="cvc", size=10, dups=0),

            #check the gpw engine for various languages
            dict(alg="gpw", language="gpw", size=8, dups=350),
            dict(alg="gpw", language="gpw", size=10, dups=20),

            #the public presets should always values at least this low
            dict(alg='strong', dups=0),
            dict(alg='human', dups=0),

            ]

        def test_duplicates(self):
            "test rate of duplicate password generation"
            for preset in self.duplicates:
                self._test_duplicates_preset(preset)

        def _test_duplicates_preset(self, preset):
            info = preset.copy()
            max_dups = info.pop('dups')
            max_dup_rate = info.pop("dup_rate", 2)
            log.info("Testing config for duplicates: config=%r rounds=%r", info, self.rounds)
            gen = pwgen.generate_secret(count="iter", **info)
            seen = set()
            hist = {}
            dups = 0
            for c in xrange(self.rounds):
                secret = gen.next()
                if secret in seen:
                    dups += 1
                    if secret in hist:
                        hist[secret] += 1
                    else:
                        hist[secret] = 2
                else:
                    seen.add(secret)
            log.info("\tresults: rate=%.2f%% dups=%r max_dups=%r",
                100.0 * dups / self.rounds, dups, max_dups)
            if hist:
                def sk(pair):
                    return pair[1], pair[0]
                values = sorted(hist.iteritems(), key=sk)[:10]
                self.assertTrue(values[0][1] <= max_dup_rate, "bias detected: %r" % (values, ))
                log.debug("\ttop dups: %s", values)

            #NOTE: having no better measurement, we'll accept a .08% dup rate, but nothing more.
            self.assertTrue(dups <= max_dups, "too many duplicates: %r > %r" % (dups, max_dups))

class ConstantTest(TestCase):
    "make sure predefined constants work"
    #NOTE: this is _very_ dependant on number of times rand is called,
    #if code changes, these constants may change.
    presets = [
        [ dict(alg="alphanum", count=3),
            ['xR0uwaf5lE1mLcc9', 'B70Ux4XSb5ZGYdTM', 'FvSW1V08TN3aAY8w'] ],
        [ dict(alg="human", count=3),
            ['yuicoboeradai', 'rahimeyiinaa', 'fiyoujaefafuk'] ],
    ]

    def setUp(self):
        #hack the gen module to use a predicatble random so we can the same output
        pwgen.srandom = random

    def tearDown(self):
        pwgen.srandom = srandom

    def test_presets(self):
        #test preset password known to be created for a given seed value
        for kwds, result in self.presets:
            drandom.seed(1234)
            out = pwgen.generate_secret(**kwds)
            self.assertEqual(out, result)

#=========================================================
#EOF
#=========================================================
