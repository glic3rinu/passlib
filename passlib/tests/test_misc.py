"""tests for bps.misc -- (c) Assurance Technologies 2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
#site
#pkg
from bps import misc
#module
from bps.tests.utils import TestCase
#=========================================================
#
#=========================================================
class PropertyTest(TestCase):
    "test various property constructors"

    def test_indirect_property(self):
        class Test(object):

            test = misc.indirect_property("tget", "tset")

            x = 1
            def tget(self):
                return self.x
            def tset(self, value):
                self.x = value

        class Test2(Test):
            def tget(self):
                return self.x*2

            def tset(self, value):
                self.x = -value

        #test direct works
        t = Test()
        self.assertEqual(t.x, 1)
        self.assertEqual(t.test, 1)
        t.test = 3
        self.assertEqual(t.x, 3)
        self.assertEqual(t.test, 3)

        #test subclass overide works
        t2 = Test2()
        self.assertEqual(t2.x, 1)
        self.assertEqual(t2.test, 2)
        t2.test = 3
        self.assertEqual(t2.x, -3)
        self.assertEqual(t2.test, -6)

        #test instance override works
        t3 = Test2()
        t3.tget = lambda : t3.x+.5
        self.assertEqual(t3.x, 1)
        self.assertEqual(t3.test, 1.5)

    def test_constructor_property(self):
        class Test(object):
            test = misc.constructor_property(dict)

        #test class view
        self.assertIsInstance(Test.test, misc.constructor_property)

        #check initial construction
        t = Test()
        d = t.test
        self.assertIsInstance(d, dict)

        #check we get same attr next time
        self.assertIs(t.test, d)

        #check overwrite works
        e = [2]
        t.test = e
        self.assertIs(t.test, e)

        #check delete causes re-creation
        del t.test
        f = t.test
        self.assertIsInstance(f, dict)
        self.assertIsNot(d, f)

    def test_constructor_property_passref(self):
        #check passref works
        def f(obj):
            return [obj]
        class Test(object):
            test = misc.constructor_property(f, passref=True)

        #test class view
        self.assertIsInstance(Test.test, misc.constructor_property)

        #check initial construction
        t = Test()
        d = t.test
        self.assertIsInstance(d, list)
        self.assertEquals(d, [t])

        #check we get same attr next time
        self.assertIs(t.test, d)

        #check overwrite works
        e = [2]
        t.test = e
        self.assertIs(t.test, e)

        #check delete causes re-creation
        del t.test
        f = t.test
        self.assertIsInstance(f, list)
        self.assertIsNot(f, d)
        self.assertEquals(f, d)

    def test_class_property(self):
        class Test(object):
            x = 1

            @misc.class_property
            def test(self):
                return self, self.x

        #make sure it works as class property
        self.assertEquals(Test.x, 1)
        self.assertEquals(Test.test, (Test, 1))

        #make sure it doesn't return instance
        t = Test()
        self.assertEquals(t.x, 1)
        self.assertEquals(t.test, (Test, 1))

        #make sure it reads from the class, not instance
        t.x = 2
        self.assertEquals(t.x, 2)
        self.assertEquals(t.test, (Test, 1))

#=========================================================
#
#=========================================================

class ParseAgentTest(TestCase):

    def test_parse_agent_string(self):
        for s in self.agents:
            #TODO: should compare to return values,
            #not just make sure we _can_ parse this
            misc.parse_agent_string(s)

    #this is just a random assorted of agent strings
    # that should be parseable
    agents = [
        #firefox
        "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.11) Gecko/2009060309 Ubuntu/9.04 (jaunty) Firefox/3.0.11"
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.12) Gecko/20050915 Firefox/1.0.7',

        #msie
        'Mozilla/4.0 (compatible; MSIE 6.0; AOL 9.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
        'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FunWebProducts; .NET CLR 1.1.4322)',
        'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)',

        #konq
        'Mozilla/5.0 (compatible; Konqueror/3.4; Linux) KHTML/3.4.1 (like Gecko)',

        #safari
        'Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/417.9 (KHTML, like Gecko) Safari/417.8',

        #TODO: chrome

        #java
        'Mozilla/4.0 (Windows XP 5.1) Java/1.6.0_07',

        #various bots
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        'Mozilla/5.0 (compatible; Ask Jeeves/Teoma; +http://about.ask.com/en/docs/about/webmasters.shtml)'
        'msnbot/0.9 (+http://search.msn.com/msnbot.htm)',
        'XmlRssTimingBot/2.03 (libwww-perl/5.800)',
    ]
