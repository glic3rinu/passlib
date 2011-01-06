"""tests for bps.text -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import os.path
#site
#pkg
from bps.text import EnglishInflector, condense, asbool, clean_filename, \
    split_condense, fmt_has_field, get_fmt_fields, parse_fmt_field, \
    parse_fmt_string
from bps.unstable import ellipsize
from bps.meta import Params as ak
#module
from bps.tests.utils import TestCase
#=========================================================
#
#=========================================================
class ParseTest(TestCase):
    condense_cases = [
        (None, None),
        ("",""),
        ("  ", ""),
        ("a", "a"),
        ("a\r\n", "a"),
        (" a", "a"),
        ("  a", "a"),
        ("a ", "a"),
        ("a  ", "a"),
        (" a ", "a"),
        (" a b ", "a b"),
        ("   aaa   bbb     ", "aaa bbb"),
        ("   aaa   bbb", "aaa bbb"),
        (" a a ", "a a"),
        (" asas  asdas ", "asas asdas"),
        ("asas    asdas", "asas asdas"),
        ("    asas   asdas  ", "asas asdas"),
        ("\t    asas \r\n  asdas  \n", "asas asdas"),
        ]
    condense_other = [
        ("", "xyz", ""),
        ("xy", "xyz", ""),
        ("xayyybz", "xyz", "axb"),
        ("xayyybz", " xyz", "a b"),
        (". ..  a ..  d .. c ..", " .", "a d c"),
        (". ..  a ..  d .. c ..", ". ", "a.d.c"),

        #make sure regexp escaping works
        ("x--[[-y]-]---z", "[-]", "x[y[z"),
        ]

    def test_condense(self):
        for i,o in self.condense_cases:
            self.assertEqual(condense(i), o)
    def test_condense_other(self):
        for i,c,o in self.condense_other:
            r = condense(i, c)
            self.assertEqual(r, o, "case %r: got %r, expected %r" % ((i, c), r, o))

    sc_cases = [
        ak([], None),
        ak([''], ''),
        ak([], '', empty="strip"),
        ak(['a'], "a"),
        ak(['a'], " a "),
        ak(['a b'], " a    b"),
        ak(['a','b'], " a  ,  b"),
        ak(['a','','b'], " a  ,,  b"),
        ak(['a','','b', ''], " a  ,    ,  b,"),
        ak(['a','b'], " a  ,    ,  b,", empty="strip"),
        ak(['a','c ; d','b ;; b'], " a  , c ;   d   , b ;; b,", empty="strip"),
        ak(['a','c ; d','b','b'], " a  , c ;   d   , b ;; b,", sep=[';;', ','], empty="strip"),

        #bug - char in sep occurs in strip chars, was causing sep to be lost
        ak(['a', 'b', '', 'c', 'd'], "a\n b \n , c \t \n d", sep=['\n', ','])
        ]
    def test_split_condense(self):
        self.check_function_results(split_condense, self.sc_cases)

    asbool_cases = [
        ('yes', True),
        ('  y   ', True),
        ('y', False, True),
        ('y', True, True),

        ('no', False),
        ('n', True, False),
        ('n', True, False),

        (None, None),
        (None, False, False),
        ('', None),
        ('null', None),
        ('null', None, None),
        ('null', False, False),
        ('null', True, True),
    ]

    def test_asbool(self):
        for elem in self.asbool_cases:
            if len(elem) == 2:
                i, o = elem
                self.assertEqual(asbool(i), o)
            else:
                i, d, o = elem
                self.assertEqual(asbool(i, d), o)
                self.assertEqual(asbool(i, default=d), o)
        self.assertRaises(ValueError, asbool, "not a bool")

    cleanfn_cases = [
        #row format: (expected_result, *args, **kwds)

        #
        #check safe preset
        #

        #random data
        ak("c def ____ ___", "/a/b/c   def ::!% ***"),
        ak("c def", "/a/b/c   def ::!% ***", safe_char=''),
        ak("_.._sbin run", "../../sbin run"),
        ak("sbin run", "../../sbin run", safe_char=' '),

        #
        #check clean preset
        #

        #random data
        ak("c def", "/a/b/c   def ::!% ***", preset='clean'),
        ak("c def", "/a/b/c   def ::!% ***", safe_char='', preset='clean'),
        ak("sbin run", "../../sbin run", preset='clean'),
        ak("sbin run", "../../sbin run", safe_char=' ', preset='clean'),

        #
        #check paranoid preset
        #

        #random data
        ak("c_def", "/a/b/c   def", preset="paranoid"),
        ak("x_y_z_123", "%     .. / / .. $#^&   *(x)[]/ y\\!!! z 123",preset="paranoid"),

        #
        #check other presets
        #
##        ak("/a/b/c", "   /  a  /  b  / c  ::\\!%", preset="posix-path", safe=""),
##        ak("/a/b/c", "/a/b/c", dialect="posix-path"),
        ak("_.._sbin run _this_ _ this", "../../sbin run [this] & this", preset="excel_sheet"),

        #
        #default should be honored for None and badset
        #
        ak(None, None), #the default default is None
        ak("xxx", None, "xxx"), #custom default is honored
        ak("xxx", ".", "xxx"),
        ak("xxx", "..", "xxx"),

        #
        #should strip absolute paths entirely
        #
        ak("name", "/a/b/c/name"), #absolute posix path
        ak("name", "xxx:\\bbb\\ccc\\name"), #absolute dos path
        ak("name", "\\\\bbb\\ccc\\name"), #absolute win network path

        #
        #should clean path-like chars (slashes, etc)
        #
        ak("_x_y_z run", "../x/y/z run"),
        ak("x_y_z__", "x\\y\\z%%"),
        ak("x_y_z__", "x\\y\\z$$"),
        ak("_ProgramFiles__EvilApp.exe", "%ProgramFiles%\\EvilApp.exe"),

        #
        #should remove badset entirely
        #
        ak(None, ""),
        ak(None, " "),
        ak(None, "."),
        ak(None, ".."),
        ak(None, "..."),
        ak(None, " !.!!.! ", safe_char=""),

        #
        #should strip dots/spaces
        #
        ak("x y z", "...  .. x y     z ..."),

        #
        #shouldn't allow unsafe chars to sneak into safe_chars
        #
        ak("xy__z", "xy%!z"),
        ak("xyz", "xy%!z", safe_char="%"),

        #
        #test safe_char mapping
        #
        ak("_--y-z_", "%!&y&z%", safe_char={"default": '_', "&!": "-"}),
        ak("_d-y-z_", "%d&y&z%", safe_char={"default": "_", "&": "-"}),

        #
        #ext_list testing
        #
        ak("a", "a", ext_list=""), #should strip all extension
        ak("a", "a.b", ext_list=""),

        ak("a", "a", ext_list=[]), #should strip all extensions
        ak("a", "a.b", ext_list=[]),

        ak("a.b", "a", ext_list=".b"), #should enforce '.b' extension
        ak("a.b", "a.b", ext_list=".b"),
        ak("a.b", "a.c", ext_list=".b"),

        ak("a.b", "a", ext_list=".b:.c"), #should enforce '.b' or '.c', using ':' sep
        ak("a.b", "a.b", ext_list=".b:.c"),
        ak("a.c", "a.c", ext_list=".b:.c"),
        ak("a.b", "a.d", ext_list=".b:.c"),

        ak("a.b", "a", ext_list=".b;.c"), #should enforce '.b' or '.c', using ';' sep
        ak("a.b", "a.b", ext_list=".b;.c"),
        ak("a.c", "a.c", ext_list=".b;.c"),
        ak("a.b", "a.d", ext_list=".b:.c"),

        ak("a.b", "a", ext_list=[".b",".c"]), #should enforce '.b' or '.c', using list
        ak("a.b", "a.b", ext_list=[".b",".c"]),
        ak("a.c", "a.c", ext_list=[".b",".c"]),
        ak("a.b", "a.d", ext_list=".b:.c"),

        ak("a", "a", ext_list=".b:"), #should allow empty or '.b'
        ak("a.b", "a.b", ext_list=".b:"),
        ak("a.b", "a.c", ext_list=".b:"),

        ak("a.c", "a", "x.c", ext_list=".b:.c"), #should promote default to front
        ak("a.b", "a.b", "x.c", ext_list=".b:.c"),
        ak("a.c", "a.c", "x.c", ext_list=".b:.c"),
        ak("a.c", "a.d", "x.c", ext_list=".b:.c"),

        ak("a.b", "a", "x.d", ext_list=".b:.c"), #should ignore default
        ak("a.b", "a.d", "x.d", ext_list=".b:.c"),
        ak("a.c", "a.c", "x.d", ext_list=".b:.c"),
        ak("a.b", "a.d", "x.d", ext_list=".b:.c"),
    ]
    def test_cleanfn(self):
        self.check_cases(clean_filename, self.cleanfn_cases)

    #TODO: replace w/ check_function_results()
    def check_cases(self, func, cases):
        "helper for running through function call cases"
        for elem in cases:
            correct = elem.args[0]
            result = func(*elem.args[1:], **elem.kwds)
            self.assertEqual(result, correct,
                    "error for case %s, got %r, expected %r" % (elem.render(1), result, correct)
                    )

#=========================================================
#formatting
#=========================================================
S = os.path.sep

class MiscTest(TestCase):

    def test_ellipsize(self):
        self.check_function_results(ellipsize, [
            #too short
            ak("abc", "abc", 3),
            ak("...", "abcd", 3),
            ak("...", "abcd", 3, "<"),
            ak("...", "abcd", 3, "^"),

            #right
            ak("", "", 6),
            ak("abc", "abc", 6),
            ak("abcdef", "abcdef", 6),
            ak("abc...", "abcdefghi", 6),

            #left
            ak("", "", 6, "<"),
            ak("abc", "abc", 6, "<"),
            ak("abcdef", "abcdef", 6, "<"),
            ak("...ghi", "abcdefghi", 6, "<"),
            ak("...jkl", "abcdefghijkl", 6, "<"),

            #center
            ak("", "", 6, "^"),
            ak("abc", "abc", 6, "^"),
            ak("abcdef", "abcdef", 6, "^"),
            ak("a...hi", "abcdefghi", 6, "^"),
            ak("a...kl", "abcdefghijkl", 6, "^"),

            #custom char
            ak("abc!!!", "abcdefghi", 6, ellipsis="!!!"),

            #left / smart
            ak("...ghijkl", "abcdefghijkl", 9, "<", mode="smart"),
            ak("... hijkl", "abcdef hijkl", 9, "<", mode="smart"),
            ak("... ijkl",  "abcdefg ijkl", 9, "<", mode="smart"),
            ak("... l",     "abcdefghij l", 9, "<", mode="smart"),
            ak("... l",     "abcdefghij l", 9, "<", mode="smart", window=5),
            ak("...ghij l", "abcdefghij l", 9, "<", mode="smart", window=4),

            #right / plain
            ak("abc...", "abcdefghijkl", 6),
            ak("a c...", "a cdefghijkl", 6),
            ak("a"+S+"c...", "a"+S+"cdefghijkl", 6),

            #right / smart
            ak("abc...", "abcdefghijkl", 6, mode="smart"),
            ak("a ...", "a cdefghijkl", 6, mode="smart"),
            ak("a" + S + "c...", "a" + S + "cdefghijkl", 6, mode="smart"),

            #right / filepath
            ak("abc...", "abcdefghijkl", 6, mode="filepath"),
            ak("a c...", "a cdefghijkl", 6, mode="filepath"),
            ak("a/...", "a"+S+"cdefghijkl", 6, mode="filepath"),

            ])

#=========================================================
#inflection
#=========================================================
class EnglishInflectorTest(TestCase):
    #=========================================================
    #setup
    #=========================================================
    def setUp(self):
        self.inf = EnglishInflector()

    #standard pairs to test
    pairs = [
        #various random words
        ('money', 'money'),
        ('cow', 'cows'),
        ('user', 'users'),
        ('matrix', 'matrices'),
        ('array', 'arrays'),
        ('baby', 'babies'),
        ('permission', 'permissions'),
        ('fez', 'fezzes'),
        ('pez', 'pez'),
        ('fetus', 'fetuses'),

        #from medicred
        ('certification', 'certifications'),
        ('policy', 'policies'),
        ('product', 'products'),
        ('contract', 'contracts'),
        ('attachment', 'attachments'),
        ('cert', 'certs'),
        ('entry', 'entries'),
        ('license', 'licenses'),
        ('affiliation', 'affiliations'),
        ('record', 'records'),

        #from other jobs
        ('loaf','loaves'),

        #from python_inflector - http://www.bermi.org/inflector/download
        ("search"      , "searches"),
        ("switch"      , "switches"),
        ("fix"         , "fixes"),
        ("box"         , "boxes"),
        ("process"     , "processes"),
        ("address"     , "addresses"),
        ("case"        , "cases"),
        ("stack"       , "stacks"),
        ("wish"        , "wishes"),
        ("fish"        , "fish"),

        ("category"    , "categories"),
        ("query"       , "queries"),
        ("ability"     , "abilities"),
        ("agency"      , "agencies"),
        ("movie"       , "movies"),

        ("archive"     , "archives"),

        ("index"       , "indices"),

        ("wife"        , "wives"),
        ("safe"        , "saves"),
        ("half"        , "halves"),

        ("move"        , "moves"),

        ("salesperson" , "salespeople"),
        ("person"      , "people"),

        ("spokesman"   , "spokesmen"),
        ("man"         , "men"),
        ("woman"       , "women"),

        ("basis"       , "bases"),
        ("diagnosis"   , "diagnoses"),

        ("datum"       , "data"),
        ("medium"      , "media"),
        ("analysis"    , "analyses"),

        ("node_child"  , "node_children"),
        ("child"       , "children"),

        ("experience"  , "experiences"),
        ("day"         , "days"),

        ("comment"     , "comments"),
        ("foobar"      , "foobars"),
        ("newsletter"  , "newsletters"),

        ("old_news"    , "old_news"),
        ("news"        , "news"),

        ("series"      , "series"),
        ("species"     , "species"),

        ("quiz"        , "quizzes"),

        ("perspective" , "perspectives"),

        ("ox" , "oxen"),
        ("photo" , "photos"),
        ("buffalo" , "buffaloes"),
        ("tomato" , "tomatoes"),
        ("dwarf" , "dwarves"),
        ("elf" , "elves"),
        ("information" , "information"),
        ("equipment" , "equipment"),
        ("bus" , "buses"),
        ("status" , "statuses"),
        ("mouse" , "mice"),

        ("louse" , "lice"),
        ("house" , "houses"),
        ("octopus" , "octopi"),
        ("virus" , "viri"),
        ("alias" , "aliases"),
        ("portfolio" , "portfolios"),

        ("vertex" , "vertices"),
        ("matrix" , "matrices"),

        ("axis" , "axes"),
        ("testis" , "testes"),
        ("crisis" , "crises"),

        ("rice" , "rice"),
        ("shoe" , "shoes"),

        ("horse" , "horses"),
        ("prize" , "prizes"),
        ("edge" , "edges"),
    ]

    #various prefixes
    prefixes = [
        '',
        'the ',
        'man-',
        'the baby-',
        'the kinda-slow ',
        'the kinda-slow baby-',
    ]

    #=========================================================
    #test base singularize & pluralize behavior
    #=========================================================
    def test_empty(self):
        inf = self.inf
        self.assertEqual(inf.pluralize(None), '')
        self.assertEqual(inf.singularize(None), '')
        self.assertEqual(inf.pluralize(''), '')
        self.assertEqual(inf.singularize(''), '')

    def test_uncountable(self):
        for word in self.inf.uncountable_words:
            self.check_pair(word, word)

    def test_irregular(self):
        for singular, plural in self.inf.irregular_plurals.iteritems():
            self.check_pair(singular, plural)

    def test_std(self):
        for singular, plural in self.pairs:
            self.check_pair(singular, plural)

    #=========================================================
    #test prefix handling
    #=========================================================
    def test_prefixes(self):
        inf = self.inf
        for singular, plural in self.pairs:
            for prefix in self.prefixes:
                self.check_pair(prefix + singular, prefix + plural)

    #TODO: test caps preservation

    def test_countof(self):
        inf = self.inf
        singular = "cow"
        plural = "cows"
        self.assertEqual(inf.countof(0, singular), "0 " + plural)
        self.assertEqual(inf.countof(1, singular), "1 " + singular)
        self.assertEqual(inf.countof(2, singular), "2 " + plural)
        self.assertEqual(inf.countof(100, singular), "100 " + plural)

    #=========================================================
    #test articles
    #=========================================================
    oneof_cases = [

        #soft H rule (the exception)
        ("hourglass", "an hourglass"),

        #hard H rule
        ("horse", "a horse"),
        ("hoe", "a hoe"),
        ("house", "a house"),

        #exceptions to the vowel rule
        ("university", "a university"), #soft U
        ("unicorn", "a unicorn"), #soft U

        #normal vowels
        ("avian", "an avian"),
        ("avian planet", "an avian planet"), #catches a normalization bug
        ("umbrella", "an umbrella"),

        #normal consonants
        ("car", "a car"),
        ]
    def test_oneof(self):
        inf = self.inf
        for input, output in self.oneof_cases:
            result = inf.oneof(input)
            self.assertEqual(result, output)

    #=========================================================
    #test ordinals
    #=========================================================
    ordinal_cases = [
        (1, "1st"),
        (2, "2nd"),
        (3, "3rd"),
        (5, "5th"),
        (199, "199th"),
        (1042, "1042nd")
    ]
    def test_ordinals(self):
        inf = self.inf
        self.assertRaises(ValueError, inf.ordinal, -1)
        self.assertRaises(ValueError, inf.ordinal, 0)
        for input, output in self.ordinal_cases:
            result = inf.ordinal(input)
            self.assertEqual(result, output)

    #=========================================================
    #helpers
    #=========================================================
    def check_pair(self, singular, plural):
        "check a given pair translated back and forth"
        self.check_pluralize(singular, plural)
        self.check_singularize(plural, singular)

    def check_pluralize(self, singular, plural):
        test = self.inf.pluralize(singular)
        self.assertEqual(test, plural, "Plural of %r is %r, not %r" % (singular, plural, test))

        #TODO: alg isn't idempotent yet
##        test = self.inf.pluralize(plural)
##        self.assertEqual(test, plural, "Plural %r mishandled as %r" % (plural, test))

    def check_singularize(self, plural, singular):
        test = self.inf.singularize(plural)
        self.assertEqual(test, singular, "Singular of %r is %r, not %r" % (plural, singular, test))

    #=========================================================
    #EOC
    #=========================================================

#=========================================================
#format introspection tests
#=========================================================
class FormatTest(TestCase):

    #TODO: test parse_fmt_string
    #TODO: test that render_format() works

    def test_parse_fmt_field(self):
        #detect bug under 2.5 where we get 'None' back
        self.check_parse_fmt_field("d","d")

        #detect nested attr mode
        self.check_parse_fmt_field("1[{2}]", 1, (False,"{2}"))
        self.check_parse_fmt_field("1.{2}", 1, (True,"{2}"))

        #check dup attrs raises error
        h, t = parse_fmt_field("1..x")
        self.assertEquals(h, 1, "head:")
        self.assertRaises(ValueError, tuple, t)
            #ValueError: Empty attribute in format string

        #allow weird chars (this is what py26 does)
        self.check_parse_fmt_field("1\x00", '1\x00')
        self.check_parse_fmt_field("1.\x00", 1, (True,"\x00"))
        self.check_parse_fmt_field("1[\x00]", 1, (False,"\x00"))

        #not sure what right thing to do here is,
        #but this is what py26 does
        self.check_parse_fmt_field("1{2}", "1{2}")

    def check_parse_fmt_field(self, source, head, *tail):
        h, t = parse_fmt_field(source)
        self.assertEquals(h,head,"head:")
        self.assertIsNot(t,None,"tail:") #should always be iter
        self.assertEquals(tuple(t),tail,"tail:")

    def test_get_fmt_fields(self):
        self.check_function_results(get_fmt_fields, [
            (set([0,  'a', 'b', 'c', 'd']), '{0.1:{c}d} {a[{b}]} {d}'),

            #this is what py2.6 does, so I guess it's right..
            (set([0,1,2,'a{b}']), '{0} {1.{2}} {a{b}}'),
            ])

    def test_fmt_has_field(self):
        self.check_function_results(fmt_has_field,[
            #check numbers
            (True, "{0} {1} {a:s}", 0),
            (True, "{0} {1.{2}} {a:s} {b:{c}d}", 1),
            (True, "{0} {1.{2}} {a:s} {b:{c}d}", 2),

            #check letters
            (True, "{0} {a:s}", 'a'),
            (True, "{0} {1} {a:s} {b:{c}d}", 'b'),
            (True, "{0} {1} {a:s} {b:{c}d}", 'c'),

            #check stringified numbers
            (False, "{0} {1} {b:d}", '0'),
            (False, "{0} {1} {b:d}", '1'),
            (False, "{0} {1} {b:d}", '2'),

            #check missing numbers
            (False, "{0} {1} {b:d}", 2),

            #check missing letters
            (False, "{0} {1} {a:s} {b:d}", 'x'),
            (False, "{0} {1} {a:s} {b:{c}d}", 'd'),
            ])

#=========================================================
#email
#=========================================================
from bps.unstable import parse_email_addr, compile_email_addr, validate_email_parts, norm_email_addr

class ParseEmailTest(TestCase):
    "test parse_email_addr()"

    #=========================================================
    #parse_email_addr
    #=========================================================

    #addrs that should always parse
    valid_addrs = [
        #check simple addrs & chars
        ("abc@def", None, "abc", "def"),
        ("abc@def", None, "abc", "def"),
        ('abc+def@369.live.com', None, 'abc+def', '369.live.com'),
        (u'Pel\xe9@live.com', None, u'Pel\xe9', u'live.com'),

        #check name parser
        ("Name <abc@def>", "Name", "abc", "def"),
        ("John Jackson <abc@def>", "John Jackson", "abc", "def"),
        ('"John Jackson" <abc@def>', "John Jackson", "abc", "def"),
        ("'John Jackson' <abc@def>", "John Jackson", "abc", "def"),
        ("N@me <abc@def>", "N@me", "abc", "def"), #this is questionable

        #check periods in local part
        ("a.b.c@def", None, "a.b.c","def"),

        #check periods in domain
        ("abc@def.com", None, "abc", "def.com"),
        ("abc@def.com.", None, "abc", "def.com."),
        ("abc@def.abc.com", None, "abc", "def.abc.com"),

        #check hyphens in domain
        ("abc@def-ghi", None, "abc", "def-ghi"),
        ("abc@def-ghi.xmas-fun.", None, "abc", "def-ghi.xmas-fun."),
    ]

    #addrs that require strip=True to parse
    strip_addrs = [
        #should parse space between parts & at ends
        (" user @ example.com ", None, "user","example.com"),

        #should get space w/in brackets
        ("Jeff Harris < user@example.com >", "Jeff Harris", "user","example.com"),

        #should condense name part
        ("  Jeff    Harris< user @ example.com   >", "Jeff Harris", "user","example.com"),
    ]

    #addrs that require strict=False to parse
    relaxed_addrs = [
        #source, name, local, domain

        #there only be one '@'
        ("A@b@c@example.com", None, "A@b@c", "example.com"), # only one @ is allowed outside quotations marks
            #NOTE: the fact that this parses as A@b@c / example.com, not A / b@c@example.com, is a border case whose behavior is not guaranteed

        #local part can't have periods at start, end, or doubled
        ("Abc.@example.com", None, "Abc.", "example.com"),
        (" user. @ example.com  ", None, "user.", "example.com"),
        (" .user @ example.com  ", None, ".user", "example.com"),
        ("Abc..123@example.com", None, "Abc..123", "example.com"),
        (" user..x @ example.com  ", None, "user..x", "example.com"),

        #local part can't have []
        ("user[xxx]@def.eu", None, "user[xxx]","def.eu"),

        #domain part can't have []
        ("user@def[xxx].eu", None, "user","def[xxx].eu"),

        #domain part can't have period at start, or doubled
        ("user@.def.eu", None, "user",".def.eu"),
        ("user@def..eu", None, "user","def..eu"),

        #domain part can't have hypen at start or end of element
        ("user@-def", None, "user", "-def"),
        ("user@abc.-def", None, "user", "abc.-def"),
        ("user@def-", None, "user", "def-"),
        ("user@def-.ghi", None, "user", "def-.ghi"),

        #invalid attrs (when not in unicode)
        ('Pel\x01@live.com', None, 'Pel\x01', 'live.com'),
        ('Pel@liv\x02.com', None, 'Pel', 'liv\x02.com'),
    ]

    #addrs that will always be rejected
    invalid_addrs = [
        #must at least have local & domain parts
        "  @ ",
        "l@ ",
        "@d",

        #must have matching <> in correct spot
        "n <l@d",
        "n l@d>",
        "n <l@d> x",
        "<n> l@d",
        "n> l@d",

        #must have @
        "Abc.example.com",
        "jimmy abc.example.com",

        #always invalid attrs
        "xyz<>@example.com",
    ]

    #addrs that should all parse as empty addresses
    empty_addrs = [
        None,
        "",
        "    \t ",
        " <>",
        "'' <   >  ",
    ]

    #test addrs that require clarify=True to parse
    clarify_addrs = [
        ("steven <jimmy at well dot net>", "steven", "jimmy","well.net"),
        ("jimmy at well dot net", None, "jimmy","well.net"),
        ("jimmy (at) well (dot) net", None, "jimmy","well.net"),
        ("jimmy (at)well(dot) net", None, "jimmy","well.net"),
        ("jimmy [at] well [dot] net", None, "jimmy","well.net"),
    ]

    def test_parse_valid(self):
        "test parse_email_addr() with valid addresses"
        for addr, name, local, domain in self.valid_addrs:
            result = parse_email_addr(addr, strip=False)
            self.assertEquals(result, (name,local,domain))

    def test_parse_strip(self):
        "test parse_email_addr() with valid addresses that require strip=True"
        for addr, name, local, domain in self.strip_addrs:
            self.assertRaises(ValueError, parse_email_addr, addr, strip=False)
            result = parse_email_addr(addr)
            self.assertEquals(result, (name,local,domain))

    def test_parse_relaxed(self):
        "test parse_email_addr() with valid addresses that require strict=False"
        for addr, name, local, domain in self.relaxed_addrs:
            self.assertRaises(ValueError, parse_email_addr, addr)
            result = parse_email_addr(addr, strict=False)
            self.assertEquals(result, (name,local,domain))

    def test_parse_invalid(self):
        "test parse_email_addr() with invalid addrs"
        for addr in self.invalid_addrs:
            self.assertRaises(ValueError, parse_email_addr, addr, strict=False)
            self.assertRaises(ValueError, parse_email_addr, addr, strict=False, clarify=True)

    def test_parse_clarify(self):
        "test parse_email_addr() with valid addresses that require clarify=True"
        for addr, name, local, domain in self.clarify_addrs:
            self.assertRaises(ValueError, parse_email_addr, addr)
            result = parse_email_addr(addr, clarify=True)
            self.assertEquals(result, (name,local,domain))

    def test_parse_empty(self):
        "test parse_email_addr() with empty strings"
        for value in self.empty_addrs:
            self.assertRaises(ValueError, parse_email_addr, value)
            result = parse_email_addr(value, allow_empty=True)
            self.assertEquals(result,(None,None,None))

class ValidateEmailTest(TestCase):
    "test validate_email_parts()"

    valid_parts = [
        ("loc", "dom"),
        ("loc","dom"),

        ("a.b","dom"),
        ("a.b.c","dom"),
        ("ab+c","dom"),
        ("ab-c","dom"),

        ("loc","dom.dom"),
        ("loc","dom.dom."),
        ("loc","dom-ghi"),
        ("loc","3com.com"),
    ]

    relaxed_parts = [
        ("loc.", "dom"),
        (".loc", "dom"),
        ("loc..loc", "dom"),
        ("loc loc", "dom"),

        ("loc",".dom"),
        ("loc","dom..dom"),
        ("loc","dom-"),
        ("loc","dom-.dom"),
        ("loc","-dom"),
        ("loc","dom.-dom"),
    ]

    invalid_parts = [
        ("", "dom"),
        ("loc", ""),
    ]

    def test_validate_valid(self):
        "test validate_email_parts() against valid tuples"
        n = None
        for l,d in self.valid_parts:
            validate_email_parts(n,l,d)

    def test_validate_relaxed(self):
        "test validate_email_parts() against valid tuples that require strict=False"
        n = None
        for l,d in self.relaxed_parts:
            self.assertRaises(ValueError, validate_email_parts,n,l,d)
            validate_email_parts(n,l,d, strict=False)

    def test_validate_invalid(self):
        "test validate_email_parts() against invalid tuples"
        n = None
        for l,d in self.invalid_parts:
            self.assertRaises(ValueError, validate_email_parts,n,l,d)
            self.assertRaises(ValueError, validate_email_parts,n,l,d, strict=False)

class NormEmailTest(TestCase):
    "test norm_email_addr()"

    valid_addrs = [
        ("user@local","user@local"),
        ("   user   @  local   ","user@local"),
        ("<user@local>","user@local"),

        ("Name J<user@local>",'"Name J" <user@local>'),
        ("  '  Name J '  <user@local>",'"Name J" <user@local>'),
    ]

    clarify_addrs =[
        ("joe at cell dot net","joe@cell.net"),
        ("joe (at) cell.net","joe@cell.net"),
        ("joe (at) cell (dot) net","joe@cell.net"),
    ]

    relaxed_addrs = [
        ("user..name@local", "user..name@local"),
    ]

    invalid_addrs = [
        "user",
        "user\x01@local",
    ]

    def test_norm_valid(self):
        "test norm_email_addr() with valid addrs"
        for value, real in self.valid_addrs:
            result = norm_email_addr(value)
            self.assertEquals(result, real)

    def test_norm_relaxed(self):
        "test norm_email_addr() with valid addrs which require strict=False"
        for value, real in self.relaxed_addrs:
            self.assertRaises(ValueError, norm_email_addr, value)
            result = norm_email_addr(value, strict=False)
            self.assertEquals(result, real)

    def test_norm_invalid(self):
        "test norm_email_addr() with invalid addrs"
        for value in self.invalid_addrs:
            self.assertRaises(ValueError, norm_email_addr, value)

    def test_norm_clarify(self):
        "test norm_email_addr() with obfucated addrs"
        for value, real in self.clarify_addrs:
            self.assertRaises(ValueError, norm_email_addr, value)
            result = norm_email_addr(value, clarify=True)
            self.assertEquals(result, real)

#=========================================================
#EOF
#=========================================================
