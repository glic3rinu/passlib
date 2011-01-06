"""bps.unstable.ansi tests"""
#=========================================================
#
#=========================================================
from bps.tests.utils import TestCase
from bps.meta import Params as ak
from bps.unstable.ansi import CODESET, AnsiCode, \
    AnsiError, AnsiCommandError, AnsiParseError, \
    parse_ansi_string

#=========================================================
#
#=========================================================
class AnsiCodeTest(TestCase):
    "test AnsiCode class"

    #=========================================================
    #constants
    #=========================================================
    c0_good = [
        #source=code
        '\x00',
        '\x01',
        '\x02',
        '\x03',
        '\x04',
        '\x05',
        '\x06',
        '\x07',
        '\n',
    ]

    c1_good = [
        #source, code
        ('\x1bA','A'),
        ('\x1bZ','Z'),
    ]

    icf_good = [
        #source, code
        ('\x1b~','~'),
    ]

    cseq_good = [
        #source, code, argstr, **other-attrs-to-test

        ak("\x1b[31;33x","x","31;33", args=(31,33)),

        ak("\x1b[A","A","", args=(), offset=1),
        ak("\x1b[1A","A","1", args=(1,), offset=1),
        ak("\x1b[3A","A","3", args=(3,), offset=3),

        ak("\x1b[m","m","", args=()),
        ak("\x1b[31m","m","31", args=(31,)),
        ak("\x1b[31;32;33m","m","31;32;33", args=(31,32,33)),

        ak("\x1b[31!x", "!x","31"),
    ]

    bad_parse = [
        "", #empty string not allowed
        " ",
        "a",
        "abc",
        "\x1b", #raw ESC isn't allowed
        "\x1b\x7F", #code not in c1 or icf range
        "\x1b[", #raw CSI isn't allowed
        "\x1b[31~x", #'~' not a valid intermediate byte
        "\x1b[31!31x", #'!' valid intermediate byte, but can't be interspersed w/ params
        "\x1b[!", #not a valid code
    ]

    #source strings which should parse correctly, and are in normalized form
    all_good = c0_good + \
                  [ x[0] for x in c1_good ] + \
                  [ x[0] for x in icf_good ] + \
                  [ x[0] for x in cseq_good ]

    #source strings which should get normalized
    all_unnormalized = [
        ("\x1b[0;0f", "\x1b[0;0H"),
    ]

    #=========================================================
    #parse tests
    #=========================================================
    def test_c0_good(self):
        "test known good c0 codes parse"
        codeset = CODESET.C0
        for source in self.c0_good:
            code = source
            c = AnsiCode.parse(source)
            self.assertEqual(c.codeset, codeset)
            self.assertEqual(c.code, code)
            self.assertEqual(repr(c), repr(AnsiCode(codeset, code)))

    def test_c1_good(self):
        "test known good c1 codes parse"
        codeset = CODESET.C1
        for source, code in self.c1_good:
            c = AnsiCode.parse(source)
            self.assertEqual(c.codeset, codeset)
            self.assertEqual(c.code, code)
            self.assertEqual(repr(c), repr(AnsiCode(codeset, code)))

    def test_icf_good(self):
        "test known good c1 codes parse"
        codeset = CODESET.ICF
        for source, code in self.icf_good:
            c = AnsiCode.parse(source)
            self.assertEqual(c.codeset, codeset)
            self.assertEqual(c.code, code)
            self.assertEqual(repr(c), repr(AnsiCode(codeset, code)))

    def test_cseq_good(self):
        "test known good cseq codes parse"
        codeset = CODESET.CSEQ
        for row in self.cseq_good:
            source, code, argstr = row.args
            c = AnsiCode.parse(source)
            self.assertEqual(c.codeset, codeset)
            self.assertEqual(c.code, code)
            self.assertEqual(c.argstr, argstr)
            for k,v in row.kwds.iteritems():
                self.assertEqual(getattr(c,k),v)
            self.assertEqual(repr(c), repr(AnsiCode(codeset, code, argstr=argstr)))

    def test_bad(self):
        "test known bad codes don't parse"
        for source in self.bad_parse:
            self.assertRaises(AnsiParseError, AnsiCode.parse, source)

    #=========================================================
    #test try-parse
    #=========================================================
    def test_try_parse_good(self):
        for source in self.all_good:
            ok, result = AnsiCode.try_parse(source)
            self.assert_(ok)
            self.assertIsInstance(result, AnsiCode)
            self.assertEqual(result.render(), source)

    def test_try_parse_bad(self):
        for source in self.bad_parse:
            ok, result = AnsiCode.try_parse(source)
            self.assert_(not ok)
            self.assertIsInstance(result, AnsiParseError)

    #=========================================================
    #render
    #=========================================================
    def test_render_good(self):
        "test known good codes render/str like source"
        for source in self.all_good:
            c = AnsiCode.parse(source)
            self.assertEquals(c.render(), source)
            self.assertEquals(str(c), source)

    def test_render_normalized(self):
        "test known redundant codes render/str properly"
        for source, result in self.all_unnormalized:
            c = AnsiCode.parse(source)
            norm = c.render()
            self.assertEquals(norm, result)
            self.assertEquals(str(c), source) #since this contains 'source', will render original
            c2 = AnsiCode.parse(norm)
            self.assertEquals(c2.render(), result)
            self.assertEquals(str(c2), result)

    #=========================================================
    #repr
    #=========================================================
    def test_repr(self):
        "test known good codes have working repr"
        for source in self.all_good:
            c = AnsiCode.parse(source)
            c2 = eval(repr(c))
            self.assertEqual(repr(c), repr(c2))
            c2.source = source #so dicts match
            self.assertEquals(c.__dict__, c2.__dict__)

    def test_repr_normalized(self):
        for source, result in self.all_unnormalized:
            c = AnsiCode.parse(source)
            c2 = eval(repr(c))
            self.assertEqual(repr(c), repr(c2))
            #NOTE: 'source' should have been preserved in repr
            self.assertEquals(c2.source, source)
            self.assertEquals(c.__dict__, c2.__dict__)

    #TODO: test malformed

    #=========================================================
    #test eq
    #=========================================================
    def test_eq(self):
        "test known good codes have working __eq__"
        codeset = CODESET.C0
        for source in self.all_good:
            c1 = AnsiCode.parse(source)
            for other in self.all_good:
                c2 = AnsiCode.parse(other)
                if other == source:
                    self.assert_(c1 == c2)
                    self.assert_(not c1 != c2)
                else:
                    self.assert_(not c1 == c2)
                    self.assert_(c1 != c2)

    #TODO: test malformed

    #=========================================================
    #xxx_code attrs
    #=========================================================
    def test_code_attrs(self):
        for source in self.all_good:
            c = AnsiCode.parse(source)
            for cs in (CODESET.C0, CODESET.C1, CODESET.ICF, CODESET.CSEQ):
                v = getattr(c, cs + "_code")
                if cs == c.codeset:
                    self.assertEquals(v, c.code)
                else:
                    self.assertIs(v,None)

    #=========================================================
    #test specific init funcs
    #=========================================================

    #=========================================================
    #test malformed methods (kwd, is_malformed, get_malformed_reasons)
    #=========================================================

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#utils
#=========================================================
class UtilTest(TestCase):
    "test util funcs"

    # is_ansi_code
    # is_malformed_ansi_code
    # len_ansi_string
    # strip_ansi_string

class AnsiStripperTest(TestCase):
    "test AnsiStripper class"

#=========================================================
#
#=========================================================
class ParseTest(TestCase):
    'test parse_ansi_string(source, rtype=list, malformed_codes="ignore")'

    def test_sample_normal(self):
        "test normal functioning"
        text = "\x1b[34mXYZ\x1b[Dtest test\x1b(sdasda\x00asdasda\x1b~sdfsdf\n\nrwerwer"
        result = parse_ansi_string(text)
        self.assertEquals(result,[
            AnsiCode('cseq','m','34'),
            'XYZ',
            AnsiCode('cseq','D'),
            'test test',
            AnsiCode('c1','('),
            "sdasda",
            AnsiCode('c0','\x00'),
            'asdasda',
            AnsiCode('icf','~'),
            'sdfsdf\n\nrwerwer',
        ])

    def test_empty(self):
        result = parse_ansi_string("")
        self.assertEquals(result,[""])

    def test_alpha(self):
        result = parse_ansi_string("abc")
        self.assertEquals(result,["abc"])

    def test_1code(self):
        result = parse_ansi_string("\x1b[X")
        self.assertEquals(result,[AnsiCode("cseq",'X')])

    def test_rtype(self):
        "test rtype kwd"
        text = "abc\ndef\x1b[34mghi\x1b~"
        correct = [
            'abc\ndef',
            AnsiCode('cseq','m','34'),
            'ghi',
            AnsiCode('icf','~'),
        ]

        #test 'list'
        result = parse_ansi_string(text)
        self.assertIsInstance(result,list)
        self.assertEquals(result, correct)

        #test 'iter'
        result = parse_ansi_string(text, rtype=iter)
        self.assert_(hasattr(result,"next"))
        self.assertIs(iter(result),result)
        self.assertEquals(list(result), correct)

        #test 'tuple'
        result = parse_ansi_string(text, rtype=tuple)
        self.assertIsInstance(result,tuple)
        self.assertEquals(list(result), correct)

    def test_sample_malformed_codes(self):
        "test malformed_codes kwd"
        text = "XYZ\x1b[4;Dtest test"

        #try the default ("ignore")
        result = parse_ansi_string(text)
        self.assertEquals(result,[
            'XYZ',
            '\x1b[4;D',
            'test test',
        ])

        #try explicit parse mode
        result = parse_ansi_string(text, malformed_codes="parse")
        self.assertEquals(result,[
            'XYZ',
            AnsiCode(None, None, malformed="argstr contains non-integer: '4;'", source='\x1b[4;D'),
            'test test',
        ])

        #try strip mode
        result = parse_ansi_string(text, malformed_codes="strip")
        self.assertEquals(result,[
            'XYZ',
            'test test',
        ])

        #try raise-error mode
        self.assertRaises(AnsiParseError, parse_ansi_string, text, malformed_codes="raise")

#=========================================================
#
#=========================================================
