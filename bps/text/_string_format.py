"""
This is a cobbled together implemenation of PEP3101, for pre-2.6 python.
it should *not* be used for 2.6 and on.

It implements a Formatter lifted directly from Python 2.6.1's string.Formatter,
but with custom pure-python parsers replacing the CPython parsing functions.

It's format() implementation uses code taken from the "historical purposes only"
implementation stored in PEP3101's sandbox. This could probably use a cleanup.

This module shouldn't be used directly,
any applicable methods will be imported into bps.text.

.. note::
    This also contains some parsing code which
    should be reimplemented so that they use
    native python implementations when possible.
"""
#=========================================================
#imports
#=========================================================
from logging import getLogger
from array import array
log = getLogger(__name__)
import re
from decimal import Decimal

from math import log as logarithm
try:
    import locale
except:
    locale = None
try:
    import fpformat
except:
    fpformat = None

__all__ = [
    #backported funcs
    'format', #equivalent to python builtin
    'Formatter', #work-alike for 2.6's string.Formatter
    ##NOTE: importing bps.text.patch_format will add format method to str & unicode

    #format parsing helpers
]

from bps.numeric import int_to_base

#=========================================================
#constants
#=========================================================
class FormatError(ValueError):
    "base exception for Formatter errors"
    pass

def EmptyFieldAttr():
    return FormatError("Empty attribute in format string")

def AltFormError(spec_type):
    return FormatError("Alternate form (#) not allowed in %s format specifier" % spec_type)

def UnknownFormatCodeError(code, value):
    "helper for raising error when ctype is unknown"
    return FormatError("Unknown format code %r for object of type %r" % (code, type(value)))

def InvalidFormatSpecError():
    "helper for raising error when spec malformed"
    return FormatError("Invalid conversion specification")

def UnexpectedFieldChar(field_name, ch):
    return FormatError, "unexpected %r character in field %r" % (ch, field_name)
##                raise FormatError, "unexpected character in field %s" % (field_name,)

#=========================================================
#field formatting - taken from StringFormat.py example in PEP3101,
# then recoded to pass the python 2.6.2 unitests 
#=========================================================

def format(value, spec=''):
    """pure-python implementation of python 2.6's builtin format() function"""
    log.debug("format(%r,%r)...", value, spec)

    #class-defined formatter
    if hasattr(value, "__format__"):
        result = value.__format__(spec)
    else:
        result = object_format(value, spec)

    #validate
    log.debug("... format=%r", result)
    if not isinstance(result, (str, unicode)):
        raise TypeError, "%s.__format__ must return string or unicode, not %r" % (type(value), type(result),)
    return result

def object_format(value, spec):
    "helper for unitests, equivalent of object.__format__"

    #TODO: add support for python's datetime, date objects

    #int formatters
    if isinstance(value, (int, long)):
        return int_format(value, spec)
    elif isinstance(value, bool):
        return bool_format(value, spec)

    #float formatters
    elif isinstance(value, float):
        return float_format(value, spec)
    elif isinstance(value, Decimal):
        return decimal_format(value, spec)

    #string & fallback formatters
    elif isinstance(value, (str, unicode)):
        return string_format(value, spec)
    else:
        return other_format(value, spec)

def other_format(value, spec):
    return string_format(str(value), spec)

#=========================================================
#string formatting
#=========================================================

def string_format(value, spec):
    fill, align, sign_fmt, alt, zero, width, prec, ctype = _parse_std_spec(spec)
    if ctype is None:
        ctype = 's'
    elif ctype != 's':
        raise UnknownFormatCodeError(ctype, value)
    if zero and fill is None:
        fill = '0'
    if sign_fmt:
        raise FormatError, "Sign not allowed in string format specifier"
    if alt:
        raise AltFormError("string")
    if align is None:
        align = "<"
    elif align == "=":
        raise ValueError, "'=' alignment not allowed in string format specifier"
    if prec is not None:
        #clip string (not documented, but py2.6 does it)
        value = value[:prec]
    return _pad_output('', value, fill, align, width)

#=========================================================
#int/long/bool formatting
#=========================================================
def bool_format(value, spec):
    fill, align, sign_fmt, alt, zero, width, prec, ctype = _parse_std_spec(spec)
    if ctype is None:
        return other_format(value, spec)
    elif ctype in 'bcdoxXn':
        value = 1 if value else 0
        return int_format(value, spec)
    elif ctype in 'eEfFgGn%':
        value = 1.0 if value else 0.0
        return float_format(value, spec)
    else:
        raise UnknownFormatCodeError(ctype, value)

def int_format(value, spec):
    fill, align, sign_fmt, alt, zero, width, prec, ctype = _parse_std_spec(spec)
    if ctype is None:
        ctype = 'd'
    elif ctype not in 'bcdoxXn':
        raise UnknownFormatCodeError(ctype, value)
    if align is None:
        align = "="
    if zero and fill is None:
        #FIXME: when 'alt' is enabled,
        # fill, align, and zero interact in a weird way,
        # not quite like a default fill
        fill = '0'
    sign, value = split_sign(value)
    prefix = _get_sign_char(sign, sign_fmt)
    if ctype == 'b':
        result = int_to_base(value, 2)
        if alt:
            prefix += '0b'
    elif ctype == 'c':
        result = chr(value)
    elif ctype == 'd':
        result = '%d' % (value,)
    elif ctype == 'o':
        result = "%o" % (value,)
        if alt:
            prefix += '0o'
    elif ctype == 'x':
        result = "%x" % (value,)
        if alt:
            prefix += '0x'
    elif ctype == 'X':
        result = "%X" % (value,)
        if alt:
            prefix += '0X'
    elif ctype == 'n':
        if locale:
            result = locale.format("%d", value)
        else:
            result = "%d" % (value,)
    else:
        raise AssertionError, "shouldn't be here"
    return _pad_output(prefix, result, fill, align, width)

#=========================================================
#float / decimal formatting
#=========================================================
def decimal_format(value, spec):
    return float_format(value, spec)

def float_format(value, spec):
    fill, align, sign_fmt, alt, zero, width, prec, ctype = _parse_std_spec(spec)
    if ctype is None:
        ctype = 'g'
    elif ctype not in 'eEfFgGn%':
        raise UnknownFormatCodeError(ctype, value)
    if zero and fill is None:
        fill = '0'
    if align is None:
        align = "="
    if alt:
        raise AltFormError("string")
    sign, value = split_sign(value)
    prefix = _get_sign_char(sign, sign_fmt)
    if ctype == '%':
        ctype = 'f'
        value = value*100.0
    elif ctype == 'n':
        ctype = 'g' #FIXME: this doesn't _quite_ do the same thing
    if ctype == 'g' or ctype == 'G':
        p = prec
        if p is None:
            result = str(value)
        else:
            tu = (ctype == 'G')
            if value < 10**-p or value > 10**p:
                ctype = 'e'
            else:
                ctype = 'f'
            if tu:
                ctype = ctype.upper()
    if ctype == 'e' or ctype == 'E':
        if prec is None:
            result = ('%' + ctype) % (value,)
        else:
            result = ("%." + str(prec) + ctype) % (value,) #to_sci
    elif ctype == 'f' or ctype == 'F':
        if prec is None:
            result = str(value)
            if ctype == 'F':
                result = result.upper()
        else:
            result = ("%." + str(prec) + ctype) % (value,) #to_fix
##    else:
##        raise AssertionError, "shouldn't be here"
    return _pad_output(prefix, result, fill, align, width)

#=========================================================
#format helpers
#=========================================================
def split_sign(val):
    "split number into sign char and positive value"
    if val < 0:
        return '-', -val
    return '+', val

def _get_sign_char(sign, sign_fmt):
    "return correct prefix"
    if sign == '-':
        return sign
    elif sign == '+' and sign_fmt and sign_fmt in '+ ':
        return sign_fmt
    return ''

def _pad_output(prefix, result, fill, align, width):
    "helper for padding & aligning result"
    if width is not None:
        padding = width - len(result) - len(prefix)
        if padding > 0:
            if fill is None:
                fill = ' ' #pick a default fillchar
            if align is None:
                align = ">" #pick a default align
            if align == '>':
                return fill * padding + prefix + result
            elif align == "^":
                left = padding//2
                right = padding-left
                return fill * left + prefix + result + fill * right
            elif align == '=':
                return prefix + fill * padding + result
            else:
                assert align == '<'
                return prefix + result + fill * padding
    return prefix + result

def _parse_std_spec(spec):
    """parse python's standard format specifier.

    described at
        http://docs.python.org/library/string.html#format-specification-mini-language
    the grammar is::
        format_spec ::=  [[fill]align][sign][#][0][width][.precision][type]
        fill        ::=  <a character other than '}'>
        align       ::=  "<" | ">" | "=" | "^"
        sign        ::=  "+" | "-" | " "
        width       ::=  integer
        precision   ::=  integer
        type        ::=  "b" | "c" | "d" | "e" | "E" | "f" | "F" | "g" | "G" |
                            "n" | "o" | "x" | "X" | "%"

    this function returns a tuple of:
        (fill, align, sign, alt, zero, width, prec, type)

    any unspecified values are set to ``None``.
    'alt' indicated the presence of the hash mark (#)
    """
    fill_char = None
    align = None
    sign = None
    alt = None
    zero = None
    width = None
    precision = None
    ctype = None

    spec_len = len(spec)

    # If the second char is an alignment token,
    # then parse the fill char
    if spec_len >=2 and spec[ 1 ] in '<>=^':
        fill_char = spec[ 0 ]
        align = spec[ 1 ]
        index = 2
    # Otherwise, parse the alignment token
    elif spec_len >= 1 and spec[ 0 ] in '<>=^':
        align = spec[ 0 ]
        index = 1
    else:
        index = 0

    # Parse the sign char
    if index < spec_len and spec[ index ] in ' +-':
        sign = spec[ index ]
        index += 1

    # The special case for '#' (only used for integers)
    if index < spec_len and spec[index] == '#':
        alt = True
        index += 1

    # The special case for 0-padding
    if index < spec_len and spec [ index ] == '0':
        zero = True
        #NOTE: strings treat this like a fill_char='0',
        #but ints treat this slightly differently, IF # is enabled.
        index += 1

    # Parse field width
    saveindex = index
    while index < spec_len and spec[index].isdigit():
        index += 1

    if index > saveindex:
        width = int(spec[saveindex : index])

    # Parse field precision
    if index < spec_len and spec[index] == '.':
        index += 1
        saveindex = index
        while index < spec_len and spec[index].isdigit():
            index += 1
        if index > saveindex:
            precision = int(spec[saveindex:index])

    # Finally, parse the type field
    if index < spec_len:
        if index < spec_len-1:
            raise InvalidFormatSpecError()
        ctype = spec[index]

    log.debug("_parse_std_spec(%r) => fill=%r align=%r sign=%r alt=%r zero=%r width=%r prec=%r type=%r",
        spec, fill_char, align, sign, alt, zero, width, precision, ctype)
    return fill_char, align, sign, alt, zero, width, precision, ctype

#---------------------------------------------------
#helpers for numeric formatting
#---------------------------------------------------

##if fpformat:
##    to_sci = fpformat.sci
##    to_fix = fpformat.fix
##else:
##    def to_sci(val,precision):
##        """Pure python implementation of the C printf 'e' format specificer"""
##        # Split into sign and magnitude (not really needed for formatting
##        # since we already did this part. Mainly here in case 'sci'
##        # ever gets split out as an independent function.)
##        sign = ''
##        if val < 0:
##            sign = '-'
##            val = -val
##
##        # Calculate the exponent
##        exp = int(floor(logarithm(val,10)))
##
##        # Normalize the value
##        val *= 10**-exp
##
##        # If the value is exactly an integer, then we don't want to
##        # print *any* decimal digits, regardless of precision
##        if val == floor(val):
##            val = int(val)
##        else:
##            # Otherwise, round it based on precision
##            val = round(val,precision)
##            # The rounding operation might have increased the
##            # number to where it is no longer normalized, if so
##            # then adjust the exponent.
##            if val >= 10.0:
##                exp += 1
##                val = val * 0.1
##
##        # Convert the exponent to a string using only str().
##        # The existing C printf always prints at least 2 digits.
##        esign = '+'
##        if exp < 0:
##            exp = -exp
##            esign = '-'
##        if exp < 10: exp = '0' + str(exp)
##        else: exp = str(exp)
##
##        # The final result
##        return sign + str(val) + 'e' + esign + exp
##
##    def to_fix(value, precision):
##        #FIXME: implement this!
##        return str(value)

#=========================================================
#template formatting
#=========================================================
class Formatter(object):
    """Formatter, taken directly from python 2.6.1.
    the only change is that the CPython hooks have been replaced
    by python code"""

    def format(self, format_string, *args, **kwargs):
        return self.vformat(format_string, args, kwargs)

    def vformat(self, format_string, args, kwargs):
        used_args = set()
        result = self._vformat(format_string, args, kwargs, used_args, 2)
        self.check_unused_args(used_args, args, kwargs)
        return result

    def _vformat(self, format_string, args, kwargs, used_args, recursion_depth):
        if not format_string: #accelerate the simple cases
            if isinstance(format_string, unicode):
                return u''
            else:
                return ''
        if recursion_depth <= 0:
            raise ValueError('Max string recursion exceeded')
        result = []
        for literal_text, field_name, format_spec, conversion in self.parse(format_string):

            # output the literal text
            if literal_text:
                result.append(literal_text)

            # if there's a field, output it
            if field_name is not None:
                # this is some markup, find the object and do
                #  the formatting

                # given the field_name, find the object it references
                #  and the argument it came from
                obj, arg_used = self.get_field(field_name, args, kwargs)
                used_args.add(arg_used)

                # do any conversion on the resulting object
                obj = self.convert_field(obj, conversion)

                # expand the format spec, if needed
                format_spec = self._vformat(format_spec, args, kwargs,
                                            used_args, recursion_depth-1)
                # format the object and append to the result
                text = self.format_field(obj, format_spec)
                if not isinstance(format_string, unicode) and isinstance(text, unicode):
                    text = str(text)
                result.append(text)

        return ''.join(result)

    def get_value(self, key, args, kwargs):
        if isinstance(key, (int, long)):
            return args[key]
        else:
            return kwargs[key]

    def check_unused_args(self, used_args, args, kwargs):
        pass

    def format_field(self, value, format_spec):
        return format(value, format_spec)

    def convert_field(self, value, conversion):
        # do any conversion on the resulting object
        if conversion == 'r':
            return repr(value)
        elif conversion == 's':
            return str(value)
        elif conversion is None:
            return value
        raise ValueError("Unknown converion specifier %s" % (conversion,))

    def parse(self, format_string):
        return _parse_template(format_string)

    def get_field(self, field_name, args, kwargs):
        first, rest = _parse_field_name(field_name)

        obj = self.get_value(first, args, kwargs)

        # loop through the rest of the field_name, doing
        #  getattr or getitem as needed
        if rest: #save us creating a empty iterable
            for is_attr, i in rest:
                if is_attr:
                    obj = getattr(obj, i)
                else:
                    obj = obj[i]

        return obj, first

#---------------------------------------------------
#pure-python replacement parsers
#---------------------------------------------------
def _parse_template(format_string):
    "parse template into chunks of (literal_text, field_name, format_spec, conversion)"
    buffer, render = _make_array_like(format_string)
    if isinstance(format_string, unicode):
        umap = unicode
    else:
        umap = lambda x: x
    state = 0
    depth = 0 #used by spec
    head = None
    field_name = None
    conversion = None
    format_spec = None
    for ch in format_string:
        #
        #text parsing states
        #
        if state == 0: #just reading text into buffer
            if ch == "{":
                state = 1
            elif ch == "}":
                state = 2
            else:
                buffer.append(ch)

        elif state == 1: #just saw a single "{"
            if ch == "{": #unescape the "{{"
                buffer.append(umap("{"))
                state = 0
            elif ch == "}": # "{}" isn't allowed
                raise FormatError, "empty field specifier in %r" % (format_string,)
            elif ch == "!":
                raise FormatError, "end of format while looking for conversion specifier"
            elif ch == ":":
                raise FormatError, "zero length field name in format"
            else: #assume we're looking at a field name
                head = render()
                del buffer[:]
                buffer.append(ch)
                state = 3

        elif state == 2: #just saw a single "}"
            if ch == "}": #unescape the "}}"
                buffer.append(umap("}"))
                state = 0
            else:
                raise FormatError, "unmatched closing brace in %r" % (format_string,)

        #
        #field parsing states
        #
        elif state == 3: #parsing field name, at least 1 char in buffer, head is set
            if ch == "}": #field is entirely over
                if depth == 0: #end field
                    yield head, render(), None, None
                    del buffer[:]
                    state = 0
                else: #end a nested {}
                    depth -= 1
                    buffer.append(ch)
            elif ch == "{": #start a nested {}
                depth += 1
                buffer.append(ch)
            elif ch == "!": #begin conversion section
                field_name = render()
                del buffer[:]
                state = 4
            elif ch == ":": #begin spec
                field_name = render()
                conversion = None #skipping this field
                del buffer[:]
                depth = 0
                state = 5
            else: #assume it's part of field name
                buffer.append(ch)

        elif state == 4: #parsing conversion section, head & field_name are set
            if ch == ":": #end conversion, begin spec
                conversion = render()
                del buffer[:]
                depth = 0
                state = 5
            elif ch == "}": #end field
                yield head, field_name, None, render()
                del buffer[:]
                state = 0
            else: #add a char
                buffer.append(ch)

        elif state == 5: #parsing spec, head & field_name & conversion are set
            if ch == "}":
                if depth == 0: #end field
                    yield head, field_name, render(), conversion
                    del buffer[:]
                    state = 0
                else: #end a nested {}
                    depth -= 1
                    buffer.append(ch)
            elif ch == "{": #start a nested {}
                depth += 1
                buffer.append(ch)
            else: #add a char
                buffer.append(ch)

    #end parser loop
    if state == 0: #general text
        head = render()
        if head:
            yield head, None, None, None
    elif state == 1: #"{"
        raise FormatError, "unmatched open brace at end of %r" % (format_string,)
    elif state == 2: #"}"
        raise FormatError, "unmatched close brace at end of %r" % (format_string,)
    else: #states 3-5
        raise FormatError, "unfinished field at end of %r" % (format_string,)

def _parse_field_name(field_name):
    "parse field name in head, (is_attr,value)*"
    offset = field_name.find(".") #look for ATTR
    if offset == -1:
        offset = field_name.find("[") #look for IDX
        if offset == -1: #neither were found, we have plain field name
            if field_name.isdigit():
                field_name = int(field_name)
            return field_name, []
    else: #found ATTR, check for closer IDX
        alt = field_name.find("[", 0, offset)
        if alt != -1:
            assert alt < offset
            offset = alt
    head = field_name[:offset]
    if head.isdigit():
        head = int(head)
    return head, _parse_field_tail(field_name, offset)

def _parse_field_tail(field_name, offset):
    "helper for _parse_field_name"
    state = 0
    buffer, render = _make_array_like(field_name)
    for ch in field_name[offset:]:
        if state == 0: #expecting either ATTR or IDX
            assert not buffer, "buffer should be empty"
            if ch == '.': #start parsing ATTR
                state = 1
            elif ch == '[': #start parsing IDX
                state = 2
            else:
                raise UnexpectedFieldChar(field_name, ch) #not sure how to get here
        elif state == 1: #parsing ATTR
            if ch == '.': #flush, start parsing new ATTR
                x = render()
                if not x:
                    raise EmptyFieldAttr()
                yield True, x
                del buffer[:]
            elif ch == '[': #flush, start parsing IDX
                x = render()
                if not x:
                    raise EmptyFieldAttr()
                yield True, x
                del buffer[:]
                state = 2
            else:
                buffer.append(ch)

        else: #parsing IDX
            if ch == ']': #flush, return to state 0
                text = render()
                if text.isdigit():
                    text = int(text)
                yield False, text
                del buffer[:]
                state = 0
            else:
                buffer.append(ch)
    if state == 0: #nothing to do
        assert not buffer, "buffer should be empty"
    elif state == 1: #flush last attr
        x = render()
        if not x:
            raise EmptyFieldAttr()
        yield True, x
    else:
        raise FormatError, "unmatched open bracket in field %r" % (field_name,)

def _make_array_like(source):
    "Use unicode array if the original string is unicode, else use string array"
    if isinstance(source, unicode):
        arr = array('u')
        return arr, arr.tounicode
    else:
        arr = array('c')
        return arr, arr.tostring

#=========================================================
#helper functions
#=========================================================
_formatter = Formatter() #the default formatter used by this module

#=========================================================
#eof
#=========================================================
