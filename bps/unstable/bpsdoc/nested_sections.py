"""
This extension should be used in conjunction with autodoc.
It permits docstrings to have embedded rst section headers,
by translating them into indented paragraphs with
italicized section headers.

TODO: make this more flexible and less hackneyed
"""
from bps.develop import dbgcon
import re
from bps import *

def indent_sections(lines, reference_prefix=''):
    "replaces any section headers with indented paragraphs"
    end = len(lines)-1
    out = []

    sections = []
    indent_char = ' ' * 4
    indent_level = 0
    SCHARS = '#*=-^"'
    def get_level(c):
        return SCHARS.index(c)
    #FIXME: this doesn't detect double-barred sections
    def detect_section(idx):
        if idx == end:
            return None
        line = lines[idx].rstrip()
        if not line or line.lstrip() != line:
            return None
        next = lines[idx+1].rstrip()
        if next.lstrip() != next:
            return None
        for c in SCHARS:
            if next.startswith(c * len(line)):
                return c
        return None
    idx = 0
    while idx <= end:
        line = lines[idx].rstrip()
        if not line:
            out.append("")
            idx += 1
            continue
        new_char = detect_section(idx)
        if new_char:
            new_level = get_level(new_char)
            while sections and sections[-1] > new_level:
                sections.pop()
            if not sections or sections[-1] < new_level:
                sections.append(new_level)
            name = line.lower().strip().replace(" ", "-").replace("--", "-")
            indent = indent_char * (indent_level-1)
            #TODO: would be nice to add a special directive instead of **%s**,
            # so that we could render appropriate html styling to the section header
            out.extend([
                indent + ".. _%s:" % (reference_prefix + name),
                "",
                indent + "**%s**\n" % line.rstrip(),
                ])
            idx += 2 #skip section header
            indent_level = max(0, len(sections))
            continue
        indent = indent_char * indent_level
        out.append(indent + line)
        idx += 1
    return out

def _remove_oneline(name, lines):
    #remove one-line description from top of module, if present,
    #cause we don't want it being duplicated (should already be listed in module's header)
    _title_re = re.compile(r"""
        ^ \s*
        ( {0} \s* -- \s* )?
        [a-z0-9 _."']*
        $
    """.format(re.escape(name)), re.X|re.I)
    if len(lines) > 1 and _title_re.match(lines[0]) and lines[1].strip() == '':
        del lines[:2]

def mangle_docstrings(app, what, name, obj, options, lines):
    if what == 'module':
        _remove_oneline(name, lines)
    elif what in ('class', 'exception', 'function', 'method'):
        name = "%s.%s" % (obj.__module__, obj.__name__)
        name = name.replace(".", "-").lower()
        lines[:] = indent_sections(lines, reference_prefix=name + "-")
    elif what in ('attribute',):
        pass
    else:
        print "unknown what: %r %r" % (what, obj)
        dbgcon()

def setup(app):
    app.connect('autodoc-process-docstring', mangle_docstrings)
