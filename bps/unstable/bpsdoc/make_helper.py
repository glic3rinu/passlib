"""helper for quick cross-platform makefile for sphinx

TODO: this was hacked up really quickly, could use a facelift.
"""
#===============================================================
#imports
#===============================================================
import os,sys
from bps import *
from string import Template
import subprocess
def sub(fmt, **kwds):
	if not kwds:
			kwds = globals()
	return Template(fmt).substitute(**kwds)
__all__ = [
    "SphinxMaker",
]
#===============================================================
#main class
#===============================================================
class SphinxMaker(BaseClass):
    #===============================================================
    #class attrs
    #===============================================================
    # You can subclass these variables
    #TODO: cmd line override support
    SPHINXOPTS    = []
    SPHINXBUILD   = "sphinx-build"
    PAPER         = "letter"

    # Paths
    BUILD = "_build"
    STATIC = "_static"

    #internal opts
    PAPEROPT_a4     = ["-D","latex_paper_size=a4"]
    PAPEROPT_letter = ["-D","latex_paper_size=letter"]
    #===============================================================
    #instance attrs
    #===============================================================
    root_dir = None
    conf_file = None
    conf = None

    #===============================================================
    #frontend
    #===============================================================
    def __init__(self, root=None):
        if root is None:
            root = sys.modules[self.__class__.__module__]
        self.root_dir = filepath(root).abspath.dir
        self.conf_file = self.root_dir / "conf.py"
        if self.conf_file.ismissing:
            raise RuntimeError, "conf file not found in root: %r" % (self.root_dir)
        #XXX: load conf file?

        self.BUILD = filepath(self.BUILD)
        self.STATIC = filepath(self.STATIC)

    @classmethod
    def execute(cls, args=None, **kwds):
        return cls(**kwds).run(args)

    def run(self, args=None):
        if args is None:
            args = sys.argv[1:]
        self.root_dir.chdir() #due to relative paths like self.BUILD
        for arg in args:
            getattr(self,"target_"+arg)()

    #===============================================================
    #targets
    #===============================================================
    def target_help(self):
        print "Please use \`make <target>' where <target> is one of"
        print "  clean     remove all compiled files"
        print "  html      to make standalone HTML files"
        print "  http      to serve standalone HTML files on port 8000"
#        print "  pickle    to make pickle files"
#        print "  json      to make JSON files"
        print "  htmlhelp  to make HTML files and a HTML help project"
#        print "  latex     to make LaTeX files, you can set PAPER=a4 or PAPER=letter"
#        print "  changes   to make an overview over all changed/added/deprecated items"
#        print "  linkcheck to check all external links for integrity"

    def target_clean(self):
        BUILD = self.BUILD
        if BUILD.exists:
            BUILD.clear()

    def target_html(self):
        #just in case htmldev was run
        (self.BUILD / "html" / "_static" / "default.css").discard()
        self.build("html")

    def target_htmlhelp(self):
        self.build("htmlhelp")

    def target_http(self):
        self.target_html()
        path = self.BUILD.canonpath / "html"
        path.chdir()
        port = 8000
        print "Serving files from %r on port %r" % (path, port)
        import SimpleHTTPServer as s
        s.BaseHTTPServer.HTTPServer(('',port), s.SimpleHTTPRequestHandler).serve_forever()

    ##def target_latex(self):
    ##    build("latex")
    ##    print "Run \`make all-pdf' or \`make all-ps' in that directory to" \
    ##        "run these through (pdf)latex."
    ##
    ##def target_pdf():
    ##    assert os.name == "posix", "pdf build support not automated for your os"
    ##    build("latex")
    ##    target = BUILD / "latex"
    ##    target.chdir()
    ##    subprocess.call(['make', 'all-pdf'])
    ##    print "pdf built"

    #===============================================================
    #helpers
    #===============================================================
    def build(self, name):
        BUILD = self.BUILD
        ALLSPHINXOPTS = self.get_sphinx_opts()
        dt = BUILD / "doctrees"; dt.ensuredirs()
        target = BUILD/ name; target.ensuredirs()
        rc = subprocess.call([self.SPHINXBUILD, "-b", name] + ALLSPHINXOPTS + [ target ])
        if rc:
            print "Sphinx-Build returned error, exiting."
            sys.exit(rc)
        print "Build finished. The %s pages are in %r." % (name, target,)
        return target

    def get_paper_opts(self):
        return getattr(self,"PAPER_" + self.PAPER, [])

    def get_sphinx_opts(self):
        return ["-d", self.BUILD / "doctrees"] + self.get_paper_opts() + self.SPHINXOPTS + [ "." ]

    #===============================================================
    #eoc
    #===============================================================

#===============================================================
#eof
#===============================================================
