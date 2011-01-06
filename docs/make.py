"Makefile for Sphinx documentation, adapted to python"
import os, sys
doc_root = os.path.abspath(os.path.join(__file__,os.path.pardir))
source_root = os.path.abspath(os.path.join(doc_root,os.path.pardir))
sys.path.insert(0, source_root)

from bps.unstable.bpsdoc.make_helper import SphinxMaker
SphinxMaker.execute(root=__file__)
