"""BPS (version 4) -- Big Package of Stuff -- (c) Assurance Technologies LLC 2003-2009

Requirements:
    BPS requires at least Python 2.5,
    but tries to be compatible with Python 2.6.
    Python 3.0 compatibility has not yet been explored.

    Some parts of BPS (namely :mod:`bps.host.windows`) relies
    on the ``win32all`` library under windows.

    Outside of that, there should be no external dependancies.

To import:
    pxhelpers.threads
    apf.exception_hook
"""

#----- BEGIN VERSION STAMP -----
__version__ = "4.8.1"
#----- END VERSION STAMP -----

#=========================================================
#imports
#=========================================================
#import first for monkeypatching purposes
import bps.logs

#core
from functools import partial
from warnings import warn

#pkg
from bps.fs import filepath
from bps.logs import log
from bps.meta import abstractmethod
from bps.types import BaseClass, Undef

#local
__all__ = [
    #classes & class constructors
    "BaseClass", "filepath",

    #functions
    "partial",

    #decorators
    "abstractmethod",

    #constants
    "Undef",

    #exceptions

    #logging
    "log",
    "warn",
    ]

#=========================================================
#EOF
#=========================================================
