"""bps.logs -- logging system extensions"""
#=========================================================
#imports
#=========================================================
#import for monkeypatching
import bps.logs.loggers
import bps.logs.capture

#config utilties
from bps.logs.config import setup_lib_logging, setup_std_logging, \
    config_logging, add_handler
##... parse_config

#logger utilities
from bps.logs.loggers import get_logger
##from bps.logs.loggers import is_logger, parse_level_name, get_level_name

#handler utilities
##from bps.logs.handlers import is_handler, purge_handlers, has_default_handler

#formatter utilities
##from bps.logs.formatters import is_formatter

#proxy logging object
from bps.logs.proxy_logger import log, multilog, classlog

#register ourselves as a library to quiet the log files
setup_lib_logging("bps")
setup_lib_logging("bps3")

#=========================================================
#
#=========================================================
__all__ = [
    #preset configuration
    'setup_lib_logging', 'setup_std_logging',

    #general configuration
    'config_logging',
    'add_handler',

    #logger proxies
    'log', 'multilog', 'classlog', 

    #utility functions
    'get_logger',
    #XXX: there are a LOT more utilities funcs, tucked away in the submodules,
    # should we import them all to this module?
]

#=========================================================
#eof
#=========================================================
