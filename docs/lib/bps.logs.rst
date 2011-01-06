=====================================
:mod:`bps.logs` -- Logging Utilities
=====================================

.. module:: bps.logs
    :synopsis: logging utilities

This module provides a number of extensions to the standard python logging module.
Features include:

    * `setup_std_logging`: a replacement for ``basicConfig()`` for initializing the logging system,
      This features many additional features, such as improved default heuristics,
      the ability to capture stdout, stderr, and python warnings and rerouting them
      through the logging system, etc.
    * `config_logging`: a replacement for ``fileConfig()`` which supports a more compact file format.
    * `FancyFormatter`: a formatter which supports numerous formatting options
    * `log`: a intelligent proxy Logger, which uses module inspection to determine which logger it should invoke

General usage:

    Call setupLogging() to initialize logging system,
    and/or call configLogging(path) to load configuration from a file.
    Most of the components (log, the formatters, etc) are designed
    to be used individually, they don't require use of any of the other
    bps3.logs components.

.. toctree::

    bps.logs-config_format

.. todo::

    document this module

