=======================
BPS Logging File Format
=======================

The BPS Logging Format is an alternate ini-based file format
for configuring python's builtin logging system. Both this format
and the stdlib format are accepted (and auto-detected) by :func:`bps3.logs.config_logging`.

.. warning::

    This documentation currently assumes you are familiar with
    the python logging package, it's standard format,
    and it's object system. There may eventually be a rewrite to
    correct this.

Why another format?
===================
Python's builtin logging system specifies a format for configuring the logging
system [#stdfmt]_. While this format offers the ability to configure every
aspect of the logging system, the manner in which it does this is somewhat
verbose, makes some simple tasks much more time consuming than they need to be,
and deciphering an existing config file is not the trivial task it should be.

A prime example of this issue is configuring the logging levels of a number
of loggers at once.  Under the stdlib logging format, you would need to do
the following:

.. code-block:: cfg

    [loggers]
    keys=root,app,app.model,mylib

    [logger_root]
    level = WARNING

    [logger_app]
    level = DEBUG

    [logger_app.model]
    level = INFO

    [logger_mylib]
    level = DEBUG

For doing development work, where various loggers may need to be added and
removed frequently, this format becomes incredibly cumbersome. This
was the main motivation for creating a new format. Under the BPS Logging Format,
the equivalent commands to acheive the above would be:

.. code-block:: cfg

    [logging:levels]
    <root> = WARNING
    app = DEBUG
    app.model = INFO
    mylib = DEBUG

While a couple of rare features of the stdlib format have not been replicated
in the new format, work is ongoing, and the majority of the features have been
converted over into what is hoped to be a more consise, understandable, and
easily editable format.

Format Overview
===============
The BPS Logging Format is based around the ConfigParser's file format.
It defines the following section names, all of which begin with the prefix
``logging:``, and sections lacking this prefix will be ignored.
None of the following sections are required, except where interdepedant
references exist. The sections are as follows:

    `logging:levels`_
        This section lets you configure the logging levels for any logger
        in the logging system.

    `logging:options`_
        This section lets you set various global logging system options,
        including some custom extensions provided by BPS.

    `logging:output`_
        This section maps loggers to handlers,
        allowing you to control where the output of the logging system
        is going.

    `logging:handler:$NAME`_
        Sections of this type (eg `logging:handler:myhandler`) define
        the configuration to be used when a handler name is referenced
        in the `logging:output`_ section.

    `logging:formatter:$NAME`_
        Sections of this type (eg `logging:formatter:myformatter`) define
        the configuration to be used when a formatter name is referenced
        in a `logging:handler:* <logging:handler:$NAME>`_ section.

logging:levels
--------------
This section lets you configure the logging levels for any logger
in the logging system.

The keys in this section correspond to logger names,
and the values to a predefined logging level. This logging level can
be a predefined name (eg ``NOTSET``, ``DEBUG``, etc), or an integer value ( ``0``, ``10``, etc).
Spaces in the logging level will be ignored, as will any text following a ``#`` symbol,
allowing in-line comments.

The logger name of ``<root>`` is interpreted as a convenient alias for the empty string,
which corresponds to the root logger of python's logging system. All other logger names
which start with ``<``, contain a series of letters, and end with ``>``,
are considered reserved by this format, for use in an grouping/alias system which is still under development.

A very verbose example of the ``logging:levels`` section, showing off the various options:

.. code-block:: cfg

    [logging:levels]

    #this is an example of a full-line comment

    #this will set the root logger level
    <root> = WARNING

    app = DEBUG #this is an example of a in-line comment

    #note that "#WARNING" below will be ignored
    app.model = INFO #WARNING

    #this uses an integer level
    mylib = 10

A more compact example, without all the comments:

.. code-block:: cfg

    [logging:levels]
    <root> = WARNING
    app = DEBUG
    app.model = INFO
    mylib = 10

.. note::
    If a undefined textual logging level is specified,
    a :exc:`KeyError` will be raised at the time this file is loaded.

logging:options
---------------

This section controls for the python logging system.
The following keys are currently recognized (unrecognized
keys will be ignored):

    ``capture_stdout``
        This is a boolean keyword. If set to ``true``,
        standard output will be captured, and re-routed to
        a logger object named ``sys.stdout``.
        If set to ``false``, and stdout is currently being
        captured by BPS, the capturing of stdou will be stopped.

        See :mod:`bps3.log.capture` for details.

    ``capture_stderr``
        This functions identically to ``capture_stdout``,
        except that it operates on standard error.

    ``capture_warnings``
        This functions similarly to ``capture_stdout``,
        except that it captures the warning issued by the
        python :mod:`warning` module, and sends such messages
        to the logger appropriate for the module which issued
        the warning.

        *Setting this option is HIGHLY recommended*, as it will
        integrate the warnings module into the logging system
        (how python should have had it to begin with).

    ``warning_fmt``
        When used with ``capture_warnings``, this option
        allows you to specify a custom warning format string.
        See :func:`capture_warnings` for details about the format
        of this string, which correponds to the ``fmt`` keyword.

    ``warning_target``
        When used with ``capture_warnings``, this options
        allows you to specify a custom target for any warnings
        sent to the logging system.
        See :func:`capture_warnings` for details about the format
        of this string, which correponds to the ``target`` keyword.

As an example, the following configuration snippet captures
everything from stdout and warnings, and leaves stderr alone:

.. code-block:: cfg

    [logging:options]
    capture_warnings = true
    #if no warning_fmt is specified, the default will be used:
    #warning_fmt = %(category)s:\n\t message: %(message)s\n\tfilename: %(filename)s\n\t  lineno: %(lineno)s

    capture_stderr = true

    #uncomment this next to explicitly release stdout
    #capture_stdout = false

logging:output
--------------
This section maps loggers to handlers,  allowing you to control where the output of the logging system
is going. It consists of "name = handler1, handler2, ..." entries,
which have the effect of attaching (one or more) handlers to the named logger.
If a given entry ends with ``" only"``, any existing handlers attached to the logger
will be removed before adding the specified handlers, and messages
will not propagate past this logger.

.. todo::
    give examples

logging:handler:$NAME
---------------------
If a handler is specified by name in `logging:output`_,
the configuration loader will look for a section with
the corresponding name to determine the handler's class
and configuration. If a handler entry is present,
but not referenced by the `logging:output`_ section
of the that file, it will be ignored.

It consists of keyword arguments passed to the
:func:`compile_handler` function, which has pretty much
the same syntax as the `fileConfig` format.

.. todo::
    document keywords, give examples

logging:formatter:$NAME
-----------------------
This section configures a named formatter,
and must be present for all formatters
referenced in a ``[logging:handler:$NAME]`` section.
It consists of keyword arguments passed to the
`create_formatter` function, which has pretty much
the same syntax as the `fileConfig` format.


Example Files
=============

An example of a full-featured logging config file,
which is probably overkill for a typical application:

.. code-block:: cfg

    [logging:options]
    capture_stdout = false
    capture_warnings = true
    warning_fmt = %(category)s: %(message)s

    [logging:levels]
    <root> = INFO
    myapp = DEBUG
    pylons = WARNING

    [logging:output]
    <root> = console
    myapp = syslog

    [logging:handler:console]
    class = StreamHandler
    args = (sys.stderr,)
    level = NOTSET
    formatter = generic
    startup_msg = True

    [logging:handler:syslog]
    class=handlers.SysLogHandler
    level=ERROR
    formatter=generic
    args=(('localhost', handlers.SYSLOG_UDP_PORT), handlers.SysLogHandler.LOG_USER)

    [logging:formatter:generic]
    format = %(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s
    datefmt = %H:%M:%S

=============

.. rubric:: Footnotes

.. [#stdfmt] `<http://docs.python.org/library/logging.html#configuration-file-format>`_
