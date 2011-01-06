Overview
========
Python's logging system offers two levels
of interaction when you want to configure the 
loggers: you can either interact with 
the low-level logger, handler, and formatter objects;
or you can hand it a filepath to a separate file
containing a monolithic configuration of the entire
system.

The :mod:`bps.logs` package attempts to fill in the
programmatic "middle ground" between these two
styles, through it's :func:`parse_config`
and :func:`config_logging` functions.
Take a large number of input styles,
included external files or strings
containing a full configuration file,
or fragments, all of which are normalized
into a standard dictionary-based data structure.
This may then be manipuled programmatically, re-normalized,
or passed on to the the configuration function,
allowing for complex configuration needs
to be accomplished with a few short commands.

Normalized Configuration Structure
==================================
The data structure which BPS uses
to represent a set of changes to be applied
to the logging system's configuration is a dictionary
which contains certain predefined keys (none are required unless otherwise noted).
The value attached to each key has a "normalized" format,
which will be the format it is in as returned by :func:`parse_config`,
but there are also other "input" formats, which will be accepted
by :func`parse_config` and returned normalized.
The following keys are recognized:
            
        ``"levels"``
            If present, this should be a dictionary whose keys
            are the names of logger objects, and the corresponding
            values the level that logger should be set to. 
            
        formatters
            [Optional]
            This should be a dictionary mapping formatter names to dicts of formatter options,
            to be passed to compile_formatter(). The names may be referred to by the handlers.
        handlers
            [Optional]
            This should be a dictionary mapping handlers names to dicts of handlers options,
            to be passed to compile_handler(). The names may be referred to be the output section.
        outputs
            [Optional]
            This should be a dictionary mapping loggers to lists of handler names,
            as specified in the handler section, or in the default handler presets.

The following keywords are accepted by :func:`parse_config`,
and will be merged into one of the above keys during normalization:

        ``"level"``
            This keyword specifies the logging level used by the root logger.
            This is a shortcut allowing the master level to be set quickly,
            without needing to create a dictionary.
            
            It will be used as the default value for the "<root>" key
            inside the "levels" dictionary (above).

        ``"default_handler"``
            This is a shortcut which allows you to specify just a keywords
            for creating a handler, but which will result in all the commands
            needed to create the handler and attach it as the sole output
            for the root logger. For example, setting ``default_handler=opts``
            will result in the following normalized options: 
            ``output="<root>=default only", handlers=dict(default=opts)``.

