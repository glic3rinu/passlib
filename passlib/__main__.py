"""passlib.__main__ -- command line helper tool

this is a work in progress. it has significant functionality,
but many border cases are lacking.

todo
====
* for all commands, add support for dot-separated handler names
  to be interpreted as external handler object to import.

* add 'guess' support to verify()

* potential additional commands:
    - gencfg_cmd - generate config w/ timings, possibly taking in another
    - chkcfg_cmd - check config file for errors.
    - should add 'selftest' command as well

* unittests for all the commands (and internals)

* expand examine module into the unittests (probably should wait
  until merged back into default).

* instead of 'help' handler giving alg list, should make it a separate option,
  so it doesn't suprise users.

* support for raw salts to be provided to encrypt

* benchmark should support testing multiple variants (e.g. FSHP, SCRAM)
"""
#=========================================================
#imports
#=========================================================
from __future__ import division
# core
from optparse import OptionParser
import re
import sys
# package
from passlib import __version__
from passlib.exc import MissingBackendError
from passlib.utils.compat import print_, iteritems, imap, exc_err
import passlib.utils._examine as examine
import passlib.utils.handlers as uh

vstr = "Passlib " + __version__

#=========================================================
# general support funcs
#=========================================================
def maxlen(source):
    return max(len(elem) for elem in source)

#=========================================================
# encrypt & verify commands
#=========================================================
def _print_algorithms():
    "print list of available algorithms for encrypt & verify"
    print_("Hash algorithms currently supported by encrypt/verify:\n"
           "------------------------------------------------------")
    names = examine.registered_handlers(disabled=False)
    fmt = "%-" + str(3+maxlen(names)) + "s %s"
    for name in names:
        text = examine.description(name) or '<no description>'
        extra = []
        if examine.has_user(name):
            if examine.is_user_optional(name):
                extra.append("supports --user")
            else:
                extra.append("requires --user")
        if examine.is_variable(name):
            extra.append("supports --rounds")
        if extra:
            text = "%s (%s)" % (text, ", ".join(extra))
        print_(fmt % (name, text))

def encrypt_cmd(args):
    """encrypt password using specific format"""
    # FIXME: this should read password from file / stdin
    # XXX: ask for user on cmdline?

    #
    # parse args
    #
    p = OptionParser(prog="passlib encrypt", version=vstr,
                     usage="%prog [options] <method> [<password>]",
                     description="This subcommand will hash the specified password, "
                                 "using the specified hashing method, and output a single line containing the result.",
                     epilog="Specify the method 'help' to get a list of available methods")
    p.add_option("-u", "--user", dest="user", default=None,
                 help="specify username for algorithms which require it",
                 )
    p.add_option("-s", "--salt", dest="salt", default=None,
                 help="specify fixed salt string",
                 )
    p.add_option("-z", "--salt-size", dest="salt_size", default=None, type="int",
                 metavar="NUM",
                 help="specify size of generated salt",
                 )
    p.add_option("-r", "--rounds", dest="rounds", default=None, type="int",
                 metavar="NUM",
                 help="specify rounds/cost parameter for variable-cost algorithms",
                 )
    p.add_option("-i", "--ident", dest="ident", default=None,
                 help="specify identifier or subformat for certain algorithms",
                 )

    #
    # handle positional args
    #
    opts, args = p.parse_args(args)
    if not args:
        p.error("no method specified")
    method = args.pop(0)
    if method == "help":
        _print_algorithms()
        return 0
    if args:
        password = args.pop(0)
    else:
        password = None
    if args:
        p.error("Unexpected positional arguments")

    #
    # validate & assemble options
    #
    if not method:
        p.error("No method provided")
    handler = examine.get_crypt_handler(method)
    kwds = {}
    if examine.has_user(handler):
        if opts.user:
            kwds['user'] = opts.user
        elif not examine.is_user_optional(handler):
            print_("error: %s requires a --user" % method)
            return 1
    if opts.rounds is not None and examine.is_variable(handler):
        kwds['rounds'] = int(opts.rounds)
    if opts.salt and examine.has_salt(handler):
        kwds['salt'] = opts.salt
    if opts.salt_size and examine.has_salt_size(handler):
        kwds['salt_size'] = int(opts.salt_size)
    if opts.ident and examine.has_many_idents(handler):
        kwds['ident'] = opts.ident

    #
    # read password
    #
    if password is None:
        import getpass
        password = getpass.getpass("Password: ")

    #
    # create hash, and done
    #
    print_(handler.encrypt(password, **kwds))
    return 0

def verify_cmd(args):
    """verify password using specific format"""
    # FIXME: this should read password from file / stdin

    #
    # parse args
    #
    p = OptionParser(prog="passlib verify", version=vstr,
                     usage="%prog [options] <method> <hash> [<password>]",
                     description="This subcommand will attempt to verify the hash against the specified password,"
                                 "using the specified hashing method, and output success or failure.",
                     epilog="The <method> may be a comma-separated list, 'help', or 'guess', in the latter case"
                            "multiple methods will be tried, to see if any succeed")
    p.add_option("-u", "--user", dest="user", default=None,
                 help="specify username for algorithms which require it",
                 )

    #
    # handle positional args
    #
    opts, args = p.parse_args(args)
    if not args:
        p.error("no method specified")
    method = args.pop(0)
    if method == "help":
        _print_algorithms()
        return 0
    if not args:
        p.error("no hash specified")
    hash = args.pop(0)
    if args:
        password = args.pop(0)
    else:
        password = None
    if args:
        p.error("Unexpected positional arguments")

    #
    # validate & assemble options
    #
    if not method:
        p.error("No method provided")
    # TODO: support multiple methods, and 'guess'
    handler = examine.get_crypt_handler(method)
    kwds = {}
    if examine.has_user(handler):
        if opts.user:
            kwds['user'] = opts.user
        elif not examine.is_user_optional(handler):
            print_("error: %s requires a --user" % method)
            return 1

    #
    # read password
    #
    if password is None:
        import getpass
        password = getpass.getpass("Password: ")
        print_("")

    #
    # create hash, and done
    #
    result = handler.verify(password, hash, **kwds)
    if result:
        print_("password VERIFIED successfully.")
        return 0
    else:
        print_("password FAILED to verify.")
        return 1

#=========================================================
# identify command
#=========================================================
def identify_cmd(args):
    """attempt to identify format of unknown password hashes.
    this is just a wrapper for the more python-friendly fuzzy_identify()
    """
    from passlib.utils._identify import fuzzy_identify_hash, identify_hash_format

    #
    # parse args
    #
    p = OptionParser(prog="passlib identify", version=vstr,
                     usage="%prog [options] <hash>")
    ##p.add_option("-d", "--details", action="store_true", dest="details",
    ##             default=False, help="show details about referenced hashes")
    p.add_option("--csv", action="store_true", dest="csv", default=False,
                 help="output results in csv format")

    opts, args = p.parse_args(args)
    if not args:
        p.error("No hash provided for identification")
    candidate = args.pop(0)
    if args:
        p.error("Unexpected positional arguments")

    #
    # identify hash
    #
    results = fuzzy_identify(candidate)

    #
    # display results
    #
    if opts.csv:
        import csv
        writer = csv.writer(sys.stdout)
        writer.writerow(("name", "category", "score", "description"))
        for name, cat, score in results:
            row = (name, cat, score)
            description = examine.description(name)
            if description:
                row += (description,)
            writer.writerow(row)
    elif results:
        cat_aliases = dict(config="config-string", malformed="malformed-hash")
        def pl(cond, p, s=""):
            return p if cond else s
        best = results[0][2]
        multi = len(results) > 1
        accurate = (best>50)
        if best == 100 and not multi:
            print_("Input identified:")
        else:
            print_("Input is " + pl(accurate, "likely", "possibly") +
                   pl(multi, " one of the following") + ":")
        for name, cat, score in results:
            if accurate and score < 50:
                print_("\nLess likely alternatives include:")
                accurate = False
            txt = name
            if cat != "hash":
                txt += " " + cat_aliases.get(cat,cat)
            txt += " (score=%s)" % score
            description = examine.description(name) or ""
            if description:
                description = " %s" % description
            print "  %-40s %s" % (txt, description)
    else:
        print_("Input could not be identified by Passlib.")
        best = 0

    # inform user about general class of hash if the guesses were poor.
    if not opts.csv and best < 25:
        fmt, ident = identify_hash_format(hash)
        if fmt == "mcf":
            print_("\nDue to the %r prefix, "
                   "input is possibly an unknown/unsupported "
                   "hash using Modular Crypt Format." % (ident,))

        elif fmt == "ldap":
            print_("\nDue to the %r prefix, "
                   "input is possibly an unknown/unsupported "
                   "hash using an LDAP-style hash format." % (ident,))

    return 0 if results else 1

#=========================================================
# benchmark command
#=========================================================
def benchmark_cmd(args):
    """benchmark speed of hash algorithms.
    this is mainly a wrapper for the benchmark() function.
    """
    # TODO: support way to list preset filters.

    #
    # parse args
    #
    p = OptionParser(prog="passlib benchmark", version=vstr,
                     usage="%prog [options] [all | variable | <alg> ... ]",
                     description="""\
This command runs a speed test of one or more password hashing algorithms.
You should provide the names of one or more algorithms to benchmark, as
positional arguments. If you provide the special name "all", all algorithms
in Passlib will be tested. If you provide the special name "variable",
all variable-cost algorithms will be tested.""",
                     )
    p.add_option("-b", "--backend-filter", action="store", default="installed",
                 dest="backend_filter",
                 help="only list specific backends (possible values are: "
                      "'all', 'default', 'installed', 'fastest';"
                      " default is '%default')")
    p.add_option("-t", "--target-time", action="store", type="float",
                 dest="target_time", default=.25, metavar="SECONDS",
                 help="display cost setting required for verify()"
                      " to take specified time (default=%default)",
                )
    p.add_option("-x", "--measure-time", action="store", type="float",
                 dest="measure_time", default=2.0, metavar="SECONDS",
                 help="spend at most SECONDS benchmarking each hash (default=%default)",
                )
    p.add_option("--csv", action="store_true",
                 dest="csv", default=False,
                 help="Output results in CSV format")
    p.add_option("--speed-scale", action="store", type="float",
                 dest="speed_scale", default=1.0,
                 help="scale results based on external factor, e.g. cpu speed")
    p.add_option("--password-size", action="store",
                 dest="password_size", default="10/2", metavar="SIZE",
                 help="size of password to test (default=%default)",
                )
    ##p.add_option("--with-default", action="store_true", dest="with_default",
    ##             default=False, help="Include default cost in listing")

    opts, args = p.parse_args(args)

    opts.exact = True # XXX: add pretty_estimate flag?

    # normalize password size
    if isinstance(opts.password_size, str):
        if '/' in opts.password_size:
            mu, sigma = opts.password_size.split("/")
            opts.password_size = int(mu), int(sigma)
        else:
            opts.password_size = int(opts.password_size)

    # prepare formatters
    if opts.csv:
        fmt = "%s,%s,%s,%s,%s,%s"
        print_(fmt % ("handler", "backend", "speed", "costscale", "targetcost",
                      "curdefault"))
        null = ""
    else:
        fmt = "%-30s %-10s %10s %10s %10s"
        print_(fmt % ("handler", "speed", "costscale", "targetcost", "curdefault"))
        print_(fmt % ("-" * 30, "-" * 10, "-" * 10, "-" * 10, "-" * 10))
        null = "-"

    from passlib.utils._cost import benchmark, BenchmarkError
    try:
        for timer in benchmark(schemes=args or None,
                               max_time=opts.measure_time,
                               backend_filter=opts.backend_filter,
                               password_size=opts.password_size,
                               ):
            name = timer.handler.name
            backend = timer.backend
            scale = timer.scale if timer.hasrounds else "fixed"
            spd = cost = curdef = null
            if timer.speed is not None:
                timer.speed *= opts.speed_scale
                spd = ("%g" if timer.speed < 10 else "%d") % (timer.speed,)
                if timer.hasrounds:
                    if opts.exact:
                        cost = timer.estimate(opts.target_time)
                    else:
                        cost = timer.pretty_estimate(opts.target_time)
                    if examine.avoid_even_rounds(timer.handler):
                        cost |= 1
                    curdef = timer.handler.default_rounds
            if opts.csv:
                print_(fmt % (name, backend or '', spd, scale, cost, curdef))
            else:
                tag = "%s (%s)" % (name, backend) if backend else name
                print_(fmt % (tag, spd, scale, cost, curdef))
    except BenchmarkError:
        print_("\nerror: %s" % exc_err())
        return 1
    return 0

#=========================================================
# main
#=========================================================
commands = {
    "identify": identify_cmd,
    "encrypt": encrypt_cmd,
    "verify": verify_cmd,
    "benchmark": benchmark_cmd,
}

def _print_avail():
    print_("Available commands:")
    for name, func in sorted(iteritems(commands)):
        doc = getattr(func, "__doc__", None)
        doc = doc.splitlines()[0] if doc else ""
        print_(" %-10s %s" % (name, doc))

def _print_usage():
    from passlib import __version__ as vstr
    print_("Passlib %s Command Line Helper\n"
           "Usage: python -m passlib <command> [options|--help]\n" % (vstr,))
    _print_avail()

def main(args):
    if not args:
        _print_usage()
        return 1
    cmd = args[0]
    if cmd in ["help", "-h", "--help"]:
        _print_usage()
        return 0
    elif cmd in ["version", "--version", "-v"]:
        print_(vstr)
        return 0
    func = commands.get(cmd)
    if not func:
        print_("Unknown command: %s\n" % (cmd,))
        _print_avail()
        return 1
    try:
        return func(args[1:])
    except SystemExit, KeyboardInterrupt:
        raise
    except:
        print_("\n\nAn internal error has occurred:\n"
                   "-------------------------------")
        sys.__excepthook__(*sys.exc_info())
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))

#=========================================================
# eof
#=========================================================
