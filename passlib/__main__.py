"""passlib.__main__ -- command line helper tool"""
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
from passlib.registry import list_crypt_handlers, get_crypt_handler
from passlib.utils.compat import print_, iteritems, imap, exc_err
import passlib.utils._examine as examine
import passlib.utils.handlers as uh

vstr = "Passlib " + __version__

#=========================================================
# encrypt & verify commands
#=========================================================

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
    elif method == "help":
        print_("available hash algorithms:\n"
               "--------------------------")
        for name in list_crypt_handlers():
            print_(name)
        return 0
    handler = get_crypt_handler(method)
    kwds = {}
    if examine.has_user(handler):
        if opts.user:
            kwds['user'] = opts.user
        elif not examine.has_optional_user(handler):
            print_("error: %s requires a --user" % method)
            return 1
    if examine.is_variable(handler):
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
                     epilog="The <method> may be a comma-separated list, or 'guess', in which case"
                            "multi methods will be tries, to see if any suceed")
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
    elif method == "help":
        print_("available hash algorithms:\n"
               "--------------------------")
        for name in list_crypt_handlers():
            print_(name)
        return 0
    # TODO: support multiple methods, and 'guess'
    handler = get_crypt_handler(method)
    kwds = {}
    if examine.has_user(handler):
        if opts.user:
            kwds['user'] = opts.user
        elif not examine.has_optional_user(handler):
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

# some handlers lack fixed identifier, and may match against hashes
# that aren't their own; this is used to rate those as less likely.
_handler_weights = dict(
    des_crypt=90,
    bigcrypt=25,
    crypt16=25,
)

# list of known character ranges
_char_ranges = [
    uh.LOWER_HEX_CHARS,
    uh.UPPER_HEX_CHARS,
    uh.HEX_CHARS,
    uh.HASH64_CHARS,
    uh.BASE64_CHARS,
]

def _identify_char_range(source):
    "identify if source string uses known character range"
    source = set(source)
    for cr in _char_ranges:
        if source.issubset(cr):
            return cr
    return None

def _identify_helper(hash, handler):
    """try to interpret hash as belonging to handler, report results
    :arg hash: hash string to check
    :arg handler: handler to check against
    :returns:
        ``(category, score)``, where category is one of:

        * ``"hash"`` -- if parsed correctly as hash string
        * ``"salt"`` -- if parsed correctly as salt / configuration string
        * ``"malformed"`` -- if identified, but couldn't be parsed
        * ``None`` -- no match whatsoever
    """
    # fix odds of identifying malformed vs other hash
    malformed = 75

    # check if handler identifies hash
    if not handler.identify(hash):
        # last-minute check to see if it *might* be one,
        # but identify() method was too strict.
        if isinstance(hash, bytes):
            hash = hash.decode("utf-8")
        if any(hash.startswith(ident) for ident in
               examine.iter_ident_values(handler)):
            return "malformed", malformed
        return None, 0

    # apply hash-specific fuzz checks (if any).
    # currently only used by cisco_type7
    fid = getattr(handler, "_fuzzy_identify", None)
    if fid:
        score = fid(hash)
        assert 0 <= score <= 100
        if score == 0:
            return None, 0
    else:
        score = 100

    # first try to parse the hash using GenericHandler.from_string(),
    # since that's cheaper than always calling verify()
    if hasattr(handler, "from_string"):
        try:
            hobj = handler.from_string(hash)
        except ValueError:
            return "malformed", malformed
        checksum = hobj.checksum

        # detect salts
        if checksum is None:
            return "config", score

        # if checksum contains suspiciously fewer chars than it should
        # (e.g. is strictly hex, but should be h64), weaken score.
        # uc>1 is there so we skip 'fake' checksums that are all one char.
        uc = len(set(checksum))
        chars = getattr(handler, "checksum_chars", None)
        if isinstance(checksum, unicode) and uc > 1 and chars:
            cr = _identify_char_range(checksum)
            hr = _identify_char_range(chars)
            if (cr in [uh.LOWER_HEX_CHARS, uh.UPPER_HEX_CHARS] and
                    hr in [uh.HASH64_CHARS, uh.BASE64_CHARS]):
                # *really* unlikely this belongs to handler.
                return None, 0
        return "hash", score

    # as fallback, try to run hash through verify & genhash and see
    # if any errors are thrown.
    else:

        # prepare context kwds
        ctx = {}
        if examine.has_optional_user(handler):
            ctx['user'] = 'user'

        # check if it verifies against password
        try:
            ok = handler.verify('xxx', hash, **ctx)
        except ValueError:
            pass
        else:
            return "hash", score

        # check if we can encrypt against password
        try:
            handler.genhash('xxx', hash, **ctx)
        except ValueError:
            pass
        else:
            return "config", score

        # identified, but can't parse
        return "malformed", malformed

def fuzzy_identify(hash):
    """try to identify format of hash.

    :arg hash: hash to try to identify
    :returns:
        list of ``(name, category, confidence)`` entries.
        * ``name`` -- name of handler
        * ``category`` -- one of ``"hash", "salt", "malformed", "guess"``
        * ``confidence`` -- confidence rating used to rank possibilities.
          currently rather arbitrary and inexact.
    """
    # gather results, considering all handlers which don't use wildcard identify
    results = []
    for name in list_crypt_handlers():
        if examine.has_wildcard_identify(name):
            continue
        handler = get_crypt_handler(name)
        cat, score = _identify_helper(hash, handler)
        if cat:
            score *= _handler_weights.get(name, 100) // 100
            results.append([name, cat, score])

    # sort by score and return
    so = ["hash", "config", "malformed"]
    def sk(record):
        return -record[2], so.index(record[1]), record[0]
    results.sort(key=sk)
    return results

def identify_format(hash):
    "identify scheme used by format (mcf, ldap, None:unknown)"
    m = re.match(r"(\$[a-zA-Z0-9_-]+\$)\w+", candidate)
    if m:
        return "mcf", m.group(1)
    m = re.match(r"(\{\w+\})\w+", candidate)
    if m:
        return "ldap", m.group(1)
    return None, None

def identify_cmd(args):
    """attempt to identify format of unknown password hashes.
    this is just a wrapper for the more python-friendly fuzzy_identify()
    """
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
        writer.writerow(("name", "category", "score", "summary"))
        for name, cat, score in results:
            row = (name, cat, score)
            summary = examine.summary(name)
            if summary:
                row += (summary,)
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
            summary = examine.summary(name) or ""
            if summary:
                summary = " %s" % summary
            print "  %-40s %s" % (txt, summary)
    else:
        print_("Input could not be identified by Passlib.")
        best = 0

    # inform user about general class of hash if the guesses were poor.
    if not opts.csv and best < 25:
        fmt, ident = identify_format(hash)
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
class BenchmarkError(ValueError):
    pass

_backend_filter_aliases = dict(a="all", d="default",
                               f="fastest", i="installed")

_benchmark_presets = dict(
    all=lambda name: True,
    variable=lambda name: examine.is_variable(name) and not examine.is_wrapper(name),
    base=lambda name: not examine.is_wrapper(name),
)

def benchmark(schemes=None, backend_filter="all", max_time=None):
    """helper for benchmark command, times specified schemes.

    :arg schemes:
        list of schemes to test.
        presets ("all", "variable", "base") will be expanded.

    :arg backend_filter:
        how to handler multi-backend. should be "all", "default",
        "installed", or "fastest".

    :arg max_time:
        maximum time to spend measuring each hash.

    :returns:
        this function yeilds a series of HashTimer objects,
        one for every scheme/backend combination tested.

        * if a backend is not available, the object will have ``.speed=None``.
        * if no backend is available, the object ``.speed=None`` and
          ``.backend=None``
    """
    # expand aliases from list of schemes
    if schemes is None:
        schemes = ["all"]
    names = set(schemes)
    for scheme in schemes:
        func = _benchmark_presets.get(scheme)
        if func:
            names.update(name for name in list_crypt_handlers()
                         if not examine.is_psuedo(name) and func(name))
            names.discard(scheme)

    # validate backend filter
    backend_filter = _backend_filter_aliases.get(backend_filter, backend_filter)
    if backend_filter not in ["all", "default", "installed", "fastest"]:
        raise ValueError("unknown backend filter value: %r" % (backend_filter,))

    # prepare for loop
    from passlib.utils._cost import HashTimer

    def measure(handler, backend=None):
        if backend and not handler.has_backend(backend):
            # create stub instance by not running measurements;
            # detected via .speed=None
            return HashTimer(handler, backend=backend, autorun=False)
        return HashTimer(handler, backend=backend, max_time=max_time)

    def stub(handler):
        return HashTimer(handler, 'none', autorun=False)

    # run through all schemes
    for name in sorted(names):
        handler = get_crypt_handler(name)
        if not hasattr(handler, "backends"):
            yield measure(handler)
        elif backend_filter == "fastest":
            best = None
            for backend in handler.backends:
                timer = measure(handler, backend)
                if timer.speed is not None and (best is None or
                                                timer.speed > best.speed):
                    best = timer
            yield best or stub(handler)
        elif backend_filter == "all":
            for backend in handler.backends:
                yield measure(handler, backend)
        elif backend_filter == "installed":
            found = False
            for backend in handler.backends:
                if handler.has_backend(backend):
                    found = True
                    yield measure(handler, backend)
            if not found:
                yield stub(handler)
        else:
            assert backend_filter == "default"
            try:
                default = handler.get_backend()
            except MissingBackendError:
                yield stub(handler)
            else:
                yield measure(handler, default)

def benchmark_cmd(args):
    """benchmark speed of hash algorithms.
    this is mainly a wrapper for the benchmark() function.
    """
    #
    # parse args
    #
    p = OptionParser(prog="passlib benchmark", version=vstr,
                     usage="%prog [options] [all | variable | <alg> ... ]",
                     description="""You should provide the names of one
or more algorithms to benchmark, as positional arguments. If you
provide the special name "all", all algorithms in Passlib will be tested.""",
                     )
    p.add_option("-b", "--backend-filter", action="store", default="installed",
                 dest="backend_filter",
                 help="only list specific backends (possible values are: all, default, installed, fastest)")
    p.add_option("-t", "--target-time", action="store", type="float",
                 dest="target_time", default=.25, metavar="SECONDS",
                 help="display cost setting required for verify() to take specified time (default=%default)",
                )
    p.add_option("--max-time", action="store", type="float",
                 dest="max_time", default=1.0, metavar="SECONDS",
                 help="spend at most SECONDS benchmarking each hash (default=%default)",
                )
    p.add_option("--csv", action="store_true",
                 dest="csv", default=False,
                 help="Output results in CSV format")
    ##p.add_option("--with-default", action="store_true", dest="with_default",
    ##             default=False, help="Include default cost in listing")

    opts, args = p.parse_args(args)

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

    try:
        for timer in benchmark(schemes=args or None,
                               max_time=opts.max_time,
                               backend_filter=opts.backend_filter,
                               ):
            name = timer.handler.name
            backend = timer.backend
            scale = timer.scale if timer.hasrounds else "fixed"
            spd = cost = curdef = null
            if timer.speed is not None:
                spd = ("%g" if timer.speed < 10 else "%d") % (timer.speed,)
                if timer.hasrounds:
                    cost = timer.estimate(opts.target_time)
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
    # TODO: verify_cmd
    # TODO: gencfg_cmd - generate config w/ timings, possibly taking in another
    # TODO: chkcfg_cmd - check config file for errors.
    # TODO: test_cmd
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
