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
from passlib.registry import list_crypt_handlers, get_crypt_handler
from passlib.utils.compat import print_, iteritems
import passlib.utils.handlers as uh

vstr = "Passlib " + __version__

#=========================================================
# utils
#=========================================================

#=========================================================
# encrypt command
#=========================================================
def encrypt_cmd(args):
    """encrypt password using specific format"""
    # FIXME: this should read password from file / stdin
    # TODO: add --salt, --user, --rounds etc for extra options.

    #
    # parse args
    #
    p = OptionParser(prog="passlib encrypt", version=vstr,
                     usage="%prog [options] <format> <password>")
    ##p.add_option("-d", "--details",
    ##                  action="store_true", dest="details", default=False,
    ##                  help="show details about referenced hashes")

    opts, args = p.parse_args(args)
    if not args:
        p.error("No format provided")
    format = args.pop(0)
    if not args:
        p.error("No password provided")
    password = args.pop(0)
    if args:
        p.error("Unexpected positional arguments")

    handler = get_crypt_handler(format)
    print_(handler.encrypt(password))
    return 0

#=========================================================
# identify command
#=========================================================

# handlers that will match anything, and shouldn't be checked.
_skip_handlers = [
    "plaintext",
    "ldap_plaintext",
    "unix_fallback",
]

# some handlers lack fixed identifier, and may match against hashes
# that aren't their own; this is used to rate those as less likely.
_handler_weights = dict(
    des_crypt=90,
    bigcrypt=25,
    crypt16=25,
)

def _match_ident_prefixes(hash, handler):
    if isinstance(hash, bytes):
        hash = hash.decode("utf-8")
    ident = getattr(handler, "ident", None)
    if ident is not None and hash.startswith(ident):
        return True
    ident_values = getattr(handler, "ident_values", None)
    if ident_values and any(hash.startswith(ident) for ident in ident_values):
        return True
    return False

def _examine(hash, handler):
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
        if _match_ident_prefixes(hash, handler):
            return "malformed", malformed
        return None, 0

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
            return "salt", 100

        # examine checksum distribution - if should be base64,
        # but is only using hex chars - probably false positive.
        chars = getattr(handler, "checksum_chars", None)
        if set(checksum).issubset(uh.HEX_CHARS) and \
                len(set(uh.HEX_CHARS)) * 3 < len(set(chars)):
            return "hash", 10

        return "hash", 100

    # prepare context kwds
    if handler.context_kwds == ("user",):
        ctx = dict(user="user")
    else:
        ctx = {}

    # check if it verifies against password
    try:
        ok = handler.verify('xxx', hash, **ctx)
    except ValueError:
        pass
    else:
        return "hash", 100

    # check if we can encrypt against password
    try:
        handler.genhash('xxx', hash, **ctx)
    except ValueError:
        pass
    else:
        return "salt", 100

    # identified, but can't parse
    return "malformed", malformed

def identify(hash):
    """try to identify format of hash.

    :arg hash: hash to try to identify
    :returns:
        list of ``(name, category, confidence)`` entries.
        * ``name`` -- name of handler
        * ``category`` -- one of ``"hash", "salt", "malformed", "guess"``
        * ``confidence`` -- confidence rating used to rank possibilities.
          currently rather arbitrary and inexact.
    """
    # gather results
    results = []
    hist = dict(hash=0, salt=0, malformed=0)
    for name in list_crypt_handlers():
        if name not in _skip_handlers:
            handler = get_crypt_handler(name)
            cat, score = _examine(hash, handler)
            if cat:
                score = score * _handler_weights.get(name, 100) // 100
                results.append([name, cat, score])
                hist[cat] += 1

    # sort by score and return
    so = ["hash", "salt", "malformed"]
    def sk(record):
        return -record[2], so.index(record[1]), record[0]
    results.sort(key=sk)
    return results

def identify_cmd(args):
    """attempt to identify format of unknown password hashes"""
    #
    # parse args
    #
    p = OptionParser(prog="passlib identify", version=vstr,
                     usage="%prog [options] <hash>")
    p.add_option("-d", "--details",
                      action="store_true", dest="details", default=False,
                      help="show details about referenced hashes")

    opts, args = p.parse_args(args)
    if not args:
        p.error("No hash provided for identification")
    candidate = args.pop(0)
    if args:
        p.error("Unexpected positional arguments")

    #
    # identify hash
    #
    results = identify(candidate)

    #
    # display results
    #
    def pl(cond, p, s=""):
        return p if cond else s
    rc = 0
    if results:
        best = results[0][2]
        multi = len(results) > 1
        if best == 100 and not multi:
            print_("Input identified:")
        else:
            print_("Input is " + pl(best > 50, "likely", "possibly") +
                   pl(multi, " one of the following") + ":")
        for name, cat, conf in results:
            details = []
            if cat != "hash":
                details.append(cat)
            details.append("score=%s" % conf)
            print "  %s (%s)" % (name, ", ".join(details))
    else:
        print_("Input could not be identified by Passlib.")
        best = 0

    # inform user about general class of hash if the guesses were poor.
    if best < 25:
        m = re.match(r"(\$[a-zA-Z0-9_-]+\$)\w+", candidate)
        if m:
            print_("\nDue to the %r prefix, "
                   "input is possibly an unknown/unsupported "
                   "hash using Modular Crypt Format." % (m.group(1),))

    return 0 if results else 1

#=========================================================
# timer command
#=========================================================
def benchmark_cmd(args):
    """benchmark speed of hash algorithms"""
    #
    # parse args
    #
    p = OptionParser(prog="passlib benchmark", version=vstr,
                     usage="%prog [options] <alg> [ <alg> ... ]",
                     description="""You should provide the names of one
or more algorithms to benchmark, as positional arguments. If you
provide the special name "all", all algorithms in Passlib will be tested.""",
                     )
    p.add_option("--max-time", action="store", type="float",
                 dest="max_time", default=1.0, metavar="TIME",
                 help="spend at most TIME seconds benchmarking each hash (default=%default)",
                )

    p.add_option("--csv", action="store_true",
                 dest="csv", default=False,
                 help="Output results in CSV format")

    opts, args = p.parse_args(args)
    if not args:
        p.error("no algorithm names provided")
    elif len(args) == 1 and args[0] == "all":
        autoall = True
        args = [ name for name in list_crypt_handlers()
                if name not in _skip_handlers ]
    else:
        autoall = False

    from passlib.utils._cost import HashTimer

    kwds = dict(max_time=opts.max_time)

    if opts.csv:
        fmt = "%s,%s,%s,%s"
        print_(fmt % ("handler", "backend", "cost", "speed"))
    else:
        fmt = "%-30s %-10s %10s"
        print_(fmt % ("handler", "cost", "speed"))
        print_(fmt % ("-" * 30, "-" * 10, "-" * 10))

    def measure(handler, backend=None):
        if backend:
            tag = "%s (%s)" % (handler.name, backend)
            if not hasattr(handler, "backends"):
                print_("\nerror: %r handler does not support multiple backends"
                                % (handler.name,))
                return 1
            if backend not in handler.backends:
                print_("\nerror: %r handler has no backend named %r" %
                                 (handler.name, backend))
                return 1
            if not handler.has_backend(backend):
                cost = getattr(handler, "rounds_cost", None) or "fixed"
                if opts.csv:
                    print_(fmt % (handler.name, backend, cost, ""))
                else:
                    print_(fmt % (tag, cost, ""))
                return
        else:
            tag = handler.name
        timer = HashTimer(handler, backend=backend, **kwds)
        cost = timer.scale if timer.hasrounds else "fixed"
        if timer.speed < 10:
            spd = "%g" % (timer.speed,)
        else:
            spd = "%d" % (timer.speed,)
        if opts.csv:
            print_(fmt % (handler.name, backend or '', cost, spd))
        else:
            print_(fmt % (tag, cost, spd))

    for name in args:
        if ":" in name:
            name, backend = name.split(":")
        else:
            backend = None
        handler = get_crypt_handler(name)
        if (backend == "all" or autoall) and hasattr(handler, "backends"):
            for backend in handler.backends:
                rc = measure(handler, backend)
                if rc:
                    return rc
        else:
            rc = measure(handler, backend)
            if rc:
                return rc

    return 0

#=========================================================
# main
#=========================================================
commands = {
    "identify": identify_cmd,
    "encrypt": encrypt_cmd,
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
