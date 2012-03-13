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
import passlib.utils.handlers as uh

vstr = "Passlib " + __version__

#=========================================================
# utils
#=========================================================

# handlers which aren't hashes
_disabled_handlers = ["unix_fallback", "unix_disabled", "django_disabled"]

# plaintext handlers
_plaintext_handlers = ["plaintext", "roundup_plaintext", "ldap_plaintext"]

# hashes with a username, but don't require one.
_user_optional_hashes = ["cisco_pix"]

def _is_psuedo(name):
    return name in _disabled_handlers or name in _plaintext_handlers

def _is_variable(name):
    return 'rounds' in get_crypt_handler(name).setting_kwds

def _is_wrapper(name):
    return hasattr(get_crypt_handler(name), "orig_prefix")

#=========================================================
# encrypt command
#=========================================================

def encrypt_cmd(args):
    """encrypt password using specific format"""
    # FIXME: this should read password from file / stdin
    # TODO: look at unix mkpasswd command (and maybe rename encrypt to that or digest)

    #
    # parse args
    #
    p = OptionParser(prog="passlib encrypt", version=vstr,
                     usage="%prog [options] <method> <password>",
                     description="This subcommand will hash the specified password, "
                                 "using the specified hashing method, and output a single line containing the result.",
                     epilog="Specify the method 'help' to get a list of available methods")
    p.add_option("-u", "--user", dest="user", default=None,
                 help="specify username for algorithms which require it")
    p.add_option("-s", "--salt", dest="salt", default=None,
                 help="specify custom salt")
    p.add_option("-z", "--salt-size", dest="salt_size", default=None, type="int",
                 help="specify size of generated salt", metavar="SIZE")
    p.add_option("-r", "--rounds", dest="rounds", default=None, type="int",
                 help="specify number of rounds")
    p.add_option("-i", "--ident", dest="ident", default=None,
                 help="specify identifier or subformat")

    #
    # handle positional args
    #
    opts, args = p.parse_args(args)
    if not args:
        p.error("no method specified")
    method = args.pop(0)
    if not args:
        p.error("No password provided")
    password = args.pop(0)
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
    if 'user' in handler.context_kwds:
        if opts.user:
            kwds['user'] = opts.user
        elif method not in _user_optional_hashes:
            print_("error: %s requires a --user" % method)
            return 1
    if opts.rounds and 'rounds' in handler.setting_kwds:
        kwds['rounds'] = int(opts.rounds)
    if opts.salt and 'salt' in handler.setting_kwds:
        kwds['salt'] = opts.salt
    if opts.salt_size and 'salt_size' in handler.setting_kwds:
        kwds['salt_size'] = int(opts.salt_size)
    if opts.ident and 'ident' in handler.setting_kwds:
        kwds['ident'] = opts.ident

    #
    # create hash, and done
    #
    print_(handler.encrypt(password, **kwds))
    return 0

#=========================================================
# identify command
#=========================================================

# handlers that will match anything, and shouldn't be checked.
_skip_handlers = [
    "plaintext",
    "ldap_plaintext",
    "unix_fallback",
    "unix_disabled",
]

# some handlers lack fixed identifier, and may match against hashes
# that aren't their own; this is used to rate those as less likely.
_handler_weights = dict(
    des_crypt=90,
    bigcrypt=25,
    crypt16=25,
)

_char_ranges = [
    uh.LOWER_HEX_CHARS,
    uh.UPPER_HEX_CHARS,
    uh.HEX_CHARS,
    uh.HASH64_CHARS,
    uh.BASE64_CHARS,
]

def _identify_char_range(source):
    source = set(source)
    for cr in _char_ranges:
        if source.issubset(cr):
            return cr
    return None

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

    # hack for cisco_type7
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
            return "salt", score

        # if checksum contains suspiciously fewer chars than it should
        # (e.g. is strictly hex, but should be h64), weaken score.
        # uc>1 is there so we skip 'fake' checksums that are all one char.
        uc = len(set(checksum))
        chars = getattr(handler, "checksum_chars", None)
        if isinstance(checksum, unicode) and uc > 1 and chars:
            cr = _identify_char_range(checksum)
            hr = _identify_char_range(chars)
            if hr != cr:
                if (cr in [uh.LOWER_HEX_CHARS, uh.UPPER_HEX_CHARS] and
                    hr in [uh.HASH64_CHARS, uh.BASE64_CHARS]):
                        # *really* unlikely this is right
                        return None, 0
        return "hash", score

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
        return "hash", score

    # check if we can encrypt against password
    try:
        handler.genhash('xxx', hash, **ctx)
    except ValueError:
        pass
    else:
        return "salt", score

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
    # TODO: weight based on smallest encompassing character set
    # (upper hex, lower hex, mixed hex, base64)

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
        trigger = (best>50)
        if best == 100 and not multi:
            print_("Input identified:")
        else:
            print_("Input is " + pl(best > 50, "likely", "possibly") +
                   pl(multi, " one of the following") + ":")
        for name, cat, conf in results:
            if trigger and conf < 50:
                print_("\nLess likely alternatives include:")
                trigger = False
            details = []
            if cat != "hash":
                details.append(cat)
            details.append("score=%s" % conf)
            details = "(%s)" % ", ".join(details)
            summary = getattr(get_crypt_handler(name), "summary", "")
            if summary:
                summary = " %s" % summary
            x = "%s %s" % (name, details)
            print "  %-40s %s" % (x, summary)
#            print "  %-15s %-20s %s" % (name, details, summary)
#            print "  %s (%s) %s" % (name, ", ".join(details), summary)
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

        m = re.match(r"(\{\w+\})\w+", candidate)
        if m:
            print_("\nDue to the %r prefix, "
                   "input is possibly an unknown/unsupported "
                   "hash using an LDAP-style hash format." % (m.group(1),))

    return 0 if results else 1

#=========================================================
# timer command
#=========================================================
class BenchmarkError(ValueError):
    pass

_bf_aliases = dict(a="all", d="default", f="fastest", i="installed")

_benchmark_presets = dict(
    all=lambda name: True,
    variable=lambda name: _is_variable(name) and not _is_wrapper(name),
    base=lambda name: not _is_wrapper(name),
)

def benchmark(schemes=None, backend_filter="all", max_time=None):
    """helper for benchmark command"""

    # expand aliases from list of schemes
    if schemes is None:
        schemes = ["all"]
    names = set(schemes)
    for scheme in schemes:
        func = _benchmark_presets.get(scheme)
        if func:
            names.update(name for name in list_crypt_handlers()
                         if not _is_psuedo(name) and func(name))
            names.discard(scheme)

    # validate backend filter
    backend_filter = _bf_aliases.get(backend_filter, backend_filter)
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
    """benchmark speed of hash algorithms"""
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
                 dest="target_time", default=.25, metavar="TIME",
                 help="display cost setting needed to take specified amount of seconds (default=%default)",
                )
    p.add_option("--max-time", action="store", type="float",
                 dest="max_time", default=1.0, metavar="TIME",
                 help="spend at most TIME seconds benchmarking each hash (default=%default)",
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
