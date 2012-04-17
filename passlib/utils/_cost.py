"""passlib.utils._cost - hash cost analysis

this modules contains routines for measuring the cost/speed of a hash.
it may eventually made public.
"""
#=========================================================
#imports
#=========================================================
from __future__ import division
#core
from math import log as logb
import logging; log = logging.getLogger(__name__)
import random
import sys
#site
#pkg
from passlib.registry import get_crypt_handler
from passlib.utils import tick, repeat_string
from passlib.utils.compat import u
from passlib.utils.handlers import BASE64_CHARS
import passlib.utils._examine as examine
#local
__all__ = [
    "HashTimer",
    "benchmark", "BenchmarkError",
]
#=========================================================
# timer class
#=========================================================
SECRET = u("dummy password")

class HashTimer(object):
    """helper class which determines speed of hash implementation

    :arg handler: passlib handler object to test
    :param max_time: maximum amount of time to speed timing hash
    :param backend: optionally use specific backend for handler

    once created...

    * :meth:`estimate` can be called to determine correct rounds value
      which will take a specific amount of time.
    * :attr:`speed` will report the handler's speed in iterations per second.
    * :attr:`scale` will report the scale that the hash's rounds parameter
      uses relative to the *speed*, which is always linear.
    """
    #====================================================================
    # instance attrs
    #====================================================================

    # inputs
    handler = None
    max_time = 1
    backend = None

    # results
    hasrounds = None #: True if has variable rounds, False if fixed
    scale = None #: scaling of cost parameter (linear/log2)
    speed = None #: raw rounds/second

    # public helpers
    c2v = None # convert cost parameter -> rounds value
    v2c = None # convert rounds value -> cost parameter

    # helper to generate passwords
    _gensecret = None

    #====================================================================
    # init / main loop
    #====================================================================
    def __init__(self, handler, max_time=None, backend=None, autorun=True,
                 password_size=10):
        # validate params
        if max_time is not None:
            self.max_time = max(0, max_time)

        # init gensecret
        if isinstance(password_size, int):
            secret = repeat_string(BASE64_CHARS, password_size)
            self._gensecret = lambda : secret
        else:
            mu, sigma = password_size
            def gensecret():
                size = int(random.gauss(mu, sigma))
                return repeat_string(BASE64_CHARS, min(1,size))
            self._gensecret = gensecret

        # characterize handler
        self.handler = handler
        self.hasrounds = examine.has_rounds(handler)
        self.scale = handler.rounds_cost if self.hasrounds else "linear"

        # init cost manipulation helpers
        if self.scale == "log2":
            self.c2v = lambda c: 1<<c
            self.v2c = lambda v: int(logb(v,2))
            self.cshift = lambda c,p: max(0,c+p)
        else:
            self.c2v = self.v2c = lambda x: int(x)
            self.cshift = lambda c,p: c<<p if p > 0 else c>>(-p)

        # init stub context kwds
        ctx = self.ctx = {}
        if handler.context_kwds:
            if examine.has_user(handler):
                ctx['user'] = u("dummyuser")
            if examine.has_realm(handler):
                ctx['realm'] = u("dummyrealm")

        # run timing loop
        self.backend = backend
        if autorun:
            self.run()

    def run(self):
        "(re)run measurements"
        handler = self.handler
        backend = self.backend
        if backend:
            orig_backend = handler.get_backend()
            handler.set_backend(backend)
        try:
            self._run()
        finally:
            if backend:
                handler.set_backend(orig_backend)

    def _run(self):
        # init locals
        terminate = tick() + self.max_time
        handler = self.handler
        ctx = self.ctx
        samples = self._samples = []

        # pick small rounds value to start with
        if self.hasrounds:
            rounds = max(handler.min_rounds,
                         self.cshift(handler.default_rounds, -1))
            setup_factor = 1.9
        else:
            rounds = 16
            setup_factor = 1
            secret = self._gensecret()
            hash = handler.encrypt(secret, **ctx)

        # do main testing loop
        while True:
            # test with specified number of rounds
            secret = self._gensecret()
            if self.hasrounds:
                # NOTE: the extra time taken by this encrypt() call is
                #       why setup_factor is set to 1.9, above
                if getattr(handler, "_avoid_even_rounds", False):
                    rounds |= 1
                hash = handler.encrypt(secret, rounds=rounds, **ctx)
                start = tick()
                handler.verify(secret, hash, **ctx)
                end = tick()
            else:
                i = 0
                start = tick()
                while i < rounds:
                    handler.verify(secret, hash, **ctx)
                    i += 1
                end = tick()

            # record speed, and decide if we have time to go again w/ 2x rounds
            elapsed = end - start
            samples.append((rounds, elapsed))
            remaining = (terminate - end) / (setup_factor * elapsed)
            if remaining < 1:
                break
            elif remaining >= 2:
                rounds = self.cshift(rounds, 1)
            # else get another sample at same # rounds, since there's time

        # calculate speed - this discards the first 1/3 of the samples,
        # since the smaller rounds are frequently inaccurate. it then takes
        # the median value, to cheaply discard any outliers.
        count = len(samples)
        if count < 2:
            c,e = samples[0]
            self.speed = self.c2v(c)/e
        else:
            speeds = sorted(self.c2v(c)/e for c,e in samples[count//3:])
            self.speed = speeds[(len(speeds)+1)//2]

    #====================================================================
    # public helpers
    #====================================================================
    def estimate(self, target):
        "estimate rounds value to reach target time"
        value = self.speed * target
        rounds = self.v2c(value)
        if self.scale == "log2" and value > 1.5 * self.c2v(rounds):
            return rounds+1
        return rounds

    def pretty_estimate(self, target, tolerance=.05):
        "find a nice round number near desired target"
        cost = self.estimate(target)
        if self.scale != "linear":
            return cost
        handler = self.handler
        start = max(getattr(handler,"min_rounds", 1), int(cost*(1-tolerance)))
        end = min(getattr(handler, "max_rounds", 1<<32), int(cost*(1+tolerance)))
        def valid(value):
            return start < value < end
        for mag in (10000, 1000, 100):
            upper = cost+(-cost%mag)
            if valid(upper):
                return upper
            lower = cost-(cost%mag)
            if valid(lower):
                return lower
        return cost

    #====================================================================
    # eoc
    #====================================================================

def estimate_rounds_value(handler, target_time=.25, max_time=None, **kwds):
    "estimate number of rounds handler should use to take target_time"
    if max_time is None:
        max_time = target_time*2
    timer = HashTimer(handler, max_time, **kwds)
    return timer.estimate(target_time)

#=========================================================
# benchmark frontend
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

def benchmark(schemes=None, backend_filter="all", max_time=None,
              password_size=10):
    """helper for benchmark command, times specified schemes.

    :arg schemes:
        list of schemes to test.
        presets ("all", "variable", "base") will be expanded.

    :arg backend_filter:
        how to handler multi-backend. should be "all", "default",
        "installed", or "fastest".

    :arg max_time:
        maximum time to spend measuring each hash.

    :arg password_size:
        specify size of password to benchmark.
        if a tuple, interpreted as ``(avg, sigma)``.

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
            names.update(name for name in examine.list_crypt_handlers()
                         if not examine.is_psuedo(name) and func(name))
            names.discard(scheme)

    # validate backend filter
    backend_filter = _backend_filter_aliases.get(backend_filter, backend_filter)
    if backend_filter not in ["all", "default", "installed", "fastest"]:
        raise ValueError("unknown backend filter value: %r" % (backend_filter,))

    # prepare for loop
    def measure(handler, backend=None):
        if backend and not handler.has_backend(backend):
            return stub(handler, backend)
        return HashTimer(handler, backend=backend, max_time=max_time,
                         password_size=password_size)

    def stub(handler, backend='none'):
        return HashTimer(handler, backend, autorun=False)

    # run through all schemes
    for name in sorted(names):
        handler = examine.get_crypt_handler(name)
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

#=========================================================
# development helpers
#=========================================================

##def _test_timer(timer, cost):
##    "helper to test HashTimer's accuracy"
##    handler = timer.handler
##    ctx = timer.ctx
##    if timer.hasrounds:
##        h = handler.encrypt(SECRET, rounds=cost, **ctx)
##        s = default_timer()
##        handler.verify(SECRET, h, **ctx)
##        return default_timer()-s
##    else:
##        h = handler.encrypt(SECRET, **ctx)
##        s = default_timer()
##        i = 0
##        while i < cost:
##            handler.verify(SECRET, h, **ctx)
##            i += 1
##        return default_timer()-s
##
##def main(*args):
##    "test script used to develop & test HashTimer"
##    from bps.logs import setup_std_logging
##    setup_std_logging(level="warn", dev=True)
##    from passlib import hash
##
##    target_delta = .25
##
##    for name in dir(hash):
##        if name.startswith("_"):
##            continue
##        handler = getattr(hash, name)
##
##        s = default_timer()
##        timer = HashTimer(handler, max_time=1)
##        run_time = default_timer()-s
##
##        target_cost = timer.estimate(target_delta)
##        real_delta = _test_timer(timer, target_cost)
##        real_speed = timer.c2v(target_cost)/real_delta
##
##        speeds = [ timer.c2v(c)/e for c,e in timer._samples ]
##        def fpe(value, correct):
##            return round((value-correct)/correct*100,2)
##        print "%30s, %10s, % 10.2f, % 5.4f%%, % 5.4fs [%s]" % \
##            (timer.handler.name,
##             timer.scale if timer.hasrounds else "fixed",
##             timer.speed,
##             fpe(timer.speed, real_speed),
##             run_time,
##             ", ".join(str(fpe(s,real_speed)) for s in sorted(speeds))
##             )
##
##if __name__ == "__main__":
##    sys.exit(main(sys.argv[1:]))

#=========================================================
#eof
#=========================================================
