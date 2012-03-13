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
import sys
#site
#pkg
from passlib.registry import get_crypt_handler
from passlib.utils import tick
from passlib.utils.compat import u
#local
__all__ = [
    "HashTimer",
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

    #====================================================================
    # init / main loop
    #====================================================================
    def __init__(self, handler, max_time=None, backend=None, autorun=True):
        # validate params
        if max_time is not None:
            self.max_time = max(0, max_time)

        # characterize handler
        self.handler = handler
        self.hasrounds = 'rounds' in handler.setting_kwds
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
            if 'user' in handler.context_kwds:
                ctx['user'] = u("dummyuser")

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
            hash = handler.encrypt(SECRET, **ctx)

        # do main testing loop
        while True:
            # test with specified number of rounds
            if self.hasrounds:
                # NOTE: the extra time taken by this encrypt() call is
                #       why setup_factor is set to 1.9, above
                hash = handler.encrypt(SECRET, rounds=rounds, **ctx)
                start = tick()
                handler.verify(SECRET, hash, **ctx)
                end = tick()
            else:
                i = 0
                start = tick()
                while i < rounds:
                    handler.verify(SECRET, hash, **ctx)
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
# development helpers
#=========================================================

def _test_timer(timer, cost):
    "helper to test HashTimer's accuracy"
    handler = timer.handler
    ctx = timer.ctx
    if timer.hasrounds:
        h = handler.encrypt(SECRET, rounds=cost, **ctx)
        s = default_timer()
        handler.verify(SECRET, h, **ctx)
        return default_timer()-s
    else:
        h = handler.encrypt(SECRET, **ctx)
        s = default_timer()
        i = 0
        while i < cost:
            handler.verify(SECRET, h, **ctx)
            i += 1
        return default_timer()-s

def main(*args):
    "test script used to develop & test HashTimer"
    from bps.logs import setup_std_logging
    setup_std_logging(level="warn", dev=True)
    from passlib import hash

    target_delta = .25

    for name in dir(hash):
        if name.startswith("_"):
            continue
        handler = getattr(hash, name)

        s = default_timer()
        timer = HashTimer(handler, max_time=1)
        run_time = default_timer()-s

        target_cost = timer.estimate(target_delta)
        real_delta = _test_timer(timer, target_cost)
        real_speed = timer.c2v(target_cost)/real_delta

        speeds = [ timer.c2v(c)/e for c,e in timer._samples ]
        def fpe(value, correct):
            return round((value-correct)/correct*100,2)
        print "%30s, %10s, % 10.2f, % 5.4f%%, % 5.4fs [%s]" % \
            (timer.handler.name,
             timer.scale if timer.hasrounds else "fixed",
             timer.speed,
             fpe(timer.speed, real_speed),
             run_time,
             ", ".join(str(fpe(s,real_speed)) for s in sorted(speeds))
             )

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#=========================================================
#eof
#=========================================================
