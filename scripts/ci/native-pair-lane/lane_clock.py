"""Root's original job clock, shared by intake, selection and guardian."""
import math
import time


class OriginalClock:
    def __init__(self, start, *, clock=time.monotonic):
        if type(start) not in (int, float) or not math.isfinite(start) or start <= 0:
            raise ValueError('registered-original-start')
        self.start, self.J, self.E = start, start + 7200, start + 6840
        self.clock, self.last, self.primary = clock, None, None
        self.recovery_end = self.J - 180
        self.execution_granted = False

    def record_failure(self, error, *, cleanup=False):
        if self.primary is None:
            self.primary = error
            try:
                observed = self.clock()
                if not self.start <= observed <= self.J: observed = self.start
            except BaseException: observed = self.start
            try:
                earlier = getattr(error, 'first_failure_at', None)
                if type(earlier) in (int, float) and math.isfinite(earlier) and self.start <= earlier <= observed:
                    observed = earlier
            except BaseException: pass
            self.recovery_end = min(self.recovery_end, observed + 180)
            try: error.first_failure_at = observed
            except BaseException: pass
        return self.primary

    def check(self, *, cleanup=False, publication=False):
        if cleanup and publication: raise ValueError('registered-clock-role')
        if self.primary is not None and not cleanup: raise self.primary
        try:
            now = self.clock()
            end = self.recovery_end if cleanup else self.J if publication else self.E
            if (type(now) not in (int, float) or not math.isfinite(now) or
                not self.start <= now < end or self.last is not None and now < self.last):
                raise ValueError('registered-original-cutoff')
            self.last = now
            return now
        except BaseException as error: raise self.record_failure(error)

    def call(self, function, *args, cleanup=False, publication=False, **kwargs):
        self.check(cleanup=cleanup, publication=publication)
        try: result = function(*args, **kwargs)
        except BaseException as error: raise self.record_failure(error)
        self.check(cleanup=cleanup, publication=publication)
        return result
