# SPDX-License-Identifier: MIT
"""Caller-owned immutable clock/cause custody; this module issues no actor grant."""
import math


class Cancelled(BaseException):
    pass


def need(value, reason):
    if not value:
        raise ValueError(reason)


class Authority:
    def __init__(self, start, J, E, *, clock, cancelled, execution_granted=False,
                 cancel_types=(Cancelled, KeyboardInterrupt, SystemExit)):
        need(all(type(v) in (int, float) and math.isfinite(v) for v in (start, J, E)), 'pair-clock-type')
        need(0 <= start < E <= J - 360 and J <= start + 7200, 'pair-clock-binding')
        need(callable(clock) and callable(cancelled) and type(execution_granted) is bool, 'pair-caller-binding')
        need(type(cancel_types) is tuple and all(isinstance(t, type) and issubclass(t, BaseException)
             for t in cancel_types), 'pair-cancellation-types')
        self._ends = (start, J, E)
        self.clock, self.cancel_test = clock, cancelled
        self.execution_granted = execution_granted
        self.cancel_types = cancel_types
        self.first_failure = self.cleanup_failure = None
        self._primary = None
        self.cancelled = False
        self._last = start
        self._custody = None
        self._checker = None

    @property
    def start(self): return self._ends[0]
    @property
    def J(self): return self._ends[1]
    @property
    def E(self): return self._ends[2]
    @property
    def primary(self):
        return self._primary

    def record_failure(self, error, cleanup=False):
        need(isinstance(error, BaseException) and type(cleanup) is bool, 'pair-failure-type')
        name = 'cleanup_failure' if cleanup else 'first_failure'
        if getattr(self, name) is None:
            setattr(self, name, error)
        if self._primary is None:
            self._primary = error
        if isinstance(error, self.cancel_types):
            self.cancelled = True

    def claim_custody(self, owner):
        try:
            self.check()
            need(owner is not None and self._custody is None, 'pair-custody-already-claimed')
            self._custody = owner
        except BaseException as error:
            self.record_failure(error)
            raise

    def claim_checker(self, grant, owner):
        try:
            self.check()
            need(grant is not None and owner is self._custody and owner is not None
                 and self._checker is None, 'pair-checker-already-claimed-or-foreign-owner')
            self._checker = grant
        except BaseException as error:
            self.record_failure(error)
            raise

    def check(self, cleanup=False):
        try:
            need(type(cleanup) is bool, 'pair-phase-type')
            if not cleanup and self.primary is not None:
                raise self.primary
            now = self.clock()
            need(type(now) in (int, float) and math.isfinite(now) and now >= self._last, 'pair-clock-regression')
            self._last = now
            need(now < (self.J if cleanup else self.E), 'pair-original-deadline')
            flag = self.cancel_test()
            need(type(flag) is bool, 'pair-cancellation-type')
            if flag:
                self.cancelled = True
                error = Cancelled('pair-cancelled')
                self.record_failure(error, cleanup=cleanup)
                if not cleanup:
                    raise error
            return now
        except BaseException as error:
            self.record_failure(error, cleanup=cleanup)
            raise
