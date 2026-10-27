#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One fixed original Apps16 source suite with whole verified workspace input94."""
import argparse,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(HERE))
import source_guard as G
OLD="D.parent/'apps16-inputs/recipe-source/packages/tools/cachy-asahi-apps16/inventory.py'"
NEW="_EXACT_APPS16_INPUTS/'recipe-source/packages/tools/cachy-asahi-apps16/inventory.py'"
def main():
 p=argparse.ArgumentParser();p.add_argument('--control',choices=('apps16-common',),required=True);p.add_argument('--apps16-inputs',type=Path,required=True);a=p.parse_args();G.verify(require_known=True);carrier=a.apps16_inputs;G.need(carrier.is_absolute()and carrier==carrier.resolve()and not any(q.is_symlink()for q in(carrier,*carrier.parents)),'canonical explicit Apps16 workspace input')
 home=ROOT/'parent574';s=importlib.util.spec_from_file_location('_exact_original_apps16_input_policy',home/'apps16_common.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C);selection=G.obj(home/'apps16-selection.json')['selection'];G.need(len(selection['files'])==94 and selection['source']=='950b0699a6e3f7a56758d4d17a5d30dabc7b6e11','exact original whole94 carrier selection');C.closed(carrier,selection['files']);index=C.obj(carrier/'index.json');C.need(C.pin(C.read(carrier/'index.json'))==selection['index'],'whole exact input index');decision=C.obj(carrier/C.member(index['acceptance']));C.need(C.pin(C.read(carrier/index['acceptance']))==selection['acceptance'],'original Root input custody');C.index_check(index,selection['files'],G.obj(home/'apps16-recipe-map.json'),decision)
 raw=G.read(home/'apps16_common.py');text=raw.decode();G.need(text.count(OLD)==1,'one exact original workspace-relative control input operand');text=text.replace(OLD,NEW,1);G.need(text.count(NEW)==1 and text.replace(NEW,OLD,1).encode()==raw,'entire original control byte inverse');scope=dict(__name__='__main__',__file__=str(home/'apps16_common.py'),_EXACT_APPS16_INPUTS=carrier);sys.argv=[scope['__file__']];exec(compile(text,scope['__file__'],'exec'),scope)
# SPDX-License-Identifier: MIT
"""Selected host phase leases. Timing DATA and admission never grant acceptance.

Policy is DATA: {schema: 1, phases: {prep|vm|contract|cleanup:
    {seconds: int, local_io_seconds: int, fixed_tail_seconds: int}}}.
The local-I/O pool and fixed tail are included in each phase's total seconds.
No guest timestamp, process, GPG, filesystem or network actor is consulted.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
import signal
import threading
import time

NANO = 10**9
MAX_SECONDS = 86400
PHASES = ('prep', 'vm', 'contract', 'cleanup')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def integer(value, *, positive=False):
    return type(value) is int and (1 if positive else 0) <= value <= MAX_SECONDS


def label(value):
    need(type(value) is str and 0 < len(value) <= 64 and value.isascii()
         and value.isprintable(), 'bounded ASCII phase label required')
    return value


@dataclass(frozen=True, slots=True)
class PhaseSpec:
    seconds: int
    local_io_seconds: int
    fixed_tail_seconds: int


@dataclass(frozen=True, slots=True)
class Policy:
    phases: tuple

    def spec(self, name):
        need(type(name) is str and name in PHASES, 'fixed host phase required')
        return self.phases[PHASES.index(name)]


def validate_policy(value):
    """Validate before consulting a clock or changing a signal/timer."""
    if type(value) is Policy:
        value = dict(schema=1, phases={name: dict(
            seconds=spec.seconds, local_io_seconds=spec.local_io_seconds,
            fixed_tail_seconds=spec.fixed_tail_seconds)
            for name, spec in zip(PHASES, value.phases)}) if (
                type(value.phases) is tuple and len(value.phases) == 4
                and all(type(v) is PhaseSpec for v in value.phases)) else None
    need(type(value) is dict and set(value) == {'schema', 'phases'}
         and type(value['schema']) is int and value['schema'] == 1,
         'closed version1 phase policy required')
    rows = value['phases']
    need(type(rows) is dict and set(rows) == set(PHASES), 'four exact phases required')
    specs = []
    for name in PHASES:
        row = rows[name]
        need(type(row) is dict and set(row) == {
            'seconds', 'local_io_seconds', 'fixed_tail_seconds'}, 'closed phase specification')
        need(integer(row['seconds'], positive=True)
             and integer(row['local_io_seconds'], positive=True)
             and integer(row['fixed_tail_seconds'])
             and row['local_io_seconds'] + row['fixed_tail_seconds'] < row['seconds'],
             'positive phase with contained local-I/O and fixed-tail reservations required')
        specs.append(PhaseSpec(**row))
    return Policy(tuple(specs))


class PositiveDeadline(BaseException):
    """Cannot be swallowed by a retained cleanup's broad except Exception."""
    pass


PhaseTimeout = PositiveDeadline


class _Clock:
    def __init__(self, read):
        self.read, self.last = read, None

    def now(self):
        value = self.read()
        need(type(value) is int and 0 <= value < 2**63, 'finite monotonic_ns required')
        need(self.last is None or value >= self.last, 'host monotonic clock regressed')
        self.last = value
        return value


class _Alarm:
    def __init__(self, clock, backend, duration_ns, tail_ns, timeout):
        self.clock, self.backend = clock, backend
        self.duration_ns, self.tail_ns, self.timeout = duration_ns, tail_ns, timeout
        self.changed = False

    def __enter__(self):
        need(threading.current_thread() is threading.main_thread(),
             'POSIX phase alarm requires main thread')
        b = self.backend
        self.start = self.clock.now()
        self.handler = b.getsignal(b.SIGALRM)
        timer = b.getitimer(b.ITIMER_REAL)
        need(type(timer) in (tuple, list) and len(timer) == 2
             and all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in timer),
             'finite prior POSIX timer required')
        self.prior_ns = int(timer[0] * NANO)
        need(timer[0] == 0 or self.prior_ns > 0,
             'active prior timer must have representable remaining nanoseconds')
        self.interval = timer[1]
        self.outer_deadline = self.start + self.prior_ns if self.prior_ns else None
        self.deadline = self.start + self.duration_ns
        need(self.outer_deadline is None or
             self.deadline + self.tail_ns <= self.outer_deadline,
             'full phase and tail do not fit existing outer timer')
        try:
            self.changed = True
            b.signal(b.SIGALRM, self._expired)
            now = self.clock.now()
            need(now < self.deadline and (self.outer_deadline is None or
                 self.deadline + self.tail_ns <= self.outer_deadline), 'phase setup exhausted lease')
            b.setitimer(b.ITIMER_REAL, (self.deadline - now) / NANO)
        except BaseException:
            self._restore()
            raise
        return self

    def _expired(self, signum, frame):
        self._mark_timeout()
        raise PhaseTimeout('host phase deadline expired')

    def _mark_timeout(self):
        self.timeout()
        parent = getattr(self.handler, '__self__', None)
        if isinstance(parent, _Alarm):
            parent._mark_timeout()

    def _restore(self):
        if not self.changed:
            return
        self.changed = False
        b = self.backend
        # Attempt all three restoration operations even when one fails.
        try:
            b.setitimer(b.ITIMER_REAL, 0)
        finally:
            try:
                b.signal(b.SIGALRM, self.handler)
            finally:
                fault = None
                try:
                    now = self.clock.now()
                except BaseException as error:
                    # An invalid clock cannot justify preserving future time.
                    fault, now = error, self.outer_deadline or self.start
                remaining = max(0, self.outer_deadline - now) if self.outer_deadline else 0
                remaining = min(self.prior_ns, remaining)
                b.setitimer(b.ITIMER_REAL, remaining / NANO, self.interval)
                if fault is not None:
                    raise fault
                if self.outer_deadline is not None and remaining == 0:
                    self._mark_timeout()
                    raise PhaseTimeout('existing outer timer exhausted')

    def __exit__(self, kind, error, traceback):
        try:
            if self.clock.now() >= self.deadline:
                self._mark_timeout()
                if error is None:
                    raise PhaseTimeout('host phase deadline expired')
        finally:
            self._restore()


class Lease:
    def __init__(self, name, spec, clock, backend, report):
        self.name, self.spec, self.clock, self.backend = name, spec, clock, backend
        self.report, self.records = report, 0
        self.failed, self.closed, self.active = False, False, False
        self.io_used_ns = 0

    def _timeout(self):
        self.failed = True

    def _emit(self, event, **values):
        need(self.records < 64, 'bounded phase timing DATA record count exceeded')
        self.records += 1
        row = dict(schema=1, role='HOST_PHASE_TIMING_DATA_ONLY', phase=self.name,
                   event=event, ordinal=self.records, monotonic_ns=self.clock.now(),
                   acceptance=False, clock_domain='HOST_MONOTONIC_NS', **values)
        need(len(json.dumps(row, allow_nan=False, separators=(',', ':')).encode()) <= 2048,
             'bounded phase timing DATA required')
        if self.report is not None:
            self.report(row)

    def _check(self):
        need(not self.closed, 'phase lease already closed')
        if self.failed or self.clock.now() >= self.deadline:
            self.failed = True
            raise PhaseTimeout('host phase lease exhausted')

    def admit(self, name, seconds, retirement, *, tail=0):
        """Return the full requested cap; never silently clip a child."""
        label(name)
        need(integer(seconds, positive=True) and integer(retirement) and integer(tail),
             'strict bounded child/retirement/tail seconds required')
        self._check()
        remaining = self.deadline - self.clock.now()
        reserved = ((retirement + tail + self.spec.fixed_tail_seconds) * NANO
                    + max(0, self.spec.local_io_seconds * NANO - self.io_used_ns))
        need(seconds * NANO + reserved <= remaining,
             'full child, retirement and remaining fixed/local-I/O tail do not fit')
        self._emit('child_admitted', label=name, requested_seconds=seconds,
                   retirement_seconds=retirement, extra_tail_seconds=tail,
                   reserved_tail_ns=reserved)
        self._check()
        need(seconds * NANO + reserved <= self.deadline - self.clock.now(),
             'admission callback exhausted child reservation')
        return seconds

    @contextmanager
    def child(self, name, seconds, retirement, *, tail=0):
        need(not self.active, 'child/local-I/O contexts must be sequential')
        self.admit(name, seconds, retirement, tail=tail)
        self.active = True
        try:
            with _Alarm(self.clock, self.backend, seconds * NANO,
                        (retirement + tail + self.spec.fixed_tail_seconds) * NANO
                        + max(0, self.spec.local_io_seconds * NANO - self.io_used_ns),
                        self._timeout):
                yield seconds
            self._check()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.active = False

    @contextmanager
    def local_io(self, name):
        """Bound all synchronous local work by one aggregate per-phase pool."""
        label(name)
        self._check()
        need(not self.active, 'child/local-I/O contexts must be sequential')
        available = self.spec.local_io_seconds * NANO - self.io_used_ns
        need(available > 0 and available + self.spec.fixed_tail_seconds * NANO <=
             self.deadline - self.clock.now(), 'complete remaining local-I/O pool must fit')
        self.active = True
        started = self.clock.now()
        try:
            with _Alarm(self.clock, self.backend, available,
                        self.spec.fixed_tail_seconds * NANO, self._timeout):
                yield
            self._check()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.io_used_ns += max(0, self.clock.now() - started)
            self.active = False


@contextmanager
def phase(policy, name, *, report=None, outer_tail=0,
          _clock_ns=time.monotonic_ns, _signal=signal):
    """Start a new relative phase. Private backend arguments are MODEL seams."""
    policy = validate_policy(policy)
    spec = policy.spec(name)
    need(report is None or callable(report), 'timing DATA callback required')
    need(integer(outer_tail), 'strict bounded outer tail required')
    clock = _Clock(_clock_ns)
    lease = Lease(name, spec, clock, _signal, report)
    try:
        with _Alarm(clock, _signal, spec.seconds * NANO, outer_tail * NANO,
                    lease._timeout) as alarm:
            lease.started_ns, lease.deadline = alarm.start, alarm.deadline
            try:
                lease._emit('begin', cap_seconds=spec.seconds,
                            local_io_seconds=spec.local_io_seconds,
                            fixed_tail_seconds=spec.fixed_tail_seconds)
                lease._check()
                yield lease
                lease._check()
            except BaseException:
                lease.failed = True
                raise
            finally:
                lease._emit('end', status='FAILED' if lease.failed else 'EXIT_PENDING_TIMER_RESTORATION',
                            elapsed_ns=clock.now() - lease.started_ns,
                            local_io_used_ns=lease.io_used_ns)
    finally:
        lease.closed = True

# SPDX-License-Identifier: MIT
"""Fixed crypto call waves; validation and subprocess argv remain Source-owned."""
CALL_SECONDS = 30
RETIREMENT_SECONDS = 30  # Original public-home15 + private signer-agent15.


def bounded_map(items, callback, *, workers, phase_deadline):
    """Return an ordered tuple only after all Source-owned callbacks succeed.

    Contract: each private callback performs its original subprocess call with
    timeout=30 and completes validation before returning. It must not start
    background work, mutate shared publication state, or retire a shared home.
    The actor sites retain exact GPG argv, all signer/status/stream/pin checks,
    and distinct29 signing paths/distinct607 verification rows. This scheduler
    preserves every input occurrence; it never deduplicates or merges rows.

    A Python thread cannot safely be killed. A callback violating its bounded
    subprocess contract cannot be declared canceled or drained. This function
    waits for started work before propagating failure, so caller cleanup may
    never retire private material underneath a still-running callback.
    """
    import math
    import time
    from concurrent.futures import ThreadPoolExecutor

    if (type(items) is not tuple or len(items) > 607 or type(workers) is not int
            or workers not in (8, 64) or not callable(callback)
            or type(phase_deadline) not in (int, float)
            or not math.isfinite(phase_deadline)):
        raise ValueError('exact bounded tuple, fixed workers and finite phase deadline required')
    if time.monotonic() >= phase_deadline:
        raise TimeoutError('crypto phase deadline exhausted before admission')
    if not items:
        return ()

    results = []
    failure = None
    executor = None

    def remember(exc):
        nonlocal failure
        if failure is None:
            failure = exc

    def drain(futures):
        values = []
        for future in futures:
            while True:
                try:
                    value = future.result()
                except BaseException as exc:
                    remember(exc)
                    if not future.done():
                        # A main-thread signal interrupted the wait, rather than
                        # completing/canceling the callback. Keep its reservation.
                        continue
                    value = None
                values.append(value)
                break
        return values

    try:
        for start in range(0, len(items), workers):
            # No clipping: every newly admitted callback keeps its original30.
            if phase_deadline - time.monotonic() <= CALL_SECONDS + RETIREMENT_SECONDS:
                raise TimeoutError('full30 crypto wave and30 retirement reserve required')
            if executor is None:
                executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='source-crypto')
            futures = []
            try:
                for item in items[start:start + workers]:
                    futures.append(executor.submit(callback, item))
            except BaseException as exc:
                remember(exc)
            values = drain(futures)
            if failure is not None:
                break
            if time.monotonic() >= phase_deadline - RETIREMENT_SECONDS:
                raise TimeoutError('completed crypto wave exhausted retirement reserve')
            results.extend(values)
    except BaseException as exc:
        remember(exc)
    finally:
        if executor is not None:
            # shutdown also covers a submission interrupted after queueing but
            # before submit returned its Future. No cancellation or early return.
            while True:
                try:
                    executor.shutdown(wait=True, cancel_futures=False)
                    break
                except BaseException as exc:
                    remember(exc)
    if failure is None and time.monotonic() >= phase_deadline - RETIREMENT_SECONDS:
        failure = TimeoutError('crypto shutdown exhausted retirement reserve')
    if failure is not None:
        raise failure
    if len(results) != len(items):
        raise ValueError('complete crypto occurrence coverage required')
    return tuple(results)

POSITIVE_PROFILE={'acceptance': False, 'actual': None, 'bootstrap_child_seconds': [300, 30, 30, 90, 90, 30, 60, 30, 1200], 'bootstrap_cleanup_seconds': 180, 'bootstrap_legacy_child_seconds': [1800, 120, 120, 600, 600, 120, 930, 120, 5400], 'bootstrap_shell_retirement_seconds': 210, 'bootstrap_shell_seconds': 2550, 'bootstrap_step_minutes': 47, 'bootstrap_total_seconds': 2520, 'bootstrap_work_seconds': 2340, 'case': 'minimal-generic4k', 'guest_service_seconds': 3460, 'guest_unit_start_seconds': 3580, 'guest_unit_stop_seconds': 120, 'gui_shell_retirement_seconds': 600, 'gui_shell_seconds': 11000, 'gui_step_minutes': 194, 'job_minutes': 360, 'native_control_slack_seconds': 20, 'native_entry_and_finally_seconds': 320, 'native_fit': 'NOT_ESTABLISHED', 'native_seconds': 10980, 'ordered_cleanup_producer_child_seconds': 240, 'ordered_cleanup_receipt_seconds': 30, 'ordered_cleanup_retirement_seconds': 10, 'ordered_cleanup_seconds': 450, 'ordered_cleanup_source_and_local_seconds': 180, 'ordered_cleanup_step_minutes': 8, 'owner_post_seconds': 100, 'owner_pre_seconds': 100, 'owner_retirement_seconds': 480, 'owner_work_seconds': 6880, 'positive_program_startup_seconds': 20, 'prepare_seconds': 3280, 'profile': 'GUI607_POSITIVE_PHASES_V1', 'runtime_child_seconds': 6680, 'runtime_entry_seconds': 100, 'runtime_phase_total_seconds': 6580, 'runtime_phases': {'cleanup': {'fixed_tail_seconds': 0, 'local_io_seconds': 30, 'seconds': 460}, 'contract': {'fixed_tail_seconds': 0, 'local_io_seconds': 20, 'seconds': 150}, 'prep': {'fixed_tail_seconds': 0, 'local_io_seconds': 100, 'seconds': 1850}, 'vm': {'fixed_tail_seconds': 0, 'local_io_seconds': 110, 'seconds': 4120}}, 'schema': 1, 'vm_loop_seconds': 3820}

if __name__=='__main__':main()
