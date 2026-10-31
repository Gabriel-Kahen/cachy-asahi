"""Fresh owned Python/subreaper fixtures for the opt-in retirement profile.

Fault injections model ownership loss or conflicting DATA; they are not native
observations. Fixture cleanup has its own known-child ledger and exact WNOWAIT
waits. No broad wait, historical PID, package, GPG, VM or network actor is used.
"""
import contextlib
import contextvars
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    '_new_owned_adopted_core', ROOT / 'scripts/virtual/owned_process_retirement_v2.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
WAITID, WAITPID, SCANDIR, STAT = os.waitid, os.waitpid, os.scandir, R._stat
ACTIVE = contextvars.ContextVar('owned_adopted_fixture', default=False)


def actor_fence(event, args):
    if not ACTIVE.get():
        return
    if event == 'subprocess.Popen':
        executable, argv, cwd, env = args
        if executable != '/usr/bin/python3' or argv[:3] != ['/usr/bin/python3', '-I', '-B']:
            raise ValueError('only isolated fresh Python fixture children')
    elif event.startswith('socket.') or event in {
            'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec'}:
        raise ValueError('owned Python fixtures only')


sys.addaudithook(actor_fence)


class OwnedFixture:
    def __init__(self, case, exits):
        self.case, self.exits = case, exits
        self.child = None
        self.extra = []
        self.consumed = set()
        self.cleanup = []

    def start(self):
        R.prepare()
        code = '''import json,os,subprocess,time
children=[subprocess.Popen(['/usr/bin/python3','-I','-B','-c','import os;os._exit('+str(code)+')']) for code in EXITS]
print(json.dumps([c.pid for c in children]),flush=True)
limit=time.monotonic()+3
while any(os.waitid(os.P_PID,c.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG) is None for c in children):
 if time.monotonic()>=limit:os._exit(90)
 time.sleep(.002)
os._exit(0)
'''.replace('EXITS', repr(self.exits))
        self.child = subprocess.Popen(
            ['/usr/bin/python3', '-I', '-B', '-c', code],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,
            env=dict(PATH='/usr/bin:/bin', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1'))
        ready, _, _ = select.select([self.child.stdout], [], [], 5)
        self.case.assertTrue(ready, 'fresh fixture PID ledger readiness')
        self.extra = json.loads(self.child.stdout.readline())
        self.case.assertEqual(len(self.extra), len(self.exits))
        return self

    def finish(self):
        return R.supervise(self.child, cap=8, retirement=1, grace=.2)

    def close(self):
        # Source spies are already removed. The isolated fixture owns only these
        # explicitly created/adopted children; each unfinished entry is reserved
        # again with the real kernel API before its exact consuming wait.
        if self.child is None:
            return
        for pid in [*self.extra, self.child.pid]:
            if pid in self.consumed:
                continue
            limit = time.monotonic() + 3
            while True:
                row = WAITID(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if row is not None:
                    break
                self.case.assertLess(time.monotonic(), limit, 'fixture cleanup deadline')
                time.sleep(.002)
            self.case.assertEqual(row.si_pid, pid)
            got, status = WAITPID(pid, os.WNOHANG)
            self.case.assertEqual(got, pid)
            code = row.si_status if row.si_code == os.CLD_EXITED else -row.si_status
            self.case.assertEqual(os.waitstatus_to_exitcode(status), code)
            self.consumed.add(pid)
            self.cleanup.append(pid)
            if pid == self.child.pid:
                self.child.returncode = code
        if self.child.stdout is not None:
            self.child.stdout.close()


class Spy:
    """Observe Source calls; fixture cleanup runs outside this ownership scope."""
    def __init__(self, case, fixture, mode=None):
        self.case, self.f, self.mode = case, fixture, mode
        self.events, self.violations = [], []
        self.extra_waitable = False
        self.extra_lost = False
        self.extra_stat_calls = 0
        self.synthetic_initial = False
        self.stack = contextlib.ExitStack()

    @property
    def target(self):
        return self.f.extra[0] if self.f.extra else None

    def guard(self, op, pid=None):
        why = None
        if self.f.child.pid in self.f.consumed:
            why = op + ' after leader consumption/ECHILD'
        elif pid == self.target and (pid in self.f.consumed or self.extra_lost):
            why = op + ' after extra consumption/ECHILD'
        if why:
            self.violations.append(why)
            raise AssertionError(why)
        self.events.append((op, pid))

    def waitid(self, kind, pid, options):
        self.guard('waitid', pid)
        if pid not in [self.f.child.pid, *self.f.extra]:
            self.violations.append('foreign waitid target')
            raise AssertionError('foreign waitid target')
        self.case.assertEqual(kind, os.P_PID)
        self.case.assertTrue(options & os.WNOWAIT)
        if pid == self.target and self.mode == 'extra-echild':
            # A modeled competing reaper consumes a genuinely reserved fixture
            # child before this Source acquisition returns ECHILD.
            row = WAITID(kind, pid, options)
            self.case.assertIsNotNone(row)
            got, status = WAITPID(pid, os.WNOHANG)
            self.case.assertEqual(got, pid)
            self.f.consumed.add(pid)
            self.extra_lost = True
            raise ChildProcessError('fixture competing reaper')
        if pid == self.f.child.pid and self.mode == 'leader-echild' and self.extra_waitable:
            row = WAITID(kind, pid, options)
            self.case.assertIsNotNone(row)
            got, status = WAITPID(pid, os.WNOHANG)
            self.case.assertEqual(got, pid)
            self.f.consumed.add(pid)
            raise ChildProcessError('fixture competing leader reaper')
        row = WAITID(kind, pid, options)
        if pid == self.target and row is not None:
            self.extra_waitable = True
        return row

    def waitpid(self, pid, options):
        self.guard('waitpid', pid)
        if pid not in [self.f.child.pid, *self.f.extra]:
            self.violations.append('broad or foreign waitpid target')
            raise AssertionError('broad or foreign waitpid target')
        self.case.assertGreater(pid, 0, 'no broad child wait')
        got, status = WAITPID(pid, options)
        if got > 0:
            self.f.consumed.add(got)
            self.events.append(('RAW_CONSUMED', got))
        if pid == self.target and self.mode == 'raw-status-mismatch' and got == pid:
            return got, status ^ 0x100
        if pid == self.target and self.mode == 'raw-echild' and got == pid:
            self.extra_lost = True
            raise ChildProcessError('fixture raw-wait ownership loss')
        return got, status

    def stat(self, pid, **kwargs):
        self.guard('stat', pid)
        row = STAT(pid, **kwargs)
        if pid == self.target:
            self.extra_stat_calls += 1
            if self.mode == 'identity-mismatch' and self.extra_waitable:
                row = (*row[:4], row[4] + 1, *row[5:])
        return row

    def scan(self, path):
        self.guard('scandir')
        if self.mode == 'retired-pid-listed' and self.target in self.f.consumed and path == '/proc':
            with SCANDIR(path) as entries:
                rows = list(entries)
            rows.insert(0, types.SimpleNamespace(name=str(self.target)))
            class Entries:
                def __enter__(self):
                    return iter(rows)
                def __exit__(self, *args):
                    return False
            return Entries()
        return SCANDIR(path)

    def signal(self, pid, sig):
        self.guard('signal', pid)
        self.violations.append('unexpected signal to terminal fixture')
        self.case.fail('these terminal fixtures require no signal')

    def __enter__(self):
        for obj, name, value in ((R.os, 'waitid', self.waitid), (R.os, 'waitpid', self.waitpid),
                                 (R, '_stat', self.stat), (R.os, 'scandir', self.scan),
                                 (R.os, 'kill', self.signal), (R.os, 'killpg', self.signal)):
            self.stack.enter_context(patch.object(obj, name, side_effect=value))
        if self.mode in ('foreign-ppid', 'live-extra'):
            scan = R._rss_members
            def changed(pid, deadline, owned, parentage=None, **kwargs):
                result = scan(pid, deadline, owned, parentage=parentage, **kwargs)
                if parentage is not None and self.target in result and not self.synthetic_initial:
                    self.synthetic_initial = True
                    if self.mode == 'foreign-ppid':
                        parentage[self.target] = os.getpid() + 1
                    else:
                        result[self.target]['state'] = 'S'
                return result
            self.stack.enter_context(patch.object(R, '_rss_members', side_effect=changed))
        return self

    def __exit__(self, *args):
        self.stack.close()
        self.case.assertEqual(self.violations, [])
        return False


class AdoptedZombie(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != 'linux':
            raise unittest.SkipTest('Linux WNOWAIT/subreaper fixture')
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.prctl = cls.libc.prctl
        cls.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_ulong, ctypes.c_ulong]
        cls.prctl.restype = ctypes.c_int
        previous = ctypes.c_int()
        if cls.prctl(37, ctypes.addressof(previous), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_GET_CHILD_SUBREAPER fixture')
        cls.previous_subreaper = previous.value
        if cls.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER fixture')

    @classmethod
    def tearDownClass(cls):
        if cls.prctl(36, cls.previous_subreaper, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'restore fixture subreaper state')

    def setUp(self):
        self.actor_token = ACTIVE.set(True)

    def tearDown(self):
        ACTIVE.reset(self.actor_token)

    @contextlib.contextmanager
    def fixture(self, exits=(0,)):
        f = OwnedFixture(self, list(exits))
        try:
            yield f.start()
        finally:
            f.close()

    def check_refused(self, result):
        self.assertFalse(result['passed'])
        self.assertNotEqual(result['group_census'], 'EMPTY_ONCE')
        self.assertNotEqual(result['group_census'], 'EMPTY_TWICE')

    def test_real_adopted_zombie_is_qualified_reaped_then_freshly_censused(self):
        with self.fixture() as f:
            with Spy(self, f) as s:
                result = f.finish()
            self.assertTrue(result['passed'], result)
            self.assertEqual(result['group_census'], 'RESERVED_LEADER_ONLY')
            snapshot = result['group_retirement']
            self.assertEqual(snapshot['member_count'], 1)
            self.assertFalse(snapshot['truncated'])
            proof = snapshot['adopted_child']
            self.assertEqual(proof['status'], 'QUALIFIED_ONE_ADOPTED_CHILD_REAPED')
            self.assertEqual(proof['candidate']['pid'], f.extra[0])
            self.assertEqual(proof['candidate']['ppid'], os.getpid())
            self.assertEqual(proof['candidate']['state'], 'Z')
            self.assertEqual(proof['initial_member_count'], 2)
            self.assertTrue(proof['initial_scan_complete'])
            self.assertEqual(proof['waitid'], dict(observed=True, pid=f.extra[0], code='CLD_EXITED', status=0))
            self.assertTrue(proof['identity_reverified'])
            self.assertTrue(proof['leader_reserved_before_reap'])
            self.assertEqual(proof['raw_reap'], dict(attempted=True, pid=f.extra[0], exit=0, status_matches=True))
            self.assertEqual(proof['ownership'], 'REAPED')
            self.assertTrue(proof['target_queries_closed'])
            self.assertTrue(proof['before_leader_reap'])
            self.assertEqual(proof['final_census'], 'RESERVED_LEADER_ONLY')
            self.assertIs(proof['final_scan_complete'], True)
            self.assertEqual(proof['refusal'], 'NONE')
            consumed = [pid for op, pid in s.events if op == 'RAW_CONSUMED']
            self.assertEqual(consumed, [f.extra[0], f.child.pid])
            self.assertEqual(f.cleanup, [])

    def test_sole_leader_still_qualifies_without_adoption_attempt(self):
        with self.fixture(()) as f:
            with Spy(self, f):
                result = f.finish()
            self.assertTrue(result['passed'], result)
            self.assertNotIn('adopted_child', result['group_retirement'])

    def test_default_stat_keeps_five_fields_and_optional_parent_is_same_identity(self):
        with self.fixture(()) as f:
            limit = time.monotonic() + 3
            while WAITID(os.P_PID, f.child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
                self.assertLess(time.monotonic(), limit)
                time.sleep(.002)
            default = R._stat(f.child.pid)
            parent = R._stat(f.child.pid, with_parent=True)
            self.assertEqual(len(default), 5)
            self.assertEqual(parent[:5], default)
            self.assertEqual(parent[5], os.getpid())
            with Spy(self, f):
                result = f.finish()
            self.assertTrue(result['passed'], result)

    def test_default_rss_member_rows_keep_their_five_field_contract(self):
        with self.fixture(()) as f:
            limit = time.monotonic() + 3
            def owned():
                row = WAITID(os.P_PID, f.child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if row is not None:
                    self.assertEqual(row.si_pid, f.child.pid)
                return row is not None
            while not owned():
                self.assertLess(time.monotonic(), limit)
                time.sleep(.002)
            before = R._rss_members(f.child.pid, time.monotonic() + 2, owned)
            parentage = {}
            selected = R._rss_members(f.child.pid, time.monotonic() + 2, owned, parentage=parentage)
            self.assertEqual(before, selected)
            self.assertEqual(set(before), {f.child.pid})
            self.assertEqual(set(before[f.child.pid]), {'pid', 'state', 'group', 'session', 'start_ticks'})
            self.assertEqual(parentage, {f.child.pid: os.getpid()})
            with Spy(self, f):
                result = f.finish()
            self.assertTrue(result['passed'], result)

    def test_two_adopted_children_still_fail_and_are_not_consumed_by_source(self):
        with self.fixture((0, 0)) as f:
            with Spy(self, f) as s:
                result = f.finish()
            self.check_refused(result)
            self.assertEqual(result['group_census'], 'RESERVED_MEMBERS_REMAIN')
            self.assertFalse(any(op == 'waitid' and pid in f.extra for op, pid in s.events))
            self.assertTrue(all(pid not in f.consumed for pid in f.extra))

    def test_nonzero_adopted_exit_cannot_qualify(self):
        with self.fixture((7,)) as f:
            with Spy(self, f):
                result = f.finish()
            self.check_refused(result)
            proof = result['group_retirement']['adopted_child']
            self.assertEqual(proof['status'], 'REFUSED_ONE_ADOPTED_CHILD')
            self.assertNotEqual(proof['refusal'], 'NONE')

    def test_synthetic_foreign_parent_never_acquires_wait_authority(self):
        with self.fixture() as f:
            with Spy(self, f, 'foreign-ppid') as s:
                result = f.finish()
            self.check_refused(result)
            self.assertFalse(any(op == 'waitid' and pid == f.extra[0] for op, pid in s.events))

    def test_synthetic_live_member_is_not_adopted_or_ignored(self):
        with self.fixture() as f:
            with Spy(self, f, 'live-extra') as s:
                result = f.finish()
            self.check_refused(result)
            self.assertFalse(any(op == 'waitid' and pid == f.extra[0] for op, pid in s.events))

    def test_extra_echild_closes_target_without_followup(self):
        with self.fixture() as f:
            with Spy(self, f, 'extra-echild'):
                result = f.finish()
            self.check_refused(result)
            self.assertIn(f.extra[0], f.consumed)

    def test_identity_mismatch_after_wnowait_prevents_consumption(self):
        with self.fixture() as f:
            with Spy(self, f, 'identity-mismatch') as s:
                result = f.finish()
            self.check_refused(result)
            self.assertTrue(s.extra_waitable)
            self.assertNotIn(f.extra[0], f.consumed)

    def test_mismatched_raw_status_never_qualifies(self):
        with self.fixture() as f:
            with Spy(self, f, 'raw-status-mismatch'):
                result = f.finish()
            self.check_refused(result)
            self.assertIn(f.extra[0], f.consumed)

    def test_raw_echild_has_no_target_followup(self):
        with self.fixture() as f:
            with Spy(self, f, 'raw-echild'):
                result = f.finish()
            self.check_refused(result)
            self.assertIn(f.extra[0], f.consumed)

    def test_retired_pid_enumeration_is_refused_before_stat(self):
        with self.fixture() as f:
            with Spy(self, f, 'retired-pid-listed'):
                result = f.finish()
            self.check_refused(result)
            self.assertIn(f.extra[0], f.consumed)
            self.assertEqual(result['group_census'], 'UNKNOWN')

    def test_leader_echild_while_extra_reserved_stops_all_source_actions(self):
        with self.fixture() as f:
            with Spy(self, f, 'leader-echild') as s:
                result = f.finish()
            self.check_refused(result)
            self.assertTrue(s.extra_waitable)
            self.assertIn(f.child.pid, f.consumed)
            self.assertNotIn(f.extra[0], f.consumed)
            self.assertEqual(result['ownership'], 'UNKNOWN')


    def test_real_foreign_exit73_sentinel_stays_reserved(self):
        R.prepare()
        foreign = subprocess.Popen(
            ['/usr/bin/python3', '-I', '-B', '-c', 'import os;os._exit(73)'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
            env=dict(PATH='/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1'))
        open_custody = True

        def reserve():
            nonlocal open_custody
            self.assertTrue(open_custody, 'foreign query after closure')
            try:
                return WAITID(os.P_PID, foreign.pid,
                              os.WEXITED | os.WNOWAIT | os.WNOHANG)
            except ChildProcessError:
                open_custody = False
                foreign._child_created = False
                raise

        try:
            limit = time.monotonic() + 3
            while reserve() is None:
                self.assertLess(time.monotonic(), limit, 'foreign readiness')
                time.sleep(.002)
            with self.fixture() as f:
                # Spy rejects broad or foreign waits before transparently
                # delegating each permitted exact call to the real kernel.
                with Spy(self, f) as spy:
                    result = f.finish()
                self.assertTrue(result['passed'], result)
                proof = result['group_retirement']['adopted_child']
                self.assertEqual(proof['status'],
                                 'QUALIFIED_ONE_ADOPTED_CHILD_REAPED')
                consumed = [pid for op, pid in spy.events
                            if op == 'RAW_CONSUMED']
                self.assertEqual(consumed, [f.extra[0], f.child.pid])
                self.assertNotIn(foreign.pid, consumed)
                held = reserve()
                self.assertIsNotNone(held)
                self.assertEqual((held.si_pid, held.si_code, held.si_status),
                                 (foreign.pid, os.CLD_EXITED, 73))
        finally:
            if open_custody:
                held = reserve()
                self.assertIsNotNone(held)
                self.assertEqual((held.si_pid, held.si_code, held.si_status),
                                 (foreign.pid, os.CLD_EXITED, 73))
                open_custody = False  # Close queries before the one raw wait.
                foreign._child_created = False
                got, status = WAITPID(foreign.pid, os.WNOHANG)
                self.assertEqual(got, foreign.pid)
                self.assertEqual(os.waitstatus_to_exitcode(status), 73)
                foreign.returncode = 73


if __name__ == '__main__':
    unittest.main(verbosity=2)
