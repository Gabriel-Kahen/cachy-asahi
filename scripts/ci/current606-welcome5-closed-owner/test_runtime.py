import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import runtime as R
import selection as S


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


class Runtime(unittest.TestCase):
    def test_extended_api_remains_unbound_before_lease_or_map_io(self):
        for role in S.CAPS:
            with self.assertRaises(ValueError):
                S.verify_actor(dict(schema_version=1, purpose=S.PURPOSE, status='UNBOUND'), role, '2' * 32)
        with self.assertRaises(ValueError):
            S.lease(dict(identity=[1, 2], uid=0, gid=0, mode=0o700))
        with self.assertRaises(ValueError):
            S.retired(dict(nonce='2' * 32, prior_consumers_absent=True), 'finalizer', '2' * 32)

    def test_failed_original_retirement_context_authorizes_disposal_only(self):
        # Schema control only: no source decision, actor or accepted606 fixture.
        value = dict(nonce='2' * 32, prior_consumers_absent=True,
                     processes=[dict(phase='original606', pid=12345, returncode=1,
                                     direct_child_reaped=True, group_absent=True)],
                     containers=[dict(name='cachy-asahi-schema-fixture-' + str(i),
                                      status='PASS_ABSENCE_VERIFIED', id=format(i, '064x')) for i in range(9)])
        self.assertEqual(S.retired(value, 'dispose', '2' * 32), value)
        for role in ('finalizer', 'copy-worker8'):
            with self.assertRaises(ValueError):
                S.retired(value, role, '2' * 32)

    def test_actual_worker_mounts_match_independent_worker_guard(self):
        source = HERE.parents[2] / 'copyworker/scripts/ci/current606-welcome5-copy/contract.py'
        guard = module('_runtime_independent_copy_contract', source)
        paths = {n: Path('/owned') / n for n in ('runner', 'seed', 'proof', 'work', 'out')}
        command = R.argv('worker', 'sha256:' + '1' * 64, '2' * 32, paths)
        rows = []
        for i, token in enumerate(command):
            if token != '--mount':
                continue
            parts = command[i + 1].split(',')
            fields = dict(p.split('=', 1) for p in parts if '=' in p)
            rows.append(dict(source=fields['src'], target=fields['dst'], readonly='readonly' in parts))
        self.assertTrue(guard.bindings(rows))
        self.assertEqual(tuple(x.split('=', 1)[1] for x in command if x.startswith('--cap-add=')), guard.WORKER_CAPS)
        self.assertIn('--network=none', command)
        self.assertNotIn('--privileged', command)
        self.assertNotIn('--rm', command)
        rows[-1]['readonly'] = True
        with self.assertRaises(ValueError):
            guard.bindings(rows)

    def test_bridge_roles_share_exact_five_caps_and_fixed_inputs(self):
        paths = {n: Path('/owned') / n for n in ('runner', 'measurement', 'selection', 'out')}
        for role in ('finalize', 'dispose'):
            command = R.argv(role, 'sha256:' + '1' * 64, '2' * 32, paths)
            self.assertEqual(sum(x.startswith('--cap-add=') for x in command), 5)
            self.assertIn('/runner/bridge-code', command)
            self.assertIn('/bridge-input/selection.json', command)
            self.assertNotIn('--cap-add=SYS_ADMIN', command)
        paths['out'] = Path('/owned/comma,readonly')
        with self.assertRaises(ValueError):
            R.argv('dispose', 'sha256:' + '1' * 64, '2' * 32, paths)

    def test_real_directory_lease_rejects_replacement_and_nonempty(self):
        with tempfile.TemporaryDirectory(dir=HERE) as t:
            p = Path(t) / 'measurement'
            p.mkdir(mode=0o700)
            lease = R.measurement_lease(p)
            (p / 'unretired').write_bytes(b'x')
            with self.assertRaises(ValueError):
                R.measurement_lease(p)
            (p / 'unretired').unlink()
            p.rename(p.with_name('old'))
            p.mkdir(mode=0o700)
            self.assertNotEqual(R.measurement_lease(p)['identity'], lease['identity'])

    def test_real_child_reservation_reap_and_group_absence(self):
        # The production owner uses the held WNOWAIT implementation rather than
        # process.wait followed by a mutating signal to an unreserved numeric PID.
        common = module('_runtime_held_common', HERE.parents[2] / 'held606/held604/scripts/virtual/common.py')
        with tempfile.TemporaryDirectory(dir=HERE) as t:
            child = common.LoggedProcess([sys.executable, '-I', '-B', '-c', 'print("ready")'],
                                         Path(t) / 'child.log', owner_signals_only=True)
            terminal = common.await_terminal(child.process, time.monotonic() + 10)
            self.assertIsNone(child.process.returncode)
            self.assertEqual((terminal.si_code, terminal.si_status), (os.CLD_EXITED, 0))
            self.assertEqual(common.reap(child.process, verify_absence=True), 0)
            child.finish()
            self.assertTrue(R.group_absent(child.process.pid))
            self.assertEqual((Path(t) / 'child.log').read_bytes(), b'ready\n')

    def test_unretired_original_cannot_launch_postcapture_actor(self):
        class Owned:
            image = 'sha256:' + '1' * 64
            rows = []
            def launch(self, argv):
                raise AssertionError('must refuse before actor creation')
        with tempfile.TemporaryDirectory(dir=HERE) as t:
            owner = R.AfterCapture(owned=Owned(), common=None, env={}, image=Owned.image,
                                   nonce='2' * 32, output=Path(t), owner_deadline=time.monotonic() + 10)
            with self.assertRaises(ValueError):
                owner.run('worker', {})
            with self.assertRaises(ValueError):
                owner.run('finalize', {})


if __name__ == '__main__':
    unittest.main()
