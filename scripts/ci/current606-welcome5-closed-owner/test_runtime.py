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


class FailureRetention(unittest.TestCase):
    """Private inert children and real file guards, never a passing native606 fixture."""
    def record(self, root, *, role='worker', nonce='a'*32, terminal=None, error=None, code=7):
        from types import SimpleNamespace
        return R.failed_role_record(root, role, nonce, [sys.executable, '-I', '-B', '-c', 'INERT_CONTROL'],
                                    SimpleNamespace(process=SimpleNamespace(returncode=code,pid=12345)), terminal, error, 10)

    def tree(self, root, raw=b'original failure\n'):
        (root/'bridge-output').mkdir(mode=0o700)
        (root/'worker.log').write_bytes(raw)

    def test_failure_data_full_capture_hash_tail_and_no_authority(self):
        import base64, hashlib, json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);raw=b'FIRST\n'+bytes(range(256))*400;self.tree(root,raw)
            value=self.record(root);capture=value['capture']
            self.assertEqual(capture['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(base64.b64decode(capture['tail_base64'],validate=True),raw[-8192:])
            self.assertEqual((capture['bytes'],capture['tail_bytes'],capture['omitted_bytes'],capture['truncated']),
                             (len(raw),8192,len(raw)-8192,True))
            path=root/'bridge-output/failed-worker.json';encoded=path.read_bytes()
            self.assertLessEqual(len(encoded),32768);self.assertEqual(json.loads(encoded),value)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(value['acceptance'],'NOT_GRANTED')
            with self.assertRaises(FileExistsError):self.record(root)
            self.assertEqual(path.read_bytes(),encoded)

    def test_failure_data_alias_hardlink_and_wrong_nonce_refused(self):
        for kind in ('symlink','hardlink','fifo','oversize','bad-nonce','unknown-role','receipt-alias'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.tree(root)
                kw={}
                if kind=='symlink':(root/'worker.log').rename(root/'private');(root/'worker.log').symlink_to('private')
                elif kind=='hardlink':os.link(root/'worker.log',root/'alias')
                elif kind=='fifo':(root/'worker.log').unlink();os.mkfifo(root/'worker.log')
                elif kind=='oversize':
                    with (root/'worker.log').open('r+b') as f:f.truncate(16*1024**2+1)
                elif kind=='bad-nonce':kw['nonce']='x'*32
                elif kind=='unknown-role':kw['role']='private/path'
                else:(root/'bridge-output').rename(root/'private-output');(root/'bridge-output').symlink_to('private-output')
                with self.assertRaises((ValueError,OSError)):self.record(root,**kw)
                self.assertFalse((root/'bridge-output/failed-worker.json').exists())

    def test_failure_data_detects_actual_log_mutation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.tree(root,b'x'*90000);original=os.read;changed=[]
            def read(fd,count):
                raw=original(fd,count)
                if raw and not changed:
                    changed.append(True)
                    with (root/'worker.log').open('ab') as stream:stream.write(b'changed')
                return raw
            with patch.object(os,'read',side_effect=read),self.assertRaisesRegex(ValueError,'drift'):
                self.record(root)
            self.assertFalse((root/'bridge-output/failed-worker.json').exists())

    def common(self):
        import importlib.util
        name='_failed_role_held_common'
        spec=importlib.util.spec_from_file_location(name,HERE.parents[2]/'held606/held604/scripts/virtual/common.py')
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value

    def execute(self,root,script,*,timeout=False):
        from unittest.mock import patch
        common=self.common();seen=[]
        class Owned:
            image='sha256:'+'1'*64
            rows=[dict(status='PASS_ABSENCE_VERIFIED')]
            def launch(self,command):
                seen.append(command)
                return [sys.executable,'-I','-B','-c',script]
            def cleanup(self):pass
        self.tree(root,b'')
        (root/'worker.log').unlink()  # Original logger must itself create the capture.
        owner=R.AfterCapture(owned=Owned(),common=common,env=dict(os.environ),image=Owned.image,
                             nonce='a'*32,output=root,owner_deadline=time.monotonic()+20)
        owner.phase='finalized';paths={n:root/n for n in('runner','seed','proof','work','out')}
        error=None
        with patch.dict(R.SECONDS,worker=.08 if timeout else 10):
            try:owner.run('worker',paths)
            except BaseException as caught:error=caught
        self.assertEqual(len(seen),1);self.assertIn('--network=none',seen[0]);return owner,error

    def test_real_inert_failed_child_result_and_existing_refusal_retained(self):
        import base64,json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'import sys;print("OUT",flush=True);print("ERR",file=sys.stderr,flush=True);sys.exit(7)')
            self.assertIsInstance(error,ValueError);self.assertEqual(str(error),'phase failed; receipt cannot authorize continuation')
            self.assertEqual(owner.phase,'retired');self.assertEqual(owner.events[-1]['exit'],'FAILED')
            value=json.loads((root/'bridge-output/failed-worker.json').read_bytes())
            self.assertEqual(value['outcome']['returncode'],7);self.assertEqual(value['outcome']['waitid'],dict(code=os.CLD_EXITED,status=7))
            self.assertEqual(base64.b64decode(value['capture']['tail_base64']),b'OUT\nERR\n')
            self.assertTrue(R.group_absent(owner.events[-1]['pid']))

    def test_real_inert_timeout_original_error_and_retirement_retained(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'import time;print("before-timeout",flush=True);time.sleep(10)',timeout=True)
            self.assertIsNotNone(error);self.assertIn('child terminal deadline',str(error))
            value=json.loads((root/'bridge-output/failed-worker.json').read_bytes())
            self.assertIsNone(value['outcome']['waitid']);self.assertEqual(value['outcome']['returncode'],-9)
            self.assertEqual(value['outcome']['error_type'],type(error).__name__);self.assertEqual(owner.phase,'retired')
            self.assertTrue(R.group_absent(owner.events[-1]['pid']))

    def test_success_does_not_export_failure_or_change_event_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'print("inert success only")')
            self.assertIsNone(error);self.assertEqual(owner.phase,'worker-retired')
            self.assertEqual(set(owner.events[-1]),{'phase','argv','pid','exit','direct_child_reaped','group_absent','containers_absent'})
            self.assertEqual(owner.events[-1]['exit'],0);self.assertEqual(list((root/'bridge-output').iterdir()),[])

    def test_unavailable_diagnostic_never_replaces_original_failure(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(R,'failed_role_record',side_effect=OSError('inert diagnostic unavailable')):
                owner,error=self.execute(root,'raise SystemExit(7)')
            self.assertEqual(str(error),'phase failed; receipt cannot authorize continuation')
            self.assertEqual(owner.events[-1]['exit'],'FAILED');self.assertEqual(list((root/'bridge-output').iterdir()),[])

    def test_small_empty_and_bridge_role_failures_have_exact_counts(self):
        import hashlib,json
        for role,raw in (('finalize',b''),('dispose',b'original disposer failure')):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.tree(root);(root/'worker.log').rename(root/(role+'.log'));(root/(role+'.log')).write_bytes(raw)
                value=self.record(root,role=role);capture=value['capture']
                self.assertEqual(capture['bytes'],len(raw));self.assertEqual(capture['tail_bytes'],len(raw))
                self.assertEqual(capture['omitted_bytes'],0);self.assertIs(capture['truncated'],False)
                self.assertEqual(capture['sha256'],hashlib.sha256(raw).hexdigest())
                self.assertEqual(value['outcome']['pid'],12345)
                self.assertEqual(json.loads((root/('bridge-output/failed-'+role+'.json')).read_bytes()),value)


if __name__ == '__main__':
    unittest.main()
