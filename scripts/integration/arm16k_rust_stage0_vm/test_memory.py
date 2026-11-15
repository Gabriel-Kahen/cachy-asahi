# SPDX-License-Identifier: MIT
"""Private synthetic cgroup files only; no actual cgroup, quota or process use."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location('fenced_memory_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

M,K=load('memory'),load('contracts')
NONCE='a'*32
LIMIT=4*1024**3


def fixture(root):
    c=root/'cgroup';w=root/'output';c.mkdir();w.mkdir()
    (c/'memory.events').write_text('low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n')
    for name in M.COUNTERS:(c/name).write_text(str(LIMIT if name=='memory.max' else 0))
    return c,w


class MemoryControls(unittest.TestCase):
    def test_private_numeric_snapshots_are_durable_exclusive_and_collected(self):
        with tempfile.TemporaryDirectory() as t:
            c,w=fixture(Path(t))
            for stage in M.STAGES:M.snapshot(w,NONCE,stage,LIMIT,c)
            values=M.collect(w,NONCE,LIMIT);self.assertEqual(set(values),set(M.STAGES))
            self.assertTrue(all(v['status']=='OBSERVED' for v in values.values()))
            self.assertTrue(all((w/('memory-'+s+'.json')).stat().st_mode&0o777==0o600 for s in M.STAGES))
            with self.assertRaises(FileExistsError):M.snapshot(w,NONCE,'final',LIMIT,c)

    def test_missing_wrong_unlimited_duplicate_and_symlink_refuse_with_receipt(self):
        for fault in ('missing','wrong','unlimited','duplicate','symlink'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as t:
                c,w=fixture(Path(t))
                if fault=='missing':(c/'memory.peak').unlink()
                if fault=='wrong':(c/'memory.max').write_text(str(3*1024**3))
                if fault=='unlimited':(c/'memory.max').write_text('max')
                if fault=='duplicate':(c/'memory.events').write_text('oom 0\noom 1\n')
                if fault=='symlink':(c/'memory.current').unlink();(c/'memory.current').symlink_to(c/'memory.max')
                with self.assertRaises((OSError,ValueError)):M.snapshot(w,NONCE,'before-vm',LIMIT,c)
                self.assertEqual(json.loads((w/'memory-before-vm.json').read_text())['status'],'REFUSED')

    def test_final_snapshot_attempted_on_exception_no_oom_cause_inferred(self):
        calls=[]
        def observe(*a):calls.append(a[2])
        with patch.object(M,'snapshot',side_effect=observe):
            with self.assertRaisesRegex(ValueError,'fixture failure'):
                with M.receipts(Path('/FENCED_NOT_PRESENT'),NONCE,LIMIT):raise ValueError('fixture failure')
        self.assertEqual(calls,['before-vm','final'])
        with tempfile.TemporaryDirectory() as t:
            c,w=fixture(Path(t));(c/'memory.events').write_text('low 0\nhigh 0\nmax 5\noom 2\noom_kill 1\n')
            row=M.snapshot(w,NONCE,'at-qemu-exit',LIMIT,c)
            self.assertEqual(row['memory.events']['oom_kill'],1);self.assertNotIn('cause',row)

    def test_untrusted_host_receipt_fields_and_modes_refuse(self):
        with tempfile.TemporaryDirectory() as t:
            c,w=fixture(Path(t));M.snapshot(w,NONCE,'before-vm',LIMIT,c)
            path=w/'memory-before-vm.json';path.chmod(0o644)
            with self.assertRaises(ValueError):M.collect(w,NONCE,LIMIT)
            path.chmod(0o600);row=json.loads(path.read_text());row['nonce']='b'*32;path.write_text(json.dumps(row))
            with self.assertRaises(ValueError):M.collect(w,NONCE,LIMIT)

    def test_root_quota_guard_requires_whole_actor_phase_and_full_headroom(self):
        with tempfile.TemporaryDirectory() as t:
            parent=Path(t);auth={'source_lock':{'FENCED':'DATA'},'resource_review':{}}
            with self.assertRaisesRegex(ValueError,'whole-actor'):K.quota_guard(auth,parent,'prepare')
            q=dict(issued_by='Root',status='ROOT_REVIEWED_OWN_UID_QUOTA_GUARD_FOR_ENTIRE_ACTOR',uid=K.os.getuid(),output_parent=str(parent),device=parent.stat().st_dev,phase='prepare',operation=K.OP,source_lock=auth['source_lock'],initial_headroom_bytes=4*1024**3,live_reserve_bytes=2*1024**3,method='READ_ONLY_Q_GETQUOTA',on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP');auth['resource_review']['quota_guard']=q
            self.assertEqual(K.quota_guard(auth,parent,'prepare'),q)
            q['initial_headroom_bytes']=1500*1024**2
            with self.assertRaisesRegex(ValueError,'headroom'):K.quota_guard(auth,parent,'prepare')
            q.update(phase='boot',initial_headroom_bytes=4608*1024**2)
            self.assertEqual(K.quota_guard(auth,parent,'boot'),q)


if __name__=='__main__':unittest.main()
