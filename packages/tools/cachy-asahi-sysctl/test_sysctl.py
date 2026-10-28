# SPDX-License-Identifier: MIT
"""Real temporary-tree changes and crash recovery; never mutate host proc/sys."""
from contextlib import redirect_stdout,redirect_stderr
import argparse
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
options=argparse.ArgumentParser(add_help=False)
options.add_argument('--command-source',type=Path,default=HERE/'cachy-asahi-sysctl')
selected,remaining=options.parse_known_args();sys.argv=[sys.argv[0],*remaining]
SOURCE=selected.command_source.absolute()
loader=importlib.machinery.SourceFileLoader('sysctl_candidate',str(SOURCE))
spec=importlib.util.spec_from_loader(loader.name,loader);s=importlib.util.module_from_spec(spec);loader.exec_module(s)


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='sysctl-product-model-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.root=self.base/'tree';self.root.mkdir(mode=0o700)
        (self.root/'vm').mkdir(mode=0o700);self.leaf=self.root/'vm/swappiness';self.leaf.write_bytes(b'60\n');self.leaf.chmod(0o600)
        random=self.root/'kernel/random';random.mkdir(parents=True,mode=0o700)
        (random/'boot_id').write_bytes(b'12345678-1234-1234-1234-123456789abc\n')
        self.state=self.base/'state';self.state.mkdir(mode=0o700);self.tree=s.Tree(self.root,model=True)

    def plan(self,target=30,name='trial'):
        return s.plan(self.tree,self.state,name,s.KEY,target)

    def operate(self,action,name='trial'):
        return s.operate(self.tree,self.state,name,action)

    def journal(self):return json.loads((self.state/'trial/journal.json').read_text())

    def test_real_plan_apply_inspect_restore_and_repetition(self):
        self.assertEqual(self.plan()['baseline'],60);baseline=(self.state/'trial/plan.json').read_bytes()
        self.assertEqual(self.leaf.read_bytes(),b'60\n')
        self.assertEqual(self.operate('inspect')['observed'],'BASELINE')
        self.assertEqual(self.operate('apply')['status'],'APPLIED');self.assertEqual(self.leaf.read_bytes(),b'30\n')
        self.assertEqual(self.operate('inspect')['observed'],'EXPERIMENT')
        with patch.object(self.tree,'write',side_effect=AssertionError('must not repeat writes')):
            self.assertEqual(self.operate('apply')['status'],'ALREADY_APPLIED')
        self.assertEqual(self.operate('undo')['status'],'UNDONE');self.assertEqual(self.leaf.read_bytes(),b'60\n')
        with patch.object(self.tree,'write',side_effect=AssertionError('must not repeat undo')):
            self.assertEqual(self.operate('undo')['status'],'ALREADY_UNDONE')
        self.assertEqual((self.state/'trial/plan.json').read_bytes(),baseline)
        with self.assertRaises(ValueError):self.operate('apply')

    def test_saved_baseline_outside_candidate_range_restores_exactly(self):
        self.leaf.write_bytes(b'200\n');self.plan(100);self.operate('apply');self.assertEqual(self.leaf.read_bytes(),b'100\n')
        self.operate('undo');self.assertEqual(self.leaf.read_bytes(),b'200\n')

    def test_foreign_change_before_apply_is_preserved(self):
        self.plan();self.leaf.write_bytes(b'45\n')
        with self.assertRaisesRegex(ValueError,'baseline changed'):self.operate('apply')
        self.assertEqual(self.leaf.read_bytes(),b'45\n');self.assertEqual(self.journal()['state'],'PLANNED')

    def test_foreign_change_after_apply_refuses_undo_without_touching_journal(self):
        self.plan();self.operate('apply');held=(self.state/'trial/journal.json').read_bytes();self.leaf.write_bytes(b'77\n')
        self.assertEqual(self.operate('inspect')['observed'],'CONFLICT')
        with self.assertRaisesRegex(ValueError,'conflict preserved'):self.operate('undo')
        self.assertEqual(self.leaf.read_bytes(),b'77\n');self.assertEqual((self.state/'trial/journal.json').read_bytes(),held)

    def test_unapplied_foreign_target_is_not_owned_for_undo(self):
        self.plan();self.leaf.write_bytes(b'30\n')
        with self.assertRaisesRegex(ValueError,'conflict preserved'):self.operate('undo')
        self.assertEqual(self.leaf.read_bytes(),b'30\n')

    def test_write_then_error_retains_intent_and_explicit_undo_recovers(self):
        self.plan();original=self.tree.write
        def interrupted(*args):original(*args);raise OSError('injected after real model write/readback')
        with patch.object(self.tree,'write',side_effect=interrupted):
            with self.assertRaises(OSError):self.operate('apply')
        self.assertEqual(self.leaf.read_bytes(),b'30\n');self.assertEqual(self.journal()['state'],'APPLY_INTENT')
        with self.assertRaisesRegex(ValueError,'interrupted'):self.operate('apply')
        self.operate('undo');self.assertEqual(self.leaf.read_bytes(),b'60\n')

    def test_real_sigkill_after_write_before_commit_is_recoverable(self):
        self.plan()
        code='''import importlib.machinery,importlib.util,os,signal,sys
l=importlib.machinery.SourceFileLoader('sysctl_model',sys.argv[1]);p=importlib.util.spec_from_loader(l.name,l);m=importlib.util.module_from_spec(p);l.exec_module(m)
t=m.Tree(m.Path(sys.argv[2]),model=True);original=t.write
def stop(*args):
 original(*args)
 os.kill(os.getpid(),signal.SIGKILL)
t.write=stop
m.operate(t,m.Path(sys.argv[3]),'trial','apply')
'''
        row=subprocess.run([sys.executable,'-I','-B','-c',code,str(SOURCE),str(self.root),str(self.state)],capture_output=True,timeout=10)
        self.assertEqual(row.returncode,-signal.SIGKILL,row.stderr)
        self.assertEqual(self.journal()['state'],'APPLY_INTENT');self.assertEqual(self.leaf.read_bytes(),b'30\n')
        self.assertEqual(self.operate('inspect')['status'],'APPLY_INTENT')
        self.operate('undo');self.assertEqual(self.leaf.read_bytes(),b'60\n')

    def test_interrupted_undo_is_idempotently_finished(self):
        self.plan();self.operate('apply');original=self.tree.write
        def interrupted(*args):original(*args);raise OSError('after real restore')
        with patch.object(self.tree,'write',side_effect=interrupted):
            with self.assertRaises(OSError):self.operate('undo')
        self.assertEqual(self.journal()['state'],'UNDO_INTENT');self.assertEqual(self.leaf.read_bytes(),b'60\n')
        with patch.object(self.tree,'write',side_effect=AssertionError('baseline already restored')):
            self.assertEqual(self.operate('undo')['status'],'UNDONE')

    def test_stale_file_identity_refuses_before_write(self):
        self.plan();old=self.root/'vm/previous';self.leaf.rename(old);self.leaf.write_bytes(b'60\n');self.leaf.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'identity differs'):self.operate('apply')
        self.assertEqual(self.leaf.read_bytes(),b'60\n');self.assertEqual(old.read_bytes(),b'60\n')

    def test_new_boot_refuses_saved_experiment_even_when_value_inode_match(self):
        self.plan();self.operate('apply')
        (self.root/'kernel/random/boot_id').write_bytes(b'23456789-1234-1234-1234-123456789abc\n')
        with self.assertRaisesRegex(ValueError,'identity differs'):self.operate('undo')
        self.assertEqual(self.leaf.read_bytes(),b'30\n')

    def test_links_special_files_and_directory_aliases_refused(self):
        self.leaf.unlink();outside=self.base/'outside';outside.write_bytes(b'60\n');outside.chmod(0o600)
        self.leaf.symlink_to(outside)
        with self.assertRaises(OSError):self.plan()
        self.leaf.unlink();os.link(outside,self.leaf)
        with self.assertRaises(ValueError):self.plan()
        self.leaf.unlink();os.mkfifo(self.leaf,0o600)
        with self.assertRaises(ValueError):self.plan()
        alias=self.base/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):s.plan(s.Tree(alias,model=True),self.state,'alias',s.KEY,30)
        self.assertEqual(outside.read_bytes(),b'60\n')

    def test_private_store_lock_excludes_another_call(self):
        self.plan()
        with s.store(self.state,'trial'):
            with self.assertRaises(BlockingIOError):self.operate('apply')
        self.assertEqual(self.leaf.read_bytes(),b'60\n')

    def test_unknown_keys_values_names_and_available_missing_key(self):
        for key,target in [('kernel.printk',1),(s.KEY,-1),(s.KEY,101),(s.KEY,True)]:
            with self.assertRaises(ValueError):s.plan(self.tree,self.state,'invalid',key,target)
        for name in ('../escape','Bad','a'*49):
            with self.assertRaises(ValueError):self.plan(name=name)
        self.leaf.unlink()
        with self.assertRaises(FileNotFoundError):self.plan()
        self.assertFalse((self.state/'trial').exists())

    def test_malformed_or_oversized_values_refuse(self):
        for raw in (b'060\n',b'1 2\n',b'-1\n',b'30',b'4294967296\n',b'9'*65+b'\n'):
            self.leaf.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.plan()

    def test_tampered_baseline_or_journal_refuses(self):
        self.plan();plan=self.state/'trial/plan.json';original=plan.read_bytes()
        v=json.loads(original);v['baseline']=15;plan.write_text(json.dumps(v))
        with self.assertRaisesRegex(ValueError,'binding differs'):self.operate('apply')
        plan.write_bytes(original);journal=self.state/'trial/journal.json';journal.write_text('{"schema_version":1,"state":"PLANNED","state":"APPLIED"}')
        with self.assertRaisesRegex(ValueError,'duplicate'):self.operate('apply')
        self.assertEqual(self.leaf.read_bytes(),b'60\n')

    def test_state_permissions_links_and_existing_plan_preserved(self):
        self.state.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'private'):self.plan()
        self.state.chmod(0o700);self.plan();before=(self.state/'trial/plan.json').read_bytes()
        with self.assertRaises(FileExistsError):self.plan(50)
        self.assertEqual((self.state/'trial/plan.json').read_bytes(),before)
        os.link(self.state/'trial/plan.json',self.base/'linked-plan')
        with self.assertRaises(ValueError):self.operate('apply')

    def test_noop_does_not_write_and_expired_intent_stays_recoverable(self):
        self.plan(60)
        with patch.object(self.tree,'write',side_effect=AssertionError('noop write')):
            self.operate('apply');self.operate('undo')
        self.plan(30,'expired')
        with patch.object(s.time,'monotonic',side_effect=[0,1,6]):
            with self.assertRaisesRegex(ValueError,'deadline expired'):self.operate('apply','expired')
        self.assertEqual(self.leaf.read_bytes(),b'60\n')
        self.assertEqual(json.loads((self.state/'expired/journal.json').read_text())['state'],'APPLY_INTENT')
        self.operate('undo','expired')

    def test_real_cli_route_on_model_has_no_root_override_or_live_writes(self):
        output,error=io.StringIO(),io.StringIO()
        with redirect_stdout(output),redirect_stderr(error):
            self.assertEqual(s.main(['keys'],tree=self.tree),0)
            self.assertEqual(json.loads(output.getvalue())['status'],'AVAILABLE')
        for action,extra in [('plan',['--key',s.KEY,'--value','25']),('inspect',[]),('apply',[]),('undo',[])]:
            with redirect_stdout(io.StringIO()),redirect_stderr(error):
                self.assertEqual(s.main([action,'--state',str(self.state),'--name','cli',*extra],tree=self.tree),0)
        self.assertEqual(self.leaf.read_bytes(),b'60\n')
        with redirect_stderr(error),self.assertRaises(SystemExit):s.main(['keys','--root',str(self.root)],tree=self.tree)
        with self.assertRaises(ValueError):s.Tree(s.LIVE,model=True)

    def test_original_source_license_provenance(self):
        provenance=json.loads((HERE/'source-provenance.json').read_text())
        self.assertEqual(provenance['implementation'],'ORIGINAL_PROJECT_SOURCE')
        self.assertEqual(provenance['license'],'MIT')
        for name,row in provenance['files'].items():
            raw=(SOURCE if name=='cachy-asahi-sysctl' else HERE/name).read_bytes()
            self.assertEqual(row,dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))


if __name__=='__main__':unittest.main(verbosity=2)
