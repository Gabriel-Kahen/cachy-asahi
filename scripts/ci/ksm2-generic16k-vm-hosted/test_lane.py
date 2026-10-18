#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source/emission/refusal controls; no accepting component or VM fixture."""
import argparse,copy,json,os,signal,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import hosted as O,prepare,retain,owner,cleanup,entry
ROOT=None
class Source(unittest.TestCase):
 def test_whole605_role_and_alias(self):
  O.files(ROOT);role=O.decode(O.read(ROOT/O.LANE/'runtime-role.json'));self.assertEqual(len(role['files']),605)
  self.assertEqual({p.relative_to(ROOT/'runtime').as_posix():O.pin(O.read(p))for p in(ROOT/'runtime').rglob('*')if p.is_file()},role['files'])
 def test_popen_blocked_default_preflight(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')):r=entry.preflight(ROOT)
  self.assertEqual(r['actual_run'],None);self.assertEqual(r['runtime']['actual_sysfs'],'NOT_RUN')
 def test_real_emitter_byte_equality(self):
  with tempfile.TemporaryDirectory()as d:
   out=Path(d)/'source'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('source emitter no process')):prepare.assemble(ROOT/'runtime',out,None if O.policy(ROOT)==O.defaults()else ROOT/O.LANE/'input-policy.json')
   self.assertEqual({p.relative_to(out).as_posix():O.pin(O.read(p))for p in out.rglob('*')if p.is_file()},{p.relative_to(ROOT).as_posix():O.pin(O.read(p))for p in ROOT.rglob('*')if p.is_file()and p.relative_to(ROOT).parts[0]not in('.git','.ci-inputs')})
 def test_default_before_io_or_actor(self):
  v=O.defaults()
  with patch.object(O,'read',side_effect=AssertionError('must refuse before IO')),patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):O.components(ROOT,v,{},Path('/unsupplied'),Path('/unsupplied'),Path('/unsupplied'))
 def test_missing_each_selector(self):
  v=O.defaults()
  # No Root decision fixture: only inert syntactic selector values.
  v.update(native_carrier='0'*40,kernel_carrier='1'*40,kernel_run=1)
  for k,path in [('native_inputs','index.json'),('native_decision','Root-acceptance.json'),('kernel_authority','kernel/Root-acceptance.json'),('kernel_transport','kernel/original-transport.json'),('kernel_build','kernel/kernel-artifacts.json')]:v[k]=dict(path=path,bytes=1,sha256='0'*64)
  for k in('native_carrier','kernel_carrier','native_decision','native_inputs','kernel_authority','kernel_transport','kernel_build','kernel_run'):
   bad=copy.deepcopy(v);bad[k]=None
   with self.assertRaisesRegex(ValueError,'UNBOUND'):O.selected(bad)
  for key,value in [('native_carrier','moving-branch'),('kernel_run',True),('actual_run',1)]:
   bad=copy.deepcopy(v);bad[key]=value
   with self.assertRaises(ValueError):O.selected(bad)
  for path in('outside/kernel-artifacts.json','kernel/../kernel-artifacts.json','/kernel/a'):
   bad=copy.deepcopy(v);bad['kernel_build']['path']=path
   with self.assertRaises(ValueError):O.selected(bad)
 def test_duplicate_or_nonfinite_json(self):
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):O.decode(raw)
 def test_source_symlink_or_hardlink_refused(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'a';p.write_bytes(b'x');q=Path(d)/'b';q.symlink_to(p)
   with self.assertRaises(ValueError):O.read(q)
   q.unlink();os.link(p,q)
   with self.assertRaises(ValueError):O.read(p)
 def test_changed_runtime_refused_before_output(self):
  with tempfile.TemporaryDirectory()as d:
   out=Path(d)/'source';fake=Path(d)/'fake';fake.mkdir();(fake/'host.py').write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'whole605'):prepare.assemble(fake,out)
   self.assertFalse(out.exists())
 def test_retention_whitelist_and_actual_pin(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d)/'work';w.mkdir(mode=0o700);(w/'owner-result.json').write_bytes(b'{}\n');(w/'private-map.json').write_bytes(b'NEVER_EXPORT');out=Path(d)/'public';r=retain.run(w,out)
   self.assertEqual(set(r['files']),{'owner-result.json'});self.assertFalse((out/'private-map.json').exists());self.assertEqual(O.pin((out/'owner-result.json').read_bytes()),r['files']['owner-result.json'])
 def test_retention_symlink_refusal(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d)/'work';w.mkdir(mode=0o700);(w/'owner-result.json').symlink_to('/dev/null');out=Path(d)/'public'
   with self.assertRaises(ValueError):retain.run(w,out)
   self.assertFalse(out.exists())
 def test_unknown_group_blocks_cleanup(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d);(w/'commands.json').write_bytes(O.encoded([dict(group_absence_verified=False)]))
   with patch.object(subprocess,'Popen',side_effect=AssertionError('must not invoke Docker')):
    with self.assertRaisesRegex(ValueError,'groups'):cleanup.groups(w)
 def test_missing_qemu_wait_blocks_cleanup(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d);(w/'commands.json').write_bytes(O.encoded([dict(group_absence_verified=True)]));(w/'owner-result.json').write_bytes(O.encoded(dict(phase='VM')))
   with self.assertRaisesRegex(ValueError,'QEMU launch/wait'):cleanup.groups(w)
 def test_exact_secrets_and_bounds(self):
  self.assertEqual(len(owner.SECRET_NAMES),24);self.assertEqual(len(set(owner.SECRET_NAMES)),24);self.assertTrue(all(n.startswith(('CACHY_OLD_FOUR_','CACHY_RETAINED_BUBBLEWRAP_V1_'))for n in owner.SECRET_NAMES));self.assertEqual(O.BOUNDS,dict(owner_seconds=6600,producer_seconds=2300,seed_seconds=120,prepare_seconds=1900,VM_seconds=3000,QEMU_output_bytes=16777216,public_output_bytes=201326592))
 def test_source_owned_workflow_order(self):
  text=O.workflow(ROOT).decode();steps=['Exact source proof','Source factory','Require both published','Exact component DATA','Bounded disposable runner','Original574 producer','Retain bounded']
  self.assertEqual([text.index(s)for s in steps],sorted(text.index(s)for s in steps));self.assertIn('Acquire::Retries=0',text);self.assertIn('timeout-minutes: 117',text);self.assertIn('qemu-system-arm',text)
 def test_real_inert_alarm_retires_original_child_group(self):
  R=O.load('_ksm_test_held_supervisor',ROOT/'runtime/borrowed/runtime.py');saved=signal.signal(signal.SIGALRM,owner.interrupted)
  try:
   signal.setitimer(signal.ITIMER_REAL,.15)
   with tempfile.TemporaryDirectory()as d:row,out,err,error=R.run_command([sys.executable,'-I','-B','-c','import time; print("owned",flush=True); time.sleep(10)'],Path(d),dict(PATH='/usr/bin:/bin'),3,4096)
   self.assertIsInstance(error,owner.OwnerInterrupted);self.assertTrue(row['group_absence_verified']);self.assertEqual(out,b'owned\n');self.assertNotEqual(row['exit_code'],0)
  finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,saved)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);a,left=p.parse_known_args();ROOT=a.source.absolute();unittest.main(argv=[sys.argv[0]]+left)
