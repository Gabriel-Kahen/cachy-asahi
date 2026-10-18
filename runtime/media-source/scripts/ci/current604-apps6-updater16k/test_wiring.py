# SPDX-License-Identifier: MIT
"""Source-only wiring and inert filesystem controls; no native/kernel/VM credit."""
import ast,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ.get('APPS6_WIRING_SOURCE',Path(__file__).resolve().parents[3]))
sys.path.insert(0,str(SOURCE/'scripts/ci/current604-apps6-updater16k'));sys.path.insert(0,str(HERE))
import contract as C
import wiring as W,job,kernel_job,retain16k as T,freeze_wiring as F
class Controls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors/Git/network forbidden'));p.start();self.addCleanup(p.stop)
 def test_unbound_all_cases_before_source_output_or_kernel(self):
  original=C.read
  def inert(path,cap=4*1024**2):return C.encoded(dict(schema_version=1,status='INERT_UNBOUND_CONTROL',binding=None)) if Path(path)==C.HERE/'input-policy.json' else original(path,cap)
  with patch.object(C,'read',side_effect=inert),patch.object(W,'check_source',side_effect=AssertionError('wiring source before gate')):
   for case in C.CASES:
    with self.subTest(case=case),self.assertRaisesRegex(ValueError,'UNBOUND'):job.main(['preflight','--implementation','/absent','--source','a'*40,'--workflow-sha','a'*40,'--case',case])
    with self.assertRaisesRegex(ValueError,'UNBOUND'):kernel_job.main(['acquire','--implementation','/absent','--source','a'*40,'--case',case,'--work','/absent/managed-gui16k-kernel','--cache','/absent/cache','--output','/tmp/absent','--receipt','/absent/receipt'])
 def test_complete_source_workflow_and_original13_conservation(self):
  with tempfile.TemporaryDirectory() as td:
   output=Path(td)/'source';r=F.emit(SOURCE,output);self.assertLessEqual(r['source_rows'],512)
   rows=C.decode((output/C.LANE/'wiring-source-manifest.json').read_bytes())['files']
   for n,pin in rows.items():self.assertEqual(C.row(output/n),pin)
   base=C.decode((SOURCE/C.LANE/'source-manifest.json').read_bytes())['files'];names={n for n in base if n.startswith(C.LANE+'/')}|{C.LANE+'/source-manifest.json'};self.assertEqual(len(names),13)
   for n in names:self.assertEqual((output/n).read_bytes(),(SOURCE/n).read_bytes())
   wf=(output/F.WF).read_text();self.assertEqual(wf.count('job.py preflight'),1);self.assertEqual(wf.count('job.py decisions'),1);self.assertEqual(wf.count('job.py inputs'),1);self.assertEqual(wf.count('/job.py" run'),1)
   for v in ('options: [normal, precommit-exit86, postcommit-exit87]','timeout-minutes: 350','15600s','3700s','timeout-minutes: 270','fail-on-cache-miss: false','lookup-only: false','updater16k-kernel-cleanup.json','apps6-current604-updater16k-public'):self.assertIn(v,wf)
   self.assertLess(wf.index('job.py preflight'),wf.index('secrets.'));self.assertLess(wf.index('job.py decisions'),wf.index('Retrieve only the six original pinned audio inputs'));self.assertLess(wf.index('job.py inputs'),wf.index('secrets.'))
   self.assertIn(r['manifest']['sha256'],wf);self.assertIn(C.row(output/C.LANE/'job.py')['sha256'],wf);self.assertIn('path: apps6-inputs',wf);self.assertIn('apps6-inputs/payload',wf);self.assertNotIn('ignore.git',wf)
   for p in (output/C.LANE).glob('*.py'):ast.parse(p.read_bytes())
 def test_original_native_steps_unchanged_before_new_kernel(self):
  with tempfile.TemporaryDirectory() as td:
   output=Path(td)/'source';F.emit(SOURCE,output)
   old=(SOURCE/F.OLD).read_text();new=(output/F.WF).read_text()
   for start,end in (('      - name: Seed the six frozen private cache objects','      - name: Checkout exact retained public input source'),('      - name: Build the fresh native base','      - name: Provision existing accepted kernel tools')):
    a=old.index(start);b=old.index(end,a) if end in old else old.index('      - name: Required separate native604',a)
    c=new.index(start);d=new.index(end,c)
    self.assertEqual(old[a:b],new[c:d])
 def failed_original(self,source):
  C.save(source/'owner.json',dict(purpose='expanded604-apps6-updater',case='normal',output=str(source),token='inert-not-native'))
  for n in T.NAMES:
   p=source/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'original fixture tail' if n.endswith('.log') else C.encoded(dict(status='FAIL',fixture='INERT_NOT_NATIVE')))
 def test_exact_seven_originals_and_no_private_copy(self):
  with tempfile.TemporaryDirectory(prefix='update16k-retain-',dir='/tmp') as sd,tempfile.TemporaryDirectory() as td:
   source=Path(sd);self.failed_original(source);(source/'PRIVATE_KEY_MUST_NOT_EXPORT').write_bytes(b'not-public');target=Path(td)/'public'
   missing=Path(td)/'absent';v=T.retain(source,target,dict(status='NOT_RUN'),'a'*40,'normal',missing,missing,missing)
   self.assertEqual({str(p.relative_to(target)) for p in target.rglob('*') if p.is_file()},set(T.NAMES)|{'retention.json'});self.assertEqual(v['status'],'ORIGINALS_RETAINED_NOT_ACCEPTED')
   for n in T.NAMES:self.assertEqual((target/n).read_bytes(),(source/n).read_bytes())
   self.assertLessEqual(sum(p.stat().st_size for p in target.rglob('*') if p.is_file()),8*1024**2)
 def test_retention_refuses_hardlink_oversize_and_false_pass(self):
  with tempfile.TemporaryDirectory(prefix='update16k-retain-',dir='/tmp') as sd,tempfile.TemporaryDirectory() as td:
   source=Path(sd);self.failed_original(source);root=Path(td);absent=root/'absent'
   os.link(source/'result.json',source/'alias')
   with self.assertRaises(ValueError):T.retain(source,root/'bad',{},'a'*40,'normal',absent,absent,absent)
   (source/'alias').unlink()
   with patch.object(T,'CAP',128),self.assertRaises(ValueError):T.retain(source,root/'small',{},'a'*40,'normal',absent,absent,absent)
   C.save(source/'result.json',dict(status='PASS'))
   result=T.retain(source,root/'false-pass',{},'a'*40,'normal',absent,absent,absent);self.assertFalse(result['proof_complete']);self.assertEqual(result['completion'],'INCOMPLETE_OR_FAILED_NOT_ADMISSIBLE');self.assertTrue((root/'false-pass/result.json').exists())
   self.assertFalse((root/'bad').exists())
 def kernel_fixture(self,root):
  work=root/'managed-gui16k-kernel';work.mkdir(mode=0o700);i=work.stat();C.save(work/'wiring-owner.json',dict(source='a'*40,case='normal',identity=[i.st_dev,i.st_ino]));(work/'helper/built').mkdir(parents=True);C.save(work/'helper/built/build-receipt.json',dict(status='BUILT_ONLY',fixture='INERT_CLEANUP_CONTROL_NOT_A_KERNEL'))
  return work,root/'no-native-output'
 def test_kernel_cleanup_fixed_inode_and_unknown_child_refusal(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);work,output=self.kernel_fixture(root);home=output.with_name(output.name+'-job-home');home.mkdir(mode=0o700);C.save(home/'child.json',dict(status='LAUNCH_ATTEMPTED_TERMINAL_UNKNOWN',source='a'*40,case='normal'))
   with self.assertRaisesRegex(ValueError,'GROUP_UNKNOWN'):kernel_job.cleanup(work,output,'a'*40,'normal')
   self.assertTrue(work.exists());C.save(home/'child.json',dict(status='WAIT_RETURNED',source='a'*40,case='normal',child=dict(group_absence_verified=True)))
   with self.assertRaisesRegex(ValueError,'identity'):kernel_job.cleanup(work,output,'b'*40,'normal')
   self.assertTrue(work.exists());result=kernel_job.cleanup(work,output,'a'*40,'normal');self.assertEqual(result['status'],'PASS_OWNED_KERNEL_WORK_REMOVED');self.assertFalse(work.exists());self.assertFalse(home.exists())
 def test_actual_wait_not_intended_child_status_and_no_base_mutation(self):
  text=(HERE/'job.py').read_text();self.assertIn("status='LAUNCH_ATTEMPTED_TERMINAL_UNKNOWN'",text);self.assertIn("status='WAIT_RETURNED'",text);self.assertIn("row['exit_code']==0",text);self.assertIn("row['group_absence_verified'] is True",text);self.assertIn('15600,4*1024**2',text)
  self.assertNotIn("source/'result.json').write",text);self.assertIn("original13",(HERE/'wiring.py').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
