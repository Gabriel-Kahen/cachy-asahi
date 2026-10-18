# SPDX-License-Identifier: MIT
"""Finite public-pair routing/source/WF guards; no actual authorities or actors."""
import ast,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import contract as C
import wiring as W,job,kernel_job,retain16k as T,prepare as P
class Wiring(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def test_full_source_guards_and_three_case_workflow(self):
  rows=W.check_source(C.ROOT);self.assertLessEqual(len(rows),512)
  for n,r in rows.items():self.assertEqual(C.row(C.ROOT/n),r)
  text=(C.ROOT/P.WF).read_text()
  for marker in ('options: [normal, precommit-exit86, postcommit-exit87]','timeout-minutes: 350','timeout-minutes: 270','15600s','3700s','job.py preflight','job.py decisions','job.py inputs','--apps6-authority-source','apps6-inputs/payload','test_*.py'):self.assertIn(marker,text)
  self.assertNotIn('--apps6-native-source',text);self.assertLess(text.index('job.py preflight'),text.index('secrets.'));self.assertLess(text.index('job.py decisions'),text.index('secrets.'))
  self.assertIn(C.row(C.HERE/'job.py')['sha256'],text);self.assertIn(C.row(C.HERE/'wiring-source-manifest.json')['sha256'],text)
 def test_new_authority_and_runtime_status_no_old_case_credit(self):
  self.assertEqual(C.OLD,'scripts/ci/expanded604-apps6-public-pair-updater');self.assertIn('PUBLIC_PAIRS',C.PASS)
  value=C.decode(C.read(C.HERE/'policy.json'));self.assertIn('UNBOUND',value['status']);self.assertIsNone(value['binding'])
  text=(C.HERE/'contract.py').read_text();self.assertEqual(text.count('ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_COPIED_ROOT_'),3);self.assertNotIn("'ROOT_ACCEPTED_APPS6_CURRENT604_COPIED_ROOT_",text)
  public=(C.ROOT/C.OLD/'selected_package.py').read_text();self.assertIn('NOT_PRESENT_NOT_FABRICATED',public);self.assertIn('BUILDINFO_installed',public)
 def test_original_runtime_numeric_caps_and_guards_preserved(self):
  old=C.ROOT/'scripts/ci/current604-apps6-updater16k'
  for name in ('guest.py','disk.py','vm.py','cap_scope.py','kernel_job.py','retain16k.py','job.py'):
   a,b=(old/name).read_bytes(),(C.HERE/name).read_bytes()
   if name=='kernel_job.py':
    tree=ast.parse(b);tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef) and n.name=='home_failure')];b=ast.unparse(tree).encode()
   nums=lambda raw:[n.value for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.Constant) and type(n.value) in (int,float)]
   self.assertEqual(nums(a),nums(b),name)
  self.assertEqual((old/'cap_scope.py').read_bytes(),(C.HERE/'cap_scope.py').read_bytes())
 def test_failed_originals_remain_retained_not_accepted(self):
  with tempfile.TemporaryDirectory(dir='/tmp') as td,tempfile.TemporaryDirectory() as dest:
   root=Path(td);C.save(root/'owner.json',dict(purpose='expanded604-apps6-public-pair-updater',case='normal',output=str(root)))
   for name in T.NAMES:
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'inert failure' if name.endswith('.log') else C.encoded(dict(status='FAIL',scope='INERT_ONLY')))
   absent=Path(dest)/'absent';r=T.retain(root,Path(dest)/'public',dict(status='NOT_RUN'),'a'*40,'normal',absent,absent,absent)
   self.assertEqual(r['status'],'ORIGINALS_RETAINED_NOT_ACCEPTED');self.assertFalse(r['proof_complete']);self.assertLessEqual(sum(p.stat().st_size for p in (Path(dest)/'public').rglob('*') if p.is_file()),8*1024**2)
 def fixture(self,base):
  work=base/'managed-gui16k-kernel';work.mkdir(mode=0o700);(work/'helper/built').mkdir(parents=True)
  C.save(work/'helper/built/build-receipt.json',dict(status='BUILT_ONLY'));C.save(work/'wiring-owner.json',dict(source='a'*40,case='normal',identity=[work.stat().st_dev,work.stat().st_ino]))
  output=base/'absent-output';home=base/'absent-output-job-home';home.mkdir(mode=0o700)
  C.save(home/'child.json',dict(status='WAIT_RETURNED',source='a'*40,case='normal',child=dict(group_absence_verified=True)))
  return work,output,home
 def test_shallow_runtime_contract_import_has_no_invented_source(self):
  space=dict(__file__='/workspace/contract.py');exec(compile((C.HERE/'contract.py').read_bytes(),'/workspace/contract.py','exec'),space)
  self.assertEqual(space['HERE'],Path('/workspace'));self.assertIsNone(space['ROOT']);self.assertEqual(C.ROOT,C.HERE.parents[2])
  with self.assertRaisesRegex(ValueError,'UNBOUND'):space['need'](False,'UNBOUND')
 def test_real_owned_cleanup_exact_child_completes(self):
  with tempfile.TemporaryDirectory()as tmp:
   work,output,home=self.fixture(Path(tmp));self.assertEqual(kernel_job.cleanup(work,output,'a'*40,'normal')['status'],'PASS_OWNED_KERNEL_WORK_REMOVED');self.assertFalse(work.exists());self.assertFalse(home.exists())
 def test_unknown_home_refuses_before_kernel_deletion_and_projects_no_names(self):
  with tempfile.TemporaryDirectory()as tmp:
   work,output,home=self.fixture(Path(tmp));unknown=home/'PRIVATE-ARBITRARY-NAME';unknown.write_bytes(b'untouched original bytes');before=C.row(unknown)
   with self.assertRaisesRegex(ValueError,'exact owned job HOME closure'):kernel_job.cleanup(work,output,'a'*40,'normal')
   self.assertTrue(work.exists());self.assertEqual(C.row(unknown),before);self.assertTrue((home/'child.json').exists())
   row=kernel_job.home_failure(home);self.assertEqual(row['counts'],dict(child_record=1,unexpected=1));self.assertEqual(row['group_absence'],'VERIFIED');self.assertNotIn('PRIVATE',C.encoded(row).decode());self.assertNotIn('untouched',C.encoded(row).decode())
   receipt=Path(tmp)/'kernel-cleanup.json';C.save(receipt,dict(status='FAIL',job_home_diagnostic=row));absent=Path(tmp)/'absent'
   retained=T.retain(Path(tmp),Path(tmp)/'retained',{},'a'*40,'normal',receipt,absent,absent)
   self.assertEqual(retained['kernel_cleanup']['value']['job_home_diagnostic'],row);self.assertFalse(retained['proof_complete']);self.assertIn('NOT_ADMISSIBLE',retained['completion'])
 def test_uncertain_original_child_and_alias_stay_retained(self):
  with tempfile.TemporaryDirectory()as tmp:
   work,output,home=self.fixture(Path(tmp));child=C.decode(C.read(home/'child.json'));child['child']['group_absence_verified']=False;C.save(home/'child.json',child)
   with self.assertRaisesRegex(ValueError,'GROUP_UNKNOWN'):kernel_job.cleanup(work,output,'a'*40,'normal')
   self.assertTrue(work.exists());self.assertEqual(kernel_job.home_failure(home)['group_absence'],'UNKNOWN')
   child['child']['group_absence_verified']=True;C.save(home/'child.json',child);(home/'unknown-alias').symlink_to(work)
   with self.assertRaisesRegex(ValueError,'exact owned job HOME closure'):kernel_job.cleanup(work,output,'a'*40,'normal')
   self.assertTrue(work.exists());self.assertTrue((home/'unknown-alias').is_symlink());self.assertEqual(kernel_job.home_failure(home)['types']['symlink'],1)

if __name__=='__main__':unittest.main(verbosity=2)
