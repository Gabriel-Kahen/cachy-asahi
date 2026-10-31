#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-denied Desktop Source construction and finite update-contract controls."""
import hashlib,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('desktop_factory_tested',HERE/'prepare.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
def deny(event,args):
 if event.startswith(('subprocess.','socket.')) or event in ('os.system','os.posix_spawn','os.fork','os.exec','os.kill','os.killpg'):
  raise AssertionError('Source DATA actor denied:'+event)
sys.addaudithook(deny)
class Factory(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.basis=Path(os.environ['DESKTOP_NATIVE_BASIS']).absolute();cls.policy,cls.before,cls.after=F.render(cls.basis)
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='desktop-factory-data-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def test_complete199_profile_and_default_cap_held(self):
  self.assertEqual(len(self.before),191);self.assertEqual(len(self.after),199)
  self.assertEqual(self.after['native/common.py'],self.before['native/common.py'])
  self.assertIn(b'len(rows) <= 200',self.after['native/common.py'][0])
  self.assertEqual(len(json.loads(self.after['native/source-map.json'][0])['files']),198)
  changed={n for n in self.after if self.after[n]!=self.before.get(n)};self.assertEqual(changed,set(self.policy['payload']));self.assertEqual(len(changed),15)
  for leaf in ('native/transport_proof.py','native/provision.py','native/retained_transport.py','native/input-profile.json','scripts/virtual/owned_process.py'):
   self.assertEqual(self.after[leaf],self.before[leaf])
 def test_full_temporary_emission_and_authorization(self):
  target=self.root/'trial';result=F.emit(self.basis,target)
  self.assertEqual(F.rows(F.tree(target/'source')),self.policy['after'])
  self.assertEqual(result['operation'],'desktop-alpm-v1');self.assertEqual(result['source_files'],199)
  self.assertTrue(all(value is None for value in result['actual'].values()))
  self.assertEqual(json.loads((target/'source-modes.json').read_text()),{n:mode for n,(_,mode)in self.after.items()})
 def test_emitted_delta_has_full_parent_inverse(self):
  target=self.root/'trial';F.emit(self.basis,target);source=target/'source'
  changes=json.loads((target/'delta191.json').read_text())['changes']
  for name,row in changes.items():
   if row['before'] is None:(source/name).unlink()
   else:shutil.copyfile(target/'before191'/name,source/name);(source/name).chmod(row['before']['mode'])
  for d in sorted((p for p in source.rglob('*')if p.is_dir()),key=lambda p:len(p.parts),reverse=True):
   if not any(d.iterdir()):d.rmdir()
  self.assertEqual(F.tree(source),self.before);self.assertEqual(F.git_tree(F.tree(source)),self.policy['parent_tree'])
 def test_private_fixture_update_is_explicit_and_payload_held(self):
  contract=json.loads(self.after['native/desktop-contract-v1.json'][0]);base=contract['recipe'];update=contract['update_recipe']
  self.assertEqual(base['version'],'0.1.0-1');self.assertEqual(update['version'],'0.1.0-2')
  self.assertEqual(update['scope'],'TEST_LIFECYCLE_UPDATE_FIXTURE_ONLY');self.assertEqual(update['payload_files'],base['payload_files'])
  for name in set(base['source_files'])-{'PKGBUILD'}:self.assertEqual(update['source_files'][name],base['source_files'][name])
  self.assertNotEqual(update['source_files']['PKGBUILD'],base['source_files']['PKGBUILD'])
  self.assertEqual(contract['bundle']['members'],5);self.assertEqual(base['expected_test_count'],81);self.assertEqual(update['expected_test_count'],81)
 def test_concurrency_unique_fixed_queued_and_inverse(self):
  aliases=F.WORKFLOW_ALIASES;self.assertEqual(self.after[aliases[0]],self.after[aliases[1]])
  raw=self.after[aliases[0]][0];expected=b'concurrency:\n  group: native-arm-desktop-tools\n  cancel-in-progress: false\n  queue: max\njobs:\n'
  legacy=b'concurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
  self.assertEqual(raw.count(expected),1)
  unscheduled=F.tree(HERE/'payload')[aliases[0]][0];self.assertEqual(raw.replace(expected,legacy,1),unscheduled)
  self.assertNotIn(b'${{ inputs.',expected)
 def test_wrong_existing_queue_and_alias_drift_refuse(self):
  legacy=b'name: inert\nconcurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
  for bad in (legacy.replace(b'jobs:',b'  queue: max\njobs:'),legacy.replace(b'native-arm-developer-workflows',b'foreign'),legacy+legacy):
   with self.subTest(bad=bad),self.assertRaises(ValueError):F.scheduled_workflows({n:bad for n in F.WORKFLOW_ALIASES})
  with self.assertRaises(ValueError):F.scheduled_workflows({F.WORKFLOW_ALIASES[0]:legacy,F.WORKFLOW_ALIASES[1]:legacy+b'\n'})
 def test_bad_basis_refuses_before_output(self):
  bad=self.root/'bad';bad.mkdir();(bad/'README').write_text('wrong parent')
  with self.assertRaises(ValueError):F.emit(bad,self.root/'trial')
  self.assertFalse((self.root/'trial').exists())
 def test_existing_output_preserved(self):
  target=self.root/'trial';target.mkdir();(target/'keep').write_text('preserve')
  with self.assertRaises(ValueError):F.emit(self.basis,target)
  self.assertEqual((target/'keep').read_text(),'preserve')
 def test_changed_payload_refuses_before_output(self):
  local=self.root/'factory';shutil.copytree(HERE,local);path=local/'payload/native/desktop_guest_v1.py';path.write_bytes(path.read_bytes()+b'\n# drift\n')
  with patch.object(F,'HERE',local),self.assertRaises(ValueError):F.emit(self.basis,self.root/'trial')
  self.assertFalse((self.root/'trial').exists())
 def test_profile_and_raw_parent_tamper_refuse(self):
  local=self.root/'factory';shutil.copytree(HERE,local);(local/'profile.json').write_text('{}')
  with patch.object(F,'HERE',local),self.assertRaises(ValueError):F.emit(self.basis,self.root/'trial')
  shutil.copyfile(HERE/'profile.json',local/'profile.json');(local/'parent-commit.raw').write_text('wrong')
  with patch.object(F,'HERE',local),self.assertRaises(ValueError):F.emit(self.basis,self.root/'trial')
 def test_special_alias_and_hardlink_inputs_refuse(self):
  fifo=self.root/'fifo';os.mkfifo(fifo)
  with self.assertRaises(ValueError):F.read(fifo)
  data=self.root/'data';data.write_text('source');os.link(data,self.root/'hardlink')
  with self.assertRaises(ValueError):F.read(data)
  alias=self.root/'alias';alias.symlink_to(self.basis,target_is_directory=True)
  with self.assertRaises(ValueError):F.emit(alias,self.root/'trial')
if __name__=='__main__':unittest.main(verbosity=2)
