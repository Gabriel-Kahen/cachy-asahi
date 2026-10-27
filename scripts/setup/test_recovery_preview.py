# SPDX-License-Identifier: MIT
"""Actual interrupted private-user CLI recovery preview/apply workflows."""
import json,os,subprocess,sys,unittest
from pathlib import Path
import test_setup
import test_shell_modules
setup=test_setup.setup
class RecoveryPreviewTests(unittest.TestCase):
 setUp=test_setup.SetupTests.setUp
 target=test_setup.SetupTests.target
 put=test_setup.SetupTests.put
 state=test_setup.SetupTests.state
 snapshot=test_setup.SetupTests.snapshot
 env=test_shell_modules.ShellModuleTests.env
 cli=test_shell_modules.ShellModuleTests.cli
 def crash(self,operation,checkpoint,components=None):
  code='''import importlib.util,os,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('setup_child',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
e=m.Setup(Path(sys.argv[2]),Path(sys.argv[3]));original=e.fs.atomic
point=e.journal_path if sys.argv[4]=='journal' else e.state_path if sys.argv[4]=='state' else e.targets[sys.argv[4]]
def atomic(path,data,expected,private=False):
 original(path,data,expected,private)
 if path==point:os._exit(71)
e.fs.atomic=atomic
e.run(sys.argv[5],sys.argv[6:],True)
'''
  argv=[sys.executable,'-B','-c',code,str(Path(setup.__file__)),str(self.home),str(self.templates),checkpoint,operation,*(components or setup.ALL_COMPONENTS)];result=subprocess.run(argv,env=self.env(),capture_output=True,text=True,timeout=10);self.assertEqual(result.returncode,71,result.stdout+result.stderr);self.assertTrue((self.home/self.engine.journal_path).is_file())
 def preview(self):
  before=self.snapshot();result=self.cli('recover');self.assertEqual(self.snapshot(),before);self.assertEqual(result.returncode,2,result.stdout+result.stderr);return json.loads(result.stdout)
 def test_real_interrupted_activate_lists_applied_and_pending_then_recovers(self):
  self.crash('activate','fish');report=self.preview();actions={a['component']:a for a in report['actions']};self.assertEqual(set(actions),set(setup.ALL_COMPONENTS));fish={'fish',*setup.MODULES[:3]}
  for c,a in actions.items():self.assertEqual(a['path'],self.engine.targets[c]);self.assertEqual(a['status'],'already-applied'if c in fish else'would-add')
  self.assertEqual(self.cli('recover',apply=True).returncode,0);self.assertEqual(set(self.state()['components']),set(setup.ALL_COMPONENTS));self.assertFalse((self.home/self.engine.journal_path).exists())
 def test_real_interrupted_remove_reports_remaining_removals(self):
  self.assertEqual(self.cli('activate',setup.ALL_COMPONENTS,True).returncode,0);self.crash('remove','fish');report=self.preview();fish={'fish',*setup.MODULES[:3]}
  for a in report['actions']:self.assertEqual(a['status'],'already-applied'if a['component']in fish else'would-remove')
  self.assertEqual(self.cli('recover',apply=True).returncode,0);self.assertEqual(self.state()['components'],{});self.assertTrue(all(not self.target(c).exists()for c in setup.ALL_COMPONENTS))
 def test_edited_target_is_reported_before_apply_without_content_or_writes(self):
  self.crash('activate','fish');secret='# private fixture edit never printed\n';self.target('fish').write_text(secret);before=self.snapshot();result=self.cli('recover');self.assertEqual(result.returncode,1);self.assertIn('user edits preserved',result.stderr);self.assertNotIn(secret,result.stdout+result.stderr);self.assertEqual(self.snapshot(),before);self.assertEqual(self.cli('recover',apply=True).returncode,1);self.assertEqual(self.snapshot(),before)
 def test_changed_required_template_refuses_preview_and_retains_journal(self):
  self.crash('activate','journal');p=self.templates/setup.TEMPLATES['hyprland'];p.write_bytes(b'changed template');before=self.snapshot();result=self.cli('recover');self.assertEqual(result.returncode,1);self.assertIn('Pending template changed',result.stderr);self.assertEqual(self.snapshot(),before);self.assertTrue((self.home/self.engine.journal_path).is_file())
 def test_after_state_commit_preview_is_all_applied_and_never_duplicates_blocks(self):
  self.crash('activate','state');before={c:self.target(c).read_bytes()for c in setup.ALL_COMPONENTS};report=self.preview();self.assertTrue(all(a['status']=='already-applied'for a in report['actions']));self.assertEqual(self.cli('recover',apply=True).returncode,0);self.assertEqual({c:self.target(c).read_bytes()for c in setup.ALL_COMPONENTS},before);self.assertEqual(self.cli('recover').returncode,0)
 def test_preview_and_apply_share_exact_preparation_and_apply_rechecks(self):
  self.crash('activate','journal',setup.COMPONENTS);report=self.preview();self.assertTrue(all(a['status']=='would-add'for a in report['actions']));self.put('fish',b'user edit between preview and apply');before=self.snapshot();result=self.cli('recover',apply=True);self.assertEqual(result.returncode,1);self.assertEqual(self.snapshot(),before);self.assertIn('user edits preserved',result.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
