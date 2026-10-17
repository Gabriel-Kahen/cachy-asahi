# SPDX-License-Identifier: MIT
"""Current target and first-gate controls; inert source/temporary data only."""
import ast,copy,os,stat,subprocess,tempfile,unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch
import contract as C
import gate,run as owner,prepare as P
ROOT=Path(os.environ.get('CURRENT604_UPDATER_ROOT',Path(__file__).resolve().parents[3]))
class Current(unittest.TestCase):
 def test_pinned_support_and_only_two_rebased_package_versions(self):
  P.sources(ROOT);before,after=C.locks();self.assertEqual(after,before|{'cachy-asahi-setup':'0.1.0-5'})
  old=dict(line.split() for line in (ROOT/'scripts/ci/expanded604-root-upgrade/after604.lock').read_text().splitlines())
  self.assertEqual({n for n in old if old[n]!=after[n]},{'cachy-asahi-welcome','cachy-asahi-orphans'})
  self.assertEqual((after['cachy-asahi-welcome'],after['cachy-asahi-orphans']),('0.1.0-4','0.1.0-2'))
 def test_actual_current_native_and_fresh_installer_are_unbound(self):
  template=C.read(C.HERE/'policy.json');original=C.read
  with patch.object(C,'read',side_effect=lambda p:copy.deepcopy(template) if p==C.HERE/'input-policy.json' else original(p)):
   value=C.policy(bound=False);self.assertIsNone(value['installer_source']);self.assertIsNone(value['decision_source'])
   for key in ('native604','fresh604'):self.assertIsNone(value['prerequisites'][key])
   self.assertIsNone(value['installer_inputs']['native604_decisions'])
   self.assertEqual(value['installer_inputs']['welcome_source'],'77bd2c6ecf2e5c28a04116c3da85c45f70d1cc90')
   with tempfile.TemporaryDirectory() as name,patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):
    root=Path(name)
    with self.assertRaisesRegex(ValueError,'UNBOUND'):gate.main(['--implementation',str(root),'--source','a'*40,'--workflow-sha','a'*40,'--case','normal','--preflight'])
    self.assertEqual(list(root.iterdir()),[])
 def test_historical_target_and_authority_refuse(self):
  value=copy.deepcopy(C.policy(bound=False));value['after_sha256']='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'
  with patch.object(C,'read',return_value=value),self.assertRaisesRegex(ValueError,'fixed separate'):C.policy(bound=False)
  value=C.policy(bound=False);value.update(status='ROOT_BOUND_ACTUAL_PREREQUISITES',installer_source='a'*40,decision_source='b'*40)
  with patch.object(C,'read',return_value=value),self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
 def test_emit_and_freeze_keeps_all_current_support_operands(self):
  with tempfile.TemporaryDirectory() as name,patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):
   out=Path(name)/'source';P.emit(ROOT,out);lane=out/P.NEW
   workflow=out/P.WORKFLOW;text=workflow.read_text()
   for marker,path in (('@OWNER_SHA256@',lane/'run.py'),('@MANIFEST_SHA256@',lane/'source-manifest.json')):
    digest=C.sha(path);self.assertEqual(text.count(digest),1);text=text.replace(digest,marker)
   workflow.write_text(text)
   facade=SimpleNamespace(policy=lambda:{},safe=lambda p:p,SOURCE=out,HERE=lane,read=C.read,need=C.need,sha=C.sha,encoded=C.encoded)
   node=next(n for n in ast.parse((lane/'freeze.py').read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='freeze')
   scope=dict(C=facade,Path=Path,stat=stat);exec(compile(ast.Module(body=[node],type_ignores=[]),'<emitted-freeze>','exec'),scope)
   result=scope['freeze'](out);files=C.read(lane/'source-manifest.json')['files'];pins=C.read(lane/'source-pins.json')['files']
   self.assertEqual(result['files'],198);self.assertTrue(set(pins)<=set(files))
   for path,row in files.items():self.assertEqual(row,dict(bytes=(out/path).stat().st_size,sha256=C.sha(out/path)))
 def test_original_commit_checkpoint_preservation_functions_are_exact(self):
  original=ast.parse((ROOT/'scripts/ci/expanded604-root-upgrade/run.py').read_bytes());current=ast.parse(Path(owner.__file__).read_bytes())
  funcs=lambda t:{n.name:ast.dump(n,include_attributes=False) for n in t.body if isinstance(n,ast.FunctionDef)}
  a,b=funcs(original),funcs(current)
  for name in ('verify_result','prepare_with_plan'):self.assertEqual(a[name],b[name])
 def test_additive_progress_helper_retains_all_output_time_and_truth_checks(self):
  import driver_progress as D
  original=ast.parse((ROOT/'scripts/ci/expanded604-root-upgrade/driver_progress.py').read_bytes());current=ast.parse(Path(D.__file__).read_bytes())
  funcs=lambda t:{n.name:ast.dump(n,include_attributes=False) for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  a,b=funcs(original),funcs(current)
  self.assertEqual({n for n in a if a[n]!=b[n]},{'transformed'})
  self.assertEqual((D.CAP,D.RECORDS,D.OUTPUT),(32768,64,1024**2))
if __name__=='__main__':unittest.main(verbosity=2)
