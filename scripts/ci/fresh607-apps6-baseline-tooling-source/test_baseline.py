# SPDX-License-Identifier: MIT
"""Apps6-specific target, complete inverse, role and import-context controls."""
import builtins,importlib.util,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('baseline_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
S=F.canonical(os.environ['FRESH_TOOLING_SOURCE']);P=F.canonical(os.environ['FRESH_TOOLING_PARENT']);FOREIGN=F.canonical(os.environ['FRESH_TOOLING_PRIMARY_PARENT']);sys.path.insert(0,str(S/'implementation'))
import common as C,tooling_source as G
from loaders import load
TARGET=dict(bytes=12075,sha256='72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4')
class BaselineControls(unittest.TestCase):
 def test_exact_apps6_other606_runtime1_and_whole_held_bodies(self):
  p=C.profile();self.assertEqual(p['target'],TARGET);self.assertEqual(C.pin(C.read(S/'implementation/expected607.lock')),TARGET);self.assertEqual(len(p['incoming']),7);self.assertNotIn('cachy-asahi-apps',p['incoming']);self.assertEqual(p['held604']['cachy-asahi-apps']['version'],'0.1.0-6')
  raw=C.read(S/'implementation/expected607.lock');rows=dict(line.split()for line in raw.decode().splitlines());self.assertEqual(len(rows),607);self.assertEqual(rows['cachy-asahi-apps'],'0.1.0-6');self.assertEqual(rows['cachy-asahi-repository-runtime'],'0.1.0-1');other=b'\n'.join(line for line in raw.splitlines()if not line.startswith(b'cachy-asahi-apps '))+b'\n';self.assertEqual(C.pin(other),json.loads(F.read(HERE/'profile.json'))['other606_projection'])
  for n in('implementation/profile.json','implementation/expected607.lock','implementation/materialize.py','implementation/adapter.py','implementation/runtime_context.py','implementation/validate.py','parent604/run.py','parent604/prepare.py','parent604/guest.py','parent604/installer.py','parent604/numeric_vm.py'):self.assertEqual(C.read(S/n),C.read(P/n),n)
 def test_complete1192_inverse_actual_owner_and_workflow_source_bindings(self):
  p,old,actual=G.inverse();self.assertEqual(old,F.tree(P));self.assertEqual(len(old),1192);self.assertEqual(len(actual),1197);self.assertEqual(p['before'],p['authorization']);self.assertEqual(p['before'],p['git']['files']);self.assertEqual(p['publication']['source'],'412742e6320aaf8f546c537cdcda534a843b6dcd')
  template=C.read(S/'implementation/workflow-template.yml');self.assertEqual(G.with_tooling(C.read(P/'implementation/workflow-template.yml')),template)
  for literal in(b'ref: fb515d735a81194f06ea117539dee60438bb8d87',b'--tooling-inputs "$GITHUB_WORKSPACE/fresh607-tooling-inputs"',b'test "$CURRENT_CHILD_SOURCE" = "$CURRENT_WORKFLOW_SHA"',b'default: bd0cf1891083d011b70edab10501c317d3720b78'):self.assertIn(literal,template)
  for n in G.ALIASES:self.assertEqual(C.read(S/n),template.replace(b'@FRESH607_MANIFEST@',C.pin(C.read(S/'source-manifest.json'))['sha256'].encode()))
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR_OR_PARENT_ENTRY_IN_BOUNDARY_CONTROL')):
   before=load('_baseline_parent_owner',P/'implementation/run.py');after=load('_baseline_current_owner',S/'implementation/run.py');raw=C.read(P/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py');self.assertEqual(after.derive(raw).replace('            Y.seed_tooling(auditor,downloads,cache,owner)\n',''),before.derive(raw));self.assertIn('auditor.fetch(row,cache,True)',after.derive(raw))
 def test_shared_exact35_runtime_bytes_and_truthful_separate_provenance(self):
  q=json.loads(F.read(HERE/'profile.json'))
  for n,w in q['shared_runtime'].items():self.assertEqual(C.pin(C.read(S/(n if'/'in n else'implementation/'+n))),w,n)
  ctx=json.loads(C.read(S/'implementation/tooling-parent.json'));self.assertEqual(ctx['baseline_failure']['source'],'412742e6320aaf8f546c537cdcda534a843b6dcd');self.assertEqual(ctx['baseline_failure']['run'],40220983184)
  for value in(ctx,json.loads(C.read(S/'implementation/tooling-profile.json'))):self.assertTrue(all(value[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')))
  self.assertEqual(q['role'],'APPS6_BASELINE');self.assertEqual(q['Apps_version'],'0.1.0-6');self.assertEqual(q['other606'],q['Runtime1']);self.assertEqual(q['other606'],'HELD')
 def test_real_apps16_parent_refuses_and_common_restores_on_module_failure(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'refused'
   with self.assertRaisesRegex(ValueError,'whole exact public1192'):F.build(FOREIGN,out,'null')
   self.assertFalse(out.exists())
  missing=object();previous=sys.modules.get('common',missing);sentinel=types.SimpleNamespace(held='ORIGINAL_COMMON');original=builtins.compile
  def fail(source,filename,*args,**kwargs):
   return original('import common\nraise RuntimeError("INERT_MODULE_IMPORT_FAILURE")',filename,'exec')if filename==str(HERE/'tooling_source.py.in')else original(source,filename,*args,**kwargs)
  try:
   sys.modules['common']=sentinel
   with patch.object(builtins,'compile',side_effect=fail),self.assertRaisesRegex(RuntimeError,'INERT_MODULE_IMPORT_FAILURE'):F.render(P)
   self.assertIs(sys.modules['common'],sentinel)
  finally:
   if previous is missing:sys.modules.pop('common',None)
   else:sys.modules['common']=previous
if __name__=='__main__':unittest.main(verbosity=2)
