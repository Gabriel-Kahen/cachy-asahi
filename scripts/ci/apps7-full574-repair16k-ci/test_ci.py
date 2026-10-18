# SPDX-License-Identifier: MIT
"""Pure complete-source emission/workflow controls; no future decision fixture."""
import importlib.util,json,subprocess,tempfile,unittest,sys
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE));import support as S
spec=importlib.util.spec_from_file_location('_apps7_16k_ci_prepare_controls',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Controls(unittest.TestCase):
 def test_genuine_complete195_emission_has_exact_source_maps(self):
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('no actor/Git/API')):
   out=Path(td)/'source';P.emit(ROOT,out);mf=json.loads((out/P.LANE/'source-manifest.json').read_bytes());self.assertEqual(len(mf['files']),193)
   self.assertEqual({p.relative_to(out).as_posix()for p in out.rglob('*')if p.is_file()},set(mf['files'])|{P.LANE+'/source-manifest.json',P.WF})
   for n,r in mf['files'].items():self.assertEqual(P.pin((out/n).read_bytes()),r)
 def test_workflow_source_authorities_before_secrets_queue_and_all_kernel_cleanup(self):
  wf=(ROOT/P.WF).read_text();self.assertIn('native-arm-apps7-full574-repair16k-${{ inputs.repair_case }}',wf);self.assertIn('  queue: max\n  cancel-in-progress: false',wf)
  self.assertLess(wf.index('Verify actual native-case and prior kernel authorities'),wf.index('Seed the six exact retained inputs'));self.assertIn('--kernel-authority ',wf);self.assertIn('--kernel-receipt ',wf);self.assertIn('Retire completed kernel only after original consumer and producer absence',wf);self.assertIn('--native-decisions ',wf);self.assertIn('timeout-minutes: 350',wf)
  self.assertIn("-p test_ci.py",wf);self.assertIn('apps7-full574-repair16k-ci',wf);self.assertNotIn('4870s',wf) # Native4320 slot is not a new VM envelope.
 def test_unbound_authorization_refuses_before_git_or_actors(self):
  C=S.bridge(ROOT);original=C.read
  def unbound(p,*args):return C.encoded(dict(schema_version=1,status='UNBOUND_NEW_NATIVE_REPAIR_CASES_AND_ACCEPTED_KERNEL',binding=None))if Path(p)==C.HERE/'input-policy.json'else original(p,*args)
  with patch.object(S,'bridge',return_value=C),patch.object(C,'read',side_effect=unbound),patch.object(subprocess,'Popen',side_effect=AssertionError('no actor/Git/API')):
   for case in('repair-bytes','repair-missing'):
    with self.assertRaisesRegex(ValueError,'UNBOUND16K'):S.authorize(ROOT,case)
 def test_alias_exact_and_closed_source_namespace(self):
  self.assertEqual((ROOT/P.WF).read_bytes(),(ROOT/'.github/workflows/native-arm-build.yml').read_bytes());C=S.bridge(ROOT);self.assertEqual(len(S.source(ROOT,C)),193)
if __name__=='__main__':unittest.main()
