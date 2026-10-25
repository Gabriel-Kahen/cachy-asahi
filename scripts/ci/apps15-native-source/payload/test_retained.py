# SPDX-License-Identifier: MIT
"""Actual emitted producer routing, original clock/security and new check markers."""
import importlib.util,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock,patch
import adapter as A
import contract as C
import job,producer
ROOT=A.ROOT
class Controls(unittest.TestCase):
 def test_actual_private_loader_and_exec_routes_unchanged_producer(self):
  actual=producer.importlib.util.module_from_spec;seen={};prepare=Mock(return_value={'actual':None})
  def module(spec):
   m=actual(spec);execute=spec.loader.exec_module
   def capture(value):execute(value);seen['name']=value.__name__;seen['file']=value.__file__;value.prepare=prepare
   spec.loader.exec_module=capture;return m
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'owned';carrier=Path(td)/'carrier';carrier.mkdir()
   with patch.object(C,'verify_source'),patch.object(job,'inherited',return_value=NS(manifest_files=Mock())),patch.object(producer.importlib.util,'module_from_spec',side_effect=module),patch.object(os,'execv')as execute,patch.object(time,'monotonic',return_value=100):producer.execute(ROOT,carrier,out,'a'*16)
   self.assertEqual(seen['name'],'_apps15_retained_prepare');self.assertEqual(Path(seen['file']),ROOT/'scripts/ci/setup6-retained-helpers/prepare.py')
   self.assertEqual(prepare.call_args.args,(carrier,out/'context/deps','desktop574',ROOT/'scripts/ci/maintained-desktop574-inputs.json',2400,carrier/'.git'))
   argv=execute.call_args.args[1];self.assertEqual(argv,[sys.executable,'-I','-B',str(ROOT/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(ROOT/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(out),'--job-token','a'*16])
   for rel in ('','context','context/deps','context/keys','home'):self.assertEqual((out/rel).stat().st_mode&0o777,0o700)
 def test_fresh_output_and_source_drift_refuse_before_prepare_or_exec(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'existing';out.mkdir()
   with patch.object(C,'verify_source'),patch.object(job,'inherited',return_value=NS(manifest_files=Mock())),patch.object(os,'execv')as execute:
    with self.assertRaisesRegex(ValueError,'fresh owned'):producer.execute(ROOT,Path(td),out,'a'*16)
    execute.assert_not_called()
   with patch.object(C,'verify_source',side_effect=ValueError('source drift')),patch.object(os,'execv')as execute:
    with self.assertRaisesRegex(ValueError,'source drift'):producer.execute(ROOT,Path(td),Path(td)/'absent','a'*16)
    self.assertFalse((Path(td)/'absent').exists());execute.assert_not_called()
 def test_full_retained_closure_and_original574_body_are_source_pinned(self):
  manifest=C.read(C.HERE/'source-manifest.json')['files'];helper=ROOT/'scripts/ci/setup6-retained-helpers';files={p.relative_to(ROOT).as_posix()for p in helper.iterdir()if p.is_file()}
  self.assertEqual(len(files),20);self.assertTrue(files<=set(manifest))
  profile=json.loads((helper/'carrier-profile.json').read_bytes());self.assertEqual(profile['source'],'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad');self.assertEqual(len(profile['files']),1154)
  self.assertEqual(C.digest(ROOT/'scripts/ci/maintained_desktop574.py'),'27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760')
  text=(ROOT/'.github/workflows/native-arm-apps15-client.yml').read_text();self.assertNotIn('${{ secrets.',text);self.assertIn('2300s',text);self.assertIn('2500s',text);self.assertIn('timeout-minutes: 100',text)
 def test_native_check_log_requires_both_complete_suites_and_no_errors(self):
  good='Starting check()\nPASS_SOURCE_AND_STAGING_CONTRACT\nRan 45 tests in 1.234s\n\nOK\nRan 32 tests in 2.345s\n\nOK\n'
  good+='test_owned_child_sigterm_and_timeout_leave_inflight_phase_no_output\nRan 8 tests in 0.123s\n\nOK\n'
  row={'check_markers':['PASS_SOURCE_AND_STAGING_CONTRACT','Ran 45 tests','Ran 32 tests','Ran 8 tests','OK','test_owned_child_sigterm_and_timeout_leave_inflight_phase_no_output']}
  with tempfile.TemporaryDirectory()as td,patch.dict(C.check_log.__globals__,{'row':lambda _:row}):
   p=Path(td)/'build.log';p.write_text(good);self.assertEqual(C.check_log(p,C.ROLES['apps'])['status'],'PASS_CHECK_EXIT_NO_SKIPS')
   for raw in (good.replace('Ran 32 tests','Ran 8 tests'),good.replace('Ran 32 tests','Ran 13 tests'),good.replace('Ran 8 tests','Ran 32 tests'),good.replace('Ran 8 tests','Ran 4 tests'),good.replace('Ran 8 tests','Ran 3 tests'),good.replace('Ran 45 tests','Ran 44 tests'),good+'Ran 8 tests in 1.000s\nOK\n',good.replace('OK\n','FAILED (errors=1)\n',1),good.replace('OK\n','OK (skipped=1)\n',1),good.replace('Ran 8 tests in','xRan 8 tests in')):
    p.write_text(raw)
    with self.assertRaises(ValueError):C.check_log(p,C.ROLES['apps'])
if __name__=='__main__':unittest.main(verbosity=2)
