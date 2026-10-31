# SPDX-License-Identifier: MIT
"""Historical SOURCE is durable; original live expiry/authentication still refuses."""
import argparse,importlib.util,json,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch,Mock

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.root=Path(ARGS.source);cls.original=cls.root/'parent574/original';cls.assets=Path(ARGS.assets);cls.home=cls.original/'scripts/ci/welcome5-native-gui';cls.H=load('_fixed_historical_source',cls.root/'implementation/historical_source.py')
 def renewal(self):return load('_private_live_renewal_control',self.home/'renewal.py')
 def test_historical_reference_does_not_read_current_clock(self):
  R=self.renewal();old=R.overlay.__code__
  def forbidden():raise AssertionError('CURRENT_CLOCK_MUST_NOT_BE_READ_BY_HISTORICAL_API')
  R.time=types.SimpleNamespace(time=forbidden)
  value=self.H.historical_overlay(R,self.assets/'renewal');self.assertEqual((value['reference_epoch'],value['actor_ready']),(1792457344,False));self.assertEqual(value['source_scope'],self.H.SCOPE);self.assertIs(R.overlay.__code__,old)
  with self.assertRaisesRegex(AssertionError,'CURRENT_CLOCK_MUST'):R.overlay(self.assets/'renewal')
 def test_original_live_overlay_apply_and_candidate_stage_refuse_expiry(self):
  for now in(1792457343,1793062144,1793666944):
   R=self.renewal();R.time=types.SimpleNamespace(time=lambda:now)
   with self.subTest(now=now),self.assertRaisesRegex(ValueError,'current seven-day'):R.overlay(self.assets/'renewal')
   with tempfile.TemporaryDirectory()as td:
    out=Path(td)/'absent'
    with self.assertRaisesRegex(ValueError,'current seven-day'):R.apply(self.original,self.assets,out,{})
    self.assertFalse(out.exists())
   C=load('_private_live_candidates_control',self.home/'candidates.py');original=C.load
   C.load=lambda name,path:R if Path(path)==self.home/'renewal.py'else original(name,path)
   C.stage_data=Mock(return_value={})
   with self.assertRaisesRegex(ValueError,'current seven-day'):C.stage(self.original,self.assets,Path('/unused-source-test-output'))
   self.assertEqual(C.stage_data.call_count,1)
 def test_original_live_overlay_still_accepts_its_genuine_valid_window(self):
  R=self.renewal();R.time=types.SimpleNamespace(time=lambda:1792457344)
  value=R.overlay(self.assets/'renewal');self.assertNotIn('source_scope',value);self.assertEqual(value['expires'],1793062144)
 def test_historical_refuses_changed_epoch_member_and_caller_timestamp(self):
  with self.assertRaises(TypeError):self.H.historical_overlay(self.renewal(),self.assets/'renewal',1792457345)
  for kind in('epoch','signature','foreign'):
   with tempfile.TemporaryDirectory()as td:
    root=Path(td)/'renewal';shutil.copytree(self.assets/'renewal',root)
    if kind=='epoch':p=root/'index.json';value=json.loads(p.read_bytes());value['created']+=1;p.write_text(json.dumps(value))
    elif kind=='signature':p=root/'signatures/doctor.sig';p.write_bytes(p.read_bytes()+b'foreign')
    else:(root/'foreign').write_bytes(b'foreign')
    with self.subTest(kind=kind),self.assertRaises(ValueError):self.H.historical_overlay(self.renewal(),root)
 def test_source_facade_cannot_emit_or_prepare_without_no_actors(self):
  f=load('_held_default_factory_refusal',self.root/'implementation/factory/factory.py');api=self.H.historical_factory(f,self.original,self.assets)
  with self.assertRaisesRegex(ValueError,'refuses every actor'):api.emit()
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source'
   with self.assertRaisesRegex(ValueError,'NO_ACTORS'):api.prepare_code(self.original,self.assets,out,'minimal','generic4k')
   self.assertFalse(out.exists())
   with self.assertRaisesRegex(ValueError,'actor-ready'):api.seal(out,'minimal','generic4k',{}, {},True)
 def test_source_output_marker_unbound_seal_and_original_actor_entry(self):
  f=load('_held_default_factory_source',self.root/'implementation/factory/factory.py');original_prepare=f.prepare_code;original_emit=f.emit;api=self.H.historical_factory(f,self.original,self.assets)
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source'
   with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):basis,changes=api.prepare_code(self.original,self.assets,out,'minimal','generic4k')
   fact=api.seal(out,'minimal','generic4k',basis,changes,False);self.assertFalse(fact['actor_ready']);self.assertEqual(fact['status'],'UNBOUND_LATEST607_GUI_CODE_ONLY_RUNTIME_REFUSES');self.assertIsNone(fact['actual_run']);self.assertEqual(fact['source_scope'],self.H.SCOPE)
   receipt=json.loads((out/'candidates/test-signature-renewal.json').read_bytes());self.assertEqual(receipt['status'],self.H.SCOPE);self.assertFalse(receipt['actor_ready']);self.assertTrue((out/self.H.MARKER).is_file())
   with self.assertRaisesRegex(ValueError,'actor-ready'):api.seal(out,'minimal','generic4k',basis,changes,True)
   context=load('_original_live_actor_entry',out/'context606.py')
   with self.assertRaisesRegex(ValueError,'ready source-owned606'):context.authorize_runner(out)
  self.assertIs(f.prepare_code,original_prepare);self.assertIs(f.emit,original_emit);self.assertIs(f.prepare_code.__globals__['load'],f.load)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--assets',required=True);ARGS,rest=p.parse_known_args();unittest.main(argv=[sys.argv[0]]+rest,verbosity=2)
