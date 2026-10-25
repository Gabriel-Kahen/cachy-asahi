# SPDX-License-Identifier: MIT
"""Owned filesystem/source/refusal controls; no accepting native fixture."""
import ast,copy,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D/'implementation'));BASE=D.parent/'historical/boot391'
import latest_owner as O,latest_component as C,latest_plan as P,latest_validate as V,latest_selection as S
class Composition(unittest.TestCase):
 def test_whole_owner_bridge_andouter_inverses_keeporiginalclocks(self):
  import latest_guard as G
  g=G.original();_,_,contract,adapter,bridge,_=g.original_context();raw=adapter.owner(BASE/'held606');text=O.owner(raw);back=text.replace('active.process.wait(timeout=4200)','active.process.wait(timeout=1800)',1)
  for before,after in reversed(O.OWNER_EDITS):self.assertEqual(back.count(after),1);back=back.replace(after,before,1)
  self.assertEqual(back,raw);self.assertIn('timeout=4200',text);self.assertIn('ITIMER_REAL,6600',text);self.assertIn('latest607-public-verifier',text)
  old=(BASE/'held606/scripts/ci/current606-native/bridge606.py').read_text();new=O.bridge_source(old);self.assertIn('other600_physical_preservation',new);self.assertNotIn('base604_preserved=True',new);self.assertIn('selected_four_inode_restoration=',new)
 def test_actual_emitted_support_namespace_imports_without_actors(self):
  import latest_guard as G
  g=G.original();_,_,_,_,bridge,_=g.original_context()
  with tempfile.TemporaryDirectory(prefix='latest-source-import-control-',dir=D.parent.parent)as directory:
   runner,_=bridge.emit_runner(BASE/'held606',Path(directory)/'runner');ledger=O.emit_runner(D.parent,BASE,runner);self.assertIn('boot607/boot_fixture.py',ledger['support_files']);self.assertEqual((runner/'latest_domain.py').read_bytes(),(runner/'latest/latest_domain.py').read_bytes())
   before=list(sys.path);old=sys.modules.pop('boot_fixture',None);sys.path.insert(0,str(runner/'boot607'))
   try:
    spec=importlib.util.spec_from_file_location('_latest_emitted_original_commands',runner/'boot607/accepted-lifecycle.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);self.assertTrue(callable(module.command));self.assertEqual(Path(module.F.__file__),runner/'boot607/boot_fixture.py')
   finally:
    sys.path[:]=before;sys.modules.pop('boot_fixture',None)
    if old is not None:sys.modules['boot_fixture']=old
 def test_real_expected606_accounting_fourlogical_and602physical(self):
  rows=dict(r.split()for r in(D/'implementation/expected606.lock').read_text().splitlines());graph=dict(packages=[dict(name=n,version=v)for n,v in rows.items()]);physical=C.physical_domain(graph);self.assertEqual(len(physical),602);self.assertIn(P.RUNTIME,physical);self.assertIn('cachy-asahi-dns',physical);self.assertIn('cachy-asahi-sysctl',physical)
  for _,name,old,_ in P.PRODUCTS:self.assertNotIn(name,physical)
 def test_allfinalactualandpolicydefaultsNULL_refuse(self):
  import latest_guard as G
  value=json.loads((D/'implementation/default-policy.json').read_bytes());old=json.loads((BASE/'boot607/input-policy.json').read_bytes())['current606']
  with self.assertRaisesRegex(ValueError,'NULL'):S.authorize(value,old)
  for actual in('actual_source','actual_ref','actual_run','Root_acceptance'):self.assertIsNone(value[actual])
 def test_no_accepting_fixture_andabsent_partial_failure_receipts_refuse(self):
  for value in({},dict(status='FAIL'),dict(status='CI_FAILURE'),dict(status='PASS_NATIVE607_LATEST_FIVE_TOOL_COMPONENT_REQUIRES_FULL_REPLAY')):
   with self.assertRaises((ValueError,KeyError)):V.validate(value,{}, {},'0'*32,{})
 def test_every_auxiliary_observation_is_fresh_before_exact_shared_blob_retention(self):
  tree=ast.parse((D/'implementation/latest_component.py').read_bytes());exercise=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='exercise');aux=next(n for n in exercise.body if isinstance(n,ast.FunctionDef)and n.name=='auxiliary');text=ast.get_source_segment((D/'implementation/latest_component.py').read_text(),aux)
  self.assertEqual(text.count(".ld_state(context['adapter'],context['audio_rows'])"),1);self.assertEqual(text.count('.ld_aux_read(state)'),1);self.assertLess(text.index('.ld_state('),text.index("if label=='baseline606'"));self.assertLess(text.index('data==previous_aux and state==previous_ld'),text.index("if label=='baseline606'"));self.assertIn("source_owned_nonce=plan['nonce']",text);self.assertIn("state_ref==aux[0]['state_reference']",text);self.assertIn('EXACT_EQUAL_BLOB_SHARED_AFTER_FRESH_COMPLETE_OBSERVATION',text)
 def test_installed_controls_fulloriginalmethodidentities(self):
  expected={'Diagnostics':10,'QueryControls':2,'Reports':4,'Audio':8,'RealIPC':3};counts={}
  for filename in('test_doctor.py','test_audio.py'):
   tree=ast.parse((D.parent/'roles/doctor-worker/held-doctor'/filename).read_bytes())
   for cls in tree.body:
    if isinstance(cls,ast.ClassDef)and cls.name in expected:counts[cls.name]=len([n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')])
  self.assertEqual(counts,expected);self.assertEqual(sum(counts.values()),27)
 def test_strict_full_doctor_unknowns_andaudio_noinventedhealth(self):
  base=dict(schema_version=1,tool='cachy-asahi-doctor',scope='local observations only',version='0.2.0',checks=[dict(check='platform',value=dict(architecture='aarch64',kernel='CONTROL_ONLY',page_size_bytes=4096)),dict(check='package/cachy-asahi-doctor',state='unknown',value=dict(presence='unknown',version=None)),dict(check='audio/default-output',state='unavailable',value=None)])
  self.assertEqual(V.doctor(base,'0.2.0-1',{'cachy-asahi-doctor':'0.2.0-1'}),base)
  for change in(lambda v:v['checks'][1]['value'].update(presence='absent'),lambda v:v['checks'][2].update(state='checked',value={'volume':1.0}),lambda v:v.update(version='0.1.0')):
   v=copy.deepcopy(base);change(v)
   with self.assertRaises(ValueError):V.doctor(v,'0.2.0-1',{'cachy-asahi-doctor':'0.2.0-1'})
if __name__=='__main__':unittest.main(verbosity=2)
