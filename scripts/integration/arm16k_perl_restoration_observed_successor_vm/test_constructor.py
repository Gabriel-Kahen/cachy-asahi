# SPDX-License-Identifier: MIT
"""Pure canonical-lock/byte-inverse/tamper/export controls; no actors or Raw."""
import ast,copy,hashlib,importlib.util,json,os,shutil,stat,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('compact_successor',HERE/'constructor.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
PARENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-ldcache-lifecycle-successor-readiness-20261117-r2/constructed-source')
DIAGNOSTIC=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-cache-restoration-diagnostic-20261117/scripts/integration/arm16k_perl_cache_restoration_diagnostic')
COMPONENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-guest-hold-qmp-successor-20261117/scripts/integration/arm16k_perl_guest_hold_qmp_diagnostic/source387-component.DATA.json')
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.old=C.snapshot(PARENT);cls.diagnostic=C.snapshot(DIAGNOSTIC);cls.own=C.snapshot(HERE);cls.inputs=C.decode(cls.own['inputs.json'][0]);cls.component=C.component(COMPONENT,cls.inputs['qmp']);cls.result=C.project(cls.old,cls.diagnostic,cls.own,DIAGNOSTIC,cls.component)
 def test_old_canonical_lock_exact69318_byte_identity(self):
  raw=self.old['source.lock.json'][0];self.assertEqual(len(raw),69318);self.assertEqual(C.canonical(C.decode(raw)),raw);self.assertEqual(C.pin(raw),self.inputs['predecessor']['source_lock'])
 def test_positive_projection_and_complete387_inverse(self):
  self.assertEqual(C.inverse(self.result,self.inputs['predecessor']),self.old);self.assertEqual(len(self.result),389);self.assertLessEqual(sum(len(b)for b,_ in self.result.values()),C.CAP)
 def test_runtime_only_no_full_old_lock_or_root_duplicate(self):
  added=set(self.result)-set(self.old);self.assertEqual(added,{C.PREFIX+'construction.DATA.json','hold_state_observations.py'})
  for n in added:self.assertNotEqual(self.result[n][0],self.old['source.lock.json'][0]);self.assertNotEqual(self.result[n][0],self.old['guest/root.sh'][0]);self.assertNotIn('test_',n);self.assertNotIn('README',n)
  changed={n for n in self.old if n!='source.lock.json'and self.old[n]!=self.result[n]};self.assertEqual(changed,{'guest/root.sh','controller.py','adapter.py'})
 def test_exact_changed_segment_bytes_and_tiny_preimages(self):
  m=C.decode(self.result[C.PREFIX+'construction.DATA.json'][0]);c=m['changes']['guest/root.sh'];self.assertEqual(C.restore_patch(self.result['guest/root.sh'][0],c['patch']),self.old['guest/root.sh'][0]);self.assertLess(sum(len(C.base64.b64decode(p['before_b64']))for p in c['patch']),1024)
 def reseal_manifest(self,edit):
  files=dict(self.result);m=C.decode(files[C.PREFIX+'construction.DATA.json'][0]);edit(m);files[C.PREFIX+'construction.DATA.json']=(C.canonical(m),0o644);lock=C.decode(files['source.lock.json'][0]);lock['files']=C.rows({n:r for n,r in files.items()if n!='source.lock.json'});files['source.lock.json']=(C.canonical(lock),0o644);return files
 def test_inverse_patch_bytes_offsets_and_membership_tamper_refuse(self):
  for edit in(lambda m:m['changes']['guest/root.sh']['patch'][0].__setitem__('before_b64','Y29ycnVwdA=='),lambda m:m['changes']['guest/root.sh']['patch'][0].__setitem__('start',1),lambda m:m['added_membership'].append('guest/root.sh')):
   with self.assertRaises(ValueError):C.inverse(self.reseal_manifest(edit),self.inputs['predecessor'])
 def test_original_mode_metadata_and_unchanged_body_tamper_refuse(self):
  files=dict(self.result);files['controller.py']=(files['controller.py'][0]+b' ',files['controller.py'][1]);self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
  files=self.reseal_manifest(lambda m:m['changes']['guest/root.sh']['before'].__setitem__('mode',0o755));self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
  files=self.reseal_manifest(lambda m:m['original_lock_metadata'].__setitem__('kind','WEAKENED'));self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
 def test_wrong_parent_family_and_unbound_qmp_refuse_before_import(self):
  for old,diagnostic in((dict(self.old,EXTRA=(b'extra',0o644)),self.diagnostic),(self.old,dict(self.diagnostic,EXTRA=(b'extra',0o644)))):
   with patch.object(C.importlib.util,'spec_from_file_location',side_effect=AssertionError('no unauthenticated import')):self.assertRaises(ValueError,C.project,old,diagnostic,self.own,DIAGNOSTIC)
  self.assertRaises(ValueError,C.project,self.old,self.diagnostic,self.own,DIAGNOSTIC,{'UNISSUED':True})
 def test_template_roles_null_and_no_default_paths(self):
  v=C.decode((HERE/'selection.TEMPLATE.json').read_bytes());self.assertTrue(all(v[n]is None for n in('predecessor','diagnostic','qmp','output')));self.assertTrue(all(v is None for v in self.inputs['actual'].values()))
  with self.assertRaises((ValueError,TypeError)):C.construct(None,None,None,C.pin(self.own['source.lock.json'][0]))
 def test_physical_export_replay_and_no_input_mutation(self):
  with tempfile.TemporaryDirectory()as d:
   report=C.construct(PARENT,DIAGNOSTIC,Path(d)/'source',C.pin(self.own['source.lock.json'][0]),COMPONENT);self.assertEqual(report['files'],389);self.assertFalse(report['full_old_lock_copied']);self.assertFalse(report['full_old_root_copied']);self.assertEqual(C.snapshot(PARENT),self.old);self.assertEqual(C.snapshot(DIAGNOSTIC),self.diagnostic);self.assertTrue(all(v is None for v in report['actual'].values()))
 def test_exact_Gcontract_and_component_tamper_refuses(self):
  C.authenticate_component(self.component,self.inputs['qmp']);bad=dict(self.component);bad['transform.py']=(bad['transform.py'][0]+b' ',0o644)
  with patch.object(C.importlib.util,'spec_from_file_location',side_effect=AssertionError('no unverified producer')):self.assertRaises(ValueError,C.project,self.old,self.diagnostic,self.own,DIAGNOSTIC,bad)
 def test_Gfive_second_quit_and_retirement_predicates_unchanged(self):
  def selected(raw):
   tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='normal_hold_cleanup');return[ast.dump(n)for n in ast.walk(node)if isinstance(n,ast.Call)and(isinstance(n.func,ast.Name)and n.func.id=='quit_hold_qmp'or isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='K'and n.func.attr=='need')]
  self.assertEqual(selected(self.old['controller.py'][0]),selected(self.result['controller.py'][0]))
 def test_combined_actual_fixture_delivery_and_exact_controller_loader(self):
  # Real adapter.contents delivery with maintained MODEL cert data; no Root issue.
  spec=importlib.util.spec_from_file_location('combined_model_contracts',PARENT/'contracts.py');K=importlib.util.module_from_spec(spec);spec.loader.exec_module(K);tree=ast.parse((PARENT/'test_controls.py').read_text());defs=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('pin','seal','modeled')];env=dict(K=K,HERE=PARENT,Path=Path,copy=copy,time=time,hashlib=hashlib,os=os);exec(compile(ast.Module(body=defs,type_ignores=[]),'maintained DATA factory','exec'),env);a=env['modeled'](dependency=True);cert=dict(zip(K.EVIDENCE,a[2:]));cert['_initialized_state']={'MODEL_ONLY':True};cert['_initialized_qualified']={'proof':{'MODEL_ONLY':True}}
  with tempfile.TemporaryDirectory()as d:
   root=Path(d)/'source';root.mkdir()
   for name in('contracts.py','preboot.py','expected-cache-transition.tsv'):shutil.copy2(PARENT/name,root/name)
   for name in('guest','frozen'):shutil.copytree(PARENT/name,root/name)
   for name in('adapter.py','controller.py','guest/root.sh','hold_state_observations.py'):(root/name).write_bytes(self.result[name][0]);(root/name).chmod(self.result[name][1])
   spec=importlib.util.spec_from_file_location('actual_combined_adapter',root/'adapter.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A);fixture=A.contents(a[0],cert,env['pin']('MODEL_source'),'a'*32);out=Path(d)/'fixture';out.mkdir()
   for n,(raw,mode)in fixture.items():
    p=out/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(mode)
   self.assertEqual((out/'expected-cache-transition.tsv').read_bytes(),self.old['expected-cache-transition.tsv'][0]);self.assertEqual((out/'hold_state_observations.py').read_bytes(),self.component['hold_state_observations.py'][0]);self.assertEqual(stat.S_IMODE((out/'hold_state_observations.py').stat().st_mode),0o644);self.assertIn(b'_cr_mark COMPARE_ENTER',(out/'root.sh').read_bytes())
   tree=ast.parse(self.result['controller.py'][0]);f=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='bind_hold_observer');namespace=dict(module=lambda n:K,HERE=root,stat=stat,importlib=__import__('importlib'));exec(compile(ast.Module(body=[f],type_ignores=[]),'fixed loader','exec'),namespace);binder=namespace['bind_hold_observer'];token=object();binding=Mock(return_value=token);calls=[];original=importlib.util.spec_from_file_location
   def tracked(name,path):
    calls.append(Path(path));spec=original(name,path);execute=spec.loader.exec_module
    def mocked(module):execute(module);module.Binding=binding
    spec.loader.exec_module=mocked;return spec
   with patch.object(importlib.util,'spec_from_file_location',side_effect=tracked):self.assertIs(binder(None,None,out,dict(files=C.rows(fixture))),token)
   self.assertEqual(calls,[out/'hold_state_observations.py']);(out/'hold_state_observations.py').chmod(0o755)
   with patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('must refuse before import')):self.assertRaises(ValueError,binder,None,None,out,dict(files=C.rows(fixture)))
 def test_cap_is_unchanged_and_own_closure_authenticated(self):
  self.assertEqual(self.inputs['fixture_source_cap_bytes'],4194304);self.assertEqual(C.CAP,4194304);self.assertEqual(C.own(C.pin(self.own['source.lock.json'][0]))[0],self.own)
if __name__=='__main__':unittest.main(verbosity=2)
