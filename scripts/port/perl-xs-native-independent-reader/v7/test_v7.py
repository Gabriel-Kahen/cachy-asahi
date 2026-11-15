# SPDX-License-Identifier: MIT
"""Fenced actual Source DATA and inherited full pipeline models; no Reader role."""
import argparse,ast,copy,hashlib,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT_SOURCE=None

def load(name,path=None):
 p=path or HERE/(name+'.py');s=importlib.util.spec_from_file_location('xs_v7_test_'+name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
R=load('reader');A=load('adapters');d=R.d
# Reuse reviewed controls as local trusted test source, never exported artifact code.
old=HERE.parent/'v6/test_v6.py';body=old.read_bytes()
if hashlib.sha256(body).hexdigest()!='3525ba84968f2438f4ffc18a23f49b282e86d8756b4719fdb2ff228e69389f43':raise ValueError('whole frozen6 test source')
T=load('frozen_controls',old);T.R=R;T.A=A;T.d=d;T.C=A.C
R.B.source_projection=R.B.ancestor.source_projection;R.B.raw5=R.B.ancestor.raw5;R.B.V5=R.B.ancestor.V5

def binding():return dict(source='a'*40,ref=R.REF,run='7',job='8',approval='3'*64,source_map_sha256=R.MAP,operation=R.OUTER)
T.binding=binding
EXCLUDE={'test_new_v6_binding_rejects_old_sources_or_wrong_literals','test_actual321_to316_to311_to305_to298_to272_original200_Source_DATA','test_archived_v3_inverse_bodies_cannot_be_changed_or_missing','test_new_actor_delta_is_explicit_and_global_path_guard_not_relaxed','test_changed_ALPM_fixed_root_or_bounded_helper_refuses','test_unprofiled_runtime_probe_or_global_change_refuses','test_primary_error_reverse_chain_or_early_success_refuses','test_passive_producer_generator_projection_exact_inverse_only','test_exact_published_v6_binding_rejects_closed316'}
methods={n:v for n,v in vars(T.Controls).items()if callable(v)and(n in('setUp','producer_fixture','run_producer')or n.startswith('test_')and n not in EXCLUDE)}
def frozen_substitution_refuses(self):
 with patch.object(R.B.ancestor.ancestor.ancestor,'raw3',return_value=b'not expected'):
  with self.assertRaises((ValueError,SyntaxError)):R.B.source_projection(3)
methods['test_frozen_passive_substitution_refused']=frozen_substitution_refuses
Inherited=type('InheritedPipelineControls',(unittest.TestCase,),methods)

def envelope():return dict(schema=1,binding=binding(),artifact=dict(id='9',bytes=1,sha256='5'*64,metadata_sha256='6'*64))
def leaves():
 m=d.decode(d.read(ROOT_SOURCE,'source-map.json',d.MIB));r={n:(d.read(ROOT_SOURCE,n,64*d.MIB),v['mode'])for n,v in m['files'].items()};r['source-map.json']=(d.read(ROOT_SOURCE,'source-map.json',d.MIB),0o644);return r
class SuccessorControls(unittest.TestCase):
 def setUp(self):
  T.Controls.setUp(self)
  for n in('os.statvfs','os.fstatvfs'):
   p=patch(n,side_effect=AssertionError('no actual capacity/quota observation in DATA controls'));p.start();self.addCleanup(p.stop)
 def test_full_actual326_and_all_historical_inverses(self):self.assertEqual(R.source(ROOT_SOURCE,binding())['actual'],R.ACTUAL)
 def test_external_actual_tuple_preserved(self):
  v=envelope();b,a=R.binding(v);self.assertEqual(b,v['binding']);self.assertIs(b,v['binding']);self.assertEqual(A.inner_binding(b,{'operation':R.INNER},d),dict(b,operation=R.INNER))
 def test_NULL_and_closed_source_and_wrong_literals_refuse(self):
  for k,v in(('source',None),('source',R.PARENT),('source',True),('source','a'*39),('ref',None),('ref',R.B.parent.REF),('operation',R.INNER),('source_map_sha256',R.PARENT_MAP),('run',None),('job','0'),('approval',None)):
   bad=envelope();bad['binding'][k]=v
   with self.subTest(k=k,v=v),self.assertRaises(ValueError):R.binding(bad)
 def test_inverse_requires_all_five_old_leaves_and_exact_mode(self):
  original=leaves()
  for n in R.ARCHIVE_MAP.values():
   for mode in('missing','changed','mode'):
    bad=dict(original)
    if mode=='missing':bad.pop(n)
    elif mode=='changed':bad[n]=(bad[n][0]+b' ',bad[n][1])
    else:bad[n]=(bad[n][0],0o755)
    with self.subTest(n=n,mode=mode),self.assertRaises(ValueError):R.inverse321(bad)
 def test_one_Path_to_string_seam_and_every_other_function_frozen(self):
  old=d.read(ROOT_SOURCE,'previous-v6/native.py',d.MIB);new=d.read(ROOT_SOURCE,'consumer/native_adapter/native.py',d.MIB);proof=R.native_delta(old,new);self.assertNotEqual(proof['before'],proof['after']);self.assertEqual(new.replace(R.AFTER,R.BEFORE),old)
  functions=lambda raw:{n.name:ast.dump(n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  a,b=functions(old),functions(new);self.assertEqual([n for n in a if a[n]!=b[n]],['actor'])
 def test_nonstring_or_second_conversion_or_guard_mutation_refused(self):
  old=d.read(ROOT_SOURCE,'previous-v6/native.py',d.MIB);new=d.read(ROOT_SOURCE,'consumer/native_adapter/native.py',d.MIB)
  for changed in(new.replace(R.AFTER,R.BEFORE),new+R.AFTER,new.replace(b'DOCKER = [',b'DOCKER = [# GLOBAL CHANGE\n'),new.replace(b"value['page_bytes'] in (4096, 16384)",b"value['page_bytes'] in (4096,)")):
   with self.subTest(pin=d.pin(changed)),self.assertRaises(ValueError):R.native_delta(old,changed)
 def test_actual_runtime_tuple_is_not_retagged_to_parent(self):
  P=R.B.inner();F=load('fixture',HERE.parent/'v6/producer_fixture.py')
  for key,value in(('source',dict(sha=R.PARENT,ref=R.B.parent.REF.removeprefix('refs/heads/'))),('run','99'),('job','99')):
   f=F.fixture(P,d,binding(),ROOT_SOURCE);f['op'][key]=value
   raw=T.encoded(f['op']);f['data']['xs/operation.json']=f['data']['bundle/operation.json']=raw;f['h']['operation_sha256']=d.pin(raw)['sha256']
   data=f['finish']();d.set_names(data)
   with self.subTest(key=key),self.assertRaises(ValueError):P.producer(lambda n,cap=16*d.MIB:data[n],f['image'],f['work'],f['h'],f['b'],f['daemon'],d)
 def test_closed_failed_and_incomplete_producer_receipts_refuse(self):
  P=R.B.inner();F=load('fixture',HERE.parent/'v6/producer_fixture.py')
  for key,value in(('status','SMOKE_FAILED'),('error','MODELED_FAILURE'),('owned_resources_absent',False),('XS_acceptance',True)):
   f=F.fixture(P,d,binding(),ROOT_SOURCE);f['report'][key]=value;data=f['finish']();d.set_names(data)
   with self.subTest(key=key),self.assertRaises(ValueError):P.producer(lambda n,cap=16*d.MIB:data[n],f['image'],f['work'],f['h'],f['b'],f['daemon'],d)
 def test_strict_runner_and_preflight_are_exact_archived_bytes(self):
  r=leaves();old=R.inverse321(r)
  for n in('consumer/preflight.py','consumer/runner/run.py'):self.assertEqual(r[n],old[n])
  self.assertIn(b'path(sandbox_path)',r['consumer/runner/run.py'][0])
 def test_producer_generator_projection_exact_and_duplicate_refused(self):
  raw=R.B.raw5('producer.py');new=R.B.producer_projection(raw);before=b"NATIVE_SHA='1db474ed81295c3604212998617bb44c1ed0339c224d63f61b06768cef6bde4f'";after=("NATIVE_SHA='"+R.B.NEW_NATIVE+"'").encode();self.assertEqual(new.count(after),1);self.assertEqual(new.replace(after,before),raw)
  with self.assertRaises(ValueError):R.B.producer_projection(raw+before)
 def test_frozen6_source_projection_is_only_three_leaf_read_seams(self):
  r=leaves();old=R.inverse321(r);b=dict(binding(),source=R.PARENT,ref=R.B.parent.REF,source_map_sha256=R.PARENT_MAP,operation=R.B.parent.OUTER);self.assertEqual(R.B.source6(old,b)['actual'],R.ACTUAL)
  self.assertEqual(binding()['source'],'a'*40);self.assertEqual(binding()['ref'],R.REF)
 def test_whole_passive6_dependency_changes_refuse(self):
  original=R.B.PINS['reader.py'];R.B.PINS['reader.py']='0'*64
  try:
   with self.assertRaises(ValueError):R.B.raw6('reader.py')
  finally:R.B.PINS['reader.py']=original
 def test_adapters_change_only_outer_identity(self):
  raw=R.B.raw6('adapters.py');new=(HERE/'adapters.py').read_bytes();expected=raw.replace(b'xs_v6',b'xs_v7').replace(b'outer v6',b'outer v7').replace(b'actual external v6',b'actual external v7').replace(b'complete v6',b'complete v7').replace(b'perl5423-native-xs-v6',b'perl5423-native-xs-v7');self.assertEqual(new,expected)
 def test_source_and_actor_role_selectors_still_unissued(self):
  v=d.decode((HERE/'binding.TEMPLATE.json').read_bytes());self.assertIsNone(v['binding']['source']);self.assertIsNone(v['binding']['run']);self.assertIsNone(v['binding']['job']);self.assertIsNone(v['artifact']['id'])

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--v7-source',required=True,type=Path);a=p.parse_args();ROOT_SOURCE=a.v7_source.resolve();T.ROOT_SOURCE=ROOT_SOURCE
 suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)for c in(Inherited,SuccessorControls));result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
