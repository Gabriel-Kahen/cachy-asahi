#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned temporary fixtures only; no producer, GPG, VM, installation or acquisition."""
import ast,importlib.util,json,sys,tempfile,types,unittest
from pathlib import Path
import os,shutil
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C,adapter,materialize,validate
from run import Integration,derive
import workflow,stage_inputs

def module(name,raw):
 m=types.ModuleType(name);m.__file__=str(C.ROOT/'parent604'/(name+'.py'));exec(compile(raw,m.__file__,'exec'),m.__dict__);return m
class Source(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory(prefix='fresh607-fixture-',dir=C.ROOT.parent);self.work=Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def base(self):return dict(packages=[dict(name=n,**r)for n,r in C.profile()['held604'].items()])
 def vm(self):return module('vm',adapter.transform(C.read(C.ROOT/'parent604/run.py'),'run.py')[0])
 def test_whole_six_bodies_and_clocks(self):
  for n in adapter.NAMES:
   raw=C.read(C.ROOT/'parent604'/n);after,r=adapter.transform(raw,n);self.assertTrue(r['whole_inverse']);self.assertEqual(r['before'],C.pin(raw));self.assertEqual(r['after'],C.pin(after))
   clocks=lambda b:[q.value for q in ast.walk(ast.parse(b))if isinstance(q,ast.Constant)and type(q.value)is int and q.value in(600,4500,5400,9600,15600)]
   self.assertEqual(clocks(raw),clocks(after))
   with self.assertRaises(ValueError):adapter.transform(raw+b'\n# late drift\n',n)
 def test_exact607_not_version_labels(self):
  base=self.base();held,want,lock=materialize.selection(base);self.assertEqual((len(held),len(want)),(599,607));self.assertEqual(C.pin(lock),C.profile()['target']);self.assertEqual(want['cachy-asahi-repository-runtime'],'0.1.0-1');self.assertEqual(want['cachy-asahi-boot-report'],'0.1.0-1')
  for field,value in(('version','invented'),('sha256','0'*64),('size',0)):
   other=json.loads(C.enc(base));other['packages'][0][field]=value
   with self.assertRaises(ValueError):materialize.selection(other)
  base['packages'].append(base['packages'][0]);self.assertRaises(ValueError,materialize.selection,base)
 def test_original_complete_positive_and_each_refusal(self):
  vm=self.vm();kernel=types.SimpleNamespace(KERNEL='PRIVATE_SYNTHETIC_KERNEL');nonce='1'*32;profile='2'*64;result=dict(event='result',status='PASS_PUBLIC_PAIRS_APPS6_CURRENT607_INSTALLER',phase='complete',package_count=607,expected_lock_sha256=C.profile()['target']['sha256'],hooks='DISABLED',scriptlets='DISABLED',hardware='NOT RUN',native_container_P0='UNCHANGED-FAILED',nonce=nonce,profile_sha256=profile,**{k:True for k in vm.PASS_FLAGS});events=[dict(event='boot',scope='generic-arm-full-installer-software',page_size=4096,kernel=kernel.KERNEL,uid=0),result,dict(event='exit',status=result['status'],cleanup='PASS')]
  self.assertIs(validate.completion(vm,events,nonce,kernel,profile),result)
  for key in vm.PASS_FLAGS:
   bad=json.loads(C.enc(events));bad[1][key]=False
   with self.assertRaises(ValueError):validate.completion(vm,bad,nonce,kernel,profile)
  for key,value in(('package_count',604),('expected_lock_sha256','0'*64),('nonce','3'*32),('profile_sha256','4'*64),('hooks','ENABLED'),('scriptlets','ENABLED')):
   bad=json.loads(C.enc(events));bad[1][key]=value
   with self.assertRaises(ValueError):validate.completion(vm,bad,nonce,kernel,profile)
 def test_original_protocol_failure_nonce_and_partial(self):
  vm=self.vm();nonce='1'*32;data=b'FULL_INSTALLER '+nonce.encode()+b' '+json.dumps(dict(event='boot')).encode()+b'\n';self.assertEqual(validate.failure(vm,data,nonce)['acceptance'],'NOT_GRANTED')
  for raw in(data.replace(nonce.encode(),b'2'*32),b'FULL_INSTALLER '+nonce.encode()+b' {"event":"unknown"}\n',data.rstrip(b'\n')):
   with self.assertRaises(ValueError):validate.failure(vm,raw,nonce)
 def test_whole_owner_main_and_three_runtime_seams(self):
  raw=C.read(C.ROOT/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py');derived=derive(raw);self.assertIn('Y.verifier_absent',derived)
  self.assertEqual([n.name for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)],[n.name for n in ast.parse(derived).body if isinstance(n,ast.FunctionDef)])
  with self.assertRaises(ValueError):derive(raw.replace(b'adapter.materialize(args.legacy_source,candidate)',b'adapter.materialize(args.legacy_source,other)'))
  producer=self.work/'producer';(producer/'private').mkdir(parents=True);target=self.work/'ready604';calls=[]
  original=types.SimpleNamespace(prepare=lambda *args:calls.append(('original',args)));contract=types.SimpleNamespace(scoped_load=lambda *a:{})
  api=Integration(self.work,self.work,self.work,contract);args=['eight','seven','audio','legacy',target,'policy','management','setup','welcome','source','apps','authority']
  with patch('run.runtime_context.BaseCache'),patch('run.load',return_value=object()),patch('run.materialize.prepare',side_effect=lambda *a,**k:calls.append(('new',a))):self.assertEqual(api.bind(original,producer).prepare('ready587',producer,*args),target)
  self.assertEqual(calls[0][1][6],producer/'private/latest607-base604');self.assertEqual(calls[1][1][:4],(producer/'private/latest607-base604',self.work,producer,target));self.assertTrue(api.verifier_absent(producer));(producer/'private/latest607-verifier').mkdir();self.assertFalse(api.verifier_absent(producer))
 def test_paths_before_writes_and_singlelink_fd(self):
  outside=self.work/'outside';outside.write_bytes(b'private sentinel');alias=self.work/'alias';alias.symlink_to('outside')
  with self.assertRaises(ValueError):C.read(alias)
  hard=self.work/'hard';hard.hardlink_to(outside)
  with self.assertRaises(ValueError):C.read(outside)
  with self.assertRaises(ValueError):C.fresh(self.work/'new',self.work/'new/child')
  with self.assertRaises(ValueError):C.fresh(self.work/'same',self.work/'same')
  self.assertFalse((self.work/'new').exists());self.assertEqual(outside.read_bytes(),b'private sentinel')
 def test_eight_archive_bodies_metadata_and_source_private_copy(self):
  public=os.environ.get('FRESH607_ACCEPTED_PUBLIC')
  if not public:raise RuntimeError('explicit qualified DATA fixture root required; no skipped source controls')
  public=Path(public);private=self.work/'accepted-data';private.mkdir()
  for row in C.profile()['incoming'].values():
   for n,w in ((row['path'],{k:row[k]for k in('bytes','sha256')}),(row['signature']['path'],{k:row['signature'][k]for k in('bytes','sha256')})):
    target=private/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(C.checked(public/n,w))
  checks_path=C.ROOT/'parent853/historical/boot391/held606/held-tools/scripts/checks/package_checks.py';spec=importlib.util.spec_from_file_location('_private_trusted_archive_inspector',checks_path);checks=importlib.util.module_from_spec(spec);spec.loader.exec_module(checks);self.assertEqual(set(materialize.inspect(private,checks)),set(C.profile()['incoming']))
  row=next(iter(C.profile()['incoming'].values()));path=private/row['path'];path.write_bytes(path.read_bytes()+b'private drift')
  with self.assertRaises(ValueError):materialize.inspect(private,checks)
 def test_current_workflow_and_whole_parent_inverse(self):
  old=C.read(C.ROOT/'installer604'/workflow.OLD);template=__import__('page_source').with_mode(__import__('tooling_source').with_tooling(__import__('compiler6_source').with_compiler6(__import__('cache_controls_context').with_cache(workflow.derive(old)))));self.assertEqual(template,C.read(C.HERE/'workflow-template.yml'));expected=template.replace(b'@FRESH607_MANIFEST@',C.pin(C.read(C.ROOT/'source-manifest.json'))['sha256'].encode())
  for n in workflow.ALIASES:self.assertEqual(C.read(C.ROOT/n),expected)
  self.assertIn(b'WORKFLOW_SOURCE: ${{ inputs.source }}',expected);self.assertIn(b'FRESH_SOURCE: ${{ inputs.fresh_source_revision }}',expected);self.assertIn(b'      fresh_source_revision:',expected);self.assertIn(b'test \"$CURRENT_CHILD_SOURCE\" = \"$CURRENT_WORKFLOW_SHA\"',expected)
 def test_data_stage_private_synthetic991_original_transport_and_refusals(self):
  path=C.ROOT/'parent853/latest/implementation/latest_transport.py';spec=importlib.util.spec_from_file_location('_held_original_synthetic_transport',path);T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T);values={'fixture/%04d'%n:(b'hello'if n==0 else b'')for n in range(991)};files={}
  for n,b in values.items():files[n]=dict(**C.pin(b),chunks=[dict(packet='part-0001',path='chunk-0001.bin',**C.pin(b))]if b else[])
  index=dict(files=files,bytes=5,cap=T.TOTAL,packet_raw_cap=T.PACKET,packet_count=1,reconstruction=T.RECONSTRUCTION,scope=T.SCOPE);packets={'part-0000':{'retention.json':C.enc(index)},'part-0001':{'chunk-0001.bin':b'hello'}};_,actual=T.reconstruct(packets);self.assertEqual(actual,values);out=self.work/'data';stage_inputs.write_values(actual,{n:C.pin(b)for n,b in values.items()},out);self.assertEqual(len(list(out.rglob('*'))),992)
  bad=dict(values);bad['fixture/0000']=b'changed'
  with self.assertRaises(ValueError):stage_inputs.write_values(bad,{n:C.pin(b)for n,b in values.items()},self.work/'bad')
  self.assertFalse((self.work/'bad').exists());packets['part-0001']['chunk-0001.bin']=b'changed'
  with self.assertRaises(ValueError):T.reconstruct(packets)
 def test_closed_owner_retirement(self):
  value=dict(status='PASS',container_cleanup='PASS',private_cleanup='PASS',source_cache_preservation='PASS',image_cleanup='PASS');self.assertIs(validate.owner(value),value)
  for key in value:
   bad=dict(value);bad[key]='UNKNOWN'
   with self.assertRaises(ValueError):validate.owner(bad)
if __name__=='__main__':unittest.main(verbosity=2)
