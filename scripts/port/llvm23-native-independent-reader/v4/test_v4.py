#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fenced independent256 Source/tuple DATA controls; no operational Reader."""
import argparse,copy,ctypes,fcntl,hashlib,importlib.util,json,os,socket,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('independent_reader256_controls',HERE/'reader.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r);v=r.v
SOURCE=PARENT=ANCESTOR=None

def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','fcntl.flock','fcntl.lockf','os.unshare','os.setns'):raise RuntimeError('independent Reader DATA fence: '+event)
sys.addaudithook(fence)
def desc(rows):return{n:dict(**r.descriptor(row),blob=v.git_oid('blob',row[0]))for n,row in rows.items()}
def rebind(rows,pins):
 m=v.decode(rows['source-map.json'][0]);m['files']={n:r.descriptor(row)for n,row in rows.items()if n!='source-map.json'};rows['source-map.json']=(v.canonical(m),0o644)
 found=desc(rows);p=copy.deepcopy(pins);p.update(source_map_sha256=hashlib.sha256(rows['source-map.json'][0]).hexdigest(),source_tree=r.git_tree(found),source_files=len(rows),source_bytes=sum(len(b)for b,_ in rows.values()));return rows,p,found
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  v.END=time.monotonic()+120;cls.pins=v.load(HERE/'pins.json');cls.found=v.source_namespace(SOURCE,cls.pins);cls.rows={n:(v.read(SOURCE/n,64*v.MIB),row['mode'])for n,row in cls.found.items()}
  cls.prior=dict(cls.rows);cls.prior.pop('source-map.json');cls.prior.pop(r.META);cls.prior[r.VOLUME]=cls.prior.pop(r.SAVED_VOLUME);cls.prior['source-map.json']=cls.prior.pop(r.SAVED_MAP)
 def setUp(self):
  v.END=time.monotonic()+120
  def denied(*a,**k):raise AssertionError('operational Reader entry/decode/replay forbidden')
  for module,names in[(r,('main',)),(v,('main','replay','full_zip'))]:
   for name in names:p=patch.object(module,name,denied);p.start();self.addCleanup(p.stop)
 def model(self):
  pins=copy.deepcopy(self.pins);b=v.load(HERE/'binding.TEMPLATE.json');b['actual']=dict(source=pins['source'],ref=pins['ref'],run='11',job='22',attempt=1,approval='a'*64,authority='MODELED_ROOT_AUTHORITY_NOT_ISSUED',image='sha256:'+'b'*64,artifact='33',reader='MODELED_READER_NOT_ENTERED')
  for n in('provider_sha256','source_commit_sha256','export_sha256','package_sha256','reader_sha256','pins_sha256'):b[n]='c'*64
  b['original_archive']=dict(bytes=1,sha256='d'*64);b['full_original_decode']=dict(bytes=1,files=1,map_sha256='e'*64);return b,pins
 def observations(self):
  b,pins=self.model();a=b['actual'];approval=dict(status='ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT',authority=a['authority'],source_reviewed=True,holds_preserved=True,operation=pins['operation'],source=a['source'],ref=a['ref'],source_map_sha256=pins['source_map_sha256'],resources=pins['policy'])
  provider=dict(run=dict(id=11,run_attempt=1,event='workflow_dispatch',head_sha=a['source'],head_branch=a['ref'].removeprefix('refs/heads/'),repository={'full_name':'Gabriel-Kahen/cachy-asahi'},status='completed',conclusion='success'),job=dict(id=22,run_id=11,head_sha=a['source'],name='llvm23-native-v2',status='completed',conclusion='success'),artifact=dict(id=33,expired=False,name='llvm23-native-v2-11-1',workflow_run=dict(id=11,head_sha=a['source'])))
  return provider,approval,b,pins
 def test_published256_pins_and_unissued_actual_template(self):
  self.assertEqual(self.pins['source'],'365a763bc515a1b3550cc804536ddbf66353aac8');self.assertEqual(self.pins['ref'],'refs/heads/codex/llvm23-source-reference-native-v2-20261115-r2');self.assertEqual((len(self.found),self.pins['source_bytes']),(256,40919517));self.assertIsNone(self.pins['historical253']['source'])
  b=v.load(HERE/'binding.TEMPLATE.json');self.assertEqual(b['actual']['source'],self.pins['source']);self.assertEqual(b['actual']['ref'],self.pins['ref']);self.assertTrue(all(x is None for k,x in b['actual'].items()if k not in('source','ref')))
  with self.assertRaises(ValueError):r.binding(b,self.pins)
 def test_binding_scope_only_preserves_actual_tuple(self):
  b,pins=self.model();before=copy.deepcopy(b);self.assertEqual(r.binding(b,pins),before);self.assertEqual(b['actual'],before['actual'])
  for key,value in [('source',r.B.old_pins['parent']['source']),('ref','refs/heads/codex/llvm23-source-reference-native-v2-20261115')]:
   bad=copy.deepcopy(b);bad['actual'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):r.binding(bad,pins)
 def test_complete_physical256_to253_to251_to248(self):
  historical,restored=r.inverse253(SOURCE,self.pins,self.found,PARENT,ANCESTOR);self.assertEqual(len(historical),253);self.assertEqual(len(restored),251);self.assertEqual(historical,r.namespace_rows(self.prior,r.B.old_pins))
 def test_only_volume_map_and_three_added_leaves(self):
  self.assertEqual(set(self.rows)-set(self.prior),{r.META,r.SAVED_VOLUME,r.SAVED_MAP});self.assertEqual({n for n in self.prior if self.rows[n]!=self.prior[n]},{r.VOLUME,'source-map.json'});self.assertEqual(self.rows[r.VOLUME],(self.prior[r.VOLUME][0].replace(r.OLD.encode(),r.NEW.encode()),0o644))
 def test_recomputed_map_metadata_tamper_refused(self):
  for kind in('parent','before','after','count','literal','extra','NULL'):
   rows=dict(self.rows);m=v.decode(rows[r.META][0])
   if kind=='parent':m['parent']['source']='f'*40
   elif kind in('before','after'):m['changed'][r.VOLUME][kind]['sha256']='0'*64
   elif kind=='count':m['changed'][r.VOLUME]['inverse']['count']=2
   elif kind=='literal':m['changed'][r.VOLUME]['inverse']['new']="h['CapAdd']in(['CHOWN'],['CAP_CHOWN'],['SYS_ADMIN'])"
   elif kind=='NULL':m['actual']['run']='11'
   else:m['extra']='unreviewed'
   rows[r.META]=(v.canonical(m),0o644);rows,pins,found=rebind(rows,self.pins)
   with self.subTest(kind=kind),self.assertRaises(ValueError):r.inverse253_rows(rows,pins,found,PARENT,ANCESTOR)
 def test_archives_actor_mode_and_membership_tamper_refused(self):
  for kind in('savedvolume','savedmap','volume','actor','mode','extra'):
   rows=dict(self.rows)
   if kind=='extra':rows['unrecorded.DATA']=(b'unknown\n',0o644)
   elif kind=='mode':rows[r.SAVED_VOLUME]=(rows[r.SAVED_VOLUME][0],0o755)
   else:
    name={'savedvolume':r.SAVED_VOLUME,'savedmap':r.SAVED_MAP,'volume':r.VOLUME,'actor':'actor/work_check.py'}[kind];rows[name]=(rows[name][0]+b'\n',rows[name][1])
   rows,pins,found=rebind(rows,self.pins)
   with self.subTest(kind=kind),self.assertRaises(ValueError):r.inverse253_rows(rows,pins,found,PARENT,ANCESTOR)
 def test_historical_map_mode_membership_schema_refuse(self):
  for kind in('mode','body','extra','NULL','schema'):
   rows=dict(self.prior)
   if kind=='mode':rows['actor/entry.py']=(rows['actor/entry.py'][0],0o755)
   elif kind=='body':rows['actor/entry.py']=(rows['actor/entry.py'][0]+b'\n',0o644)
   elif kind=='extra':rows['unrecorded.DATA']=(b'unknown\n',0o644)
   else:
    m=v.decode(rows['source-map.json'][0]);m['actual']['source']='f'*40 if kind=='NULL'else None
    if kind=='schema':m['schema']=True
    rows['source-map.json']=(v.canonical(m),0o644)
   with self.subTest(kind=kind),self.assertRaises(ValueError):r.namespace_rows(rows,r.B.old_pins)
 def test_provider_approval_models_preserve_actual256_tuple(self):r.admitted_provider(*self.observations())
 def test_old_head_map_failed_attempt_and_artifact_refuse(self):
  for kind in('run','job','artifact','approval_source','approval_map','failed','attempt'):
   provider,approval,b,pins=self.observations()
   if kind in('run','job'):provider[kind]['head_sha']=r.B.old_pins['parent']['source']
   elif kind=='artifact':provider['artifact']['workflow_run']['head_sha']=r.B.old_pins['parent']['source']
   elif kind=='approval_source':approval['source']=r.B.old_pins['parent']['source']
   elif kind=='approval_map':approval['source_map_sha256']=r.B.old_pins['source_map_sha256']
   elif kind=='attempt':provider['run']['run_attempt']=2
   else:provider['run']['conclusion']='failure'
   with self.subTest(kind=kind),self.assertRaises(ValueError):r.admitted_provider(provider,approval,b,pins)
 def test_actual_proof_requires256_members_new_volume_current_head_map(self):
  b,pins=self.model();proof=dict(status='PASS_EXACT_HOSTED_SOURCE_READBACK',files=self.found,binding=dict(b['actual'],source_map_sha256=pins['source_map_sha256']));r.proof_join(proof,self.found,b['actual'],pins)
  for kind in('volume','membership','head','map'):
   bad=copy.deepcopy(proof)
   if kind=='volume':bad['files'][r.VOLUME]=r.namespace_rows(self.prior,r.B.old_pins)[r.VOLUME]
   elif kind=='membership':bad['files']=r.namespace_rows(self.prior,r.B.old_pins)
   elif kind=='head':bad['binding']['source']=r.B.old_pins['parent']['source']
   else:bad['binding']['source_map_sha256']=r.B.old_pins['source_map_sha256']
   with self.subTest(kind=kind),self.assertRaises(ValueError):r.proof_join(bad,self.found,b['actual'],pins)
 def test_frozen_dependencies_and_exact_historical_projection_proofs(self):
  self.assertEqual(r.B.projection_proof['historical253']['inverse'],'EXACT_FUNCTION_BYTES');self.assertFalse(r.B.projection_proof['actual_Source_ref_run_job_map_changes']);self.assertEqual(r.B.initializer_proof['inverse'],'EXACT_FUNCTION_BYTES')
 def test_unchanged_resource_actor_initializer_policy(self):
  old=r.B.old_pins;self.assertEqual(self.pins['policy'],old['policy']);self.assertEqual(self.pins['initializer_code_sha256'],old['initializer_code_sha256'])
  for name in('actor/entry.py','actor/runtime.py','actor/container_mode.py','actor/work_check.py','hosted/entry.py','hosted/producer.py','hosted/common.py'):self.assertEqual(self.pins['files'].get(name),old['files'].get(name))
 def test_permanent_process_network_ffi_lease_fence(self):
  for event in('subprocess.Popen','socket.__new__','ctypes.dlopen','os.system','os.fork','fcntl.flock'):
   with self.subTest(event=event),self.assertRaises(RuntimeError):sys.audit(event)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--parent-source',type=Path,required=True);p.add_argument('--ancestor-source',type=Path,required=True);a=p.parse_args();SOURCE,PARENT,ANCESTOR=a.source_root,a.parent_source,a.ancestor_source;unittest.main(argv=[__file__],verbosity=2)
