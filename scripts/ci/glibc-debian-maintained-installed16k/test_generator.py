# SPDX-License-Identifier: MIT
"""Finite portable data/source controls; subprocess actors are always forbidden."""
import ast,copy,io,json,shutil,subprocess,sys,tempfile,unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());sys.path.insert(0,str(HERE));import generator as G
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));p.start();self.addCleanup(p.stop)
 def emitted(self,complete=False):
  out=self.work/'emitted';result=G.emit(ROOT,out)
  if complete:
   for name,row in G.source(ROOT)['files'].items():
    p=out/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
  folder=out/G.NEW;C=G.load('installed_caa3_contract',folder/'contract.py')
  with patch.dict(sys.modules,{'contract':C}):A=G.load('installed_caa3_adapter',folder/'adapter.py')
  with patch.dict(sys.modules,{'contract':C,'adapter':A}):R=G.load('installed_caa3_run',folder/'run.py')
  P=G.load('installed_caa3_phase',folder/'phase_gate.py');return out,result,folder,C,A,R,P
 def test_exact116_source_and30_derived_files_without_framework_copy(self):
  out,r,folder,C,*_=self.emitted(True);self.assertEqual(len(G.source(ROOT)['files']),119);self.assertEqual(len(r['files']),31);self.assertEqual(r['composed_normal_native_files'],15);self.assertEqual(len(list(out.rglob('*')))>29,True);C.check_source(out)
  for p in out.rglob('*.py'):ast.parse(p.read_bytes())
  for name in ('sandbox.py','support.py'):self.assertEqual((folder/name).read_bytes(),(ROOT/G.OLD/name).read_bytes())
  self.assertFalse((out/'scripts/ci/glibc-debian-maintained-provider-interruption').exists())
 def test_default_unbound_blocks_before_missing_paths_output_and_actors(self):
  out,r,folder,C,A,R,P=self.emitted();policy=json.loads((folder/'input-policy.json').read_bytes());self.assertEqual(policy['binding'],dict(native_lifecycle=None,system16k=None));self.assertEqual(policy['interruption'],'SEPARATE_NOT_A_PREREQUISITE')
  with self.assertRaisesRegex(ValueError,'UNBOUND'):C.gate(Path('/missing'))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):R.execute(type('Args',(),dict(acceptances=Path('/missing')))())
  self.assertEqual({p.name for p in self.work.iterdir()},{'emitted'})
 def test_native_four_edits20_bodies_and_current_composed_candidate(self):
  out,r,folder,C,A,*_=self.emitted(True);text,receipt=A.derive(out);self.assertEqual(receipt['counted_edits'],4);self.assertEqual(len(receipt['unchanged_bodies']),20);self.assertIn('config_handoff',receipt['unchanged_bodies']);self.assertEqual(receipt['changed_bodies'],['guard','validate_runtime']);original=(ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/container.py').read_text();bodies=lambda s:{n.name:ast.get_source_segment(s,n) for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};a,b=bodies(original),bodies(text)
  for name in ('transaction','run_case','copy_probes','payload','unchanged','runtime_mounts','snapshot','Commands','main'):self.assertEqual(a[name],b[name],name)
  self.assertEqual((out/G.NATIVE/'container.py').read_bytes(),(ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/container.py').read_bytes());self.assertIn("'2.43.caa3-1'",(out/G.NATIVE/'common.py').read_text());self.assertIn('CACHY_GNU_PROVIDER_LIFECYCLE',text);self.assertEqual(r['composed_identity_edits'],{'common.py':2,'owner/job.py':5})
 def bound(self,folder,C,P):
  acceptance=self.work/'acceptance';acceptance.mkdir();policy=json.loads((folder/'input-policy.json').read_bytes());values={}
  for i,(kind,status) in enumerate(P.STATUSES.items(),2):values[kind]=dict(status=status,candidate=policy['candidate'],source_authority_sha256=policy['candidate']['authority_sha256'],native_pair=P.PAIR,provider_archive_sha256=P.PAIR['archive_sha256'],provider_archive_bytes=P.ARCHIVE_BYTES,source_sha=str(i)*40,run_id=i,hardware='NOT_RUN',release='NOT_ADMITTED',ordered_cleanup='PASS',cleanup='PASS',page_size=4096 if kind=='native_lifecycle' else 16384,scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',ALPM_installation='PASS' if kind=='native_lifecycle' else 'NOT_RUN')
  def save():
   policy['status']='BOUND_BY_ROOT'
   for kind,value in values.items():raw=G.encoded(value);(acceptance/kind).write_bytes(raw);policy['binding'][kind]=dict(path=kind,**G.pin(raw))
   (folder/'input-policy.json').write_bytes(G.encoded(policy))
  save();return acceptance,values,save
 def test_gate_two_actual_typed_decisions_same_current_archive_authority_and_pair(self):
  _,_,folder,C,_,_,P=self.emitted();root,values,save=self.bound(folder,C,P);self.assertEqual(set(C.gate(root)),{'native_lifecycle','system16k'})
  original=copy.deepcopy(values)
  for field,bad in (('candidate',dict(original['system16k']['candidate'],version='2.43.caa1-1')),('candidate',dict(original['system16k']['candidate'],version='2.43.caa2-1')),('provider_archive_sha256','b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12'),('provider_archive_bytes',1),('source_authority_sha256','0'*64),('native_pair',dict(P.PAIR,payload=dict(node_count=1066,node_manifest_sha256='a'*64)))):
   values.clear();values.update(copy.deepcopy(original));values['system16k'][field]=bad;save()
   with self.subTest(field=field),self.assertRaises(ValueError):C.gate(root)
 def test_gate_native_actual_alpm_and_staged_only16k_qualifications(self):
  _,_,folder,C,_,_,P=self.emitted();root,values,save=self.bound(folder,C,P);original=copy.deepcopy(values)
  for kind,field,bad in (('native_lifecycle','ALPM_installation','NOT_RUN'),('native_lifecycle','page_size',16384),('native_lifecycle','ordered_cleanup','UNKNOWN'),('system16k','ALPM_installation','PASS'),('system16k','scope','ALPM_INSTALLED'),('system16k','page_size',4096),('system16k','cleanup','UNKNOWN'),('system16k','status','ROOT_ACCEPTED_GNU_PROVIDER_SYSTEM_PATHS_GENERIC16K'),('native_lifecycle','status','ROOT_ACCEPTED_CONVENTIONAL_PROVIDER_NORMAL_LIFECYCLE')):
   values.clear();values.update(copy.deepcopy(original));values[kind][field]=bad;save()
   with self.subTest(kind=kind,field=field),self.assertRaises(ValueError):C.gate(root)
 def test_pair_or_source_carrier_and_same_execution_do_not_supply_future_prerequisite(self):
  _,_,folder,C,_,_,P=self.emitted();root,values,save=self.bound(folder,C,P);original=copy.deepcopy(values)
  for kind,field,bad in (('native_lifecycle','source_sha',original['native_lifecycle']['candidate']['source_packet_ref']),('native_lifecycle','run_id',P.PAIR['run_id']),('system16k','source_sha',original['native_lifecycle']['source_sha']),('system16k','run_id',original['native_lifecycle']['run_id'])):
   values.clear();values.update(copy.deepcopy(original));values[kind][field]=bad;save()
   with self.subTest(field=field),self.assertRaises(ValueError):C.gate(root)
 def protocol(self,C):
  selection=dict(nonce='a'*32,kernel=dict(release='exact16k'),kernel_profile_sha256='b'*64,source_nodes_sha256='c'*64,capabilities_sha256='d'*64);files={'result.json':dict(bytes=0,sha256='e'*64)}
  for case in ('pristine','modified'):
   for stage in ('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'):files[case+'-'+stage+'-root.json.gz']=dict(bytes=0,sha256='e'*64)
  rows=[dict(event='boot',observer_nofile=dict(before=[1024,4096],after=[8192,8192],scope='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD'),page_size=16384,kernel='exact16k',architecture='aarch64',kernel_profile_sha256='b'*64),dict(event='result',status=C.PASS,page_size=16384,normal_runtime_observations=8,hardware='NOT_RUN',release='NOT_ADMITTED',source_nodes_sha256='c'*64,capabilities=dict(status='EXACT_SOURCE_MAP_PRESERVED',cases=2,stages=8,source_capabilities_sha256='d'*64),isolation=dict(status='PASS_OBSERVED_NATIVE_CAPS_AND_MOUNT_FENCE',mask=2149843195,no_new_privs=1,seccomp=2,raw_block_devices=[],writable_source_alias=False,mount_flags=[15,4096]),files=files,bytes=0),dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_CLONES_REMOVED')];return selection,rows
 def test_actual_guest_string_emitter_and_host_byte_parser_roundtrip(self):
  _,_,folder,C,_,R,_=self.emitted();selection,rows=self.protocol(C);node=next(n for n in ast.parse((folder/'guest.py').read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='emit');scope=dict(json=json,C=C);exec(compile(ast.Module(body=[node],type_ignores=[]),'<trusted-source-emitter>','exec'),scope);stream=io.StringIO()
  with redirect_stdout(stream):
   for row in rows:scope['emit'](selection['nonce'],row)
  uart=stream.getvalue().encode();self.assertEqual(R.protocol(uart,selection)['status'],C.PASS);self.assertTrue(uart.startswith(b'DEBIAN_MAINTAINED_INSTALLED16K '));self.assertIn("b'DEBIAN_MAINTAINED_INSTALLED16K '",(folder/'run.py').read_text());self.assertNotIn(b'GNU_INSTALLED16K ',uart)
  with self.assertRaises(ValueError):R.protocol(uart.replace(b'DEBIAN_MAINTAINED_INSTALLED16K ',b'GNU_INSTALLED16K '),selection)
 def test_protocol_keeps16_maps8_runtime10caps_nonce_and_cleanup(self):
  _,_,folder,C,_,R,_=self.emitted();selection,rows=self.protocol(C)
  def uart(v):return b'\n'.join(('DEBIAN_MAINTAINED_INSTALLED16K '+selection['nonce']+' '+json.dumps(r)).encode() for r in v)
  for kind in ('page','normal','maps','caps','alias','cleanup','duplicate','nonce'):
   v=copy.deepcopy(rows)
   if kind=='page':v[0]['page_size']=4096
   elif kind=='normal':v[1]['normal_runtime_observations']=4
   elif kind=='maps':v[1]['files'].pop('modified-held574-root.json.gz')
   elif kind=='caps':v[1]['isolation']['mask']=2149843163
   elif kind=='alias':v[1]['isolation']['writable_source_alias']=True
   elif kind=='cleanup':v[2]['cleanup']='UNKNOWN'
   elif kind=='duplicate':v+=copy.deepcopy(rows)
   raw=uart(v)
   if kind=='nonce':raw=raw.replace(b'a'*32,b'f'*32)
   with self.subTest(kind=kind),self.assertRaises(ValueError):R.protocol(raw,selection)
 def test_only_counted_identity_and_gate_sites_change_nine_vm_modules(self):
  _,_,folder,*_=self.emitted()
  for name in G.MODULES:
   raw=(ROOT/G.OLD/name).read_bytes();adapted,_=G.adapt(raw,name);self.assertEqual((folder/name).read_bytes(),adapted)
   if name!='contract.py':
    text=adapted.decode()
    for before,after,n in reversed(G.RULES[name]):text=text.replace(after,before)
    self.assertEqual(text,raw.decode(),name)
 def test_same_disk_memory_process_time_syscall_and_isolation_bounds(self):
  _,_,folder,*_=self.emitted();prepare=(folder/'prepare.py').read_text();run=(folder/'run.py').read_text();guest=(folder/'guest.py').read_text();sandbox=(folder/'sandbox.py').read_text()
  for term in ('umount /volume','umount /dev','remount,bind,ro /held','16*C.GIB','24*C.GIB','allocated<=10*C.GIB','free>=48*C.GIB'):self.assertIn(term,prepare)
  for term in ('seconds=10800','cap=16*1024**2','--network=none','--read-only','free>=48*C.GIB','544*1024**2','--memory=4g','--cpus=2'):self.assertIn(term,run)
  self.assertIn('10500,512*1024',guest);self.assertIn('CAPS=(0,1,3,4,5,6,7,18,21,31)',sandbox);self.assertIn('len(files)<=256 and total<=512*1024**2',guest);self.assertIn('prctl(4,0,0,0,0)',guest)
 def test_bootstrap_relative_paths_all_match_distinct_guest_namespace(self):
  _,_,folder,*_=self.emitted();tree=ast.parse((folder/'prepare.py').read_bytes());paths={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and type(n.value) is str and n.value.startswith('debian-maintained-installed16k')};self.assertTrue({'debian-maintained-installed16k/'+n for n in ('container16k.py','adapter.json','selection.json')}<=paths);self.assertNotIn("'installed16k/",(folder/'prepare.py').read_text());self.assertIn('init-debian-maintained-installed16k',(folder/'prepare.py').read_text())
 def test_source_or_anchor_drift_and_fresh_output_refused(self):
  out,_,folder,C,*_=self.emitted(True)
  with self.assertRaisesRegex(ValueError,'fresh'):G.emit(ROOT,out)
  (out/G.NATIVE/'container.py').write_text('tampered')
  with self.assertRaises(ValueError):C.check_source(out)
  raw=(ROOT/G.OLD/'run.py').read_bytes().replace(b'b\'GNU_INSTALLED16K ',b'b\'BROKEN_INSTALLED16K ')
  with self.assertRaisesRegex(ValueError,'anchor'):G.adapt(raw,'run.py')
if __name__=='__main__':unittest.main(verbosity=2)
