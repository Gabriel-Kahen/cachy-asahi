# SPDX-License-Identifier: MIT
"""Portable finite data/source controls; no Docker, VM or privileged actor."""
import ast,copy,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
G=load('interrupted16k_generator',HERE/'generator.py')
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));p.start();self.addCleanup(p.stop)
 def emitted(self):
  output=self.work/'emitted';result=G.emit(ROOT,output);folder=output/G.NEW;C=load('interrupted_contract',folder/'contract.py')
  with patch.dict(sys.modules,{'contract':C}):R=load('interrupted_run',folder/'run.py');A=load('interrupted_adapter',folder/'adapter.py');V=load('interrupted_recovery',folder/'recovery.py')
  return result,folder,C,R,A,V
 def test_exact104_source_pins_and_closed14file_emission(self):
  self.assertEqual(len(G.source(ROOT)['files']),106);value,folder,C,*_=self.emitted();self.assertEqual(len(value['files']),15);self.assertEqual(C.NATIVE,G.NATIVE);self.assertEqual(C.LANE,G.NEW);self.assertIn('INTERRUPTED_REPLACEMENT',C.PASS)
  for p in folder.glob('*.py'):ast.parse(p.read_bytes())
  self.assertEqual((folder/'sandbox.py').read_bytes(),(ROOT/G.OLD/'sandbox.py').read_bytes())
  self.assertEqual((folder/'snapshot_progress.py').read_bytes(),(ROOT/G.OLD/'snapshot_progress.py').read_bytes());self.assertIn("('guest.py','contract.py','sandbox.py','snapshot_progress.py','observer_progress.py','recovery.py')",(folder/'prepare.py').read_text())
 def test_unbound_gate_blocks_execution_before_any_output_actor(self):
  _,folder,C,R,*_=self.emitted();policy=json.loads((folder/'input-policy.json').read_bytes());self.assertEqual(policy['binding'],dict(native_interruption=None,normal_installed16k=None))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):C.gate(Path('/missing'))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):R.execute(type('Args',(),dict(acceptances=Path('/missing')))())
  self.assertEqual({p.name for p in self.work.iterdir()},{'emitted'})
 def test_native_four_edits20_bodies_and_unchanged_interruption_sequence(self):
  _,folder,C,_,A,_=self.emitted();source=self.work/'source';source.mkdir()
  for name in G.source(ROOT)['files']:
   p=source/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
  shutil.copytree(folder,source/G.NEW)
  text,receipt=A.derive(source);self.assertEqual(receipt['counted_edits'],4);self.assertEqual(len(receipt['unchanged_bodies']),20);self.assertIn('config_handoff',receipt['unchanged_bodies']);self.assertEqual(receipt['changed_bodies'],['guard','validate_runtime'])
  raw=(source/G.NATIVE/'container.py').read_text();bodies=lambda t:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(t).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  a,b=bodies(raw),bodies(text)
  for name in ('transaction','run_case','copy_probes','runtime_mounts','snapshot','main','Commands'):self.assertEqual(a[name],b[name])
  self.assertIn('interruption.exercise',text);self.assertIn('CACHY_GNU_PROVIDER_INTERRUPTION',text)
 def test_root_prerequisites_require_real_interruption_and_full_normal_installed16k_shapes(self):
  _,folder,C,*_=self.emitted();decisions=self.work/'decisions';decisions.mkdir();policy=json.loads((folder/'input-policy.json').read_bytes());policy['status']='BOUND_BY_ROOT';values={};statuses=dict(native_interruption='ROOT_ACCEPTED_CONVENTIONAL_PROVIDER_INTERRUPTION_RECOVERY',normal_installed16k='ROOT_ACCEPTED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY')
  for kind,status in statuses.items():values[kind]=dict(status=status,hardware='NOT_RUN',ordered_cleanup='PASS',provider_archive_sha256='b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12',source_sha='1'*40,run_id=1,page_size=16384,ALPM_installation='PASS')
  def save():
   for kind,value in values.items():
    raw=G.encoded(value);(decisions/kind).write_bytes(raw);policy['binding'][kind]=dict(path=kind,**G.pin(raw))
   (folder/'input-policy.json').write_bytes(G.encoded(policy))
  save();self.assertEqual(set(C.gate(decisions)),set(statuses))
  original=copy.deepcopy(values)
  for field,bad in (('status','ROOT_ACCEPTED_GNU_PROVIDER_SYSTEM_PATHS_GENERIC16K'),('ALPM_installation','NOT_RUN'),('page_size',4096),('ordered_cleanup','UNKNOWN'),('provider_archive_sha256','0'*64)):
   values=copy.deepcopy(original);values['normal_installed16k'][field]=bad;save()
   with self.subTest(field=field),self.assertRaises(ValueError):C.gate(decisions)
 def test_counted_anchor_drift_refused(self):
  raw=(ROOT/G.OLD/'guest.py').read_bytes().replace(b'normal_runtime_observations=8',b'normal_runtime_observations=7')
  with self.assertRaisesRegex(ValueError,'anchor'):G.adapt(raw,'guest.py')
 def test_same_disk_mount_topology_budgets_and_ten_cap_worker(self):
  _,folder,C,R,*_=self.emitted()
  prepare=(folder/'prepare.py').read_text();run=(folder/'run.py').read_text();guest=(folder/'guest.py').read_text();sandbox=(folder/'sandbox.py').read_text()
  for term in ('umount /volume','umount /dev','remount,bind,ro /held','16*C.GIB','24*C.GIB','allocated<=10*C.GIB'):self.assertIn(term,prepare)
  for term in ('seconds=10800','cap=16*1024**2','--network=none','--cap-drop=ALL','free>=48*C.GIB','544*1024**2'):self.assertIn(term,run)
  self.assertIn('10500,512*1024',guest);self.assertIn('CAPS=(0,1,3,4,5,6,7,18,21,31)',sandbox);self.assertIn('normal_runtime_observations=10',guest);self.assertIn("'recovered_runtime'",guest)
 def test_prepared_bootstrap_paths_match_guest_readback_paths(self):
  _,folder,*_=self.emitted();tree=ast.parse((folder/'prepare.py').read_text());paths={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and type(n.value) is str and n.value.startswith('installed16k')};wanted={'installed16k-interruption/'+n for n in ('container16k.py','adapter.json','selection.json')};self.assertTrue(wanted<=paths);self.assertTrue(all(p=='installed16k-interruption' or p.startswith('installed16k-interruption/') for p in paths))
 def stages(self):return ('source-before','source-after','clone','before574','precommit-refused','interrupted-before-unlock','recovered-held574','provider574','reinstalled574','held574')
 def protocol(self,C,R):
  selection=dict(nonce='a'*32,kernel=dict(release='exact16k'),kernel_profile_sha256='b'*64,source_nodes_sha256='c'*64,capabilities_sha256='d'*64);names=['result.json']+[case+'-'+stage+'-root.json.gz' for case in ('pristine','modified') for stage in self.stages()];files={n:dict(bytes=1,sha256='e'*64) for n in names};result=dict(event='result',status=C.PASS,page_size=16384,normal_runtime_observations=10,hardware='NOT_RUN',release='NOT_ADMITTED',source_nodes_sha256='c'*64,capabilities=dict(status='EXACT_SOURCE_MAP_PRESERVED',cases=2,stages=10,source_capabilities_sha256='d'*64),isolation=dict(status='PASS_OBSERVED_NATIVE_CAPS_AND_MOUNT_FENCE',mask=2149843195,no_new_privs=1,seccomp=2,raw_block_devices=[],writable_source_alias=False,mount_flags=[15,4096]),files=files,bytes=len(files),interruption=dict(status='PASS_COMPLETE_INTERRUPTION_AND_NORMAL_RUNTIME_RECORDS',files=names));events=[dict(event='boot',observer_nofile=dict(before=[1024,4096],after=[8192,8192],scope='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD'),page_size=16384,kernel='exact16k',architecture='aarch64',kernel_profile_sha256='b'*64),result,dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_CLONES_REMOVED')]
  def uart(rows):return b'\n'.join(('GNU_INTERRUPTED16K '+selection['nonce']+' '+json.dumps(r)).encode() for r in rows)
  return selection,events,uart
 def test_new_protocol_requires10_runtimes20_maps_and_same_isolation(self):
  _,_,C,R,*_=self.emitted();selection,events,uart=self.protocol(C,R);self.assertEqual(R.protocol(uart(events),selection)['normal_runtime_observations'],10)
  for kind in ('normal','maps','caps','page','alias','evidence'):
   rows=copy.deepcopy(events);v=rows[1]
   if kind=='normal':v['normal_runtime_observations']=8
   elif kind=='maps':v['files'].pop('modified-recovered-held574-root.json.gz');v['bytes']-=1
   elif kind=='caps':v['isolation']['mask']=2149843163
   elif kind=='page':v['page_size']=4096
   elif kind=='alias':v['isolation']['writable_source_alias']=True
   else:v['interruption']['files'].pop()
   with self.subTest(kind=kind),self.assertRaises(ValueError):R.protocol(uart(rows),selection)
 def test_progress_projection_uses_only_exact_interruption_statuses_and_phases(self):
  _,folder,C,*_=self.emitted()
  with patch.dict(sys.modules,{'contract':C}):E=load('interrupted_export',folder/'export.py')
  phases={n:dict(complete=True,unsupported_counts={'unit-refusal':1}) for n in ('pristine-interrupted-before-unlock','pristine-recovered-held574')}
  report=dict(status='PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY',cases=dict(pristine=dict(status='PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE',root_observation_failures=phases)),commands=[])
  projected=E.diagnostic_projection(json.dumps(report).encode());self.assertEqual(projected['original_status'],report['status']);self.assertEqual(projected['cases']['pristine']['original_status'],report['cases']['pristine']['status']);self.assertEqual(set(projected['cases']['pristine']['observation_failures']),{'interrupted-before-unlock','recovered-held574'})
  report['status']='PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE';report['cases']['pristine']['status']='PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE';projected=E.diagnostic_projection(json.dumps(report).encode());self.assertEqual(projected['original_status'],'UNKNOWN_OR_UNEXPECTED');self.assertEqual(projected['cases']['pristine']['original_status'],'UNFINISHED_OR_UNRECORDED')
 def test_strict_original8192_observer_boot_required(self):
  _,_,C,R,*_=self.emitted();selection,events,uart=self.protocol(C,R)
  for value in (None,dict(before=[1024,4096],after=[8192,16384],scope='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD')):
   rows=copy.deepcopy(events);rows[0]['observer_nofile']=value
   with self.assertRaises(ValueError):R.protocol(uart(rows),selection)
 def recovery_fixture(self,folder):
  root=self.work/'readback';root.mkdir();normal=dict(normal_parent_and_child=True,result=dict(status='PASS',cases=8,page_size=16384));rows={}
  for case in ('pristine','modified'):
   interrupted=dict(status='PASS_ACTUAL_REMOVE_PHASE_KILL_AND_EXTERNAL_RECOVERY',writer=dict(group_absence_verified=True,exit_code=-9),observed_stop='KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER',checkpoint=dict(phase='ALPM_COMMIT_REMOVE_PAYLOAD_BEFORE_OLD_DATABASE_REMOVAL',event=4,package='glibc'),partial_state='HELD574_DATABASE_WITH_PARTIALLY_REMOVED_HELD_PAYLOAD_CANDIDATE_NOT_ADDED',lock_recovery=dict(status='PASS_EXACT_OWNED_STALE_LOCK_REMOVED_AFTER_GROUP_ABSENCE'),outer_runtime_before={'UNIT':'synthetic'},outer_runtime_after={'UNIT':'synthetic'})
   rows[case]=dict(status='PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE',source_before='a'*64,source_after='a'*64,copy_lifetime=dict(cleanup='PASS-owned-workspace-removed'),interruption=interrupted,**{n:copy.deepcopy(normal) for n in ('before_runtime','recovered_runtime','provider_runtime','reinstalled_runtime','held_runtime')})
   for stage in self.stages():(root/(case+'-'+stage+'-root.json.gz')).write_bytes(b'UNIT inert data')
  result=dict(status='PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY',hardware='NOT_RUN',interrupted_in_progress_replacement='REMOVE_PHASE_ONLY_CANDIDATE_EXTRACTION_NOT_TESTED',cases=rows);(root/'result.json').write_text(json.dumps(result));return root,result
 def test_exact_native_owner_recovery_validator_reused_with_only2_edits(self):
  _,folder,C,R,A,V=self.emitted();root,result=self.recovery_fixture(folder);value=V.consumer_records(root,'a'*64);self.assertEqual(len(value['files']),21)
  original=(ROOT/G.OWNER).read_text();node=next(n for n in ast.parse(original).body if isinstance(n,ast.FunctionDef) and n.name=='consumer_records');expected=ast.get_source_segment(original,node).replace("public=output/'inner/public'","public=output").replace("runtime['result']['page_size']==4096","runtime['result']['page_size']==16384");actual=next(n for n in ast.parse((folder/'recovery.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='consumer_records');self.assertEqual(ast.dump(ast.parse(expected).body[0]),ast.dump(actual))
 def test_synthetic_stop_or_missing_recovery_or_unknown_group_refused(self):
  _,folder,C,R,A,V=self.emitted();root,result=self.recovery_fixture(folder)
  for kind in ('stopped','group','outer','runtime'):
   value=copy.deepcopy(result);row=value['cases']['pristine']
   if kind=='stopped':row['interruption']['observed_stop']='SYNTHETIC'
   elif kind=='group':row['interruption']['writer']['group_absence_verified']=False
   elif kind=='outer':row['interruption']['outer_runtime_after']={}
   else:row['recovered_runtime']['result']['page_size']=4096
   (root/'result.json').write_text(json.dumps(value))
   with self.subTest(kind=kind),self.assertRaises(ValueError):V.consumer_records(root,'a'*64)
  (root/'result.json').write_text(json.dumps(result));(root/'modified-interrupted-before-unlock-root.json.gz').unlink()
  with self.assertRaises(FileNotFoundError):V.consumer_records(root,'a'*64)
if __name__=='__main__':unittest.main()
