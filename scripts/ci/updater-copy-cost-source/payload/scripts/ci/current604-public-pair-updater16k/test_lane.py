# SPDX-License-Identifier: MIT
"""Inert adapters plus actual owned filesystem controls; never VM evidence."""
import ast,copy,hashlib,os,subprocess,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import contract as C
import adapter as A,cap_scope,prepare as P,run,vm
ROOT=Path(os.environ.get('PUBLIC_PAIR_UPDATER16K_SOURCE',C.ROOT));UPDATER=Path(os.environ.get('PUBLIC_PAIR_UPDATER_SOURCE',ROOT))
def pre_signature_diagnostic(raw):
 text=raw.decode();start=text.index('_SIGNATURE_FAILURE_DATA = None');end=text.index('def guard():',start);text=text[:start]+text[end:]
 before="    if proc.returncode:\n        signature_failure(args, proc)\n        print(proc.stdout[-8192:], proc.stderr[-8192:], flush=True)";assert text.count(before)==1;text=text.replace(before,"    if proc.returncode:\n        print(proc.stdout[-8192:], proc.stderr[-8192:], flush=True)")
 before="run(pacman + ['--debug', '--noconfirm', '--noscriptlet', '--ask', '4', '-U', *archives])";assert text.count(before)==1;text=text.replace(before,"run(pacman + ['--noconfirm', '--noscriptlet', '--ask', '4', '-U', *archives])")
 before="    if _SIGNATURE_FAILURE_DATA is not None:\n        print('APPS6_KEYRING_FAILURE_DATA '+json.dumps(_SIGNATURE_FAILURE_DATA,sort_keys=True,separators=(',',':')),flush=True)\n";assert text.count(before)==1;text=text.replace(before,'')
 return text.encode()

def focused_prepare_without_capacity(*args,**kwargs):
 with patch.object(A,'materialization_validation_profile',return_value=None),patch.object(A,'driver_copy_validation_profile',return_value=None),patch.object(A,'driver_descriptor_profile',return_value=None),patch.object(A,'driver_cost_profile',return_value=None):return A.prepare_selected(*args,**kwargs)

class Controls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors/Git/network forbidden'));p.start();self.addCleanup(p.stop)
 def test_all_cases_unbound_before_source_output_or_actor(self):
  original=C.read
  def read(p,cap=4*1024**2):return C.encoded(dict(schema_version=1,status='INERT_UNBOUND',binding=None)) if Path(p)==C.HERE/'input-policy.json' else original(p,cap)
  with patch.object(C,'read',side_effect=read):
   for case in C.CASES:
    with self.subTest(case=case),patch.object(C,'check_source',side_effect=AssertionError('source before policy')),self.assertRaisesRegex(ValueError,'UNBOUND'):run.main(['--implementation','/does-not-exist','--case',case])
 def test_original_owner_functions_and_budgets_unchanged(self):
  raw=(ROOT/C.OLD/'run.py').read_bytes();derived=A.owner(raw)
  funcs=lambda d:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(d).body if isinstance(n,ast.FunctionDef)}
  before,after=funcs(raw),funcs(derived);self.assertEqual([n for n in before if before[n]!=after[n]],['main'])
  for text in (b'vm.run(a,argv,image,public,raw,old,3900)',b'vm.retire_outer(',b"generic16k=C.read(public/'updater16k-result.json')"):self.assertIn(text,derived)
  for n in ('prepare_with_plan','verify_result','cleanup_ready'):self.assertEqual(before[n],after[n])
  with self.assertRaises(ValueError):A.owner(raw.replace(b"public/'transaction.log',3900",b"public/'transaction.log',3901"))
 def test_guard_derivative_refreshes_exact_config_pin(self):
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp)/'target';calling=target/'scripts/ci/full-root-upgrade-caller';calling.mkdir(parents=True)
   raw=(ROOT/'scripts/ci/full-root-upgrade-caller/container.py').read_bytes();(calling/'container.py').write_bytes(raw);config=target/'upgrade-config.json';name='scripts/ci/full-root-upgrade-caller/container.py'
   scope=(ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').read_bytes();(calling/'persistent_scope.py').write_bytes(scope)
   C.save(config,dict(code_pins={name:C.sha(raw),'scripts/ci/full-root-upgrade-caller/persistent_scope.py':C.sha(scope),'other':'b'*64},external_pins={'/persistent_scope.py':C.sha(scope)},copy_seconds=600,driver_seconds=1800,stage_seconds=900,verify_seconds=600));C.save(target/'adapter.json',dict(config_sha256='prior'))
   original=SimpleNamespace(prepare=lambda *a,**kw:(config,calling));focused_prepare_without_capacity(original,ROOT,target,'normal');value=C.decode(C.read(config))
   self.assertEqual(value['code_pins'][name],C.sha((calling/'container.py').read_bytes()));self.assertEqual(value['code_pins']['other'],'b'*64);self.assertEqual(value['driver_seconds'],1800)
   self.assertEqual(C.decode(C.read(target/'adapter.json'))['config_sha256'],C.sha(config.read_bytes()))
 def test_caller_changes_only_fixed_vm_entry_predicate(self):
  raw=(ROOT/'scripts/ci/full-root-upgrade-caller/container.py').read_bytes();out=pre_signature_diagnostic(A.caller(raw))
  funcs=lambda d:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(d).body if isinstance(n,ast.FunctionDef)}
  a,b=funcs(raw),funcs(out);self.assertEqual([n for n in a if a[n]!=b[n]],['guard']);self.assertIn(b"os.sysconf('SC_PAGE_SIZE') == 16384",out);self.assertNotIn(b"Path('/.dockerenv').is_file()",out)
  self.assertEqual(sum(1<<n for n in C.CAPS),C.MASK);self.assertNotIn(21,C.CAPS)
 def test_source_emit_closed_and_tamper_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   output=Path(tmp)/'source';receipt=P.emit(ROOT,UPDATER,output);self.assertLessEqual(receipt['source_rows'],512)
   lane=output/C.LANE;rows=C.decode((lane/'wiring-source-manifest.json').read_bytes())['files']
   self.assertEqual(set(rows),{str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}-{C.LANE+'/wiring-source-manifest.json',P.WF,'source-emission.json'})
   for n,r in rows.items():self.assertEqual(C.row(output/n),r)
   with patch.object(P,'pin',return_value={}),self.assertRaisesRegex(ValueError,'pinned source'):P.emit(ROOT,UPDATER,Path(tmp)/'bad')
 def test_real_empty_cap_roundtrip_hardlink_and_boundaries(self):
  roots=C.load('test_roots',ROOT/'scripts/update/full_root.py');raw=(ROOT/'scripts/apps/file_capabilities.py').read_bytes()
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'usr').mkdir();(root/'usr/file').write_bytes(b'actual owned ordinary payload');os.link(root/'usr/file',root/'usr/alias');(root/'proc').mkdir();(root/'proc/runtime').write_bytes(b'runtime-boundary')
   lim=roots.Limits(deadline=time.monotonic()+10);obs=roots.observe(root,limits=lim,hardlinks='generic-development-internal',absolute_paths=True);self.assertTrue(obs['complete'])
   nodes=cap_scope.nodes(obs['nodes']);m=cap_scope.derive(raw,{'proc'});self.assertEqual(m.observe(root,nodes,lim),{});self.assertEqual(m.restore(root,nodes,{},lim),{})
   (root/'unexpected').write_bytes(b'refused');
   with self.assertRaisesRegex(ValueError,'actual node graph'):m.observe(root,nodes,lim)
   (root/'unexpected').unlink();os.link(root/'usr/file',root/'external')
   with self.assertRaises(ValueError):m.observe(root,nodes,lim)
 def test_unknown_xattr_not_discarded_or_normalized(self):
  roots=C.load('attr_roots',ROOT/'scripts/update/full_root.py')
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);p=root/'payload';p.write_bytes(b'ordinary');lim=roots.Limits(deadline=time.monotonic()+10);nodes=roots.observe(root,limits=lim)['nodes'];os.setxattr(p,'user.fixture',b'reject-me')
   m=cap_scope.derive((ROOT/'scripts/apps/file_capabilities.py').read_bytes(),set())
   with self.assertRaises(ValueError):m.observe(root,nodes,lim)
   self.assertEqual(os.getxattr(p,'user.fixture'),b'reject-me')
 def test_source_guard_alias_hardlink_and_closed_input_inventory(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);p=root/'file';p.write_bytes(b'actual');r=vm.snapshot({'/inputs':dict(source=str(root),readonly=True)});self.assertEqual(r['/inputs/file']['sha256'],hashlib.sha256(b'actual').hexdigest())
   (root/'link').symlink_to('file')
   with self.assertRaises(ValueError):vm.snapshot({'/inputs':dict(source=str(root),readonly=True)})
   (root/'link').unlink();os.link(p,root/'alias')
   with self.assertRaises(ValueError):vm.snapshot({'/inputs':dict(source=str(root),readonly=True)})
 def test_actual_original_mount_builder_and_capability_refusal(self):
  held=C.load('mount_builder',ROOT/'scripts/ci/full-root-upgrade-caller/run.py')
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);helpers=root/'helpers';helpers.mkdir();held.CALLER=held.HERE=helpers
   for n in ('container.py','upgrade_hook.py','persistent_scope.py','setup4.py','footprint.py'):(helpers/n).write_bytes(b'fixture only')
   for n in ('inputs','public','raw','code','pair'):(root/n).mkdir()
   for n in ('footprint-source','test-signing'):(root/'raw'/n).mkdir()
   (root/'config').write_bytes(b'{}');args=SimpleNamespace(upgrade_code=root/'code',upgrade_config=root/'config',setup4_pair=root/'pair')
   argv=held.container_args(args,root/'inputs',root/'public',root/'raw','owned-name','owned-volume')
   bindings,markers=vm.mounts(argv);self.assertEqual(set(bindings),vm.MOUNTS-{'/measurement'});self.assertEqual(len(markers),2)
   for bad in (argv+['--cap-add=SYS_ADMIN'],[x.replace('dst=/inputs,readonly','dst=/inputs') for x in argv]):
    with self.assertRaises(ValueError):vm.mounts(bad)
 def test_uncertain_vm_blocks_original_outer_cleanup(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);public=root/'public';public.mkdir();(root/'update16k').mkdir();old=SimpleNamespace(retire_outer=lambda *_:self.fail('backing data retired with unknown VM'));result={}
   self.assertTrue(vm.retire_outer(old,root/'actor',result,public));self.assertIn('RETAINED',result['upgrade_volume_cleanup'])
   (root/'update16k').rmdir();old.retire_outer=lambda *_:[];self.assertEqual(vm.retire_outer(old,root/'actor',{},public),[])
   C.save(public/'updater16k-cleanup.json',dict(status='RETAINED_ABSENCE_UNKNOWN'));self.assertTrue(vm.retire_outer(old,root/'actor',{},public))
 def test_vm_and_pid1_original_resource_scopes(self):
  q=vm.qemu(Path('/Image'),Path('/boot.raw'),Path('/data.raw'),1700000000);self.assertIn('tcg,thread=multi',q);self.assertEqual(q[q.index('-nic')+1],'none');self.assertEqual(q[q.index('-display')+1],'none');self.assertEqual(q[q.index('-m')+1],'4096')
  text=(C.HERE/'guest.py').read_text();self.assertIn('resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))',text);self.assertEqual(text.count(',3900,2*1024**2)'),2);self.assertIn("helper.capability_mask=lambda fixture_identity_map=None:C.MASK",text);self.assertNotIn('helper.block_service_ipc(',text)
  text=(C.HERE/'disk.py').read_text();self.assertIn('limits(roots,900)',text);self.assertIn("caps.restore(boot,cap_scope.nodes(measured['nodes']),mapping,budget)",text);self.assertIn('48*1024**3',text)
 def test_original_case_verifier_preserves_normal_pre86_post87_truth(self):
  # Compile only the source-owned pure verifier; no borrowed entrypoint executes.
  tree=ast.parse((ROOT/C.OLD/'run.py').read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='verify_result');before='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5';space=dict(C=SimpleNamespace(need=C.need,BEFORE=before));exec(compile(ast.Module(body=[node],type_ignores=[]),'exact-original-verifier','exec'),space)
  for case,t in zip(C.CASES,((1,True,True,True),(0,False,False,False),(1,True,True,False))):
   driver=dict(status='PASS',copy_cleanup='PASS-owned-workspace-removed',case=case,failure_cases=1,original_source_preserved=True,update=dict(checkpoint_directory_synced=True),after604_database_verified=True,postcommit_payload_verified=True,postcommit_preservation_verified=True,**dict(zip(('committed_transactions','commit_started','packages_committed','checkpoint_changed'),t)))
   row=dict(status='PASS',package_count=604,final_package_count=604,installed_inventory_sha256=before,final_inventory_sha256=before,dependency_checks='PASS-no-waivers',payload_ownership='PASS',full_root_upgrade=dict(status='PASS',persistent_source_preserved=True,persistent_source=dict(source_manifest_sha256='x'),persistent_source_after=dict(source_manifest_sha256='x'),driver=driver))
   self.assertIs(space['verify_result'](row,case),row['full_root_upgrade']);bad=copy.deepcopy(row);bad['full_root_upgrade']['driver']['commit_started']='UNKNOWN'
   with self.assertRaises(ValueError):space['verify_result'](bad,case)
 def test_emitted_corrected_roles_and_all80_real_runtime_recipe_dependencies(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);out=root/'closed';original_read=P.read
   # Reuse the explicit NULL fixture from test_all_cases_unbound_before_source_output_or_actor.
   # This source-role test does not assume that the selected trial itself is unbound.
   selected_policy=original_read(P.HERE/'input-policy.json')
   unbound=C.encoded(dict(schema_version=1,status='INERT_UNBOUND',binding=None))
   with patch.object(P,'read',side_effect=lambda p:unbound if p==P.HERE/'input-policy.json' else original_read(p)):P.emit(ROOT,UPDATER,out)
   self.assertEqual(original_read(P.HERE/'input-policy.json'),selected_policy)
   pins=C.decode(C.read(C.HERE/'source-pins.json'));required=pins['runtime_recipe_inputs'];self.assertEqual(len(required),80)
   self.assertEqual(C.row(out/C.OLD/'source-manifest.json')['sha256'],'ec9a759bbb5be161a0a77c2983e731c3b09e71b33688a2ecdf54abce9d1ba41b');self.assertEqual(C.row(out/'scripts/ci/expanded604-apps6-public-pair-installer/source-manifest.json')['sha256'],'5f4dbc150a5f8ca6a85843b783e7b5472251a4b0761e75e65f7d82b165a7b629')
   selected=pins['selected_source_roles'];self.assertEqual(selected['status'],'SOURCE_ONLY_NOT_ACTUAL_ACCEPTANCE');self.assertEqual(selected['updater_source'],'37d9ffa166e0d7262ef8afab56baa0b3ea060b22');self.assertEqual(selected['fresh_source'],'bd0cf1891083d011b70edab10501c317d3720b78')
   self.assertIsNone(selected['updater_three_case_positive_decisions']);self.assertIsNone(selected['GUI_two_profile_positive_decisions'])
   held=C.load('selected_actual_source_contract',out/C.OLD/'contract.py');held_policy=held.policy();self.assertEqual(held_policy['installer_source'],selected['fresh_source']);self.assertEqual(held_policy['decision_source'],'c38375818f116bfc129a8db853d0c9cd2d360eb9')
   for n,row in pins['groups']['updater'].items():self.assertEqual(C.row(out/n),row,n)
   for n,row in required.items():self.assertEqual(C.row(out/n),row,n)
   controls=pins['fresh_control_inputs'];self.assertEqual(len(controls),9)
   for n,row in controls.items():self.assertEqual(C.row(out/n),row,n)
   guard=C.load('genuine_emitted_setup_guard',out/'scripts/ci/setup5-native/contract.py');recipe=guard.recipe(out);self.assertEqual(len(recipe['input_sha256']),12);self.assertEqual(recipe['metadata']['pkgrel'],['5'])
   leaf=out/'packages/settings/cachy-asahi-setup/.SRCINFO';raw=leaf.read_bytes();leaf.unlink()
   with self.assertRaises(FileNotFoundError):guard.recipe(out)
   with self.assertRaises((ValueError,FileNotFoundError)):P.emit(out,out,root/'refused')
   self.assertFalse((root/'refused').exists());leaf.write_bytes(raw)
   for n in ('policy.json','input-policy.json'):self.assertIsNone(C.decode(C.read(out/C.LANE/n))['binding'])


 def test_all_three_corrected_auxiliary_and_16k_adapter_derivations_exact(self):
  selected=C.load('corrected_selected_contract',ROOT/C.OLD/'contract.py');adapter=selected.scoped('corrected_selected_adapter',ROOT/C.OLD/'adapter.py',{'contract':selected});helper=selected.load('corrected_auxiliary',ROOT/C.OLD/'aux_transition.py')
  fixtures={'scripts/ci/full-root-upgrade-caller/upgrade-config.json':'normal-upgrade-config.json','scripts/ci/full-root-failed-update/lane-config.json':'precommit-lane-config.json','scripts/install/local_transaction.py':'local_transaction.py'}
  held=selected.read(ROOT/'scripts/ci/expanded600-root-upgrade/held-pins.json')
  with tempfile.TemporaryDirectory() as td:
   base=Path(td)
   for case in C.CASES:
    source=base/('held-'+case);source.mkdir()
    for name,row in held[case]['pins'].items():
     path=ROOT/name
     if not path.is_file() or C.row(path)!=row:path=ROOT/C.OLD/'fixtures'/fixtures[name]
     self.assertEqual(C.row(path),row,name);target=source/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(path.read_bytes())
    prior=base/('prior-'+case);adapter.prior.prepare(source,prior,case,git=False,implementation=ROOT)
    output=base/('derived-'+case);config,calling=A.prepare_selected(adapter,source,output,case,git=False,implementation=ROOT)
    for p in prior.rglob('*'):
     if not p.is_file():continue
     n=p.relative_to(prior).as_posix()
     if n.startswith(adapter.PREFIX) or n in ('upgrade-config.json','adapter.json'):continue
     raw=p.read_bytes()
     if n=='scripts/update/aux_runtime.py':raw,proof=helper.derive(raw);self.assertEqual(proof['status'],'EXACT_APPS5_TO6_AUXILIARY_SELECTION_ONLY')
     elif n=='scripts/update/aux_copy.py':raw=raw+b'\n\n'+A.DRIVER_DESCRIPTOR_SOURCE
     elif n=='scripts/update/linked_runtime.py':raw,linked_proof=helper.derive_linked(raw);self.assertEqual(linked_proof['new_allowances'],'NONE')
     elif n=='scripts/ci/full-root-postcommit-failure/run.py':raw,postcommit_proof=helper.derive_postcommit(raw);self.assertEqual(postcommit_proof['status'],'SOURCE_BOUND_AUTHENTICATED_CHILD_TO_DISTINCT_PARENT_SELECTION')
     elif n=='scripts/ci/full-root-upgrade/construct_repository.py':raw=adapter.constructor(raw)
     elif n=='scripts/ci/full-root-upgrade-caller/container.py':raw=A.caller(raw)
     elif n=='scripts/ci/full-root-upgrade-caller/persistent_scope.py':raw=A.persistent_stage(raw)
     elif n=='scripts/ci/full-root-upgrade-caller/upgrade_hook.py':raw=A.driver_cost_hook(A.driver_copy_hook(A.validation_hook(raw,case),case))
     self.assertEqual((output/n).read_bytes(),raw,case+':'+n)
    value=C.decode(C.read(config));oldvalue=selected.read(prior/'upgrade-config.json')
    for key,value_before in oldvalue.items():
     if key=='driver_seconds' and case=='normal':self.assertEqual(value_before,1800);self.assertEqual(value[key],1860)
     elif key=='copy_seconds':self.assertEqual(value_before,600);self.assertEqual(value[key],1200)
     elif key=='stage_seconds':self.assertEqual(value_before,900);self.assertEqual(value[key],1200)
     elif key=='external_pins':
      wanted=dict(value_before);wanted['/persistent_scope.py']=C.sha((calling/'persistent_scope.py').read_bytes());self.assertEqual(value[key],wanted,case+':'+key)
     elif key not in ('code_pins','release'):self.assertEqual(value[key],value_before,case+':'+key)
    for n,digest in value['code_pins'].items():self.assertEqual(C.sha((output/n).read_bytes()),digest,case+':'+n)
    receipt=selected.read(output/'adapter.json');self.assertEqual(receipt['config_sha256'],C.sha(config.read_bytes()));self.assertIn('auxiliary_selection',receipt);self.assertEqual(receipt['updater16k_dispatch']['counted_edits'],5)
    copy_profile=receipt['updater16k_dispatch']['driver_copy_validation_profile'];self.assertEqual(copy_profile['profile'],A.DRIVER_COPY_PROFILE);self.assertEqual(copy_profile['copy_before_seconds'],600);self.assertEqual(copy_profile['copy_seconds'],1200);self.assertEqual(copy_profile['caller_seconds'],3900);self.assertEqual(copy_profile['worker_seconds'],3900);self.assertEqual(copy_profile['additive_composition_fit'],'NOT_ESTABLISHED');self.assertEqual(copy_profile['old600_copy_fit'],'NOT_ESTABLISHED')
    profile=receipt['updater16k_dispatch']['validation_capacity_profile'];self.assertEqual(profile['profile'],A.MATERIALIZATION_PROFILE);self.assertEqual(profile['stage_seconds'],1200);self.assertEqual(profile['caller_seconds'],3900);self.assertEqual(profile['worker_seconds'],3900);self.assertEqual(profile['nested_stage_driver_verify_sum'],3660 if case=='normal' else 4200);self.assertEqual(profile['additive_composition_fit'],'NOT_ESTABLISHED');self.assertEqual(profile['old900_fit'],'NOT_ESTABLISHED')


class PersistentStageFailureData(unittest.TestCase):
 def scope(self):
  import types
  raw=(ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').read_bytes();derived=A.persistent_stage(raw);m=types.ModuleType('_source_derived_stage_diagnostic');exec(compile(derived,'<source-pinned-persistent-scope>','exec'),m.__dict__);return raw,derived,m
 def test_whole_original_helper_inverse_and_failclosed_source(self):
  raw,new,m=self.scope();self.assertEqual(pre_observation(new).decode().replace(A.PERSISTENT_STAGE_DATA,'',1).replace(A.PERSISTENT_STAGE_WRAPPER,A.PERSISTENT_STAGE_GUARD,1).encode(),raw)
  self.assertEqual(new.count(b'persistent_stage_failure(before, staged, limits)'),2)
  with self.assertRaises(ValueError):A.persistent_stage(raw+b'\n')
 def record(self,m,before,staged):
  import contextlib,io,json
  s=io.StringIO()
  with contextlib.redirect_stderr(s):m.persistent_stage_failure(before,staged,SimpleNamespace(deadline=time.monotonic()+1))
  text=s.getvalue();self.assertLessEqual(len(text.encode()),6144+40)
  return None if not text else json.loads(text.split(' ',1)[1])
 def test_complete_mismatch_hashes_fields_first5_no_values(self):
  raw,new,m=self.scope();before={f'usr/payload-{i}':dict(type='file',mode=420,uid=0,gid=0,bytes=9,sha256='a'*64)for i in range(9)};after=copy.deepcopy(before)
  for v in after.values():v['sha256']='b'*64
  row=self.record(m,before,dict(complete=True,nodes=after,unsupported_counts={}))
  self.assertTrue(row['observation_complete']);self.assertFalse(row['node_maps_equal']);self.assertEqual(row['changed_nodes'],9);self.assertEqual(len(row['examples']),5);self.assertEqual(row['omitted_examples'],4)
  for e in row['examples']:self.assertEqual(e['fields'],['sha256']);self.assertEqual(e['kind'],'changed');self.assertNotEqual(e['before'],e['after']);self.assertNotIn('a'*64,str(e))
  self.assertFalse(row['acceptance_authority']);self.assertFalse(row['cleanup_authority'])
 def test_incomplete_vs_equal_complete_and_original_guard(self):
  import contextlib,io
  raw,new,m=self.scope();before={'etc/a':dict(type='file',mode=420,uid=0,gid=0,bytes=1,sha256='a'*64)};partial=dict(complete=False,nodes={},unsupported_counts={'root observation deadline':1})
  row=self.record(m,before,partial);self.assertEqual(row['comparison_scope'],'PARTIAL_OBSERVATION_NOT_EVIDENCE_OF_SOURCE_DRIFT');self.assertEqual(row['unsupported_counts'],partial['unsupported_counts']);self.assertFalse(row['observation_complete'])
  self.assertIsNone(self.record(m,before,dict(complete=True,nodes=before,unsupported_counts={})))
  module=ast.parse(A.strip_phase(new));fn=next(n for n in module.body if isinstance(n,ast.FunctionDef)and n.name=='materialize');gate=next(n for n in fn.body if isinstance(n,ast.Try)and any(isinstance(v,ast.Constant)and v.value=='complete persistent stage differs'for v in ast.walk(n)))
  stream=io.StringIO()
  with contextlib.redirect_stderr(stream),self.assertRaisesRegex(ValueError,'complete persistent stage differs'):
   exec(compile(ast.Module(body=[gate],type_ignores=[]),'<unchanged-original-stage-guard>','exec'),dict(need=m.need,persistent_stage_failure=m.persistent_stage_failure,before=before,staged=partial,limits=SimpleNamespace(deadline=time.monotonic()+1)))
  self.assertIn('PERSISTENT_STAGE_FAILURE',stream.getvalue())
 def test_diagnostic_loss_malformed_and_huge_maps_grant_nothing(self):
  raw,new,m=self.scope()
  for before,staged in(({},{}),({},dict(complete=False,nodes={},unsupported_counts={'bad':-1})),({},dict(complete=False,nodes={'x':None},unsupported_counts={}))):
   self.assertIsNone(self.record(m,before,staged))
  with patch.object(m.json,'dumps',side_effect=OSError('INERT_DIAGNOSTIC_LOSS')):self.assertIsNone(self.record(m,{},dict(complete=False,nodes={},unsupported_counts={})))
 def test_actual_prepare_updates_exact_externalpin_without_budget_change(self):
  with tempfile.TemporaryDirectory()as td:
   target=Path(td)/'target';caller=target/'scripts/ci/full-root-upgrade-caller';caller.mkdir(parents=True)
   raw=(ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').read_bytes();(caller/'persistent_scope.py').write_bytes(raw);(caller/'container.py').write_bytes((ROOT/'scripts/ci/full-root-upgrade-caller/container.py').read_bytes())
   name='scripts/ci/full-root-upgrade-caller/container.py';config=target/'config.json';C.save(config,dict(code_pins={name:C.sha((caller/'container.py').read_bytes()),'scripts/ci/full-root-upgrade-caller/persistent_scope.py':C.sha(raw)},external_pins={'/persistent_scope.py':C.sha(raw),'unchanged':'a'*64},stage_seconds=900,verify_seconds=600,driver_seconds=1800,copy_seconds=600));C.save(target/'adapter.json',{})
   focused_prepare_without_capacity(SimpleNamespace(prepare=lambda *a,**k:(config,caller)),ROOT,target,'normal');v=C.decode(C.read(config));self.assertEqual(v['external_pins']['/persistent_scope.py'],C.sha((caller/'persistent_scope.py').read_bytes()));self.assertEqual(v['external_pins']['unchanged'],'a'*64);self.assertEqual([v[n]for n in('stage_seconds','verify_seconds','driver_seconds','copy_seconds')],[900,600,1800,600])

def pre_observation(raw):
 raw=A.strip_phase(raw)
 text=raw.decode();C.need(text.count(A.PERSISTENT_OBSERVATION_API)==text.count(A.PERSISTENT_API_NEW)==1,'one private persistent observer seam');return text.replace(A.PERSISTENT_OBSERVATION_API,'',1).replace(A.PERSISTENT_API_NEW,A.PERSISTENT_API_OLD,1).encode()

class PersistentObservation(unittest.TestCase):
 def test_no_cache_relative_oracle_and_complete_original_fallback(self):
  import itertools,random
  scope,roots,copier,fresh,copyfresh=self.apis()
  driver=C.load('_relative_original_driver',ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py')
  _,_,_,private=scope.persistent_apis(roots,copier,None,driver)
  self.assertIs(fresh.observe.__code__,roots.observe.__code__);self.assertIs(fresh.observe.__globals__['installer'],fresh.installer)
  self.assertIs(private.database.__code__,driver.database.__code__);self.assertIs(private.database.__globals__['relative'],private.relative);self.assertIs(driver.database.__globals__['relative'],driver.relative)
  self.assertIsNot(fresh.installer,roots.installer);self.assertIsNot(private,driver)
  values=[None,[],{},0,True,b'a',Path('a')];alphabet=['','a','.','..','/','\\','\0','é','\udcff',':',' ','\n']
  values+=[''.join(parts)for size in range(4)for parts in itertools.product(alphabet,repeat=size)]
  randomizer=random.Random(489);values+=[''.join(randomizer.choices(alphabet,k=randomizer.randrange(1,15)))for _ in range(10000)]
  class String(str):pass
  values += [String('usr/lib/a'),'.','..','a/','a//b','//server/a','usr/lib/a']
  for original,candidate in((roots.installer.relative,fresh.installer.relative),(driver.relative,private.relative)):
   for value in values:
    outputs=[]
    for fn in(original,candidate):
     try:outputs.append(('return',fn(value)))
     except Exception as error:outputs.append((type(error).__name__,str(error)))
    self.assertEqual(outputs[0],outputs[1],repr(value))
   for value in('usr/lib/a','a','é/x','a\\b/c',':/a','a\n/b'):self.assertIs(candidate(value),value)
  self.assertIs(copyfresh.copy_data.__globals__['roots'],fresh)

 def test_no_cache_relative_real_independent_fresh_payload_and_aliases(self):
  scope,roots,copier,fresh,copyfresh=self.apis()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'dir').mkdir();(root/'dir/a').write_bytes(b'original');os.link(root/'dir/a',root/'dir/b');(root/'link').symlink_to('dir/a')
   before=fresh.observe(root,limits=self.limits(roots),hardlinks='generic-development-internal')
   self.assertEqual(before['nodes'],roots.observe(root,limits=self.limits(roots),hardlinks='generic-development-internal')['nodes'])
   (root/'dir/a').write_bytes(b'changed independently')
   after=fresh.observe(root,limits=self.limits(roots),hardlinks='generic-development-internal')
   self.assertEqual(after['nodes'],roots.observe(root,limits=self.limits(roots),hardlinks='generic-development-internal')['nodes']);self.assertNotEqual(before['nodes']['dir/a']['sha256'],after['nodes']['dir/a']['sha256']);self.assertEqual(after['nodes']['dir/a']['hardlink_group'],after['nodes']['dir/b']['hardlink_group'])


 def apis(self):
  import sys,types
  text=A.persistent_stage((ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').read_bytes()).decode();scope=types.ModuleType('_private_persistent_observation');exec(compile(text,'<source-pinned-persistent-observer>','exec'),scope.__dict__)
  roots=C.load('_source_observation_roots',ROOT/'scripts/update/full_root.py');sys.path.insert(0,str(ROOT/'scripts/update'))
  try:copier=C.load('_source_observation_copy',ROOT/'scripts/update/measure_copy.py')
  finally:sys.path.pop(0)
  fresh,copyfresh,_,_=scope.persistent_apis(roots,copier,None,None);return scope,roots,copier,fresh,copyfresh
 def limits(self,roots):return roots.Limits(deadline=time.monotonic()+20,max_nodes=1000,max_bytes=8*1024**2,max_file_bytes=1024**2,max_package_files=1000)
 def test_internal_copy_complete_private_namespace_and_real_hardlink_equivalence(self):
  scope,roots,copier,fresh,copyfresh=self.apis()
  namespace=copyfresh.copy_data.__globals__;self.assertIs(namespace['roots'],fresh)
  for name in('_parent','_root_check','_source_alias','_copy_internal','copy_data'):
   old=getattr(copier,name);new=getattr(copyfresh,name)
   if name=='_parent':old,new=old.__wrapped__,new.__wrapped__
   self.assertIs(old.__code__,new.__code__);self.assertIs(new.__globals__,namespace);self.assertIsNot(old.__globals__,namespace)
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);os.chmod(base,0o700);source=base/'source';source.mkdir();(source/'dir').mkdir();(source/'dir/a').write_bytes(b'fresh copy bytes');os.link(source/'dir/a',source/'dir/b');(source/'alias').symlink_to('dir/a')
   calls=[];query=fresh._mount_id
   def fresh_query(fd,limits):calls.append((fd,os.fstat(fd).st_ino));return query(fd,limits)
   fresh._mount_id=fresh_query
   # observe carries its own exact private globals; copy functions must also
   # reach the private facade rather than silently escaping into originals.
   copied=[]
   for name,m in(('old',copier),('new',copyfresh)):
    target=base/name;report=m.copy_data(source,target,limits=self.limits(roots),hardlinks='generic-development-internal')
    value=roots.observe(target,limits=self.limits(roots),hardlinks='generic-development-internal');self.assertTrue(value['eligible']);copied.append((report,value['nodes']))
    self.assertEqual((target/'dir/a').stat().st_ino,(target/'dir/b').stat().st_ino);self.assertEqual(os.readlink(target/'alias'),'dir/a')
   self.assertEqual(copied[0][1],copied[1][1]);self.assertEqual(copied[0][0]['copied_nodes'],copied[1][0]['copied_nodes']);self.assertGreater(len(calls),20)
   os.link(source/'dir/a',base/'external')
   for m in(copier,copyfresh):
    with self.assertRaisesRegex(ValueError,'unsupported or incomplete root observation'):m.copy_data(source,base/('refused'+str(id(m))),limits=self.limits(roots),hardlinks='generic-development-internal')
   fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY);other=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY)
   try:
    first=namespace['roots']._mount_id(fd,self.limits(roots));os.dup2(other,fd);second=namespace['roots']._mount_id(fd,self.limits(roots));self.assertNotEqual(first,second);self.assertEqual(second,roots._mount_id(fd,self.limits(roots)))
   finally:os.close(other);os.close(fd)
   for m in(copier,copyfresh):
    with self.assertRaisesRegex(ValueError,'root observation deadline'):m.copy_data(source,base/('deadline'+str(id(m))),limits=roots.Limits(deadline=time.monotonic()-1),hardlinks='generic-development-internal')

 def test_selected604_actual_apis_origin_and_complete_source_inverse(self):
  import shutil,sys,types
  raw=(ROOT/'scripts/update/full_root.py').read_bytes()
  anchor=b'max_packages: int = 587';self.assertEqual(raw.count(anchor),1)
  selected=raw.replace(anchor,b'max_packages: int = 604',1)
  with tempfile.TemporaryDirectory()as td:
   code=Path(td)/'code'
   names=['scripts/update/'+n+'.py'for n in('full_root','measure_copy','root_path','capacity','supervision')]+['scripts/install/local_transaction.py','scripts/ci/full-root-upgrade/root_upgrade.py']
   for name in names:
    target=code/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(selected if name=='scripts/update/full_root.py'else(ROOT/name).read_bytes())
   rendered=A.persistent_stage((ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').read_bytes())
   helper=types.ModuleType('_selected604_persistent_apis');exec(compile(rendered,'<selected604-original-apis>','exec'),helper.__dict__)
   with patch.dict(sys.modules):
    for name in('full_root','measure_copy','root_path','capacity','supervision'):sys.modules.pop(name,None)
    roots,copier,resolver,driver=helper._apis(code)
    self.assertEqual(roots.Limits.__dataclass_fields__['max_packages'].default,604)
    self.assertEqual(Path(roots.__file__),code/'scripts/update/full_root.py')
    self.assertEqual(Path(copier.__file__),code/'scripts/update/measure_copy.py')
    with (code/'scripts/update/full_root.py').open('rb')as stream:self.assertEqual(stream.read(),selected)
    root=Path(td)/'payload';root.mkdir();(root/'ordinary').write_bytes(b'selected604 unchanged payload')
    observed=roots.observe(root,limits=self.limits(roots),hardlinks='generic-development-internal')
    self.assertTrue(observed['complete']);self.assertEqual(observed['nodes']['ordinary']['bytes'],29)
    # Every other source byte and any other composition default still refuses
    # before libc setup or the first fresh-descriptor query can run.
    for bad in(raw.replace(anchor,b'max_packages: int = 600'),raw.replace(anchor,b'max_packages: int = 605'),selected+b'\n',selected.replace(b'def observe(',b'def changed_observe(')):
     (code/'scripts/update/full_root.py').write_bytes(bad)
     with patch.object(helper,'_mount600',side_effect=AssertionError('source proof precedes query')),self.assertRaisesRegex(ValueError,'whole persistent observation API source'):
      helper.persistent_apis(roots,copier,resolver,driver)
    (code/'scripts/update/full_root.py').write_bytes(selected)
    old=(code/'scripts/update/measure_copy.py').read_bytes();(code/'scripts/update/measure_copy.py').write_bytes(old+b'\n')
    with patch.object(helper,'_mount600',side_effect=AssertionError('whole copier proof precedes query')),self.assertRaisesRegex(ValueError,'whole persistent observation API source'):
     helper.persistent_apis(roots,copier,resolver,driver)

 def test_whole_rendered_inverse_and_all_walker_copy_code_held(self):
  scope,roots,copier,fresh,copyfresh=self.apis();raw=(ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').read_bytes();rendered=A.persistent_stage(raw);prior=pre_observation(rendered)
  self.assertEqual(prior.decode().replace(A.PERSISTENT_STAGE_DATA,'',1).replace(A.PERSISTENT_STAGE_WRAPPER,A.PERSISTENT_STAGE_GUARD,1).encode(),raw)
  fn=lambda b:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)};before,after=fn(prior),fn(A.strip_phase(rendered));self.assertEqual(set(after)-set(before),{'_mount600','persistent_apis'});self.assertEqual({n for n in before if before[n]!=after[n]},{'_apis'})
  self.assertIs(roots.observe.__code__,fresh.observe.__code__);self.assertIs(copier.copy_data.__code__,copyfresh.copy_data.__code__);self.assertIs(roots.observe.__globals__['_mount_id'],roots._mount_id);self.assertIsNot(fresh._mount_id,roots._mount_id);self.assertIs(copyfresh.copy_data.__globals__['roots'],fresh);self.assertEqual(roots._file_hash,fresh._file_hash)
 def test_real_descriptor_reuse_is_fresh_not_identity_cached(self):
  scope,roots,copier,fresh,copyfresh=self.apis()
  with tempfile.TemporaryDirectory()as td:
   fd=os.open(td,os.O_RDONLY|os.O_DIRECTORY);other=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY)
   try:
    before=fresh._mount_id(fd,self.limits(roots));self.assertEqual(before,roots._mount_id(fd,self.limits(roots)));os.dup2(other,fd);after=fresh._mount_id(fd,self.limits(roots));self.assertEqual(after,roots._mount_id(fd,self.limits(roots)));self.assertNotEqual(before,after)
   finally:os.close(other);os.close(fd)
 def test_exact_fallback_mismatch_and_unexpected_errno_refuse(self):
  import ctypes,errno
  scope,roots,copier,fresh,copyfresh=self.apis()
  class Call:
   def __init__(self,mode):self.mode=mode;self.calls=0
   def __call__(self,fd,path,flags,mask,result):
    self.calls+=1
    if self.mode in('fallback','error'):ctypes.set_errno(errno.ENOSYS if self.mode=='fallback'else errno.EIO);return -1
    result._obj.mask=0x1000;result._obj.mnt_id=2**63;return 0
  with tempfile.TemporaryDirectory()as td:
   fd=os.open(td,os.O_RDONLY|os.O_DIRECTORY)
   try:
    for mode in('fallback','mismatch','error'):
     call=Call(mode);old=[]
     def original(descriptor,limits):old.append(descriptor);return roots._mount_id(descriptor,limits)
     with patch.object(ctypes,'CDLL',return_value=SimpleNamespace(statx=call)):query=scope._mount600(original)
     if mode=='fallback':
      self.assertEqual(query(fd,self.limits(roots)),roots._mount_id(fd,self.limits(roots)));query(fd,self.limits(roots));self.assertEqual((call.calls,old),(1,[fd,fd]))
     else:
      with self.assertRaises(ValueError if mode=='mismatch'else OSError):query(fd,self.limits(roots))
   finally:os.close(fd)
 def test_real_literal_absolute_hardlink_copy_and_complete_observation_equal(self):
  scope,roots,copier,fresh,copyfresh=self.apis()
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);source=base/'source';source.mkdir();(source/'usr').mkdir();(source/'etc').mkdir();(source/'usr/a').write_bytes(b'private unchanged');os.link(source/'usr/a',source/'usr/b');(source/'usr/alias').symlink_to('/usr/a')
   for n in scope.RUNTIME:(source/n).mkdir()
   for n in scope.MOUNT_FILES:(source/n).write_bytes(b'ordinary boundary')
   fd=roots._open_root(source)
   try:mount=roots._mount_id(fd,self.limits(roots))
   finally:os.close(fd)
   before,excluded=scope.source_manifest(source,self.limits(roots),fresh,dict(source_mount=mount,observed_mounts=[]))
   for name,r,m in(('old',roots,copier),('new',fresh,copyfresh)):
    target=base/name;report=m.copy_data(source,target,limits=self.limits(roots),excluded=scope.RUNTIME|scope.MOUNT_FILES,absolute_paths=True);self.assertFalse(report['unsupported_counts']);scope._restore_boundaries(source,target,before,r,m,self.limits(roots));v=r.observe(target,limits=self.limits(roots),hardlinks='generic-development-internal',absolute_paths=True);self.assertTrue(v['complete']);self.assertEqual(v['nodes'],before);self.assertGreater(v['unsupported_counts']['absolute-symlink'],0);self.assertFalse(v['eligible']);self.assertEqual((target/'usr/a').stat().st_ino,(target/'usr/b').stat().st_ino)
 def test_original_deadline_special_hardlink_and_source_drift_refuse(self):
  scope,roots,copier,fresh,copyfresh=self.apis()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'root';root.mkdir();(root/'a').write_bytes(b'payload');os.link(root/'a',Path(td)/'outside')
   for r in(roots,fresh):
    observed=r.observe(root,limits=self.limits(roots),hardlinks='generic-development-internal');self.assertFalse(observed['complete']);self.assertIn('hardlink group not closed',observed['unsupported_counts'])
    with self.assertRaisesRegex(ValueError,'root observation deadline'):r.observe(root,limits=r.Limits(deadline=time.monotonic()-1))
   (Path(td)/'outside').unlink();os.mkfifo(root/'fifo')
   for r in(roots,fresh):self.assertIn('special-node',r.observe(root,limits=self.limits(roots))['unsupported_counts'])
   fake=SimpleNamespace(**vars(roots));fake.__file__=str(Path(td)/'wrong.py');Path(fake.__file__).write_bytes(b'INERT_SOURCE_DRIFT')
   with self.assertRaisesRegex(ValueError,'whole persistent observation API source'):scope.persistent_apis(fake,copier,None,None)
 def test_exact_archive20_factory_native_subset_and_absolute_routes(self):
  self.assertEqual(P.ARCHIVE20_NATIVE4,{'libei-1.6.0-1-aarch64.pkg.tar.xz','libei-1.6.0-1-aarch64.pkg.tar.xz.sig','libgudev-238-3-aarch64.pkg.tar.xz','libgudev-238-3-aarch64.pkg.tar.xz.sig'})
  for n,pin in [('archive20.py',dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968')),('archive20-policy.json',dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'))]:self.assertEqual(C.row(C.HERE/n),pin)
  text=(C.HERE/'prepare.py').read_text();self.assertIn('timeout-minutes: 4',text);self.assertIn('$GITHUB_WORKSPACE/archive32-original-lock/',text);self.assertIn('$GITHUB_WORKSPACE/composition-desktop/',text);self.assertIn('steps.frozen574_archive20.outcome',text);self.assertIn('EXACT_NATIVE_BASE4_FROM_ARCHIVE20_SEEDED_NOT_FULL20',text);self.assertNotIn('module.C.encoded(module.seed_archive20_native',text);self.assertTrue(callable(P.encoded))

if __name__=='__main__':unittest.main(verbosity=2)

class PersistentPhaseMarkers(unittest.TestCase):
 def scope(self):
  import types
  raw=(ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').read_bytes();new=A.persistent_stage(raw);m=types.ModuleType('_bounded_phase_scope');exec(compile(new,'<source-owned-phase-scope>','exec'),m.__dict__);return raw,new,m
 def test_complete_strip_only_inverse_and_unchanged_actions(self):
  raw,new,m=self.scope();self.assertEqual(pre_observation(new).decode().replace(A.PERSISTENT_STAGE_DATA,'',1).replace(A.PERSISTENT_STAGE_WRAPPER,A.PERSISTENT_STAGE_GUARD,1).encode(),raw)
  tree=ast.parse(new);labels=[ast.literal_eval(n.items[0].context_expr.args[0])for n in ast.walk(tree)if isinstance(n,ast.With)and isinstance(n.items[0].context_expr,ast.Call)and isinstance(n.items[0].context_expr.func,ast.Name)and n.items[0].context_expr.func.id=='_updater_phase'];self.assertEqual(set(labels),set(A.PHASE_LABELS));self.assertEqual(len(labels),20)
 def test_fixed_begin_end_fail_and_exception_identity(self):
  _,_,m=self.scope();out=[]
  with patch.object(m.os,'write',side_effect=lambda fd,raw:out.append((fd,raw))or len(raw)):
   with m._updater_phase('COPY'):pass
   error=ValueError('original-error')
   with self.assertRaises(ValueError)as caught:
    with m._updater_phase('SOURCE_BEFORE'):raise error
  self.assertIs(caught.exception,error);self.assertEqual(out,[(2,b'UPDATER489_STAGE_PHASE BEGIN COPY\n'),(2,b'UPDATER489_STAGE_PHASE END COPY\n'),(2,b'UPDATER489_STAGE_PHASE BEGIN SOURCE_BEFORE\n'),(2,b'UPDATER489_STAGE_PHASE FAIL SOURCE_BEFORE\n')])
 def test_cancellation_identity_and_marker_loss(self):
  _,_,m=self.scope();error=KeyboardInterrupt('original-cancel')
  with patch.object(m.os,'write',side_effect=OSError('lost-marker')):
   with self.assertRaises(KeyboardInterrupt)as caught:
    with m._updater_phase('COPY'):raise error
  self.assertIs(caught.exception,error)
 def test_whole_stream_cap_no_runtime_values_or_paths(self):
  _,_,m=self.scope();out=[]
  with patch.object(m.os,'write',side_effect=lambda fd,raw:out.append(raw)or len(raw)):
   for _ in range(1000):
    with m._updater_phase('COPY'):pass
   m._updater_phase_write('BEGIN','/private/path');m._updater_phase_write('other','COPY')
  self.assertLessEqual(sum(map(len,out)),4096);self.assertEqual(m._UPDATER_PHASE_BYTES,4096-sum(map(len,out)));self.assertTrue(all(x in(b'UPDATER489_STAGE_PHASE BEGIN COPY\n',b'UPDATER489_STAGE_PHASE END COPY\n')for x in out))
 def test_existing_complete_caller_frame_forwards_stderr_not_stdout_tail(self):
  import base64,contextlib,io,json
  _,_,m=self.scope();markers=[]
  with patch.object(m.os,'write',side_effect=lambda fd,raw:markers.append(raw)or len(raw)):
   for label in A.PHASE_LABELS:
    with m._updater_phase(label):pass
  stderr=b''.join(markers);stdout=b'original-stdout-prefix\n'+b'x'*9000
  raw=(ROOT/C.LANE/'guest.py').read_bytes();tree=ast.parse(raw);selected=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('caller_failure','forward_caller_failure')];namespace=dict(C=C,json=json);exec(compile(ast.Module(body=selected,type_ignores=[]),'<whole-held-caller-frame-functions>','exec'),namespace)
  nonce='1'*32;record=dict(argv=['/usr/bin/python3','-I','-B','/runner.py'],exit_code=1,seconds=1,time_limit=3900,output_limit=2*1024**2,group_absence_verified=False,stdout_bytes=len(stdout),stdout_sha256=C.sha(stdout),stderr_bytes=len(stderr),stderr_sha256=C.sha(stderr));capture=io.StringIO()
  with contextlib.redirect_stdout(capture):namespace['caller_failure'](dict(nonce=nonce),record,stdout,stderr,None)
  frame=capture.getvalue().encode();worker=dict(argv=['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],stdout_bytes=len(frame),stdout_sha256=C.sha(frame));capture=io.StringIO()
  with contextlib.redirect_stdout(capture):namespace['forward_caller_failure'](dict(nonce=nonce),worker,frame)
  forwarded=json.loads(capture.getvalue().split(' ',2)[2]);self.assertEqual(base64.b64decode(forwarded['stderr']['tail_base64'],validate=True),stderr);self.assertFalse(forwarded['stderr']['truncated']);self.assertTrue(forwarded['stdout']['truncated']);self.assertEqual(forwarded['worker_capture']['frame_sha256'],C.sha(frame.rstrip(b'\n')));self.assertLess(len(frame),25*1024);self.assertEqual(forwarded['nonce'],nonce)
