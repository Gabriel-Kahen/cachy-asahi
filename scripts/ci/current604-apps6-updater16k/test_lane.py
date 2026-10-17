# SPDX-License-Identifier: MIT
"""Inert adapters plus actual owned filesystem controls; never VM evidence."""
import ast,copy,hashlib,os,subprocess,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import contract as C
import adapter as A,cap_scope,prepare as P,run,vm
ROOT=Path(os.environ.get('APPS6_UPDATER16K_SOURCE',C.ROOT))
class Controls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors/Git/network forbidden'));p.start();self.addCleanup(p.stop)
 def test_all_cases_unbound_before_source_output_or_actor(self):
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
   C.save(config,dict(code_pins={name:C.sha(raw),'other':'b'*64},copy_seconds=600,driver_seconds=1800,stage_seconds=900,verify_seconds=600));C.save(target/'adapter.json',dict(config_sha256='prior'))
   original=SimpleNamespace(prepare=lambda *a,**kw:(config,calling));A.prepare_selected(original,ROOT,target,'normal');value=C.decode(C.read(config))
   self.assertEqual(value['code_pins'][name],C.sha((calling/'container.py').read_bytes()));self.assertEqual(value['code_pins']['other'],'b'*64);self.assertEqual(value['driver_seconds'],1800)
   self.assertEqual(C.decode(C.read(target/'adapter.json'))['config_sha256'],C.sha(config.read_bytes()))
 def test_caller_changes_only_fixed_vm_entry_predicate(self):
  raw=(ROOT/'scripts/ci/full-root-upgrade-caller/container.py').read_bytes();out=A.caller(raw)
  funcs=lambda d:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(d).body if isinstance(n,ast.FunctionDef)}
  a,b=funcs(raw),funcs(out);self.assertEqual([n for n in a if a[n]!=b[n]],['guard']);self.assertIn(b"os.sysconf('SC_PAGE_SIZE') == 16384",out);self.assertNotIn(b"Path('/.dockerenv').is_file()",out)
  self.assertEqual(sum(1<<n for n in C.CAPS),C.MASK);self.assertNotIn(21,C.CAPS)
 def test_source_emit_closed_and_tamper_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   output=Path(tmp)/'source';receipt=P.emit(ROOT,output);self.assertLessEqual(receipt['source_rows'],512)
   lane=output/C.LANE;rows=C.decode((lane/'source-manifest.json').read_bytes())['files']
   self.assertEqual(set(rows),{str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}-{C.LANE+'/source-manifest.json'})
   for n,r in rows.items():self.assertEqual(C.row(output/n),r)
   with patch.object(C,'row',return_value={}),self.assertRaisesRegex(ValueError,'frozen original source'):P.emit(ROOT,Path(tmp)/'bad')
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
  q=vm.qemu(Path('/Image'),Path('/boot.raw'),Path('/data.raw'));self.assertIn('tcg,thread=multi',q);self.assertEqual(q[q.index('-nic')+1],'none');self.assertEqual(q[q.index('-display')+1],'none');self.assertEqual(q[q.index('-m')+1],'4096')
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
if __name__=='__main__':unittest.main(verbosity=2)
