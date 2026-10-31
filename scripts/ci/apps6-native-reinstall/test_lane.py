# SPDX-License-Identifier: MIT
"""Finite inert/source/data controls; no container, signing or native claims."""
import ast,copy,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import adapter as A
import contract as C
import rules
import run
SOURCE=A.ROOT

def actual_shape():
 worker=dict(direct_child_reaped=True,termination=None,returncode=0)
 tx=dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',architecture='aarch64',commit_started=True,packages_committed=True,cleanup='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED',scope='DEVELOPMENT_OWNED_OFFLINE_COPIED_ROOT_ONLY',synthetic=True,dependency_checks='ORDINARY_LIBALPM',worker=worker,before=dict(packages_sha256='a'*64),after=dict(packages_sha256='a'*64),prepared_add={'fixture':'1-1'},prepared_remove={})
 return dict(status=rules.LIFECYCLE,plans_applied_scope='INSTALLED_CATALOG_CLI_CASES_ONLY',repair=dict(status='PASS_REAL_SIGNED_SYNTHETIC_SAME_VERSION_REPAIR',host_architecture='aarch64',native_aarch64='EXECUTED_SIGNED_SYNTHETIC_COPY_ONLY',hardware='NOT_RUN',host_database='NOT_ACCESSED',trust='ISOLATED_TEST_AUTHORITY_NOT_PRODUCTION',damaged_selected_payload_restored=True,missing_selected_leaf_restored=True,repeat_reinstall_committed=True,source_preserved=True,copied_workspace_absent=True,transactions=[dict(copy.deepcopy(tx),operation=op) for op in ('install','reinstall','reinstall','reinstall','remove')],refusals=[dict(status='FAIL',commit_started=False,packages_committed=False,error=e) for e in ('caller plan SHA256 differs','complete before snapshot differs')],libalpm={'sha256':'94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902'}))

class Lane(unittest.TestCase):
 def test_unbound_before_derivative_or_actor(self):
  with patch.object(C._original,'read',return_value={'status':'UNBOUND'}),patch.object(A,'module',side_effect=AssertionError('derivative before binding')),patch.object(subprocess,'Popen',side_effect=AssertionError('actor before binding')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):run.execute(SOURCE,Path('/unused'),Path('/unused-output'),'a'*32)
 def test_distinct_policy_not_historical_receipt(self):
  self.assertEqual(rules.VERSIONS,dict(runtime='0.1.0-1',apps='0.1.0-6',cache='0.2.0-1'));self.assertNotEqual(rules.REPORT,'PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE')
 def test_exact_original_pin_and_anchor_refusal(self):
  with tempfile.TemporaryDirectory() as t:
   with self.assertRaises(FileNotFoundError):A.text(Path(t),'run.py')
  with self.assertRaisesRegex(ValueError,'anchor'):A.replace('duplicate duplicate','duplicate','new')
  with self.assertRaisesRegex(ValueError,'anchor'):A.replace('absent','missing','new')
 def test_all_derived_modules_compile_without_execution(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')):
   for name in ('run.py','job.py','lifecycle.py'):compile(A.text(SOURCE,name),name,'exec')
 def test_run_actor_cleanup_bodies_unchanged(self):
  original=ast.parse(A.read(SOURCE,'run.py'));adapted=ast.parse(A.text(SOURCE,'run.py'))
  def f(tree,name):return next(n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==name)
  for name in ('Owners','command','capture','build_pair','dependency_image'):
   self.assertEqual(ast.dump(f(original,name)),ast.dump(f(adapted,name)))
 def test_original_cleanup_body_ast_identical(self):
  a=ast.parse(A.read(SOURCE,'job.py'));b=ast.parse(A.text(SOURCE,'job.py'))
  get=lambda t:next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name=='cleanup')
  self.assertEqual(ast.dump(get(a)),ast.dump(get(b)))
 def test_runner_emits_real_rules_and_contract_import_without_registered_module(self):
  with tempfile.TemporaryDirectory() as t:
   context=Path(t);runner=A.runner(SOURCE,context);policy=json.loads((runner/'input-policy.json').read_bytes());policy['status']='UNBOUND';(runner/'input-policy.json').write_text(json.dumps(policy));manifest=json.loads((context/'runner-derivations.json').read_bytes());self.assertEqual(set(manifest['outputs']),{p.relative_to(runner).as_posix() for p in runner.rglob('*') if p.is_file()})
   old=sys.path[:];sys.path.insert(0,str(runner))
   try:
    spec=importlib.util.spec_from_file_location('not_registered_apps6_runtime_contract',runner/'contract.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    self.assertEqual(m.HERE,runner);self.assertEqual(m.LABEL,C.LABEL)
    with self.assertRaisesRegex(ValueError,'UNBOUND'):m.policy()
   finally:sys.path[:]=old
 def test_unchanged_repair_child_call_not_outer_unshare(self):
  text=(HERE/'repair.py').read_text();self.assertIn('driver.child(case)',text);self.assertNotIn('driver.outer(',text);self.assertNotIn('cap-add',text);self.assertNotIn('seccomp=',text)
 def test_repair_inputs_dependency_set_is_closed(self):
  import repair
  self.assertEqual(len(repair.DEPENDENCIES),15);self.assertEqual(len(set(repair.DEPENDENCIES)),15)
  self.assertIn('scripts/apps/test_actual_reinstall.py',repair.DEPENDENCIES);self.assertIn('scripts/install/local_transaction.py',repair.DEPENDENCIES)
 def test_full_valid_shape_and_old_status_refusal(self):
  value=actual_shape();C.validate_repair(value)
  with self.assertRaises(ValueError):C.validate_repair(dict(value,status='PASS_APPS_CACHE_INSTALLED_LIFECYCLE'))
 def test_missing_or_wrong_transition_refuses(self):
  for change in ('missing','wrong','expanded','unreaped','commit-unknown','inventory'):
   v=actual_shape();tx=v['repair']['transactions']
   if change=='missing':tx.pop()
   elif change=='wrong':tx[2]['operation']='install'
   elif change=='expanded':tx[2]['prepared_add']['extra']='1'
   elif change=='unreaped':tx[2]['worker']['direct_child_reaped']=False
   elif change=='commit-unknown':tx[2]['packages_committed']='UNKNOWN'
   else:tx[2]['after']['packages_sha256']='b'*64
   with self.subTest(change=change),self.assertRaises(ValueError):C.validate_repair(v)
 def test_refusal_or_architecture_or_preservation_mismatch_fails(self):
  for change in ('refusal','architecture','disposal','library'):
   v=actual_shape();r=v['repair']
   if change=='refusal':r['refusals'][0]['commit_started']=True
   elif change=='architecture':r['host_architecture']='x86_64'
   elif change=='disposal':r['copied_workspace_absent']=False
   else:r['libalpm']['sha256']='0'*64
   with self.subTest(change=change),self.assertRaises(ValueError):C.validate_repair(v)
 def test_lifecycle_repair_is_between_first_install_and_original_reinstall(self):
  s=A.text(SOURCE,'lifecycle.py');self.assertLess(s.index("installed('install')"),s.index('repair_result=repair.run()'));self.assertLess(s.index('repair_result=repair.run()'),s.index("installed('same-version-reinstall')"));self.assertIn("I.payloads(L,products);preserve()",s)
 def test_native_workflow_boundaries_and_no_capability_widening(self):
  path=HERE.parents[2]/'.github/workflows/native-arm-apps6-reinstall.yml';s=path.read_text();self.assertIn('ubuntu-24.04-arm',s);self.assertIn('timeout-minutes: 100',s);self.assertTrue(('@JOB_SHA256@' in s and '@MANIFEST_SHA256@' in s) or __import__('re').search(r"'[0-9a-f]{64}' \"\$SLICE/job.py\" '[0-9a-f]{64}' \"\$SLICE/source-manifest.json\"",s));self.assertLess(s.index('Prove the explicit'),s.index('existing secrets'));self.assertNotIn('--privileged',s)
 def test_all_inherited_here_paths_and_actual_catalog_mount_operand(self):
  tree=ast.parse(A.text(SOURCE,'run.py'))
  remaining=[n for n in ast.walk(tree) if isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name) and n.value.id=='C' and n.attr=='HERE'];self.assertEqual(remaining,[])
  mounts=[n for n in ast.walk(tree) if isinstance(n,ast.JoinedStr) and any(isinstance(v,ast.Constant) and isinstance(v.value,str) and '/catalog_fixture.py,dst=' in v.value for v in n.values)];self.assertEqual(len(mounts),1)
  for node in mounts[0].values:
   if isinstance(node,ast.FormattedValue):self.assertIsInstance(node.value,ast.Name);self.assertEqual(node.value.id,'source')
  operand=eval(compile(ast.Expression(mounts[0]),'<exact catalog mount operand>','eval'),{'__builtins__':{}},{'source':SOURCE})
  parts=operand.split(',');self.assertEqual(parts[0],'type=bind');self.assertEqual(parts[2:],["dst=/catalog_fixture.py",'readonly']);path=Path(parts[1].removeprefix('src='));self.assertTrue(path.is_file());self.assertEqual(path.read_bytes(),A.read(SOURCE,'catalog_fixture.py'))
  oldjob=ast.parse(A.text(SOURCE,'job.py'));paths=[]
  for node in ast.walk(oldjob):
   if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Div) and isinstance(node.left,ast.Attribute) and isinstance(node.left.value,ast.Name) and node.left.value.id=='C' and node.left.attr=='HERE':
    self.assertIsInstance(node.right,ast.Constant);paths.append(node.right.value);self.assertTrue((HERE/node.right.value).is_file())
  self.assertEqual(paths,['source-manifest.json']*4)
  for name in ('rules.py','repair.py','input-policy.json'):self.assertTrue((HERE/name).is_file())
  with tempfile.TemporaryDirectory() as temporary:
   runner=A.runner(SOURCE,Path(temporary));borrowed=[]
   for filename in ('lifecycle.py','installed.py','runtime_image.py'):
    for node in ast.walk(ast.parse(A.read(SOURCE,filename))):
     if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value.startswith('/runner/'):
      relative=node.value[len('/runner/'):];self.assertTrue((runner/relative).is_file());borrowed.append(relative)
   self.assertEqual(set(borrowed),{'contract.py','accepted/lifecycle.py','accepted/root_upgrade.py'})
   self.assertTrue((runner/'lifecycle.py').is_file());self.assertTrue((runner/'installed.py').is_file());self.assertTrue((runner/'runtime_image.py').is_file())
 def test_actual_workflow_entrypoint_imports_from_outside_checkout(self):
  workflow=(HERE.parents[2]/'.github/workflows/native-arm-apps6-reinstall.yml').read_text()
  entries=[(('job.py',),['-I','-B'],'"$SLICE/job.py"'),(('run.py',),['-B'],'"$SLICE/run.py"'),(('..','maintained_desktop574.py'),['-I','-B'],'scripts/ci/maintained_desktop574.py'),(('..','test_maintained_desktop574.py'),['-I','-B'],'scripts/ci/test_maintained_desktop574.py')]
  with tempfile.TemporaryDirectory() as temporary:
   for relative,flags,operand in entries:
    path=HERE.joinpath(*relative).resolve()
    self.assertIn('python3 '+' '.join(flags)+' '+operand,workflow)
    result=subprocess.run([sys.executable,*flags,str(path),'--help'],cwd=temporary,env=dict(PATH='/usr/bin:/bin',HOME=temporary,LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1'),capture_output=True,timeout=15)
    self.assertEqual(result.returncode,0,(str(path),result.stderr.decode()));self.assertLessEqual(len(result.stdout)+len(result.stderr),65536);self.assertIn(b'usage:',result.stdout.lower())
 def test_actual_eight_file_layout_and_installed_helpers_load_unchanged_backend(self):
  import repair
  source=Path(os.environ.get('APPS6_CANDIDATE_SOURCE',str(SOURCE))).absolute()
  backend=repair.load('apps6_layout_unchanged_backend',source/'scripts/apps/transaction.py')
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);stage=root/'stage';stage.mkdir()
   for name in ('cachy-asahi-apps','cachy-asahi-repository-runtime'):
    recipe=source/'packages/tools'/name
    row=subprocess.run(['/bin/bash','-c','set -euo pipefail; source "$1"; package','package-layout',str(recipe/'PKGBUILD')],env=dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',srcdir=str(recipe),startdir=str(recipe),pkgdir=str(stage)),capture_output=True,timeout=30)
    self.assertEqual(row.returncode,0,row.stderr.decode())
   paths={p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file() and ('cachy-asahi-apps' in p.parts or p.name=='cachy-asahi-apps')};self.assertEqual(len(paths),8)
   provenance=stage/'usr/share/doc/cachy-asahi-apps/source-provenance.json';pin=dict(bytes=provenance.stat().st_size,sha256=repair.sha(provenance));runtime=stage/C.RUNTIME.relative_to('/')
   view=repair.installed_view(stage,root/'view',pin)
   args=__import__('types').SimpleNamespace(apps_source=str(view),apps_provenance_sha256=pin['sha256'],repository_source=str(runtime))
   app,client,release=backend.app_source(args)
   self.assertEqual(app.HERE,view);self.assertEqual(Path(client.__file__),runtime/'scripts/client/client.py');self.assertEqual(Path(release.__file__),runtime/'scripts/release/release.py');self.assertEqual(set(p.name for p in view.iterdir()),{'apps.py','inventory.py','helper-pins.json','cachy-asahi-apps','source-provenance.json'})
   for number,kind in enumerate(('missing','tampered','hardlink','symlink')):
    installed=stage/'usr/bin/cachy-asahi-apps';data=installed.read_bytes();installed.unlink()
    if kind=='tampered':installed.write_bytes(b'tampered')
    elif kind=='hardlink':(stage/'alias').write_bytes(data);os.link(stage/'alias',installed)
    elif kind=='symlink':(stage/'alias').write_bytes(data);installed.symlink_to('../../alias')
    with self.subTest(kind=kind),self.assertRaises((ValueError,FileNotFoundError)):repair.installed_view(stage,root/('refuse-'+str(number)),pin)
    if installed.is_symlink() or installed.exists():installed.unlink()
    if (stage/'alias').exists():(stage/'alias').unlink()
    installed.write_bytes(data);installed.chmod(0o755)
   (runtime/'scripts/client/client.py').write_bytes(b'tampered installed helper')
   with self.assertRaises(ValueError):backend.app_source(args)
 def test_retainer_keeps_raw_repair_and_derivation_receipts(self):
  s=A.text(SOURCE,'job.py');self.assertIn("signed-repair/native-result.json",s);self.assertIn('runner-derivations.json',s);self.assertIn("len(entries)<=256",s);self.assertIn("result['bytes']<=old.MAX_TOTAL",s);self.assertIn('original/native/lifecycle repair receipts differ',s);self.assertIn('original worker/plan repair joins differ',s)


 def evidence_case(self,root):
  import repair
  source=root/'private';source.mkdir(mode=0o700)
  for name in repair.PUBLIC_FILES:(source/name).write_bytes(('TEST '+name+'\n').encode())
  for name in ('seed/boot/platform-fixture','bundle/repo/test.db.tar.gz'):
   path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'unchanged TEST evidence\n')
  (source/'bundle/repo/test.db').symlink_to('test.db.tar.gz');return source
 def test_evidence_publication_preserves_complete_bytes_aliases_and_private_mode(self):
  import repair,stat
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);source=self.evidence_case(root);target=root/'public'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('publication has no actors')):receipt=repair.publish_evidence(source,target,True)
   self.assertTrue(receipt['complete']);self.assertEqual(stat.S_IMODE(source.stat().st_mode),0o700)
   self.assertTrue(repair.PUBLIC_FILES<=receipt['files'].keys());self.assertEqual(os.readlink(target/'bundle/repo/test.db'),'test.db.tar.gz')
   for name,row in receipt['files'].items():
    path=target/name
    if row['type']=='file':self.assertEqual(path.read_bytes(),(source/name).read_bytes());self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o644)
    elif row['type']=='directory':self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o755)
   self.assertEqual(json.loads((target/'publication.json').read_bytes()),receipt)
 def test_missing_worker_or_private_workspace_never_publishes_completion(self):
  import repair
  for kind in ('missing-worker','workspace'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as t:
    root=Path(t);source=self.evidence_case(root)
    if kind=='missing-worker':(source/'worker-4.stderr').unlink()
    else:(source/'owned-copy').mkdir();(source/'owned-copy/private').write_bytes(b'never export')
    with self.assertRaisesRegex(ValueError,'complete five-worker'):repair.publish_evidence(source,root/'complete',True)
    self.assertFalse((root/'complete').exists());row=repair.publish_evidence(source,root/'failed',False);self.assertFalse(row['complete']);self.assertNotIn('owned-copy',row['files']);self.assertFalse((root/'failed/owned-copy').exists())
 def test_evidence_unknown_private_file_hardlink_and_unsafe_alias_refuse(self):
  import repair
  for kind in ('private','hardlink','alias'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as t:
    root=Path(t);source=self.evidence_case(root)
    if kind=='private':(source/'private-key').write_bytes(b'never publish')
    elif kind=='hardlink':os.link(source/'public.gpg',root/'alias')
    else:(source/'bundle/repo/test.db').unlink();(source/'bundle/repo/test.db').symlink_to('../../public.gpg')
    with self.assertRaises(ValueError):repair.publish_evidence(source,root/'public',True)
    self.assertFalse((root/'public').exists())
 def test_native_annotation_precedes_publication_and_all_outputs_remain_required(self):
  s=(HERE/'repair.py').read_text();self.assertLess(s.index("(case/'native-result.json').write_bytes"),s.index('try:publish_evidence'));self.assertNotIn("shutil.copytree(case,'/out/repair'",s)
  for i in range(5):
   import repair
   self.assertTrue({f'worker-{i}.stdout',f'worker-{i}.stderr',f'plan-{i}.json',f'inventory-{i}.json'}<=repair.PUBLIC_FILES)

if __name__=='__main__':unittest.main(verbosity=2)
