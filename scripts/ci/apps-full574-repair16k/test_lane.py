# SPDX-License-Identifier: MIT
"""Actor-blocked finite source and real-temporary-file controls; no native credit."""
import ast,copy,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import contract as C
import adapter,prepare,vm,job

def dump(node):return ast.dump(node,include_attributes=False)
def function(raw,name):return next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name==name)

class Lane(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.original=Path(os.environ['FULL574_REPAIR16K_SOURCE']).absolute();cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)/'source'
  # Bound workflow inputs are not emitter templates. Select an explicit NULL
  # fixture only for source-emission controls; original bound policy is held.
  fixture=prepare.C.HERE
  if C.decode(C.read(fixture/'input-policy.json'))['binding'] is not None:
   original=fixture;fixture=Path(cls.tmp.name)/'explicit-null-template';fixture.mkdir()
   for name in prepare.OWN:(fixture/name).write_bytes(C.read(original/name))
   (fixture/'input-policy.json').write_bytes(C.encoded(dict(schema_version=1,status='UNBOUND_NEW_NATIVE_REPAIR_CASES_AND_ACCEPTED_KERNEL',binding=None)))
  with patch.object(prepare.C,'HERE',fixture),patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):cls.emitted=prepare.emit(cls.original,cls.root,os.environ.get('FULL574_REPAIR16K_NATIVE_SOURCE'))
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def setUp(self):self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));self.block.start()
 def tearDown(self):self.block.stop()
 def native(self,name):return C.read(self.root/C.NATIVE/name)
 def test_closed_exact_emission_and_unbound_before_output(self):
  with patch.object(C,'HERE',self.root/C.LANE):rows=C.check_source(self.root)
  self.assertEqual(len(rows),134);self.assertEqual(len(prepare.OWN),11);self.assertEqual(C.row(self.root/C.NATIVE/'source-manifest.json')['sha256'],C.NATIVE_MANIFEST)
  self.assertEqual(C.row(self.root/C.LANE/'vm.py'),C.row(HERE/'vm.py'))
  with patch.object(C,'HERE',self.root/C.LANE),self.assertRaisesRegex(ValueError,'UNBOUND16K'):C.gate(self.root,'repair-bytes')
  self.assertEqual(set(C.decode(self.native('source-manifest.json'))['files']),set(C.decode(C.read(Path(os.environ.get('FULL574_REPAIR16K_NATIVE_SOURCE',self.original))/C.NATIVE/'source-manifest.json'))['files']))
 def test_explicit_frozen_baseline_keeps_original113_and_current_helpers(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'source'
   with patch.object(prepare.C,'HERE',self.root/C.LANE):prepare.emit(self.original,out,self.root)
   frozen=C.decode(C.read(self.root/C.NATIVE/'source-manifest.json'))
   for name,row in frozen['files'].items():self.assertEqual(C.row(out/name),row)
   self.assertEqual(C.row(out/C.NATIVE/'source-manifest.json')['sha256'],C.NATIVE_MANIFEST)
   self.assertEqual(C.row(out/'manifests/packages.toml'),C.row(self.root/'manifests/packages.toml'))
   self.assertEqual(C.row(out/C.LANE/'prepare.py'),C.row(HERE/'prepare.py'))
 def test_explicit_baseline_missing_drift_and_alias_refuse_before_output(self):
  import shutil
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);empty=root/'empty';empty.mkdir();out=root/'missing-output'
   with self.assertRaises((ValueError,FileNotFoundError)):prepare.emit(self.original,out,empty)
   self.assertFalse(out.exists());alias=root/'alias';alias.symlink_to(self.root,target_is_directory=True)
   with self.assertRaises(ValueError):prepare.emit(self.original,out,alias)
   self.assertFalse(out.exists());baseline=root/'baseline';baseline.mkdir()
   values=C.decode(C.read(HERE/'source-pins.json'))
   for name in values['files']:
    if values['origins'][name]!=C.NATIVE_SOURCE:continue
    p=baseline/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(self.root/name,p)
   leaf=baseline/'manifests/packages.toml';leaf.write_bytes(leaf.read_bytes()+b'\n# actual drift\n')
   with self.assertRaisesRegex(ValueError,'borrowed source differs: manifests/packages.toml'):prepare.emit(self.original,out,baseline)
   self.assertFalse(out.exists())
 def test_actual_media_argv_reaches_genuine_backend_parser_with_original_common_scope(self):
  import contextlib,io
  from types import SimpleNamespace
  D=C.load('disk_backend_parser_control',HERE/'disk.py');T=C.load('genuine_backend_parser_control',self.root/'scripts/apps/transaction.py')
  # Original39048514241 media ledger: argparse exit2, before any VM/copy.
  captured=['/usr/bin/python3','-I','-B','/source/scripts/apps/transaction.py','prepare-copy','--workspace','/work/main','--full574-policy','/inputs/full574-policy.json','--full574-policy-sha256','ffa7fc3e995bfc79ea86ffaa7ff1b5376431fd5be098cc7c18e519a0d40fda7d','--full574-lease','/inputs/full574-lease.json','--full574-lease-sha256','6679fe96d56b96a29ead067096c47e4df4d4cbe061ee7cfe360fc5e7a7ab0b99','--source','/seed']
  with patch.object(sys,'argv',[captured[3],*captured[4:]]),contextlib.redirect_stderr(io.StringIO()) as errors,self.assertRaises(SystemExit) as refused:T.main()
  self.assertEqual(refused.exception.code,2)
  for flag in ('--apps-source','--apps-provenance-sha256','--repository-source'):self.assertIn(flag,errors.getvalue())
  raw={Path('/inputs/apps-source/source-provenance.json'):b'bounded actual temporary provenance',Path('/inputs/full574-policy.json'):b'bounded policy',Path('/inputs/full574-lease.json'):b'bounded lease'}
  read=lambda path:raw[Path(path)];api=SimpleNamespace(read=read,sha=C.sha)
  common=C.function(self.root/'scripts/ci/apps-full574-native/lifecycle.py','common',dict(C=api,INPUTS=Path('/inputs')))
  for mode,owner,seconds in (('prepare-copy',None,610),('dispose-copy','a'*64,75)):
   with self.subTest(mode=mode):
    recorded=[]
    def command(s,argv,cap):recorded.append((argv,cap));return {},b'{}',b''
    # Parser-only boundary; the new independent control exercises actual pinned policy authentication.
    with patch.object(D,'caller_seconds',return_value=610),patch.object(D.C,'read',side_effect=read),patch.object(D.C,'row',side_effect=lambda path:dict(sha256=C.sha(read(path)))),patch.object(D,'command',side_effect=command):D.backend({},mode,Path('/work/main'),owner)
    argv,cap=recorded[0];self.assertEqual(cap,seconds)
    expected=common(Path('/work/main'),owner)+(['--source','/seed'] if mode=='prepare-copy' else [])
    self.assertEqual(argv[:5],captured[:4]+[mode]);self.assertEqual(argv[5:],expected)
    seen=[]
    def prepared(args):seen.append(args);return dict(status='OWNED_COPY_PREPARED')
    def guarded(args):seen.append(args);return self.root,self.root/'root',dict(workspace=[1,2])
    with patch.object(sys,'argv',[argv[3],*argv[4:]]),patch.object(T,'prepare_copy',side_effect=prepared),patch.object(T,'root_guard',side_effect=guarded),patch.object(T,'locked',return_value=contextlib.nullcontext()),patch.object(T,'dispose') as dispose,contextlib.redirect_stdout(io.StringIO()):self.assertEqual(T.main(),0)
    a=seen[0];self.assertEqual((a.action,a.workspace,a.apps_source,a.apps_provenance_sha256,a.repository_source),(mode,'/work/main','/inputs/apps-source',C.sha(raw[Path('/inputs/apps-source/source-provenance.json')]),'/inputs/candidate/usr/share/cachy-asahi/repository-runtime'))
    self.assertEqual((a.full574_policy_sha256,a.full574_lease_sha256),(C.sha(raw[Path('/inputs/full574-policy.json')]),C.sha(raw[Path('/inputs/full574-lease.json')])))
    self.assertEqual((a.source,a.ownership_sha256),('/seed',None) if mode=='prepare-copy' else (None,owner))
    if mode=='dispose-copy':dispose.assert_called_once_with(self.root,[1,2])
 def test_real_cross_filesystem_old_refusal_and_work_stage_roundtrip(self):
  import errno,shutil
  with tempfile.TemporaryDirectory(dir='/tmp') as a,tempfile.TemporaryDirectory(dir='/dev/shm') as b:
   work=Path(a);media=Path(b);self.assertNotEqual(work.stat().st_dev,media.stat().st_dev)
   root=work/'main/root';root.mkdir(parents=True);leaf=root/'ordinary';leaf.write_bytes(b'bounded real fixture');os.link(leaf,root/'hard');(root/'link').symlink_to('ordinary')
   identity=lambda p:(p.lstat().st_dev,p.lstat().st_ino,p.lstat().st_uid,p.lstat().st_gid,p.lstat().st_mode)
   before={p.name:identity(p) for p in root.iterdir()};root_id=identity(root)
   with self.assertRaises(OSError) as old:root.rename(media/'old-boot')
   self.assertEqual(old.exception.errno,errno.EXDEV);self.assertTrue(root.is_dir());self.assertFalse((media/'old-boot').exists())
   stage=work/'repair16k-stage';stage.mkdir(mode=0o700);stage_id=identity(stage);root.rename(stage/'boot')
   self.assertEqual(identity(stage/'boot'),root_id);self.assertEqual({p.name:identity(p) for p in (stage/'boot').iterdir()},before)
   (stage/'boot').rename(root);self.assertEqual(identity(root),root_id);self.assertEqual(identity(stage),stage_id);shutil.rmtree(stage);self.assertFalse(stage.exists());self.assertEqual(leaf.read_bytes(),b'bounded real fixture')
 def test_stage_scope_real_descriptors_refuse_foreign_mount_alias_drift_and_nested_mount(self):
  import io
  from types import SimpleNamespace
  D=C.load('stage_guard_control',HERE/'disk.py');real_fstat=os.fstat;real_open=Path.open
  with tempfile.TemporaryDirectory(dir='/tmp') as td,tempfile.TemporaryDirectory(dir='/dev/shm') as shm:
   work=Path(td);work.chmod(0o700);stage=work/'repair16k-stage';stage.mkdir(mode=0o700);root=work/'main/root';root.mkdir(parents=True)
   def mapped(value):
    path=Path(value);text=str(path)
    if text=='/work':return work
    if text.startswith('/source/'):return self.root/text.removeprefix('/source/')
    return path
   s=dict(deadline_monotonic=__import__('time').monotonic()+30,source_files={'scripts/update/full_root.py':C.row(self.root/'scripts/update/full_root.py')})
   def owned(fd):
    info=real_fstat(fd);return SimpleNamespace(st_dev=info.st_dev,st_ino=info.st_ino,st_mode=info.st_mode,st_uid=0,st_gid=0)
   with patch.object(D,'Path',side_effect=mapped):
    if os.geteuid()!=0:
     with self.assertRaisesRegex(ValueError,'root-owned'):D.stage_guard(s,stage,roots=(root,))
    with patch.object(D.os,'fstat',side_effect=owned):
     proof=D.stage_guard(s,stage,roots=(root,));self.assertEqual(proof['inode'],[stage.stat().st_dev,stage.stat().st_ino]);self.assertGreater(proof['mount_id'],0)
     with self.assertRaisesRegex(ValueError,'identity drift'):D.stage_guard(s,stage,dict(proof,inode=[0,0]))
     foreign=Path(shm)
     with self.assertRaises(ValueError):D.stage_guard(s,stage,roots=(foreign,))
     raw=Path('/proc/self/mountinfo').read_bytes()+b'999999 1 0:1 / '+os.fsencode(str(stage/'nested'))+b' rw - tmpfs tmpfs rw\n'
     def opened(path,*args,**kwargs):return io.BytesIO(raw) if path==Path('/proc/self/mountinfo') else real_open(path,*args,**kwargs)
     with patch.object(Path,'open',opened),self.assertRaisesRegex(ValueError,'nested'):D.stage_guard(s,stage,proof)
   stage.rmdir();stage.symlink_to(root,target_is_directory=True)
   with patch.object(D,'Path',side_effect=mapped),self.assertRaisesRegex(ValueError,'fixed private'):D.stage_guard(s,stage)
 def test_exact_prepare_small_command_map_restores_disposes_and_retires_work_stage(self):
  import shutil,time
  from types import SimpleNamespace
  D=C.load('stage_prepare_control',HERE/'disk.py');real_open=Path.open;real_row=C.row;real_mount=Path.is_mount
  for fail in (False,True):
   with self.subTest(mkfs_failure=fail),tempfile.TemporaryDirectory() as td:
    base=Path(td);dirs={n:base/n for n in ('work','media','inputs','source','execution','workspace')}
    for p in dirs.values():p.mkdir(mode=0o700)
    for n in ('main','interrupted'):
     root=dirs['work']/n/'root';root.mkdir(parents=True);(root/'ordinary').write_bytes(n.encode())
    (dirs['source']/'tiny.py').write_bytes(b'# inert source fixture\n')
    for n in ('inputs','execution','workspace'):(dirs[n]/'inert').write_bytes(n.encode())
    def mapped(value):
     path=Path(value);text=str(path)
     for name,root in dirs.items():
      if text=='/'+name or text.startswith('/'+name+'/'):return root/text[len(name)+1:].lstrip('/')
     return path
    identities={n:[(dirs['work']/n/'root').stat().st_dev,(dirs['work']/n/'root').stat().st_ino] for n in ('main','interrupted')};disposed=[];commands=[];logical={}
    def backend(s,mode,work,owner=None):
     name=work.name
     if mode=='prepare-copy':return dict(status='OWNED_COPY_PREPARED',source_preserved=True,ownership_sha256=('a' if name=='main' else 'b')*64)
     root=work/'root';self.assertEqual([root.stat().st_dev,root.stat().st_ino],identities[name]);disposed.append(name);shutil.rmtree(work);return dict(status='OWNED_COPY_DISPOSED')
    def guard(s,stage,proof=None,roots=()):
     self.assertEqual(stage,dirs['work']/'repair16k-stage');self.assertTrue(stage.is_dir());self.assertTrue(all(p.is_relative_to(dirs['work']) for p in roots));value=dict(path=str(stage),inode=[stage.stat().st_dev,stage.stat().st_ino],work_inode=[dirs['work'].stat().st_dev,dirs['work'].stat().st_ino],mount_id=1)
     if proof is not None:self.assertEqual(proof,value)
     return value
    def command(s,argv,cap=600):
     commands.append(argv)
     if argv[0]=='/usr/bin/cp':self.assertEqual(argv[1:4],['-a','--reflink=never','--']);shutil.copytree(argv[-2],argv[-1])
     else:
      self.assertEqual(argv[:8],['/usr/bin/mkfs.ext4','-F','-b','4096','-m','0','-L',argv[7]]);self.assertEqual(argv[8],'-d');self.assertTrue(Path(argv[9]).is_relative_to(dirs['work']/'repair16k-stage'))
      if fail:raise ValueError('inert mkfs failure')
     return {},b'',b''
    class SparseModel:
     def __init__(self,path):self.path=path;self.stream=real_open(path,'xb')
     def __enter__(self):return self
     def __exit__(self,*args):self.stream.close()
     def truncate(self,size):self.asserted_size=size;logical[self.path]=size;self.stream.truncate(0)
    def opened(path,*args,**kwargs):return SparseModel(path) if path.parent==dirs['media'] and args==('xb',) else real_open(path,*args,**kwargs)
    def row(path):
     path=Path(path);return dict(bytes=logical[path],sha256='e'*64) if path in logical else real_row(path)
    audit=SimpleNamespace(audit=lambda *args:dict(status='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT'))
    s=dict(media_identity=[dirs['media'].stat().st_dev,dirs['media'].stat().st_ino],nonce='c'*32,case='repair-bytes',deadline_monotonic=time.monotonic()+30,uid=os.getuid(),gid=os.getgid(),source_files={'tiny.py':real_row(dirs['source']/'tiny.py')})
    with patch.object(D,'Path',side_effect=mapped),patch.object(D,'backend',side_effect=backend),patch.object(D,'stage_guard',side_effect=guard),patch.object(D,'command',side_effect=command),patch.object(D.C,'load',return_value=audit),patch.object(D.C,'row',side_effect=row),patch.object(D.shutil,'disk_usage',return_value=SimpleNamespace(free=100*1024**3)),patch.object(Path,'is_mount',lambda p: p==dirs['media'] or real_mount(p)),patch.object(Path,'open',opened):
     if fail:
      with self.assertRaisesRegex(ValueError,'inert mkfs'):D.prepare(s)
     else:D.prepare(s)
    self.assertEqual(disposed,['interrupted','main']);self.assertFalse((dirs['work']/'repair16k-stage').exists());self.assertFalse(any(dirs['work'].iterdir()));self.assertEqual(set(logical),{dirs['media']/'boot.raw'} if fail else {dirs['media']/'boot.raw',dirs['media']/'data.raw'})
    if not fail:
     value=C.decode(C.read(dirs['media']/'prepared.json'));self.assertTrue(value['staging']['retired']);self.assertEqual([value[k]['bytes'] for k in ('boot','data')],[16*1024**3,24*1024**3]);owner=C.decode(C.read(dirs['media']/'stage-owner.json'));self.assertEqual(owner['nonce'],s['nonce']);self.assertTrue(owner['retired'])
  scrub=C.read(self.root/'scripts/ci/apps-full574-native/scrub.py').decode();self.assertIn("for name in ('work','authority')",scrub);self.assertIn('T.LIFETIME._empty(fd,mount,budget,[0],depth=-1)',scrub);self.assertIn('not list(root.iterdir())',scrub)
 def test_guard_derivative_preserves_all_other_backend_functions(self):
  raw=C.read(self.root/'scripts/apps/transaction.py');changed=adapter.backend(raw);before=adapter.functions(raw);after=adapter.functions(changed)
  self.assertEqual([n for n in before if before[n]!=after[n]],['environment_guard']);self.assertIn(adapter.ENV_AFTER.encode(),changed)
  with self.assertRaises(ValueError):adapter.backend(changed)
 def test_lifecycle_genuine_case_loop_and_helpers_byte_AST_preserved(self):
  raw=self.native('lifecycle.py');out=adapter.lifecycle(raw);before=adapter.functions(raw);after=adapter.functions(out)
  self.assertEqual([n for n in before if before[n]!=after[n]],['inspected','main']);self.assertEqual(set(after)-set(before),{'_vm_backend','_vm_backend_note','_vm_backend_call'})
  # Transaction loops stay exact; only readonly /seed baseline/after budgets route.
  self.assertEqual([dump(n) for n in ast.walk(function(raw,'main')) if isinstance(n,ast.For)],[dump(n) for n in ast.walk(function(out,'main')) if isinstance(n,ast.For)])
  for n in ('owned','observed','argv','leaf','damage','restore','repaired'):self.assertEqual(before[n],after[n])
  self.assertIn(b"sys.path.insert(0,'/source/scripts/ci/apps-full574-repair-native');import contract as C",out);self.assertIn(b"SOURCE/'scripts/ci/apps-full574-repair-native/checks.py'",out);self.assertIn(b'/execution/scripts/apps/repair_inspection.py',out);self.assertNotIn(b"Path('/.dockerenv')",out)
 def test_real_execution_tree_closed_preserved_and_drift_refused(self):
  manifest=C.decode(self.native('source-manifest.json'))
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'execution';r=adapter.execution(self.root,out,manifest);self.assertEqual(r['changed'],['scripts/apps/transaction.py']);self.assertTrue(r['original_source_preserved']);self.assertEqual(len(r['execution_files']),113)
   for n,pin in r['execution_files'].items():self.assertEqual(C.row(out/n),pin)
   bad=copy.deepcopy(manifest);bad['files']['scripts/apps/transaction.py']['sha256']='0'*64
   with self.assertRaises(ValueError):adapter.execution(self.root,Path(d)/'drift',bad)
   self.assertFalse((Path(d)/'drift').exists())
 def test_source_alias_and_input_tree_alias_refusal(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'a').write_bytes(b'actual');(root/'alias').symlink_to('a')
   with self.assertRaises(ValueError):C.row(root/'alias')
   with self.assertRaises(ValueError):C.tree(root)
   (root/'alias').unlink();os.link(root/'a',root/'hard')
   with self.assertRaises(ValueError):C.tree(root)
  for n in ('../x','a/../x','/x','a//x','a\\x','a/.'):
   with self.assertRaises(ValueError):C.relative(n)
 def test_native_module_identity_and_original_actor_security(self):
  native=C.load('control_native',self.root/C.NATIVE/'contract.py');original=sys.modules['contract'];J=job.native_job(self.root,native)
  self.assertIs(J.C,native);self.assertIs(J.H.C,native);self.assertIs(sys.modules['contract'],original);self.assertIs(vm.C,C)
  parts=J.derived(C.read(J.H.__file__).decode());changed=job.actor_body(parts['actor'])
  call=function(changed,'actor');calls=[n for n in ast.walk(call) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='_repair16k_dispatch'];self.assertEqual(len(calls),1)
  reverse=changed.replace(' result=_repair16k_dispatch(command,role,root,output,report,api,argv,False,',' result=command(argv,False,');self.assertEqual(reverse,parts['actor'])
  for flag in ('--network=none','--read-only','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--ulimit=nofile=8192:8192'):self.assertIn(flag,changed)
 def test_actual_isolation_source_uses_only_original_five_caps(self):
  guest=C.read(HERE/'guest.py');self.assertEqual(C.CAPS,(0,1,3,4,31));self.assertEqual(C.MASK,2147483675)
  borrowed=C.read(self.root/'scripts/ci/current604-apps6-updater16k/guest.py');old=ast.get_source_segment(borrowed.decode(),function(borrowed,'isolate'))
  self.assertIn("'EXACT_ORIGINAL_CALLER_NINE_CAPABILITIES_NO_SYS_ADMIN'",old);self.assertIn(b"'EXACT_ORIGINAL_REPAIR_FIVE_CAPABILITIES_NO_SYS_ADMIN'",guest)
  self.assertIn(b"os.statvfs('/seed').f_flag&os.ST_RDONLY",guest);self.assertIn(b"changed_fields=['source_identity']",guest)
 def test_qemu_no_network_and_shared_deadline_no_reset(self):
  argv=vm.qemu(Path('/Image'),Path('/boot.raw'),Path('/data.raw'),1792191793115000000)
  self.assertEqual(argv[argv.index('-nic')+1],'none');self.assertEqual(argv[argv.index('-m')+1],'4096');self.assertEqual(argv[argv.index('-smp')+1],'2');self.assertEqual(argv.count('-drive'),2);self.assertIn('caa_apps574_repair16k=1',argv[argv.index('-append')+1])
  with patch.object(vm.time,'monotonic',return_value=150):self.assertEqual(vm.remaining(200,3000),50)
  with patch.object(vm.time,'monotonic',return_value=201):
   with self.assertRaises(ValueError):vm.remaining(200,3000)
  raw=C.read(HERE/'vm.py').decode();self.assertEqual(raw.count('deadline=time.monotonic()+3000'),1);self.assertIn('remaining(deadline,3000);return result',raw)
 def test_real_native_context_calls_actual_borrowed_kernel_with_bridge_contract(self):
  # Fixture only tests the import/interface seam; no authority or kernel proof.
  import types,shutil
  native=C.load('native_contract',self.root/C.NATIVE/'contract.py');seen=[];load=C.load
  with tempfile.TemporaryDirectory() as d:
   work=Path(d);helper=self.root/'scripts/ci/managed-gui-generic16k/build_kernel.py';fragment=self.root/'scripts/ci/managed-gui-generic16k/kernel.fragment'
   paths={n:work/n for n in ('helper','fragment','image','config')}
   shutil.copyfile(helper,paths['helper']);shutil.copyfile(fragment,paths['fragment']);paths['image'].write_bytes(b'INERT_NOT_A_KERNEL');paths['config'].write_bytes(b'INERT_NOT_A_CONFIG')
   receipt={n:dict(path=str(path),**C.row(path)) for n,path in paths.items()};receipt_path=work/'receipt.json';receipt_path.write_bytes(C.encoded(receipt))
   profile=dict(Image=C.row(paths['image']),scope='INERT_IMPORT_INTERFACE_ONLY_NOT_KERNEL_EVIDENCE');args=types.SimpleNamespace(source=self.root,case='repair-bytes',native_decisions=work,kernel_authority=work/'unused',kernel_work=work,kernel_receipt=receipt_path)
   def loading(name,path):
    module=load(name,path)
    if name=='kernel_contract':
     def from_receipt(value,H,raw,helper_sha,fragment_sha):
      self.assertEqual(value,receipt);self.assertEqual(Path(H.__file__),helper);self.assertEqual(raw,C.read(fragment));self.assertEqual(helper_sha,C.row(helper)['sha256']);self.assertEqual(fragment_sha,C.row(fragment)['sha256']);seen.append(name);return profile,paths['image'],paths['config']
     module.from_receipt=from_receipt
    return module
   with patch.object(C,'decisions',return_value=(native,{'scope':'INERT_NO_AUTHORITY'},{})),patch.object(C,'prior_kernel',return_value=(profile,{'scope':'INERT_NO_AUTHORITY'})),patch.object(C,'load',side_effect=loading),job.contract_context(native):
    result=C.authorize(args);self.assertIs(sys.modules['contract'],native)
   self.assertIs(result[0],native);self.assertEqual(result[2],(profile,paths['image'],paths['config']));self.assertEqual(seen,['kernel_contract']);self.assertIs(C.SELF,C)
 def test_bridge_helpers_loaded_inside_native_context_bind_bridge_only(self):
  native=C.load('native_contract',self.root/C.NATIVE/'contract.py');original=sys.modules['contract']
  with job.contract_context(native):
   for name in ('vm','disk','guest','job','prepare'):
    module=C.load('context_'+name,HERE/(name+'.py'));self.assertIs(module.C,C,name);self.assertIs(sys.modules['contract'],native)
   J=job.native_job(self.root,native);self.assertIs(J.C,native);self.assertIs(J.H.C,native);self.assertIs(sys.modules['contract'],native)
  self.assertIs(sys.modules['contract'],original);self.assertIs(vm.C,C)
 def test_own_helper_exception_restores_native_contract_alias(self):
  native=C.load('native_contract',self.root/C.NATIVE/'contract.py')
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);bad=root/'bad.py';bad.write_text("import contract as C\nraise ValueError('OWNED_INERT_IMPORT_FAILURE')\n")
   with job.contract_context(native),patch.object(C,'HERE',root):
    with self.assertRaisesRegex(ValueError,'OWNED_INERT_IMPORT_FAILURE'):C.load('bad_context',bad)
    self.assertIs(sys.modules['contract'],native)
   self.assertIs(sys.modules['contract'],C)

 def model(self):
  old=dict(source='/seed',token='control',source_identity=[1,2]);after=dict(old,source_identity=[3,4]);fresh=dict(status='FRESH_ACTUAL_GUEST_SOURCE_LEASE',before=old,before_sha256=C.sha(C.encoded(old)),after=after,after_sha256=C.sha(C.encoded(after)),source_identity=[3,4],changed_fields=['source_identity'])
  s=dict(nonce='model-only-not-runtime',case='repair-bytes',kernel=dict(release='model'),clock_seed_ns=123,host_lease=old,host_lease_sha256=C.sha(C.encoded(old)),source_tree_sha256='a'*64,source_capabilities_sha256='b'*64)
  boot=dict(event='boot',page_size=16384,architecture='aarch64',kernel='model',kernel_profile_sha256=C.sha(C.encoded(s['kernel'])),clock=dict(nofile=dict(after=[8192,8192]),seed_realtime_ns=123),lease=fresh)
  worker=dict(case=s['case'],status='PRIVATE_COMPLETE_CASE',isolation=dict(after=dict(mask=C.MASK,nnp=1,inh=0,amb=0),uid=0,gid=0,groups=[],seccomp=2),child=dict(exit_code=0,group_absence_verified=True),source_tree_sha256='a'*64,source_capabilities_sha256='b'*64,ELF=dict(status='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT',count=1))
  result=dict(event='result',status=C.PASS,case=s['case'],worker=worker,page_size=16384,lease_sha256=fresh['after_sha256']);end=dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_MOUNTS_RETIRED');return s,[boot,result,end]
 def protocol(self,s,frames):return b'\n'.join(('APPS574_REPAIR16K '+s['nonce']+' '+json.dumps(v)).encode() for v in frames)
 def test_protocol_inert_positive_and_original_runtime_refusals(self):
  s,frames=self.model();vm.protocol(self.protocol(s,frames),s,None)
  for path,value in [(('0','page_size'),4096),(('1','worker','child','exit_code'),1),(('1','worker','isolation','after','mask'),0),(('2','cleanup'),'UNKNOWN'),(('0','clock','seed_realtime_ns'),456),(('1','case'),'repair-missing')]:
   bad=copy.deepcopy(frames);v=bad[int(path[0])]
   for n in path[1:-1]:v=v[n]
   v[path[-1]]=value
   with self.assertRaises(ValueError):vm.protocol(self.protocol(s,bad),s,None)
  with self.assertRaises(ValueError):vm.protocol(self.protocol(s,frames).replace(b'APPS574_REPAIR16K',b'APPS6_UPDATE16K'),s,None)
 def test_prior_kernel_narrow_scope_and_pins_data_only(self):
  # Fake revision identity ONLY; no Git/native/boot authorization is claimed.
  K=C.load('control_kernel',self.root/'scripts/ci/managed-gui-generic16k/kernel_contract.py')
  profile=dict(schema_version=1,profile=K.PROFILE,release=K.RELEASE,architecture='aarch64',page_size=16384,source_revision=K.REVISION,archive_sha256=K.ARCHIVE,helper_sha256=K.HELPER_SHA,fragment_sha256=K.FRAGMENT_SHA,diagnostic_fragment_sha256=K.DIAGNOSTIC_SHA,Image=dict(bytes=64,sha256='1'*64),config=dict(bytes=1,sha256='2'*64),modules='DISABLED')
  authority=dict(status='ROOT_ACCEPTED_GENERIC16K_KERNEL_PROFILE',scope='MANAGED_GUI_KERNEL_BUILD_AND_BOOT_COMPONENT_ONLY',GNU_installed_lifecycle='NOT_ACCEPTED',hardware='NOT_RUN',release='NOT_ADMITTED',source_sha='3'*40,run_id='123',profile=profile,retained_receipt=dict(bytes=1,sha256='4'*64),root_decision=dict(bytes=1,sha256='5'*64))
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'authority.json'
   def invoke(value):
    C.save(path,value);binding=dict(kernel_authority=dict(path='authority.json',**C.row(path)),kernel_authority_source='6'*40)
    with patch.object(C,'gate',return_value=(None,binding)),patch.object(C.subprocess,'check_output',return_value='6'*40+'\n'):return C.prior_kernel(self.root,'repair-bytes',path)
   self.assertEqual(invoke(authority)[0],profile)
   for k,v in (('scope','WHOLE_GNU_LIFECYCLE'),('GNU_installed_lifecycle','ACCEPTED'),('status','ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME')):
    with self.assertRaises(ValueError):invoke(dict(authority,**{k:v}))
 def test_cleanup_absence_fail_closed_and_source_bounds(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d);job.cleanup_gate(out);(out/'repair16k-media').mkdir()
   with self.assertRaises(ValueError):job.cleanup_gate(out)
   (out/'repair16k-media').rmdir();C.save(out/'repair16k-state.json',dict(status='RETAINED_VM_OR_MEDIA_ABSENCE_UNKNOWN'))
   with self.assertRaises(ValueError):job.cleanup_gate(out)
   C.save(out/'repair16k-state.json',dict(status='PASS_VM_GROUP_AND_PRIVATE_MEDIA_RETIRED'));job.cleanup_gate(out)
  disk=C.read(HERE/'disk.py');self.assertIn(b'48*1024**3',disk);self.assertIn(b"('boot',16*1024**3),('data',24*1024**3)",disk);self.assertIn(b"backend(s,'dispose-copy'",disk)

class FailureDiagnostic(unittest.TestCase):
 def setUp(self):
  import io
  self.io=io;self.guest=C.load('failure_control_guest',HERE/'guest.py');self.selection=dict(nonce='a'*32,case='repair-bytes');self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors permitted'));self.block.start();self.addCleanup(self.block.stop)
 def row(self,out,err,**change):
  v=dict(argv=['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],exit_code=1,seconds=1,time_limit=3000,output_limit=2*1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err));return dict(v,**change)
 def capture(self,out,err,row,error):
  from contextlib import redirect_stdout
  stream=self.io.StringIO()
  with redirect_stdout(stream):emitted=self.guest.worker_failure(self.selection,row,out,err,error)
  return emitted,stream.getvalue()
 def test_failure_original_buffers_prefixes_hashes_and_finite_frame(self):
  import base64
  out=b'original-output'*2000;err=b'original-error'*2000;before=(out,err);row=self.row(out,err);saved=copy.deepcopy(row);emitted,wire=self.capture(out,err,row,ValueError('bounded supervisor failure'))
  self.assertTrue(emitted);self.assertEqual((out,err),before);self.assertEqual(row,saved);self.assertLess(len(wire.encode()),65536)
  prefix='APPS574_REPAIR16K_FAILURE '+self.selection['nonce']+' ';self.assertTrue(wire.startswith(prefix));value=C.decode(wire[len(prefix):]);self.assertEqual(value['supervisor'],row);self.assertFalse(value['acceptance_authority']);self.assertFalse(value['cleanup_authority'])
  for n,raw in (('stdout',out),('stderr',err)):
   v=value['streams'][n];self.assertEqual(base64.b64decode(v['prefix_base64'],validate=True),raw[:16384]);self.assertEqual(v['prefix_sha256'],C.sha(raw[:16384]));self.assertEqual(v['sha256'],C.sha(raw));self.assertEqual(v['bytes'],len(raw));self.assertTrue(v['truncated'])
  self.assertEqual(value['error'],dict(type='ValueError',utf8_bytes=26,sha256=C.sha(b'bounded supervisor failure')))
 def test_failure_unknown_group_absence_never_grants_cleanup_or_success(self):
  emitted,wire=self.capture(b'',b'',self.row(b'',b'',group_absence_verified=False),None);self.assertTrue(emitted);v=C.decode(wire.split(' ',2)[2]);self.assertEqual(v['retirement'],'UNKNOWN_GROUP_ABSENCE_NO_CLEANUP_AUTHORITY');self.assertFalse(v['cleanup_authority']);self.assertEqual(v['guest_disk_readback'],'NOT_ESTABLISHED')
  s,frames=Lane.model(self);success=Lane.protocol(self,s,frames)
  with self.assertRaises(ValueError):vm.protocol(wire.encode(),dict(s,nonce=self.selection['nonce']),None)
 def test_success_emits_no_extra_frame_and_original_guard_stays(self):
  emitted,wire=self.capture(b'x',b'',self.row(b'x',b'',exit_code=0),None);self.assertFalse(emitted);self.assertEqual(wire,'')
  raw=C.read(HERE/'guest.py').decode();main=function(raw,'main');calls=[n for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='worker_failure'];self.assertEqual(len(calls),1)
  expected=" worker_failure(s,record,out,err,error)\n C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'whole actual case worker retirement')";self.assertIn(expected,raw);self.assertIn("env,3000,2*1024**2)",raw.replace("dict(PATH='/usr/bin:/bin',HOME='/tmp',TMPDIR='/tmp')","env"))
 def test_failure_bad_record_or_output_bound_refuses_without_frame(self):
  for out,err,change in ((b'a',b'',dict(stdout_sha256='0'*64)),(b'a',b'',dict(argv=['/arbitrary'])),(b'a',b'',dict(output_limit=4*1024**2)),(b'a'*(2*1024**2+1),b'',{})):
   with self.assertRaises(ValueError):self.capture(out,err,self.row(out,err,**change),None)


class SourceStateBudget(unittest.TestCase):
 def _exercise_factory(self,final=False):
  from types import SimpleNamespace
  import hashlib,time,zipfile
  source=Path(os.environ['FULL574_REPAIR16K_SOURCE']);T=C.load('actual_budget_factory',source/'scripts/apps/transaction.py')
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);common=dict(schema_version=1,purpose='APPS_ORIGINAL574_READONLY_CLOSURE',execution_budget=dict(backend_seconds=600,caller_seconds=610),**{n:'a'*64 for n in ('snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256','source_capabilities_sha256')})
   policy=dict(common,baseline_lock_sha256='b'*64,candidates={},source_capabilities={});lease=dict(common,token='c'*32,source='/seed',source_identity=[1,2]);paths={}
   for name,value in [('full574-policy.json',policy),('full574-lease.json',lease)]:
    p=base/name;p.write_bytes(C.encoded(value));paths['/inputs/'+name]=p
   def reading(path,cap=2*1024**2):
    if str(path)=='/out/guest-lease.json':return C.encoded(dict(after_sha256=C.sha(paths['/inputs/full574-lease.json'].read_bytes())))
    return paths[str(path)].read_bytes()
   rows=[];nodes={'actual':dict(type='file')};caps={};A=SimpleNamespace(digest=lambda v:C.sha(C.encoded(v)))
   def measured(path,budget):
    self.assertEqual(path,Path('/seed'));rows.append(budget);budget.tick();return {'nodes':nodes}
   def capabilities(path,before,budget,*expected):
    if expected:self.assertEqual(expected,(caps,))
    rows.append(budget);self.assertIs(before['nodes'],nodes);budget.tick();return caps
   A.measure=measured;A.capability_map=capabilities;native=SimpleNamespace(source=lambda _:None,adapter=lambda _:A)
   scope=dict(C=SimpleNamespace(NATIVE=C.NATIVE,load=lambda name,path:T if name=='native_metrics' else native,decode=C.decode,read=reading,need=C.need),Path=Path)
   raw=(HERE/'guest.py').read_text();helper=function(raw,'source_budget');node=function(raw,'source_state');exec(compile(ast.Module(body=[helper,node],type_ignores=[]),'<actual-source-state>','exec'),scope)
   invoke=scope['source_state']
   if final:
    worker=function(raw,'worker');start=next(i for i,n in enumerate(worker.body) if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='limits' for x in n.targets))
    tail=worker.body[start:start+4];self.assertEqual([type(n).__name__ for n in tail],['Assign','Assign','Expr','Expr'])
    header=ast.parse('def final_readback(s,A,T,before,caps):\n return (None,A,T,after,caps)').body[0];header.body=tail+header.body;ast.fix_missing_locations(header);exec(compile(ast.Module(body=[header],type_ignores=[]),'<original-final-readback-fragment>','exec'),scope)
    invoke=lambda s:scope['final_readback'](s,A,T,{'nodes':nodes},caps)
   selection=dict(input_map={'full574-policy.json':C.row(paths['/inputs/full574-policy.json'])},source_tree_sha256=A.digest(nodes),source_capabilities_sha256=A.digest(caps))
   factory=T.limits;arguments=[]
   def capture(args=None):arguments.append(args);return factory(args)
   def reader(path,*args,**kwargs):return reading(path)
   with patch.object(T.B.client,'read_path',side_effect=reader),patch.object(T,'limits',side_effect=capture),patch.object(T.time,'monotonic',return_value=1000):
    result=invoke(selection)
    self.assertEqual(len(arguments),1);args=arguments[0];self.assertEqual(args.full574_policy,Path('/inputs/full574-policy.json'));self.assertEqual(args.full574_policy_sha256,selection['input_map']['full574-policy.json']['sha256']);self.assertEqual(args.full574_lease,Path('/inputs/full574-lease.json'));self.assertEqual(args.full574_lease_sha256,C.row(paths['/inputs/full574-lease.json'])['sha256'])
    self.assertEqual(T.execution_seconds(args),600);self.assertEqual(T.execution_seconds(),300);self.assertIs(rows[0],rows[1]);self.assertEqual(rows[0].deadline,1600)
    with patch.object(T.time,'monotonic',return_value=1600):
     with self.assertRaisesRegex(ValueError,'root observation deadline'):rows[0].tick()
   self.assertIs(result[3]['nodes'],nodes)
   # Real signed-policy shape path remains strict: changed bytes, mixed budget, or missing binding fail before measurement.
   for variant in ('changed','mixed','missing'):
    bad=copy.deepcopy(policy)
    if variant=='mixed':bad['execution_budget']['backend_seconds']=300
    paths['/inputs/full574-policy.json'].write_bytes(C.encoded(bad)+ (b' ' if variant=='changed' else b''));sel=copy.deepcopy(selection)
    if variant=='mixed':sel['input_map']['full574-policy.json']=C.row(paths['/inputs/full574-policy.json'])
    if variant=='missing':sel['input_map'].clear()
    rows.clear()
    with patch.object(T.B.client,'read_path',side_effect=reader):
     with self.assertRaises((ValueError,KeyError)):invoke(sel)
    self.assertEqual(rows,[])
 def test_genuine_initial_factory_uses_exact_policy_freshlease_shared600(self):self._exercise_factory()
 def test_genuine_final_readback_factory_uses_exact_policy_freshlease_shared600(self):self._exercise_factory(final=True)
 def test_only_source_state_and_final_readback_change_all_other_guards_held(self):
  import hashlib
  # Frozen46ea function text pins are independent of the emitter input version.
  held={'emit': '650d75247ddbdf3928580177f5c9c06eba6474905ac254b847e8b92795939585', 'worker_failure': 'fbfdca318e1c51b496798c8ebb33657f0dfea1f757ccc015e97076665ef96636', 'borrowed_isolation': '6b38825b912670d361da3d552b3fffc2b9a2fd93a99abbe9e1eccf96b82bde8f', 'startup': 'e112e6fb79d144dfc88292551fa30ac06b217399f75a5262d57d18fc975e6e95', 'lease': '355f10825acd172d933b8b44958e202b028610f3651185cc4a072094c89f6a57', 'source_state': '78411b4340d8db0b93957fbe7d660adb72c537780b36e2531103d91c8745053d', 'worker': '8e4ee93f6e88e66be5f8fb045c5d546d1e7bf91925d0b76d1ae234926af589c7', 'main': '69e1b579e7d6b698eaa6499a359bbafe07243581296c4843b563f548c50fa0ab'}
  after=(HERE/'guest.py').read_text();nodes={n.name:n for n in ast.parse(after).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(set(nodes),set(held)|{'source_budget','lifecycle_failure'})
  changed=[name for name,digest in held.items() if hashlib.sha256(ast.get_source_segment(after,nodes[name]).encode()).hexdigest()!=digest]
  self.assertEqual(changed,['source_state','worker']);self.assertIn('env,3000,2*1024**2)',after);self.assertEqual(after.count('limits=source_budget(s,T)'),2)

class InnerLifecycleBudget(unittest.TestCase):
 def test_genuine_factory_refuses_old300_deadline_and_retains_authenticated600(self):
  from types import SimpleNamespace
  source=Path(os.environ['FULL574_REPAIR16K_SOURCE']);T=C.load('inner_budget_real_transaction',source/'scripts/apps/transaction.py')
  derived=adapter.lifecycle(C.read(source/C.NATIVE/'lifecycle.py'))
  nodes=[n for n in ast.parse(derived).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id.startswith('_vm_source_') for t in n.targets)]
  self.assertEqual(len(nodes),3)
  with tempfile.TemporaryDirectory() as td:
   inputs=Path(td);common=dict(schema_version=1,purpose='APPS_ORIGINAL574_READONLY_CLOSURE',execution_budget=dict(backend_seconds=600,caller_seconds=610),**{n:'a'*64 for n in ('snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256','source_capabilities_sha256')})
   policy=dict(common,baseline_lock_sha256='b'*64,candidates={},source_capabilities={});lease=dict(common,token='c'*32,source='/seed',source_identity=[1,2])
   C.save(inputs/'full574-policy.json',policy);C.save(inputs/'full574-lease.json',lease)
   def factory():
    import types
    space=dict(INPUTS=inputs,C=C,types=types);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<derived-real-source-budget>','exec'),space);return T.limits(space['_vm_source_scope'])
   # Real T.limits, policy_pair, pinned reads and full-root deadline tick, no synthetic success.
   with patch.object(T.time,'monotonic',return_value=100):old=T.limits();new=factory()
   self.assertEqual(old.deadline,400);self.assertEqual(new.deadline,700)
   with patch.object(T.time,'monotonic',return_value=401):
    with self.assertRaisesRegex(ValueError,'root observation deadline'):old.tick()
    new.tick()
   with patch.object(T.time,'monotonic',return_value=701):
    with self.assertRaisesRegex(ValueError,'root observation deadline'):new.tick()
   for variant in ('mixed','missing','fields'):
    changed=copy.deepcopy(policy)
    if variant=='mixed':changed['execution_budget']['backend_seconds']=300
    if variant=='missing':changed.pop('execution_budget')
    if variant=='fields':changed['unexpected']='refuse'
    C.save(inputs/'full574-policy.json',changed)
    with self.assertRaises(ValueError):factory()
 def test_exact_four_source_operands_only_and_genuine_case_loops_held(self):
  source=Path(os.environ['FULL574_REPAIR16K_SOURCE']);raw=C.read(source/C.NATIVE/'lifecycle.py');derived=adapter.lifecycle(raw)
  self.assertEqual(derived.count(b'T.limits(_vm_source_scope)'),4)
  self.assertEqual(adapter.functions(raw)['observed'],adapter.functions(derived)['observed'])
  self.assertIn(b"adapter.measure(workspace/'root',T.limits())",derived)
  for before,after in zip([n for n in ast.walk(function(raw,'main')) if isinstance(n,ast.For)],[n for n in ast.walk(function(derived,'main')) if isinstance(n,ast.For)]):self.assertEqual(dump(before),dump(after))
  for altered in (raw.replace(b"adapter.measure(Path('/seed'),T.limits())",b"adapter.measure(Path('/seed'),T.limits(None))",1),raw.replace(b"adapter.capability_map(Path('/seed'),baseline,T.limits())",b'changed_scan')):
   with self.assertRaises(ValueError):adapter.lifecycle(altered)

class InnerLifecycleDiagnostic(unittest.TestCase):
 def setUp(self):
  import io
  self.io=io;self.guest=C.load('inner_failure_guest',HERE/'guest.py');self.selection=dict(nonce='d'*32,case='repair-bytes')
 def row(self,out,err,**change):
  return dict(dict(argv=['/usr/bin/python3','-I','-B','/workspace/execution-lifecycle.py'],exit_code=1,seconds=300.1,time_limit=3000,output_limit=2*1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err)),**change)
 def capture(self,row,out,err,error=None):
  from contextlib import redirect_stdout
  stream=self.io.StringIO()
  with redirect_stdout(stream):result=self.guest.lifecycle_failure(self.selection,row,out,err,error)
  return result,stream.getvalue()
 def test_exact_original_inner_failure_nested_frame_no_stdout_map_export(self):
  import base64
  out=b'PRIVATE_COMPLETE_MAP_NEVER_PREVIEW'*100;err=b'Traceback original failure\n'*150+b'ValueError: root observation deadline\n';row=self.row(out,err);saved=copy.deepcopy(row)
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')):emitted,wire=self.capture(row,out,err)
  self.assertTrue(emitted);self.assertEqual(saved,row);self.assertNotIn('PRIVATE_COMPLETE_MAP',wire);self.assertLess(len(wire.encode()),12288)
  v=C.decode(wire.split(' ',2)[2]);self.assertEqual(v['supervisor'],row);self.assertEqual(base64.b64decode(v['stderr_tail']['base64'],validate=True),err[-2048:]);self.assertEqual(v['stderr_tail']['sha256'],C.sha(err[-2048:]));self.assertTrue(v['stderr_tail']['truncated']);self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority'])
  # A real original outer diagnostic can carry the entire inner frame within its16KiB prefix.
  outer_out=wire.encode();outer=self.row(outer_out,b'',argv=['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'])
  from contextlib import redirect_stdout
  capture=self.io.StringIO()
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')),redirect_stdout(capture):self.guest.worker_failure(self.selection,outer,outer_out,b'',None)
  original=C.decode(capture.getvalue().split(' ',2)[2]);self.assertEqual(base64.b64decode(original['streams']['stdout']['prefix_base64']),outer_out);self.assertFalse(original['streams']['stdout']['truncated'])
 def test_success_unknown_absence_and_changed_input_never_change_original_guard(self):
  self.assertEqual(self.capture(self.row(b'',b'',exit_code=0),b'',b''),(False,''))
  _,wire=self.capture(self.row(b'',b'',group_absence_verified=False),b'',b'',ValueError('command-time-limit'));v=C.decode(wire.split(' ',2)[2]);self.assertEqual(v['retirement'],'UNKNOWN_GROUP_ABSENCE_NO_CLEANUP_AUTHORITY');self.assertEqual(v['error']['sha256'],C.sha(b'command-time-limit'))
  for change in (dict(stdout_sha256='0'*64),dict(argv=['/arbitrary']),dict(time_limit=600),dict(output_limit=4*1024**2)):
   with self.assertRaises(ValueError):self.capture(self.row(b'a',b'',**change),b'a',b'')
  raw=(HERE/'guest.py').read_text();self.assertIn(" lifecycle_failure(s,record,out,err,error)\n C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'original case direct child/group retirement')",raw)
  self.assertIn("env,3000,2*1024**2)",raw)

class BackendFailureNoteControls(unittest.TestCase):
 def functions(self):
  import ast
  names={'_vm_backend_note','_vm_backend_call'};tree=ast.parse(adapter.BACKEND_NOTE)
  env=dict(C=C,types=__import__('types'));exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names],type_ignores=[]),'<source-pinned-backend-note>','exec'),env);return env
 def test_genuine_bounded_failed_child_note_survives_existing_inner_tail(self):
  import traceback,base64,contextlib,io,json,sys
  env=self.functions();runner=C.load('real_backend_note_runner',Path(os.environ['FULL574_REPAIR16K_SOURCE'])/'scripts/ci/glibc-owned-runtime/runner.py')
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);script=root/'failure.py';script.write_text("import json,sys\nprint(json.dumps(dict(status='FAIL',error_type='ValueError',error='UNIT cooperative full-root deadline diagnostic',packages_committed=False,commit_started=False,recovery='DISPOSE_OWNED_COPY_IF_COMMIT_OR_CLEANUP_UNCERTAIN',rollback='NOT_CLAIMED')))\nsys.stderr.write('UNIT bounded child stderr\\n')\nsys.exit(1)\n")
   row,out,err,error=runner.run_command([sys.executable,'-I','-B',str(script),'prepare-copy'],root,dict(PATH='/usr/bin:/bin',HOME=str(root),LANG='C.UTF-8'),5,1024**2)
  self.assertIsNone(error);self.assertEqual(row['exit_code'],1);self.assertIs(row['group_absence_verified'],True)
  note=env['_vm_backend_note'](row,out,err,error);self.assertLessEqual(len(note.encode()),1900)
  value=json.loads(note.split(' ',1)[1]);self.assertEqual(value['supervisor'],row);self.assertEqual(value['result']['error'],'UNIT cooperative full-root deadline diagnostic');self.assertIs(value['acceptance_authority'],False);self.assertNotIn('stdout_preview',value)
  exc=ValueError('bounded actual command failed: /usr/bin/python3');exc.add_note(note);stderr=('UNIT earlier traceback padding\n'*200+''.join(traceback.format_exception(exc))).encode()
  guest=C.load('note_framing_guest',HERE/'guest.py');selection=dict(nonce='a'*32,case='repair-bytes');stdout=b''
  inner=dict(argv=['/usr/bin/python3','-I','-B','/workspace/execution-lifecycle.py'],exit_code=1,seconds=1,time_limit=3000,output_limit=2*1024**2,group_absence_verified=True,stdout_bytes=0,stdout_sha256=C.sha(stdout),stderr_bytes=len(stderr),stderr_sha256=C.sha(stderr))
  stream=io.StringIO()
  with contextlib.redirect_stdout(stream):guest.lifecycle_failure(selection,inner,stdout,stderr,None)
  frame=json.loads(stream.getvalue().split(' ',2)[2]);tail=base64.b64decode(frame['stderr_tail']['base64'],validate=True)
  self.assertEqual(tail,stderr[-2048:]);self.assertIn(note.encode()+b'\n',tail);self.assertIn(b'ValueError: bounded actual command failed:',stderr)
 def test_exact_failure_guard_preserved_and_invalid_stdout_never_previewed(self):
  env=self.functions();result=dict(argv=['/usr/bin/python3','-I','-B','/execution/scripts/apps/transaction.py','prepare-copy'],exit_code=1,seconds=1,time_limit=610,output_limit=1024**2,group_absence_verified=False,stdout_bytes=15,stdout_sha256=C.sha(b'PRIVATE_MAP!!!'),stderr_bytes=0,stderr_sha256=C.sha(b''))
  # The formatter rejects changed receipts, never substituting a passing row.
  with self.assertRaises(ValueError):env['_vm_backend_note'](result,b'PRIVATE_MAP!!!',b'',None)
  result['stdout_bytes']=len(b'PRIVATE_MAP!!!');note=env['_vm_backend_note'](result,b'PRIVATE_MAP!!!',b'',None);self.assertNotIn('PRIVATE_MAP',note);self.assertIn('"result":null',note)
  api=__import__('types').SimpleNamespace(run_command=lambda *a,**kw:(result,b'PRIVATE_MAP!!!',b'',None));instance=__import__('types').SimpleNamespace(api=api)
  def original(self,argv,*,seconds=610,expected=0):
   self.api.run_command();raise ValueError('bounded actual command failed: /usr/bin/python3')
  env['_vm_original_call']=original
  with self.assertRaisesRegex(ValueError,'^bounded actual command failed: /usr/bin/python3$')as failure:env['_vm_backend_call'](instance,result['argv'])
  self.assertIs(instance.api,api);self.assertEqual(len(failure.exception.__notes__),1);self.assertIn('"group_absence_verified":false',failure.exception.__notes__[0])


import base64,traceback,types
_PHASE_ORIGINAL_NOTE="def _vm_backend_note(record,out,err,error):\n import base64,json\n keys={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}\n C.need(set(record)==keys and record['output_limit']==1024**2,'original backend receipt required')\n for side,data in (('stdout',out),('stderr',err)):\n  C.need(record[side+'_bytes']==len(data) and record[side+'_sha256']==C.sha(data),'original backend stream join')\n result=None\n try:\n  v=C.decode(out)\n  if set(v)=={'status','error_type','error','packages_committed','commit_started','recovery','rollback'} and v['status']=='FAIL' and v['packages_committed'] is False and v['commit_started'] is False and v['recovery']=='DISPOSE_OWNED_COPY_IF_COMMIT_OR_CLEANUP_UNCERTAIN' and v['rollback']=='NOT_CLAIMED' and type(v['error_type'])is str and len(v['error_type'])<=128 and type(v['error'])is str and len(v['error'])<=1024:\n   raw=v['error'].encode('utf8');result=dict(status='FAIL',error_type=v['error_type'],error=v['error'][:96],error_utf8_bytes=len(raw),error_sha256=C.sha(raw),truncated=len(v['error'])>96,commit_started=False,packages_committed=False)\n except (ValueError,KeyError,TypeError,UnicodeError):pass\n tail=err[-64:]\n value=dict(schema_version=1,event='prepare_copy_backend_failure',supervisor=record,result=result,stderr_tail=dict(bytes=len(tail),sha256=C.sha(tail),base64=base64.b64encode(tail).decode(),truncated=len(err)>64),supervisor_error=None if error is None else type(error).__name__,acceptance_authority=False,cleanup_authority=False)\n note='APPS574_BACKEND_FAILURE '+json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)\n C.need(len(note.encode())<=1900,'complete backend note must fit original2KiB tail');return note\n_vm_original_call=H.Calls.call\ndef _vm_backend_call(self,argv,*,seconds=610,expected=0):\n original=self.api;captured=[]\n def capture(*a,**kw):\n  row=original.run_command(*a,**kw);captured.append(row);return row\n self.api=types.SimpleNamespace(run_command=capture)\n try:return _vm_original_call(self,argv,seconds=seconds,expected=expected)\n except Exception as error:\n  if list(map(str,argv[:5]))==['/usr/bin/python3','-I','-B','/execution/scripts/apps/transaction.py','prepare-copy'] and len(captured)==1:\n   try:error.add_note(_vm_backend_note(*captured[0]))\n   except Exception:pass # Diagnostic loss cannot replace the original exception.\n  raise\n finally:self.api=original\nH.Calls.call=_vm_backend_call\n"
class BackendPhaseProjectionControls(unittest.TestCase):
 def setUp(self):
  self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));self.block.start();self.addCleanup(self.block.stop)
  raw=adapter.BACKEND_NOTE;tree=ast.parse(raw);self.env=dict(C=types.SimpleNamespace(need=C.need,sha=C.sha,decode=C.decode),types=types)
  exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'<proposed-data-formatter>','exec'),self.env)
  self.phase={};exec(compile((Path(os.environ['FULL574_REPAIR16K_SOURCE'])/'scripts/apps/full574_statx.py').read_bytes(),'<trusted-original-phase-producer>','exec'),self.phase)
  self.saved=[];self.write=patch.object(self.phase['os'],'write',side_effect=lambda fd,b:(self.saved.append(b),len(b))[1]);self.write.start();self.addCleanup(self.write.stop)
 def row(self,err,out=b''):
  value={'argv': ['/usr/bin/python3', '-I', '-B', '/execution/scripts/apps/transaction.py', 'prepare-copy', '--workspace', '/work/main', '--apps-source', '/inputs/apps-source', '--apps-provenance-sha256', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '--repository-source', '/inputs/candidate/usr/share/cachy-asahi/repository-runtime', '--full574-policy', '/inputs/full574-policy.json', '--full574-policy-sha256', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '--full574-lease', '/inputs/full574-lease.json', '--full574-lease-sha256', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', '--source', '/seed'], 'exit_code': -15, 'seconds': 610.047357, 'time_limit': 610, 'output_limit': 1048576, 'group_absence_verified': True};return dict(value,stdout_bytes=len(out),stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err))
 def note(self,err,out=b''):
  note=self.env['_vm_backend_note'](self.row(err,out),out,err,ValueError('command-time-limit'));self.assertLessEqual(len(note.encode()),1900);return note,json.loads(note.split(' ',1)[1])
 def nested(self):
  traced=self.phase['traced']
  @traced('tree-observe')
  def tree():return 7
  @traced('tree-and-aux-observation')
  def measure():return tree()
  @traced('capability-scan')
  def scan():return 9
  @traced('complete-capability-map')
  def caps():return scan()
  @traced('source-revalidation')
  def source():return measure()+caps()
  self.assertEqual(source(),16);return b''.join(self.saved)
 def test_real_existing_producer_exact_phase_timing_counts_and_tail(self):
  err=self.nested();note,v=self.note(err);p=v['phase_summary'];rows=[json.loads(line.split(b' ',1)[1])for line in err.splitlines()]
  self.assertEqual(p['records'],10);self.assertEqual(p['first_ns'],rows[0]['monotonic_ns']);self.assertEqual(p['last'][-1],[10,0,1,rows[-1]['monotonic_ns']-p['first_ns']]);self.assertEqual([r[:4]for r in p['stages']],[[s,1,1,0]for s in range(5)]);self.assertTrue(all(r[4]>=0 for r in p['stages']))
  self.assertEqual(base64.b64decode(v['stderr_tail']['base64']),err[-64:]);self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority']);self.assertEqual(v['schema_version'],2)
  failure=ValueError('original failure');failure.add_note(note);tail=''.join(traceback.format_exception(failure)).encode()[-2048:];self.assertIn(note.encode()+b'\n',tail)
 def test_open_phase_stays_open_no_stall_or_success_claim(self):
  self.phase['emit']('source-revalidation','BEGIN');_,v=self.note(b''.join(self.saved));self.assertEqual(v['phase_summary']['stages'],[[0,1,0,0,0]]);self.assertEqual(v['phase_summary']['last'][0][2],0);self.assertIsNone(v['result'])
 def test_failed_phase_retains_original_exception_and_closed_span(self):
  @self.phase['traced']('tree-observe')
  def fail():raise ValueError('root observation deadline')
  with self.assertRaisesRegex(ValueError,'^root observation deadline$'):fail()
  _,v=self.note(b''.join(self.saved));self.assertEqual(v['phase_summary']['stages'][0][:4],[2,1,0,1]);self.assertEqual(v['phase_summary']['last'][-1][2],2)
 def test_invalid_phase_never_exports_foreign_payload_or_guesses_counts(self):
  err=self.nested();rows=err.splitlines(keepends=True)
  bad=[b'APPS574_PHASE PRIVATE_PAYLOAD\n',rows[0].replace(b'"seq":1',b'"seq":2'),rows[0].replace(b'"BEGIN"',b'"UNKNOWN"'),rows[1],rows[0]+rows[0],err[:-2]]
  for item in bad:
   with self.subTest(item=item[:20]):
    _,v=self.note(item);self.assertEqual(v['phase_summary'],dict(version=1,status='INVALID_PHASE_RECORDS'));self.assertNotIn('PRIVATE_PAYLOAD',json.dumps(v['phase_summary']))
 def test_original_max96_and_512_bounds_fit_note_and_tail(self):
  for _ in range(60):
   self.phase['emit']('source-revalidation','BEGIN');self.phase['emit']('source-revalidation','END')
  self.assertEqual(len(self.saved),96);self.assertTrue(all(len(r)<=512 for r in self.saved));note,v=self.note(b''.join(self.saved));self.assertEqual(v['phase_summary']['records'],96);self.assertEqual(v['phase_summary']['last'][-1][1:3],[7,3]);self.assertLessEqual(len(note.encode()),1900)
 def test_exact_supervisor_guard_exception_and_api_restoration(self):
  err=self.nested();row=self.row(err);api=types.SimpleNamespace(run_command=lambda *a,**k:(row,b'',err,ValueError('command-time-limit')));instance=types.SimpleNamespace(api=api)
  def original(self,argv,*,seconds=610,expected=0):self.api.run_command();raise ValueError('original bounded actual command failed')
  self.env['_vm_original_call']=original
  with self.assertRaisesRegex(ValueError,'^original bounded actual command failed$')as exc:self.env['_vm_backend_call'](instance,row['argv'])
  self.assertIs(instance.api,api);self.assertEqual(len(exc.exception.__notes__),1);self.assertEqual(json.loads(exc.exception.__notes__[0].split(' ',1)[1])['supervisor'],row)
  with self.assertRaises(ValueError):self.env['_vm_backend_note'](dict(row,stderr_sha256='0'*64),b'',err,None)
 def test_no_phases_and_full_note_keep_original_diagnostic_byte_exact(self):
  oldtree=ast.parse(_PHASE_ORIGINAL_NOTE);env=dict(C=self.env['C'],types=types);exec(compile(ast.Module(body=[n for n in oldtree.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'<trusted-original-formatter>','exec'),env)
  err=b'original stderr, no phases';row=self.row(err);self.assertEqual(self.env['_vm_backend_note'](row,b'',err,None),env['_vm_backend_note'](row,b'',err,None))
  err=self.nested();out=json.dumps(dict(status='FAIL',error_type='ValueError'+'X'*118,error='X'*1024,packages_committed=False,commit_started=False,recovery='DISPOSE_OWNED_COPY_IF_COMMIT_OR_CLEANUP_UNCERTAIN',rollback='NOT_CLAIMED')).encode();row=self.row(err,out)
  old=env['_vm_backend_note'](row,out,err,None);new=self.env['_vm_backend_note'](row,out,err,None);self.assertLessEqual(len(old.encode()),1900);self.assertEqual(new,old)


class NativeMediaPhaseControls(unittest.TestCase):
 def disk(self):return C.load('_media_phase_controls',HERE/'disk.py')
 def phase(self,seq,stage,event,now):return b'APPS574_PHASE '+C.encoded(dict(schema_version=1,seq=seq,stage=stage,event=event,monotonic_ns=now)).replace(b'\n',b'').replace(b'  ',b'')+b'\n'
 def test_exact_existing_guest_projection_and_no_runtime_budget_change(self):
  disk=self.disk();node=next(n for n in ast.walk(ast.parse(adapter.BACKEND_NOTE))if isinstance(n,ast.FunctionDef)and n.name=='phase_summary')
  self.assertEqual(dump(node),dump(function(C.read(HERE/'disk.py'),'phase_summary')))
  text=(HERE/'disk.py').read_text()
  for original in ("remaining(s,cap),1024**2)","command(s,args,seconds)","for name in ('main','interrupted')", "raw[:1024]", "len(rows)<192", "len(C.encoded(rows))<=2*1024**2"):
   self.assertIn(original,text)
  self.assertIsNone(disk.phase_summary(b'no phase records'))
  self.assertEqual(disk.phase_summary(b'APPS574_PHASE {}\n'),dict(version=1,status='INVALID_PHASE_RECORDS'))
 def test_genuine_failed_child_full_phase_projection_survives_original_prefix(self):
  import time,base64
  disk=self.disk();root=Path(os.environ['FULL574_REPAIR16K_SOURCE']);runtime=C.load('_real_media_failure_runtime',root/'scripts/ci/glibc-owned-runtime/runner.py')
  with tempfile.TemporaryDirectory()as td:
   work=Path(td);out=work/'commands.json';child=work/'failed.py';lines=[];seq=0
   for i in range(20):
    for event in ('BEGIN','END'):
     seq+=1;lines.append(self.phase(seq,'tree-observe',event,seq*1000).decode())
   seq+=1;lines.append(self.phase(seq,'copy-data','BEGIN',seq*1000).decode());seq+=1;lines.append(self.phase(seq,'copy-data','FAIL',seq*1000).decode())
   err=''.join(lines);self.assertGreater(len(err.encode()),1024);child.write_text('import sys\nsys.stderr.write('+repr(err)+')\nsys.exit(7)\n')
   realpath=Path
   def path(value):return work if str(value)=='/work'else out if str(value)=='/out/repair16k-media-commands.json'else realpath(value)
   state=dict(deadline_monotonic=time.monotonic()+10,env=dict(OWNER_TOKEN='INERT_NEGATIVE_CHILD_NO_NATIVE_AUTHORITY'),uid=os.getuid(),gid=os.getgid())
   with patch.object(disk.C,'load',return_value=runtime),patch.object(disk,'Path',side_effect=path),self.assertRaisesRegex(ValueError,'bounded owned media command/group retirement'):
    disk.command(state,[sys.executable,'-I','-B',str(child)],2)
   rows=C.decode(C.read(out));self.assertEqual(len(rows),1);row=rows[0];self.assertEqual(row['record']['exit_code'],7);self.assertIsNone(row['error']);self.assertTrue(row['record']['group_absence_verified']);self.assertEqual(row['record']['time_limit'],2);self.assertEqual(row['record']['stderr_sha256'],C.sha(err.encode()))
   self.assertEqual(base64.b64decode(row['previews']['stderr']['base64']),err.encode()[:1024]);self.assertTrue(row['previews']['stderr']['truncated']);self.assertEqual(row['phase_summary']['records'],42);self.assertEqual(row['phase_summary']['last'][-1],[42,6,2,41000]);self.assertEqual(row['phase_summary']['stages'],[[2,20,20,0,20000],[6,1,0,1,1000]])
   self.assertLess(len(C.encoded(row['phase_summary'])),1024);self.assertNotIn('native',row['phase_summary']);self.assertNotIn('status',row['phase_summary']);self.assertNotIn('nodes',row['phase_summary'])
 def test_nested_closed_spans_stay_distinct_and_open_call_has_no_credit(self):
  raw=b''.join(self.phase(*v)for v in ((1,'source-revalidation','BEGIN',10),(2,'tree-observe','BEGIN',20),(3,'tree-observe','END',70),(4,'source-revalidation','END',100),(5,'copy-data','BEGIN',110)))
  summary=self.disk().phase_summary(raw);self.assertEqual(summary['stages'],[[0,1,1,0,90],[2,1,1,0,50],[6,1,0,0,0]]);self.assertEqual(summary['last'][-1],[5,6,0,100]);self.assertNotIn('elapsed',summary);self.assertNotIn('complete',summary)


class NativeMediaCallerBudget(unittest.TestCase):
 def test_trusted_policy_routes610_not_outer600_and_refuses_unbound_or_mutated(self):
  from types import SimpleNamespace
  import time
  source=Path(os.environ['FULL574_REPAIR16K_SOURCE']);helper=source/'scripts/apps/full574_closure.py';policy_api=C.load('_actual_native_media_policy',helper);disk=C.load('_media_caller_budget',HERE/'disk.py')
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);common=dict(schema_version=1,purpose=policy_api.PURPOSE,execution_budget=dict(backend_seconds=600,caller_seconds=610),**{n:'a'*64 for n in ('snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256','source_capabilities_sha256')})
   policy=dict(common,baseline_lock_sha256='b'*64,candidates={},source_capabilities={});lease=dict(common,token='c'*32,source='/seed',source_identity=[1,2]);paths={}
   for name,value in(('full574-policy.json',policy),('full574-lease.json',lease)):
    p=base/name;p.write_bytes(C.encoded(value));paths['/inputs/'+name]=p
   provenance=base/'source-provenance.json';provenance.write_bytes(b'inert negative/source-route fixture only');paths['/inputs/apps-source/source-provenance.json']=provenance
   state=dict(source_files={'scripts/apps/full574_closure.py':C.row(helper)},input_map={n:C.row(paths['/inputs/'+n])for n in ('full574-policy.json','full574-lease.json')})
   realread,realrow=C.read,C.row;calls=[]
   def read(path,cap=4*1024**2):return realread(paths[str(path)],cap)
   def row(path):return realrow(helper if str(path)=='/source/scripts/apps/full574_closure.py'else paths[str(path)])
   def command(s,argv,cap):calls.append((argv,cap));return None,b'{}',b''
   with patch.object(C,'row',side_effect=row),patch.object(C,'read',side_effect=read),patch.object(C,'load',return_value=policy_api),patch.object(disk,'command',side_effect=command):
    for work in('/work/main','/work/interrupted'):
     disk.backend(state,'prepare-copy',Path(work));self.assertEqual(calls[-1][1],610);self.assertEqual(calls[-1][0][5:7],['--workspace',work]);self.assertEqual(calls[-1][0][-2:],['--source','/seed'])
    self.assertEqual(policy_api.EXECUTION_BUDGET,dict(backend_seconds=600,caller_seconds=610));
    with patch.object(disk.time,'monotonic',return_value=100):self.assertEqual(disk.remaining(dict(deadline_monotonic=105),610),5)
    for variant in('missing','changed','mixed','duplicate','helper'):
     value=copy.deepcopy(state);raw=C.encoded(policy)
     if variant=='missing':value['input_map'].clear()
     if variant=='changed':raw+=b' '
     if variant=='mixed':
      bad=copy.deepcopy(policy);bad['execution_budget']['caller_seconds']=611;raw=C.encoded(bad)
     if variant=='duplicate':raw=raw.replace(b'{',b'{"purpose":"duplicate",',1)
     paths['/inputs/full574-policy.json'].write_bytes(raw)
     if variant in('mixed','duplicate'):value['input_map']['full574-policy.json']=realrow(paths['/inputs/full574-policy.json'])
     if variant=='helper':value['source_files']['scripts/apps/full574_closure.py']={'bytes':1,'sha256':'0'*64}
     before=len(calls)
     with self.assertRaises((ValueError,KeyError)):disk.backend(value,'prepare-copy',Path('/work/main'))
     self.assertEqual(len(calls),before)
if __name__=='__main__':unittest.main()
