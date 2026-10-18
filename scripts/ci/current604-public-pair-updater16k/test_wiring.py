# SPDX-License-Identifier: MIT
"""Finite public-pair routing/source/WF guards; no actual authorities or actors."""
import ast,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import contract as C
import wiring as W,job,kernel_job,retain16k as T,prepare as P,vm,base64
class Wiring(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def test_full_source_guards_and_three_case_workflow(self):
  rows=W.check_source(C.ROOT);self.assertLessEqual(len(rows),512)
  for n,r in rows.items():self.assertEqual(C.row(C.ROOT/n),r)
  text=(C.ROOT/P.WF).read_text()
  for marker in ('options: [normal, precommit-exit86, postcommit-exit87]','timeout-minutes: 350','timeout-minutes: 270','15600s','3700s','job.py preflight','job.py decisions','job.py inputs','--apps6-authority-source','apps6-inputs/payload','test_*.py'):self.assertIn(marker,text)
  self.assertNotIn('--apps6-native-source',text);self.assertLess(text.index('job.py preflight'),text.index('secrets.'));self.assertLess(text.index('job.py decisions'),text.index('secrets.'))
  self.assertIn(C.row(C.HERE/'job.py')['sha256'],text);self.assertIn(C.row(C.HERE/'wiring-source-manifest.json')['sha256'],text)
 def test_new_authority_and_runtime_status_no_old_case_credit(self):
  self.assertEqual(C.OLD,'scripts/ci/expanded604-apps6-public-pair-updater');self.assertIn('PUBLIC_PAIRS',C.PASS)
  value=C.decode(C.read(C.HERE/'policy.json'));self.assertIn('UNBOUND',value['status']);self.assertIsNone(value['binding'])
  text=(C.HERE/'contract.py').read_text();self.assertEqual(text.count('ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_COPIED_ROOT_'),3);self.assertNotIn("'ROOT_ACCEPTED_APPS6_CURRENT604_COPIED_ROOT_",text)
  public=(C.ROOT/C.OLD/'selected_package.py').read_text();self.assertIn('NOT_PRESENT_NOT_FABRICATED',public);self.assertIn('BUILDINFO_installed',public)
 def test_original_runtime_numeric_caps_and_guards_preserved(self):
  old=C.ROOT/'scripts/ci/current604-apps6-updater16k'
  for name in ('guest.py','disk.py','vm.py','cap_scope.py','kernel_job.py','retain16k.py','job.py'):
   a,b=(old/name).read_bytes(),(C.HERE/name).read_bytes()
   if name in ('job.py','kernel_job.py'):
    before={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(a).body if isinstance(n,ast.FunctionDef)}
    after={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
    expected={'parent'} if name=='job.py' else {'cleanup','main'}
    self.assertEqual({n for n in before if before[n]!=after[n]},expected)
    self.assertEqual(set(after)-set(before),set() if name=='job.py' else {'home_failure','docker_config_tree'})
    if name=='job.py':self.assertIn(',15600,4*1024**2)',b.decode())
    else:self.assertEqual(C.sha(ast.get_source_segment(b.decode(),next(n for n in ast.parse(b).body if isinstance(n,ast.FunctionDef) and n.name=='main')).encode()),'028606ac467be8c5ac4c7bc58ce9a57bd9721efb04f6dfcff486dbbac3f3756a')
    continue
   if name=='cap_scope.py':
    tree=ast.parse(b);tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef) and n.name=='runtime_boundaries')];derive=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='derive');self.assertEqual(ast.unparse(derive.body[0]),'omitted = runtime_boundaries(omitted)');derive.body.pop(0);self.assertEqual(ast.dump(tree,include_attributes=False),ast.dump(ast.parse(a),include_attributes=False));b=ast.unparse(tree).encode()
   if name=='vm.py':
    tree=ast.parse(b);tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef) and n.name=='prepare_failure')];b=ast.unparse(tree).encode()
   nums=lambda raw:[n.value for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.Constant) and type(n.value) in (int,float)]
   self.assertEqual(nums(a),nums(b),name)
  self.assertIn('omitted=runtime_boundaries(omitted)',(C.HERE/'cap_scope.py').read_text())
 def test_failed_originals_remain_retained_not_accepted(self):
  with tempfile.TemporaryDirectory(dir='/tmp') as td,tempfile.TemporaryDirectory() as dest:
   root=Path(td);C.save(root/'owner.json',dict(purpose='expanded604-apps6-public-pair-updater',case='normal',output=str(root)))
   for name in T.NAMES:
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'inert failure' if name.endswith('.log') else C.encoded(dict(status='FAIL',scope='INERT_ONLY')))
   absent=Path(dest)/'absent';r=T.retain(root,Path(dest)/'public',dict(status='NOT_RUN'),'a'*40,'normal',absent,absent,absent)
   self.assertEqual(r['status'],'ORIGINALS_RETAINED_NOT_ACCEPTED');self.assertFalse(r['proof_complete']);self.assertLessEqual(sum(p.stat().st_size for p in (Path(dest)/'public').rglob('*') if p.is_file()),8*1024**2)
 def fixture(self,base):
  work=base/'managed-gui16k-kernel';work.mkdir(mode=0o700);(work/'helper/built').mkdir(parents=True)
  C.save(work/'helper/built/build-receipt.json',dict(status='BUILT_ONLY'));C.save(work/'wiring-owner.json',dict(source='a'*40,case='normal',identity=[work.stat().st_dev,work.stat().st_ino]))
  output=base/'absent-output';home=base/'absent-output-job-home';home.mkdir(mode=0o700)
  config=output.with_name(output.name+'-docker-config');config.mkdir(mode=0o700);info=config.stat()
  C.save(home/'child.json',dict(status='WAIT_RETURNED',source='a'*40,case='normal',docker_config=dict(path=str(config),identity=[info.st_dev,info.st_ino],source='a'*40,case='normal'),child=dict(group_absence_verified=True)))
  return work,output,home
 def test_shallow_runtime_contract_import_has_no_invented_source(self):
  space=dict(__file__='/workspace/contract.py');exec(compile((C.HERE/'contract.py').read_bytes(),'/workspace/contract.py','exec'),space)
  self.assertEqual(space['HERE'],Path('/workspace'));self.assertIsNone(space['ROOT']);self.assertEqual(C.ROOT,C.HERE.parents[2])
  with self.assertRaisesRegex(ValueError,'UNBOUND'):space['need'](False,'UNBOUND')
 def test_real_owned_cleanup_exact_child_completes(self):
  with tempfile.TemporaryDirectory()as tmp:
   work,output,home=self.fixture(Path(tmp));self.assertEqual(kernel_job.cleanup(work,output,'a'*40,'normal')['status'],'PASS_OWNED_KERNEL_WORK_REMOVED');self.assertFalse(work.exists());self.assertFalse(home.exists())
 def test_unknown_home_refuses_before_kernel_deletion_and_projects_no_names(self):
  with tempfile.TemporaryDirectory()as tmp:
   work,output,home=self.fixture(Path(tmp));unknown=home/'PRIVATE-ARBITRARY-NAME';unknown.write_bytes(b'untouched original bytes');before=C.row(unknown)
   with self.assertRaisesRegex(ValueError,'exact owned job HOME closure'):kernel_job.cleanup(work,output,'a'*40,'normal')
   self.assertTrue(work.exists());self.assertEqual(C.row(unknown),before);self.assertTrue((home/'child.json').exists())
   row=kernel_job.home_failure(home);self.assertEqual(row['counts'],dict(child_record=1,unexpected=1));self.assertEqual(row['group_absence'],'VERIFIED');self.assertNotIn('PRIVATE',C.encoded(row).decode());self.assertNotIn('untouched',C.encoded(row).decode())
   receipt=Path(tmp)/'kernel-cleanup.json';C.save(receipt,dict(status='FAIL',job_home_diagnostic=row));absent=Path(tmp)/'absent'
   retained=T.retain(Path(tmp),Path(tmp)/'retained',{},'a'*40,'normal',receipt,absent,absent)
   self.assertEqual(retained['kernel_cleanup']['value']['job_home_diagnostic'],row);self.assertFalse(retained['proof_complete']);self.assertIn('NOT_ADMISSIBLE',retained['completion'])
 def test_uncertain_original_child_and_alias_stay_retained(self):
  with tempfile.TemporaryDirectory()as tmp:
   work,output,home=self.fixture(Path(tmp));child=C.decode(C.read(home/'child.json'));child['child']['group_absence_verified']=False;C.save(home/'child.json',child)
   with self.assertRaisesRegex(ValueError,'GROUP_UNKNOWN'):kernel_job.cleanup(work,output,'a'*40,'normal')
   self.assertTrue(work.exists());self.assertEqual(kernel_job.home_failure(home)['group_absence'],'UNKNOWN')
   child['child']['group_absence_verified']=True;C.save(home/'child.json',child);(home/'unknown-alias').symlink_to(work)
   with self.assertRaisesRegex(ValueError,'exact owned job HOME closure'):kernel_job.cleanup(work,output,'a'*40,'normal')
   self.assertTrue(work.exists());self.assertTrue((home/'unknown-alias').is_symlink());self.assertEqual(kernel_job.home_failure(home)['types']['symlink'],1)


 def test_prepare_failure_original_short_stream_and_refusals(self):
  raw=b'original private fixture error\n';record=dict(argv=['python3','-I','/workspace/disk.py','prepare'],exit_code=1,stderr_bytes=len(raw),stderr_sha256=C.sha(raw))
  row=vm.prepare_failure(record,raw);self.assertEqual(base64.b64decode(row['stderr']['tail_base64']),raw);self.assertEqual(row['stderr']['omitted_bytes'],0);self.assertIn('NOT_ACCEPTANCE',row['status'])
  for wrong in (dict(record,exit_code=0),dict(record,stderr_sha256='0'*64),dict(record,argv=['python3','/workspace/disk.py','export'])):
   with self.assertRaises(ValueError):vm.prepare_failure(wrong,raw)
 def test_prepare_failure_tail_cap_full_pin_and_existing_transport(self):
  raw=b'fixture prefix '*1000+b'original failure end\n';record=dict(argv=['python3','/workspace/disk.py','prepare'],exit_code=1,stderr_bytes=len(raw),stderr_sha256=C.sha(raw));row=vm.prepare_failure(record,raw)
  self.assertEqual(base64.b64decode(row['stderr']['tail_base64']),raw[-4096:]);self.assertEqual(row['stderr']['tail_bytes'],4096);self.assertEqual(row['stderr']['omitted_bytes'],len(raw)-4096);self.assertEqual(row['stderr']['sha256'],C.sha(raw));self.assertLess(len(C.encoded(row)),8192)
  with tempfile.TemporaryDirectory(dir='/tmp') as td,tempfile.TemporaryDirectory() as dest:
   root=Path(td);(root/'public').mkdir();C.save(root/'owner.json',dict(purpose='expanded604-apps6-public-pair-updater',case='normal',output=str(root)));C.save(root/'public/updater16k-cleanup.json',dict(status='PASS',prepare_failure=row))
   absent=Path(dest)/'absent';value=T.retain(root,Path(dest)/'retained',{},'a'*40,'normal',absent,absent,absent)
   self.assertEqual(value['vm_cleanup']['value']['prepare_failure'],row);self.assertFalse(value['proof_complete']);self.assertIn('NOT_ADMISSIBLE',value['completion'])
 def test_real_vm_failed_prepare_saves_original_tail_before_guard(self):
  types=__import__('types')
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   root=Path(td);public=root/'public';public.mkdir();raw=root/'raw';raw.mkdir();(raw/'test-signing').mkdir();image=root/'Image';image.write_bytes(b'inert kernel control, no guest')
   original=b'inert source-only prepare failure\n';live=set()
   def command(argv,work,env,seconds,cap):
    out=err=b'';code=0
    if argv[1]=='inspect':
     if argv[2]in live:out=C.encoded([dict(Id='owned-control',Image='sha256:'+'a'*64,Config=dict(Labels={'org.cachy-asahi.apps6-updater16k':argv[2].split('-')[-2]}))])
     else:code=1;err=('No such '+argv[2]).encode()
    elif argv[1]=='run':live.add(argv[argv.index('--name')+1]);code=1;err=original
    elif argv[1]=='rm':live.clear()
    else:raise AssertionError('no other actor/control command')
    row=dict(argv=argv,exit_code=code,group_absence_verified=True,stderr_bytes=len(err),stderr_sha256=C.sha(err),stdout_bytes=len(out),stdout_sha256=C.sha(out))
    return row,out,err,None
   a=types.SimpleNamespace(implementation=C.ROOT,case='normal');old=types.SimpleNamespace(command=lambda *args:None)
   runtime=types.SimpleNamespace(run_command=command)
   with patch.object(vm,'authorize',return_value=({'Image':C.row(image)},image,None)),patch.object(vm,'mounts',return_value=({'/upgrade-signing':dict(source=str(raw/'test-signing'),readonly=True)},{})),patch.object(vm,'snapshot',return_value={}),patch.object(C,'check_source',return_value={}),patch.object(C,'load',return_value=runtime):
    with self.assertRaisesRegex(ValueError,'VM command/group failure'):vm.run(a,[],'sha256:'+'a'*64,public,raw,old,3900)
   value=C.decode(C.read(public/'updater16k-cleanup.json'));self.assertEqual(value['status'],'PASS');self.assertEqual(base64.b64decode(value['prepare_failure']['stderr']['tail_base64']),original);self.assertFalse((root/'update16k').exists());self.assertFalse(live);self.assertFalse(any('qemu' in r['argv'][0]for r in value['group_records']))

class DockerConfigControls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def fixture(self,base):return Wiring().fixture(base)
 def test_actual_parent_clean_environment_forwards_only_fresh_owned_config(self):
  import shutil
  from types import SimpleNamespace
  for failed in (False,True):
   with tempfile.TemporaryDirectory(dir='/tmp') as td:
    base=Path(td);output=base.with_name(base.name+'-output');home=output.with_name(output.name+'-job-home');config=output.with_name(output.name+'-docker-config');seen={}
    def run(argv,cwd,env,timeout,limit):
     seen.update(argv=argv,cwd=cwd,env=env,timeout=timeout,limit=limit)
     self.assertEqual(set(home.iterdir()),{home/'child.json'});self.assertEqual(list(config.iterdir()),[]);self.assertEqual(config.stat().st_mode&0o7777,0o700)
     output.mkdir(mode=0o700);C.save(output/'owner.json',dict(purpose='expanded604-apps6-public-pair-updater',case='normal',output=str(output)))
     return dict(exit_code=1 if failed else 0,group_absence_verified=True),b'',b'',RuntimeError('original child failure') if failed else None
    try:
     with patch.object(W,'authorize'),patch.object(W,'load',return_value=SimpleNamespace(run_command=run)),patch.dict(os.environ,DOCKER_CONFIG='/private-parent-config-not-inherited',DOCKER_HOST='tcp://private-parent-not-inherited'):
      if failed:
       with self.assertRaisesRegex(RuntimeError,'original child failure'):job.parent(C.ROOT,'a'*40,'normal',['--output',str(output)])
      else:self.assertEqual(job.parent(C.ROOT,'a'*40,'normal',['--output',str(output)]),0)
     self.assertEqual(seen['env'],dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=str(home),DOCKER_CONFIG=str(config),LANG='C.UTF-8',TZ='UTC',PYTHONDONTWRITEBYTECODE='1'))
     self.assertEqual((seen['timeout'],seen['limit']),(15600,4*1024**2));self.assertEqual(seen['argv'][:3],['/usr/bin/python3','-I','-B'])
     child=C.decode(C.read(home/'child.json'));self.assertEqual(child['status'],'WAIT_RETURNED');self.assertEqual(kernel_job.docker_config_tree(output,child,'a'*40,'normal'),config)
     self.assertTrue(config.exists());self.assertEqual({p.name for p in home.iterdir()},{'child.json'})
    finally:
     for path in (output,home,config):
      if path.exists():shutil.rmtree(path)
 def test_known_retired_failed_job_config_removed_with_kernel_and_exact_home(self):
  with tempfile.TemporaryDirectory() as td:
   work,output,home=self.fixture(Path(td));config=output.with_name(output.name+'-docker-config');(config/'contexts').mkdir();(config/'contexts/meta.json').write_bytes(b'PRIVATE_CLIENT_DATA_NOT_EXPORTED')
   self.assertEqual(kernel_job.cleanup(work,output,'a'*40,'normal')['status'],'PASS_OWNED_KERNEL_WORK_REMOVED')
   self.assertFalse(config.exists());self.assertFalse(home.exists());self.assertFalse(work.exists())
 def test_config_symlink_hardlink_and_fifo_refuse_before_any_deletion(self):
  for kind in ('symlink','hardlink','fifo'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as td:
    work,output,home=self.fixture(Path(td));config=output.with_name(output.name+'-docker-config');target=Path(td)/'external';target.write_bytes(b'UNTOUCHED')
    bad=config/'bad'
    if kind=='symlink':bad.symlink_to(target)
    elif kind=='hardlink':os.link(target,bad)
    else:os.mkfifo(bad)
    with self.assertRaisesRegex(ValueError,'ordinary Docker config'):kernel_job.cleanup(work,output,'a'*40,'normal')
    self.assertTrue(work.exists());self.assertTrue(config.exists());self.assertTrue((home/'child.json').exists());self.assertEqual(target.read_bytes(),b'UNTOUCHED')
 def test_config_identity_mode_case_record_and_size_refuse(self):
  for kind in ('identity','mode','case','missing-record','size','nodes'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as td:
    work,output,home=self.fixture(Path(td));config=output.with_name(output.name+'-docker-config');child=C.decode(C.read(home/'child.json'))
    if kind=='identity':child['docker_config']['identity'][1]+=1
    elif kind=='mode':config.chmod(0o755)
    elif kind=='case':child['docker_config']['case']='postcommit-exit87'
    elif kind=='missing-record':child.pop('docker_config')
    elif kind=='nodes':
     for i in range(2049):(config/str(i)).touch()
    else:
     with (config/'oversize').open('wb') as stream:stream.truncate(8*1024**2+1)
    C.save(home/'child.json',child)
    with self.assertRaisesRegex(ValueError,'Docker config'):kernel_job.cleanup(work,output,'a'*40,'normal')
    self.assertTrue(work.exists());self.assertTrue(config.exists());self.assertTrue((home/'child.json').exists())
 def test_unknown_group_and_producer_cleanup_keep_config(self):
  for kind in ('group','producer'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as td:
    work,output,home=self.fixture(Path(td));config=output.with_name(output.name+'-docker-config');child=C.decode(C.read(home/'child.json'))
    if kind=='group':child['child']['group_absence_verified']=False;C.save(home/'child.json',child)
    else:
     output.mkdir();(output/'public').mkdir();C.save(output/'owner.json',dict(output=str(output),purpose='expanded604-apps6-public-pair-updater'));C.save(output/'wiring-owner.json',dict(child=child['child']));C.save(output/'public/updater16k-cleanup.json',dict(status='PASS'));C.save(output/'result.json',dict(producer_cleanup='UNKNOWN',outer_cleanup='PASS',caller_private_cleanup='PASS'))
    with self.assertRaisesRegex(ValueError,'UNKNOWN'):kernel_job.cleanup(work,output,'a'*40,'normal')
    self.assertTrue(work.exists());self.assertTrue(config.exists());self.assertTrue(home.exists())
 def test_preexisting_config_or_alias_refuses_before_home_or_child_creation(self):
  for alias in (False,True):
   with tempfile.TemporaryDirectory(dir='/tmp') as td:
    base=Path(td);output=base.with_name(base.name+'-output');config=output.with_name(output.name+'-docker-config');home=output.with_name(output.name+'-job-home')
    try:
     if alias:config.symlink_to(base)
     else:config.mkdir(mode=0o700)
     with patch.object(W,'authorize'),patch.object(W,'load'),self.assertRaisesRegex(ValueError,'fresh ordinary'):job.parent(C.ROOT,'a'*40,'normal',['--output',str(output)])
     self.assertFalse(home.exists());self.assertTrue(config.is_symlink() if alias else config.is_dir())
    finally:
     if alias:config.unlink()
     else:config.rmdir()

 def test_orphan_config_refuses_when_kernel_work_or_child_record_absent(self):
  import shutil
  for missing in ('work','home'):
   with self.subTest(missing=missing),tempfile.TemporaryDirectory() as td:
    work,output,home=self.fixture(Path(td));config=output.with_name(output.name+'-docker-config')
    shutil.rmtree(work if missing=='work' else home)
    with self.assertRaisesRegex(ValueError,'CONFIG_WITHOUT_KERNEL_WORK|without owned child record'):kernel_job.cleanup(work,output,'a'*40,'normal')
    self.assertTrue(config.exists())


class RuntimeMountBoundaryControls(unittest.TestCase):
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));p.start();self.addCleanup(p.stop)
 def modules(self):
  return C.load('runtime_boundary_scope',C.ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py'),C.load('runtime_boundary_roots',C.ROOT/'scripts/update/full_root.py'),C.load('runtime_boundary_caps',C.HERE/'cap_scope.py')
 def test_real_mount_policy_to_complete_cap_observer_and_restore(self):
  import time
  scope,roots,caps=self.modules();raw=C.read(C.ROOT/'scripts/apps/file_capabilities.py')
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);root=base/'root';root.mkdir();(root/'usr').mkdir();(root/'usr/payload').write_bytes(b'ordinary persistent data');os.link(root/'usr/payload',root/'usr/hardlink');(root/'usr/relative').symlink_to('payload')
   for n in scope.RUNTIME:(root/n).mkdir()
   (root/'proc/private-runtime').write_bytes(b'excluded exact original runtime scope')
   rows=[dict(id=1,path=str(root),fs='ext4'),dict(id=2,path=str(base),fs='ext4')]
   for i,n in enumerate(('proc','proc/bus','proc/sys','sys','sys/fs/cgroup','dev','dev/pts','dev/shm','run','run/credentials','tmp','tmp/fixture'),10):rows.append(dict(id=i,path=str(root/n),fs='tmpfs'))
   policy=scope.mount_policy(root,base/'stage',rows);self.assertIn('proc/bus',policy['observed_mounts']);omitted=set(policy['observed_mounts'])|scope.RUNTIME
   limits=roots.Limits(deadline=time.monotonic()+10);observed=roots.observe(root,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);nodes=caps.nodes(observed['nodes'])
   module=caps.derive(raw,omitted);self.assertEqual(module.OMITTED,set(scope.RUNTIME));self.assertEqual(module.observe(root,nodes,limits),{});self.assertEqual(module.restore(root,nodes,{},limits),{})
   self.assertEqual((root/'usr/payload').read_bytes(),b'ordinary persistent data');self.assertEqual((root/'usr/hardlink').stat().st_ino,(root/'usr/payload').stat().st_ino);self.assertEqual(os.readlink(root/'usr/relative'),'payload')
   (root/'usr/foreign').write_bytes(b'not omitted')
   with self.assertRaisesRegex(ValueError,'actual node graph'):module.observe(root,nodes,limits)
 def test_all_original_literal_infrastructure_and_mount_files_exact(self):
  scope,roots,caps=self.modules();raw=C.read(C.ROOT/'scripts/apps/file_capabilities.py');literal=set(scope.RUNTIME|scope.INFRASTRUCTURE|scope.MOUNT_FILES);module=caps.derive(raw,literal)
  self.assertEqual(module.OMITTED,literal-set(scope.MOUNT_FILES));self.assertEqual(module.MOUNT_FILES,set(scope.MOUNT_FILES))
  for n in scope.INFRASTRUCTURE|scope.MOUNT_FILES:
   with self.subTest(n=n),self.assertRaisesRegex(ValueError,'only existing persistent-scope'):caps.derive(raw,{n+'/unexpected'})
 def test_unsafe_or_unrelated_mount_names_refuse_before_compile(self):
  scope,roots,caps=self.modules();raw=C.read(C.ROOT/'scripts/apps/file_capabilities.py')
  for name in ('','/proc/bus','proc//bus','proc/../usr','proc/./bus','proc/bus/','proc\\bus','proc/evil\0','usr/mounted','var/lib/runtime','proctools','etc/hosts/child',None):
   with self.subTest(name=repr(name)),self.assertRaises(ValueError):caps.derive(raw,{name})
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'root';root.mkdir();rows=[dict(id=1,path=str(root),fs='ext4'),dict(id=2,path=td,fs='ext4'),dict(id=3,path=str(root/'usr/mounted'),fs='tmpfs')]
   with self.assertRaisesRegex(ValueError,'unrecognized source mount'):scope.mount_policy(root,Path(td)/'stage',rows)
 def test_original_observer_source_anchor_and_xattr_refusals_held(self):
  import time
  scope,roots,caps=self.modules();raw=C.read(C.ROOT/'scripts/apps/file_capabilities.py')
  with self.assertRaisesRegex(ValueError,'source anchor'):caps.derive(raw.replace(b'actual node graph differs',b'foreign node graph differs'),{'proc/bus'})
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);p=root/'payload';p.write_bytes(b'original');limits=roots.Limits(deadline=time.monotonic()+10);nodes=roots.observe(root,limits=limits)['nodes'];os.setxattr(p,'user.fixture',b'original-refusal');module=caps.derive(raw,{'dev/pts'})
   with self.assertRaises(ValueError):module.observe(root,nodes,limits)
   self.assertEqual(os.getxattr(p,'user.fixture'),b'original-refusal')

if __name__=='__main__':unittest.main(verbosity=2)
