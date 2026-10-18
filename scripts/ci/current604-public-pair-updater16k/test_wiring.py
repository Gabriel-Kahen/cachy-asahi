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
   if name=='disk.py':
    original_file_branch='else:target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target,follow_symlinks=False)';new_file_branch="else:target.parent.mkdir(parents=True,exist_ok=True);command(['/usr/bin/cp','-a','--reflink=never','--',source,target],900)";self.assertEqual(b.decode().count(new_file_branch),1);b=b.decode().replace(new_file_branch,original_file_branch).encode()
   if name=='guest.py':
    tree=ast.parse(b);tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef)and n.name=='worker_failure')]
    main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');extra=[n for n in main.body if isinstance(n,ast.If)and any(isinstance(q,ast.Call)and isinstance(q.func,ast.Name)and q.func.id=='worker_failure'for q in ast.walk(n))];self.assertEqual(len(extra),1);main.body.remove(extra[0]);b=ast.unparse(tree).encode()
   if name=='vm.py':
    tree=ast.parse(b);tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef) and n.name in ('prepare_failure','qemu_failure'))];b=ast.unparse(tree).encode()
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

 def test_failed_qemu_original_stream_and_nonce_prefix_data_refusals(self):
  nonce='a'*32;raw=('APPS6_UPDATE16K '+nonce+' INERT_NOT_A_RECORD\nAPPS6_UPDATE16K '+'b'*32+' INERT_FOREIGN\nAPPS6_UPDATE16K_ERROR InertFailure\n').encode();err=b''
  record=dict(argv=['/usr/bin/qemu-system-aarch64'],exit_code=0,stdout_bytes=len(raw),stdout_sha256=C.sha(raw),stderr_bytes=0,stderr_sha256=C.sha(err));value=vm.qemu_failure(record,raw,err,nonce)
  self.assertEqual(base64.b64decode(value['stdout']['preview_base64']),raw);self.assertEqual(value['prefix_counts'],dict(protocol_prefix=2,nonce_bound_prefix=1,guest_error_prefix=1));self.assertIn('NOT_ACCEPTANCE',value['status'])
  complete=b'INERT_NOT_ORIGINAL_UART'.ljust(11358,b'!');r=dict(record,stdout_bytes=len(complete),stdout_sha256=C.sha(complete));v=vm.qemu_failure(r,complete,err,nonce)['stdout'];self.assertFalse(v['truncated']);self.assertEqual(v['preview_bytes'],11358);self.assertEqual(v['omitted_bytes'],0);self.assertEqual(base64.b64decode(v['preview_base64']),complete)
  for wrong,n in((dict(record,stdout_sha256='0'*64),nonce),(dict(record,stderr_bytes=1),nonce),(dict(record,argv=['foreign']),nonce),(record,'bad')):
   with self.assertRaises(ValueError):vm.qemu_failure(wrong,raw,err,n)
 def test_failed_qemu_tail_and_existing_retention_caps_with_no_success_credit(self):
  raw=b'INERT_PREFIX '*10000+b'APPS6_UPDATE16K_ERROR InertOnly\n';err=b'INERT_STDERR '*1000;record=dict(argv=['/usr/bin/qemu-system-aarch64'],stdout_bytes=len(raw),stdout_sha256=C.sha(raw),stderr_bytes=len(err),stderr_sha256=C.sha(err));value=vm.qemu_failure(record,raw,err,'a'*32)
  for key,data in(('stdout',raw),('stderr',err)):
   v=value[key];limit=65536 if key=='stdout'else 4096;self.assertEqual(base64.b64decode(v['preview_base64']),data[-limit:]);self.assertEqual(v['preview_bytes'],limit);self.assertTrue(v['truncated']);self.assertEqual(v['omitted_bytes'],len(data)-limit);self.assertEqual(v['sha256'],C.sha(data))
  self.assertLessEqual(len(C.encoded(value)),128*1024)
  with tempfile.TemporaryDirectory(dir='/tmp')as td,tempfile.TemporaryDirectory()as dest:
   root=Path(td);(root/'public').mkdir();C.save(root/'owner.json',dict(purpose='expanded604-apps6-public-pair-updater',case='normal',output=str(root)));C.save(root/'public/updater16k-cleanup.json',dict(status='PASS',qemu_failure=value));absent=Path(dest)/'absent'
   result=T.retain(root,Path(dest)/'retained',{},'a'*40,'normal',absent,absent,absent);self.assertEqual(result['vm_cleanup']['value']['qemu_failure'],value);self.assertFalse(result['proof_complete']);self.assertIn('NOT_ADMISSIBLE',result['completion']);self.assertEqual(T.CAP,8*1024**2)
 def test_real_vm_natural_qemu_exit_protocol_failure_keeps_diagnostics_and_cleanup(self):
  types=__import__('types')
  with tempfile.TemporaryDirectory(dir='/tmp')as td:
   root=Path(td);public=root/'public';public.mkdir();raw=root/'raw';raw.mkdir();(raw/'test-signing').mkdir();image=root/'Image';image.write_bytes(b'INERT_NO_GUEST');uart=b'INERT_BOOT_NOT_NATIVE\nAPPS6_UPDATE16K_ERROR InertOnly\n';live=set()
   def command(argv,work,env,seconds,cap):
    out=err=b'';code=0
    if argv[0]=='/usr/bin/qemu-system-aarch64':out=uart
    elif argv[1]=='inspect':
     if argv[2]in live:out=C.encoded([dict(Id='inert-owned-control',Image='sha256:'+'a'*64,Config=dict(Labels={'org.cachy-asahi.apps6-updater16k':argv[2].split('-')[-2]}))])
     else:code=1;err=('No such '+argv[2]).encode()
    elif argv[1]=='run':
     self.assertEqual(argv[-1],'prepare');live.add(argv[argv.index('--name')+1]);disks=work/'disks'
     for n in('boot','data'):(disks/(n+'.raw')).write_bytes(b'INERT_DISK_NOT_NATIVE')
     C.save(disks/'prepared.json',dict(boot=C.row(disks/'boot.raw'),data=C.row(disks/'data.raw'),capabilities_sha256='0'*64))
    elif argv[1]=='rm':live.clear()
    else:raise AssertionError('no other command')
    row=dict(argv=argv,exit_code=code,group_absence_verified=True,stderr_bytes=len(err),stderr_sha256=C.sha(err),stdout_bytes=len(out),stdout_sha256=C.sha(out));return row,out,err,None
   a=types.SimpleNamespace(implementation=C.ROOT,case='normal');old=types.SimpleNamespace(command=lambda *args:None)
   with patch.object(vm,'authorize',return_value=({'Image':C.row(image)},image,None)),patch.object(vm,'mounts',return_value=({'/upgrade-signing':dict(source=str(raw/'test-signing'),readonly=True)},{})),patch.object(vm,'snapshot',return_value={}),patch.object(vm,'old_verify',return_value=lambda *_:None),patch.object(C,'check_source',return_value={}),patch.object(C,'load',return_value=types.SimpleNamespace(run_command=command)):
    with self.assertRaisesRegex(ValueError,'three nonce-bound original guest records'):vm.run(a,[],'sha256:'+'a'*64,public,raw,old,3900)
   value=C.decode(C.read(public/'updater16k-cleanup.json'));self.assertEqual(value['status'],'PASS');self.assertEqual(value['error']['message'],'three nonce-bound original guest records');self.assertEqual(base64.b64decode(value['qemu_failure']['stdout']['preview_base64']),uart);self.assertEqual(value['qemu_failure']['prefix_counts'],dict(protocol_prefix=0,nonce_bound_prefix=0,guest_error_prefix=1));self.assertFalse((root/'update16k').exists());self.assertFalse(live);self.assertFalse((public/'updater16k-result.json').exists())

class WorkerFailureControls(unittest.TestCase):
 def guest(self):
  import importlib.util
  spec=importlib.util.spec_from_file_location('_source_worker_failure_guest',C.HERE/'guest.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 def record(self,out=b'',err=b'',**values):return dict(dict(argv=['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],exit_code=7,seconds=.1,time_limit=3900,output_limit=2*1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=C.sha(out),stderr_bytes=len(err),stderr_sha256=C.sha(err)),**values)
 def project(self,record,out,err,error=None,nonce='a'*32):
  import io,contextlib
  text=io.StringIO();G=self.guest()
  with contextlib.redirect_stdout(text):G.worker_failure(dict(nonce=nonce),record,out,err,error)
  raw=text.getvalue().encode()
  if not raw:return None,raw
  self.assertLessEqual(len(raw),33*1024);self.assertTrue(raw.startswith(('APPS6_UPDATE16K_WORKER_FAILURE '+nonce+' ').encode()));value=json.loads(raw.split(b' ',2)[2]);self.assertLessEqual(len(raw.split(b' ',2)[2]),32*1024);self.assertNotIn('APPS6_UPDATE16K ',raw.decode());return value,raw
 def test_real_inert_child_record_and_original_streams_project_without_native_credit(self):
  runner=C.load('_source_inert_worker_runner',C.ROOT/'scripts/ci/glibc-owned-runtime/runner.py')
  with tempfile.TemporaryDirectory()as td:
   # This exact real negative child is a component control, not /workspace/guest
   # or a fabricated accepting native outcome. Its record is retained unmodified.
   argv=[sys.executable,'-I','-B','-c',"import sys;sys.stdout.buffer.write(b'INERT_OUT\\n');sys.stderr.buffer.write(b'INERT_WORKER_ERROR\\n');raise SystemExit(7)"]
   record,out,err,error=runner.run_command(argv,Path(td),dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=td),3900,2*1024**2)
   self.assertIsNone(error);self.assertEqual(record['exit_code'],7);self.assertTrue(record['group_absence_verified']);value,raw=self.project(record,out,err,error);self.assertEqual(value['record'],record);self.assertEqual(value['status'],'FAILED_ORIGINAL_GUEST_WORKER_DATA_NOT_ACCEPTANCE');self.assertEqual(base64.b64decode(value['stdout']['tail_base64']),out);self.assertEqual(base64.b64decode(value['stderr']['tail_base64']),err);self.assertEqual(value['stdout']['sha256'],C.sha(out));self.assertEqual(value['stderr']['sha256'],C.sha(err));self.assertEqual(value['cleanup_acceptance'],'NOT_GRANTED')
 def test_bounded_tail_pin_truncation_nonce_and_tamper_unavailable(self):
  out=b'O'*5000;err=b'E'*9000;record=self.record(out,err);value,raw=self.project(record,out,err)
  for side,data,cap in(('stdout',out,4096),('stderr',err,8192)):
   row=value[side];self.assertEqual(row['bytes'],len(data));self.assertEqual(row['sha256'],C.sha(data));self.assertEqual(row['tail_bytes'],cap);self.assertEqual(base64.b64decode(row['tail_base64']),data[-cap:]);self.assertEqual(row['omitted_bytes'],len(data)-cap);self.assertTrue(row['truncated'])
  for changed in(dict(stdout_sha256='0'*64),dict(stderr_bytes=1),dict(time_limit=3901),dict(output_limit=2*1024**2+1),dict(argv=['x'*8193]),dict(group_absence_verified=1)):
   row,_=self.project(dict(record,**changed),out,err);self.assertEqual(row['status'],'DIAGNOSTIC_UNAVAILABLE_NOT_ACCEPTANCE');self.assertNotIn('message',row)
  self.assertEqual(self.project(record,out,err,nonce='bad'),(None,b''))
  record=self.record(b'',b'',exit_code=0);row,_=self.project(record,b'',b'',ValueError('PRIVATE_ERROR_TEXT_NOT_EXPORTED'));self.assertEqual(row['error_type'],'ValueError');self.assertNotIn('PRIVATE',C.encoded(row).decode())
 def route(self,record,out,err,error=None,broken=False):
  import io,contextlib,types
  G=self.guest();raw=(C.HERE/'guest.py').read_text();tree=ast.parse(raw);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');start=next(i for i,n in enumerate(main.body)if isinstance(n,ast.Assign)and any(isinstance(v,ast.Call)and isinstance(v.func,ast.Attribute)and v.func.attr=='load'and v.args and isinstance(v.args[0],ast.Constant)and v.args[0].value=='supervisor'for v in ast.walk(n)));guard=next(i for i,n in enumerate(main.body)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and any(isinstance(x,ast.Constant)and x.value=='whole updater worker exit/group absence'for x in ast.walk(n)))
  def run(argv,work,env,seconds,cap):
   self.assertEqual(argv,['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']);self.assertEqual((work,seconds,cap),(Path('/tmp'),3900,2*1024**2));return record,out,err,error
  space=dict(C=types.SimpleNamespace(load=lambda *a:types.SimpleNamespace(run_command=run),need=C.need),Path=Path,s=dict(nonce='a'*32),worker_failure=G.worker_failure);stream=io.StringIO();code=compile(ast.Module(body=main.body[start:guard+1],type_ignores=[]),'<actual-source-worker-call-and-held-guard>','exec')
  with contextlib.redirect_stdout(stream):
   if broken:
    with patch('builtins.print',side_effect=OSError('closed UART')):exec(code,space)
   else:exec(code,space)
  return stream.getvalue()
 def test_actual_worker_guard_positive_protocol_and_failed_output_order_conserved(self):
  original=(C.ROOT/'scripts/ci/current604-apps6-updater16k/guest.py').read_text();new=(C.HERE/'guest.py').read_text()
  self.assertEqual(original.count("emit(s,"),new.count("emit(s,"));self.assertEqual(new.count("'whole updater worker exit/group absence'"),1)
  self.assertEqual(self.route(self.record(exit_code=0),b'',b''), '')
  for group in(True,False):
   with self.assertRaisesRegex(ValueError,'whole updater worker exit/group absence'):self.route(self.record(group_absence_verified=group),b'',b'')
  with self.assertRaisesRegex(ValueError,'whole updater worker exit/group absence'):self.route(self.record(),b'',b'',broken=True)
  import io,contextlib
  buffer=io.StringIO()
  with contextlib.redirect_stdout(buffer):
   # Original emit() still emits only its exact old positive prefix/record.
   self.guest().emit(dict(nonce='a'*32),dict(event='boot'))
  self.assertTrue(buffer.getvalue().startswith('APPS6_UPDATE16K '+'a'*32+' '));self.assertNotIn('WORKER_FAILURE',buffer.getvalue())


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

class InputFileStaging(unittest.TestCase):
 """Only real bounded cp on private files; no Docker/guest/installation actor."""
 def file_command(self):
  import disk
  tree=ast.parse(C.read(C.HERE/'disk.py'));prepare=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='prepare')
  loops=[n for n in prepare.body if isinstance(n,ast.For)and ast.unparse(n.target)=='dest'];self.assertEqual(len(loops),2)
  branch=next(n for n in loops[0].body if isinstance(n,ast.If)and ast.unparse(n.test)=="dest == '/measurement'")
  while branch.orelse and isinstance(branch.orelse[0],ast.If):branch=branch.orelse[0]
  self.assertEqual(ast.unparse(branch.test),'source.is_dir()');call=branch.orelse[-1].value
  self.assertEqual(ast.unparse(call),"command(['/usr/bin/cp', '-a', '--reflink=never', '--', source, target], 900)")
  expression=compile(ast.Expression(call),'<exact-disk-file-command>','eval')
  return lambda source,target:eval(expression,dict(command=disk.command,source=source,target=target))
 def guest_readback(self,input_map):
  tree=ast.parse(C.read(C.HERE/'guest.py'));worker=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='worker');loop=next(n for n in worker.body if isinstance(n,ast.For)and ast.unparse(n.target)=='(n, pin)')
  exec(compile(ast.Module(body=[loop],type_ignores=[]),'<exact-original-guest-input-loop>','exec'),dict(C=C,Path=Path,input_map=input_map))
 def test_real_all_standalone_roles_modes_bytes_and_source_preserved(self):
  names=('runner.py','upgrade-config.json','upgrade-hook.py','persistent_scope.py','setup4.py','footprint.py')
  with tempfile.TemporaryDirectory(dir='/tmp',prefix='input-files-')as td:
   root=Path(td);src=root/'source';src.mkdir();dst=root/'target';dst.mkdir();bindings={}
   for i,name in enumerate(names):
    p=src/name;p.write_bytes(('INERT_PRIVATE_'+name).encode());p.chmod((0o600,0o640,0o755)[i%3]);bindings[str(dst/name)]=dict(source=str(p))
   before=vm.snapshot(bindings)
   for n in names:self.file_command()(src/n,dst/n)
   self.guest_readback(before);self.assertEqual(vm.snapshot(bindings),before)
   self.assertEqual(vm.snapshot({n:dict(source=n)for n in before}),before)
 def test_original_guest_refuses_mode_owner_alias_content_and_hardlink_drift(self):
  with tempfile.TemporaryDirectory(dir='/tmp',prefix='input-refuse-')as td:
   root=Path(td);source=root/'source';target=root/'target';source.write_bytes(b'original');source.chmod(0o600);self.file_command()(source,target);expected=vm.snapshot({str(target):dict(source=str(source))})
   for uid,gid,mode in ((os.getuid()+1,os.getgid(),0o600),(os.getuid(),os.getgid()+1,0o600),(os.getuid(),os.getgid(),0o644)):
    changed=json.loads(json.dumps(expected));changed[str(target)].update(uid=uid,gid=gid,mode=mode)
    with self.assertRaisesRegex(ValueError,'copied input metadata'):self.guest_readback(changed)
   target.write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'copied input source/content'):self.guest_readback(expected)
   target.unlink();self.file_command()(source,target);os.link(target,root/'alias')
   with self.assertRaisesRegex(ValueError,'copied input source/content'):self.guest_readback(expected)
   (root/'alias').unlink();target.unlink();target.symlink_to(source)
   with self.assertRaisesRegex(ValueError,'copied input metadata'):self.guest_readback(expected)
 def test_exact_inverse_and_original_staging_command_budgets(self):
  old=C.read(C.ROOT/'scripts/ci/current604-apps6-updater16k/disk.py');new=C.read(C.HERE/'disk.py')
  before="else:target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target,follow_symlinks=False)"
  after="else:target.parent.mkdir(parents=True,exist_ok=True);command(['/usr/bin/cp','-a','--reflink=never','--',source,target],900)"
  import disk
  helper='BOOT_DEV_CHECK = '+repr(disk.BOOT_DEV_CHECK)+'\n\n'
  initial="'mount -t devtmpfs -o nosuid devtmpfs /dev'"
  revised="'/usr/bin/python3 -I -B -c '+__import__('shlex').quote(BOOT_DEV_CHECK),'mount -o remount,nosuid /dev'"
  self.assertEqual(new.decode().count(helper),1);self.assertEqual(new.decode().count(revised),1)
  new=new.decode().replace(helper,'').replace(revised,initial).encode()
  self.assertEqual(new.decode().count(after),1);self.assertEqual(new.decode().replace(after,before).encode(),old)
  self.assertIn("elif source.is_dir():command(['/usr/bin/cp','-a','--reflink=never','--',source,target],900)",new.decode())
  self.assertIn("C.need(not target.exists() and not target.is_symlink(),'fresh staged infrastructure role')",new.decode())
  self.assertEqual((C.HERE/'guest.py').read_bytes().count(b"'copied input metadata'"),1)

class KernelAutoDevMount(unittest.TestCase):
 """Controlled kernel-format tables and real owned descriptors, never a guest fixture."""
 def bootstrap(self):
  import disk
  space=dict(__name__='source_bootstrap_control');exec(compile(disk.BOOT_DEV_CHECK,'<exact-generated-dev-check>','exec'),space);return space
 def table(self,dev=True):
  rows=['1 0 254:0 / / rw - ext4 /dev/vda rw','2 1 0:1 / /proc ro - proc proc ro','3 1 0:2 / /sys ro - sysfs sysfs ro','4 1 254:1 /measurement /measurement rw - ext4 /dev/vdb rw','5 1 254:1 /upgrade-signing /upgrade-signing rw - ext4 /dev/vdb rw']
  if dev:rows.append('10 1 0:5 / /dev rw - devtmpfs devtmpfs rw')
  return '\n'.join(rows)+'\n'
 def test_kernel_autodev_old_init_stack_refuses_and_single_mount_route_passes(self):
  import disk
  scope=C.load('original_mount_stack_scope',C.ROOT/'scripts/ci/full-root-upgrade-caller/persistent_scope.py')
  fragment=C.read(C.ROOT/'scripts/ci/managed-gui-generic16k/kernel.fragment').decode();self.assertIn('CONFIG_DEVTMPFS_MOUNT=y\n',fragment)
  initial=self.table();self.assertEqual(self.bootstrap()['verify'](initial,10),10);scope.mounts(initial)
  # Source-route fixture, not exported actual mountinfo: automatic devtmpfs10,
  # redundant explicit devtmpfs11, one umount removes11, tmpfs12 leaves10+12.
  stacked=initial+'11 10 0:5 / /dev rw,nosuid - devtmpfs devtmpfs rw\n'
  with self.assertRaisesRegex(ValueError,'unambiguous mount table'):scope.mounts(stacked)
  old_final=initial+'12 10 0:6 / /dev rw,nosuid - tmpfs tmpfs rw\n'
  with self.assertRaisesRegex(ValueError,'unambiguous mount table'):scope.mounts(old_final)
  # New route remounts existing10 (same ID), then original umount removes10;
  # original tmpfs12 has a unique /dev and the strict original policy passes.
  final=self.table(dev=False)+'12 1 0:6 / /dev rw,nosuid - tmpfs tmpfs rw\n'
  rows=scope.mounts(final);policy=scope.mount_policy(Path('/'),Path('/measurement/inspection'),rows)
  self.assertEqual((policy['source_mount'],policy['target_mount']),(1,4));self.assertIn('dev',policy['observed_mounts'])
  self.assertNotIn("'mount -t devtmpfs -o nosuid devtmpfs /dev'",C.read(C.HERE/'disk.py').decode())
 def test_missing_wrong_stacked_alias_or_unmatched_existing_mount_refuses(self):
  verify=self.bootstrap()['verify'];raw=self.table()
  wrong=[(self.table(dev=False),10),(raw.replace('devtmpfs devtmpfs','tmpfs tmpfs'),10),(raw,11),(raw,True),(raw+'11 10 0:5 / /dev rw - devtmpfs devtmpfs rw\n',10),(raw+'11 1 254:0 / / rw - ext4 /dev/vda rw\n',10),(raw.replace('10 1 0:5 / /dev','10 1 0:5 /sub /dev'),10),(raw.replace('/dev rw - devtmpfs','/dev/../dev rw - devtmpfs'),10),(raw+'10 1 0:9 / /run rw - tmpfs tmpfs rw\n',10)]
  for text,identity in wrong:
   with self.subTest(text=text,identity=identity),self.assertRaises(ValueError):verify(text,identity)
 def test_actual_generated_shell_entry_and_fresh_owned_fd_readback(self):
  import disk,io,shlex
  tree=ast.parse(C.read(C.HERE/'disk.py'));prepare=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='prepare');node=next(n for n in prepare.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='init'for t in n.targets))
  script=eval(compile(ast.Expression(body=node.value),'<actual-init-list>','eval'),dict(BOOT_DEV_CHECK=disk.BOOT_DEV_CHECK))
  entries=[s for s in script if s.startswith('/usr/bin/python3 -I -B -c ')];self.assertEqual(len(entries),1);self.assertEqual(shlex.split(entries[0])[-1],disk.BOOT_DEV_CHECK)
  self.assertEqual(script.count('mount -o remount,nosuid /dev'),1);self.assertFalse(any(s.startswith('mount -t devtmpfs ')for s in script))
  original_open=os.open;path_open=Path.open
  with tempfile.TemporaryDirectory()as tmp:
   directory=Path(tmp);fd=original_open(directory,os.O_RDONLY|os.O_DIRECTORY)
   try:mount_id=int(next(line.split()[1]for line in Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines()if line.startswith('mnt_id:')))
   finally:os.close(fd)
   raw=self.table().replace('10 1 0:5 / /dev',str(mount_id)+' 1 0:5 / /dev')
   def opened(path,*args,**kwargs):return io.StringIO(raw)if str(path)=='/proc/self/mountinfo'else path_open(path,*args,**kwargs)
   def dev_open(path,flags,*args,**kwargs):
    if path=='/dev':self.assertTrue(flags&os.O_NOFOLLOW);return original_open(directory,flags,*args,**kwargs)
    return original_open(path,flags,*args,**kwargs)
   before=len(os.listdir('/proc/self/fd'))
   with patch.object(Path,'open',opened),patch.object(os,'open',side_effect=dev_open):exec(compile(shlex.split(entries[0])[-1],'<actual-generated-bootstrap>','exec'),dict(__name__='__main__'))
   self.assertEqual(len(os.listdir('/proc/self/fd')),before)
 def test_bad_descriptor_identity_fails_closed_and_retires_fd(self):
  import io
  space=self.bootstrap();original_open=os.open;path_open=Path.open
  with tempfile.TemporaryDirectory()as tmp:
   directory=Path(tmp)
   def opened(path,*args,**kwargs):
    if str(path)=='/proc/self/mountinfo':return io.StringIO(self.table())
    if str(path).startswith('/proc/self/fdinfo/'):return io.StringIO('mnt_id:\t999\n')
    return path_open(path,*args,**kwargs)
   def dev_open(path,flags,*args,**kwargs):return original_open(directory if path=='/dev'else path,flags,*args,**kwargs)
   before=len(os.listdir('/proc/self/fd'))
   with patch.object(Path,'open',opened),patch.object(os,'open',side_effect=dev_open),self.assertRaisesRegex(ValueError,'kernel devtmpfs identity'):space['main']()
   self.assertEqual(len(os.listdir('/proc/self/fd')),before)


if __name__=='__main__':unittest.main(verbosity=2)
