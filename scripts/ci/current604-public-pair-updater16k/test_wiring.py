# SPDX-License-Identifier: MIT
"""Finite public-pair routing/source/WF guards; no actual authorities or actors."""
import ast,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import contract as C
import wiring as W,job,kernel_job,retain16k as T,prepare as P,vm,base64
def pre_boot_witness(raw):
 text=raw.decode();start=text.index('def boot_witness(');end=text.index('def snapshot(bindings):',start);text=text[:start]+text[end:]
 before='guest=result,launcher_realtime=boot_witness(uart,selection),kernel=profile,source=';assert text.count(before)==1;text=text.replace(before,'guest=result,kernel=profile,source=');return text.encode()

def pre_launcher_clock(raw,name):
 if name=='vm.py':raw=pre_boot_witness(raw)
 text=raw.decode()
 if name=='guest.py':
  start=text.index('def initialize_launcher_clock():');end=text.index('def main():',start);text=text[:start]+text[end:]
  before=" clock=initialize_launcher_clock()\n";assert text.count(before)==1;text=text.replace(before,'')
  before='nofile=dict(before=before,after=after),clock=clock))';assert text.count(before)==1;text=text.replace(before,'nofile=dict(before=before,after=after)))')
 elif name=='vm.py':
  text=text.replace('import base64,json,os,re,shutil,time','import base64,json,os,re,shutil')
  before="def qemu(image,boot,data,epoch):\n C.need(type(epoch)is int and 1700000000<=epoch<2**32,'bounded launcher UTC epoch required')";assert text.count(before)==1;text=text.replace(before,'def qemu(image,boot,data):')
  before="init=/init-updater16k caa_apps6_update16k=1 cachy_asahi_updater_epoch='+str(epoch)";assert text.count(before)==1;text=text.replace(before,"init=/init-updater16k caa_apps6_update16k=1'")
  start=text.index(" clock=boot['clock'];");end=text.index('\n',start);text=text[:start]+text[end+1:]
  before="  epoch=int(time.time());selection['launcher_epoch_s']=epoch\n";assert text.count(before)==1;text=text.replace(before,'')
  before="qemu(work/'Image',disks/'boot.raw',disks/'data.raw',epoch)";assert text.count(before)==1;text=text.replace(before,"qemu(work/'Image',disks/'boot.raw',disks/'data.raw')")
 else:raise ValueError('finite clock inverse role')
 return text.encode()

def pre_caller_failure(raw):
 text=raw.decode();start=text.index('def caller_failure(');end=text.index('def worker(s):',start);text=text[:start]+text[end:]
 a=" if error is not None or record['exit_code']!=0 or record['group_absence_verified']is not True:caller_failure(s,record,stdout,stderr,error)\n";assert text.count(a)==1;text=text.replace(a,'')
 a=" if error is not None or record['exit_code']!=0 or record['group_absence_verified']is not True:\n  forward_caller_failure(s,record,out)\n  worker_failure(s,record,out,err,error)";b=" if error is not None or record['exit_code']!=0 or record['group_absence_verified']is not True:worker_failure(s,record,out,err,error)";assert text.count(a)==1;text=text.replace(a,b)
 return text.encode()

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
   if name in ('guest.py','vm.py'):b=pre_launcher_clock(b,name)
   if name=='guest.py':b=pre_caller_failure(b)
   if name in ('disk.py','guest.py'):b=pre_boot_readback(b,name)
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
  space=dict(C=types.SimpleNamespace(load=lambda *a:types.SimpleNamespace(run_command=run),need=C.need),Path=Path,s=dict(nonce='a'*32),worker_failure=G.worker_failure,forward_caller_failure=G.forward_caller_failure);stream=io.StringIO();code=compile(ast.Module(body=main.body[start:guard+1],type_ignores=[]),'<actual-source-worker-call-and-held-guard>','exec')
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
  old=C.read(C.ROOT/'scripts/ci/current604-apps6-updater16k/disk.py');new=pre_boot_readback(C.read(C.HERE/'disk.py'),'disk.py')
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


def pre_boot_readback(raw,name):
 """Counted byte inverse for only the declared formatter/diagnostic change."""
 text=raw.decode()
 additions=('image_directory','formatter_recovery_directory')if name=='disk.py'else('boot_readback_diagnostic',)
 for function in additions:
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==function);lines=text.splitlines(keepends=True);assert lines[node.end_lineno]=='\n';segment=''.join(lines[node.lineno-1:node.end_lineno+1]);assert text.count(segment)==1;text=text.replace(segment,'')
 if name=='disk.py':
  old="C.need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=2*1024**2,'owned disk command refused: '+str(argv[0]))";new=old+';return p.stdout';assert text.count(new)==1;text=text.replace(new,old)
  call="\n  if name=='boot':formatter_recovery_directory(image,before,out)";assert text.count(call)==1;text=text.replace(call,'')
 else:
  new="expected=C.decode(C.read('/workspace/baseline-nodes.json',64*1024**2))\n if before!=expected or C.sha(C.encoded(mapping))!=s['capabilities_sha256']:boot_readback_diagnostic(s,before,expected,mapping)\n C.need(";old="expected=C.decode(C.read('/workspace/baseline-nodes.json',64*1024**2));C.need(";assert text.count(new)==1;text=text.replace(new,old)
 return text.encode()

class BootImageReadback(unittest.TestCase):
 """Real private ext4 regular files, never devices/mounts/native acceptance."""
 def disk(self):
  # Host-only fixture seam: Ubuntu uses sbin, runtime Arch paths stay fixed.
  import shutil,stat
  disk=C.load('boot_recovery_controls',C.HERE/'disk.py');command=disk.command;tools={}
  for name in('mkfs.ext4','debugfs'):
   found=shutil.which(name);C.need(found is not None,'required real host image tool missing: '+name)
   actual=Path(found).resolve(strict=True);info=actual.stat();C.need(actual.is_absolute()and stat.S_ISREG(info.st_mode)and os.access(actual,os.X_OK),'real executable host image tool required: '+name);tools['/usr/bin/'+name]=str(actual)
  def host_command(argv,*args):
   argv=list(argv)
   if str(argv[0])in tools:argv[0]=tools[str(argv[0])]
   return command(argv,*args)
  disk.command=host_command;return disk
 def test_missing_real_host_tool_refuses_without_skip_or_command(self):
  import shutil
  with patch.object(shutil,'which',return_value=None),patch.object(subprocess,'Popen',side_effect=AssertionError('no tool may execute')),self.assertRaisesRegex(ValueError,'required real host image tool missing'):self.disk()
 def test_unexecutable_host_tool_refuses_without_command(self):
  import shutil
  with tempfile.TemporaryDirectory()as td:
   fake=Path(td)/'mkfs.ext4';fake.write_bytes(b'not executable')
   with patch.object(shutil,'which',return_value=str(fake)),patch.object(subprocess,'Popen',side_effect=AssertionError('no tool may execute')),self.assertRaisesRegex(ValueError,'real executable host image tool required'):self.disk()
 def test_real_host_prerequisites_precede_controls_with_bounded_apt(self):
  text=(C.ROOT/P.WF).read_text();start=text.index('      - name: Provision host ext4 test tools on disposable runner');end=text.index('      - name: Source-only public-pair updater16K controls');self.assertLess(start,end);step=text[start:end]
  for marker in('timeout-minutes: 9','180s sudo apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 update -qq','240s sudo env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 install -y --no-install-recommends e2fsprogs','command -v mkfs.ext4','command -v debugfs','dpkg-query -W e2fsprogs'):self.assertIn(marker,step)
 def image(self,root):
  seed=root/'seed';seed.mkdir();(seed/'usr').mkdir();(seed/'usr/data').write_bytes(b'exact private payload\n');os.link(seed/'usr/data',seed/'usr/hardlink');(seed/'alias').symlink_to('usr/data');image=root/'boot.raw'
  with image.open('xb')as f:f.truncate(64*1024**2)
  disk=self.disk();disk.command(['/usr/bin/mkfs.ext4','-F','-b','4096','-m','0','-L','APPS6_BOOT','-d',seed,image],30);return disk,image,seed
 def test_real_mkfs_extra_removed_exactly_payload_hardlinks_symlink_preserved(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);disk,image,seed=self.image(root);before=disk.image_directory(disk.command(['/usr/bin/debugfs','-R','ls -p /',image]));self.assertIn('lost+found',before)
   stats={n:disk.command(['/usr/bin/debugfs','-R','stat '+n,image])for n in('/usr/data','/usr/hardlink','/alias')};self.assertEqual(stats['/usr/data'].splitlines()[0],stats['/usr/hardlink'].splitlines()[0])
   disk.formatter_recovery_directory(image,{},root);after=disk.image_directory(disk.command(['/usr/bin/debugfs','-R','ls -p /',image]));self.assertEqual(after,{n:r for n,r in before.items()if n!='lost+found'})
   for n,raw in stats.items():self.assertEqual(disk.command(['/usr/bin/debugfs','-R','stat '+n,image]),raw)
   self.assertEqual(disk.command(['/usr/bin/debugfs','-R','cat /usr/data',image]),b'exact private payload\n');self.assertEqual((seed/'usr/data').read_bytes(),b'exact private payload\n')
 def test_real_nonempty_formatter_directory_refuses_without_deletion(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);disk,image,seed=self.image(root);disk.command(['/usr/bin/debugfs','-w','-R','write '+str(seed/'usr/data')+' /lost+found/foreign',image])
   with self.assertRaisesRegex(ValueError,'only empty formatter'):disk.formatter_recovery_directory(image,{},root)
   self.assertEqual(disk.command(['/usr/bin/debugfs','-R','cat /lost+found/foreign',image]),b'exact private payload\n')
 def test_original_baseline_recovery_directory_never_removed_or_read(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);disk,image,seed=self.image(root);before=C.row(image)
   with patch.object(disk,'command',side_effect=AssertionError('original data must stay')):disk.formatter_recovery_directory(image,{'lost+found':{'type':'directory'}},root)
   self.assertEqual(C.row(image),before)
 def test_image_alias_hardlink_and_wrongpath_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);disk,image,seed=self.image(root);alias=root/'alias.raw';alias.symlink_to(image)
   with self.assertRaises(ValueError):disk.formatter_recovery_directory(alias,{},root)
   hard=root/'hard';os.link(image,hard)
   with self.assertRaisesRegex(ValueError,'single-link'):disk.formatter_recovery_directory(image,{},root)
   hard.unlink()
   with self.assertRaisesRegex(ValueError,'absent recovery subtree'):disk.formatter_recovery_directory(image,{'lost+found/data':{}},root)
 def test_changed_formatter_mode_and_zero_exit_without_removal_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);disk,image,seed=self.image(root);disk.command(['/usr/bin/debugfs','-w','-R','set_inode_field /lost+found mode 040755',image])
   with self.assertRaisesRegex(ValueError,'exact new formatter'):disk.formatter_recovery_directory(image,{},root)
   disk.command(['/usr/bin/debugfs','-w','-R','set_inode_field /lost+found mode 040700',image]);original=disk.command
   def no_remove(argv,*args):return b''if argv[1:4]==['-w','-R','rmdir /lost+found']else original(argv,*args)
   with patch.object(disk,'command',side_effect=no_remove),self.assertRaisesRegex(ValueError,'removal readback'):disk.formatter_recovery_directory(image,{},root)
 def test_directory_data_rejects_malformed_duplicate_or_fake_free_slots(self):
  disk=self.disk()
  for raw in(b'',b'garbage',b'/0/000000/0/0/SECRET/0/\n',b'/11/040700/0/0/.//\n/2/040755/0/0/..//\n/11/040700/0/0/.//\n'):
   with self.subTest(raw=raw),self.assertRaises(ValueError):disk.image_directory(raw)
 def test_actual_readback_guard_diagnostic_is_failure_only_bounded_no_values(self):
  import io,contextlib
  guest=C.load('boot_readback_diagnostic_controls',C.HERE/'guest.py');tree=ast.parse(C.read(C.HERE/'guest.py'));worker=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='worker');index=next(i for i,n in enumerate(worker.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='expected'for t in n.targets));body=worker.body[index:index+3];self.assertIsInstance(body[1],ast.If);self.assertIn('complete original boot574 metadata/hash/hardlink/capability map readback',ast.unparse(body[2]));code=compile(ast.Module(body=body,type_ignores=[]),'<unchanged-actual-readback-guard>','exec')
  expected={'private-key':dict(type='file',mode=0o644,uid=0,gid=0,bytes=21,sha256='a'*64)};before=json.loads(json.dumps(expected));before['private-key']['mode']=0o600;secret='DO_NOT_EXPORT_PRIVATE_VALUES';before['private-key']['sha256']=secret;mapping={};api=type('API',(),dict(read=staticmethod(lambda *a:C.encoded(expected)),decode=staticmethod(C.decode),sha=staticmethod(C.sha),encoded=staticmethod(C.encoded),need=staticmethod(C.need)))
  space=dict(C=api,s=dict(nonce='a'*32,capabilities_sha256=C.sha(C.encoded(mapping))),before=before,mapping=mapping,boot_readback_diagnostic=guest.boot_readback_diagnostic);stream=io.StringIO()
  with contextlib.redirect_stdout(stream),self.assertRaisesRegex(ValueError,'complete original boot574'):exec(code,space)
  text=stream.getvalue();self.assertLess(len(text.encode()),3072);self.assertNotIn(secret,text);value=json.loads(text.split(' ',1)[1]);self.assertFalse(value['node_equal']);self.assertTrue(value['cap_hash_equal']);self.assertEqual(value['changed_nodes'],1);self.assertEqual(value['first_key'],'private-key');self.assertEqual(value['differing_fields'],['mode','sha256']);self.assertFalse(value['acceptance_authority']);self.assertFalse(value['cleanup_authority'])
  space['boot_readback_diagnostic']=lambda *a:None
  with self.assertRaisesRegex(ValueError,'complete original boot574'):exec(code,space)
 def test_only_declared_source_seams_are_added_no_guard_or_budget_rewrite(self):
  # The two original runtime predicates/arguments remain exact after inversion.
  for name in('disk.py','guest.py'):
   raw=pre_boot_readback(C.read(C.HERE/name),name);self.assertNotIn(b'formatter_recovery_directory',raw);self.assertNotIn(b'BOOT_READBACK_DIAGNOSTIC',raw)
  disk=C.read(C.HERE/'disk.py').decode();self.assertEqual(disk.count("if name=='boot':formatter_recovery_directory(image,before,out)"),1)
  guest=C.read(C.HERE/'guest.py').decode();self.assertEqual(guest.count("C.need(before==expected and C.sha(C.encoded(mapping))==s['capabilities_sha256'],'complete original boot574 metadata/hash/hardlink/capability map readback')"),1)





class CallerFailureControls(unittest.TestCase):
 def guest(self):return WorkerFailureControls().guest()
 def record(self,out=b'',err=b'',**extra):return WorkerFailureControls().record(out,err,argv=['/usr/bin/python3','-I','-B','/runner.py'],**extra)
 def capture(self,record,out,err,error=None):
  import contextlib,io
  stream=io.StringIO()
  with contextlib.redirect_stdout(stream):self.guest().caller_failure(dict(nonce='a'*32),record,out,err,error)
  raw=stream.getvalue().encode();self.assertTrue(raw.startswith(b'APPS6_UPDATE16K_CALLER_FAILURE '+'a'.encode()*32+b' '));return raw,json.loads(raw.split(b' ',2)[2])
 def test_small_complete_caller_streams_and_exact_record(self):
  out=b'INERT_CALLER_OUT\n';err=b'INERT_CALLER_FAILURE\n';record=self.record(out,err);raw,v=self.capture(record,out,err)
  self.assertEqual(v['record'],record);self.assertEqual(v['status'],'FAILED_ORIGINAL_GUEST_CALLER_DATA_NOT_ACCEPTANCE');self.assertIsNone(v['error_type'])
  for side,data in(('stdout',out),('stderr',err)):
   self.assertEqual(base64.b64decode(v[side]['tail_base64']),data);self.assertFalse(v[side]['truncated']);self.assertEqual(v[side]['sha256'],C.sha(data))
  self.assertFalse(any(line.startswith(b'APPS6_UPDATE16K ')for line in raw.splitlines()))
 def test_tails_and_partial_error_scope_do_not_claim_timeout(self):
  out=b'O'*5000;err=b'E'*9000;raw,v=self.capture(self.record(out,err),out,err,TimeoutError('PRIVATE_NOT_EXPORTED'))
  self.assertLessEqual(len(raw),25*1024);self.assertEqual(v['error_type'],'TimeoutError');self.assertNotIn('PRIVATE',raw.decode())
  for side,data,cap in(('stdout',out,4096),('stderr',err,8192)):
   self.assertEqual(base64.b64decode(v[side]['tail_base64']),data[-cap:]);self.assertEqual(v[side]['omitted_bytes'],len(data)-cap);self.assertTrue(v[side]['truncated'])
  self.assertEqual(v['capture_scope'],'ORIGINAL_RUN_COMMAND_CAPTURE_MAY_BE_PARTIAL_ON_ERROR')
 def test_foreign_argv_bad_hash_budget_success_and_group_type_unavailable(self):
  record=self.record()
  for extra in(dict(argv=['/foreign.py']),dict(stdout_sha256='0'*64),dict(time_limit=3901),dict(output_limit=1),dict(exit_code=0),dict(group_absence_verified=1)):
   raw,v=self.capture(dict(record,**extra),b'',b'');self.assertEqual(v['status'],'DIAGNOSTIC_UNAVAILABLE_NOT_ACCEPTANCE');self.assertNotIn('record',v)
 def test_forward_long_caller_frame_from_original_capture_with_no_success_prefix(self):
  import contextlib,io
  raw,original=self.capture(self.record(b'O'*5000,b'E'*9000),b'O'*5000,b'E'*9000)
  data=b'INERT_WORKER_PREFIX\n'+raw+b'APPS6_UPDATE16K_ERROR inert failure\n';record=WorkerFailureControls().record(data,b'');stream=io.StringIO()
  with contextlib.redirect_stdout(stream):self.guest().forward_caller_failure(dict(nonce='a'*32),record,data)
  forwarded=stream.getvalue().encode();value=json.loads(forwarded.split(b' ',2)[2]);meta=value.pop('worker_capture');self.assertEqual(value,original);self.assertEqual(meta['sha256'],C.sha(data));self.assertEqual(meta['bytes'],len(data));self.assertEqual(meta['frame_offset'],len(b'INERT_WORKER_PREFIX\n'));self.assertEqual(meta['frame_sha256'],C.sha(raw.rstrip(b'\n')))
  self.assertFalse(any(x.startswith(b'APPS6_UPDATE16K ')for x in forwarded.splitlines()));self.assertLessEqual(len(forwarded),33*1024)
  for invalid,body in((dict(record,stdout_sha256='0'*64),data),(record,data+raw),(record,data.replace(b'a'*32,b'b'*32))):
   stream=io.StringIO()
   with contextlib.redirect_stdout(stream):self.guest().forward_caller_failure(dict(nonce='a'*32),invalid,body)
   self.assertEqual(stream.getvalue(),'')
 def test_actual_worker_caller_pre_guard_route_with_private_out_files(self):
  import contextlib,io,types
  guest=self.guest();tree=ast.parse((C.HERE/'guest.py').read_bytes());worker=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='worker');start=next(i for i,n in enumerate(worker.body)if isinstance(n,ast.Assign)and any(isinstance(x,ast.Constant)and x.value=='supervisor'for x in ast.walk(n)));end=next(i for i,n in enumerate(worker.body)if any(isinstance(x,ast.Constant)and x.value=='original caller exit/group absence'for x in ast.walk(n)))
  for group,error,code in((True,None,7),(False,None,0),(True,ValueError('PRIVATE'),0)):
   out=b'INERT_ONLY';err=b'INERT_ERROR';record=self.record(out,err,group_absence_verified=group,exit_code=code)
   def run(argv,work,env,seconds,cap):self.assertEqual(argv,['/usr/bin/python3','-I','-B','/runner.py']);self.assertEqual((work,seconds,cap),(Path('/tmp'),3900,2*1024**2));return record,out,err,error
   with tempfile.TemporaryDirectory()as td:
    def private_path(name):
     self.assertIn(name,('/tmp','/out/updater16k-caller.stdout','/out/updater16k-caller.stderr'));return Path('/tmp')if name=='/tmp'else Path(td)/Path(name).name
    namespace=dict(C=types.SimpleNamespace(load=lambda *a:types.SimpleNamespace(run_command=run),need=C.need),Path=private_path,s=dict(nonce='a'*32),env={},caller_failure=guest.caller_failure);stream=io.StringIO()
    with contextlib.redirect_stdout(stream),self.assertRaisesRegex(ValueError,'original caller exit/group absence'):exec(compile(ast.Module(body=worker.body[start:end+1],type_ignores=[]),'<actual-caller-pre-guard-negative-control>','exec'),namespace)
    self.assertEqual((Path(td)/'updater16k-caller.stdout').read_bytes(),out);self.assertEqual((Path(td)/'updater16k-caller.stderr').read_bytes(),err);v=json.loads(stream.getvalue().split(' ',2)[2]);self.assertEqual(v['record'],record)
 def test_exact_guest_inverse_and_original_success_statements_held(self):
  raw=pre_launcher_clock((C.HERE/'guest.py').read_bytes(),'guest.py');self.assertEqual(C.sha(pre_caller_failure(raw)),'c23eab13a47e5f7ae10c08ee1a29c5ff0c2478bbd675dc9f6013be045861eaef')
  a,b=ast.parse(pre_caller_failure(raw)),ast.parse(raw);before={n.name:ast.dump(n,include_attributes=False)for n in a.body if isinstance(n,ast.FunctionDef)};after={n.name:ast.dump(n,include_attributes=False)for n in b.body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(set(after)-set(before),{'caller_failure','forward_caller_failure'});self.assertEqual({n for n in before if before[n]!=after[n]},{'worker','main'})
  self.assertEqual(raw.count(b'emit(s,'),pre_caller_failure(raw).count(b'emit(s,'))

class LauncherClockAndSignatureData(unittest.TestCase):
 def guest(self):return C.load('launcher_clock_controls',C.HERE/'guest.py')
 def clock(self,raw,after=1700000000000000001):
  g=self.guest()
  with patch.object(os,'getpid',return_value=1),patch.object(os,'getuid',return_value=0),patch.object(os,'geteuid',return_value=0),patch.object(Path,'read_text',return_value=raw),patch.object(g.time,'clock_settime')as setter,patch.object(g.time,'time_ns',side_effect=[0,after]):
   value=g.initialize_launcher_clock();setter.assert_called_once_with(g.time.CLOCK_REALTIME,1700000000);return value
 def test_clock_handoff_real_source_no_host_clock_mutation(self):
  value=self.clock('root=/dev/vda cachy_asahi_updater_epoch=1700000000');self.assertEqual(value['requested_epoch_s'],1700000000);self.assertEqual(value['before_ns'],0);self.assertGreaterEqual(value['after_ns'],1700000000000000000)
  self.assertNotIn(25,C.CAPS)
 def test_clock_missing_duplicate_unicode_noncanonical_refused_before_setter(self):
  g=self.guest()
  bad=['root=/dev/vda','cachy_asahi_updater_epoch=1700000000 cachy_asahi_updater_epoch=1700000000','cachy_asahi_updater_epoch=01700000000','cachy_asahi_updater_epoch=+1700000000','cachy_asahi_updater_epoch=١٧٠٠٠٠٠٠٠٠','cachy_asahi_updater_epoch=1699999999','cachy_asahi_updater_epoch=4294967296','x'*65537]
  for raw in bad:
   with self.subTest(raw=raw[:80]),patch.object(os,'getpid',return_value=1),patch.object(os,'getuid',return_value=0),patch.object(os,'geteuid',return_value=0),patch.object(Path,'read_text',return_value=raw),patch.object(g.time,'clock_settime',side_effect=AssertionError('clock must not change')),self.assertRaises(ValueError):g.initialize_launcher_clock()
 def test_clock_worker_and_bad_readback_refused(self):
  g=self.guest()
  with patch.object(os,'getpid',return_value=22),patch.object(Path,'read_text',side_effect=AssertionError('worker no clock IO')),self.assertRaisesRegex(ValueError,'PID1'):g.initialize_launcher_clock()
  for after in(1699999999999999999,1700000002000000000):
   with self.subTest(after=after),self.assertRaisesRegex(ValueError,'readback|handoff failed'):self.clock('cachy_asahi_updater_epoch=1700000000',after)
 def test_qemu_only_appends_exact_source_epoch(self):
  argv=vm.qemu(Path('/Image'),Path('/boot'),Path('/data'),1700000000);self.assertIn('cachy_asahi_updater_epoch=1700000000',argv[argv.index('-append')+1]);self.assertEqual(argv[argv.index('-nic')+1],'none');self.assertEqual(argv[argv.index('-m')+1],'4096')
  for bad in(None,True,1699999999,4294967296,'1700000000'):
   with self.assertRaises(ValueError):vm.qemu(Path('/I'),Path('/B'),Path('/D'),bad)
 def test_exact_clock_receipt_rejects_wrong_launcher_or_shape(self):
  tree=ast.parse(C.read(C.HERE/'vm.py'));fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='protocol');start=next(i for i,n in enumerate(fn.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='clock'for t in n.targets));nodes=fn.body[start:start+3];code=compile(ast.Module(body=nodes,type_ignores=[]),'<exact-source-clock-receipt-predicate>','exec');clock=dict(source='OWNED_QEMU_LAUNCHER_NOT_EXTERNAL_TIME_AUTHORITY',before_ns=0,requested_epoch_s=1700000000,after_ns=1700000000000000001);base=dict(C=C,boot=dict(clock=clock),selection=dict(launcher_epoch_s=1700000000));exec(code,base)
  for field,value in(('source','external-time-server'),('requested_epoch_s',1700000001),('after_ns',1700000002000000000),('before_ns',True)):
   broken=dict(clock);broken[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):exec(code,dict(C=C,boot=dict(clock=broken),selection=dict(launcher_epoch_s=1700000000)))

 def diagnostic(self):
  import adapter
  tree=ast.parse(adapter.SIGNATURE_DIAGNOSTIC);space=dict(Path=Path,need=C.need,os=os,re=__import__('re'),json=json);exec(compile(tree,'<exact-source-failure-data>','exec'),space);return space
 def test_actual_private_metadata_bounded_no_key_content(self):
  from types import SimpleNamespace
  space=self.diagnostic()
  with tempfile.TemporaryDirectory(prefix='composition-',dir='/tmp')as d:
   root=Path(d);trust=root/'trust';trust.mkdir(mode=0o700);(trust/'pubring.kbx').write_bytes(b'PRIVATE_CONTENT_NEVER_EXPORT');args=['pacman','--config',str(root/'pacman.conf'),'--debug','-U','/inputs/inert.pkg.tar.xz'];proc=SimpleNamespace(returncode=1,stdout='private unselected text\n'+'gpg error: No public key\n'*12,stderr='GPGME version: 2.0.0\n');space['signature_failure'](args,proc);value=space['_SIGNATURE_FAILURE_DATA'];text=json.dumps(value);self.assertEqual(value['status'],'FAILED_REQUIRED_SIGNATURE_OPERANDS_NOT_ACCEPTANCE');self.assertEqual(value['trust']['uid'],os.geteuid());self.assertFalse(value['files']['pubring.gpg']['present']);self.assertTrue(value['files']['pubring.kbx']['present']);self.assertNotIn('PRIVATE_CONTENT',text);self.assertNotIn('private unselected text',text);self.assertLessEqual(len(text.encode()),2048);self.assertEqual(len(value['GPGME_messages']),4);self.assertEqual(value['GPGME_messages'][-1],'GPGME version: 2.0.0');self.assertFalse(value['acceptance_authority'])
 def test_failure_data_survives_original_final_json_tail(self):
  import contextlib,io,adapter
  space=self.diagnostic();space['_SIGNATURE_FAILURE_DATA']=dict(schema_version=1,status='SIGNATURE_OPERANDS_UNAVAILABLE_NOT_ACCEPTANCE',error_type='ValueError',acceptance_authority=False)
  raw=adapter.caller((C.ROOT/'scripts/ci/full-root-upgrade-caller/container.py').read_bytes());main=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='main');nodes=main.body[-3:-1];self.assertIsInstance(nodes[1],ast.If);space['result']=dict(status='FAIL',error='unchanged original exception '+('x'*3500));stream=io.StringIO()
  with contextlib.redirect_stdout(stream):exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-original-final-json-plus-data>','exec'),space)
  tail=stream.getvalue().encode()[-4096:];line=next(x for x in tail.splitlines()if x.startswith(b'APPS6_KEYRING_FAILURE_DATA '));self.assertEqual(json.loads(line.split(b' ',1)[1]),space['_SIGNATURE_FAILURE_DATA']);self.assertIn(b'"status": "FAIL"',tail)
 def test_unrelated_failure_or_unsafe_private_path_does_not_grant_authority(self):
  from types import SimpleNamespace
  space=self.diagnostic();proc=SimpleNamespace(returncode=1,stdout='',stderr='');space['signature_failure'](['gpg','--verify','x'],proc);self.assertIsNone(space['_SIGNATURE_FAILURE_DATA']);space['signature_failure'](['pacman','--config','/etc/pacman.conf','-U','x'],proc);self.assertEqual(space['_SIGNATURE_FAILURE_DATA']['status'],'SIGNATURE_OPERANDS_UNAVAILABLE_NOT_ACCEPTANCE');self.assertFalse(space['_SIGNATURE_FAILURE_DATA']['acceptance_authority'])

class OriginalBootWitness(unittest.TestCase):
 def operand(self):
  epoch=1700000000;selection=dict(nonce='a'*32,kernel=dict(release='INERT_NOT_A_BOOT_ACCEPTANCE'),launcher_epoch_s=epoch);boot=dict(event='boot',page_size=16384,kernel=selection['kernel']['release'],architecture='aarch64',kernel_profile_sha256=C.sha(C.encoded(selection['kernel'])),nofile=dict(before=[1024,8192],after=[8192,8192]),clock=dict(source='OWNED_QEMU_LAUNCHER_NOT_EXTERNAL_TIME_AUTHORITY',before_ns=0,requested_epoch_s=epoch,after_ns=epoch*10**9+1));return selection,boot
 def wire(self,s,boot):
  prefix=('APPS6_UPDATE16K '+s['nonce']+' ').encode();line=prefix+json.dumps(boot,sort_keys=False,separators=(', ',': ')).encode()+b'\r\n';raw=b'UNEXPORTED KERNEL PREFIX\r\n'+line+prefix+b'INERT NOT RESULT\r\n'+prefix+b'INERT NOT EXIT\r\n';return raw,line
 def test_exact_original_wire_bytes_not_reconstructed_or_accepting_VM(self):
  s,b=self.operand();raw,line=self.wire(s,b);v=vm.boot_witness(raw,s);self.assertEqual(base64.b64decode(v['line']['base64'],validate=True),line);self.assertEqual(v['line']['sha256'],C.sha(line));self.assertEqual(v['offset'],raw.index(line));self.assertEqual(v['stdout'],dict(bytes=len(raw),sha256=C.sha(raw)));self.assertIn('SOURCE_ENFORCED',v['membership'])
  with self.assertRaises((ValueError,KeyError)):vm.protocol(raw,s,lambda *a:None)
 def test_missing_duplicate_wrong_nonce_and_oversize_boot_refuse(self):
  s,b=self.operand();raw,line=self.wire(s,b)
  for bad in(raw.replace(line,b''),raw+line,raw.replace(('APPS6_UPDATE16K '+s['nonce']).encode(),b'APPS6_UPDATE16K '+b'b'*32,1),raw.replace(line,line[:-2]+b' '*4096+b'\r\n')):
   with self.assertRaises(ValueError):vm.boot_witness(bad,s)
 def test_wrong_clock_kernel_profile_and_types_refuse(self):
  s,b=self.operand()
  for field,value in(('page_size',4096),('kernel','WRONG'),('architecture','x86_64'),('kernel_profile_sha256','0'*64)):
   broken=dict(b);broken[field]=value;raw,_=self.wire(s,broken)
   with self.subTest(field=field),self.assertRaises(ValueError):vm.boot_witness(raw,s)
  for field,value in(('requested_epoch_s',1700000001),('requested_epoch_s',True),('after_ns',1700000002000000000),('before_ns',True)):
   broken=dict(b,clock=dict(b['clock']));broken['clock'][field]=value;raw,_=self.wire(s,broken)
   with self.subTest(field=field),self.assertRaises(ValueError):vm.boot_witness(raw,s)
 def test_exact_source_inverse_and_success_only_separate_metadata(self):
  new=C.read(C.HERE/'vm.py');before=pre_boot_witness(new);self.assertNotIn(b'def boot_witness(',before);self.assertIn(b'guest=result,kernel=profile,source=',before);self.assertEqual(new.count(b'launcher_realtime=boot_witness(uart,selection)'),1)
  tree=ast.parse(new);run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run');calls=[(n.lineno,n.func.id)for n in ast.walk(run)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id in('protocol','boot_witness')];self.assertLess(next(n for n,k in calls if k=='protocol'),next(n for n,k in calls if k=='boot_witness'))

if __name__=='__main__':unittest.main(verbosity=2)
