# SPDX-License-Identifier: MIT
"""Original stdout/stderr/retirement preservation in pure PID1 source controls."""
import ast,base64,hashlib,importlib.util,io,json,os,resource,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
NONCE='a'*32

def need(ok,why):
 if not ok:raise ValueError(why)
def functions(path):
 tree=ast.parse(path.read_bytes());return {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
def guest(row,stdout,stderr,error=None):
 events=[]
 C=NS(need=need,decode=json.loads,read=lambda p:json.dumps(dict(nonce=NONCE,kernel={'release':'test-kernel'},kernel_profile_sha256='b'*64)).encode(),load=lambda *a:NS(run_command=lambda *a:(row,stdout,stderr,error)),PASS='TEST_PASS')
 scope=dict(supervised_progress=lambda runtime,selection,nonce:runtime.run_command(None),resource=NS(RLIMIT_NOFILE=resource.RLIMIT_NOFILE,getrlimit=lambda _: (8192,8192),setrlimit=lambda *a:None),C=C,json=json,base64=base64,hashlib=hashlib,Path=Path,ctypes=NS(CDLL=lambda *a,**k:NS(prctl=lambda *a:0)),os=NS(getpid=lambda:1,getuid=lambda:0,geteuid=lambda:0,sysconf=lambda n:16384,uname=lambda:NS(release='test-kernel'),path=NS(ismount=lambda p:False)),emit=lambda nonce,value:events.append((nonce,value)))
 funcs=functions(HERE/'guest.py');exec(compile(ast.Module(body=[funcs[n] for n in ('inner_failure_report','child_failure','observer_file_limit','run')],type_ignores=[]),'<exact-proposed-guest>','exec'),scope)
 return scope,events

def row(stdout=b'',stderr=b'',**values):
 result=dict(argv=['original-child','worker'],exit_code=1,group_absence_verified=True,seconds=1.25,time_limit=10500,output_limit=512*1024,
  stdout_bytes=len(stdout),stdout_sha256=hashlib.sha256(stdout).hexdigest(),stderr_bytes=len(stderr),stderr_sha256=hashlib.sha256(stderr).hexdigest());result.update(values);return result
class Controls(unittest.TestCase):
 def test_original_exit_and_group_failures_emit_before_unchanged_refusal(self):
  out=b'original stdout\x00\xff';err=b'actual worker traceback\n';original=row(out,err)
  for changed in (original,dict(original,exit_code=0,group_absence_verified=False)):
   scope,events=guest(changed,out,err)
   with self.assertRaisesRegex(ValueError,'lifecycle child exit/group retirement failed'):scope['run']()
   self.assertEqual([v['event'] for _,v in events],['boot','child-failure']);self.assertEqual(events[-1][0],NONCE)
   diagnostic=events[-1][1];self.assertIs(diagnostic['supervisor_record'],changed)
   for name,raw in (('stdout',out),('stderr',err)):
    self.assertEqual(base64.b64decode(diagnostic[name]['preview_base64']),raw);self.assertEqual(diagnostic[name]['sha256'],hashlib.sha256(raw).hexdigest());self.assertFalse(diagnostic[name]['truncated'])
 def test_original_error_full_hash_preview_and_output_caps(self):
  out=b'x'*(400*1024);err=b'y'*(112*1024);error=ValueError('original supervisor failure');scope,events=guest(row(out,err,exit_code=0),out,err,error)
  with self.assertRaisesRegex(ValueError,'lifecycle child'):scope['run']()
  value=events[-1][1]
  for key,raw in (('stdout',out),('stderr',err)):
   self.assertEqual(value[key]['bytes'],len(raw));self.assertEqual(value[key]['preview_bytes'],65536);self.assertTrue(value[key]['truncated']);self.assertEqual(base64.b64decode(value[key]['preview_base64']),raw[:65536]);self.assertEqual(value[key]['sha256'],hashlib.sha256(raw).hexdigest())
  self.assertEqual(value['error']['type'],'ValueError');self.assertEqual(value['error']['sha256'],hashlib.sha256(str(error).encode()).hexdigest());self.assertLess(len(json.dumps(value)),512*1024)
  with self.assertRaisesRegex(ValueError,'capture bound'):scope['child_failure']({},out+b'x',err,None,'test')
 def test_closed_worker_failure_is_diagnostic_and_still_refuses(self):
  out=('GNU_INSTALLED16K '+NONCE+' {}\n').encode();err=b'unexpected stderr';scope,events=guest(row(out,err,exit_code=0),out,err)
  with self.assertRaisesRegex(ValueError,'one closed worker result only'):scope['run']()
  self.assertEqual(events[-1][1]['phase'],'closed-worker-result');self.assertEqual(events[-1][1]['status'],'FAIL')
 def test_valid_worker_has_no_extra_record_and_original_success_bytes(self):
  out=('GNU_INSTALLED16K '+NONCE+' {"event":"result","original":"unchanged"}\n').encode();scope,events=guest(row(out,exit_code=0),out,b'');capture=io.StringIO()
  with patch.object(subprocess,'run',return_value=NS(returncode=0)),patch('sys.stdout',capture):scope['run']()
  self.assertEqual(capture.getvalue().encode(),out);self.assertEqual([v['event'] for _,v in events],['boot','exit']);self.assertNotIn('child-failure',capture.getvalue())
 def test_identity_literal_counts_budgets_and_worker_body_unchanged(self):
  root=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());original=root/'scripts/ci/glibc-gnu-provider-installed16k/guest.py';raw=original.read_text();new=(HERE/'guest.py').read_text()
  for text,count in (('/installed16k',7),('GNU_INSTALLED16K',4),('caa_gnu_installed16k=1',1)):self.assertEqual(new.count(text),count)
  self.assertEqual(hashlib.sha256(ast.get_source_segment((HERE/'guest.py').read_text(),functions(HERE/'guest.py')['worker']).encode()).hexdigest(),'cf850dfc98c5988407dcebe6fe5a059ea3d3fd648ec05fa36725985ecceb9fda')
  self.assertIn(',10500,512*1024)',new);self.assertIn("len(raw)<=512*1024",new)
class InnerReport(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'result.json';self.calls=[]
  root=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());spec=importlib.util.spec_from_file_location('original_read_contract',root/'scripts/ci/glibc-gnu-provider-installed16k/contract.py');reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
  self.scope,self.events=guest(row(),b'',b'');self.scope['C'].decode=reader.decode
  def read(path,cap):
   self.assertEqual(path,'/out/result.json');self.assertEqual(cap,8*1024**2);self.calls.append((path,cap));return reader.read(self.path,cap)
  self.scope['C'].read=read
  no=patch.object(subprocess,'Popen',side_effect=AssertionError('no actor'));no.start();self.addCleanup(no.stop)
 def capture(self,original=None):return self.scope['inner_failure_report'](dict(group_absence_verified=True) if original is None else original)
 def save(self,value):
  raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();self.path.write_bytes(raw);return raw
 def test_original_fail_report_rawbytes_and_error_fields_join(self):
  value=dict(status='FAIL',error_type='ValueError',error='INERT original failure',cases={'pristine':{}},commands=[]);raw=self.save(value);v=self.capture()
  self.assertEqual(v['status'],'READ_ORIGINAL_INNER_REPORT_DIAGNOSTIC_ONLY');self.assertEqual(v['raw']['bytes'],len(raw));self.assertEqual(v['raw']['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(base64.b64decode(v['raw']['preview_base64']),raw)
  for k in ('status','error_type','error'):self.assertEqual(v['fields'][k]['preview_utf8'],value[k]);self.assertFalse(v['fields'][k]['truncated'])
  self.assertEqual(v['acceptance'],'FORBIDDEN_DIAGNOSTIC_ONLY_NO_COMPLETION');self.assertEqual(self.calls,[('/out/result.json',8*1024**2)])
 def test_missing_invalid_json_duplicate_and_nonobject_report_are_explicit(self):
  self.assertEqual(self.capture()['status'],'MISSING_ORIGINAL_INNER_REPORT')
  for raw in (b'{broken',b'[]',b'{"status":"FAIL","status":"PASS"}',b'{"status":NaN}'):
   self.path.write_bytes(raw);v=self.capture();self.assertEqual(v['status'],'INVALID_ORIGINAL_INNER_REPORT');self.assertEqual(v['raw']['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(base64.b64decode(v['raw']['preview_base64']),raw)
 def test_over_cap_symlink_and_hardlink_fail_original_ordinary_read(self):
  with self.path.open('wb') as f:f.truncate(8*1024**2+1)
  v=self.capture();self.assertEqual(v['status'],'UNREADABLE_OR_OVER_CAP_INNER_REPORT');self.assertNotIn('raw',v);self.path.unlink()
  target=self.path.with_name('held');target.write_bytes(b'{}');self.path.symlink_to(target)
  self.assertEqual(self.capture()['status'],'UNREADABLE_OR_OVER_CAP_INNER_REPORT');self.path.unlink();os.link(target,self.path)
  self.assertEqual(self.capture()['status'],'UNREADABLE_OR_OVER_CAP_INNER_REPORT')
 def test_live_unknown_or_nonboolean_retirement_does_not_read_report(self):
  for original in ({},{'group_absence_verified':False},{'group_absence_verified':1}):
   self.assertEqual(self.capture(original)['status'],'UNAVAILABLE_UNRETIRED_CHILD')
  self.assertEqual(self.calls,[])
 def test_full_bounded_raw_hash_and_first64k_preview_are_distinct(self):
  error='\x01'*100000;raw=self.save(dict(status='FAIL',error_type='INERT',error=error,unused='x'*(7*1024**2)));self.assertLess(len(raw),8*1024**2);v=self.capture()
  self.assertEqual(v['raw']['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(v['raw']['bytes'],len(raw));self.assertTrue(v['raw']['truncated']);self.assertEqual(v['raw']['preview_bytes'],65536);self.assertEqual(base64.b64decode(v['raw']['preview_base64']),raw[:65536]);self.assertEqual(v['fields']['error']['preview_utf8'],error[:4096]);self.assertTrue(v['fields']['error']['truncated'])
 def test_failure_event_with_all_original_previews_stays_under512k(self):
  self.save(dict(status='\x01'*100000,error_type='\x02'*100000,error='\x03'*100000));out=b'o'*(400*1024);err=b'e'*(112*1024);v=self.scope['child_failure'](row(out,err),out,err,ValueError('e'*100000),'exit-or-retirement')
  self.assertLessEqual(len(json.dumps(v,sort_keys=True,separators=(',',':'))),512*1024);self.assertEqual(v['stdout']['sha256'],hashlib.sha256(out).hexdigest());self.assertEqual(v['stderr']['sha256'],hashlib.sha256(err).hexdigest());self.assertEqual(v['inner_report']['status'],'READ_ORIGINAL_INNER_REPORT_DIAGNOSTIC_ONLY')
 def test_missing_or_wrong_typed_fields_are_not_invented(self):
  self.save(dict(status={'untrusted':'object'},error=None));v=self.capture();self.assertEqual(v['fields']['status'],dict(status='INVALID_FIELD_TYPE',type='dict'));self.assertEqual(v['fields']['error'],dict(status='INVALID_FIELD_TYPE',type='NoneType'));self.assertEqual(v['fields']['error_type'],dict(status='MISSING_FIELD'))
  self.save(dict(status='FAIL',error='\ud800'));v=self.capture();self.assertEqual(v['fields']['error'],dict(status='INVALID_UTF8_FIELD'));self.assertIn('raw',v)

class ObserverDescriptors(unittest.TestCase):
 def test_pid1_sets_exact_native_limit_before_child_and_exports_readback(self):
  scope,events=guest(row(),b'',b'');sequence=[];values=iter(((1024,4096),(8192,8192)))
  scope['resource']=NS(RLIMIT_NOFILE=resource.RLIMIT_NOFILE,getrlimit=lambda key:(sequence.append(('get',key)) or next(values)),setrlimit=lambda key,value:sequence.append(('set',key,value)))
  with self.assertRaisesRegex(ValueError,'lifecycle child exit/group retirement failed'):scope['run']()
  self.assertEqual(sequence,[('get',resource.RLIMIT_NOFILE),('set',resource.RLIMIT_NOFILE,(8192,8192)),('get',resource.RLIMIT_NOFILE)])
  self.assertEqual(events[0][1]['observer_nofile'],dict(before=[1024,4096],after=[8192,8192],scope='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD'))
 def test_limit_set_or_readback_failure_refuses_before_boot_or_child(self):
  for kind in ('refused','wrong-readback'):
   scope,events=guest(row(),b'',b'');calls=[]
   def setting(*_):
    if kind=='refused':raise PermissionError('inert refused limit')
   scope['resource']=NS(RLIMIT_NOFILE=resource.RLIMIT_NOFILE,getrlimit=lambda _:(1024,4096),setrlimit=setting)
   scope['C'].load=lambda *a:calls.append(a)
   with self.subTest(kind=kind),self.assertRaises((PermissionError,ValueError)):scope['run']()
   self.assertEqual(events,[]);self.assertEqual(calls,[])
 def test_unchanged_full_observer_fails1024_and_closes1500_groups_at8192(self):
  root=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());path=root/'scripts/update/full_root.py';spec=importlib.util.spec_from_file_location('finite_descriptor_regression',path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
  before=resource.getrlimit(resource.RLIMIT_NOFILE);self.assertGreaterEqual(before[1],8192);fd_before=set(os.listdir('/proc/self/fd'));results=[]
  with tempfile.TemporaryDirectory(prefix='observer-descriptors-') as temporary,patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):
   target=Path(temporary)
   for n in range(1500):
    first=target/('%04da'%n);first.write_bytes(b'inert never executed');os.link(first,target/('%04db'%n))
   try:
    for soft in (1024,8192):
     resource.setrlimit(resource.RLIMIT_NOFILE,(soft,before[1]));results.append(module.observe(target,limits=module.Limits(deadline=time.monotonic()+30),hardlinks='generic-development-internal'))
   finally:resource.setrlimit(resource.RLIMIT_NOFILE,before)
  self.assertFalse(results[0]['complete']);self.assertEqual(results[0]['unsupported_counts'],{'filesystem-observation-failed':1});self.assertLess(results[0]['footprint']['hardlink_inodes'],1500)
  self.assertTrue(results[1]['complete']);self.assertEqual(results[1]['unsupported_counts'],{});self.assertEqual(len(results[1]['hardlink_groups']),1500);self.assertEqual(results[1]['footprint']['hardlink_entries'],3000);self.assertTrue(all(group['nlink']==2 and len(group['members'])==2 for group in results[1]['hardlink_groups'].values()));self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE),before);self.assertEqual(set(os.listdir('/proc/self/fd')),fd_before)
 def test_worker_and_observer_source_and_all_existing_limits_stay_exact(self):
  text=(HERE/'guest.py').read_text();worker=ast.get_source_segment(text,functions(HERE/'guest.py')['worker']);self.assertEqual(len(worker.encode()),2992);self.assertEqual(hashlib.sha256(worker.encode()).hexdigest(),'cf850dfc98c5988407dcebe6fe5a059ea3d3fd648ec05fa36725985ecceb9fda');self.assertIn(',10500,512*1024)',text)
  root=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file());self.assertIn('--ulimit=nofile=8192:8192',(root/'scripts/ci/glibc-gnu-provider-lifecycle/run.py').read_text());self.assertIn('resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))',text)

if __name__=='__main__':unittest.main(verbosity=2)
