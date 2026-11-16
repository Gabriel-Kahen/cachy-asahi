# SPDX-License-Identifier: MIT
"""Fenced MODEL launcher controls. No HTTP/process/privilege/native execution."""
import ast,copy,hashlib,importlib.util,json,os
from pathlib import Path
import sys,tempfile,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
MODULE=HERE/'payload/native/hosted_current_v3.py'
s=importlib.util.spec_from_file_location('FENCED_current_hosted',MODULE);L=importlib.util.module_from_spec(s);s.loader.exec_module(L)
MEMBER='scripts/ci/first-login-enrollment-native-source/payload/native/hosted_current_v3.py'
CONTEXT='''import json,hashlib
from pathlib import Path
ENV=('GITHUB_SHA','GITHUB_REF')
def validate_delegation(raw,sha,now=None):
 assert hashlib.sha256(raw).hexdigest()==sha
 d=json.loads(raw);assert d['approved'] is True
 return d
def source(d,root):
 m=json.loads((root/'source-map.json').read_bytes())
 assert hashlib.sha256((root/'source-map.json').read_bytes()).hexdigest()==d['binding']['source_lock']['sha256']
 assert {str(p.relative_to(root))for p in root.rglob('*')if p.is_file()}==set(m['files'])|{'source-map.json'}
 for n,row in m['files'].items():
  raw=(root/n).read_bytes();assert row==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=420)
 for row in [d['policy'],*d['programs'].values(),*d['materials'].values()]:
  assert {k:m['files'][row['member']][k]for k in ('bytes','sha256')}=={k:row[k]for k in ('bytes','sha256')}
 return root,m['files']
'''
EXECUTOR="API='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'\ndef validate_policy(policy,d):return policy['executor_current_v3']\ndef probe_tools():return dict(missing_or_invalid=False)\n"
OWNER="API='CURRENT_ONBOARDING_DELEGATED_OWNER_V3'\ndef run_owned_current_v3(*,delegation_raw,delegation_sha256,context,source_root,inputs,executor,output,public_output):raise AssertionError('MODEL owner must not run')\n"
ASSEMBLER="def validate_hosted_inputs_v3(*,inputs,delegation,source_root):\n assert inputs['owner_inputs']['image_inputs']['qualified_seed']=='FENCED_MODEL_SIGNED349'\n return dict(valid=True,required_refs=inputs['staged_refs'])\n"


def fence(event,args):
 if event.startswith(('subprocess.','socket.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
  raise AssertionError('FENCED no operational role: '+event)
sys.addaudithook(fence);sys.addaudithook(L.validation_fence)


class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='FENCED-current-hosted-');self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)
  self.root=self.base/'source';self.main=self.base/'main';self.staged=self.base/'staged'
  for p in (self.root,self.main,self.staged):p.mkdir(mode=0o700)
  self.files={MEMBER:MODULE.read_bytes(),'context.py':CONTEXT.encode(),'executor.py':EXECUTOR.encode(),'owner.py':OWNER.encode(),'assembler.py':ASSEMBLER.encode(),
   'owned.py':(HERE.parents[1]/'virtual/owned_process.py').read_bytes(),
   'policy.json':L.encoded(dict(executor_current_v3=dict(controller=L.SCOPE,controller_AS_bytes=512*1024**2,controller_seconds=7560)))}
  p=self.main/MEMBER;p.parent.mkdir(parents=True);p.write_bytes(MODULE.read_bytes())
  payload=self.staged/'genuine-MODEL-DATA';payload.write_bytes(b'FENCED ONLY NO REAL ARCHIVE')
  self.inputs=dict(image_inputs=dict(qualified_seed='FENCED_MODEL_SIGNED349',required_refs=[dict(path=str(payload),**L.pin(payload.read_bytes()))]),stage_inputs={})
  self.wrapper=self.staged/'inputs.json';self.now=int(time.time());self.rebuild()
 def rebuild(self):
  for n,raw in self.files.items():
   p=self.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
  self.wrapper.write_bytes(L.encoded(dict(schema=3,kind='ROOT_STAGED_CURRENT_INPUTS_V3',owner_inputs=self.inputs,staged_refs=copy.deepcopy(self.inputs['image_inputs']['required_refs']))))
  def row(n):return dict(member=n,**L.pin(self.files[n]))
  mapping=dict(files={n:dict(**L.pin(raw),mode=420)for n,raw in self.files.items()})
  raw=L.encoded(mapping);(self.root/'source-map.json').write_bytes(raw)
  self.d=dict(approved=True,nonce='a'*64,binding=dict(source='b'*40,ref='refs/heads/codex/MODEL-current',source_lock=L.pin(raw)),expires_epoch=self.now+10000,
    programs=dict(context=row('context.py'),owner=row('owner.py'),image_executor=row('executor.py'),hosted_launcher=row(MEMBER),owned_process=row('owned.py'),inputs_assembler=row('assembler.py')),
    materials={},policy=row('policy.json'),hosted=dict(repository='Gabriel-Kahen/cachy-asahi',job_key='current',workflow_ref='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-current-onboarding-delegated-v3.yml@refs/heads/codex/MODEL-current',workflow_sha='b'*40))
  raw_d=L.encoded(self.d);self.r=dict(schema=3,kind='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3',issuer='Root',approved=True,trusted_main_commit='c'*40,
    launcher=row(MEMBER),delegation_json=raw_d.decode(),delegation_pin=L.pin(raw_d),staged_inputs=dict(path=str(self.wrapper),**L.pin(self.wrapper.read_bytes())),
    staged_root=str(self.staged),control_name='cachy-current-hosted-'+self.d['nonce'],authorization=dict(jobs_metadata=True,privileged_controller=True,launcher_limits=L.LIMITS))
  self.env=dict(GITHUB_WORKSPACE=str(self.root),RUNNER_TEMP=str(self.base),GITHUB_SHA='b'*40,GITHUB_REF=self.d['binding']['ref'],GITHUB_RUN_ATTEMPT='1',GITHUB_REPOSITORY=self.d['hosted']['repository'],GITHUB_JOB='current',GITHUB_WORKFLOW_REF=self.d['hosted']['workflow_ref'],GITHUB_WORKFLOW_SHA='b'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',RUNNER_ENVIRONMENT='github-hosted',GITHUB_ACTIONS='true')
  self.control=self.base/self.r['control_name']
 def preflight(self):
  with patch.object(L.os,'uname',return_value=SimpleNamespace(sysname='Linux',machine='aarch64')),patch.object(L,'fixed_tool',return_value=dict(FENCED='NOT_OBSERVED')):
   return L.preflight(self.r,self.root,self.main,self.control,self.env,self.now)
 def test_real_file_pins_main_source_owner_assembler_and_staged_bodies(self):
  p=self.preflight();self.assertEqual(p.inputs,self.inputs);self.assertEqual(p.intake['files'],1);self.assertFalse(self.control.exists())
 def test_missing_owner_callback_assembler_or_required_inputs_hold_preprivilege(self):
  cases={'owner.py':b'def old_owner():pass\n','assembler.py':b'def old_assembler():pass\n'}
  for name,raw in cases.items():
   original=self.files[name]
   try:
    self.files[name]=raw;self.rebuild()
    with self.subTest(name=name),self.assertRaises(ValueError):self.preflight()
   finally:self.files[name]=original;self.rebuild()
  self.inputs['image_inputs'].pop('qualified_seed');self.rebuild()
  with self.assertRaises(KeyError):self.preflight()
  self.assertFalse(self.control.exists())
 def test_pure_assembler_cannot_spawn_or_write(self):
  for raw in (b'import subprocess\ndef validate_hosted_inputs_v3(**kwargs):subprocess.run(["NEVER"])\n',
              b'from pathlib import Path\ndef validate_hosted_inputs_v3(**kwargs):Path("NEVER").write_text("x")\n'):
   self.files['assembler.py']=raw;self.rebuild()
   with self.assertRaises((ValueError,AssertionError)):self.preflight()
  self.assertFalse((self.base/'NEVER').exists())
 def test_staged_missing_changed_alias_duplicate_private_or_outside_refuses(self):
  original=copy.deepcopy(self.inputs)
  for mode in ('missing','changed','outside','duplicate','private'):
   self.inputs=copy.deepcopy(original);ref=self.inputs['image_inputs']['required_refs'][0]
   if mode=='missing':ref['path']=str(self.staged/'ABSENT')
   elif mode=='changed':ref['sha256']='0'*64
   elif mode=='outside':ref['path']=str(self.base/'outside');Path(ref['path']).write_bytes(b'FENCED ONLY NO REAL ARCHIVE')
   elif mode=='duplicate':self.inputs['image_inputs']['required_refs'].append(copy.deepcopy(ref))
   else:
    p=self.staged/'.gnupg';p.mkdir();f=p/'public-looking';f.write_bytes(b'FENCED ONLY NO REAL ARCHIVE');ref['path']=str(f)
   self.rebuild()
   with self.subTest(mode=mode),self.assertRaises((ValueError,FileNotFoundError)):self.preflight()
  self.inputs=original;ref=self.inputs['image_inputs']['required_refs'][0];p=Path(ref['path']);p.unlink();p.symlink_to(self.base/'outside');self.rebuild()
  with self.assertRaises(ValueError):self.preflight()
 def test_wrong_actual_source_workspace_workflow_and_attempt_hold_before_metadata(self):
  for key in ('GITHUB_SHA','GITHUB_REF','GITHUB_WORKSPACE','GITHUB_WORKFLOW_SHA','GITHUB_RUN_ATTEMPT','RUNNER_ARCH'):
   old=self.env[key];self.env[key]='WRONG'
   with self.subTest(key=key),self.assertRaises(ValueError):self.preflight()
   self.env[key]=old
 def test_changed_controller_policy_or_insufficient_delegation_lifetime_refuses(self):
  old=self.files['policy.json'];p=L.decode(old);p['executor_current_v3']['controller_seconds']=7561;self.files['policy.json']=L.encoded(p);self.rebuild()
  with self.assertRaises(ValueError):self.preflight()
  self.files['policy.json']=old;self.rebuild();d=L.decode(self.r['delegation_json']);d['expires_epoch']=self.now+7000
  raw=L.encoded(d);self.r.update(delegation_json=raw.decode(),delegation_pin=L.pin(raw))
  with self.assertRaises(ValueError):self.preflight()
 def test_empty_source_control_and_request_stay_refused(self):
  empty=self.base/'empty.py';empty.write_bytes(b'');row=dict(member='empty.py',**L.pin(b''))
  with self.assertRaises(ValueError):L.descriptor(row)
  with self.assertRaises(ValueError):L.program(self.base,row,'NEVER_EMPTY_SOURCE')
  with self.assertRaises(ValueError):L.read(empty)
  with self.assertRaises(ValueError):L.request(empty,L.pin(b'')['sha256'])
  self.assertEqual(L.whole(L.pin(b''),allow_empty=True),L.pin(b''))
  for bad in [dict(bytes=0,sha256='0'*64),dict(bytes=False,sha256=L.pin(b'')['sha256']),dict(L.pin(b''),extra=True)]:
   with self.assertRaises(ValueError):L.whole(bad,allow_empty=True)
 def test_root_request_external_hash_limits_unknown_and_unissued_refuse(self):
  path=self.base/'request.json';path.write_bytes(L.encoded(self.r));sha=L.pin(path.read_bytes())['sha256'];self.assertEqual(L.request(path,sha),self.r)
  with self.assertRaises(ValueError):L.request(path,'0'*64)
  for key in ('approved','authorization','launcher','trusted_main_commit'):
   r=copy.deepcopy(self.r);r[key]=None;path.write_bytes(L.encoded(r))
   with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):L.request(path,L.pin(path.read_bytes())['sha256'])
  path.write_bytes(b'x'*49153)
  with self.assertRaises(ValueError):L.request(path,L.pin(path.read_bytes())['sha256'])
 def test_exact_scope_direct_argv_and_no_shell_or_environment_injection(self):
  p=self.preflight();argv=L.scope_argv(p,self.base/'request','d'*64,self.base/'context','e'*64,self.base/'inputs','f'*64)
  self.assertEqual(argv[:4],['/usr/bin/sudo','-n','/usr/bin/systemd-run','--scope'])
  for value in ('MemoryMax=536870912','MemorySwapMax=0','CPUQuota=100%','TasksMax=64','RuntimeMaxSec=7560s','TimeoutStopSec=10s'):self.assertIn('--property='+value,argv)
  self.assertIn('--unit=cachy-current-controller-'+'a'*64+'.scope',argv)
  self.assertNotIn('/bin/sh',argv);self.assertNotIn('/usr/bin/bash',argv);self.assertNotIn('GH_TOKEN',' '.join(argv));self.assertEqual(argv.count('--request-sha256'),1)
 def test_supervision_transfers_immediately_and_requires_natural_absence(self):
  class Owned:
   def __init__(self):self.prepared=False;self.row=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0,output=b'FENCED')
   def prepare(self):self.prepared=True
   def supervise(self,child,**kw):return self.row
  o=Owned();calls=[]
  def spawn(argv,**kw):
   self.assertTrue(o.prepared);calls.append((argv,kw));kw['stderr'].write(b'FENCED diagnostic');return SimpleNamespace(stdout=None)
  model_stderr=tempfile.TemporaryFile();self.addCleanup(model_stderr.close)
  with patch.object(L.os,'memfd_create',side_effect=lambda *args:os.dup(model_stderr.fileno()),create=True),patch.object(L.os,'MFD_CLOEXEC',1,create=True),patch.object(L.os,'MFD_ALLOW_SEALING',2,create=True),patch.multiple(L.fcntl,F_ADD_SEALS=1033,F_SEAL_GROW=4,F_SEAL_SHRINK=2,create=True),patch.object(L.fcntl,'fcntl',return_value=0),patch.object(L.subprocess,'Popen',side_effect=spawn):
   raw,receipt=L.run(o,['/usr/bin/true'],3,self.base);self.assertEqual(raw,b'FENCED');self.assertTrue(receipt['natural'])
   for key,value in [('signals',['SIGTERM']),('group_census','PRESENT'),('exit',1),('output_complete',False)]:
    old=o.row[key];o.row[key]=value
    with self.subTest(key=key),self.assertRaises(ValueError):L.run(o,['/usr/bin/true'],3,self.base)
    o.row[key]=old
  self.assertEqual(set(calls[0][1]['env']),{'PATH','HOME','TMPDIR','LC_ALL'});self.assertTrue(calls[0][1]['start_new_session']);self.assertNotIn('shell',calls[0][1])
 def test_fixed_jobs_url_no_credentials_headers_redirects_or_retry(self):
  url=L.metadata_url(self.d,'123');calls=[]
  class Connection:
   def request(self,*a,**kw):calls.append((a,kw))
   def getresponse(self):return SimpleNamespace(status=200,read=lambda cap:b'{"MODEL":true}')
   def close(self):pass
  with patch.object(L.http.client,'HTTPSConnection',return_value=Connection()),patch.object(L.ssl,'create_default_context',return_value='FENCED'):
   self.assertEqual(L.fetch_jobs(url,20,1024),b'{"MODEL":true}')
  self.assertEqual(len(calls),1);self.assertNotIn('Authorization',calls[0][1]['headers'])
  for bad in ('https://evil.invalid/jobs',url+'&token=SECRET','http://api.github.com/x'):
   with self.assertRaises(ValueError):L.fetch_jobs(bad,20,1024)
 def test_missing_host_tool_is_not_inferred_from_runner_label(self):
  self.files['executor.py']=EXECUTOR.replace('missing_or_invalid=False','missing_or_invalid=["bsdtar"]').encode();self.rebuild()
  with self.assertRaises(ValueError):self.preflight()
 def test_non200_metadata_refuses_without_reading_headers_or_body(self):
  class Response:
   status=302
   def read(self,cap):raise AssertionError('redirect body read')
  connection=SimpleNamespace(request=lambda *a,**k:None,getresponse=lambda:Response(),close=lambda:None)
  with patch.object(L.http.client,'HTTPSConnection',return_value=connection),patch.object(L.ssl,'create_default_context',return_value='FENCED'),self.assertRaises(ValueError):L.fetch_jobs(L.metadata_url(self.d,'123'),20,1024)
 def test_controller_observation_keeps_actual_limits_and_no_acceptance(self):
  nonce='a'*64;group='/system.slice/cachy-current-controller-'+nonce+'.scope'
  domain=dict(pid=123,starttime=456,cgroup=group,limits=L.SCOPE,executable='/FENCED/python')
  properties=dict(ControlGroup=group,ActiveEnterTimestampMonotonic='1234',RuntimeMaxUSec='2h 6min')
  value=L.controller_observation(domain,properties,nonce,dict(FENCED='MODEL_BINDING'),dict(FENCED='MODEL_POLICY'))
  self.assertIsNone(value['Root_final_acceptance']);self.assertEqual(value['domain']['limits'],L.SCOPE)
  for mode in ('domain','clock','scope'):
   d,p=copy.deepcopy(domain),dict(properties)
   if mode=='domain':d['limits']['memory.max']='max'
   elif mode=='clock':p['ActiveEnterTimestampMonotonic']='0'
   else:p['ControlGroup']='/FOREIGN'
   with self.subTest(mode=mode),self.assertRaises(ValueError):L.controller_observation(d,p,nonce,{}, {})
 def test_workflow_inline_python_and_single_manual_bounded_entry(self):
  path=HERE.parents[2]/'.github/workflows/native-arm-current-onboarding-delegated-v3.yml';text=path.read_text()
  self.assertIn('workflow_dispatch:',text);self.assertNotIn('pull_request:',text);self.assertNotIn('push:',text);self.assertIn('timeout-minutes: 140',text)
  self.assertIn('persist-credentials: false',text);self.assertIn('retention-days: 3',text);self.assertNotIn('secrets.',text)
  self.assertNotIn('run: sudo',text);self.assertEqual(text.count('root_request_json:\n'),1)
  for part in text.split("python3 -I -B - <<'PY'\n")[1:]:
   lines=[]
   for line in part.splitlines():
    if line.strip()=='PY':break
    lines.append(line[10:])
   ast.parse('\n'.join(lines))

class SharedTimingControls(unittest.TestCase):
 def model(self):
  started=time.monotonic();r=dict(delegation_pin=dict(bytes=1,sha256='a'*64),authorization=dict(whole_timing=L.TIMING))
  d=dict(capability=dict(allow_host_prerequisites=True),expires_epoch=int(time.time())+7560,policy=dict(member='policy.json',bytes=1,sha256='b'*64))
  context=dict(binding=dict(source='c'*40,ref='refs/heads/codex/MODEL',run='123',job='456'))
  plan=SimpleNamespace(request=r,d=d,policy=dict(executor_current_v3=dict(setup_seconds=180,stage_seconds=7200,cleanup_seconds=180)))
  plan.timing=L.make_timing(plan,context,started);plan.timing_path=Path('/MODEL/timing.json');plan.timing_sha=L.pin(L.encoded(plan.timing))['sha256'];plan.root=Path('/MODEL/source');d['nonce']='d'*64
  return plan,context
 def test_real_elapsed_is_charged_not_added_and_old_scope_stays7560(self):
  plan,context=self.model();clock=time.monotonic
  before=L.controller_seconds(plan)
  with patch.object(L.time,'monotonic',side_effect=lambda:clock()+495):
   after=L.controller_seconds(plan);self.assertLessEqual(after,before-495)
   self.assertLess(L.available_stage_seconds(plan),7200)
   argv=L.scope_argv(plan,Path('/MODEL/request'),'a'*64,Path('/MODEL/context'),'b'*64,Path('/MODEL/inputs'),'c'*64)
   self.assertIn('--property=RuntimeMaxSec='+str(after)+'s',argv);self.assertIn('--timing-sha256',argv)
  self.assertEqual(L.controller_seconds(SimpleNamespace(d={})),7560)
 def test_scope_identity_directargv_and_explicit495_not8055(self):
  plan,_=self.model();argv=L.prerequisite_argv(plan,Path('/MODEL/request'),'a'*64,Path('/MODEL/context'),'b'*64,Path('/MODEL/environment'),'c'*64)
  self.assertEqual(argv[:4],['/usr/bin/sudo','-n','/usr/bin/systemd-run','--scope'])
  for property in ('MemoryMax=536870912','MemorySwapMax=0','CPUQuota=100%','CPUQuotaPeriodSec=100ms','TasksMax=64','RuntimeMaxSec=495s','KillMode=control-group'):
   self.assertIn('--property='+property,argv)
  self.assertIn('--unit=cachy-current-prerequisites-'+'d'*64+'.scope',argv);self.assertIn('prerequisite',argv)
  self.assertNotIn('/bin/sh',argv);self.assertNotIn('GH_TOKEN',' '.join(argv))
 def test_timing_tamper_root_expiry_otherboot_and_exhaustion_refuse(self):
  plan,context=self.model()
  for key,bad in [('deadline_monotonic',plan.timing['started_monotonic']+8055),('expires_epoch',plan.d['expires_epoch']+495),('binding',{}),('boot_pin',{}),('started_monotonic',float('nan')),('extra',True)]:
   value=copy.deepcopy(plan.timing);value[key]=bad
   with self.subTest(key=key),self.assertRaises(ValueError):L.validate_timing(plan.request,plan.d,context,value)
  with patch.object(L.time,'time',return_value=plan.d['expires_epoch']+1):
   with self.assertRaises(ValueError):L.remaining(plan.timing)
  plan.timing['deadline_monotonic']=time.monotonic()+20
  with self.assertRaises(ValueError):L.controller_seconds(plan)
 def test_physical_controller_runtime_cannot_reextend_shared_deadline(self):
  plan,context=self.model();context['policy_pin']=L.descriptor(plan.d['policy'])
  entered=int(time.monotonic()*1000000);group='/system.slice/cachy-current-controller-'+plan.d['nonce']+'.scope'
  domain=dict(pid=123,starttime=456,cgroup=group,limits=L.SCOPE)
  props=dict(ControlGroup=group,ActiveEnterTimestampMonotonic=str(entered),RuntimeMaxUSec='7000000000')
  E=SimpleNamespace(runtime_microseconds=int)
  self.assertEqual(L.clipped_controller_observation(E,domain,props,plan.d,context,plan.timing)['domain'],domain)
  props['RuntimeMaxUSec']='8055000000'
  with self.assertRaises(ValueError):L.clipped_controller_observation(E,domain,props,plan.d,context,plan.timing)
  props['RuntimeMaxUSec']='7560000000';plan.timing['deadline_monotonic']=time.monotonic()+7000
  with self.assertRaises(ValueError):L.clipped_controller_observation(E,domain,props,plan.d,context,plan.timing)
 def test_actual_helper_missing_dependencies_refuses_before_privilege(self):
  f=Controls('test_real_file_pins_main_source_owner_assembler_and_staged_bodies');f.setUp();self.addCleanup(f.doCleanups)
  helper=HERE/'payload/native/host_prerequisites_current_v3.py';f.files['prerequisites.py']=helper.read_bytes();f.rebuild()
  row=dict(member='prerequisites.py',**L.pin(helper.read_bytes()));f.d['programs']['host_prerequisites']=row;f.d['capability']=dict(allow_host_prerequisites=True)
  Q=L.program(f.root,row,'actual_committed_prerequisite_missing_carrier')
  policy=dict(host_prerequisites_current_v3=Q.PROPOSAL,host_prerequisite_timing_v3=L.TIMING)
  with self.assertRaises(KeyError):L.prerequisite_program(f.root,f.d,policy)
  self.assertFalse(f.control.exists())
 def test_absence_requires_actual_cgroup_gone_twice(self):
  with patch.object(L.Path,'exists',side_effect=[True,False,True,False,False]),patch.object(L.time,'sleep'):
   self.assertTrue(L.prerequisite_absent('a'*64,time.monotonic()+10)['absent_twice'])
  clock=[0]
  def now():clock[0]+=1;return clock[0]
  with patch.object(L.Path,'exists',return_value=True),patch.object(L.time,'sleep'),patch.object(L.time,'monotonic',side_effect=now):
   with self.assertRaises(ValueError):L.prerequisite_absent('a'*64,100)


PREREQUISITE_FIXTURE=os.environ.get('CACHY_HOST_PREREQUISITE_FIXTURE')
if PREREQUISITE_FIXTURE:
 class RealPrerequisiteControls(unittest.TestCase):
  """Actual committed helper and three exact donor blobs; modeled roles only."""
  def setUp(self):
   self.f=Controls('test_real_file_pins_main_source_owner_assembler_and_staged_bodies');self.f.setUp();self.addCleanup(self.f.doCleanups);f=self.f
   helper=HERE/'payload/native/host_prerequisites_current_v3.py';f.files['prerequisites.py']=helper.read_bytes()
   self.names=('systemd-run','systemctl','dockerd','docker','fallocate','losetup','mkfs.ext4','mount','umount','python3','gpg','gpgconf','gpg-connect-agent','bsdtar','zstd','env')
   executor=EXECUTOR+"def checked_tool(row):return row['path']\nNAMES="+repr(self.names)+"\nMISSING=True\ndef probe_tools():return dict(missing_or_invalid=['bsdtar'] if MISSING else [],tools={n:dict(selected=dict(path='/usr/bin/'+n)) for n in NAMES if n!='bsdtar' or not MISSING})\n"
   f.files['executor.py']=executor.encode();f.rebuild()
   Q=L.program(f.root,dict(member='prerequisites.py',**L.pin(helper.read_bytes())),'actual_committed_prerequisite_fixture')
   policy=L.decode(f.files['policy.json']);policy.update(host_prerequisites_current_v3=Q.PROPOSAL,host_prerequisite_timing_v3=L.TIMING)
   policy['executor_current_v3'].update(setup_seconds=180,stage_seconds=7200,cleanup_seconds=180)
   f.files['policy.json']=L.encoded(policy)
   role_names={'host_prerequisite_plan':'host_prerequisites.py','host_prerequisite_tools':'host_tools.py','host_prerequisite_runner_basis':'hosted_owner.py'}
   for role,name in role_names.items():
    raw=L.read(Path(PREREQUISITE_FIXTURE).resolve()/name,128*1024);size,sha=Q.DONORS[role];self.assertEqual(L.pin(raw),dict(bytes=size,sha256=sha));f.files['donors/'+name]=raw
   f.files['context.py']+=b'\ndef validate_context(d,c):assert c["MODEL"] is True\n'
   f.rebuild();f.d['capability']=dict(allow_host_prerequisites=True);f.d['context_limits']=dict(metadata_query_seconds=15,metadata_max_bytes=1024**2);f.env['GITHUB_RUN_ID']='123';f.env['GITHUB_EVENT_NAME']='workflow_dispatch';f.d['expires_epoch']=f.now+7560
   f.d['programs']['host_prerequisites']=dict(member='prerequisites.py',**L.pin(helper.read_bytes()))
   for role,name in role_names.items():f.d['programs'][role]=dict(member='donors/'+name,**L.pin(f.files['donors/'+name]))
   raw=L.encoded(f.d);f.r.update(delegation_json=raw.decode(),delegation_pin=L.pin(raw));f.r['authorization'].update(host_prerequisites=True,whole_timing=L.TIMING)
  def test_actual_helper_preflight_optin_and_old_missing_cap_strict(self):
   f=self.f;plan=f.preflight();self.assertEqual(plan.Q.API,'CURRENT_ONBOARDING_HOST_PREREQUISITES_V3')
   request=f.base/'request';request.write_bytes(L.encoded(f.r));self.assertEqual(L.request(request,L.pin(request.read_bytes())['sha256']),f.r)
   missing=copy.deepcopy(f.r);missing['authorization'].pop('host_prerequisites');request.write_bytes(L.encoded(missing))
   with self.assertRaisesRegex(ValueError,'launcher authorization'):L.request(request,L.pin(request.read_bytes())['sha256'])
   d=L.decode(f.r['delegation_json']);d['capability'].clear();raw=L.encoded(d);f.r.update(delegation_json=raw.decode(),delegation_pin=L.pin(raw))
   with self.assertRaisesRegex(ValueError,'host tools missing'):f.preflight()
  def test_real_helper_wrapper_gate_executes_no_actor(self):
   f=self.f;plan=f.preflight();request=f.base/'request.json';request.write_bytes(L.encoded(f.r))
   context=dict(MODEL=True,source_root=str(f.root),binding=dict(f.d['binding'],run='123',job='456'),hosted={})
   path=f.base/'context.json';path.write_bytes(L.encoded(context));plan.timing=L.make_timing(plan,context,time.monotonic())
   timing=f.base/'timing.json';timing.write_bytes(L.encoded(plan.timing));environment=f.base/'environment.json';environment.write_bytes(L.encoded({k:'MODEL' for k in L.PREREQUISITE_ENV}))
   f.control.mkdir(mode=0o700);private=f.control/'private';private.mkdir();public=f.control/'public';public.mkdir();request=private/'request.json';request.write_bytes(L.encoded(f.r))
   args=SimpleNamespace(request=request,request_sha256=L.pin(request.read_bytes())['sha256'],source_root=f.root,context=path,context_sha256=L.pin(path.read_bytes())['sha256'],timing=timing,timing_sha256=L.pin(timing.read_bytes())['sha256'],environment=environment,environment_sha256=L.pin(environment.read_bytes())['sha256'],uid=os.getuid(),gid=os.getgid())
   # Invoke the actual whole-pinned helper; its actual infinite MODEL-host
   # rlimits must refuse before kernel entry/Popen. Never substitute its API.
   original=L.prerequisite_program;seen=[]
   def select(*a):
    Q=original(*a);actual=Q.prepare_host_prerequisites
    def call(**kwargs):seen.append(kwargs);return actual(**kwargs)
    Q.prepare_host_prerequisites=call;return Q
   with patch.object(L,'prerequisite_program',side_effect=select),patch.object(L.os,'getuid',return_value=0),patch.object(L.os,'geteuid',return_value=0),patch.object(L.resource,'setrlimit'):
    with self.assertRaisesRegex(ValueError,'finite prerequisite controller rlimit'):L.prerequisite_controller(args)
   self.assertEqual(len(seen),1);self.assertEqual(seen[0]['delegation_raw'],f.r['delegation_json'].encode());self.assertEqual(seen[0]['environment'],{k:'MODEL' for k in L.PREREQUISITE_ENV})
  def test_donor_tamper_and_missing_policy_or_descriptor_hold(self):
   f=self.f;p=f.root/'donors/host_tools.py';p.write_bytes(p.read_bytes()+b'\n')
   with self.assertRaises((ValueError,AssertionError)):f.preflight()
  def test_execution_order_refresh_context_and_clipped_scope(self):
   f=self.f;plan=f.preflight();request=f.base/'launch-request.json';request.write_bytes(L.encoded(f.r))
   args=SimpleNamespace(request=request,request_sha256=L.pin(request.read_bytes())['sha256'],source_root=f.root,main_root=f.main,control_root=f.control)
   binding=dict(f.d['binding'],run='123',job='456');context=dict(binding=binding)
   plan.H.ENV=tuple(f.env);plan.H.capture_context=lambda *a,**kw:dict(context)
   calls=[];offset=[0];mono=time.monotonic;epoch=time.time
   def run(O,argv,cap,work):
    if argv[0]=='/usr/bin/git':return ((f.r['trusted_main_commit'] if str(f.main) in argv else f.d['binding']['source'])+'\n').encode(),dict(MODEL=True)
    if 'metadata' in argv:calls.append('metadata');return b'{"MODEL":true}',dict(MODEL=True)
    if 'prerequisite' in argv:
     calls.append('prerequisite');self.assertIn('--property=RuntimeMaxSec=495s',argv);offset[0]=495;plan.E.MISSING=False
    else:
     calls.append('controller');prop=next(a for a in argv if a.startswith('--property=RuntimeMaxSec='));self.assertNotIn(prop,('--property=RuntimeMaxSec=7560s','--property=RuntimeMaxSec=8055s'))
    return b'',dict(MODEL=True)
   real_read=L.read
   def read(path,*a):
    if str(path).startswith('/var/lib/cachy-current-'):
     return L.encoded(dict(binding=binding,status='DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY',cleanup=dict(owned_storage_absent=True,errors=[]),**L.FINAL))
    return real_read(path,*a)
   with patch.object(L,'preflight',return_value=plan),patch.object(L,'run',side_effect=run),patch.object(L,'read',side_effect=read),patch.object(L,'fixed_tool'),patch.object(L.resource,'setrlimit'),patch.object(L.signal,'setitimer'),patch.object(L,'prerequisite_absent',return_value=dict(MODEL_absent=True)),patch.object(L,'scope_absent',return_value=dict(MODEL_absent=True)),patch.object(L.time,'monotonic',side_effect=lambda:mono()+offset[0]),patch.object(L.time,'time',side_effect=lambda:epoch()+offset[0]):
    status=L._execute(args,f.env)
   self.assertEqual(status,0,(calls,(f.control/'public/launcher-report.json').read_text()))
   self.assertEqual(calls,['metadata','prerequisite','metadata','controller'])
   report=L.decode((f.control/'public/launcher-report.json').read_bytes());self.assertLess(report['shared_timing']['available_stage_ceiling_seconds'],7200)
   self.assertFalse(report['independent_component_acceptance'])


class RealAssemblerControls(unittest.TestCase):
 """Actual 7a1719be assembly/validators; only its tiny existing MODEL catalogues."""
 def setUp(self):
  fixture=Path(os.environ.get('CACHY_CURRENT_INPUTS_FIXTURE',str(HERE/'payload/native/test_inputs_current_v3.py'))).resolve()
  self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),'32ac0846ecbe59d4c5459506e0c41170095a5ba993a1b0f3240237e2d91b05b7','use composed image-atime repair fixture')
  self.assertEqual(hashlib.sha256((fixture.parent/'inputs_current_v3.py').read_bytes()).hexdigest(),'a1838fe056f95ae5baae5a70b9ba20a623271475160c9010ae59e3c751e90f9c','actual committed assembler, no matching replacement stub')
  spec=importlib.util.spec_from_file_location('actual_7a1719be_inputs_fixture',fixture);self.M=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.M)
  self.f=self.M.Controls('test_backend_and_pure_preflight_match_real_image_selected_inputs');self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.f.stage.chmod(0o700)
  self.envelope=self.f.assemble()
  # The real validator's MODEL catalogues are already parameterized by its own
  # committed fixture. Keep those expected pins; never replace either validator.
  self.f.closed('programs/inputs.py',Path(self.M.A.__file__).read_bytes())
  self.path=self.f.stage/'output-backend/inputs.json'
  self.r=dict(staged_root=str(self.f.stage),staged_inputs=dict(path=str(self.path),**L.pin(self.path.read_bytes())))
 def call(self,value=None):
  if value is not None:
   self.path.write_bytes(self.M.A.encoded(value));self.r['staged_inputs']={**self.r['staged_inputs'],**L.pin(self.path.read_bytes())}
  def actual(root,row,name):
   self.assertEqual(row,self.f.d['programs']['inputs_assembler'])
   self.assertEqual(L.pin(L.read(root/row['member'])),L.descriptor(row))
   return self.M.A
  with patch.object(L,'program',side_effect=actual):
   return L.checked_inputs(self.r,self.f.d,self.f.source,self.f.H,time.monotonic()+180)
 def test_actual_committed_assembler_wrapper_real_validator_and_full_stream(self):
  self.assertEqual(set(self.envelope),{'schema','kind','owner_inputs','staged_refs'})
  self.assertEqual(set(self.envelope['owner_inputs']),{'image_inputs','stage_inputs'})
  before=copy.deepcopy(self.envelope);owner,intake=self.call()
  self.assertEqual(owner,before['owner_inputs']);self.assertEqual(self.envelope,before)
  self.assertEqual(intake,dict(files=len(before['staged_refs']),bytes=sum(row['bytes']for row in before['staged_refs'])))
  self.assertGreater(intake['files'],400);self.assertIsNone(self.f.d['binding']['run'])
 def test_actual_zero_revoked_public_leaf_is_exactly_streamed(self):
  row=next(row for row in self.envelope['staged_refs']if Path(row['path']).name=='archlinuxarm-revoked')
  self.assertEqual({k:row[k]for k in('bytes','sha256')},L.pin(b''));self.assertEqual(Path(row['path']).read_bytes(),b'')
  owner,intake=self.call();self.assertEqual(owner,self.envelope['owner_inputs'])
  self.assertIn(row,self.envelope['staged_refs']);self.assertEqual(intake['files'],len(self.envelope['staged_refs']))
 def test_zero_revoked_tamper_missing_extra_and_wrong_empty_pin_refuse(self):
  row=next(row for row in self.envelope['staged_refs']if Path(row['path']).name=='archlinuxarm-revoked');path=Path(row['path'])
  path.write_bytes(b'NOT EMPTY')
  with self.assertRaises(ValueError):self.call()
  path.unlink()
  with self.assertRaises((ValueError,FileNotFoundError)):self.call()
  path.write_bytes(b'')
  value=copy.deepcopy(self.envelope);next(ref for ref in value['staged_refs']if ref['path']==str(path))['sha256']='0'*64
  with self.assertRaises(ValueError):self.call(value)
  extra=self.f.stage/'undeclared-revoked';extra.write_bytes(b'')
  value=copy.deepcopy(self.envelope);value['staged_refs'].append(dict(path=str(extra),**L.pin(b'')))
  with self.assertRaises(ValueError):self.call(value)
 def test_real_validator_unknown_extra_duplicate_tamper_and_missing_inputs_refuse(self):
  for mode in ('outer-extra','inner-extra','duplicate','omission','wrong-ref-pin','missing-input','wrong-body-pin'):
   value=copy.deepcopy(self.envelope)
   if mode=='outer-extra':value['extra']=True
   elif mode=='inner-extra':value['owner_inputs']['extra']={}
   elif mode=='duplicate':value['staged_refs'].append(copy.deepcopy(value['staged_refs'][0]))
   elif mode=='omission':value['staged_refs'].pop()
   elif mode=='wrong-ref-pin':value['staged_refs'][0]['sha256']='0'*64
   elif mode=='missing-input':value['owner_inputs']['image_inputs'].pop('base_materials')
   else:next(iter(value['owner_inputs']['image_inputs']['base_materials'].values()))['sha256']='0'*64
   with self.subTest(mode=mode),self.assertRaises((ValueError,KeyError)):self.call(value)
 def test_wrong_wrapper_pin_or_missing_actual_staged_body_refuses(self):
  self.r['staged_inputs']['sha256']='0'*64
  with patch.object(L,'program',side_effect=AssertionError('assembler must not load before wrapper pin')),self.assertRaises(ValueError):L.checked_inputs(self.r,self.f.d,self.f.source,self.f.H,time.monotonic()+180)
  self.r['staged_inputs']['sha256']=L.pin(self.path.read_bytes())['sha256']
  # Whole metadata/recipe reproduction still succeeds; the launcher must find
  # a missing genuine body itself before any controller or privileged entry.
  row=next(row for row in self.envelope['staged_refs']if Path(row['path']).name=='rootfs')
  Path(row['path']).unlink()
  with self.assertRaises((ValueError,FileNotFoundError)):self.call(self.envelope)


if __name__=='__main__':unittest.main(verbosity=2)
