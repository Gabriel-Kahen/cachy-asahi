# SPDX-License-Identifier: MIT
"""Fenced MODEL launcher controls. No HTTP/process/privilege/native execution."""
import ast,copy,hashlib,importlib.util,io,json,os,re
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
  self.assertIn('persist-credentials: false',text);self.assertIn('retention-days: 3',text)
  names=re.findall(r'secrets\.([A-Z0-9_]+)',text);self.assertEqual(len(names),22);self.assertEqual(set(names),set(L.MATERIAL_SECRET_NAMES))
  self.assertEqual(text.count('authorization.material_staging == true && secrets.'),22)
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
 """Actual ff33d619 assembly/validators; only its tiny existing MODEL catalogues."""
 def setUp(self):
  fixture=Path(os.environ.get('CACHY_CURRENT_INPUTS_FIXTURE',str(HERE/'payload/native/test_inputs_current_v3.py'))).resolve()
  self.assertEqual(L.pin(fixture.read_bytes()),dict(bytes=43566,sha256='07344dfcbe89edca77362ef41bf34b176fa20f0cb9f1b0e7795055a2cac410b8'),'use committed full27 fixture')
  self.assertEqual(L.pin((fixture.parent/'inputs_current_v3.py').read_bytes()),dict(bytes=45247,sha256='ddc4f0da13c4e9d7ab58f2c3fe318343082f320dae105e069336ecb24c4c49cb'),'actual committed assembler, no matching replacement stub')
  spec=importlib.util.spec_from_file_location('actual_ff33d619_inputs_fixture',fixture);self.M=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.M)
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


class MaterialSelectionControls(unittest.TestCase):
 def test_inline_cap_canonical_hash_and_exact_shape(self):
  raw=L.encoded(dict(MODEL='public metadata'));row=dict(json=raw.decode(),pin=L.pin(raw));self.assertEqual(L.assembly_request(row),raw)
  for bad in [dict(row,extra=True),dict(row,pin=dict(bytes=len(raw),sha256='0'*64)),dict(json='{}',pin=L.pin(b'{}')),dict(json='x'*8193,pin=L.pin(b'x'*8193))]:
   with self.assertRaises(ValueError):L.assembly_request(bad)
 def test_only_five_base_fields_and_no_secret_values_in_request(self):
  self.assertEqual(L.BASE_FIELDS,('base_lock','bootstrap_profile','base_materials','supplemental_materials','keyring_materials'))
  self.assertEqual(len(L.MATERIAL_SECRET_NAMES),22);self.assertEqual(len(set(L.MATERIAL_SECRET_NAMES)),22)
  for name in L.MATERIAL_SECRET_NAMES:self.assertRegex(name,r'^CACHY_(OLD_FOUR|RETAINED_BUBBLEWRAP_V1)_')
 def test_exact_root_optional_fields_keep_old_path_strict(self):
  f=Controls('test_real_file_pins_main_source_owner_assembler_and_staged_bodies');f.setUp();self.addCleanup(f.doCleanups)
  raw=L.encoded(dict(schema=3,MODEL='not operational'));selection=dict(grant_json=raw.decode(),grant_pin=L.pin(raw),assembler_request=dict(json=raw.decode(),pin=L.pin(raw)))
  r=copy.deepcopy(f.r);r['material_staging']=selection;r['staged_inputs']=r['staged_root']=None;r['authorization']['material_staging']=True
  p=f.base/'optional.json';p.write_bytes(L.encoded(r));self.assertEqual(L.request(p,L.pin(p.read_bytes())['sha256']),r)
  for mutate in(lambda v:v.update(staged_root=str(f.staged)),lambda v:v['material_staging'].update(extra=True),lambda v:v['authorization'].pop('material_staging')):
   bad=copy.deepcopy(r);mutate(bad);p.write_bytes(L.encoded(bad))
   with self.assertRaises(ValueError):L.request(p,L.pin(p.read_bytes())['sha256'])
  r=copy.deepcopy(f.r);r['staged_inputs']=None;p.write_bytes(L.encoded(r))
  with self.assertRaises(ValueError):L.request(p,L.pin(p.read_bytes())['sha256'])
 def test_secret_capture_precedes_selected_import_and_all_failures_clear(self):
  secret_names=L.MATERIAL_SECRET_NAMES;env={name:'INERT_MODEL'for name in secret_names};r=dict(material_staging={});seen=[]
  def bound(args,actual,request,secrets):
   self.assertFalse(set(secret_names)&set(actual));self.assertEqual(set(secrets),set(secret_names));seen.append(secrets);raise ValueError('MODEL preflight refusal')
  with patch.object(L,'request',return_value=r),patch.object(L,'_execute_bound',side_effect=bound):
   with self.assertRaises(ValueError):L._execute(SimpleNamespace(request=None,request_sha256=None),env)
  self.assertEqual(env,{});self.assertEqual(seen,[{}])
 def test_inline_metadata_is_exact_public_bytes_only_at_named_slots(self):
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp);plan=SimpleNamespace(d=dict(materials={}),root=out);raw=L.encoded(dict(FENCED='NOT_ROOT_AUTHORITY'));value=dict(json=raw.decode(),pin=L.pin(raw))
   ref=L.assembly_selection(dict(Root_admission=value),plan,{},out)['Root_admission'];self.assertEqual(Path(ref['path']).read_bytes(),raw)
   with self.assertRaises(ValueError):L.assembly_selection(dict(archive=value),plan,{},out)
   bad=L.encoded(dict(public='-----BEGIN PGP PRIVATE KEY BLOCK-----'));value=dict(json=bad.decode(),pin=L.pin(bad))
   with self.assertRaises(ValueError):L.assembly_selection(dict(Root_admission=value),plan,{},out)
 def test_final_close_time_is_reserved_and_earliest_grant_expiry_wins(self):
  f=SharedTimingControls();plan,context=f.model();before=L.controller_seconds(plan)
  plan.S=object();plan.M=SimpleNamespace(CLOSE_SECONDS=90);self.assertLessEqual(L.controller_seconds(plan),before-90)
  r=dict(material_staging=dict(grant_json=L.encoded(dict(expires_epoch=100)).decode()))
  self.assertEqual(L.timing_expiry(r,dict(expires_epoch=200)),100)


class RealStagingAssemblyControls(unittest.TestCase):
 """Actual canonical-tool successor seams +actual27 assembler; only actors modeled."""
 def setUp(self):
  owner=RealAssemblerControls('test_actual_committed_assembler_wrapper_real_validator_and_full_stream');owner.setUp();self.addCleanup(owner.doCleanups)
  self.owner=owner;self.M=owner.M;self.f=owner.f;f=self.f
  nonce='f'*64;old=f.stage;new=f.root/('cachy-current-material-domain-'+nonce);old.rename(new);f.stage=new
  def move(value):
   if type(value)is dict:return {k:move(v)for k,v in value.items()}
   if type(value)is list:return [move(v)for v in value]
   if type(value)is str and value.startswith(str(old)+'/'):return str(new)+value[len(str(old)):]
   return value
  f.request=move(f.request)
  f.staging() # Actual committed strict59+5 subset/registry join, no predicate replacement.
  self.assertEqual(len(f.d['materials']),64)
  for trust in ('official_trust','test_trust'):
   ref=f.request[trust]['Root_admission'];p=Path(ref['path']);raw=self.M.A.encoded(move(json.loads(p.read_bytes())));p.write_bytes(raw);ref.update(self.M.A.pin(raw))
  stager=Path(os.environ.get('CACHY_CURRENT_STAGER_FIXTURE',str(HERE/'payload/native/stage_materials_current_v3_python_v1.py'))).resolve()
  spec=importlib.util.spec_from_file_location('actual_canonical_stager_seam',stager);S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
  self.assertEqual(L.pin(Path(S.__file__).read_bytes()),L.MATERIAL_STAGER_PIN);self.S=S
  provider=Path(self.M.__file__).parent/'base_inputs_current_v3.py';self.assertEqual(L.pin(provider.read_bytes())['sha256'],S.PROVIDER_SHA)
  spec=importlib.util.spec_from_file_location('actual_complete517_provider_seam',provider);B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);self.B=B
  f.closed('programs/base.py',provider.read_bytes());f.d['programs']['base_inputs']=dict(member='programs/base.py',**L.pin(provider.read_bytes()))
  now=int(time.time());f.d.update(nonce=nonce,issued_epoch=now-10,expires_epoch=now-10+7560,context_limits=dict(max_context_age_seconds=7560,max_delegation_seconds=7560));f.d['capability']['allow_material_staging']=True
  policy=json.loads((f.source/'policy.json').read_bytes());policy['material_staging_current_v3']=S.PROPOSAL
  ref=f.closed('policy.json',self.M.A.encoded(policy));f.d['policy']={k:ref[k]for k in('bytes','sha256')};f.d['policy']['member']='policy.json'
  fields={k:copy.deepcopy(f.request[k])for k in L.BASE_FIELDS};request=copy.deepcopy(f.request)
  for k in L.BASE_FIELDS:request[k]=None
  raw=self.M.A.encoded(request);g=dict(schema=3,kind='ROOT_CURRENT_COMPLETE517_STAGING_V3',issuer='Root',approved=True,**{k:f.d['binding'][k]for k in('source','ref','source_lock')},nonce=nonce,policy={k:f.d['policy'][k]for k in('bytes','sha256')},issued_epoch=now-5,expires_epoch=f.d['expires_epoch']-1,redirect_urls={},secret_provider='CALLER_ONE_SHOT_EXACT22',scope='COMPLETE517_PUBLIC_DATA_ONLY',storage_parent=str(new))
  rg=L.encoded(g);rd=L.encoded(f.d);r=dict(delegation_json=rd.decode(),delegation_pin=L.pin(rd),material_staging=dict(grant_json=rg.decode(),grant_pin=L.pin(rg),assembler_request=dict(json=raw.decode(),pin=L.pin(raw))))
  self.context=dict(FENCED='NOT_PROVIDER_OBSERVATION',source_root=str(f.source),stage='backend',binding=dict(f.binding,run='11',job='12'))
  references=dict(api=B.API,kind='VERIFIED_BASE349_CACHE_REFERENCES_DATA_V3',missing_materials={},complete=True,verified_files=517,actual=dict.fromkeys(B.ACTUAL),**fields)
  total=sum(ref['bytes']for k in ('base_materials','supplemental_materials','keyring_materials')for ref in fields[k].values());references['verified_bytes']=total
  self.result=dict(receipt=dict(status='COMPLETE517_HOSTED_CACHE_DATA_ONLY',binding=self.context['binding'],verified_files=517,verified_bytes=total,**L.FINAL),references=references,assembler_fields=B.assembler_fields(references),staging_scope_retirement=dict(natural=True,scope_absent=True,scope='cachy-current-materials-'+nonce+'.scope',FENCED='NOT_RUNTIME_EVIDENCE'))
  self.events=[];test=self
  class Session:
   def stage(self,*,secrets):
    test.events.append('stage');test.assertEqual(set(secrets),set(L.MATERIAL_SECRET_NAMES))
    role=new/('cachy-current-materials-'+nonce)
    if not role.exists():role.mkdir(mode=0o700)
    return test.result
   def close(self):test.events.append('close');return dict(closed=True,scope_absent=True,input_storage_absent=True,**L.FINAL)
  session=Session();M=SimpleNamespace(CLOSE_SECONDS=90,open_material_session=lambda **kw:session)
  self.private=f.root/'control/private';self.public=f.root/'control/public'
  for p in(self.private,self.public):p.mkdir(parents=True,mode=0o700)
  self.plan=SimpleNamespace(S=S,M=M,H=f.H,d=f.d,policy=policy,root=f.source,request=r,control=f.root/'control',timing=dict(deadline_monotonic=time.monotonic()+100,expires_epoch=int(time.time())+100),material_session=None)
 def program(self,root,row,name):
  raw=L.read(root/row['member']);self.assertEqual(L.pin(raw),L.descriptor(row))
  if row==self.f.d['programs']['inputs_assembler']:return self.M.A
  if row==self.f.d['programs']['base_inputs']:return self.B
  raise AssertionError('unexpected Source program')
 def call(self):
  secrets={name:'INERT_MODEL'for name in L.MATERIAL_SECRET_NAMES}
  with patch.object(L,'program',side_effect=self.program):result=L.stage_and_assemble(self.plan,self.context,secrets,self.private,self.public)
  self.assertEqual(secrets,{});return result
 def test_actual_successor_grant_then_actual517_assembler_and_real_stream(self):
  self.call();self.assertEqual(self.events,['stage']);self.assertIsNotNone(self.plan.material_session)
  self.assertEqual(set(self.plan.inputs),{'image_inputs','stage_inputs'});self.assertGreater(self.plan.intake['files'],517)
  self.assertEqual(self.plan.inputs['image_inputs']['keyring_materials']['archlinuxarm-revoked']['bytes'],0)
  self.plan.material_session.close();self.assertEqual(self.events,['stage','close'])
 def test_unknown_refs_wrong_pin_partial_scope_and_missing_real_body_refuse(self):
  self.result['staging_scope_retirement']['scope_absent']=False
  with self.assertRaises(ValueError):self.call()
  self.result['staging_scope_retirement']['scope_absent']=True
  row=next(iter(self.result['assembler_fields']['base_materials'].values()));Path(row['path']).unlink()
  with self.assertRaises((ValueError,FileNotFoundError)):self.call()
 def test_whole_caller_holds_input_domain_until_main_then_natural_close(self):
  plan=self.plan;f=self.f;plan.d['capability']['allow_host_prerequisites']=True
  rd=L.encoded(plan.d);r=dict(plan.request,schema=3,kind='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3',issuer='Root',approved=True,
   trusted_main_commit='9'*40,launcher=dict(member=MEMBER,**L.pin(MODULE.read_bytes())),staged_inputs=None,staged_root=None,
   control_name='cachy-current-hosted-'+plan.d['nonce'],delegation_json=rd.decode(),delegation_pin=L.pin(rd),
   authorization=dict(jobs_metadata=True,privileged_controller=True,launcher_limits=L.LIMITS,host_prerequisites=True,whole_timing=L.TIMING,material_staging=True))
  plan.request=r;plan.control=f.root/r['control_name'];plan.main=f.root/'Main';plan.main.mkdir();plan.Q=object();plan.O=object();plan.inputs=None;plan.intake=dict(status='DEFERRED');plan.material_session=None
  plan.policy['executor_current_v3']=dict(setup_seconds=180,stage_seconds=7200,cleanup_seconds=180)
  missing=[True];names=tuple(L.MATERIAL_SECRET_NAMES);context=dict(self.context)
  tool_names=('systemd-run','systemctl','dockerd','docker','fallocate','losetup','mkfs.ext4','mount','umount','python3','gpg','gpgconf','gpg-connect-agent','bsdtar','zstd','env')
  plan.E=SimpleNamespace(NAMES=tool_names,probe_tools=lambda:dict(missing_or_invalid=['bsdtar']if missing[0]else[],tools={n:dict(selected=dict(path='/usr/bin/'+n))for n in tool_names}),checked_tool=lambda row:row['path'])
  plan.H.ENV=('GITHUB_RUN_ID',);plan.H.capture_context=lambda *a,**kw:dict(context)
  plan.d['hosted']=dict(repository='Gabriel-Kahen/cachy-asahi');plan.d['context_limits'].update(metadata_query_seconds=15,metadata_max_bytes=1024**2)
  rd=L.encoded(plan.d);r.update(delegation_json=rd.decode(),delegation_pin=L.pin(rd))
  request=f.root/'root-request.json';request.write_bytes(L.encoded(r));args=SimpleNamespace(request=request,request_sha256=L.pin(request.read_bytes())['sha256'],source_root=f.source,main_root=plan.main,control_root=plan.control)
  env=dict(GITHUB_RUN_ID='11',**{name:'INERT_MODEL'for name in names});offset=[0];mono=time.monotonic;epoch=time.time
  actual_stage=L.stage_and_assemble
  def stage(*a,**kw):
   result=actual_stage(*a,**kw);offset[0]+=3600;return result
  def run(O,argv,cap,work):
   if argv[0]=='/usr/bin/git':return ((r['trusted_main_commit']if str(plan.main)in argv else plan.d['binding']['source'])+'\n').encode(),dict(FENCED=True)
   if 'metadata'in argv:return b'{}',dict(FENCED=True)
   if 'prerequisite'in argv:self.events.append('prerequisite');offset[0]+=495;missing[0]=False;return b'',dict(FENCED=True)
   self.events.append('main');self.assertIsNotNone(plan.material_session)
   self.assertTrue(Path(next(iter(self.result['assembler_fields']['base_materials'].values()))['path']).exists())
   runtime=int(next(v.split('=')[-1][:-1]for v in argv if v.startswith('--property=RuntimeMaxSec=')))
   self.assertLess(runtime,7560-4095);return b'',dict(FENCED=True)
  actual_read=L.read
  def read(path,*a):
   if str(path).startswith('/var/lib/cachy-current-'):return L.encoded(dict(binding=context['binding'],status='DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY',cleanup=dict(owned_storage_absent=True,errors=[]),**L.FINAL))
   return actual_read(path,*a)
  with patch.object(L,'preflight',return_value=plan),patch.object(L,'program',side_effect=self.program),patch.object(L,'stage_and_assemble',side_effect=stage),patch.object(L,'run',side_effect=run),patch.object(L,'read',side_effect=read),patch.object(L,'fixed_tool'),patch.object(L.resource,'setrlimit'),patch.object(L.signal,'setitimer'),patch.object(L,'prerequisite_absent',return_value=dict(FENCED=True)),patch.object(L,'scope_absent',return_value=dict(FENCED=True)),patch.object(L.time,'monotonic',side_effect=lambda:mono()+offset[0]),patch.object(L.time,'time',side_effect=lambda:epoch()+offset[0]):
   status=L._execute(args,env)
  self.assertEqual(status,0,(plan.control/'public/launcher-report.json').read_text());self.assertEqual(self.events,['stage','prerequisite','main','close'])
  self.assertFalse(set(names)&set(env));report=L.decode((plan.control/'public/launcher-report.json').read_bytes());self.assertTrue(report['material_domain_cleanup']['input_storage_absent'])
  self.assertNotIn('material_failure_before_cleanup',report);self.assertNotIn('material_children_after_cleanup',report)
 def test_actual_committed_domain_retirement_projection_and_close(self):
  # Execute real session DATA/receipt logic; replace only privileged actor and
  # mounted-storage observation boundaries. All archives remain tiny MODEL DATA.
  path=Path(os.environ.get('CACHY_CURRENT_MATERIAL_DOMAIN_FIXTURE',str(HERE/'payload/native/material_domain_current_v3.py'))).resolve()
  self.assertEqual(L.pin(path.read_bytes()),L.MATERIAL_DOMAIN_PIN)
  spec=importlib.util.spec_from_file_location('actual_ae3ab1dd_material_domain',path);D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
  executor=Path(os.environ.get('CACHY_CURRENT_EXECUTOR_FIXTURE',str(HERE/'payload/native/owned_executor_current_v3.py'))).resolve()
  self.assertEqual(L.pin(executor.read_bytes()),dict(bytes=53735,sha256='aee41c0956f3249eef2e9c8974238b214622cb385e2d8f736109d9650ce7120a'))
  spec=importlib.util.spec_from_file_location('actual_domain_retirement_executor',executor);E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
  plan=self.plan;g=json.loads(plan.request['material_staging']['grant_json'])
  plan.d['capability']['allow_host_prerequisites']=True
  for role,body in (('materials_stager',Path(self.S.__file__).read_bytes()),('material_domain_executor',path.read_bytes())):
   member='programs/'+role+'.py';self.f.closed(member,body);plan.d['programs'][role]=dict(member=member,**L.pin(body))
  plan.policy['material_domain_executor_current_v3']=D.PROPOSAL
  def selected(root,row,name):
   self.assertEqual(L.pin(L.read(root/row['member'])),L.descriptor(row))
   if row==plan.d['programs']['materials_stager']:return self.S
   if row==plan.d['programs']['material_domain_executor']:return D
   return self.program(root,row,name)
  with patch.object(L,'program',side_effect=selected):
   self.assertEqual(L.material_programs(plan.request,plan.d,plan.root,plan.policy),(self.S,D))
   plan.policy['material_domain_executor_current_v3']={}
   with self.assertRaises(ValueError):L.material_programs(plan.request,plan.d,plan.root,plan.policy)
  plan.policy['material_domain_executor_current_v3']=D.PROPOSAL
  r=dict(control_root=str(plan.control),context=self.context,shared_timing=plan.timing,runner_uid=os.getuid(),runner_gid=os.getgid())
  session=D.MaterialSession(r,(plan.root,plan.d,plan.policy,g,E,self.S,object()))
  def execute(closing=False,secrets=None):
   row=dict(kind='CLOSE'if closing else'STAGE',natural=True,
    supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0),
    scope_absence=dict(scope=D.scope_name(plan.d['nonce'],closing),absent_twice=True),**D.FINAL)
   session.receipts.append(row)
   if closing:
    D.write(plan.control/'material-domain-close.json',dict(owned_storage_absent=True,binding=self.context['binding'],nonce=plan.d['nonce'],request_pin=D.pin(D.encoded(r)),scope_absence=dict(scope=D.scope_name(plan.d['nonce']),absent_twice=True),**D.FINAL))
   else:
    session.stage_submitted=True;out=Path(g['storage_parent'])/('cachy-current-materials-'+plan.d['nonce']);out.mkdir(mode=0o700)
    receipt=dict(self.result['receipt'],Root_expires_epoch=min(plan.d['expires_epoch'],g['expires_epoch'],plan.d['issued_epoch']+7560),whole_deadline_monotonic=plan.timing['deadline_monotonic'])
    for name,value in (('staging-receipt.json',receipt),('complete517.json',self.result['references']),('assembler-fields.json',self.result['assembler_fields'])):D.write(out/name,value)
  session.execute=execute
  plan.M=SimpleNamespace(CLOSE_SECONDS=D.CLOSE_SECONDS,open_material_session=lambda **kw:session)
  with patch.object(D,'retained_storage',return_value=dict(FENCED='NOT_KERNEL_OBSERVATION')),patch.object(D,'load',side_effect=lambda root,row,name:self.program(root,row,name)):
   self.call()
  self.assertEqual(session.state,'RETAINED_FOR_CONSUMERS');self.assertTrue(Path(next(iter(self.result['assembler_fields']['base_materials'].values()))['path']).exists())
  retirement=D.scope_retirement(E,session.receipts[0],plan.d['nonce']);self.assertTrue(retirement['scope_absent']);self.assertIn('supervision_pin',retirement)
  closed=session.close();self.assertTrue(all(closed[k]for k in ('closed','scope_absent','input_storage_absent')));self.assertEqual(closed['Root_final_acceptance'],None)
  session.receipts[0]['supervision']['signals']=['MODEL_KILL']
  with self.assertRaises(ValueError):D.scope_retirement(E,session.receipts[0],plan.d['nonce'])
  session.receipts[0]['supervision']['signals']=[];session.receipts[0]['scope_absence']['absent_twice']=False
  with self.assertRaises(ValueError):D.scope_retirement(E,session.receipts[0],plan.d['nonce'])
 def test_no_issued_trust_is_synthesized_from_null_selection(self):
  row=self.plan.request['material_staging']['assembler_request'];value=json.loads(row['json']);value['official_trust']=None;raw=L.encoded(value);row.update(json=raw.decode(),pin=L.pin(raw))
  with self.assertRaises((ValueError,KeyError)):self.call()
  self.assertFalse(self.plan.inputs if hasattr(self.plan,'inputs')else False)


class FailureDiagnosticControls(unittest.TestCase):
 """Inert process/kernel boundaries; maintained session/executor predicates run."""
 SENTINEL='INERT_SECRET_NEVER_PUBLIC_71b9'
 def fixture(self):
  fixture=RealStagingAssemblyControls('test_actual_successor_grant_then_actual517_assembler_and_real_stream');fixture.setUp();self.addCleanup(fixture.doCleanups);return fixture
 def domain(self):
  modules=[]
  for name,wanted in (('material_domain_current_v3',L.MATERIAL_DOMAIN_PIN),('owned_executor_current_v3',dict(bytes=53735,sha256='aee41c0956f3249eef2e9c8974238b214622cb385e2d8f736109d9650ce7120a'))):
   path=Path(os.environ.get('CACHY_CURRENT_MATERIAL_DOMAIN_FIXTURE',str(HERE/'payload/native'/(name+'.py')))).resolve()if name=='material_domain_current_v3'else HERE/'payload/native'/(name+'.py');self.assertEqual(L.pin(path.read_bytes()),wanted)
   spec=importlib.util.spec_from_file_location('diagnostic_'+name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);modules.append(module)
  return modules
 def bound_request(self,fixture):
  plan=fixture.plan;f=fixture.f;plan.d['capability']['allow_host_prerequisites']=True
  plan.d['hosted']=dict(repository='Gabriel-Kahen/cachy-asahi');plan.d['context_limits'].update(metadata_query_seconds=15,metadata_max_bytes=1024**2)
  rd=L.encoded(plan.d);r=dict(plan.request,schema=3,kind='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3',issuer='Root',approved=True,
   trusted_main_commit='9'*40,launcher=dict(member=MEMBER,**L.pin(MODULE.read_bytes())),staged_inputs=None,staged_root=None,
   control_name='cachy-current-hosted-'+plan.d['nonce'],delegation_json=rd.decode(),delegation_pin=L.pin(rd),
   authorization=dict(jobs_metadata=True,privileged_controller=True,launcher_limits=L.LIMITS,host_prerequisites=True,whole_timing=L.TIMING,material_staging=True))
  plan.request=r;plan.control=f.root/r['control_name'];plan.main=f.root/'Main';plan.main.mkdir();plan.Q=object();plan.O=object();plan.E=object();plan.inputs=None
  plan.intake=dict(status='DEFERRED_UNTIL_ACTUAL_COMPLETE517');plan.policy['executor_current_v3']=dict(setup_seconds=180,stage_seconds=7200,cleanup_seconds=180)
  plan.H.ENV=('GITHUB_RUN_ID',);plan.H.capture_context=lambda *a,**kw:dict(fixture.context)
  request=f.root/'root-request.json';request.write_bytes(L.encoded(r));request.chmod(0o644)
  args=SimpleNamespace(request=request,request_sha256=L.pin(request.read_bytes())['sha256'],source_root=f.source,main_root=plan.main,control_root=plan.control)
  env=dict(GITHUB_RUN_ID='11',**{name:self.SENTINEL for name in L.MATERIAL_SECRET_NAMES})
  return args,env
 def test_real_session_child_failure_retained_before_real_close_and_secrets_cleared(self):
  fixture=self.fixture();plan=fixture.plan;D,E=self.domain();args,env=self.bound_request(fixture)
  grant=json.loads(plan.request['material_staging']['grant_json']);role=Path(grant['storage_parent'])/('cachy-current-materials-'+plan.d['nonce']);hold=role/'HOLD.json'
  safe=dict(status='HOLD_PARTIAL_OWNED_DATA_CLOSEONLY',scope='/system.slice/'+D.scope_name(plan.d['nonce']),Root_acceptance=None);hold_pin=L.pin(L.encoded(safe))
  packet=dict(schema=1,kind='CURRENT_MATERIAL_STAGE_FAILURE_V1',phase='TOOLS',reason='COMMAND_FAILED',command_ordinal=4);stderr=D.encoded(packet)
  sessions=[];events=[];secret_maps=[]
  def opened(**kw):
   r=dict(source_root=str(plan.root),delegation_raw=plan.request['delegation_json'],delegation_sha256=plan.request['delegation_pin']['sha256'],grant_raw=plan.request['material_staging']['grant_json'],grant_sha256=plan.request['material_staging']['grant_pin']['sha256'],control_root=str(plan.control),context=fixture.context,shared_timing=plan.timing,runner_uid=os.getuid(),runner_gid=os.getgid())
   owner=SimpleNamespace(prepare=lambda:events.append('prepare'),supervise=supervise)
   session=D.MaterialSession(r,(plan.root,plan.d,plan.policy,grant,E,fixture.S,owner));sessions.append(session);return session
  def spawn(argv,**kw):
   closing='close-entry'in argv;events.append('close-child'if closing else'stage-child')
   if closing:
    self.assertTrue(hold.exists());hold.unlink();role.rmdir();session=sessions[0]
    D.write(plan.control/'material-domain-close.json',dict(owned_storage_absent=True,binding=fixture.context['binding'],nonce=plan.d['nonce'],request_pin=D.pin(D.encoded(session.r)),scope_absence=dict(scope=D.scope_name(plan.d['nonce']),absent_twice=True),**D.FINAL))
   else:
    role.mkdir(mode=0o700);D.write(hold,safe);kw['stderr'].write(stderr)
   return SimpleNamespace(closing=closing)
  def supervise(child,**kw):
   return dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0 if child.closing else 7,output=b''if child.closing else self.SENTINEL.encode())
  def run(owner,argv,cap,work):
   if argv[0]=='/usr/bin/git':return ((plan.request['trusted_main_commit']if str(plan.main)in argv else plan.d['binding']['source'])+'\n').encode(),dict(FENCED=True)
   self.assertIn('metadata',argv);return b'{}',dict(FENCED=True)
  original_stage=D.MaterialSession.stage
  def stage(session,*,secrets):
   secret_maps.append(secrets);return original_stage(session,secrets=secrets)
  def anonymous_buffer(*a):
   # MODEL only the unavailable memfd/sealing kernel boundary on Python3.12.
   # The maintained sealing generator, stream bounds and secret clearing run.
   with tempfile.TemporaryFile()as stream:return os.dup(stream.fileno())
  plan.M=SimpleNamespace(CLOSE_SECONDS=D.CLOSE_SECONDS,open_material_session=opened)
  tools={name:dict(path='/usr/bin/'+name)for name in ('python3','systemd-run','sudo')}
  with patch.object(L,'preflight',return_value=plan),patch.object(L,'program',side_effect=fixture.program),patch.object(L,'run',side_effect=run),patch.object(L.resource,'setrlimit'),patch.object(L.signal,'setitimer'),patch.object(D,'scope_tools',return_value=tools),patch.object(D,'scope_path',return_value=fixture.f.root/'absent-model-cgroup'),patch.object(D,'absent',side_effect=lambda nonce,deadline,closing=False:dict(scope=D.scope_name(nonce,closing),absent_twice=True)),patch.object(D.subprocess,'Popen',side_effect=spawn),patch.object(E,'require_runtime_capabilities'),patch.object(E,'stderr_buffer',side_effect=io.BytesIO),patch.object(E,'natural',wraps=E.natural)as natural,patch.object(D.MaterialSession,'stage',stage),patch.multiple(D.os,create=True,memfd_create=anonymous_buffer,MFD_CLOEXEC=1,MFD_ALLOW_SEALING=2),patch.multiple(D.fcntl,create=True,F_ADD_SEALS=1033,F_GET_SEALS=1034,F_SEAL_GROW=4,F_SEAL_SHRINK=2,F_SEAL_WRITE=8,F_SEAL_SEAL=1),patch.object(D.fcntl,'fcntl',return_value=0):
   status=L._execute(args,env)
  report=L.decode((plan.control/'public/launcher-report.json').read_bytes());self.assertEqual(status,2,report)
  self.assertEqual(report['failure'],dict(phase='material_stage',reason='VALIDATION_REFUSED'));self.assertEqual(report['failure_type'],'ValueError')
  self.assertEqual(report['intake']['status'],'DEFERRED_UNTIL_ACTUAL_COMPLETE517');self.assertEqual(events,['prepare','stage-child','prepare','close-child'])
  self.assertGreaterEqual(natural.call_count,3);self.assertEqual(sessions[0].state,'CLOSED');self.assertEqual(secret_maps,[{}]);self.assertFalse(set(L.MATERIAL_SECRET_NAMES)&set(env))
  before=report['material_failure_before_cleanup'];self.assertEqual(before['state'],'HOLD_CLOSEONLY');self.assertTrue(before['stage_submitted']);self.assertEqual(len(before['children']),1)
  child=before['children'][0];self.assertFalse(child['natural_success']);self.assertEqual(child['supervision'],dict(reaped=True,output_complete=True,timeout=False,exit=7,ownership='REAPED',group_census='EMPTY_TWICE',supervisor_error=False,signals_observed=False))
  self.assertEqual(child['output_pin'],L.pin(self.SENTINEL.encode()));self.assertEqual(child['stderr_pin'],L.pin(stderr));self.assertFalse(child['scope_absent_twice'])
  source=before['source_failure'];self.assertEqual(source['status'],'DIAGNOSTIC_ONLY');self.assertEqual(source['availability'],'AVAILABLE');self.assertEqual(source['packet'],packet)
  record=L.read(plan.control/'material-stage-failure.json');self.assertEqual(source['record_pin'],L.pin(record));self.assertEqual(source['request_pin'],D.pin(D.encoded(sessions[0].r)));self.assertEqual(source['context_pin'],D.pin(D.encoded(fixture.context)));self.assertEqual(source['stderr_pin'],L.pin(stderr));self.assertEqual(source['stdout_pin'],child['output_pin']);self.assertEqual(source['retirement_pin'],L.pin(L.encoded(sessions[0].receipts[0]['supervision'])))
  self.assertEqual(before['source_hold'],dict(status=safe['status'],pin=hold_pin,source_reason='NOT_EMITTED_IN_HOLD_RECEIPT'));self.assertFalse(hold.exists())
  after=report['material_children_after_cleanup'];self.assertEqual(after['state'],'CLOSED');self.assertEqual([row['kind']for row in after['children']],['STAGE','CLOSE']);self.assertTrue(after['children'][1]['natural_success']);self.assertTrue(after['children'][1]['scope_absent_twice'])
  self.assertTrue(all(report['material_domain_cleanup'][key]for key in ('closed','scope_absent','input_storage_absent')))
  self.assertNotIn(self.SENTINEL,L.encoded(report).decode());self.assertNotIn('argv',L.encoded(report).decode())
 def test_failure_summary_is_finite_without_exception_text_or_dynamic_name(self):
  class SecretError(Exception):
   def __str__(self):raise AssertionError('exception text must not be observed')
  SecretError.__name__=self.SENTINEL
  plan=SimpleNamespace(public_phase='material_stage')
  for error,kind,reason in ((ValueError(self.SENTINEL),'ValueError','VALIDATION_REFUSED'),(TimeoutError(self.SENTINEL),'TimeoutError','DEADLINE_EXHAUSTED'),(KeyError(self.SENTINEL),'KeyError','REQUIRED_FIELD_MISSING'),(OSError(self.SENTINEL),'OSError','OS_OPERATION_FAILED'),(SystemExit(self.SENTINEL),'SystemExit','CHILD_ENTRY_REFUSED'),(KeyboardInterrupt(self.SENTINEL),'KeyboardInterrupt','INTERRUPTED'),(SecretError(),'OTHER','UNEXPECTED_FAILURE')):
   with self.subTest(kind=kind):self.assertEqual(L.failure_summary(plan,error),(dict(phase='material_stage',reason=reason),kind))
  plan.public_phase=self.SENTINEL;self.assertEqual(L.failure_summary(plan,SecretError())[0]['phase'],'UNKNOWN')
 def test_unavailable_diagnostics_and_close_error_preserve_original_failure(self):
  fixture=self.fixture();plan=fixture.plan;args,env=self.bound_request(fixture);events=[];secret_maps=[]
  def stage(*,secrets):
   events.append('stage');secret_maps.append(secrets);raise ValueError(self.SENTINEL)
  def close():events.append('close');raise OSError(self.SENTINEL)
  # A malformed existing row list must never interrupt the mandatory close path.
  session=SimpleNamespace(state='HOLD_CLOSEONLY',stage_submitted=True,receipts=[dict(kind='STAGE')]*3,stage=stage,close=close)
  plan.M=SimpleNamespace(CLOSE_SECONDS=90,open_material_session=lambda **kw:session)
  def run(owner,argv,cap,work):
   if argv[0]=='/usr/bin/git':return ((plan.request['trusted_main_commit']if str(plan.main)in argv else plan.d['binding']['source'])+'\n').encode(),dict(FENCED=True)
   self.assertIn('metadata',argv);return b'{}',dict(FENCED=True)
  with patch.object(L,'preflight',return_value=plan),patch.object(L,'run',side_effect=run),patch.object(L.resource,'setrlimit'),patch.object(L.signal,'setitimer'):
   self.assertEqual(L._execute(args,env),2)
  report=L.decode((plan.control/'public/launcher-report.json').read_bytes());self.assertEqual(events,['stage','close']);self.assertEqual(secret_maps,[{}]);self.assertFalse(set(L.MATERIAL_SECRET_NAMES)&set(env))
  self.assertEqual(report['failure'],dict(phase='material_stage',reason='VALIDATION_REFUSED'));self.assertEqual(report['failure_type'],'ValueError')
  self.assertEqual(report['material_cleanup_diagnostic'],dict(phase='material_cleanup',reason='OS_OPERATION_FAILED'));self.assertEqual(report['material_cleanup_failure'],'OSError')
  for key in ('material_failure_before_cleanup','material_children_after_cleanup'):self.assertEqual(report[key],dict(status='DIAGNOSTICS_UNAVAILABLE'))
  self.assertNotIn(self.SENTINEL,L.encoded(report).decode())
 def test_projection_excludes_secret_fields_streams_and_untyped_pins(self):
  nonce='a'*64;supervision=dict(reaped=True,output_complete=True,timeout=False,exit=7,ownership=self.SENTINEL,group_census=self.SENTINEL,error=self.SENTINEL,signals=[self.SENTINEL],output=self.SENTINEL)
  row=dict(kind='STAGE',natural=False,supervision=supervision,argv=[self.SENTINEL],tools=dict(secret=self.SENTINEL),env=dict(secret=self.SENTINEL),failure=dict(type=self.SENTINEL,message=self.SENTINEL),stdout=self.SENTINEL,stderr=self.SENTINEL,output_pin=L.pin(b'inert output'),stderr_pin=dict(bytes=True,sha256=self.SENTINEL),scope_absence=dict(scope=self.SENTINEL,absent_twice=True))
  plan=SimpleNamespace(d=dict(nonce=nonce),material_session=SimpleNamespace(state=self.SENTINEL,stage_submitted=True,receipts=[row]))
  result=L.material_failure_data(plan);self.assertEqual(result['state'],'UNKNOWN');child=result['children'][0]
  self.assertEqual(child['output_pin'],row['output_pin']);self.assertNotIn('stderr_pin',child);self.assertFalse(child['scope_absent_twice']);self.assertTrue(child['supervision']['supervisor_error']);self.assertTrue(child['supervision']['signals_observed']);self.assertNotIn(self.SENTINEL,L.encoded(result).decode())
  for rows in ([row]*3,[dict(kind=self.SENTINEL)],self.SENTINEL):
   plan.material_session.receipts=rows;self.assertEqual(L.material_failure_data(plan),dict(status='DIAGNOSTICS_UNAVAILABLE'))
 def test_only_exact_safe_hold_receipt_selected_and_bad_receipts_do_not_mask_failure(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-diagnostic-hold-')as tmp:
   root=Path(tmp);nonce='c'*64;role=root/('cachy-current-materials-'+nonce);role.mkdir(mode=0o700);path=role/'HOLD.json'
   plan=SimpleNamespace(public_phase='material_stage',d=dict(nonce=nonce),request=dict(material_staging=dict(grant_json=L.encoded(dict(storage_parent=str(root))).decode())),material_session=SimpleNamespace(state='HOLD_CLOSEONLY',stage_submitted=True,receipts=[]))
   safe=dict(status='HOLD_PARTIAL_OWNED_DATA_CLOSEONLY',scope='/system.slice/cachy-current-materials-'+nonce+'.scope',Root_acceptance=None)
   cases=[('missing',None),('malformed',b'{'+self.SENTINEL.encode()),('extra',L.encoded(dict(safe,reason=self.SENTINEL))),('wrong-scope',L.encoded(dict(safe,scope=self.SENTINEL))),('aliased',L.encoded(safe))]
   for mode,body in cases:
    with self.subTest(mode=mode):
     if path.exists()or path.is_symlink():path.unlink()
     if mode=='aliased':
      target=root/'different-receipt.json';target.write_bytes(body);target.chmod(0o644);path.symlink_to(target)
     elif body is not None:path.write_bytes(body);path.chmod(0o644)
     result=L.material_failure_data(plan,hold=True);self.assertEqual(result['source_hold']['status'],'NOT_OBSERVED'if mode=='missing'else'UNAVAILABLE_OR_UNSAFE');self.assertNotIn(self.SENTINEL,L.encoded(result).decode())
     self.assertEqual(L.failure_summary(plan,ValueError(self.SENTINEL))[0],dict(phase='material_stage',reason='VALIDATION_REFUSED'))
   path.unlink();path.write_bytes(L.encoded(safe));path.chmod(0o644);self.assertEqual(L.material_failure_data(plan,hold=True)['source_hold']['pin'],L.pin(path.read_bytes()))
   plan.material_session.stage_submitted=False
   with patch.object(L,'read',side_effect=AssertionError('unsubmitted role must not be read')):self.assertEqual(L.material_failure_data(plan,hold=True)['source_hold']['status'],'NOT_OBSERVED')
 def test_real_selection_distinguishes_receipt_validation_and_assembly_failures(self):
  for phase in ('material_receipt','assembly'):
   with self.subTest(phase=phase):
    fixture=self.fixture()
    if phase=='material_receipt':fixture.result['receipt']['verified_files']=516
    with patch.object(fixture.M.A,'assemble_inputs',side_effect=ValueError(self.SENTINEL))as assembler:
     with self.assertRaises(ValueError):fixture.call()
    self.assertEqual(fixture.plan.public_phase,phase);self.assertEqual(assembler.call_count,int(phase=='assembly'));fixture.plan.material_session.close();self.assertEqual(fixture.events,['stage','close'])
    diagnostic,kind=L.failure_summary(fixture.plan,ValueError(self.SENTINEL));self.assertEqual(diagnostic,dict(phase=phase,reason='VALIDATION_REFUSED'));self.assertEqual(kind,'ValueError');self.assertNotIn(self.SENTINEL,L.encoded(diagnostic).decode())
 def source_record(self):
  D,E=self.domain();tmp=tempfile.TemporaryDirectory(prefix='FENCED-source-failure-');self.addCleanup(tmp.cleanup);control=Path(tmp.name);private=control/'private';private.mkdir(mode=0o700)
  context=dict(binding=dict(source='b'*40,run='11',job='12'),FENCED='NOT_NATIVE_CONTEXT');r=dict(control_root=str(control),context=context)
  session=D.MaterialSession(r,(control,dict(nonce='f'*64),{}, {},E,object(),object()));session.stage_submitted=True;session.state='HOLD_CLOSEONLY'
  packet=dict(schema=1,kind='CURRENT_MATERIAL_STAGE_FAILURE_V1',phase='TRANSPORT_NATIVE248',reason='COMMAND_FAILED',command_ordinal=26);raw=D.encoded(packet)
  observation=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=2)
  row=dict(kind='STAGE',natural=False,supervision=observation,output_pin=D.pin(b''),stderr_pin=D.pin(raw),scope_absence=None)
  session.receipts=[row]
  session.retain_stage_failure(row,raw,True);L.write(private/'context.json',L.encoded(context))
  plan=SimpleNamespace(control=control,material_session=session,d=session.d);path=control/'material-stage-failure.json'
  return plan,D,L.decode(path.read_bytes()),path
 def test_source_failure_record_available_and_unavailable_are_diagnostic_only(self):
  plan,D,record,path=self.source_record();selected=L.material_stage_failure(plan)
  self.assertEqual(selected,dict(record,record_pin=L.pin(path.read_bytes())));self.assertEqual(selected['availability'],'AVAILABLE')
  self.assertIsNone(selected['Root_final_acceptance']);self.assertFalse(any(selected[key]for key in ('independent_component_acceptance','hardware_acceptance','release_acceptance')))
  path.unlink();plan.material_session.retain_stage_failure({});unavailable=L.decode(path.read_bytes());plan.material_session.receipts=[dict(kind='STAGE')]
  self.assertEqual(unavailable['availability'],'UNAVAILABLE');self.assertIsNone(unavailable['packet']);self.assertIsNone(unavailable['stderr_pin']);self.assertIsNone(unavailable['retirement_pin']);self.assertIsNone(unavailable['stdout_pin'])
  self.assertEqual(L.material_stage_failure(plan),dict(unavailable,record_pin=L.pin(path.read_bytes())))
 def test_source_failure_rejects_packet_fields_enums_ordinals_and_noncanonical_records(self):
  plan,D,record,path=self.source_record();row=plan.material_session.receipts[0]
  cases=[('extra',dict(record,secret=self.SENTINEL)),('wrong-status',dict(record,status=self.SENTINEL)),('wrong-availability',dict(record,availability=self.SENTINEL)),('acceptance',dict(record,Root_final_acceptance=True)),('bool-schema',dict(record,schema=True))]
  for key,value in (('phase',self.SENTINEL),('reason',self.SENTINEL),('command_ordinal',-1),('command_ordinal',27),('command_ordinal',True),('schema',True),('secret',self.SENTINEL)):
   packet=dict(record['packet'],**{key:value});cases.append(('packet-'+key+'-'+str(value),dict(record,packet=packet,stderr_pin=L.pin(L.encoded(packet)))))
  for name,value in cases:
   with self.subTest(case=name):
    row['stderr_pin']=value['stderr_pin'];path.write_bytes(L.encoded(value));self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'));self.assertNotIn(self.SENTINEL,L.encoded(L.material_stage_failure(plan)).decode())
  row['stderr_pin']=record['stderr_pin']
  for body in (json.dumps(record).encode(),L.encoded(record)+b'\n',b'{'+self.SENTINEL.encode(),b' '*4097):
   path.write_bytes(body);self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'))
 def test_source_failure_requires_exact_record_request_context_and_retirement_joins(self):
  plan,D,record,path=self.source_record();session=plan.material_session;row=session.receipts[0];original=copy.deepcopy(row)
  for key in ('request_pin','context_pin','stdout_pin','stderr_pin','retirement_pin'):
   with self.subTest(join=key):
    path.write_bytes(L.encoded(dict(record,**{key:L.pin(b'wrong join')})));self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'))
  path.write_bytes(L.encoded(record))
  for key,value in (('reaped',False),('ownership','OWNED'),('output_complete',False),('exit',True)):
   with self.subTest(retirement=key):
    row['supervision']=dict(original['supervision'],**{key:value});path.write_bytes(L.encoded(dict(record,retirement_pin=L.pin(L.encoded(row['supervision'])))));self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'))
  row.update(copy.deepcopy(original));path.write_bytes(L.encoded(record))
  session.stage_submitted=False;self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'));session.stage_submitted=True
  for key,value in (('control',plan.control/'other-control'),('request',plan.control/'other-request.json')):
   with self.subTest(session_path=key):
    before=getattr(session,key);setattr(session,key,value);self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'));setattr(session,key,before)
  for target in (session.request,plan.control/'private/context.json'):
   with self.subTest(fixed_input=target.name):
    before=target.read_bytes();target.write_bytes(L.encoded(dict(secret=self.SENTINEL)));self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'));target.write_bytes(before)
  path.unlink();self.assertEqual(L.material_stage_failure(plan),dict(status='NOT_OBSERVED'))
  other=plan.control/'other.json';other.write_bytes(L.encoded(record));path.symlink_to(other);self.assertEqual(L.material_stage_failure(plan),dict(status='UNAVAILABLE_OR_UNSAFE'))


BUDGET_FIXTURE=os.environ.get('CACHY_CURRENT19_BUDGET_FIXTURE')
if BUDGET_FIXTURE:
 class ActualDraftBudgetControls(unittest.TestCase):
  def test_exact_current19_null_authority_bytes_and_pins_still_not_certificate(self):
   root=Path(BUDGET_FIXTURE).resolve();wanted={'Root-request-staging.DRAFT.json':(21488,'babddf4939f6f54215d8f1c640ddf9b90ba22409026e9da767d7aee8622c03ac'),'delegation-optional19.DRAFT.json':(18142,'e003293c4c43a03df20a0de970d57fbd0e16a63485f6e0db6662b62fa1fcfc63'),'assembler-request-backend.DRAFT.json':(623,'150b07ecf971834db1a568ee67ff8b35d6bd2e4b75062dbde72e9c7efb80261f')}
   values={}
   for name,(size,sha)in wanted.items():
    raw=(root/name).read_bytes();self.assertEqual(L.pin(raw),dict(bytes=size,sha256=sha));self.assertEqual(raw,L.encoded(json.loads(raw)));values[name]=json.loads(raw)
   r=values['Root-request-staging.DRAFT.json'];d=values['delegation-optional19.DRAFT.json'];self.assertEqual((len(d['programs']),len(d['materials'])),(17,59))
   self.assertLessEqual(len(L.encoded(r)),L.LIMITS['request_bytes']);self.assertEqual(len(L.assembly_request(r['material_staging']['assembler_request'])),623)
   self.assertIsNone(r['approved']);self.assertIsNone(r['authorization']);self.assertIsNone(d['approved'])
   self.assertTrue(all(values['assembler-request-backend.DRAFT.json'][k]is None for k in L.BASE_FIELDS))


if __name__=='__main__':unittest.main(verbosity=2)
