# SPDX-License-Identifier: MIT
"""Finite inert source/frontier/one-POST controls; no network, Docker or signals."""
import ast,copy,fcntl,importlib.util,json,os,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import driver as D,observe as O,prepare as P
ROOT=Path(os.environ.get('APPS574_GITHUB_CANCEL_SOURCE',HERE.parents[2]))
class Controls(unittest.TestCase):
 def setUp(self):
  block=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));block.start();self.addCleanup(block.stop);self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def env(self):return dict(GITHUB_REPOSITORY=D.REPO,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='12345',SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40)
 def front(self):return dict(status='OBSERVED_OWNED_RUNNING_LIFECYCLE_AND_DIRECT_JOB_LEASES',identity=dict(source_sha='a'*40),cleanup_authority=False)
 def test_default_unbound_before_import_actor_or_network(self):
  policy=self.root/'input-policy.json';policy.write_text(json.dumps(dict(status='UNBOUND_DO_NOT_CANCEL_OR_START',binding=None)))
  with patch.object(D,'HERE',self.root),patch.object(D,'load',side_effect=AssertionError('before source imports')),patch.object(D,'request',side_effect=AssertionError('before network')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):D.source(self.root,'repair-bytes')
 def test_one_actual_own_run_request_intent_and_private_receipts(self):
  with patch.dict(os.environ,self.env(),clear=True),patch.object(D,'request',return_value=dict(http_status=202,response=D.pin(b''),accepted=True,cleanup_authority=False)) as call:
   value=D.cancel_once(self.root,self.front());self.assertEqual(value['status'],'CANCEL_ACCEPTED_ORIGINAL_CLEANUP_PENDING');call.assert_called_once_with(12345)
   with self.assertRaises(FileExistsError):D.cancel_once(self.root,self.front())
   self.assertEqual(call.call_count,1)
  for name in ('before.json','cancel-intent.json','cancel-response.json'):
   self.assertEqual(stat.S_IMODE((self.root/name).stat().st_mode),0o600)
  intent=json.loads((self.root/'cancel-intent.json').read_bytes());self.assertEqual(intent['frontier'],D.pin((self.root/'before.json').read_bytes()));self.assertFalse(intent['cleanup_authority'])
 def test_unknown_http_response_never_retried_or_upgraded(self):
  with patch.dict(os.environ,self.env(),clear=True),patch.object(D,'request',side_effect=TimeoutError) as call:
   self.assertEqual(D.cancel_once(self.root,self.front())['status'],'CANCEL_REQUEST_OUTCOME_UNKNOWN_NO_RETRY')
   with self.assertRaises(FileExistsError):D.cancel_once(self.root,self.front())
   self.assertEqual(call.call_count,1)
 def test_foreign_attempt_repo_source_run_or_frontier_refuses_before_POST(self):
  for key,value in (('GITHUB_REPOSITORY','other/repo'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_RUN_ID','../123'),('GITHUB_SHA','b'*40),('GITHUB_EVENT_NAME','push')):
   with self.subTest(key=key),patch.dict(os.environ,dict(self.env(),**{key:value}),clear=True),patch.object(D,'request',side_effect=AssertionError('no network')):
    with self.assertRaises(ValueError):D.cancel_once(self.root,self.front())
   self.assertFalse((self.root/'cancel-intent.json').exists())
  with patch.dict(os.environ,self.env(),clear=True),self.assertRaises(ValueError):D.cancel_once(self.root,dict(self.front(),status='GUESSED_SLEEP_FRONTIER'))
 def test_original_supervisor_main_and_no_synthetic_signal(self):
  tree=ast.parse((HERE/'driver.py').read_bytes());run=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run');calls=[n for n in ast.walk(run) if isinstance(n,ast.Call)]
  self.assertEqual(sum(isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='original' and n.func.attr=='main' for n in calls),1)
  self.assertFalse(any(isinstance(n.func,ast.Attribute) and n.func.attr in ('kill','killpg','Popen') for n in ast.walk(tree) if isinstance(n,ast.Call)))
  self.assertIn('started+3540',ast.get_source_segment((HERE/'driver.py').read_text(),run));self.assertIn('threading.Thread(target=monitor,daemon=True)',(HERE/'driver.py').read_text())
 def test_real_own_PID_flock_observation_and_absent_lease_refusal(self):
  H=O.helpers(ROOT);lease=self.root/'owner.lock';fd=os.open(lease,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);v=H['held_lease'](lease,os.getpid());self.assertTrue(v['contended']);self.assertEqual(v['owner_pid'],os.getpid());fcntl.flock(fd,fcntl.LOCK_UN)
   with self.assertRaisesRegex(ValueError,'exclusive lease'):H['held_lease'](lease,os.getpid())
  finally:os.close(fd)
 def test_exact_source_pinned_original_phase_rejects_wrong_roles_or_status(self):
  H=O.helpers(ROOT);actors=[dict(role='export',status='PASS_ABSENCE_VERIFIED'),dict(role='extract',status='EXITED',exit=0),dict(role='signer',status='PASS_ABSENCE_VERIFIED',exit=0),dict(role='lifecycle',status='RESERVED',id=None)];H['phase'](actors)
  for index,field,value in ((3,'role','interruption'),(3,'id','foreign'),(1,'exit',1),(0,'status','UNKNOWN')):
   bad=copy.deepcopy(actors);bad[index][field]=value
   with self.assertRaises(ValueError):H['phase'](bad)
 def test_exact_lifecycle_security_and_readonly_mount_refusals(self):
  import types
  def need(v,w):
   if not v:raise ValueError(w)
  C=types.SimpleNamespace(need=need);a=types.SimpleNamespace(source=Path('/source-root'),output=Path('/owned-output'),case='repair-bytes');identity=dict(consumer_token='a'*32)
  security=dict(Privileged=False,ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=['CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_FOWNER','CAP_FSETID','CAP_SETFCAP'],SecurityOpt=['no-new-privileges'],Memory=4*1024**3,NanoCpus=2000000000,PidsLimit=128,Ulimits=[dict(Name='nofile',Hard=8192,Soft=8192)])
  mounts={'/source':(str(a.source),False),'/inputs':(str(a.output/'inputs'),False),'/seed':(str(a.output/'data/original574'),False),'/work':(str(a.output/'work'),True),'/out':(str(a.output/'lifecycle-public'),True)}
  value=dict(HostConfig=security,AppArmorProfile='docker-default',Config=dict(User='0:0',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','/source/scripts/ci/apps-full574-repair-native/lifecycle.py'],Env=['OWNER_TOKEN='+identity['consumer_token'],'CACHY_APPS574_REPAIR_CASE='+a.case]),Mounts=[dict(Type='bind',Destination=n,Source=v[0],RW=v[1]) for n,v in mounts.items()]);O.actor_security(C,value,a,identity)
  for kind in ('cap','profile','command','case','seed'):
   bad=copy.deepcopy(value)
   if kind=='cap':bad['HostConfig']['CapAdd'].append('CAP_SYS_ADMIN')
   if kind=='profile':bad['AppArmorProfile']=''
   if kind=='command':bad['Config']['Cmd']=['foreign']
   if kind=='case':bad['Config']['Env'][-1]='CACHY_APPS574_REPAIR_CASE=repair-missing'
   if kind=='seed':bad['Mounts'][2]['RW']=True
   with self.assertRaises(ValueError):O.actor_security(C,bad,a,identity)
 def test_HTTP_is_one_fixed_own_run_endpoint_and_bounded_no_token_receipt(self):
  from unittest.mock import MagicMock
  response=MagicMock(status=202);response.read.return_value=b'original API response';connection=MagicMock();connection.getresponse.return_value=response
  with patch.object(D,'TOKEN',None),patch.dict(os.environ,GH_TOKEN='inert-test-token'),patch.object(D.http.client,'HTTPSConnection',return_value=connection) as transport:
   result=D.request(12345)
  transport.assert_called_once_with('api.github.com',timeout=20);connection.request.assert_called_once();args,kw=connection.request.call_args;self.assertEqual(args[:2],('POST','/repos/'+D.REPO+'/actions/runs/12345/cancel'));self.assertEqual(kw['headers']['Authorization'],'Bearer inert-test-token');response.read.assert_called_once_with(65537);connection.close.assert_called_once();self.assertNotIn('inert-test-token',json.dumps(result))
 def test_original_actor_bodies_and_always_cleanup_workflow_preserved(self):
  raw=(ROOT/P.NATIVE_WF).read_text();wf=P.workflow(raw);self.assertIn('  actions: write\n',wf);self.assertIn('GH_TOKEN: ${{ github.token }}',wf);self.assertEqual(wf.count('driver.py" run'),1);self.assertEqual(wf.count('driver.py" preflight'),1)
  start='      - name: Retire all actors copies TEST keys and snapshot before producer\n';end='      - name: Upload only the bounded public evidence directory\n';original=raw[raw.index(start):raw.index(end)];self.assertIn(original,wf)
  for s in ('3550s','650s','timeout-minutes: 60','timeout-minutes: 11','--job-outcome','if: always()'):self.assertIn(s,wf)
  self.assertLess(wf.index('driver.py" preflight'),wf.index('Seed the six exact retained inputs'));self.assertIn('apps-full574-github-cancel-${{ github.run_id }}',wf)
 def test_existing_closed_source_rows_and_current_owned_controls(self):
  rows=json.loads((ROOT/D.LANE/'source-manifest.json').read_bytes())['files'];self.assertEqual(len(rows),123)
  for n,row in rows.items():self.assertEqual(D.pin(D.read(ROOT/n,16*1024**2)),row)
  self.assertEqual(D.pin((ROOT/D.NATIVE/'source-manifest.json').read_bytes())['sha256'],D.NATIVE_MF)
  pins=json.loads((HERE/'source-pins.json').read_bytes());self.assertEqual(sum(v=='FROZEN_NATIVE505' for v in pins['origins'].values()),115)
class LauncherControls(unittest.TestCase):
 # Real local processes/flock only. These signals are NOT a GitHub cancellation.
 def route(self,exec_timeout,number,delay_handoff=False):
  import signal,time
  with tempfile.TemporaryDirectory(prefix='cachy-cancel-launcher-') as tmp:
   root=Path(tmp);supervisor=ROOT/'scripts/ci/orphans-full574-native/supervise.py'
   child=root/'child.py';child.write_text("import fcntl,os,signal,sys,time\nfrom pathlib import Path\nr=Path(sys.argv[1])\nf=(r/'lease').open('a');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\ndef stop(n,f):raise SystemExit(0)\nsignal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)\nimport json\nend=time.monotonic()+5\nwhile True:\n try:\n  v=json.loads((r/'handoff.json').read_bytes())\n  if v['job'] is not None and v['job']['pid']==os.getpid():break\n except (FileNotFoundError,json.JSONDecodeError):pass\n if time.monotonic()>=end:raise RuntimeError('complete owned fixture frontier unavailable')\n time.sleep(.01)\n(r/'ready').write_text(str(os.getpid()))\nwhile True:time.sleep(.02)\n")
   runner=root/'runner.py';runner.write_text("import importlib.util,json,sys\nfrom pathlib import Path\ns=importlib.util.spec_from_file_location('original',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nr=Path(sys.argv[2])\nif len(sys.argv)>3:\n import time\n original=m.os.pwrite\n def delayed(fd,raw,offset):\n  if b'\"pid\"' in raw:time.sleep(.05)\n  return original(fd,raw,offset)\n m.os.pwrite=delayed\nv=m.handoff([sys.executable,'-I','-B',str(r/'child.py'),str(r)],r/'handoff.json',{'local':True})\n(r/'returned').write_text(json.dumps(v))\n")
   step=root/'step.sh';step.write_text('set -euo pipefail\n'+('exec ' if exec_timeout else '')+'timeout --signal=TERM --kill-after=30s 3550s '+sys.executable+' -I -B '+str(runner)+' '+str(supervisor)+' '+str(root)+(' delayed' if delay_handoff else '')+'\n')
   proc=subprocess.Popen(['/usr/bin/bash','--noprofile','--norc','-e','-o','pipefail',str(step)],start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);initial=None;timeout_pid=None
   try:
    end=time.monotonic()+5
    while not (root/'ready').exists() and time.monotonic()<end:time.sleep(.01)
    self.assertTrue((root/'ready').exists(),'real owned lease frontier');initial=json.loads((root/'handoff.json').read_bytes());pid=initial['job']['pid'];names=[]
    for _ in range(5):
     statrow=Path('/proc/'+str(pid)+'/stat').read_text();name=statrow.split('(',1)[1].rsplit(')',1)[0];names.append(name);parent=int(statrow.rsplit(')',1)[1].split()[1])
     if name=='timeout':timeout_pid=pid
     if pid==proc.pid:break
     pid=parent
    self.assertEqual(names,['python3','python3','timeout']+([] if exec_timeout else ['bash']));self.assertIsNotNone(timeout_pid)
    os.kill(proc.pid,number);end=time.monotonic()+(5 if exec_timeout else 1)
    while not (root/'returned').exists() and time.monotonic()<end:time.sleep(.01)
    value=json.loads((root/'handoff.json').read_bytes());fd=os.open(root/'lease',os.O_RDWR)
    try:
     try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);available=True
     except BlockingIOError:available=False
    finally:os.close(fd)
    if exec_timeout:
     self.assertEqual(value['status'],'DIRECT_JOB_REAPED_GROUP_ABSENT_INNER_CLEANUP_STILL_REQUIRED');self.assertTrue(value['direct_reaped'] and value['group_absent']);self.assertTrue(available);self.assertEqual(value['cancellation_signal'],number);self.assertLess(value['cancellation_seconds'],5)
    else:
     self.assertEqual(value['status'],'RUNNING_NOT_CLEANUP_AUTHORITY');self.assertFalse(value['direct_reaped'] or value['group_absent'] or available);self.assertFalse((root/'returned').exists())
   finally:
    # Only fixture cleanup after observations; never counted as signal-path proof.
    if timeout_pid:
     try:os.kill(timeout_pid,signal.SIGTERM)
     except ProcessLookupError:pass
    try:proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate(timeout=2)
    if initial:
     with self.assertRaises(ProcessLookupError):os.killpg(initial['job']['pid'],0)
 def test_plain_shell_INT_does_not_reach_original_handler(self):
  import signal
  self.route(False,signal.SIGINT)
 def test_plain_shell_TERM_does_not_reach_original_handler(self):
  import signal
  self.route(False,signal.SIGTERM)
 def test_exec_timeout_INT_retires_original_direct_job_and_lease(self):
  import signal
  self.route(True,signal.SIGINT)
 def test_exec_timeout_INT_waits_for_complete_owned_frontier(self):
  import signal
  self.route(True,signal.SIGINT,delay_handoff=True)
 def test_exec_timeout_TERM_retires_original_direct_job_and_lease(self):
  import signal
  self.route(True,signal.SIGTERM)
 def test_only_actual_run_launcher_changes_and_emitter_matches_workflow(self):
  original=(ROOT/P.WF).read_text();proposed=P.workflow((ROOT/P.NATIVE_WF).read_text());anchor='exec timeout --signal=TERM --kill-after=30s 3550s';self.assertEqual(proposed.count(anchor),1);self.assertEqual(proposed,original);self.assertEqual(__import__('hashlib').sha256(proposed.replace(anchor,anchor[5:]).encode()).hexdigest(),'beccfc02e658f58ce1ffbe80caea4599fc741dc53751349019a07b6f7a9ef2d5')

if __name__=='__main__':unittest.main(verbosity=2)
