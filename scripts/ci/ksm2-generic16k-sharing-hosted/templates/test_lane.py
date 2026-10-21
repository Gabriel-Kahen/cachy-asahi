#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source/emission/refusal controls; no accepting component or VM fixture."""
import argparse,copy,json,os,signal,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import hosted as O,prepare,retain,owner,cleanup,entry
ROOT=None

def sharing_guest_inverse(text):
 O.need(text.count("memory_sharing='PASS_OWNED_VM_ANONYMOUS_SHARING_UNMERGE',sharing=sharing_result,release=")==1,'exact sharing inverse seam');text=text.replace("memory_sharing='PASS_OWNED_VM_ANONYMOUS_SHARING_UNMERGE',sharing=sharing_result,release=","memory_sharing='NOT_TESTED',release=",1)
 O.need(text.count(" result=scalar_case(s,call);preserve();sharing_module=C.load('_ksm_owned_sharing','/source/sharing.py');sharing_result=sharing_module.validate(C.decode(command(['/usr/bin/python3','-I','-B','/source/sharing.py','--owned-parent',str(os.getpid())],seconds=90).encode()),s['nonce']);preserve();command(")==1,'exact sharing inverse seam');text=text.replace(" result=scalar_case(s,call);preserve();sharing_module=C.load('_ksm_owned_sharing','/source/sharing.py');sharing_result=sharing_module.validate(C.decode(command(['/usr/bin/python3','-I','-B','/source/sharing.py','--owned-parent',str(os.getpid())],seconds=90).encode()),s['nonce']);preserve();command(",' result=scalar_case(s,call);preserve();command(',1)
 O.need(__import__('hashlib').sha256(text.encode()).hexdigest()=='a91e86a1db7d5123f02c2d99e101f04ef4075cea3be248cc279b06e4dd5ca24a','whole original625 guest inverse');return text

class Source(unittest.TestCase):
 def test_whole608_role_and_alias(self):
  O.files(ROOT);role=O.decode(O.read(ROOT/O.LANE/'runtime-role.json'));self.assertEqual(len(role['files']),608)
  self.assertEqual({p.relative_to(ROOT/'runtime').as_posix():O.pin(O.read(p))for p in(ROOT/'runtime').rglob('*')if p.is_file()},role['files'])
 def test_popen_blocked_default_preflight(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')):r=entry.preflight(ROOT)
  self.assertEqual(r['actual_run'],None);self.assertEqual(r['runtime']['actual_sysfs'],'NOT_RUN')
 def test_real_emitter_byte_equality(self):
  with tempfile.TemporaryDirectory()as d:
   out=Path(d)/'source'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('source emitter no process')):prepare.assemble(ROOT/'runtime',out,None if O.policy(ROOT)==O.defaults()else ROOT/O.LANE/'input-policy.json')
   self.assertEqual({p.relative_to(out).as_posix():O.pin(O.read(p))for p in out.rglob('*')if p.is_file()},{p.relative_to(ROOT).as_posix():O.pin(O.read(p))for p in ROOT.rglob('*')if p.is_file()and p.relative_to(ROOT).parts[0]not in('.git','.ci-inputs')})
 def test_default_before_io_or_actor(self):
  v=O.defaults()
  with patch.object(O,'read',side_effect=AssertionError('must refuse before IO')),patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):O.components(ROOT,v,{},Path('/unsupplied'),Path('/unsupplied'),Path('/unsupplied'))
 def test_missing_each_selector(self):
  v=O.defaults()
  # No Root decision fixture: only inert syntactic selector values.
  v.update(native_carrier='0'*40,kernel_carrier='1'*40,kernel_run=1)
  for k,path in [('native_inputs','index.json'),('native_decision','Root-acceptance.json'),('kernel_authority','kernel/Root-acceptance.json'),('kernel_transport','kernel/original-transport.json'),('kernel_build','kernel/kernel-artifacts.json')]:v[k]=dict(path=path,bytes=1,sha256='0'*64)
  for k in('native_carrier','kernel_carrier','native_decision','native_inputs','kernel_authority','kernel_transport','kernel_build','kernel_run'):
   bad=copy.deepcopy(v);bad[k]=None
   with self.assertRaisesRegex(ValueError,'UNBOUND'):O.selected(bad)
  for key,value in [('native_carrier','moving-branch'),('kernel_run',True),('actual_run',1)]:
   bad=copy.deepcopy(v);bad[key]=value
   with self.assertRaises(ValueError):O.selected(bad)
  for path in('outside/kernel-artifacts.json','kernel/../kernel-artifacts.json','/kernel/a'):
   bad=copy.deepcopy(v);bad['kernel_build']['path']=path
   with self.assertRaises(ValueError):O.selected(bad)
 def test_duplicate_or_nonfinite_json(self):
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):O.decode(raw)
 def test_source_symlink_or_hardlink_refused(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'a';p.write_bytes(b'x');q=Path(d)/'b';q.symlink_to(p)
   with self.assertRaises(ValueError):O.read(q)
   q.unlink();os.link(p,q)
   with self.assertRaises(ValueError):O.read(p)
 def test_changed_runtime_refused_before_output(self):
  with tempfile.TemporaryDirectory()as d:
   out=Path(d)/'source';fake=Path(d)/'fake';fake.mkdir();(fake/'host.py').write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'whole608'):prepare.assemble(fake,out)
   self.assertFalse(out.exists())
 def test_retention_whitelist_and_actual_pin(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d)/'work';w.mkdir(mode=0o700);(w/'owner-result.json').write_bytes(b'{}\n');(w/'private-map.json').write_bytes(b'NEVER_EXPORT');out=Path(d)/'public';r=retain.run(w,out)
   self.assertEqual(set(r['files']),{'owner-result.json'});self.assertFalse((out/'private-map.json').exists());self.assertEqual(O.pin((out/'owner-result.json').read_bytes()),r['files']['owner-result.json'])
 def test_retention_symlink_refusal(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d)/'work';w.mkdir(mode=0o700);(w/'owner-result.json').symlink_to('/dev/null');out=Path(d)/'public'
   with self.assertRaises(ValueError):retain.run(w,out)
   self.assertFalse(out.exists())
 def test_unknown_group_blocks_cleanup(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d);(w/'commands.json').write_bytes(O.encoded([dict(group_absence_verified=False)]))
   with patch.object(subprocess,'Popen',side_effect=AssertionError('must not invoke Docker')):
    with self.assertRaisesRegex(ValueError,'groups'):cleanup.groups(w)
 def test_missing_qemu_wait_blocks_cleanup(self):
  with tempfile.TemporaryDirectory()as d:
   w=Path(d);(w/'commands.json').write_bytes(O.encoded([dict(group_absence_verified=True)]));(w/'owner-result.json').write_bytes(O.encoded(dict(phase='VM')))
   with self.assertRaisesRegex(ValueError,'QEMU launch/wait'):cleanup.groups(w)
 def test_exact_secrets_and_bounds(self):
  self.assertEqual(len(owner.SECRET_NAMES),24);self.assertEqual(len(set(owner.SECRET_NAMES)),24);self.assertTrue(all(n.startswith(('CACHY_OLD_FOUR_','CACHY_RETAINED_BUBBLEWRAP_V1_'))for n in owner.SECRET_NAMES));self.assertEqual(O.BOUNDS,dict(owner_seconds=6600,producer_seconds=2300,seed_seconds=120,prepare_seconds=1900,VM_seconds=3000,QEMU_output_bytes=16777216,public_output_bytes=201326592))
 def test_source_owned_workflow_order(self):
  text=O.workflow(ROOT).decode();steps=['Exact source proof','Source factory','Require both published','Exact component DATA','Bounded disposable runner','Original574 producer','Retain bounded']
  self.assertEqual([text.index(s)for s in steps],sorted(text.index(s)for s in steps));self.assertIn('Acquire::Retries=0',text);self.assertIn('timeout-minutes: 117',text);self.assertIn('qemu-system-arm',text)
 def test_real_inert_alarm_retires_original_child_group(self):
  R=O.load('_ksm_test_held_supervisor',ROOT/'runtime/borrowed/runtime.py');saved=signal.signal(signal.SIGALRM,owner.interrupted)
  try:
   signal.setitimer(signal.ITIMER_REAL,.15)
   with tempfile.TemporaryDirectory()as d:row,out,err,error=R.run_command([sys.executable,'-I','-B','-c','import time; print("owned",flush=True); time.sleep(10)'],Path(d),dict(PATH='/usr/bin:/bin'),3,4096)
   self.assertIsInstance(error,owner.OwnerInterrupted);self.assertTrue(row['group_absence_verified']);self.assertEqual(out,b'owned\n');self.assertNotEqual(row['exit_code'],0)
  finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,saved)
class WorkerCapture(unittest.TestCase):
 def helper(self,argv=None):
  import ast,contextlib,io,types
  text=prior_retirement(prior_post_removal(before_ldconfig(sharing_guest_inverse((ROOT/'runtime/guest.py').read_text()))));tree=ast.parse(text);n=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='worker_failure_data');raw=ast.get_source_segment(text,n)
  if argv is not None:
   old="['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']";self.assertEqual(raw.count(old),1);raw=raw.replace(old,repr(argv),1)
  C=types.SimpleNamespace(need=O.need,sha=lambda b:__import__('hashlib').sha256(b).hexdigest(),SHARED_SECONDS=3000)
  ns=dict(C=C,json=json);exec(compile(raw,'<source-pinned-failure-helper-test-argv-only>','exec'),ns);return ns['worker_failure_data']
 def child(self,code):
  R=O.load('_ksm_capture_real_held_supervision',ROOT/'runtime/borrowed/runtime.py');argv=[sys.executable,'-I','-B','-c',code]
  with tempfile.TemporaryDirectory()as td:r,out,err,error=R.run_command(argv,Path(td),dict(PATH='/usr/bin:/bin'),3000,512*1024)
  self.assertTrue(r['group_absence_verified']);return argv,r,out,err,error
 def captured(self,fn,row,out,err,error):
  import contextlib,io
  stream=io.StringIO()
  with contextlib.redirect_stdout(stream):fn(dict(nonce='a'*32),row,out,err,error)
  return stream.getvalue()
 def test_whole_original_guest_inverse_and_held_positive_guard(self):
  import ast,hashlib
  text=pre_inner(prior_retirement(prior_post_removal(before_ldconfig(sharing_guest_inverse((ROOT/'runtime/guest.py').read_text())))));tree=ast.parse(text);n=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='worker_failure_data');helper=ast.get_source_segment(text,n)+'\n\n';call=' worker_failure_data(s,row,out,err,error)\n';self.assertEqual(text.count(call),1);inverse=text.replace(helper,'',1).replace(call,'',1);self.assertEqual(hashlib.sha256(inverse.encode()).hexdigest(),'17c9608949accf0e39459c45e07c18533d02cdb5ca8e5f018b3a4d26f0717e9c')
  guard=" C.need(error is None and row['exit_code']==0 and row['group_absence_verified']is True,'whole KSM guest worker exit/group retirement')";self.assertEqual(text.count(guard),1);self.assertLess(text.index(call),text.index(guard));self.assertEqual(O.decode(O.read(ROOT/'runtime/runner-files.json'))['files']['guest.py'],O.pin((ROOT/'runtime/guest.py').read_bytes()))
 def test_real_inert_child_original_stream_record_and_typed_error_DATA(self):
  argv,row,out,err,error=self.child("import sys;print('KSM2_VM_ERROR ValueError inert private failure');sys.stderr.write('inert stderr\\n');sys.exit(1)")
  # Production command-identity guard correctly refuses this different local command.
  self.assertEqual(self.captured(self.helper(),row,out,err,error),'')
  raw=self.captured(self.helper(argv),row,out,err,error);prefix='KSM2_WORKER_FAILURE_DATA '+'a'*32+' ';self.assertTrue(raw.startswith(prefix));value=json.loads(raw[len(prefix):]);self.assertEqual(value['record'],row);self.assertEqual(value['inner_result']['error_type'],'ValueError');self.assertFalse(value['positive_authority']);self.assertFalse(value['cleanup_authority'])
  import base64
  self.assertEqual(base64.b64decode(value['streams']['stdout']['tail_base64']),out);self.assertEqual(base64.b64decode(value['streams']['stderr']['tail_base64']),err)
 def test_real_long_inert_streams_bounded_tails_and_no_positive_frame(self):
  argv,row,out,err,error=self.child("import sys;sys.stdout.write('a'*20000);sys.stderr.write('b'*22000);sys.exit(1)");raw=self.captured(self.helper(argv),row,out,err,error);self.assertLessEqual(len(raw.encode()),32768+80);self.assertNotIn('KSM2_VM ',raw);v=json.loads(raw.split(' ',2)[2]);self.assertEqual(v['inner_result']['status'],'UNKNOWN')
  for name,data,cap in(('stdout',out,4096),('stderr',err,8192)):
   import base64,hashlib
   s=v['streams'][name];self.assertEqual(s['bytes'],len(data));self.assertEqual(s['sha256'],hashlib.sha256(data).hexdigest());self.assertEqual(base64.b64decode(s['tail_base64']),data[-cap:]);self.assertEqual(s['omitted_bytes'],len(data)-cap);self.assertTrue(s['truncated'])
  argv,row,out,err,error=self.child("import sys;sys.stdout.write('KSM2_VM_ERROR ValueError');sys.exit(1)");v=json.loads(self.captured(self.helper(argv),row,out,err,error).split(' ',2)[2]);self.assertEqual(v['inner_result']['status'],'UNKNOWN')
 def test_capture_mismatch_or_diagnostic_io_failure_cannot_replace_original(self):
  argv,row,out,err,error=self.child("raise SystemExit(1)");fn=self.helper(argv)
  for key,val in(('stdout_sha256','0'*64),('stdout_bytes',True),('time_limit',3001),('output_limit',1),('argv',['foreign'])):
   self.assertEqual(self.captured(fn,dict(row,**{key:val}),out,err,error),'')
  with patch('builtins.print',side_effect=OSError('inert closed diagnostic stdout')):fn(dict(nonce='a'*32),row,out,err,error)
 def test_real_success_never_emits_failure_or_changes_record(self):
  argv,row,out,err,error=self.child("print('inert success')");before=copy.deepcopy(row);self.assertEqual(row['exit_code'],0);self.assertEqual(self.captured(self.helper(argv),row,out,err,error),'');self.assertEqual(row,before)

def pre_inner(text):
 import ast
 for name in('command_failure_data','relay_inner_command'):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name);raw=ast.get_source_segment(text,node)+'\n\n';O.need(text.count(raw)==1,'one explicit inner helper inverse');text=text.replace(raw,'',1)
 for call in('  command_failure_data(s,r,out,err,error,expected,seconds,len(rows))\n',' relay_inner_command(s,row,out,err,error)\n'):
  O.need(text.count(call)==1,'one explicit inner call inverse');text=text.replace(call,'',1)
 return text

class InnerCommand(unittest.TestCase):
 def source(self):
  import ast
  text=prior_retirement(prior_post_removal(before_ldconfig(sharing_guest_inverse((ROOT/'runtime/guest.py').read_text()))));tree=ast.parse(text);functions={n.name:ast.get_source_segment(text,n)for n in tree.body if isinstance(n,ast.FunctionDef)};run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run');node=next(n for n in run.body if isinstance(n,ast.FunctionDef)and n.name=='command');return functions,ast.get_source_segment(text,node)
 def namespace(self):
  import types,hashlib
  functions,command=self.source();C=types.SimpleNamespace(need=O.need,sha=lambda b:hashlib.sha256(b).hexdigest(),pin=lambda b:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()),SHARED_SECONDS=3000,encoded=O.encoded);R=O.load('_inner_held_runtime',ROOT/'runtime/borrowed/runtime.py');space=dict(C=C,json=json,Path=Path,time=__import__('time'),runtime=R,rows=[],deadline=__import__('time').monotonic()+3000,s=dict(nonce='c'*32));exec(compile(functions['command_failure_data'],'<exact-source-helper>','exec'),space);exec(compile(command,'<exact-nested-command>','exec'),space);return space
 def captured(self,fn,*args,**kw):
  import contextlib,io
  out=io.StringIO()
  with contextlib.redirect_stdout(out):
   try:value=fn(*args,**kw);error=None
   except BaseException as e:value=None;error=e
  return value,error,out.getvalue()
 def test_whole_source_inverse_and_original_guards(self):
  import hashlib,ast
  text=prior_retirement(prior_post_removal(before_ldconfig(sharing_guest_inverse((ROOT/'runtime/guest.py').read_text()))));self.assertEqual(hashlib.sha256(pre_inner(text).encode()).hexdigest(),'25133a4f0fd9983c02d04f25e2eb8349dd5f5c43895b46803f7d772ad0c09123')
  guard="C.need(error is None and r['exit_code']==expected and r['group_absence_verified']is True,'natural direct installed command/group retirement')";self.assertEqual(text.count(guard),1);self.assertLess(text.index('  command_failure_data(s,r,'),text.index(guard));self.assertEqual(text.count(' worker_failure_data(s,row,out,err,error)\n'),1)
 def test_real_nested_natural_failure_and_success_silence(self):
  ns=self.namespace();argv=[sys.executable,'-I','-B','-c',"import sys;print('inert inner stdout');sys.stderr.write('inert inner stderr\\n');sys.exit(7)"];value,error,text=self.captured(ns['command'],argv);self.assertIsInstance(error,ValueError);self.assertEqual(str(error),'natural direct installed command/group retirement');v=json.loads(text.split(' ',2)[2]);self.assertEqual(v['record'],ns['rows'][0]);self.assertEqual(v['record']['exit_code'],7);self.assertIsNone(v['supervisor_error_type']);self.assertFalse(v['acceptance_authority']);self.assertTrue(v['record']['group_absence_verified'])
  import base64
  self.assertEqual(base64.b64decode(v['streams']['stderr']['tail_base64']),b'inert inner stderr\n');value,error,text=self.captured(ns['command'],[sys.executable,'-I','-B','-c',"print('inert success')"]);self.assertIsNone(error);self.assertEqual(value,'inert success\n');self.assertEqual(text,'')
 def test_real_nested_timeout_and_outputlimit_partial_capture(self):
  for code,seconds,why in(("import time;print('inert start',flush=True);time.sleep(2)",.15,'command-time-limit'),("import sys;sys.stdout.write('x'*160000);sys.stdout.flush()",5,'command-output-limit')):
   ns=self.namespace();_,error,text=self.captured(ns['command'],[sys.executable,'-I','-B','-c',code],seconds=seconds);self.assertEqual(str(error),'natural direct installed command/group retirement');v=json.loads(text.split(' ',2)[2]);self.assertEqual(v['supervisor_error_type'],'ValueError');self.assertEqual(v['supervisor_error_code'],why);self.assertTrue(v['record']['group_absence_verified']);self.assertLessEqual(sum(s['bytes']for s in v['streams'].values()),128*1024);self.assertLessEqual(len(text.encode()),16500)
 def test_relay_full_original_inert_worker_stream_join(self):
  import types,hashlib,base64
  functions,command=self.source();setup="import sys,json,time,types,hashlib\nfrom pathlib import Path\n"+"spec=__import__('importlib.util',fromlist=['']).spec_from_file_location('held',"+repr(str((ROOT/'runtime/borrowed/runtime.py').resolve()))+");runtime=__import__('importlib.util',fromlist=['']).module_from_spec(spec);spec.loader.exec_module(runtime)\n"+"def need(v,w):\n if not v:raise ValueError(w)\n"+"C=types.SimpleNamespace(need=need,sha=lambda b:hashlib.sha256(b).hexdigest());s={'nonce':'"+'c'*32+"'};rows=[];deadline=time.monotonic()+3000\n"+functions['command_failure_data']+'\n'+command+'\n'+"try:command([sys.executable,'-I','-B','-c',\"import sys;sys.stderr.write('inert stderr');sys.exit(7)\"])\nexcept ValueError as e:print('KSM2_VM_ERROR ValueError '+str(e),flush=True);raise SystemExit(1)\n"
  ns=self.namespace();argv=[sys.executable,'-I','-B','-c',setup];R=ns['runtime']
  with tempfile.TemporaryDirectory()as td:row,out,err,error=R.run_command(argv,Path(td),dict(PATH='/usr/bin:/bin'),3000,512*1024)
  self.assertEqual(row['exit_code'],1);self.assertTrue(row['group_absence_verified']);relay=functions['relay_inner_command'];old="['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']";self.assertEqual(relay.count(old),1);space=dict(C=ns['C'],json=json);exec(relay,space);self.assertEqual(self.captured(space['relay_inner_command'],ns['s'],row,out,err,error)[2],'');exec(relay.replace(old,repr(argv)),space);_,e,text=self.captured(space['relay_inner_command'],ns['s'],row,out,err,error);self.assertIsNone(e);v=json.loads(text.split(' ',2)[2]);self.assertEqual(base64.b64decode(v['stdout_base64']),out);self.assertEqual(v['worker_record'],row);self.assertFalse(v['acceptance_authority'])
 def test_tamper_and_failed_diagnostic_do_not_change_original_guard(self):
  ns=self.namespace();row=dict(argv=['inert'],exit_code=7,group_absence_verified=True,seconds=0,time_limit=1,output_limit=128*1024,stdout_bytes=0,stdout_sha256='0'*64,stderr_bytes=0,stderr_sha256='0'*64);_,e,text=self.captured(ns['command_failure_data'],ns['s'],row,b'',b'',None,0,1,1);self.assertIsNone(e);self.assertEqual(text,'')
  with patch('builtins.print',side_effect=OSError('INERT_CLOSED_STDOUT')):
   with self.assertRaisesRegex(ValueError,'natural direct installed command/group retirement'):ns['command']([sys.executable,'-I','-B','-c','raise SystemExit(7)'])


RETIREMENT_HELPERS='\ndef supervision_runtime(runtime,worker=False):\n """Exact borrowed supervisor; reap owned adopted children before real absence."""\n import types\n raw=C.read(Path(runtime.__file__),128*1024)\n C.need(C.sha(raw)==\'4d9aa954d95032ab9ea9085ced784efc81a5db42e2f1f3401e679ee861c16090\',\'whole original command supervisor\')\n before="""            for sig in (signal.SIGTERM,signal.SIGKILL):\n                try:os.killpg(proc.pid,sig)\n                except ProcessLookupError:pass\n            code=proc.wait(timeout=5)\n            try:os.killpg(proc.pid,0)\n            except ProcessLookupError:group_absent=True\n"""\n after="""            # One existing five-second finalization window, including leader wait.\n            finish=time.monotonic()+5\n            for sig in (signal.SIGTERM,signal.SIGKILL):\n                try:os.killpg(proc.pid,sig)\n                except ProcessLookupError:pass\n            code=proc.wait(timeout=max(0,finish-time.monotonic()))\n            # The guest worker is a child subreaper. Adopted descendants in this\n            # exact PGID must be genuinely reaped; zombies are never ignored.\n            reaped=0\n            while True:\n                try:\n                    while True:\n                        child,_status=os.waitpid(-proc.pid,os.WNOHANG)\n                        if child==0:break\n                        reaped+=1;need(reaped<=512,\'owned-command-child-bound\')\n                except ChildProcessError:pass\n                try:os.killpg(proc.pid,0)\n                except ProcessLookupError:group_absent=True;break\n                remaining=finish-time.monotonic()\n                if remaining<=0:break\n                time.sleep(min(.01,remaining))\n"""\n C.need(raw.count(before.encode())==1,\'one exact owned-group finalization seam\')\n derived=raw.replace(before.encode(),after.encode())\n C.need(derived.replace(after.encode(),before.encode())==raw,\'whole supervisor finalization inverse\')\n if worker:\n  # Only the already guarded dedicated guest worker changes its own adoption.\n  libc=ctypes.CDLL(None,use_errno=True);value=ctypes.c_int(-1)\n  C.need(libc.prctl(36,1,0,0,0)==0 and libc.prctl(37,ctypes.byref(value),0,0,0)==0 and value.value==1,\'worker child subreaper verified\')\n module=types.ModuleType(\'_ksm_owned_group_supervisor\');module.__file__=runtime.__file__\n exec(compile(derived,runtime.__file__+\':owned-group-retirement\',\'exec\'),module.__dict__)\n return module\n\n'
RETIREMENT_PROCESS_CONTROL='"""Real isolated Linux fork/group controls; never a native/VM or package actor."""\nimport argparse,ast,ctypes,hashlib,importlib.util,json,os,signal,subprocess,sys,time,types\nfrom pathlib import Path\nHERE=Path(__file__).resolve().parent\nSOURCE=Path(os.environ.get(\'KSM_RETIREMENT_SOURCE\',str(HERE/\'source-ready\')))\nif not SOURCE.exists():SOURCE=HERE.parent/\'ksm2-inner-command-trial-root-20261018/source\'\ndef module(name,path):\n s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m\ndef helper():\n path=SOURCE/\'runtime/guest.py\';tree=ast.parse(path.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==\'supervision_runtime\')\n contract=module(\'local_retirement_contract\',SOURCE/\'runtime/contract.py\');ns=dict(C=contract,Path=Path,ctypes=ctypes)\n exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),\'exec\'),ns);return ns[\'supervision_runtime\']\nLEADER="""import os,time\nr,w=os.pipe();child=os.fork()\nif child==0:\n os.close(r);os.close(0);os.close(1);os.close(2);os.write(w,b\'X\');os.close(w);time.sleep(60);os._exit(0)\nos.close(w);assert os.read(r,1)==b\'X\';os.close(r);print(str(os.getpid())+\' \'+str(child),flush=True);os._exit(0)\n"""\ndef enable():\n v=ctypes.c_int(-1);libc=ctypes.CDLL(None,use_errno=True)\n assert libc.prctl(36,1,0,0,0)==0 and libc.prctl(37,ctypes.byref(v),0,0,0)==0 and v.value==1\ndef worker(mode):\n runtime=module(\'local_original_supervisor\',SOURCE/\'runtime/borrowed/runtime.py\')\n if mode!=\'old\':runtime=helper()(runtime,worker=mode==\'fixed\')\n # This unrelated same-parent zombie is not a member of the command PGID.\n # The command-specific reaper must leave its wait status for this owner.\n unrelated=os.fork()\n if unrelated==0:os.setsid();os._exit(19)\n end=time.monotonic()+2\n while os.waitid(os.P_PID,unrelated,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None:\n  assert time.monotonic()<end;time.sleep(.001)\n row,out,err,error=runtime.run_command([sys.executable,\'-I\',\'-B\',\'-c\',LEADER],Path(\'/tmp\'),dict(PATH=\'/usr/bin:/bin\',LANG=\'C\'),2,4096)\n unconsumed=os.waitid(os.P_PID,unrelated,os.WEXITED|os.WNOHANG|os.WNOWAIT);assert unconsumed.si_pid==unrelated and unconsumed.si_status==19;assert os.waitpid(unrelated,0)[0]==unrelated\n group,grandchild=map(int,out.split());print(json.dumps(dict(mode=mode,row=row,group=group,grandchild=grandchild,error=None if error is None else type(error).__name__,unrelated_status_held=True)),flush=True)\ndef outer(mode):\n # Emulate the pinned PID1 adoption relationship only in this private process.\n enable();p=subprocess.run([sys.executable,\'-I\',\'-B\',str(Path(__file__).resolve()),\'worker\',mode],capture_output=True,timeout=12)\n assert p.returncode==0,p.stderr.decode();v=json.loads(p.stdout);pid=v[\'grandchild\'];state=None\n try:\n  status=Path(\'/proc\')/str(pid)/\'status\';text=status.read_text();fields=dict(line.split(\':\',1)for line in text.splitlines()if \':\'in line);state=dict(state=fields[\'State\'].strip().split()[0],parent=int(fields[\'PPid\']),group=os.getpgid(pid))\n except FileNotFoundError:pass\n v[\'adopted_state_before_outer_reap\']=state\n reaped=[]\n while True:\n  try:\n   child,status=os.waitpid(-1,os.WNOHANG)\n   if child==0:break\n   reaped.append(child)\n  except ChildProcessError:break\n v[\'outer_adopted_reaped_count\']=len(reaped)\n try:os.killpg(v[\'group\'],0);absent=False\n except ProcessLookupError:absent=True\n assert absent,\'owned local fixture group must be retired even on refusal\'\n if mode==\'fixed\':assert v[\'row\'][\'group_absence_verified\']is True and state is None\n else:assert v[\'row\'][\'group_absence_verified\']is False and state and state[\'state\']==\'Z\'and state[\'parent\']==os.getpid()and state[\'group\']==v[\'group\']\n assert v[\'row\'][\'exit_code\']==0 and v[\'error\']is None and v[\'unrelated_status_held\']is True\n assert v[\'row\'][\'seconds\']<=7 and v[\'row\'][\'time_limit\']==2 and v[\'row\'][\'output_limit\']==4096\n print(json.dumps(dict(context=\'LOCAL_INERT_FORK_GROUP_CONTROL_NOT_NATIVE_VM_OR_PACKAGE\',**v)))\ndef main():\n p=argparse.ArgumentParser();p.add_argument(\'role\',choices=[\'worker\',\'outer\']);p.add_argument(\'mode\',choices=[\'old\',\'adapter-only\',\'fixed\']);a=p.parse_args()\n (worker if a.role==\'worker\'else outer)(a.mode)\nif __name__==\'__main__\':main()\n'

def prior_retirement(text):
 import hashlib
 original="runtime=C.load('_ksm_vm_supervision','/source/borrowed/runtime.py')"
 changed=original+';runtime=supervision_runtime(runtime,worker=True)'
 old_pid1="R=C.load('_ksm_pid1_supervision','/source/borrowed/runtime.py');row,out,err,error="
 new_pid1="R=C.load('_ksm_pid1_supervision','/source/borrowed/runtime.py');R=supervision_runtime(R);row,out,err,error="
 O.need(text.count(RETIREMENT_HELPERS)==text.count(changed)==text.count(new_pid1)==1,'one exact worker/guest group-retirement seam')
 raw=text.replace(RETIREMENT_HELPERS,'',1).replace(changed,original,1).replace(new_pid1,old_pid1,1)
 O.need(hashlib.sha256(raw.encode()).hexdigest()=='5b6949572da21fd967ffcfff198501e2a9215f1a51b9a26633cfba3f9cbe087c','whole prior guest inverse')
 return raw

class OwnedProcessRetirement(unittest.TestCase):
 def check_mode(self,mode):
  with tempfile.TemporaryDirectory()as td:
   script=Path(td)/'process_control.py';script.write_text(RETIREMENT_PROCESS_CONTROL)
   env=dict(os.environ,KSM_RETIREMENT_SOURCE=str(ROOT))
   p=subprocess.run([sys.executable,'-I','-B',str(script),'outer',mode],env=env,capture_output=True,timeout=14)
  self.assertEqual(p.returncode,0,p.stderr.decode());v=json.loads(p.stdout);self.assertEqual(v['context'],'LOCAL_INERT_FORK_GROUP_CONTROL_NOT_NATIVE_VM_OR_PACKAGE');self.assertIsNone(v['error']);self.assertEqual(v['row']['exit_code'],0);self.assertTrue(v['unrelated_status_held']);return v
 def test_real_orphan_zombie_old_refusal_and_subreaper_group_retirement(self):
  old=self.check_mode('old');new=self.check_mode('fixed');self.assertFalse(old['row']['group_absence_verified']);self.assertEqual(old['adopted_state_before_outer_reap']['state'],'Z');self.assertEqual(old['outer_adopted_reaped_count'],1);self.assertTrue(new['row']['group_absence_verified']);self.assertIsNone(new['adopted_state_before_outer_reap']);self.assertEqual(new['outer_adopted_reaped_count'],0)
 def test_real_no_subreaper_does_not_ignore_existing_zombies(self):
  v=self.check_mode('adapter-only');self.assertFalse(v['row']['group_absence_verified']);self.assertEqual(v['adopted_state_before_outer_reap']['state'],'Z');self.assertGreaterEqual(v['row']['seconds'],5);self.assertLess(v['row']['seconds'],7)
 def test_whole_guest_inverse_and_original_guards_protocol_limits_held(self):
  text=prior_post_removal(before_ldconfig(sharing_guest_inverse((ROOT/'runtime/guest.py').read_text())));old=prior_retirement(text)
  import ast,hashlib
  before={n.name:ast.get_source_segment(old,n)for n in ast.parse(old).body if isinstance(n,ast.FunctionDef)}
  after={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(set(after)-set(before),{'supervision_runtime'})
  self.assertEqual({n for n in before if before[n]!=after[n]},{'run','main'})
  for guard in("natural direct installed command/group retirement","whole KSM guest worker exit/group retirement","unknown non-kernel guest process remains"):
   self.assertEqual(text.count(guard),old.count(guard))
  self.assertIn('finish=time.monotonic()+5',RETIREMENT_HELPERS);self.assertIn('os.waitpid(-proc.pid,os.WNOHANG)',RETIREMENT_HELPERS)
  self.assertIn('code=proc.wait(timeout=max(0,finish-time.monotonic()))',RETIREMENT_HELPERS)
 def test_changed_borrowed_source_and_failed_subreaper_refuse_before_command(self):
  import ast,ctypes,types
  raw=prior_post_removal(before_ldconfig(sharing_guest_inverse((ROOT/'runtime/guest.py').read_text())));node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='supervision_runtime')
  C=types.SimpleNamespace(read=lambda *a:(ROOT/'runtime/borrowed/runtime.py').read_bytes(),sha=lambda raw:__import__('hashlib').sha256(raw).hexdigest(),need=O.need)
  ns=dict(C=C,Path=Path,ctypes=ctypes);exec(compile(ast.Module(body=[node],type_ignores=[]),'<source-owned-group-helper>','exec'),ns);runtime=types.SimpleNamespace(__file__=str(ROOT/'runtime/borrowed/runtime.py'))
  with patch.object(C,'read',return_value=b'INERT_DRIFT'):
   with self.assertRaisesRegex(ValueError,'whole original'):ns['supervision_runtime'](runtime,worker=True)
  libc=types.SimpleNamespace(prctl=lambda *a:-1)
  with patch.object(ctypes,'CDLL',return_value=libc):
   with self.assertRaisesRegex(ValueError,'subreaper verified'):ns['supervision_runtime'](runtime,worker=True)

POST_REMOVAL_HELPER='def post_removal_data(s,expected,actual):\n """Existing failed maps only; bounded path/field/hash DATA, never acceptance."""\n try:\n  if expected==actual:return\n  import re\n  C.need(type(s.get(\'nonce\'))is str and re.fullmatch(\'[a-f0-9]{32}\',s[\'nonce\'])and type(expected)is type(actual)is dict and len(expected)<=200000 and len(actual)<=200000,\'bounded original map failure context\')\n  def whole(value):\n   raw=C.encoded(value);C.need(len(raw)<=64*1024**2,\'original node-map byte cap\');return dict(nodes=len(value),**C.pin(raw))\n  before_map=whole(expected);after_map=whole(actual);counts=dict(added=0,removed=0,changed=0);first=None\n  for name in expected.keys()|actual.keys():\n   C.need(type(name)is str,\'typed existing node path\')\n   if name not in expected:kind=\'added\'\n   elif name not in actual:kind=\'removed\'\n   elif expected[name]!=actual[name]:kind=\'changed\'\n   else:continue\n   counts[kind]+=1\n   if first is None or name<first:first=name\n  C.need(first is not None,\'actual map mismatch required\')\n  a=expected.get(first);b=actual.get(first);C.need((a is None or type(a)is dict)and(b is None or type(b)is dict),\'typed existing node records\')\n  fields=sorted(k for k in set(a or{})|set(b or{})if a is None or b is None or a.get(k)!=b.get(k))\n  C.need(set(fields)<={\'type\',\'mode\',\'uid\',\'gid\',\'bytes\',\'sha256\',\'target\',\'hardlink_group\'},\'source-owned node fields only\')\n  path=first.encode(\'utf8\');preview=first[:80]\n  value=dict(schema_version=1,status=\'POST_REMOVAL_NODE_MAP_FAILURE_DATA_ONLY\',nonce=s[\'nonce\'],expected=before_map,actual=after_map,counts=counts,first=dict(path=preview,path_utf8_bytes=len(path),path_sha256=C.sha(path),path_truncated=preview!=first,kind=(\'added\'if a is None else\'removed\'if b is None else\'changed\'),fields=fields,before=None if a is None else C.pin(C.encoded(a)),after=None if b is None else C.pin(C.encoded(b))),acceptance_authority=False,cleanup_authority=False)\n  prefix=\'KSM2_POST_REMOVAL_DATA \'+s[\'nonce\']+\' \'\n  raw=json.dumps(value,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\n  if len((prefix+raw+\'\\n\').encode())>2048:\n   value[\'first\'][\'path\']=first[:16];value[\'first\'][\'path_truncated\']=value[\'first\'][\'path\']!=first;raw=json.dumps(value,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)\n  C.need(len((prefix+raw+\'\\n\').encode())<=2048,\'post-removal DATA2KiB including frame\')\n  print(prefix+raw,flush=True)\n except BaseException:return\n\n'
POST_REMOVAL_OLD=";C.need(last_nodes==permitted,'complete post-removal node/hash/hardlink map; only existing ALPM log append permitted');command("
POST_REMOVAL_NEW=";\n try:\n  C.need(last_nodes==permitted,'complete post-removal node/hash/hardlink map; only existing ALPM log append permitted')\n except BaseException:\n  post_removal_data(s,permitted,last_nodes)\n  raise\n command("
def prior_post_removal(text):
 import hashlib
 O.need(text.count(POST_REMOVAL_HELPER)==text.count(POST_REMOVAL_NEW)==1,'one exact post-removal diagnostic seam')
 old=text.replace(POST_REMOVAL_HELPER,'',1).replace(POST_REMOVAL_NEW,POST_REMOVAL_OLD,1)
 O.need(hashlib.sha256(old.encode()).hexdigest()=='1772cac7f2b1dfa6b7e010e249bc969fbaa5b73bf11a1eca84fe1ad597a3c9e1','whole group-retirement guest inverse')
 return old

class PostRemovalData(unittest.TestCase):
 def helper(self):
  import ast,types
  text=before_ldconfig(sharing_guest_inverse((ROOT/'runtime/guest.py').read_text()));node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='post_removal_data')
  c=types.SimpleNamespace(need=O.need,encoded=O.encoded,pin=O.pin,sha=lambda b:__import__('hashlib').sha256(b).hexdigest());ns=dict(C=c,json=json);exec(compile(ast.Module(body=[node],type_ignores=[]),'<source-owned-map-data>','exec'),ns);return ns,c,text
 def output(self,fn,before,after):
  import contextlib,io
  stream=io.StringIO()
  with contextlib.redirect_stdout(stream):fn(dict(nonce='e'*32),before,after)
  raw=stream.getvalue().encode();self.assertLessEqual(len(raw),2048)
  if raw:
   prefix=b'KSM2_POST_REMOVAL_DATA '+b'e'*32+b' ';self.assertTrue(raw.startswith(prefix)and raw.endswith(b'\n'));v=json.loads(raw[len(prefix):]);self.assertFalse(v['acceptance_authority']);self.assertFalse(v['cleanup_authority']);self.assertEqual(v['expected'],dict(nodes=len(before),**O.pin(O.encoded(before))));self.assertEqual(v['actual'],dict(nodes=len(after),**O.pin(O.encoded(after))));return raw,v
  return raw,None
 def observe(self,root):
  # Real private filesystem rows matching the admitted node DATA vocabulary;
  # this is not a complete native574 preservation or accepting fixture.
  import stat,hashlib
  rows={};groups={}
  for p in sorted(root.rglob('*')):
   n=p.relative_to(root).as_posix();s=p.lstat();v=dict(mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)
   if p.is_symlink():v.update(type='symlink',target=os.readlink(p))
   elif p.is_dir():v.update(type='directory')
   else:
    raw=p.read_bytes();v.update(type='file',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    if s.st_nlink>1:groups.setdefault((s.st_dev,s.st_ino),[]).append(n)
   rows[n]=v
  for members in groups.values():
   for n in members:rows[n]['hardlink_group']=members[0]
  return rows
 def test_real_private_node_hash_mode_link_graph_membership_changes(self):
  ns,c,_=self.helper()
  for kind in('content','mode','target','hardlink','added','removed'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);(root/'a').write_bytes(b'private-before-content');(root/'b').write_bytes(b'private-before-content');(root/'link').symlink_to('a');before=self.observe(root)
    if kind=='content':(root/'a').write_bytes(b'private-after-content')
    if kind=='mode':(root/'a').chmod(0o600)
    if kind=='target':(root/'link').unlink();(root/'link').symlink_to('b')
    if kind=='hardlink':(root/'b').unlink();os.link(root/'a',root/'b')
    if kind=='added':(root/'new').write_bytes(b'PRIVATE_NOT_EXPORTED')
    if kind=='removed':(root/'a').unlink()
    after=self.observe(root);raw,v=self.output(ns['post_removal_data'],before,after);self.assertIsNotNone(v);names=sorted(n for n in before.keys()|after.keys()if before.get(n)!=after.get(n));first=names[0];self.assertEqual(v['first']['path'],first);self.assertEqual(sum(v['counts'].values()),len(names));self.assertEqual(v['first']['before'],None if first not in before else O.pin(O.encoded(before[first])));self.assertEqual(v['first']['after'],None if first not in after else O.pin(O.encoded(after[first])));self.assertNotIn(b'private-before-content',raw);self.assertNotIn(b'private-after-content',raw);self.assertNotIn(b'PRIVATE_NOT_EXPORTED',raw)
 def test_unicode_bound_no_values_and_success_silence(self):
  ns,c,_=self.helper();name='dir/'+chr(0x1f600)*1000;before={name:dict(type='symlink',mode=511,uid=0,gid=0,target='PRIVATE_TARGET_A')};after={name:dict(before[name],target='PRIVATE_TARGET_B')};raw,v=self.output(ns['post_removal_data'],before,after);self.assertIsNotNone(v);self.assertTrue(v['first']['path_truncated']);self.assertEqual(v['first']['fields'],['target']);self.assertNotIn(b'PRIVATE_TARGET',raw);self.assertEqual(v['first']['path_sha256'],__import__('hashlib').sha256(name.encode()).hexdigest());self.assertEqual(self.output(ns['post_removal_data'],before,before),(b'',None))
 def test_whole_guard_inverse_bare_reraise_and_no_new_scan(self):
  import ast,contextlib,io
  ns,c,text=self.helper();old=prior_post_removal(text);before={n.name:ast.get_source_segment(old,n)for n in ast.parse(old).body if isinstance(n,ast.FunctionDef)};after={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)};self.assertEqual(set(after)-set(before),{'post_removal_data'});self.assertEqual({n for n in before if before[n]!=after[n]},{'run'})
  helper=after['post_removal_data'];self.assertFalse(any(s in helper for s in('C.read(','.source_nodes(','.stat(','.open(','.walk(','.iterdir(')));run=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='run');guard=next(n for n in ast.walk(run)if isinstance(n,ast.Try)and any(isinstance(x,ast.ExceptHandler)and any(isinstance(y,ast.Raise)and y.exc is None for y in x.body)for x in n.handlers));expected=ValueError('complete post-removal node/hash/hardlink map; only existing ALPM log append permitted')
  def need(ok,why):
   if not ok:raise expected
  c.need=need;ns.update(s=dict(nonce='e'*32),permitted={'a':dict(type='file',bytes=1)},last_nodes={'a':dict(type='file',bytes=2)})
  with patch.object(c,'encoded',side_effect=RuntimeError('DIAGNOSTIC_LOSS')):
   with self.assertRaises(ValueError)as caught:exec(compile(ast.Module(body=[guard],type_ignores=[]),'<exact-guard-test>','exec'),ns)
  self.assertIs(caught.exception,expected);ns['last_nodes']=ns['permitted'];stream=io.StringIO()
  with contextlib.redirect_stdout(stream):exec(compile(ast.Module(body=[guard],type_ignores=[]),'<exact-guard-pass>','exec'),ns)
  self.assertEqual(stream.getvalue(),'')
 def test_original_real_worker_capture_keeps_complete_bounded_marker(self):
  ns,c,_=self.helper();before={'a':dict(type='file',mode=420,uid=0,gid=0,bytes=1,sha256='0'*64)};after={'a':dict(before['a'],sha256='1'*64)};marker,_=self.output(ns['post_removal_data'],before,after);error=b'KSM2_VM_ERROR ValueError complete post-removal node/hash/hardlink map; only existing ALPM log append permitted\n';case=WorkerCapture(methodName='runTest');argv,row,out,err,exc=case.child('import sys;sys.stdout.buffer.write('+repr(marker+error)+');sys.exit(1)');
  import contextlib,io
  stream=io.StringIO()
  with contextlib.redirect_stdout(stream):case.helper(argv)(dict(nonce='e'*32),row,out,err,exc)
  captured=json.loads(stream.getvalue().split(' ',2)[2]);self.assertEqual(captured['nonce'],'e'*32);self.assertEqual(out,marker+error);self.assertLess(len(out),4096);self.assertEqual(captured['streams']['stdout']['bytes'],len(out));self.assertEqual(captured['streams']['stdout']['omitted_bytes'],0);self.assertFalse(captured['streams']['stdout']['truncated']);self.assertFalse(captured['positive_authority'])

ARCHIVE20_OWNER_HELPER='def seed_archive20(root,runtime,archive32_cache,deps,work):\n """Seed only whole-pinned original20; no version/trust or producer command changes."""\n cache=archive32_cache.parent/\'ksm2-archive20\'\n policy_path=root/O.LANE/\'archive20-policy.json\'\n value=A20.policy(policy_path,runtime/\'borrowed/maintained574-inputs.json\')\n custody=A20.seed_exact(cache,deps,value)\n custody.update(policy=O.pin(O.read(policy_path)),files={n:{k:r[k]for k in(\'bytes\',\'sha256\')}for n,r in value[\'files\'].items()},versions=\'UNCHANGED_FROZEN574_LOCK\',trust=\'UNCHANGED_ORIGINAL_SIGNATURE_AND_KEYRING_CHECKS\')\n O.save(work/\'archive20-custody.json\',custody)\n return custody\n\n'
ARCHIVE20_OWNER_CALL="  seed_archive20(root,runtime,a.archive_cache,producer/'context/deps',a.work)\n"
ARCHIVE20_WORKFLOW_STEP='      - name: Prefetch exact20 additional frozen574 archive bytes before unchanged producer\n        timeout-minutes: 4\n        run: >-\n          python3 -I -B "$GITHUB_WORKSPACE/$SLICE/archive20.py" --policy "$GITHUB_WORKSPACE/$SLICE/archive20-policy.json"\n          --inputs "$GITHUB_WORKSPACE/runtime/borrowed/maintained574-inputs.json"\n          --cache "$RUNNER_TEMP/ksm2-archive20"\n'
ARCHIVE20_BEFORE_PINS={'owner.py': {'bytes': 6817, 'sha256': '6fe48adbd135485bc950f1a81182b45f4bc83acd9e53817ae6f58623e737117e'}, 'workflow.yml.in': {'bytes': 6593, 'sha256': 'b0fb2c242121730bf47c8027446e974c802371689dd9ab41acc08a43078babd6'}, 'retain.py': {'bytes': 2240, 'sha256': 'c49661a126bf0a16d1ec720379fefb786d50099d292baa972958d8a392c9fe9a'}}
class Archive20Integration(unittest.TestCase):
 def test_exact_frozen_helper_policy_whole_lock_and_disjoint_original32(self):
  import archive20 as A20,archive32 as A32,hashlib
  self.assertEqual(O.pin(O.read(ROOT/O.LANE/'archive20.py')),dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'))
  self.assertEqual(O.pin(O.read(ROOT/O.LANE/'archive20-policy.json')),dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'))
  lock=ROOT/'runtime/borrowed/maintained574-inputs.json';a=A20.policy(ROOT/O.LANE/'archive20-policy.json',lock);b=A32.policy(ROOT/O.LANE/'archive32-policy.json',lock)
  self.assertEqual((len(a['files']),sum(r['bytes']for r in a['files'].values())),(20,2793312));self.assertFalse(set(a['files'])&set(b['files']));self.assertEqual(a['original_inputs'],b['original_inputs']);self.assertEqual(a['original_inputs'],dict(bytes=623664,sha256='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'))
 def test_exact_owner_workflow_retainer_inverse_and_three_commands_held(self):
  import ast,hashlib
  text=before_archive8((ROOT/O.LANE/'owner.py').read_text(),'owner.py');self.assertEqual(text.count(ARCHIVE20_OWNER_HELPER),1);self.assertEqual(text.count(ARCHIVE20_OWNER_CALL),1)
  old=text.replace('import archive20 as A20\n','',1).replace(ARCHIVE20_OWNER_HELPER,'',1).replace(ARCHIVE20_OWNER_CALL,'',1)
  self.assertEqual(O.pin(old.encode()),ARCHIVE20_BEFORE_PINS['owner.py'])
  calls=lambda raw:[ast.dump(n,include_attributes=False)for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='command']
  self.assertEqual(len(calls(old)),3);self.assertEqual(calls(old),calls(text));self.assertLess(text.index(ARCHIVE20_OWNER_CALL),text.index("'build','--inputs'"));self.assertGreater(text.index(ARCHIVE20_OWNER_CALL),text.index("O.save(a.work/'archive32-custody.json'"))
  template=before_archive8((ROOT/O.LANE/'workflow.yml.in').read_text(),'workflow.yml.in');self.assertEqual(template.count(ARCHIVE20_WORKFLOW_STEP),1);self.assertEqual(O.pin(template.replace(ARCHIVE20_WORKFLOW_STEP,'',1).encode()),ARCHIVE20_BEFORE_PINS['workflow.yml.in'])
  raw=before_archive8((ROOT/O.LANE/'retain.py').read_text(),'retain.py');self.assertEqual(O.pin(raw.replace("FIXED={'archive20-custody.json','archive32-custody.json',","FIXED={'archive32-custody.json',",1).encode()),ARCHIVE20_BEFORE_PINS['retain.py'])
  self.assertEqual(O.BOUNDS,dict(owner_seconds=6600,producer_seconds=2300,seed_seconds=120,prepare_seconds=1900,VM_seconds=3000,QEMU_output_bytes=16777216,public_output_bytes=201326592));self.assertIn('timeout-minutes: 4',ARCHIVE20_WORKFLOW_STEP)
 def test_actual_workflow_absolute_cli_policy_under_foreign_cwd_before_network(self):
  import shlex
  text=O.workflow(ROOT).decode();start=text.index('      - name: Prefetch exact20');block=text[start:text.index('      - name:',start+10)];command=block.split('        run: >-\n',1)[1];command=' '.join(line.strip()for line in command.splitlines()if line.startswith('          '))
  script=r'''import runpy,sys,types,urllib.request
mode=sys.argv[1];sys.argv=[sys.argv[2],*sys.argv[3:]];calls=[]
def blocked(*args,**kwargs):
 calls.append(1);raise RuntimeError('NETWORK_FORBIDDEN_AFTER_VALIDATED_POLICY')
urllib.request.build_opener=lambda *args:types.SimpleNamespace(open=blocked)
try:runpy.run_path(sys.argv[0],run_name='__main__')
except ValueError as error:
 assert mode=='relative'and str(error)=='ordinary archive20 path'and not calls;print('RELATIVE_POLICY_REFUSED_BEFORE_NETWORK')
except RuntimeError as error:
 assert mode=='absolute'and str(error)=='NETWORK_FORBIDDEN_AFTER_VALIDATED_POLICY'and calls==[1];print('ABSOLUTE_POLICY_AND_LOCK_VALIDATED_NETWORK_BLOCKED')
else:raise AssertionError('No real CLI refusal')
'''
  with tempfile.TemporaryDirectory()as td:
   for mode in('relative','absolute'):
    expanded=command.replace('$GITHUB_WORKSPACE',str(ROOT)).replace('$SLICE',O.LANE).replace('$RUNNER_TEMP',td);argv=shlex.split(expanded);self.assertEqual(argv[:3],['python3','-I','-B']);args=argv[4:]
    for key in('--policy','--inputs','--cache'):self.assertTrue(Path(args[args.index(key)+1]).is_absolute())
    self.assertEqual(Path(args[args.index('--cache')+1]),Path(td)/'ksm2-archive20')
    if mode=='relative':args[args.index('--policy')+1]=O.LANE+'/archive20-policy.json'
    row=subprocess.run([sys.executable,'-I','-B','-c',script,mode,argv[3],*args],cwd=td,capture_output=True,timeout=10);self.assertEqual(row.returncode,0,(row.stdout,row.stderr));self.assertEqual(row.stderr,b'');self.assertIn(b'RELATIVE_POLICY_REFUSED_BEFORE_NETWORK'if mode=='relative'else b'ABSOLUTE_POLICY_AND_LOCK_VALIDATED_NETWORK_BLOCKED',row.stdout)
 def tiny(self):
  import archive20 as A20
  data={'a.pkg':b'one','a.pkg.sig':b'two'};v=dict(files={n:dict(bytes=len(b),sha256=O.pin(b)['sha256'],url='https://pkgmirror.sametimetomorrow.net/'+n)for n,b in data.items()},original_inputs=dict(bytes=1,sha256='0'*64));return A20,data,v
 def test_private_seed_exact_unrelated_preservation_idempotence_and_drift_refusal(self):
  A20,data,v=self.tiny()
  with tempfile.TemporaryDirectory()as td,patch.object(A20,'TOTAL',6):
   root=Path(td);cache=root/'cache';cache.mkdir(mode=0o700);deps=root/'deps';deps.mkdir(mode=0o700);unrelated=deps/'original-other';unrelated.write_bytes(b'ORIGINAL_OTHER_KEEP');before=A20.ordinary(unrelated)
   for n,b in data.items():(cache/n).write_bytes(b)
   index=dict(schema_version=1,status='EXACT_FROZEN574_ARCHIVE20_BYTES_ONLY_NOT_NATIVE_ACCEPTANCE',original_inputs=v['original_inputs'],files={n:O.pin(b)for n,b in data.items()},bytes=6,requests=0,reused=2,seconds_limit=180);(cache/'archive20-index.json').write_bytes(A20.encoded(index));A20.seed_exact(cache,deps,v);A20.seed_exact(cache,deps,v)
   self.assertEqual({n:(deps/n).read_bytes()for n in data},data);self.assertEqual(unrelated.read_bytes(),b'ORIGINAL_OTHER_KEEP');self.assertEqual(A20.ordinary(unrelated),before)
   (deps/'a.pkg').write_bytes(b'BAD')
   with self.assertRaisesRegex(ValueError,'hash'):A20.seed_exact(cache,deps,v)
   self.assertEqual((deps/'a.pkg').read_bytes(),b'BAD')
 def test_private_cache_and_seed_alias_foreign_entry_refusal(self):
  A20,data,v=self.tiny()
  for kind in('symlink','hardlink','unknown'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);cache=root/'cache';cache.mkdir(mode=0o700);p=cache/'a.pkg';p.write_bytes(b'one');deps=root/'deps';deps.mkdir(mode=0o700)
    if kind=='symlink':p.unlink();p.symlink_to(root/'outside')
    elif kind=='hardlink':os.link(p,root/'alias')
    else:(cache/'foreign').write_bytes(b'FOREIGN_KEEP')
    with self.assertRaises(ValueError):A20.prefetch(cache,v,lambda *a,**k:self.fail('HTTP before refusal'))
    self.assertEqual(list(deps.iterdir()),[])
    if kind=='unknown':self.assertEqual((cache/'foreign').read_bytes(),b'FOREIGN_KEEP')
 def test_only_bounded_custody_data_retained_not_archive_bodies(self):
  with tempfile.TemporaryDirectory()as td:
   work=Path(td)/'work';work.mkdir(mode=0o700);value=dict(status='EXACT_ORIGINAL20_SEEDED_BEFORE_UNCHANGED_BUILD',context='INERT_RETENTION_INTERFACE_NOT_ACCEPTANCE');raw=O.encoded(value);(work/'archive20-custody.json').write_bytes(raw);(work/'a.pkg').write_bytes(b'NO_PACKAGE_BODY_EXPORT');out=Path(td)/'public';result=retain.run(work,out)
   self.assertEqual(set(result['files']),{'archive20-custody.json'});self.assertEqual((out/'archive20-custody.json').read_bytes(),raw);self.assertEqual(result['files']['archive20-custody.json'],O.pin(raw));self.assertFalse((out/'a.pkg').exists())


ARCHIVE8_HELPER='def seed_archive8(root,runtime,archive32_cache,deps,work):\n """Seed only whole-pinned original8; no version/trust or producer command changes."""\n cache=archive32_cache.parent/\'ksm2-archive8\'\n policy_path=root/O.LANE/\'archive8-policy.json\'\n value=A8.policy(policy_path,runtime/\'borrowed/maintained574-inputs.json\')\n custody=A8.seed_exact(cache,deps,value)\n custody.update(policy=O.pin(O.read(policy_path)),files={n:{k:r[k]for k in(\'bytes\',\'sha256\')}for n,r in value[\'files\'].items()},versions=\'UNCHANGED_FROZEN574_LOCK\',trust=\'UNCHANGED_ORIGINAL_SIGNATURE_AND_KEYRING_CHECKS\')\n O.save(work/\'archive8-custody.json\',custody)\n return custody\n\n'
ARCHIVE8_CALL="  seed_archive8(root,runtime,a.archive_cache,producer/'context/deps',a.work)\n"
ARCHIVE8_STEP='      - name: Prefetch exact8 additional frozen574 archive bytes before unchanged producer\n        timeout-minutes: 4\n        run: >-\n          python3 -I -B "$GITHUB_WORKSPACE/$SLICE/archive8.py" --policy "$GITHUB_WORKSPACE/$SLICE/archive8-policy.json"\n          --inputs "$GITHUB_WORKSPACE/runtime/borrowed/maintained574-inputs.json"\n          --cache "$RUNNER_TEMP/ksm2-archive8"\n'
ARCHIVE8_BEFORE={'owner.py': {'bytes': 7566, 'sha256': 'dc62442754d70516ea445fb613853fb101b5023b6224803b2e3c7790c4ebdd8a'}, 'workflow.yml.in': {'bytes': 6980, 'sha256': 'ef72bb686d682ac2f83bcaf376dc56bf2bb2df11e102a39aa797a8f863249e71'}, 'retain.py': {'bytes': 2265, 'sha256': '7315b772be7cd44c42ce1b6921784459d27ccbde4cc7b80343c7befd7f422713'}}
def before_archive8(text,leaf):
 if leaf=='owner.py':
  O.need(text.count('PASS_SOURCE_BOUND_GENERIC16K_KSM_OWNED_SHARING_AND_SCALAR')==2,'finite new owner scope inverse');text=text.replace('PASS_SOURCE_BOUND_GENERIC16K_KSM_OWNED_SHARING_AND_SCALAR','PASS_SOURCE_BOUND_GENERIC16K_KSM_SCALAR_ONLY')
 if leaf=='workflow.yml.in':
  added='          python3 -I -B runtime/test_sharing.py\n';O.need(text.count(added)==1,'one sharing source-only control command');text=text.replace(added,'',1)
 if leaf=='owner.py':
  O.need(text.count('import archive8 as A8\n')==text.count(ARCHIVE8_HELPER)==text.count(ARCHIVE8_CALL)==1,'finite eight-input owner inverse')
  old=text.replace('import archive8 as A8\n','',1).replace(ARCHIVE8_HELPER,'',1).replace(ARCHIVE8_CALL,'',1)
 elif leaf=='workflow.yml.in':
  O.need(text.count(ARCHIVE8_STEP)==1,'finite eight-input step inverse');old=text.replace(ARCHIVE8_STEP,'',1)
 else:
  O.need(leaf=='retain.py','exact known retainer inverse');old=text.replace("FIXED={'archive8-custody.json','archive20-custody.json',","FIXED={'archive20-custody.json',",1)
 O.need(O.pin(old.encode())==ARCHIVE8_BEFORE[leaf],'whole previous623 production bytes');return old

class Archive8(unittest.TestCase):
 def test_exact_policy_whole_original_lock_disjoint_both_previous_policies(self):
  import archive8 as A8,archive20 as A20,archive32 as A32
  p=ROOT/O.LANE;lock=ROOT/'runtime/borrowed/maintained574-inputs.json';v=A8.policy(p/'archive8-policy.json',lock)
  self.assertEqual((len(v['files']),sum(r['bytes']for r in v['files'].values())),(8,2220315))
  for m,n in [(A20,'archive20'),(A32,'archive32')]:self.assertFalse(set(v['files'])&set(m.policy(p/(n+'-policy.json'),lock)['files']))
  self.assertEqual(O.pin(O.read(p/'archive8.py')),dict(bytes=11040,sha256='5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565'))
 def test_complete_previous_owner_and_workflow_retainer_inverse(self):
  for leaf in ARCHIVE8_BEFORE:before_archive8((ROOT/O.LANE/leaf).read_text(),leaf)
  self.assertLess((ROOT/O.LANE/'owner.py').read_text().index(ARCHIVE8_CALL),(ROOT/O.LANE/'owner.py').read_text().index("'build','--inputs'"))
 def test_bounded_retention_declares_eight_custody_only(self):
  import retain
  self.assertTrue(retain.permitted('archive8-custody.json'));self.assertFalse(retain.permitted('archive8/packages.pkg'))


LDCONFIG_GUEST_BEFORE={'bytes': 27481, 'sha256': '8e7572c75747701c7c73c745efa67f4d66d5ab71e56231c924b34c29da70c5d3'}
LDCONFIG_GUEST_AFTER={'bytes': 32612, 'sha256': 'a91e86a1db7d5123f02c2d99e101f04ef4075cea3be248cc279b06e4dd5ca24a'}
LDCONFIG_GUEST_HELPERS='LDCONFIG_SHIM_SOURCE=b\'/* SPDX-License-Identifier: MIT */\\n#define _GNU_SOURCE\\n#include <dlfcn.h>\\n#include <errno.h>\\n#include <string.h>\\n#include <unistd.h>\\n\\n/* Exact built-in path from pinned native libalpm; never report helper success. */\\nint execv(const char *path, char *const argv[])\\n{\\n    if (strcmp(path, "/usr/bin/ldconfig") == 0) {\\n        static const char marker[] = "CAA_KSM2_BUILTIN_LDCONFIG_EXEC_DENIED_EPERM\\\\n";\\n        ssize_t sent = write(STDERR_FILENO, marker, sizeof(marker) - 1);\\n        (void)sent;\\n        errno = EPERM;\\n        return -1;\\n    }\\n    int (*next_execv)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execv");\\n    if (!next_execv) {\\n        errno = ENOSYS;\\n        return -1;\\n    }\\n    return next_execv(path, argv);\\n}\\n\'\nNATIVE_ALPM_SHA=\'94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902\'\n\ndef ldconfig_policy(s,expected,command):\n """Native compile in owned tmp, within the existing shared command deadline."""\n native=\'/usr/lib/libalpm.so.16.0.1\';raw=C.read(native,4*1024**2)\n C.need(C.sha(raw)==NATIVE_ALPM_SHA==expected[\'usr/lib/libalpm.so.16.0.1\'][\'sha256\'],\'same original signed native libalpm bytes\')\n C.need(raw[:6]==b\'\\x7fELF\\x02\\x01\'and raw[18:20]==b\'\\xb7\\x00\'and raw.count(b\'/usr/bin/ldconfig\\x00\')==1,\'native ALPM exact built-in LDCONFIG path\')\n directory=Path(\'/tmp\')/(\'ksm2-ldconfig-policy-\'+s[\'nonce\']);C.need(not os.path.lexists(directory),\'fresh private helper-policy directory\');directory.mkdir(mode=0o700)\n source=directory/\'policy.c\';library=directory/\'policy.so\';source.write_bytes(LDCONFIG_SHIM_SOURCE);source.chmod(0o600)\n argv=[\'/usr/bin/cc\',\'-std=c11\',\'-O2\',\'-fPIC\',\'-shared\',\'-Wall\',\'-Wextra\',\'-Werror\',\'-Wl,-z,relro,-z,now\',\'-Wl,--no-undefined\',\'-Wl,-z,max-page-size=16384,-z,common-page-size=16384\',\'-o\',str(library),str(source),\'-ldl\']\n command(argv,seconds=35);library.chmod(0o500);compiled=C.read(library,1024**2)\n C.need(all((p.lstat().st_uid,p.lstat().st_gid,stat.S_IMODE(p.lstat().st_mode))==(0,0,mode)for p,mode in((source,0o600),(library,0o500))),\'private root-owned source and policy modes\')\n C.need(compiled[:6]==b\'\\x7fELF\\x02\\x01\'and compiled[16:20]==b\'\\x03\\x00\\xb7\\x00\',\'fresh native aarch64 shared policy object\')\n receipt=dict(status=\'EXPLICIT_BUILTIN_LDCONFIG_EXEC_DENIAL_NOT_HELPER_SUCCESS\',helper=\'/usr/bin/ldconfig\',deny_errno=\'EPERM\',other_execv=\'RTLD_NEXT_UNCHANGED\',native_libalpm=C.pin(raw),source=C.pin(LDCONFIG_SHIM_SOURCE),compiled=C.pin(compiled),compiler_argv=argv,library=str(library),environment_scope=\'ONLY_EXACT_SIGNED_INSTALL_AND_REMOVE_PACMAN_COMMANDS\',commands=[],helper_exit=\'NOT_OBSERVED\',production_policy=\'NOT_INSTALLED\',denial_marker=C.pin(b\'CAA_KSM2_BUILTIN_LDCONFIG_EXEC_DENIED_EPERM\\n\'))\n return directory,receipt\n\ndef ldconfig_environment(argv,pacman,archive,policy,directory):\n """Only the two exact selected transaction argv receive this private preload."""\n C.need(argv in(pacman+[\'-U\',str(archive)],pacman+[\'-R\',C.PACKAGE]),\'exact signed selected install/remove argv only\')\n library=directory/\'policy.so\';source=directory/\'policy.c\'\n C.need(C.row(source)==policy[\'source\']and C.row(library)==policy[\'compiled\']and str(library)==policy[\'library\'],\'whole compiled policy and C source held before each transaction\')\n C.need(len(policy[\'commands\'])<2,\'only two selected package transactions\')\n env=dict(PATH=\'/usr/bin:/bin\',LANG=\'C.UTF-8\',HOME=\'/root\',LD_PRELOAD=str(library));policy[\'commands\'].append(dict(argv=list(argv),environment=C.pin(C.encoded(env))))\n return env\n\ndef retire_ldconfig_policy(directory,policy):\n C.need(set(p.name for p in directory.iterdir())=={\'policy.c\',\'policy.so\'}and len(policy[\'commands\'])==2,\'exact own policy files and both transaction command records\')\n C.need(all(row.get(\'helper_denial_capture\',{}).get(\'status\')==\'HELPER_EXEC_DENIED_EPERM_NOT_HELPER_SUCCESS\'for row in policy[\'commands\']),\'both actual captured helper denials required\')\n for name,key in((\'policy.c\',\'source\'),(\'policy.so\',\'compiled\')):\n  p=directory/name;C.need(C.row(p)==policy[key],\'same private policy bytes before retirement\');p.unlink()\n directory.rmdir();C.need(not os.path.lexists(directory),\'own helper policy files retired\')\n\ndef ldconfig_denial_capture(policy,out,err):\n marker=b\'CAA_KSM2_BUILTIN_LDCONFIG_EXEC_DENIED_EPERM\\n\'\n C.need((out+err).count(marker)==1,\'one complete original built-in helper exec-denial marker\')\n C.need(policy[\'commands\']and\'helper_denial_capture\'not in policy[\'commands\'][-1],\'one actual helper denial per transaction\')\n policy[\'commands\'][-1][\'helper_denial_capture\']=dict(marker=C.pin(marker),stdout=C.pin(out),stderr=C.pin(err),status=\'HELPER_EXEC_DENIED_EPERM_NOT_HELPER_SUCCESS\')\n\n'
LDCONFIG_GUEST_EDITS=[('rows=[];deadline=time.monotonic()+C.SHARED_SECONDS', 'rows=[];deadline=time.monotonic()+C.SHARED_SECONDS;ldconfig_receipt=None;ldconfig_directory=None'), (' def command(argv,expected=0,seconds=35):', ' def command(argv,expected=0,seconds=35,transaction=False):'), ("  r,out,err,error=runtime.run_command(argv,Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',HOME='/root'),remaining,128*1024);rows.append(r)", "  environment=ldconfig_environment(argv,pacman,archive,ldconfig_receipt,ldconfig_directory)if transaction else dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',HOME='/root')\n  r,out,err,error=runtime.run_command(argv,Path('/tmp'),environment,remaining,128*1024);rows.append(r)"), (' def preserve():\n', ' ldconfig_directory,ldconfig_receipt=ldconfig_policy(s,expected,command)\n def preserve():\n'), ("  if expected==1:C.need(out==b''and err==b'KSM experiment refused: KSM changed; conflict preserved\\n','exact installed foreign-edit refusal')", "  if transaction:ldconfig_denial_capture(ldconfig_receipt,out,err)\n  if expected==1:C.need(out==b''and err==b'KSM experiment refused: KSM changed; conflict preserved\\n','exact installed foreign-edit refusal')"), ("command(pacman+['-U',str(archive)],seconds=90)", "command(pacman+['-U',str(archive)],seconds=90,transaction=True)"), ("command(pacman+['-R',C.PACKAGE],seconds=90)", "command(pacman+['-R',C.PACKAGE],seconds=90,transaction=True)"), (" staged.rmdir();C.need(not staged.exists(),'owned signed staging retired')", " staged.rmdir();C.need(not staged.exists(),'owned signed staging retired')\n retire_ldconfig_policy(ldconfig_directory,ldconfig_receipt)"), (" return dict(actual_source=s['VM_source']", " return dict(ldconfig_policy=ldconfig_receipt,actual_source=s['VM_source']")]
def before_ldconfig(text):
 O.need(O.pin(text.encode())==LDCONFIG_GUEST_AFTER,'exact new helper-policy guest before any historical assertion')
 anchor=LDCONFIG_GUEST_HELPERS+'def scalar():\n';O.need(text.count(anchor)==1,'one complete helper-policy source insertion');text=text.replace(anchor,'def scalar():\n',1)
 for before,after in reversed(LDCONFIG_GUEST_EDITS):
  O.need(text.count(after)==1,'one exact helper-policy run seam inverse');text=text.replace(after,before,1)
 O.need(O.pin(text.encode())==LDCONFIG_GUEST_BEFORE,'whole original625 guest inverse before original tests');return text


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);a,left=p.parse_known_args();ROOT=a.source.absolute();unittest.main(argv=[sys.argv[0]]+left)
