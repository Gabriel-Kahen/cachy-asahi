#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source/emission/refusal controls; no accepting component or VM fixture."""
import argparse,copy,json,os,signal,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import hosted as O,prepare,retain,owner,cleanup,entry
ROOT=None
class Source(unittest.TestCase):
 def test_whole605_role_and_alias(self):
  O.files(ROOT);role=O.decode(O.read(ROOT/O.LANE/'runtime-role.json'));self.assertEqual(len(role['files']),605)
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
   with self.assertRaisesRegex(ValueError,'whole605'):prepare.assemble(fake,out)
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
  text=(ROOT/'runtime/guest.py').read_text();tree=ast.parse(text);n=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='worker_failure_data');raw=ast.get_source_segment(text,n)
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
  text=pre_inner((ROOT/'runtime/guest.py').read_text());tree=ast.parse(text);n=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='worker_failure_data');helper=ast.get_source_segment(text,n)+'\n\n';call=' worker_failure_data(s,row,out,err,error)\n';self.assertEqual(text.count(call),1);inverse=text.replace(helper,'',1).replace(call,'',1);self.assertEqual(hashlib.sha256(inverse.encode()).hexdigest(),'17c9608949accf0e39459c45e07c18533d02cdb5ca8e5f018b3a4d26f0717e9c')
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
  text=(ROOT/'runtime/guest.py').read_text();tree=ast.parse(text);functions={n.name:ast.get_source_segment(text,n)for n in tree.body if isinstance(n,ast.FunctionDef)};run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run');node=next(n for n in run.body if isinstance(n,ast.FunctionDef)and n.name=='command');return functions,ast.get_source_segment(text,node)
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
  text=(ROOT/'runtime/guest.py').read_text();self.assertEqual(hashlib.sha256(pre_inner(text).encode()).hexdigest(),'25133a4f0fd9983c02d04f25e2eb8349dd5f5c43895b46803f7d772ad0c09123')
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

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);a,left=p.parse_known_args();ROOT=a.source.absolute();unittest.main(argv=[sys.argv[0]]+left)
