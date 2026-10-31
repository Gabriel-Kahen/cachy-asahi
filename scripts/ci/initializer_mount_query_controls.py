#!/usr/bin/env python3
"""Canonical initializer private-query/telemetry source DATA controls.

Pure AST-selected helpers and owned byte fixtures only. No initializer lifecycle,
chroot/helper execution, GPG, VM, transaction, native actor, or accepted outcome.
"""
import argparse,ast,contextlib,ctypes,errno,hashlib,json,os,sys,tempfile,types
from pathlib import Path
from unittest.mock import Mock,patch
INIT='scripts/update/aux_initialize.py'
HOOK='scripts/ci/full-root-upgrade-caller/upgrade_hook.py'
EXPECTED_INPUTS={'scripts/update/aux_initialize.py': {'bytes': 24873, 'sha256': 'd9160b842ef2dae7bc60999c4f23452ade15ba91b775d52bdef5f189a52e23e2'}, 'scripts/ci/full-root-upgrade-caller/upgrade_hook.py': {'bytes': 19972, 'sha256': '450908ffc661f78bb87a79654d040e6ed27f8311dc39ebee899218f445c73b81'}, 'scripts/update/full_root.py': {'bytes': 35970, 'sha256': 'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d'}, 'scripts/update/aux_checkpoint.py': {'bytes': 18456, 'sha256': 'd51179ca24c981bafd817d7db082c0ceb3b2f5deb922004bfe97d1e2007edda7'}}
ORIGINAL_INITIALIZE_AST='842b7948f8dde1789270a98a1d1d28c4d05819a2cb7acb389bb107c08f8a3104'
HELD_MOUNT_FACTORY_AST='166f37016d1a27fb7f74da85452faddaaa8bc2d1ccf3813fc460c8879d9cdf25'
checks=[]
def need(ok,reason):
 if not ok:raise ValueError(reason)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def passed(name):checks.append(name)
def stable_ast(node):
 if isinstance(node,ast.AST):return[type(node).__name__,{k:stable_ast(v)for k,v in ast.iter_fields(node)if v is not None and v!=[]}]
 if isinstance(node,list):return[stable_ast(n)for n in node]
 if isinstance(node,bytes):return dict(bytes_hex=node.hex())
 return node
def ast_hash(node):return hashlib.sha256(json.dumps(stable_ast(node),sort_keys=True,separators=(',',':')).encode()).hexdigest()
def load(raw,env,names=None):
 nodes=[]
 for node in ast.parse(raw).body:
  if isinstance(node,(ast.FunctionDef,ast.ClassDef))and node.name.startswith(('_initializer_','_Initializer'))and(names is None or node.name in names):nodes.append(node)
  if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id.startswith('_INITIALIZER_')for t in node.targets):nodes.append(node)
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<canonical-initializer-DATA-controls>','exec'),env);return env
class Clock:
 def __init__(self):self.n=1000
 def monotonic_ns(self):self.n+=10;return self.n
 def monotonic(self):return self.monotonic_ns()/10**9
class Limits:
 def __init__(self):self.deadline=150.;self.calls=0;self.fail=False
 def tick(self):
  self.calls+=1
  if self.fail:raise ValueError('root observation deadline')
class Call:
 def __init__(self,rows):self.rows=list(rows);self.calls=[]
 def __call__(self,fd,path,flags,mask,pointer):
  self.calls.append((fd,path.value,flags.value,mask.value))
  code,maskvalue,mount=self.rows.pop(0);ctypes.set_errno(code)
  if code:return -1
  pointer._obj.mask=maskvalue;pointer._obj.mnt_id=mount;return 0
def query(env,rows,original=None,machine=None):
 call=Call(rows);events=[];fallback=[]
 def fdinfo(fd,limits):fallback.append(fd);return 7 if original is None else original
 e=dict(env,_updater_copy_cost=types.SimpleNamespace(mount=events.append))
 factory=env['_initializer_clone'](env['_initializer_mount600'],e)
 contexts=[patch.object(ctypes,'CDLL',return_value=types.SimpleNamespace(statx=call))]
 if machine is not None:contexts.append(patch.object(os,'uname',return_value=types.SimpleNamespace(machine=machine)))
 with contextlib.ExitStack()as stack:
  for c in contexts:stack.enter_context(c)
  q=factory(fdinfo)
 return q,call,events,fallback
def refused(fn,kind=ValueError):
 try:fn()
 except kind:return
 raise AssertionError('expected query/schema refusal')
def record(lane='WORKER',seq=0,state='STARTED'):
 return dict(v=1,profile='I16K_STATX_V1',nonce='a'*32,lane=lane,seq=seq,phase='WORKER_OBSERVE'if lane=='WORKER'else'PARENT_SOURCE_BEFORE',state=state,elapsed_ns=0,remaining_ns=150000000000,ops=[0]*8,saturated=False)
def encoded(value):return b'UPDATER607_INITIALIZER_TELEMETRY '+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);args=parser.parse_args();ROOT=args.root
 need(ROOT.is_absolute()and ROOT==ROOT.resolve()and not any(p.is_symlink()for p in(ROOT,*ROOT.parents)),'explicit canonical source root')
 need(not sys.flags.optimize,'assertion-enabled ordinary Python controls')
 raws={}
 for name,wanted in EXPECTED_INPUTS.items():
  path=ROOT/name;need(path.is_file()and not path.is_symlink(),'ordinary exact canonical input '+name);raws[name]=path.read_bytes();need(pin(raws[name])==wanted,'exact adopted initializer/control input changed: '+name)
 passed('exact_two_adopted_canonical_and_two_held_support_source_inputs')
 canonical=raws[INIT];ast.parse(canonical);E=load(canonical,dict(json=json,os=os,sys=sys,time=Clock(),hashlib=hashlib))
 node=next(n for n in ast.parse(canonical).body if isinstance(n,ast.FunctionDef)and n.name=='_initializer_mount600');node.name='_mount600';assert ast_hash(node)==HELD_MOUNT_FACTORY_AST;passed('whole_held_mount_factory_AST_inverse_name_only')
 q,c,ev,fb=query(E,[(0,0x1000,7),(0,0x1000,9)]);limits=Limits();assert q(11,limits)==7 and q(12,limits)==9 and fb==[11]and ev==['statx','statx']and c.calls==[(11,b'',0x1000,0x1000),(12,b'',0x1000,0x1000)];passed('fresh_descriptor_statx_each_query_first_fdinfo_crosscheck_only')
 for code in [errno.ENOSYS,errno.EINVAL,errno.EOPNOTSUPP,errno.EPERM]:
  q,c,ev,fb=query(E,[(code,0,0)]);assert q(11,Limits())==q(12,Limits())==7 and len(c.calls)==1 and fb==[11,12]and ev==['fallback','fallback'];passed('held_supported_fallback_errno_'+str(code))
 q,c,ev,fb=query(E,[(0,0,7)]);assert q(11,Limits())==q(12,Limits())==7 and len(c.calls)==1 and len(fb)==2;passed('missing_statx_mask_fallback_semantics_held')
 q,c,ev,fb=query(E,[],machine='unsupported');assert q(11,Limits())==7 and not c.calls and fb==[11];passed('unsupported_platform_uses_original_query')
 q,c,ev,fb=query(E,[(errno.EIO,0,0)]);refused(lambda:q(11,Limits()),OSError);assert not fb;passed('hard_query_error_never_becomes_fallback')
 q,c,ev,fb=query(E,[(0,0x1000,0)]);refused(lambda:q(11,Limits()));assert not fb;passed('zero_mount_identity_refuses')
 q,c,ev,fb=query(E,[(0,0x1000,7)],original=8);refused(lambda:q(11,Limits()));passed('first_statx_fdinfo_mismatch_refuses')
 q,c,ev,fb=query(E,[(0,0x1000,7)]);limit=Limits();limit.fail=True;refused(lambda:q(11,limit));assert not c.calls and not fb;passed('original_deadline_exception_preserved_before_query')
 with patch.dict(os.environ,{'CACHY_ASAHI_BOUND_UPDATE':'a'*32}):
  state=E['_InitializerTelemetry']('WORKER');state.add(0,2**63);assert state.ops[0]==2**63-1 and state.saturated;passed('true_integer_bounded_counter_saturation_lower_bound')
  base=record();assert E['_initializer_valid'](base,'a'*32)
  for key,value in [('seq',True),('elapsed_ns',True),('remaining_ns',True),('ops',[False]*8),('saturated',0),('extra',1),('nonce','b'*32)]:
   row=dict(base);row[key]=value;assert not E['_initializer_valid'](row,'a'*32)
  passed('record_closed_fields_true_int_nonce_refusals')
  neg=dict(base,remaining_ns=-3);assert E['_initializer_valid'](neg,'a'*32);null=dict(base,remaining_ns=None);assert E['_initializer_valid'](null,'a'*32);passed('negative_expired_or_unknown_remaining_deadline_explicit')
  maxrow=dict(base,seq=5,state='REFUSED',elapsed_ns=2**63-1,remaining_ns=-(2**63-1),ops=[2**63-1]*8,saturated=True);assert E['_initializer_valid'](maxrow,'a'*32)and len(encoded(maxrow))<=768;passed('maximum_counter_frame_within768')
  r0=record();r1=record(seq=1,state='REFUSED');r1.update(elapsed_ns=10,ops=[1]*8);line=encoded(r0)+encoded(r1);last,count=E['_initializer_capture'](line,'a'*32);assert last==r1 and count==2;passed('strict_worker_sequence_and_last_refusal')
  for data in [encoded(r1),line+encoded(r1),line.replace(b'"v":1',b'"v":1,"v":1',1),b'UPDATER607_INITIALIZER_TELEMETRY '+b'x'*800+b'\n',encoded(r0)*7]:assert E['_initializer_capture'](data,'a'*32)==(None,0)
  passed('worker_partial_sequence_duplicate_key_oversize_and_count_refusals')
  assert E['_initializer_capture'](encoded(r1),'a'*32,complete=False)==(r1,1);passed('driver_last_snapshot_fallback_no_cross_invocation_sequence_claim')
  assert E['_initializer_capture'](encoded(r1)*12,'a'*32,complete=False)==(r1,12)and E['_initializer_capture'](encoded(r1)*129,'a'*32,complete=False)==(None,0);passed('bounded128_driver_frames_support_multiple_worker_sequence_resets')
  assert E['_initializer_capture'](b'private raw stderr without approved prefix','a'*32)==(None,0);passed('missing_frame_remains_unknown_never_zero_record')
  writes=[]
  with patch.object(os,'write',side_effect=lambda fd,data:writes.append((fd,data))):
   E['_initializer_emit'](r1);E['_initializer_final_emit']({},r1)
  assert len(writes)==2 and all(len(data)<=768 for _,data in writes);passed('independent_final_emitter_without_primary')
  state=E['_InitializerTelemetry']('PARENT');row=dict(returncode=1,termination='timeout',direct_child_reaped=True,stderr=line)
  writes=[]
  with patch.object(os,'write',side_effect=lambda fd,data:writes.append(data)):state.worker_row(row)
  assert state.worker['last']==r1 and state.worker['stderr']==dict(bytes=len(line),sha256=hashlib.sha256(line).hexdigest())and state.worker['capture_scope']=='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL'and writes==[encoded(r1)];passed('unconditional_worker_capture_exact_stderr_pin_and_immediate_forward')
  state.worker_row(dict(row,returncode=False));assert state.worker['last']==r1;passed('malformed_process_facts_cannot_replace_known_snapshot')
  wrapper=dict(v=1,profile='I16K_STATX_V1',history=[],saturated=False,worker=state.worker);assert E['_initializer_wrapper_valid'](wrapper,'a'*32)
  assert not E['_initializer_wrapper_valid'](dict(wrapper,worker=dict(state.worker,stderr=None)),'a'*32);passed('worker_stderr_pin_required_no_implicit_complete_or_zero_capture')
  for field,value in [('history',[record(lane='PARENT',seq=0)]*9),('saturated',0),('extra',1)]:
   bad=dict(wrapper);bad[field]=value;assert not E['_initializer_wrapper_valid'](bad,'a'*32)
  passed('bounded_parent_wrapper_closed_schema')
  for key,value in [('phase','PARENT_SOURCE_BEFORE'),('remaining_ns',True),('ops',[0]*7),('state','PASS'),('nonce','A'*32)]:
   bad=dict(base);bad[key]=value;assert not E['_initializer_valid'](bad,'a'*32)
  passed('source_schema_rejects_lane_phase_counter_outcome_and_nonce_drift')
  history=[dict(record(lane='PARENT',seq=0),elapsed_ns=10,ops=[2]*8),dict(record(lane='PARENT',seq=1),elapsed_ns=20,ops=[3]*8)]
  parent_wrapper=dict(v=1,profile='I16K_STATX_V1',history=history,saturated=False,worker=None);assert E['_initializer_wrapper_valid'](parent_wrapper,'a'*32)
  for field,value in [('seq',0),('elapsed_ns',9),('ops',[1]*8),('nonce','b'*32),('lane','WORKER')]:
   bad=dict(parent_wrapper,history=[dict(history[0]),dict(history[1],**{field:value})]);assert not E['_initializer_wrapper_valid'](bad,'a'*32)
  passed('parent_history_strict_sequence_nonce_lane_and_monotonic_cumulative_values')
  for worker in [dict(state.worker,last=None,records=1),dict(state.worker,last=r1,records=0),dict(state.worker,last=r1,records=1),dict(state.worker,capture_scope='COMPLETE_PROCESS_STDERR')]:assert not E['_initializer_wrapper_valid'](dict(wrapper,worker=worker),'a'*32)
  passed('supervisor_partial_capture_last_count_scope_consistency')
  # No initializer lifecycle entry is invoked. Only the facade's pure observer/hash
  # endpoints are called against owned DATA and inert auxiliary Reader methods.
  roots_raw=(ROOT/'scripts/update/full_root.py').read_bytes();hash_nodes=[n for n in ast.parse(roots_raw).body if isinstance(n,ast.FunctionDef)and n.name in('_identity','_file_hash')]
  h=dict(os=os,hashlib=hashlib,need=need);exec(compile(ast.Module(body=hash_nodes,type_ignores=[]),'<owned-hash-DATA>','exec'),h)
  root_ns=dict(_mount_id=lambda fd,limits:7,_file_hash=h['_file_hash'])
  exec("def observe(root,*,limits,hardlinks):\n return {'mount':_mount_id(root[0],limits),'digest':_file_hash(root[0],root[1],limits)}",root_ns)
  roots=types.SimpleNamespace(**root_ns)
  endpoint_space=dict(roots=roots,contextlib=contextlib)
  exec("@contextlib.contextmanager\ndef parent(fd,limits):\n yield roots._mount_id(fd,limits)\nclass Reader:\n def query(self,fd,limits):return roots._mount_id(fd,limits)\ndef held_observe(root,limits):\n return roots.observe(root,limits=limits,hardlinks='generic-development-internal')",endpoint_space)
  parent=endpoint_space['parent'];Reader=endpoint_space['Reader'];held_observe=endpoint_space['held_observe']
  copier=types.SimpleNamespace(_parent=parent,_root_check=lambda:None,_source_alias=lambda:None)
  checkpoint=Mock(name='checkpoint');load_comparator=Mock(name='load_comparator')
  aux=types.SimpleNamespace(Reader=Reader,checkpoint=checkpoint,load_comparator=load_comparator)
  class Injected:
   def __call__(self,*args,**kwargs):raise AssertionError('injected callable must not execute')
  for function in (checkpoint,load_comparator,Mock(spec=types.FunctionType),len,[].append,Injected()):
   assert E['_initializer_clone'](function,{})is function
  def forbidden(*args,**kwargs):raise AssertionError('lifecycle entry forbidden in control')
  E['_initializer_original']=dict(observe=held_observe,limits_from=forbidden,exec_helper=forbidden,initialize=forbidden)
  namespace=dict(roots=roots,copy=copier,aux=aux,supervision=types.SimpleNamespace(run=forbidden))
  state=E['_InitializerTelemetry']('WORKER');original_mount=roots._mount_id;original_observe=roots.observe
  with tempfile.TemporaryFile()as f:
   f.write(b'fresh unique bytes');f.flush();fd=f.fileno();info=os.fstat(fd);os.lseek(fd,0,os.SEEK_SET)
   with patch.object(ctypes,'CDLL',return_value=types.SimpleNamespace(statx=Call([(0,0x1000,7)]*3))),patch.object(os,'write'):
    api=E['_initializer_facade'](namespace,state,None)
    assert api.aux.checkpoint is checkpoint and api.aux.load_comparator is load_comparator
    checkpoint.assert_not_called();load_comparator.assert_not_called()
    value=api.observe((fd,info),Limits())
    assert api.aux.Reader().query(fd,Limits())==7
    with api.copy._parent(fd,Limits())as mount:assert mount==7
   assert value==dict(mount=7,digest=hashlib.sha256(b'fresh unique bytes').hexdigest())and state.ops[:6]==[3,3,0,1,1,len(b'fresh unique bytes')]
   old_counts=list(state.ops);assert aux.Reader().query(fd,Limits())==7
   with copier._parent(fd,Limits())as mount:assert mount==7
   assert state.ops==old_counts
  assert roots._mount_id is original_mount and roots.observe is original_observe and copier._parent is parent and aux.Reader is Reader;passed('private_facade_semantic_hash_query_equivalence_and_shared_namespace_isolation')
  reader_node=next(n for n in ast.parse((ROOT/'scripts/update/aux_checkpoint.py').read_bytes()).body if isinstance(n,ast.ClassDef)and n.name=='Reader')
  assert all(not n.decorator_list for n in reader_node.body if isinstance(n,ast.FunctionDef));passed('actual_reader_has_no_uncloned_class_or_staticmethod_descriptor')
  with patch.object(os,'write'):
   for _ in range(20):state.event('PROGRESS')
  assert state.seq<=6 and state.saturated;passed('total_worker_progress_bound_and_final_reserve')
  periodic=E['_InitializerTelemetry']('WORKER');periodic.limits(Limits());writes=[]
  with patch.object(os,'write',side_effect=lambda fd,data:writes.append(data)):
   periodic.event('STARTED')
   for i in range(10):
    E['time'].n=periodic.started+(i+1)*31*10**9;periodic.add(0);periodic.progress(E['time'].n)
   periodic.finish('REFUSED')
  final,number=E['_initializer_capture'](b''.join(writes),'a'*32);assert number==6 and final['seq']==5 and final['state']=='REFUSED'and final['remaining_ns']<0 and final['saturated']is True;passed('bounded30s_observation_progress_and_reserved_terminal_refusal')
  for body in [canonical]:
   fn=next(n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='initialize');part=ast.get_source_segment(body.decode(),fn)
   assert part.count("'aux-initialization-started'")==1
   seen=[]
   def delegate(*args,**kwargs):seen.append(kwargs['marker']);return 'DATA_ONLY_MARKER_SENTINEL'
   for marker in ['aux-initialization-started','aux-recovery-initialization-started']:
    rewritten=part.replace("'aux-initialization-started'",repr(marker));namespace={'_initializer_initialize':delegate};exec(compile(rewritten,'<source-only-recovery-marker-route>','exec'),namespace);assert namespace['initialize'](None,None,comparator_path=None)=='DATA_ONLY_MARKER_SENTINEL'
   assert seen==['aux-initialization-started','aux-recovery-initialization-started']
  passed('recovery_marker_AST_route_has_unique_explicit_delegate_no_lifecycle_entry')
  newbody=next(n for n in ast.parse(canonical).body if isinstance(n,ast.FunctionDef)and n.name=='_initializer_initialize_body');newbody.name='initialize'
  class Marker(ast.NodeTransformer):
   def visit_Name(self,node):return ast.copy_location(ast.Constant('aux-initialization-started'),node)if node.id=='_initializer_marker_name'else node
  newbody=Marker().visit(newbody);assert ast_hash(newbody)==ORIGINAL_INITIALIZE_AST;passed('entire_original_initializer_body_AST_inverse_name_and_marker_only')
  hook=raws[HOOK];text=hook.decode();assert text.index('_initializer_capture(row.get')<text.index('driver = driver_result(row)') and 'finally:\n        _initializer_final_emit(result,_initializer_last)'in text;passed('canonical_hook_capture_before_driver_result_and_final_emitter_in_finally')
  init_helpers={n.name:ast.get_source_segment(canonical.decode(),n)for n in ast.parse(canonical).body if isinstance(n,ast.FunctionDef)and n.name.startswith('_initializer_')}
  hook_helpers={n.name:ast.get_source_segment(hook.decode(),n)for n in ast.parse(hook).body if isinstance(n,ast.FunctionDef)and n.name.startswith('_initializer_')}
  for name in ('_initializer_valid','_initializer_capture','_initializer_emit','_initializer_wrapper_valid','_initializer_final_emit'):assert init_helpers[name]==hook_helpers[name]
  passed('initializer_and_caller_strict_telemetry_helper_bodies_identical')
  assert b'min(180,remaining)'in canonical and b'time.monotonic()+150'in canonical and b"value['seconds']"in canonical and b"config['verify_seconds']"in hook;passed('held_worker150_parent_config_min180_and_caller_verify_literals')
 need(len(checks)>=30,'meaningful nonempty initializer DATA controls')
 print(json.dumps(dict(status='PASS_CANONICAL_INITIALIZER_MOUNT_QUERY_SOURCE_DATA',count=len(checks),controls=checks,inputs=EXPECTED_INPUTS,lifecycle_entries_called=0,actors=0,native=0,GPG=0,API=0,Git=0,source_prefix=0,performance_claim=False,Root_acceptance=None),sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
