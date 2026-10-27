#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual emitted observer/facade and original timeout log retention; private DATA only."""
import argparse,ast,base64,hashlib,importlib.util,io,json,os,shutil,signal,subprocess,sys,tempfile,threading,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(HERE))
import observer_apply as O,observer_stage as S,source_guard as G,observer_guard as Q
ARGS=None

def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(prefix='owned-observer-control-');self.addCleanup(t.cleanup);self.work=Path(t.name)
 def test_whole676_guard_lexical_inverse_exact_actual_copy_and_all_caps(self):
  fact=G.verify();self.assertEqual((fact['files'],fact['parent676_files'],fact['packages'],fact['optional_absent']),(698,676,607,605));self.assertEqual(fact['service_seconds'],3460)
  raw=G.read(HERE/'factory/support/alpm_reader.py');self.assertEqual(O.pin(raw),O.AFTER)
  for before,after in reversed(Q.EDITS):self.assertEqual(raw.count(after.encode()),1);raw=raw.replace(after.encode(),before.encode(),1)
  self.assertEqual(O.pin(raw),O.BEFORE);self.assertEqual((O.ANNOTATION['observer_seconds'],O.ANNOTATION['caller_seconds']),(1200,1210));self.assertEqual(O.ANNOTATION['validation_profile']['default_observer_seconds'],600)
  with self.assertRaises((OSError,ValueError)):O.apply(self.work)
 def test_four_actual_emissions_and_executing_namespace_before_source_seal(self):
  n=load('_observer_actual_native',HERE/'native.py');proofs=[]
  for profile in('minimal','overlay'):
   for mode in('generic4k','generic16k'):
    f=load('_historical_observer_source',HERE/'historical_source.py').historical_selected_factory(load('_historical_observer_base',HERE/'factory/factory.py'),ROOT/'parent574/original',ARGS.assets);out=self.work/(profile+mode);self.assertIs(f.emit.__globals__['prepare_code'],f.prepare_code);self.assertIs(f.emit.__globals__['seal'],f.seal)
    with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):p,ch=f.prepare_code(ROOT/'parent574/original',ARGS.assets,out,profile,mode);r=f.seal(out,profile,mode,p,ch,False)
    self.assertEqual((r['packages'],r['optional_absent']),(607,605));self.assertEqual(r['observer_diagnostic'],O.ANNOTATION);self.assertEqual(O.pin((out/'alpm_reader.py').read_bytes()),O.AFTER);self.assertFalse((out/'observer_stage.py').exists());self.assertIn('CAP=64*1024**2',(out/'installed606.py').read_text());self.assertIn('_OBSERVER_STAGE_CAP=2048',(out/'installed606.py').read_text());self.assertEqual((out/'installed606.py').read_bytes(),O.edited((HERE/'factory/installed607.py').read_bytes(),O.observer_rows()));self.assertIn("logs,'installed606-preserved',timeout=1210)",(out/'base_guest.py').read_text());self.assertIn('TimeoutStartSec=3580',(out/'desktop574_fixture.sh').read_text());self.assertIn('TimeoutStopSec=120',(out/'desktop574_fixture.sh').read_text());self.assertIn('time.monotonic() + 3820',(out/'desktop574_runtime.py').read_text());self.assertIn('phase(POSITIVE_RUNTIME_POLICY',(out/'desktop574_runtime.py').read_text());self.assertEqual(r['positive_budget_profile']['owner_work_seconds'],6880);self.assertEqual(r['service_validation_profile']['owner_wait_seconds'],4460);proofs.append(dict(profile=profile,mode=mode,files=r['files']))
  if os.environ.get('OBSERVER_AUTHOR_RECEIPTS')=='1':Path(os.environ['OBSERVER_AUTHOR_RECEIPT_PATH']).write_bytes(O.enc(proofs))
 def test_genuine607_complete_output_and_refusal_with_diagnostic_no_live_waiver(self):
  expected=dict(line.split()for line in(HERE/'expected607.lock').read_text().splitlines());root=self.work/'root';(root/'var/lib/pacman/local').mkdir(parents=True);(root/'payload').mkdir();(root/'var/lib/pacman/local/ALPM_DB_VERSION').write_bytes(b'9\n')
  for name,version in expected.items():
   d=root/'var/lib/pacman/local'/(name+'-'+version);d.mkdir();(d/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n%ARCH%\nany\n\n');(d/'files').write_text('%FILES%\npayload/'+name+'\n\n');(root/'payload'/name).write_bytes((name+' '+version).encode())
  before=G.read(HERE/'factory/installed607.py');m=types.ModuleType('_owned_observer_body');m.__file__=str(self.work/'installed606.py');exec(compile(O.edited(before,O.observer_rows()),m.__file__,'exec'),m.__dict__);old=types.ModuleType('_whole_original607_observer');old.__file__=m.__file__;exec(compile(before,old.__file__,'exec'),old.__dict__);shutil.copyfile(HERE/'factory/support/file_capabilities.py',self.work/'file_capabilities.py');helper=load('_owned_lexical_alpm',HERE/'factory/support/alpm_reader.py')
  raw=G.read(HERE/'factory/support/alpm_reader.py')
  for a,b in reversed(Q.EDITS):raw=raw.replace(b.encode(),a.encode(),1)
  original=types.ModuleType('_whole_original_alpm');original.__file__=str(self.work/'alpm_reader.py');exec(compile(raw,original.__file__,'exec'),original.__dict__);baseline=old.observe(root,original,expected);notes=[]
  with patch.object(S.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):
   m._observer_mark=S.Stages().mark;actual=m.observe(root,helper,expected)
  self.assertEqual(actual,baseline);self.assertEqual(len(actual['nodes']),607);rows=[json.loads(x.split(b' ',1)[1])for x in notes];self.assertEqual([x['stage']for x in rows],list(S.STAGES));self.assertLessEqual(sum(map(len,notes)),2048)
  for observer,h in((old,original),(m,helper)):
   with self.assertRaises(ValueError):observer.observe(root,h,expected,deadline=0)
  target=root/'payload/cachy-asahi-boot-report';os.setxattr(target,'user.observer-control',b'inert')
  for observer,h in((old,original),(m,helper)):
   with self.assertRaises(ValueError):observer.observe(root,h,expected)
 def test_fixed_stage_allowlist_caps_capture_loss_no_contents(self):
  notes=[]
  with patch.object(S.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):
   m=S.Stages()
   for bad in(None,True,'/private/path','unknown'):self.assertFalse(m.mark(bad))
   for name in S.STAGES:self.assertTrue(m.mark(name));self.assertFalse(m.mark(name))
  self.assertEqual(len(notes),8);self.assertLessEqual(sum(map(len,notes)),S.CAP)
  for raw in notes:
   v=json.loads(raw.split(b' ',1)[1]);self.assertEqual(set(v),{'schema','role','stage','ordinal','elapsed_ns','status'});self.assertIs(type(v['elapsed_ns']),int);self.assertEqual(v['status'],'BOUNDARY_DATA_ONLY_NOT_ACCEPTANCE')
  with patch.object(S.os,'write',side_effect=OSError('capture lost')):self.assertFalse(S.Stages().mark(S.STAGES[0]))
 def test_original_command_timeout_retires_and_exports_stage_tail_before_raise(self):
  path=ROOT/'parent574/original/scripts/ci/desktop574_guest.py';raw=path.read_text();tree=ast.parse(raw);names={'need','terminate','Logged','command'};parts=[ast.get_source_segment(raw,n)for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];self.assertEqual(len(parts),4);events=[];space=dict(os=os,signal=signal,subprocess=subprocess,threading=threading,Path=Path,hashlib=hashlib,base64=base64,MAX_LOG=256*1024,emit=lambda event,**row:events.append(dict(event=event,**row)));exec(compile('\n\n'.join(parts),'<entire-original-guest-command-logging-retirement>','exec'),space)
  stage=HERE/'observer_stage.py';code="import importlib.util,time;s=importlib.util.spec_from_file_location('fixed',"+repr(str(stage))+");m=importlib.util.module_from_spec(s);s.loader.exec_module(m);v=m.Stages();v.mark('inventory_begin');v.mark('inventory_end');time.sleep(5)";logs=self.work/'logs';logs.mkdir()
  with self.assertRaises(subprocess.TimeoutExpired):space['command']([sys.executable,'-I','-B','-c',code],dict(PATH='/usr/bin:/bin'),logs,'installed606-preserved',timeout=.3)
  self.assertEqual(len(events),1);event=events[0];self.assertEqual(event['name'],'installed606-preserved');tail=base64.b64decode(event['logs'][1]['tail_base64'],validate=True);self.assertIn(b'INSTALLED607_OBSERVER_STAGE_DATA',tail);self.assertEqual(tail,(logs/'installed606-preserved.stderr').read_bytes());self.assertLessEqual(len(tail),2048);self.assertEqual(len(tail.splitlines()),2);self.assertNotEqual(event['returncode'],0)
 def test_selected_verify_only_deadline_and_original_capture_defaults(self):
  raw=G.read(HERE/'factory/installed607.py');current=O.edited(raw,O.observer_rows());m=types.ModuleType('_actual_selected_readback_main');m.__file__=str(self.work/'installed606.py');exec(compile(current,m.__file__,'exec'),m.__dict__)
  self.assertEqual(m.observe.__kwdefaults__,{'deadline':600});calls=[];actual=dict(nodes={},payload_bytes=0,capabilities={});snapshot=self.work/'snapshot.json';snapshot.write_bytes(m.encoded(actual));expected=self.work/'expected.lock';expected.write_text('inert 1\n');helper=object()
  def observe(root,h,selection,*,deadline):calls.append((root,h,selection,deadline));return actual
  with patch.object(m,'_selected_verify_observe',side_effect=observe),patch.object(m,'load_db',return_value=helper),patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'argv',['installed606.py','verify','/','alpm_reader.py',str(expected),str(snapshot)]),patch('sys.stdout',io.StringIO()):m.main()
  self.assertEqual(calls,[(Path('/'),helper,{'inert':'1'},1200)])
  capture=self.work/'fresh-snapshot.json'
  with patch.object(m,'observe',side_effect=observe),patch.object(m,'load_db',return_value=helper),patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'argv',['installed606.py','capture',str(self.work),'alpm_reader.py',str(expected),str(capture)]),patch('sys.stdout',io.StringIO()):m.main()
  self.assertEqual(calls[-1][-1],600);self.assertEqual(capture.read_bytes(),snapshot.read_bytes());self.assertEqual(capture.stat().st_mode&0o777,0o444)
  for action in('unknown','verify1200','capture1200'):
   with patch.object(m.sys,'argv',['installed606.py',action,'/','alpm_reader.py',str(expected),str(snapshot)]),self.assertRaises(ValueError):m.main()
  notes=[]
  with patch.object(S.time,'monotonic_ns',side_effect=[0,2000000000000]),patch.object(S.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):self.assertTrue(S.Stages().mark('inventory_begin'))
  self.assertEqual(json.loads(notes[0].split(b' ',1)[1])['elapsed_ns'],1215000000000);self.assertLessEqual(len(notes[0]),2048)

 def test_selected_query_actual_function_globals_and_capture_no_leak(self):
  raw=G.read(HERE/'factory/installed607.py');rendered=O.edited(raw,O.observer_rows());m=types.ModuleType('_actual_selected_query');m.__file__=str(self.work/'installed606.py');exec(compile(rendered,m.__file__,'exec'),m.__dict__)
  holder=self.work/'payload';holder.write_bytes(b'private FD fixture');fd=os.open(holder,os.O_RDONLY|os.O_NOFOLLOW);seen=[]
  def capabilities():
   spec=importlib.util.spec_from_file_location('_private_exact_caps',HERE/'factory/support/file_capabilities.py');caps=importlib.util.module_from_spec(spec);spec.loader.exec_module(caps);seen.append((caps,caps._mount));return caps
  class Limits:
   def tick(self):pass
  namespace=dict(m.observe.__globals__,capabilities=capabilities);exec('def observation(root,helper,expected,*,deadline):return capabilities()._mount(root,helper)',namespace)
  m.capabilities=capabilities;m.observe=namespace['observation'];self.assertIsNone(m.observe.__closure__)
  original=m.observe;original_globals=dict(original.__globals__)
  try:
   a=m._selected_verify_observe(fd,Limits(),{},deadline=1200);b=m._selected_verify_observe(fd,Limits(),{},deadline=1200);c=m.observe(fd,Limits(),{},deadline=600)
   self.assertEqual(a,b);self.assertEqual(b,c);self.assertGreater(a,0);self.assertIs(m.observe,original);self.assertEqual(m.observe.__globals__,original_globals);self.assertIsNot(seen[0][0],seen[1][0]);self.assertIsNot(seen[0][0]._mount,seen[0][1]);self.assertIsNot(seen[1][0]._mount,seen[1][1]);self.assertIs(seen[2][0]._mount,seen[2][1])
   for deadline in(600,1200.0,True):
    with self.assertRaises(ValueError):m._selected_verify_observe(fd,Limits(),{},deadline=deadline)
  finally:os.close(fd)


 def forwarding_space(self,current,events):
  raw=(ROOT/'parent574/original/scripts/ci/desktop574_guest.py').read_bytes()
  if current:raw=O.edited(raw,O.forwarding_rows())
  names={'need','terminate','Logged','command'}|({'_ObserverStageForward','_RecheckForward607','_ObserverAndRecheck607'}if current else set())
  parts=[ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names]
  self.assertEqual(len(parts),len(names));share=self.work/('selected-share-'+str(current)+'-'+str(len(list(self.work.iterdir()))));share.mkdir()
  space=dict(os=os,signal=signal,subprocess=subprocess,threading=threading,Path=Path,hashlib=hashlib,base64=base64,json=json,MAX_LOG=256*1024,SHARE=share,emit=lambda event,**row:events.append(dict(event=event,**row)))
  exec(compile('\n\n'.join(parts),'<actual-whole-selected-guest-logging-bodies>','exec'),space)
  self.assertIs(space['Logged'].drain.__globals__,space)
  child=O.stage_body().replace('_ObserverStages','Stages').replace('_OBSERVER_STAGES','STAGES').replace('_OBSERVER_STAGE_CAP','CAP')
  code='import json,os,time\n'+child+"\ns=Stages();s.mark('inventory_begin');s.mark('inventory_end');os.write(1,b'unchanged stdout');time.sleep(1)\n"
  (share/'installed606.py').write_text(code)
  argv=['/usr/bin/python3','-I','-B',str(share/'installed606.py'),'verify','/',str(share/'alpm_reader.py'),str(share/'expected.lock'),str(share/'installed606.json')]
  return space,argv

 def test_actual_selected_stream_forwards_before_exit_original_does_not(self):
  import time
  for current in(False,True):
   events=[];space,argv=self.forwarding_space(current,events);logs=self.work/('stream-logs-'+str(current));logs.mkdir();actor=space['Logged'](argv,'installed606-preserved',logs,dict(PATH='/usr/bin:/bin'))
   try:
    until=time.monotonic()+.6
    while current and not events and time.monotonic()<until:time.sleep(.01)
    if not current:time.sleep(.2)
    self.assertIsNone(actor.process.poll())
    self.assertEqual([e['observer_stage']for e in events]if current else events,['inventory_begin','inventory_end']if current else [])
    actor.process.wait(timeout=3);space['terminate'](actor.process);actor.finish()
    final=events[-1];self.assertEqual(final['event'],'process_exit');self.assertEqual(final['returncode'],0)
    self.assertEqual((logs/'installed606-preserved.stdout').read_bytes(),b'unchanged stdout')
    stderr=(logs/'installed606-preserved.stderr').read_bytes();self.assertEqual(len(stderr.splitlines()),2);self.assertEqual(final['logs'][1]['bytes'],len(stderr));self.assertEqual(final['logs'][1]['sha256'],hashlib.sha256(stderr).hexdigest())
    self.assertFalse(actor.errors);self.assertFalse(actor.overflow)
   finally:space['terminate'](actor.process)

 def test_forward_parser_fixed_caps_fragments_and_loss_never_authority(self):
  events=[];space,_=self.forwarding_space(True,events);klass=space['_ObserverStageForward'];f=klass(lambda event,**row:events.append(dict(event=event,**row)))
  def record(stage,**updates):
   value=dict(schema=1,role='EXACT_INSTALLED607_VERIFY',stage=stage,ordinal=klass.stages.index(stage)+1,elapsed_ns=1215000000000,status='BOUNDARY_DATA_ONLY_NOT_ACCEPTANCE');value.update(updates)
   return klass.prefix+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
  for raw in (b'/private/user/secret\n',record('inventory_begin',role='foreign'),record('inventory_begin',schema=True),record('inventory_begin',ordinal=True),record('inventory_begin',elapsed_ns=True),record('inventory_begin',elapsed_ns=1215000000001),record('inventory_begin',path='/private/user'),record('inventory_begin').replace(b'"schema":1',b'"schema": 1')):self.assertTrue(f.feed(raw))
  self.assertEqual(events,[]);self.assertLessEqual(len(f.pending),512)
  self.assertFalse(f.feed('not bytes'));self.assertFalse(f.feed(b'a'*65537))
  f.feed(b'foreign'+b'a'*6000);f.feed(b'\n');self.assertFalse(f.discard)
  for stage in klass.stages:
   raw=record(stage)
   for index in range(0,len(raw),7):self.assertTrue(f.feed(raw[index:index+7]))
   f.feed(raw)
  self.assertEqual([e['observer_stage']for e in events],list(klass.stages));self.assertLessEqual(f.input_bytes,2048);self.assertLessEqual(f.output_bytes,2048);self.assertLessEqual(len(f.pending),512)
  for row in events:self.assertEqual(set(row),{'event','schema','observer_stage','ordinal','elapsed_ns','status'});self.assertEqual(row['status'],'BOUNDARY_DATA_ONLY_NOT_ACCEPTANCE')
  def lost(*a,**k):raise OSError('private diagnostic capture loss')
  loss=klass(lost);self.assertTrue(loss.feed(record('inventory_begin')));self.assertEqual(loss.last,1)

 def test_selected_role_refuses_before_launch_and_other_drains_held(self):
  events=[];space,argv=self.forwarding_space(True,events);logs=self.work/'no-launch';logs.mkdir()
  for bad in (argv[:-1],tuple(argv),[argv[0],*argv[1:4],'capture',*argv[5:]],[*argv[:-1],'/private/foreign']):
   with patch.object(subprocess,'Popen',side_effect=AssertionError('MUST_NOT_LAUNCH')),self.assertRaises(ValueError):space['Logged'](bad,'installed606-preserved',logs,{})
  self.assertEqual(list(logs.iterdir()),[])
  class Pipe:
   def __init__(self):self.calls=[]
   def __enter__(self):return self
   def __exit__(self,*a):pass
   def read(self,size):self.calls.append(('read',size));return b''
   def read1(self,size):raise AssertionError('nonselected read semantics changed')
  for name,selected_stdout in(('unrelated',False),('installed606-preserved',True)):
   actor=space['Logged'].__new__(space['Logged']);actor.errors=[];actor.overflow=False;actor.paths=[logs/(name+'.stdout'),logs/(name+'.stderr')];actor._observer_forward=space['_ObserverStageForward'](lambda *a,**k:None)if selected_stdout else None
   pipe=Pipe();actor.drain(pipe,actor.paths[0]if selected_stdout else actor.paths[1]);self.assertEqual(pipe.calls,[('read',65536)]);self.assertEqual(actor.errors,[])

 def test_selected_timeout_and_diagnostic_loss_keep_original_result_and_logs(self):
  events=[];space,argv=self.forwarding_space(True,events);logs=self.work/'timeout-logs';logs.mkdir();child=Path(argv[3]);child.write_text(child.read_text().replace('time.sleep(1)','time.sleep(5)'))
  with self.assertRaises(subprocess.TimeoutExpired):space['command'](argv,dict(PATH='/usr/bin:/bin'),logs,'installed606-preserved',timeout=.3)
  self.assertEqual([e['observer_stage']for e in events if e['event']=='installed607_observer_stage_DATA'],['inventory_begin','inventory_end'])
  self.assertEqual(events[-1]['event'],'process_exit');self.assertNotEqual(events[-1]['returncode'],0)
  self.assertEqual(len((logs/'installed606-preserved.stderr').read_bytes().splitlines()),2)
  # Event capture loss remains diagnostic only: original stderr and exit0 survive.
  events=[];space,argv=self.forwarding_space(True,events);logs=self.work/'loss-logs';logs.mkdir();original=space['emit']
  def loss(event,**row):
   if event=='installed607_observer_stage_DATA':raise OSError('private stage loss')
   return original(event,**row)
  space['emit']=loss
  self.assertEqual(space['command'](argv,dict(PATH='/usr/bin:/bin'),logs,'installed606-preserved',timeout=3),'unchanged stdout')
  self.assertEqual(events[-1]['returncode'],0);self.assertEqual(len((logs/'installed606-preserved.stderr').read_bytes().splitlines()),2)


 def test_forwarded_stage_DATA_preserves_exact_profile_guard(self):
  import types
  raw=(ROOT/'parent574/original/scripts/ci/welcome-independent-profile-native/profile_adapter.py').read_bytes();tree=ast.parse(raw);runner=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='runner');contract=next(n for n in runner.body if isinstance(n,ast.FunctionDef)and n.name=='contract');call=contract.body[0].value
  self.assertIsInstance(call,ast.Call);self.assertEqual(ast.literal_eval(call.args[1]),'def verify_result(events,lock):')
  header=eval(compile(ast.Expression(call.args[2]),'<exact-source-generated-profile-guard>','eval'),dict(selected='minimal'))
  def need(ok,why):
   if not ok:raise ValueError(why)
  guarded=dict(C=types.SimpleNamespace(need=need));exec(compile(header+"\n    return 'PROFILE_GUARD_ONLY_NOT_GUI_ACCEPTANCE'\n",'<trusted-original-first-profile-predicate>','exec'),guarded)
  events=[];space,_=self.forwarding_space(True,events);klass=space['_ObserverStageForward'];forward=klass(lambda event,**row:events.append(dict(event=event,**row)))
  for ordinal,stage in enumerate(klass.stages,1):
   value=dict(schema=1,role='EXACT_INSTALLED607_VERIFY',stage=stage,ordinal=ordinal,elapsed_ns=1215000000000,status='BOUNDARY_DATA_ONLY_NOT_ACCEPTANCE');raw=klass.prefix+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n';self.assertTrue(forward.record(raw))
  self.assertEqual(len(events),8);self.assertTrue(all('stage'not in row and row['observer_stage']in klass.stages for row in events));self.assertLessEqual(forward.output_bytes,2048)
  baseline=[dict(event='phase_pass',stage='minimal')];self.assertEqual(guarded['verify_result'](baseline+events,{}),'PROFILE_GUARD_ONLY_NOT_GUI_ACCEPTANCE')
  old=[{('stage'if k=='observer_stage'else k):v for k,v in row.items()}for row in events]
  with self.assertRaisesRegex(ValueError,'foreign or missing profile event'):guarded['verify_result'](baseline+old,{})
  # Original decoder, no event filtering or parser edits: all8 DATA rows survive.
  raw=(ROOT/'parent574/original/scripts/ci/desktop574_runtime.py').read_bytes();tree=ast.parse(raw);decoder=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='read_events');assign=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id in('PREFIX','MAX_EVENTS')for x in n.targets)];scope=dict(json=json,require=need);exec(compile(ast.Module(body=assign+[decoder],type_ignores=[]),'<exact-source-event-decoder>','exec'),scope)
  path=self.work/'fixed-stage-events.log';path.write_bytes(b''.join((scope['PREFIX']+json.dumps(row,sort_keys=True)+'\n').encode()for row in baseline+events));_,pending,decoded=scope['read_events'](path,0,b'');self.assertFalse(pending);self.assertEqual(decoded,baseline+events)

 def test_selected_root_directory_exact_live_fd_and_no_global_leak(self):
  raw=G.read(HERE/'factory/installed607.py');m=types.ModuleType('_root_directory_actual');m.__file__=str(self.work/'installed606.py');exec(compile(O.edited(raw,O.observer_rows()),m.__file__,'exec'),vars(m))
  spec=importlib.util.spec_from_file_location('_real_root_helper',HERE/'factory/support/alpm_reader.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
  original=helper.directory;selected=m._selected_root_helper607(helper);self.assertIs(helper.directory,original);self.assertIsNot(selected,helper)
  # /usr/share is read-only host DATA. Device crossing is refused identically.
  for name in ('usr','usr/share'):
   results=[]
   for provider in(helper,selected):
    try:
     with provider.directory(Path('/'),name)as fd:results.append(('ok',helper.identity(os.fstat(fd))))
    except (ValueError,OSError)as e:results.append(('refused',type(e).__name__))
   self.assertEqual(results[0],results[1])
  for name in ('../tmp','usr//share','/usr/share','usr/./share','usr/share/../share'):
   for provider in(helper,selected):
    with self.assertRaises((ValueError,OSError)):
     with provider.directory(Path('/'),name):pass
  # Actual symlink substitution in a private nonroot fixture still uses original traversal.
  fixture=self.work/'root-helper-fixture';fixture.mkdir();(fixture/'real').mkdir();(fixture/'alias').symlink_to('real',target_is_directory=True)
  with selected.directory(fixture,'real')as fd:self.assertEqual(helper.identity(os.fstat(fd)),helper.identity((fixture/'real').stat()))
  for provider in(helper,selected):
   with self.assertRaises(OSError):
    with provider.directory(fixture,'alias'):pass
  self.assertIs(helper.directory,original)

 def test_selected_root_actual_executing_globals_and_capture_held(self):
  raw=G.read(HERE/'factory/installed607.py');m=types.ModuleType('_root_directory_bind');m.__file__=str(self.work/'installed606.py');exec(compile(O.edited(raw,O.observer_rows()),m.__file__,'exec'),vars(m))
  class Helper:pass
  helper=Helper();helper.directory=lambda *a:None;helper.relative=load('_actual_root_binding_lexical',HERE/'factory/support/alpm_reader.py').relative
  seen=[];original=m.observe
  m.__dict__['seen']=seen
  exec('def observation(root,actual,expected,*,deadline):seen.append(actual);return actual',m.__dict__)
  observation=m.observation;m.observe=observation
  try:
   selected=m._selected_verify_observe(Path('/'),helper,{},deadline=1200);self.assertIsNot(selected,helper);self.assertIs(m.observe,observation);self.assertIs(seen[-1],selected)
   other=m._selected_verify_observe(self.work,helper,{},deadline=1200);self.assertIs(other,helper)
   self.assertIs(observation(Path('/'),helper,{},deadline=600),helper)
  finally:m.observe=original


 def test_actual_selected_package_progress_complete_object_and_default_held(self):
  expected=dict(line.split()for line in(HERE/'expected607.lock').read_text().splitlines());root=self.work/'root';local=root/'var/lib/pacman/local';local.mkdir(parents=True);(local/'ALPM_DB_VERSION').write_bytes(b'9\n');(root/'payload').mkdir()
  for name,version in expected.items():
   d=local/(name+'-'+version);d.mkdir();(d/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n%ARCH%\nany\n');(d/'files').write_text('%FILES%\npayload/'+name+'\n');(root/'payload'/name).write_bytes((name+' '+version).encode())
  raw=G.read(HERE/'factory/installed607.py');m=types.ModuleType('_actual_payload_progress');m.__file__=str(self.work/'installed606.py');exec(compile(O.edited(raw,O.observer_rows()),m.__file__,'exec'),vars(m));shutil.copyfile(HERE/'factory/support/file_capabilities.py',self.work/'file_capabilities.py');helper=load('_actual_payload_progress_alpm',HERE/'factory/support/alpm_reader.py');notes=[]
  original=m.observe;default=original(root,helper,expected)
  with patch.object(m.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):actual=m._selected_verify_observe(root,helper,expected,deadline=1200)
  self.assertEqual(actual,default);self.assertIs(m.observe,original);self.assertIs(m._payload_original607,original);self.assertIs(m._payload_observe607.__globals__,vars(m));self.assertEqual(len([r for r in notes if r.startswith(b'INSTALLED607_RECHECK_DATA ')]),7);notes=[r for r in notes if r.startswith(b'INSTALLED607_PAYLOAD_DATA ')];self.assertEqual(len(notes),1214)
  values=[json.loads(row.split(b' ',1)[1])for row in notes];self.assertEqual({r['package']for r in values},set(range(1,608)));self.assertTrue(all(r['boundary']==('begin'if i%2==0 else'end')for i,r in enumerate(values)));self.assertEqual(values[0]['nodes'],0);self.assertEqual(values[-1]['nodes'],607);self.assertEqual(values[-1]['payload_bytes'],actual['payload_bytes']);self.assertLessEqual(sum(map(len,notes)),233088)
  old=ast.parse(O.unrecheck_installed607(O.edited(raw,O.observer_rows())));base=next(n for n in old.body if isinstance(n,ast.FunctionDef)and n.name=='observe');selected=next(n for n in old.body if isinstance(n,ast.FunctionDef)and n.name=='_payload_observe607');selected.name='observe'
  # Remove only source-owned DATA calls and its private emitter construction.
  selected.body=[n for n in selected.body if not(isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='progress'for t in n.targets))]
  loop=next(n for n in selected.body if isinstance(n,ast.For)and isinstance(n.target,ast.Name)and n.target.id=='row'and any(isinstance(c,ast.Expr)and isinstance(c.value,ast.Call)and isinstance(c.value.func,ast.Attribute)and c.value.func.attr=='mark'for c in n.body))
  loop.body=[n for n in loop.body if not(isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and isinstance(n.value.func.value,ast.Name)and n.value.func.value.id=='progress')]
  self.assertEqual(ast.dump(selected),ast.dump(base));self.assertEqual(m.observe.__kwdefaults__,{'deadline':600})
  with patch.object(m.os,'write',side_effect=OSError('DATA loss')):self.assertEqual(m._selected_verify_observe(root,helper,expected,deadline=1200),default)
  with patch.object(m.os,'write',side_effect=lambda *_:0),self.assertRaises(ValueError):m._selected_verify_observe(root,helper,expected,deadline=0)

 def test_package_progress_fixed_types_caps_loss_and_no_contents(self):
  raw=G.read(HERE/'factory/installed607.py');m=types.ModuleType('_bounded_payload_progress');m.__file__=str(self.work/'installed606.py');exec(compile(O.edited(raw,O.observer_rows()),m.__file__,'exec'),vars(m));notes=[];expected={'package'+str(i):'1'for i in range(607)}
  with patch.object(m.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):
   emitter=m._Payload607(expected)
   for args in((None,'package0',0,0),('begin','foreign',0,0),('begin','package0',True,0),('begin','package0',0,-1),('end','package0',200001,0)):
    self.assertFalse(emitter.mark(*args))
   for _ in range(1214):self.assertTrue(emitter.mark('begin','package0',200000,6*1024**3))
   self.assertFalse(emitter.mark('begin','package0',0,0))
  self.assertEqual(len(notes),1214);self.assertLessEqual(sum(map(len,notes))+2048,256*1024);self.assertTrue(all(len(b)<=192 for b in notes))
  for b in notes:
   self.assertTrue(b.startswith(b'INSTALLED607_PAYLOAD_DATA '));v=json.loads(b.split(b' ',1)[1]);self.assertEqual(set(v),{'schema','package','boundary','nodes','payload_bytes','elapsed_ns','status'});self.assertEqual(v['status'],'PROGRESS_DATA_ONLY');self.assertNotIn(b'package0',b)
  with patch.object(m.os,'write',side_effect=OSError('lost')):self.assertFalse(m._Payload607(expected).mark('begin','package0',0,0))

 def test_package_begin_existing_original_timeout_tail_before_error(self):
  path=ROOT/'parent574/original/scripts/ci/desktop574_guest.py';raw=path.read_text();tree=ast.parse(raw);names={'need','terminate','Logged','command'};parts=[ast.get_source_segment(raw,n)for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];self.assertEqual(len(parts),4);events=[];space=dict(os=os,signal=signal,subprocess=subprocess,threading=threading,Path=Path,hashlib=hashlib,base64=base64,MAX_LOG=256*1024,emit=lambda event,**row:events.append(dict(event=event,**row)));exec(compile('\n\n'.join(parts),'<original-command-timeout-tail>','exec'),space)
  body='import json,os,time\n'+O.PAYLOAD_BODY607+"\np=_Payload607({'fixed':'1'});p.mark('begin','fixed',12,34);time.sleep(5)";logs=self.work/'logs';logs.mkdir()
  with self.assertRaises(subprocess.TimeoutExpired):space['command']([sys.executable,'-I','-B','-c',body],dict(PATH='/usr/bin:/bin'),logs,'installed606-preserved',timeout=.3)
  self.assertEqual(len(events),1);tail=base64.b64decode(events[0]['logs'][1]['tail_base64'],validate=True);self.assertEqual(tail,(logs/'installed606-preserved.stderr').read_bytes());self.assertIn(b'INSTALLED607_PAYLOAD_DATA ',tail);self.assertIn(b'"boundary":"begin"',tail);self.assertLessEqual(len(tail),2048);self.assertNotEqual(events[0]['returncode'],0)


# Actual emitted finite recheck controls; no acceptance from diagnostic DATA.
import copy,time

def _recheck_bodies607(raw):
 return{n.name:ast.get_source_segment(raw.decode(),n)for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
class RecheckControls(unittest.TestCase):
 setUp=Controls.setUp
 def module(self):
  m=types.ModuleType('_actual_recheck_emitted');m.__file__=str(self.work/'installed606.py');raw=O.edited(G.read(HERE/'factory/installed607.py'),O.observer_rows());exec(compile(raw,m.__file__,'exec'),vars(m));m.capabilities=lambda:load('_actual_recheck_caps',HERE/'factory/support/file_capabilities.py');return m
 def fixture(self):
  root=self.work/'root';local=root/'var/lib/pacman/local';local.mkdir(parents=True);(root/'payload').mkdir();(local/'ALPM_DB_VERSION').write_bytes(b'9\n');expected={f'fixture{i:03}':'1'for i in range(607)}
  for name in expected:
   d=local/(name+'-1');d.mkdir();(d/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n1\n\n%ARCH%\nany\n\n');(d/'files').write_text('%FILES%\npayload/'+name+'\n\n');(root/'payload'/name).write_bytes(name.encode())
  return root,expected,load('_owned_actual_alpm',HERE/'factory/support/alpm_reader.py')
 def notes(self,m):
  notes=[]
  with patch.object(m.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):
   d=m._Recheck607()
   for phase in d.phases:self.assertTrue(d.mark(phase))
  return notes
 def relay(self,events):
  space=dict(json=json,_ObserverStageForward=object);exec(compile(O.RECHECK607_FORWARD,'<actual-recheck-relay>','exec'),space)
  return space['_RecheckForward607'](lambda event,**v:events.append(dict(event=event,**v)))
 def test_inverse_all_other_bodies_and_defaults_held(self):
  raw=G.read(HERE/'factory/installed607.py');before=O.edited(raw,O._recheck_prior_observer_rows607());after=O.edited(raw,O.observer_rows());self.assertEqual(O.recheck_installed607(before),after);self.assertEqual(O.unrecheck_installed607(after),before);a=_recheck_bodies607(before);b=_recheck_bodies607(after);self.assertEqual(set(b)-set(a),{'_Recheck607'});self.assertEqual([n for n in a if a[n]!=b[n]],['_payload_observe607']);self.assertEqual(self.module().observe.__kwdefaults__,{'deadline':600})
  self.assertEqual(O.unrecheck_observer_rows607(O.observer_rows()),O._recheck_prior_observer_rows607());self.assertEqual(O.unrecheck_forwarding_rows607(O.forwarding_rows()),O._recheck_prior_forwarding_rows607())
  raw=G.read(ROOT/'parent574/original/scripts/ci/desktop574_guest.py');before=O.edited(raw,O._recheck_prior_forwarding_rows607());after=O.edited(raw,O.forwarding_rows());a=_recheck_bodies607(before);b=_recheck_bodies607(after);self.assertEqual([n for n in a if a[n]!=b[n]],['Logged']);self.assertIn('timeout=20',a['command']);self.assertEqual(a['command'],b['command'])
 def test_actual607_equal_and_diagnostic_loss(self):
  root,expected,h=self.fixture();m=self.module();baseline=m.observe(root,h,expected);notes=[]
  with patch.object(m.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):actual=m._selected_verify_observe(root,h,expected,deadline=1200)
  self.assertEqual(actual,baseline);self.assertEqual(len(actual['nodes']),607);rows=[json.loads(x.split(b' ',1)[1])for x in notes if x.startswith(b'INSTALLED607_RECHECK_DATA ')]
  self.assertEqual([x['phase']for x in rows],list(m._Recheck607.phases));self.assertEqual([x['ordinal']for x in rows],list(range(1,8)))
  with patch.object(m.os,'write',side_effect=OSError('lost diagnostic')):
   self.assertEqual(m._selected_verify_observe(root,h,expected,deadline=1200),baseline)
   with self.assertRaises(ValueError)as old:m.observe(root,h,expected,deadline=0)
   with self.assertRaises(ValueError)as new:m._payload_observe607(root,h,expected,deadline=0)
   self.assertEqual(str(new.exception),str(old.exception))
 def test_drift_short_circuit_and_original_exception(self):
  root,expected,h=self.fixture();m=self.module();real=h.database;calls=[];notes=[]
  def database(*a,**kw):
   calls.append(True);rows=real(*a,**kw)
   if len(calls)==2:rows=copy.deepcopy(rows);rows[0]['version']='changed'
   return rows
  h.database=database
  with patch.object(m.os,'write',side_effect=lambda fd,b:notes.append(b)or len(b)):
   with self.assertRaisesRegex(ValueError,'database/root drift or deadline'):m._selected_verify_observe(root,h,expected,deadline=1200)
  phases=[json.loads(x.split(b' ',1)[1])['phase']for x in notes if x.startswith(b'INSTALLED607_RECHECK_DATA ')];self.assertEqual(phases,['observer_begin','database_begin','database_end'])
  d=m._Recheck607();problem=ValueError('same exception')
  with patch.object(d,'mark',return_value=False):
   with self.assertRaises(ValueError)as got:d.call('database',lambda:(_ for _ in()).throw(problem))
  self.assertIs(got.exception,problem)
 def test_finite_emitter_and_fragmented_relay_recovery(self):
  m=self.module();notes=self.notes(m);events=[];r=self.relay(events)
  for byte in b'x'*1000+b'\n'+b''.join(notes):r.feed(bytes([byte]))
  self.assertEqual([e['ordinal']for e in events],list(range(1,8)));self.assertLessEqual(r.input_bytes,1792);self.assertLessEqual(r.output_bytes,2304);self.assertEqual(r.pending,b'')
  for raw in notes:self.assertLessEqual(len(raw),256);self.assertFalse(r.record(raw))
  with patch.object(m.os,'write',return_value=0):
   d=m._Recheck607();self.assertFalse(d.mark('private/path'));self.assertFalse(d.mark(True));self.assertFalse(d.mark('observer_begin'));self.assertFalse(d.mark('observer_begin'))
  with patch.object(m.time,'monotonic_ns',side_effect=[0,2**63]):self.assertFalse(m._Recheck607().mark('observer_begin'))
 def test_hostile_relay_and_loss_refused(self):
  note=self.notes(self.module())[0];v=json.loads(note.split(b' ',1)[1])
  for row in(dict(v,schema=True),dict(v,phase='private'),dict(v,ordinal=True),dict(v,monotonic_ns=-1),dict(v,monotonic_ns=2**63),dict(v,elapsed_ns=True),dict(v,elapsed_ns=1215000000001),dict(v,acceptance=True)):
   events=[];raw=b'INSTALLED607_RECHECK_DATA '+json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n';self.assertFalse(self.relay(events).record(raw));self.assertEqual(events,[])
  notes=self.notes(self.module());events=[];r=self.relay(events);self.assertTrue(r.record(notes[0]));v2=json.loads(notes[1].split(b' ',1)[1]);v2['elapsed_ns']+=1;bad=b'INSTALLED607_RECHECK_DATA '+json.dumps(v2,sort_keys=True,separators=(',',':')).encode()+b'\n';self.assertFalse(r.record(bad));self.assertEqual(len(events),1)
  events=[];r=self.relay(events);self.assertFalse(r.record(note.replace(b':',b': ',1)));self.assertFalse(r.feed(b'x'*65537));r.send=lambda *a,**kw:(_ for _ in()).throw(OSError('lost'));self.assertFalse(r.record(note))
 def test_live_before_exit_original_command_and_retirement(self):
  raw=O.edited(G.read(ROOT/'parent574/original/scripts/ci/desktop574_guest.py'),O.forwarding_rows());names={'need','terminate','Logged','command','_ObserverStageForward','_RecheckForward607','_ObserverAndRecheck607'};parts=_recheck_bodies607(raw);events=[];share=self.work/'share';share.mkdir();logs=self.work/'logs';logs.mkdir()
  space=dict(os=os,signal=signal,subprocess=subprocess,threading=threading,Path=Path,hashlib=hashlib,base64=base64,json=json,MAX_LOG=256*1024,SHARE=share,emit=lambda event,**v:events.append(dict(event=event,**v)))
  exec(compile('\n\n'.join(parts[n]for n in parts if n in names),'<actual-rendered-command>','exec'),space)
  (share/'installed606.py').write_text('import os,json,time\n'+O.RECHECK607_BODY+"\nd=_Recheck607();d.mark('observer_begin');time.sleep(5)\n")
  argv=['/usr/bin/python3','-I','-B',str(share/'installed606.py'),'verify','/',str(share/'alpm_reader.py'),str(share/'expected.lock'),str(share/'installed606.json')];actor=space['Logged'](argv,'installed606-preserved',logs,dict(PATH='/usr/bin:/bin'))
  try:
   until=time.monotonic()+1
   while not events and time.monotonic()<until:time.sleep(.01)
   self.assertIsNone(actor.process.poll());self.assertEqual(events[0]['event'],'installed607_recheck_DATA')
  finally:space['terminate'](actor.process);actor.finish()
  self.assertEqual(events[-1]['event'],'process_exit');self.assertNotEqual(events[-1]['returncode'],0);self.assertIn(b'INSTALLED607_RECHECK_DATA',base64.b64decode(events[-1]['logs'][1]['tail_base64'],validate=True))



class ReservationControls(unittest.TestCase):
 setUp=Controls.setUp
 def test_actual_event_decoder_retains_bounded_recheck_DATA(self):
  m=RecheckControls.module(self);notes=RecheckControls.notes(self,m);events=[];relay=RecheckControls.relay(self,events)
  relay.feed(b''.join(notes));self.assertEqual(len(events),7)
  raw=G.read(ROOT/'parent574/original/scripts/ci/desktop574_runtime.py');tree=ast.parse(raw);decoder=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='read_events');assign=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id in('PREFIX','MAX_EVENTS')for x in n.targets)];space=dict(json=json,require=O.need);exec(compile(ast.Module(body=assign+[decoder],type_ignores=[]),'<held-original-DATA-decoder>','exec'),space)
  path=self.work/'recheck-events.log';path.write_bytes(b''.join((space['PREFIX']+json.dumps(e,sort_keys=True)+'\n').encode()for e in events));_,pending,actual=space['read_events'](path,0,b'');self.assertFalse(pending);self.assertEqual(actual,events);self.assertTrue(all(e['status']=='RECHECK_DATA_ONLY_NOT_ACCEPTANCE'for e in actual))
 def emitted(self):
  f=load('_historical_reserved_source',HERE/'historical_source.py').historical_selected_factory(load('_historical_reserved_base',HERE/'factory/factory.py'),ROOT/'parent574/original',ARGS.assets);out=self.work/'reserved'
  with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):profile,changes=f.prepare_code(ROOT/'parent574/original',ARGS.assets,out,'minimal','generic4k');proof=f.seal(out,'minimal','generic4k',profile,changes,False)
  return out,proof
 def test_actual_emitted_reservation_caps_shared_lease_and_admission(self):
  out,proof=self.emitted();spec=O.reservation_spec();r=spec['reservation'];self.assertEqual(spec['service_seconds'],r['pre_observer_seconds']+r['caller_seconds']+r['cleanup_seconds']);self.assertEqual((spec['service_seconds'],spec['loop_seconds'],spec['runtime_seconds'],spec['owner_wait_seconds'],spec['native_owner_seconds']),(3460,3560,4010,4460,6600));self.assertEqual(proof['service_validation_profile'],O.reservation_annotation());self.assertEqual(json.loads((out/'service-vm-profile.json').read_bytes()),spec)
  dl=load('_actual_reserved_lifetime',out/'doctor_lifetime.py');self.assertEqual(dl.SERVICE_SECONDS,3460);self.assertEqual(dl.SECONDS,1080);lease=dict(started_ns=0,deadline_ns=3460*10**9,purpose=spec['service_purpose']);seen=[]
  with patch.object(dl,'service_lease',side_effect=lambda:seen.append(True)or lease),patch.object(dl.time,'monotonic_ns',return_value=1800*10**9):self.assertIs(dl.reserve_readback607(),lease)
  with patch.object(dl,'service_lease',return_value=lease),patch.object(dl.time,'monotonic_ns',return_value=1800*10**9+1),self.assertRaisesRegex(ValueError,'full1210 caller and450 cleanup'):dl.reserve_readback607()
  self.assertEqual(seen,[True]);guest=(out/'base_guest.py').read_text();self.assertIn("DL.reserve_readback607()\n        proof=command(",guest);self.assertIn("logs,'installed606-preserved',timeout=1210)",guest);self.assertIn("deadline_ns-(1210+450)*10**9",(out/'management_root.py').read_text())
 def test_production_defaults_and_original_selected_facades_held(self):
  V=load('_actual_held_capacity',HERE/'factory/service_capacity.py');self.assertEqual((V.SPEC['service_seconds'],V.SPEC['loop_seconds'],V.SPEC['runtime_seconds'],V.SPEC['owner_wait_seconds']),(1800,1900,2350,2800));self.assertEqual((V.SPEC['default_service_seconds'],V.SPEC['default_loop_seconds'],V.SPEC['default_runtime_seconds'],V.SPEC['default_owner_wait_seconds']),(1200,1300,1750,2200));self.assertEqual(O.ANNOTATION['validation_profile']['default_observer_seconds'],600);self.assertEqual(O.ANNOTATION['validation_profile']['capture_seconds'],600)
  out,proof=self.emitted();text=(out/'management_root.py').read_text();base=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='serve');selected=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='_reserved_serve607');old=ast.get_source_segment(text,base);new=ast.get_source_segment(text,selected).replace('def _reserved_serve607(','def serve(').replace("deadline_ns-(1210+450)*10**9,'managed session readback reservation deadline'","deadline_ns,'managed session deadline'");self.assertEqual(new,old);self.assertEqual(O.reservation_spec()['old1800_fit'],'NOT_ESTABLISHED');self.assertIsNone(proof['actual_run'])

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--assets',type=Path,required=True);ARGS=p.parse_args();unittest.main(argv=[sys.argv[0]],verbosity=2)
