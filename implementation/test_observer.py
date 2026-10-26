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
  fact=G.verify();self.assertEqual((fact['files'],fact['parent676_files'],fact['packages'],fact['optional_absent']),(692,676,607,605));self.assertEqual(fact['service_seconds'],1800)
  raw=G.read(HERE/'factory/support/alpm_reader.py');self.assertEqual(O.pin(raw),O.AFTER)
  for before,after in reversed(Q.EDITS):self.assertEqual(raw.count(after.encode()),1);raw=raw.replace(after.encode(),before.encode(),1)
  self.assertEqual(O.pin(raw),O.BEFORE);self.assertEqual((O.ANNOTATION['observer_seconds'],O.ANNOTATION['caller_seconds']),(1200,1210));self.assertEqual(O.ANNOTATION['validation_profile']['default_observer_seconds'],600)
  with self.assertRaises((OSError,ValueError)):O.apply(self.work)
 def test_four_actual_emissions_and_executing_namespace_before_source_seal(self):
  n=load('_observer_actual_native',HERE/'native.py');proofs=[]
  for profile in('minimal','overlay'):
   for mode in('generic4k','generic16k'):
    f=n.factory();out=self.work/(profile+mode);self.assertIs(f.emit.__globals__['prepare_code'],f.prepare_code);self.assertIs(f.emit.__globals__['seal'],f.seal)
    with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):p,ch=f.prepare_code(ROOT/'parent574/original',ARGS.assets,out,profile,mode);r=f.seal(out,profile,mode,p,ch,False)
    self.assertEqual((r['packages'],r['optional_absent']),(607,605));self.assertEqual(r['observer_diagnostic'],O.ANNOTATION);self.assertEqual(O.pin((out/'alpm_reader.py').read_bytes()),O.AFTER);self.assertFalse((out/'observer_stage.py').exists());self.assertIn('CAP=64*1024**2',(out/'installed606.py').read_text());self.assertIn('_OBSERVER_STAGE_CAP=2048',(out/'installed606.py').read_text());self.assertEqual((out/'installed606.py').read_bytes(),O.edited((HERE/'factory/installed607.py').read_bytes(),O.observer_rows()));self.assertIn("logs,'installed606-preserved',timeout=1210)",(out/'base_guest.py').read_text());self.assertIn('TimeoutStartSec=1800',(out/'desktop574_fixture.sh').read_text());self.assertIn('time.monotonic() + 1900',(out/'desktop574_runtime.py').read_text());self.assertIn('ITIMER_REAL, 2350',(out/'desktop574_runtime.py').read_text());self.assertEqual(r['service_validation_profile']['owner_wait_seconds'],2800);proofs.append(dict(profile=profile,mode=mode,files=r['files']))
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
  names={'need','terminate','Logged','command'}|({'_ObserverStageForward'}if current else set())
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
    self.assertEqual([e['stage']for e in events]if current else events,['inventory_begin','inventory_end']if current else [])
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
  self.assertEqual([e['stage']for e in events],list(klass.stages));self.assertLessEqual(f.input_bytes,2048);self.assertLessEqual(f.output_bytes,2048);self.assertLessEqual(len(f.pending),512)
  for row in events:self.assertEqual(set(row),{'event','schema','stage','ordinal','elapsed_ns','status'});self.assertEqual(row['status'],'BOUNDARY_DATA_ONLY_NOT_ACCEPTANCE')
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
  self.assertEqual([e['stage']for e in events if e['event']=='installed607_observer_stage_DATA'],['inventory_begin','inventory_end'])
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


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--assets',type=Path,required=True);ARGS=p.parse_args();unittest.main(argv=[sys.argv[0]],verbosity=2)
