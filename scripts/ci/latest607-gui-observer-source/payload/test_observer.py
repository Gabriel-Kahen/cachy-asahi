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
  fact=G.verify();self.assertEqual((fact['files'],fact['parent676_files'],fact['packages'],fact['optional_absent']),(682,676,607,605));self.assertEqual(fact['service_seconds'],1800)
  raw=G.read(HERE/'factory/support/alpm_reader.py');self.assertEqual(O.pin(raw),O.AFTER)
  for before,after in reversed(Q.EDITS):self.assertEqual(raw.count(after.encode()),1);raw=raw.replace(after.encode(),before.encode(),1)
  self.assertEqual(O.pin(raw),O.BEFORE);self.assertEqual(O.ANNOTATION['observer_seconds'],O.ANNOTATION['caller_seconds']);self.assertEqual(O.ANNOTATION['observer_seconds'],600)
  with self.assertRaises((OSError,ValueError)):O.apply(self.work)
 def test_four_actual_emissions_and_executing_namespace_before_source_seal(self):
  n=load('_observer_actual_native',HERE/'native.py');proofs=[]
  for profile in('minimal','overlay'):
   for mode in('generic4k','generic16k'):
    f=n.factory();out=self.work/(profile+mode);self.assertIs(f.emit.__globals__['prepare_code'],f.prepare_code);self.assertIs(f.emit.__globals__['seal'],f.seal)
    with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):p,ch=f.prepare_code(ROOT/'parent574/original',ARGS.assets,out,profile,mode);r=f.seal(out,profile,mode,p,ch,False)
    self.assertEqual((r['packages'],r['optional_absent']),(607,605));self.assertEqual(r['observer_diagnostic'],O.ANNOTATION);self.assertEqual(O.pin((out/'alpm_reader.py').read_bytes()),O.AFTER);self.assertFalse((out/'observer_stage.py').exists());self.assertIn('CAP=64*1024**2',(out/'installed606.py').read_text());self.assertIn('_OBSERVER_STAGE_CAP=2048',(out/'installed606.py').read_text());self.assertEqual((out/'installed606.py').read_bytes(),O.edited((HERE/'factory/installed607.py').read_bytes(),O.observer_rows()));self.assertIn('timeout=600',(out/'base_guest.py').read_text());self.assertIn('TimeoutStartSec=1800',(out/'desktop574_fixture.sh').read_text());self.assertIn('time.monotonic() + 1900',(out/'desktop574_runtime.py').read_text());self.assertIn('ITIMER_REAL, 2350',(out/'desktop574_runtime.py').read_text());self.assertEqual(r['service_validation_profile']['owner_wait_seconds'],2800);proofs.append(dict(profile=profile,mode=mode,files=r['files']))
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
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--assets',type=Path,required=True);ARGS=p.parse_args();unittest.main(argv=[sys.argv[0]],verbosity=2)
