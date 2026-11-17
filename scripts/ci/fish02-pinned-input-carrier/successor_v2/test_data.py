#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite transport-fenced actual counter, audit, cadence and exporter controls."""
import ast
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
HERE=Path(__file__).resolve().parent

def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
D=load(HERE.parent/'test_data.py','fish_carrier_model_fence');P=load(HERE/'prepare.py','finite512_source')
PARENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-fish02-pinned-input-carrier-20261117/artifacts/development/fish02-pinned-input-carrier-20261117-r1/Source-DATA')
BASE='held-source32/scripts/ci/fish-config02-native-source/'

class Clock:
 def __init__(self):self.now=0.;self.waits=[]
 def monotonic(self):return self.now
 def sleep(self,n):assert 0<=n<=10;self.waits.append(n);self.now+=n

def need(ok,msg):
 if not ok:raise ValueError(msg)

def retirement():return dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,passed=True,output=b'')

class Controls(unittest.TestCase):
 setUp=D.Controls.setUp
 clean=D.Controls.clean
 def source(self):
  old=P.physical(PARENT);new=P.assemble(old);return old,new
 def test_complete_carrier62_inverse_no_other_guard_or_workflow_change(self):
  old,new=self.source();self.assertEqual(P.inverse(new),old);self.assertEqual(len(new),63);self.assertLess(sum(map(len,new.values())),2*1024**2);self.assertTrue(all(v is None for v in json.loads(new['source-map.json'])['actual'].values()))
  self.assertTrue(all(new[n]==raw for n,raw in old.items()if n.startswith('held-source32/')));self.assertEqual(new[P.A.NEW_WF],old[P.A.NEW_WF])
  policy=json.loads(new[P.PREFIX+'policy.json']);prior=json.loads(old[P.PREFIX+'policy.json']);policy.pop('finite_command_case');policy.pop('inner_public_retention');policy['private_pinned_input_carrier']=prior['private_pinned_input_carrier'];self.assertEqual(policy,prior)
  methods=lambda raw:{n.name:ast.dump(n,include_attributes=False)for c in ast.parse(raw).body if isinstance(c,ast.ClassDef)and c.name=='Controller'for n in c.body if isinstance(n,ast.FunctionDef)}
  before,after=methods(old[P.PREFIX+'hosted_owner.py']),methods(new[P.PREFIX+'hosted_owner.py'])
  for key in('run','stop','cleanup','show','loop_identity'):self.assertEqual(before[key],after[key],key)
  self.assertIn(b"self.cleanup_end=min(self.cleanup_end,time.monotonic()+90)",new[P.PREFIX+'hosted_owner.py'])
  for n in(P.A.HELPER,P.PREFIX+'public_evidence.py',P.PREFIX+'hosted_owner.py',P.MARKER):
   with self.assertRaises((ValueError,KeyError,json.JSONDecodeError)):P.inverse(dict(new,**{n:new[n]+b'\nMODEL-tamper'}))
 def test_actual_inner_and_outer_512th_allowed_513th_refused_before_child(self):
  old,new=self.source();n={ '__name__':'MODEL_carrier','__file__':str(HERE/'MODEL.py')};exec(compile(new[P.A.HELPER],n['__file__'],'exec'),n)
  self.assertEqual(n['N'].binding(),P.BINDING);self.assertEqual(P.BINDING['commit'],'9d9e1ab7ce694e33238ec1152bef72270d4bf91f')
  projected=n['project_entry'](old[BASE+'entry.py']);tree=ast.parse(projected)
  part=[x for x in tree.body if isinstance(x,(ast.FunctionDef,ast.ClassDef))and x.name in('natural','Commands')]
  process=Mock(return_value=SimpleNamespace(returncode=0,_child_created=True));fakeproc=SimpleNamespace(Popen=process,DEVNULL=subprocess.DEVNULL,PIPE=subprocess.PIPE,CompletedProcess=subprocess.CompletedProcess)
  out=self.area/'commands';out.mkdir();c=SimpleNamespace(need=need,pin=P.P.pin);o=SimpleNamespace(prepare=lambda:None,supervise=lambda *_a,**_k:retirement())
  ns=dict(C=c,threading=threading,time=time,math=math,resource=SimpleNamespace(),os=os,json=json,subprocess=fakeproc)
  exec(compile(ast.Module(body=part,type_ignores=[]),'MODEL-inner','exec'),ns);runner=ns['Commands'](o,out,time.monotonic()+100,time.monotonic()+190,SimpleNamespace(pending=False,cleaning=False));runner.rows=[{}]*511
  runner(['/MODEL/gpg'],60);self.assertEqual(len(runner.rows),512);self.assertEqual(process.call_count,1);self.assertTrue((out/'511.json').is_file())
  with self.assertRaises(ValueError):runner(['/MODEL/gpg'],60)
  self.assertEqual(process.call_count,1)
  host=ast.parse(new[P.PREFIX+'hosted_owner.py']);klass=next(x for x in host.body if isinstance(x,ast.ClassDef)and x.name=='Controller')
  ns=dict(D=c,H=SimpleNamespace(checked=lambda r:r['path']),V=SimpleNamespace(controller_limit=lambda p:(1,1),child_plan=lambda *a:{},child_limits=lambda a:lambda:None),resource=SimpleNamespace(getrlimit=lambda _: (1,1),RLIMIT_AS=9),subprocess=fakeproc,time=time,write=lambda p,v:p.write_text(json.dumps(v)))
  exec(compile(ast.Module(body=[klass],type_ignores=[]),'MODEL-outer','exec'),ns);controller=ns['Controller'].__new__(ns['Controller']);controller.tools={'MODEL':dict(path='/MODEL/gpg')};controller.commands=[{}]*511;controller.cleaning=False;controller.end=time.monotonic()+100;controller.cleanup_end=controller.end+90;controller.policy={};controller.O=o;controller.out=self.area
  controller.run(['/MODEL/gpg']);self.assertEqual(len(controller.commands),512);calls=process.call_count
  with self.assertRaises(ValueError):controller.run(['/MODEL/gpg'])
  self.assertEqual(process.call_count,calls)
 def test_original_all501_audit_executes250_mocked_GPG_commands(self):
  old,new=self.source();inputs=json.loads(old[BASE+'runtime/scripts/ci/inputs.lock.json']);self.assertEqual(len(inputs['packages']),248)
  calls=[];verified=[];out=self.area/'audit';out.mkdir();cache=self.area/'cache'
  n=SimpleNamespace();n.__dict__.update(dict(Path=Path,signature_item=lambda i:dict(filename=i['filename']+'.sig',sha256=i['signature_sha256']),acquire=lambda items,*a:self.assertEqual(len(items),501),run=lambda argv,*a:calls.append(argv),subprocess=SimpleNamespace(run=lambda argv,**k:(calls.append(argv)or SimpleNamespace(returncode=0,stdout='MODEL',stderr=''))),save=lambda *_:None,valid_signature=lambda stdout,fingerprint:verified.append(fingerprint),rootfs_inventory=lambda _:inputs['rootfs_packages'],rootfs_hooks=lambda _:[],inspect_package=lambda *_:{}))
  c=load(PARENT/BASE/'contract.py','MODEL_whole_audit_projector');c.audit_adapter(n,old[BASE+'runtime/scripts/ci/native_arm.py']);n.audit(inputs,cache,out)
  self.assertEqual(len(calls),250);self.assertEqual(sum('--import'in x for x in calls),1);self.assertEqual(sum('--verify'in x for x in calls),249);self.assertEqual(verified,[inputs['signer_fingerprint']]*249)
 def test_actual_start_and_running_loops_obey_clipped_cadence_ledger(self):
  old,new=self.source();host=ast.parse(new[P.PREFIX+'hosted_owner.py']);klass=next(x for x in host.body if isinstance(x,ast.ClassDef)and x.name=='Controller');clock=Clock();queries=[]
  ns=dict(D=SimpleNamespace(need=need,unit=lambda nonce,kind:'MODEL-unit',service_args=lambda *a,**k:['/MODEL/systemd-run','a','b','c']),H=SimpleNamespace(checked=lambda r:r['path']),Q=SimpleNamespace(project_service=lambda *a:a[0]),time=clock)
  exec(compile(ast.Module(body=[klass],type_ignores=[]),'MODEL-start','exec'),ns);c=ns['Controller'].__new__(ns['Controller']);c.tools={'MODEL':dict(path='/MODEL/python')};c.nonce='MODEL';c.policy={'owner':{}};c.out=self.area;c.root=self.area;c.units={};c.end=1650;c.run=lambda *_:None;c.tool=lambda n:'/MODEL/'+n
  def show(kind):queries.append(kind);return dict(LoadState='not-found')if len(queries)==1 else dict(MainPID='0',ActiveState='activating')
  c.show=show
  with self.assertRaises(TimeoutError):c.start('owner',['/MODEL/python'])
  self.assertLessEqual(len(queries),32);self.assertEqual(clock.now,30);self.assertTrue(all(w<=1 for w in clock.waits))
  main=next(x for x in host.body if isinstance(x,ast.FunctionDef)and x.name=='main');loop=next(x for x in main.body if isinstance(x,ast.Try)).body
  loop=next(x for x in loop if isinstance(x,ast.While));clock=Clock();calls=[];owner=SimpleNamespace(end=1650,show=lambda kind:(calls.append(kind)or dict(ActiveState='active')))
  with self.assertRaises(ValueError):exec(compile(ast.Module(body=[loop],type_ignores=[]),'MODEL-running','exec'),dict(D=SimpleNamespace(need=need),owner=owner,time=clock))
  self.assertLessEqual(len(calls),166);self.assertEqual(clock.now,1650);self.assertTrue(all(w<=10 for w in clock.waits))
  ledger=json.loads((HERE/'command-ledger.DATA.json').read_bytes());self.assertEqual(ledger['inner']['conservative_upper'],250+6+6+1+15+4);self.assertEqual(ledger['outer']['conservative_upper'],1+5+66+1+166+1+8+5);self.assertLess(ledger['outer']['conservative_upper'],512)
 def test_actual_finally_exports_hold_before_cleanup_and_refusal_never_skips_cleanup(self):
  old,new=self.source();host=ast.parse(new[P.PREFIX+'hosted_owner.py']);main=next(n for n in host.body if isinstance(n,ast.FunctionDef)and n.name=='main');operation=next(n for n in main.body if isinstance(n,ast.Try))
  final=operation.finalbody;preserve=final[0];self.assertIn('E.preserve',ast.unparse(preserve))
  cleanup=next(n for n in final if isinstance(n,ast.Try)and 'owner.cleanup()'in ast.unparse(n));guard=next(n for n in final if isinstance(n,ast.If)and 'PAIR_PASSED_PENDING_EXTERNAL_CLEANUP'in ast.unparse(n))
  e_ns=dict(__name__='MODEL_FISH_EXPORT',__file__=str(HERE/'MODEL-E.py'));exec(compile(new[P.PREFIX+'public_evidence.py'],e_ns['__file__'],'exec'),e_ns);e=SimpleNamespace(**e_ns)
  expected=dict(source='a'*40,ref='refs/heads/codex/MODEL',source_map_sha256='b'*64,run='123',attempt=1,job='pair',nonce='c'*32)
  for refused in(False,True):
   output=self.area/('owner-refused'if refused else'owner-held');inner=output/'volume/work/fish02-native';inner.mkdir(parents=True,mode=0o700);(inner/'report.json').write_bytes(e.encode(dict(expected,status='HOLD',Root_acceptance=None,hardware='NOT RUN',release='NOT ADMITTED')));(inner/'cleanup.json').write_text('{}')
   if refused:(inner/'report.json').chmod(0o666)
   events=[]
   def cleanup_model():
    events.append('cleanup');self.assertEqual((output/'evidence/report.json').exists(),not refused);(inner/'report.json').unlink();return dict(errors=[],owned_storage_absent=True)
   report=dict(status='HOLD');tree=ast.Module(body=[ast.Try(body=[ast.Raise(exc=ast.Call(func=ast.Name(id='ValueError',ctx=ast.Load()),args=[ast.Constant(value='MODEL held payload')],keywords=[]),cause=None)],handlers=operation.handlers,orelse=[],finalbody=[preserve,cleanup,guard])],type_ignores=[]);ast.fix_missing_locations(tree)
   exec(compile(tree,'MODEL-actual-finally','exec'),dict(E=e,report=report,a=SimpleNamespace(output=output,source_map_sha256=expected['source_map_sha256'],runner_uid=os.getuid()),actual=dict(source=expected['source'],ref=expected['ref'],nonce=expected['nonce']),os=SimpleNamespace(environ=dict(GITHUB_RUN_ID='123',GITHUB_JOB='pair')),owner=SimpleNamespace(cleanup=cleanup_model)))
   self.assertEqual(events,['cleanup']);self.assertEqual(report['status'],'HOLD');self.assertFalse(report['inner_public_evidence']['accepting']);self.assertEqual(report['inner_public_evidence']['status'],'REFUSED'if refused else'EXPORTED')

 def test_strict_public_511_exports_512_never_read_hold_and_budget_preserved(self):
  old,new=self.source();e=SimpleNamespace();ns=dict(__name__='MODEL_export',__file__=str(HERE/'MODEL-E.py'));exec(compile(new[P.PREFIX+'public_evidence.py'],ns['__file__'],'exec'),ns);e=SimpleNamespace(**ns)
  self.assertEqual(len(e.PUBLIC_LEAVES),1582);self.assertEqual(e.MAX_BYTES,16*1024**2);self.assertEqual(len(e.PUBLIC_LEAVES)+1,1583)
  inner=self.area/'owner/volume/work/fish02-native';inner.mkdir(parents=True,mode=0o700);public=inner.parents[2]/'evidence';(inner/'commands').mkdir(mode=0o700)
  expected=dict(source='a'*40,ref='refs/heads/codex/MODEL',source_map_sha256='b'*64,run='123',attempt=1,job='pair',nonce='c'*32)
  report=dict(expected,status='HOLD',Root_acceptance=None,hardware='NOT RUN',release='NOT ADMITTED');(inner/'report.json').write_bytes(e.encode(report));(inner/'cleanup.json').write_text('{}')
  for label in('159','160','511','512'):(inner/'commands'/f'{label}.stdout').write_text('MODEL_PUBLIC'if label!='512'else'MODEL_NEVER_READ')
  r=e.export(inner,public,expected,os.getuid());self.assertFalse(r['accepting']);self.assertEqual(r['payload_status'],'HOLD');self.assertTrue((public/'commands/511.stdout').is_file());self.assertFalse((public/'commands/512.stdout').exists())
  manifest=json.loads((public/'inner-public-manifest.json').read_bytes());self.assertFalse(manifest['private_trees_read']);self.assertFalse(manifest['truncation'])

if __name__=='__main__':
 if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:raise SystemExit('Use python -I -B unoptimized')
 unittest.main(verbosity=2)
