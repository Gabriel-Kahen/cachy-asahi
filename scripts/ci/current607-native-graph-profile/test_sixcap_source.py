# SPDX-License-Identifier: MIT
"""Inert actual-emitted routing and unchanged supervisor credential controls."""
import argparse,ast,copy,importlib.util,json,os,signal,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--parent',type=Path,required=True);args,rest=parser.parse_known_args();ROOT=args.source.absolute();PARENT=args.parent.absolute();I=ROOT/'latest/implementation';sys.path.insert(0,str(I));import latest_guard as G,latest_owner as O,latest_plan as P

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
C=load('_sixcap_actual_consumer_contract',ROOT/'historical/boot391/held606/held604/scripts/ci/expanded604-apps6-public-pairs/contract.py')
def profile():return dict(uid=0,gid=0,CapEff=0xdb,CapPrm=0xdb,CapBnd=0xdb,CapInh=0,CapAmb=0,NoNewPrivs=1)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='sixcap-exact-runner-');cls.runner=Path(cls.tmp.name)/'runner';g=G.original();_,_,_,_,bridge,_=g.original_context();runner,_=bridge.emit_runner(ROOT/'historical/boot391/held606',cls.runner);cls.ledger=O.emit_runner(ROOT,ROOT/'historical/boot391',runner)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def native(self,fixed):
  boot=self.runner/'boot607';A=C.load('_sixcap_emitted_native_inputs',boot/'accepted_inputs.py');N=C.scoped_load('_sixcap_emitted_native_contract',boot/'native_contract.py',{'accepted_inputs':A})
  if fixed:
   # Execute exactly the new emitted exercise statement, with its fixed absolute
   # runner prefix mapped only to this fresh owned source-shaped runner.
   text=(self.runner/'latest/latest_component.py').read_text();tree=ast.parse(text);fun=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='exercise');line=next(n for n in fun.body if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and n.value.func.attr=='scoped_load');statement=ast.get_source_segment(text,line);self.assertIn("Path('/runner/real606/native_api.py')",statement)
   def owned_path(value):self.assertEqual(value,'/runner/real606/native_api.py');return self.runner/'real606/native_api.py'
   sentinel=types.ModuleType('_unrelated_native_contract');prior=sys.modules.get('native_contract');sys.modules['native_contract']=sentinel
   try:exec(compile(statement,'<exact-emitted-sixcap-binding>','exec'),dict(C=C,N=N,Path=owned_path));self.assertIs(sys.modules['native_contract'],sentinel)
   finally:
    if prior is None:sys.modules.pop('native_contract',None)
    else:sys.modules['native_contract']=prior
  supervised=C.scoped_load('_sixcap_whole_original_supervised',self.runner/'boot607/copyworker/scripts/ci/current606-apps7-copy/supervised.py',{'contract':N});return N,supervised
 def test_actual_old_signal_uid_refusal_new_existing_api_route(self):
  N,S=self.native(False);state=((0,0,0),(0,0,0),(0,),profile())
  with patch.object(S,'_credentials',return_value=state),self.assertRaisesRegex(AttributeError,'capability_profile'):S._SignalOS(23001)
  N,S=self.native(True)
  with patch.object(S,'_credentials',return_value=state):self.assertEqual(S._SignalOS(23001).before,state)
  self.assertIs(N.capability_profile.__globals__['C'],N);self.assertEqual(N.capability_profile(profile()),profile())
 def test_exact_sixcap_foreign_worker_ordinary_nnp_and_credential_refusals(self):
  N,S=self.native(True)
  for k in profile():
   bad=profile();bad[k]=0x800400db if k.startswith('Cap')else 1 if k in('uid','gid')else 0
   with self.subTest(field=k),self.assertRaises(ValueError):N.capability_profile(bad)
  for mask in(0,0x400db,0x800400db,0xffffffffffffffff):
   bad=profile();bad.update(CapEff=mask,CapPrm=mask,CapBnd=mask)
   with self.subTest(mask=mask),self.assertRaises(ValueError):N.capability_profile(bad)
  with patch.object(S,'_credentials',return_value=((1,0,0),(0,0,0),(0,),profile())),self.assertRaises(ValueError):S._SignalOS(23001)
 def test_whole_signal_uid_group_restoration_success_and_error(self):
  N,S=self.native(True);current={'uid':0};base=((0,0,0),(0,0,0),(0,),profile());calls=[]
  fake=types.SimpleNamespace(geteuid=lambda:current['uid'],seteuid=lambda uid:(calls.append(('seteuid',uid)),current.update(uid=uid)),killpg=lambda group,sig:calls.append(('killpg',group,sig)))
  with patch.object(S,'_credentials',return_value=base),patch.object(S,'os',fake):
   actor=S._SignalOS(23001);actor.killpg(12345,signal.SIGTERM);self.assertEqual(calls,[('seteuid',23001),('killpg',12345,signal.SIGTERM),('seteuid',0)]);self.assertEqual(current['uid'],0)
   with self.assertRaises(ValueError):actor.killpg(54321,0)
   fake.killpg=lambda group,sig:(_ for _ in()).throw(ProcessLookupError())
   with self.assertRaises(ProcessLookupError):actor.killpg(12345,0)
   self.assertEqual(current['uid'],0)
   with patch.object(S,'_credentials',return_value=((0,0,0),(0,0,0),(99,),profile())),self.assertRaises(ValueError):actor.killpg(12345,0)
 def test_actual_emission_whole240_api_supervisor_body_and_clocks_held(self):
  self.assertEqual(sum(n.startswith('setup240/')for n in self.ledger['support_files']),240)
  for n in('native_api.py','native_contract.py','accepted_inputs.py','ordinary_entry.py'):self.assertEqual((self.runner/'real606'/n).read_bytes(),(PARENT/'next/ordinary'/n).read_bytes())
  for n in('supervised.py','contract.py'):
   relative='historical/boot391/copyworker/scripts/ci/current606-apps7-copy/'+n;self.assertEqual((ROOT/relative).read_bytes(),(PARENT/relative).read_bytes())
  self.assertEqual(P.BOUNDS,dict(consumer=4200,owner=6600,component=2400,transaction=90,fixture=100,real_module_suite=240,cleanup=60));self.assertEqual((ROOT/'latest/implementation/latest_setup.py').read_bytes(),(PARENT/'latest/implementation/latest_setup.py').read_bytes())
 def test_entire_parent_inverse_no_runtime_or_foreign_source_drift(self):
  v=json.loads((ROOT/'latest/implementation/sixcap-successor.json').read_bytes());old=v['before'];changed=set(v['before_bodies']);actual={p.relative_to(ROOT).as_posix():C.sha(p)for p in ROOT.rglob('*')if p.is_file()};self.assertEqual((len(old),len(actual),len(changed),len(v['added'])),(838,840,5,2));self.assertEqual(len(set(old)-changed),833)
  for n,w in old.items():
   if n not in changed:self.assertEqual(C.sha(ROOT/n),w['sha256'])
 def test_deterministic_emission_and_preoutput_parent_drift(self):
  B=load('_sixcap_source_emitter',D/'prepare.py')
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';v=B.emit_sixcap(PARENT,out);self.assertEqual(v['files'],B.files(ROOT));self.assertIsNone(v['actual']);bad=Path(td)/'refused';real=B.files
   def changed(root):
    result=real(root)
    if Path(root)==PARENT:result['latest/implementation/latest_component.py']=dict(bytes=1,sha256='0'*64)
    return result
   with patch.object(B,'files',side_effect=changed),self.assertRaisesRegex(ValueError,'genuine838'):B.emit_sixcap(PARENT,bad)
   self.assertFalse(bad.exists())
 def test_AUTHENTIC_failure_fact_pin_and_no_acceptance_transfer(self):
  B=load('_sixcap_facts_factory',D/'prepare.py');B.sixcap_inputs();facts=D/'sixcap840/parent-failure-facts.json';v=json.loads(facts.read_bytes());self.assertEqual((v['source'],v['run'],v['status']),('1e80073ffa9d50a8ac19fb67a8e9e58221a3985f',39775520949,'ROOT_AUTHENTIC_COMPLETE_TRANSPORT_OF_FAILED_SIX_TOOL_RUN'));self.assertEqual(v['lifecycle']['error'],"module '_latest_exact_native_contract' has no attribute 'capability_profile'");self.assertFalse(v['native_acceptance']);self.assertEqual(v['progress']['phase'],'upgrade-setup')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
