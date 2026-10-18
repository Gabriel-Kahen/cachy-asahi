#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source controls and optional original packet data; never accepted repair fixtures."""
import argparse,ast,contextlib,copy,hashlib,importlib.util,io,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import derive as D
import prepare as P
import source_only as S
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
PACKET=None
if '--local-packet' in sys.argv:
 n=sys.argv.index('--local-packet');PACKET=Path(sys.argv[n+1]).absolute();del sys.argv[n:n+2]
load=S.load
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='apps7-repair-control-');self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
 def test_default_public_policy_refuses_before_actors(self):
  C=load('apps7_null_contract',HERE/'contract.py');v=json.loads((HERE/'input-policy.json').read_bytes())
  self.assertEqual(v['status'],'UNBOUND');self.assertIsNone(v['packet_source']);self.assertIsNone(v['packet_index']);self.assertEqual(v['cases'],['repair-bytes','repair-missing'])
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')),self.assertRaisesRegex(ValueError,'UNBOUND'):C.source(ROOT)
 def test_whole_original_baseline_and_recipe_bytes_held(self):
  rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];self.assertEqual(len(rows),130)
  for n,row in rows.items():self.assertEqual(P.pin((ROOT/n).read_bytes()),row,n)
 def test_declared_derivations_conserve_every_other_source_byte(self):
  for name in json.loads((HERE/'derivation-pins.json').read_bytes())['files']:
   raw,ledger=D.derive(ROOT,name);self.assertTrue(ledger);ast.parse(raw)
   if name in ('closure','transaction','inspection'):self.assertIn('derive.run(', (HERE/(name+'.py')).read_text())
  with patch.object(D,'pin',return_value={}):
   with self.assertRaisesRegex(ValueError,'whole original'):D.derive(ROOT,'transaction')
 def test_actual_composed_inspection_backend_and_closure_loader(self):
  I=load('apps7_composed_inspection',HERE/'inspection.py');T=I.backend();seen=[];original=T.load
  def capture(name,path):
   module=original(name,path);seen.append(path);self.assertEqual(path,HERE/'closure.py');self.assertEqual(module.VERSIONS['cachy-asahi-apps'],'0.1.0-7');return module
  args=types.SimpleNamespace(full574_policy='/nonexistent-apps7-policy',full574_policy_sha256='0'*64,full574_lease='/nonexistent-apps7-lease',full574_lease_sha256='0'*64)
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actor')),patch.object(T,'load',side_effect=capture):
   with self.assertRaises(FileNotFoundError):T.closure_for(args,None)
  self.assertEqual(seen,[HERE/'closure.py'])
 def test_inspection_supervisor_reenters_lane_with_failure_only_probe(self):
  I=load('apps7_worker_inspection',HERE/'inspection.py');T=I.backend();calls=[]
  def supervise(argv,**kwargs):
   calls.append((argv,kwargs));return dict(termination=None,direct_child_reaped=True,group_kill_sent=True,returncode=1,stdout=b'{"status":"FAIL","commit_started":false,"packages_committed":false,"transaction":"NOT_RUN"}')
  argv=['inspect-reinstall']
  for option in ('workspace','ownership-sha256','apps-source','apps-provenance-sha256','repository-source','full574-policy','full574-policy-sha256','full574-lease','full574-lease-sha256','release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','plan','plan-sha256'):argv+=['--'+option,str(self.work)]
  argv+=['--applications','apps']
  with patch.object(I,'backend',return_value=T),patch.object(T,'root_guard',return_value=(self.work,self.work,{})),patch.object(T,'execution_seconds',return_value=600),patch.object(T.SUP,'run',side_effect=supervise),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(I.main(argv),1)
  self.assertEqual(Path(calls[0][0][3]),HERE/'inspection.py');self.assertEqual(calls[0][0][-1],'--worker');self.assertEqual(calls[0][1]['timeout'],600);self.assertEqual(calls[0][1]['output_limit'],512*1024)
 def test_transaction_supervisor_reenters_lane_with_failure_only_probe(self):
  T=load('apps7_worker_transaction',HERE/'transaction.py');calls=[]
  def supervise(argv,**kwargs):
   calls.append((argv,kwargs));return dict(termination=None,direct_child_reaped=True,group_kill_sent=True,returncode=1,stdout=b'{"status":"FAIL"}')
  argv=['transaction.py','apply','--workspace',str(self.work),'--apps-source',str(self.work),'--apps-provenance-sha256','0'*64,'--repository-source',str(self.work),'--confirm-disposable-transaction']
  with patch.object(sys,'argv',argv),patch.object(T,'root_guard',return_value=(self.work,self.work,{})),patch.object(T,'execution_seconds',return_value=600),patch.object(T.SUP,'run',side_effect=supervise),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(T.main(),1)
  self.assertEqual(Path(calls[0][0][3]),HERE/'transaction.py');self.assertEqual(calls[0][0][-1],'--worker');self.assertEqual(calls[0][1]['timeout'],600);self.assertEqual(calls[0][1]['output_limit'],1024**2)
 def test_unchanged_normal_owner_derivation_and_all_limits(self):
  C=load('contract',HERE/'contract.py')
  with patch.dict(sys.modules,{'contract':C}):J=load('apps7_derived_owner',HERE/'job.py')
  source=(ROOT/'scripts/ci/apps-full574-native/job.py').read_text();parts=J.derived(source)
  self.assertEqual(set(parts),{'run','retain','actor'});self.assertIn('3000 if role',parts['actor']);self.assertIn("'--memory=4g'",parts['actor']);self.assertIn("'--cpus=2'",parts['actor']);self.assertIn('SETFCAP',parts['actor']);self.assertNotIn("api,'interruption'",parts['run'])
  closure=load('apps7_real_source_closure',HERE/'closure.py');self.assertEqual(closure.EXECUTION_BUDGET,dict(backend_seconds=600,caller_seconds=610))
  text=(HERE/'lifecycle.py').read_text();self.assertIn("H.backend('inspect',workspace,owner),expected=1",text)
  for label in ('wrong-plan-sha','unselected-damage','foreign-alpm-lock'):self.assertIn(label,text)
 def test_emitter_and_default_workflow_source(self):
  out=self.work/'emitted';result=P.emit(ROOT,out);self.assertEqual(result['status'],'SOURCE_ONLY_UNBOUND_APPS7_NATIVE574_REPAIR')
  self.assertEqual((out/P.WF).read_bytes(),(out/'.github/workflows/native-arm-build.yml').read_bytes())
  self.assertEqual((out/'scripts/apps/transaction.py').read_bytes(),(ROOT/'scripts/apps/transaction.py').read_bytes())
  text=(out/P.WF).read_text();self.assertIn(P.NEW,text);self.assertEqual(text.count('--case "$REPAIR_CASE" --source "$GITHUB_WORKSPACE"'),5)
  for limit in ('2300s','3550s','650s'):self.assertIn(limit,text)
  v=json.loads((out/P.NEW/'input-policy.json').read_bytes());self.assertIsNone(v['packet_source']);self.assertIsNone(v['packet_index'])

if PACKET is not None:
 class ActualData(unittest.TestCase):
  def setUp(self):
   self.tmp=tempfile.TemporaryDirectory(prefix='apps7-retained-data-');self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
  def facade(self,root):
   original=load('original_bounded_data',ROOT/'scripts/ci/management-tools-generic16k/contract.py');C=types.SimpleNamespace(**vars(original));C.policy=lambda:dict(packet_index=dict(path='index.json',**P.pin((root/'index.json').read_bytes())));factory=load('apps7_actual_packet',HERE/'packet.py');return factory.module(C,ROOT)
  def test_actual_four_pairs_complete_sources_and_payload(self):
   with patch.object(subprocess,'Popen',side_effect=AssertionError('no process')):v=S.inspect(ROOT,PACKET)
   self.assertEqual(v['status'],'LOCAL_SOURCE_ONLY_NOT_PUBLIC');self.assertEqual(v['payload_files'],25);self.assertIsNone(v['public_carrier']);self.assertEqual(v['packages']['cachy-asahi-apps'],'0.1.0-7')
  def test_unreferenced_extra_refused(self):
   root=self.work/'packet';shutil.copytree(PACKET,root);(root/'foreign').write_bytes(b'no')
   with self.assertRaisesRegex(ValueError,'reference closure'):self.facade(root).packet(root)
  def test_old_apps6_identity_refused(self):
   root=self.work/'packet';shutil.copytree(PACKET,root);v=json.loads((root/'index.json').read_bytes());v['packages']['cachy-asahi-apps']['version']='0.1.0-6';(root/'index.json').write_bytes(P.encoded(v))
   with self.assertRaisesRegex(ValueError,'exact native pair'):self.facade(root).packet(root)
  def test_original_native_root_authority_cannot_be_rewritten(self):
   root=self.work/'packet';shutil.copytree(PACKET,root);v=json.loads((root/'index.json').read_bytes());name=v['packages']['cachy-asahi-apps']['decision']['path'];(root/name).write_bytes(b'{"status":"PASS_INVENTED"}');new=dict(path=name,**P.pin((root/name).read_bytes()))
   def refs(node):
    if type(node)is dict:
     if set(node)=={'path','bytes','sha256'} and node['path']==name:node.update(new)
     else:
      for x in node.values():refs(x)
    elif type(node)is list:
     for x in node:refs(x)
   refs(v);(root/'index.json').write_bytes(P.encoded(v))
   with self.assertRaisesRegex(ValueError,'original Apps7 native Root'):self.facade(root).packet(root)
if __name__=='__main__':unittest.main(verbosity=2)
