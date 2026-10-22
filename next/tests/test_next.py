# SPDX-License-Identifier: MIT
import copy,hashlib,importlib.util,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];I=ROOT/'latest/implementation';sys.path.insert(0,str(I))
import latest_plan as P,latest_setup as S,next_inputs as N,next_workflow as W,latest_run as RUN

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
class Next(unittest.TestCase):
 def baseline(self):return dict(r.split()for r in(I/'expected606.lock').read_text().splitlines())
 def test_all32_complete_transactions_65graphs_33aux_601protected(self):
  base=self.baseline();events=P.transitions(base);self.assertEqual((len(events),P.GRAPHS,P.AUXILIARY),(32,65,33));self.assertEqual(events[-1]['after'],base);self.assertEqual(P.product('apps')[3],'0.1.0-10');self.assertEqual(P.product('welcome')[3],'0.1.0-8');self.assertEqual(P.product('setup')[3],'0.1.0-6');self.assertEqual([e['phase']for e in events if e['role']=='setup'],['upgrade-setup','same-version-setup','rollback-setup','forward-setup','remove-setup','reinstall-setup','restore-original-setup']);self.assertEqual([r['name']for r in P.physical_domain(dict(packages=[dict(name=n,version=v)for n,v in base.items()])).values()].count(P.RUNTIME),1)
  self.assertEqual(len(P.physical_domain(dict(packages=[dict(name=n,version=v)for n,v in base.items()]))),601)
  for e in events:self.assertEqual({n:v for n,v in e['before'].items()if n!=e['name']},{n:v for n,v in e['after'].items()if n!=e['name']})
  self.assertEqual(P.BOUNDS,dict(consumer=4200,owner=6600,component=2400,transaction=90,fixture=100,real_module_suite=240,cleanup=60))
 def test_changed_baseline_or_unknown_role_refuses(self):
  for key,v in((P.RUNTIME,'foreign'),('cachy-asahi-setup','0.1.0-6'),('cachy-asahi-apps','0.1.0-10'),('foreign','0.1.0')):
   row=self.baseline();row[key]=v
   with self.assertRaises(ValueError):P.transitions(row)
  with self.assertRaises(ValueError):P.product('unknown')
 def test_exact_inputs_and_null_qualification_before_any_actor(self):
  p=N.profile();self.assertIsNotNone(p['apps10_current606']);self.assertEqual(N.qualification()['record_source'],'180f3ad1440cd82b16b7b944e86b0ba11a1b238d');self.assertEqual(N.ARCHIVES['welcome8'][2:],(40400,'1cbb8f5f9fd5f072ba2974837cf10dc7e90edbd236cbf3a34916cd0af3d4b240'))
  empty=copy.deepcopy(p);empty['apps10_current606']=None
  with patch.object(N,'profile',return_value=empty),patch('subprocess.run',side_effect=AssertionError('NO ACTOR/GIT')),self.assertRaisesRegex(ValueError,'NULL Apps10'):N.inspect({},None)
  bad=copy.deepcopy(p);bad['profiles']['welcome8']['archive']['bytes']=40332
  with patch.object(N.json,'loads',return_value=bad),self.assertRaises(ValueError):N.profile()
 def test_both_actual_workflow_argv_routes_require_every_new_packet(self):
  import shlex
  paths=W.WF,W.ALIAS
  for name in paths:
   text=(ROOT/name).read_text();W.order(text)
   for line in text.splitlines():
    if 'latest_run.py'not in line or '--apps-packet'not in line:continue
    argv=shlex.split(line.strip().removesuffix('\\'));at=next(i for i,v in enumerate(argv)if v.endswith('/latest/implementation/latest_run.py'));argv=argv[at+1:]
    def boundary(packets,*,apps8_packet,extra_packets):
     self.assertEqual(set(packets),{'apps','doctor','ksm','welcome','boot'});self.assertEqual(set(extra_packets),set(N.SOURCES));self.assertTrue(all(str(extra_packets[r]).endswith('latest607-next-'+r+'-inputs')for r in extra_packets));raise RuntimeError('OWNED_INERT_INPUT_BOUNDARY')
    with patch.object(RUN.G,'verify',return_value={}),patch.object(RUN.G,'authorize',return_value={}),patch.object(RUN.G,'public_checkouts',side_effect=boundary),self.assertRaisesRegex(RuntimeError,'OWNED_INERT'):RUN.main(argv)
   self.assertEqual((ROOT/paths[0]).read_bytes(),(ROOT/paths[1]).read_bytes())
 def test_whole240_actual_historical_real_receipt_codec_and_refusals(self):
  C=load('_next_test_whole240',ROOT/'next/setup240/scripts/ci/setup6-real-modules/contract.py');C.verify_source(ROOT/'next/setup240');historical=json.loads((ROOT/'next/fixtures/accepted-real240.json').read_bytes());C.validate_real(historical);nonce='f'*32;raw=(json.dumps(historical,sort_keys=True)+'\n').encode();rows=[]
  for phase,work in P.REAL_PHASES.items():rows.append(dict(phase=phase,workspace='setup6-real-'+work,nonce=nonce,receipt=historical,source='WHOLE_UNCHANGED_SETUP240_INSTALLED_AND_REAL_RECOVERY',ordinary_retirement=True,process=dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True),stdout=N.pin(raw),stderr=N.pin(b'')))
  # Historical receipt + explicitly synthetic process envelope is DATA only, never native acceptance.
  self.assertEqual(S.validate(rows,nonce,C.validate_real),rows)
  for key,v in(('workspace','foreign'),('nonce','0'*32),('ordinary_retirement',False)):
   bad=copy.deepcopy(rows);bad[0][key]=v
   with self.assertRaises(ValueError):S.validate(bad,nonce,C.validate_real)
  bad=copy.deepcopy(rows);bad[0]['stdout']=N.pin(b'changed')
  with self.assertRaises(ValueError):S.validate(bad,nonce,C.validate_real)
  bad=copy.deepcopy(rows);bad[0]['process']['group_retired']=False
  with self.assertRaises(ValueError):S.validate(bad,nonce,C.validate_real)
 def test_actual_emitted_native_support_namespace_full240_and_real_entry(self):
  import latest_guard as G,latest_owner as O
  base=ROOT/'historical/boot391';g=G.original();_,_,_,_,bridge,_=g.original_context()
  with tempfile.TemporaryDirectory(prefix='next607-owned-emission-')as td:
   runner,_=bridge.emit_runner(base/'held606',Path(td)/'runner');ledger=O.emit_runner(ROOT,base,runner)
   selected={k:v for k,v in ledger['support_files'].items()if k.startswith('setup240/')};self.assertEqual(len(selected),240)
   for n,w in selected.items():self.assertEqual(N.pin((runner/n).read_bytes()),w)
   for name in('ordinary_entry.py','native_api.py','native_contract.py','accepted_inputs.py'):self.assertEqual((runner/'real606'/name).read_bytes(),(ROOT/'next/ordinary'/name).read_bytes())
   self.assertIn('timeout=4200',O.owner(g.original_context()[3].owner(base/'held606')))
   saved,paths=dict(sys.modules),sys.path[:]
   try:
    for n in('native_api','native_contract','accepted_inputs'):sys.modules.pop(n,None)
    sys.path.insert(0,str(runner/'real606'));m=load('_next_emitted_actual_ordinary_entry',runner/'real606/ordinary_entry.py');self.assertTrue(callable(m.main));self.assertEqual(Path(m.C.__file__),runner/'real606/native_contract.py')
   finally:
    sys.path[:]=paths
    for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
    sys.modules.update(saved)
 def test_actual_setup6_isolated_cli_preview_no_home_writes(self):
  import subprocess,shutil
  source=ROOT/'next/setup240';helper=source/'packages/settings/cachy-asahi-setup/cachy-asahi-setup'
  with tempfile.TemporaryDirectory(prefix='next607-readonly-setup-')as td:
   root=Path(td);home=root/'home';home.mkdir(mode=0o700);templates=root/'templates/fish-bang-bang';templates.mkdir(parents=True);shutil.copyfile(source/'packages/shells/cachy-asahi-fish-bang-bang/opt-in.fish',templates/'opt-in.fish')
   p=subprocess.run([sys.executable,'-I','-B',str(helper),'--help'],capture_output=True,timeout=5);self.assertEqual(p.returncode,0)
   for operation in('activate','remove','recover'):
    argv=[sys.executable,'-I','-B',str(helper),operation,'--home',str(home),'--template-root',str(templates.parent)]
    if operation!='recover':argv+=['--components','fish-bang-bang']
    p=subprocess.run(argv,capture_output=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr);v=json.loads(p.stdout);self.assertEqual((v['mode'],v['operation']),('preview',operation));self.assertEqual(list(home.rglob('*')),[])
 def test_real_suite_entry_source_and_original_clock_security(self):
  src=(ROOT/'next/ordinary/ordinary_entry.py').read_text();self.assertIn("source=Path('/runner/setup240');entry=source/'scripts/ci/setup6-real-modules/installed.py'",src);self.assertIn('CACHY_SETUP6_REAL_USER',src);self.assertIn('native_scope',src)
  data=json.loads((I/'next-setup-source.json').read_bytes());self.assertEqual(len(data['copied_setup240']),240)
  for n,w in data['copied_ordinary'].items():self.assertEqual(N.pin((ROOT/'next/ordinary'/n).read_bytes()),w)
  self.assertEqual(len(P.REAL_PHASES),4);source=(I/'latest_component.py').read_text();self.assertIn('after_fixture==current',source);self.assertIn('g[\'verify_signature\']',source);self.assertIn('setup_suites.run(phase)',source)
if __name__=='__main__':unittest.main(verbosity=2)
