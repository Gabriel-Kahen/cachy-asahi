# SPDX-License-Identifier: MIT
import base64,copy,hashlib,importlib.util,json,sys,tempfile,types,unittest
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
  for phase,work in P.REAL_PHASES.items():rows.append(dict(phase=phase,workspace='setup6-real-'+work,nonce=nonce,receipt=historical,source='WHOLE_UNCHANGED_SETUP240_INSTALLED_AND_REAL_RECOVERY',ordinary_retirement=True,process=dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True),stdout=N.pin(raw),stdout_base64=base64.b64encode(raw).decode('ascii'),stderr=N.pin(b'')))
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
class InstalledCodec(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.C=load('_codec_full_original_setup240',ROOT/'next/setup240/scripts/ci/setup6-real-modules/contract.py');cls.C.verify_source(ROOT/'next/setup240')
 def receipt(self):
  value=json.loads((ROOT/'next/fixtures/accepted-real240.json').read_bytes());self.C.validate_real(value)
  # Deliberately nonlexical insertion order, with the complete real typed proof.
  return {k:value[k]for k in reversed(list(value))}
 def printed(self,value):
  import ast,contextlib,io
  text=(ROOT/'next/setup240/scripts/ci/setup6-real-modules/installed.py').read_text();tree=ast.parse(text);main=tree.body[-1];statement=main.body[-1]
  self.assertIsInstance(statement,ast.Expr);self.assertEqual(ast.get_source_segment(text,statement),'print(json.dumps(exercise(a.source.absolute(),a.output.absolute())))')
  output=io.StringIO()
  with contextlib.redirect_stdout(output):exec(compile(ast.Module(body=[statement],type_ignores=[]),'<whole-held-original-installed-final-print>','exec'),dict(json=json,exercise=lambda source,out:value,a=types.SimpleNamespace(source=Path('/source-only/exact240'),output=Path('/source-only/owned'))))
  return output.getvalue().encode()
 def rows(self,receipt=None,raw=None):
  value=self.receipt()if receipt is None else receipt;raw=self.printed(value)if raw is None else raw;nonce='e'*32
  rows=[dict(phase=phase,workspace='setup6-real-'+work,nonce=nonce,receipt=copy.deepcopy(value),source='WHOLE_UNCHANGED_SETUP240_INSTALLED_AND_REAL_RECOVERY',ordinary_retirement=True,process=dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True),stdout=N.pin(raw),stdout_base64=base64.b64encode(raw).decode('ascii'),stderr=N.pin(b''))for phase,work in P.REAL_PHASES.items()]
  return rows,nonce,raw
 def test_whole_original_unsorted_printer_old_failure_and_persisted_exact_new_join(self):
  import ast
  rows,nonce,raw=self.rows();self.assertNotEqual(N.pin(raw),N.pin((json.dumps(rows[0]['receipt'],sort_keys=True)+'\n').encode()))
  proof=json.loads((I/'installed-codec-successor.json').read_bytes());old=base64.b64decode(proof['before_bodies']['latest/implementation/latest_setup.py'],validate=True).decode();node=next(n for n in ast.parse(old).body if isinstance(n,ast.FunctionDef)and n.name=='validate');ns=dict(P=P,json=json,hashlib=hashlib);exec(compile(ast.Module(body=[node],type_ignores=[]),'<whole-old840-validate>','exec'),ns)
  oldrows=[{k:v for k,v in row.items()if k!='stdout_base64'}for row in rows]
  with self.assertRaisesRegex(ValueError,'printed receipt/stdout codec join'):ns['validate'](oldrows,nonce,self.C.validate_real)
  # Outer publication sorts every nested receipt; original stdout bytes survive.
  persisted=json.loads(json.dumps(rows,sort_keys=True));self.assertEqual(S.validate(persisted,nonce,self.C.validate_real),persisted)
  self.assertEqual(base64.b64decode(persisted[0]['stdout_base64'],validate=True),raw)
 def test_raw_drift_duplicate_nonfinite_codec_cap_oldrow_and_retirement_refusals(self):
  rows,nonce,raw=self.rows()
  for label,change in [('base64',lambda row:row.update(stdout_base64='!')),('encoded-cap',lambda row:row.update(stdout_base64='A'*(4*((128*1024+2)//3)+1))),('pin',lambda row:row.update(stdout=N.pin(b'wrong'))),('missing',lambda row:row.pop('stdout_base64')),('retirement',lambda row:row['process'].update(group_retired=False)),('receipt',lambda row:row['receipt'].update(status='FAIL'))]:
   bad=copy.deepcopy(rows);change(bad[0])
   with self.subTest(label=label),self.assertRaises(ValueError):S.validate(bad,nonce,self.C.validate_real)
  for label,data in [('decoded-cap',b' '*(128*1024+1)),('duplicate',b'{"x":1,"x":1}\n'),('nonfinite',b'{"x":NaN}\n'),('codec',b' '+raw),('typed',b'{"x":1}\n'),('trailing',raw+b'\n')]:
   bad=copy.deepcopy(rows);bad[0].update(stdout=N.pin(data),stdout_base64=base64.b64encode(data).decode('ascii'))
   with self.subTest(label=label),self.assertRaises(ValueError):S.validate(bad,nonce,self.C.validate_real)
 def test_whole_emitted_suite_run_records_raw_before_outer_sorted_serialization(self):
  import os,time
  receipt=self.receipt();raw=self.printed(receipt);calls=[]
  with tempfile.TemporaryDirectory(prefix='codec-four-private-workspaces-')as td:
   root=Path(td);tmp=root/'tmp';tmp.mkdir();out=root/'out';out.mkdir()
   obj=S.Suites.__new__(S.Suites);obj.account=types.SimpleNamespace(pw_uid=23001,pw_gid=23001);obj.deadline=time.monotonic()+240;obj.nonce='e'*32;obj.rows=[];obj.retained={};obj.context=dict(home=root/'public-keys');obj.SC=self.C;obj.scope=None;obj.users=lambda:calls.append('private-registry-boundary');obj.registry=lambda parent,value:dict(source_only_inert_registry=parent.name)
   obj.N=types.SimpleNamespace(decode=json.loads,pin=N.pin);obj.g=dict(C=types.SimpleNamespace(read=lambda path:json.loads(path.read_bytes()),encoded=lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()),OUT=out)
   def run(argv,**kwargs):
    calls.append((argv,kwargs));parent=Path(argv[-1]);work=parent/'work';work.mkdir();(work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    self.assertEqual(argv[:4],['/usr/bin/python3','-I','-B','/runner/real606/ordinary_entry.py']);self.assertEqual(kwargs['output_limit'],128*1024);self.assertLessEqual(kwargs['timeout'],240)
    return dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True,stdout=raw,stderr=b'')
   obj.supervised=types.SimpleNamespace(run=run);original=Path
   def path(value):return tmp if value=='/tmp'else original(value)
   with patch.object(S,'Path',side_effect=path),patch.object(S.os,'chown',side_effect=lambda *args:calls.append(('inert-chown-boundary',args))),patch.object(S,'ordinary_absent',side_effect=lambda uid:calls.append(('inert-process-boundary',uid))),patch.dict(S.os.environ,{'CACHY_ASAHI_EXPANDED604':'source-only-inert-container'}):
    for phase in P.REAL_PHASES:obj.run(phase)
   self.assertEqual(len(obj.retained),4);self.assertEqual(len(obj.rows),4)
   persisted=[json.loads((out/('latest607-setup-real-'+phase+'.json')).read_bytes())for phase in P.REAL_PHASES]
   self.assertEqual(S.validate(persisted,obj.nonce,self.C.validate_real),persisted)
   self.assertTrue(all(base64.b64decode(row['stdout_base64'],validate=True)==raw for row in persisted));self.assertEqual(len([x for x in calls if isinstance(x,tuple)and x[0]=='inert-chown-boundary']),4)
 def test_original_installed_printer_runtime_suite_bounds_and_parent_security_held(self):
  proof=json.loads((I/'installed-codec-successor.json').read_bytes());before=proof['before'];self.assertEqual(len(before),840)
  prefix='next/setup240/';actual={p.relative_to(ROOT).as_posix():N.pin(p.read_bytes())for p in(ROOT/'next/setup240').rglob('*')if p.is_file()};self.assertEqual(actual,{n:v for n,v in before.items()if n.startswith(prefix)});self.assertEqual(len(actual),240)
  for n in('next/ordinary/ordinary_entry.py','next/ordinary/native_api.py','latest/implementation/latest_component.py','latest/implementation/latest_validate.py','latest/implementation/latest_plan.py'):self.assertEqual(N.pin((ROOT/n).read_bytes()),before[n])
  self.assertEqual(P.BOUNDS,dict(consumer=4200,owner=6600,component=2400,transaction=90,fixture=100,real_module_suite=240,cleanup=60));self.assertEqual((P.GRAPHS,P.AUXILIARY),(65,33));self.assertEqual(len(P.REAL_PHASES),4)


if __name__=='__main__':unittest.main(verbosity=2)
