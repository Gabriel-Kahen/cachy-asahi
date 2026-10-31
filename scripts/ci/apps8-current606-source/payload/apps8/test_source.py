#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite Apps8 source/plan/order/refusal controls; synthetic boundaries grant no native credit."""
import copy,hashlib,importlib.util,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(HERE));import source,packet,test_signer
WORK=ROOT/'copyworker/scripts/ci/current606-apps7-copy';LANE=ROOT/'scripts/ci/current606-apps7-closed-owner'
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
sys.path[:0]=[str(WORK),str(ROOT/'copyworker/held-copy/scripts/update'),str(ROOT/'copyworker/held-copy/scripts/apps')];C=load('contract',WORK/'contract.py');G=load('guard',WORK/'guard.py');physical=load('physical',WORK/'physical.py');L=load('lifecycle',WORK/'lifecycle.py');P=load('plan',WORK/'plan.py')
class Controls(unittest.TestCase):
 def test_whole_source_inverse_and_real_isolated_cli_self_emission(self):
  v=source.verify();self.assertEqual(v['parent_inverse_files'],348);self.assertIsNone(v['actual'])
  with tempfile.TemporaryDirectory(prefix='apps8-source-control-')as td:
   root=Path(td);out=root/'output';source.emit(out)
   expected={p.relative_to(ROOT).as_posix():p.read_bytes()for p in ROOT.rglob('*')if p.is_file()and '.git'not in p.relative_to(ROOT).parts}
   actual={p.relative_to(out).as_posix():p.read_bytes()for p in out.rglob('*')if p.is_file()};self.assertEqual(actual,expected)
   r=subprocess.run([sys.executable,'-I','-B',str(out/'apps8/entry.py'),'--source-only'],capture_output=True,text=True,timeout=20);self.assertEqual(r.returncode,0,r.stderr)
   wf=out/'.github/workflows/native-arm-build.yml';held=wf.read_bytes();wf.write_bytes(held+b'\n# drift\n')
   r=subprocess.run([sys.executable,'-I','-B',str(out/'apps8/entry.py'),'--output',str(root/'wf-refused')],capture_output=True,text=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse((root/'wf-refused').exists());wf.write_bytes(held)
   (out/'copyworker/scripts/ci/current606-apps7-copy/driver.py').write_bytes(b'changed\n')
   r=subprocess.run([sys.executable,'-I','-B',str(out/'apps8/entry.py'),'--output',str(root/'refused')],capture_output=True,text=True,timeout=20);self.assertNotEqual(r.returncode,0);self.assertFalse((root/'refused').exists())
   with self.assertRaises(AssertionError):source.emit(ROOT/'nested-refused')
 def test_entire_original_sign_body_with_complete_import_and_subprocess_bindings(self):
  signer=load('_source_shape_whole_test_signer',HERE/'test_signer.py');fpr='A'*40;calls=[]
  class Boundary:
   def run(self,argv,**kw):
    calls.append((argv,kw));self_check=kw['check']and kw['capture_output']and kw['timeout']==30
    if not self_check:raise ValueError('whole original subprocess contract')
    if '--detach-sign'in argv:Path(argv[argv.index('--output')+1]).write_bytes(b'owned synthetic signature')
   def check_output(self,argv,**kw):
    calls.append((argv,kw));assert kw['timeout']==30
    return ('fpr:::::::::'+fpr+':\n')if '--list-keys'in argv else b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC INERT\n'
  signer.subprocess=Boundary()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);inputs=root/'inputs';inputs.mkdir();archive=root/'package';archive.write_bytes(b'exact inert archive')
   self.assertEqual(signer.sign(inputs,root,[archive]),fpr);self.assertEqual((root/'test-signing').stat().st_mode&0o777,0o700);self.assertTrue((inputs/'TEST-public.asc').is_file());self.assertEqual(Path(str(archive)+'.sig').read_bytes(),b'owned synthetic signature');self.assertEqual(len(calls),4)
 def test_eight_phase_full_loop_with_seven_retired_transactions_and_all_fixtures(self):
  expected={f'held{i}':'1'for i in range(605)}|{L.NAME:'0.1.0-6'};state=dict(expected);events=[];fixtures=[];reads=[]
  products={v:dict(version=v)for v in('0.1.0-6','0.1.0-7','0.1.0-8')}
  def observe():reads.append(dict(state));return dict(inventory=dict(state),observation=dict(nodes={}),physical={},capabilities={})
  def transact(phase,before,product):
   self.assertEqual(before,state);events.append(phase)
   if product is None:state.pop(L.NAME)
   else:state[L.NAME]=product['version']
   return dict(direct_child_reaped=True,group_retired=True,returncode=0)
  def fixture(phase,version,product):
   fixtures.append((phase,version));return dict(homes={n:dict(CLI=2,inventory_count=606,installed_controls=15 if version in('0.1.0-7','0.1.0-8')else 0)for n in('fresh','existing')},zero_capabilities=True,NNP=1)
  def readback(before,after,**kw):G.inventory(after['inventory'],expected,kw['version']);return dict(count=len(state),selected_version=kw['version'])
  with patch.object(L,'operands',return_value=products),patch.object(L,'verify_readback',side_effect=readback):
   result=L.exercise(expected=expected,original6=products['0.1.0-6'],new7=products['0.1.0-7'],new8=products['0.1.0-8'],original606_manifest={},observe=observe,transact=transact,fixtures=fixture,source_unchanged=lambda:True)
  self.assertEqual([e['phase']for e in result['events']],[p for p,_ in L.PHASES]);self.assertEqual(len(events),7);self.assertEqual(len(fixtures),7);self.assertEqual(len(reads),16);self.assertEqual(state,expected);self.assertEqual(result['counts'],[606,606,606,606,605,606,606,606])
  with patch.object(L,'operands',return_value=products),patch.object(L,'verify_readback',side_effect=readback),self.assertRaises(ValueError):
   L.exercise(expected=expected,original6={},new7={},new8={},original606_manifest={},observe=observe,transact=lambda *a:dict(direct_child_reaped=True,group_retired=False,returncode=0),fixtures=fixture,source_unchanged=lambda:True)
 def test_new8_scope_preserves_all_other605_raw_database_user_and_runtime_nodes(self):
  node=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='0'*64)
  before=dict(complete=True,unsupported_counts={},nodes={'usr/bin/cachy-asahi-apps':dict(node),'var/lib/pacman/local/runtime-1/desc':dict(node),'home/alarm/.config/user':dict(node),'usr/share/cachy-asahi/repository-runtime/scripts/client/client.py':dict(node)},hardlink_groups={})
  after=copy.deepcopy(before);after['nodes']['usr/bin/cachy-asahi-apps']=dict(node,sha256='1'*64)
  args=dict(old_paths=['usr/bin/cachy-asahi-apps'],new_paths=['usr/bin/cachy-asahi-apps'],old_database='var/lib/pacman/local/cachy-asahi-apps-0.1.0-6',new_database='var/lib/pacman/local/cachy-asahi-apps-0.1.0-8')
  self.assertTrue(G.target(before,after,**args))
  for name in list(before['nodes'])[1:]:
   changed=copy.deepcopy(after);changed['nodes'][name]['sha256']='2'*64
   with self.subTest(name=name),self.assertRaises(ValueError):G.target(before,changed,**args)
  with self.assertRaises(ValueError):G.target(before,after,**dict(args,new_database='var/lib/pacman/local/cachy-asahi-apps-0.1.0-9'))
 def test_typed_real_archive_identity_and_unchanged_plan_local_fields(self):
  profile=json.loads((HERE/'carrier-profile.json').read_bytes());self.assertEqual(len(profile['files']),93);self.assertEqual(profile['archives'][0]['sha256'],packet.PAIR['sha256']);self.assertEqual(profile['acceptance']['accepted_pair']['archive'],packet.PAIR)
  pkg=dict(pkgname=['cachy-asahi-apps'],pkgver=['0.1.0-8'],arch=['any'],size=['1'],builddate=['1'],packager=['fixture'])
  fields={'INSTALLDATE':['1'],'REASON':['0'],'VALIDATION':['pgp']};new=P.fields(pkg,fields);self.assertEqual(new['VERSION'],['0.1.0-8']);self.assertEqual(new['VALIDATION'],['pgp'])
  for version in('0.1.0-9','',None):
   with self.subTest(version=version),self.assertRaises(ValueError):P.fields(dict(pkg,pkgver=[version]),fields)
 def test_actual_owner_authorize_before_original_timer_has_finite_input_deadline(self):
  old={k:sys.modules.get(k)for k in('contract','selection','runtime','builds')};paths=list(sys.path)
  try:
   for k in old:sys.modules.pop(k,None)
   sys.path.insert(0,str(LANE));owner=load('_source_shaped_apps8_owner',LANE/'owner.py')
   app=owner.Integration(ROOT,types.SimpleNamespace(),types.SimpleNamespace(),{},Path('/legacy-packet'))
   self.assertIsNone(app.deadline)
   with patch.object(owner.O,'authorize'),patch.object(owner.O,'module',return_value=packet),patch.object(owner.builds,'public_checkout'),patch.dict(os.environ,APPS8_CARRIER='/accepted-carrier'),patch.object(packet,'inspect',return_value={})as inspect:
    self.assertEqual(app.authorize(),{});self.assertGreater(inspect.call_args.kwargs['deadline'],__import__('time').monotonic())
  finally:
   sys.path[:]=paths
   for k,v in old.items():
    if v is None:sys.modules.pop(k,None)
    else:sys.modules[k]=v
 def test_original_runtime_security_bodies_and_clocks_byte_held(self):
  parent=json.loads((HERE/'parent348.json').read_bytes())
  for name in('copyworker/scripts/ci/current606-apps7-copy/worker.py','copyworker/scripts/ci/current606-apps7-copy/contract.py','copyworker/scripts/ci/current606-apps7-copy/physical.py','copyworker/held-apps/fixture_checks.py','copyworker/held-apps/fixture-apps/test_apps.py'):
   self.assertEqual(source.pin((ROOT/name).read_bytes()),parent['files'][name])
  text=(WORK/'contract.py').read_text();self.assertIn('COPY_SECONDS=600;WORKER_SECONDS=1800;CLEANUP_SECONDS=60',text)
  self.assertIn("timeout=min(70,budget.deadline-time.monotonic())",(WORK/'driver.py').read_text());self.assertIn('time.monotonic()+90',(WORK/'alpm_step.py').read_text())
  self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',(LANE/'owner.py').read_text())
 def test_null_carrier_refuses_before_actor_or_output(self):
  with patch.object(packet,'policy',side_effect=ValueError('Apps8 carrier NULL/unpublished')),patch.object(packet,'module')as module,self.assertRaises(ValueError):packet.inspect(Path('/absent-carrier'))
  module.assert_not_called()
 def test_actual_workflow_cache_order_and_all_shell_blocks(self):
  raw=(ROOT/'.github/workflows/native-arm-build.yml').read_text()
  labels=['Checkout exact original574 archive lock before native base','Prefill exact Doctor32/20/8/6 caches before unchanged legacy CLIs','Prefetch exact original26 native-base plus six extra574 bytes before original build','Seed complete exact248 inputs before unchanged native base','Build the fresh native base and original package pairs','Seed complete exact574 inputs before unchanged original producer','Prefetch and seed exact32 frozen574 bytes before unchanged producer']
  positions=[raw.index('      - name: '+n+'\n')for n in labels];self.assertEqual(positions,sorted(positions))
  self.assertIn('path: apps8-native-pair',raw);self.assertIn('APPS8_CARRIER:',raw);self.assertIn('apps8-retained-inputs/native248.json',raw);self.assertIn('apps8-retained-inputs/desktop574.json',raw)
  import re
  lines=[line.strip()for line in raw.splitlines()if line.strip().startswith("printf '%s  %s\\n'")and 'expanded604-code/'+str(LANE.relative_to(ROOT))+'/owner.py' in line];self.assertEqual(len(lines),1)
  stanza=lines[0].replace('expanded604-code/',str(ROOT)+'/');subprocess.run(['/bin/bash','--noprofile','--norc','-c',stanza],capture_output=True,text=True,check=True,timeout=10)
  for block in re.findall(r'^        run: \|\n((?:          .*\n|\n)+)',raw,re.M):subprocess.run(['/bin/bash','-n'],input='\n'.join(line[10:]for line in block.splitlines()),text=True,check=True)
if __name__=='__main__':unittest.main(verbosity=2)
