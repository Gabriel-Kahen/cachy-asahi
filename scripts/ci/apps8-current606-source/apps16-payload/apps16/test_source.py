# SPDX-License-Identifier: MIT
"""Pure Apps16 finite source/protocol controls; no native actors or acceptance."""
import copy,importlib.util,json,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;WORK=ROOT/'copyworker/scripts/ci/current606-apps7-copy';LANE=ROOT/'scripts/ci/current606-apps7-closed-owner'
sys.path[:0]=[str(HERE),str(WORK),str(ROOT/'copyworker/held-copy/scripts/update'),str(ROOT/'copyworker/held-copy/scripts/apps')]
import source,packet
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
C=load('contract',WORK/'contract.py');G=load('guard',WORK/'guard.py');L=load('lifecycle',WORK/'lifecycle.py');P=load('plan',WORK/'plan.py')
class Controls(unittest.TestCase):
 def test_whole380_source_guard_and_exact_self_emission(self):
  value=source.verify();self.assertEqual(value['parent_files'],380);self.assertIsNone(value['actual']);self.assertEqual(value['parent389']['source'],'97666b742d1b29e469e6de171da6e7a0d15c18c7');self.assertEqual(value['parent389']['files'],389)
  with tempfile.TemporaryDirectory(prefix='apps16-source-')as tmp:
   out=Path(tmp)/'source';source.emit(out);self.assertEqual(source.rows(out),source.rows(ROOT))
   r=subprocess.run([sys.executable,'-I','-B',str(out/'apps16/entry.py'),'--source-only'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr.decode())
 def test_unknown_pair_carrier_refuses_before_external_or_output(self):
  profile=json.loads((HERE/'carrier-profile.json').read_bytes())
  if profile['source']is not None:
   self.assertEqual(packet.policy(),profile);self.assertEqual(C.APPS16_PAIR,profile['archive']);return
  self.assertTrue(all(profile[k]is None for k in('source','ref','publication','git_authorization','files','archives','native_source','native_run','acceptance','archive')));self.assertIsNone(C.APPS16_PAIR)
  with patch.object(packet,'module',side_effect=AssertionError('NO_ACTOR_API_GIT'))as external,self.assertRaisesRegex(ValueError,'NULL'):packet.inspect(Path('/absent'))
  external.assert_not_called()
  forged=dict(profile,source='0'*40,ref='codex/false',publication={},git_authorization={},files={},archives=[],native_source=profile['expected_native_source'],native_run=profile['expected_native_run'],acceptance={},archive={})
  with patch.object(packet.json,'loads',return_value=forged),self.assertRaisesRegex(ValueError,'94'):packet.policy()
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp)/'refused';r=subprocess.run([sys.executable,'-I','-B',str(HERE/'entry.py'),'--require-selection','--output',str(out)],capture_output=True,timeout=10);self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL',r.stderr);self.assertFalse(out.exists())
 def test_complete_eight_phase_loop_seven_transactions_bothhomes_and_original_restoration(self):
  expected={f'held{i}':'1'for i in range(605)}|{L.NAME:'0.1.0-6'};state=dict(expected);tx=[];reads=[];fixtures=[];source_reads=[];products={v:dict(version=v)for v in('0.1.0-6','0.1.0-7','0.1.0-16')}
  def observe():reads.append(1);return dict(inventory=dict(state),observation=dict(nodes={}),physical={},capabilities={})
  def transact(phase,before,product):
   self.assertEqual(before,state);tx.append(phase)
   if product is None:state.pop(L.NAME)
   else:state[L.NAME]=product['version']
   return dict(direct_child_reaped=True,group_retired=True,returncode=0)
  def fixture(phase,version,product):fixtures.append(phase);return dict(homes={h:dict(CLI=2,inventory_count=606,installed_controls=15 if version in('0.1.0-7','0.1.0-16')else 0)for h in('fresh','existing')},zero_capabilities=True,NNP=1)
  def readback(before,after,**kw):G.inventory(after['inventory'],expected,kw['version']);return dict(count=len(state),selected_version=kw['version'])
  with patch.object(L,'operands',return_value=products),patch.object(L,'verify_readback',side_effect=readback):v=L.exercise(expected=expected,original6=products['0.1.0-6'],new7=products['0.1.0-7'],new16=products['0.1.0-16'],original606_manifest={},observe=observe,transact=transact,fixtures=fixture,source_unchanged=lambda:source_reads.append(1)or True)
  self.assertEqual([e['phase']for e in v['events']],['baseline6','upgrade7','upgrade16','same-version16','remove16','reinstall16','restore7','restore-original6']);self.assertEqual(v['counts'],[606,606,606,606,605,606,606,606]);self.assertEqual((len(tx),len(reads),len(fixtures),len(source_reads)),(7,16,7,8));self.assertEqual(state,expected)
 def test_only13_replaces8_runtime1_other605_scope_and_plan_refusals(self):
  pkg=dict(pkgname=['cachy-asahi-apps'],pkgver=['0.1.0-16'],arch=['any'],size=['1'],builddate=['1'],packager=['fixture']);fields={'INSTALLDATE':['1'],'REASON':['0'],'VALIDATION':['pgp']};self.assertEqual(P.fields(pkg,fields)['VERSION'],['0.1.0-16'])
  for version in('0.1.0-8','0.1.0-9','0.1.0-10','0.1.0-11','0.1.0-12','0.1.0-13','',None):
   with self.assertRaises(ValueError):P.fields(dict(pkg,pkgver=[version]),fields)
  node=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='0'*64);before=dict(complete=True,unsupported_counts={},nodes={'usr/bin/cachy-asahi-apps':dict(node),'usr/share/cachy-asahi/repository-runtime/scripts/client/client.py':dict(node),'home/alarm/.config/user':dict(node)},hardlink_groups={});after=copy.deepcopy(before);after['nodes']['usr/bin/cachy-asahi-apps']['sha256']='1'*64
  args=dict(old_paths=['usr/bin/cachy-asahi-apps'],new_paths=['usr/bin/cachy-asahi-apps'],old_database='var/lib/pacman/local/cachy-asahi-apps-0.1.0-6',new_database='var/lib/pacman/local/cachy-asahi-apps-0.1.0-16');self.assertTrue(G.target(before,after,**args))
  for version in('1','8','9','10','11','12','13','111','131','14/desc','6.0'):
   with self.assertRaises(ValueError):G.target(before,after,**dict(args,new_database='var/lib/pacman/local/cachy-asahi-apps-0.1.0-'+version))
  for name in list(before['nodes'])[1:]:
   bad=copy.deepcopy(after);bad['nodes'][name]['sha256']='2'*64
   with self.assertRaises(ValueError):G.target(before,bad,**args)
 def test_both_workflows_explicit_new_env_and_original_clocks(self):
  a=(ROOT/'.github/workflows/native-arm-build.yml').read_text();b=(ROOT/'.github/workflows/native-arm-current606-apps7-owned-copy.yml').read_text();self.assertEqual(a,b);profile=json.loads((HERE/'carrier-profile.json').read_bytes());self.assertIn(profile['source']or'APPS16_CARRIER_NULL_UNPUBLISHED',a);self.assertIn('APPS16_CARRIER="$APPS16_CARRIER" RUNNER_TEMP="$RUNNER_TEMP"',a)
  self.assertIn('COPY_SECONDS=600;WORKER_SECONDS=1800;CLEANUP_SECONDS=60',(WORK/'contract.py').read_text());self.assertIn('time.monotonic()+90',(WORK/'alpm_step.py').read_text());self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',(LANE/'owner.py').read_text());self.assertIn('timeout=min(70,budget.deadline-time.monotonic())',(WORK/'driver.py').read_text())
 def test_actual_owner_null_gate_and_exact_generated_checksum(self):
  r=subprocess.run([sys.executable,'-B',str(LANE/'owner.py'),'--source-preflight'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr.decode())
  r=subprocess.run([sys.executable,'-B',str(LANE/'owner.py'),'--require-selection'],capture_output=True,timeout=10)
  if json.loads((HERE/'carrier-profile.json').read_bytes())['source']is None:self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL',r.stderr)
  else:self.assertEqual(r.returncode,0,r.stderr.decode())
  text=(ROOT/'.github/workflows/native-arm-build.yml').read_text();lines=[s.strip()for s in text.splitlines()if'printf'in s and'expanded604-code/'+str(LANE.relative_to(ROOT))+'/owner.py' in s and'sha256sum --check'in s];self.assertEqual(len(lines),1)
  command=lines[0].replace('expanded604-code/',str(ROOT)+'/');r=subprocess.run(['bash','-c','set -euo pipefail\n'+command],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(r.stdout.count(b': OK\n'),2)
 def test_actual_both_owner_shells_forward_only_explicit_new_inputs(self):
  import os,textwrap
  for name in('native-arm-build.yml','native-arm-current606-apps7-owned-copy.yml'):
   text=(ROOT/'.github/workflows'/name).read_text();start=text.index('      - name: Required signed604 plus606 additions and restoration lifecycle\n');end=text.index('      - name:',start+8);command=textwrap.dedent(text[start:end].split('        run: |\n',1)[1])
   with tempfile.TemporaryDirectory(prefix='apps16-shell-')as tmp:
    root=Path(tmp);workspace=root/'workspace';runner=root/'runner';runner.mkdir();entry=workspace/'expanded604-code'/LANE.relative_to(ROOT)/'owner.py';entry.parent.mkdir(parents=True);entry.write_text('import json,os,sys\nprint(json.dumps(dict(env=dict(os.environ),argv=sys.argv[1:])))\n')
    env=dict(os.environ,GITHUB_WORKSPACE=str(workspace),RUNNER_TEMP=str(runner),APPS16_CARRIER=str(workspace/'apps16-native-pair'),GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',FDK_PAIR_OUTCOME='success',AUDIO_INPUTS_OUTCOME='success',IMPLEMENTATION_SOURCE='a'*40,FOREIGN_UNLISTED_INPUT='REFUSE')
    result=subprocess.run(['bash','-c',command],env=env,capture_output=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr.decode());actual=json.loads(result.stdout);self.assertEqual(actual['env']['APPS16_CARRIER'],env['APPS16_CARRIER']);self.assertEqual(actual['env']['RUNNER_TEMP'],env['RUNNER_TEMP']);self.assertNotIn('FOREIGN_UNLISTED_INPUT',actual['env']);self.assertNotIn('APPS8_CARRIER',actual['env']);self.assertEqual(actual['argv'][:2],['--apps-packet',str(workspace/'apps7-native-pairs')])
 def test_whole389_parent_missing_or_drift_refuses_before_ancestry_execution(self):
  proof=json.loads((HERE/'successor.json').read_bytes());self.assertEqual(len(proof['parent389']['files']),389)
  key='apps14/successor.json'
  for mode in('missing','drift','git'):
   bad=copy.deepcopy(proof)
   if mode=='missing':del bad['parent389']['before_bodies'][key]
   elif mode=='drift':bad['parent389']['before_bodies'][key]='eA=='
   else:bad['parent389']['git_authorization']['source']='0'*40
   with self.assertRaises((AssertionError,FileNotFoundError)):source.parent389(ROOT,bad)
 def test_exact13_recipe_carrier_and_issued_decision_no_old13_transfer(self):
  profile=json.loads((HERE/'carrier-profile.json').read_bytes())
  if profile['source']is None:
   with patch.object(packet,'module',side_effect=AssertionError('NO_ACTOR')),self.assertRaisesRegex(ValueError,'NULL'):packet.inspect(Path('/absent'))
   return
  common=load('_apps16_control_common',HERE/'contract_common.py');index={'status':'EXACT_ACCEPTED_APPS16_PAIR_INPUT_DATA_ONLY','actual':None,'source':profile['native_source'],'ref':'codex/apps16-pair-native-v1','run':profile['native_run'],'recipe_source':profile['recipe_source'],'GUI':'NOT_RUN','installed_current606':'NOT_RUN','hardware':'NOT_RUN','recipe_prefix':'recipe-source','archives':profile['archives'],'acceptance':'qualification/Root-component-acceptance.json','acceptance_archive_pointer':['accepted_pair','archive']}
  fact=common.index_check(index,profile['files'],profile['recipe_files'],profile['acceptance']);self.assertEqual(fact['version'],'0.1.0-16')
  for mode in('native','recipe','archive','decision'):
   value=copy.deepcopy(index);decision=copy.deepcopy(profile['acceptance'])
   if mode=='native':value['source']='6ff102c0883b5088ed93297eb47d14f99049ab68'
   elif mode=='recipe':value['recipe_source']='fa27f3294385884e8cb0d33720dc5e1e074178d4'
   elif mode=='archive':value['archives'][0]['path']=value['archives'][0]['path'].replace('0.1.0-16','0.1.0-13')
   else:decision['status']='ROOT_ACCEPTED_APPS13_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE'
   with self.assertRaises((ValueError,KeyError)):common.index_check(value,profile['files'],profile['recipe_files'],decision)
if __name__=='__main__':unittest.main(verbosity=2)
