# SPDX-License-Identifier: MIT
"""Concrete Apps8 source/DATA integration controls; no native/container acceptance."""
import copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parents[1];ROOT=D.parent;I=D/'implementation';BASE=ROOT/'historical/boot391';sys.path.insert(0,str(I))
import latest_plan as P,latest_guard as G,latest_selection as S,latest_inputs as INPUTS,apps8_inputs as A,apps8_workflow as W
PACKET=Path(os.environ['LATEST607_APPS8_TEST_PACKET']).absolute()
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class Apps8(unittest.TestCase):
 def test_same25_transactions_original606_fourother_versions_and_all_clocks(self):
  before=json.loads((I/'apps8-successor.json').read_bytes());self.assertEqual(before['clocks'],dict(component=2400,consumer=4200,owner=6600,transaction=90,fixture=100,cleanup=60))
  self.assertEqual(P.PRODUCTS,(('apps','cachy-asahi-apps','0.1.0-6','0.1.0-8'),('doctor','cachy-asahi-doctor','0.1.0-1','0.2.0-1'),('ksm','cachy-asahi-ksmctl','0.1.0-1','0.1.0-2'),('welcome','cachy-asahi-welcome','0.1.0-4','0.1.0-7'),('boot','cachy-asahi-boot-report',None,'0.1.0-1')))
  base=dict(r.split()for r in(I/'expected606.lock').read_text().splitlines());events=P.transitions(base);self.assertEqual(len(events),25);self.assertEqual(events[-1]['after'],base);self.assertEqual(base['cachy-asahi-apps'],'0.1.0-6')
  self.assertTrue(all(e['after'][P.RUNTIME]=='0.1.0-1'for e in events));self.assertEqual([e['version']for e in events if e['role']=='apps'],['0.1.0-8','0.1.0-8',None,'0.1.0-8','0.1.0-6'])
 def test_separate_qualified113_packet_data_and_complete_two_archives(self):
  Q=module('_apps8_source_qualified_checker',I/'apps8_qualified_check.py');data=Q.check(PACKET);self.assertFalse(data['actual_authority']);self.assertEqual(data['current_composition'],'NOT_QUALIFIED');self.assertEqual(data['files'],113)
  checks=module('_apps8_original_package_checks',BASE/'held606/held-tools/scripts/checks/package_checks.py');L=module('_apps8_original_git_reader',I/'apps8_git.py');profile=json.loads((I/'apps8-carrier-profile.json').read_bytes())
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):
   fact=A.inspect_archives(PACKET/'apps8',checks,profile,L,time.monotonic()+30)
  self.assertEqual((fact['archive'].stat().st_size,fact['report']['sha256']),(23528,A.PAIR['sha256']));self.assertEqual(len(fact['payload']),8);self.assertNotIn('custody',fact)
  for field,value in(('arch',['x86_64']),('pkgver',['0.1.0-7'])):
   report=copy.deepcopy(fact['report']);report['metadata']['.PKGINFO'][field]=value
   with patch.object(checks,'package',return_value=report),self.assertRaises(ValueError):A.inspect_archives(PACKET/'apps8',checks,profile,L,time.monotonic()+30)
 def test_actual_qualified_data_and_raw_archives_route_to_typed_custody(self):
  checks=module('_apps8_custody_package_checks',BASE/'held606/held-tools/scripts/checks/package_checks.py');L=module('_apps8_custody_git_reader',I/'apps8_git.py');Q=module('_apps8_custody_checker',I/'apps8_qualified_check.py')
  if json.loads((I/'apps8-qualified-profile.json').read_bytes())['source']is None:
   with self.assertRaisesRegex(ValueError,'NULL'):A.inspect(PACKET,checks)
   return
  profile=A.qualified_profile()
  # Only the already separately proven external Git syscall boundary is inert.
  # Full113 freshbytes, Root input decision and both raw package parsers are real.
  proof=dict(source=profile['source'],ref=profile['ref'],files=113,blob_joins=113,tree='532b97ccd0763c6641fa8b6e29a9b3bee68444ca',status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY')
  def git(gitdir,deadline,*argv):
   self.assertEqual(gitdir,PACKET/'.git');self.assertEqual(argv,('rev-parse',profile['source']+':apps8'));return b'58e4aea8af2b8af57b67ec34a19b41baed60b253\n'
  def load(name,path):
   self.assertIn(path.name,('apps8_git.py','apps8_qualified_check.py'));return L if path.name=='apps8_git.py'else Q
  with patch.object(A,'load',side_effect=load),patch.object(L,'prove',return_value=proof)as proved,patch.object(L,'git',side_effect=git),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):
   result=A.inspect(PACKET,checks)
  proved.assert_called_once();self.assertEqual(A.validate_custody(result['custody']),result['custody']);self.assertEqual(result['archive'].stat().st_size,23528);self.assertEqual(result['authority'],'EXACT_ACCEPTED_NATIVE_PAIR_INPUT_ONLY')
  for path,value in((('carrier','tree'),'0'*40),(('carrier','blob_joins'),112),(('archive','sha256'),'0'*64),(('qualification','run'),39727987029),(('scope',),'COMBINED_ACCEPTED')):
   altered=copy.deepcopy(result['custody']);row=altered
   for key in path[:-1]:row=row[key]
   row[path[-1]]=value
   with self.assertRaises(ValueError):A.validate_custody(altered)
 def test_issued_full606_qualifier_input_only_and_null_publication_refuses(self):
  fact=A.qualification();self.assertEqual((fact['source'],fact['run'],fact['scope']),('5c3c2d0ce5b4f6c2672c9367b722170687c7de69',39735431322,'INPUT_QUALIFICATION_ONLY_NO_NEW_COMBINED_CREDIT'))
  value=json.loads((I/'input-policy.json').read_bytes());old=json.loads((BASE/'boot607/input-policy.json').read_bytes())['current606']
  if json.loads((I/'apps8-qualified-profile.json').read_bytes())['source']is None:
   with self.assertRaisesRegex(ValueError,'NULL'):S.authorize(value,old)
  else:self.assertEqual(S.authorize(value,old),value)
  for v in(value|{'apps8_current606':None},value|{'actual_run':39735431322}):
   with self.assertRaises(ValueError):S.authorize(v,old)
 def test_both_registered_and_named_actual_argv_reach_explicit_apps8_boundary(self):
  actual=(ROOT/'.github/workflows/native-arm-build.yml').read_text();self.assertEqual(actual,(ROOT/'.github/workflows/native-arm-current607-latest-tools.yml').read_text());W.order(actual)
  # Execute the actual CLI parser; only source/actor boundaries are inert.
  run=module('_apps8_actual_run_control',I/'latest_run.py');seen=[]
  class Stop(Exception):pass
  def checked(packets,*,apps8_packet):seen.append((packets,apps8_packet));raise Stop('BEFORE_ACTORS')
  with patch.object(run.G,'verify',return_value={'SOURCE_ONLY':True}),patch.object(run.G,'authorize',return_value={}),patch.object(run.G,'public_checkouts',side_effect=checked):
   for path in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current607-latest-tools.yml'):
    rows=W.order((ROOT/path).read_text());self.assertEqual(rows['apps8'],W.order(actual)['apps8'])
    import re
    for line in(ROOT/path).read_text().splitlines():
     if 'latest_run.py'in line and '--boot-packet'in line:
      operands=re.findall(r'--([a-z0-9]+)-packet "\$GITHUB_WORKSPACE/([^"\n]+)"',line);self.assertEqual(len(operands),6)
      argv=[v for role,name in operands for v in('--'+role+'-packet','/owned-workspace/'+name)]
      if '--native-inputs'in line:argv.insert(0,'--native-inputs')
      with self.assertRaises(Stop):run.main(argv)
   self.assertEqual(len(seen),4);self.assertTrue(all(len(p)==5 and a==Path('/owned-workspace/latest607-apps8-inputs')for p,a in seen))
   with self.assertRaisesRegex(ValueError,'one separate qualified Apps8'):run.main(['--native-inputs'])
 def test_checkout_and_argv_drift_refuses(self):
  raw=(ROOT/'.github/workflows/native-arm-build.yml').read_text()
  for value in(raw.replace(W.OPERAND,'',1),raw.replace('path: latest607-apps8-inputs','path: wrong',1),raw.replace('6dbfdbad6d9ec75a230ce366096206de933b1c28','0'*40,1)):
   # The final new carrier source replaces the historical979b checkout token.
   if value!=raw:
    with self.assertRaises(ValueError):W.order(value)
 def test_all15_original_controls_run_on_real_apps8_source_private_files(self):
  with tempfile.TemporaryDirectory(prefix='apps8-source-private-')as tmp:
   root=Path(tmp);actual=root/'usr/lib/cachy-asahi-apps';actual.mkdir(parents=True)
   for name in('apps.py','inventory.py'):shutil.copyfile(I/'apps8-source'/name,actual/name)
   fixture=BASE/'copyworker/held-apps';shutil.copyfile(fixture/'fixture-apps/helper-pins.json',actual/'helper-pins.json')
   recipe=BASE/'held606/held604/packages/tools/cachy-asahi-repository-runtime';runtime=root/'usr/share/cachy-asahi/repository-runtime'
   for rel,name in(('scripts/client/client.py','client.py'),('scripts/release/release.py','release.py'),('scripts/release/source_delivery.py','source_delivery.py')):
    path=runtime/rel;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(recipe/name,path)
   fixture_api=module('_apps8_whole_original15_fixture',fixture/'fixture_checks.py');old=sys.argv[:]
   try:
    original_popen=subprocess.Popen;calls=[]
    def bounded_python(argv,*args,**kwargs):
     self.assertEqual(argv[:4],[sys.executable,'-I','-B',str(actual/'apps.py')]);self.assertEqual(argv[4:7],['--repository-source',str(runtime),'inventory']);self.assertEqual(len(argv),11);self.assertEqual(argv[7],'--dbpath');self.assertEqual(argv[9],'--output');self.assertTrue(Path(argv[8]).is_relative_to(Path(tempfile.gettempdir())));self.assertTrue(Path(argv[10]).is_relative_to(Path(tempfile.gettempdir())));calls.append(argv[:]);return original_popen(argv,*args,**kwargs)
    with patch.object(subprocess,'Popen',side_effect=bounded_python):result=fixture_api.run_suite('apps',prefix=root,fixtures=fixture)
    self.assertEqual(len(calls),1)
   finally:sys.argv[:]=old
   self.assertEqual((result['tests'],result['failures'],result['errors'],result['skipped']),(15,0,0,0));self.assertTrue(result['installed_source'])
 def test_non_apps_component_capture_auxiliary_and_signature_bodies_held(self):
  import base64
  proof=json.loads((I/'apps8-successor.json').read_bytes());component=(I/'latest_component.py').read_text()
  for old,new in reversed(proof['edits']['latest/implementation/latest_component.py']):self.assertEqual(component.count(new),1);component=component.replace(new,old,1)
  self.assertEqual(component.encode(),base64.b64decode(proof['before_bodies']['latest/implementation/latest_component.py']));self.assertIn('deadline=time.monotonic()+2400',component);self.assertIn('for event in P.transitions(base):step(event)',component);self.assertIn("auxiliary('baseline606')",component)
if __name__=='__main__':unittest.main(verbosity=2)
