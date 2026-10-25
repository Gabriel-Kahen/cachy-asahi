# SPDX-License-Identifier: MIT
"""Finite Apps16 composition controls. Git/actors are never called by these tests."""
import copy,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];I=ROOT/'latest/implementation';sys.path.insert(0,str(I))
import apps16_inputs as A,latest_plan as P,next_inputs as N,apps16_successor as X
class Apps16(unittest.TestCase):
 def packets(self):return{n:Path(os.environ['APPS16_COMPOSITION_TEST_'+dict(apps16='CARRIER',apps16qualification='RECORD',apps16current606qualification='CURRENT606_RECORD')[n]]).absolute()for n in A.SOURCES}
 def test_only_apps_product_full32_65_33_four240_and_all_bounds(self):
  p=json.loads((I/'apps16-successor.json').read_bytes());base=dict(r.split()for r in(I/'expected606.lock').read_text().splitlines());events=P.transitions(base);self.assertEqual((len(events),P.GRAPHS,P.AUXILIARY,len(P.REAL_PHASES)),(32,65,33,4));self.assertEqual(P.product('apps')[3],'0.1.0-16');self.assertEqual(events[-1]['after'],base);self.assertEqual(P.BOUNDS,p['bounds'])
  for n in('latest/implementation/latest_component.py','latest/implementation/latest_validate.py','latest/implementation/latest_setup.py','latest/implementation/latest_graph_scope.py','latest/implementation/latest_owner.py','latest/implementation/latest_restoration.py','latest/implementation/expected606.lock'):
   self.assertEqual(A.pin((ROOT/n).read_bytes()),p['before'][n],n)
  self.assertEqual(base['hyprland-qt-support'],'0.1.0-14')
  self.assertEqual({r:v for r,n,o,v in P.PRODUCTS if r!='apps'},dict(doctor='0.2.0-1',ksm='0.1.0-2',welcome='0.1.0-8',boot='0.1.0-1',setup='0.1.0-6'))
 def test_exact94_22_native_scope_and_NULL_or_wrong_selector_refuses(self):
  p=A.profile();self.assertEqual([len(p['profiles'][n]['files'])for n in A.SOURCES],[94,22,16])
  if p['selection']is None:
   with self.assertRaisesRegex(ValueError,'NULL Apps16'):A.qualification()
  else:self.assertEqual(A.qualification()['status'],'ISSUED_APPS16_NATIVE_AND_CURRENT606_INPUT_ONLY')
  for mutate in(lambda p:p.update(selection=None),lambda p:p['selection'].update(source='0'*40),lambda p:p['selection'].update(run=1),lambda p:p['selection'].update(record_source='0'*40),lambda p:p['selection'].update(current606_run=1),lambda p:p['selection'].update(current606_source='0'*40),lambda p:p['selection'].update(current606_record_source='0'*40)):
   wrong=copy.deepcopy(p);wrong['selection']=copy.deepcopy(json.loads((I/'apps16-inputs.json').read_bytes())['selection'])or dict(source=A.NATIVE,ref=A.NATIVE_REF,run=A.RUN,record_source=A.SOURCES['apps16qualification'][0],carrier_source=A.SOURCES['apps16'][0],current606_record_source=A.SOURCES['apps16current606qualification'][0],current606_source='fdf045f0d9c0d5c7646b160b3b9890969d7f9fcb',current606_run=40171836477);mutate(wrong)
   with patch.object(A,'profile',return_value=wrong),patch('subprocess.run',side_effect=AssertionError('NO ACTOR/GIT')),self.assertRaises(ValueError):A.qualification()
 def test_all_genuine_input_files_and_qualified22_no_inner_replay(self):
  packets=self.packets();p=A.profile()
  class ReadOnly:
   @staticmethod
   def read(path,deadline):return Path(path).read_bytes()
  for role,root in packets.items():self.assertEqual({q.relative_to(root).as_posix():A.pin(q.read_bytes())for q in root.rglob('*')if q.is_file()and'.git'not in q.relative_to(root).parts},p['profiles'][role]['files'])
  root=packets['apps16qualification'];index=json.loads((root/'index.json').read_bytes());value=A.record(root,index,ReadOnly,0);self.assertEqual(value['full606'],'NOT_TRANSFERRED');self.assertEqual(len(value['originals']),8)
  for mutate in(lambda i:i.update(native_source='0'*40),lambda i:i.update(new_native_acceptance=True),lambda i:i.update(files={}),lambda i:i.update(native_run=1)):
   wrong=copy.deepcopy(index);mutate(wrong)
   with self.assertRaises(ValueError):A.record(root,wrong,ReadOnly,0)
 def test_genuine_current606_record16_exact_source_carrier_and_refusal_controls(self):
  root=self.packets()['apps16current606qualification'];index=json.loads((root/'index.json').read_bytes());p=A.profile()
  class ReadOnly:
   @staticmethod
   def read(path,deadline):return Path(path).read_bytes()
  value=A.current606_record(root,index,ReadOnly,0);self.assertEqual(value['scope'],'FINITE_CURRENT606_INPUT_ONLY');self.assertEqual(len(value['originals']),6);self.assertEqual(value['new_composition'],'NOT_QUALIFIED')
  for mutate in(lambda i:i.update(native_source='0'*40),lambda i:i.update(native_run=1),lambda i:i.update(new_native_acceptance=True),lambda i:i.update(files={})):
   bad=copy.deepcopy(index);mutate(bad)
   with self.assertRaises(ValueError):A.current606_record(root,bad,ReadOnly,0)
  wrong=copy.deepcopy(p);wrong['profiles']['apps16current606qualification']['carrier_binding']['value']['archive']['sha256']='0'*64
  with patch.object(A,'profile',return_value=wrong),self.assertRaises(ValueError):A.current606_record(root,index,ReadOnly,0)
 def test_old_five_input_predicate_AND_new_Apps16_inspector_and_custody(self):
  if A.profile()['selection']is None:
   with self.assertRaises(ValueError):N.inspect({},None)
   return
  old=object();current=object();called=[];packets={n:Path('/inert-host-fixture')/n for n in set(N.SOURCES)|set(A.SOURCES)}
  def before(rows,checks):self.assertEqual(set(rows),set(N.SOURCES));called.append('whole_old');return dict(apps10=old,welcome8=object(),setup6=object(),custody={'prior':'kept'})
  def new(rows,checks):self.assertEqual(set(rows),set(A.SOURCES));called.append('new16');return dict(apps16=current,custody={'new16':'kept'})
  with patch.object(N,'_before_apps16_inspect',side_effect=before),patch.object(A,'inspect',side_effect=new):result=N.inspect(packets,None)
  self.assertEqual(called,['whole_old','new16']);self.assertIs(result['apps16'],current);self.assertIs(result['apps10'],old);self.assertEqual(result['custody'],{'prior':{'prior':'kept'},'Apps16_native':{'new16':'kept'}})
  with patch.object(N,'_before_apps16_validate_custody',return_value={})as a,patch.object(A,'validate_custody',return_value={})as b:N.validate_custody(result['custody']);a.assert_called_once_with(result['custody']['prior']);b.assert_called_once_with(result['custody']['Apps16_native'])
  for value in({},dict(result['custody'],extra=True)):
   with self.assertRaises(ValueError):N.validate_custody(value)
 def test_actual_archives_metadata_payload_and_custody_with_inert_git_boundary(self):
  packets=self.packets();profile=A.profile()
  if profile['selection']is None:
   with self.assertRaises(ValueError):A.inspect(packets,None)
   return
  def module(name,path):
   spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
  git=module('_apps16_fixture_original_source_reader',I/'apps8_git.py');checks=module('_apps16_fixture_original_package_checks',ROOT/'historical/boot391/held606/held-tools/scripts/checks/package_checks.py')
  # Only the external Git-object process boundary is inert. Real source files,
  # tree encoding, exact byte hashes, archive parser and all provenance/record
  # predicates execute. This fixture does not claim a new actual Git proof.
  def prove(root,dotgit,row,deadline):
   actual={q.relative_to(root).as_posix():A.pin(git.read(q,deadline))for q in root.rglob('*')if q.is_file()and'.git'not in q.relative_to(root).parts};self.assertEqual(actual,row['files']);table={}
   for n in actual:
    raw=git.read(root/n,deadline);table[n]=dict(mode='100755'if(root/n).stat().st_mode&0o111 else'100644',oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
   self.assertEqual(git.tree_oid(table),row['tree']);return dict(status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY',source=row['source'],ref=row['ref'],files=len(actual),blob_joins=len(actual),tree=row['tree'])
  real_load=A.load
  def load(name,path):
   if name=='_apps16_complete_input_git_custody':git.prove=prove;return git
   return real_load(name,path)
  with patch.object(A,'load',side_effect=load),patch('subprocess.Popen',side_effect=AssertionError('NO ACTOR/API/GIT')):out=A.inspect(packets,checks)
  self.assertEqual(out['apps16']['report']['sha256'],A.ARCHIVE['sha256']);self.assertEqual(A.validate_custody(out['custody']),out['custody'])
  for mutate in(lambda v:v.update(actual_authority=True),lambda v:v['profiles']['apps16']['source'].update(files=93),lambda v:v['profiles']['apps16qualification']['record'].update(full606='ACCEPTED'),lambda v:v['qualification'].update(source='0'*40)):
   wrong=copy.deepcopy(out['custody']);mutate(wrong)
   with self.assertRaises(ValueError):A.validate_custody(wrong)
 def test_apps16_source_code_equals_accepted_runtime_and_real_help(self):
  packets=self.packets();record=json.loads((packets['apps16qualification']/'qualification/Root-archived-runtime-provenance.json').read_bytes())
  for name in('apps.py','inventory.py'):self.assertEqual(A.pin((I/'apps16-source'/name).read_bytes()),record['runtime_sources'][name])
  source=(I/'latest_fixture.py').read_text();self.assertIn("if version=='0.1.0-16':",source);self.assertIn("HERE/'apps16-source'/name",source);self.assertIn("controls['tests']==15",source)
  result=subprocess.run([sys.executable,'-I','-B',str(I/'apps16-source/apps.py'),'--help'],capture_output=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr)
 def test_three_new_pinned_readonly_checkouts_precede_consumers_both_routes(self):
  import latest_workflow as W,re
  for filename in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current607-latest-tools.yml'):
   text=(ROOT/filename).read_text();steps=W.steps(text);positions=[]
   for role,row in A.profile()['profiles'].items():
    found=[i for i,s in enumerate(steps)if s['name']=='Checkout exact Apps16 '+role+' public input DATA'];self.assertEqual(len(found),1);i=found[0];positions.append(i);body=steps[i]['body'];self.assertIn('ref: '+row['source'],body);self.assertIn('persist-credentials: false',body);self.assertIn('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',body)
    self.assertEqual(text.count('--'+role+'-packet "$GITHUB_WORKSPACE/latest607-next-'+role+'-inputs"'),2)
   consumers=[i for i,s in enumerate(steps)if '--native-inputs'in s['body']or '${{ secrets.'in s['body']or'docker build'in s['body']or'docker run'in s['body']or'next/test_source.py'in s['body']];self.assertLess(max(positions),min(consumers));self.assertIn('timeout-minutes: 220',text);self.assertIn('timeout-minutes: 115',text);self.assertIn('6660s',text)
if __name__=='__main__':unittest.main(verbosity=2)
