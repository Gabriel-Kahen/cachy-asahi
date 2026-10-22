# SPDX-License-Identifier: MIT
"""Pure source/adapter controls; inert bytes do not supply carrier or repair authority."""
import ast,copy,hashlib,importlib.util,json,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(HERE));import selection as S,carrier
N=ROOT/S.NATIVE;K=ROOT/S.BRIDGE
class Controls(unittest.TestCase):
 def test_complete_original210_inverse_both_original_source_gates(self):
  self.assertEqual(S.source_only()['parent'],210)
  with S.original()as(old,C):
   self.assertEqual(sum(p.is_file()for p in old.rglob('*')),210)
   for case in C.CASES:
    native,_=C.gate(old,case);self.assertEqual(native.VERSIONS['cachy-asahi-apps'],'0.1.0-7');self.assertEqual(native.VERSIONS['cachy-asahi-repository-runtime'],'0.1.0-1')
 def test_actual_isolated_source_entry_null_before_external_or_actor(self):
  r=subprocess.run([sys.executable,'-I','-B',str(HERE/'entry.py'),'--source-only'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertIsNone(json.loads(r.stdout)['authority'])
  profile=json.loads((HERE/'carrier-profile.json').read_bytes())
  if profile['source']is not None:
   C=S.load(K/'contract.py','_test_bound_apps11_bridge')
   for case in C.CASES:
    native,_=C.gate(ROOT,case);self.assertEqual(native.VERSIONS[S.NAME],'0.1.0-11');self.assertEqual(native.VERSIONS['cachy-asahi-repository-runtime'],'0.1.0-1')
   return
  with patch.object(carrier,'module',side_effect=AssertionError('NO_EXTERNAL_GIT_OR_ACTOR'))as external,self.assertRaisesRegex(ValueError,'NULL'):carrier.inspect(Path('/absent'))
  external.assert_not_called();r=subprocess.run([sys.executable,'-I','-B',str(HERE/'entry.py'),'--require-selection'],capture_output=True,timeout=10);self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL',r.stderr)
  C=S.load(K/'contract.py','_test_apps11_bridge')
  with self.assertRaisesRegex(ValueError,'NULL'):C.gate(ROOT,'repair-bytes')
 def test_complete_selected_derivation_and_reverse_all_original_body_seams(self):
  D=S.load(N/'derive.py','_test_apps11_derivation')
  for name in('contract','closure','transaction','inspection','base_lifecycle','lifecycle','checks'):
   raw,ledger=D.derive(ROOT,name);restored=raw.decode()
   for row in reversed(ledger):
    self.assertEqual(restored.count(row['after']),row['count']);restored=restored.replace(row['after'],row['before'],row['count'])
   ref=json.loads((N/'derivation-pins.json').read_bytes())['files'][name];self.assertEqual(restored.encode(),(ROOT/ref['path']).read_bytes())
   if name in('contract','closure','lifecycle','checks'):self.assertIn('0.1.0-11',raw.decode())
   if name=='closure':self.assertIn("'cachy-asahi-apps11' if package==",raw.decode())
 def fixture(self):
  names=[S.NAME,'cachy-asahi-repository-runtime','cachy-asahi-cache','cachy-asahi-orphans'];packet={'packages':{n:dict(version=v,unchanged=n)for n,v in zip(names,('0.1.0-7','0.1.0-1','0.2.0-1','0.1.0-2'))}}
  files=['usr/bin/cachy-asahi-apps','usr/lib/cachy-asahi-apps/helper-pins.json',*('usr/share/fixture/'+str(i)for i in range(6))];payload={n:(0o644,b'old')for n in files};origins={n:S.NAME for n in files};new={n:(0o644,b'new')for n in files};helpers={}
  for i in range(3):
   key='scripts/helper'+str(i)+'.py';raw=('held-runtime-'+str(i)).encode();n='usr/share/cachy-asahi/repository-runtime/'+key;payload[n]=(0o644,raw);origins[n]='cachy-asahi-repository-runtime';helpers[key]=S.pin(raw)
  new['usr/lib/cachy-asahi-apps/helper-pins.json']=(0o644,S.enc(dict(files=helpers)))
  return packet,payload,origins,dict(version='0.1.0-11'),new
 def test_only_apps_changes_three_authorities_and_runtime_helpers_held(self):
  args=self.fixture();before=copy.deepcopy(args);v,payload,origins=S.merge(*args);self.assertEqual(args,before)
  for n,row in args[0]['packages'].items():
   if n!=S.NAME:self.assertEqual(v['packages'][n],row)
  self.assertEqual(v['packages'][S.NAME]['version'],'0.1.0-11');self.assertEqual(origins,args[2]);self.assertEqual(len(payload),11)
  for bad in('0.1.0-7','0.1.0-10','0.1.0-1'):
   a=list(copy.deepcopy(args));a[3]['version']=bad
   with self.assertRaises(ValueError):S.merge(*a)
  a=list(copy.deepcopy(args));a[0]['packages']['cachy-asahi-repository-runtime']['version']='0.1.0-2'
  with self.assertRaises(ValueError):S.merge(*a)
  a=list(copy.deepcopy(args));a[4]['usr/lib/cachy-asahi-apps/helper-pins.json']=(0o644,S.enc(dict(files={})))
  with self.assertRaises(ValueError):S.merge(*a)
 def test_whole_original_materialize_body_selects_new_index_without_old_index_relabel(self):
  raw=(ROOT/'scripts/ci/apps-full574-native/job.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='materialize');body=ast.get_source_segment(raw,node)
  packet,payload,origins,_,_=self.fixture();packet['packages'][S.NAME]['version']='0.1.0-11';blobs={}
  for name,row in packet['packages'].items():
   prefix='APPS11_CARRIER/'if name==S.NAME else'OLD/';row['source_files']={n:dict(path=prefix+n)for n in('apps.py','inventory.py','helper-pins.json','cachy-asahi-apps','source-provenance.json')};row['files']={'a':dict(path=prefix+name+'.pkg.tar.xz')}
   for ref in[*row['source_files'].values(),row['files']['a']]:blobs[ref['path']]=ref['path'].encode()
  def checked(root,row):
   self.assertNotEqual(row['path'],'OLD_INDEX');return blobs[row['path']]
  C=types.SimpleNamespace(inputs=lambda *a:(packet,payload,origins),checked=checked,encoded=S.enc,policy=lambda:dict(packet_index=dict(path='OLD_INDEX'),packet_source='held-old-packet'),save=lambda p,v:p.write_bytes(S.enc(v)),need=S.need)
  space=dict(C=C,Path=Path);exec(compile(body,'whole-materialize-control','exec'),space)
  with tempfile.TemporaryDirectory()as td:
   output=Path(td)/'output';output.mkdir();args=types.SimpleNamespace(source=ROOT,packet=Path('/inert-old-packet'));report=dict(source_sha='a'*40,token='fixture',image='sha256:'+'b'*64);space['materialize'](args,output,report)
   self.assertEqual(json.loads((output/'inputs/native-index.json').read_bytes()),packet);self.assertEqual((output/'inputs/apps-source/apps.py').read_bytes(),b'APPS11_CARRIER/apps.py');self.assertEqual(len(list((output/'inputs/archives').iterdir())),4)
 def test_null_profile_known_context_only_and_explicit_apps11_labels(self):
  p=json.loads((HERE/'carrier-profile.json').read_bytes());self.assertEqual(p['recipe_source'],'31bc46cdd58840e5c4337d2270a307d23a171373');self.assertEqual(p['expected_native_source'],'d4e86c4e7799b4138fc1a1a8720b223e78b99fe6');self.assertEqual(p['expected_native_run'],39769794548)
  if p['source']is None:self.assertTrue(all(p[n]is None for n in('source','ref','publication','git_authorization','files','archives','native_source','native_run','acceptance','archive')))
  self.assertIn('EXACT_ACCEPTED_APPS11_PAIR_INPUT_DATA_ONLY',(HERE/'carrier.py').read_text());self.assertIn('ROOT_ACCEPTED_APPS11_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE',(HERE/'carrier.py').read_text())
 def test_all_nested_source_seals_aliases_and_original_30_45_9000_9010_clocks(self):
  for mf in(S.NATIVE+'/source-manifest.json',S.BRIDGE+'/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json'):
   rows=json.loads((ROOT/mf).read_bytes())['files']
   for n,w in rows.items():self.assertEqual(S.pin((ROOT/n).read_bytes()),w,n)
  a=(ROOT/'.github/workflows/native-arm-build.yml').read_bytes();b=(ROOT/'.github/workflows/native-arm-apps7-full574-repair16k.yml').read_bytes();self.assertEqual(a,b);self.assertIn(b'APPS11_CARRIER_NULL_UNPUBLISHED'if json.loads((HERE/'carrier-profile.json').read_bytes())['source']is None else json.loads((HERE/'carrier-profile.json').read_bytes())['source'].encode(),a)
  self.assertLess(a.index(b'--require-selection'),a.index(b'owner.py" proof'))
  self.assertIn('seconds=45',(ROOT/'scripts/ci/apps7-full574-repair-native/base_lifecycle.py').read_text());self.assertIn('seconds=9010',(K/'adapter.py').read_text());self.assertIn('9000',(K/'adapter.py').read_text());self.assertIn('deadline=time.monotonic()+30',(ROOT/'packages/tools/cachy-asahi-apps11/inventory.py').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
