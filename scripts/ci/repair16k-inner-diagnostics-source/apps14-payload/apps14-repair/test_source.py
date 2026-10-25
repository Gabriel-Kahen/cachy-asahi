# SPDX-License-Identifier: MIT
"""Pure source/adapter controls; inert bytes do not supply carrier or repair authority."""
import ast,copy,hashlib,importlib.util,json,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(HERE));import selection as S,carrier
N=ROOT/S.NATIVE;K=ROOT/S.BRIDGE
class Controls(unittest.TestCase):
 def test_complete_original210_inverse_both_original_source_gates(self):
  self.assertEqual(S.source_only()['parent'],235)
  with S.original()as(old,C):
   self.assertEqual(sum(p.is_file()for p in old.rglob('*')),235)
   for case in C.CASES:
    native,_=C.gate(old,case);self.assertEqual(native.VERSIONS['cachy-asahi-apps'],'0.1.0-13');self.assertEqual(native.VERSIONS['cachy-asahi-repository-runtime'],'0.1.0-1')
 def test_actual_isolated_source_entry_null_before_external_or_actor(self):
  r=subprocess.run([sys.executable,'-I','-B',str(HERE/'entry.py'),'--source-only'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertIsNone(json.loads(r.stdout)['authority'])
  profile=json.loads((HERE/'carrier-profile.json').read_bytes())
  if profile['source']is not None:
   C=S.load(K/'contract.py','_test_bound_apps14_bridge')
   for case in C.CASES:
    native,_=C.gate(ROOT,case);self.assertEqual(native.VERSIONS[S.NAME],'0.1.0-14');self.assertEqual(native.VERSIONS['cachy-asahi-repository-runtime'],'0.1.0-1')
   return
  with patch.object(carrier,'module',side_effect=AssertionError('NO_EXTERNAL_GIT_OR_ACTOR'))as external,self.assertRaisesRegex(ValueError,'NULL'):carrier.inspect(Path('/absent'))
  external.assert_not_called();r=subprocess.run([sys.executable,'-I','-B',str(HERE/'entry.py'),'--require-selection'],capture_output=True,timeout=10);self.assertNotEqual(r.returncode,0);self.assertIn(b'NULL',r.stderr)
  C=S.load(K/'contract.py','_test_apps14_bridge')
  with self.assertRaisesRegex(ValueError,'NULL'):C.gate(ROOT,'repair-bytes')
 def test_complete_selected_derivation_and_reverse_all_original_body_seams(self):
  D=S.load(N/'derive.py','_test_apps14_derivation')
  for name in('contract','closure','transaction','inspection','base_lifecycle','lifecycle','checks'):
   raw,ledger=D.derive(ROOT,name);restored=raw.decode()
   for row in reversed(ledger):
    self.assertEqual(restored.count(row['after']),row['count']);restored=restored.replace(row['after'],row['before'],row['count'])
   ref=json.loads((N/'derivation-pins.json').read_bytes())['files'][name];self.assertEqual(restored.encode(),(ROOT/ref['path']).read_bytes())
   if name in('contract','closure','lifecycle','checks'):self.assertIn('0.1.0-14',raw.decode())
   if name=='closure':self.assertIn("'cachy-asahi-apps14' if package==",raw.decode())
 def fixture(self):
  names=[S.NAME,'cachy-asahi-repository-runtime','cachy-asahi-cache','cachy-asahi-orphans'];packet={'packages':{n:dict(version=v,unchanged=n)for n,v in zip(names,('0.1.0-7','0.1.0-1','0.2.0-1','0.1.0-2'))}}
  files=['usr/bin/cachy-asahi-apps','usr/lib/cachy-asahi-apps/helper-pins.json',*('usr/share/fixture/'+str(i)for i in range(6))];payload={n:(0o644,b'old')for n in files};origins={n:S.NAME for n in files};new={n:(0o644,b'new')for n in files};helpers={}
  for i in range(3):
   key='scripts/helper'+str(i)+'.py';raw=('held-runtime-'+str(i)).encode();n='usr/share/cachy-asahi/repository-runtime/'+key;payload[n]=(0o644,raw);origins[n]='cachy-asahi-repository-runtime';helpers[key]=S.pin(raw)
  new['usr/lib/cachy-asahi-apps/helper-pins.json']=(0o644,S.enc(dict(files=helpers)))
  return packet,payload,origins,dict(version='0.1.0-14'),new
 def test_only_apps_changes_three_authorities_and_runtime_helpers_held(self):
  args=self.fixture();before=copy.deepcopy(args);v,payload,origins=S.merge(*args);self.assertEqual(args,before)
  for n,row in args[0]['packages'].items():
   if n!=S.NAME:self.assertEqual(v['packages'][n],row)
  self.assertEqual(v['packages'][S.NAME]['version'],'0.1.0-14');self.assertEqual(origins,args[2]);self.assertEqual(len(payload),11)
  for bad in('0.1.0-7','0.1.0-10','0.1.0-1'):
   a=list(copy.deepcopy(args));a[3]['version']=bad
   with self.assertRaises(ValueError):S.merge(*a)
  a=list(copy.deepcopy(args));a[0]['packages']['cachy-asahi-repository-runtime']['version']='0.1.0-2'
  with self.assertRaises(ValueError):S.merge(*a)
  a=list(copy.deepcopy(args));a[4]['usr/lib/cachy-asahi-apps/helper-pins.json']=(0o644,S.enc(dict(files={})))
  with self.assertRaises(ValueError):S.merge(*a)
 def test_whole_original_materialize_body_selects_new_index_without_old_index_relabel(self):
  raw=(ROOT/'scripts/ci/apps-full574-native/job.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='materialize');body=ast.get_source_segment(raw,node)
  packet,payload,origins,_,_=self.fixture();packet['packages'][S.NAME]['version']='0.1.0-14';blobs={}
  for name,row in packet['packages'].items():
   prefix='APPS14_CARRIER/'if name==S.NAME else'OLD/';row['source_files']={n:dict(path=prefix+n)for n in('apps.py','inventory.py','helper-pins.json','cachy-asahi-apps','source-provenance.json')};row['files']={'a':dict(path=prefix+name+'.pkg.tar.xz')}
   for ref in[*row['source_files'].values(),row['files']['a']]:blobs[ref['path']]=ref['path'].encode()
  def checked(root,row):
   self.assertNotEqual(row['path'],'OLD_INDEX');return blobs[row['path']]
  C=types.SimpleNamespace(inputs=lambda *a:(packet,payload,origins),checked=checked,encoded=S.enc,policy=lambda:dict(packet_index=dict(path='OLD_INDEX'),packet_source='held-old-packet'),save=lambda p,v:p.write_bytes(S.enc(v)),need=S.need)
  space=dict(C=C,Path=Path);exec(compile(body,'whole-materialize-control','exec'),space)
  with tempfile.TemporaryDirectory()as td:
   output=Path(td)/'output';output.mkdir();args=types.SimpleNamespace(source=ROOT,packet=Path('/inert-old-packet'));report=dict(source_sha='a'*40,token='fixture',image='sha256:'+'b'*64);space['materialize'](args,output,report)
   self.assertEqual(json.loads((output/'inputs/native-index.json').read_bytes()),packet);self.assertEqual((output/'inputs/apps-source/apps.py').read_bytes(),b'APPS14_CARRIER/apps.py');self.assertEqual(len(list((output/'inputs/archives').iterdir())),4)
 def test_null_profile_known_context_only_and_explicit_apps14_labels(self):
  p=json.loads((HERE/'carrier-profile.json').read_bytes());self.assertEqual(p['recipe_source'],'2e58341f6fa25de5167fd8a59566b3dd7f066fe3');self.assertEqual(p['expected_native_source'],('5bbf9b2078d67d5543d01a849144fbd5696fa677'));self.assertEqual(p['expected_native_run'],(39788418793))
  if p['source']is None:self.assertTrue(all(p[n]is None for n in('source','ref','publication','git_authorization','files','archives','native_source','native_run','acceptance','archive')))
  self.assertIn('EXACT_ACCEPTED_APPS14_PAIR_INPUT_DATA_ONLY',(HERE/'carrier.py').read_text());self.assertIn('ROOT_ACCEPTED_APPS14_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE',(HERE/'carrier.py').read_text())
 def test_all_nested_source_seals_aliases_and_original_30_45_9000_9010_clocks(self):
  for mf in(S.NATIVE+'/source-manifest.json',S.BRIDGE+'/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json'):
   rows=json.loads((ROOT/mf).read_bytes())['files']
   for n,w in rows.items():self.assertEqual(S.pin((ROOT/n).read_bytes()),w,n)
  a=(ROOT/'.github/workflows/native-arm-build.yml').read_bytes();b=(ROOT/'.github/workflows/native-arm-apps7-full574-repair16k.yml').read_bytes();self.assertEqual(a,b);self.assertIn(b'APPS14_CARRIER_NULL_UNPUBLISHED'if json.loads((HERE/'carrier-profile.json').read_bytes())['source']is None else json.loads((HERE/'carrier-profile.json').read_bytes())['source'].encode(),a)
  self.assertLess(a.index(b'--require-selection'),a.index(b'owner.py" proof'))
  self.assertIn('seconds=45',(ROOT/'scripts/ci/apps7-full574-repair-native/base_lifecycle.py').read_text());self.assertIn('seconds=9010',(K/'adapter.py').read_text());self.assertIn('9000',(K/'adapter.py').read_text());self.assertIn('deadline=time.monotonic()+30',(ROOT/'packages/tools/cachy-asahi-apps14/inventory.py').read_text())
# These controls execute the complete emitted backend and the actual source loader.
# Only the surrounding host/VM launch is absent; no GPG or transaction is invoked.
class ObserverControls(unittest.TestCase):
 def adapter(self):return S.load(K/'adapter.py','_apps14_emitted_observer_control')
 def backend(self,adapter):
  raw,ledger=adapter.rendered_backend(ROOT)
  m=types.ModuleType('_apps14_whole_rendered_backend');m.__file__=str(N/'transaction.py');sys.modules[m.__name__]=m
  exec(compile(raw,m.__file__,'exec'),m.__dict__)
  return m,ledger
 def stage(self,path):
  recipe=ROOT/'packages/tools/cachy-asahi-apps14';path.mkdir()
  for n in('apps.py','inventory.py','helper-pins.json','cachy-asahi-apps','source-provenance.json'):(path/n).write_bytes((recipe/n).read_bytes())
  return types.SimpleNamespace(apps_source=path,apps_provenance_sha256=S.pin((path/'source-provenance.json').read_bytes())['sha256'],repository_source=ROOT)
 def test_whole_emitter_app_source_original_pin_refusal_and_unchanged_apps14_bodies(self):
  A=self.adapter();B,ledger=self.backend(A)
  self.assertEqual(ledger['inventory_source_before'],'f5de0fc3d5067cb97986152385c37c2ec9c51237c5b37bc566b766d906405080')
  self.assertEqual(ledger['inventory_source_after'],ledger['inventory_source_before'])
  with tempfile.TemporaryDirectory(prefix='apps14-rendered-source-')as td:
   args=self.stage(Path(td)/'apps-source');app,c,r=B.app_source(args)
   canonical=S.load(ROOT/'packages/tools/cachy-asahi-apps14/apps.py','_apps14_original_functions')
   inventory=app.inventory_reader();original=canonical.inventory_reader()
   observer=types.ModuleType('_apps14_body_source');exec(compile(A.INVENTORY_OBSERVER,'<whole-observer-source>','exec'),observer.__dict__)
   text=(ROOT/'packages/tools/cachy-asahi-apps14/apps.py').read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='package')
   self.assertEqual(observer.package_source(text.encode()),ast.get_source_segment(text,node))
   self.assertEqual(app.package.__code__.co_names,canonical.package.__code__.co_names)
   for name,value in vars(original).items():
    if isinstance(value,types.FunctionType):self.assertEqual(vars(inventory)[name].__code__.co_code,value.__code__.co_code,name)
   self.assertEqual(A.functions((Path(inventory.__file__)).read_bytes()),A.functions((ROOT/'packages/tools/cachy-asahi-apps14/inventory.py').read_bytes()))
   # Complete old observer is recovered from the original210 inverse, not recreated.
   _,bodies=S.proof();text=bodies[S.BRIDGE+'/adapter.py'].decode();tree=ast.parse(text)
   old=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='INVENTORY_OBSERVER'for t in n.targets)))
   before=A.INVENTORY_OBSERVER;A.INVENTORY_OBSERVER=old
   try:
    oldB,_=self.backend(A)
    oldapp,_,_=oldB.app_source(args)
    with self.assertRaisesRegex(ValueError,'whole selected Apps7 inventory source differs'):oldapp.inventory_reader()
   finally:A.INVENTORY_OBSERVER=before
 def test_unchanged_actual_corrected_provenance_and_emitted_loader_drift_refusals(self):
  original=(ROOT/'packages/tools/cachy-asahi-apps14/source-provenance.json').read_bytes();value=json.loads(original)
  self.assertEqual(value['version'],'0.1.0-14')
  self.assertEqual(value['runtime_sources'],{n:S.pin((ROOT/'packages/tools/cachy-asahi-apps14'/n).read_bytes())for n in value['runtime_sources']})
  B,_=self.backend(self.adapter())
  with tempfile.TemporaryDirectory(prefix='apps14-rendered-drift-')as td:
   args=self.stage(Path(td)/'source');raw=(args.apps_source/'apps.py').read_bytes();(args.apps_source/'apps.py').write_bytes(raw+b'\n')
   with self.assertRaisesRegex(ValueError,'Apps source bytes differ: apps.py'):B.app_source(args)
   (args.apps_source/'apps.py').write_bytes(raw)
   provenance=json.loads((args.apps_source/'source-provenance.json').read_bytes());provenance['runtime_sources']=provenance['apps14_parent']['runtime_sources'];(args.apps_source/'source-provenance.json').write_bytes(S.enc(provenance));args.apps_provenance_sha256=S.pin((args.apps_source/'source-provenance.json').read_bytes())['sha256']
   with self.assertRaisesRegex(ValueError,'Apps source bytes differ: inventory.py'):B.app_source(args)
   args.apps_provenance_sha256='0'*64
   with self.assertRaisesRegex(ValueError,'Apps provenance/source closure pin differs'):B.app_source(args)
 def test_complete_observer_unknown_source_and_normalizer_refusals(self):
  A=self.adapter();observer=types.ModuleType('_apps14_exact_observer');exec(compile(A.INVENTORY_OBSERVER,'<whole-observer-control>','exec'),observer.__dict__)
  appraw=(ROOT/'packages/tools/cachy-asahi-apps14/apps.py').read_bytes();invraw=(ROOT/'packages/tools/cachy-asahi-apps14/inventory.py').read_bytes()
  self.assertEqual(observer.derive(invraw),invraw)
  for raw in(invraw+b'\n',b'',appraw):
   with self.assertRaises(ValueError):observer.derive(raw)
  for raw in(appraw+b'\n',b'',invraw):
   with self.assertRaises(ValueError):observer.package_source(raw)
  # Function body and lexical/path refusals are real accepted Apps14 behavior.
  B,_=self.backend(A)
  with tempfile.TemporaryDirectory(prefix='apps14-package-parity-')as td:
   args=self.stage(Path(td)/'source');app,c,r=B.app_source(args)
   original=S.load(ROOT/'packages/tools/cachy-asahi-apps14/apps.py','_apps14_normalizer_parity')
   row=dict(name='fixture',version='1-1',arch='any',depend=[],provides=[],conflict=[],replaces=[],files=['usr/share/fixture','literal\\backslash/é'])
   self.assertEqual(app.package(row,r),original.package(row,r))
   for path in('/absolute','a//b','a/./b','a/../b','', '.', '..'):
    bad=dict(row,files=[path])
    with self.assertRaises(ValueError):app.package(bad,r)
    with self.assertRaises(ValueError):original.package(bad,r)

if __name__=='__main__':unittest.main(verbosity=2)
