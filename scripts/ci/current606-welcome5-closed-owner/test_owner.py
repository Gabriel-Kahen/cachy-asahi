"""Source/emission/real argv controls; no accepting606 decision or native fixture."""
import ast,copy,importlib.util,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import contract as C,owner as O,runtime as R,selection as S,prepare as E
NULL_POLICY={'actual_ref': None, 'actual_run': None, 'actual_source': None, 'capture_receipt': None, 'current606': {'decision_base64': None, 'decision_path': None, 'decision_pin': None, 'decision_source': None, 'run': None, 'source': None}, 'expected606_sha256': '3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1', 'measurement': None, 'nonce': None, 'output': None, 'purpose': 'CURRENT606_WELCOME5_CLOSED_NATIVE', 'retirement': None, 'schema_version': 1, 'source_manifest606': None, 'status': 'UNBOUND_SOURCE_TEMPLATE', 'welcome_source': '85ffec834fc72ef8764cdcae828a12ec8ddf7f20'}
class Owner(unittest.TestCase):
 def default_policy(self):
  real=C.read
  return patch.object(C,'read',side_effect=lambda p,*a,**k:copy.deepcopy(NULL_POLICY)if p==HERE/'input-policy.json'else real(p,*a,**k))
 def emit_default(self,*args,**kwargs):
  with self.default_policy():return E.emit(*args,**kwargs)

 def test_real_four_complete_source_roles(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   fact=C.verify();self.assertEqual(fact['roles']['held606'],263);self.assertEqual(fact['roles']['heldwelcome'],99)
 def test_actual_default_authority_before_actors(self):
  with self.default_policy(),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):O.main(['--require-selection'])
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):O.main([])
 def test_counted_complete_owner_and_capture_derivations(self):
  P,A,X,old=O.source_context(C.ROOT);raw=A.owner(P.ROOT);derived=O.owner_program(raw)
  self.assertIn('active.process.wait(timeout=1800)',derived);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',derived)
  self.assertEqual(derived.count('Y.complete(active,report)'),1);self.assertEqual(derived.count('Y.failure(active,absence,report)'),1)
  original=(P.HERE/'tools606.py').read_text();capture=O.capture_program(original);self.assertEqual(capture.replace(O.CAPTURE_HOOK,O.CAPTURE_LINE),original)
  self.assertLess(capture.index("install('same-version606')"),capture.index("bridge=runpy"));self.assertLess(capture.index("bridge=runpy"),capture.index("remove('remove604')"))
  self.assertIn('return previous_ld,previous_aux',capture)
 def actual_capture(self):
  P,A,X,old=O.source_context(C.ROOT);tree=ast.parse(O.owner_program(A.owner(P.ROOT)));main=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='main');body=next(x.body for x in main.body if isinstance(x,ast.Try));start=next(i for i,x in enumerate(body)if isinstance(x,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='name'for t in x.targets));stop=next(i for i,x in enumerate(body[start:],start)if isinstance(x,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='command'for t in x.targets)and isinstance(x.value,ast.Call)and isinstance(x.value.func,ast.Attribute)and x.value.func.attr=='launch')
  code=ast.Module(body=body[start:stop],type_ignores=[]);scope={'os':os,'owned':types.SimpleNamespace(token='1'*32),'Y':types.SimpleNamespace(nonce='2'*32,measurement=Path('/owned/measurement')),'HERE':Path('/owned/held-runner'),'ready':Path('/owned/original'),'target':Path('/owned/target'),'planroot':Path('/owned/plan'),'runner606':Path('/owned/runner'),'tools606':Path('/owned/tools606'),'args':types.SimpleNamespace(code=Path('/owned/code'),legacy_source=Path('/owned/combined')),'resultdir':Path('/owned/out')};exec(compile(code,'<actual-counted-owner-argv>','exec'),scope);return scope['command']
 def test_actual_capture_argv_matches_bridge_mount_runtime_allowlist(self):
  argv=self.actual_capture();rows=O.parse_mounts(argv);B=C.module('_owned_bridge_contract',C.ROOT/'bridge/scripts/ci/current606-welcome5-source-bridge/bridge.py')
  apis=B.load_apis(C.ROOT/'bridge');self.assertEqual({r['target'].lstrip('/')for r in rows},B.INFRA);self.assertEqual(apis.scope.INFRASTRUCTURE,B.INFRA)
  self.assertEqual(apis.scope.MOUNT_FILES,{'etc/hosts','etc/hostname','etc/resolv.conf'});self.assertTrue({'proc','sys','dev','run','tmp'}<=apis.scope.RUNTIME)
  self.assertEqual(tuple(t.split('=',1)[1]for t in argv if t.startswith('--cap-add=')),S.CAPS['capture']);self.assertEqual(sum(not r['readonly']for r in rows),2)
  self.assertIn('--env=CAA_CURRENT606_BRIDGE='+'2'*32,argv);self.assertIn('--network=none',argv);self.assertNotIn('--rm',argv);self.assertNotIn('--privileged',argv)
 def test_actual_worker_argv_matches_worker_typed_guard(self):
  paths={n:Path('/owned')/n for n in('runner','seed','proof','work','out')};argv=R.argv('worker','sha256:'+'1'*64,'2'*32,paths)
  W=C.module('_owned_worker_contract',C.ROOT/'copyworker/scripts/ci/current606-welcome5-copy/contract.py');self.assertTrue(W.bindings(O.parse_mounts(argv)));self.assertEqual(tuple(t.split('=',1)[1]for t in argv if t.startswith('--cap-add=')),W.WORKER_CAPS)
  bad=O.parse_mounts(argv);bad[1]['readonly']=False
  with self.assertRaises(ValueError):W.bindings(bad)
 def test_whole_owner_api_is_exact_in_both_components(self):
  actual=C.pin((HERE/'selection.py').read_bytes());bridge=C.read(C.ROOT/'bridge/scripts/ci/current606-welcome5-source-bridge/owner-api.json');worker=C.read(C.ROOT/'copyworker/scripts/ci/current606-welcome5-copy/owner-api.json')
  self.assertEqual(bridge,dict(path='/runner/owner/selection.py',pin=actual));self.assertEqual(worker,dict(path='/runner/owner/selection.py',**actual))
 def test_fresh_emission_default_and_all_bash_hash_pairs(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   output=Path(d)/'source';inputs={r:C.ROOT/r for r in C.ROLES};auth=self.emit_default(inputs,output)
   self.assertEqual(len(auth),len(C.read(HERE/'source-manifest.json')['files'])+3)
   wf=(output/'.github/workflows/native-arm-build.yml').read_text();self.assertEqual(wf,(output/'.github/workflows/native-arm-current606-welcome5-owned-copy.yml').read_text())
   self.assertIn('/'+C.LANE+'/owner.py"',wf);self.assertIn('--require-selection',wf)
   workspace=Path(d)/'workspace';workspace.mkdir();(workspace/'expanded604-code').symlink_to(output)
   commands=[line.strip()for line in wf.splitlines()if 'expanded604-code/'in line and ('| sha256sum --check'in line or('test "$(sha256sum 'in line))]
   self.assertGreaterEqual(len(commands),4)
   for command in commands:subprocess.run(['bash','-euo','pipefail','-c',command],cwd=workspace,check=True,capture_output=True)
   self.assertTrue(all(x is None for x in json.loads((output/C.LANE/'input-policy.json').read_bytes())['current606'].values()))
 def test_second_source_role_drift_refuses_before_output(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   output=Path(d)/'forbidden';inputs={r:C.ROOT/r for r in C.ROLES};inputs['heldwelcome']=C.ROOT/'held606'
   with self.assertRaisesRegex(ValueError,'whole role set'):self.emit_default(inputs,output)
   self.assertFalse(output.exists())
 def test_real_untouched_measurement_cleanup_before_any_actor(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   i=O.Integration(C.ROOT,None,None,{});i.measurement=Path(d)/'measurement';i.measurement.mkdir(mode=0o700);i.lease=R.measurement_lease(i.measurement)
   with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):i.failure(None,True,{})
   self.assertFalse(i.measurement.exists())
 def test_only_two_fixed_capture_selection_data_exports(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   out=Path(d);(out/'plan').mkdir();(out/'plan/private-map.json').write_text('{}')
   owner=O.Integration(C.ROOT,types.SimpleNamespace(export_names=lambda _:[]),None,{})
   self.assertEqual(owner.export_names(out),['container/bridge-capture.json','plan/bridge-selection.json'])
 def test_only_duplicate_fixture_source_exports_omitted_runtime_inputs_held(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   out=Path(d);selected=[]
   for role in('cachy-asahi-welcome','cachy-asahi-welcome5'):
    policy=C.read(C.ROOT/'heldwelcome/scripts/ci/welcome5-native-upgrade/input-policy.json')['products'][role]
    self.assertEqual(len(policy['source_files']),25)
    for name in policy['source_files']:
     for prefix in('welcome-inputs/sources/'+role,'welcome-builds/'+role+'-a/inputs','welcome-builds/'+role+'-b/inputs'):
      p=out/prefix/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'preserved runtime source')
     selected.append(out/'welcome-inputs/sources'/role/name)
   for name in('welcome-inputs/products.json','welcome-inputs/lifecycle-plan.json','welcome-inputs/sources-shadow/ordinary','bridge-output/result.json'):
    p=out/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'data')
   owner=O.Integration(C.ROOT,types.SimpleNamespace(export_names=lambda _:[]),None,{})
   names=owner.export_names(out);self.assertEqual(len(names),106)
   self.assertFalse(any(n.startswith('welcome-inputs/sources/')for n in names));self.assertTrue(all(p.read_bytes()==b'preserved runtime source'for p in selected))
   self.assertEqual(sum('/inputs/'in n for n in names),100);self.assertIn('welcome-inputs/sources-shadow/ordinary',names)
 def producer_key_fixture(self,base):
  import shutil
  _,_,_,old=O.source_context(C.ROOT);inputs=base/'inputs';inputs.mkdir();ready=base/'ready';(ready/'keys').mkdir(parents=True)
  (inputs/'archlinuxarm.gpg').write_bytes(b'INERT_ALARM_PUBLIC_NOT_A_KEY');(inputs/'TEST-public.asc').write_bytes(b'INERT_TEST_PUBLIC_NOT_A_KEY')
  raw=(C.ROOT/'held606/held604/scripts/ci/full-composition-installer-vm/producer.py').read_text();tree=ast.parse(raw);check=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='checked_copy');export=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='export_ready');loop=next(n for n in export.body if isinstance(n,ast.For)and isinstance(n.target,ast.Tuple)and [x.id for x in n.target.elts]==['source','name'])
  row=dict(filename='archlinuxarm.gpg',size=(inputs/'archlinuxarm.gpg').stat().st_size,sha256=old.sha(inputs/'archlinuxarm.gpg'));scope=dict(need=old.need,sha=old.sha,shutil=shutil,MAX_ARCHIVE=256*1024**2,inputs=inputs,ready=ready,base_input=dict(keyring_files=[row]),keys=[])
  exec(compile(ast.Module(body=[check,loop],type_ignores=[]),'<whole pinned original producer key export loop>','exec'),scope)
  manifest=dict(keyrings=scope['keys'],preparation=dict(signer_roles={'ephemeral_TEST':'A'*40,'upstream_ALARM':'B'*40}));(ready/'manifest.json').write_bytes(C.encoded(manifest));return ready,manifest,old
 def test_actual_producer_key_export_reproduces_wrong_path_and_resolver(self):
  import builds
  with tempfile.TemporaryDirectory()as d:
   ready,manifest,old=self.producer_key_fixture(Path(d));self.assertFalse((ready/'TEST-public.asc').exists())
   with self.assertRaises(FileNotFoundError):(ready/'TEST-public.asc').read_bytes()
   p=builds.test_public_key(ready,manifest,old);self.assertEqual(p,ready/'keys/TEST-public.asc');self.assertEqual(p.read_bytes(),b'INERT_TEST_PUBLIC_NOT_A_KEY');self.assertEqual(old.row(p)if hasattr(old,'row')else dict(bytes=p.stat().st_size,sha256=old.sha(p)),dict(bytes=manifest['keyrings'][1]['size'],sha256=manifest['keyrings'][1]['sha256']))
 def test_public_key_manifest_role_pin_path_and_alias_refuse(self):
  import builds,copy,os
  with tempfile.TemporaryDirectory()as d:
   ready,manifest,old=self.producer_key_fixture(Path(d))
   for kind in('path','duplicate','size','hash','role','fields'):
    value=copy.deepcopy(manifest)
    if kind=='path':value['keyrings'][1]['path']='keys/../TEST-public.asc'
    elif kind=='duplicate':value['keyrings'][1]=value['keyrings'][0]
    elif kind=='size':value['keyrings'][1]['size']=True
    elif kind=='hash':value['keyrings'][1]['sha256']='0'*64
    elif kind=='role':value['preparation']['signer_roles']['ephemeral_TEST']='B'*40
    else:value['keyrings'][1]['private']='unrecognized'
    with self.subTest(kind=kind),self.assertRaises(ValueError):builds.test_public_key(ready,value,old)
   p=ready/'keys/TEST-public.asc';alias=ready/'public-alias';os.link(p,alias)
   with self.assertRaises(ValueError):builds.test_public_key(ready,manifest,old)
   alias.unlink();p.unlink();p.symlink_to(ready/'keys/archlinuxarm.gpg')
   with self.assertRaises(ValueError):builds.test_public_key(ready,manifest,old)
 def test_both_actual_key_copy_seams_use_original_manifest_resolver(self):
  import builds,shutil
  tree=ast.parse((HERE/'builds.py').read_bytes());functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
  with tempfile.TemporaryDirectory()as d:
   ready,manifest,old=self.producer_key_fixture(Path(d));context=Path(d)/'welcome-inputs';context.mkdir();keys=context/'keys';keys.mkdir();scope=dict(ready=ready,C=old,context=context,keys=keys,shutil=shutil,test_public_key=builds.test_public_key)
   welcome=next(n for n in ast.walk(functions['_welcome'])if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='copyfile'and isinstance(n.args[0],ast.Call)and isinstance(n.args[0].func,ast.Name)and n.args[0].func.id=='test_public_key');exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.Expr(welcome)],type_ignores=[])),'<actual Welcome input key copy>','exec'),scope)
   block=functions['lifecycle_plan'].body;at=next(i for i,n in enumerate(block)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='pub'for t in n.targets));exec(compile(ast.Module(body=block[at:at+2],type_ignores=[]),'<actual lifecycle plan key copy>','exec'),scope)
   self.assertEqual((context/'TEST-public.asc').read_bytes(),(keys/'TEST-public.asc').read_bytes());self.assertEqual(scope['pub'],ready/'keys/TEST-public.asc')
 def test_realistic_primary_git_file_or_directory_metadata_allowed(self):
  from unittest.mock import patch
  for kind in('file','directory'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=HERE)as d:
    root=Path(d)/'source';self.emit_default({r:C.ROOT/r for r in C.ROLES},root)
    if kind=='file':(root/'.git').write_text('gitdir: /owned/metadata\n')
    else:
     (root/'.git/objects').mkdir(parents=True);(root/'.git/objects/ordinary').write_text('metadata');(root/'.git/config').write_text('[core]\n')
    with patch.object(C,'HERE',root/C.LANE):self.assertEqual(C.verify(root)['files'],len(C.read(root/C.LANE/'source-manifest.json')['files'])+3)
 def test_only_git_metadata_excluded_unknown_root_private_refuses(self):
  from unittest.mock import patch
  for name in('.git-shadow','private/unexpected'):
   with self.subTest(path=name),tempfile.TemporaryDirectory(dir=HERE)as d:
    root=Path(d)/'source';self.emit_default({r:C.ROOT/r for r in C.ROLES},root);(root/'.git').mkdir();(root/'.git/metadata').write_text('ignored');p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('unexpected source')
    with patch.object(C,'HERE',root/C.LANE),self.assertRaisesRegex(ValueError,'closed exact owner source closure'):C.verify(root)
 def test_advertised_source_drift_refuses_with_git_metadata(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d)/'source';self.emit_default({r:C.ROOT/r for r in C.ROLES},root);(root/'.git').write_text('gitdir: /owned/metadata\n');p=root/C.LANE/'selection.py';p.write_bytes(p.read_bytes()+b'\n# drift\n')
   with patch.object(C,'HERE',root/C.LANE),self.assertRaisesRegex(ValueError,'whole source differs'):C.verify(root)
 def test_unknown_measurement_never_removed(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   i=O.Integration(C.ROOT,None,None,{});i.measurement=Path(d)/'measurement';i.measurement.mkdir(mode=0o700);i.lease=R.measurement_lease(i.measurement);p=i.measurement/'unknown';p.write_bytes(b'held')
   with self.assertRaisesRegex(ValueError,'unknown partial capture retained'):i.failure(None,True,{})
   self.assertEqual(p.read_bytes(),b'held')
class AudioReadRetry(unittest.TestCase):
 def helper(self):
  raw=(C.ROOT/'held606/held604/scripts/ci/full-development-composition/retrieve_audio.py').read_bytes()
  self.assertEqual(C.pin(raw),dict(bytes=13846,sha256='fac76ea6d0a31bd14cc27d82af79c577370f6307554597d3f7805d0095ea5108'))
  tree=ast.parse((HERE/'owner.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='audio_retrieval')
  values={n.targets[0].id:ast.literal_eval(n.value)for n in fn.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('before','after')}
  self.assertEqual(raw.decode().count(values['before']),1);candidate=raw.decode().replace(values['before'],values['after']);module=types.ModuleType('inert_source_audio_retry');module.__file__=str(C.ROOT/'held606/held604/scripts/ci/full-development-composition/retrieve_audio.py');exec(compile(candidate,module.__file__+':source-retry-control','exec'),module.__dict__)
  return module,raw,candidate
 def response(self,items,headers=None):
  class Response:
   status=200;closed=False
   def __init__(self):self.items=list(items);self.headers={}if headers is None else headers;self.requested=[]
   def read1(self,n):
    self.requested.append(n);value=self.items.pop(0)
    if isinstance(value,BaseException):raise value
    return value
   def __enter__(self):return self
   def __exit__(self,*_):self.closed=True
  return Response()
 def fetch(self,m,responses,target,limit=100,deadline=100,clock=None):
  from unittest.mock import Mock
  opener=types.SimpleNamespace(open=Mock(side_effect=responses))
  with patch.object(m.urllib.request,'build_opener',return_value=opener),patch.object(m.time,'monotonic',side_effect=clock or(lambda:0)):
   m.fetch('https://api.github.com/repos/owned/inert/logs',target,limit,deadline,token='INERT_NOT_A_TOKEN')
  return opener
 def test_real_private_partial_is_discarded_once_never_appended(self):
  from http.client import IncompleteRead
  m,_,_=self.helper();a=self.response([b'old',IncompleteRead(b'x',10)]);b=self.response([b'complete',b''])
  with tempfile.TemporaryDirectory()as td:
   target=Path(td)/'private';opener=self.fetch(m,[a,b],target);self.assertEqual(target.read_bytes(),b'complete');self.assertEqual(target.stat().st_mode&0o777,0o600);self.assertEqual(opener.open.call_count,2);self.assertTrue(a.closed and b.closed)
   self.assertEqual(opener.open.call_args_list[0].args[0].full_url,opener.open.call_args_list[1].args[0].full_url)
 def test_second_incomplete_read_refuses_and_never_third_get(self):
  from http.client import IncompleteRead
  from unittest.mock import Mock
  m,_,_=self.helper();opener=types.SimpleNamespace(open=Mock(side_effect=[self.response([IncompleteRead(b'',1)]),self.response([IncompleteRead(b'',1)])]))
  with tempfile.TemporaryDirectory()as td,patch.object(m.urllib.request,'build_opener',return_value=opener),patch.object(m.time,'monotonic',return_value=0):
   with self.assertRaisesRegex(m.Refused,'fixed-input-incomplete-read'):m.fetch('https://api.github.com/inert',Path(td)/'out',100,100,token='INERT')
  self.assertEqual(opener.open.call_count,2)
 def test_failed_bytes_and_exception_partial_debit_same_original_cap(self):
  from http.client import IncompleteRead
  m,_,_=self.helper()
  with tempfile.TemporaryDirectory()as td:
   with self.assertRaisesRegex(m.Refused,'download-size-refused'):self.fetch(m,[self.response([b'123456',IncompleteRead(b'x',1)]),self.response([b'78901',b''])],Path(td)/'out',limit=10)
 def test_other_errors_or_existing_destination_never_retry(self):
  from unittest.mock import Mock
  m,_,_=self.helper()
  for error in(TimeoutError('inert'),OSError('inert')):
   opener=types.SimpleNamespace(open=Mock(return_value=self.response([error])))
   with tempfile.TemporaryDirectory()as td,patch.object(m.urllib.request,'build_opener',return_value=opener),patch.object(m.time,'monotonic',return_value=0):
    with self.assertRaises(type(error)):m.fetch('https://api.github.com/inert',Path(td)/'out',100,100,token='INERT')
    self.assertEqual(opener.open.call_count,1)
  with tempfile.TemporaryDirectory()as td:
   target=Path(td)/'out';target.write_bytes(b'caller-owned')
   with self.assertRaises(FileExistsError):self.fetch(m,[self.response([b'new',b''])],target)
   self.assertEqual(target.read_bytes(),b'caller-owned')
 def test_one_shared_deadline_and_no_retry_after_expiry(self):
  from http.client import IncompleteRead
  m,_,_=self.helper();ticks=iter([0,0,100])
  with tempfile.TemporaryDirectory()as td:
   with self.assertRaisesRegex(m.Refused,'retrieval-deadline'):self.fetch(m,[self.response([IncompleteRead(b'',1)])],Path(td)/'out',clock=lambda:next(ticks))
 def test_redirect_total_and_auth_stripping_held_across_retry(self):
  from http.client import IncompleteRead
  from urllib.error import HTTPError
  from unittest.mock import Mock
  m,_,_=self.helper();urls=['https://owned.blob.core.windows.net/'+str(i)for i in range(5)]
  def redirect(url):return HTTPError('https://api.github.com/inert',302,'inert',{'Location':url},None)
  sequence=[redirect(urls[0]),self.response([IncompleteRead(b'',1)]),*[redirect(u)for u in urls[1:]]];opener=types.SimpleNamespace(open=Mock(side_effect=sequence))
  with tempfile.TemporaryDirectory()as td,patch.object(m.urllib.request,'build_opener',return_value=opener),patch.object(m.time,'monotonic',return_value=0):
   with self.assertRaisesRegex(m.Refused,'redirect-limit-or-location'):m.fetch('https://api.github.com/inert',Path(td)/'out',100,100,token='INERT')
  self.assertEqual(opener.open.call_count,6)
  self.assertIn('Authorization',opener.open.call_args_list[0].args[0].headers)
  for call in opener.open.call_args_list[1:]:self.assertNotIn('Authorization',call.args[0].headers)
 def test_partial_replacement_identity_refuses_without_removing_foreign_file(self):
  from http.client import IncompleteRead
  m,_,_=self.helper()
  with tempfile.TemporaryDirectory()as td:
   target=Path(td)/'out';foreign=Path(td)/'foreign';foreign.write_bytes(b'foreign')
   response=self.response([IncompleteRead(b'',1)])
   def replace(*_):response.closed=True;target.unlink();foreign.rename(target)
   response.__class__.__exit__=replace
   with self.assertRaisesRegex(m.Refused,'owned-partial-identity-drift'):self.fetch(m,[response],target)
   self.assertEqual(target.read_bytes(),b'foreign')
 def test_all_nonfetch_functions_policy_and_exact_payload_validators_held(self):
  m,raw,candidate=self.helper();functions=lambda t:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(t).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};a,b=functions(raw),functions(candidate);self.assertEqual(a.keys(),b.keys())
  for name in a.keys()-{'fetch'}:self.assertEqual(a[name],b[name],name)
  self.assertEqual(m.POLICY,'5dae018a1357708e85393048728a6fb44cd9c9eb02a78ab19e60435d370ffdf2');self.assertEqual(len(m.RUNS),2)
 def test_unbound_audio_entry_refuses_before_any_request(self):
  with Owner().default_policy(),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch('urllib.request.build_opener',side_effect=AssertionError('unbound GET')):
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):O.main(['--retrieve-audio','--output','/not-touched/audio-archives'])

if __name__=='__main__':unittest.main()
