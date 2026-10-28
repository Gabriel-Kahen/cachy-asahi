# SPDX-License-Identifier: MIT
"""Exact corrected556 emission, real both-alias CLI routing and drift refusals."""
import argparse,ast,contextlib,importlib.util,io,json,os,shlex,shutil,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--predecessor-root',type=Path,required=True);p.add_argument('--expected-root',type=Path,required=True);p.add_argument('--apps8-input-root',type=Path,required=True);args,rest=p.parse_known_args();P,E,I=args.predecessor_root.absolute(),args.expected_root.absolute(),args.apps8_input_root.absolute()
def load_file(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load_file('_Apps8_maintained_emitter',HERE/'prepare.py')
PRIMARY='.github/workflows/native-arm-build.yml'
NAMED='.github/workflows/native-arm-current606-welcome8-gui.yml'
def workflow(root,name):
 # Emitted workflows quote their complete run scalar as one JSON string.
 # Decode that actual scalar; no third-party YAML/runtime dependency is needed.
 runs=[json.loads(line.strip().split(':',1)[1].strip())for line in(root/name).read_text().splitlines()if line.strip().startswith('"run":')and '$CURRENT' in line and ' run --case' in line]
 selected=[r for r in runs if '"$CURRENT" run --case' in r];assert len(selected)==1;return selected[0]
def load(root):return load_file('_actual_both_alias_native',root/'native.py')
HELD_FUNCTIONS={'need': 'a8ebc8f5f3a23b40b0c85a9adaa7e6f5bb29fcb122a2f824dc2f25deed384a8a', 'pin': 'f71b81de3a25bf17c4f69ffdebe13551b8d55744df3da3469a5b12a9b5ae1076', 'encoded': 'aa1b17862d0d560152b5f639b753eb459fb17ec1cb2bec71d40dfc9c68030452', 'relative': 'e3de32788dd994b66c973aac81f6dd804da191193c586f43e621c60d11e1be97', 'ordinary': '11603e23294c5416e9f96281094deaa4cb51adbd270ba80c6b178725b14734b5', 'files': '8ae1436227ec346e561b8a513e7a6ba7079c37a0a06c340e7125ae4a6fcb4e98', 'profile': '8d795c49bd7a407d973a463f7e8b970e4f021d38bd36cc9ce84dbbedc337ac93', 'prepare': '692658e23db894163ad617417b1dd288c90f896e792ead457e9b3213e70d2ce6', 'prepare_welcome8': 'ad97ab861c65b05c3d53490cd171ffa1e62b75c32de8ece2c32f8c9f385b7174', 'prepare_transport': '930d03db1c1ace488387a77ed3d85f8dbb93b73155abbeb7e36b9bc076c60e35', 'buildkit_profile': '0182334454d3fd01c1041421885d8fb8fa425f4611f4a2b2d7f2caaa501b4a08', 'prepare_buildkit': '8a6b0721368847d95250ab4f4fb1f02174a98b85ad42d7c5196aed3843089fbc', 'loader_profile': 'cc46de295f8f1335f9a392e5090abd1cbdb65a2fa2c9469b0396d3d3d11fcf44', 'prepare_loader': 'c82cc8d4dc5e6cb19005fa9316b3f0604b3868635310cd42dd682fb40227cba8'}
def exercise(root,name,missing=False):
 n=load(root)
 with tempfile.TemporaryDirectory()as t:
  t=Path(t);state=t/'state';state.mkdir();(state/'source-proof.json').write_text('{}');env=dict(GITHUB_WORKSPACE=str(t/'workspace'),RUNNER_TEMP=str(t/'runner-temp'),STATE=str(state),PROFILE='minimal',CASE='minimal-generic4k',CURRENT=str(root/'native.py'))
  with patch.dict(os.environ,env):words=shlex.split(os.path.expandvars(workflow(root,name)))
  tail=words[words.index(str(root/'native.py'))+1:];calls=[]
  def prepare(*args):calls.append(('prepare',args));return dict(status='INERT_INPUT_BOUNDARY_NOT_NATIVE_ACCEPTANCE')
  def emit(*args):calls.append(('emit',args));args[3].mkdir();(args[3]/'current606-proof.json').write_text('{}')
  owner=types.SimpleNamespace(run=lambda *args:dict(status='INERT_OWNER_BOUNDARY_NOT_NATIVE_ACCEPTANCE'))
  with patch.object(n.A,'prove',return_value={}),patch.object(n,'binding',return_value=dict(owner_deadline=time.monotonic()+5,profile='minimal',mode='generic4k')),patch.object(n,'factory',return_value=types.SimpleNamespace(emit=emit)),patch.object(n,'load',return_value=owner),patch.dict(sys.modules,{'input606':types.SimpleNamespace(prepare=prepare)}),patch.object(sys,'argv',[str(root/'native.py'),*tail]),contextlib.redirect_stdout(io.StringIO()):
   if missing:
    try:n.main()
    except AttributeError as e:
     assert 'absolute' in str(e)and not calls;return
    raise AssertionError('original PRIMARY must fail before native.run')
   assert n.main()==0
   assert calls[0][0]=='prepare'and calls[0][1][-1]==Path(env['GITHUB_WORKSPACE'])/'apps8-inputs'
   actual=json.loads((state/'actual-invocation.json').read_bytes())
   assert actual['argv']==tail and tail[-2:]==['--apps8',str(Path(env['GITHUB_WORKSPACE'])/'apps8-inputs')]
   assert calls[1][0]=='emit'
   # Execute the same real native.run argument guard with a foreign Apps8 operand.
   paths=[Path(tail[tail.index('--'+flag)+1])for flag in('base','assets','carrier','tooling','bootstrap','kernel-carrier','welcome8','apps8')]
   bad=list(tail);bad[-1]+='-foreign'
   try:n.run('minimal-generic4k',state,*paths,bad)
   except ValueError as e:assert 'complete actual fixed native CLI' in str(e)
   else:raise AssertionError('foreign actual Apps8 operand accepted')

class Controls(unittest.TestCase):
 def test_exact556_emission_and_whole_ancestor_guard(self):
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'source';value=F.prepare_apps8(P,out);self.assertEqual(F.files(out),F.files(E));self.assertEqual(value['source_authority'],'a8304cecaee54141b42edd48f9482b9f4ab0700f');self.assertIsNone(value['actual_run']);self.assertEqual(value['acceptance'],'NOT_GRANTED');sys.path.insert(0,str(out));proof=load_file('_actual_emitted_Apps8_admission',out/'admission.py').prove(out);self.assertEqual(proof['files'],556)
 def test_all_historical_functions_and_authorities_byteheld(self):
  raw=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  for name,want in HELD_FUNCTIONS.items():self.assertEqual(F.pin(functions[name].encode())['sha256'],want)
  self.assertEqual(F.profile()['output']['source'],'bb72a0fc5e84af5621f0b783056137efdd780282');self.assertEqual(F.buildkit_profile()['output']['source'],'865cc33c8f114c15cef75b3472fbb8d1f4e8da06');self.assertEqual(F.loader_profile()['output']['source'],'4e63aa1c67898417d3a47335c0af1cc8e0b7fa3f')
 def test_both_emitted_workflow_CLIs_execute_actual_native_run(self):
  self.assertEqual(F.ordinary(E/PRIMARY),F.ordinary(E/NAMED))
  for name in(PRIMARY,NAMED):exercise(E,name)
 def test_isolated_actual_emitter_CLI_and_conflicting_modes(self):
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--apps8','--predecessor-root',str(P),'--output',str(t/'source')];r=subprocess.run(argv,capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(F.files(t/'source'),F.files(E))
   for flag in('--welcome8','--transport','--buildkit','--loader'):
    out=t/flag[2:];r=subprocess.run(argv[:-1]+[str(out),flag],capture_output=True,timeout=30);self.assertEqual(r.returncode,2);self.assertFalse(out.exists())
 def test_source_profile_and_template_drift_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);source=t/'source';source.mkdir();out=t/'out'
   with self.assertRaisesRegex(ValueError,'whole genuine549'):F.prepare_apps8(source,out)
   self.assertFalse(out.exists())
   for name in('apps8.json','templates/apps8/native.py'):
    factory=t/name.replace('/','-');shutil.copytree(HERE,factory);q=factory/name;q.write_bytes(q.read_bytes()+b' ');r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--apps8','--predecessor-root',str(P),'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_guest_helper_real_isolated_loader_and_readback(self):
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);share=t/'share';share.mkdir()
   for name in('current_products.py','apps8_runtime.py','apps8-installed-profile.json'):shutil.copyfile(E/'factory'/name,share/name)
   code="import importlib.util,sys;from pathlib import Path;p=Path(sys.argv[1]);s=importlib.util.spec_from_file_location('guest',p/'current_products.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);h=m._apps8_runtime();assert Path(h.__file__).parent==p;assert callable(h.observe)"
   r=subprocess.run([sys.executable,'-I','-B','-Werror','-c',code,str(share)],capture_output=True,timeout=10);self.assertEqual((r.returncode,r.stdout,r.stderr),(0,b'',b''))
   selection=F.apps8_profile()['selection']['selection'];self.assertEqual({n:F.pin(b)for n,b in F.files(I).items()},selection['files']);profile=json.loads(F.ordinary(share/'apps8-installed-profile.json'));root=t/'installed';root.mkdir();recipe=I/'recipe-source/packages/tools/cachy-asahi-apps8'
   for name,row in profile['payload'].items():
    q=root/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(F.ordinary(recipe/q.name));q.chmod(profile['modes'][name])
   for name,row in profile['runtime'].items():
    q=root/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(F.ordinary(I/'recipe-source'/name.split('repository-runtime/',1)[1]))
   helper=load_file('_actual_rooted_apps8_readback',share/'apps8_runtime.py');a=helper.observe(root);helper.validate(a,helper.observe(root));q=root/next(iter(profile['runtime']));q.write_bytes(q.read_bytes()+b' ')
   with self.assertRaises(ValueError):helper.observe(root)
   text=F.ordinary(E/'factory/current_products.py').decode();self.assertIn('installed_before=apps8_runtime.observe()',text);self.assertIn('installed_after=apps8_runtime.observe()',text);self.assertIn('timeout=35',text);self.assertEqual(json.loads(F.ordinary(E/'factory/apps8-installed-profile.json'))['inventory_limit_seconds'],30)
 def test_full_exact_source_checksums_and_fixed_scope(self):
  p=F.apps8_profile();self.assertLessEqual(F.APPS8_PROFILE['bytes'],256*1024);self.assertEqual((len(p['changed']),len(p['added'])),(11,7));self.assertEqual(p['selection']['selection']['source'],'979b2d6ec7417e607a911d8c25bef2f1f7f72dcb');self.assertEqual(p['selection']['selection']['package']['size'],23528)
  text=''.join(w['sha256']+'  '+str(E/n)+'\n'for n,w in p['output']['files'].items());r=subprocess.run(['sha256sum','--check','--status'],input=text.encode(),capture_output=True);self.assertEqual((r.returncode,r.stdout,r.stderr),(0,b'',b''))
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
