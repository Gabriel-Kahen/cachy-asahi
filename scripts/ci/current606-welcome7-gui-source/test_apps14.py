# SPDX-License-Identifier: MIT
"""Actual portable opt-in559 emission and finite source CLI/diagnostic controls."""
import argparse,ast,base64,contextlib,copy,importlib.util,io,json,os,shlex,shutil,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;p=argparse.ArgumentParser()
for n in('parent','expected','carrier','recipe','native','old-parent','old-expected'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();ARGS={k:v.absolute()for k,v in vars(a).items()};PARENT,EXPECTED,CARRIER,RECIPE,NATIVE,OLD,OLD_EXPECTED=(ARGS[n]for n in('parent','expected','carrier','recipe','native','old_parent','old_expected'));sys.dont_write_bytecode=True
def load(name,path):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_maintained_GUI559_factory',HERE/'prepare.py');M=load('_maintained_GUI559_option',HERE/'apps14.py');PROFILE,MAPS,_=M.inputs(F.__dict__)
def shell_blocks(raw):
 # Extract only the three exact run encodings in this whole-hash-pinned workflow.
 lines=raw.decode().splitlines();out=[]
 for index,line in enumerate(lines):
  text=line.strip()
  if text.startswith('"run": "'):out.append(json.loads('{'+text+'}')['run']);continue
  if text.startswith('"run": '):text='run: '+text[len('"run": '):]
  if text not in('run: |','run: >-'):continue
  indent=len(line)-len(line.lstrip());body=[]
  for following in lines[index+1:]:
   if following.strip()and len(following)-len(following.lstrip())<=indent:break
   body.append(following[indent+2:]if following.strip()else'')
  out.append((' '.join(body)if text=='run: >-'else'\n'.join(body))+'\n')
 return out
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.bound=cls.root/'gui606-source';cls.null=cls.root/'null';F.prepare_apps14_stage(PARENT,cls.bound);F.prepare_apps14_stage(PARENT,cls.null,True);shutil.copytree(CARRIER,cls.root/'apps14-inputs',ignore=shutil.ignore_patterns('.git'));cls.C=load('_selected_Apps14_common',cls.bound/'apps14_common.py')
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_exact_isolated_CLI_whole559_and_genuine_five_fixture_custody(self):
  self.assertEqual({n:F.pin(b)for n,b in F.files(self.bound).items()},MAPS['selected']);self.assertEqual({n:F.pin(b)for n,b in F.files(EXPECTED).items()},MAPS['selected'])
  for key,path in [('parent',PARENT),('output',EXPECTED),('carrier',CARRIER),('recipe',RECIPE),('native',NATIVE)]:self.assertEqual({n:F.pin(b)for n,b in F.files(path).items()},PROFILE['custody'][key]['git']['files'])
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--apps14-stage','--predecessor-root',str(PARENT),'--output',str(out)];r=subprocess.run(argv,capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['source'],'803ed9c5c0357162ef9868bf6f82d37936ba7842');self.assertEqual(F.files(out),F.files(self.bound));r=subprocess.run(argv,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertEqual(F.files(out),F.files(self.bound))
 def test_every_old_function_unchanged_and_actual_old_Apps9_emit(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in PROFILE['held_functions'].items():self.assertEqual(F.pin(functions[n].encode()),w,n)
  self.assertEqual(F.profile()['output']['source'],'bb72a0fc5e84af5621f0b783056137efdd780282')
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'old';F.prepare_apps10_stage(OLD,out);self.assertEqual(F.files(out),F.files(OLD_EXPECTED))
 def test_actual_NULL_and_bound_source_guards_before_actors(self):
  A=load('_bound559_admission',self.bound/'admission.py');N=load('_null559_admission',self.null/'admission.py')
  with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS_API_GIT')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):
   fact=A.prove(self.bound);self.assertEqual((fact['files'],fact['Apps14_inputs'],fact['native_GUI']),(559,'ROOT_BOUND_INPUT_ONLY','NOT_RUN'))
   with self.assertRaisesRegex(ValueError,'BEFORE ACTORS'):N.prove(self.null)
  self.assertEqual({n:F.pin(b)for n,b in F.files(self.null).items()},MAPS['unbound']);r=subprocess.run([sys.executable,'-I','-B',str(self.bound/'native.py'),'preflight'],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['files'],559)
 def test_both_registered_aliases_actual_native_main_all_four_cases(self):
  self.assertEqual((self.bound/M.WF).read_bytes(),(self.bound/M.ALIAS).read_bytes())
  for role in(M.WF,M.ALIAS):
   blocks=shell_blocks((self.bound/role).read_bytes());self.assertGreater(len(blocks),10);command=next(b for b in blocks if '"$CURRENT" run --case'in b)
   for body in blocks:
    r=subprocess.run(['bash','-n'],input=body.encode(),capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
   for profile in('minimal','overlay'):
    for mode in('generic4k','generic16k'):
     with tempfile.TemporaryDirectory()as td:
      root=Path(td);state=root/'state';state.mkdir();(state/'source-proof.json').write_text('{}');case=profile+'-'+mode;env=dict(GITHUB_WORKSPACE=str(root/'workspace'),RUNNER_TEMP=str(root/'temp'),STATE=str(state),PROFILE=profile,CASE=case,CURRENT=str(self.bound/'native.py'))
      with patch.dict(os.environ,env):words=shlex.split(os.path.expandvars(command))
      tail=words[words.index(str(self.bound/'native.py'))+1:];n=load('_actual_native559_cli',self.bound/'native.py');calls=[]
      def prepare(*args):calls.append(args);return dict(status='INERT_INPUT_BOUNDARY_NOT_NATIVE_ACCEPTANCE')
      def emit(*args):args[3].mkdir();(args[3]/'current606-proof.json').write_text('{}')
      with patch.object(n.A,'prove',return_value={}),patch.object(n,'binding',return_value=dict(owner_deadline=time.monotonic()+5,profile=profile,mode=mode,source='803ed9c5c0357162ef9868bf6f82d37936ba7842',run=1,attempt=1,job_token='0'*16)),patch.object(n,'factory',return_value=types.SimpleNamespace(emit=emit)),patch.object(n,'load',return_value=types.SimpleNamespace(run=lambda *_:dict(status='INERT_OWNER_NOT_NATIVE_ACCEPTANCE'),prove=lambda *_:dict(tree=n.A.obj(n.ROOT/'kernel-media-profile.json')['tree']))),patch.dict(sys.modules,{'input606':types.SimpleNamespace(prepare=prepare)}),patch.object(sys,'argv',[str(self.bound/'native.py'),*tail]),contextlib.redirect_stdout(io.StringIO()):
       self.assertEqual(n.main(),0);self.assertEqual(calls[0][-1],Path(env['GITHUB_WORKSPACE'])/'apps14-inputs');self.assertEqual(tail[-2:],['--apps14',str(Path(env['GITHUB_WORKSPACE'])/'apps14-inputs')]);self.assertEqual(json.loads((state/'actual-invocation.json').read_bytes())['argv'],tail);paths=[Path(tail[tail.index('--'+f)+1])for f in('base','assets','carrier','tooling','bootstrap','kernel-carrier','welcome8','apps14')];bad=list(tail);bad[-1]+='-foreign'
       with self.assertRaisesRegex(ValueError,'complete actual fixed native CLI'):n.run(case,state,*paths,bad)
 def test_six_actual_emitted_diagnostic_source_controls(self):
  r=subprocess.run([sys.executable,'-I','-B','-Werror',str(self.bound/'apps14_common.py')],capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'Ran 6 tests',r.stderr);self.assertTrue(r.stderr.endswith(b'\nOK\n'))
 def test_whole559_inverse_other32_inputs_605_versions_clocks_and_checksums(self):
  before=F.files(PARENT);after=F.files(self.bound);self.assertEqual(sum(n in after and b==after[n]for n,b in before.items()),539);parent=self.C.obj(self.bound/'apps14-parent.json');self.assertEqual(parent['files'],MAPS['before'])
  for n,body in parent['before_bodies'].items():self.assertEqual(base64.b64decode(body,validate=True),before[n])
  old=self.C.obj(PARENT/'input-policy33.json')['packages'];new=self.C.obj(self.bound/'input-policy33.json')['packages'];self.assertEqual({n:v for n,v in old.items()if n!='cachy-asahi-apps'},{n:v for n,v in new.items()if n!='cachy-asahi-apps'})
  for n in('factory/run.py','factory/context606.py','bootstrap2.py','factory/kernel_stage.py','factory/hwcap_probe.c','factory/user_hwcap.py','factory/welcome8_stop.py'):self.assertEqual(before[n],after[n])
  p=self.C.obj(self.bound/'factory/apps14-installed-profile.json');self.assertEqual((p['GUI_command_limit_seconds'],p['inventory_limit_seconds'],p['required_fresh_scans']),(35,30,2));lock=self.C.pin(after['factory/expected606.lock'])['sha256'];self.assertIn(lock.encode(),after['factory/install606.py']);self.assertIn(b'gui/guest.log',after['transport.py']);self.assertIn(b'--diagnostic-stage',after['factory/current_products.py']);self.assertIn(b'CURRENT606_APPS14_STAGE_FAILURE_DATA',after['factory/current_products.py'])
  checks=''.join(F.pin(b)['sha256']+'  '+str(self.bound/n)+'\n'for n,b in after.items());r=subprocess.run(['sha256sum','--check','--status'],input=checks.encode(),capture_output=True,timeout=30);self.assertEqual((r.returncode,r.stdout,r.stderr),(0,b'',b''))
 def test_profile_payload_parent_and_output_alias_drift_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory)
   for name in('apps14-profile.json','apps14-maps.json','apps14-payload/factory/apps14_diagnostic.py'):
    leaf=factory/name;raw=leaf.read_bytes();leaf.write_bytes(raw+b'drift')
    with patch.object(M,'HERE',factory),self.assertRaises(ValueError):M.emit(F.__dict__,PARENT,root/'absent')
    self.assertFalse((root/'absent').exists());leaf.write_bytes(raw)
   parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));leaf=parent/'native.py';leaf.write_bytes(leaf.read_bytes()+b'drift')
   with self.assertRaises(ValueError):F.prepare_apps14_stage(parent,root/'bad-parent')
   alias=root/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   with self.assertRaises(ValueError):F.prepare_apps14_stage(alias,root/'bad-alias')
   self.assertFalse((root/'bad-parent').exists());self.assertFalse((root/'bad-alias').exists())
   for parent,out in [(PARENT,root/'missing/../escaped'),(PARENT/'missing/..',root/'bad-spelling'),(PARENT,PARENT/'new-child')]:
    with self.assertRaises(ValueError):F.prepare_apps14_stage(parent,out)
   self.assertFalse((root/'escaped').exists());self.assertFalse((root/'bad-spelling').exists());self.assertFalse((PARENT/'new-child').exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
