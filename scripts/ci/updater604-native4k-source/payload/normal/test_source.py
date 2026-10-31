"""Source-only native4K controls; no Docker, Git, signing or kernel actors."""
import argparse,ast,copy,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,types,unittest,uuid,zipfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import case as C,runtime as R,entry as E,retain as T,cleanup as K
p=argparse.ArgumentParser();p.add_argument('--held',type=Path,required=True);args,rest=p.parse_known_args();HELD=args.held.absolute()
def load(name,path):return C.load(name,path)
class Controls(unittest.TestCase):
 def test_01_whole_source_and_separate489_input_custody(self):
  p=C.source_context(HELD);self.assertEqual(len(p['held_files']),489);self.assertEqual(p['limits'],dict(owner=3900,stage=1200,copy=1200,driver=1860,verify=600,lifetime_cleanup=60,job_owner=15600,job=21000));self.assertIsNone(p['wrapper_run']);self.assertEqual(C.read(HERE/C.WF),C.read(HERE/C.NAMED))
 def test_02_NULL_or_foreign_identity_refuses_before_native_actor_or_Git(self):
  with patch.object(C,'native',side_effect=AssertionError('NO_NATIVE_OR_ACTOR')),patch.object(C,'git',side_effect=AssertionError('NO_GIT')):
   for source,workflow,case in((None,None,'normal'),('0'*40,'1'*40,'normal'),('0'*40,'0'*40,'precommit-exit86')):
    with self.assertRaises(ValueError):C.authenticate(HELD,source,workflow,case,{})
 def test_03_exact_current_workflow_identity_and_actual4K_readback_refusals(self):
  source='1'*40;env=dict(GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_SHA=source,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='99',GITHUB_REF='refs/heads/codex/test',GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/'+C.WF+'@refs/heads/codex/test',GITHUB_WORKFLOW='native-arm-updater604-copy4k')
  def git(root,*args):return (source if root==HERE else C.HELD)if args==('rev-parse','HEAD')else C.read(HERE/C.WF).decode().strip()if args[0]=='show'else''
  with patch.object(C,'native',return_value=dict(sysname='Linux',architecture='aarch64',kernel_release='SOURCE_CONTROL_KERNEL',page_size=4096,uid=1000,euid=1000)),patch.object(C,'git',side_effect=git):
   value=C.authenticate(HELD,source,source,'normal',env);self.assertEqual((value['source'],value['held_source'],value['page_size']),(source,C.HELD,4096))
   for key,bad in(('GITHUB_SHA','0'*40),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_WORKFLOW_REF','foreign'),('GITHUB_WORKFLOW','native-arm-build'),('GITHUB_EVENT_NAME','push')):
    with self.assertRaises(ValueError):C.authenticate(HELD,source,source,'normal',dict(env,**{key:bad}))
  with patch.object(os,'uname',return_value=types.SimpleNamespace(sysname='Linux',machine='aarch64',release='SOURCE_CONTROL_KERNEL')),patch.object(os,'getuid',return_value=1000),patch.object(os,'geteuid',return_value=1000):
   with patch.object(os,'sysconf',return_value=4096):C.native()
   with patch.object(os,'sysconf',return_value=16384),self.assertRaises(ValueError):C.native()
 def test_04_actual_caller_entry_full_body_inverse_and_4K_Docker_only(self):
  c,w,a=C.apis(HELD);raw=C.read(HELD/'scripts/ci/full-root-upgrade-caller/container.py');before=a.caller(raw);after=R.native_caller(before);self.assertEqual(after.replace(R.PREDICATE4.encode(),R.PREDICATE16.encode(),1),before);self.assertIn(b'signature_failure(args, proc)',after);self.assertIn(b'--noscriptlet',after)
  expression=R.PREDICATE4.removeprefix('and ');scope={'os':types.SimpleNamespace(geteuid=lambda:0,sysconf=lambda n:4096),'Path':lambda n:types.SimpleNamespace(is_file=lambda:True)};self.assertTrue(eval(expression,scope));scope['os'].sysconf=lambda n:16384;self.assertFalse(eval(expression,scope));scope['os'].sysconf=lambda n:4096;scope['Path']=lambda n:types.SimpleNamespace(is_file=lambda:False);self.assertFalse(eval(expression,scope))
  with self.assertRaises(ValueError):R.native_caller(after)
 def test_05_real_prepare_repin_keeps_all_clocks_and_protections(self):
  c,w,a=C.apis(HELD);old=types.SimpleNamespace(scoped=lambda *x:None,read=lambda p:C.obj(p),encoded=C.enc);raw=a.caller(C.read(HELD/'scripts/ci/full-root-upgrade-caller/container.py'))
  with tempfile.TemporaryDirectory()as td:
   target=Path(td)/'candidate';target.mkdir();calling=Path(td)/'calling';calling.mkdir();(calling/'container.py').write_bytes(raw);config=target/'config.json';name='scripts/ci/full-root-upgrade-caller/container.py';original=dict(stage_seconds=1200,copy_seconds=1200,driver_seconds=1860,verify_seconds=600,code_pins={name:C.pin(raw)['sha256'],'held':'0'*64},crypto='HELD',scale={'before':604});config.write_bytes(C.enc(original));(target/'adapter.json').write_bytes(C.enc(dict(config_sha256=C.pin(C.read(config))['sha256'],updater16k_dispatch={'source_only':'HELD_ORIGINAL_PREPARATION'})))
   with patch.object(a,'prepare_selected',return_value=(config,calling)):R.preparation(HELD,old,a,HELD,target,'normal')
   final=C.obj(config);self.assertEqual({k:v for k,v in final.items()if k!='code_pins'},{k:v for k,v in original.items()if k!='code_pins'});self.assertEqual(final['code_pins']['held'],original['code_pins']['held']);self.assertEqual(final['code_pins'][name],C.pin(C.read(calling/'container.py'))['sha256']);self.assertEqual(C.obj(target/'adapter.json')['native4k_entry']['held_source'],C.HELD)
 def test_06_whole_owner_runtime_dispatch_never_uses_VM_rewrite(self):
  calls=[];old=types.SimpleNamespace(scoped=lambda name,path,aliases:types.SimpleNamespace(main=lambda argv:calls.append((path,argv))or 17));w=types.SimpleNamespace(authorize=lambda *x:(old,{},{}),old_gate=lambda *x:object());a=types.SimpleNamespace(owner=lambda *x:(_ for _ in()).throw(AssertionError('NO_VM_ROUTE')))
  with patch.object(C,'apis',return_value=(None,w,a)):self.assertEqual(R.execute(HELD,['held-original-argv']),17)
  self.assertEqual(calls,[(HELD/C.OLD/'run.py',['held-original-argv'])]);self.assertEqual(R.policy_owner_pin(HELD),C.pin(C.read(HELD/C.OLD/'run.py')))
 def test_07_whole_original_owner_reaches_original_Docker_boundary_with3900(self):
  raw=C.read(HELD/C.OLD/'run.py');tree=ast.parse(C.read(HELD/C.OLD/'contract.py'));inputs=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='INPUTS'for t in n.targets));events=[];token=uuid.uuid4().hex;output=Path('/tmp')/('native4k-source-control-'+token);producer=output.with_name(output.name+'-producer')
  self.addCleanup(lambda:shutil.rmtree(output)if output.exists()else None);self.addCleanup(lambda:shutil.rmtree(producer)if producer.exists()else None)
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);dummy=base/'input';dummy.mkdir();public=producer/'public';private=producer/'private'
   def prepare(producer_api,a):
    public.mkdir(parents=True);(private/'desktop574').mkdir(parents=True);(private/'desktop574/image-id').write_text('CONTROL_NO_REAL_IMAGE');(producer/'producer-owner.json').write_text('{}');return private,{}
   def selected(source,target,case):
    target.mkdir();(target/'adapter.json').write_text('{}');calling=base/'calling';calling.mkdir();return target/'configuration',calling
   footprint=types.SimpleNamespace(prepare=lambda *x:events.append('footprint-prepare'),volume_present=lambda n:[],create_volume=lambda n:events.append('volume-boundary-inert'))
   class BoundaryStop(Exception):pass
   def command(argv,path,seconds):events.append(('Docker-command',argv[-5:],seconds));raise BoundaryStop('CONTROL_INERT_ACTOR_BOUNDARY_NOT_NATIVE')
   def retire(owned,result):result['upgrade_volume_cleanup']='PASS-absence-verified';events.append('retirement-boundary-inert');return[]
   owner_api=types.SimpleNamespace(container_args=lambda *x:['CONTROL_NO_DOCKER'],command=command,retire_outer=retire)
   producer_api=types.SimpleNamespace(cleanup=lambda *x:dict(status='PASS'))
   def modules(name,path):
    if name=='_root604_producer':return producer_api
    if name=='apps6_pair_stage':return types.SimpleNamespace(stage=lambda *x:output/'apps6')
    if name=='_root604_constructor':return types.SimpleNamespace(inspect_package=lambda *x:events.append('constructor-boundary-inert'))
    if name=='_root604_original_owner':return owner_api
    if name=='_root604_volume_owner':return footprint
    raise AssertionError(name)
   fake=types.SimpleNamespace(HERE=HELD/C.OLD,BEFORE='CONTROL_BEFORE',AFTER='CONTROL_AFTER',INPUTS=inputs,SOURCES={'normal':'held'},policy=lambda:dict(apps6={}),safe=lambda p:p,load=modules,encoded=C.enc,read=lambda p:C.obj(p),need=C.need,old600=lambda:(None,types.SimpleNamespace(prepare_with_plan=prepare)))
   gate=types.SimpleNamespace(own_source=lambda *x:events.append('source-gate-inert'),inputs=lambda *x:(types.SimpleNamespace(LEGACY='CONTROL',COMPOSITION='CONTROL_NO_COMPOSITION_ACTOR'),types.SimpleNamespace(prepare=lambda *x:None),{}, {},{}));cache=types.SimpleNamespace(bind=lambda *x:None,flat_inputs=lambda *x:{});adapter=types.SimpleNamespace(prepare=selected)
   with patch.dict(sys.modules,contract=fake,adapter=adapter,gate=gate,before_cache=cache):
    ns={'__name__':'_whole_original_owner_control','__file__':str(HELD/C.OLD/'run.py')};exec(compile(raw,ns['__file__'],'exec'),ns)
   names=('implementation','installer-source','decision-source','upgrader-source','baseline-source','baseline-decisions-source','preparation-source','product','updater','desktop','updater-v2-source','native','fdk','cache','setup4-pair',*(n.replace('_','-')for n in inputs),'audio-inputs');argv=[piece for n in names for piece in('--'+n,str(dummy))]+['--output',str(output),'--case','normal','--implementation-revision',C.HELD]
   with patch.object(ns['platform'],'machine',return_value='aarch64'),patch.object(os,'getuid',return_value=1000),patch.object(os,'geteuid',return_value=1000),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTOR_GIT_API')):rc=ns['main'](argv)
   self.assertEqual(rc,1);result=C.obj(output/'result.json');self.assertEqual(result['error_type'],'BoundaryStop',result);self.assertEqual(result['status'],'FAIL');self.assertEqual(result['source'],C.HELD);row=next(e for e in events if isinstance(e,tuple));self.assertEqual(row[2],3900);self.assertEqual(row[1],['--entrypoint=/usr/bin/python3','CONTROL_NO_REAL_IMAGE','-I','-B','/runner.py']);self.assertIn('retirement-boundary-inert',events)
 def test_08_public_retention_fixed_original_roles_and_alias_refusal(self):
  run=int('9'+str(os.getpid()));source=Path('/tmp')/('cachy-asahi-updater604-copy4k-'+str(run)+'-1-normal');source.mkdir(mode=0o700);self.addCleanup(lambda:shutil.rmtree(source)if source.exists()else None);(source/'result.json').write_text('{"status":"CONTROL_FAIL_NOT_NATIVE"}\n');proof=dict(run=run,attempt=1,source='1'*40)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);cleanup=root/'cleanup.json';cleanup.write_text('{"status":"CONTROL_NOT_CREATED"}\n');out=root/'public';v=T.retain(source,out,proof,cleanup);self.assertEqual(v['files'],3)
   with zipfile.ZipFile(out/'evidence.zip')as z:self.assertIsNone(z.testzip());self.assertEqual(set(z.namelist()),{'result.json','job-cleanup.json','retention.json'})
   with self.assertRaises(ValueError):T.retain(source,out,proof,cleanup)
   (source/'result.json').unlink();(source/'result.json').symlink_to(cleanup)
   with self.assertRaises(ValueError):T.retain(source,root/'bad',proof,cleanup)
 def test_09_cleanup_unknown_group_keeps_home_and_config(self):
  run=int('8'+str(os.getpid()));output=Path('/tmp')/('cachy-asahi-updater604-copy4k-'+str(run)+'-1-normal');home=output.with_name(output.name+'-job-home');config=output.with_name(output.name+'-docker-config');home.mkdir(mode=0o700);config.mkdir(mode=0o700);self.addCleanup(lambda:shutil.rmtree(home)if home.exists()else None);self.addCleanup(lambda:shutil.rmtree(config)if config.exists()else None);(home/'child.json').write_bytes(C.enc(dict(status='WAIT_RETURNED',source='1'*40,case='normal',child=dict(group_absence_verified=False))))
  with self.assertRaisesRegex(ValueError,'group unknown'):K.cleanup(HELD,output,dict(run=run,source='1'*40))
  self.assertTrue(home.exists());self.assertTrue(config.exists())
 def test_11_real_original_config_retirement_body_and_source_preservation(self):
  run=int('7'+str(os.getpid()));output=Path('/tmp')/('cachy-asahi-updater604-copy4k-'+str(run)+'-1-normal');output.mkdir(mode=0o700);home=output.with_name(output.name+'-job-home');config=output.with_name(output.name+'-docker-config');home.mkdir(mode=0o700);config.mkdir(mode=0o700)
  for directory in(output,home,config):self.addCleanup(lambda p=directory:shutil.rmtree(p)if p.exists()else None)
  proof=dict(source='1'*40,run=run);info=config.stat();child=dict(status='WAIT_RETURNED',source=proof['source'],case='normal',child=dict(group_absence_verified=True),docker_config=dict(path=str(config),identity=[info.st_dev,info.st_ino],source=proof['source'],case='normal'));(home/'child.json').write_bytes(C.enc(child));(config/'config.json').write_text('{}');(output/'owner.json').write_bytes(C.enc(dict(purpose='expanded604-apps6-public-pair-updater',output=str(output),case='normal')));(output/'result.json').write_bytes(C.enc(dict(status='CONTROL_FAILED_NOT_A_NATIVE_PASS',source=C.HELD,producer_cleanup='PASS',outer_cleanup='PASS',caller_private_cleanup='PASS')));(output/'wiring-owner.json').write_bytes(C.enc(dict(wrapper=proof,child=dict(group_absence_verified=True))));before=C.read(output/'result.json')
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_NATIVE_API_GIT')):value=K.cleanup(HELD,output,proof)
  self.assertEqual(value['status'],'PASS_ORIGINAL_OWNED_JOB_HOME_AND_CONFIG_REMOVED');self.assertFalse(home.exists());self.assertFalse(config.exists());self.assertEqual(C.read(output/'result.json'),before)
 def test_10_source_drift_and_isolated_CLI_help(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';shutil.copytree(HERE,root);(root/'runtime.py').write_bytes((root/'runtime.py').read_bytes()+b'drift');bad=load('_bad_wrapper_case',root/'case.py')
   with self.assertRaises(ValueError):bad.source_context(HELD)
  for name in('entry.py','retain.py','cleanup.py'):
   r=subprocess.run([sys.executable,'-I','-B',str(HERE/name),'--help'],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'usage:',r.stdout)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
