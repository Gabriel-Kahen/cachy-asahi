"""Actual recovery routing and held-body controls; no native actors or acceptance."""
import argparse,ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest,uuid,zipfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import case as C,runtime as R,entry as E,cleanup as K,retain as T
p=argparse.ArgumentParser();p.add_argument('--held',type=Path,required=True);p.add_argument('--decisions',type=Path,required=True);args,rest=p.parse_known_args();HELD=args.held.absolute();DECISIONS=args.decisions.absolute()
def noactor(*a,**kw):raise AssertionError('NO_NATIVE_API_GIT_SIGNING')
def verify():
 raw=C.read(HELD/C.OLD/'run.py').decode();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='verify_result');text=ast.get_source_segment(raw,node);space={'C':types.SimpleNamespace(need=C.need,BEFORE='held-before')};exec(compile(text,'<whole-held-verify_result>','exec'),space);return space['verify_result']
def result(case):
 truth={'precommit-exit86':(0,False,False,False),'postcommit-exit87':(1,True,True,False)}[case]
 driver=dict(status='PASS',copy_cleanup='PASS-owned-workspace-removed',case=case,failure_cases=1,original_source_preserved=True,**dict(zip(('committed_transactions','commit_started','packages_committed','checkpoint_changed'),truth)))
 if case=='postcommit-exit87':driver.update(after604_database_verified=True,postcommit_payload_verified=True,postcommit_preservation_verified=True)
 return dict(status='PASS',package_count=604,final_package_count=604,installed_inventory_sha256='held-before',final_inventory_sha256='held-before',dependency_checks='PASS-no-waivers',payload_ownership='PASS',full_root_upgrade=dict(status='PASS',persistent_source_preserved=True,persistent_source=dict(source_manifest_sha256='fresh-equal'),persistent_source_after=dict(source_manifest_sha256='fresh-equal'),driver=driver))
class Controls(unittest.TestCase):
 def test_01_complete_custody_NULL_and_original_per_case_clocks(self):
  p=C.source_context(HELD);self.assertEqual(p['cases'],list(C.CASES));self.assertEqual(p['limits'],dict(owner=3900,stage=1200,copy=1200,driver=2400,verify=600,lifetime_cleanup=60,job_owner=15600,job=21000));self.assertEqual(len(p['held_files']),489);self.assertEqual(p['normal_wrapper_parent']['source'],'94297073ac36f257edd118aceba3e375a7148550');self.assertEqual(len(p['normal_wrapper_parent']['files']),10);self.assertEqual(p['normal_wrapper_parent']['git']['files'],p['normal_wrapper_parent']['files']);self.assertEqual(p['normal_wrapper_parent']['acceptance'],'NOT_TRANSFERRED');self.assertTrue(all(p[k]is None for k in('wrapper_source','wrapper_ref','wrapper_run')))
 def test_02_exact_current_metadata_and_native4K_before_actors(self):
  with patch.object(C,'native',side_effect=noactor),patch.object(C,'git',side_effect=noactor):
   for source,workflow,case in[(None,None,C.CASES[0]),('0'*40,'1'*40,C.CASES[1]),('0'*40,'0'*40,'normal')]:
    with self.assertRaises(ValueError):C.authenticate(HELD,source,workflow,case,{})
  source='1'*40;env=dict(GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_SHA=source,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='99',GITHUB_REF='refs/heads/codex/control',GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/'+C.WF+'@refs/heads/codex/control',GITHUB_WORKFLOW='native-arm-updater604-recovery4k')
  def git(root,*args):return(source if root==HERE else C.HELD)if args==('rev-parse','HEAD')else C.read(HERE/C.WF).decode().strip()if args[0]=='show'else''
  with patch.object(C,'native',return_value=dict(page_size=4096,architecture='aarch64',kernel_release='CONTROL_READBACK')),patch.object(C,'git',side_effect=git):
   for case in C.CASES:self.assertEqual(C.authenticate(HELD,source,source,case,env)['case'],case)
   for key,bad in [('GITHUB_SHA','0'*40),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_WORKFLOW','native-arm-updater604-copy4k'),('GITHUB_WORKFLOW_REF','old16K'),('GITHUB_REPOSITORY','foreign')]:
    with self.assertRaises(ValueError):C.authenticate(HELD,source,source,C.CASES[0],dict(env,**{key:bad}))
  with patch.object(os,'uname',return_value=types.SimpleNamespace(sysname='Linux',machine='aarch64',release='CONTROL_READBACK')),patch.object(os,'getuid',return_value=1000),patch.object(os,'geteuid',return_value=1000):
   with patch.object(os,'sysconf',return_value=4096):self.assertEqual(C.native()['page_size'],4096)
   with patch.object(os,'sysconf',return_value=16384),self.assertRaises(ValueError):C.native()
 def test_03_real_selected_case_reaches_whole_owner_and_never_VM_adapter(self):
  events=[];old=types.SimpleNamespace(scoped=lambda name,path,aliases:types.SimpleNamespace(main=lambda argv:events.append(('owner',path,argv))or 13))
  w=types.SimpleNamespace(authorize=lambda *a:events.append(('authorize',a[-1]))or(old,{},{}),old_gate=lambda *a:object());a=types.SimpleNamespace(owner=noactor)
  with patch.object(C,'apis',return_value=(None,w,a)),patch.object(subprocess,'Popen',side_effect=noactor):
   for case in C.CASES:
    argv=['--case',case,'--implementation-revision',C.HELD];self.assertEqual(R.execute(HELD,argv),13);self.assertEqual(events[-2],('authorize',case));self.assertEqual(events[-1],('owner',HELD/C.OLD/'run.py',argv))
   for argv in([],['--case','normal'],['--case',C.CASES[0],'--case',C.CASES[1]]):
    with self.assertRaises(ValueError):R.execute(HELD,argv)
  self.assertEqual(R.policy_owner_pin(HELD),C.pin(C.read(HELD/C.OLD/'run.py')))
 def test_04_actual_two_case_preparation_only_native4K_predicate_and_config_pin_change(self):
  _,_,a=C.apis(HELD);old=C.load('_recovery_actual_old_contract',HELD/C.OLD/'contract.py');scoped=old.scoped;prepare=a.prepare_selected;fixtures={'scripts/ci/full-root-upgrade-caller/upgrade-config.json':'normal-upgrade-config.json','scripts/ci/full-root-failed-update/lane-config.json':'precommit-lane-config.json','scripts/install/local_transaction.py':'local_transaction.py'}
  with tempfile.TemporaryDirectory()as td:
   base=Path(td)
   for case in C.CASES:
    source=base/('source-'+case);source.mkdir()
    pins=C.obj(HELD/'scripts/ci/expanded600-root-upgrade/held-pins.json')[case]['pins']
    for name,w in pins.items():
     p=HELD/name
     if not p.is_file()or C.pin(C.read(p))!=w:p=HELD/C.OLD/'fixtures'/fixtures[name]
     self.assertEqual(C.pin(C.read(p)),w);target=source/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(C.read(p))
    def selected(name,path,aliases):
     module=scoped(name,path,aliases);held_prepare=module.prepare
     if name=='_native4k_original_adapter':module.prepare=lambda source,target,selected_case:held_prepare(source,target,selected_case,git=False,implementation=HELD)
     return module
    captured={}
    def real_prepare(*args,**kw):
     config,calling=prepare(*args,**kw);captured.update(config=C.obj(config),caller=C.read(calling/'container.py'));return config,calling
    with patch.object(old,'scoped',side_effect=selected),patch.object(a,'prepare_selected',side_effect=real_prepare),patch.object(subprocess,'Popen',side_effect=noactor):config,calling=R.preparation(HELD,old,a,source,base/('candidate-'+case),case)
    value=C.obj(config);before=captured['config'];name='scripts/ci/full-root-upgrade-caller/container.py';self.assertEqual(C.read(calling/'container.py').replace(R.PREDICATE4.encode(),R.PREDICATE16.encode(),1),captured['caller']);self.assertEqual({k:v for k,v in value.items()if k!='code_pins'},{k:v for k,v in before.items()if k!='code_pins'});self.assertEqual({n:w for n,w in value['code_pins'].items()if n!=name},{n:w for n,w in before['code_pins'].items()if n!=name});self.assertEqual([value[k]for k in('stage_seconds','copy_seconds','driver_seconds','verify_seconds')],[1200,1200,2400,600]);self.assertEqual(value['code_pins'][name],C.pin(C.read(calling/'container.py'))['sha256']);self.assertIn(b'signature_failure(args, proc)',C.read(calling/'container.py'));self.assertIn(b'--noscriptlet',C.read(calling/'container.py'))
 def test_05_whole_original_recovery_truth_preservation_and_retirement_refusals(self):
  check=verify()
  for case in C.CASES:
   row=result(case);self.assertIs(check(row,case),row['full_root_upgrade'])
   for key,bad in [('committed_transactions',True),('checkpoint_changed',True),('original_source_preserved',False),('copy_cleanup','UNKNOWN'),('failure_cases',2),('case','normal')]:
    changed=copy.deepcopy(row);changed['full_root_upgrade']['driver'][key]=bad
    with self.assertRaises(ValueError):check(changed,case)
   for key,bad in [('package_count',603),('final_inventory_sha256','foreign'),('dependency_checks','SKIPPED'),('payload_ownership','UNKNOWN')]:
    with self.assertRaises(ValueError):check(dict(row,**{key:bad}),case)
   changed=copy.deepcopy(row);changed['full_root_upgrade']['persistent_source_after']['source_manifest_sha256']='changed'
   with self.assertRaises(ValueError):check(changed,case)
  for key in('after604_database_verified','postcommit_payload_verified','postcommit_preservation_verified'):
   row=result(C.CASES[1]);row['full_root_upgrade']['driver'][key]=False
   with self.assertRaises(ValueError):check(row,C.CASES[1])
 def test_06_all_three_original_prior_decisions_still_mandatory_per_case(self):
  calls=[];old=types.SimpleNamespace();binding={'decision_carrier_source':'HELD_THREE'};contract=types.SimpleNamespace(accepted=lambda *a:calls.append(('full-three',a[1])));gate=types.SimpleNamespace(main=lambda argv:calls.append(('gate',argv))or 0);w=types.SimpleNamespace(authorize=lambda *a:calls.append(('selected',a[-1]))or(old,{},binding),old_gate=lambda *a:gate)
  with patch.object(C,'apis',return_value=(contract,w,None)),patch.object(subprocess,'Popen',side_effect=noactor):
   for case in C.CASES:
    args=['--case',case,'--source','1'*40,'--workflow-sha','1'*40,'--updater-decisions','/fixed-prior-data'];E.prerequisites(HELD,'decisions',args);self.assertIn(('selected',case),calls);self.assertIn(('full-three',Path('/fixed-prior-data')),calls);forward=calls[-1][1];self.assertEqual(forward[forward.index('--case')+1],case);self.assertEqual(forward[forward.index('--source')+1],C.HELD);self.assertNotIn('--updater-decisions',forward)
    with self.assertRaisesRegex(ValueError,'three original'):E.prerequisites(HELD,'decisions',['--case',case])
 def test_07_public_zip_fixed_roles_case_paths_and_symlink_refusal(self):
  for case in C.CASES:
   run=int('9'+str(os.getpid()));source=Path('/tmp')/f'cachy-asahi-updater604-recovery4k-{run}-1-{case}';source.mkdir(mode=0o700);self.addCleanup(lambda p=source:shutil.rmtree(p)if p.exists()else None);(source/'result.json').write_text('{"status":"CONTROL_FAILED_NOT_NATIVE"}');proof=dict(source='1'*40,run=run,attempt=1,case=case)
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);cleanup=root/'cleanup.json';cleanup.write_text('{}');out=root/'retained';v=T.retain(source,out,proof,cleanup);self.assertEqual(v['files'],3)
    with zipfile.ZipFile(out/'evidence.zip')as z:self.assertIsNone(z.testzip());self.assertEqual(set(z.namelist()),{'result.json','job-cleanup.json','retention.json'})
    with self.assertRaises(ValueError):T.retain(source,root/'foreign',dict(proof,case='normal'),cleanup)
    (source/'result.json').unlink();(source/'result.json').symlink_to(cleanup)
    with self.assertRaises(ValueError):T.retain(source,root/'alias',proof,cleanup)
 def test_08_actual_original_config_retirement_both_cases_and_unknown_group_refuses(self):
  for case in C.CASES:
   run=int('8'+str(os.getpid()));output=Path('/tmp')/f'cachy-asahi-updater604-recovery4k-{run}-1-{case}';output.mkdir(mode=0o700);home=output.with_name(output.name+'-job-home');config=output.with_name(output.name+'-docker-config');home.mkdir(mode=0o700);config.mkdir(mode=0o700)
   for p in(output,home,config):self.addCleanup(lambda p=p:shutil.rmtree(p)if p.exists()else None)
   proof=dict(source='1'*40,run=run,case=case);info=config.stat();child=dict(status='WAIT_RETURNED',source=proof['source'],case=case,child=dict(group_absence_verified=False),docker_config=dict(path=str(config),identity=[info.st_dev,info.st_ino],source=proof['source'],case=case));(home/'child.json').write_bytes(C.enc(child));(config/'config.json').write_text('{}')
   with self.assertRaisesRegex(ValueError,'group unknown'):K.cleanup(HELD,output,proof)
   self.assertTrue(home.exists());self.assertTrue(config.exists());child['child']['group_absence_verified']=True;(home/'child.json').write_bytes(C.enc(child));(output/'owner.json').write_bytes(C.enc(dict(purpose='expanded604-apps6-public-pair-updater',output=str(output),case=case)));(output/'result.json').write_bytes(C.enc(dict(status='CONTROL_FAILED_NOT_NATIVE',source=C.HELD,producer_cleanup='PASS',outer_cleanup='PASS',caller_private_cleanup='PASS')));(output/'wiring-owner.json').write_bytes(C.enc(dict(wrapper=proof,child=dict(group_absence_verified=True))));before=C.read(output/'result.json')
   with patch.object(subprocess,'Popen',side_effect=noactor):v=K.cleanup(HELD,output,proof)
   self.assertEqual(v['status'],'PASS_ORIGINAL_OWNED_JOB_HOME_AND_CONFIG_REMOVED');self.assertFalse(home.exists());self.assertFalse(config.exists());self.assertEqual(C.read(output/'result.json'),before)
 def test_09_source_drift_closed_aliases_and_isolated_CLI(self):
  with tempfile.TemporaryDirectory()as td:
   source=Path(td)/'source';shutil.copytree(HERE,source);(source/'runtime.py').write_bytes((source/'runtime.py').read_bytes()+b'drift');bad=C.load('_recovery_drift',source/'case.py')
   with self.assertRaises(ValueError):bad.source_context(HELD)
  for n in('entry.py','retain.py','cleanup.py'):
   r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/n),'--help'],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'usage:',r.stdout)
  self.assertEqual(C.read(HERE/C.WF),C.read(HERE/C.NAMED));self.assertEqual(set(json.loads(C.read(HERE/C.WF))['on']['workflow_dispatch']['inputs']['case']['options']),set(C.CASES))
 def test_10_whole_original_three_actual_prior_decision_bodies_and_data_hashes(self):
  contract,_,_=C.apis(HELD);old,_,binding=contract.gate(HELD,C.CASES[0])
  # Only the Git subprocess boundary is inert here; the complete original
  # decision parser, exact pinned bytes and all three typed truths execute.
  with patch.object(old,'revision',return_value=binding['decision_carrier_source']),patch.object(subprocess,'Popen',side_effect=noactor):value=contract.accepted(old,DECISIONS,binding)
  self.assertEqual(set(value),{'normal',*C.CASES});self.assertEqual(len({v['run_id']for v in value.values()}),3)
  self.assertEqual(value['normal']['checkpoint_changed'],True);self.assertEqual(value['precommit-exit86']['before_inventory_preserved'],True);self.assertEqual(value['postcommit-exit87']['postcommit_preservation_verified'],True)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'decisions';shutil.copytree(DECISIONS,root);p=root/'payload/precommit-exit86.json';p.write_bytes(p.read_bytes()+b' ')
   with patch.object(old,'revision',return_value=binding['decision_carrier_source']),patch.object(subprocess,'Popen',side_effect=noactor),self.assertRaises(ValueError):contract.accepted(old,root,binding)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
