# SPDX-License-Identifier: MIT
"""Inert host controls: real reviewed bodies, synthetic receipts, never crypto."""
import contextlib,copy,json,os,shutil,signal,socket,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if(p/'scripts/ci/sign_fixture.py').is_file())
sys.path.insert(0,str(HERE));import plan as P,route as R
# Deliberately synthetic shape-only marker; no matching key/certificate exists.
UNIT_FP='F'*40

class HostControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='INERT_GUI_SIGNER_HOST_TESTS_');cls.work=Path(cls.tmp.name);cls.source=cls.work/'source';cls.slice=cls.source/P.SLICE;cls.slice.mkdir(parents=True)
  for name in P.rows(HERE):
   if name!='source-manifest.json':target=cls.slice/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(HERE/name,target)
  if not(cls.slice/'environment.py').exists():shutil.copyfile(HERE.parent/'environment.py',cls.slice/'environment.py')
  for original in P.BASE_PATHS.values():
   target=cls.source/original;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/original,target)
  workflow=HERE.parent/'workflow.yml'
  if not workflow.exists():workflow=ROOT/'.github/workflows/native-arm-gui-fresh-test-signer.yml'
  target=cls.source/'.github/workflows/native-arm-gui-fresh-test-signer.yml';target.parent.mkdir(parents=True);shutil.copyfile(workflow,target)
  cls.plan=cls.slice/'input-contract.json';original=HERE/'input-contract.json'
  if not original.exists():original=HERE.parent/'input-contract.json'
  shutil.copyfile(original,cls.plan);cls.manifest,cls.docs=P.manifest(P.read(cls.plan));cls.source_files=P.rows(cls.source)
  cls.source_table=dict(schema_version=1,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,files=cls.source_files);(cls.slice/'source-manifest.json').write_bytes(P.enc(cls.source_table))
  cls.inputs=cls.work/'public-carriers';cls.inputs.mkdir();explicit=os.environ.get('GUI_SIGNER_INPUTS_ROOT')
  if explicit:roots={alias:Path(explicit)/alias for alias in cls.manifest['carriers']}
  else:
   audit=json.loads((HERE.parent/'input-audit.json').read_bytes());roots={alias:Path(row['local_root'])for alias,row in audit['carriers'].items()}
  for alias,root in roots.items():shutil.copytree(root,cls.inputs/alias)
  cls.sid=cls.manifest['carriers']['native73']['source']
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def setUp(self):self.case=Path(tempfile.mkdtemp(prefix='case-',dir=self.work))
 @staticmethod
 def no(*args,**kwargs):raise AssertionError('INERT_TEST_NO_GPG_DOCKER_PROCESS_NETWORK')
 def source_proof(self):
  with patch.object(subprocess,'Popen',self.no),patch.object(subprocess,'run',self.no),patch.object(subprocess,'check_output',self.no),patch.object(socket,'socket',self.no):return R.source_check(self.source,self.plan,P.PLAN_PIN['sha256'],self.inputs)
 def test_real_source_and_all_six_bodies_static_checker_without_actors(self):
  proof=self.source_proof();self.assertEqual(proof['status'],'PASS_GUI_FRESH_SIGNER_SOURCE_ONLY');self.assertEqual(proof['carrier_closures'],'PASS');self.assertEqual((proof['native'],proof['crypto'],proof['Root_acceptance']),('NOT_RUN','NOT_RUN',None));self.assertEqual(len(self.docs),6)
  for row in self.docs:self.assertEqual(P.validate_body(self.inputs/row['carrier']/row['path'],row)['pin'],{k:row[k]for k in('bytes','sha256')})
 def test_exact_plan_and_typed_json_paths_readers(self):
  raw=P.read(self.plan);self.assertEqual(P.pin(raw),P.PLAN_PIN);self.assertEqual(P.manifest(raw)[1],self.docs)
  with self.assertRaises(ValueError):P.manifest(raw+b'\n')
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
   with self.assertRaises(ValueError):P.obj(raw)
  for name in('../body','/body','body//leaf','body/./leaf','body\\leaf','body\nleaf'):
   with self.assertRaises(ValueError):P.relative(name)
  body=self.case/'ordinary';body.write_bytes(b'UNIT TEST DATA');self.assertEqual(P.read(body),b'UNIT TEST DATA');alias=self.case/'alias';alias.symlink_to(body)
  with self.assertRaises(ValueError):P.read(alias)
  hard=self.case/'hard';os.link(body,hard)
  with self.assertRaises(ValueError):P.read(body)
  hard.unlink();fifo=self.case/'fifo';os.mkfifo(fifo)
  with self.assertRaises(ValueError):P.read(fifo)
  with self.assertRaises(ValueError):P.read(body,1)
 def test_source_body_and_closed_carrier_drift_before_actors(self):
  source=self.case/'source';shutil.copytree(self.source,source);leaf=source/P.SLICE/'inside.py';leaf.write_bytes(leaf.read_bytes()+b'\n')
  with patch.object(subprocess,'Popen',self.no),self.assertRaises(ValueError):R.source_check(source,self.plan,P.PLAN_PIN['sha256'],self.inputs)
  for change in('missing','changed','extra','empty','alias'):
   inputs=self.case/('inputs-'+change);shutil.copytree(self.inputs,inputs);row=self.docs[0];body=inputs/row['carrier']/row['path']
   if change=='missing':body.unlink()
   elif change=='changed':body.write_bytes(b'INERT ALTERED INPUT')
   elif change=='extra':(inputs/'native73/foreign').write_bytes(b'INERT EXTRA')
   elif change=='empty':(inputs/'native73/empty').mkdir()
   else:body.unlink();body.symlink_to(self.inputs/row['carrier']/row['path'])
   with patch.object(subprocess,'Popen',self.no),self.assertRaises((ValueError,OSError)):R.source_check(self.source,self.plan,P.PLAN_PIN['sha256'],inputs)
 def image_fixture(self):
  # Syntax-only UNIT DATA; not an acquired or Root-qualified image.
  return dict(schema_version=1,purpose='GUI-FRESH-TEST-SIGNER-IMAGE',source_sha=self.sid,oci_ref='registry.example.invalid/inert/test@sha256:'+P.PLAN_PIN['sha256'],image_id='sha256:'+P.PLAN_PIN['sha256'],alarm_uid=max(1,os.getuid()),alarm_gid=os.getgid(),packages_sha256=P.PLAN_PIN['sha256'],tools={name:dict(bytes=1,sha256=P.PLAN_PIN['sha256'])for name in('/usr/bin/python3','/usr/bin/gpg','/usr/bin/gpgconf','/usr/bin/gpg-agent','/usr/bin/pacman')})
 def test_real_snapshot_complete_source_and_six_immutable_body_joins(self):
  proof=self.source_proof();image=self.image_fixture();raw=P.enc(image);out=self.case/'snapshot';out.mkdir();args=types.SimpleNamespace(plan=self.plan,inputs_root=self.inputs,image_contract_sha256=P.pin(raw)['sha256'])
  inputs,contract,manifest,docs=R.snapshot(args,self.source,proof,out,image,raw);self.assertEqual(set(contract['files']),P.CODE_PATHS);self.assertEqual(contract['manifest_pin'],P.PLAN_PIN)
  for row in docs:self.assertEqual(P.pin(P.read(P.body_path(inputs,row))),{k:row[k]for k in('bytes','sha256')})
  self.assertEqual(P.obj(P.read(inputs/'contract.json')),contract);self.assertEqual(manifest,self.manifest);self.assertEqual(P.pin(P.read(inputs/'image-contract.json')),P.pin(raw))
 def test_unknown_current_source_and_bound_table_refuse_before_any_actor(self):
  table=copy.deepcopy(self.source_table);table['actual_source']=self.sid;read=P.read
  with patch.object(P,'read',side_effect=lambda path,cap=16*1024**2:P.enc(table)if Path(path)==self.slice/'source-manifest.json'else read(path,cap)),patch.object(R,'actor',self.no),self.assertRaises(ValueError):R.source_check(self.source,self.plan,P.PLAN_PIN['sha256'])
  image=self.image_fixture();imagepath=self.case/'image.json';imagepath.write_bytes(P.enc(image));environment=self.case/'environment';environment.mkdir();receipt=dict(status='PASS',source_sha=image['source_sha'],image_id=image['image_id'],contract_sha256=P.pin(P.enc(image))['sha256'],container_cleanup=dict(status='PASS',container_absent=True),uid=os.getuid(),gid=os.getgid(),unit_test_fixture_only='NOT_IMAGE_OR_ROOT_AUTHORITY');(environment/'environment.json').write_bytes(P.enc(receipt))
  args=types.SimpleNamespace(source=self.source,plan=self.plan,plan_sha256=P.PLAN_PIN['sha256'],inputs_root=self.inputs,image_contract=imagepath,image_contract_sha256=P.pin(P.enc(image))['sha256'],environment=environment,output=self.case/'must-not-sign')
  for current in(None,self.manifest['carriers']['renewal7cf7']['source']):
   with patch.dict(os.environ,{}if current is None else{'SOURCE_SHA':current},clear=True),patch.object(R,'HERE',self.slice),patch.object(R,'actor',self.no),patch.object(subprocess,'Popen',self.no),self.assertRaises(ValueError):R.sign(args)
   self.assertFalse(args.output.exists())

 def test_source_built_without_production_refuses_before_keys_or_actors(self):
  image=self.image_fixture();image['oci_ref']=None;imagepath=self.case/'source-built-contract.json';imagepath.write_bytes(P.enc(image));environment=self.case/'unqualified-source-built';environment.mkdir()
  args=types.SimpleNamespace(source=self.source,plan=self.plan,plan_sha256=P.PLAN_PIN['sha256'],inputs_root=self.inputs,image_contract=imagepath,image_contract_sha256=P.pin(P.enc(image))['sha256'],environment=environment,output=self.case/'must-not-create-keys')
  proof=self.source_proof();spec=R.importlib.util.spec_from_file_location
  def no_image_module(name,path,*extra,**kwargs):
   if Path(path).name in('provision.py','environment.py'):self.no()
   return spec(name,path,*extra,**kwargs)
  with patch.dict(os.environ,{},clear=True),patch.object(R,'source_check',return_value=proof),patch.object(R.importlib.util,'spec_from_file_location',side_effect=no_image_module),patch.object(R,'actor',self.no),patch.object(subprocess,'Popen',self.no),self.assertRaisesRegex(ValueError,'current exact workflow source'):R.sign(args)
  self.assertFalse(args.output.exists())
  for malformed in(False,True):
   if malformed:(environment/'production.json').write_bytes(P.enc(dict(status='INERT_UNIT_DATA_NOT_GENUINE_PRODUCTION',TEST_key_generation=False,Root_acceptance=None)))
   with patch.dict(os.environ,{'SOURCE_SHA':self.sid}),patch.object(R,'HERE',self.slice),patch.object(R,'actor',self.no),patch.object(subprocess,'Popen',self.no),patch.object(subprocess,'run',self.no),patch.object(subprocess,'check_output',self.no),patch.object(socket,'socket',self.no),self.assertRaises((ValueError,OSError,KeyError)):R.sign(args)
   self.assertFalse(args.output.exists());self.assertFalse((environment/'public-key.asc').exists())

 def export_fixture(self):
  # All crypto/image/retirement receipts below are labeled UNIT DATA. They
  # exercise host selection only and supply no Root or cryptographic authority.
  run=self.case/'INERT-export-run';(run/'public/signatures').mkdir(parents=True);(run/'inputs').mkdir();(run/'verify-output').mkdir();environment=self.case/'INERT-environment';environment.mkdir()
  for name in P.public_names(self.docs):
   path=run/'public'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('INERT UNIT PUBLIC DATA '+name+'\n').encode())
  shutil.copyfile(self.plan,run/'inputs/manifest.json');verify=P.enc(dict(status=R.VERIFY,public_only_home_retired=True,fingerprint=UNIT_FP,expiry=86401,native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',unit_test_fixture_only='NO_CRYPTO_OR_ROOT_AUTHORITY',Root_acceptance=None));(run/'verify-output/verify-result.json').write_bytes(verify)
  image='sha256:'+P.PLAN_PIN['sha256'];cleanup=dict(status='PASS',image_id=image,contract_sha256=P.PLAN_PIN['sha256'],unit_test_fixture_only='NO_IMAGE_WAS_CREATED');(environment/'cleanup.json').write_bytes(P.enc(cleanup))
  record=dict(status=R.PASS,crypto='PASS_FRESH_TEST_ONLY',native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None,actors=[dict(cleanup=dict(status='PASS',container_absent=True,unit_test_fixture_only='NO_CONTAINER_WAS_CREATED'))for unused in range(2)],environment=str(environment),image_id=image,image_contract_sha256=P.PLAN_PIN['sha256'],source_sha=self.sid,fingerprint=UNIT_FP,created=1,expiry=86401,public_outputs=P.rows(run/'public'),verification_pin=P.pin(verify),unit_test_fixture_only='NO_CRYPTO_OR_ROOT_AUTHORITY')
  (run/'provenance.json').write_bytes(P.enc(record));return run,record,environment
 def test_export_exact_allowlist_two_actor_retirements_and_environment_cleanup(self):
  run,record,environment=self.export_fixture();output=self.case/'public-export'
  with patch.object(subprocess,'Popen',self.no),patch.object(socket,'socket',self.no):index=R.export(run,output)
  self.assertEqual(set(P.rows(output)),P.public_names(self.docs)|{'provenance.json','index.json'});self.assertIsNone(index['Root_acceptance']);self.assertEqual(index['actual_GUI'],'NOT_RUN')
  public=P.obj(P.read(output/'provenance.json'));self.assertTrue(all(public[n]=='NOT_RUN'for n in('native_build','GUI','hardware')));self.assertIsNone(public['Root_acceptance'])
  self.assertTrue(all(p.stat().st_mode&0o777==0o644 for p in output.rglob('*')if p.is_file()))
 def test_export_refuses_missing_cleanup_extra_private_and_false_credit(self):
  for change in('one-actor','signer-live','verifier-live','environment-failed','environment-image','environment-contract','missing-cleanup','extra','private-dir','private','changed-public','changed-verification','root-credit','fingerprint-shape','created-bool','expiry-range','oversize-body','oversize-total'):
   run,record,environment=self.export_fixture();output=self.case/('refused-'+change)
   if change=='one-actor':record['actors'].pop()
   elif change in('signer-live','verifier-live'):record['actors'][int(change=='verifier-live')]['cleanup']['container_absent']=False
   elif change.startswith('environment-'):
    path=environment/'cleanup.json';value=P.obj(P.read(path));key={'environment-failed':'status','environment-image':'image_id','environment-contract':'contract_sha256'}[change];value[key]='INERT_WRONG';path.write_bytes(P.enc(value))
   elif change=='missing-cleanup':(environment/'cleanup.json').unlink()
   elif change=='extra':(run/'public/unselected').write_bytes(b'INERT EXTRA')
   elif change=='private-dir':(run/'public/.gnupg').mkdir();(run/'public/.gnupg/private').write_bytes(b'INERT EXTRA')
   elif change=='private':
    (run/'public/public-key.asc').write_bytes(b'-----BEGIN PRIVATE KEY-----\nINERT LEAK TEST\n');record['public_outputs']=P.rows(run/'public')
   elif change=='changed-public':(run/'public/catalog.json').write_bytes(b'INERT ALTERED')
   elif change=='changed-verification':(run/'verify-output/verify-result.json').write_bytes(b'INERT ALTERED')
   elif change=='root-credit':record['Root_acceptance']='INERT_FALSE_CREDIT'
   elif change=='fingerprint-shape':record['fingerprint']='INERT_NOT_A_KEY'
   elif change=='created-bool':record['created']=True
   elif change=='expiry-range':record['expiry']+=1
   elif change=='oversize-body':(run/'public/public-key.asc').write_bytes(b'X'*(4*1024**2+1));record['public_outputs']=P.rows(run/'public')
   elif change=='oversize-total':
    for name in('catalog.json','public-key.asc'):(run/'public'/name).write_bytes(b'X'*(2*1024**2))
    record['public_outputs']=P.rows(run/'public')
   (run/'provenance.json').write_bytes(P.enc(record))
   with self.subTest(change=change),self.assertRaises((ValueError,OSError,KeyError)):R.export(run,output)
   self.assertFalse(output.exists(),'rejected export must remain unpublished')
   shutil.rmtree(run);shutil.rmtree(environment)

 def test_atomic_export_staging_failure_never_publishes_partial_bundle(self):
  run,record,environment=self.export_fixture();output=self.case/'must-remain-absent';write=R.write;calls=[]
  def interrupted(path,raw):
   calls.append(path)
   if len(calls)==3:raise OSError('INERT_STAGING_WRITE_FAILURE')
   write(path,raw)
  with patch.object(R,'write',side_effect=interrupted),self.assertRaises(OSError):R.export(run,output)
  self.assertEqual(len(calls),3);self.assertFalse(output.exists());self.assertEqual(list(self.case.glob('gui-fresh-public-*')),[])

 def retire_fixture(self):
  token='0'*32;name='cachy-asahi-test-signer-'+token;cid='1'*64;image='sha256:'+P.PLAN_PIN['sha256']
  row=dict(Id=cid,Name='/'+name,Image=image,Config=dict(Labels={'org.cachy-asahi.gui-fresh-signer':token}))
  result=lambda code=0,raw=b'':subprocess.CompletedProcess([],code,raw,b'')
  return token,name,cid,image,row,result
 def test_retirement_successful_absence_and_exact_owned_CID_target(self):
  token,name,cid,image,row,result=self.retire_fixture();core=types.SimpleNamespace(command_result=Mock(return_value=result()))
  self.assertEqual(R.retire(core,name,token,image),dict(status='PASS',container_absent=True,already_absent=True));self.assertEqual(core.command_result.call_count,1)
  core.command_result=Mock(side_effect=[result(raw=(cid+'\n').encode()),result(raw=json.dumps([row]).encode()),result(),result()]);receipt=R.retire(core,name,token,image)
  self.assertTrue(receipt['container_absent']);self.assertEqual(receipt['id'],cid);self.assertEqual(core.command_result.call_args_list[2].args[0],['docker','rm','-f',cid]);self.assertIn('id='+cid,core.command_result.call_args_list[3].args[0])
 def test_retirement_failed_query_inspect_foreign_identity_and_absence_refuse(self):
  token,name,cid,image,row,result=self.retire_fixture()
  for failure in('query','inspect','foreign-label','foreign-image','foreign-name','rm','after-query','still-present'):
   observed=copy.deepcopy(row)
   if failure=='foreign-label':observed['Config']['Labels']['org.cachy-asahi.gui-fresh-signer']='FOREIGN_UNIT_LABEL'
   if failure=='foreign-image':observed['Image']='sha256:'+'2'*64
   if failure=='foreign-name':observed['Name']='/FOREIGN_UNIT_NAME'
   replies=[result(1)if failure=='query'else result(raw=(cid+'\n').encode()),result(1)if failure=='inspect'else result(raw=json.dumps([observed]).encode()),result(1)if failure=='rm'else result(),result(1)if failure=='after-query'else result(raw=b'UNIT_STILL_PRESENT'if failure=='still-present'else b'')]
   core=types.SimpleNamespace(command_result=Mock(side_effect=replies))
   with self.subTest(failure=failure),self.assertRaises(ValueError):R.retire(core,name,token,image)
   if failure in('query','inspect','foreign-label','foreign-image','foreign-name'):self.assertFalse(any(call.args[0][:2]==['docker','rm']for call in core.command_result.call_args_list))
 def test_actor_scope_flags_deadlines_and_retirement_on_cancellation(self):
  token,name,cid,image,row,result=self.retire_fixture();contract=dict(nonce=token,image_id=image);signals=[signal.getsignal(n)for n in(signal.SIGTERM,signal.SIGINT)]
  for mode in('inside-sign','inside-verify'):
   record=dict(actors=[]);core=types.SimpleNamespace(command_result=Mock(return_value=result()),run=Mock(side_effect=KeyboardInterrupt('INERT_CANCELLATION')))
   def retire(*args):
    self.assertEqual([signal.getsignal(n)for n in(signal.SIGTERM,signal.SIGINT)],[signal.SIG_IGN,signal.SIG_IGN]);return dict(status='PASS',container_absent=True)
   with patch.object(R,'retire',side_effect=retire)as cleanup,self.assertRaises(KeyboardInterrupt):R.actor(core,self.inputs,self.case/mode,contract,mode,record)
   command=core.run.call_args.args[0];self.assertEqual(core.run.call_args.kwargs['timeout'],300 if mode=='inside-sign'else 180)
   for flag in('--pull=never','--platform=linux/arm64','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--cgroupns=private','--pids-limit=128'):self.assertIn(flag,command)
   self.assertIn('org.cachy-asahi.gui-fresh-signer=',command[command.index('--label')+1]);self.assertEqual(cleanup.call_count,1);self.assertTrue(record['actors'][0]['cleanup']['container_absent']);self.assertEqual([signal.getsignal(n)for n in(signal.SIGTERM,signal.SIGINT)],signals)
 def test_actor_unknown_prior_state_refuses_before_run(self):
  token,name,cid,image,row,result=self.retire_fixture()
  for response in(result(1),result(raw=b'UNIT_EXISTING_CONTAINER')):
   core=types.SimpleNamespace(command_result=Mock(return_value=response),run=Mock(side_effect=self.no));record=dict(actors=[])
   with self.assertRaises(ValueError):R.actor(core,self.inputs,self.case/('output-'+str(core.command_result.return_value.returncode)+'-'+str(len(response.stdout))),dict(nonce=token,image_id=image),'inside-sign',record)
   core.run.assert_not_called();self.assertEqual(record['actors'],[])

 def test_late_original_public_drift_refuses_before_success(self):
  # The mock produces deliberately noncryptographic UNIT DATA. It exercises
  # only the host's late byte-map joins, never a native/signing acceptance.
  self.source_proof();image=self.image_fixture();raw=P.enc(image);imagepath=self.case/'image.json';imagepath.write_bytes(raw);environment=self.case/'unit-environment';environment.mkdir();(environment/'docker-config').mkdir(mode=0o700)
  receipt=dict(status='PASS',source_sha=image['source_sha'],image_id=image['image_id'],contract_sha256=P.pin(raw)['sha256'],container_cleanup=dict(status='PASS',container_absent=True),uid=os.getuid(),gid=os.getgid(),unit_test_fixture_only='NO_NATIVE_IMAGE_OR_ROOT_AUTHORITY');(environment/'environment.json').write_bytes(P.enc(receipt))
  output=self.case/'unit-run';args=types.SimpleNamespace(source=self.source,plan=self.plan,plan_sha256=P.PLAN_PIN['sha256'],inputs_root=self.inputs,image_contract=imagepath,image_contract_sha256=P.pin(raw)['sha256'],environment=environment,output=output);captured={}
  core=types.SimpleNamespace(package=P.PACKAGE_CHECK,host_probe=Mock(),cancellation_scope=contextlib.nullcontext)
  def actor(core,inputs,out,contract,mode,record):
   out.mkdir(mode=0o700);record['actors'].append(dict(mode=mode,cleanup=dict(status='PASS',container_absent=True),unit_test_fixture_only='NO_CONTAINER_WAS_CREATED'))
   if mode=='inside-sign':
    for name in P.public_names(self.docs)-{'result.json'}:
     path=out/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('INERT UNIT DATA '+name).encode())
    signatures={row['role']:dict(signature_pin=P.pin(P.read(out/row['signature_path'])))for row in self.docs};catalog=dict(body_pin=P.pin(P.read(out/'catalog.json')),signature_pin=P.pin(P.read(out/'catalog.json.sig')))
    report=dict(status=R.PASS,private_home_retired=True,contract=contract,fingerprint=UNIT_FP,created=1,expiry=86401,signatures=signatures,public_catalog=catalog,unit_test_fixture_only='NO_CRYPTO_OR_ROOT_AUTHORITY');(out/'result.json').write_bytes(P.enc(report));captured.update(signatures=signatures,catalog=catalog)
   else:
    verify=dict(status=R.VERIFY,public_only_home_retired=True,fingerprint=UNIT_FP,expiry=86401,contract=contract,Root_acceptance=None,signatures=captured['signatures'],public_catalog=captured['catalog'],unit_test_fixture_only='NO_CRYPTO_OR_ROOT_AUTHORITY');(out/'verify-result.json').write_bytes(P.enc(verify));(output/'public/catalog.json').write_bytes(b'INERT LATE ORIGINAL PUBLIC DRIFT')
  with patch.dict(os.environ,{'SOURCE_SHA':self.sid}),patch.object(R,'HERE',self.slice),patch.object(R,'load_core',return_value=core),patch.object(R,'actor',side_effect=actor),patch.object(subprocess,'Popen',self.no),patch.object(socket,'socket',self.no),self.assertRaises(ValueError):R.sign(args)
  report=P.obj(P.read(output/'provenance.json'));self.assertEqual(len(report['actors']),2);self.assertEqual(report['status'],'FAIL');self.assertEqual(report['crypto'],'NOT_RUN');self.assertIsNone(report['Root_acceptance'])

if __name__=='__main__':unittest.main(verbosity=2)
