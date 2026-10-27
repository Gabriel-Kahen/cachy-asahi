# SPDX-License-Identifier: MIT
"""Synthetic files and mocked GPG only; no keys, Docker, ARM or network."""
import contextlib,copy,importlib.util,json,os,shutil,stat,tempfile,types,unittest
from pathlib import Path
from unittest.mock import MagicMock,patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_gui_test_inside',HERE/'inside.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
ACTUAL_IMAGE_STATE=M.image_state
NOW=1800000000;FP='A'*40
GOOD_STATUS='[GNUPG:] VALIDSIG '+FP+' 2027-01-15 1800000000 0 4 0 1 8 00 '+FP+'\n'
SUCCESS_FIELDS={'schema_version','purpose','status','contract','guard','fingerprint','created','expiry','public_certificate_pin','signatures','public_catalog','private_home_retired','production_credentials_used','native_build','GUI','hardware','Root_acceptance'}

class Fixture:
 def __init__(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='SYNTHETIC-gui-signer-');self.work=Path(self.tmp.name);self.root=self.work/'inputs';self.output=self.work/'out';self.home=self.work/'MOCK-HOME';self.root.mkdir();self.output.mkdir();self.home.mkdir(mode=0o700);self.calls=[];self.cleanup_failure=False;self.generation_failure=False;self.after_catalog=None;self.creation=NOW;self.key_bits='2048';self.key_uid=None;self.retired=['B'*40];self.verify_status=GOOD_STATUS;self.public_mode=False
  files={}
  for name in sorted(M.SOURCE_FILES):
   p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);raw=('SYNTHETIC SOURCE '+name+'\n').encode();p.write_bytes(raw);files[name]=M.pin(raw)
  self.base_files={n:files[n]for n in M.BASE_FILES};self.docs=[]
  (self.root/'bodies').mkdir()
  for i,role in enumerate(('welcome5','dns2','doctor','orphans','native73-index','held77-index')):
   raw=('SYNTHETIC BODY '+role+'\n').encode();(self.root/'bodies'/role).write_bytes(raw);self.docs.append(dict(role=role,carrier='native'if i<4 else'held',path='fixture/'+role,**M.pin(raw),kind='package-archive'if i<4 else'metadata-json',package=None,signature_path='signatures/'+role+'.sig',**(dict(legacy_role_alias=role,native_evidence={'status':'SYNTHETIC_NOT_NATIVE'})if i<4 else dict(body_policy='SYNTHETIC_IMMUTABLE_BODY'))))
  self.manifest={'retired_signers':self.retired};raw=M.encoded(self.manifest);(self.root/'manifest.json').write_bytes(raw);self.contract=dict(schema_version=1,purpose=M.PURPOSE,nonce='c'*32,source_sha='d'*40,image_id='sha256:'+'e'*64,image_contract_sha256='f'*64,manifest_pin=M.pin(raw),files=files,baseline=dict(schema_version=1,purpose='TEST-ONLY-integration-signatures',nonce='c'*32,image_id='sha256:'+'e'*64,manifest_sha256=M.pin(raw)['sha256'],entry_sha256=files['runner/sign_fixture.py']['sha256'],helpers_sha256={n:files[n]['sha256']for n in('runner/native_arm.py','scripts/checks/package_checks.py')}));(self.root/'contract.json').write_bytes(M.encoded(self.contract))
  native=types.SimpleNamespace(__file__=str(self.root/'runner/native_arm.py'),valid_signature=MagicMock(side_effect=self.valid_signature))
  self.core=types.SimpleNamespace(__file__=str(self.root/'runner/sign_fixture.py'),PURPOSE='TEST-ONLY-integration-signatures',native=native,environment=MagicMock(return_value={'SYNTHETIC_GUARD':True}),signer_guard=MagicMock(side_effect=self.guard),fingerprint=MagicMock(return_value=(FP,NOW+86400)),public_certificate=MagicMock(),checked=self.checked,gpg_home=MagicMock(side_effect=self.gpg_home),validate_manifest=MagicMock(side_effect=AssertionError('GENERIC_EIGHT_ARCHIVE_GATE_FORBIDDEN')),artifact_bind=MagicMock(side_effect=AssertionError('GENERIC_CONFIGURATION_GATE_FORBIDDEN')))
  self.plan=types.SimpleNamespace(__file__=str(self.root/'route/plan.py'),validate=MagicMock(side_effect=lambda root,contract,**kwargs:(self.manifest,self.docs)),body_path=lambda root,row:root/'bodies'/row['role'],validate_body=MagicMock())
 def close(self):self.tmp.cleanup()
 def guard(self,observed,baseline):
  assert observed=={'SYNTHETIC_GUARD':True}and baseline==self.contract['baseline']and set(baseline)==M.BASELINE_FIELDS
 def valid_signature(self,status,fp):
  assert fp==FP and status==self.verify_status
 def key_rows(self):
  uid=self.key_uid or'CACHY-ASAHI TEST ONLY '+self.contract['nonce']+' <test-only@invalid.example>'
  return 'pub:u:'+self.key_bits+':1:KEYID:'+str(self.creation)+':'+str(NOW+86400)+'::u:::scSC:\n'+'fpr:::::::::'+FP+':\n'+'uid:u::::::::'+uid+':\n'
 def checked(self,args,label,timeout=60):
  self.calls.append((args,label,timeout));assert not any('faked' in a or'export-secret'in a for a in args);assert'--import'not in args or self.public_mode
  if'--quick-generate-key'in args:
   assert not self.public_mode
   assert args[-3:]==['rsa2048','sign','1d']and timeout==120
   if self.generation_failure:raise ValueError('PRIVATE KEY diagnostic must never escape')
   return''
  if'--with-colons'in args:return self.key_rows()
  if'--import'in args:
   assert self.public_mode and args[-1]==str(self.root/'public/public-key.asc');return''
  if'--export'in args:return'-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nSYNTHETIC PUBLIC\n-----END PGP PUBLIC KEY BLOCK-----\n'
  if'--detach-sign'in args:
   assert not self.public_mode
   out=Path(args[args.index('--output')+1]);out.write_bytes(('SYNTHETIC DETACHED '+Path(args[-1]).name).encode());out.chmod(0o600);return''
  if'--verify'in args:
   if args[-1].endswith('/catalog.json')and self.after_catalog:self.after_catalog()
   return self.verify_status
  raise AssertionError('Unexpected mocked command')
 @contextlib.contextmanager
 def gpg_home(self,prefix,directory):
  assert directory=='/tmp'and prefix in('cachy-asahi-gui-fresh-test-','cachy-asahi-gui-public-only-');self.calls.append(('MOCK_HOME_ENTER',prefix,directory))
  yield self.home
  self.calls.append(('MOCK_HOME_CLEANUP',prefix,directory))
  if self.cleanup_failure:raise ValueError('PRIVATE KEY cleanup diagnostic suppressed')
 @contextlib.contextmanager
 def context(self):
  with patch.dict(M.os.environ,{name:''for name in M.ENV_OVERRIDES}),patch.object(M,'INPUT_ROOT',self.root),patch.object(M,'OUTPUT_ROOT',self.output),patch.object(M,'BASE_FILES',self.base_files),patch.object(M,'__file__',str(self.root/'route/inside.py')),patch.object(M,'image_state',return_value=('SYNTHETIC_IMAGE_STATE',)),patch.object(M.time,'time',return_value=float(NOW)):
   yield self
 def run(self):
  with self.context():rc=M.run(self.root,self.output,self.contract,self.core,self.plan)
  return rc,json.loads((self.output/'result.json').read_bytes())
 def public_inputs(self):
  rc,report=self.run();assert rc==0;shutil.copytree(self.output,self.root/'public');self.public_mode=True;self.verify_output=self.work/'verify-out';self.verify_output.mkdir();self.calls.clear();self.core.gpg_home.reset_mock();self.core.native.valid_signature.reset_mock();return report
 def verify(self):
  with self.context(),patch.object(M,'OUTPUT_ROOT',self.verify_output):rc=M.verify(self.root,self.verify_output,self.contract,self.core,self.plan)
  return rc,json.loads((self.verify_output/'verify-result.json').read_bytes())

class Controls(unittest.TestCase):
 def setUp(self):self.f=Fixture()
 def tearDown(self):self.f.close()
 def test_success_has_exact_public_schema_six_detached_bodies_and_new_signed_catalog(self):
  rc,report=self.f.run();self.assertEqual(rc,0);self.assertEqual(set(report),SUCCESS_FIELDS);self.assertEqual(report['status'],M.STATUS);self.assertTrue(report['private_home_retired']);self.assertFalse(report['production_credentials_used']);self.assertIsNone(report['Root_acceptance']);self.assertEqual([report[n]for n in('native_build','GUI','hardware')],['NOT_RUN']*3);self.assertEqual((report['created'],report['expiry']),(NOW,NOW+86400));self.assertEqual(self.f.core.native.valid_signature.call_count,7);self.f.core.signer_guard.assert_called_once_with({'SYNTHETIC_GUARD':True},self.f.contract['baseline']);self.f.core.validate_manifest.assert_not_called();self.f.core.artifact_bind.assert_not_called()
  self.assertEqual(set(report['signatures']),{row['role']for row in self.f.docs})
  for row in self.f.docs:
   signed=report['signatures'][row['role']];self.assertEqual(set(signed),{'input_pin','signature_pin','status','gpg_exit'});self.assertEqual(signed['input_pin'],{k:row[k]for k in('bytes','sha256')});self.assertEqual(signed['gpg_exit'],0)
  catalog=json.loads((self.f.output/'catalog.json').read_bytes());self.assertEqual(catalog['authority_scope'],M.AUTHORITY);self.assertEqual(catalog['signer'],FP);self.assertEqual(catalog['signatures'],{r:s['signature_pin']for r,s in report['signatures'].items()});self.assertEqual(report['public_catalog']['body_pin'],M.pin((self.f.output/'catalog.json').read_bytes()));self.assertEqual(set(report['public_catalog']),{'body_pin','signature_pin','status','gpg_exit'});self.assertEqual(len([p for p in self.f.output.rglob('*')if p.is_file()]),10)
 def test_source_byte_drift_refuses_before_guard_or_key_storage(self):
  (self.f.root/'route/plan.py').write_bytes(b'CHANGED');rc,report=self.f.run();self.assertEqual(rc,1);self.assertEqual(report['status'],'FAIL');self.f.core.gpg_home.assert_not_called();self.f.core.environment.assert_not_called();self.assertFalse(report['private_home_retired'])
 def test_body_hash_drift_refuses_before_key_storage(self):
  (self.f.root/'bodies/welcome5').write_bytes(b'CHANGED');rc,report=self.f.run();self.assertEqual(rc,1);self.f.core.gpg_home.assert_not_called();self.assertFalse(report['private_home_retired'])
 def test_metadata_inspection_refusal_happens_before_keys(self):
  self.f.plan.validate_body.side_effect=ValueError('NOT_REVIEWED');rc,unused=self.f.run();self.assertEqual(rc,1);self.f.core.gpg_home.assert_not_called()
 def test_retired_key_is_refused_and_cleanup_still_required(self):
  self.f.retired[:]=[FP];rc,report=self.f.run();self.assertEqual(rc,1);self.assertTrue(report['private_home_retired']);self.assertIsNone(report['fingerprint']);self.assertFalse((self.f.output/'public-key.asc').exists())
 def test_cleanup_failure_cannot_publish_pass_or_home_retirement(self):
  self.f.cleanup_failure=True;rc,report=self.f.run();self.assertEqual(rc,1);self.assertEqual(report['status'],'FAIL');self.assertFalse(report['private_home_retired']);self.assertEqual(report['error_type'],'ValueError');self.assertNotIn(b'PRIVATE KEY',(self.f.output/'result.json').read_bytes())
 def test_inner_failure_preserves_successful_cleanup_and_suppresses_exception_text(self):
  self.f.generation_failure=True;rc,report=self.f.run();self.assertEqual(rc,1);self.assertTrue(report['private_home_retired']);self.assertEqual(set(report),SUCCESS_FIELDS|{'error_type'});self.assertNotIn('diagnostic',json.dumps(report));self.assertEqual(report['error_type'],'ValueError')
 def test_late_body_drift_refuses_after_catalog_verification(self):
  self.f.after_catalog=lambda:(self.f.root/'bodies/welcome5').write_bytes(b'FOREIGN');rc,report=self.f.run();self.assertEqual(rc,1);self.assertTrue(report['private_home_retired']);self.assertEqual(self.f.core.native.valid_signature.call_count,7)
 def test_late_same_bytes_source_inode_replacement_is_refused(self):
  def swap():
   path=self.f.root/'route/plan.py';replacement=path.with_name('swap');replacement.write_bytes(path.read_bytes());replacement.replace(path)
  self.f.after_catalog=swap;rc,report=self.f.run();self.assertEqual(rc,1);self.assertTrue(report['private_home_retired'])
 def test_unknown_public_output_cannot_publish_pass(self):
  self.f.after_catalog=lambda:(self.f.output/'foreign').write_bytes(b'PUBLIC_UNKNOWN');rc,report=self.f.run();self.assertEqual(rc,1);self.assertTrue(report['private_home_retired'])
 def test_current_signature_status_rejects_expiry_even_if_primary_parser_is_mocked(self):
  self.f.verify_status=GOOD_STATUS+'[GNUPG:] KEYEXPIRED 1\n';rc,report=self.f.run();self.assertEqual(rc,1);self.assertTrue(report['private_home_retired']);self.assertEqual(self.f.core.native.valid_signature.call_count,1)
 def test_fresh_key_requires_actual_creation_bits_nonce_and_exact_one_day(self):
  for creation,bits,uid in((NOW-86400,'2048',None),(NOW,'4096',None),(NOW,'2048','CACHY-ASAHI TEST ONLY OLD')):
   self.f.creation,self.f.key_bits,self.f.key_uid=creation,bits,uid
   with self.subTest(creation=creation,bits=bits,uid=uid),self.assertRaises(ValueError):M.fresh_key(self.f.core,self.f.home,['gpg'],self.f.contract['nonce'],NOW,NOW,self.f.retired)
  self.f.creation,self.f.key_bits,self.f.key_uid=NOW,'2048',None
  self.assertEqual(M.fresh_key(self.f.core,self.f.home,['gpg'],self.f.contract['nonce'],NOW,NOW,self.f.retired),(FP,NOW,NOW+86400))
 def test_closed_document_role_and_output_path(self):
  for key,value in(('role','../escape'),('signature_path','foreign.sig')):
   docs=copy.deepcopy(self.f.docs);docs[0][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):M.body_state(self.f.root,docs,self.f.plan)
 def test_regular_read_rejects_bound_symlink_and_hardlink(self):
  path=self.f.work/'ordinary';path.write_bytes(b'BOUNDED')
  with self.assertRaises(ValueError):M.read(path,1)
  alias=self.f.work/'alias';alias.symlink_to(path)
  with self.assertRaises(ValueError):M.read(alias,100)
  other=self.f.work/'other';os.link(path,other)
  with self.assertRaises(ValueError):M.read(path,100)
 def test_original_baseline_pins_and_extra_outer_fields_are_refused(self):
  self.f.contract['extra']=True;(self.f.root/'contract.json').write_bytes(M.encoded(self.f.contract));rc,unused=self.f.run();self.assertEqual(rc,1);self.f.core.gpg_home.assert_not_called()
 def test_real_manifest_row_kinds_require_exact_ten_archive_and_nine_metadata_fields(self):
  self.assertEqual([len(row)for row in self.f.docs],[10]*4+[9]*2);self.assertEqual(len(M.body_state(self.f.root,self.f.docs,self.f.plan)),6)
  for index,key in((0,'native_evidence'),(4,'body_policy')):
   docs=copy.deepcopy(self.f.docs);docs[index].pop(key)
   with self.subTest(index=index),self.assertRaises(ValueError):M.body_state(self.f.root,docs,self.f.plan)

class PublicControls(unittest.TestCase):
 def setUp(self):self.f=Fixture();self.f.public_inputs()
 def tearDown(self):self.f.close()
 def mutate_report(self,change):
  path=self.f.root/'public/result.json';value=json.loads(path.read_bytes());change(value);path.write_bytes(M.encoded(value));path.chmod(0o644)
 def test_second_fresh_home_imports_public_only_and_verifies_all_six_and_catalog(self):
  rc,report=self.f.verify();self.assertEqual(rc,0);self.assertEqual(set(report),{'schema_version','status','contract','fingerprint','expiry','guard','signatures','public_catalog','public_only_home_retired','Root_acceptance'});self.assertEqual(report['status'],'PASS_INDEPENDENT_PUBLIC_ONLY_TEST_SIGNATURE_VERIFICATION');self.assertTrue(report['public_only_home_retired']);self.assertIsNone(report['Root_acceptance']);self.assertEqual(self.f.core.native.valid_signature.call_count,14);self.assertEqual(len(list(self.f.verify_output.iterdir())),1);self.f.core.gpg_home.assert_called_once_with('cachy-asahi-gui-public-only-','/tmp')
  commands=[c[0]for c in self.f.calls if isinstance(c[0],list)];self.assertEqual(sum('--import'in c for c in commands),1);self.assertEqual(sum('--verify'in c for c in commands),7);self.assertFalse(any('--quick-generate-key'in c or'--detach-sign'in c for c in commands));self.assertEqual(set(report['signatures']),{r['role']for r in self.f.docs});self.assertTrue(all(set(r)=={'input_pin','signature_pin','status','gpg_exit'}for r in report['signatures'].values()))
 def test_original_private_home_must_already_be_retired_before_public_home(self):
  self.mutate_report(lambda r:r.update(private_home_retired=False));rc,report=self.f.verify();self.assertEqual(rc,1);self.assertFalse(report['public_only_home_retired']);self.f.core.gpg_home.assert_not_called()
 def test_original_contract_cannot_be_rebound(self):
  self.mutate_report(lambda r:r['contract'].update(nonce='0'*32));rc,unused=self.f.verify();self.assertEqual(rc,1);self.f.core.gpg_home.assert_not_called()
 def test_original_signature_pin_and_literal_success_exit_are_required(self):
  self.mutate_report(lambda r:r['signatures']['welcome5'].update(gpg_exit=False));rc,report=self.f.verify();self.assertEqual(rc,1);self.assertTrue(report['public_only_home_retired'])
 def test_tampered_detached_signature_is_not_independently_admitted(self):
  (self.f.root/'public/signatures/welcome5.sig').write_bytes(b'ALTERED_SIGNATURE');rc,report=self.f.verify();self.assertEqual(rc,1);self.assertTrue(report['public_only_home_retired'])
 def test_catalog_cannot_upgrade_GUI_or_native_authority_even_with_matching_receipt_hash(self):
  path=self.f.root/'public/catalog.json';value=json.loads(path.read_bytes());value['GUI']='PASS';raw=M.encoded(value);path.write_bytes(raw);self.mutate_report(lambda r:r['public_catalog'].update(body_pin=M.pin(raw)));rc,report=self.f.verify();self.assertEqual(rc,1);self.assertTrue(report['public_only_home_retired'])
 def test_retired_fingerprint_remains_refused_by_independent_stage(self):
  self.f.retired[:]=[FP];rc,report=self.f.verify();self.assertEqual(rc,1);self.assertTrue(report['public_only_home_retired']);self.assertEqual(self.f.core.native.valid_signature.call_count,0)
 def test_public_home_cleanup_failure_never_yields_pass(self):
  self.f.cleanup_failure=True;rc,report=self.f.verify();self.assertEqual(rc,1);self.assertFalse(report['public_only_home_retired']);self.assertEqual(report['error_type'],'ValueError');self.assertNotIn(b'PRIVATE KEY',(self.f.verify_output/'verify-result.json').read_bytes())
 def test_private_or_foreign_export_directory_is_refused_before_public_home(self):
  (self.f.root/'public/private-keys-v1.d').mkdir();rc,report=self.f.verify();self.assertEqual(rc,1);self.assertFalse(report['public_only_home_retired']);self.f.core.gpg_home.assert_not_called()
 def test_late_original_body_drift_refuses_after_all_public_verifications(self):
  self.f.after_catalog=lambda:(self.f.root/'bodies/welcome5').write_bytes(b'LATE_FOREIGN_BODY');rc,report=self.f.verify();self.assertEqual(rc,1);self.assertTrue(report['public_only_home_retired']);self.assertEqual(self.f.core.native.valid_signature.call_count,14)
 def test_wrong_output_path_never_receives_any_failure_file(self):
  foreign=self.f.work/'foreign-output';foreign.mkdir()
  with self.f.context():
   self.assertEqual(M.run(self.f.root,foreign,self.f.contract,self.f.core,self.f.plan),1);self.assertEqual(M.verify(self.f.root,foreign,self.f.contract,self.f.core,self.f.plan),1)
  self.assertEqual(list(foreign.iterdir()),[]);self.f.core.gpg_home.assert_not_called()
 def test_every_actual_environment_override_refuses_sign_and_public_verify_before_commands_or_homes(self):
  for name in M.ENV_OVERRIDES:
   for handler in(M.run,M.verify):
    output=self.f.work/('env-'+name+'-'+handler.__name__);output.mkdir()
    with self.subTest(name=name,handler=handler.__name__),self.f.context(),patch.object(M,'OUTPUT_ROOT',output),patch.object(M,'image_state',ACTUAL_IMAGE_STATE),patch.dict(M.os.environ,{name:'SYNTHETIC_OVERRIDE'}):
     self.assertEqual(handler(self.f.root,output,self.f.contract,self.f.core,self.f.plan),1)
    self.assertFalse(any(isinstance(call[0],list)for call in self.f.calls));self.f.core.gpg_home.assert_not_called()

class ImageControls(unittest.TestCase):
 def test_actual_inventory_call_is_bounded_and_must_join_complete_package_hash(self):
  body=b'SYNTHETIC EXECUTABLE';source='d'*40;image_id='sha256:'+'e'*64;packages='alpha 1\nbeta 2\n';info=types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o755,st_nlink=1,st_uid=0,st_gid=0,st_size=len(body),st_mtime_ns=3,st_ctime_ns=4)
  class ToolPath:
   def __init__(self,name):self.name=name
   def resolve(self,strict=True):return self
   def stat(self):return info
   def lstat(self):return info
   def is_relative_to(self,parent):return parent=='/usr'
   def __str__(self):return self.name
  image=dict(schema_version=1,purpose='GUI-FRESH-TEST-SIGNER-IMAGE',source_sha=source,oci_ref='registry.invalid/test@sha256:'+'a'*64,image_id=image_id,alarm_uid=os.geteuid(),alarm_gid=os.getegid(),packages_sha256=M.pin(packages.encode())['sha256'],tools={name:M.pin(body)for name in M.TOOLS});raw=M.encoded(image);contract=dict(image_contract_sha256=M.pin(raw)['sha256'],source_sha=source,image_id=image_id);core=types.SimpleNamespace(checked=MagicMock(return_value=packages))
  def read(path,cap):return(raw,('IMAGE_ID',))if str(path).endswith('/image-contract.json')else(body,('TOOL_ID',))
  with patch.dict(M.os.environ,{name:''for name in M.ENV_OVERRIDES}),patch.object(M,'Path',ToolPath),patch.object(M,'read',side_effect=read),patch.object(M.os,'access',return_value=True):
   value=M.image_state(Path('/SYNTHETIC_INPUTS'),contract,core);self.assertEqual(len(value[2]),5);core.checked.assert_called_once_with(['/usr/bin/pacman','-Q'],'unchanged image package inventory',30)
   core.checked.return_value='alpha 1\nalpha 2\n'
   with self.assertRaises(ValueError):M.image_state(Path('/SYNTHETIC_INPUTS'),contract,core)
   core.checked.return_value='alpha 1\nbeta 3\n'
   with self.assertRaises(ValueError):M.image_state(Path('/SYNTHETIC_INPUTS'),contract,core)
 def test_override_guard_precedes_any_image_read_tool_or_command(self):
  for name in M.ENV_OVERRIDES:
   core=types.SimpleNamespace(checked=MagicMock(side_effect=AssertionError('NO_COMMAND')))
   with self.subTest(name=name),patch.dict(M.os.environ,{key:('SYNTHETIC_OVERRIDE'if key==name else'')for key in M.ENV_OVERRIDES}),patch.object(M,'read',side_effect=AssertionError('NO_INPUT_READ'))as read:
    with self.assertRaises(ValueError):M.image_state(Path('/UNREAD'),{},core)
    read.assert_not_called();core.checked.assert_not_called()

if __name__=='__main__':unittest.main(verbosity=2)
