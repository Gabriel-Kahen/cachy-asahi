#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actor-fenced DATA controls only. Modeled receipts never become admission DATA."""
import ast,contextlib,copy,ctypes,gzip,hashlib,importlib.util,inspect,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,path=None):
 spec=importlib.util.spec_from_file_location('c01_rtc_test_'+name,path or HERE/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
I=load('inputs');B=load('boot');K=load('contracts');P=load('prepare');OLD=load('frozen_fields',HERE/'frozen/c01/test_controls.py');RTC=load('rtc_source_controls',HERE.parent/'arm16k_project_lifecycle_rtc/test_successor.py')
N='a'*32;E=1794716100
F={**OLD.fields(),**{k:v for k,v in RTC.F.items()if k not in RTC.LEGACY.FIELDS}}
def frame(values=F):return ('ARM16K_C01_RTC_BEGIN '+N+'\n'+''.join(k+'='+str(v)+'\n'for k,v in values.items())+'ARM16K_C01_RTC_END '+N).encode()
def modeled_ksm():
 return {'schema_version':1,'status':'PASS_EMULATED_ARM16K_RTC_SIGNED_PROJECT_INSTALL_REMOVE_ONLY','project':copy.deepcopy(RTC.F)|{k:int(RTC.F[k])for k in ('HOST_BOOT_UTC','GUEST_BEFORE_CRYPTO_UTC','RTC_BEFORE_CRYPTO_UTC')},'session':{'UID':'1000','PID1':'systemd','ARCH':'aarch64','PAGESIZE':'16384','LOGIND':'active','DBUS':'active','Service':'login','Type':'tty','Active':'yes'},'normal_PAM_logout_observed':True,'QMP_quit_requested':True,'owned_container_absence_verified':True,'owned_container_removed':True,'cleanup_ownership_verified':True,'image_id':K.TOOL,'QEMU_retirement':{'passed':True,'reaped':True,'ownership':'REAPED','group_census':'EMPTY_TWICE','timeout':False,'output_complete':True,'exit':0,'actor_cancelled':[]},'cleanup_errors':[]}

class Results(unittest.TestCase):
 def test_complete_c01_rtc_frame(self):self.assertEqual(B.parse_lifecycle(frame(),N,E,E+20)['ENCODES'],'42')
 def test_every_c01_exact_invariant_stays_required(self):
  for key in OLD.fields():
   with self.subTest(key=key),self.assertRaises(ValueError):B.parse_lifecycle(frame({**F,key:'wrong'}),N,E,E+20)
 def test_each_clock_or_durability_field_required(self):
  for key in set(F)-set(OLD.fields()):
   fields=dict(F);fields.pop(key)
   with self.subTest(key=key),self.assertRaises(ValueError):B.parse_lifecycle(frame(fields),N,E,E+20)
 def test_stale_future_and_diverging_clock_refuse(self):
  for change in ({'HOST_BOOT_UTC':str(E-1)},{'GUEST_BEFORE_CRYPTO_UTC':str(E+486)},{'RTC_BEFORE_CRYPTO_UTC':str(E-5)}):
   with self.assertRaises(ValueError):B.parse_lifecycle(frame(F|change),N,E,E+600)
 def test_old_ksm_or_c01_frames_cannot_be_replayed(self):
  for data in (frame().replace(b'ARM16K_C01_RTC_',b'ARM16K_RTC_PROJECT_'),OLD.frame(OLD.fields()),frame()*2):
   with self.assertRaises(ValueError):B.parse_lifecycle(data,N,E,E+20)
 def test_hold_remains_hold(self):self.assertEqual(B.parse_lifecycle(frame({'STATUS':'HOLD','FAILED_PHASE':'trust'}),N,E,E+20)['STATUS'],'HOLD')

class Prerequisite(unittest.TestCase):
 def check(self,report,change=None):
  with tempfile.TemporaryDirectory(prefix='modeled-receipt-only-')as tmp:
   path=Path(tmp)/'modeled.json';path.write_text(json.dumps(report));approved={'ksm_pass_receipt':I.pin(path)}
   if change:approved=change(approved)
   return I.trust_prerequisite(path,I.pin(path)['sha256'],approved)
 def test_complete_modeled_schema_is_parseable_but_not_actual_evidence(self):self.assertIn('sha256',self.check(modeled_ksm()))
 def test_hold_missing_and_legacy_status_refuse(self):
  for report in ({'status':'HOLD'},modeled_ksm()|{'status':'PASS_EMULATED_ARM16K_SIGNED_PROJECT_INSTALL_REMOVE_ONLY'},modeled_ksm()|{'project':{'STATUS':'HOLD'}}):
   with self.assertRaises(ValueError):self.check(report)
 def test_each_package_restoration_and_rtc_invariant_refuses(self):
  for key in RTC.F:
   report=modeled_ksm();report['project'][key]='wrong'
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(report)
 def test_each_session_field_refuses(self):
  for key in modeled_ksm()['session']:
   report=modeled_ksm();report['session'].pop(key)
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(report)
 def test_each_retirement_logout_or_cleanup_failure_refuses(self):
  for key in ('normal_PAM_logout_observed','QMP_quit_requested','owned_container_absence_verified','owned_container_removed','cleanup_ownership_verified'):
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(modeled_ksm()|{key:False})
  for key in ('passed','reaped','ownership','group_census','timeout','output_complete','exit'):
   report=modeled_ksm();report['QEMU_retirement'][key]='wrong'
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(report)
 def test_cancellation_and_wrong_tool_image_refuse(self):
  for change in ({'cleanup_errors':['modeled']},{'cancelled_signals':[15]},{'image_id':'wrong'}):
   with self.assertRaises(ValueError):self.check(modeled_ksm()|change)
 def test_no_separate_root_pin_and_tampered_pin_refuse(self):
  for change in (lambda _: {},lambda a: {'ksm_pass_receipt':a['ksm_pass_receipt']|{'sha256':'0'*64}}):
   with self.assertRaises(ValueError):self.check(modeled_ksm(),change)
 def test_missing_and_symlink_receipts_refuse(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);p=root/'receipt';p.write_text('{}');link=root/'link';link.symlink_to(p)
   with self.assertRaises(ValueError):I.trust_prerequisite(link,I.pin(p)['sha256'],{'ksm_pass_receipt':I.pin(p)})
   with self.assertRaises(FileNotFoundError):I.trust_prerequisite(root/'absent','a'*64,{})

class SigningAndKernel(unittest.TestCase):
 def signing(self,tmp):
  lock=json.loads((HERE/'inputs.lock.json').read_text());data={'issued_by':'Root','private_key_given_to_workers_or_guests':False,'signer_fingerprint':lock['signer'],'public_key':lock['materials']['TEST-public.asc'],'private_operator_path':'not projected','records':[]}
  for name,version in lock['added_packages'].items():
   filename=name+'-'+version+'-aarch64.pkg.tar.xz';data['records'].append({'archive':lock['materials'][filename],'signature':lock['materials'][filename+'.sig'],'archive_path':'private operator path'})
  path=Path(tmp)/'receipt';path.write_text(json.dumps(data));lock['root_signing_receipt']=I.pin(path);return path,lock,data
 def test_two_package_signing_projection_has_no_paths(self):
  with tempfile.TemporaryDirectory()as tmp:
   path,lock,_=self.signing(tmp);result=K.signing(path,lock,now=E);self.assertEqual(len(result['records']),2);self.assertNotIn('private operator path',json.dumps(result))
 def test_live_key_bounds_and_stale_preparation_refuse(self):
  with tempfile.TemporaryDirectory()as tmp:
   path,lock,_=self.signing(tmp)
   for now in (1794713060,1795317861):
    with self.assertRaises(ValueError):K.signing(path,lock,now=now)
   with patch.object(K.time,'time',return_value=1795317862),self.assertRaises(ValueError):K.signing(path,lock)
 def test_duplicate_missing_or_changed_archive_association_refuse(self):
  with tempfile.TemporaryDirectory()as tmp:
   path,lock,data=self.signing(tmp)
   for records in (data['records'][:1],[data['records'][0]]*2,[data['records'][0],data['records'][1]|{'signature':{'bytes':1,'sha256':'0'*64}}]):
    path.write_text(json.dumps(data|{'records':records}));lock['root_signing_receipt']=I.pin(path)
    with self.assertRaises(ValueError):K.signing(path,lock,now=E)
 def test_pending_external_authority_cannot_reach_tools(self):
  p=HERE/'authority.template.json'
  with self.assertRaises(ValueError):K.authority(p,I.pin(p)['sha256'],HERE/'rtc_actor.py')
 def test_actual_new_actor_and_ksm_receipt_are_authority_bound(self):
  with tempfile.TemporaryDirectory()as tmp:
   path=Path(tmp)/'authority';data=json.loads((HERE/'authority.template.json').read_text());data.update({'rtc_actor':I.pin(HERE/'rtc_actor.py'),'kernel_bundle':{'bytes':1,'sha256':'a'*64},'ksm_pass_receipt':{'bytes':1,'sha256':'b'*64},'approved_compiler_facts':{}});path.write_text(json.dumps(data));self.assertEqual(K.authority(path,I.pin(path)['sha256'],HERE/'rtc_actor.py'),data)
   data['ksm_pass_receipt']=None;path.write_text(json.dumps(data))
   with self.assertRaises(ValueError):K.authority(path,I.pin(path)['sha256'],HERE/'rtc_actor.py')
 def test_helper_is_exact11th_required_state_with_bound_producer_source(self):
  lock=json.loads((HERE/'inputs.lock.json').read_text());proof=lock['derived_rtc_helper_source'];self.assertEqual(len(K.RTC),11);self.assertEqual(K.RTC['CONFIG_RTC_I2C_AND_SPI'],'y');self.assertEqual(proof['actual_feature_delta_symbols'],8);self.assertEqual(proof['existing_buses_held'],{'CONFIG_I2C':'y','CONFIG_SPI':'n'})
 def test_kernel_and_rtc_clock_contracts_are_exact_reviewed_source(self):
  self.assertEqual(inspect.getsource(K.kernel),inspect.getsource(RTC.K.kernel));self.assertEqual(K.RTC,RTC.K.RTC)
  for name in ('rtc-clock.sh','durable.sh'):self.assertEqual((HERE/name).read_bytes(),(HERE.parent/'arm16k_project_lifecycle_rtc'/name).read_bytes())

class CustodyAndData(unittest.TestCase):
 def test_all_frozen_references_and_workload_bytes_match(self):
  I.reference();self.assertEqual((HERE/'guest-workload.sh').read_bytes(),(HERE/'frozen/c01/guest-workload.sh').read_bytes())
 def test_distinct_mounted_actor_cmd_retains_original_validator(self):
  scope=B.OwnedContainer('x',Path('/tmp/cid'),K.TOOL,{},Path('/tmp/source'),Path('/tmp/out'))
  for cmd in (['-I','-B','/opt/vm_actor.py'],['-I','-B','/inputs/other.py']):
   with self.assertRaises(AssertionError):scope.validate({'Config':{'Cmd':cmd}})
  with patch.object(B.B.OwnedContainer,'validate')as original:
   scope.validate({'Config':{'Cmd':['-I','-B','/inputs/rtc_actor.py']}});self.assertEqual(original.call_args.args[0]['Config']['Cmd'][-1],'/opt/vm_actor.py')
 def test_clock_and_ksm_gates_precede_crypto_output_and_markers(self):
  prep=(HERE/'prepare.py').read_text();boot=(HERE/'boot.py').read_text();guest=(HERE/'guest-root.sh').read_text()
  self.assertLess(prep.index('I.trust_prerequisite('),prep.index('out.mkdir('));self.assertLess(boot.index('I.trust_prerequisite('),boot.index("attempt.open('x')"));self.assertLess(guest.index('\nrtc_clock_guard\n'),guest.index('\ngpg_run_fixed trust_import'))
 def test_no_signature_dependency_clock_or_hook_bypass(self):
  text='\n'.join((HERE/n).read_text()for n in ('prepare.py','guest-root.sh','gpg-receipts.sh','rtc-clock.sh','rtc_actor.py'))
  for forbidden in ('--nodeps','--assume-installed','--noscriptlet','--ignore-time-conflict','--faked-system-time','SigLevel = Never','date -s','clock_settime'):self.assertNotIn(forbidden,text)
  self.assertIn('Required TrustedOnly',text);self.assertIn('CACHY_ASAHI_ALLOW_ARM16K_C01_RTC_BOOT',text);self.assertIn("'-rtc','base=utc,clock=host'",text)
 def test_exact_four_gpg_operations_and_no_ksm_package_argv(self):
  root=(HERE/'guest-root.sh').read_text();helper=(HERE/'gpg-receipts.sh').read_text();self.assertNotIn('ksmctl',root+helper);self.assertNotIn('python-',helper);self.assertNotIn('archlinuxarm.gpg',helper)
  self.assertIn('gpg_run_fixed ownertrust',root);self.assertIn('gpg_verify_fixed "$name"',root);self.assertIn('sync -f "$directory"',helper)
 def test_all_35_tools_and_helpers_are_hash_bound(self):
  review=json.loads((HERE/'tools.lock.json').read_text());self.assertEqual(len(review['baseline_tools']),35);self.assertIn('sync',review['baseline_tools'])
  for name,ref in review['reviewed_source'].items():self.assertEqual(I.pin(HERE/name),ref)
 def test_binary_boundary_and_invalid_fixture_contract_preserved(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);pins=I.fixtures(root);self.assertEqual([pins['corpus-'+str(i)]['bytes']for i in range(7)],[0,1,114688,262144,16383,16384,16385])
   for i in range(3):
    with self.assertRaises((OSError,EOFError)):gzip.decompress((root/('invalid-'+str(i))).read_bytes())
 def test_import_and_ast_parse_never_reach_actors(self):
  load('rtc_actor');load('boot')
  for path in HERE.rglob('*.py'):ast.parse(path.read_text(),filename=str(path))

if __name__=='__main__':
 with contextlib.ExitStack()as stack:
  for module,names in ((subprocess,('Popen',)),(socket,('socket','create_connection')),(ctypes,('CDLL',)),(os,('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','execvp','execvpe'))):
   for name in names:
    if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=AssertionError('actor fenced: '+name)))
  unittest.main()
