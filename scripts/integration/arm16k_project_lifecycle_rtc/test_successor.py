#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Source/model and private-host shell controls. No Docker, QEMU or package code."""
import copy,importlib.util,json,os,struct,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,path=None):
 spec=importlib.util.spec_from_file_location('rtc_test_'+name,path or HERE/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
K=load('contracts');I=load('inputs');B=load('boot');P=load('prepare');N='1'*32;E=1794716100
LEGACY=load('legacy_tests',HERE.parent/'arm16k_project_lifecycle/test_lifecycle.py')
F={**LEGACY.FIELDS,'RTC_PRESENT':'yes','RTC_DRIVER':'pl031','RTC_HCTOSYS':'1','RTC_CLOCK_ADVANCED':'yes','CLOCK_SETTING':'none','DURABLE_RECEIPTS':'sync_f_completed','HOST_BOOT_UTC':str(E),'GUEST_BEFORE_CRYPTO_UTC':str(E+2),'RTC_BEFORE_CRYPTO_UTC':str(E+2)}
def frame(fields=F):return ('ARM16K_RTC_PROJECT_BEGIN '+N+'\n'+''.join(k+'='+str(v)+'\n'for k,v in fields.items())+'ARM16K_RTC_PROJECT_END '+N+'\n').encode()
def shell(code):return subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',code],capture_output=True,timeout=10,env={'PATH':'/usr/bin','LANG':'C'})

class Bundle(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.dir=self.root/'bundle';self.dir.mkdir();self.base=self.root/'baseline'
  self.before={k:'n'for k in K.RTC};self.before.update({k:'y'for k in ('CONFIG_ARM64_16K_PAGES','CONFIG_ARM_AMBA','CONFIG_VIRTIO_MMIO','CONFIG_VIRTIO_BLK','CONFIG_EXT4_FS')});self.before['CONFIG_I2C']='y';self.before['CONFIG_SPI']='n';self.before['CONFIG_MODULES']='n';self.before['CONFIG_LOCALVERSION']='"-generic16k-managed-gui"'
  self.base.write_text(''.join(k+'='+v+'\n'for k,v in self.before.items()));self.after={**self.before,**K.RTC,'CONFIG_LOCALVERSION':'"-generic16k-managed-gui-rtc1"'}
  head=bytearray(64);head[56:60]=b'ARM\x64';struct.pack_into('<Q',head,24,4);struct.pack_into('<Q',head,16,64);(self.dir/'Image').write_bytes(head)
  self.bundle={'schema_version':1,'kind':'ARM16K_RTC_REFERENCE_KERNEL_BUNDLE_V1','status':'BUILT_ONLY_RTC_BOOT_NOT_RUN','kernel_release':'7.1.13-generic16k-managed-gui-rtc1','files':{},'source':{'revision':'94fb23346d522edf53722357c426a3e58030beea','original_source':'4056e2505ed7081674e949e0460258672cce14ff','original_run':39156901928,'archive':{'bytes':262965559,'sha256':'874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'}},'config_proof':{'baseline':K.pin(self.base),'rtc_required':K.RTC,'compiler_facts':{},'non_rtc_features_unchanged':True},'toolchain':{'mode':'HOST_CROSS_ARM64','profile_sha256':'a'*64,'actual_tools':{'clang':'MODELED'},'same_toolchain':False},'build':{'commands':['MODELED DATA ONLY'],'actual_started_utc':'MODELED','actual_finished_utc':'MODELED'},'guest_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN','release_accepted':False};self.approval={'approved_compiler_facts':{}};self.seal()
 def seal(self):
  (self.dir/'config').write_text(''.join(k+'='+v+'\n'for k,v in self.after.items()));self.bundle['files']={n:K.pin(self.dir/n)for n in ('Image','config')};self.bundle['config_proof']['feature_delta']={k:{'before':self.before.get(k,'n'),'after':v}for k,v in self.after.items()if self.before.get(k,'n')!=v and k in K.RTC.keys()|K.METADATA_DELTA.keys()};(self.dir/'bundle.json').write_text(json.dumps(self.bundle));self.approval['kernel_bundle']=K.pin(self.dir/'bundle.json')
 def verify(self):return K.kernel(self.dir,self.approval,self.base)
 def test_modeled_complete_bundle_passes(self):self.assertEqual(self.verify()['kernel_release'],self.bundle['kernel_release'])
 def test_each_required_rtc_feature_refuses(self):
  for key in K.RTC:
   with self.subTest(key=key):
    old=self.after[key];self.after[key]='n'if old!='n'else'y';self.seal()
    with self.assertRaises(ValueError):self.verify()
    self.after[key]=old
 def test_exact_release_metadata_is_separate_from_rtc_and_compiler_facts(self):
  self.verify();self.assertEqual(len(K.RTC),11);self.assertEqual(self.bundle['config_proof']['feature_delta']['CONFIG_LOCALVERSION'],K.METADATA_DELTA['CONFIG_LOCALVERSION']);self.assertNotIn('CONFIG_LOCALVERSION',self.bundle['config_proof']['compiler_facts'])
 def test_missing_or_wrong_release_metadata_refuses(self):
  for value in ('"-generic16k-managed-gui"','"-unreviewed"'):
   self.after['CONFIG_LOCALVERSION']=value;self.seal()
   with self.assertRaisesRegex(ValueError,'metadata'):self.verify()
  self.after['CONFIG_LOCALVERSION']='"-generic16k-managed-gui-rtc1"';self.seal();self.bundle['config_proof']['feature_delta'].pop('CONFIG_LOCALVERSION');(self.dir/'bundle.json').write_text(json.dumps(self.bundle));self.approval['kernel_bundle']=K.pin(self.dir/'bundle.json')
  with self.assertRaisesRegex(ValueError,'metadata'):self.verify()
 def test_derived_helper_requires_y_and_preserves_held_buses(self):
  self.verify();self.assertEqual(K.RTC['CONFIG_RTC_I2C_AND_SPI'],'y');self.assertEqual(len(self.bundle['config_proof']['feature_delta']),8);self.assertEqual(self.before['CONFIG_I2C'],self.after['CONFIG_I2C']);self.assertEqual(self.before['CONFIG_SPI'],self.after['CONFIG_SPI'])
  for key,value in (('CONFIG_I2C','n'),('CONFIG_SPI','y'),('CONFIG_RTC_DRV_DS3232','y')):
   old=self.after.get(key);self.after[key]=value;self.seal()
   with self.assertRaisesRegex(ValueError,'unapproved'):self.verify()
   if old is None:self.after.pop(key)
   else:self.after[key]=old
 def test_unprofiled_additional_rtc_helper_or_driver_refuses(self):
  for key in ('CONFIG_RTC_UNREVIEWED_HELPER','CONFIG_RTC_DRV_PCF2127'):
   self.after[key]='y';self.seal()
   with self.assertRaisesRegex(ValueError,'unapproved'):self.verify()
   self.after.pop(key)
 def test_non_rtc_drift_refuses(self):
  self.after['CONFIG_UNAPPROVED']='y';self.seal()
  with self.assertRaisesRegex(ValueError,'unapproved'):self.verify()
 def test_approved_finite_compiler_fact_can_pass(self):
  self.after['CONFIG_CC_VERSION_TEXT']='"new pinned compiler"';delta={'CONFIG_CC_VERSION_TEXT':{'before':'n','after':'"new pinned compiler"'}};self.approval['approved_compiler_facts']=delta;self.bundle['config_proof']['compiler_facts']=delta;self.seal();self.verify()
 def test_unmatched_compiler_fact_refuses(self):
  self.bundle['config_proof']['compiler_facts']={'CONFIG_CC_UNKNOWN':{'before':'n','after':'y'}};self.seal()
  with self.assertRaises(ValueError):self.verify()
 def test_modules_and_baseline_feature_loss_refuse(self):
  for key,value in (('CONFIG_MODULES','y'),('CONFIG_EXT4_FS','n')):
   old=self.after[key];self.after[key]=value;self.seal()
   with self.assertRaises(ValueError):self.verify()
   self.after[key]=old
 def test_changed_image_and_config_refuse(self):
  for name in ('Image','config'):
   old=(self.dir/name).read_bytes();(self.dir/name).write_bytes(old+b'X')
   with self.assertRaises(ValueError):self.verify()
   (self.dir/name).write_bytes(old)
 def test_bss_memory_span_can_exceed_file_bytes_up_to128mib(self):
  for span in (1048576,134217728):
   head=bytearray((self.dir/'Image').read_bytes());struct.pack_into('<Q',head,16,span);(self.dir/'Image').write_bytes(head);self.seal();self.verify()
  self.assertEqual((self.dir/'Image').stat().st_size,64)
 def test_zero_or_over128mib_memory_span_refuses(self):
  for span in (0,134217729):
   head=bytearray((self.dir/'Image').read_bytes());struct.pack_into('<Q',head,16,span);(self.dir/'Image').write_bytes(head);self.seal()
   with self.assertRaisesRegex(ValueError,'16K ARM64'):self.verify()
 def test_over64mib_file_refuses_independent_of_valid_memory_span(self):
  with (self.dir/'Image').open('r+b')as stream:stream.truncate(67108865)
  with self.assertRaisesRegex(ValueError,'bound exceeded'):self.verify()
 def test_bad_arch_page_size_and_endian_refuse(self):
  for flag in (0,2,5,6):
   head=bytearray((self.dir/'Image').read_bytes());struct.pack_into('<Q',head,24,flag);(self.dir/'Image').write_bytes(head);self.seal()
   with self.assertRaises(ValueError):self.verify()
 def test_extra_or_symlink_bundle_refuses(self):
  (self.dir/'unexpected').write_text('x')
  with self.assertRaises(ValueError):self.verify()
  (self.dir/'unexpected').unlink();link=self.root/'link';link.symlink_to(self.dir)
  with self.assertRaises(ValueError):K.kernel(link,self.approval,self.base)
 def test_wrong_source_or_pending_build_refuse(self):
  for field,value in (('status','PENDING'),('guest_boot','PASS'),('release_accepted',True)):
   old=self.bundle[field];self.bundle[field]=value;self.seal()
   with self.assertRaises(ValueError):self.verify()
   self.bundle[field]=old
 def test_duplicate_config_refuses(self):
  with self.assertRaises(ValueError):K.config('CONFIG_X=y\nCONFIG_X=n\n')

class AuthorityAndSigning(unittest.TestCase):
 def test_pending_template_refuses(self):
  path=HERE/'authority.template.json'
  with self.assertRaises(ValueError):K.authority(path,K.pin(path)['sha256'],HERE/'rtc_actor.py')
 def test_external_digest_and_actor_binding(self):
  with tempfile.TemporaryDirectory()as tmp:
   path=Path(tmp)/'authority';data=json.loads((HERE/'authority.template.json').read_text());data.update({'rtc_actor':K.pin(HERE/'rtc_actor.py'),'kernel_bundle':{'bytes':1,'sha256':'a'*64},'approved_compiler_facts':{}});path.write_text(json.dumps(data));self.assertEqual(K.authority(path,K.pin(path)['sha256'],HERE/'rtc_actor.py'),data)
   for digest in ('b'*64,'pending'):
    with self.assertRaises(ValueError):K.authority(path,digest,HERE/'rtc_actor.py')
 def receipt(self,tmp):
  lock=json.loads((HERE/'inputs.lock.json').read_text());spec=lock['Root_signing_receipt'];data={'issued_by':'Root','private_key_supplied_to_actors':False,'signer_fingerprint':spec['signer'],'key_created_epoch':spec['created_epoch'],'key_expires_epoch':spec['expires_epoch'],'private_operator_path':'DO NOT PROJECT'}
  for field,name in (('archive','cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz'),('signature','cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz.sig'),('public_key','TEST-public.asc')):data[field]={k:lock['materials'][name][k]for k in ('bytes','sha256')}
  path=Path(tmp)/'receipt';path.write_text(json.dumps(data));lock['Root_signing_receipt'].update(K.pin(path));return path,lock
 def test_live_signing_projection_has_no_operator_paths(self):
  with tempfile.TemporaryDirectory()as tmp:
   path,lock=self.receipt(tmp);data=K.signing(path,lock,now=E);self.assertNotIn('private_operator_path',data)
 def test_before_creation_expiry_and_stale_prepare_time_refuse(self):
  with tempfile.TemporaryDirectory()as tmp:
   path,lock=self.receipt(tmp);spec=lock['Root_signing_receipt']
   for now in (spec['created_epoch']-1,spec['expires_epoch'],spec['expires_epoch']+1):
    with self.assertRaises(ValueError):K.signing(path,lock,now=now)
   with patch.object(K.time,'time',return_value=spec['expires_epoch']+1),self.assertRaises(ValueError):K.signing(path,lock)
 def test_old_signature_and_public_certificate_preserved_historical(self):
  lock=json.loads((HERE/'inputs.lock.json').read_text());old=json.loads((HERE.parent/'arm16k_project_lifecycle/inputs.lock.json').read_text())
  for name,ref in lock['historical_expired_signatures'].items():self.assertEqual(ref,old['materials'][name]);self.assertNotEqual(ref['sha256'],lock['materials'][name]['sha256'])
 def test_import_has_no_process_or_vm_effect_and_old_sources_match(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actor allowed')):I.reference();load('rtc_actor');load('boot')

class ResultAndCustody(unittest.TestCase):
 def test_complete_rtc_lifecycle_model(self):self.assertEqual(B.parse_lifecycle(frame(),N,E,E+20)['FINAL_PACKAGES'],'111')
 def test_each_clock_durability_field_is_required(self):
  for key in set(F)-set(LEGACY.FIELDS):
   fields=dict(F);fields.pop(key)
   with self.subTest(key=key),self.assertRaises(ValueError):B.parse_lifecycle(frame(fields),N,E,E+20)
 def test_future_stale_disagreeing_times_refuse(self):
  for changes in ({'HOST_BOOT_UTC':str(E-1)},{'GUEST_BEFORE_CRYPTO_UTC':str(E+486)},{'RTC_BEFORE_CRYPTO_UTC':str(E-20)},{'GUEST_BEFORE_CRYPTO_UTC':str(E-6)}):
   with self.subTest(changes=changes),self.assertRaises(ValueError):B.parse_lifecycle(frame({**F,**changes}),N,E,E+600)
 def test_all_original_restoration_and_count_invariants_retained(self):
  for key,value in (('FINAL_PACKAGES','112'),('FINAL_hash','c'*64),('USER_FINAL','c'*64),('ORDINARY_HOOKS_SCRIPTLETS','skipped'),('M2','PASS')):
   with self.assertRaises(ValueError):B.parse_lifecycle(frame({**F,key:value}),N,E,E+20)
 def test_hold_not_promoted_and_duplicate_frame_refuses(self):
  self.assertEqual(B.parse_lifecycle(frame({'STATUS':'HOLD','FAILED_PHASE':'rtc_clock'}),N,E,E+20)['STATUS'],'HOLD')
  with self.assertRaises(ValueError):B.parse_lifecycle(frame()+frame(),N,E,E+20)
 def test_actor_entry_requires_new_path_before_frozen_custody(self):
  scope=B.OwnedContainer('x',Path('/tmp/cid'),'sha256:x',{},Path('/tmp/source'),Path('/tmp/out'))
  with self.assertRaisesRegex(AssertionError,'new RTC actor'):scope.validate({'Config':{'Cmd':['-I','-B','/opt/vm_actor.py']}})
  with patch.object(B.B.OwnedContainer,'validate')as original:
   row={'Config':{'Cmd':['-I','-B','/inputs/rtc_actor.py']}};scope.validate(row);self.assertEqual(original.call_args.args[0]['Config']['Cmd'],['-I','-B','/opt/vm_actor.py']);self.assertEqual(row['Config']['Cmd'][-1],'/inputs/rtc_actor.py')
 def test_no_clock_setting_or_time_policy_relaxation(self):
  text='\n'.join((HERE/name).read_text()for name in ('rtc_actor.py','rtc-clock.sh','guest-root.sh','gpg-receipts.sh'))
  for forbidden in ('--ignore-time-conflict','--faked-system-time','date -s','clock_settime','--nodeps','--noscriptlet','--nohooks'):self.assertNotIn(forbidden,text)
  self.assertIn("'-rtc','base=utc,clock=host'",text);self.assertIn("time.time_ns()",text);self.assertIn('SigLevel = Required TrustedOnly',(HERE/'prepare.py').read_text())
 def test_clock_gate_precedes_signature_execution(self):
  text=(HERE/'guest-root.sh').read_text();self.assertLess(text.index('\nrtc_clock_guard\n'),text.index('\ngpg_run_fixed trust_import'))
 def test_tool_review_bound_to_all_executed_helpers(self):
  review=json.loads((HERE/'tools.lock.json').read_text());self.assertEqual(len(review['baseline_tools']),33);self.assertIn('sync',review['baseline_tools'])
  for name,ref in review['reviewed_source'].items():self.assertEqual(K.pin(HERE/name),ref)

class ShellControls(unittest.TestCase):
 def run_durable(self,mode='ok',summary=b'STATUS=HOLD\nBINARY=\0\n'):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);d=root/'disk';o=root/'run';d.mkdir();o.mkdir();(o/'summary.env').write_bytes(summary)
   setup=f'D={d};O={o};nonce={N}; . {HERE}/guest-runtime.sh; . {HERE}/gpg-receipts.sh; . {HERE}/durable.sh; '
   if mode=='fail':setup+='sync(){ return 9; }; '
   if mode=='second_fail':setup+='calls=0;sync(){ calls=$((calls+1)); [[ $calls == 1 ]]; }; '
   if mode=='symlink':(o/'summary.env').unlink();(root/'external').write_bytes(summary);(o/'summary.env').symlink_to(root/'external')
   result=shell(setup+'durable_terminal');return result,(o/'terminal').exists(),(d/'final-summary.env').read_bytes()if(d/'final-summary.env').exists()else None,(o/'summary.env').read_bytes()
 def test_real_private_host_sync_preserves_binary_summary(self):
  result,terminal,saved,summary=self.run_durable();self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(terminal);self.assertEqual(saved,summary);self.assertIn(b'\0',saved);self.assertTrue(saved.endswith(b'DURABLE_RECEIPTS=sync_f_completed\n'))
 def test_first_sync_failure_never_publishes_terminal(self):
  result,terminal,_,_=self.run_durable('fail');self.assertNotEqual(result.returncode,0);self.assertFalse(terminal)
 def test_final_sync_failure_never_publishes_terminal(self):
  result,terminal,_,_=self.run_durable('second_fail');self.assertNotEqual(result.returncode,0);self.assertFalse(terminal)
 def test_symlink_summary_refuses(self):
  result,terminal,_,_=self.run_durable('symlink');self.assertNotEqual(result.returncode,0);self.assertFalse(terminal)
 def clock(self,hctosys='1',name='rtc-pl031 9010000.pl031',before=E,after=E+1,rtc_before=E,rtc_after=E+1,host=E):
  with tempfile.TemporaryDirectory()as tmp:
   d=Path(tmp);rtc=d/'rtc0';rtc.mkdir();(rtc/'hctosys').write_text(hctosys);(rtc/'name').write_text(name);(rtc/'since_epoch').write_text(str(rtc_before));(d/'cmdline').write_text('arm16k_rtc_host_epoch='+str(host));helper=(HERE/'rtc-clock.sh').read_text().replace('/sys/class/rtc/rtc0',str(rtc)).replace('/proc/cmdline',str(d/'cmdline'));(d/'helper').write_text(helper)
   code=f'D={d};clock_test_epoch={before};date(){{ printf "%s\\n" "$clock_test_epoch"; }};sleep(){{ clock_test_epoch={after};printf "%s\\n" {rtc_after} > {rtc}/since_epoch; }};. {d}/helper;rtc_clock_guard'
   result=shell(code);return result,(d/'rtc-clock.env').read_text()if(d/'rtc-clock.env').exists()else ''
 def test_modeled_advancing_rtc_hctosys_passes(self):
  result,data=self.clock();self.assertEqual(result.returncode,0,result.stderr);self.assertIn('CLOCK_SETTING=none',data)
 def test_missing_hctosys_wrong_driver_and_frozen_clock_refuse(self):
  for changes in ({'hctosys':'0'},{'name':'unreviewed'},{'name':'rtc-pl031'},{'after':E},{'rtc_after':E}):
   with self.subTest(changes=changes):self.assertNotEqual(self.clock(**changes)[0].returncode,0)
 def test_stale_future_and_disagreeing_clock_refuse(self):
  for changes in ({'before':E-6},{'before':E+486},{'rtc_before':E-3},{'host':'bad'}):
   with self.subTest(changes=changes):self.assertNotEqual(self.clock(**changes)[0].returncode,0)
 def test_shell_sources_parse(self):
  for name in ('guest-root.sh','guest-runtime.sh','gpg-receipts.sh','rtc-clock.sh','durable.sh','guest-proof.sh'):
   result=subprocess.run(['/usr/bin/bash','-n',str(HERE/name)],capture_output=True,timeout=5);self.assertEqual(result.returncode,0,result.stderr)


class RestorationReceipts(unittest.TestCase):
 def fixture(self,root):
  d=root/'disk';o=root/'run';d.mkdir(mode=0o700);o.mkdir(mode=0o700)
  for stage in ('before','after'):
   for suffix in ('paths','meta','hash','db','xattr'):
    p=o/(stage+'.'+suffix);p.write_bytes(b'private control\0with newline\n');p.chmod(0o600)
  return d,o
 def execute(self,d,o,body):
  return shell(f'umask 077;D={d};O={o};nonce={N};. {HERE}/guest-runtime.sh;. {HERE}/gpg-receipts.sh;. {HERE}/durable.sh;'+body)
 def capture(self,d,o,body=''):
  return self.execute(d,o,'restoration_capture before || exit $?;restoration_capture after || exit $?;'+body)
 def test_actual_binary_copies_nonce_manifest_and_private_modes(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp));result=self.capture(d,o,'for suffix in paths meta hash db xattr;do restoration_compare "$suffix" || exit $?;done')
   self.assertEqual(result.returncode,0,result.stderr);r=d/'receipts/restoration';self.assertEqual(r.stat().st_mode&0o777,0o700);self.assertEqual((r/'nonce').read_text(),N+'\n')
   for stage in ('before','after'):
    for suffix in ('paths','meta','hash','db','xattr'):
     p=r/(stage+'.'+suffix);self.assertEqual(p.read_bytes(),(o/p.name).read_bytes());self.assertEqual(p.stat().st_mode&0o777,0o600)
   self.assertEqual(len((r/'snapshots.tsv').read_text().splitlines()),10);self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')
 def test_each_real_difference_retains_only_fixed_category_size_digest(self):
  for suffix in ('paths','meta','hash','db','xattr'):
   with self.subTest(suffix=suffix),tempfile.TemporaryDirectory()as tmp:
    d,o=self.fixture(Path(tmp));(o/('after.'+suffix)).write_bytes(b'SECRET DIFFERENCE\0\n');result=self.capture(d,o,'restoration_compare '+suffix)
    self.assertEqual(result.returncode,1);text=(d/'receipts/restoration/comparison.env').read_text();fields=dict(line.split('=',1)for line in text.splitlines());self.assertEqual(fields['RESTORATION_COMPARISON'],suffix);self.assertEqual(int(fields['RESTORATION_AFTER_BYTES']),len(b'SECRET DIFFERENCE\0\n'));self.assertEqual(fields['RESTORATION_AFTER_SHA256'],I.pin(o/('after.'+suffix))['sha256']);self.assertNotIn('SECRET',text);self.assertEqual(result.stdout+result.stderr,b'')
 def test_successful_comparison_does_not_label_a_later_unrelated_failure(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp));result=self.capture(d,o,'restoration_compare xattr');self.assertEqual(result.returncode,0);self.assertFalse((d/'receipts/restoration/comparison.env').exists())
 def test_individual16mib_cap_refuses_before_snapshot_copy(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp))
   with(o/'before.meta').open('r+b')as stream:stream.truncate(16777217)
   result=self.execute(d,o,'restoration_capture before');self.assertEqual(result.returncode,2);self.assertEqual(list((d/'receipts/restoration').iterdir()),[])
 def test_aggregate_includes_retained_before_and_refuses_after_copy(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp))
   for stage in ('before','after'):
    for suffix in ('paths','meta','hash','db','xattr'):(o/(stage+'.'+suffix)).write_bytes(b'')
    with(o/(stage+'.meta')).open('r+b')as stream:stream.truncate(16777216)
   result=self.capture(d,o);self.assertEqual(result.returncode,2);r=d/'receipts/restoration';self.assertTrue((r/'before.meta').exists());self.assertFalse((r/'after.meta').exists());self.assertLessEqual(sum(p.stat().st_size for p in r.iterdir()),33554432)
 def test_symlink_source_and_restoration_directory_refuse(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp));(o/'before.meta').unlink();(o/'before.meta').symlink_to(o/'after.meta');self.assertEqual(self.execute(d,o,'restoration_capture before').returncode,2)
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);d,o=self.fixture(root);(d/'receipts').mkdir(mode=0o700);other=root/'other';other.mkdir();(d/'receipts/restoration').symlink_to(other);self.assertEqual(self.execute(d,o,'restoration_capture before').returncode,2);self.assertEqual(list(other.iterdir()),[])
 def test_wrong_nonce_and_replayed_stage_refuse_without_overwrite(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp));self.assertEqual(self.execute(d,o,'restoration_capture before').returncode,0);r=d/'receipts/restoration';original=(r/'before.meta').read_bytes();self.assertEqual(self.execute(d,o,'restoration_capture before').returncode,2);self.assertEqual((r/'before.meta').read_bytes(),original);(r/'nonce').write_text('2'*32+'\n');self.assertEqual(self.execute(d,o,'restoration_capture after').returncode,2)
 def test_public_source_file_and_unknown_operand_refuse(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp));(o/'before.meta').chmod(0o644);self.assertEqual(self.execute(d,o,'restoration_capture before').returncode,2);self.assertEqual(self.execute(d,o,'restoration_compare arbitrary_path').returncode,2)
 def test_copy_corruption_cannot_replace_exact_equality(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp));result=self.execute(d,o,'cp(){ /usr/bin/cp "$@";local target=${@: -1};printf corrupt > "$target";};restoration_capture before');self.assertEqual(result.returncode,1)
 def test_actual_durable_boundary_flushes_private_failed_comparison(self):
  with tempfile.TemporaryDirectory()as tmp:
   d,o=self.fixture(Path(tmp));(o/'after.meta').write_bytes(b'changed\0\n');result=self.capture(d,o,'restoration_compare meta;rc=$?;[[ $rc == 1 ]] || exit 99;printf "STATUS=HOLD\\n" > "$O/summary.env";cat "$D/receipts/restoration/comparison.env" >> "$O/summary.env";durable_terminal')
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual((o/'terminal').read_text(),N+'\n');self.assertEqual((d/'final-summary.env').read_bytes(),(o/'summary.env').read_bytes());self.assertIn(b'RESTORATION_COMPARISON=meta',(d/'final-summary.env').read_bytes());self.assertEqual((d/'receipts/restoration/after.meta').read_bytes(),b'changed\0\n')
 def test_source_orders_capture_before_original_comparisons_and_terminal(self):
  text=(HERE/'guest-root.sh').read_text();self.assertLess(text.index('restoration_capture before'),text.index('phase=trust'));self.assertLess(text.index('restoration_capture after'),text.index('restoration_compare "$suffix"'));self.assertIn('same_bytes "$O/before.$suffix" "$O/after.$suffix"',(HERE/'guest-runtime.sh').read_text());self.assertIn('receipts/restoration/comparison.env',text);self.assertIn('durable_terminal',text)


class OutputFilesystem(unittest.TestCase):
 def usage(self,free=3*1024**3):return type('Usage',(),{'free':free})()
 def test_fresh_private_tmp_leaf_checks_parent_without_creation(self):
  with tempfile.TemporaryDirectory(prefix='rtc-path-control-')as tmp:
   path=Path(tmp)/'fresh'
   with patch.object(P.shutil,'disk_usage',return_value=self.usage())as usage:self.assertEqual(P.output_path(path),path)
   usage.assert_called_once_with(path.parent);self.assertFalse(path.exists())
 def test_explicit_dev_shm_leaf_checks_that_filesystem(self):
  path=Path('/dev/shm/rtc-source-path-control-fresh-8d128ef4')
  with patch.object(P.shutil,'disk_usage',return_value=self.usage())as usage:self.assertEqual(P.output_path(path),path)
  usage.assert_called_once_with(Path('/dev/shm'));self.assertFalse(path.exists())
 def test_other_roots_prefix_fakes_relative_and_parent_escape_refuse(self):
  with patch.object(P.shutil,'disk_usage',side_effect=AssertionError('must refuse before capacity query')):
   for path in ('/tmpx/fresh','/dev/shm-other/fresh','/home/operator/fresh','relative/fresh','/tmp','/dev/shm','/tmp/allowed/../escape','/tmp/bad name'):
    with self.subTest(path=path),self.assertRaises(ValueError):P.output_path(Path(path))
 def test_symlink_ancestor_and_dangling_leaf_refuse(self):
  with tempfile.TemporaryDirectory(prefix='rtc-path-control-')as tmp:
   root=Path(tmp);(root/'real').mkdir(mode=0o700);(root/'link').symlink_to(root/'real');(root/'dangling').symlink_to(root/'absent')
   for path in (root/'link/fresh',root/'dangling'):
    with self.assertRaisesRegex(ValueError,'symlink'):P.output_path(path)
 def test_existing_file_directory_and_missing_parent_refuse(self):
  with tempfile.TemporaryDirectory(prefix='rtc-path-control-')as tmp:
   root=Path(tmp);(root/'file').write_text('control');(root/'dir').mkdir(mode=0o700)
   for path in (root/'file',root/'dir',root/'absent/fresh'):
    with self.assertRaises(ValueError):P.output_path(path)
 def test_nonprivate_or_wrong_owner_ancestor_refuses(self):
  with tempfile.TemporaryDirectory(prefix='rtc-path-control-')as tmp:
   root=Path(tmp);public=root/'public';public.mkdir(mode=0o755)
   with self.assertRaisesRegex(ValueError,'private'):P.output_path(public/'fresh')
   with patch.object(P.os,'getuid',return_value=os.getuid()+1),self.assertRaisesRegex(ValueError,'user-owned'):P.output_path(root/'fresh')
 def test_full3gib_boundary_holds_on_actual_parent(self):
  with tempfile.TemporaryDirectory(prefix='rtc-path-control-')as tmp:
   path=Path(tmp)/'fresh'
   with patch.object(P.shutil,'disk_usage',return_value=self.usage(3*1024**3-1)),self.assertRaisesRegex(ValueError,'actual output filesystem'):P.output_path(path)
   with patch.object(P.shutil,'disk_usage',return_value=self.usage(3*1024**3)):self.assertEqual(P.output_path(path),path)


class NewGpgReceipts(unittest.TestCase):
 # Exercise the new source with retained finite failure/privacy controls.
 fixture=LEGACY.GpgReceipts.fixture
 fields=LEGACY.GpgReceipts.fields
 mock_verification=LEGACY.GpgReceipts.mock_verification
 test_status_categories_dates_and_private_text_redaction=LEGACY.GpgReceipts.test_status_categories_dates_and_private_text_redaction
 test_failed_verification_persists_bounded_private_receipts_not_raw_export=LEGACY.GpgReceipts.test_failed_verification_persists_bounded_private_receipts_not_raw_export
 test_trust_import_is_fixed_bounded_and_has_no_invented_archive_dates=LEGACY.GpgReceipts.test_trust_import_is_fixed_bounded_and_has_no_invented_archive_dates
 test_receipt_limit_and_existing_leaf_refusal_do_not_overwrite=LEGACY.GpgReceipts.test_receipt_limit_and_existing_leaf_refusal_do_not_overwrite
 def shell(self,body,*args,env=None):
  with tempfile.TemporaryDirectory()as home:
   environment={'HOME':home,'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'}
   if env:environment.update(env)
   return subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c','. "$1/guest-runtime.sh"; . "$1/gpg-receipts.sh"; '+body,'receipt-test',str(HERE),*map(str,args)],env=environment,capture_output=True,timeout=15)
 def test_fresh_primary_identity_is_used_in_runtime_date_comparison(self):
  fp=json.loads((HERE/'inputs.lock.json').read_text())['project']['signer']
  with tempfile.TemporaryDirectory()as tmp:
   d=Path(tmp);(d/'ksm.status').write_text('[GNUPG:] VALIDSIG '+fp+' 2026-11-15 1794716090 0 4 0 22 8 00 '+fp+'\n');(d/'ksm.keys').write_text('pub:u:255:22:ID:1794716090:1795320890:::PRIVATE_UID:\nfpr:::::::::'+fp+':\n');(d/'dates').write_text('ksm 1794716090 0\n')
   result=self.shell('gpg_failure_fields ksm 2 "$2" "$2/dates" 1794716100 2026-11-15T04:15:00Z',d);fields=self.fields(result);self.assertEqual(fields['GPG_EXPECTED_PRIMARY_MATCH'],'yes');self.assertEqual(fields['GPG_UTC_BEFORE_KEY_CREATION'],'no');self.assertEqual(fields['GPG_UTC_AFTER_KEY_EXPIRY'],'no');self.assertNotIn(b'PRIVATE_UID',result.stdout)

if __name__=='__main__':unittest.main()
