#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Finite DATA/bridge controls; never start Docker/QEMU or execute package code."""
import copy,ctypes,importlib.util,io,json,os,struct,subprocess,sys,tarfile,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent


def load(name):
 spec=importlib.util.spec_from_file_location('project_test_'+name,HERE/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


I=load('inputs');B=load('boot');C=load('check-probes');P=load('prepare');N='1'*32
FIELDS={'STATUS':'PASS','BASELINE_PACKAGES':'111','INSTALLED_PACKAGES':'114','FINAL_PACKAGES':'111','ARCH':'aarch64','PAGESIZE':'16384','CLI_UID':'1000','CLI_HELP_EXIT':'0','CLI_VERSION_EXIT':'0','CLI_STATUS_EXIT':'3','CLI_REPORT_EXIT':'3','CLI_ENABLE_EXIT':'2','CLI_DISABLE_EXIT':'2','EXCLUSIVE_PAYLOAD_ABSENT':'yes','PRIVATE_TEST_TRUST_REMOVED':'yes','ORDINARY_HOOKS_SCRIPTLETS':'unsuppressed','KSM_POLICY_ACTION':'none_requested','KSM_KERNEL_FUNCTIONALITY':'not_qualified','NATIVE16K':'NOT_RUN','M2':'NOT_RUN',**{prefix+key:'a'*64 for key in ('meta','hash','db','xattr')for prefix in ('BASE_','FINAL_')},'USER_BEFORE':'b'*64,'USER_FINAL':'b'*64}


def frame(fields=FIELDS,nonce=N):return ('ARM16K_PROJECT_BEGIN '+nonce+'\n'+''.join(key+'='+value+'\n'for key,value in fields.items())+'ARM16K_PROJECT_END '+nonce+'\n').encode()


class Results(unittest.TestCase):
 def test_positive_frame_is_explicit_emulated_diagnostic_scope(self):self.assertEqual(B.parse_lifecycle(frame(),N),FIELDS)
 def test_arch_page_count_and_privilege_drift_refused(self):
  for key,value in (('ARCH','x86_64'),('PAGESIZE','4096'),('CLI_UID','0'),('FINAL_PACKAGES','112'),('ORDINARY_HOOKS_SCRIPTLETS','skipped'),('M2','PASS')):
   with self.subTest(key=key),self.assertRaises(ValueError):B.parse_lifecycle(frame({**FIELDS,key:value}),N)
 def test_each_restoration_digest_is_bound(self):
  for key in ('FINAL_meta','FINAL_hash','FINAL_db','FINAL_xattr','USER_FINAL'):
   with self.subTest(key=key),self.assertRaisesRegex(ValueError,'restoration'):B.parse_lifecycle(frame({**FIELDS,key:'c'*64}),N)
 def test_missing_duplicate_and_other_nonce_frames_refused(self):
  for data,nonce in ((frame(),'2'*32),(frame()+frame(),N),(frame().replace(b'STATUS=PASS\n',b'STATUS=PASS\nSTATUS=PASS\n'),N)):
   with self.subTest(),self.assertRaises(ValueError):B.parse_lifecycle(data,nonce)
 def test_missing_metadata_or_extra_pass_field_refused(self):
  missing=dict(FIELDS);del missing['FINAL_xattr']
  for fields in (missing,{**FIELDS,'EXTRA':'true'}):
   with self.assertRaises(ValueError):B.parse_lifecycle(frame(fields),N)
 def test_real_hold_preserves_failed_phase_instead_of_promoting(self):self.assertEqual(B.parse_lifecycle(frame({'STATUS':'HOLD','FAILED_PHASE':'install','EXIT':'1'}),N)['STATUS'],'HOLD')
 def test_installed_status_exit_must_be_success_or_unavailable(self):
  with self.assertRaisesRegex(ValueError,'diagnostic status'):B.parse_lifecycle(frame({**FIELDS,'CLI_STATUS_EXIT':'1'}),N)


class Material(unittest.TestCase):
 def test_reference_is_exact_and_import_has_no_process_effect(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('must not start a process')):lock,_,_=I.reference()
  self.assertEqual(set(lock['added_packages']),{'cachy-asahi-ksmctl','python','mpdecimal'})
 def test_changed_material_and_symlink_refused(self):
  with tempfile.TemporaryDirectory()as tmp:
   file=Path(tmp)/'file';file.write_text('original');ref=I.pin(file);file.write_text('changed')
   with self.assertRaisesRegex(ValueError,'pin differs'):I.checked(file,ref)
   link=Path(tmp)/'link';link.symlink_to(file)
   with self.assertRaisesRegex(ValueError,'ordinary pinned'):I.pin(link)
 def test_missing_material_refused(self):
  with self.assertRaises(ValueError):I.pin(Path('/definitely-absent-project-material'))
 def archive(self,tmp,entries):
  path=Path(tmp)/'fixture.pkg.tar.xz'
  with tarfile.open(path,'w:xz')as archive:
   for name,data in entries:
    node=tarfile.TarInfo(name);node.size=len(data);archive.addfile(node,io.BytesIO(data))
  return path
 def test_package_traversal_is_data_refusal(self):
  with tempfile.TemporaryDirectory()as tmp,self.assertRaisesRegex(ValueError,'unsafe package'):I.package(self.archive(tmp,[('../escape',b'no')]))
 def test_package_metadata_and_scriptlet_are_never_executed(self):
  with tempfile.TemporaryDirectory()as tmp:
   marker=Path(tmp)/'executed';path=self.archive(tmp,[('.PKGINFO',b'pkgname = demo\npkgver = 1\narch = any\n'),('.INSTALL',('touch '+str(marker)).encode()),('usr/share/demo',b'DATA')]);result=I.package(path)
   self.assertEqual(result['metadata']['pkgname'],['demo']);self.assertFalse(marker.exists())
 def elf(self,kind=3,align=65536,offset=0,vaddr=0):
  raw=bytearray(120);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',raw,16,kind,183);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1);struct.pack_into('<IIQQQQQQ',raw,64,1,5,offset,vaddr,0,120,120,align);return bytes(raw)
 def test_actual_geometry_rule_accepts16k_capable_aarch64(self):self.assertEqual(I.elf_geometry(self.elf())['machine'],'aarch64')
 def test_wrong_arch_and4k_only_loads_refuse(self):
  wrong=bytearray(self.elf());struct.pack_into('<H',wrong,18,62)
  for raw in (bytes(wrong),self.elf(align=4096),self.elf(offset=4096)):
   with self.assertRaises(ValueError):I.elf_geometry(raw)
 def test_relocatable_data_is_not_promoted_to_runtime_geometry(self):self.assertIn('NOT RUN',I.elf_geometry(self.elf(kind=1))['LOAD_geometry'])
 def test_truncated_or_unhandled_elf_refuses(self):
  for raw in (b'\x7fELF',self.elf()[:100],self.elf(kind=4)):
   with self.assertRaises(ValueError):I.elf_geometry(raw)


class Dependency(unittest.TestCase):
 def data(self):
  lock,root,reference=I.reference();base={'base_packages':[{'name':name,'version':'1'}for name in ['glibc','libgcc','libstdc++',*('base'+str(i)for i in range(108))]]}
  packages={name:{'metadata':{'pkgname':[name],'pkgver':[version],'arch':['any'if name=='cachy-asahi-ksmctl'else'aarch64'],'depend':['python>=3.11']if name=='cachy-asahi-ksmctl'else['glibc']},'payload':{},'logical_bytes':1}for name,version in lock['added_packages'].items()}
  packages['cachy-asahi-ksmctl']['payload']={name:{'type':'0','sha256':'f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558'if name=='usr/bin/cachy-asahi-ksmctl'else'0'*64}for name in ('usr/bin/cachy-asahi-ksmctl','usr/share/doc/a','usr/share/doc/b','usr/share/licenses/a','usr/share/licenses/b')}
  return base,packages
 def call(self,base,packages,library):
  with tempfile.TemporaryDirectory()as tmp:
   directory=Path(tmp)
   for name in packages:(directory/(name+'-fixture.pkg.tar.xz')).touch()
   with patch.object(I,'package',side_effect=lambda path:packages[next(name for name in packages if path.name.startswith(name+'-'))]),patch.object(ctypes,'CDLL',library):return I.closure(directory,base)
 def test_modeled_alpm_abi_seam_keeps_finite_declared_closure(self):
  base,packages=self.data();seen=[]
  def compare(left,right):seen.append((left,right));return 1
  result=self.call(base,packages,lambda name:types.SimpleNamespace(alpm_pkg_vercmp=compare))
  self.assertEqual(result['installed_packages'],114);self.assertEqual(seen,[(b'3.14.8-1',b'3.11')])
 def test_missing_actual_alpm_library_refuses_without_fallback(self):
  base,packages=self.data()
  with self.assertRaisesRegex(OSError,'missing ALPM16'):self.call(base,packages,lambda name:(_ for _ in ()).throw(OSError('missing ALPM16')))
 def test_invented_dependency_refuses(self):
  base,packages=self.data();packages['python']['metadata']['depend']=['not-supplied']
  with self.assertRaisesRegex(ValueError,'missing actual declared'):self.call(base,packages,lambda name:types.SimpleNamespace(alpm_pkg_vercmp=lambda left,right:1))
 def test_wrong_initial_baseline_count_refuses(self):
  base,packages=self.data();base['base_packages'].pop()
  with self.assertRaisesRegex(ValueError,'pristine111'):self.call(base,packages,lambda name:None)


class Probes(unittest.TestCase):
 def test_real_unavailable_is_reported_without_kernel_functionality_credit(self):
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)
   for name in ('status','report'):(p/(name+'.stderr')).write_text('KSM interface unavailable\n')
   self.assertEqual(C.validate(p,3,3)['KSM_kernel_functionality'],'NOT QUALIFIED')
 def test_successful_report_requires_actual16k_pages(self):
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp);value={'tool':'cachy-asahi-ksmctl','version':'0.1.0','mode':'read-only','management_available':False,'page_size_bytes':4096}
   for name in ('status','report'):(p/(name+'.json')).write_text(json.dumps(value))
   with self.assertRaisesRegex(ValueError,'page size'):C.validate(p,0,0)
   value['page_size_bytes']=16384;(p/'report.json').write_text(json.dumps(value));C.validate(p,0,0)
 def test_root_service_has_only_fixed_packages_and_ordinary_alpm(self):
  text=(HERE/'guest-root.sh').read_text();self.assertIn('[[ $# == 0',text)
  self.assertIn('-R cachy-asahi-ksmctl python mpdecimal',text);self.assertIn('python-3.14.8-1-aarch64.pkg.tar.xz',text)
  for flag in ('--nodeps','--noscriptlet','--hookdir','--assume-installed','--overwrite'):self.assertNotIn(flag,text)
  self.assertIn('getfattr --no-dereference',text);self.assertIn('paths meta hash db xattr',text)
 def test_boot_without_admission_cannot_reach_reference_actor(self):
  with patch.object(sys,'argv',['boot.py','--prepared','/absent','--prepared-sha256','a'*64,'--output','/absent']),patch.object(B,'inputs',side_effect=AssertionError('actor must not be reached')),patch.object(sys,'stderr',io.StringIO()),self.assertRaises(SystemExit):B.main()


class Runtime(unittest.TestCase):
 def run_shell(self,body,*args,environment=None):
  with tempfile.TemporaryDirectory()as home:
   env={'PATH':'/usr/bin','HOME':home,'LANG':'C','LC_ALL':'C'}
   if environment:env.update(environment)
   return subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c','. "$1"; '+body,'runtime-test',str(HERE/'guest-runtime.sh'),*map(str,args)],env=env,capture_output=True,timeout=30)
 def files(self,tmp,left,right):
  a=Path(tmp)/'left';b=Path(tmp)/'right';a.write_bytes(left);b.write_bytes(right);return a,b
 def test_actual_binary_nul_and_trailing_newline_equality(self):
  with tempfile.TemporaryDirectory()as tmp:
   for value in (b'',b'\0',b'\0\xff\0binary\n\n',b'trailing\n',bytes(range(256))):
    with self.subTest(value=value):self.assertEqual(self.run_shell('same_bytes "$2" "$3"',*self.files(tmp,value,value)).returncode,0)
 def test_actual_binary_nul_and_trailing_newline_difference(self):
  with tempfile.TemporaryDirectory()as tmp:
   for left,right in ((b'\0',b''),(b'a\0b',b'ab'),(b'end\n',b'end'),(b'\xff',b'\xfe')):
    with self.subTest(left=left):self.assertEqual(self.run_shell('same_bytes "$2" "$3"',*self.files(tmp,left,right)).returncode,1)
 def test_exact16mib_limit_is_allowed(self):
  with tempfile.TemporaryDirectory()as tmp:
   a=Path(tmp)/'left';b=Path(tmp)/'right'
   for path in (a,b):
    with path.open('wb')as stream:stream.truncate(16*1024**2)
   self.assertEqual(self.run_shell('same_bytes "$2" "$3"',a,b).returncode,0)
 def test_over_cap_refuses_before_encoding(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);a,b=self.files(tmp,b'x',b'x')
   with a.open('r+b')as stream:stream.truncate(16*1024**2+1)
   result=self.run_shell('base64() { printf ENCODER_CALLED; return 99; }; same_bytes "$2" "$3"',a,b)
   self.assertEqual(result.returncode,2);self.assertNotIn(b'ENCODER_CALLED',result.stdout)
 def test_symlink_directory_fifo_missing_and_wrong_arity_refused(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);a,b=self.files(tmp,b'x',b'x');link=root/'link';link.symlink_to(a);fifo=root/'fifo';os.mkfifo(fifo)
   for bad in (link,root,fifo,root/'absent'):
    with self.subTest(path=bad):self.assertEqual(self.run_shell('same_bytes "$2" "$3"',bad,b).returncode,2)
   self.assertEqual(self.run_shell('same_bytes "$2"',a).returncode,2)
 def test_encoder_and_stat_failures_cannot_become_equal_empty_outputs(self):
  with tempfile.TemporaryDirectory()as tmp:
   a,b=self.files(tmp,b'x',b'x')
   self.assertEqual(self.run_shell('base64() { return 7; }; same_bytes "$2" "$3"',a,b).returncode,7)
   self.assertEqual(self.run_shell('stat() { return 8; }; same_bytes "$2" "$3"',a,b).returncode,8)
 def test_failed_tool_diagnostic_exports_only_whitelisted_labels(self):
  result=self.run_shell('phase=baseline; failed_line=0; failure_record 52 "cmp --secret PASSWORD" 127 /private/guest-root.sh; failure_fields 127')
  self.assertIn(b'FAILED_PHASE=baseline\n',result.stdout);self.assertIn(b'FAILED_LINE=52\n',result.stdout);self.assertIn(b'FAILED_TOOL=unknown\n',result.stdout)
  self.assertNotIn(b'PASSWORD',result.stdout);self.assertNotIn(b'/private',result.stdout);self.assertNotIn(b'--secret',result.stdout)
 def test_known_failure_expected_probes_and_unknown_phase_are_sanitized(self):
  result=self.run_shell('phase=UNSAFE_SECRET; failed_line=0; expected_probes=1; failure_record 4 "pacman --secret PASSWORD" 3 guest-root.sh; expected_probes=0; failure_record 67 "base64 --secret PASSWORD" 7 guest-runtime.sh; failure_fields 7')
  self.assertIn(b'FAILED_PHASE=unknown\n',result.stdout);self.assertIn(b'FAILED_LINE=67\n',result.stdout);self.assertIn(b'FAILED_TOOL=base64\n',result.stdout);self.assertNotIn(b'PASSWORD',result.stdout);self.assertNotIn(b'UNSAFE_SECRET',result.stdout)
 def test_expected_nonzero_probe_status_is_preserved(self):
  result=self.run_shell('phase=unprivileged-probes; expected_probes=1; failed_line=0; trap \'failure_record "$LINENO" "$BASH_COMMAND" "$?" guest-root.sh\' ERR; mock_probe() { return 3; }; mock_probe; rc=$?; printf "CODE=%s LINE=%s\\n" "$rc" "$failed_line"')
  self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'CODE=3 LINE=0\n')
 def test_errexit_reports_line_tool_without_raw_command(self):
  result=self.run_shell('set -Ee; phase=baseline; failed_line=0; trap \'failure_record "$LINENO" "$BASH_COMMAND" "$?" "${BASH_SOURCE[0]:-unknown}"\' ERR; trap \'rc=$?; trap - ERR EXIT; failure_fields "$rc"\' EXIT; false')
  self.assertEqual(result.returncode,1);self.assertIn(b'FAILED_TOOL=assertion\n',result.stdout);self.assertRegex(result.stdout.decode(),r'FAILED_LINE=[1-9][0-9]*')
 def test_fixed_guard_checks_only_exact_reviewed_baseline_tools(self):
  review=json.loads((HERE/'tools.lock.json').read_text());self.assertEqual(len(review['baseline_tools']),32)
  self.assertEqual(self.run_shell('BASE_TOOLS=(bash base64); require_base_tools').returncode,0)
  result=self.run_shell('phase=tool_presence; failed_line=0; BASE_TOOLS=(not_available_in_fixture); require_base_tools; rc=$?; failure_fields "$rc"; exit "$rc"')
  self.assertEqual(result.returncode,127);self.assertIn(b'FAILED_PHASE=tool_presence\n',result.stdout)
 def test_reviewed_runtime_and_service_source_are_bound(self):
  review=json.loads((HERE/'tools.lock.json').read_text())
  for name,ref in review['reviewed_source'].items():I.checked(HERE/name,ref)
 def test_installed_script_maps_to_fixed_public_label(self):
  result=self.run_shell('phase=trust; failed_line=0; failure_record 81 "gpg --secret PASSWORD" 2 /usr/local/libexec/arm16k-project-lifecycle-root; failure_fields 2')
  self.assertIn(b'FAILED_SOURCE=guest-root.sh\n',result.stdout);self.assertNotIn(b'/usr/local',result.stdout)
 def test_static_namespace_refuses_missing_nonexecutable_and_looped_tools(self):
  T=load('tool_namespace')
  with self.assertRaises(ValueError):T.resolve({},set(),'usr/bin/cmp')
  nodes={'usr/bin/tool':{'type':'0','mode':0o644}}
  with self.assertRaises(ValueError):T.resolve(nodes,set(nodes),'usr/bin/tool')
  nodes={'usr/bin/tool':{'type':'2','link':'tool','mode':0o777}}
  with self.assertRaises(ValueError):T.resolve(nodes,set(nodes),'usr/bin/tool')


class GpgReceipts(unittest.TestCase):
 def shell(self,body,*args,env=None):
  with tempfile.TemporaryDirectory()as home:
   environment={'HOME':home,'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'}
   if env:environment.update(env)
   return subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c','. "$1/guest-runtime.sh"; . "$1/gpg-receipts.sh"; '+body,'receipt-test',str(HERE),*map(str,args)],env=environment,capture_output=True,timeout=15)
 def fixture(self,root,status,keys='',dates='python 200 0\n'):
  (root/'python.status').write_text(status);(root/'python.keys').write_text(keys);(root/'dates').write_text(dates)
 def fields(self,result):return dict(line.split('=',1)for line in result.stdout.decode().splitlines())
 def test_status_categories_dates_and_private_text_redaction(self):
  fp='68B3537F39A313B3E574D06777193F152BDBE6A6'
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);self.fixture(root,'[GNUPG:] EXPKEYSIG PRIVATE_UID\n[GNUPG:] VALIDSIG '+fp+' 1970-01-01 200 0 4 0 1 10 00 '+fp+'\n[GNUPG:] FAILURE SECRET_LOCATION 67108875_SECRET_SYMBOL\n[GNUPG:] SECRET_STATUS PASSWORD\n','pub:u:4096:1:KEY:100:150:::PRIVATE_UID:\nfpr:::::::::'+fp+':\n')
   result=self.shell('gpg_failure_fields python 2 "$2" "$2/dates" 300 1970-01-01T00:05:00Z',root);fields=self.fields(result)
   self.assertEqual(fields['GPG_ERROR_CATEGORY'],'expired_signing_key');self.assertEqual(fields['GPG_ERROR_CODE'],'67108875');self.assertEqual(fields['GPG_UTC_AFTER_KEY_EXPIRY'],'yes');self.assertEqual(fields['GPG_UTC_BEFORE_SIG_CREATION'],'no')
   for private in ('PRIVATE_UID','SECRET_LOCATION','SECRET_SYMBOL','SECRET_STATUS','PASSWORD',fp):self.assertNotIn(private,result.stdout.decode())
 def test_missing_runtime_date_uses_pinned_verified_input_and_named_unknowns(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);self.fixture(root,'[GNUPG:] ERROR verify 67108875\n',dates='python 999999999999 0\n')
   fields=self.fields(self.shell('gpg_failure_fields python 2 "$2" "$2/dates" 300 1970-01-01T00:05:00Z',root))
   self.assertEqual(fields['GPG_SIG_DATE_SOURCE'],'pinned_verified_input');self.assertEqual(fields['GPG_UTC_BEFORE_SIG_CREATION'],'yes');self.assertEqual(fields['GPG_KEY_CREATED'],'unknown')
 def test_unhandled_timestamp_missing_key_and_trust_codes_stay_explicit(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);self.fixture(root,'[GNUPG:] ERRSIG ID 1 10 00 UNHANDLED_ISO 9 -\n[GNUPG:] NO_PUBKEY ID\n[GNUPG:] TRUST_UNDEFINED PRIVATE_TEXT\n',dates='malformed DATA\n')
   fields=self.fields(self.shell('gpg_failure_fields python 2 "$2" "$2/dates" BAD BAD',root))
   self.assertEqual(fields['GPG_ERROR_CATEGORY'],'missing_public_key');self.assertEqual(fields['GPG_SIG_CREATED'],'unknown');self.assertEqual(fields['GPG_UTC'],'unknown');self.assertIn('TRUST_UNDEFINED',fields['GPG_STATUS_CODES'])
 def test_oversized_symlink_and_unknown_archive_data_refuse_or_remain_unknown(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);self.fixture(root,'[GNUPG:] BADSIG SECRET\n')
   (root/'python.status').write_bytes(b'x'*32769)
   fields=self.fields(self.shell('gpg_failure_fields python 2 "$2" "$2/dates" 300 1970-01-01T00:05:00Z',root));self.assertEqual(fields['GPG_STATUS_CODES'],'unknown')
   (root/'python.status').unlink();(root/'python.status').symlink_to(root/'dates')
   self.assertEqual(self.fields(self.shell('gpg_failure_fields python 2 "$2" "$2/dates" 300 1970-01-01T00:05:00Z',root))['GPG_STATUS_CODES'],'unknown')
   self.assertEqual(self.shell('gpg_archive arbitrary.pkg.tar.xz').returncode,2)
 def test_exact_input_signature_date_contract_and_format_hold(self):
  lock=json.loads((HERE/'inputs.lock.json').read_text());statuses={name:lock['materials'][next(key for key in lock['materials']if key.startswith(name+'-')and key.endswith('.pkg.tar.xz'))]['VALIDSIG']for name in lock['added_packages']}
  self.assertEqual(set(I.signature_dates(statuses)),{'ksm','python','mpdecimal'})
  with self.assertRaisesRegex(ValueError,'timestamp format'):I.signature_dates({**statuses,'python':statuses['python'].replace('1791644569','UNHANDLED_ISO')})
 def mock_verification(self,root,large=False):
  directory=root/'fixture';directory.mkdir();(directory/'materials').mkdir();(directory/'trust').mkdir();(directory/'signature-dates.lock').write_text('python 200 0\n')
  binpath=root/'bin';binpath.mkdir();script=binpath/'gpg'
  status=b'[GNUPG:] GOODSIG SECRET_UID\n[GNUPG:] FAILURE verify 67108875\n'
  code='import os,sys,signal\nsignal.signal(signal.SIGXFSZ,signal.SIG_DFL)\n'
  code+="if '--list-keys' in sys.argv:\n os.write(1,b'pub:u:4096:1:ID:100:::::UID:\\n');sys.exit(0)\n"
  code+='os.write(1,'+repr(b'x'*131072 if large else status)+')\nos.write(2,b\'ARBITRARY_PRIVATE_ERROR\')\nsys.exit(2)\n'
  script.write_text('#!'+sys.executable+'\n'+code);script.chmod(0o755)
  return directory,binpath
 def test_failed_verification_persists_bounded_private_receipts_not_raw_export(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);directory,binpath=self.mock_verification(root)
   result=self.shell('D=$2;phase=trust;failed_line=0;gpg_verify_fixed python-3.14.8-1-aarch64.pkg.tar.xz; rc=$?;failure_fields "$rc";cat "$D/receipts/gpg-failure.env";exit "$rc"',directory,env={'PATH':str(binpath)+':/usr/bin'})
   self.assertEqual(result.returncode,2);self.assertNotIn(b'ARBITRARY_PRIVATE_ERROR',result.stdout+result.stderr);self.assertNotIn(b'SECRET_UID',result.stdout+result.stderr)
   receipts=directory/'receipts';self.assertEqual(receipts.stat().st_mode&0o777,0o700)
   for path in receipts.iterdir():self.assertLessEqual(path.stat().st_size,32768);self.assertEqual(path.stat().st_mode&0o777,0o600)
   self.assertIn('ARBITRARY_PRIVATE_ERROR',(receipts/'python.stderr').read_text());self.assertIn(b'FAILED_SOURCE=gpg-receipts.sh',result.stdout)
 def test_trust_import_is_fixed_bounded_and_has_no_invented_archive_dates(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);directory,binpath=self.mock_verification(root)
   result=self.shell('D=$2;phase=trust;failed_line=0;gpg_run_fixed trust_import; rc=$?;cat "$D/receipts/gpg-failure.env";exit "$rc"',directory,env={'PATH':str(binpath)+':/usr/bin'})
   self.assertEqual(result.returncode,2);fields=self.fields(result);self.assertEqual(fields['GPG_ARCHIVE'],'none');self.assertEqual(fields['GPG_OPERATION'],'trust_import');self.assertEqual(fields['GPG_SIG_CREATED'],'unknown');self.assertNotIn(b'ARBITRARY_PRIVATE_ERROR',result.stdout+result.stderr)
 def test_receipt_limit_and_existing_leaf_refusal_do_not_overwrite(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);directory,binpath=self.mock_verification(root,large=True)
   result=self.shell('D=$2;phase=trust;failed_line=0;gpg_verify_fixed python-3.14.8-1-aarch64.pkg.tar.xz; rc=$?;cat "$D/receipts/gpg-failure.env";exit "$rc"',directory,env={'PATH':str(binpath)+':/usr/bin'})
   self.assertNotEqual(result.returncode,0);self.assertLessEqual((directory/'receipts/python.status').stat().st_size,32768);self.assertNotIn(b'--verify',result.stderr)
   before=(directory/'receipts/python.status').read_bytes();again=self.shell('D=$2;phase=trust;failed_line=0;gpg_verify_fixed python-3.14.8-1-aarch64.pkg.tar.xz',directory,env={'PATH':str(binpath)+':/usr/bin'})
   self.assertEqual(again.returncode,2);self.assertEqual((directory/'receipts/python.status').read_bytes(),before)


if __name__=='__main__':unittest.main(verbosity=2)
