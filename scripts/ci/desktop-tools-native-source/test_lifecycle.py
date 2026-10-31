#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-denied TEST-update source, build, transaction and failure DATA controls."""
import copy,importlib.util,io,json,os,sys,tarfile,tempfile,unittest
from pathlib import Path
from types import ModuleType,SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE/'payload/native'))
import desktop_tools_v1 as T
import desktop_alpm_v1 as A

def deny(event,args):
 if event.startswith(('subprocess.','socket.')) or event in {'os.system','os.posix_spawn','os.fork','os.exec'}:raise AssertionError('DATA controls forbid actor:'+event)
sys.addaudithook(deny)

def row(raw,mode=0o644):return dict(mode=mode,**T.data_pin(raw))
def tar_bytes(rows):
 buffer=io.BytesIO()
 with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as archive:
  for name,(raw,mode,kind) in rows.items():
   info=tarfile.TarInfo(name);info.uid=info.gid=info.mtime=0;info.mode=mode;info.type=tarfile.DIRTYPE if kind=='directory' else tarfile.REGTYPE;info.size=0 if kind=='directory' else len(raw)
   archive.addfile(info,None if kind=='directory' else io.BytesIO(raw))
 return buffer.getvalue()

class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='desktop-update-data-');self.addCleanup(self.temp.cleanup);self.p=Path(self.temp.name)
  self.prefix=self.p/'prefix';self.prefix.mkdir();self.source=self.prefix/'source';(self.source/'native').mkdir(parents=True)
  self.baseline=b'# SYNTHETIC inert recipe DATA\npkgname=cachy-asahi-desktop-tools\npkgver=0.1.0\npkgrel=1\n'
  self.members={'recipe/PKGBUILD':self.baseline,'recipe/'+T.SOURCE_ARCHIVE:b'ORIGINAL SYNTHETIC SOURCE ARCHIVE; NO BUILD','recipe/export_source.py':b'# inert export fixture\n','recipe/test_export_source.py':b'# inert control fixture\n','update/PKGBUILD':T.update_recipe_bytes(self.baseline)}
  paths=['usr/bin/'+T.NAME,'usr/lib/'+T.NAME+'/cli.py','usr/lib/'+T.NAME+'/desktop_applications.py','usr/share/doc/'+T.NAME+'/PROVENANCE.json','usr/share/doc/'+T.NAME+'/README.md','usr/share/licenses/'+T.NAME+'/LICENSE']
  self.payload={name:('ORIGINAL SIX-FILE SYNTHETIC PAYLOAD '+name+'\n').encode() for name in paths}
  files={name:row(self.members['recipe/'+name]) for name in T.SOURCE_FILES}
  update=copy.deepcopy(files);update['PKGBUILD']=row(self.members['update/PKGBUILD'])
  self.base=''.join('fixture%03d 1.0-1\n'%i for i in range(349)).encode()
  self.policy=dict(recipe=dict(version=T.VERSION,archive=T.NAME+'-'+T.VERSION+'-any.pkg.tar.zst',expected_test_count=81,source_files=files,payload_files={name:row(raw,0o755 if '/bin/' in name else 0o644) for name,raw in self.payload.items()}),update_recipe=dict(scope=T.UPDATE_FIXTURE,version=T.UPDATE_VERSION,archive=T.NAME+'-'+T.UPDATE_VERSION+'-any.pkg.tar.zst',expected_test_count=81,source_files=update),bundle=dict(path='native/desktop-sources-v1.tar',max_bytes=1024**2,members=5),makepkg_config=dict(path='native/desktop-makepkg-v1.conf'),build_pair=dict(source_date_epoch='1793145600',packager='TEST builder'),buildinfo_installed=['fixture%03d-1.0-1-aarch64'%i for i in range(349)])
  self.write_bundle()
  (self.source/'native/desktop-contract-v1.json').write_bytes(T.encoded(self.policy));(self.source/'native/desktop-makepkg-v1.conf').write_bytes(b'INERT configuration fixture\n')
  self.alarm=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
 def write_bundle(self):
  raw=tar_bytes({name:(body,0o644,'file') for name,body in self.members.items()});(self.source/self.policy['bundle']['path']).write_bytes(raw);self.policy['bundle'].update(T.data_pin(raw))
 def recipes(self):return T.extract_recipes(self.source,self.prefix/'inputs',self.policy)
 def build_report(self):return dict(builds={},stages=[])
 def build_run(self,step,argv,cwd):
  name=self.policy['update_recipe' if step=='build-update' else 'recipe']['archive'];(cwd/name).write_bytes(b'SYNTHETIC PACKAGE DATA '+(b'update' if step=='build-update' else b'baseline'))
  return b'Starting check()\nRan 81 tests in 1s\n\nOK\n'
 def build_baseline(self,recipes,report):
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'):
   archives=A.build_pair(self.build_run,self.source,recipes,self.policy,self.alarm,report)
  report['stages'].append('compare');return archives
 def archive_model(self,version=T.UPDATE_VERSION,recipe_hash=None):
  recipe=self.policy['update_recipe'] if version==T.UPDATE_VERSION else self.policy['recipe']
  pkg=('pkgname = '+T.NAME+'\npkgbase = '+T.NAME+'\npkgver = '+version+'\narch = any\nlicense = MIT\ndepend = python>=3.11\n').encode()
  build=('format = 2\npkgname = '+T.NAME+'\npkgbase = '+T.NAME+'\npkgver = '+version+'\npkgarch = any\npkgbuild_sha256sum = '+(recipe_hash or recipe['source_files']['PKGBUILD']['sha256'])+'\nbuildenv = check\n'+''.join('installed = '+name+'\n' for name in self.policy['buildinfo_installed'])).encode()
  entries={'.PKGINFO':(pkg,0o644,'file'),'.BUILDINFO':(build,0o644,'file'),'.MTREE':(b'SYNTHETIC MTREE MODEL',0o644,'file')}
  for name,item in self.policy['recipe']['payload_files'].items():
   entries[name]=(self.payload[name],item['mode'],'file')
   for parent in Path(name).parents:
    if str(parent)!='.':entries[str(parent)]=(b'',0o755,'directory')
  return tar_bytes(entries)
 def test_exact_generated_five_source_bundle_three_independent_trees(self):
  members=T.recipe_members(self.source,self.policy);self.assertEqual(len(members),5);root=self.recipes()
  self.assertEqual({p.name for p in root.iterdir()},{'a','b','update'})
  self.assertEqual(len({(root/name).stat().st_ino for name in ('a','b','update')}),3)
  for name in T.SOURCE_FILES:
   self.assertEqual((root/'a'/name).read_bytes(),(root/'b'/name).read_bytes())
   self.assertEqual((root/'update'/name).read_bytes(),members['update/PKGBUILD' if name=='PKGBUILD' else 'recipe/'+name])
 def test_generation_proof_only_pkgrel_and_held_source_payload(self):
  proof=T.update_generation(self.policy,self.members)
  self.assertEqual(proof['scope'],T.UPDATE_FIXTURE);self.assertEqual(proof['recipe_before'],T.data_pin(self.baseline));self.assertEqual(proof['recipe_after'],T.data_pin(T.update_recipe_bytes(self.baseline)))
  self.assertEqual(proof['replacement'],dict(before='pkgrel=1\n',after='pkgrel=2\n',count=1));self.assertEqual(proof['changed_sources'],['PKGBUILD']);self.assertTrue(proof['unchanged_payload'])
 def test_duplicate_or_nonexact_pkgrel_refused(self):
  for raw in (self.baseline+b'pkgrel=1\n',self.baseline.replace(b'pkgrel=1',b'pkgrel = 1'),self.baseline+b'pkgrel=9\n'):
   with self.subTest(raw=raw),self.assertRaisesRegex(ValueError,'one exact'):T.update_recipe_bytes(raw)
 def test_rebound_extra_change_cannot_pass_generation(self):
  self.members['update/PKGBUILD']+=b'# unrelated change\n';self.policy['update_recipe']['source_files']['PKGBUILD']=row(self.members['update/PKGBUILD']);self.write_bundle()
  with self.assertRaisesRegex(ValueError,'one-line'):self.recipes()
  self.assertFalse((self.prefix/'inputs').exists())
 def test_shared_source_change_refused(self):
  self.policy['update_recipe']['source_files'][T.SOURCE_ARCHIVE]=row(b'different')
  with self.assertRaisesRegex(ValueError,'only PKGBUILD'):T.update_policy(self.policy)
 def test_non_test_scope_or_payload_change_refused(self):
  for mutate in ('scope','payload'):
   value=copy.deepcopy(self.policy)
   if mutate=='scope':value['update_recipe']['scope']='RELEASE'
   else:value['update_recipe']['payload_files']={}
   with self.subTest(mutate=mutate),self.assertRaises(ValueError):T.update_policy(value)
 def test_missing_or_extra_update_member_refused_before_output(self):
  self.members['update/other']=b'extra';self.write_bundle()
  with self.assertRaisesRegex(ValueError,'exact regular'):self.recipes()
  self.assertFalse((self.prefix/'inputs').exists())
 def test_baseline_pair_stays_two_clean81_builds(self):
  recipes=self.recipes();report=self.build_report();calls=[]
  def run(step,argv,cwd):calls.append((step,argv,str(cwd)));return self.build_run(step,argv,cwd)
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'):A.build_pair(run,self.source,recipes,self.policy,self.alarm,report)
  self.assertEqual(report['stages'],['build-a','build-b']);self.assertEqual(calls[0][1:],calls[1][1:]);self.assertNotIn('update',report['builds']);self.assertEqual(set(p.name for p in (recipes/'update').iterdir()),set(T.SOURCE_FILES))
 def test_update_is_fresh_clean81_build_same_slot(self):
  recipes=self.recipes();report=self.build_report();self.build_baseline(recipes,report)
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'):archive=A.build_update(self.build_run,self.source,recipes,self.policy,self.alarm,report)
  self.assertEqual(archive,recipes/'update'/self.policy['update_recipe']['archive']);self.assertEqual(report['builds']['update']['check_tests'],81);self.assertEqual(report['builds']['update']['fixture'],T.UPDATE_FIXTURE);self.assertFalse((self.prefix/'build-current').exists())
  self.assertEqual(len({tuple(item['build_directory']['identity'].values()) for item in report['builds'].values()}),3)
 def test_update_failed_check_restores_tree_and_preserves_first_error(self):
  recipes=self.recipes();report=self.build_report();self.build_baseline(recipes,report);first=ValueError('first update check')
  def fail(*args,**kwargs):raise first
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'),self.assertRaises(ValueError) as found:A.build_update(fail,self.source,recipes,self.policy,self.alarm,report)
  self.assertIs(found.exception,first);self.assertFalse((self.prefix/'build-current').exists());self.assertTrue((recipes/'update').is_dir());self.assertNotIn('build-update',report['stages'])
 def test_incomplete_update_check_refused(self):
  recipes=self.recipes();report=self.build_report();self.build_baseline(recipes,report)
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'),self.assertRaisesRegex(ValueError,'complete81'):
   A.build_update(lambda *a,**k:b'Starting check()\nRan 80 tests in 1s\nOK\n',self.source,recipes,self.policy,self.alarm,report)
  self.assertFalse((self.prefix/'build-current').exists())
 def test_update_input_tamper_refuses_before_command(self):
  recipes=self.recipes();report=self.build_report();self.build_baseline(recipes,report);(recipes/'update'/'PKGBUILD').write_bytes(b'changed');calls=[]
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'),self.assertRaisesRegex(ValueError,'input bytes'):
   A.build_update(lambda *a,**k:calls.append(a),self.source,recipes,self.policy,self.alarm,report)
  self.assertEqual(calls,[]);self.assertFalse((self.prefix/'build-current').exists())
 def test_inventory_only_two_finite_versions(self):
  for version in (T.VERSION,T.UPDATE_VERSION):self.assertIn((T.NAME+' '+version+'\n').encode(),T.inventory_expected(self.base,version))
  with self.assertRaises(ValueError):T.inventory_expected(self.base,'0.1.0-3')
 def test_update_archive_same_payload_new_provenance(self):
  archive=self.p/'update.pkg.tar.zst';archive.write_bytes(b'INERT COMPRESSED MODEL');calls=[]
  result=T.compare_update(lambda step,argv:(calls.append((step,argv)) or self.archive_model()),archive,self.policy,'a'*64)
  self.assertEqual(result['status'],'PASS_TEST_LIFECYCLE_UPDATE_ARCHIVE');self.assertEqual(result['fixture'],T.UPDATE_FIXTURE);self.assertEqual(result['version'],T.UPDATE_VERSION);self.assertEqual(result['payload'],self.policy['recipe']['payload_files']);self.assertEqual(result['base_inventory_count'],349);self.assertEqual(calls,[('archive-update',['/usr/bin/zstd','-dc',str(archive)])])
 def test_baseline_metadata_cannot_qualify_update(self):
  archive=self.p/'update.pkg.tar.zst';archive.write_bytes(b'INERT')
  with self.assertRaisesRegex(ValueError,'PKGINFO pkgver'):T.compare_update(lambda *a:self.archive_model(T.VERSION),archive,self.policy,'a'*64)
 def test_update_wrong_recipe_provenance_refused(self):
  archive=self.p/'update.pkg.tar.zst';archive.write_bytes(b'INERT')
  with self.assertRaisesRegex(ValueError,'pkgbuild_sha256sum'):T.compare_update(lambda *a:self.archive_model(recipe_hash='b'*64),archive,self.policy,'a'*64)
 def test_missing_update_supervision_is_unknown_data_only(self):
  commands=SimpleNamespace(records=[]);A.retain_exception(commands,self.p,'build-update',['/fixed/build'],self.p,0,RuntimeError(),0)
  self.assertIsNone(commands.records[0]['supervision']);self.assertEqual(commands.records[0]['output_state'],'UNKNOWN_IF_SUPERVISION_DID_NOT_RETURN');self.assertFalse(commands.records[0]['success'])
 def test_cleanup_never_overwrites_update_first_failure(self):
  first=ValueError('update first failure');self.assertIs(A.primary_failure(first,dict(failures=['cleanup later'])),first)
 def inside_model(self,fail_step=None,wrong_version=False,cleanup_failure=False):
  """Exercise actual actor control flow with DATA-only command responses."""
  calls=[];state=dict(version=None,failed=False)
  fingerprint='A'*40
  signature=('[GNUPG:] VALIDSIG '+fingerprint+' 2026-10-31 1793404800 0 4 0 22 8 00 '+fingerprint+'\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n').encode()
  original_copy=A.shutil.copyfile;original_lexists=os.path.lexists;source=self.source;policy=self.policy;test=self
  def copy_file(src,dst,*args,**kwargs):
   if str(src) in self.payload:Path(dst).write_bytes(self.payload[str(src)]);return str(dst)
   if str(src).startswith('/') and str(src).lstrip('/') in self.payload:Path(dst).write_bytes(self.payload[str(src).lstrip('/')]);return str(dst)
   return original_copy(src,dst,*args,**kwargs)
  def lexists(path):
   if str(path).startswith('/usr/') and T.NAME in str(path):return False
   return original_lexists(path)
  def protected():calls.append('protected-state');return {name:dict(files=1,bytes=10,sha256='d'*64) for name in ('alpm_db','alarm_home','root_home','global_trust','global_config','package_cache')}
  class Lock:
   def is_file(self):return True
   def read_bytes(self):return test.base
  def path(value,*args):return Lock() if str(value)=='/builder-packages.lock' and not args else Path(value,*args)
  class Commands:
   def __init__(self,output,home,tool_path,**kwargs):self.output=output;self.records=[]
   def run(self,step,argv,cwd,expected=0):
    calls.append(step);raw=b'';error=None
    if step in ('build-a','build-b','build-update'):raw=test.build_run(step,argv,cwd)
    elif step=='test-primary-fingerprint' or step=='trust-key-membership':raw=('fpr:::::::::'+fingerprint+':\n').encode()
    elif step=='export-only-test-public':raw=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC PUBLIC TEST DATA\n-----END PGP PUBLIC KEY BLOCK-----\n'
    elif step.startswith('sign-'):Path(argv[argv.index('--output')+1]).write_bytes(('SYNTHETIC SIGNATURE '+step).encode())
    elif step.startswith('verify-'):raw=signature
    elif step=='untrusted-signature-control':raw=b'[GNUPG:] NO_PUBKEY AAAAAAAAAAAAAAAA\n'
    elif step=='tampered-signature-control':raw=b'[GNUPG:] BADSIG AAAAAAAAAAAAAAAA synthetic\n'
    elif step=='required-signature-config':raw=Path(argv[-1]).read_bytes()
    elif step=='install':state['version']=T.VERSION
    elif step=='update':state['version']=T.UPDATE_VERSION
    elif step in ('remove','cleanup-remove'):state['version']=None
    elif step.endswith('-inventory'):
     raw=T.inventory_expected(test.base,state['version'])
    elif step.startswith('no-autostart-'):raw=A.AGENT_ABSENT
    elif step=='updated-package-version':raw=(T.NAME+' '+('WRONG' if wrong_version else T.UPDATE_VERSION)+'\n').encode()
    elif step.endswith('-explicit'):raw=b'fixture000\n'
    elif step.endswith('-dependencies'):raw=b'fixture001\n'
    if step==fail_step and not state['failed']:
     state['failed']=True;raw=b'SYNTHETIC FIRST UPDATE FAILURE\n';error=ValueError('first update command failed')
    if cleanup_failure and step=='retire-signing':error=ValueError('later cleanup failure')
    name='%03d-%s.log'%(len(self.records),step);(self.output/name).write_bytes(raw)
    self.records.append(dict(step=step,argv=argv,cwd=str(cwd),expected=expected,success=error is None,log=name,log_pin=T.data_pin(raw),supervision=dict(exit=1 if error else 0,ownership='REAPED')))
    if error:raise error
    return raw
  def payload(root,policy,run,pacman,version=T.VERSION):calls.append('payload-'+version);return dict(version=version,count=6,verified=True,files=policy['recipe']['payload_files'])
  def business(run,cli,root,uid,gid,label,version=T.VERSION):
   calls.append('business-'+label);test.assertEqual(version,T.UPDATE_VERSION if label=='updated' else T.VERSION)
   root.mkdir();(root/'output.json').write_bytes(b'SYNTHETIC BUSINESS DATA; NO CLI OR PAYLOAD EXECUTION')
   return dict(status='PASS_ACTUAL_STATIC_CAPTURE_AUDIT_REFUSAL',version=version,payload_cli_version='0.1.0')
  common=ModuleType('common');common.verify_source=lambda *args:None
  with patch.dict(sys.modules,{'common':common}),patch.object(A,'PREFIX',self.prefix),patch.object(A,'SOURCE',self.source),patch.object(A,'STORE',self.prefix/'evidence'),patch.object(A,'Path',side_effect=path),patch.object(A.os,'getuid',return_value=0),patch.object(A.os,'geteuid',return_value=0),patch.object(A.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(A.os,'chown'),patch.object(A.os.path,'lexists',side_effect=lexists),patch.object(A.pwd,'getpwnam',return_value=self.alarm),patch.object(A,'protected_state',side_effect=protected),patch.object(T,'source_policy',return_value=(self.policy,self.base)),patch.object(T,'load_workflow',return_value=SimpleNamespace(Commands=Commands)),patch.object(T,'compare_archives',return_value=dict(status='SYNTHETIC_PAIR_DATA_ONLY')),patch.object(T,'compare_update',return_value=dict(status='SYNTHETIC_UPDATE_DATA_ONLY')),patch.object(T,'check_payload',side_effect=payload),patch.object(T,'business',side_effect=business),patch.object(A.shutil,'copyfile',side_effect=copy_file):
   report=A.inside(self.source,'a'*64)
  persisted=json.loads((self.prefix/'evidence/journey/desktop-alpm-v1/result.json').read_text());self.assertEqual(persisted,report)
  return report,calls
 def test_mocked_install_update_remove_complete_order_and_restoration(self):
  report,calls=self.inside_model()
  self.assertEqual(report['status'],A.PASS);self.assertEqual(report['stages'],list(T.STAGES));self.assertEqual(set(report['signatures']),{'a','b','update'})
  self.assertEqual([report['inventory'][name]['version'] for name in ('baseline','installed','updated','removed')],[None,T.VERSION,T.UPDATE_VERSION,None]);self.assertEqual(report['payloads']['updated']['version'],T.UPDATE_VERSION)
  self.assertEqual(report['business']['updated']['version'],T.UPDATE_VERSION);self.assertTrue(report['update_exports_preserved']);self.assertTrue(report['exports_preserved']);self.assertTrue(all(row['unchanged'] for row in report['restore'].values()));self.assertTrue(report['cleanup']['private_directory_absent'])
  self.assertLess(calls.index('business-moved'),calls.index('update'));self.assertLess(calls.index('update'),calls.index('updated-package-version'));self.assertLess(calls.index('payload-'+T.UPDATE_VERSION),calls.index('business-updated'));self.assertLess(calls.index('business-updated'),calls.index('remove'));self.assertLess(calls.index('remove'),calls.index('retire-signing'))
 def test_committed_update_failure_keeps_first_diagnostic_before_cleanup(self):
  report,calls=self.inside_model(fail_step='update',cleanup_failure=True)
  self.assertEqual(report['status'],'FAIL');self.assertEqual(report['first_failure']['phase'],'update');self.assertEqual(report['first_failure']['message'],'first update command failed');self.assertEqual(report['failure'],report['first_failure']);self.assertNotIn('business-updated',calls)
  self.assertLess(calls.index('update'),calls.index('cleanup-inventory'));self.assertLess(calls.index('cleanup-remove'),calls.index('retire-signing'));self.assertLess(calls.index('retire-trust'),len(calls)-1);self.assertTrue(report['cleanup']['private_directory_absent'])
  failed=[row for row in report['commands'] if row['step']=='update'][0];self.assertFalse(failed['success']);self.assertEqual((self.prefix/'evidence/journey/desktop-alpm-v1'/failed['log']).read_bytes(),b'SYNTHETIC FIRST UPDATE FAILURE\n')
 def test_wrong_actual_update_version_refuses_and_removes_before_trust_retirement(self):
  report,calls=self.inside_model(wrong_version=True)
  self.assertEqual(report['status'],'FAIL');self.assertEqual(report['first_failure']['phase'],'updated-package-version');self.assertNotIn('business-updated',calls);self.assertIn('cleanup-remove',calls);self.assertLess(calls.index('cleanup-remove'),calls.index('retire-signing'))

 def test_update_archive_changed_original_payload_refused(self):
  archive=self.p/'update.pkg.tar.zst';archive.write_bytes(b'INERT')
  self.payload[next(iter(self.payload))]+=b'changed'
  with self.assertRaisesRegex(ValueError,'payload bytes'):T.compare_update(lambda *a:self.archive_model(),archive,self.policy,'a'*64)
 def test_update_build_failure_retained_before_any_signature_actor(self):
  report,calls=self.inside_model(fail_step='build-update')
  self.assertEqual(report['status'],'FAIL');self.assertEqual(report['first_failure']['phase'],'build-update');self.assertNotIn('generate-test-key',calls);self.assertNotIn('install',calls);self.assertNotIn('update',calls);self.assertTrue(report['cleanup']['private_directory_absent'])
  self.assertFalse(report['builds']['update']['check_invoked']);self.assertNotIn('build-update',report['stages'])
 def test_updated_business_uses_original_static_payload_inprocess(self):
  # Read source-bound code as DATA from the maintained five-member bundle.
  source=HERE/'payload';policy=json.loads((source/'native/desktop-contract-v1.json').read_text());members=T.recipe_members(source,policy)
  library=self.p/'original-static-library';library.mkdir()
  with tarfile.open(fileobj=io.BytesIO(members['recipe/'+T.SOURCE_ARCHIVE]),mode='r:gz') as archive:
   for name in ('cli.py','desktop_applications.py'):
    raw=archive.extractfile('cachy-asahi-desktop-tools-0.1.0/payload/lib/'+T.NAME+'/'+name).read()
    self.assertEqual(T.data_pin(raw),{key:policy['recipe']['payload_files']['usr/lib/'+T.NAME+'/'+name][key] for key in ('bytes','sha256')});(library/name).write_bytes(raw)
  spec=importlib.util.spec_from_file_location('updated_static_cli_control',library/'cli.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
  calls=[]
  def run(step,argv,expected=0,cwd=None):
   import contextlib
   calls.append((step,expected));output=io.StringIO()
   with contextlib.redirect_stdout(output):code=cli.main(argv[7:])
   self.assertEqual(code,expected);return output.getvalue().encode()
  value=T.business(run,Path('/usr/bin')/T.NAME,self.p/'updated-business',os.getuid(),os.getgid(),'updated',T.UPDATE_VERSION)
  self.assertEqual(value['version'],T.UPDATE_VERSION);self.assertEqual(value['payload_cli_version'],'0.1.0');self.assertEqual(value['fixture'],T.UPDATE_FIXTURE);self.assertTrue(value['zero_payload_execution']);self.assertEqual(calls,[('updated-capture',0),('updated-audit',0),('updated-moved-root',0),('updated-changed-data',2)])

 def test_update_slot_custody_loss_does_not_mask_original_build_failure(self):
  recipes=self.recipes();report=self.build_report();self.build_baseline(recipes,report);first=ValueError('original update build failure')
  def fail(step,argv,cwd):cwd.rename(self.prefix/'quarantined-slot');raise first
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'),self.assertRaises(ValueError) as found:A.build_update(fail,self.source,recipes,self.policy,self.alarm,report)
  self.assertIs(found.exception,first);self.assertEqual(report['builds']['update']['build_directory']['restoration'],'UNKNOWN_NO_CUSTODY_FALLBACK');self.assertFalse((recipes/'update').exists());self.assertTrue((self.prefix/'quarantined-slot').is_dir())

 def test_baseline_slot_custody_loss_does_not_mask_original_build_failure(self):
  recipes=self.recipes();report=self.build_report();first=ValueError('original baseline build failure');calls=[]
  def fail(step,argv,cwd):calls.append(step);cwd.rename(self.prefix/'quarantined-baseline-slot');raise first
  with patch.object(A,'PREFIX',self.prefix),patch.object(A.os,'chown'),self.assertRaises(ValueError) as found:A.build_pair(fail,self.source,recipes,self.policy,self.alarm,report)
  self.assertIs(found.exception,first);self.assertEqual(calls,['build-a']);self.assertEqual(report['builds']['a']['build_directory']['restoration'],'UNKNOWN_NO_CUSTODY_FALLBACK');self.assertFalse((recipes/'a').exists());self.assertTrue((recipes/'b').is_dir());self.assertTrue((self.prefix/'quarantined-baseline-slot').is_dir());self.assertEqual(report['stages'],[])

if __name__=='__main__':unittest.main(verbosity=2)
