# SPDX-License-Identifier: MIT
"""Source/fiction controls only. No build, ALPM, GPG, Reader or Docker executes."""
import ast
import copy
import ctypes  # Preload stdlib; all later ctypes operations are fenced.
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
def module(name):
 s=importlib.util.spec_from_file_location('current_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
N=module('native');C=module('prepare');PROFILE=json.loads((HERE/'profile.json').read_bytes());INPUTS=json.loads((HERE/'inputs.TEMPLATE.json').read_bytes());SHA=hashlib.sha256((HERE/'profile.json').read_bytes()).hexdigest()
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):raise RuntimeError('fenced '+event)
sys.addaudithook(fence)
def populated(stage='backend'):
 v=copy.deepcopy(INPUTS)
 v.update(source={'FICTION':True},source_date_epoch=1791748800,Root_admission={'FICTION':True},Root_capacity={'build_seconds':180,'builder_cpus':4,'builder_memory_bytes':4*1024**3,'builder_pids':512},image_namespace_qualification={'FICTION':True})
 packages={n:'FICTION'for n in ['python','gnupg','pacman','coreutils','libarchive','bubblewrap','util-linux','fish','zsh','gtk4','python-gobject']};packages.update({'cachy-asahi-setup':'0.3.0-1','cachy-asahi-first-login':'0.1.0-3'})
 for prefix in ('','ui_'):v[prefix+'builder_image']='sha256:'+'a'*64;v[prefix+'builder_inventory']=dict(path='/FICTION/inventory.lock',bytes=123,sha256='b'*64,packages=packages.copy())
 for name in ['archive','signature','current_TEST_signature_verification']:v['setup8'][name]={'FICTION':True}
 for name in ['native_pair','archive','signature','current_TEST_signature_verification']:v['first_login_backend'][name]={'FICTION':True}
 for name in ['exact_closure','archive_signature_inputs','verification']:v['official_ui_dependencies'][name]={'FICTION':True}
 return v

def log(kind):
 body=b'==> Starting check()...\n'
 if kind=='enrollment':return body+json.dumps(PROFILE['enrollment_check_report']).encode()+b'\n'
 return body+b''.join(('Ran '+str(n)+' tests in 0.123s\n\nOK\n').encode()for n in PROFILE['packages'][kind]['check_counts'])

class Controls(unittest.TestCase):
 def test_exact_current_versions_payloads_and_held_bases(self):
  N.policy(PROFILE);self.assertEqual([len(PROFILE['packages'][k]['payload_files'])for k in N.KINDS],[16,6,8])
  for kind in N.KINDS:
   bad=copy.deepcopy(PROFILE);bad['packages'][kind]['version']='0.0.0-1'
   with self.assertRaises(ValueError):N.policy(bad)
  for name,row in PROFILE['prior_factory'].items():
   f=HERE.parent/name;raw=f.read_bytes();self.assertEqual(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=f.stat().st_mode&0o777),row)
 def test_real_source_staging_and_exact_map(self):
  H,files,result=C.construct(ROOT,SHA);self.assertEqual(result['files'],59);self.assertEqual(set(json.loads(files['source.lock.json'][0])['files']),set(files)-{'source.lock.json'})
  for name in ['scripts/build/build.py','scripts/build/container-entry.sh','scripts/build/compare.py']:
   self.assertEqual(files[name][0],(ROOT/name).read_bytes())
  self.assertTrue(all(v is None for v in result['actual'].values()));self.assertEqual(result['status'],'STAGED_CURRENT_SOURCE_ONLY_NOT_NATIVE_READY')
 def test_external_profile_pin_refuses(self):
  with self.assertRaises(ValueError):C.construct(ROOT,'0'*64)
 def test_source_drift_extra_alias_and_hardlink_refuse(self):
  H,files,_=C.construct(ROOT,SHA)
  with tempfile.TemporaryDirectory(prefix='current-first-login-source-DATA-')as temp:
   root=Path(temp)
   for name,(raw,mode)in files.items():
    if name.startswith(('packages/','scripts/')):
     f=root/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(raw);f.chmod(mode)
   target=root/PROFILE['packages']['first-login']['path']/'first_login.py';old=target.read_bytes()
   target.write_bytes(old+b'\n')
   with self.assertRaises(ValueError):C.construct(root,SHA)
   target.write_bytes(old);extra=target.parent/'EXTRA';extra.write_text('FICTION')
   with self.assertRaises(ValueError):C.construct(root,SHA)
   extra.unlink();target.rename(extra);target.symlink_to(extra)
   with self.assertRaises(ValueError):C.construct(root,SHA)
   target.unlink();extra.rename(target)
   import os
   os.link(target,root/'alias')
   with self.assertRaises(ValueError):C.construct(root,SHA)
 def test_null_missing_inputs_are_honest_and_default_refuses(self):
  d=N.missing_inputs(INPUTS);self.assertEqual(d['status'],'HOLD_MISSING_PROSPECTIVE_INPUTS');self.assertIn('first_login_backend.archive',d['missing']);self.assertIn('official_ui_dependencies.exact_closure',d['missing']);self.assertIsNone(d['Root_acceptance'])
  for stage in ['backend','ui']:
   with self.assertRaises(ValueError):N.build_vectors('/FICTION/source',PROFILE,INPUTS,stage,'/FICTION/output')
 def test_exact_six_builds_three_comparisons_offline_no_bypass(self):
  rows=N.build_vectors('/FICTION/source',PROFILE,populated(),'backend','/FICTION/output')+N.build_vectors('/FICTION/source',PROFILE,populated(),'ui','/FICTION/output')
  self.assertEqual(len(rows),9);self.assertEqual(sum(r['label']=='compare'for r in rows),3)
  for row in rows:
   argv=row['argv'];self.assertNotIn('--nodeps',argv);self.assertNotIn('--nocheck',argv)
   if row['label']=='compare':self.assertIn('--require-bytes',argv)
   else:self.assertEqual(argv[argv.index('--network')+1],'none');self.assertEqual(argv[argv.index('--timeout')+1],'180');self.assertEqual(argv[argv.index('--mode')+1],'native')
 def test_missing_setup_backend_official_or_namespace_refuses(self):
  for field in ['image_namespace_qualification','Root_admission','Root_capacity','source']:
   v=populated();v[field]=None
   with self.assertRaises(ValueError):N.build_vectors('/FICTION/source',PROFILE,v,'backend','/FICTION/output')
  for group,field in [('setup8','signature'),('first_login_backend','archive'),('official_ui_dependencies','verification')]:
   v=populated();v[group][field]=None
   with self.assertRaises(ValueError):N.build_vectors('/FICTION/source',PROFILE,v,'ui','/FICTION/output')
  for name in ['gtk4','python-gobject','cachy-asahi-first-login']:
   v=populated();del v['ui_builder_inventory']['packages'][name]
   with self.assertRaises(ValueError):N.build_vectors('/FICTION/source',PROFILE,v,'ui','/FICTION/output')
 def test_full_current_checks_and_old_or_skipped_logs_refuse(self):
  for kind in N.KINDS:
   N.check_log(log(kind),kind,PROFILE)
   for raw in [log(kind)+b'FAILED\n',log(kind)+b'OK (skipped=1)\n',log(kind)+b'expected failures=1\n',log(kind)+log(kind),b'==> Starting check()...\nRan 11 tests in 0.1s\nOK\n']:
    with self.assertRaises(ValueError):N.check_log(raw,kind,PROFILE)
 def test_enrollment_report_matches_exact_recipe_return(self):
  tree=ast.parse((ROOT/PROFILE['packages']['enrollment']['path']/'test_package.py').read_bytes());row=next(n.value for n in ast.walk(tree)if isinstance(n,ast.Return)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='dict'and any(k.arg=='runtime_files'for k in n.value.keywords))
  expected={k.arg:(16 if isinstance(k.value,ast.Call)else ast.literal_eval(k.value))for k in row.keywords};self.assertEqual(expected,PROFILE['enrollment_check_report'])
 def test_native_suite_counts_match_recipe_check_order(self):
  for kind in ['first-login','ui']:
   names=['test_first_login.py','test_delivery.py']if kind=='first-login'else['test_bridge.py','test_delivery.py'];counts=[]
   for name in names:counts.append(sum(isinstance(n,ast.FunctionDef)and n.name.startswith('test_')for n in ast.walk(ast.parse((ROOT/PROFILE['packages'][kind]['path']/name).read_bytes()))))
   self.assertEqual(counts,PROFILE['packages'][kind]['check_counts'])
 def test_first_pair_failure_stops_later_work(self):
  calls=[]
  def run(label,argv):calls.append(label);raise ValueError('FICTION actual check failed')
  with self.assertRaisesRegex(ValueError,'FICTION'):N.build_pairs(run,None,'/FICTION/source',PROFILE,populated(),'backend','/FICTION/output')
  self.assertEqual(calls,['current-enrollment-a'])
 def test_pair_adapter_checks_actual_logs_and_complete_comparison_fields(self):
  calls=[]
  def run(label,argv):
   calls.append(label)
   if label.endswith('-compare'):
    kind=label.removeprefix('current-').removesuffix('-compare');return json.dumps(dict(status='contents-reproduced',errors=[],packages={PROFILE['packages'][kind]['archive']:dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)})).encode()
   return b''
  def ordinary(path,maximum):return log('first-login'if 'first-login-'in str(path)else 'enrollment')
  T=SimpleNamespace(ordinary=ordinary);result=N.build_pairs(run,T,'/FICTION/source',PROFILE,populated(),'backend','/FICTION/output');self.assertEqual(set(result['pairs']),{'enrollment','first-login'});self.assertEqual(len(calls),6)
  T.ordinary=lambda *args:log('enrollment')+b'FAILED\n'
  with self.assertRaises(ValueError):N.build_pairs(run,T,'/FICTION/source',PROFILE,populated(),'backend','/FICTION/output')
  T.ordinary=ordinary
  def partial(label,argv):
   if label.endswith('-compare'):return json.dumps(dict(status='contents-reproduced',errors=[],packages={PROFILE['packages']['enrollment']['archive']:{}})).encode()
   return b''
  with self.assertRaises(ValueError):N.build_pairs(partial,T,'/FICTION/source',PROFILE,populated(),'backend','/FICTION/output')
 def lifecycle_fixture(self,fail=None,restore_failure=False,bad_signature=False):
  # This is an inert callback model, not libalpm, GPG or filesystem evidence.
  signer='A'*40;signed={};calls=[];versions={'base':'1'};restored=[]
  for key in ['setup8',*N.KINDS]:
   expected=PROFILE['setup8']if key=='setup8'else PROFILE['packages'][key]
   signed[key]=dict(name=expected['name'],version=expected['version'],archive='/FICTION/'+key+'.pkg',signature='/FICTION/'+key+'.sig',archive_pin=expected['archive_pin']if key=='setup8'else dict(bytes=123,sha256='b'*64),signature_pin=dict(bytes=99,sha256='c'*64),payload_files=expected['payload_files'])
  pins={r['archive']:r['archive_pin']for r in signed.values()}|{r['signature']:r['signature_pin']for r in signed.values()}
  config=b'[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = /tmp/build-tools-test-FICTION/trust\nHookDir = /builder-disabled-hooks\nLogFile = /tmp/build-tools-test-FICTION/pacman.log\n'
  def pin(path):return pins[str(path)]
  def metadata(raw):return {k:[v]for k,v in json.loads(raw).items()}
  def inventory(base,added):return ''.join(k+' '+v+'\n'for k,v in sorted(({'base':'1'}|added).items())).encode()
  T=SimpleNamespace(ordinary=lambda path,*args:config,pin=pin,_metadata=metadata,check_payload=lambda *args:dict(verified=True),inventory_expected=inventory,data_pin=lambda raw:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
  def run(label,argv):
   calls.append((label,argv))
   if label==fail:raise ValueError('FICTION first actor failure')
   if label.startswith('current-signature-'):
    return (('[GNUPG:] BADSIG '+signer+'\n')if bad_signature else '[GNUPG:] VALIDSIG '+signer+' 2026-11-16 1 0 4 0 1 10 00 '+signer+'\n[GNUPG:] TRUST_ULTIMATE\n').encode()
   if label.startswith('current-pkginfo-'):
    row=signed[label.removeprefix('current-pkginfo-')];return json.dumps(dict(pkgname=row['name'],pkgver=row['version'],arch='any')).encode()
   if '-U'in argv:
    for row in signed.values():
     if row['archive']in argv:versions[row['name']]=row['version']
   if '-R'in argv:
    for name in argv[argv.index('-R')+1:]:versions.pop(name)
   if argv==['/usr/bin/pacman','-Q']:return ''.join(k+' '+v+'\n'for k,v in sorted(versions.items())).encode()
   return b''
  def verify():
   restored.append(True);self.assertEqual(versions,{'base':'1'})
   if restore_failure:raise ValueError('FICTION protected state changed')
  return T,signed,run,verify,calls,restored,signer
 def test_signed_lifecycle_exact_orders_and_restoration_model(self):
  T,rows,run,verify,calls,restored,signer=self.lifecycle_fixture();r=N.lifecycle(run,T,PROFILE,rows,['--config','/tmp/build-tools-test-FICTION/pacman.conf'],['/usr/bin/gpg','--homedir','/tmp/build-tools-test-FICTION/trust','--batch','--no-auto-key-retrieve','--auto-key-locate','clear'],signer,verify)
  self.assertEqual(r['status'],'PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY');self.assertEqual(restored,[True]);self.assertIsNone(r['Root_acceptance'])
  install=[argv for label,argv in calls if label in ['current-install','current-reinstall']];self.assertEqual(len(install),2)
  for argv in install:self.assertEqual(argv[-3:],[rows[k]['archive']for k in N.KINDS])
  for label,argv in calls:
   if label.startswith('current-remove-')and label!='current-remove-setup8':self.assertEqual(argv[-3:],[N.VERSIONS[k][0]for k in reversed(N.KINDS)])
  self.assertTrue(any('-L'in argv for label,argv in calls));self.assertTrue(any('-e'in argv for label,argv in calls))
 def test_bad_signature_and_changed_protected_state_cannot_pass(self):
  for opts in [dict(bad_signature=True),dict(restore_failure=True),dict(fail='current-install')]:
   T,rows,run,verify,calls,restored,signer=self.lifecycle_fixture(**opts)
   with self.assertRaises(ValueError):N.lifecycle(run,T,PROFILE,rows,['--config','/tmp/build-tools-test-FICTION/pacman.conf'],['/usr/bin/gpg','--homedir','/tmp/build-tools-test-FICTION/trust','--batch','--no-auto-key-retrieve','--auto-key-locate','clear'],signer,verify)
   if opts.get('bad_signature'):self.assertFalse(any('-U'in argv for label,argv in calls))
 def test_lifecycle_rejects_old_payload_and_unsigned_or_network_config(self):
  for field in ['payload','config','verifier']:
   T,rows,run,verify,calls,restored,signer=self.lifecycle_fixture();verifier=['/usr/bin/gpg','--homedir','/tmp/build-tools-test-FICTION/trust','--batch','--no-auto-key-retrieve','--auto-key-locate','clear']
   if field=='payload':rows['first-login']['payload_files']={}
   elif field=='config':T.ordinary=lambda *args:b'[options]\nSigLevel = Optional\n[remote]\nServer = https://example.invalid/\n'
   else:verifier=['/usr/bin/gpg','--auto-key-retrieve']
   with self.assertRaises(ValueError):N.lifecycle(run,T,PROFILE,rows,['--config','/tmp/build-tools-test-FICTION/pacman.conf'],verifier,signer,verify)
   self.assertFalse(any('-U'in argv for label,argv in calls))
 def test_all_python_syntax(self):
  for f in HERE.glob('*.py'):ast.parse(f.read_bytes())
if __name__=='__main__':unittest.main(verbosity=2)
