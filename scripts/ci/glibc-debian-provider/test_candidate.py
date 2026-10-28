# SPDX-License-Identifier: MIT
"""Portable source/data controls; recorded parser fixtures grant no authority."""
import ast,hashlib,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import auth as A
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
RECIPE=ROOT/'packages/core/cachy-asahi-glibc-debian-provider';OLD=ROOT/'scripts/ci/glibc-gnu-provider'
FIXTURE_PIN={'bytes': 4120, 'sha256': '340a5941d44cf61dc7c04121e405b7017a6986a624f0e84a647917d7d05d7c31'}
def recorded():
 # Replay at the real receipt's check epoch. Production freshness still uses
 # its actual current clock; this historical parser fixture never grants it.
 raw=A.read(HERE/'fixtures/recorded-public-status.json',16384);A.need(A.pin(raw)==FIXTURE_PIN,'recorded public test fixture byte identity differs')
 value=A.decode(raw);A.need(value.get('schema_version')==1 and value.get('status')=='HISTORICAL_PARSER_TEST_DATA_ONLY' and value.get('authority')=='NOT_ESTABLISHED' and value.get('native')=='NOT_RUN' and value.get('release')=='NOT_ADMITTED','test fixture cannot supply acceptance or authority')
 return value
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
adapter=load('candidate_adapter',HERE/'adapter.py')
class Candidate(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='glibc-debian-provider-test-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  no=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors prohibited'));no.start();self.addCleanup(no.stop)
  self.harness=self.root/'harness';self.receipt=adapter.emit(ROOT,self.harness);self.oldpath=list(sys.path);sys.path.insert(0,str(self.harness));self.addCleanup(lambda:sys.path.__setitem__(slice(None),self.oldpath))
  self.m=load('candidate_materialize',self.harness/'materialize.py')
 def test_emitted_executor_and_present_core_checks_are_exact_original_bytes(self):
  self.assertEqual((self.harness/'runner.py').read_bytes(),(OLD/'run.py').read_bytes())
  for n in adapter.COPY:self.assertEqual((self.harness/n).read_bytes(),(OLD/n).read_bytes(),n)
  self.assertEqual((self.harness/'metadata.py').read_text().replace('2.43.caa2','2.43.caa1'),(OLD/'metadata.py').read_text())
  self.assertFalse((self.harness/'job.py').exists());self.assertFalse((self.harness/'bindings.json').exists())
  self.assertLessEqual(len(json.loads((self.harness/'source-manifest.json').read_bytes())['files']),32)
 def test_original_fatal_check_function_config_flags_and_stage_stay(self):
  old=(ROOT/'packages/core/cachy-asahi-glibc-gnu-provider/PKGBUILD').read_text();new=(RECIPE/'PKGBUILD').read_text()
  self.assertEqual(old[old.index('check() {'):old.index('package() {')],new[new.index('check() {'):new.index('package() {')])
  for option in ('--disable-multi-arch','--enable-bind-now','--enable-stack-protector=strong','--enable-fortify-source','--disable-systemtap','--disable-nscd','--disable-profile'):
   self.assertEqual(old.count(option),new.count(option))
  self.assertNotIn('make -s info',new);self.assertIn('[[ ! -e manual && ! -L manual ]]',new)
  self.assertEqual((RECIPE/'stage.py').read_bytes(),(OLD/'provider_stage.py').read_bytes())
 def test_unbound_authority_refuses_materialization_before_gpg_and_output(self):
  target=self.root/'bundle'
  policy=self.harness/'authority.json';value=json.loads(policy.read_bytes());value['status']='UNBOUND_ROOT_INDEPENDENT_ARCHIVE_KEY_AUTHORITY';value['decision']=None;policy.write_text(json.dumps(value))
  with self.assertRaisesRegex(ValueError,'UNBOUND'):self.m.materialize(RECIPE,self.root/'absent-inputs',target)
  self.assertFalse(target.exists())
 def test_changed_recipe_or_patch_cannot_waive_any_check(self):
  recipe=self.root/'recipe';shutil.copytree(RECIPE,recipe);lock=A.decode(A.read(recipe/'source-lock.json',65536))
  self.m.configuration(recipe,lock);path=recipe/'PKGBUILD';path.write_text(path.read_text().replace('make -s -j4 check-abi','true # attempted ABI bypass'))
  with self.assertRaisesRegex(ValueError,'recipe identity'):self.m.configuration(recipe,lock)
  shutil.copyfile(RECIPE/'PKGBUILD',path);path=recipe/'0003-debian-manual-omission.patch';path.write_bytes(path.read_bytes()+b'\n')
  with self.assertRaisesRegex(ValueError,'manual omission patch'):self.m.configuration(recipe,lock)
 def test_old_GNU_bundle_and_wrong_source_namespace_refuse(self):
  bundle=self.root/'old';bundle.mkdir();raw=json.dumps(dict(status='SOURCE_BUNDLE_READY_UNSELECTED_GNU_PROVIDER',package_version='2.43.caa1-1',payload_tree='97ac10e146c65ecbd22d36e3743eb5b5e9166ae9',files={})).encode();(bundle/'bundle.json').write_bytes(raw)
  with self.assertRaisesRegex(ValueError,'NEW Debian'):self.m.inputs(bundle,hashlib.sha256(raw).hexdigest())
 def test_recorded_signature_status_requires_all_pinned_signers_and_no_unknown_status(self):
  raw=A.read(HERE/'fixtures/recorded-public-status.json',16384)
  with patch.object(A,'read',return_value=raw+b'\n'),self.assertRaisesRegex(ValueError,'fixture byte identity'):recorded()
  evidence=recorded()['chain'];text=evidence['signature_status'];now=evidence['checked_epoch'];A.signature_status(text,0,now)
  for status in ('EXPKEYSIG','KEYEXPIRED','REVKEYSIG','KEYREVOKED','BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','FUTURE_UNKNOWN'):
   with self.subTest(status=status),self.assertRaises(ValueError):A.signature_status(text+'\n[GNUPG:] '+status+' refused\n',0,now)
  with self.assertRaises(ValueError):A.signature_status(text,2,now)
  valid=next(line for line in text.splitlines() if 'VALIDSIG' in line)
  with self.assertRaises(ValueError):A.signature_status(text.replace(valid,''),0,now)
 def test_signature_future_time_and_expiry_are_not_waived(self):
  evidence=recorded()['chain'];text=evidence['signature_status'];now=evidence['checked_epoch'];line=next(line for line in text.splitlines() if 'VALIDSIG' in line);parts=line.split()
  for index,value in ((4,str(now+3600)),(5,str(now-1))):
   bad=list(parts);bad[index]=value
   with self.assertRaises(ValueError):A.signature_status(text.replace(line,' '.join(bad)),0,now)
 def test_recorded_key_material_refuses_future_expired_revoked_or_unknown_keys(self):
  evidence=recorded()['chain'];text=evidence['key_status'];now=evidence['checked_epoch'];A.key_status(text,now)
  with self.assertRaisesRegex(ValueError,'archive key'):A.key_status(text,now+15*365*86400)
  with self.assertRaisesRegex(ValueError,'archive key'):A.key_status(text,1)
  for tag in ('pub','sub'):
   line=next(line for line in text.splitlines() if line.startswith(tag+':'));parts=line.split(':');parts[1]='r'
   with self.assertRaisesRegex(ValueError,'archive key'):A.key_status(text.replace(line,':'.join(parts)),now)
  with self.assertRaises(ValueError):A.key_status(text.replace(next(iter(A.KEYS)),'0'*40),now)
 def test_release_freshness_has_no_future_or_valid_until_waiver(self):
  chain=recorded()['chain'];now=chain['checked_epoch'];raw=('Origin: Debian\nCodename: sid\nDate: '+chain['date']+'\nValid-Until: '+chain['valid_until']+'\n').encode()
  A.current_release(raw,now)
  with self.assertRaisesRegex(ValueError,'not current'):A.current_release(raw,1)
  with self.assertRaisesRegex(ValueError,'not current'):A.current_release(raw,now+8*86400)
 def test_retained_source_patch_results_are_exact_fuzz0_and_no_manual_insertion(self):
  r=recorded()['preparation'];lock=A.decode(A.read(RECIPE/'source-lock.json',65536))
  self.assertEqual(r['before_tree'],A.TREE);self.assertEqual(r['after_tree'],lock['expected_patched_payload_tree']);self.assertEqual(len(r['patches']),3)
  for row in r['patches']:
   self.assertEqual(row['exit'],0);self.assertIn('--fuzz=0',row['arguments']);self.assertNotIn('offset',row['stdout']);self.assertNotIn('fuzz',row['stdout'])
  self.assertFalse(r['manual_reinserted']);self.assertIsNone(lock['accepted_source_packet']);self.assertEqual(lock['version'],'2.43.caa2')
 def test_wrong_original_helper_bytes_refuse_before_harness_creation(self):
  clone=self.root/'source';pins=A.decode(A.read(HERE/'dependency-pins.json',65536))['files']
  for name in pins:
   path=clone/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,path)
  path=clone/'scripts/ci/glibc-gnu-provider/run.py';path.write_bytes(path.read_bytes()+b'\n');target=self.root/'wrong-harness'
  with self.assertRaisesRegex(ValueError,'byte identity'):adapter.emit(clone,target)
  self.assertFalse(target.exists())
if __name__=='__main__':unittest.main(verbosity=2)
