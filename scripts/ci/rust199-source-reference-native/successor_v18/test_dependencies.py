# SPDX-License-Identifier: MIT
"""Fenced package/input/image DATA controls; no native build, package install or GET."""
import copy,hashlib,importlib.util,io,json,os,sys,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
s=importlib.util.spec_from_file_location('v18_dependencies_MODEL',HERE/'payload/hosted/build_dependencies.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)

def fence(event,args):
 if event=='ctypes.dlopen'and args and args[0]not in(None,''):raise AssertionError('no native package library loads in MODEL')
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.fork','os.exec','os.posix_spawn','fcntl.flock'):raise AssertionError('MODEL attempted operational role '+event)
sys.addaudithook(fence)
BODY=b'\x7fELF\x02\x01\x01'+bytes(9)+b'\x03\x00\xb7\x00'+bytes(44)+b'MODEL_ONLY_NOT_EXECUTABLE'
RECIPE=b'# MODEL DATA ONLY; never execute\npkgname=libgit2\npkgver=0.0MODEL\n'
LICENSE=b'MODEL source license fixture, not an upstream license grant.\n'
REVISION='0'*40

def buildinfo(row):
 return ('format = 2\npkgname = '+row['name']+'\npkgver = '+row['version']+'\npkgarch = aarch64\npkgbuild_sha256sum = '+D.pin(RECIPE)['sha256']+'\n').encode()

def source_provenance(root,row):
 for name,wanted in D.provenance_inputs(row).items():
  path=root/name;path.parent.mkdir(parents=True,exist_ok=True);body=RECIPE if name.endswith('/PKGBUILD')else LICENSE;assert D.pin(body)==wanted;path.write_bytes(body)

def package():
 providers={'usr/lib/libgit2.so.0':dict(kind='file',mode=0o755,**D.pin(BODY)),'usr/lib/libgit2.so':dict(kind='symlink',mode=0o777,target='libgit2.so.0')}
 metadata=dict(pkgname=['libgit2'],pkgver=['0.0MODEL-1'],arch=['aarch64'],license=['GPL2'],depend=['openssl','libssh2','pcre2'],provides=[],conflict=[],replaces=[])
 row=dict(url='https://MODEL.invalid/libgit2.pkg.tar.xz',name='libgit2',version='0.0MODEL-1',filename='libgit2-0.0MODEL-1-aarch64.pkg.tar.xz',archive=dict(bytes=1,sha256='a'*64),signature=dict(bytes=1,sha256='b'*64),metadata=metadata,providers=providers)
 row['license_provenance']=dict(url='https://MODEL.invalid/source/'+REVISION,revision=REVISION,licenses=['GPL2'],pkgbuild=dict(path='dependency-provenance/libgit2/PKGBUILD',**D.pin(RECIPE)),buildinfo=D.pin(buildinfo(row)),license_files={'dependency-provenance/libgit2/licenses/COPYING':D.pin(LICENSE)})
 return row

def policy(row=None):return dict(schema=18,status='PINNED_SIGNED_ALARM_BUILD_DEPENDENCIES_DATA_ONLY',parent350=D.PARENT350,keyring=D.KEYRING,signer=D.SIGNER,packages=[row or package()],actual=D.ACTUAL)

def archive(path,row,mutation=None):
 meta=''.join(k+' = '+v+'\n'for k,values in row['metadata'].items()for v in values).encode();members=[('.PKGINFO',meta,0o644),('.BUILDINFO',buildinfo(row),0o644),('usr/lib/libgit2.so.0',BODY,0o755)]
 if mutation=='missing-buildinfo':members=[m for m in members if m[0]!='.BUILDINFO']
 if mutation=='hook':members.append(('usr/share/libalpm/hooks/MODEL.hook',b'MODEL',0o644))
 if mutation=='install':members.append(('.INSTALL',b'MODEL',0o644))
 if mutation=='duplicate':members.append(('.PKGINFO',meta,0o644))
 if mutation=='traversal':members.append(('../MODEL',b'MODEL',0o644))
 with tarfile.open(path,'w:xz')as t:
  for name,body,mode in members:
   info=tarfile.TarInfo(name);info.size=len(body);info.mode=mode;t.addfile(info,io.BytesIO(body))
  info=tarfile.TarInfo('usr/lib/libgit2.so');info.type=tarfile.SYMTYPE;info.linkname='libgit2.so.0';info.mode=0o777;t.addfile(info)
 row['archive']=D.pin(path.read_bytes());return row

def image(base,p,include=True):
 source=base/'source';source.mkdir();(source/'expected349.lock').write_bytes((HERE.parent/'expected349.lock').read_bytes())
 root=base/'image';db=root/'var/lib/pacman/local';db.mkdir(parents=True)
 rows=D.inventory((HERE/'fixtures/parent350.ACTUAL367.lock').read_bytes())
 if include:rows.update({r['name']:r['version']for r in p['packages']})
 for name,version in rows.items():
  folder=db/(name+'-'+version.replace(':','_'));folder.mkdir();meta=dict(pkgname=[name],pkgver=[version])
  if name=='libgit2':meta=p['packages'][0]['metadata']
  mapping={'pkgname':'%NAME%','pkgver':'%VERSION%','arch':'%ARCH%','license':'%LICENSE%','depend':'%DEPENDS%','provides':'%PROVIDES%','conflict':'%CONFLICTS%','replaces':'%REPLACES%'}
  (folder/'desc').write_text(''.join(mapping[k]+'\n'+'\n'.join(v)+'\n\n'for k,v in meta.items()if v))
  if name=='libgit2':(folder/'files').write_text('%FILES%\n'+'\n'.join(p['packages'][0]['providers'])+'\n')
 if include:
  lib=root/'usr/lib';lib.mkdir(parents=True);(lib/'libgit2.so.0').write_bytes(BODY);(lib/'libgit2.so.0').chmod(0o755);(lib/'libgit2.so').symlink_to('libgit2.so.0')
 return source,root

class Dependencies(unittest.TestCase):
 def test_actual_failure_is_dependency_refusal_after_successful_manifest_import(self):
  raw=(HERE/'fixtures/public-failure.ACTUAL367.json').read_bytes();self.assertEqual(D.pin(raw),dict(bytes=2912,sha256='23ddd9727f6f6e43bd42ec1ee48daf88d94dcb53417b0cb713c9b9c98263c89d'))
  v=json.loads(raw);self.assertEqual(v['actual_makepkg_command']['returncode'],8);self.assertIn('  -> libgit2\n',v['actual_makepkg_stdout']);self.assertTrue(v['prepare_completed']);self.assertEqual(v['import_status'],'PASS_IMPORTED_VERIFIED_BOOTSTRAP_PHASE_DATA')
  prior=(HERE/'fixtures/parent350.ACTUAL367.lock').read_bytes();self.assertEqual(D.pin(prior),D.PARENT350);self.assertNotIn('libgit2',D.inventory(prior))
 def test_unavailable_real_tuple_holds_and_policy_never_issues_authority(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'hosted').mkdir();(root/'hosted/build-dependencies.json').write_bytes(D.encode(policy()))
   with patch.object(D,'POLICY_PIN',None),self.assertRaisesRegex(ValueError,'HOLD'):D.policy(root)
  self.assertTrue(all(v is None for v in policy()['actual'].values()))
 def test_old_actual350_image_refuses_but_added_owned_model_provider_passes(self):
  for include in(False,True):
   with self.subTest(include=include),tempfile.TemporaryDirectory()as td:
    p=D.validate_policy(policy());source,root=image(Path(td),p,include)
    if include:
     result=D.observe(root,source,p);self.assertEqual(result['inventory'],D.pin(D.expected_inventory(source,p)));self.assertEqual(result['providers']['usr/lib/libgit2.so.0']['owner'],'libgit2');self.assertFalse(result['native_acceptance']);self.assertIsNone(result['Root_acceptance'])
    else:
     with self.assertRaisesRegex(ValueError,'complete dependency inventory'):D.observe(root,source,p)
 def test_no_baseline_upgrade_extra_or_missing_owner_provider_can_qualify(self):
  for mutation in('upgrade','extra','bytes','mode','alias','ownership','metadata'):
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory()as td:
    p=policy();source,root=image(Path(td),p);db=root/'var/lib/pacman/local'
    if mutation=='upgrade':
     path=next(db.glob('openssl-*/desc'));path.write_text(path.read_text().replace('%VERSION%\n3.6.5-1','%VERSION%\nMODEL-NEW'))
    elif mutation=='extra':
     folder=db/'EXTRA';folder.mkdir();(folder/'desc').write_text('%NAME%\nEXTRA\n\n%VERSION%\n1\n')
    elif mutation=='bytes':(root/'usr/lib/libgit2.so.0').write_bytes(b'WRONG')
    elif mutation=='mode':(root/'usr/lib/libgit2.so.0').chmod(0o644)
    elif mutation=='alias':(root/'usr/lib/libgit2.so').unlink();(root/'usr/lib/libgit2.so').symlink_to('MODEL_WRONG')
    elif mutation=='ownership':next(db.glob('libgit2-*/files')).write_text('%FILES%\nusr/lib/MODEL_WRONG\n')
    else:
     path=next(db.glob('libgit2-*/desc'));path.write_text(path.read_text().replace('aarch64','x86_64'))
    with self.assertRaises(ValueError):D.observe(root,source,p)
 def test_new_signed_package_may_not_replace_baseline_even_with_new_pin(self):
  with tempfile.TemporaryDirectory()as td:
   p=policy();source,_=image(Path(td),p);extra=package();extra.update(name='openssl',version='MODEL-NEW');p['packages'].append(extra)
   with self.assertRaisesRegex(ValueError,'never upgrade'):D.expected_inventory(source,p)
 def test_package_audit_joins_signed_metadata_whole_bytes_and_actual_library_aliases(self):
  with tempfile.TemporaryDirectory()as td:
   path=Path(td)/'package.xz';row=archive(path,package());result=D.audit_archive(path,row);self.assertEqual(result['providers'],row['providers'])
   bad=copy.deepcopy(row);bad['metadata']['depend']=[]
   with self.assertRaises(ValueError):D.audit_archive(path,bad)
   bad=copy.deepcopy(row);bad['providers']['usr/lib/libgit2.so.0']['sha256']='f'*64
   with self.assertRaises(ValueError):D.audit_archive(path,bad)
   path.write_bytes(path.read_bytes()+b'CHANGED')
   with self.assertRaisesRegex(ValueError,'whole original'):D.audit_archive(path,row)
 def test_package_scripts_hooks_duplicate_and_traversal_never_enter_context(self):
  for mutation in('hook','install','duplicate','traversal'):
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory()as td:
    path=Path(td)/'package.xz';row=archive(path,package(),mutation)
    with self.assertRaises(ValueError):D.audit_archive(path,row)
 def test_official_recipe_must_match_signed_BUILDINFO_and_retained_license_bytes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);row=archive(root/'MODEL.xz',package());source_provenance(root,row);D.audit_provenance(root,row);D.audit_archive(root/'MODEL.xz',row)
   bad=copy.deepcopy(row);bad['license_provenance']['pkgbuild']['sha256']='f'*64
   with self.assertRaisesRegex(ValueError,'recipe hash correspondence'):D.audit_archive(root/'MODEL.xz',bad)
   bad=copy.deepcopy(row);bad['license_provenance']['buildinfo']['sha256']='f'*64
   with self.assertRaisesRegex(ValueError,'BUILDINFO pin'):D.audit_archive(root/'MODEL.xz',bad)
   (root/next(iter(row['license_provenance']['license_files']))).write_bytes(b'SUBSTITUTED')
   with self.assertRaisesRegex(ValueError,'source license bytes'):D.audit_provenance(root,row)
   row=archive(root/'MISSING.xz',package(),'missing-buildinfo')
   with self.assertRaisesRegex(ValueError,'recipe hash correspondence'):D.audit_archive(root/'MISSING.xz',row)
 def test_mutable_unretained_or_unpinned_source_provenance_cannot_be_policy(self):
  for mutate in(lambda r:r['license_provenance'].update(revision='master'),lambda r:r['license_provenance'].update(url='https://MODEL.invalid/master'),lambda r:r['license_provenance'].update(license_files={}),lambda r:r['license_provenance']['pkgbuild'].update(path='dependency-provenance/other/PKGBUILD'),lambda r:r['license_provenance'].pop('buildinfo')):
   row=package();mutate(row)
   with self.assertRaises(ValueError):D.validate_policy(policy(row))
 def test_signature_trust_is_full_existing_alarm_fingerprint_not_test_key(self):
  good=('[GNUPG:] VALIDSIG '+D.SIGNER+' 2026-11-17 1790000000 0 4 0 1 10 00 '+D.SIGNER+'\n').encode();D.signature_status(good)
  for bad in(good.replace(D.SIGNER.encode(),b'F'*40),good+b'[GNUPG:] BADSIG MODEL\n',good+b'[GNUPG:] EXPKEYSIG MODEL\n',good+good,b''):
   with self.assertRaises(ValueError):D.signature_status(bad)
 def test_policy_duplicates_nonintegers_foreign_trust_and_authority_refuse(self):
  for raw in(b'{"schema":18,"schema":18}',b'{"bytes":1.0}',b'{"bytes":NaN}'):
   with self.assertRaises(ValueError):D.decode(raw)
  for key,value in(('signer','F'*40),('actual',dict(D.ACTUAL,Root_acceptance=True)),('keyring',dict(D.KEYRING,sha256='f'*64)),('packages',[])):
   p=policy();p[key]=value
   with self.assertRaises(ValueError):D.validate_policy(p)
 def test_observation_receipt_cannot_normalize_modes_pins_or_acceptance(self):
  with tempfile.TemporaryDirectory()as td:
   p=policy();source,root=image(Path(td),p);host=D.observe(root,source,p);native=dict(host,native_uid_gid_checked=True,runtime_loads=D.expected_loads(p))
   D.validate_observation(native,source,p,host)
   for mutate in(lambda v:v.update(native_acceptance=True),lambda v:v['inventory'].update(bytes=float(v['inventory']['bytes'])),lambda v:v['providers']['usr/lib/libgit2.so.0'].update(mode=493.0),lambda v:v.update(native_uid_gid_checked=False)):
    bad=copy.deepcopy(native);mutate(bad)
    with self.assertRaises(ValueError):D.validate_observation(bad,source,p,host)
 def test_bounded_public_signature_context_is_exact_and_image_install_keeps_checks(self):
  with tempfile.TemporaryDirectory()as td,patch.object(D,'KEYRING',D.pin(b'MODEL_PUBLIC_KEYRING')):
   base=Path(td);p=policy();source,root=image(base,p);folder=source/'build-dependencies';folder.mkdir();row=p['packages'][0];archive(folder/row['filename'],row);source_provenance(source,row);sig=(folder/row['filename']).with_name(row['filename']+'.sig');sig.write_bytes(b'MODEL_SIGNATURE');row['signature']=D.pin(sig.read_bytes())
   cache=base/'cache';cache.mkdir();(cache/'archlinuxarm.gpg').write_bytes(b'MODEL_PUBLIC_KEYRING');context=base/'context';context.mkdir();out=base/'out';out.mkdir();calls=[]
   def call(argv,timeout):
    calls.append(argv);self.assertEqual(timeout,30);self.assertEqual(argv[0],'/usr/bin/gpgv');self.assertNotIn('--import',argv)
    good=('[GNUPG:] VALIDSIG '+D.SIGNER+' 2026-11-17 1790000000 0 4 0 1 10 00 '+D.SIGNER+'\n').encode();return type('MODEL',(),dict(stdout=good,returncode=0))()
   receipt=D.prepare_context(source,context,out,cache,p,call);self.assertEqual(len(calls),1);self.assertFalse(receipt['network']);self.assertIsNone(receipt['Root_acceptance'])
   self.assertEqual((context/'build-dependencies'/row['filename']).read_bytes(),(folder/row['filename']).read_bytes());self.assertEqual((context/'build-dependencies/expected-qualified.lock').read_bytes(),D.expected_inventory(source,p))
   original=b'MODEL_PARENT\nUSER alarm\nWORKDIR /tmp\n';dockerfile=D.extend_dockerfile(original,p);self.assertTrue(dockerfile.startswith(original));self.assertIn(b'--gpgdir /etc/pacman.d/gnupg',dockerfile);self.assertIn(b'LocalFileSigLevel = Required',dockerfile);self.assertIn(b'--noscriptlet',dockerfile);self.assertIn(b'pacman --config /etc/pacman.conf -T',dockerfile);self.assertIn(b'cmp -s /builder-qualified.lock',dockerfile);self.assertNotIn(b'--nodeps',dockerfile);self.assertNotIn(b'--sync',dockerfile)
 def test_native_loader_uses_only_selected_regular_paths_now_local_and_propagates_failure(self):
  import ctypes
  p=policy();other=package();other['name']='llhttp';other['providers']={'usr/lib/libllhttp.so.9.3.1':dict(kind='file',mode=0o755,**D.pin(BODY))};p['packages'].append(other);calls=[]
  def loader(path,mode):calls.append((path,mode));return object()
  with patch.object(ctypes,'CDLL',side_effect=loader):self.assertEqual(D.load_runtime(p),D.expected_loads(p))
  self.assertEqual(calls,[('/usr/lib/libgit2.so.0',os.RTLD_NOW|os.RTLD_LOCAL),('/usr/lib/libllhttp.so.9.3.1',os.RTLD_NOW|os.RTLD_LOCAL)])
  with patch.object(ctypes,'CDLL',side_effect=OSError('MODEL missing ELF dependency')),self.assertRaisesRegex(OSError,'missing ELF'):D.load_runtime(p)
 def test_observer_cancellation_and_native_owner_predicate_are_not_waived(self):
  with tempfile.TemporaryDirectory()as td:
   p=policy();source,root=image(Path(td),p)
   def cancel():raise ValueError('MODEL cancelled')
   with self.assertRaisesRegex(ValueError,'cancelled'):D.observe(root,source,p,tick=cancel)
   if os.getuid()!=0:
    with self.assertRaisesRegex(ValueError,'root-owned'):D.observe(root,source,p,native=True)
if __name__=='__main__':unittest.main(verbosity=2)
