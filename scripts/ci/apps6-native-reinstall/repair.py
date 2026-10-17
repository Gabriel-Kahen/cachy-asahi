# SPDX-License-Identifier: MIT
"""TEST signing stays outside consumers; reuse the exact reviewed repair child body."""
import hashlib,importlib.util,json,os,shutil,stat,sys,tempfile
from pathlib import Path
DEPENDENCIES=('scripts/update/test_snapshot.py','scripts/update/supervision.py','scripts/update/bound_update.py','scripts/update/full_root.py','scripts/update/measure_copy.py','scripts/update/disposable_copy.py','scripts/update/capacity.py','scripts/install/local_transaction.py','scripts/client/client.py','scripts/release/release.py','scripts/release/source_delivery.py','packages/tools/cachy-asahi-update/asahi-policy.py','scripts/apps/transaction.py','scripts/apps/test_actual_reinstall.py','manifests/packages.toml')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
encoded=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def prepare(source,life,out):
 """Ordinary coordinator-only TEST authority, removed before consumer starts."""
 import contract as C
 tree=life/'repair-source';pins={}
 for name in DEPENDENCIES:
  path=C.safe(source/name);info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=4*1024**2,'ordinary repair source required')
  dst=tree/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dst);pins[name]=dict(bytes=info.st_size,sha256=sha(path))
 (life/'repair-source.json').write_bytes(encoded(pins));case=life/'repair-case';case.mkdir(mode=0o700)
 fixture=load('apps6_signed_repair_fixture',source/'scripts/update/test_snapshot.py')
 with tempfile.TemporaryDirectory(prefix='repair-TEST-authority-',dir=out) as private:
  with fixture.signing(Path(private)/'keys') as (signer,public,sign):
   (case/'public.gpg').write_bytes(public);(case/'signer').write_text(signer)
   base=[dict(name='platform-fixture',version='1-1',arch='any',depend=[],provides=[],conflict=[],replaces=[],files=['boot/platform-fixture'])]
   bundle=fixture.make_bundle(case,signer,sign,base_packages=base)
   catalog=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',release_sha256=sha(bundle/'release.json'),repository='fixture',applications=[dict(id='fixture',title='Synthetic fixture',description='Owned disposable repair only',packages=['fixture'])])
   (case/'catalog.json').write_bytes(encoded(catalog));sign(case/'catalog.json')
 seed=case/'seed';local=seed/'var/lib/pacman/local/platform-fixture-1-1';local.mkdir(parents=True);(local.parent/'ALPM_DB_VERSION').write_bytes(b'9\n');(local/'desc').write_bytes(b'%NAME%\nplatform-fixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n');(local/'files').write_bytes(b'%FILES%\nboot/platform-fixture\n\n')
 for name,data in [('boot/platform-fixture',b'preserve platform\n'),('home/test/note',b'preserved user bytes\n'),('etc/pacman.conf',b'# preserve config\n'),('etc/pacman.d/public',b'preserved base trust\n')]:
  p=seed/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o644)
 (seed/'usr/share/fixture').mkdir(parents=True)


def installed_view(root,view,provenance_pin):
 """Join split installed package paths into the unchanged backend source closure."""
 import contract as C
 root=C.safe(root.absolute());view=C.safe(view.absolute());C.need(not view.exists(),'fresh private installed-source view required')
 names={'apps.py':'usr/lib/cachy-asahi-apps/apps.py','inventory.py':'usr/lib/cachy-asahi-apps/inventory.py','helper-pins.json':'usr/lib/cachy-asahi-apps/helper-pins.json','cachy-asahi-apps':'usr/bin/cachy-asahi-apps'}
 original=C.checked(root,'usr/share/doc/cachy-asahi-apps/source-provenance.json',provenance_pin)
 raw=original.read_bytes();C.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==provenance_pin,'installed provenance drift')
 provenance=json.loads(raw);C.need(provenance.get('package')=='cachy-asahi-apps' and provenance.get('version')=='0.1.0-6' and set(provenance.get('runtime_sources',{}))==set(names),'exact installed Apps6 runtime closure required')
 blobs={'source-provenance.json':raw}
 for name,path in names.items():
  pin=provenance['runtime_sources'][name];C.need(type(pin.get('bytes')) is int and 0<pin['bytes']<=128*1024,'bounded Apps runtime source required')
  data=C.checked(root,path,pin).read_bytes();C.need(dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())==pin,'installed runtime drift');blobs[name]=data
 view.mkdir(mode=0o700)
 for name,data in blobs.items():
  path=view/name
  with path.open('xb') as stream:stream.write(data)
  path.chmod(0o755 if name=='cachy-asahi-apps' else 0o644)
 return view


def run():
 import contract as C
 C.need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64','existing owned native lifecycle PID1 required')
 C.need(os.environ.get('CACHY_ASAHI_APPS_CACHE_OPERATION')=='lifecycle','same owned operation required')
 source=Path('/inputs/repair-source');pins=C.read(Path('/inputs/repair-source.json'))
 C.need(set(pins)==set(DEPENDENCIES),'closed repair source map differs')
 for name,pin in pins.items():C.checked(source,name,pin)
 driver=load('apps6_exact_repair_child',source/'scripts/apps/test_actual_reinstall.py')
 # The original child body supports a tokened offline Docker owner already. No nested
 # user/mount namespace or extra capability/seccomp grant is needed or requested.
 provenance_pin=C.row(C.ROLES['apps'])['source_files']['source-provenance.json']
 driver.ROOT=C.RUNTIME;driver.APPDIR=installed_view(Path('/'),Path('/tmp/apps6-installed-source'),provenance_pin)
 case=Path('/tmp/apps6-signed-repair');C.need(not case.exists(),'fresh private repair case required');shutil.copytree('/inputs/repair-case',case,symlinks=True);case.chmod(0o700)
 previous=dict(os.environ);token=hashlib.sha256((C.digest(Path('/inputs/repair-source.json'))+':repair').encode()).hexdigest()[:32]
 try:
  os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',HOME=str(case),LC_ALL='C.UTF-8',CACHY_ASAHI_APPS_TRANSACTION=token,PYTHONDONTWRITEBYTECODE='1')
  driver.child(case)
 finally:
  os.environ.clear();os.environ.update(previous)
  shutil.copytree(case,'/out/repair',symlinks=True)
 value=C.read(case/'result.json');C.need(value.get('host_architecture')=='aarch64' and value.get('native_aarch64')=='NOT_RUN','unchanged host fixture qualification expected before truthful native wrapper annotation')
 value['native_aarch64']='EXECUTED_SIGNED_SYNTHETIC_COPY_ONLY';value['installed_apps']='0.1.0-6';value['input_source_sha256']=C.digest(Path('/inputs/repair-source.json'))
 (Path('/out/repair')/'native-result.json').write_bytes(encoded(value));return value
