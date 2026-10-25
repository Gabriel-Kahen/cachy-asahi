# SPDX-License-Identifier: MIT
"""Hold599 archive bodies, replace five and add Boot/DNS2/Sysctl2; no platform edits."""
import json,os,re
from pathlib import Path
import common as C

def selection(base):
 p=C.profile();rows=base['packages'];C.need(type(rows)is list and len(rows)==604 and len({r['name']for r in rows})==604,'complete duplicate-free original604 manifest')
 C.need({r['name']:{k:r[k]for k in('version','size','sha256')}for r in rows}==p['held604'],'all604 original versions/archive bodies match Six853 base')
 expected={r['name']:r['version']for r in rows}|{n:r['version']for n,r in p['incoming'].items()};lock=''.join(n+' '+v+'\n'for n,v in sorted(expected.items())).encode()
 C.need(len(expected)==607 and C.pin(lock)==p['target']and expected['cachy-asahi-repository-runtime']=='0.1.0-1'and 'cachy-asahi-boot-report'not in p['held604'],'exact607 lock/protected Runtime1/initial Boot absence')
 held=[dict(r)for r in rows if r['name']not in p['incoming']];C.need(len(held)==599,'exact599 held original604 archive rows');return held,expected,lock

def inspect(public,checks):
 result={}
 for name,row in C.profile()['incoming'].items():
  path=public/row['path'];C.checked(path,{k:row[k]for k in('bytes','sha256')});C.checked(public/row['signature']['path'],{k:row['signature'][k]for k in('bytes','sha256')});r=checks.package(path)
  C.need(not r['errors']and r['sha256']==row['sha256'],'accepted exact package archive inspection');pkg=r['metadata']['.PKGINFO'];payload={n:v for n,v in r['members'].items()if n not in('.PKGINFO','.BUILDINFO','.MTREE')and v['type']!='5'}
  C.need(pkg['pkgname']==[name]and pkg['pkgver']==[row['version']]and pkg['arch'][0]in('any','aarch64')and not pkg.get('install')and not any(n.startswith(('usr/share/libalpm/hooks/','etc/pacman.d/hooks/'))for n in payload),'exact metadata and no added hooks/scriptlets')
  C.need(payload==row['payload']and('metadata'not in row or r['metadata']==row['metadata']),'entire source-bound metadata/payload, not version-only selection');result[name]=r
 return result

def prepare(ready,public,producer_root,target,*,helper,verifier_api,checks,payload_api):
 ready,public,producer_root=map(C.safe,(ready,public,producer_root));target,=C.fresh(target,protected=(ready,public,producer_root,C.ROOT));base=json.loads(C.read(ready/'manifest.json'));held,expected,lock=selection(base);incoming=inspect(public,checks);roles=base['preparation']['signer_roles']
 C.need(set(roles)=={'ephemeral_TEST','upstream_ALARM'}and all(re.fullmatch('[0-9A-F]{40}',s)for s in roles.values()),'same two fresh producer signer roles')
 # All original archive/signature/key bodies and the whole incoming source data
 # are checked before creating output or invoking the original signer.
 for r in base['packages']:
  C.checked(ready/r['archive'],dict(bytes=r['size'],sha256=r['sha256']));C.checked(ready/r['signature'],dict(bytes=r['signature_size'],sha256=r['signature_sha256']))
 for k in base['keyrings']:C.checked(ready/k['path'],dict(bytes=k['size'],sha256=k['sha256']))
 C.need((producer_root/'private/test-signing').is_dir()and producer_root.parent==Path('/tmp')and producer_root.stat().st_uid==os.getuid(),'fresh original owned producer state, no borrowed historical signing home')
 target.mkdir(mode=0o700);(target/'packages').mkdir();(target/'keys').mkdir();rows=[];sign=[]
 for r in held:
  helper.copy_archive(ready/r['archive'],target/r['archive'],r);helper.copy_archive(ready/r['signature'],target/r['signature'],dict(size=r['signature_size'],sha256=r['signature_sha256']));rows.append(r)
 for name,r in sorted(C.profile()['incoming'].items()):
  relative='packages/'+Path(r['path']).name;dest=target/relative;helper.copy_archive(public/r['path'],dest,dict(size=r['bytes'],sha256=r['sha256']));rows.append(dict(name=name,version=r['version'],size=r['bytes'],sha256=r['sha256'],archive=relative,signature=relative+'.sig',signer=roles['ephemeral_TEST']));sign.append(dest)
 C.need(len(rows)==607 and len(sign)==8 and {r['name']:r['version']for r in rows}==expected,'exact607/eight current TEST signature operands')
 helper.sign(producer_root/'private/test-signing',sign,roles['ephemeral_TEST'])
 for r in rows:
  sig=target/r['signature'];r.update(signature_size=sig.stat().st_size,signature_sha256=C.pin(C.read(sig))['sha256']);sig.chmod(0o444)
 for k in base['keyrings']:helper.copy_archive(ready/k['path'],target/k['path'],dict(size=k['size'],sha256=k['sha256']))
 verifier=verifier_api.PublicVerifier(producer_root/'private/latest607-verifier',[target/k['path']for k in base['keyrings']])
 try:
  for r in rows:verifier(target/r['archive'],target/r['signature'],r['signer'])
 finally:verifier.close()
 projects=[r for r in base['projects']if r['name']not in incoming]
 for name,r in incoming.items():
  pkg=r['metadata']['.PKGINFO'];projects.append(dict(name=name,version=expected[name],archive=Path(C.profile()['incoming'][name]['path']).name,sha256=r['sha256'],depends=pkg.get('depend',[]),provides=pkg.get('provides',[]),conflicts=pkg.get('conflict',[]),payload=payload_api.payload(r)))
 total=sum(r['size']for r in rows);C.need(total<=4*1024**3 and len(projects)==24 and len({r['name']for r in projects})==24,'held cache bound/complete24 project metadata rows')
 value=dict(base,status='READY_SIGNED_EXPANDED607',expected_lock=dict(path='expected-installed.lock',sha256=C.profile()['target']['sha256']),packages=sorted(rows,key=lambda r:r['name']),projects=projects,preparation=dict(base['preparation'],archive_count=607,compressed_archive_bytes=total),fresh607=dict(status='SOURCE_ONLY_FRESH_TRANSACTION_REQUIRES_NATIVE_TRIAL',historical_input_source=C.profile()['native_source'],historical_input_run=C.profile()['native_run'],held_original604=599,incoming_exact_archives=8,original_signatures='RETAINED_SOURCE_BOUND_HISTORICAL_DATA_NOT_FRESH_GPG',fresh_TEST_signatures=8,all607_current_signatures='REQUIRED_FRESH_ORIGINAL_PUBLIC_VERIFIER',Asahi_platform='UNCHANGED',hardware='NOT_RUN',release='NOT_ADMITTED'))
 (target/'manifest.json').write_bytes(C.enc(value));(target/'expected-installed.lock').write_bytes(lock);(target/'builder-packages.lock').write_bytes(C.read(ready/'builder-packages.lock'))
 for n in('manifest.json','expected-installed.lock','builder-packages.lock'):(target/n).chmod(0o444)
 for n in('packages','keys'):(target/n).chmod(0o555)
 return value
