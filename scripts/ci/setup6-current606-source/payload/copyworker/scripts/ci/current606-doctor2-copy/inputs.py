# SPDX-License-Identifier: MIT
"""Exact accepted unsigned Doctor2 DATA; fresh original producer TEST signing only."""
import importlib.util,json,os,shutil,stat,sys,zipfile
from pathlib import Path
import contract as C
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
NAME='cachy-asahi-setup';RUNTIME='cachy-asahi-repository-runtime'
NATIVE='141ba835bb632483342c6a7f0246c7fe0f2bc5c3';RUN=39595642635
INDEX={'bytes': 140641, 'sha256': '741c5a86b66d0189c0de78a660fa6b7c83c9feca37623db1bf28389c1c9a4237'}
ARCHIVE=dict(bytes=27188,sha256='a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8')
def legacy():
 p=HERE/'held-runtime-inputs.py';spec=importlib.util.spec_from_file_location('_held_complete_runtime_inputs',p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def data(root,name):
 profile=C.decode(C.ordinary(HERE/'setup6-carrier.json',1024**2));row=profile['files'].get(name)
 if row!=dict(bytes=0,sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'):return C.ordinary(root/name,16*1024**2)
 path=root/name;C.need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary exact source-pinned empty DATA')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);raw=os.read(fd,1);b=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  C.need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==0 and raw==b''and key(a)==key(b)==key(path.lstat()),'exact source-pinned empty DATA identity')
  return raw
 finally:os.close(fd)

def checked(root,row):
 C.need(type(row)is dict and set(row)=={'path','bytes','sha256'},'closed Doctor DATA reference');name=row['path'];C.need(type(name)is str and name and not name.startswith('/')and '..'not in Path(name).parts and Path(name).as_posix()==name,'ordinary relative public DATA')
 raw=data(root,name);C.need(C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'whole Doctor DATA pin');return root/name

def inspect(packet):
 profile=C.decode(C.ordinary(HERE/'setup6-carrier.json',1024**2));wanted=profile['files']
 C.need(profile['source']=='24f8d8ed9de7f4ea1aedcc9624110e553204b36c'and len(wanted)==384,'whole fixed accepted384 carrier source')
 actual={p.relative_to(packet).as_posix()for p in packet.rglob('*')if p.is_file()and'.git'not in p.relative_to(packet).parts}
 C.need(actual==set(wanted)and all(not p.is_symlink()for p in packet.rglob('*')if'.git'not in p.relative_to(packet).parts),'exact ordinary entire384 input closure')
 for name,row in wanted.items():checked(packet,dict(path=name,**row))
 C.need(C.pin(C.ordinary(packet/'index.json',1024**2))==INDEX,'whole exact accepted Setup6 index')
 index=C.decode(C.ordinary(packet/'index.json',1024**2));decision=C.decode(C.ordinary(packet/'qualification/Root-component-acceptance.json',65536))
 C.need(index['source']==NATIVE and index['native_run']==RUN and index['version']=='0.1.0-6'and len(index['source_files'])==73 and index['status']=='ROOT_ACCEPTED_SETUP6_PAIR_AND_FIXTURE_LIFECYCLE_INPUTS_ONLY','finite original Setup6 source/run/pair prerequisite')
 C.need(decision['source']==NATIVE and decision['run']==RUN and decision['source_files']==73 and decision['status']=='ROOT_ACCEPTED_FINITE_NATIVE_SETUP6_PAIR_AND_INSTALLED_FIXTURE_LIFECYCLE'and decision['package']==ARCHIVE and decision['real_setup_modules']=='NOT_RUN'and decision['current606']=='NOT_RUN','honest accepted pair/fixture prerequisite no invented606 authority')
 checks=legacy().inspector();recipe=packet/'source/packages/settings/cachy-asahi-setup';reports=[];paths=[]
 for side in('a','b'):
  path=packet/('native/packages/cachy-asahi-setup-'+side+'/cachy-asahi-setup-0.1.0-6-any.pkg.tar.xz');C.need(C.pin(C.ordinary(path))==ARCHIVE,'exact accepted27188-byte pair')
  report=checks.package(path);C.need(report['errors']==[]and not report['elf']and report['metadata']['.PKGINFO']['pkgname']==[NAME]and report['metadata']['.PKGINFO']['pkgver']==['0.1.0-6']and report['metadata']['.PKGINFO']['arch']==['any'],'complete original selected Setup6 package report')
  payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(set(payload)==C.DOCTOR_FILES,'all six selected Setup payload/license leaves')
  sources={'usr/bin/cachy-asahi-setup':'cachy-asahi-setup','usr/bin/cachy-asahi-repository':'cachy-asahi-repository','usr/share/doc/cachy-asahi-setup/README.md':'README.md','usr/share/doc/cachy-asahi-setup/repository-enrollment.md':'repository-enrollment.md','usr/share/licenses/cachy-asahi-setup/LICENSE':'LICENSE','usr/share/licenses/cachy-asahi-setup/NOTICE':'NOTICE'}
  for name,source in sources.items():
   raw=C.ordinary(recipe/source,1024**2);row=payload[name];mode=0o755 if name.startswith('usr/bin/')else 0o644;C.need(row['type']=='0'and row['uid']==row['gid']==0 and row['mode']==mode and row['size']==len(raw)and row['sha256']==C.pin(raw)['sha256'],'all installed source/license bytes bound to actual archive')
  C.need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[C.pin(C.ordinary(recipe/'PKGBUILD'))['sha256']],'actual selected recipe BUILDINFO join');reports.append(report);paths.append(path)
 C.need(reports[0]==reports[1]and paths[0].read_bytes()==paths[1].read_bytes(),'whole accepted native pair equality')
 return dict(path=paths[0],version='0.1.0-6',payload=payload,report=reports[0],provenance=dict(source=NATIVE,run=RUN,index=INDEX,signature='UNSIGNED_REQUIRES_FRESH_ORIGINAL_PRODUCER_TEST_SIGNING',full606_real_shell='NOT_RUN'))

def sign_candidate(*,path,output,source,producer,original_public,signer_fingerprint,original_api):
 signing=output/'signing';signing.mkdir(mode=0o700);candidate_path=signing/path.name;shutil.copyfile(path,candidate_path);C.need(C.pin(C.ordinary(candidate_path))==ARCHIVE,'candidate before TEST signing')
 signer=original_api.scoped_load('_doctor606_original_signer',source/'held604/scripts/ci/expanded600-installer-vm/materializer.py',{'contract':original_api});signer.sign(producer/'private/test-signing',[candidate_path],signer_fingerprint)
 verifier=original_api.load('_doctor606_original_public_verifier',source/'held604/scripts/ci/full-composition-installer-vm/producer.py');verification_home=producer/'private/doctor606-verifier';C.need(not verification_home.exists()and not verification_home.is_symlink(),'fresh source-owned public verifier home')
 public_verifier=verifier.PublicVerifier.__new__(verifier.PublicVerifier)
 try:
  public_verifier.__init__(verification_home,[original_public]);public_verifier(candidate_path,candidate_path.with_name(candidate_path.name+'.sig'),signer_fingerprint)
 finally:
  if getattr(public_verifier,'home',None)==verification_home:public_verifier.close()
 C.need(C.pin(C.ordinary(candidate_path))==ARCHIVE,'accepted archive unchanged after fresh TEST signing')
 return candidate_path

def make(*,packet,doctor_packet,ready604,output,source,producer,original_api):
 """Only a gated native owner calls this; development never runs signing/actors."""
 C.need(not output.exists(),'fresh owned Doctor input context');old_api=legacy();runtime_input=old_api.inspect(packet);new=inspect(doctor_packet);checks=old_api.inspector()
 manifest=C.decode(C.ordinary(ready604/'manifest.json',16*1024**2));products={r['name']:r for r in manifest['packages']};projects={r['name']:r for r in manifest['projects']};old=products[NAME]
 C.need(old['version']=='0.1.0-5'and old['sha256']=='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'and products[RUNTIME]['version']=='0.1.0-1','same original606 Doctor1/Runtime1 manifest')
 original_public=old_api.original_key(ready604,manifest,old['signer']);oldpath=ready604/old['archive'];oldsig=ready604/old['signature'];C.need(C.pin(C.ordinary(oldpath))==dict(bytes=old['size'],sha256=old['sha256'])and C.pin(C.ordinary(oldsig,65536))==dict(bytes=old['signature_size'],sha256=old['signature_sha256']),'whole exact original Doctor1 archive/signature')
 oldreport=checks.package(oldpath);C.need(not oldreport['errors'],'complete original Doctor1 archive');oldpayload={n:r for n,r in oldreport['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}
 records={}
 for name,payload in((NAME,oldpayload),(RUNTIME,runtime_input[RUNTIME]['payload'])):
  project=projects[name];C.need(project['sha256']==products[name]['sha256']and {r['path'].lstrip('/'):dict(mode=r['mode'],sha256=r['sha256'])for r in project['payload']}=={n:{k:v[k]for k in('mode','sha256')}for n,v in payload.items()},'complete original606 project payload provenance')
  records[name]=dict(products[name],payload=payload,original_project=project,original_manifest=C.pin(C.ordinary(ready604/'manifest.json',16*1024**2)))
 # All immutable input/source/payload checks precede output or private signing.
 output.mkdir(mode=0o700);archives=output/'archives';archives.mkdir();keys=output/'keys';keys.mkdir()
 def operand(path,sig,version,signer,payload,source_record=None):
  dest=archives/path.name;C.need(not dest.exists(),'distinct exact archive operand');shutil.copyfile(path,dest);shutil.copyfile(sig,dest.with_name(dest.name+'.sig'))
  value=dict(path='/runner/inputs/archives/'+dest.name,**C.pin(C.ordinary(dest)),signature=dict(path='/runner/inputs/archives/'+dest.name+'.sig',**C.pin(C.ordinary(sig,65536))),version=version,signer=signer,payload=payload)
  if source_record is not None:value['source_record']=source_record
  return value
 original=operand(oldpath,oldsig,old['version'],old['signer'],oldpayload,records[NAME])
 # Fresh signature is created only for the exact accepted unsigned candidate,
 # under the original already-owned TEST home. No new private/public key role.
 candidate_path=sign_candidate(path=new['path'],output=output,source=source,producer=producer,original_public=original_public,signer_fingerprint=old['signer'],original_api=original_api)
 candidate=operand(candidate_path,candidate_path.with_name(candidate_path.name+'.sig'),new['version'],old['signer'],new['payload'])
 dependency=runtime_input[RUNTIME];runtime=operand(dependency['path'],dependency['signature'],dependency['version'],dependency['signer'],dependency['payload'],records[RUNTIME])
 keyrows=[]
 for basename,key,fpr in [('original-public.asc',original_public,old['signer']),('runtime-public.asc',dependency['key'],dependency['signer'])]:
  shutil.copyfile(key,keys/basename);keyrows.append(dict(path='/runner/inputs/keys/'+basename,signer=fpr,**C.pin(C.ordinary(key,65536))))
 import plan
 value=plan.make(original1=original,new2=candidate,runtime=runtime,original606_manifest=records,original1_report=oldreport,new2_report=new['report'],runtime_report=dependency['report'],verification_keys=keyrows)
 (output/'lifecycle-plan.json').write_bytes(C.encoded(value));(output/'native-inputs.json').write_bytes(C.encoded(new['provenance']))
 shutil.rmtree(output/'signing')
 return value
