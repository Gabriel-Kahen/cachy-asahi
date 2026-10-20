# SPDX-License-Identifier: MIT
"""Exact accepted unsigned Doctor2 DATA; fresh original producer TEST signing only."""
import importlib.util,json,os,shutil,stat,sys,zipfile
from pathlib import Path
import contract as C
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
NAME='cachy-asahi-doctor';RUNTIME='cachy-asahi-repository-runtime'
NATIVE='705c5a095f9cabbfd2f3cd137127f4bbc7665f52';RUN=39321557701
INDEX=dict(bytes=25869,sha256='848ed2fed42236ac166e927bccb86c9957e136f9c9583dce0d650c2edf2bd83b')
ARCHIVE=dict(bytes=16000,sha256='5d27ef618bfc571c0238cfbbbcf382d0e4c689df509d1f62123ad5fe53245ee7')
def legacy():
 p=HERE/'held-runtime-inputs.py';spec=importlib.util.spec_from_file_location('_held_complete_runtime_inputs',p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def data(root,name):
 # The genuine complete native artifact has one exact empty lifecycle log.
 # This finite DATA leaf does not relax any worker/source/archive read guard.
 if name!='retained/runtime/lifecycle.log':return C.ordinary(root/name,16*1024**2)
 path=root/name;C.need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary exact empty retained log')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);raw=os.read(fd,1);b=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  C.need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==0 and raw==b''and key(a)==key(b)==key(path.lstat()),'exact empty retained log identity/content')
  return raw
 finally:os.close(fd)

def checked(root,row):
 C.need(type(row)is dict and set(row)=={'path','bytes','sha256'},'closed Doctor DATA reference');name=row['path'];C.need(type(name)is str and name and not name.startswith('/')and '..'not in Path(name).parts and Path(name).as_posix()==name,'ordinary relative public DATA')
 raw=data(root,name);C.need(C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'whole Doctor DATA pin');return root/name

def inspect(packet):
 C.need(C.pin(C.ordinary(packet/'index.json',1024**2))==INDEX,'exact published Doctor native DATA index')
 index=C.decode(C.ordinary(packet/'index.json',1024**2));wanted=index['files'];actual={p.relative_to(packet).as_posix()for p in packet.rglob('*')if p.is_file()}
 C.need(actual==set(wanted)|{'index.json'}and len(actual)==131 and not any(p.is_symlink()for p in packet.rglob('*')),'closed entire131 Doctor DATA files')
 for name,row in wanted.items():checked(packet,dict(path=name,**row))
 C.need(index['schema_version']==1 and index['kind']=='DOCTOR2_ACCEPTED_NATIVE_PAIR_INPUTS_ONLY'and index['authority_scope']=='UNSIGNED_ACCEPTED_PAIR_NO_CURRENT606_CREDIT'and index['native']==dict(source=NATIVE,run=RUN,source_files=62,ref='codex/doctor2-native-products-v1'),'exact native unsigned pair-only authority')
 authority=C.decode(C.ordinary(checked(packet,index['source_authorization']),1024**2));C.need(len(authority)==62 and {n.removeprefix('source/'):{k:r[k]for k in('bytes','sha256')}for n,r in wanted.items()if n.startswith('source/')}==authority,'whole exact62 source DATA')
 publication=C.decode(C.ordinary(checked(packet,index['publication'])));C.need(publication['source']==NATIVE and publication['files']==publication['git_joins']==62 and publication['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE','genuine Root62 source publication')
 decision=C.decode(C.ordinary(checked(packet,index['decision'])));C.need(decision['status']=='ROOT_ACCEPTED_FINITE_NATIVE_DOCTOR2_PAIR_AND_OFFLINE_INSTALLED_CLI_LIFECYCLE'and decision['source']==NATIVE and decision['run']==RUN and decision['source_files']==decision['independent_git_blob_joins']==62 and decision['release']=='NOT_ADMITTED','finite exact native Doctor Root decision')
 run=C.decode(C.ordinary(checked(packet,index['original_metadata']['run'])));C.need(run['id']==RUN and run['head_sha']==NATIVE and run['conclusion']=='success'and run['run_attempt']==1,'exact accepted native API DATA')
 with zipfile.ZipFile(checked(packet,index['original_artifact']))as archive:
  names=archive.namelist();C.need(len(names)==len(set(names))==60 and archive.testzip()is None,'complete accepted native artifact ZIP')
  C.need({n.removeprefix('retained/')for n in wanted if n.startswith('retained/')}==set(names),'whole60 retained artifact DATA closure')
  for name in names:C.need(archive.read(name)==data(packet,'retained/'+name),'retained native bytes exactly original ZIP')
 package=index['package'];C.need(package['name']==NAME and package['version']=='0.2.0-1','Doctor2 archive identity')
 checks=legacy().inspector();reports=[];paths=[];recipe=packet/'source/packages/tools/cachy-asahi-doctor2'
 sources={'usr/bin/cachy-asahi-doctor':('cachy-asahi-doctor',0o755),'usr/share/doc/cachy-asahi-doctor/README.md':('README.md',0o644),'usr/share/licenses/cachy-asahi-doctor/LICENSE':('LICENSE',0o644),'usr/share/licenses/cachy-asahi-doctor/NOTICE':('NOTICE',0o644)}
 for side in('a','b'):
  path=checked(packet,package['archives'][side]);C.need(C.pin(C.ordinary(path))==ARCHIVE,'exact accepted16000-byte Doctor pair');report=checks.package(path);C.need(not report['errors']and report['metadata']['.PKGINFO']['pkgname']==[NAME]and report['metadata']['.PKGINFO']['pkgver']==['0.2.0-1']and report['metadata']['.PKGINFO']['arch']==['any'],'complete Doctor archive metadata')
  payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(set(payload)==set(sources)==C.DOCTOR_FILES,'complete exact four Doctor payload leaves')
  for name,(source,mode)in sources.items():
   raw=C.ordinary(recipe/source,1024**2);r=payload[name];C.need(r['type']=='0'and r['uid']==r['gid']==0 and r['mode']==mode and r['size']==len(raw)and r['sha256']==C.pin(raw)['sha256'],'all Doctor payload/source/license bytes')
  C.need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[C.pin(C.ordinary(recipe/'PKGBUILD'))['sha256']],'exact accepted Doctor recipe/BUILDINFO')
  reports.append(report);paths.append(path)
 C.need(reports[0]==reports[1]and paths[0].read_bytes()==paths[1].read_bytes(),'complete accepted native Doctor pair equality')
 return dict(path=paths[0],version='0.2.0-1',payload=payload,report=reports[0],provenance=dict(source=NATIVE,run=RUN,index=INDEX,decision=index['decision'],original_artifact=index['original_artifact'],signature='UNSIGNED_REQUIRES_FRESH_ORIGINAL_PRODUCER_TEST_SIGNING'))

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
 C.need(old['version']=='0.1.0-1'and old['sha256']=='06898669fdd6c9e5bdcc9909e6b0e75e958bdbd57520a7082c0e9f5f7fac7482'and products[RUNTIME]['version']=='0.1.0-1','same original606 Doctor1/Runtime1 manifest')
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
