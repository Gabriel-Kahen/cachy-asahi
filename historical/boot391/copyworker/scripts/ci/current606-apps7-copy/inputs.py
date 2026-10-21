# SPDX-License-Identifier: MIT
"""Pure public192 native-pair proof and exact live-producer original6 input builder."""
import importlib.util,json,shutil,sys
from pathlib import Path
import contract as C
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
APPS='cachy-asahi-apps';RUNTIME='cachy-asahi-repository-runtime'
ARCHIVES={APPS:(23212,'23fc2fe5707606b0f3bd8c6322b9e7ae0c47a6ff1024cd239f4486679638be39'),RUNTIME:(28888,'1c8a9149da02e60a4c14598cdf7007d6dbffcd6150757fcf6711977aa00cf8aa')}
NATIVE='1dc9ecfee51145ba9cc43a95cc45bee97faed8b9';RUN='39095436036'

def checked(root,row):
 C.need(type(row)is dict and set(row)=={'path','bytes','sha256'},'closed public DATA reference');name=row['path'];C.need(type(name)is str and name and not name.startswith('/')and '..'not in Path(name).parts and Path(name).as_posix()==name,'ordinary relative public DATA')
 raw=C.ordinary(root/name,16*1024**2);C.need(C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'whole public DATA pin');return root/name

def inspector():
 path=ROOT/'held-apps/checks/package_checks.py';spec=importlib.util.spec_from_file_location('_apps606_package_inspector',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def inspect(packet):
 pins=C.decode(C.ordinary(HERE/'prerequisite-pins.json',1024**2));wanted=pins['files'];actual={p.relative_to(packet).as_posix()for p in packet.rglob('*')if p.is_file()}
 C.need(actual==set(wanted)and len(actual)==196 and all(not p.is_symlink()for p in packet.rglob('*')),'whole192 public packet closure')
 for name,row in wanted.items():checked(packet,dict(path=name,**row))
 index=C.decode(C.ordinary(packet/'index.json',1024**2));C.need(C.pin(C.ordinary(packet/'index.json',1024**2))==pins['index']and index['kind']=='APPS7_FOUR_NATIVE_PAIRS_FOR_PROSPECTIVE_FULL574_REPAIR'and index['authority_scope']=='PUBLIC_NATIVE_PAIR_INPUTS_ONLY_NO_REPAIR_ACCEPTANCE','whole declared public pair/input-only authority')
 checks=inspector();inner=C.decode(C.ordinary(packet/'apps7/index.json',1024**2));result={}
 for name in (APPS,RUNTIME):
  row=index['packages'][name];version='0.1.0-7'if name==APPS else'0.1.0-1';C.need((row['version'],row['native_source'],row['native_run'],row['qualification'])==(version,NATIVE,RUN,'NATIVE_PAIR_ONLY'),'exact actual Apps7/Runtime native prerequisite')
  decision=checked(packet,row['decision']);d=C.decode(C.ordinary(decision,65536));C.need(C.pin(C.ordinary(decision,65536))['sha256']=='589498543381db1124fbfbdea85810b7ff1e60261be3dde098ad060cbb2b1b22'and d['source']==NATIVE and str(d['run'])==RUN and d['status']=='ROOT_ACCEPTED_NATIVE_APPS7_CLIENT_RETAINED_SCOPE','genuine native Root decision byte identity')
  reports=[];paths=[]
  for side in ('a','b'):
   path=checked(packet,row['files'][side]);C.need((path.stat().st_size,C.pin(C.ordinary(path,8*1024**2))['sha256'])==ARCHIVES[name],'exact accepted pair archive')
   report=checks.package(path);C.need(report['errors']==[]and report['metadata']['.PKGINFO']['pkgname']==[name]and report['metadata']['.PKGINFO']['pkgver']==[version]and report['metadata']['.PKGINFO']['arch']==['any'],'actual archive complete metadata')
   payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(set(payload)==set(row['payload']),'complete actual payload closure')
   for n,w in row['payload'].items():
    source=checked(packet,row['source_files'][w['source']]);raw=C.ordinary(source,8*1024**2);r=payload[n];C.need(r['type']=='0'and r['uid']==r['gid']==0 and r['mode']==w['mode']and r['size']==len(raw)and r['sha256']==C.pin(raw)['sha256'],'full native payload/source bytes')
   buildinfo=report['metadata']['.BUILDINFO'];C.need(buildinfo['pkgbuild_sha256sum']==[row['source_files']['PKGBUILD']['sha256']],'complete BUILDINFO recipe join')
   reports.append(report);paths.append(path)
  C.need(reports[0]==reports[1]and paths[0].read_bytes()==paths[1].read_bytes(),'complete independent accepted pair equality')
  native=inner['packages'][name];sig=checked(packet/'apps7',native['signature']);key=checked(packet/'apps7',native['public_key']);signer=inner['signer']['fingerprint'];C.need(signer=='DA8AD638E79414E661656E4C23132CAA1000DA38','exact native TEST fingerprint')
  result[name]=dict(path=paths[0],signature=sig,key=key,signer=signer,version=version,payload=payload,report=reports[0])
 return result

def original_key(ready,manifest,signer):
 roles=manifest['preparation']['signer_roles'];C.need(set(roles)=={'ephemeral_TEST','upstream_ALARM'}and len(set(roles.values()))==2 and all(__import__('re').fullmatch('[A-F0-9]{40}',v or '')for v in roles.values())and roles['ephemeral_TEST']==signer,'exact two distinct original signer roles')
 C.need(type(manifest['keyrings'])is list and len(manifest['keyrings'])==2 and {r.get('path')for r in manifest['keyrings']}=={'keys/archlinuxarm.gpg','keys/TEST-public.asc'},'exact original two-keyring operand set')
 rows=[r for r in manifest['keyrings']if r.get('path')=='keys/TEST-public.asc'];C.need(len(rows)==1 and set(rows[0])=={'path','size','sha256'},'one exact manifest TEST key operand')
 row=rows[0];path=ready/row['path'];C.need(C.pin(C.ordinary(path,65536))==dict(bytes=row['size'],sha256=row['sha256']),'whole original manifest public key bytes')
 return path

def make(*,packet,ready604,output):
 """Called only after actual owner/public-source gates, before new actors.

 ready604 is the SAME original producer's complete signed604 constructor output.
 Its original Apps6 and Runtime1 rows remain independent restoration authority.
 """
 C.need(not output.exists(),'fresh owned Apps input context');native=inspect(packet);checks=inspector();manifest=C.decode(C.ordinary(ready604/'manifest.json',16*1024**2));products={r['name']:r for r in manifest['packages']};projects={r['name']:r for r in manifest['projects']}
 C.need(products[APPS]['version']=='0.1.0-6'and products[RUNTIME]['version']=='0.1.0-1'and products[APPS]['sha256']=='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7'and products[RUNTIME]['sha256']==ARCHIVES[RUNTIME][1],'exact original606 Apps6/Runtime1 constructor rows')
 original_public=original_key(ready604,manifest,products[APPS]['signer'])
 output.mkdir(mode=0o700);archives=output/'archives';archives.mkdir();keys=output/'keys';keys.mkdir();keyrows=[];records={}
 def operand(path,sig,version,signer,payload,source_record=None):
  dest=archives/path.name;C.need(not dest.exists(),'distinct exact archive operands');shutil.copyfile(path,dest);shutil.copyfile(sig,dest.with_name(dest.name+'.sig'))
  value=dict(path='/runner/inputs/archives/'+dest.name,**C.pin(dest.read_bytes()),signature=dict(path='/runner/inputs/archives/'+dest.name+'.sig',**C.pin(sig.read_bytes())),version=version,signer=signer,payload=payload)
  if source_record is not None:value['source_record']=source_record
  return value
 old=products[APPS];path=ready604/old['archive'];sig=ready604/old['signature'];C.need(C.pin(C.ordinary(path,8*1024**2))==dict(bytes=old['size'],sha256=old['sha256'])and C.pin(C.ordinary(sig,65536))==dict(bytes=old['signature_size'],sha256=old['signature_sha256']),'whole actual original6 archive/signature')
 oldreport=checks.package(path);C.need(not oldreport['errors'],'original6 inspector');payload={n:r for n,r in oldreport['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}
 for name,report_payload in ((APPS,payload),(RUNTIME,native[RUNTIME]['payload'])):
  project=projects[name];C.need(project['sha256']==products[name]['sha256']and {r['path'].lstrip('/'):dict(mode=r['mode'],sha256=r['sha256'])for r in project['payload']}=={n:{k:v[k]for k in('mode','sha256')}for n,v in report_payload.items()},'exact original606 complete project payload')
  records[name]=dict(products[name],payload=report_payload,original_project=project,original_manifest=C.pin((ready604/'manifest.json').read_bytes()))
 original=operand(path,sig,old['version'],old['signer'],payload,records[APPS])
 new=native[APPS];candidate=operand(new['path'],new['signature'],new['version'],new['signer'],new['payload'])
 dependency=native[RUNTIME];runtime=operand(dependency['path'],dependency['signature'],dependency['version'],dependency['signer'],dependency['payload'],records[RUNTIME])
 for basename,key,signer in [('original-public.asc',original_public,old['signer']),('apps7-public.asc',new['key'],new['signer'])]:
  shutil.copyfile(key,keys/basename);keyrows.append(dict(path='/runner/inputs/keys/'+basename,signer=signer,**C.pin(key.read_bytes())))
 import plan
 value=plan.make(original6=original,new7=candidate,runtime=runtime,original606_manifest=records,original6_report=oldreport,new7_report=new['report'],runtime_report=dependency['report'],verification_keys=keyrows)
 (output/'lifecycle-plan.json').write_bytes(C.encoded(value));return value
