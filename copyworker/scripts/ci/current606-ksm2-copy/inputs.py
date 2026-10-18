# SPDX-License-Identifier: MIT
"""Finite native KSM DATA joins; exact producer KSM1 remains restoration authority."""
import importlib.util,shutil
from pathlib import Path
import contract as C
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];NAME='cachy-asahi-ksmctl'
def checked(root,row):
 C.need(type(row)is dict and set(row)=={'path','bytes','sha256'},'closed DATA ref');name=row['path'];C.need(type(name)is str and name and not name.startswith('/')and Path(name).as_posix()==name and not{'.','..'}&set(name.split('/')),'relative DATA ref')
 p=root/name;C.need(C.pin(C.ordinary(p,16*1024**2))=={k:row[k]for k in('bytes','sha256')},'whole DATA pin');return p
def inspector():
 p=ROOT/'held-ksm/checks/package_checks.py';s=importlib.util.spec_from_file_location('_ksm606_inspector',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def inspect(packet):
 pins=C.decode(C.ordinary(HERE/'prerequisite-pins.json',1024**2));wanted=pins['files'];actual={p.relative_to(packet).as_posix()for p in packet.rglob('*')if p.is_file()}
 C.need(actual==set(wanted)and len(actual)==29 and not any(p.is_symlink()for p in packet.rglob('*')),'whole29 carrier DATA closure')
 for n,v in wanted.items():checked(packet,dict(path=n,**v))
 index=C.decode(C.ordinary(packet/'index.json',1024**2));C.need(C.pin(C.ordinary(packet/'index.json',1024**2))==pins['index'],'exact carrier index')
 C.need((index['source'],index['run'],index['name'],index['version'])==(pins['native_source'],pins['native_run'],NAME,'0.1.0-2'),'exact accepted native pair identity')
 d=checked(packet,index['native_decision']);raw=C.ordinary(d,65536);decision=C.decode(raw)
 C.need(C.pin(raw)==pins['native_decision']and decision['source']==pins['native_source']and decision['run']==pins['native_run']and decision['status']=='ROOT_ACCEPTED_NATIVE_KSM1_TO2_UPGRADE_RETAINED_SCOPE'and decision['installed_controls']=={'ordinary_homes':2,'v1':18,'v2':44}and decision['transitions']==[575,575,574,575,574],'whole exact Root native qualification')
 recipe=index['recipe'];C.need(recipe['source']==pins['recipe_source']and len(recipe['files'])==14,'exact native recipe14')
 for n,v in recipe['files'].items():checked(packet,dict(path=recipe['path']+'/'+n,**v));C.need(C.pin(C.ordinary(ROOT/'held-ksm/source'/n))==v,'source-owned recipe equals carrier')
 reports=[];paths=[];checks=inspector()
 for side in ('a','b'):
  p=checked(packet,index['files'][side]);C.need(C.pin(C.ordinary(p))==dict(bytes=24128,sha256='bac3d222b6490412c1c9c7bafd72d8169e8679a1e7b411b5794246aed0b57b5f'),'exact native KSM2 archive')
  r=checks.package(p);C.need(r['errors']==[]and r['metadata']['.PKGINFO']['pkgname']==[NAME]and r['metadata']['.PKGINFO']['pkgver']==['0.1.0-2']and r['metadata']['.PKGINFO']['arch']==['any'],'actual complete archive identity')
  payload={n:v for n,v in r['members'].items()if v['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(set(payload)==C.KSM_FILES,'complete KSM2 payload7')
  expected={'usr/bin/cachy-asahi-ksmctl':'cachy-asahi-ksmctl','usr/bin/cachy-asahi-ksm-experiment':'cachy-asahi-ksm-experiment',**{'usr/share/doc/'+NAME+'/'+n:n for n in('README.md','source-provenance.json','experiment-provenance.json')},**{'usr/share/licenses/'+NAME+'/'+n:n for n in('LICENSE','NOTICE')}}
  for name,leaf in expected.items():
   row=payload[name];C.need(row['type']=='0'and row['uid']==row['gid']==0 and row['mode']==(0o755 if name.startswith('usr/bin/')else 0o644)and dict(bytes=row['size'],sha256=row['sha256'])==recipe['files'][leaf],'all native payload/source bytes')
  C.need(r['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[recipe['files']['PKGBUILD']['sha256']],'whole BUILDINFO recipe join');reports.append(r);paths.append(p)
 C.need(reports[0]==reports[1]and paths[0].read_bytes()==paths[1].read_bytes(),'native complete pair equality')
 sig=checked(packet,index['files']['signature']);key=checked(packet,index['files']['public_key']);C.need(index['signer']=='7E73A80AF8FD5DA6529EF27E1AB823DC28925AA5','exact TEST signer')
 return dict(path=paths[0],signature=sig,key=key,signer=index['signer'],version='0.1.0-2',payload=payload,report=reports[0],authority='NATIVE_PAIR_ONLY_NOT606_ACCEPTANCE')
def original_key(ready,manifest,signer):
 roles=manifest['preparation']['signer_roles'];C.need(set(roles)=={'ephemeral_TEST','upstream_ALARM'}and len(set(roles.values()))==2 and roles['ephemeral_TEST']==signer,'exact original signer roles')
 rows=manifest['keyrings'];C.need(type(rows)is list and len(rows)==2 and {r['path']for r in rows}=={'keys/archlinuxarm.gpg','keys/TEST-public.asc'},'exact original keyring set')
 row=next(r for r in rows if r['path']=='keys/TEST-public.asc');C.need(set(row)=={'path','size','sha256'},'closed original key metadata');p=ready/row['path'];C.need(C.pin(C.ordinary(p,65536))==dict(bytes=row['size'],sha256=row['sha256']),'whole original TEST key');return p
def make(*,packet,ready604,output):
 C.need(not output.exists(),'fresh KSM input context');native=inspect(packet);checks=inspector();manifest=C.decode(C.ordinary(ready604/'manifest.json',16*1024**2));products={r['name']:r for r in manifest['packages']};projects={r['name']:r for r in manifest['projects']};old=products[NAME]
 C.need(old['version']=='0.1.0-1','same606 producer original KSM1');p=ready604/old['archive'];sig=ready604/old['signature'];C.need(C.pin(C.ordinary(p))==dict(bytes=old['size'],sha256=old['sha256'])and C.pin(C.ordinary(sig,65536))==dict(bytes=old['signature_size'],sha256=old['signature_sha256']),'exact actual original archive/signature')
 report=checks.package(p);C.need(not report['errors'],'complete original archive inspector');payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(set(payload)==C.OLD_FILES and payload['usr/bin/'+NAME]['sha256']=='f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558','whole original KSM1 payload/reporter')
 project=projects[NAME];C.need(project['sha256']==old['sha256']and {r['path'].lstrip('/'):dict(mode=r['mode'],sha256=r['sha256'])for r in project['payload']}=={n:{k:r[k]for k in('mode','sha256')}for n,r in payload.items()},'exact original project payload')
 source_record=dict(old,payload=payload,original_project=project,original_manifest=C.pin(C.ordinary(ready604/'manifest.json',16*1024**2)));key=original_key(ready604,manifest,old['signer']);output.mkdir(mode=0o700);(output/'archives').mkdir();(output/'keys').mkdir()
 def operand(path,sig,version,signer,payload,record=None):
  dst=output/'archives'/path.name;C.need(not dst.exists(),'distinct archive operands');shutil.copyfile(path,dst);shutil.copyfile(sig,dst.with_name(dst.name+'.sig'))
  row=dict(path='/runner/inputs/archives/'+dst.name,**C.pin(dst.read_bytes()),signature=dict(path='/runner/inputs/archives/'+dst.name+'.sig',**C.pin(sig.read_bytes())),version=version,signer=signer,payload=payload)
  if record is not None:row['source_record']=record
  return row
 original=operand(p,sig,'0.1.0-1',old['signer'],payload,source_record);candidate=operand(native['path'],native['signature'],'0.1.0-2',native['signer'],native['payload']);keys=[]
 for basename,path,signer in(('original-public.asc',key,old['signer']),('ksm2-public.asc',native['key'],native['signer'])):
  shutil.copyfile(path,output/'keys'/basename);keys.append(dict(path='/runner/inputs/keys/'+basename,**C.pin(path.read_bytes()),signer=signer))
 import plan
 value=plan.make(original1=original,new2=candidate,original606_manifest={NAME:source_record},original1_report=report,new2_report=native['report'],verification_keys=keys);(output/'lifecycle-plan.json').write_bytes(C.encoded(value));return value
