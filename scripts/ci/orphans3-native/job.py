#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse source proof/owned retirement; retain bounded real-removal evidence."""
import argparse,hashlib,json,os,re,shutil,stat,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def save(p,v):p.write_bytes(C.encoded(v))
def inherited(source):
 m=C.load('orphans3_existing_job',source/'scripts/ci/orphans-native/job.py');m.C=C;return m

def prove(source,environment):
 C.verify_source(source);m=C.load('orphans3_existing_proof',source/'scripts/ci/welcome-native/ci/caller.py');v=m.prove(source,C.read(source/C.LANE/'source-manifest.json'),environment)
 v['consumer_token']=hashlib.sha256(('orphans3-consumer:'+v['run_id']+':'+v['run_attempt']+':'+v['source_sha']).encode()).hexdigest()[:32];v['manifest_sha256']=C.digest(source/C.LANE/'source-manifest.json');return v

def cleanup(source,base,runtime,proof,output):
 C.verify_source(source);M=inherited(source);v=M.cleanup(source,C.read(source/C.LANE/'source-manifest.json'),proof,base,runtime,output)
 v['authority']='NOT_STARTED'
 try:
  C.need(v['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','consumer/producer cleanup uncertain; TEST authority preserved')
  key=runtime/'test-signing';owner=runtime/'authority.json'
  if key.exists() or owner.exists():
   a=C.read(owner);s=key.lstat();C.need(a['directory']=='test-signing' and (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode))==(a['dev'],a['ino'],os.getuid(),0o700) and a['mode']==0o700 and stat.S_ISDIR(s.st_mode) and not key.is_symlink(),'unknown TEST key directory preserved')
   r=subprocess.run(['gpgconf','--homedir',str(key),'--kill','all'],capture_output=True,timeout=20);C.need(r.returncode==0,'TEST signer shutdown failed');shutil.rmtree(key);C.need(not key.exists() and not key.is_symlink(),'TEST signing authority remains');v['authority']='PASS_ABSENT_AFTER_ACTORS_AND_PRODUCER'
  else:C.need(not (runtime/'lifecycle-inputs/control.json').exists(),'signing control without recorded authority')
 except BaseException as error:v.update(status='FAIL',authority='PRESERVED_OR_UNCERTAIN',error_type=type(error).__name__,error=str(error)[:500])
 save(output,v);return v

def retain(source,base,runtime,proof,ordered,output):
 C.safe(output);C.need(not output.exists(),'fresh public evidence output required');output.mkdir(mode=0o700)
 v=dict(status='FAIL_OR_INCOMPLETE',scope='PRIVATE_OFFLINE_ROOT_ONLY',files={},errors=[],total_bytes=0,hardware='NOT_RUN',release='NOT_ADMITTED',broad_live_removal='NOT_IMPLEMENTED',actual_source=None,actual_ref=None,actual_run=None)
 def copy(p,n,cap=128*1024**2,required=True):
  if not required and not os.path.lexists(p):return
  try:
   C.safe(p);s=p.lstat();C.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=cap and v['total_bytes']+s.st_size<=384*1024**2 and len(v['files'])<1024,'bounded ordinary evidence set')
   dest=output/n;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(p,dest);v['files'][n]=dict(bytes=s.st_size,sha256=C.digest(dest));v['total_bytes']+=s.st_size
  except Exception as error:v['errors'].append(n+': '+str(error)[:300])
 copy(proof,'source-proof.json');copy(ordered,'ordered-cleanup.json')
 copy(proof.parent/'orphans3-retained-audit.json','retained-audit.json',required=False)
 for n in ('report.json','installed-packages.lock','retained-inputs.json'):copy(base/n,'base/'+n)
 for n in ('report.json','owner.json','authority.json','comparison.json','lifecycle.log'):copy(runtime/n,'runtime/'+n)
 roots=[C.PRODUCT+'-a',C.PRODUCT+'-b','fixtures','lifecycle-inputs','lifecycle-output']
 for name in roots:
  parent=runtime/name
  if not parent.is_dir():v['errors'].append('missing '+name);continue
  for p in sorted(parent.rglob('*')):
   if p.is_dir() and not p.is_symlink():continue
   relative=p.relative_to(runtime).as_posix();C.need(re.fullmatch(r'[A-Za-z0-9_+./:@ -]{1,512}',relative) and '..' not in Path(relative).parts,'ordinary retained name required');copy(p,'runtime/'+relative)
 manifest=C.read(source/C.LANE/'source-manifest.json');copy(source/C.LANE/'source-manifest.json','source/source-manifest.json')
 for name in manifest['files']:copy(source/name,'source/'+name,16*1024**2)
 for name in C.WORKFLOWS:copy(source/name,'source/'+name)
 try:
  C.verify_source(source);p=C.read(proof);b=C.read(base/'report.json');r=C.read(runtime/'report.json');o=C.read(ordered);owner=C.read(runtime/'owner.json');life=C.read(runtime/'lifecycle-output/lifecycle.json');C.validate_lifecycle(life)
  C.need(p['status']=='SOURCE_PROOF_PASS' and p['manifest_sha256']==C.digest(source/C.LANE/'source-manifest.json') and b['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and b['ownership']['token']==p['job_token'],'source/original producer proof differs')
  transport=C.load('orphans3_hosted_input_replay',source/C.LANE/'closed.py');v['hosted_input_transport']=transport.validate_transport(source,C.read(base/'retained-inputs.json'))
  C.need(b.get('acquired')==1153 and b.get('failures')==[],'all original1153 acquisition/verification inputs required')
  C.need(r['status']=='PASS_NATIVE_ORPHANS3_PAIR_AND_REAL_PRIVATE_REMOVAL' and r['lifecycle']==life and r['base_image']==b['image']==owner['image'] and r['base_lock_sha256']==C.digest(base/'installed-packages.lock')==C.BASE and r['ownership_token']==owner['token']==p['consumer_token'] and owner['label']==C.LABEL,'runtime/source/base/ownership mismatch')
  C.need(len(r.get('commands',[]))==4 and all(row.get('exitcode')==0 and row.get('retirement',{}).get('ownership')=='RETIRED' and row['retirement'].get('leader_reaped') is True and row['retirement'].get('observed_returncode')==0 and row['retirement'].get('log_drained') is True and row['retirement'].get('log_error') is None and row['retirement'].get('error') is None for row in r['commands']),'all four command leaders/logs require observed owned retirement')
  actor=C.load('orphans3_retained_map_replay',source/C.LANE/'lifecycle.py');maps={}
  for name,row in life['maps'].items():
   relative=Path(row['path']);C.need(not relative.is_absolute() and '..' not in relative.parts and relative.parts[0]=='maps','fixed target map path')
   path=runtime/'lifecycle-output'/relative;C.need(C.digest(path)==row['sha256'],'actual target map hash differs');maps[name]=C.read(path,128*1024**2);C.need(len(maps[name])==row['nodes'],'actual map node count differs')
  for name in ('different-selection','duplicate-selection','protected-needed-protected','protected-needed-explicit','protected-needed-required','protected-needed-optional','same-bytes-assessment','foreign-lock','stale-after-removal','helper-alias','unsafe-payload'):
   actor.preservation(maps[name+'-before'],maps[name+'-after'])
  before_map=maps['positive-before'];leaf='caa-orphans3-leaf-a';prefixes=('var/lib/pacman/local/'+leaf+'-1-1','usr/share/licenses/'+leaf)
  removed={n for n in before_map if n=='usr/share/orphans3-fixture/'+leaf+'.txt' or any(n==x or n.startswith(x+'/') for x in prefixes)};actor.preservation(before_map,maps['positive-after'],removed)
  C.need('var/lib/pacman/db.lck' not in maps['final-target'],'final ALPM lock remains')
  for event in life['events']:
   if event['durable_result'] is not None:
    relative=Path(event['durable_result']);C.need(not relative.is_absolute() and '..' not in relative.parts and relative.parts[0]=='reports','fixed removal result path');C.need(C.read(runtime/'lifecycle-output'/relative)==event['result'],'durable actual removal result differs')
  held=life['base_before'];held_path=runtime/'lifecycle-output'/held['path'];C.need(held['path']=='base-before.json' and C.digest(held_path)==held['sha256'] and len(C.read(held_path,128*1024**2)['packages'])==574,'complete original574 before map missing')
  after=life['base_after'];after_path=runtime/'lifecycle-output'/after['path'];C.need(after['path']=='base-after.json' and C.digest(after_path)==after['sha256'],'complete original574 after map missing')
  before_base=C.read(held_path,128*1024**2);after_base=C.read(after_path,128*1024**2);C.need(before_base==after_base and len(before_base['nodes'])==held['nodes']==after['nodes'] and hashlib.sha256(json.dumps(before_base,sort_keys=True,separators=(',',':')).encode()).hexdigest()==life['base_preservation_sha256'],'independent complete original574 preservation replay differs')
  expected_base=dict(line.split() for line in (base/'installed-packages.lock').read_text().splitlines());C.need({row['name']:row['version'] for row in before_base['packages']}==expected_base==C.read(runtime/'lifecycle-inputs/base.json'),'actual original574 map/image/input lock identities differ')
  C.need(o['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and o['authority']=='PASS_ABSENT_AFTER_ACTORS_AND_PRODUCER' and o['producer']==b['owned_cleanup'] and b['owned_cleanup']['status']=='PASS' and len(owner['containers'])==4 and len(o['consumer']['containers'])==4 and {x['container'] for x in o['consumer']['containers']}==set(owner['containers']) and all(x['status']=='PASS' and x['absence_verified'] is True for x in o['consumer']['containers']),'complete four-consumer then producer then authority absence required')
  sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')];comparison=C.load('orphans3_export_compare',source/'scripts/build/compare.py').compare(runtime/(C.PRODUCT+'-a'),runtime/(C.PRODUCT+'-b'));C.pair_gate(comparison)
  C.need(comparison==C.read(runtime/'comparison.json')==r['pair']['comparison'],'actual pair evidence differs')
  control=C.read(runtime/'lifecycle-inputs/control.json');C.need(set(control['fixtures'])==set(C.FIXTURES) and re.fullmatch('[0-9A-F]{40}',control['signer']),'exact9 TEST-signed inputs required')
  expected=[control['candidate'],*control['fixtures'].values()]
  for row in expected:
   name=row['archive'];C.need(Path(name).name==name and C.digest(runtime/'lifecycle-inputs'/name)==row['sha256'] and 'runtime/lifecycle-inputs/'+name in v['files'],'retained archive identity missing')
  C.need(not v['errors'],'complete retained raw evidence required');v['status']='PASS_NATIVE_ORPHANS3_PRIVATE_REMOVAL_AND_ORDERED_CLEANUP'
 except BaseException as error:v['errors'].append(type(error).__name__+': '+str(error)[:800])
 save(output/'retention.json',v);return v

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('proof','cleanup','retain'))
 for n in ('source','base','runtime','proof','cleanup','output'):p.add_argument('--'+n,type=Path)
 a=p.parse_args();source=a.source.absolute()
 if a.phase=='proof':
  v=prove(source,os.environ);save(a.proof,v)
  with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('job_token='+v['job_token']+'\nconsumer_token='+v['consumer_token']+'\n')
 elif a.phase=='cleanup':v=cleanup(source,a.base,a.runtime,C.read(a.proof),a.output)
 else:v=retain(source,a.base,a.runtime,a.proof,a.cleanup,a.output)
 print(json.dumps(v,sort_keys=True));raise SystemExit(v['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','PASS_NATIVE_ORPHANS3_PRIVATE_REMOVAL_AND_ORDERED_CLEANUP'))
