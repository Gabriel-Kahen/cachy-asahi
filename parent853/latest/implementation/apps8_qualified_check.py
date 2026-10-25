# SPDX-License-Identifier: MIT
"""Pure DATA qualification; caller must first prove the whole new carrier Git/source."""
import argparse,hashlib,io,json,os,stat,zipfile
from pathlib import Path
OLD='979b2d6ec7417e607a911d8c25bef2f1f7f72dcb';OLD_TREE='58e4aea8af2b8af57b67ec34a19b41baed60b253';SOURCE='5c3c2d0ce5b4f6c2672c9367b722170687c7de69';REF='codex/apps8-current606-carrier-env-v1';RUN=39735431322
OLD_MAP={'bytes': 15477, 'sha256': 'b1151b68a6b15c94bd156a4c503e728f8a245570ce7a2c84bc213883a76477d1'}
QUALIFICATION={'Root-component-acceptance.json': {'bytes': 2602, 'sha256': '1c5606eba4d1c3fafbb959a8ef3ba6dac0132c2ef9780256f74a6622d3ceafe0'}, 'Root-passive-result.json': {'bytes': 110315, 'sha256': '92adcb002a2cf49d493ee207b9fcddfa65e3e998d6624ccb51c73678ed967816'}, 'Root-post-replay-pins.json': {'bytes': 383418, 'sha256': '2a3566c9ae65b391f4ff0a963db25afd418f4aff67e5e5a02a3b18626119b3c7'}, 'source/Root-committed-publication.json': {'bytes': 273, 'sha256': 'cf1c2b7a857928c24f3861b255caf207a5b1547b04bd883365c775be720adbf7'}, 'source/source-authorization.json': {'bytes': 65519, 'sha256': '3fe5cc563d0ca09c3cdfdac1739d490dd10f4a598d932c7ddc0910682c8c8c08'}, 'source/Root-git-source-authorization.json': {'bytes': 68733, 'sha256': 'ab600726474e24547b6a627661eef5f058e822be7d1399e832b835ffa2b7ca2a'}, 'originals/run.json': {'bytes': 13001, 'sha256': 'ff35965fef39d3f5a63607c7409ff6a6acfb05fee2ac7d3cf748b71d09ed94fa'}, 'originals/jobs.json': {'bytes': 15305, 'sha256': '3c4b5941915d73b98f133bd8ca3e5a670a556a839817cbd7c69e2b633a68cca4'}, 'originals/artifacts.json': {'bytes': 788, 'sha256': '7a106c3de4c4033f07cb6993063faf35bd919421c2a0ca829b9aba6412507530'}, 'originals/artifact.zip': {'bytes': 12732645, 'sha256': '6befe0b35fbfc3b72910f1e84bff4a03ad5359193c62ca44dcf56e7f51c1c5ff'}, 'originals/collection.json': {'bytes': 723, 'sha256': '6e792f1c0137ec83d45e5b2042ef76e54903cf2d8d524f2646105520cb2f4cef'}}
LINEAGE={'Root-committed-publication.json': {'bytes': 264, 'sha256': 'c4e3c454d9ef97e893624f03f03b82c9d622e6e385e2f6b1dfc1d2e6cb9c40f7'}, 'source-authorization.json': {'bytes': 15477, 'sha256': 'b1151b68a6b15c94bd156a4c503e728f8a245570ce7a2c84bc213883a76477d1'}, 'Root-git-source-authorization.json': {'bytes': 16388, 'sha256': '3d0de8329b7c1bc8637f3dbe3d7540343200f3b56f3a6b25ce4167c8597585b3'}, 'carrier-profile.json': {'bytes': 20798, 'sha256': '8158fa4b32e1f0fe1c45eda5c27d30e30012062df7f326ccc51ff564f8787aa9'}}
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
 path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary input ancestry');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'bounded singlelink public input');out=bytearray()
  while part:=os.read(fd,65536):out.extend(part);need(len(out)<=a.st_size,'input grew')
  key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns);need(key(a)==key(os.fstat(fd))==key(path.lstat())and len(out)==a.st_size,'whole stable public input');return bytes(out)
 finally:os.close(fd)
def files(root):
 root=Path(root).absolute();need(root.is_dir()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary explicit carrier');out={};total=0
 for base,ds,fs in os.walk(root):
  if Path(base)==root:ds[:]=[n for n in ds if n!='.git'];fs=[n for n in fs if n!='.git']
  for n in ds:need(not(Path(base)/n).is_symlink(),'directory alias')
  for n in fs:
   name=(Path(base)/n).relative_to(root).as_posix();raw=read(Path(base)/n);total+=len(raw);need(len(out)<128 and total<=32*1024**2,'finite public packet128/32MiB');out[name]=raw
 return out
def tree(bodies):
 root={}
 for name,raw in bodies.items():
  p=Path(name);need(name and p.as_posix()==name and not p.is_absolute()and not{'.','..','.git'}&set(p.parts),'canonical original Git tree path');node=root
  for part in p.parts[:-1]:node=node.setdefault(part,{})
  node[p.name]=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).digest()
 def walk(node):
  raw=b''
  for name,value in sorted(node.items(),key=lambda row:(row[0]+('/'if isinstance(row[1],dict)else'')).encode()):raw+=(b'40000'if isinstance(value,dict)else b'100644')+b' '+name.encode()+b'\0'+(walk(value)if isinstance(value,dict)else value)
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
 return walk(root).hex()
def admission(value,result,post):
 need(value['status']=='ROOT_ACCEPTED_FINITE_APPS8_CURRENT606_NATIVE_LIFECYCLE'and(value['source'],value['ref'],value['run'],value['attempt'])==(SOURCE,REF,RUN,1),'exact issued Root finite606 source/run admission')
 need(value['phases']==['baseline6','upgrade7','upgrade8','same-version8','remove8','reinstall8','restore7','restore-original6']and value['counts']==[606,606,606,606,605,606,606,606]and value['selected_versions']==['0.1.0-6','0.1.0-7','0.1.0-8','0.1.0-8',None,'0.1.0-8','0.1.0-7','0.1.0-6']and(value['transactions'],value['signed_installs'],value['installed_controls'])==(7,6,150)and value['ordinary_homes']==['fresh','existing'],'whole finite installed lifecycle shape')
 need((value['source_files'],value['reader_files'],value['public_files'],value['public_bytes'])==(380,1590,950,43567308)and value['Runtime1']=='PROTECTED_EXACT_NATIVE_PAIR_NO_TRANSACTION'and value['private_full_maps']=='NOT_EXPORTED_SOURCE_ENFORCED'and value['selected_inode_restoration']=='NOT_CLAIMED'and value['GUI']=='NOT_QUALIFIED'and value['hardware']=='NOT_RUN'and value['release']=='NOT_ADMITTED','preservation and finite acceptance limitations held')
 need(result['status']=='VERIFIED_APPS606_PROTOCOL_NOT_ROOT_ACCEPTANCE'and(result['source'],result['run_id'],result['source_files'],result['public_files'],result['public_bytes'])==(SOURCE,RUN,380,950,43567308),'matching complete passive result, no authority inferred from result alone')
 need(post['status']=='PASS_ALL380_SOURCE1590_READER_AND_ORIGINALS_AFTER_COMPLETE_POSITIVE'and len(post['source_files'])==380 and len(post['reader_files'])==1590 and post['originals']==value['originals'],'complete final source/reader/once-original pin maps');return True

def check(root):
 bodies=files(root);index=json.loads(bodies['index.json']);rows={n:pin(raw)for n,raw in bodies.items()if n!='index.json'};need(index['status']=='EXACT_ACCEPTED_APPS8_PAIR_AND_FINITE_CURRENT606_INPUT_DATA_ONLY'and index['files']==rows and len(bodies)==113 and index['actual_source']is index['actual_ref']is index['actual_run']is None and index['current_composition']=='NOT_QUALIFIED'and index['Root_acceptance']=='NOT_GRANTED'and index['external_whole_carrier_source_Git_proof']=='MANDATORY_BEFORE_CONSUMPTION','closed DATA-only packet and no new composition authority')
 old={n.removeprefix('apps8/'):raw for n,raw in bodies.items()if n.startswith('apps8/')};oldrows={n:pin(raw)for n,raw in old.items()};need(len(old)==93 and pin(enc(oldrows))==OLD_MAP and index['apps8']==dict(prefix='apps8',source=OLD,ref='codex/apps8-accepted-inputs-v1',tree=OLD_TREE,files=oldrows)and tree(old)==OLD_TREE,'entire old93 bytes and original100644 Git tree identity')
 original=json.loads(old['index.json']);need(original['files']=={n:w for n,w in oldrows.items()if n!='index.json'}and original['source']=='f1984a2481c541add7eb99b311a3ae3228307aa6'and original['run']==39727987029 and original['actual']is None,'old index/pair custody remains exact')
 qual={n.removeprefix('qualification/'):pin(raw)for n,raw in bodies.items()if n.startswith('qualification/')};lineage={n.removeprefix('lineage/apps8/'):pin(raw)for n,raw in bodies.items()if n.startswith('lineage/apps8/')};need(qual==QUALIFICATION==index['qualification']['files']and lineage==LINEAGE==index['lineage']['files']and index['qualification']==dict(prefix='qualification',source=SOURCE,ref=REF,run=RUN,files=qual),'complete fixed accepted606 and old93 provenance roles')
 for prefix,source,ref,wanted in(('lineage/apps8/',OLD,'codex/apps8-accepted-inputs-v1',oldrows),('qualification/source/',SOURCE,REF,None)):
  pub=json.loads(bodies[prefix+'Root-committed-publication.json']);auth=json.loads(bodies[prefix+'source-authorization.json']);git=json.loads(bodies[prefix+'Root-git-source-authorization.json']);need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=source,ref=ref,files=len(auth),git_joins=len(auth),actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and git==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=source,ref=ref,files=auth),'original Root publication/full source Git metadata')
  if wanted is not None:need(auth==wanted,'original Root93 subset map')
  else:source_rows=auth
 profile=json.loads(bodies['lineage/apps8/carrier-profile.json']);need(profile['source']==OLD and profile['files']==oldrows and profile['actual']is None,'held consumer original93 source profile')
 decision=json.loads(bodies['qualification/Root-component-acceptance.json']);result=json.loads(bodies['qualification/Root-passive-result.json']);post=json.loads(bodies['qualification/Root-post-replay-pins.json']);admission(decision,result,post);need(pin(bodies['qualification/Root-passive-result.json'])==decision['result']and pin(bodies['qualification/Root-post-replay-pins.json'])==decision['post_replay']and post['source_files']==source_rows,'whole issued decision/result/post/source380 hash joins')
 originals={n.removeprefix('originals/'):w for n,w in qual.items()if n.startswith('originals/')};need(set(originals)=={'run.json','jobs.json','artifacts.json','artifact.zip','collection.json'}and originals==decision['originals']==post['originals'],'all five exact once originals')
 run=json.loads(bodies['qualification/originals/run.json']);need(run['id']==RUN and run['run_attempt']==1 and run['head_sha']==SOURCE and run['head_branch']==REF and run['event']=='workflow_dispatch'and run['path']=='.github/workflows/native-arm-build.yml'and run['status']=='completed'and run['conclusion']=='success','matching genuine original completed workflow')
 collection=json.loads(bodies['qualification/originals/collection.json']);arts=json.loads(bodies['qualification/originals/artifacts.json']);matches=[r for r in arts['artifacts']if r['id']==collection['artifact_id']];need(len(matches)==1 and collection['source']==SOURCE and collection['run_id']==RUN and collection['attempt']==1 and collection['artifact']==originals['artifact.zip']and matches[0]['digest']=='sha256:'+originals['artifact.zip']['sha256']and matches[0]['size_in_bytes']==originals['artifact.zip']['bytes'],'artifact role/id/API digest/collection whole bytes')
 with zipfile.ZipFile(io.BytesIO(bodies['qualification/originals/artifact.zip']))as z:
  need(z.namelist()==['retention-step.txt','transport.json']and len(z.infolist())==2 and sum(r.file_size for r in z.infolist())<=16*1024**2 and z.testzip()is None,'fixed original two-member wrapper and every CRC')
  transport=json.loads(z.read('transport.json'));need(transport['status']=='COMPLETE_ORIGINAL_FRAMED_TRANSPORT_ONLY','original framed public transport DATA, no alternative positive parser')
 return dict(status='EXACT_PUBLIC_ACCEPTED_INPUTS_DATA_REQUIRES_EXTERNAL_SOURCE_GIT_PROOF',index=pin(bodies['index.json']),files=len(bodies),bytes=sum(map(len,bodies.values())),old93=dict(source=OLD,tree=OLD_TREE,files=93),qualification=dict(source=SOURCE,ref=REF,run=RUN,decision=qual['Root-component-acceptance.json'],source_files=380,reader_files=1590,public_files=950,public_bytes=43567308),current_composition='NOT_QUALIFIED',actual_authority=False,Root_acceptance='NOT_GRANTED',API='NOT_RUN',fresh_GPG='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--carrier',type=Path,required=True);a=p.parse_args();print(json.dumps(check(a.carrier.absolute()),sort_keys=True))
