# SPDX-License-Identifier: MIT
"""Independent passive compiler-image predicates and exact ordered log joins."""
import hashlib,json,re
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock'];OUTER='perl5423-native-xs-v3'
PIN=dict(bytes=11025,sha256='fa613490865d94362d4d9efe6c5860904158c09733439a9f6c5709168f88d23c')
INVENTORY='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
def qualified(parent,derived,q,io):
 io.need(all(type(v)is str and re.fullmatch('sha256:[0-9a-f]{64}',v)for v in [parent['Id'],derived['Id'],q['layer'],*parent['RootFS']['Layers'],*derived['RootFS']['Layers']]),'literal immutable image/layer SHA256 identities')
 io.need(q['parent_image']==parent['Id']and q['image']==derived['Id']and parent['Id']!=derived['Id']and derived['Architecture']==parent['Architecture']=='arm64'and derived['Os']==parent['Os']=='linux'and not derived['Config'].get('Volumes'),'distinct actual ARM image with exact parent')
 io.need(derived['RepoTags']==[q['tag']]and derived['Config']['Labels']==q['labels'],'exact unique derived tag/labels')
 io.need(derived['RootFS']['Layers'][:-1]==parent['RootFS']['Layers']and len(derived['RootFS']['Layers'])==len(parent['RootFS']['Layers'])+1 and derived['RootFS']['Layers'][-1]==q['layer']and type(q['image_delta_bytes'])is int and q['image_delta_bytes']==derived['Size']-parent['Size']and 0<q['image_delta_bytes']<=8388608,'one exact positive <=8MiB layer')
 def configuration(c):
  result=dict(c);result.pop('Labels',None)
  for key in ['Entrypoint','Cmd']:
   if not result.get(key):result[key]=None
  return result
 io.need(configuration(parent['Config'])==configuration(derived['Config']),'parent defaults preserved except explicit owner labels/null-empty argv encoding');return derived

def confinement(row,name,parent,labels,source,b,cid,io):
 io.need(row['Id']==cid and re.fullmatch('[0-9a-f]{64}',cid)and row['Name']=='/'+name and row['Image']==parent and row['Config']['Labels']==labels and row['Config']['User']=='0:0'and row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',b['source']],'exact Source-bound copy actor ID/argv/user/image')
 mounts=row['Mounts'];io.need(len(mounts)==1 and mounts[0]['Type']=='bind'and mounts[0]['Source']==str(source)and mounts[0]['Destination']=='/tmp/source'and mounts[0]['RW']is False,'only readonly host Source mount')
 h=row['HostConfig'];io.need(h['ReadonlyRootfs']is False and h['NetworkMode']=='none'and h['CapDrop']==['ALL']and not h.get('CapAdd')and not h['Privileged']and not h.get('Devices')and not h.get('DeviceRequests')and h.get('PidMode','')==''and h.get('IpcMode','private')=='private'and h.get('UTSMode','')==''and h['Init']is False and h['SecurityOpt']==['no-new-privileges']and h['Memory']==h['MemorySwap']==536870912 and h['NanoCpus']==2000000000 and h['PidsLimit']==64 and h['Tmpfs']=={'/tmp':'rw,noexec,nosuid,nodev,size=8m'},'explicit Root-owned image writable domain/cap0/NNP2CPU512MiB0swap64PIDs; no host bypass')

def copy_receipt(value,descriptor,b,io):
 io.need(value['kind']=='XS_V3_SINGLE_LINK_COMPILER_COPY_V1'and value['status']=='COPIED_DATA_ONLY'and value['source']==b['source']and value['operation']==OUTER and value['manifest']==PIN and value['path']=='/usr/bin/cachy-asahi-xs-gcc'and value['inventory_sha256']==INVENTORY and value['count']==349 and type(value['compiler_invocations'])is int and value['compiler_invocations']==0 and value['network']=='NONE'and value['source_license_freshness_native_acceptance']is False and value['writable_domain']=='OWNED_CONTAINER_IMAGE_LAYER_ONLY_ROOT_UID0_CAP0','exact actual copy receipt, original349 inventory/no compiler or acceptance')
 driver=descriptor['payload'][descriptor['driver_source']];io.need(value['driver']==dict(bytes=driver['bytes'],sha256=driver['sha256'],mode=driver['mode'],nlink=1)and type(value['driver']['nlink'])is int,'exact unchanged single-link0755 native driver')
 expected=dict(descriptor['payload'])
 for archive in descriptor['archives'].values():
  for name,row in archive['license_payloads'].items():expected['/'+name]=dict(row,aliases=['/'+name])
 actual=value['original_payloads'];io.need(set(actual)==set(expected),'all exact original tool/helper/provider/notice observations')
 for name,row in expected.items():
  got=actual[name];io.need(set(got)=={'bytes','sha256','mode','nlink','device','inode','aliases'}and all(type(got[k])is int for k in ['bytes','mode','nlink','device','inode'])and got['device']>0 and got['inode']>0 and {k:got[k]for k in ['bytes','sha256','mode','aliases']}=={k:row[k]for k in ['bytes','sha256','mode','aliases']}and got['nlink']==len(row['aliases']),'actual original payload/alias identity: '+name)
 return value

def create(name,parent,labels,source,work,b):
 argv=DOCKER+['create','--name',name,'--pull=never','--user=0:0','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=512m','--memory-swap=512m','--pids-limit=64','--ulimit','core=0','--init=false','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=8m','--mount','type=bind,src='+str(source)+',dst=/tmp/source,readonly','--workdir=/tmp','--entrypoint=/usr/bin/python3','--cidfile',str(work/'compiler-image.cid')]
 for k,v in sorted(labels.items()):argv+=['--label',k+'='+v]
 return argv+[parent,'-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',b['source']]

def stage(get,root,b,h,parent,work,source,seq,io):
 raw=get('compiler-image-qualification.json');q=io.decode(raw);io.need(q==h['compiler_image']and q['kind']=='XS_V3_DERIVED_COMPILER_IMAGE_QUALIFICATION_V1'and q['status']=='QUALIFIED_COPY_ONLY_XS_NOT_RUN'and q['binding']==b and q['manifest']==PIN and q['parent_image']==parent and q['original_inventory']==349 and q['compiler_invocations']==0 and q['owned_sealing_container_absent']is True,'same Source/job actual separate compiler qualification')
 body=io.read(root,'accepted/compiler-inputs.json',io.MIB);io.need(io.pin(body)==PIN,'whole compiler descriptor');descriptor=io.decode(body)
 token=hashlib.sha256((b['source']+':'+b['run']+':compiler-v3').encode()).hexdigest()[:24];name='perl-xs-compiler-'+token;tag='perl-xs-compiler:'+token;query=DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+name+'$'];first=seq.index
 out,_=seq.take(query);io.need(not out.strip(),'empty exact compiler actor baseline');out,_=seq.take(DOCKER+['image','ls','--no-trunc','-q','--filter','reference='+tag]);io.need(not out.strip(),'empty exact derived image baseline')
 out,_=seq.take(DOCKER+['image','inspect',parent]);base=io.decode(out)[0];io.need(base['Id']==parent and base['Config']['User']=='alarm'and base['Config']['WorkingDir']=='/tmp'and not base['Config'].get('Entrypoint')and not base['Config'].get('Cmd'),'fixed parent defaults')
 parent_token=hashlib.sha256((b['source']+':'+b['ref']+':'+b['run']).encode()).hexdigest()[:24];io.need(base['RepoTags']==['perl-native-base:'+parent_token]and base['Config']['Labels'].get('cachy-asahi.hosted-perl')==parent_token and base['Config']['Labels'].get('cachy-asahi.hosted-perl.source')==b['source']and base['Architecture']=='arm64'and base['Os']=='linux'and not base['Config'].get('Volumes'),'actual owned signed349 parent inspection')
 labels=dict(base['Config']['Labels']);labels.update({'cachy-asahi.xs-compiler':token,'cachy-asahi.xs-compiler.source':b['source'],'cachy-asahi.xs-compiler.parent':parent});io.need(q['labels']==labels and q['tag']==tag,'owned derived labels/source/parent')
 out,_=seq.take(create(name,parent,labels,source,work,b));cid=out.decode().strip();io.need(re.fullmatch('[0-9a-f]{64}',cid)and cid==q['sealing_container_id'],'actual copy create/qualification ID')
 out,_=seq.take(DOCKER+['inspect',name]);before=io.decode(out)[0];confinement(before,name,parent,labels,source,b,cid,io);io.need(before['State']['Running']is False and before['State']['Pid']==0,'created copy actor not running')
 out,_=seq.take(DOCKER+['start','--attach',name]);receipt=copy_receipt(io.decode(out),descriptor,b,io);io.need(receipt==q['copy_receipt']and out==(json.dumps(receipt,sort_keys=True)+'\n').encode(),'raw actual sealed copy output joins qualification')
 out,_=seq.take(DOCKER+['inspect',name]);after=io.decode(out)[0];confinement(after,name,parent,labels,source,b,cid,io);io.need(after['State']['Running']is False and after['State']['Pid']==0 and after['State']['ExitCode']==0 and after['State']['OOMKilled']is False,'natural zero copy actor')
 out,_=seq.take(DOCKER+['diff',name]);diff=out.decode().splitlines();io.need(diff==q['filesystem_diff']and len(diff)==len(set(diff))and'A /usr/bin/cachy-asahi-xs-gcc'in diff and set(diff)<={'C /usr','C /usr/bin','A /usr/bin/cachy-asahi-xs-gcc'},'only one new driver and ancestor metadata, no other package/policy changes')
 out,_=seq.take(DOCKER+['commit','--pause=false','--change','USER alarm','--change','WORKDIR /tmp','--change','ENTRYPOINT []','--change','CMD []',name,tag]);io.need(out.decode().strip()==q['image'],'actual derived commit ID')
 out,_=seq.take(DOCKER+['image','inspect',q['image']]);derived=qualified(base,io.decode(out)[0],q,io);end_role=seq.index
 out,_=seq.take(query);io.need(out.decode().splitlines()==[name],'exact stopped copy actor to retire');out,_=seq.take(DOCKER+['inspect',name]);again=io.decode(out)[0];confinement(again,name,parent,labels,source,b,cid,io);io.need(again['State']['Running']is False and again['State']['Pid']==0,'same actor naturally stopped')
 seq.take(DOCKER+['rm',name]);out,_=seq.take(query);io.need(not out.strip(),'actual owned copy actor absent')
 cleanup=io.decode(get('compiler-image-cleanup.json'));io.need(cleanup==dict(errors=[],original_error=None,qualified=True),'actual independent clean sealing retirement')
 elapsed=lambda a,z:sum(r['lifecycle']['elapsed_seconds']for r in seq.rows[a:z]);io.need(elapsed(first,end_role)<=120 and elapsed(end_role,seq.index)<=60,'separate120s role/60s cleanup actor budgets')
 prep=io.decode(get('bundle/preparation.json'));io.need(prep['compiler_image']==dict(manifest=PIN,qualification=io.pin(raw),image=q['image']),'prepared compiler/image/whole qualifier join')
 return q,base,derived

def retire(seq,q,h,base,io):
 out,_=seq.take(DOCKER+['image','inspect',q['image']]);qualified(base,io.decode(out)[0],q,io)
 out,_=seq.take(DOCKER+['image','rm',q['image']]);io.need(('Deleted: '+q['image']).encode()in out.splitlines()and all(s.startswith((b'Deleted: ',b'Untagged: '))for s in out.splitlines()),'actual no-force derived image removal')
 out,err=seq.take(DOCKER+['image','inspect',q['image']],code=1,empty_error=False);io.need(not out.strip()or out.strip()==b'[]','no derived image inspect payload');io.need(err.decode().strip()=='Error response from daemon: No such image: '+q['image'],'exact derived image absence')
 io.need(h['cleanup']['compiler_image']==dict(image=q['image'],removed=True,absence_verified=True),'separate actual derived image retirement receipt')
