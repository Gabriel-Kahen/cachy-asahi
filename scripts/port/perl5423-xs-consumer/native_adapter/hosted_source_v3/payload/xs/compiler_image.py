#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""One future Root-admitted cap0 image seal; import and DATA controls run no role."""
import hashlib,json,os,re,stat,sys,time
from pathlib import Path
MANIFEST={'bytes':11025,'sha256':'fa613490865d94362d4d9efe6c5860904158c09733439a9f6c5709168f88d23c'}
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock'];OP='perl5423-native-xs-v3'
SOURCE=Path('/tmp/source');TARGET=Path('/usr/bin/cachy-asahi-xs-gcc')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(body):return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
def state(s):return tuple(getattr(s,n)for n in ['st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'])
def ordinary(path,cap=1024**2,links=1):
 path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary compiler DATA path')
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==links and 0<=before.st_size<=cap,'exact compiler DATA file/link/size bound')
  with os.fdopen(os.dup(fd),'rb')as f:body=f.read(cap+1)
  need(len(body)==before.st_size and state(before)==state(os.fstat(fd))==state(path.lstat()),'compiler DATA changed while reading');return body,before
 finally:os.close(fd)
def observation(manifest,root=Path('/')):
 result={};driver=None;expected=dict(manifest['payload'])
 for archive in manifest['archives'].values():
  for name,row in archive['license_payloads'].items():expected['/'+name]=dict(row,aliases=['/'+name])
 for name,row in expected.items():
  path=root/name.lstrip('/');body,before=ordinary(path,row['bytes'],len(row['aliases']))
  need(pin(body)=={k:row[k]for k in ['bytes','sha256']}and stat.S_IMODE(before.st_mode)==row['mode']and before.st_uid==before.st_gid==0,'actual signed-package tool body/mode/owner differs')
  for alias in row['aliases']:
   other=root/alias.lstrip('/');need(not other.is_symlink()and state(other.lstat())==state(before),'exact packaged hardlink alias identity required')
  result[name]=dict(**pin(body),mode=stat.S_IMODE(before.st_mode),nlink=before.st_nlink,device=before.st_dev,inode=before.st_ino,aliases=row['aliases'])
  if name==manifest['driver_source']:driver=body
 for name,target in manifest['symlinks'].items():
  path=root/name.lstrip('/');st=path.lstat();need(stat.S_ISLNK(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and os.readlink(path)==target,'original GCC symbolic alias differs')
 need(driver is not None,'one exact GCC driver body required');return result,driver

def inventory(root=Path('/')):
 rows={};base=root/'var/lib/pacman/local';dirs=[p for p in base.iterdir()if p.is_dir()];need(len(dirs)==349,'actual349 ALPM registrations required')
 for directory in dirs:
  raw,_=ordinary(directory/'desc');lines=raw.decode().splitlines();fields={}
  for key in ['NAME','VERSION']:
   marker='%'+key+'%';need(lines.count(marker)==1,'unique actual ALPM identity');i=lines.index(marker);need(i+2<len(lines)and lines[i+1]and lines[i+2]=='','single ALPM identity');fields[key]=lines[i+1]
  need(fields['NAME']not in rows,'unique ALPM package name');rows[fields['NAME']]=fields['VERSION']
 return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode()

def copy_driver(body,target,row):
 need(pin(body)=={k:row[k]for k in ['bytes','sha256']}and row['mode']==0o755,'only reviewed unchanged driver bytes/mode')
 need(not os.path.lexists(target),'fresh compiler driver destination')
 with target.open('xb')as out:out.write(body);os.fchmod(out.fileno(),row['mode']);out.flush();os.fsync(out.fileno())
 fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 copied,st=ordinary(target,16*1024**2);need(copied==body and stat.S_IMODE(st.st_mode)==row['mode'],'copied single-link driver bytes/mode differ');return copied,st

def actor(source):
 need(re.fullmatch('[0-9a-f]{40}',source)and __debug__ and sys.flags.isolated and sys.dont_write_bytecode,'actual Source-bound isolated copy stage')
 need(os.uname().machine=='aarch64'and os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'explicit Root-owned image writable domain only')
 status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
 need(all(int(status[k].strip(),16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])and status['NoNewPrivs'].strip()=='1','actual cap0/NNP copy stage')
 limits={n:Path('/sys/fs/cgroup',n).read_text().strip()for n in ['cpu.max','memory.max','memory.swap.max','pids.max']}
 need(limits=={'cpu.max':'200000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'},'actual2CPU512MiB64task copy bounds')
 need(sorted(p.name for p in Path('/sys/class/net').iterdir())==['lo'],'offline image seal')
 mounts={}
 for line in Path('/proc/self/mountinfo').read_text().splitlines():
  left,_,right=line.partition(' - ');a,b=left.split(),right.split()
  if a[4]in ['/','/tmp','/tmp/source']:need(a[4]not in mounts,'unique copy mount');mounts[a[4]]=(set(a[5].split(',')),b[0])
 need(set(mounts)=={'/','/tmp','/tmp/source'}and'rw'in mounts['/'][0]and mounts['/tmp'][1]=='tmpfs'and'ro'in mounts['/tmp/source'][0],'only owned image layer writable; readonly Source and excluded tmpfs')
 raw,_=ordinary(SOURCE/'accepted/compiler-inputs.json');need(pin(raw)==MANIFEST,'whole Root-reviewed compiler descriptor');m=json.loads(raw)
 expected,_=ordinary(SOURCE/'held/original/native/expected349.lock');before_inventory=inventory();need(before_inventory==expected,'exact prior signed349 inventory')
 before,body=observation(m);copied,st=copy_driver(body,TARGET,m['payload'][m['driver_source']]);after,_=observation(m)
 need(copied==body and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==m['payload'][m['driver_source']]['mode']and before==after and inventory()==before_inventory,'exact single-link driver copy, originals and inventory unchanged')
 print(json.dumps(dict(kind='XS_V3_SINGLE_LINK_COMPILER_COPY_V1',status='COPIED_DATA_ONLY',source=source,operation=OP,manifest=MANIFEST,path=str(TARGET),driver=dict(**pin(copied),mode=stat.S_IMODE(st.st_mode),nlink=st.st_nlink),original_payloads=before,inventory_sha256=hashlib.sha256(expected).hexdigest(),count=349,writable_domain='OWNED_CONTAINER_IMAGE_LAYER_ONLY_ROOT_UID0_CAP0',compiler_invocations=0,network='NONE',source_license_freshness_native_acceptance=False),sort_keys=True))

def create_argv(name,image,labels,source_root,source,cidfile=None):
 argv=DOCKER+['create','--name',name,'--pull=never','--user=0:0','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=512m','--memory-swap=512m','--pids-limit=64','--ulimit','core=0','--init=false','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=8m','--mount','type=bind,src='+str(source_root)+',dst=/tmp/source,readonly','--workdir=/tmp','--entrypoint=/usr/bin/python3']
 if cidfile is not None:argv+=['--cidfile',str(cidfile)]
 for k,v in sorted(labels.items()):argv+=['--label',k+'='+v]
 return argv+[image,'-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',source]

def confined(row,name,image,labels,source_root,source):
 need(row['Name']=='/'+name and row['Image']==image and row['Config']['Labels']==labels and row['Config']['User']=='0:0'and row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',source],'owned exact image-sealing container')
 mounts=row['Mounts'];need(len(mounts)==1 and mounts[0]['Type']=='bind'and mounts[0]['Source']==str(source_root)and mounts[0]['Destination']=='/tmp/source'and mounts[0]['RW']is False,'only readonly Source bind')
 h=row['HostConfig'];need(h['NetworkMode']=='none'and h['CapDrop']==['ALL']and not h['CapAdd']and not h['Privileged']and not h['ReadonlyRootfs']and not h['Devices']and not h.get('DeviceRequests')and h.get('PidMode','')==''and h.get('IpcMode','private')=='private'and h.get('UTSMode','')==''and h['Init']is False and h['SecurityOpt']==['no-new-privileges']and h['Memory']==h['MemorySwap']==512*1024**2 and h['NanoCpus']==2000000000 and h['PidsLimit']==64 and h['Tmpfs']=={'/tmp':'rw,noexec,nosuid,nodev,size=8m'},'explicit root-writable private image stage, cap0 bounds; no host/privilege fallback')

def image_qualified(parent,derived,labels,tag):
 need(derived['Id']!=parent['Id']and derived['Architecture']==parent['Architecture']=='arm64'and derived['Os']==parent['Os']=='linux'and derived['RepoTags']==[tag]and derived['Config']['Labels']==labels,'distinct exact owned compiler image')
 need(derived['RootFS']['Layers'][:-1]==parent['RootFS']['Layers']and len(derived['RootFS']['Layers'])==len(parent['RootFS']['Layers'])+1 and 0<derived['Size']-parent['Size']<=8*1024**2,'one bounded additional compiler layer')
 def normalized(config):
  d=dict(config);d.pop('Labels',None)
  for k in ['Entrypoint','Cmd']:
   if not d.get(k):d[k]=None
  return d
 need(normalized(parent['Config'])==normalized(derived['Config']),'original image configuration preserved except explicit ownership labels and null/empty command encoding')
 return dict(image=derived['Id'],tag=tag,parent_image=parent['Id'],labels=labels,layer=derived['RootFS']['Layers'][-1],image_delta_bytes=derived['Size']-parent['Size'])

def run(common,command,work,binding,parent_image,source_root):
 """Root future role. Reuses held Commands; no new process supervisor."""
 token=hashlib.sha256((binding['source']+':'+binding['run']+':compiler-v3').encode()).hexdigest()[:24];name='perl-xs-compiler-'+token;tag='perl-xs-compiler:'+token;own={'cachy-asahi.xs-compiler':token,'cachy-asahi.xs-compiler.source':binding['source'],'cachy-asahi.xs-compiler.parent':parent_image}
 deadline,cleaning=command.deadline,command.cleaning;command.deadline=time.monotonic()+120;result=None;labels=None;submitted=False;failure=None;container_id=None;cidfile=work/'compiler-image.cid'
 def call(argv,timeout=30):
  r=command(argv,timeout=timeout);need(r.returncode==0,'compiler image command refused: '+str(argv[:4]));return r.stdout
 def query():return call(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+name+'$']).decode().splitlines()
 def owned(row):
  nonlocal container_id
  confined(row,name,parent_image,labels,source_root,binding['source']);need(re.fullmatch('[0-9a-f]{64}',row['Id']),'exact compiler container ID')
  if cidfile.exists():
   recorded,_=ordinary(cidfile,128);need(recorded.decode().strip()==row['Id'],'compiler cidfile identity join')
  if container_id is None:container_id=row['Id']
  need(row['Id']==container_id,'held compiler container identity CAS')
 try:
  need(not os.path.lexists(cidfile),'fresh private compiler cidfile');need(query()==[],'fresh compiler container identity');need(not call(DOCKER+['image','ls','--no-trunc','-q','--filter','reference='+tag]).strip(),'fresh compiler image identity')
  parent=common.decode(call(DOCKER+['image','inspect',parent_image]))[0];need(parent['Id']==parent_image and parent['Config']['User']=='alarm'and parent['Config']['WorkingDir']=='/tmp'and not parent['Config'].get('Entrypoint')and not parent['Config'].get('Cmd')and not parent['Config'].get('Volumes'),'exact signed349 parent defaults')
  labels=dict(parent['Config'].get('Labels')or{});labels.update(own);submitted=True;call(create_argv(name,parent_image,labels,source_root,binding['source'],cidfile))
  row=common.decode(call(DOCKER+['inspect',name]))[0];owned(row)
  receipt=common.decode(call(DOCKER+['start','--attach',name],60));need(receipt['kind']=='XS_V3_SINGLE_LINK_COMPILER_COPY_V1'and receipt['status']=='COPIED_DATA_ONLY'and receipt['source']==binding['source']and receipt['operation']==OP and receipt['manifest']==MANIFEST and receipt['count']==349 and receipt['driver']['nlink']==1 and receipt['compiler_invocations']==0,'Source-bound exact compiler copy receipt')
  row=common.decode(call(DOCKER+['inspect',name]))[0];owned(row);need(row['State']['Running']is False and row['State']['Pid']==0 and row['State']['ExitCode']==0 and not row['State']['OOMKilled'],'natural compiler copy actor retirement')
  diff=call(DOCKER+['diff',name]).decode().splitlines();need('A /usr/bin/cachy-asahi-xs-gcc'in diff and set(diff)<={'C /usr','C /usr/bin','A /usr/bin/cachy-asahi-xs-gcc'},'only one compiler file plus ancestor metadata may change')
  argv=DOCKER+['commit','--pause=false','--change','USER alarm','--change','WORKDIR /tmp','--change','ENTRYPOINT []','--change','CMD []',name,tag];image=call(argv).decode().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',image),'actual committed compiler image ID')
  derived=common.decode(call(DOCKER+['image','inspect',image]))[0];result=image_qualified(parent,derived,labels,tag);result.update(kind='XS_V3_DERIVED_COMPILER_IMAGE_QUALIFICATION_V1',status='QUALIFIED_COPY_ONLY_XS_NOT_RUN',binding=binding,manifest=MANIFEST,copy_receipt=receipt,filesystem_diff=diff,compiler_invocations=0,original_inventory=349,sealing_container_id=container_id,Root_future_authority='SEPARATE_REVIEW_REQUIRED')
 except BaseException as error:
  failure=error;raise
 finally:
  command.deadline=time.monotonic()+60;command.cleaning=True;errors=[]
  try:
   if submitted and query():
    row=common.decode(call(DOCKER+['inspect',name]))[0];owned(row);
    if row['State']['Running']:
     errors.append('compiler actor required forced retirement; no qualification')
     call(DOCKER+['stop','--time=1',name],10)
     row=common.decode(call(DOCKER+['inspect',name]))[0];owned(row)
    need(not row['State']['Running']and row['State']['Pid']==0,'owned compiler actor did not retire')
    call(DOCKER+['rm',name]);need(query()==[],'owned compiler actor absent')
  except BaseException as error:errors.append('container cleanup: '+type(error).__name__+': '+str(error)[:512])
  try:
   if result is None or errors:
    ids=call(DOCKER+['image','ls','--no-trunc','-q','--filter','label=cachy-asahi.xs-compiler='+token]).decode().splitlines();need(len(ids)<=1,'unambiguous compiler image recovery')
    if ids:retire(common,command,dict(image=ids[0],tag=tag,labels=labels,parent_image=parent_image))
  except BaseException as error:errors.append('image cleanup: '+type(error).__name__+': '+str(error)[:512])
  finally:
   command.deadline=deadline;command.cleaning=cleaning
   (work/'compiler-image-cleanup.json').write_bytes(common.encode(dict(errors=errors,original_error=None if failure is None else {'category':type(failure).__name__,'message':str(failure)[:512]},qualified=result is not None and not errors)))
  if errors and failure is None:raise ValueError('compiler sealing cleanup failed: '+'; '.join(errors))
 need(result is not None,'compiler qualification required');result['owned_sealing_container_absent']=True
 (work/'compiler-image-qualification.json').write_bytes(common.encode(result));return result

def retire(common,command,receipt):
 image=receipt['image'];row=command(DOCKER+['image','inspect',image],timeout=20);need(row.returncode==0,'exact compiler image before retirement');v=common.decode(row.stdout)[0];need(v['Id']==image and v.get('RepoTags')==[receipt['tag']]and v['Config']['Labels']==receipt['labels'],'only exact derived image can retire')
 r=command(DOCKER+['image','rm',image],timeout=20);need(r.returncode==0,'derived image retirement');r=command(DOCKER+['image','inspect',image],timeout=20);need(r.returncode==1 and r.stderr.decode().strip()=='Error response from daemon: No such image: '+image,'exact derived image absence')
 return {'image':image,'removed':True,'absence_verified':True}

if __name__=='__main__':
 need(len(sys.argv)==3 and sys.argv[1]=='--copy-driver','fixed one-file image stage only');actor(sys.argv[2])
