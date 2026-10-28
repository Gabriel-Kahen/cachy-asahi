#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Two exact source copies and sealed ext4 media inside the original owned role."""
import base64,json,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def remaining(s,cap):
 value=min(cap,s['deadline_monotonic']-time.monotonic());C.need(value>0,'shared original3000 lifecycle deadline');return value

def phase_summary(data):
  # Data-only projection of existing records; never inspect a root again.
  stages=('source-revalidation','tree-and-aux-observation','tree-observe','complete-capability-map','capability-scan','copy-with-capability-restoration','copy-data','diagnostic-limit')
  events=('BEGIN','END','FAIL','FURTHER_PHASE_RECORDS_OMITTED')
  records=[];stats={};stack=[];first=None;previous=None
  try:
   for line in data.splitlines():
    if not line.startswith(b'APPS574_PHASE '):continue
    if len(line)>511 or len(records)>=96:raise ValueError('phase record bound')
    v=json.loads(line[len(b'APPS574_PHASE '):]);base={'schema_version','seq','stage','event','monotonic_ns'}
    if type(v)is not dict or set(v)not in (base,base|{'error_type','error_reason'}):raise ValueError('phase fields')
    if type(v['schema_version'])is not int or v['schema_version']!=1 or type(v['seq'])is not int or v['seq']!=len(records)+1 or type(v['monotonic_ns'])is not int or not 0<=v['monotonic_ns']<2**63:raise ValueError('phase scalar')
    stage=stages.index(v['stage']);event=events.index(v['event']);now=v['monotonic_ns']
    if previous is not None and now<previous:raise ValueError('phase clock order')
    if first is None:first=now
    if stage==7 or event==3:
     if (stage,event,v['seq'])!=(7,3,96):raise ValueError('phase limit marker')
    else:
     counts=stats.setdefault(stage,[0,0,0,0]);counts[event]+=1
     if event==0:stack.append((stage,now))
     else:
      if not stack or stack[-1][0]!=stage:raise ValueError('phase nesting')
      counts[3]+=now-stack.pop()[1]
    records.append([v['seq'],stage,event,now-first]);previous=now
   if not records:return None
   return dict(version=1,records=len(records),first_ns=first,stages=[[s,*counts]for s,counts in sorted(stats.items())],last=records[-2:])
  except (ValueError,TypeError,KeyError,IndexError):return dict(version=1,status='INVALID_PHASE_RECORDS')

def command(s,argv,cap=600):
 runtime=C.load('disk_runtime','/source/scripts/ci/glibc-owned-runtime/runner.py');record,out,err,error=runtime.run_command(list(map(str,argv)),Path('/work'),dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',HOME='/tmp',TMPDIR='/tmp',CACHY_ASAHI_APPS_TRANSACTION=s['env']['OWNER_TOKEN']),remaining(s,cap),1024**2)
 summary=phase_summary(err)
 path=Path('/out/repair16k-media-commands.json');rows=C.decode(C.read(path,2*1024**2)) if path.exists() else [];C.need(len(rows)<192,'finite media command count');rows.append(dict(record=record,error=None if error is None else str(error)[:1024],previews={side:dict(base64=base64.b64encode(raw[:1024]).decode(),truncated=len(raw)>1024,original_bytes=len(raw),original_sha256=C.sha(raw)) for side,raw in (('stdout',out),('stderr',err))},**({} if summary is None else {'phase_summary':summary})));C.need(len(C.encoded(rows))<=2*1024**2,'bounded media diagnostics');C.save(path,rows);os.chown(path,s['uid'],s['gid'])
 C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'bounded owned media command/group retirement: '+str(argv[0]));return record,out,err

def caller_seconds(s):
 name='scripts/apps/full574_closure.py';path=Path('/source')/name
 C.need(C.row(path)==s['source_files'][name],'exact trusted native media policy helper')
 policy=C.load('native_media_policy',path)
 args=SimpleNamespace(full574_policy=Path('/inputs/full574-policy.json'),full574_policy_sha256=s['input_map']['full574-policy.json']['sha256'],full574_lease=Path('/inputs/full574-lease.json'),full574_lease_sha256=s['input_map']['full574-lease.json']['sha256'])
 backend=SimpleNamespace(B=SimpleNamespace(client=SimpleNamespace(read_path=C.read)))
 selected,_=policy.policy_pair(args,backend)
 C.need(selected['execution_budget']==dict(backend_seconds=600,caller_seconds=610),'original authenticated native media execution budget')
 return selected['execution_budget']['caller_seconds']

def backend(s,mode,work,owner=None):
 seconds=caller_seconds(s) if mode=='prepare-copy' else 75
 args=['/usr/bin/python3','-I','-B','/source/scripts/apps/transaction.py',mode,'--workspace',str(work),'--apps-source','/inputs/apps-source','--apps-provenance-sha256',C.sha(C.read('/inputs/apps-source/source-provenance.json')),'--repository-source','/inputs/candidate/usr/share/cachy-asahi/repository-runtime','--full574-policy','/inputs/full574-policy.json','--full574-policy-sha256',C.row('/inputs/full574-policy.json')['sha256'],'--full574-lease','/inputs/full574-lease.json','--full574-lease-sha256',C.row('/inputs/full574-lease.json')['sha256']]
 args+=['--source','/seed'] if mode=='prepare-copy' else ['--ownership-sha256',owner]
 return C.decode(command(s,args,seconds)[1])

def stage_guard(s,stage,proof=None,roots=()):
 work=Path('/work');C.need(stage==work/'repair16k-stage' and not stage.is_symlink(),'fixed private work staging path')
 source=Path('/source/scripts/update/full_root.py');C.need(C.row(source)==s['source_files']['scripts/update/full_root.py'],'pinned original descriptor/mount primitives')
 namespace=dict(Path=Path,os=os,need=C.need);open_root=C.function(source,'_open_root',namespace);mount_id=C.function(source,'_mount_id',namespace)
 class Limit:
  def tick(self):remaining(s,3000)
 limit=Limit();fds=[]
 try:
  for p in (work,stage,*roots):
   C.need(p==work or p.is_relative_to(work),'fixed owned work mount only');fds.append(open_root(p))
  infos=[os.fstat(fd) for fd in fds];mounts=[mount_id(fd,limit) for fd in fds]
  C.need(all(stat.S_ISDIR(v.st_mode) for v in infos) and all(v.st_dev==infos[0].st_dev for v in infos) and len(set(mounts))==1,'same actual work filesystem and mount for atomic rename')
  C.need(all(v.st_uid==v.st_gid==0 and stat.S_IMODE(v.st_mode)==0o700 for v in infos[:2]),'root-owned private work/staging directories')
  named=os.stat(stage.name,dir_fd=fds[0],follow_symlinks=False);C.need((named.st_dev,named.st_ino)==(infos[1].st_dev,infos[1].st_ino),'named/held staging inode equality')
  with Path('/proc/self/mountinfo').open('rb') as stream:raw=stream.read(1024**2+1)
  C.need(len(raw)<=1024**2,'bounded mount-table identity');rows=[line.split() for line in raw.splitlines()];C.need(rows and all(len(v)>=10 and v[0].isdigit() and b'-' in v for v in rows),'complete mount-table shape')
  targets=[os.fsencode(str(p)) for p in (stage,*roots)]
  C.need(not any(v[4]==p or v[4].startswith(p+b'/') for v in rows for p in targets),'nested work staging/root mounts refused')
  current=dict(path=str(stage),inode=[infos[1].st_dev,infos[1].st_ino],work_inode=[infos[0].st_dev,infos[0].st_ino],mount_id=mounts[0])
  C.need(proof is None or current==proof,'original work/staging identity drift');return current
 finally:
  for fd in reversed(fds):os.close(fd)

def prepare(s):
 media=Path('/media');C.need(media.is_mount() and not any(media.iterdir()) and [media.stat().st_dev,media.stat().st_ino]==s['media_identity'] and shutil.disk_usage(media).free>=48*1024**3,'fresh exact48GiB owned media mount');stage=Path('/work/repair16k-stage');C.need(not stage.exists() and not stage.is_symlink(),'fresh fixed work staging directory');stage.mkdir(mode=0o700);stage_info=stage_guard(s,stage);C.save(media/'stage-owner.json',dict(nonce=s['nonce'],**stage_info,retired=False));copies=[];moved=[]
 try:
  for name in ('main','interrupted'):
   workspace=Path('/work')/name;value=backend(s,'prepare-copy',workspace);C.need(value['status']=='OWNED_COPY_PREPARED' and value['source_preserved'] is True,'original complete capability-preserving source copy');copies.append((workspace,value['ownership_sha256']))
  boot=stage/'boot';data=stage/'data';data.mkdir();seed=data/'seed'
  for original,target in ((Path('/work/main/root'),boot),(Path('/work/interrupted/root'),seed)):
   C.need(not target.exists() and original.is_dir() and not original.is_mount(),'fresh own staging root');stage_guard(s,stage,stage_info,(original,));identity=[original.stat().st_dev,original.stat().st_ino];original.rename(target);moved.append((original,target,identity))
  # Only fixed owned data roles. The readonly original source is not decorated.
  for name in ('inputs','source','execution','workspace'):
   origin=Path('/'+name);target=data/name;C.need(origin.is_dir() and not target.exists(),'fixed data role source')
   if name=='source':
    target.mkdir();dirs={Path('.')}
    for relative,pin in s['source_files'].items():
     C.relative(relative);p=origin/relative;C.need(C.row(p)==pin,'closed original source bytes');q=target/relative;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q);info=p.stat();os.chown(q,info.st_uid,info.st_gid);dirs.update(Path(relative).parents)
    for relative in sorted(dirs,key=lambda p:len(p.parts),reverse=True):
     info=(origin/relative).stat();q=target/relative;q.chmod(stat.S_IMODE(info.st_mode));os.chown(q,info.st_uid,info.st_gid)
   else:command(s,['/usr/bin/cp','-a','--reflink=never','--',origin,target],600)
  for name in ('work','out'): (data/name).mkdir(mode=0o700)
  for name in ('seed','inputs','source','execution','workspace','work','out'):
   target=boot/name;C.need(not target.is_symlink() and (not target.exists() or target.is_dir() and not list(target.iterdir())),'VM role placeholder must be absent or original empty directory: '+name)
   if not target.exists():target.mkdir(mode=0o755)
  C.need(not (boot/'init-repair16k').exists() and not (boot/'volume').exists(),'fresh reserved init/media paths')
  init=['#!/usr/bin/bash','set -euo pipefail','export PATH=/usr/bin:/bin LC_ALL=C LANG=C','mount -t proc -o ro,nosuid,nodev,noexec proc /proc','mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys','mount -t devtmpfs -o nosuid devtmpfs /dev','mount -t tmpfs -o nosuid,nodev,size=1g,mode=1777 tmpfs /tmp','mount -t tmpfs -o nosuid,nodev,size=64m,mode=755 tmpfs /run','mkdir /volume','mount -t ext4 -o rw,nosuid,nodev /dev/vdb /volume']
  for name in ('seed','inputs','source','execution','workspace','work','out'):
   init+=['mount --bind /volume/'+name+' /'+name]
   if name not in ('work','out','inputs'):init+=['mount -o remount,bind,ro /'+name]
  init+=['umount /volume','rmdir /volume','umount /dev','mount -t tmpfs -o nosuid,size=1m,mode=755 tmpfs /dev','mknod -m 666 /dev/null c 1 3','mknod -m 666 /dev/zero c 1 5','mknod -m 666 /dev/random c 1 8','mknod -m 666 /dev/urandom c 1 9','rm /init-repair16k','exec /usr/bin/python3 -I -B /workspace/guest.py'];(boot/'init-repair16k').write_text('\n'.join(init)+'\n');(boot/'init-repair16k').chmod(0o755)
  audit=C.load('boot_elf','/source/scripts/ci/managed-gui-generic16k/elf_audit.py');reader=C.load('boot_reader','/source/scripts/virtual/generic16k/fixture.py');elf=audit.audit(boot,reader);C.need(elf['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT','complete sealed boot ELF alignment');C.save(data/'workspace/boot-elf.json',elf)
  for name,size in (('boot',16*1024**3),('data',24*1024**3)):
   image=media/(name+'.raw');tree=stage/name;allocated=sum(p.lstat().st_blocks*512 for p in tree.rglob('*'));C.need(allocated<=10*1024**3 and shutil.disk_usage(media).free>=allocated+8*1024**3,'finite private media allocation')
   with image.open('xb') as f:f.truncate(size)
   command(s,['/usr/bin/mkfs.ext4','-F','-b','4096','-m','0','-L','APPS574_'+name.upper(),'-d',tree,image],600)
  C.save(media/'prepared.json',dict(status='PREPARED_NOT_EXECUTED',nonce=s['nonce'],case=s['case'],copies=[dict(workspace=str(w),ownership_sha256=o) for w,o in copies],boot=C.row(media/'boot.raw'),data=C.row(media/'data.raw'),boot_ELF_sha256=C.sha(C.encoded(elf))))
 finally:
  # Rejoin actual held copy identities before invoking the original disposer.
  for original,target,identity in reversed(moved):
   C.need(not original.exists() and target.is_dir() and [target.stat().st_dev,target.stat().st_ino]==identity,'owned staging relocation identity');stage_guard(s,stage,stage_info,(target,));target.rename(original)
  for workspace,owner in reversed(copies):
   value=backend(s,'dispose-copy',workspace,owner);C.need(value['status']=='OWNED_COPY_DISPOSED' and not workspace.exists(),'original prepare-copy retirement')
  stage_guard(s,stage,stage_info);shutil.rmtree(stage);C.need(not stage.exists() and not stage.is_symlink(),'fixed work staging absence after restoration/disposal')
 prepared=C.decode(C.read(media/'prepared.json'));prepared['staging']=dict(stage_info,retired=True);C.save(media/'prepared.json',prepared);C.save(media/'stage-owner.json',dict(nonce=s['nonce'],**stage_info,retired=True))
 for p in media.iterdir():os.chown(p,s['uid'],s['gid'])

def readback(s):
 media=Path('/media');files=s['guest_files'];C.need(type(files)is dict and 1<=len(files)<=160 and sum(v['bytes'] for v in files.values())<=192*1024**2,'finite nonce-bound guest outputs')
 for name,pin in files.items():
  C.need(C.relative(name)==name and re.fullmatch('[A-Za-z0-9_.-]{1,128}',name) and type(pin['bytes'])is int and 0<=pin['bytes']<=16*1024**2,'ordinary direct readback name/size');target=Path('/out')/name;C.need(name!='repair16k-media-commands.json' and not target.exists() and not target.is_symlink(),'fresh actual readback output')
  command(s,['/usr/bin/debugfs','-R','dump /out/'+name+' '+str(target),media/'data.raw'],120);C.need(C.row(target)==pin,'exact original guest readback bytes');os.chown(target,s['uid'],s['gid'])

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_LIFECYCLE')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'original owned offline native preparation/readback actor only');s=C.decode(C.read('/workspace/selection.json'));C.need(s['case'] in C.CASES and os.environ['CACHY_APPS574_REPAIR_CASE']==s['case'],'exact inherited single case')
 C.need(s['phase'] in ('prepare','readback'),'finite lifecycle media phase')
 os.chown('/work',0,0);Path('/work').chmod(0o700)
 return prepare(s) if s['phase']=='prepare' else readback(s)
if __name__=='__main__':main()
