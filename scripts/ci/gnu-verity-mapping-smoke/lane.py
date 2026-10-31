#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Standalone owned read-only-drive mapping smoke. No host kernel/DM IO."""
import argparse,json,os,platform,re,secrets,shutil,signal,stat,time
from pathlib import Path
import contract as C,fixture as F,protocol as P,supervise as S,layout as V
ENV={'PATH':'/usr/lib/llvm-18/bin:/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC'}
FLAGS=['--target=aarch64-linux-gnu','-std=c11','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-mgeneral-regs-only','-nostdlib','-nostdinc','-static','-Werror','-Wall','-Wextra','--ld-path=/usr/lib/llvm-18/bin/ld.lld','-Wl,-e,_start','-Wl,--build-id=none','-Wl,-z,noexecstack','-Wl,-z,max-page-size=16384']

def qemu(work):
 args=['/usr/bin/qemu-system-aarch64','-no-user-config','-nodefaults','-machine','virt,gic-version=3','-accel','tcg','-cpu','max','-m','64M','-smp','1','-display','none','-monitor','none','-serial','stdio','-net','none','-no-reboot','-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny','-kernel',str(work/'Image'),'-initrd',str(work/'initramfs.cpio'),'-append','console=ttyAMA0 rdinit=/init panic=-1 oops=panic']

 for role,name in(('good','data.raw'),('hash','hash.raw'),('bad','corrupt.raw')):
  args+=['-blockdev',json.dumps(dict(driver='file',filename=str(work/name),**{'node-name':role+'-file','read-only':True}),sort_keys=True,separators=(',',':')),'-blockdev',json.dumps(dict(driver='raw',file=role+'-file',**{'node-name':role,'read-only':True}),sort_keys=True,separators=(',',':')),'-device','virtio-blk-device,drive='+role+',serial=gnu-verity-'+role]
 return args

def identity(path):
 p=Path(path);s=p.lstat();C.need(not any(q.is_symlink()for q in(p,*p.parents))and stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'owned ordinary0700 directory');return [s.st_dev,s.st_ino,s.st_uid]
def fresh(path):
 C.need(path.is_absolute()and not path.exists()and path.parent.is_dir()and not any(q.is_symlink()for q in(path,*path.parents)),'fresh ordinary owned directory');path.mkdir(mode=0o700);return identity(path)
def remove(work,owner):
 C.need(identity(work)==owner and {p.name for p in work.iterdir()}<={'owner.json','Image','init.elf','initramfs.cpio','kernel-replay','data.raw','hash.raw','corrupt.raw'},'known owned work identity/top-level contents');total=0
 for p in work.rglob('*'):
  s=p.lstat();C.need(not p.is_symlink()and s.st_dev==owner[0]and s.st_uid==owner[2]and(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)and s.st_nlink==1),'owned same-device ordinary work only')
  if p.is_file():total+=s.st_size;C.need(total<=128*1024**2,'bounded owned work')
 shutil.rmtree(work);C.need(not work.exists(),'owned work remains');return dict(status='PASS_OWNED_MAPPING_SMOKE_WORK_REMOVED',identity=owner,absence_verified=True,order='AFTER_ALL_NATIVE_CHILD_GROUP_ABSENCE',live_reobservation='SOURCE_ENFORCED_AT_ORIGINAL_RUN_ONLY')

def remove_input(originals,acquisition):
 root=originals.parent;owner=acquisition['owner'];C.need(acquisition['root']==str(root)and identity(root)==owner,'owned acquired input identity')
 record=C.obj(C.read(root/'owner.json'));C.need(record==dict(identity=owner,descriptor=C.pin(C.read(C.HERE/'kernel-descriptor.json')),mode='ROOT_HISTORICAL_SMALL_DATA_PLUS_IDENTICAL_FIXED_ARTIFACT_TRANSFER'),'input acquisition owner/descriptor')
 names={'owner.json','current-run.json','current-run.json.stderr','current-run.json.request.json','current-artifacts.json','current-artifacts.json.stderr','current-artifacts.json.request.json','artifact-transfer.zip.stderr','artifact-transfer.zip.request.json','originals','strict-input-replay','input-replay.json','input-acquisition.json'}
 C.need({q.name for q in root.iterdir()}==names,'closed owned input-acquisition work');total=0
 for q in root.rglob('*'):
  st=q.lstat();C.need(not q.is_symlink()and st.st_dev==owner[0]and st.st_uid==owner[2]and(stat.S_ISDIR(st.st_mode)or stat.S_ISREG(st.st_mode)and st.st_nlink==1),'same-device ordinary owned input only')
  if q.is_file():total+=st.st_size;C.need(total<=64*1024**2,'bounded owned input work')
 shutil.rmtree(root);C.need(not root.exists(),'input work remains');return dict(status='PASS_OWNED_KERNEL_INPUT_WORK_REMOVED',identity=owner,absence_verified=True,order='AFTER_ALL_NATIVE_CHILD_GROUP_ABSENCE_AND_PUBLIC_ORIGINAL_RETENTION',live_reobservation='SOURCE_ENFORCED_AT_ORIGINAL_RUN_ONLY')

def source_proof(root):
 fact=C.source(root);e=os.environ;source=e.get('SOURCE_SHA');run=e.get('GITHUB_RUN_ID');ref=e.get('GITHUB_REF_NAME');C.need(re.fullmatch('[0-9a-f]{40}',source or'')and source==e.get('GITHUB_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run or'')and e.get('GITHUB_RUN_ATTEMPT')=='1'and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and e.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and e.get('GITHUB_WORKFLOW')=='native-arm-gnu-verity-mapping-smoke-only'and re.fullmatch('codex/[a-z0-9-]+',ref or''),'genuine first-attempt boot source/workflow environment')
 return dict(status='GENUINE_SOURCE_PROOF_MAPPING_SMOKE_SCOPE_ONLY',source=source,ref=ref,run_id=run,attempt=1,manifest=fact['manifest'],scope=P.SCOPE)

def _probe(root,originals,work,out):
 # NULL/foreign kernel authority must refuse before native checks, mkdir or actors.
 fact=C.source(root);policy,d,decision,build_result=C.bound();proof=source_proof(root)
 acquisition=C.obj(C.read(originals.parent/'input-acquisition.json'));C.need(acquisition.get('status')=='ACQUIRED_EXACT_ROOT_ACCEPTED_KERNEL_INPUT_ONLY'and acquisition.get('descriptor')==C.pin(C.read(C.HERE/'kernel-descriptor.json'))and acquisition.get('root')==str(originals.parent)and acquisition.get('owner')==identity(originals.parent),'explicit fresh input transfer ownership before actors')
 C.need(platform.system()=='Linux'and platform.machine()=='aarch64'and os.getuid()==os.geteuid()>0,'ordinary native aarch64 host only');release=dict(line.split('=',1)for line in Path('/etc/os-release').read_text().splitlines()if'='in line);C.need(release.get('ID')=='ubuntu'and release.get('VERSION_ID','').strip('"')=='24.04','pinned Ubuntu24.04-arm host')
 C.need(work.parent==out.parent and work!=out and not any(p.is_relative_to(root)or root.is_relative_to(p)or p.is_relative_to(originals)or originals.is_relative_to(p)for p in(work,out)),'disjoint runner-owned work/export and kernel inputs')
 tool_rows={}
 for kind in('compiler','linker'):
  row=policy[kind];raw=C.read(Path(row['path']),64*1024**2);C.need(C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'exact pinned Ubuntu ARM '+kind);tool_rows[kind]=row
 C.need(Path(policy['linker']['invocation']).resolve(strict=True)==Path(policy['linker']['path']),'fixed GNU lld invocation resolves to whole pinned real linker')
 raw=C.read(Path(policy['qemu']['path']),64*1024**2);tool_rows['qemu']=dict(path=policy['qemu']['path'],**C.pin(raw),package=policy['qemu']['package'],package_version=policy['qemu']['package_version'])
 owner=fresh(work);fresh(out);nonce=secrets.token_hex(16);started=time.monotonic();deadline=started+240;retired=True;commands=[];files={};total=0
 def emit(name,raw):
  nonlocal total
  C.need(type(name)is str and re.fullmatch('[A-Za-z0-9_./-]+',name)and all(x not in('','.','..')for x in name.split('/'))and name not in files,'closed ordinary boot output name');total+=len(raw);C.need(total<=64*1024**2,'complete64MiB output cap');p=out/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);files[name]=C.pin(raw)
 def call(label,argv,limit,cap):
  nonlocal retired
  remaining=deadline-time.monotonic();C.need(remaining>0,'shared240s owned-host actor envelope');retired=False;row,stdout,stderr,error=S.run(argv,work,dict(ENV,HOME=str(work),TMPDIR=str(work)),min(limit,remaining),cap);retired=row['group_absence_verified'];commands.append(dict(label=label,**row));emit(label+'.stdout',stdout);emit(label+'.stderr',stderr);C.need(error is None and row['exit_code']==0 and row['natural_exit']and row['termination']=='NONE'and retired,'natural successful owned child and group absence');return stdout
 (work/'owner.json').write_bytes(C.encoded(dict(source=proof,nonce=nonce,identity=owner)))
 try:
  emit('source-proof.json',C.encoded(proof));emit('source-manifest.json',C.read(root/C.LANE/'source-manifest.json'));emit('kernel-descriptor.json',C.read(C.HERE/'kernel-descriptor.json'));emit('Root-build-decision.json',C.read(C.HERE/'Root-build-decision.json'));emit('kernel-build-result.json',C.read(C.HERE/'kernel-build-result.json',2*1024**2))
  for name in('current-run.json','current-artifacts.json','input-acquisition.json'):emit('kernel-current/'+name,C.read(originals.parent/name,2*1024**2))
  kernel_files,replayed=C.input_replay(originals,d,work/'kernel-replay');(work/'Image').write_bytes(kernel_files['Image']);emit('kernel-input-replay.json',C.encoded(replayed))
  for name in('artifact.zip','logs.zip','run.json','artifacts.json','collection-outcome.json','bound-original.json'):emit('kernel-originals/'+name,C.read(originals/name,32*1024**2 if name=='artifact.zip'else 8*1024**2 if name=='logs.zip'else 2*1024**2))
  fixture_inputs={n:C.pin(b)for n,b in V.assets().items()};layout_fact=dict(schema_version=1,format=1,data_block_bytes=4096,hash_block_bytes=4096,data_blocks=2,hash_start=0,algorithm='sha256',root_digest=V.ROOT,salt=V.SALT.hex(),corrupt_offset=V.CORRUPT_OFFSET,files=fixture_inputs)
  for name,body in V.assets().items():(work/name).write_bytes(body);emit(name,body)
  emit('layout-manifest.json',C.encoded(layout_fact));emit('Root-boot-basis-decision.json',C.read(C.HERE/'Root-boot-basis-decision.json'));emit('boot-basis-source-authorization.json',C.read(C.HERE/'boot-basis-source-authorization.json',2*1024**2))
  C.need(call('qemu-package',['/usr/bin/dpkg-query','-W','-f=${Version}',policy['qemu']['package']],5,65536).decode()==policy['qemu']['package_version'],'source-pinned QEMU package version')
  C.need(call('qemu-version',[policy['qemu']['path'],'--version'],5,65536).decode().splitlines()[0]==policy['qemu']['version_line'],'source-pinned QEMU version line')
  argv=[policy['compiler']['path'],*FLAGS,str(root/C.LANE/'init.c'),'-o',str(work/'init.elf')];call('compile',argv,30,1024**2)
  init=C.read(work/'init.elf',512*1024);elf=F.elf(init);image=F.cpio(init,nonce);(work/'initramfs.cpio').write_bytes(image);emit('init.elf',init);emit('initramfs.cpio',image);emit('init-build.json',C.encoded(dict(status='NATIVE_AARCH64_FREESTANDING_STATIC_PID1_BUILD',source=C.pin(C.read(root/C.LANE/'init.c')),uapi=C.pin(C.read(root/C.LANE/'probe-uapi.h')),fixture_header=C.pin(C.read(root/C.LANE/'fixture-data.h')),layout_source=C.pin(C.read(root/C.LANE/'layout.py')),ELF=elf,initramfs=C.pin(image),nonce=nonce,tools=tool_rows,host=dict(system=platform.system(),machine=platform.machine(),uid=os.getuid(),Ubuntu='24.04'))))
  stdout=call('qemu',qemu(work),240,4*1024**2);guest=P.uart(stdout,nonce)
  for kind in('compiler','linker','qemu'):
   row=tool_rows[kind];C.need(C.pin(C.read(Path(row['path']),64*1024**2))=={k:row[k]for k in('bytes','sha256')},'same native tool bytes after all actors')
  C.need(Path(policy['linker']['invocation']).resolve(strict=True)==Path(policy['linker']['path']),'same pinned GNU linker invocation after actors')
  C.source(root)
  for name,expected in(('Image',d['Image']),('init.elf',C.pin(init)),('initramfs.cpio',C.pin(image)),*fixture_inputs.items()):C.need(C.pin(C.read(work/name,16*1024**2))==expected,'same source-bound VM inputs after actors')
  C.need(time.monotonic()-started<=246 and retired,'shared actor deadline and all groups retired');cleanup=remove(work,owner);input_cleanup=remove_input(originals,acquisition)
  report=dict(status='PASS_STANDALONE_GNU_VERITY_MAPPING_INTEGRITY_SMOKE_ONLY',source=proof,nonce=nonce,source_root=str(root),work_root=str(work),work_owner=owner,kernel_descriptor=C.pin(C.read(C.HERE/'kernel-descriptor.json')),kernel_input=dict(source=d['source'],ref=d['ref'],run_id=d['run_id'],artifact=d['artifact'],Image=d['Image'],config=d['config']),commands=commands,guest=guest,fixture_inputs=fixture_inputs,cleanup=cleanup,input_cleanup=input_cleanup,shared_seconds=240,seconds=round(time.monotonic()-started,6),scope=P.SCOPE,verity_mapping='TWO_READONLY_NONCE_OWNED_MAPPINGS_EXERCISED_AND_REMOVED',integrity='EXPECTED_DATA_VERIFIED_AND_CORRUPT_COPY_REJECTED_EIO',lifecycle='NOT_TESTED',hardware='NOT_RUN',performance='NOT_MEASURED',Root_acceptance='NOT_ISSUED')
  emit('result.json',C.encoded(report));emit('retention.json',C.encoded(dict(status='RETAINED_ORIGINAL_MAPPING_SMOKE_ONLY_NOT_ROOT_ACCEPTANCE',files=dict(files),bytes=sum(v['bytes']for v in files.values()),scope=P.SCOPE)));return report
 except BaseException as e:
  cleanup=dict(status='UNKNOWN_WORK_RETAINED',reason='GROUP_OR_CONTENT_CUSTODY_NOT_PROVED')
  if retired:
   try:cleanup=remove(work,owner)
   except Exception:pass
  # Failure facts never become the positive result or conceal unknown work.
  failure=dict(status='FAIL_MAPPING_SMOKE_NO_AUTHORITY',error_type=type(e).__name__,error=str(e)[:512],source=proof,nonce=nonce,commands=commands,cleanup=cleanup,scope=P.SCOPE,Root_acceptance='NOT_ISSUED')
  try:emit('failure.json',C.encoded(failure));emit('retention.json',C.encoded(dict(status='FAILED_ORIGINAL_MAPPING_SMOKE_DATA_ONLY',files=dict(files),bytes=sum(v['bytes']for v in files.values()),scope=P.SCOPE)))
  except Exception:pass
  raise
def probe(root,originals,work,out):
 def interrupted(sig,frame):raise InterruptedError('outer owned actor interruption '+str(sig))
 saved={s:signal.signal(s,interrupted)for s in(signal.SIGINT,signal.SIGTERM)}
 try:return _probe(root,originals,work,out)
 finally:
  for sig,handler in saved.items():signal.signal(sig,handler)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('check-source','check-authority','probe'));p.add_argument('--source',type=Path,default=C.ROOT);p.add_argument('--originals',type=Path);p.add_argument('--work',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
 value=C.source(a.source)if a.action=='check-source'else C.bound()[1]if a.action=='check-authority'else probe(a.source.absolute(),a.originals.absolute(),a.work.absolute(),a.output.absolute());print(json.dumps(value,sort_keys=True))
