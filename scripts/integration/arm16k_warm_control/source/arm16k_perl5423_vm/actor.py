#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit cap0/NNP rootless actor. No actions on import."""
import argparse,base64,hashlib,importlib.util,json,os,resource,socket,stat,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
D='/var/lib/arm16k-perl5423-vm'
UNIT='arm16k-perl5423-vm.service'

def module(n):
 s=importlib.util.spec_from_file_location('perl_actor_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def qemu_argv(m,r,epoch):
 return ['/usr/bin/qemu-system-aarch64','-machine','virt','-accel','tcg,thread=multi','-rtc','base=utc,clock=host','-cpu','max',
 '-smp',str(r['cpus']),'-m',str(r['guest_memory_bytes']//1024**2),'-nodefaults','-no-user-config','-display','none','-monitor','none','-nic','none','-no-reboot',
 '-kernel','/kernel/Image','-append','root=/dev/vda rootfstype=ext4 rw console=ttyAMA0,115200n8 rootwait init=/usr/lib/systemd/systemd systemd.unit=multi-user.target arm16k_systemd_nonce='+m['baseline_nonce']+' arm16k_perl5423_vm_nonce='+m['nonce']+' arm16k_perl5423_vm_preboot_etc_sha256='+m['preboot_etc_descriptor']['sha256']+' arm16k_perl5423_vm_root_ssh_sha256='+m['root_ssh_descriptor']['sha256']+' arm16k_rtc_host_epoch='+str(epoch),
 '-drive','if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2','-device','virtio-blk-device,drive=refdisk',
 '-serial','unix:/work/serial.sock,server=on,wait=off','-qmp','unix:/work/qmp.sock,server=on,wait=off',
 '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def retire_guest_hold(K,R,W,nonce):
 P=module('protocol');path=W/P.HOLD_MARKER;info=K.ordinary(path).lstat()
 K.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_uid==os.getuid()and info.st_gid==os.getgid()and stat.S_IMODE(info.st_mode)==0o600,'ordinary own-UID single-link private HOLD marker')
 marker_pin=K.pin(path,4096);value=K.load(path,4096);K.keys(value,('nonce','failure'),'failure-only retirement marker');P._nonce(nonce)
 K.need(value['nonce']==nonce,'exact case nonce in HOLD marker');P.hold_failure(value['failure'])
 row=R.receipt(W/'qemu.json');K.need(R.natural(row)and row['argv']==K.load(W/'qemu-argv.json')['argv'],'same naturally retired QEMU command')
 K.need(K.pin(path,4096)==marker_pin,'HOLD marker stable through retirement')
 receipt=dict(status='HOLD_GUEST_FAILURE_QEMU_NATURALLY_RETIRED',nonce=nonce,failure=value['failure'],marker=marker_pin,qemu=K.pin(W/'qemu.json'),VM_acceptance=None,Root_acceptance=None)
 path=W/P.HOLD_RETIRED
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(K.canonical(receipt))
 return False


FAILURE_FILE='actor-failure.json'
FAILURE_CAP=4096
BOOT_STAGES=('boot_entry','overlay_create','qemu','readback_convert','journal_replay','readonly_fsck',
 'baseline_scan','final_scan','preservation','retention','trust_absence','preservation_write','verification_remove')
FAILURE_MESSAGES={
 'UNKNOWN':'actor exception details unavailable',
 'PREBOOT_ETC_FIELDS':'integer original and final preboot etc inode metadata',
 'PREBOOT_ETC_PRESERVATION':'exact original preboot parent identity metadata and mtime',
 'ROOT_SSH_PARENT':'exact original preboot root identity metadata and mtime',
 'ROOT_SSH_ABSENCE':'final certified root SSH path and descendants absent',
 'ROOT_SSH_PRIVACY':'SSH privacy protected target must be absent before inventory',
 'SCAN_DEADLINE':'finite readonly scan deadline',
 'ACTOR_CANCELLED_OR_DEADLINE':'actor cancellation/deadline',
 'EXT4_NODE_BOUND':'node exceeds content bound',
 'EXT4_NODE_TYPE':'unsupported special or unused inode',
 'EXT4_LINK_COUNT':'inode link-count mismatch',
 'EXT4_DIRECTORY_TYPE':'directory type differs from inode',
 'EXT4_DIRECTORY_CYCLE':'directory hardlink/cycle',
 'EXT4_DIRECTORY_ENTRY':'invalid directory entry',
 'EXT4_SHORT_READ':'short image read',
 'EXT4_READ_BUDGET':'read budget exhausted',
 'EXT4_UNSUPPORTED_FEATURE':'unsupported ext4 incompat feature',
 'EXT4_SIZE':'filesystem/image size mismatch',
 'EXT4_INODE_EXTRA':'invalid inode extra size',
 'ALPM_TEXT_HASH':'ALPM text hash',
 'ALPM_OWNED_PATH':'literal owned path exists without alias substitution',
 'ALPM_INVENTORY':'exact actual complete baseline ALPM inventory',
 'BASELINE_OWNERSHIP_SET':'complete baseline ALPM ownership set',
 'BASELINE_OWNED_CHANGED':'baseline owned file bytes/mode/owner/version/time',
 'PROTECTED_NAMESPACE_CHANGED':'baseline user/platform/database/fixture bytes and metadata',
 'UNREVIEWED_TIMESTAMP':'unrelated baseline timestamp drift',
 'UNREVIEWED_RESIDUE':'unreviewed user/payload/database/log residue',
 'BASELINE_LOG_ABSENCE':'certified baseline pacman log absence restored',
 'RETAINED_LOG_METADATA':'actual safe retained transaction log for absent baseline log',
 'RETAINED_LOG_BYTES':'actual retained normal transaction log bytes/hash',
 'RESULT_MEMBERSHIP':'exact durable result membership',
 'RECEIPT_MEMBERSHIP':'exact reviewed receipt allowlist',
 'RETAINED_NODE':'ordinary root-owned single-link nonexecutable guest DATA',
 'RETAINED_SIZE':'bounded selected DATA file',
 'RETAINED_BUDGET':'combined results/receipts/manifest byte budget',
 'TRUST_RESIDUE':'private TEST trust absent on disk',
 'OS_ERROR':'actor operating-system error',
}
FAILURE_CATEGORIES=('ValueError','ReadbackError','TimeoutError','OSError','FileNotFoundError','PermissionError',
 'MemoryError','AssertionError','KeyboardInterrupt','SystemExit','Exception')
PATH_FAILURES={FAILURE_MESSAGES[k]+': ':k for k in('BASELINE_OWNED_CHANGED','PROTECTED_NAMESPACE_CHANGED','UNREVIEWED_TIMESTAMP')}


def public_failure_path(value,runtime):
 # Only already certified /usr runtime operands may name a path. User homes,
 # credentials, arbitrary filenames and all nonmatching exception text are absent.
 import re
 allowed={p.lstrip('/')for group in('files','baseline_files')for p in runtime.get(group,{})}
 return value if type(value)is str and value in allowed and value.startswith(('usr/bin/','usr/lib/','usr/share/'))and len(value)<=512 and all(re.fullmatch('[A-Za-z0-9._+@-]+',part)and part not in('.','..')for part in value.split('/'))else None


def failure_fields(error,runtime):
 text=str(error);category=type(error).__name__;category=category if category in FAILURE_CATEGORIES else'Exception'
 code=next((code for code,message in FAILURE_MESSAGES.items()if code not in('UNKNOWN','OS_ERROR')and text==message),'UNKNOWN');public_path=None
 for prefix,selected in PATH_FAILURES.items():
  if text.startswith(prefix):code=selected;public_path=public_failure_path(text[len(prefix):],runtime);break
 number=getattr(error,'errno',None);number=number if type(number)is int and 0<=number<=4095 else None
 if isinstance(error,OSError)and number is not None:code='OS_ERROR'
 return dict(category=category,code=code,message=FAILURE_MESSAGES[code],public_path=public_path,errno=number)


def write_failure(K,W,phase,packet,progress,error,runtime):
 stage=progress['stage'];K.need(phase in('prepare','boot')and stage in(('prepare',)if phase=='prepare'else BOOT_STAGES),'fixed actor failure phase/stage')
 module('protocol')._nonce(packet['nonce']);K.pin_shape(packet['Source_lock'])
 value=dict(schema=1,status='HOLD_ACTOR_FAILURE_DATA_ONLY',phase=phase,stage=stage,nonce=packet['nonce'],source_lock=packet['Source_lock'],
  failure=failure_fields(error,runtime),VM_acceptance=None,Root_acceptance=None)
 raw=K.canonical(value);K.need(0<len(raw)<=FAILURE_CAP,'bounded public actor failure receipt')
 fd=os.open(W/FAILURE_FILE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw)
 return value


def read_failure(K,W,phase,nonce,source_lock,runtime):
 path=K.ordinary(W/FAILURE_FILE);fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);K.need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.getuid()and before.st_gid==os.getgid()and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=FAILURE_CAP,'owned single-link private bounded actor failure DATA')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(FAILURE_CAP+1)
  identity=lambda row:tuple(getattr(row,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
  K.need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable complete actor failure DATA')
 finally:os.close(fd)
 value=json.loads(raw);K.keys(value,('schema','status','phase','stage','nonce','source_lock','failure','VM_acceptance','Root_acceptance'),'actor failure DATA')
 K.need(type(value['schema'])is int and value['schema']==1 and value['status']=='HOLD_ACTOR_FAILURE_DATA_ONLY'and value['phase']==phase and value['stage']in(('prepare',)if phase=='prepare'else BOOT_STAGES)and value['nonce']==nonce and value['source_lock']==source_lock and value['VM_acceptance']is value['Root_acceptance']is None,'same phase/nonce/Source failure only; no acceptance')
 failure=value['failure'];K.keys(failure,('category','code','message','public_path','errno'),'public actor failure fields')
 K.need(failure['category']in FAILURE_CATEGORIES and failure['code']in FAILURE_MESSAGES and failure['message']==FAILURE_MESSAGES[failure['code']]and
  (failure['public_path']is None or public_failure_path(failure['public_path'],runtime)==failure['public_path'])and
  (failure['errno']is None or type(failure['errno'])is int and 0<=failure['errno']<=4095)and raw==K.canonical(value),'allowlisted canonical public failure fields only')
 return value,dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def run_phase(phase,K,R,I,W,packet,cert,guard,deadline):
 progress=dict(stage='prepare'if phase=='prepare'else'boot_entry')
 try:
  return prepare(K,R,I,W,packet,cert,guard,deadline)if phase=='prepare'else boot(K,R,I,W,packet,cert,guard,deadline,progress)
 except BaseException as error:
  try:write_failure(K,W,phase,packet,progress,error,cert['runtime_certificate'])
  except BaseException:pass # Diagnostic failure never replaces the original failed operation.
  raise


def prepare(K,R,I,W,packet,cert,guard,deadline):
 r=cert['resource_certificate'];base=cert['baseline_certificate'];rt=cert['runtime_certificate']
 scan=I.scan(Path('/base/guest.raw'),deadline,guard);K.need(scan['filesystem_free_bytes']==r['guest_filesystem_free_bytes'],'actual baseline ext4 free bytes');owned=I.owners(scan,base['inventory']);I.qualify(scan,rt['baseline_files'],owned)
 log=base64.b64decode(scan['log_data_b64'],validate=True)if scan['log_data_b64']is not None else None
 actual_log=dict(bytes=len(log),sha256=hashlib.sha256(log).hexdigest())if log is not None else None
 K.need(actual_log==rt['restoration_allowances']['pacman_log_before'],'actual baseline normal pacman log presence/pin')
 hooks={n:I.stable(v)for n,v in scan['nodes'].items()if any(n==q.lstrip('/') or n.startswith(q.lstrip('/')+'/')for q in rt['effective_hook_policy']['hook_directories'])}
 K.need(hooks and K.json_pin(hooks)==rt['effective_hook_policy']['namespace_pin'],'actual complete preserved effective default hook namespace')
 if rt['dependency_transaction']:
  K.need(not any(n=='etc/pacman.d/gnupg' or n.startswith('etc/pacman.d/gnupg/')for n in scan['nodes']),'Root-reviewed absent global GPG directory')
  trust={p.lstrip('/'):I.stable(scan['nodes'][p.lstrip('/')])for p in K.ALARM_FILES}
  K.need(K.json_pin(trust)==rt['dependency_transaction']['baseline_public_trust'] and all(scan['nodes'][p]['type']=='file' and scan['nodes'][p]['uid']==scan['nodes'][p]['gid']==0 for p in trust),'actual unchanged exact three ALARM public files')
 if rt['kind']=='ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1':
  observed=module('expected_payload').observe(rt['expected_payload'],scan,base['inventory']);observed.update(baseline_certificate=K.pin(Path('/packet/baseline_certificate.json')),raw=base['raw'])
  (W/'baseline-provider-observation.json').write_bytes(K.canonical(observed))
 K.need(K.json_pin({n:I.stable(v)for n,v in scan['nodes'].items()})==rt['baseline_namespace_pin'],'Root-selected complete readonly baseline namespace')
 K.need(Path('/base/guest.raw').stat().st_size==r['prepared_raw_bytes']==r['baseline_raw_bytes'],'fixed raw geometry; resizing is outside this actor')
 K.need(Path('/base/guest.raw').stat().st_blocks*512<=r['baseline_allocated_bytes'],'actual baseline allocated-block envelope')
 raw=W/'guest.raw'
 def cmd(n,args,sec):return R.command(args,W,n,sec,deadline,watched_tree=(W,r['clone_allocated_cap_bytes']+r['logs_cap_bytes'],r['reserve_bytes']))
 cmd('sparse-clone',['cp','--sparse=always','--reflink=never','/base/guest.raw',str(raw)],r['prepare_seconds']-r['cleanup_seconds'])
 # Only new case files, one oneshot and its one enablement link. Existing
 # PAM, passwords, profiles, nonce and baseline package records remain untouched.
 additions={};edits=[];nodes=scan['nodes']
 def directory(path,mode=0o755):
  if path.lstrip('/') in nodes:
   K.need(nodes[path.lstrip('/')]['type']=='directory','existing image ancestor must be directory');return
  if path in additions:return
  parent=path.rsplit('/',1)[0]
  if parent:directory(parent)
  edits.extend(['mkdir '+path,'set_inode_field '+path+' mode 0'+format(0o040000|mode,'o'),'set_inode_field '+path+' uid 0','set_inode_field '+path+' gid 0']);additions[path]=dict(type='directory',mode=mode,uid=0,gid=0)
 def file(path,source,pin,mode):
  K.need(path.lstrip('/') not in nodes and path not in additions,'fresh exact preparation delta')
  directory(path.rsplit('/',1)[0]);edits.extend(['write '+str(source)+' '+path,'set_inode_field '+path+' mode 0'+format(0o100000|mode,'o'),'set_inode_field '+path+' uid 0','set_inode_field '+path+' gid 0'])
  additions[path]=dict(type='file',mode=mode,uid=0,gid=0,sha256=pin['sha256'])
 for name,row in packet['files'].items():
  path=D+'/'+name
  if name==UNIT:path='/etc/systemd/system/'+UNIT
  file(path,Path('/packet')/name,row,row['mode'])
 for group in ('materials','rollback_materials','dependency_materials'):
  for name,row in packet[group].items():
   if group=='materials' and name not in K.MATERIALS:continue
   source=Path('/materials')/row['guest_name'];file(D+'/'+row['guest_name'],source,row,0o644)
 # Derive only from the authenticated /base readonly scan, never running guest time.
 context_raw=Path('/packet/preboot-context.json').read_bytes()
 descriptor=module('preboot').descriptor(K,I,packet,cert,scan,context_raw)
 descriptor_path=W/'preboot-etc.tsv'
 fd=os.open(descriptor_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(descriptor)
 descriptor_pin=K.pin(descriptor_path,4096)
 file(D+'/preboot-etc.tsv',descriptor_path,descriptor_pin,0o600)
 root_ssh_descriptor=module('root_ssh').descriptor(K,I,packet,cert,scan,context_raw)
 root_ssh_path=W/'root-ssh-preboot.tsv'
 fd=os.open(root_ssh_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(root_ssh_descriptor)
 root_ssh_pin=K.pin(root_ssh_path,1024)
 file(D+'/root-ssh-preboot.tsv',root_ssh_path,root_ssh_pin,0o600)
 directory(D+'/trust',0o700);directory(D+'/cache',0o700)
 link='/etc/systemd/system/multi-user.target.wants/'+UNIT;directory(link.rsplit('/',1)[0]);K.need(link.lstrip('/') not in nodes,'fresh case enablement link')
 edits.append('symlink '+link+' /etc/systemd/system/'+UNIT)
 additions[link]=dict(type='symlink',mode=0o777,uid=0,gid=0,target_b64=base64.b64encode(('/etc/systemd/system/'+UNIT).encode()).decode())
 script=W/'edits.debugfs';script.write_text('\n'.join(edits)+'\n')
 cmd('write-case',['debugfs','-w','-f',str(script),str(raw)],r['prepare_seconds']-r['cleanup_seconds'])
 cmd('prepared-readonly-fsck',['e2fsck','-fn',str(raw)],r['prepare_seconds']-r['cleanup_seconds'])
 after=I.scan(raw,deadline,guard)
 K.need(after['nodes'].keys()-nodes.keys()=={p.lstrip('/')for p in additions},'exact complete preparation membership')
 K.need(all(I.stable(after['nodes'][n])==I.stable(row) for n,row in nodes.items()),'all baseline file bytes/type/mode/UID/GID/xattrs preserved')
 for path,expected in additions.items():K.need(all(after['nodes'][path.lstrip('/')].get(n)==v for n,v in expected.items()),'actual case delta readback: '+path)
 K.need(all(after['nodes'][p].get(n)==nodes[p].get(n)for p in (*module('preboot').PARENTS,'root') for n in ('inode','links','type','mode','uid','gid','mtime','mtime_ns','atime','atime_ns','xattrs')),'exact preboot parent inode metadata retained by preparation')
 K.need(after['nodes'][(D+'/preboot-etc.tsv').lstrip('/')]['size']==len(descriptor) and after['nodes'][(D+'/preboot-etc.tsv').lstrip('/')]['links']==1,'bounded single-link prepared preboot descriptor readback')
 K.need(after['nodes'][(D+'/root-ssh-preboot.tsv').lstrip('/')]['size']==len(root_ssh_descriptor) and after['nodes'][(D+'/root-ssh-preboot.tsv').lstrip('/')]['links']==1,'bounded single-link prepared root SSH descriptor readback')
 I.owners(after,base['inventory']);I.qualify(after,rt['baseline_files'],owned)
 (W/'prepared.json').write_bytes(K.canonical(dict(status='PREPARED_NOT_BOOTED',operation=K.OP,nonce=packet['nonce'],baseline_nonce=K.load(Path('/base/prepared.json'))['nonce'],
  packet=K.pin(Path('/packet/case-packet.json')),raw=K.pin(raw),preboot_etc_descriptor=descriptor_pin,root_ssh_descriptor=root_ssh_pin,preboot_context=K.pin(Path('/packet/preboot-context.json')),addition_namespace=additions,baseline=base['raw'],VM=None,ALPM=None,Root_acceptance=None)))


def boot(K,R,I,W,packet,cert,guard,deadline,progress=None):
 if progress is None:progress=dict(stage='boot_entry')
 r=cert['resource_certificate'];m=K.load(Path('/prepared/prepared.json'));K.need(m['packet']==K.pin(Path('/packet/case-packet.json')) and m['operation']==K.OP,'prepared exact packet join')
 K.need(K.pin(Path('/prepared/guest.raw'))==m['raw'],'prepared raw original input')
 epoch=K.load(W/'host-epoch.json');K.need(epoch['nonce']==m['nonce'] and 0<=time.time_ns()-epoch['utc_ns']<=30*10**9,'fresh host RTC boot epoch')
 def cmd(n,args,sec,**kw):return R.command(args,W,n,sec,deadline,watched_tree=(W,r['overlay_cap_bytes']+r['readback_allocated_cap_bytes']+r['logs_cap_bytes'],r['reserve_bytes']),**kw)
 progress['stage']='overlay_create'
 cmd('overlay-create',['qemu-img','create','-f','qcow2','-F','raw','-b','/prepared/guest.raw','/work/overlay.qcow2'],15)
 argv=qemu_argv(m,r,epoch['utc_ns']//10**9);(W/'qemu-argv.json').write_bytes(K.canonical(dict(argv=argv)))
 progress['stage']='qemu'
 cmd('qemu',argv,deadline-time.monotonic(),child_file_size_cap=r['overlay_cap_bytes'])
 row=R.receipt(W/'qemu.json');K.need(R.natural(row),'natural QEMU reap and group absence')
 marker=W/module('protocol').HOLD_MARKER
 if marker.exists()or marker.is_symlink():return retire_guest_hold(K,R,W,packet['nonce'])
 raw=W/'verification.raw'
 progress['stage']='readback_convert'
 cmd('readback-convert',['qemu-img','convert','-f','qcow2','-O','raw','-S','4k','/work/overlay.qcow2',str(raw)],r['cleanup_seconds'])
 progress['stage']='journal_replay'
 replay=cmd('journal-copy-only',['e2fsck','-p','-E','journal_only',str(raw)],r['cleanup_seconds'],check=False,completed=True)
 K.need(replay.returncode in (0,1),'verification-copy journal replay')
 progress['stage']='readonly_fsck'
 cmd('readback-readonly-fsck',['e2fsck','-fn',str(raw)],r['cleanup_seconds'])
 progress['stage']='baseline_scan'
 before=I.scan(Path('/prepared/guest.raw'),deadline,guard)
 progress['stage']='final_scan'
 after=I.scan(raw,deadline,guard)
 progress['stage']='preservation'
 module('preboot').preserve_etc(K,before,after)
 module('root_ssh').preserve(K,before,after)
 preservation=I.preserve(before,after,cert['baseline_certificate']['inventory'],cert['runtime_certificate'])
 # Bounded exact ordinary DATA only, read from the disposable verification copy.
 progress['stage']='retention'
 F=K.helper('independent_readback.py')
 with F.Ext4Reader(raw,max_nodes=150000,max_file_bytes=256*1024**2)as reader:
  preservation['retained_DATA']=module('retention').export(reader,after['nodes'],W,cert['runtime_certificate'],r,packet,K.pin(Path('/packet/case-packet.json')),guard)
 progress['stage']='trust_absence'
 K.need(not any(n==D.lstrip('/')+'/trust' or n.startswith(D.lstrip('/')+'/trust/')for n in after['nodes']),'private TEST trust absent on disk')
 progress['stage']='preservation_write'
 (W/'preservation.json').write_bytes(K.canonical(preservation))
 progress['stage']='verification_remove'
 raw.unlink()


def main():
 p=argparse.ArgumentParser();p.add_argument('phase',choices=['prepare','boot']);a=p.parse_args();K,R,I=module('contracts'),module('runtime'),module('image')
 K.need(os.environ.get('CACHY_PERL5423_ACTOR')=='1' and Path('/.dockerenv').is_file(),'explicit disposable actor entry')
 status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
 K.need(all(int(status[n],16)==0 for n in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')) and status['NoNewPrivs'].strip()=='1' and {n for _,n in socket.if_nameindex()}=={'lo'} and not Path('/dev/kvm').exists(),'cap0 NNP network-none software-only actor')
 packet=K.load(Path('/packet/case-packet.json'));cert={n:K.load(Path('/packet')/(n+'.json'))for n in K.EVIDENCE}
 for name,row in packet['files'].items():K.need(K.pin(Path('/packet')/name)=={k:row[k]for k in('bytes','sha256')},'complete packet file pin')
 for name,row in K.load(Path('/work/actor-tools.json'))['files'].items():K.need(R.image_tool_pin(name)==row,'Root-qualified actual tool image binary')
 for group in ('materials','rollback_materials','dependency_materials'):
  for name,row in packet[group].items():
   if group=='materials'and name not in K.MATERIALS:continue
   K.need(K.pin(Path('/materials')/row['guest_name'])=={k:row[k]for k in('bytes','sha256')},'actual retained actor material')
 r=cert['resource_certificate'];W=Path('/work');deadline=K.load(W/'actor-envelope.json')['deadline_monotonic_ns']/10**9
 K.END=deadline
 K.need(0<deadline-time.monotonic()<=r[a.phase+'_seconds'],'finite Root assigned actor envelope')
 def guard():
  K.need(time.monotonic()<deadline and not(W/'STOP').exists(),'actor cancellation/deadline')
  R.component_limits(W,[(W/'guest.raw',r['clone_allocated_cap_bytes']),(W/'overlay.qcow2',r['overlay_cap_bytes']),(W/'verification.raw',r['readback_allocated_cap_bytes'])])
 R.GUARD=guard;resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 result=run_phase(a.phase,K,R,I,W,packet,cert,guard,deadline)
 return 1 if result is False else 0
if __name__=='__main__':raise SystemExit(main())
