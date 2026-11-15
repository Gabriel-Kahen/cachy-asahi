#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit cap0/NNP rootless actor. No actions on import."""
import argparse,base64,hashlib,importlib.util,json,os,resource,socket,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
D='/var/lib/arm16k-perl5423-vm'
UNIT='arm16k-perl5423-vm.service'

def module(n):
 s=importlib.util.spec_from_file_location('perl_actor_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def qemu_argv(m,r,epoch):
 return ['/usr/bin/qemu-system-aarch64','-machine','virt','-accel','tcg,thread=multi','-rtc','base=utc,clock=host','-cpu','max',
 '-smp',str(r['cpus']),'-m',str(r['guest_memory_bytes']//1024**2),'-nodefaults','-no-user-config','-display','none','-monitor','none','-nic','none','-no-reboot',
 '-kernel','/kernel/Image','-append','root=/dev/vda rootfstype=ext4 rw console=ttyAMA0,115200n8 rootwait init=/usr/lib/systemd/systemd systemd.unit=multi-user.target arm16k_systemd_nonce='+m['baseline_nonce']+' arm16k_perl5423_vm_nonce='+m['nonce']+' arm16k_rtc_host_epoch='+str(epoch),
 '-drive','if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2','-device','virtio-blk-device,drive=refdisk',
 '-serial','unix:/work/serial.sock,server=on,wait=off','-qmp','unix:/work/qmp.sock,server=on,wait=off',
 '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


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
 I.owners(after,base['inventory']);I.qualify(after,rt['baseline_files'],owned)
 (W/'prepared.json').write_bytes(K.canonical(dict(status='PREPARED_NOT_BOOTED',operation=K.OP,nonce=packet['nonce'],baseline_nonce=K.load(Path('/base/prepared.json'))['nonce'],
  packet=K.pin(Path('/packet/case-packet.json')),raw=K.pin(raw),addition_namespace=additions,baseline=base['raw'],VM=None,ALPM=None,Root_acceptance=None)))


def boot(K,R,I,W,packet,cert,guard,deadline):
 r=cert['resource_certificate'];m=K.load(Path('/prepared/prepared.json'));K.need(m['packet']==K.pin(Path('/packet/case-packet.json')) and m['operation']==K.OP,'prepared exact packet join')
 K.need(K.pin(Path('/prepared/guest.raw'))==m['raw'],'prepared raw original input')
 epoch=K.load(W/'host-epoch.json');K.need(epoch['nonce']==m['nonce'] and 0<=time.time_ns()-epoch['utc_ns']<=30*10**9,'fresh host RTC boot epoch')
 def cmd(n,args,sec,**kw):return R.command(args,W,n,sec,deadline,watched_tree=(W,r['overlay_cap_bytes']+r['readback_allocated_cap_bytes']+r['logs_cap_bytes'],r['reserve_bytes']),**kw)
 cmd('overlay-create',['qemu-img','create','-f','qcow2','-F','raw','-b','/prepared/guest.raw','/work/overlay.qcow2'],15)
 argv=qemu_argv(m,r,epoch['utc_ns']//10**9);(W/'qemu-argv.json').write_bytes(K.canonical(dict(argv=argv)))
 cmd('qemu',argv,deadline-time.monotonic(),child_file_size_cap=r['overlay_cap_bytes'])
 row=R.receipt(W/'qemu.json');K.need(R.natural(row),'natural QEMU reap and group absence')
 raw=W/'verification.raw'
 cmd('readback-convert',['qemu-img','convert','-f','qcow2','-O','raw','-S','4k','/work/overlay.qcow2',str(raw)],r['cleanup_seconds'])
 replay=cmd('journal-copy-only',['e2fsck','-p','-E','journal_only',str(raw)],r['cleanup_seconds'],check=False,completed=True)
 K.need(replay.returncode in (0,1),'verification-copy journal replay')
 cmd('readback-readonly-fsck',['e2fsck','-fn',str(raw)],r['cleanup_seconds'])
 before=I.scan(Path('/prepared/guest.raw'),deadline,guard);after=I.scan(raw,deadline,guard)
 preservation=I.preserve(before,after,cert['baseline_certificate']['inventory'],cert['runtime_certificate'])
 # Bounded selected DATA readback only, never a filesystem/tree export.
 results=W/'results';results.mkdir(mode=0o700)
 F=K.helper('independent_readback.py');prefix=D.lstrip('/')+'/results/'
 selected={n:row for n,row in after['nodes'].items()if n.startswith(prefix)}
 K.need(selected and all(row['type']=='file'and '/'not in n[len(prefix):]for n,row in selected.items()),'closed flat ordinary durable result set')
 with F.Ext4Reader(raw,max_nodes=150000,max_file_bytes=256*1024**2)as reader:
  total=0
  for name,row in sorted(selected.items()):
   guard();total+=row['size'];K.need(total<=r['guest_output_cap_bytes'],'bounded durable readback')
   fields,data=reader.inode(row['inode'])
   with (results/name[len(prefix):]).open('xb')as stream:
    for block in reader.chunks(fields,data):guard();stream.write(block)
   (results/name[len(prefix):]).chmod(0o600);K.need(K.pin(results/name[len(prefix):])['sha256']==row['sha256'],'actual durable readback hashes')
 K.need(not any(n==D.lstrip('/')+'/trust' or n.startswith(D.lstrip('/')+'/trust/')for n in after['nodes']),'private TEST trust absent on disk')
 (W/'preservation.json').write_bytes(K.canonical(preservation));raw.unlink()


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
 (prepare if a.phase=='prepare'else boot)(K,R,I,W,packet,cert,guard,deadline)
 return 0
if __name__=='__main__':raise SystemExit(main())
