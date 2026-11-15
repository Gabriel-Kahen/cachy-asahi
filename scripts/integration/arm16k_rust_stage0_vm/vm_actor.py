#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Future owned software-emulated guest; no launch or tool execution on import."""
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import sys
import time

HERE=Path(__file__).resolve().parent


def module(name):
    s=importlib.util.spec_from_file_location('stage0_actor_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def qemu_argv(prepared,epoch):
    return ['/usr/bin/qemu-system-aarch64','-machine','virt','-accel','tcg,thread=multi','-rtc','base=utc,clock=host','-cpu','max','-smp','2','-m','2048','-nodefaults','-no-user-config','-display','none','-monitor','none','-nic','none','-no-reboot','-kernel','/inputs/Image','-append','root=/dev/vda rootfstype=ext4 rw console=ttyAMA0,115200n8 rootwait init=/usr/lib/systemd/systemd systemd.unit=multi-user.target arm16k_systemd_nonce='+prepared['baseline_nonce']+' arm16k_rust_stage0_nonce='+prepared['nonce']+' arm16k_rtc_host_epoch='+str(epoch),'-drive','if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2','-device','virtio-blk-device,drive=refdisk','-serial','unix:/work/serial.sock,server=on,wait=off','-qmp','unix:/work/qmp.sock,server=on,wait=off','-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def postboot(K,R,O,inputs,work,prepared,deadline):
    """Read the disposable overlay only after a natural, signal-free QEMU reap."""
    K.checked(inputs/'ownership.json',prepared['ownership'])
    baseline=K.load(inputs/'ownership.json',64*1024**2)
    raw=work/'verification.raw';view=work/'verification-view'
    K.need(not raw.exists() and not view.exists(),'fresh owned postboot scratch required')
    budget=(work,K.RESOURCES['boot_allocated_cap'],K.RESOURCES['reserve_bytes'])
    def cmd(label,argv,cap,**options):
        return R.command(argv,work,label,cap,deadline,**options,watched_tree=budget)
    cmd('postboot-convert',['qemu-img','convert','-f','qcow2','-O','raw','-S','4k',str(work/'overlay.qcow2'),str(raw)],75)
    K.need(raw.stat().st_size==prepared['files']['guest.raw']['bytes'] and raw.stat().st_size<=K.RESOURCES['raw_cap_bytes'],'postboot raw geometry differs')
    # QMP quit is not shutdown. Replay committed ext4 journal records only on
    # this fresh verification copy; never repair the selected base or overlay.
    replay=cmd('postboot-journal',['e2fsck','-p','-E','journal_only',str(raw)],35,completed=True,check=False)
    K.need(replay.returncode in (0,1),'verification-copy journal replay failed')
    cmd('postboot-ext4-readonly',['e2fsck','-fn',str(raw)],45)
    view.mkdir(mode=0o700)
    cmd('postboot-rdump',['debugfs','-R','rdump / '+str(view),str(raw)],90)
    proof=O.preservation(view,baseline,prepared['fixture_payload'],K.PREFIX)
    proof.update(status='PASS_COMPLETE_POSTBOOT_PRESERVATION',nonce=prepared['nonce'],source_lock=prepared['source_lock'],ownership=prepared['ownership'],guest_sync='REQUIRED_BY_HOST_PROTOCOL',journal_replay='VERIFICATION_COPY_ONLY',readonly_ext4_check='PASS')
    # Delete only these fixed new scratch objects after a complete comparison.
    shutil.rmtree(view);raw.unlink()
    proof['retained_allocated_bytes']=R.allocated(work)
    K.need(proof['retained_allocated_bytes']<=K.RESOURCES['boot_allocated_cap'] and shutil.disk_usage(work).free>=K.RESOURCES['reserve_bytes'],'postboot allocation/reserve differs')
    (work/'postboot-preservation.json').write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')


def main():
    K,R=module('contracts'),module('runtime')
    K.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.environ.get('CACHY_RUST_STAGE0_BOOT')=='1' and Path('/.dockerenv').is_file(),'explicit Root-owned VM entry required')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    K.need(all(int(status[n].strip(),16)==0 for n in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and status['NoNewPrivs'].strip()=='1' and {n for _,n in socket.if_nameindex()}=={'lo'} and not Path('/dev/kvm').exists(),'actual no-device cap0/NNP/software-only domain')
    I,W=Path('/inputs'),Path('/work');m=K.load(I/'prepared.json');K.need(m['source_lock']==K.source(),'exact prepared Source binding')
    for name,row in m['files'].items():K.checked(I/name,row)
    tool=K.load(HERE/'data/qemu-metadata.json');K.checked(Path('/usr/bin/qemu-system-aarch64'),tool['actual_tool_pin'])
    epoch=K.load(W/'host-epoch.json');K.need(epoch['nonce']==m['nonce'] and 0<=time.time_ns()-epoch['utc_ns']<=30*10**9,'fresh Root host boot epoch required')
    K.need(not (W/'attempt.json').exists() and not (W/'overlay.qcow2').exists(),'one owned VM attempt only')
    (W/'attempt.json').write_text(json.dumps(dict(operation=K.OP,nonce=m['nonce'],source_lock=m['source_lock']))+'\n')
    deadline=epoch['deadline_monotonic']-5;K.need(5<deadline-time.monotonic()<=550,'finite assigned VM work budget');K.END=deadline
    R.command(['qemu-img','create','-f','qcow2','-F','raw','-b','/inputs/guest.raw','/work/overlay.qcow2'],W,'overlay-create',10,deadline)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    argv=qemu_argv(m,epoch['utc_ns']//10**9);(W/'qemu-argv.json').write_text(json.dumps(argv,indent=2)+'\n')
    (W/'host-qemu-start.json').write_text(json.dumps(dict(nonce=m['nonce'],utc_ns=time.time_ns(),monotonic_ns=time.monotonic_ns()))+'\n')
    failed=False
    try:R.command(argv,W,'qemu',seconds=max(5,deadline-time.monotonic()),deadline=deadline,child_file_size_cap=K.RESOURCES['overlay_cap_bytes'],watched_tree=(W,K.RESOURCES['boot_allocated_cap'],K.RESOURCES['reserve_bytes']))
    except BaseException:failed=True
    finally:
        receipt=W/'qemu.json'
        if receipt.is_file():
            row=K.load(receipt);row['actor_cancelled']=row.get('command_cancelled',[])
            (W/'qemu-retirement.json').write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')
        else:row={}
    if failed or not R.natural(row):return 1
    try:postboot(K,R,module('ownership'),I,W,m,deadline)
    except BaseException as error:
        (W/'postboot-preservation.json').write_text(json.dumps(dict(status='HOLD_POSTBOOT_PRESERVATION',nonce=m['nonce'],failure=dict(category=type(error).__name__,message=str(error)[:1024])),indent=2,sort_keys=True)+'\n')
        return 1
    return 0



if __name__=='__main__':raise SystemExit(main())
