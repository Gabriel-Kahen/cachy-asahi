# SPDX-License-Identifier: MIT
"""Owned real libalpm removal checkpoint; never invoked by source controls."""
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import stat
import time
import common as C

REMOVE_PROGRESS=4  # libalpm16.0.1 alpm_progress_t, pinned alpm.h.
CALLBACK=ctypes.CFUNCTYPE(None,ctypes.c_void_p,ctypes.c_int,ctypes.c_char_p,
                         ctypes.c_int,ctypes.c_size_t,ctypes.c_size_t)
LOCK='var/lib/pacman/db.lck'
LOCAL='var/lib/pacman/local'


def identity(info):
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]


def lock_identity(root):
    path=root/LOCK
    C.need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary owned lock path')
    info=path.lstat()
    C.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0 and
           info.st_uid==info.st_gid==0 and info.st_nlink==1 and info.st_size==0,
           'exact libalpm16 empty mode000 owned lock')
    return identity(info)


def choose(before,old,new):
    candidates=sorted(n for n,row in old['nodes'].items() if row['type']=='file' and
                      n.startswith('usr/') and n not in new['nodes'] and n not in C.CACHES)
    C.need(len(candidates)>=2,'two held-only regular files required for partial removal proof')
    removed,remaining=candidates[-1],candidates[0]
    for name in (removed,remaining):
        C.need(before['nodes'].get(name)==old['nodes'][name],'exact held checkpoint fixture')
    return dict(removed=removed,remaining=remaining,
                remaining_sha256=old['nodes'][remaining]['sha256'])


def partial(root,point):
    removed=root/point['removed'];remaining=root/point['remaining']
    C.need(not removed.exists() and not removed.is_symlink(),'real held payload removal required')
    C.need(C.sha(C.read(remaining,64*1024**2))==point['remaining_sha256'],
           'remaining held-only payload required; full removal is not this checkpoint')


def send(fd,row):
    raw=(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()
    C.need(len(raw)<=4096,'bounded atomic checkpoint record')
    C.need(os.write(fd,raw)==len(raw),'complete checkpoint write')


class Checkpoint:
    def __init__(self,root,point,fd):
        self.root,self.point,self.fd=root,point,fd
        self.armed=False
        self.prepared=None
        self.hit=False

    def bind(self,alpm):
        def progress(ctx,event,package,percent,howmany,current):
            if not (self.armed and event==REMOVE_PROGRESS and package==b'glibc' and
                    0<=percent<100 and howmany==current==1):return
            try:
                removed=self.root/self.point['removed']
                if removed.exists() or removed.is_symlink():return
                C.need(not self.hit,'single deterministic checkpoint')
                partial(self.root,self.point)
                self.hit=True
                send(self.fd,dict(type='CHECKPOINT',pid=os.getpid(),pgid=os.getpgrp(),
                     phase='ALPM_COMMIT_REMOVE_PAYLOAD_BEFORE_OLD_DATABASE_REMOVAL',
                     event=event,package='glibc',percent=percent,howmany=howmany,current=current,
                     point=self.point,lock=lock_identity(self.root),prepared=self.prepared))
                # Stop inside the real C progress callback, never return to commit.
                os.kill(os.getpid(),signal.SIGSTOP)
                os._exit(72)  # Continuing this stopped writer is forbidden.
            except BaseException as error:
                send(self.fd,dict(type='ERROR',message=str(error)[:512]));os._exit(71)
        self.callback=CALLBACK(progress)  # Keep the ctypes trampoline alive through commit.
        setter=alpm.lib.alpm_option_set_progresscb
        setter.restype=ctypes.c_int
        setter.argtypes=[ctypes.c_void_p,CALLBACK,ctypes.c_void_p]
        alpm.ok(setter(alpm.handle,self.callback,None),'install owned observer progress callback')


def receive(fd,deadline):
    raw=bytearray()
    while b'\n' not in raw:
        C.need(time.monotonic()<deadline,'interruption checkpoint deadline')
        ready,_,_=select.select([fd],[],[],min(.1,max(0,deadline-time.monotonic())))
        if ready:
            part=os.read(fd,4097-len(raw));C.need(part,'writer exited before checkpoint')
            raw.extend(part);C.need(len(raw)<=4096,'checkpoint output limit')
    C.need(raw.count(b'\n')==1 and raw.endswith(b'\n'),'single checkpoint protocol record')
    return json.loads(raw)


def validate_checkpoint(row,pid,root,point):
    C.need(set(row)=={'type','pid','pgid','phase','event','package','percent','howmany',
                     'current','point','lock','prepared'} and row['type']=='CHECKPOINT' and
           row['pid']==row['pgid']==pid and row['phase']==
           'ALPM_COMMIT_REMOVE_PAYLOAD_BEFORE_OLD_DATABASE_REMOVAL' and
           row['event']==REMOVE_PROGRESS and row['package']=='glibc' and
           type(row['percent']) is int and 0<=row['percent']<100 and
           row['howmany']==row['current']==1 and row['point']==point,
           'exact real commit checkpoint protocol')
    prepared=row['prepared']
    C.need(type(prepared) is dict and set(prepared)=={'prepared_add','prepared_remove','dependencies','commit_started','observer_root','hooks','scriptlets'} and
           prepared['prepared_add']=={C.NAME:C.VERSION} and set(prepared['prepared_remove'])=={'glibc'} and
           prepared['dependencies']=='PASS_ALPM_PREPARE' and prepared['commit_started'] is True and
           prepared['observer_root']=='INTACT_OUTER_HELD574' and prepared['hooks']=='DISABLED' and
           prepared['scriptlets']=='DISABLED_EXPLICIT_HELD_POST_UPGRADE_LATER',
           'actual dependency-checked combined replacement before checkpoint')
    C.need(row['lock']==lock_identity(root),'held owned lock identity drift')
    partial(root,point)


def stop_and_kill(api,lane,root,index,point,case,report):
    C.need(not (root/LOCK).exists() and not (root/LOCK).is_symlink(),'no existing lock before owned writer')
    read_fd,write_fd=os.pipe2(os.O_CLOEXEC)
    ack_read,ack_write=os.pipe2(os.O_CLOEXEC)
    started=time.monotonic();deadline=started+120
    pid=None;checkpoint=None;group_absent=False;exit_code=None
    try:
        pid=os.fork()
        if pid==0:
            try:
                os.close(read_fd);os.close(ack_write)
                os.setsid()
                for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM):signal.signal(sig,signal.SIG_DFL)
                signal.alarm(120)
                send(write_fd,dict(type='READY',pid=os.getpid(),pgid=os.getpgrp()))
                C.need(os.read(ack_read,1)==b'1','outer owner session acknowledgement')
                os.close(ack_read)
                observer=Checkpoint(root,point,write_fd)
                lane.transaction(api,root,lane.INPUTS/index['archives']['a']['path'],
                                 'glibc',C.NAME,lane.OUT/(case+'-interrupted-commit.log'),progress=observer)
                send(write_fd,dict(type='ERROR',message='commit returned without exact interruption'))
                os._exit(73)
            except BaseException as error:
                try:send(write_fd,dict(type='ERROR',message=str(error)[:512]))
                finally:os._exit(70)
        os.close(write_fd);write_fd=None;os.close(ack_read);ack_read=None
        ready=receive(read_fd,deadline)
        C.need(ready==dict(type='READY',pid=pid,pgid=pid) and os.getpgid(pid)==pid,
               'owned writer session before any ALPM mutation')
        C.need(os.write(ack_write,b'1')==1,'writer session acknowledgement');os.close(ack_write);ack_write=None
        checkpoint=receive(read_fd,deadline)
        validate_checkpoint(checkpoint,pid,root,point)
        while True:
            state=os.waitid(os.P_PID,pid,os.WSTOPPED|os.WEXITED|os.WNOHANG|os.WNOWAIT)
            if state is not None:
                C.need(state.si_code==os.CLD_STOPPED and state.si_status==signal.SIGSTOP,
                       'real writer stopped inside commit callback')
                break
            C.need(time.monotonic()<deadline,'writer stop deadline');time.sleep(.01)
        report['checkpoint']=checkpoint
        report['observed_stop']='KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER'
    finally:
        if pid not in (None,0):
            blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
            try:
                # No reaping before the last group signal: numeric group ownership remains reserved.
                try:
                    if os.getpgid(pid)==pid:os.killpg(pid,signal.SIGKILL)
                    else:os.kill(pid,signal.SIGKILL)  # Child failed before setsid/READY, no commit acknowledged.
                except ProcessLookupError:pass
                reap_deadline=time.monotonic()+5
                while os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                    C.need(time.monotonic()<reap_deadline,'owned writer reap deadline');time.sleep(.01)
                _,status=os.waitpid(pid,0);exit_code=os.waitstatus_to_exitcode(status)
                try:os.killpg(pid,0)
                except ProcessLookupError:group_absent=True
            finally:
                report['writer']=dict(pid=pid,pgid=pid,exit_code=exit_code,
                    group_absence_verified=group_absent,seconds=round(time.monotonic()-started,6),
                    time_limit=120,output_limit=8192,expected_signal='SIGKILL_AFTER_OBSERVED_REAL_CHECKPOINT')
                signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
        for fd in (read_fd,write_fd,ack_read,ack_write):
            if fd is not None:os.close(fd)
    C.need(checkpoint is not None and exit_code==-signal.SIGKILL and group_absent,
           'exact deliberate writer kill and actual process-group absence required')
    return checkpoint


def local_nodes(snapshot):
    return {n:row for n,row in snapshot['nodes'].items() if n==LOCAL or n.startswith(LOCAL+'/')}


def clear_owned_lock(root,expected,writer):
    C.need(writer['group_absence_verified'] is True and writer['exit_code']==-signal.SIGKILL,
           'no lock mutation before actual writer absence')
    C.need(lock_identity(root)==expected,'foreign/replaced lock preserved')
    directory=os.open(root/'var/lib/pacman',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        C.need(identity(os.stat('db.lck',dir_fd=directory,follow_symlinks=False))==expected,
               'owned lock identity before unlink')
        os.unlink('db.lck',dir_fd=directory)
        os.fsync(directory)
    finally:os.close(directory)
    C.need(not (root/LOCK).exists() and not (root/LOCK).is_symlink(),'owned stale lock removal verified')
    return dict(status='PASS_EXACT_OWNED_STALE_LOCK_REMOVED_AFTER_GROUP_ABSENCE',identity=expected)


def outer_identity(api,lane,old):
    path=Path(api['roots'].installer.LIBRARY)
    raw=C.read(path,64*1024**2);info=path.stat()
    C.need(C.sha(raw)==api['roots'].installer.architecture_profile('aarch64')[0],
           'actual intact outer held libalpm hash')
    return dict(roles=lane.role_identities(Path('/'),old),
                libalpm=dict(path=str(path),sha256=C.sha(raw),device=info.st_dev,inode=info.st_ino))


def exercise(api,lane,root,index,base,new,old,before,case,report):
    point=choose(before,old,new);report['point']=point
    report['outer_runtime_before']=outer_identity(api,lane,old)
    checkpoint=stop_and_kill(api,lane,root,index,point,case,report)
    C.need(checkpoint['prepared']['prepared_remove']=={'glibc':base['glibc']},'exact held version in interrupted prepared removal')
    interrupted=lane.snapshot(api,root,case+'-interrupted-before-unlock')
    partial(root,point)
    C.need(local_nodes(interrupted)==local_nodes(before),
           'recovery classification requires COMPLETE unchanged original574 local DB records')
    C.need({n:v for n,v in interrupted['nodes'].items() if n in lane.CONFIGS}==
           {n:v for n,v in before['nodes'].items() if n in lane.CONFIGS},
           'interruption point must precede all config/backup mutation')
    # The complete pre-unlock observation retains db.lck. Only this verified owned lock is excluded.
    compare=dict(interrupted,nodes={n:r for n,r in interrupted['nodes'].items() if n!=LOCK})
    report['partial_preservation']=lane.unchanged(before,compare,old,new,base['glibc'])
    report['partial_state']='HELD574_DATABASE_WITH_PARTIALLY_REMOVED_HELD_PAYLOAD_CANDIDATE_NOT_ADDED'
    report['lock_recovery']=clear_owned_lock(root,checkpoint['lock'],report['writer'])
    C.need(lane.inventory(lane.database(api,root))==base,'actual574 DB re-read after exact stale lock removal')
    # Ordinary same-name reinstall reuses ownership in the intact old DB: no --nodeps/overwrite/DB editing.
    report['external_recovery']=lane.transaction(api,root,lane.INPUTS/index['held']['path'],
                                                'glibc','glibc',lane.OUT/(case+'-external-recovery.log'))
    recovered=lane.snapshot(api,root,case+'-recovered-held574')
    C.need(lane.inventory(lane.database(api,root))==base,'recovered exact574 held versions')
    lane.payload(recovered['nodes'],old['nodes'],C.CACHES|{'etc/gai.conf','etc/locale.gen'})
    C.need({n:v for n,v in recovered['nodes'].items() if n in lane.CONFIGS}==
           {n:v for n,v in before['nodes'].items() if n in lane.CONFIGS},
           'recovery preserves all user configs and backup sidecars exactly')
    report['recovered_preservation']=lane.unchanged(before,recovered,old,new,base['glibc'])
    C.need(C.read(root/point['removed'],64*1024**2)==old['data'][point['removed']],
           'actual interrupted held payload restored')
    report['outer_runtime_after']=outer_identity(api,lane,old)
    C.need(report['outer_runtime_before']==report['outer_runtime_after'],'intact outer held runtime identity preserved through recovery')
    report.update(status='PASS_ACTUAL_REMOVE_PHASE_KILL_AND_EXTERNAL_RECOVERY',
                  recovery_runtime='INTACT_OUTER_HELD_LIBC_LIBALPM',
                  candidate_extraction_interruption='NOT_TESTED',power_loss_durability='NOT_TESTED')
