#!/usr/bin/python3 -I -B
"""One fixed policy metadata observer after a bounded, exact ready/GO handshake."""
import argparse, hashlib, json, math, os, re, resource, signal, stat, subprocess, sys, time, importlib.util
from pathlib import Path
OUTPUT=Path('/output')
LIMITS={'AS':[4294967296,4294967296],'FSIZE':[1610612736,1610612736],'CORE':[0,0]}


def need(ok,why):
    if not ok:raise ValueError(why)


def encoded(v):
    return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def apply_limits():
    for name,pair in LIMITS.items():resource.setrlimit(getattr(resource,'RLIMIT_'+name),tuple(pair))
    need(all(resource.getrlimit(getattr(resource,'RLIMIT_'+name))==tuple(pair) for name,pair in LIMITS.items()),'fixed decoder hard/soft limits applied')


def ready(nonce,authority,deadline_text):
    return dict(kind='FIXED_LDCACHE_RECOVERY_LIMITS_READY_V1',nonce=nonce,authority_sha256=authority,
        deadline_monotonic=deadline_text,namespace_pid=1,limits=LIMITS)


def go_bytes(nonce,authority,ready_raw):
    return encoded(dict(kind='ROOT_GO_FIXED_LDCACHE_RECOVERY_V1',nonce=nonce,authority_sha256=authority,
        ready_sha256=hashlib.sha256(ready_raw).hexdigest()))


def read_go(root,expected):
    p=root/'decoder.go.json'
    try:fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except FileNotFoundError:return False
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==os.geteuid() and stat.S_IMODE(a.st_mode)==0o600 and a.st_size==len(expected)<=4096,'ordinary exact-size private GO')
        raw=os.read(fd,4097);b=os.fstat(fd);c=p.lstat()
        identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        need(raw==expected and identity(a)==identity(b)==identity(c),'exact fresh nonce/authority/ready-bound GO token')
        return True
    finally:os.close(fd)


def wait_for_go(root,expected,deadline,clock=time.monotonic,sleeper=time.sleep):
    while True:
        need(clock()<deadline,'shared decoder deadline before GO')
        if read_go(root,expected):return
        sleeper(min(.025,max(0,deadline-clock())))


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixed-ldcache-recovery',action='store_true',required=True)
    p.add_argument('--qualification-authority-sha256',required=True);p.add_argument('--nonce',required=True);p.add_argument('--authority-sha256',required=True);p.add_argument('--deadline-monotonic',required=True);a=p.parse_args(argv)
    need(a.fixed_ldcache_recovery and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()==0 and os.getpid()==1,'only isolated fixed namespace-root PID1 metadata helper')
    need(re.fullmatch('[0-9a-f]{32}',a.nonce) and re.fullmatch('[0-9a-f]{64}',a.authority_sha256) and re.fullmatch(r'[0-9]{1,12}\.[0-9]{6}',a.deadline_monotonic),'exact fresh Root nonce/authority/deadline arguments')
    deadline=float(a.deadline_monotonic);need(math.isfinite(deadline) and 0<deadline-time.monotonic()<=180,'same finite decoder phase deadline')
    def stop(sig,frame):raise SystemExit(128+sig)
    for number in(signal.SIGINT,signal.SIGTERM):signal.signal(number,stop)
    st=OUTPUT.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700 and not OUTPUT.is_symlink(),'fixed private namespace-root-owned output')
    os.umask(0o077);apply_limits();body=encoded(ready(a.nonce,a.authority_sha256,a.deadline_monotonic));need(len(body)<=4096,'bounded ready DATA')
    staging=OUTPUT/'.decoder.ready.staging';published=OUTPUT/'decoder.ready.json'
    need(not published.exists() and not (OUTPUT/'decoder.go.json').exists(),'fresh ready/GO destinations')
    fd=os.open(staging,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:need(os.write(fd,body)==len(body),'whole ready write');os.fsync(fd)
    finally:os.close(fd)
    os.rename(staging,published)
    wait_for_go(OUTPUT,go_bytes(a.nonce,a.authority_sha256,body),deadline)
    need(time.monotonic()<deadline,'shared deadline immediately before fixed exec')
    # Only after Root's actual PIDFD/cgroup/proc-limit proof and atomic GO.
    need(re.fullmatch('[0-9a-f]{64}',a.qualification_authority_sha256),'fixed qualification authority SHA')
    spec=importlib.util.spec_from_file_location('fixed_metadata_operation','/draft/observe_initialized.py');operation=importlib.util.module_from_spec(spec);spec.loader.exec_module(operation)
    def deadline_stop(sig,frame):raise SystemExit(124)
    signal.signal(signal.SIGALRM,deadline_stop);signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.monotonic()))
    try:code=operation.execute('/authority/Root-qualification.ACTUAL.json',a.qualification_authority_sha256)
    finally:signal.setitimer(signal.ITIMER_REAL,0)
    raise SystemExit(code)


if __name__=='__main__':main()
