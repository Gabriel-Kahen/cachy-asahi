# SPDX-License-Identifier: MIT
"""Exact Docker28 default plus native-proven USER-only unshare and chroot rules."""
import hashlib,json,os,stat,subprocess
from pathlib import Path
PROFILE=dict(bytes=16157,sha256='a573639eda750bbd31fbc03b5e5c1427c8c4859986dbcd51d520b57545203d2d')
COMMAND=['docker','version','--format','{{json .Server}}']
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(p):
 p=Path(p);fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=1024**2,'bounded ordinary profile');raw=os.read(fd,1024**2+1);t=os.fstat(fd);keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');need(len(raw)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in keys),'profile physical identity/bytes held');return raw
 finally:os.close(fd)
def save(path,raw):
 with Path(path).open('xb')as f:f.write(raw)
def arguments(kind,path):
 need(kind in('systemd','pacman'),'exact original recipe')
 return ['--security-opt','seccomp='+str(path)]if kind=='systemd'else[]
def prepare(kind,out,art):
 need(kind in('systemd','pacman'),'exact original recipe')
 if kind=='pacman':return None
 raw=read(Path(__file__).with_name('systemd-seccomp.json'));need(pin(raw)==PROFILE,'exact native-proven full default plus two rules');r=subprocess.run(COMMAND,stdin=subprocess.DEVNULL,capture_output=True,timeout=10);need(len(r.stdout)+len(r.stderr)<=1024**2,'bounded fresh Engine output');save(art/'systemd-engine.stdout',r.stdout);save(art/'systemd-engine.stderr',r.stderr);need(r.returncode==0 and not r.stderr,'fresh successful Engine query');server=json.loads(r.stdout);need(server['Version']=='28.0.4'and server['Os']=='linux'and server['Arch']=='arm64','fresh exact native Docker28.0.4 profile consistency');save(out/'systemd-seccomp.json',raw);save(art/'systemd-seccomp.json',raw)
 return dict(schema=1,status='EXACT_DOCKER28_DEFAULT_PLUS_USERNS_CHROOT_SYSTEMD_ONLY',profile=PROFILE,path=str(out/'systemd-seccomp.json'),engine=dict(command=COMMAND,returncode=r.returncode,limit_seconds=10,stdout=pin(r.stdout),stderr=pin(r.stderr),server=server),package_assertions='UNCHANGED_FULL_TESTS_STILL_REQUIRED',hardware='NOT_RUN')
def verify(kind,out):
 if kind=='systemd':need(pin(read(out/'systemd-seccomp.json'))==PROFILE,'host-only loaded profile remains exact')
