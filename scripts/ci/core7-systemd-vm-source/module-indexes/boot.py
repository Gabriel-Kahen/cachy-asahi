# SPDX-License-Identifier: MIT
"""Literal owned bootstrap: real devtmpfs/cgroup2 and exec of genuine systemd."""
import os,re,shlex,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,initramfs as J
ROLES=('/inputs','/out','/upgrade-code','/upgrade-config.json','/persistent_scope.py','/upgrade-signing','/measurement','/workspace','/source')
UNITS=('caa-core.target','caa-core-worker.service','caa-core-probe.service','caa-core-observer.service')

def bootstrap(nonce):
 C.need(re.fullmatch('[a-f0-9]{32}',nonce or''),'literal fresh nonce')
 lines=['#!/usr/bin/bash','set -euo pipefail','trap \'rc=$?; trap - ERR; printf "CORE7_BOOTSTRAP_FAILURE_DATA line=%s rc=%s\\n" "$LINENO" "$rc" >/dev/console || printf "CORE7_BOOTSTRAP_FAILURE_DATA line=%s rc=%s\\n" "$LINENO" "$rc" >&2; exit "$rc"\' ERR','export PATH=/usr/bin:/bin LC_ALL=C LANG=C',
 'test "$(id -u)" = 0','test "$(uname -m)" = aarch64',
 'mount -t proc -o nosuid,nodev,noexec proc /proc',
 'grep -qw "caa_core_vm='+nonce+'" /proc/cmdline',
 'mount -t sysfs -o nosuid,nodev,noexec sysfs /sys',
 'test "$(cat /sys/class/block/vda/serial)" = '+shlex.quote(C.disk_serial(nonce,'boot')),
 'test "$(cat /sys/class/block/vdb/serial)" = '+shlex.quote(C.disk_serial(nonce,'data')),
 'mount -o remount,nosuid /dev','mkdir -p /dev/pts',
 'mount -t devpts -o nosuid,noexec,gid=5,mode=620 devpts /dev/pts',
 'mount -t tmpfs -o nosuid,nodev,size=512m,mode=1777 tmpfs /tmp',
 'mount -t tmpfs -o nosuid,nodev,size=128m,mode=755 tmpfs /run',
 'mkdir -p /sys/fs/cgroup','mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup',
 'mkdir /volume','mount -t ext4 -o rw,nosuid,nodev /dev/vdb /volume']
 for name in ROLES:
  lines.append('mount --bind /volume'+name+' '+name)
  if name not in('/out','/measurement'):lines.append('mount -o remount,bind,ro '+name)
 lines+=['umount /volume','rmdir /volume',
 '/usr/bin/python3 -I -B /workspace/guest.py bootstrap',
 'exec /usr/lib/systemd/systemd --system --unit=caa-core.target --log-target=console --log-level=info --show-status=yes']
 return ('\n'.join(lines)+'\n').encode()

def overlay(nonce):
 result={'init-core7':dict(mode=0o755,data=bootstrap(nonce)),
 'etc/machine-id':dict(mode=0o444,data=(nonce+'\n').encode())}
 for name in UNITS:result['etc/systemd/system/'+name]=dict(mode=0o644,data=C.read(C.HERE/'units'/name,16384))
 return result

def apply(root,nonce,command):
 """Only an owned staging directory; never / or a live root."""
 root=Path(root).absolute();C.need(root!=Path('/')and root.name=='boot'and root.parent.name=='stage'and not any(p.is_symlink()for p in(root,*root.parents)),'exact fresh media staging root')
 C.need(not(root/'volume').exists()and not(root/'volume').is_symlink(),'reserved new bootstrap mount point absent');result={};files=overlay(nonce)
 for name,row in files.items():
  p=root/name;C.need(not any(q.is_symlink()for q in(p.parent,*p.parent.parents)),'ordinary overlay ancestors')
  before=None
  if os.path.lexists(p):
   C.need(name=='etc/machine-id'and stat.S_ISREG(p.lstat().st_mode)and p.lstat().st_nlink==1,'only original ordinary machine-id may be replaced');before=dict(mode=stat.S_IMODE(p.stat().st_mode),uid=p.stat().st_uid,gid=p.stat().st_gid,**C.pin(C.read(p,128)))
  p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(row['data']);p.chmod(row['mode']);os.chown(p,0,0)
  result[name]=dict(before=before,after=dict(type='file',mode=row['mode'],uid=0,gid=0,**C.pin(C.read(p))))
 for name in('etc/pacman.conf','etc/systemd/system.conf'):
  p=root/name;st=p.lstat();C.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==st.st_gid==0,'owned full original user config fixture');raw=C.read(p,1024**2);line=('\n# Core7 owned VM user configuration '+nonce+'\n').encode();before=dict(type='file',mode=stat.S_IMODE(st.st_mode),uid=0,gid=0,**C.pin(raw));p.write_bytes(raw+line);p.chmod(before['mode']);os.chown(p,0,0);result[name]=dict(before=before,after=dict(before,**C.pin(raw+line)),append=C.pin(line))
 marker=root/'.dockerenv'
 if os.path.lexists(marker):
  st=marker.lstat();C.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==st.st_gid==0 and st.st_size==0,'only exact inherited empty Docker marker removed from private boot copy');result['.dockerenv']=dict(before=dict(type='file',mode=stat.S_IMODE(st.st_mode),uid=0,gid=0,**C.pin(C.read(marker))),after=None);marker.unlink()
 result.update(J.initialize(root,command))
 return result

def expected_baseline(nodes,overlay):
 """Apply exactly the recorded owned boot/user overlay, with every before join."""
 C.need(type(nodes)is dict and set(overlay)=={'init-core7','etc/machine-id','etc/pacman.conf','etc/systemd/system.conf',*('etc/systemd/system/'+n for n in UNITS),*J.INDEXES}|({'.dockerenv'}if'.dockerenv'in nodes else set()),'whole literal owned boot overlay closure')
 J.validate_overlay(overlay);result=dict(nodes)
 for name,row in overlay.items():
  before=row['before']
  if before is not None:before=dict(before,type='file')
  C.need(result.get(name)==before,'every original overlay before node pin '+name)
  if row['after']is None:result.pop(name)
  else:result[name]=row['after']
 return result
