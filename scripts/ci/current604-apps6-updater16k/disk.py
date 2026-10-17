#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated original producer image → bounded owned ext4 files; no host mount."""
import os,shutil,stat,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import cap_scope

def command(argv,seconds=600):
 p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds);C.need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=2*1024**2,'owned disk command refused: '+str(argv[0]))

def apis():
 # All updater root/copy/aux/checkpoint source bodies remain the generated exact
 # original Apps6 adapter bodies. Capability metadata is an additional roundtrip.
 scope=C.load('scope','/persistent_scope.py');roots,copier,resolver,driver=scope._apis(Path('/upgrade-code'))
 return scope,roots,copier,None

def limits(roots,seconds):
 conf=C.decode(C.read('/upgrade-config.json'))['scale']['limits']
 return roots.Limits(deadline=time.monotonic()+seconds,max_nodes=conf['root_nodes'],max_bytes=conf['root_bytes'],max_file_bytes=conf['file_bytes'],max_package_files=conf['package_files'])

def prepare(s):
 out=Path('/measurement');C.need(not any(out.iterdir()) and shutil.disk_usage(out).free>=48*1024**3,'fresh48GiB owned staging reserve')
 stage=out/'stage';stage.mkdir(mode=0o700);C.save(out/'stage-owner.json',dict(nonce=s['nonce'],inode=[stage.stat().st_dev,stage.stat().st_ino]));boot=stage/'boot';data=stage/'data';data.mkdir()
 scope,roots,copier,caps=apis();budget=limits(roots,900)
 policy=scope.mount_policy(Path('/'),boot,scope.mounts(scope._mount_table()))
 before,_=scope.source_manifest(Path('/'),budget,roots,policy)
 caps=cap_scope.derive(C.read('/source/scripts/apps/file_capabilities.py'),set(policy['observed_mounts'])|scope.RUNTIME);mapping=caps.observe(Path('/'),cap_scope.nodes(before),budget)
 copy=copier.copy_data(Path('/'),boot,limits=budget,excluded=scope.RUNTIME|(scope.INFRASTRUCTURE&set(policy['observed_mounts']))|scope.MOUNT_FILES,absolute_paths=True)
 C.need(not copy['unsupported_counts'],'source data copy must be complete');scope._restore_boundaries(Path('/'),boot,before,roots,copier,budget)
 measured=roots.observe(boot,limits=budget,hardlinks='generic-development-internal',absolute_paths=True);C.need(measured['complete'] is True and measured['nodes']==before,'complete original574 node/content/hardlink copy')
 caps.restore(boot,cap_scope.nodes(measured['nodes']),mapping,budget);after,_=scope.source_manifest(Path('/'),budget,roots,policy);C.need(before==after and caps.observe(Path('/'),cap_scope.nodes(after),budget)==mapping,'complete original source preserved during staging')
 for dest in (*s['bindings'],'/measurement','/workspace','/source'):
  name=dest.lstrip('/');source=Path(dest);target=data/name
  C.need(not target.exists() and not target.is_symlink(),'fresh staged infrastructure role')
  if dest=='/measurement':target.mkdir(mode=0o700)
  elif dest=='/workspace':
   target.mkdir();
   for n,pin in s['runner_files'].items():C.need(C.row(Path('/workspace')/n)==pin,'exact own source');shutil.copyfile(Path('/workspace')/n,target/n)
  elif dest=='/source':
   target.mkdir()
   for n,pin in s['source_files'].items():
    src=source/C.relative(n);C.need(C.row(src)==pin,'exact support source');q=target/n;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,q)
  elif source.is_dir():command(['/usr/bin/cp','-a','--reflink=never','--',source,target],900)
  else:target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target,follow_symlinks=False)
  q=boot/name
  if not q.exists():q.mkdir(mode=0o755) if target.is_dir() else q.touch()
 s=dict(s,capabilities_sha256=C.sha(C.encoded(mapping)))
 C.save(data/'workspace/input-map.json',C.decode(C.read('/workspace/input-map.json',16*1024**2)));
 C.save(data/'workspace/selection.json',s);C.save(data/'workspace/baseline-nodes.json',before);C.save(data/'workspace/capabilities.json',mapping)
 # Recreate the original literal mounted infrastructure and discard raw aliases
 # before dropping authority. No physical input/network/card devices exist.
 init=['#!/usr/bin/bash','set -euo pipefail','export PATH=/usr/bin:/bin LC_ALL=C LANG=C','mount -t proc -o ro,nosuid,nodev,noexec proc /proc','mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys','mount -t devtmpfs -o nosuid devtmpfs /dev','mount -t tmpfs -o nosuid,nodev,size=512m,mode=1777 tmpfs /tmp','mount -t tmpfs -o nosuid,nodev,size=64m,mode=755 tmpfs /run','mkdir /volume','mount -t ext4 -o rw,nosuid,nodev /dev/vdb /volume']
 for dest in (*s['bindings'],'/measurement','/workspace','/source'):
  init.append('mount --bind /volume'+dest+' '+dest)
  if dest not in ('/out','/measurement','/upgrade-signing'):init.append('mount -o remount,bind,ro '+dest)
 init+=['umount /volume','rmdir /volume','umount /dev','mount -t tmpfs -o nosuid,size=1m,mode=755 tmpfs /dev','mknod -m 666 /dev/null c 1 3','mknod -m 666 /dev/zero c 1 5','mknod -m 666 /dev/random c 1 8','mknod -m 666 /dev/urandom c 1 9','rm /init-updater16k','exec /usr/bin/python3 -I -B /workspace/guest.py']
 C.need(not (boot/'init-updater16k').exists() and not (boot/'volume').exists(),'reserved VM bootstrap names absent');(boot/'init-updater16k').write_text('\n'.join(init)+'\n');(boot/'init-updater16k').chmod(0o755)
 audit=C.load('elf_audit','/source/scripts/ci/managed-gui-generic16k/elf_audit.py');reader=C.load('elf_reader','/source/scripts/virtual/generic16k/fixture.py');elf=audit.audit(boot,reader);C.save(data/'workspace/boot-elf16k.json',elf)
 for name,size in (('boot',16*1024**3),('data',24*1024**3)):
  root=stage/name;allocated=sum(p.lstat().st_blocks*512 for p in root.rglob('*'));C.need(allocated<=10*1024**3 and shutil.disk_usage(out).free>=allocated+8*1024**3,'finite source/disk allocation')
  image=out/(name+'.raw')
  with image.open('xb') as f:f.truncate(size)
  command(['/usr/bin/mkfs.ext4','-F','-b','4096','-m','0','-L','APPS6_'+name.upper(),'-d',root,image])
 shutil.rmtree(stage);C.save(out/'prepared.json',dict(status='PREPARED_NOT_EXECUTED',boot=C.row(out/'boot.raw'),data=C.row(out/'data.raw'),capabilities_sha256=s['capabilities_sha256'],source_nodes_sha256=C.sha(C.encoded(before))))
 for p in out.iterdir():os.chown(p,s['uid'],s['gid'])

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CAA_APPS6_UPDATE16K_PREPARE')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline preparation/export only')
 s=C.decode(C.read('/workspace/selection.json'));role=sys.argv[1]
 if role=='prepare':return prepare(s)
 if role=='scrub':
  p=Path('/measurement/stage');v=C.decode(C.read('/measurement/stage-owner.json'));info=p.lstat();C.need(v==dict(nonce=s['nonce'],inode=[info.st_dev,info.st_ino]) and stat.S_ISDIR(info.st_mode) and not p.is_mount() and shutil.rmtree.avoids_symlink_attacks,'exact recorded stage inode');shutil.rmtree(p);return
 C.need(role=='export','closed stage role');files=C.decode(C.read('/workspace/guest-files.json'));C.need(set(files)=={'result.json','updater16k-worker.json','updater16k-caller.stdout','updater16k-caller.stderr'} and sum(v['bytes'] for v in files.values())<=8*1024**2,'closed original transaction result')
 out=Path('/measurement/export');out.mkdir(mode=0o700)
 for n,pin in files.items():
  command(['/usr/bin/debugfs','-R','dump /out/'+n+' '+str(out/n),'/measurement/data.raw'],120);C.need(C.row(out/n)==pin,'original guest export bytes');os.chown(out/n,s['uid'],s['gid'])
 os.chown(out,s['uid'],s['gid'])
if __name__=='__main__':main()
