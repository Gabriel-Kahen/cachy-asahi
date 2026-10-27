#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a private writable original341 ext4 guest root inside one owned container."""
import base64,hashlib,json,os,platform,shutil,stat,subprocess,sys,time
from pathlib import Path

IN=Path('/inputs');OUT=Path('/out');WORK=Path('/tmp/c01-root');ROOT=WORK/'root'
LOCK='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
DISK=8*1024**3

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(path):
 h=hashlib.sha256();size=0
 with Path(path).open('rb') as stream:
  while data:=stream.read(1024**2):h.update(data);size+=len(data)
 return dict(bytes=size,sha256=h.hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def inventory():return subprocess.check_output(['pacman','-Q'],timeout=30).decode().splitlines()
def command(argv,seconds=180):
 result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=seconds,check=False)
 if len(result.stdout)>1024**2:
  # Preserve fixed byte excerpts before the existing output-bound refusal.
  first,last=result.stdout[:4096],result.stdout[-4096:]
  diagnostic=dict(schema=1,status='OUTPUT_BOUND_EXCEEDED_NOT_ACCEPTED',output_bound_bytes=1024**2,
                  command_returncode=result.returncode,output_bytes=len(result.stdout),output_sha256=hashlib.sha256(result.stdout).hexdigest(),
                  first=dict(bytes=len(first),base64=base64.b64encode(first).decode('ascii')),
                  last=dict(bytes=len(last),base64=base64.b64encode(last).decode('ascii')))
  print('C01_CAPTURE_OUTPUT_BOUND '+json.dumps(diagnostic,sort_keys=True,separators=(',',':')),flush=True)
 need(len(result.stdout)<=1024**2,'bounded filesystem command log')
 # Retain bounded merged stderr before propagating the original nonzero status.
 print(result.stdout.decode(errors='replace'),end='',flush=True)
 result.check_returncode()
 return result.stdout

def stage_page_data(root):
 path=Path(root)/'page-data'
 need(not path.exists() and not path.is_symlink(),'reserved static page-probe data path absent')
 path.write_bytes(b'A'*16384+b'B'*16384);path.chmod(0o444)
 return pin(path)

def extract_root(roots):
 # /out is the existing private disk-backed bind; only the root uses /tmp tmpfs.
 archive=OUT/'base.tar'
 fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 original=os.fstat(fd);os.close(fd)
 def owned():
  row=archive.lstat()
  need(stat.S_ISREG(row.st_mode) and row.st_nlink==1 and (row.st_dev,row.st_ino)==(original.st_dev,original.st_ino),'owned private root tar identity')
  return row
 try:
  command(['tar','--one-file-system','--numeric-owner','--acls','--xattrs',
           '--exclude=etc/pacman.d/gnupg','--exclude=var/cache/pacman/pkg','--exclude=var/log','--exclude=var/tmp',
           '-C','/','-cf',str(archive),*roots],300)
  need(0<owned().st_size<=4*1024**3,'finite original341 root tar')
  command(['tar','--numeric-owner','--acls','--xattrs','--xattrs-include=user.*','--xattrs-include=security.capability','--same-owner','-xf',str(archive),'-C',str(ROOT)],180)
 finally:
  owned();archive.unlink()

def main(uid,gid):
 need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64' and os.sysconf('SC_PAGE_SIZE')==4096
      and Path('/.dockerenv').is_file() and os.environ.get('CACHY_ASAHI_C01_CAPTURE16K')=='1','owned native4K capture root required')
 need(not WORK.exists() and OUT.is_dir() and not any(OUT.iterdir()),'fresh private capture work/output')
 selection=json.loads((IN/'selection.json').read_bytes())
 need(selection['host_page_size']==4096 and 0<uid<2**31 and 0<gid<2**31,'observed host page/ordinary owner')
 lock=('\n'.join(sorted(inventory()))+'\n').encode();need(hashlib.sha256(lock).hexdigest()==LOCK and lock==(IN/'packages.lock').read_bytes(),'complete original341 capture inventory')
 sentinels={p:pin(p)['sha256'] for p in selection['base_sentinels']}
 need(sentinels==selection['base_sentinels'],'exact accepted system sentinels before capture')
 WORK.mkdir();ROOT.mkdir()
 try:
  # Only static image directories; never proc/dev/sys/tmp/home or caller bind mounts.
  roots=[n for n in ('usr','etc','var','opt','boot','bin','sbin','lib','lib64','builder-disabled-hooks','builder-packages.lock') if Path('/'+n).exists()]
  need('usr' in roots and 'etc' in roots and 'var' in roots and 'builder-disabled-hooks' in roots,'complete base roots/hook masks')
  extract_root(roots)
  for name,mode in (('dev',0o755),('proc',0o555),('sys',0o555),('run',0o755),('tmp',0o1777),('root',0o700),('home',0o755),('var/tmp',0o1777),('var/log',0o755),('var/cache/pacman/pkg',0o755)):
   path=ROOT/name;path.mkdir(parents=True,exist_ok=True);path.chmod(mode)
  need(not (ROOT/'etc/pacman.d/gnupg').exists(),'ephemeral bootstrap private keyring excluded')
  page_data=stage_page_data(ROOT)
  target=ROOT/'c01';target.mkdir();(target/'output').mkdir()
  for f in ('guest.py','package_variants.py','packages.lock','selection.json'):
   shutil.copyfile(IN/f,target/f)
  shutil.copytree(IN/'packages',target/'packages')
  # Exact original static mmap/mprotect/file-offset source, compiled natively here.
  command(['gcc','-nostdlib','-static','-O2','-fno-stack-protector','-fno-pie','-no-pie',
           '-Wl,-z,max-page-size=65536,-z,common-page-size=16384,-e,_start',str(IN/'smoke.c'),'-o',str(target/'smoke')],60)
  smoke_elf=command(['readelf','-h','-lW',str(target/'smoke')],30)
  need(b'AArch64' in smoke_elf and b'INTERP' not in smoke_elf,'native static page probe')
  nonce=selection['nonce']
  init='''#!/usr/bin/bash
export PATH=/usr/bin:/bin HOME=/tmp LC_ALL=C LANG=C PYTHONDONTWRITEBYTECODE=1
fail() { printf 'C01_INSTALL16K_FAIL NONCE\n'; exec /c01/smoke poweroff; }
/usr/bin/mount -t proc -o nosuid,nodev,noexec proc /proc || fail
/usr/bin/mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || fail
[[ -c /dev/null && -c /dev/console ]] || fail
printf 'UNAME16K %s %s\nGETCONF16K %s\n' "$(uname -m)" "$(uname -r)" "$(getconf PAGESIZE)"
/c01/smoke || fail
/usr/bin/python3 -I -B /c01/guest.py || fail
sync || fail
printf 'C01_INSTALL16K_DONE NONCE\n'
exec /c01/smoke poweroff
'''.replace('NONCE',nonce)
  (target/'init').write_text(init);(target/'init').chmod(0o755)
  need((ROOT/'builder-packages.lock').read_bytes()==lock,'captured original base lock')
  for path,row in sentinels.items():need(pin(ROOT/path.lstrip('/'))['sha256']==row,'captured system sentinel changed')
  disk=OUT/'root.raw'
  with disk.open('wb') as f:f.truncate(DISK)
  command(['mke2fs','-F','-t','ext4','-b','4096','-m','0','-L','C01_ORIGINAL341','-d',str(ROOT),str(disk)],300)
  command(['e2fsck','-f','-n',str(disk)],120)
  # Real filesystem readback before boot, separate from producer-source facts.
  export=WORK/'readback';export.mkdir()
  for i,path in enumerate(('/builder-packages.lock','/c01/selection.json','/page-data','/c01/smoke',*sentinels)):
   saved=export/str(i)
   command(['debugfs','-R','dump '+path+' '+str(saved),str(disk)],60)
   need(saved.read_bytes()==(ROOT/path.lstrip('/')).read_bytes(),'ext4 byte readback differs: '+path)
  result=dict(status='PASS_ORIGINAL341_EXT4_PREPARATION_NOT_GUEST_EXECUTION',host_page_size=os.sysconf('SC_PAGE_SIZE'),
              source_commit=selection['source_commit'],nonce=nonce,accepted_origin=selection['accepted_origin'],
              base_inventory_sha256=LOCK,base_sentinels=sentinels,disk_bytes=DISK,
              filesystem_block_size=4096,static_probe=pin(target/'smoke'),page_data=page_data,
              excluded_private_state=['etc/pacman.d/gnupg','home','root','var/cache/pacman/pkg','var/log','var/tmp'],
              guest_pages='NOT OBSERVED',guest_lifecycle='NOT RUN',kernel_data_source='1c6a2e7a7c6709eb1462cdcb0b449c98fe33d845')
  (OUT/'capture.json').write_bytes(encoded(result))
  for path in OUT.iterdir():os.chown(path,uid,gid);path.chmod(0o600)
 finally:
  shutil.rmtree(WORK)
 need(not WORK.exists(),'owned capture workspace retired')
 result['capture_workspace_absent']=True;(OUT/'capture.json').write_bytes(encoded(result));os.chown(OUT/'capture.json',uid,gid)
 return 0
if __name__=='__main__':raise SystemExit(main(int(sys.argv[1]),int(sys.argv[2])))
