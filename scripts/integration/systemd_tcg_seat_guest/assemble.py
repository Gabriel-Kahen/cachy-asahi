#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New offline VT/seat fixture using existing exact base/modules/payload DATA."""
import hashlib,json,os,secrets,shutil,socket,subprocess
from pathlib import Path
I=Path('/opt');W=Path('/work');R=Path('/tmp/tcg-seat-root')
assert __debug__ and Path('/.dockerenv').exists()and os.environ.get('FAKEROOTKEY')and {v for _,v in socket.if_nameindex()}=={'lo'}
caps=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l);assert all(int(caps[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and caps['NoNewPrivs'].strip()=='1'
assert not R.exists()and not any(W.iterdir())
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def command(label,args,timeout=120):
 with(W/(label+'.log')).open('wb')as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 assert r.returncode==0,(label,r.returncode)
contract=json.loads((I/'seat-inputs.json').read_text())
for name,pin in contract['sources'].items():assert sha(I/name)==pin,name
R.mkdir();command('base',['bsdtar','-xpf',str(I/'guest-base.tar.zst'),'-C',str(R)]);command('additions',['bsdtar','-xpf',str(I/'nm-session-additions.tar.zst'),'-C',str(R)])
export=json.loads((I/'nm-session-export.json').read_text())
for rel,ref in export['file_pins'].items():
 p=R/rel
 if 'symlink'in ref:assert p.is_symlink()and os.readlink(p)==ref['symlink']
 elif ref.get('directory'):assert p.is_dir()and not p.is_symlink()and p.stat().st_mode&0o7777==ref['mode']
 else:assert p.is_file()and p.stat().st_size==ref['bytes']and sha(p)==ref['sha256'],rel
command('sysusers',['systemd-sysusers','--root',str(R)])
nonce=secrets.token_hex(16);password=secrets.token_hex(16).encode()
for folder in ['dev','proc','sys','run','tmp','root','boot','home/builder','usr/local/libexec','etc/modules-load.d','etc/systemd/system/getty.target.wants','etc/systemd/system/sockets.target.wants','etc/systemd/system/multi-user.target.wants']:(R/folder).mkdir(parents=True,exist_ok=True)
(R/'tmp').chmod(0o1777);(R/'root').chmod(0o700)
for name,line in [('passwd','builder:x:1000:1000:VT reference TEST user:/home/builder:/usr/bin/bash'),('group','builder:x:1000:')]:
 p=R/'etc'/name;content=p.read_text();assert not any(s.split(':')[0]=='builder'or s.split(':')[2]=='1000'for s in content.splitlines());p.write_text(content+line+'\n')
hashed=subprocess.run(['openssl','passwd','-6','-stdin'],input=password,stdout=subprocess.PIPE,check=True,timeout=10).stdout.decode().strip();assert hashed.startswith('$6$')
p=R/'etc/shadow';p.write_text(p.read_text()+f'builder:{hashed}:20771:0:99999:7:::\n');p.chmod(0o600)
for rel,data in {'etc/hostname':'tcg-real-seat\n','etc/hosts':'127.0.0.1 localhost tcg-real-seat\n::1 localhost\n','etc/resolv.conf':'# Offline reference; no NIC.\n','etc/machine-id':nonce+'\n','etc/locale.conf':'LANG=C.UTF-8\n','etc/vconsole.conf':'KEYMAP=us\n','etc/tcg-reference-nonce':nonce+'\n','etc/fstab':'/dev/vda / ext4 defaults 0 1\n','etc/modules-load.d/seat-reference.conf':'# Exact existing stock virtual VGA driver; guest only.\nbochs\n','home/builder/.bash_profile':"umask 077\nprintf entered > /home/builder/PROFILE_ENTERED\n/usr/bin/python3 -I -B /usr/local/libexec/seat-user-proof.py 2>/home/builder/SEAT_ERROR\nprintf '%s' \"$?\" > /home/builder/PROOF_EXIT_STATUS\nprintf ready > /home/builder/SHELL_RETURNED\nPS1='seat$ '\n"}.items():(R/rel).write_text(data)
for p in(R/'home/builder').iterdir():os.chown(p,1000,1000)
os.chown(R/'home/builder',1000,1000);(R/'home/builder').chmod(0o700)
links=[('default.target','/usr/lib/systemd/system/multi-user.target'),('getty.target.wants/getty@tty1.service','/usr/lib/systemd/system/getty@.service'),('sockets.target.wants/dbus.socket','/usr/lib/systemd/system/dbus.socket'),('multi-user.target.wants/seat-observer.service','/etc/systemd/system/seat-observer.service'),('serial-getty@ttyS0.service','/dev/null')]
for rel,target in links:
 p=R/'etc/systemd/system'/rel
 if p.is_symlink():p.unlink()
 assert not p.exists();p.symlink_to(target)
# No autologin, seat/session override, Polkit rule or PAM edits. Real keyboard
# input goes through stock getty/login on VT1. Serial is observer-only.
for source,dest in [('seat-user-proof.py','usr/local/libexec/seat-user-proof.py'),('seat-observer.py','usr/local/libexec/seat-observer.py'),('seat-observer.service','etc/systemd/system/seat-observer.service'),('seat-input.py','usr/local/libexec/seat-input.py'),('seat-keyboard.py','usr/local/libexec/seat-keyboard.py')]:shutil.copyfile(I/source,R/dest);(R/dest).chmod(0o644 if dest.endswith('.service')else 0o755)
k=Path('/usr/lib/modules/7.2.14-arch1-1');shutil.copytree(k,R/'usr/lib/modules'/k.name,symlinks=True)
command('offline-module-indices',['depmod','-b',str(R),'-a',k.name]);assert (R/'usr/lib/modules'/k.name/'modules.dep.bin').is_file()
for source,dest in [('reference-vmlinuz','vmlinuz'),('reference-initramfs.img','initramfs.img')]:shutil.copyfile(I/source,W/dest)
command('guest-dependencies',['pacman','--root',str(R),'-Dk'])
image=W/'guest.raw'
with image.open('xb')as f:f.truncate(1536*1024**2)
command('mkfs',['mkfs.ext4','-F','-L','TCG_REAL_SEAT','-d',str(R),str(image)]);command('fsck',['e2fsck','-fn',str(image)]);command('home-ownership',['debugfs','-R','stat /home/builder',str(image)]);assert 'User:  1000'in(W/'home-ownership.log').read_text()
assert sha(R/'usr/lib/udev/rules.d/71-seat.rules')=='b57a64ab6c973d0b734dea808e6caf9a49b40739c7c7649784d09bd6d90c36d3'
policy=['usr/lib/udev/rules.d/71-seat.rules','etc/pam.d/login','etc/pam.d/system-login','usr/lib/pam.d/polkit-1','usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy','usr/share/polkit-1/rules.d/50-default.rules','usr/share/polkit-1/rules.d/empower.rules']
credentials=W/'credentials.json';credentials.write_text(json.dumps({'username':'builder','password':password.decode()})+'\n');credentials.chmod(0o600)
report={'schema_version':1,'status':'PREPARED_NOT_BOOTED','scope':'generic x86 real-seat/PAM/Polkit reference; ARM/M2/release NOT RUN','nonce':nonce,'files':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p)}for p in [image,W/'vmlinuz',W/'initramfs.img']},'source_pins':contract['sources'],'original_PAM_policy_pins':{p:sha(R/p)for p in policy},'base_tar_sha256':sha(I/'guest-base.tar.zst'),'package_export_sha256':sha(I/'nm-session-export.json'),'kernel_module_index':'offline depmod -b owned-root only; no host module execution','guest_code_execution':'NOT RUN','disk_allocated_bytes':image.stat().st_blocks*512}
shutil.copyfile(I/'nm-session-export.json',W/'package-export.json');(W/'prepared.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
for p in [image,W/'vmlinuz',W/'initramfs.img',W/'prepared.json']:p.chmod(0o600)
shutil.rmtree(R);print(json.dumps(report),flush=True)
