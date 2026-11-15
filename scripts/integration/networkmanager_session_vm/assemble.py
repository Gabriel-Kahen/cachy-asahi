#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh offline NM full-system guest assembly under fakeroot; never boots."""
import hashlib,json,os,secrets,shutil,socket,subprocess
from pathlib import Path
I=Path('/opt');W=Path('/work');R=Path('/tmp/nm-session-root')
assert __debug__ and Path('/.dockerenv').is_file()and os.environ.get('FAKEROOTKEY')and {v for _,v in socket.if_nameindex()}=={'lo'}
caps=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
assert all(int(caps[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and caps['NoNewPrivs'].strip()=='1'
assert not R.exists()and not any(W.iterdir())
def command(label,args,timeout=120):
 with (W/(label+'.log')).open('wb')as log:p=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
 assert p.returncode==0,(label,p.returncode)
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
source_contract=json.loads((I/'nm-session-inputs.json').read_text())
for relative,ref in source_contract['runtime_sources'].items():assert sha(I/relative)==ref,relative
R.mkdir();command('base',['bsdtar','-xpf',str(I/'guest-base.tar.zst'),'-C',str(R)]);command('additions',['bsdtar','-xpf',str(I/'nm-session-additions.tar.zst'),'-C',str(R)])
export=json.loads((I/'nm-session-export.json').read_text())
for rel,ref in export['file_pins'].items():
 f=R/rel
 if 'symlink'in ref:assert f.is_symlink()and os.readlink(f)==ref['symlink']
 elif ref.get('directory'):assert f.is_dir()and not f.is_symlink()and f.stat().st_mode&0o7777==ref['mode']and f.stat().st_uid==ref['uid']and f.stat().st_gid==ref['gid'],rel
 else:assert f.is_file()and f.stat().st_size==ref['bytes']and sha(f)==ref['sha256'],rel
# Standard offline account declarations only; no PAM/rules modification.
command('sysusers',['systemd-sysusers','--root',str(R)])
nonce=secrets.token_hex(16);password=secrets.token_urlsafe(24).encode()
for folder in ['dev','proc','sys','run','tmp','root','boot','home/builder','usr/local/libexec','etc/systemd/system/getty.target.wants','etc/systemd/system/sockets.target.wants','etc/systemd/system/multi-user.target.wants','etc/NetworkManager/system-connections']:(R/folder).mkdir(parents=True,exist_ok=True)
(R/'tmp').chmod(0o1777);(R/'root').chmod(0o700)
for file,lines in [('passwd',['builder:x:1000:1000:NM session TEST user:/home/builder:/usr/bin/bash','fixture:x:1001:1001:Foreign profile TEST user:/nonexistent:/usr/bin/nologin']),('group',['builder:x:1000:','fixture:x:1001:'])]:
 p=R/'etc'/file;text=p.read_text();assert not any(x.split(':')[0]in {'builder','fixture'}or x.split(':')[2]in {'1000','1001'}for x in text.splitlines());p.write_text(text+'\n'.join(lines)+'\n')
hashed=subprocess.run(['openssl','passwd','-6','-stdin'],input=password,stdout=subprocess.PIPE,check=True,timeout=10).stdout.decode().strip();assert hashed.startswith('$6$')
p=R/'etc/shadow';p.write_text(p.read_text()+f'builder:{hashed}:20771:0:99999:7:::\nfixture:!:20771:0:99999:7:::\n');p.chmod(0o600)
for rel,data in {'etc/hostname':'nm-session-reference\n','etc/hosts':'127.0.0.1 localhost nm-session-reference\n::1 localhost\n','etc/resolv.conf':'# Offline reference; no NIC.\n','etc/machine-id':nonce+'\n','etc/locale.conf':'LANG=C.UTF-8\n','etc/tcg-reference-nonce':nonce+'\n','etc/fstab':'/dev/vda / ext4 defaults 0 1\n','home/builder/.bash_profile':"printf '\\nTCG_SHELL_READY "+nonce+"\\n'\nPS1='tcg$ '\n",'home/builder/user-config.txt':'user-owned NM session fixture\n'}.items():(R/rel).write_text(data)
for p in (R/'home/builder').iterdir():os.chown(p,1000,1000)
os.chown(R/'home/builder',1000,1000);(R/'home/builder').chmod(0o700)
for rel,target in [('default.target','/usr/lib/systemd/system/multi-user.target'),('getty.target.wants/serial-getty@ttyS0.service','/usr/lib/systemd/system/serial-getty@.service'),('sockets.target.wants/dbus.socket','/usr/lib/systemd/system/dbus.socket'),('multi-user.target.wants/NetworkManager.service','/usr/lib/systemd/system/NetworkManager.service'),('multi-user.target.wants/nm-session-fixture.service','/etc/systemd/system/nm-session-fixture.service')]:
 p=R/'etc/systemd/system'/rel
 if p.is_symlink():p.unlink()
 assert not p.exists();p.symlink_to(target)
for name in ['fixture.py','client.py']:
 shutil.copyfile(I/('nm-session-'+name),R/'usr/local/libexec'/('nm-session-'+name));(R/'usr/local/libexec'/('nm-session-'+name)).chmod(0o755)
shutil.copyfile(I/'nm-session-session-proof.sh',R/'usr/local/libexec/tcg-reference-session-proof');(R/'usr/local/libexec/tcg-reference-session-proof').chmod(0o755)
(R/'usr/local/libexec/tcg-login-proof').write_text('#!/usr/bin/bash\n/usr/bin/python3 -I -B /usr/local/libexec/nm-session-client.py\nexec /usr/local/libexec/tcg-reference-session-proof\n');(R/'usr/local/libexec/tcg-login-proof').chmod(0o755)
shutil.copyfile(I/'nm-session-fixture.service',R/'etc/systemd/system/nm-session-fixture.service')
for name,uuid,permission in [('system','e3140000-0000-4000-8000-000000000021',''),('foreign','e3140000-0000-4000-8000-000000000022','user:fixture:;')]:
 p=R/'etc/NetworkManager/system-connections'/(name+'-fixture.nmconnection');p.write_text('[connection]\nid=TEST-session-'+name+'\nuuid='+uuid+'\ntype=ethernet\ninterface-name=cachy-absent0\nautoconnect=false\npermissions='+permission+'\n\n[ethernet]\n\n[ipv4]\nmethod=disabled\n\n[ipv6]\nmethod=disabled\n');p.chmod(0o600)
# Kernel/modules/initrd are exact fixed-substrate bytes; no host autodetection.
k=Path('/usr/lib/modules/7.2.14-arch1-1');assert (k/'vmlinuz').is_file();shutil.copytree(k,R/'usr/lib/modules'/k.name,symlinks=True)
shutil.copyfile(I/'reference-vmlinuz',W/'vmlinuz');shutil.copyfile(I/'reference-initramfs.img',W/'initramfs.img')
image=W/'guest.raw'
with image.open('xb')as f:f.truncate(1536*1024**2)
command('mkfs',['mkfs.ext4','-F','-L','NM_SESSION','-d',str(R),str(image)]);command('fsck',['e2fsck','-fn',str(image)])
command('guest-home',['debugfs','-R','stat /home/builder',str(image)]);assert 'User:  1000'in(W/'guest-home.log').read_text()
# Metadata-only dependency check against actual selected local ALPM database.
command('guest-dependencies',['pacman','--root',str(R),'-Dk'])
protected=['etc/pam.d/login','etc/pam.d/system-login','usr/lib/pam.d/polkit-1','usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy','usr/share/polkit-1/rules.d/50-default.rules','usr/lib/systemd/system/NetworkManager.service','usr/lib/systemd/system/polkit.service']
assert all((R/p).is_file()for p in protected)
credentials=W/'credentials.json';credentials.write_text(json.dumps({'username':'builder','password':password.decode()})+'\n');credentials.chmod(0o600)
report={'schema_version':1,'status':'PREPARED_NOT_BOOTED','VM_boot':'NOT RUN','scope':'fresh x86 full-system NM/session fixture; ARM/M2/release NOT RUN','nonce':nonce,'guest_user':'builder','guest_user_uid':1000,'files':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p)}for p in [image,W/'vmlinuz',W/'initramfs.img']},'fixed_policy_PAM_unit_pins':{p:sha(R/p)for p in protected},'runtime_source_pins':source_contract['runtime_sources'],'package_export_sha256':sha(I/'nm-session-export.json'),'base_tar_sha256':sha(I/'guest-base.tar.zst'),'guest_dependency_check':'PASS pacman --root <owned offline root> -Dk','guest_code_execution':'NOT RUN','disk_allocated_bytes':image.stat().st_blocks*512}
shutil.copyfile(I/'nm-session-export.json',W/'package-export.json');(W/'prepared.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
for p in [image,W/'vmlinuz',W/'initramfs.img',W/'prepared.json']:p.chmod(0o600)
shutil.rmtree(R);print(json.dumps(report),flush=True)
