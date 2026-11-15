#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline ext4/kernel/initramfs assembly only, under fakeroot; no VM launch."""
import hashlib,json,os,secrets,shutil,socket,stat,subprocess,time
from pathlib import Path
W=Path('/work');R=Path('/tmp/tcg-reference-root');I=Path('/opt')
assert Path('/.dockerenv').is_file()and {x[1]for x in socket.if_nameindex()}=={'lo'}
assert W.is_dir()and not any(W.iterdir())and not R.exists()
status=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
assert all(int(status[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and status['NoNewPrivs'].strip()=='1'
assert os.environ.get('FAKEROOTKEY'),'ownership-preserving fakeroot boundary required'

def command(name,argv,timeout=90):
 with (W/(name+'.log')).open('wb')as f:p=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 assert p.returncode==0,(name,p.returncode)

def digest(path):
 with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()

R.mkdir();command('extract-base',['bsdtar','-xpf',str(I/'guest-base.tar.zst'),'-C',str(R)])
nonce=secrets.token_hex(16);user='builder'
for folder in ['dev','proc','sys','run','tmp','root','home/builder','boot','etc/systemd/system/getty.target.wants','etc/systemd/system/sockets.target.wants','usr/local/libexec']:(R/folder).mkdir(parents=True,exist_ok=True)
(R/'tmp').chmod(0o1777);(R/'root').chmod(0o700);(R/'home/builder').chmod(0o700);os.chown(R/'home/builder',1000,1000)
passwd=(R/'etc/passwd').read_text().splitlines();assert not any(x.split(':')[0]==user or x.split(':')[2]=='1000'for x in passwd)
(R/'etc/passwd').write_text('\n'.join(passwd)+f'\n{user}:x:1000:1000:TCG reference TEST user:/home/{user}:/usr/bin/bash\n')
with (R/'etc/group').open('a')as f:f.write(user+':x:1000:\n')
password=secrets.token_urlsafe(24).encode()
hashed=subprocess.run(['openssl','passwd','-6','-stdin'],input=password,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout.decode().strip();assert hashed.startswith('$6$')
shadow=(R/'etc/shadow').read_text().splitlines();(R/'etc/shadow').write_text('\n'.join(shadow)+f'\n{user}:{hashed}:20771:0:99999:7:::\n');(R/'etc/shadow').chmod(0o600)
credentials=W/'credentials.json';credentials.write_text(json.dumps({'username':user,'password':password.decode()},indent=2)+'\n');credentials.chmod(0o600)
(R/'etc/hostname').write_text('cachy-tcg-reference\n');(R/'etc/hosts').write_text('127.0.0.1 localhost cachy-tcg-reference\n::1 localhost\n');(R/'etc/resolv.conf').write_text('# Offline reference VM; no NIC or resolver.\n')
(R/'etc/machine-id').write_text(nonce+'\n');(R/'etc/locale.conf').write_text('LANG=C.UTF-8\n');(R/'etc/tcg-reference-nonce').write_text(nonce+'\n')
(R/'home/builder/.bash_profile').write_text("printf '\\nTCG_SHELL_READY "+nonce+"\\n'\nPS1='tcg$ '\n");(R/'home/builder/.bash_profile').chmod(0o644);os.chown(R/'home/builder/.bash_profile',1000,1000)
(R/'etc/fstab').write_text('/dev/vda / ext4 defaults 0 1\n')
for path,target in [('etc/systemd/system/default.target','/usr/lib/systemd/system/multi-user.target'),('etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service','/usr/lib/systemd/system/serial-getty@.service'),('etc/systemd/system/sockets.target.wants/dbus.socket','/usr/lib/systemd/system/dbus.socket')]:
 p=R/path
 if p.is_symlink():p.unlink()
 assert not p.exists();p.symlink_to(target)
shutil.copyfile(I/'guest-proof.sh',R/'usr/local/libexec/tcg-login-proof');(R/'usr/local/libexec/tcg-login-proof').chmod(0o755)
modules=[p for p in Path('/usr/lib/modules').iterdir()if(p/'vmlinuz').is_file()];assert len(modules)==1
k=modules[0];assert k.name=='7.2.14-arch1-1',k.name
command('target-depmod',['depmod','-a',k.name])
shutil.copytree(k,R/'usr/lib/modules'/k.name,symlinks=True)
kernel=W/'vmlinuz';shutil.copyfile(k/'vmlinuz',kernel)
with kernel.open('rb')as f:f.seek(0x202);assert f.read(4)==b'HdrS','x86 boot protocol header missing'
config=W/'mkinitcpio.conf';config.write_text('MODULES=(virtio_pci virtio_blk ext4)\nBINARIES=()\nFILES=()\nHOOKS=(base udev)\nCOMPRESSION="zstd"\nCOMPRESSION_OPTIONS=(-T1 -3)\n')
command('initramfs',['mkinitcpio','-k',k.name,'-c',str(config),'-g',str(W/'initramfs.img')],120)
command('initramfs-list',['lsinitcpio',str(W/'initramfs.img')])
assert (W/'initramfs.img').stat().st_size<128*1024**2
image=W/'guest.raw'
with image.open('xb')as f:f.truncate(1536*1024**2)
command('ext4-build',['mkfs.ext4','-F','-L','TCG_REFERENCE','-U',nonce[:8]+'-'+nonce[8:12]+'-'+nonce[12:16]+'-'+nonce[16:20]+'-'+nonce[20:],'-d',str(R),str(image)],120)
command('ext4-readonly-check',['e2fsck','-fn',str(image)])
command('guest-home-ownership',['debugfs','-R','stat /home/builder',str(image)])
text=(W/'guest-home-ownership.log').read_text();assert 'User:  1000'in text and 'Group:  1000'in text,text
required=['usr/lib/systemd/systemd','usr/lib/systemd/systemd-logind','usr/bin/login','usr/bin/agetty','usr/lib/systemd/system/serial-getty@.service','etc/pam.d/login','etc/pam.d/system-login']
assert all((R/p).is_file()for p in required)
report={'schema_version':1,'status':'PREPARED_NOT_BOOTED','VM_boot':'NOT RUN','scope':'stock x86 Arch software reference only; ARM/M2/release NOT RUN','nonce':nonce,'kernel_version':k.name,'guest_user_uid':1000,'guest_user':user,'disk_logical_bytes':image.stat().st_size,'disk_allocated_bytes':image.stat().st_blocks*512,'files':{p.name:{'bytes':p.stat().st_size,'sha256':digest(p)}for p in [image,kernel,W/'initramfs.img']},'guest_input_provenance_sha256':digest(I/'tool-provenance.json'),'guest_base_tar_sha256':digest(I/'guest-base.tar.zst'),'guest_required_pins':{p:digest(R/p)for p in required},'guest_package_inventory_source':'exact official OCI base; stock signed kernel modules added; no guest code executed','source_native_hardware_legal_acceptance':'HOLD/NOT RUN'}
shutil.copyfile(I/'tool-provenance.json',W/'tool-provenance.json');(W/'prepared.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
for p in [image,kernel,W/'initramfs.img',W/'prepared.json',W/'tool-provenance.json']:p.chmod(0o600)
shutil.rmtree(R)
print(json.dumps({'status':report['status'],'files':report['files'],'VM_boot':'NOT RUN'}),flush=True)
