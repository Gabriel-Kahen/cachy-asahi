#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed offline ext4 fixture edits; no ARM code, ALPM or guest execution here."""
import hashlib,json,os,re,secrets,shutil,socket,stat,subprocess,sys
from pathlib import Path
W=Path('/work/assembly');T=Path('/tmp/ui-fixture');D='/var/lib/arm16k-virtio-seat'

def pin(p):
 with Path(p).open('rb') as f:return {'bytes':Path(p).stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def command(label,argv,timeout=60,input=None):
 with (W/(label+'.log')).open('wb') as log:r=subprocess.run(argv,input=input,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
 if r.returncode:raise RuntimeError((label,r.returncode))
def main():
 assert __debug__ and sys.flags.isolated and os.environ.get('CACHY_ARM16K_UI_GLIB290_PREPARE')=='1' and Path('/.dockerenv').is_file()
 fields=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
 assert all(int(fields[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and fields['NoNewPrivs'].strip()=='1'
 assert {n for _,n in socket.if_nameindex()}=={'lo'} and not Path('/dev/kvm').exists()
 assert not any(W.iterdir());T.mkdir(mode=0o700)
 m=json.loads(Path('/work/input-manifest.json').read_text());base=json.loads(Path('/base-prepared.json').read_text())
 assert pin('/base.raw')==m['base_files']['guest.raw']
 for name,ref in m['material_pins'].items():assert pin(Path('/materials')/name)==ref
 raw=W/'guest.raw';command('sparse-clone',['cp','--sparse=always','--reflink=never','/base.raw',str(raw)],180)
 command('grow-owned-sparse',['truncate','-s',str(3*1024**3),str(raw)]);command('grow-owned-ext4',['resize2fs',str(raw)],120)
 nonce=secrets.token_hex(16);password=secrets.token_hex(16)
 result=subprocess.run(['openssl','passwd','-6','-stdin'],input=password.encode(),capture_output=True,timeout=10,check=True);hashed=result.stdout.decode().strip();assert hashed.startswith('$6$')
 command('original-shadow',['debugfs','-R','dump /etc/shadow '+str(T/'shadow.original'),'/base.raw'])
 rows=(T/'shadow.original').read_text().splitlines();assert sum(x.startswith('builder:') for x in rows)==1
 for i,line in enumerate(rows):
  fields=line.split(':')
  if fields[0]=='root':assert fields[1]=='!'
  if fields[0]=='builder':fields[1]=hashed;rows[i]=':'.join(fields)
 (T/'shadow').write_text('\n'.join(rows)+'\n');(T/'nonce').write_text(nonce+'\n')
 edits=[];written={};attrs={};links={};directories=[]
 def directory(path):
  edits.extend(['mkdir '+path,'set_inode_field '+path+' mode '+('040700' if (path.startswith(D)or path=='/var/lib/cachy-asahi-ui-session-reference') else '040755'),'set_inode_field '+path+' uid 0','set_inode_field '+path+' gid 0']);directories.append(path)
 def write(source,destination,mode=0o644,uid=0,gid=0,replace=False):
  assert re.fullmatch('[A-Za-z0-9_/@.+:-]+',str(source)) and re.fullmatch('[A-Za-z0-9_/@.+:-]+',destination)
  if replace:edits.append('rm '+destination)
  edits.extend(['write '+str(source)+' '+destination,'set_inode_field '+destination+' mode 0'+format(0o100000|mode,'o'),'set_inode_field '+destination+' uid '+str(uid),'set_inode_field '+destination+' gid '+str(gid)])
  written[destination]=Path(source);attrs[destination]=(mode,uid,gid)
 def link(path,target):edits.append('symlink '+path+' '+target);links[path]=target
 for p in (D,D+'/materials','/etc/systemd/system/multi-user.target.wants','/etc/systemd/system/getty.target.wants','/etc/systemd/system/arm16k-virtio-seat-observer.service.d','/etc/systemd/system/getty@tty1.service.d','/opt/ui-session','/opt/ui-session/packages','/opt/ui-session/templates','/opt/ui-session/templates/fish','/opt/ui-session/templates/zsh','/opt/ui-session/ownership'):directory(p)
 # These fixed fresh-fixture files are reviewed independently of package payload.
 write(T/'shadow','/etc/shadow',0o600,replace=True);write(T/'nonce','/etc/machine-id',replace=True);write(T/'nonce','/etc/arm16k-systemd-nonce',replace=True);write(T/'nonce','/etc/arm16k-virtio-seat-nonce')
 files=m['guest_files']
 for name,row in files.items():
  prefix={'ui':Path('/code'),'arm':Path('/arm-source'),'x86':Path('/x86-source'),'fixture':Path('/work/fixture-data')}[row['source_root']];src=prefix/row['source'];assert pin(src)==row['pin'];write(src,row['guest_path'],int(row['mode'],8),row.get('uid',0),row.get('gid',0),row.get('replace',False))
 for p in (Path('/work/fixture-data')/'seat').iterdir():
  assert p.is_file()and not p.is_symlink();write(p,D+'/'+p.name,0o600)
 for src in sorted((Path('/work/fixture-data')/'ui').rglob('*')):
  if src.is_dir():
   dest='/opt/ui-session/'+str(src.relative_to('/work/fixture-data/ui'))
   if dest not in directories:directory(dest)
   continue
  assert src.is_file()and not src.is_symlink();dest='/opt/ui-session/'+str(src.relative_to('/work/fixture-data/ui'));write(src,dest,0o644)
 sentinel=Path('/work/fixture-data/UI-unrelated.txt');write(sentinel,'/home/builder/UI-unrelated.txt',0o600,1000,1000)
 for name in m['material_pins']:
  write(Path('/materials')/name,D+'/materials/'+name,0o600)
 link('/etc/systemd/system/multi-user.target.wants/arm16k-seat-install.service','/etc/systemd/system/arm16k-seat-install.service')
 link('/etc/systemd/system/multi-user.target.wants/arm16k-virtio-seat-observer.service','/etc/systemd/system/arm16k-virtio-seat-observer.service')
 link('/etc/systemd/system/multi-user.target.wants/arm16k-ui-fixture.service','/etc/systemd/system/arm16k-ui-fixture.service')
 link('/etc/systemd/system/multi-user.target.wants/arm16k-ui-observer.service','/etc/systemd/system/arm16k-ui-observer.service')
 link('/etc/systemd/system/getty.target.wants/getty@tty1.service','/usr/lib/systemd/system/getty@.service')
 link('/etc/systemd/system/serial-getty@ttyAMA0.service','/dev/null');link('/etc/systemd/system/NetworkManager.service','/dev/null')
 (T/'edits.debugfs').write_text('\n'.join(edits)+'\n');command('fixed-ext4-edits',['debugfs','-w','-f',str(T/'edits.debugfs'),str(raw)],180)
 uuid=nonce[:8]+'-'+nonce[8:12]+'-'+nonce[12:16]+'-'+nonce[16:20]+'-'+nonce[20:];command('fresh-uuid',['tune2fs','-U',uuid,str(raw)]);command('readonly-fs-check',['e2fsck','-fn',str(raw)])
 # Exit0 from debugfs alone is insufficient: verify every regular-file byte/owner.
 for i,(dest,src) in enumerate(written.items()):
  p=T/'readback';p.unlink(missing_ok=True);command('readback-'+str(i),['debugfs','-R','dump '+dest+' '+str(p),str(raw)]);assert pin(p)==pin(src)
  label='stat-'+str(i);command(label,['debugfs','-R','stat '+dest,str(raw)]);text=(W/(label+'.log')).read_text();mode=re.search(r'Mode:\s+([0-7]{4})',text);owner=re.search(r'User:\s+(\d+)\s+Group:\s+(\d+)',text);assert mode and owner and (int(mode[1],8),int(owner[1]),int(owner[2]))==attrs[dest]
 for i,(dest,target) in enumerate(links.items()):
  label='link-'+str(i);command(label,['debugfs','-R','stat '+dest,str(raw)]);text=(W/(label+'.log')).read_text();assert 'Type: symlink' in text and ('Fast link dest: "'+target+'"') in text
 for i,(path,digest) in enumerate({**base['guest_required_pins'],**{k.lstrip('/'):v for k,v in m['additions']['original_file_pins'].items()}}.items()):
  p=T/'stock';p.unlink(missing_ok=True);command('stock-'+str(i),['debugfs','-R','dump /'+path+' '+str(p),str(raw)]);assert pin(p)['sha256']==digest,'original baseline/PAM/udev payload changed'
 for name,src in [('Image','/base-Image'),('kernel.config','/base-config'),('ui_glib_actor.py','/code/ui_glib_actor.py')]:shutil.copyfile(src,W/name)
 (W/'credentials.json').write_text(json.dumps({'username':'builder','password':password})+'\n')
 result={**base,'operation':'arm16k-first-login-ui-glib290-vm-v1','status':'PREPARED_NOT_BOOTED','nonce':nonce,'kernel_version':m['kernel']['kernel_release'],'kernel':m['kernel'],'authority':m['authority'],'lineage':m,'filesystem_uuid':uuid,'files':{name:pin(W/name) for name in ('guest.raw','Image','kernel.config','ui_glib_actor.py')},'fixture_paths':directories+list(written)+list(links),'fixture_regular_readbacks':len(written),'credentials':'fresh private0600; never passed in argv/environment','VM_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN'}
 (W/'prepared.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 for p in W.iterdir():
  if p.is_file():p.chmod(0o600)
 print(json.dumps({'status':'PREPARED_NOT_BOOTED','nonce':nonce,'prepared':pin(W/'prepared.json')}))
if __name__=='__main__':main()
