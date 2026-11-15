#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Owned offline ext4 edits only. Never run an ARM program or launch a guest."""
import hashlib,json,os,re,secrets,shutil,socket,stat,subprocess,sys
from pathlib import Path
W=Path('/work/assembly');T=Path('/tmp/project-fixture');D='/var/lib/arm16k-project-lifecycle'


def pin(path):
 with path.open('rb')as stream:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}


def command(label,argv,timeout=60,input=None):
 with (W/(label+'.log')).open('wb')as log:result=subprocess.run(argv,input=input,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
 if result.returncode:raise RuntimeError((label,result.returncode))


def main():
 assert __debug__ and sys.flags.isolated and os.environ.get('CACHY_ARM16K_PROJECT_PREPARE')=='1'and Path('/.dockerenv').is_file()
 status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
 assert all(int(status[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb'))and status['NoNewPrivs'].strip()=='1'
 assert {row[1]for row in socket.if_nameindex()}=={'lo'}and not Path('/dev/kvm').exists()
 assert not any(W.iterdir());T.mkdir(mode=0o700)
 manifest=json.loads(Path('/work/input-manifest.json').read_text());base=json.loads(Path('/base-prepared.json').read_text())
 assert pin(Path('/base.raw'))==manifest['base_files']['guest.raw']
 for name,ref in manifest['materials'].items():assert pin(Path('/materials')/name)=={k:ref[k]for k in ('bytes','sha256')}
 raw=W/'guest.raw';command('sparse-clone',['cp','--sparse=always','--reflink=never','/base.raw',str(raw)],180)
 nonce=secrets.token_hex(16);password=secrets.token_urlsafe(24)
 hashed=subprocess.run(['openssl','passwd','-6','-stdin'],input=password.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True).stdout.decode().strip();assert hashed.startswith('$6$')
 command('read-original-shadow',['debugfs','-R','dump /etc/shadow '+str(T/'shadow.original'),'/base.raw'])
 rows=(T/'shadow.original').read_text().splitlines();assert sum(line.startswith('builder:')for line in rows)==1
 for i,line in enumerate(rows):
  fields=line.split(':')
  if fields[0]=='builder':fields[1]=hashed;rows[i]=':'.join(fields)
  if fields[0]=='root':assert fields[1]=='!'
 (T/'shadow').write_text('\n'.join(rows)+'\n')
 command('read-original-proof',['debugfs','-R','dump /usr/local/libexec/arm16k-login-proof '+str(T/'proof.original'),'/base.raw'])
 assert pin(T/'proof.original')==manifest['baseline_proof_script']
 (T/'nonce').write_text(nonce+'\n');(T/'machine-id').write_text(nonce+'\n')
 (T/'profile').write_text("printf '\\nARM16K_SHELL_READY "+nonce+"\\n'\nPS1='arm16k$ '\n")
 unit='''[Unit]
Description=Exact disposable ARM16K project lifecycle TEST fixture
After=systemd-tmpfiles-setup.service systemd-logind.service dbus.service systemd-user-sessions.service
Wants=systemd-logind.service dbus.service
ConditionKernelCommandLine=arm16k_systemd_nonce=NONCE
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/bash /usr/local/libexec/arm16k-project-lifecycle-root
TimeoutStartSec=240
KillMode=control-group
MemoryMax=768M
TasksMax=96
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
'''.replace('NONCE',nonce)
 (T/'unit').write_text(unit)
 edits=[];fixture=[];attributes={}
 def directory(path):edits.append('mkdir '+path);fixture.append(path)
 def write(source,destination,mode=0o644,uid=0,gid=0,replace=False):
  assert all(c.isalnum()or c in '/._:-'for c in str(source)+destination)
  if replace:edits.append('rm '+destination)
  edits.extend(['write '+str(source)+' '+destination,'set_inode_field '+destination+' mode 0'+format(0o100000|mode,'o'),'set_inode_field '+destination+' uid '+str(uid),'set_inode_field '+destination+' gid '+str(gid)])
  fixture.append(destination);attributes[destination]=(mode,uid,gid)
 directory(D);directory(D+'/materials');directory('/etc/systemd/system/multi-user.target.wants')
 write(T/'shadow','/etc/shadow',0o600,replace=True)
 write(T/'machine-id','/etc/machine-id',replace=True)
 write(T/'nonce','/etc/arm16k-systemd-nonce',replace=True);write(T/'nonce','/etc/arm16k-project-lifecycle-nonce')
 write(T/'profile','/home/builder/.bash_profile',uid=1000,gid=1000,replace=True)
 write(T/'proof.original','/usr/local/libexec/arm16k-login-proof-baseline',0o755)
 write(Path('/code/guest-proof.sh'),'/usr/local/libexec/arm16k-login-proof',0o755,replace=True)
 write(Path('/code/guest-root.sh'),'/usr/local/libexec/arm16k-project-lifecycle-root',0o755)
 write(T/'unit','/usr/lib/systemd/system/arm16k-project-lifecycle.service')
 for name in ('expected111.lock','expected113.lock','materials.sha256','project-payload.sha256','project-metadata.lock','pacman.conf','expected-workload.env','signature-dates.lock'):
  write(Path('/work/fixture-data')/name,D+'/'+name)
 write(Path('/code/guest-workload.sh'),D+'/guest-workload.sh',0o755)
 for name in manifest['workload_fixtures']:write(Path('/work/fixture-data')/name,D+'/'+name)
 write(Path('/code/guest-runtime.sh'),D+'/guest-runtime.sh')
 for name in ('gpg-receipts.sh','rtc-clock.sh','durable.sh'):write(Path('/code')/name,D+'/'+name)
 for name in manifest['materials']:write(Path('/materials')/name,D+'/materials/'+name)
 edits.append('symlink /etc/systemd/system/multi-user.target.wants/arm16k-project-lifecycle.service /usr/lib/systemd/system/arm16k-project-lifecycle.service')
 fixture.append('/etc/systemd/system/multi-user.target.wants/arm16k-project-lifecycle.service')
 (T/'edits.debugfs').write_text('\n'.join(edits)+'\n');command('fixture-ext4-edit',['debugfs','-w','-f',str(T/'edits.debugfs'),str(raw)],180)
 uuid=nonce[:8]+'-'+nonce[8:12]+'-'+nonce[12:16]+'-'+nonce[16:20]+'-'+nonce[20:]
 command('fresh-filesystem-uuid',['tune2fs','-U',uuid,str(raw)])
 command('readonly-ext4-check',['e2fsck','-fn',str(raw)])
 for path,digest in base['guest_required_pins'].items():
  output=T/'stock-file';output.unlink(missing_ok=True);command('stock-'+path.replace('/','_'),['debugfs','-R','dump /'+path+' '+str(output),str(raw)])
  assert pin(output)['sha256']==digest,'stock baseline payload changed'
 # Independently read back every injected regular file: debugfs can report errors
 # while returning0, so command status alone never establishes a completed edit.
 written={line.split(' ',2)[2]:Path(line.split(' ',2)[1])for line in edits if line.startswith('write ')}
 for i,(destination,source)in enumerate(written.items()):
  output=T/'written-file';output.unlink(missing_ok=True);command('fixture-readback-'+str(i),['debugfs','-R','dump '+destination+' '+str(output),str(raw)])
  assert pin(output)==pin(source),'injected fixture readback differs'
  command('fixture-stat-'+str(i),['debugfs','-R','stat '+destination,str(raw)])
  text=(W/('fixture-stat-'+str(i)+'.log')).read_text();mode=re.search(r'Mode:\s+([0-7]{4})',text);owner=re.search(r'User:\s+(\d+)\s+Group:\s+(\d+)',text)
  assert mode and owner and(int(mode[1],8),int(owner[1]),int(owner[2]))==attributes[destination],'fixture mode/owner readback differs'
 shutil.copyfile('/code/rtc_actor.py',W/'rtc_actor.py')
 for filename,source in (('Image','/base-Image'),('kernel.config','/base-config')):shutil.copyfile(source,W/filename)
 credentials=W/'credentials.json';credentials.write_text(json.dumps({'username':'builder','password':password},indent=2)+'\n');credentials.chmod(0o600)
 report={**base,'nonce':nonce,'status':'PREPARED_NOT_BOOTED','VM_boot':'NOT RUN','operation':'arm16k-c01-baseline-lto-rtc-v1',
  'provenance':{**base['provenance'],'original_kernel_is_historical':True,'selected_rtc_kernel':manifest['rtc_bundle'],'project_lifecycle':manifest},'base_first_boot':'separate Root reference passed; this fresh clone NOT BOOTED',
  'fixture_paths':fixture,'fixture_readback_files':len(written),'filesystem_uuid':uuid,'disk_allocated_bytes':raw.stat().st_blocks*512,
  'kernel_version':manifest['rtc_bundle']['kernel_release'],'rtc_bundle':manifest['rtc_bundle'],'rtc_authority':manifest['rtc_authority'],'fresh_signing':manifest['fresh_signing'],'files':{p.name:pin(p)for p in (raw,W/'Image',W/'kernel.config',W/'rtc_actor.py')},'native16K':'NOT RUN','M2':'NOT RUN'}
 (W/'prepared.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 for path in W.iterdir():
  if path.is_file():path.chmod(0o600)
 print(json.dumps({'status':report['status'],'operation':report['operation'],'files':report['files'],'VM_boot':'NOT RUN'}),flush=True)


if __name__=='__main__':main()
