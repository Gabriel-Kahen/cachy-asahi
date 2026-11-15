#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Only inside a separately admitted owned container; no guest or host install."""
import datetime,importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
_spec=importlib.util.spec_from_file_location('virtio_image_contract',Path(__file__).with_name('contract.py'));C=importlib.util.module_from_spec(_spec);exec(compile(Path(__file__).with_name('contract.py').read_bytes(),str(Path(__file__).with_name('contract.py')),'exec'),C.__dict__)

def load(path):
 s=importlib.util.spec_from_file_location('virtio_owned_process',path);m=importlib.util.module_from_spec(s);exec(compile(Path(path).read_bytes(),str(path),'exec'),m.__dict__);return m

def main():
 need=C.need;v=C.lock();need(sys.version_info>=(3,14)and sys.flags.isolated and __debug__ and os.environ.get('CACHY_VIRTIO_TOOL_IMAGE')=='ROOT_ADMITTED_V1','explicit isolated image actor only');stage=sys.argv[1];need(stage in('install','probe'),'fixed stage');out=Path('/receipts');report=dict(stage=stage,status='HOLD',commands=[],guest_boot='NOT RUN');O=load('/runtime/owned_process.py');O.prepare();deadline=time.monotonic()+240
 def command(label,argv,cap=120):
  need(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL and 2<cap<=180 and time.monotonic()+cap<=deadline,'owned command launch bounds');child=None
  try:
   child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);r=O.supervise(child,cap=cap,retirement=1,grace=.2,max_output=1024**2,log_fd=None)
  except BaseException:
   if child is not None and child.returncode is None and child._child_created:O.supervise(child,cap=1.5,retirement=.5,grace=.1,max_output=65536,log_fd=None)
   raise
  raw=r.pop('output',b'');(out/(label+'.log')).write_bytes(raw);report['commands'].append(dict(label=label,argv=argv,retirement=r,output=C.pin(raw)));need(r['passed']and r['exit']==0 and r['ownership']=='REAPED'and r['group_census']=='EMPTY_TWICE','natural exact command retirement');return raw
 try:
  C.checked('/runtime/owned_process.py',v['runtime']['owned_process.py']);C.checked('/usr/bin/qemu-system-aarch64',v['qemu']);need(v['module']['stamp'].encode()in C.read(Path('/usr/bin/qemu-system-aarch64')),'QEMU module loader ABI stamp')
  if stage=='install':
   C.parent(C.local('/var/lib/pacman/local'));p=Path('/packages')/v['package']['filename'];C.archive(p);C.checked(str(p)+'.sig',v['package']['signature'])
   status=command('signature',['gpg','--batch','--no-options','--homedir','/etc/pacman.d/gnupg','--no-auto-key-retrieve','--status-fd','1','--verify',str(p)+'.sig',str(p)]);report['signature']=C.signed(status)
   command('dependencies',['pacman','-T','glibc','pixman','libpixman-1.so=0-64','qemu-common=11.1.3-1'])
   mask=Path('/tmp/masked-hooks');mask.mkdir()
   for base in('/usr/share/libalpm/hooks','/etc/pacman.d/hooks'):
    for hook in Path(base).glob('*.hook'):
     target=mask/hook.name
     if not target.exists()and not target.is_symlink():target.symlink_to('/dev/null')
   config=Path('/tmp/install.conf');config.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
   command('install',['pacman','--config',str(config),'--hookdir',str(mask),'--noscriptlet','--noconfirm','-U',str(p)])
   C.successor(C.local('/var/lib/pacman/local'));C.checked('/'+v['module']['path'],v['module']);command('agent-retirement',['gpgconf','--homedir','/etc/pacman.d/gnupg','--kill','gpg-agent'])
   report['status']='EXACT_OFFLINE_ONE_PACKAGE_INSTALLED'
  else:
   C.successor(C.local('/var/lib/pacman/local'));module=C.checked('/'+v['module']['path'],v['module']);need(C.elf(module)==dict(needed=v['module']['needed'],stamps=[v['module']['stamp']]),'installed module ABI')
   for soname,row in v['providers'].items():C.checked('/'+row['path'],row)
   version=command('qemu-version',['/usr/bin/qemu-system-aarch64','--version'],15);need(version.startswith(b'QEMU emulator version 11.1.3'),'actual matching QEMU version')
   raw=command('device-help',['/usr/bin/qemu-system-aarch64','-device','help'],15);report.update(status='THREE_ACTUAL_VIRTIO_DEVICES_OBSERVED',required_devices=C.devices(raw),device_help=C.pin(raw),actual_observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),qemu=v['qemu'],module=v['module'],providers=v['providers'])
  report['status_before_retirement']=report['status']
  for _ in range(2):need(sorted(n for n in os.listdir('/proc')if n.isdecimal())==['1'],'owned container has no leftover child');time.sleep(.05)
  report['children_absent_twice']=True
 except BaseException as error:report.update(status='HOLD',failure=dict(type=type(error).__name__,message=str(error)[:1000]));raise
 finally:(out/'actor-result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
if __name__=='__main__':main()
