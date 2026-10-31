# SPDX-License-Identifier: MIT
"""No mutating guest operation is reachable from a host/source-only control."""
import os,re,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C

def kernel_fields(raw):
 C.need(type(raw)is str and len(raw)<=16384,'bounded actual kernel command line')
 rows=raw.split();result={}
 for name in('caa_core_vm','caa_core_phase'):
  values=[x.split('=',1)[1]for x in rows if x.startswith(name+'=')];C.need(len(values)==1,'one owned kernel selector '+name);result[name]=values[0]
 C.need(re.fullmatch('[0-9a-f]{32}',result['caa_core_vm'])and result['caa_core_phase']in('1','2'),'finite literal guest selectors');return result

def guard(s,role):
 C.selection(s);C.need(role in('bootstrap','worker','observer','hook','finish'),'closed foreground guest role')
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'actual root ARM64 16K guest');C.need(os.uname().release==s['kernel']['profile']['release'],'exact accepted kernel release on actual boot')
 fields=kernel_fields(Path('/proc/cmdline').read_text());C.need(fields['caa_core_vm']==s['nonce'],'actual kernel/selection nonce join')
 C.need(not os.path.lexists('/.dockerenv')and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'genuine no-network VM; no Docker marker')
 root=Path('/').stat();C.need(root.st_ino==2 and os.major(root.st_dev)>0,'actual ext4 root inode')
 C.need(Path('/sys/class/block/vda/serial').read_text().strip()=='core7-'+s['nonce'],'exact owned boot block serial')
 C.need(Path('/sys/class/block/vdb/serial').read_text().strip()=='core7-data-'+s['nonce'],'exact owned data block serial')
 C.need(Path('/etc/machine-id').read_text()==s['nonce']+'\n','source-owned unique machine id')
 mounts=Path('/proc/self/mountinfo').read_text();C.need(len(mounts)<=1024**2,'bounded complete mount table')
 rows=[];options={}
 for line in mounts.splitlines():
  left,right=line.split(' - ',1);parts=left.split();tail=right.split();rows.append((parts[4],tail[0]));options[parts[4]]=parts[5].split(',')
 required={'/':'ext4','/proc':'proc','/sys':'sysfs','/dev':'devtmpfs','/dev/pts':'devpts','/sys/fs/cgroup':'cgroup2','/run':'tmpfs','/tmp':'tmpfs'}
 for path,fs in required.items():C.need([v for p,v in rows if p==path]==[fs],'one genuine guest mount '+path)
 data_device=Path('/sys/class/block/vdb/dev').read_text().strip().split(':');C.need(len(data_device)==2 and all(n.isdigit()for n in data_device),'actual data block device number');data_dev=os.makedev(*map(int,data_device))
 for name in('/inputs','/out','/upgrade-code','/upgrade-config.json','/persistent_scope.py','/upgrade-signing','/measurement','/workspace','/source'):
  C.need(Path(name).stat().st_dev==data_dev and [v for p,v in rows if p==name]==['ext4']and ('rw'if name in('/out','/measurement')else'ro')in options[name],'exact source-owned data mount and write role '+name)
 if role=='bootstrap':C.need(os.getppid()==1 and os.readlink('/proc/1/exe')=='/usr/bin/bash','literal bootstrap shell is actual PID1 before exec')
 else:
  C.need(os.readlink('/proc/1/exe')=='/usr/lib/systemd/systemd'and Path('/run/systemd/system').is_dir(),'actual systemd PID1')
  if role=='hook':C.need(Path('/proc/self/cgroup').read_text().strip()=='0::/system.slice/caa-core-worker.service','hook is inside exact owned foreground worker cgroup')
  else:C.need(os.getppid()==1,'direct actual systemd supervised child')
 status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line);last=int(Path('/proc/sys/kernel/cap_last_cap').read_text());C.need(0<last<64,'bounded actual kernel capability set');mask=(1<<(last+1))-1
 C.need(all(int(status[n],16)==mask for n in('CapEff','CapPrm','CapBnd'))and int(status['CapInh'],16)==int(status['CapAmb'],16)==0 and status['NoNewPrivs'].strip()=='0','explicit whole owned-guest root capability profile for actual init/hooks; old copied-root mask unchanged')
 return int(fields['caa_core_phase']),dict(device=root.st_dev,inode=root.st_ino,serial='core7-'+s['nonce'],machine_id=s['nonce'])
