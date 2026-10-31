# SPDX-License-Identifier: MIT
"""Closed generic16K test projection; original default4K bodies remain exact."""
import json,shutil,struct
from pathlib import Path
import common as C
IMAGE={'bytes':9019400,'sha256':'cd8053ebdb83302015efbad97ab1cc53fcd5a2353bf3f37ba208f4e6360946ec'}
CONFIG={'bytes':68789,'sha256':'e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b'}
RELEASE='7.1.13-generic16k-managed-gui';EXTRA=('kernel16k.Image','kernel16k.config','kernel16k-input.json')
def configuration():return json.loads(C.read(C.HERE/'page-mode-profile.json'))
def descriptor():
 p=configuration();return dict(purpose='FRESH607_GENERIC16K_BUILD_ONLY_KERNEL_INPUT',source=p['kernel']['source'],ref=p['kernel']['ref'],run=p['kernel']['run'],artifact=p['kernel']['artifact'],Image=IMAGE,config=CONFIG,header=p['kernel']['members']['Image.header'],build_decision=p['kernel']['kernel_decision'],page_size=16384,kernel=RELEASE,modules='DISABLED',boot='NOT_RUN',fresh607='NOT_RUN',hardware='NOT_RUN')
def kernel_bytes(image,config):
 C.need(C.pin(image)==IMAGE and C.pin(config)==CONFIG,'exact accepted BUILD_ONLY Image/config bytes');C.need(C.pin(image[:64])==configuration()['kernel']['members']['Image.header']and image[56:60]==b'ARMd'and(struct.unpack_from('<Q',image,24)[0]>>1)&3==2,'exact AArch64 Image header and16K geometry')
 rows={}
 for line in config.decode('ascii').splitlines():
  if line.startswith('CONFIG_')and'='in line:
   k,v=line.split('=',1);C.need(k not in rows,'duplicate kernel configuration');rows[k]=v
  elif line.startswith('# CONFIG_')and line.endswith(' is not set'):
   k=line[2:-11];C.need(k not in rows,'duplicate disabled configuration');rows[k]='n'
 wanted={k:'y'for k in('CONFIG_ARM64_16K_PAGES','CONFIG_USER_NS','CONFIG_PID_NS','CONFIG_NET_NS','CONFIG_SECCOMP','CONFIG_SECCOMP_FILTER','CONFIG_EXT4_FS','CONFIG_EXT4_FS_POSIX_ACL','CONFIG_EXT4_FS_SECURITY','CONFIG_VIRTIO_PCI','CONFIG_VIRTIO_BLK','CONFIG_DEVTMPFS','CONFIG_PROC_FS','CONFIG_SYSFS','CONFIG_CGROUPS','CONFIG_TMPFS_POSIX_ACL','CONFIG_TMPFS_XATTR')};wanted.update(CONFIG_MODULES='n',CONFIG_ARM64_4K_PAGES='n',CONFIG_ARM64_64K_PAGES='n',CONFIG_LOCALVERSION='"-generic16k-managed-gui"');C.need(all(rows.get(k)==v for k,v in wanted.items()),'complete fixed kernel configuration facilities; modules disabled');return descriptor()
def inputs(root):
 root=C.safe(root);C.need({p.relative_to(root).as_posix()for p in root.rglob('*')}=={'Image','config','kernel-input.json'},'closed three-file kernel DATA input');image=C.checked(root/'Image',IMAGE);config=C.checked(root/'config',CONFIG);d=kernel_bytes(image,config);C.need(C.read(root/'kernel-input.json')==C.enc(d),'source-owned BUILD_ONLY provenance; no priorboot authority');return image,config,C.enc(d)
def export(image,config,output):
 image=C.safe(image);config=C.safe(config);d=kernel_bytes(C.checked(image,IMAGE),C.checked(config,CONFIG));output,=C.fresh(output,protected=(image.parent,config.parent,C.ROOT));values={'Image':C.checked(image,IMAGE),'config':C.checked(config,CONFIG),'kernel-input.json':C.enc(d)};output.mkdir(mode=0o700)
 for n,b in values.items():(output/n).write_bytes(b)
 inputs(output);return dict(status='EXACT_KERNEL20_BUILD_ONLY_DATA',files=3,boot='NOT_RUN',fresh607='NOT_RUN',hardware='NOT_RUN')
def select(mode,kernel):
 C.need(type(mode)is str and mode in('generic4k','generic16k'),'closed page mode')
 if mode=='generic4k':C.need(kernel is None,'4K default rejects unused kernel operand');return None
 C.need(kernel is not None,'explicit16K kernel DATA input required');return inputs(kernel)
def edit(raw,before,after):
 C.need(raw.count(before.encode())==1,'one typed16K source seam '+before[:60]);out=raw.replace(before.encode(),after.encode(),1);C.need(out.count(after.encode())==1 and out.replace(after.encode(),before.encode(),1)==raw,'whole16K seam inverse');return out

def edits():
 return {
 'guest.py':[("os.uname().release=='7.2.10-1-aarch64-ARCH'","os.uname().release=="+repr(RELEASE)),("os.sysconf('SC_PAGE_SIZE')==4096","os.sysconf('SC_PAGE_SIZE')==16384"),('fixed generic4K root guest entry required','fixed generic16K root guest entry required'),('page_size=4096,kernel=os.uname().release','page_size=16384,kernel=os.uname().release')],
 'installer.py':[("os.uname().release=='7.2.10-1-aarch64-ARCH'","os.uname().release=="+repr(RELEASE)),("os.sysconf('SC_PAGE_SIZE')==4096","os.sysconf('SC_PAGE_SIZE')==16384"),('ordinary generic4K guest required','ordinary generic16K guest required')],
 'numeric_vm.py':[("os.uname().release=='7.2.10-1-aarch64-ARCH'","os.uname().release=="+repr(RELEASE)),("os.sysconf('SC_PAGE_SIZE')==4096","os.sysconf('SC_PAGE_SIZE')==16384"),('owned generic4K root guest bootstrap required','owned generic16K root guest bootstrap required')],
 'prepare.py':[("    shutil.copyfile('/boot/Image',output/'Image')","    selected=checked_file('/candidate','kernel16k.Image',c['runner_files']['kernel16k.Image'],common)\n    need(common.digest(selected)=="+repr(IMAGE['sha256'])+",'exact separate16K QEMU kernel')\n    shutil.copyfile(selected,output/'Image')")],
 'run.py':[("page_size=4096,kernel=common.KERNEL,uid=0)","page_size=16384,kernel="+repr(RELEASE)+",uid=0)"),('generic4K boot identity differs','generic16K boot identity differs'),("common.digest(kernel)==common.IMAGE_SHA==prepared['kernel_sha256']","common.digest(kernel)=="+repr(IMAGE['sha256'])+"==prepared['kernel_sha256']"),("scope='generic4K-current607-installer-software-only'","scope='generic16K-current607-installer-software-only'"),("('run.py','prepare.py','guest.py','installer.py','profile.py','numeric_vm.py'):","('run.py','prepare.py','guest.py','installer.py','profile.py','numeric_vm.py','kernel16k.Image','kernel16k.config','kernel16k-input.json'):"),("'numeric_vm.py','installer-profile.json','payload.json')}","'numeric_vm.py','installer-profile.json','payload.json','kernel16k.Image','kernel16k.config','kernel16k-input.json')}" )],
 'profile.py':[("'M2 hardware','16K kernel','performance'","'M2 hardware','Asahi/platform kernel','performance'"),("fresh signed expanded607 transaction plus declared user fixtures in generic4K VM","fresh signed expanded607 transaction plus declared user fixtures in generic16K VM")],
 }
def transform(raw,name):
 C.need(name in edits(),'one of six emitted source bodies');out=raw
 for a,b in edits()[name]:out=edit(out,a,b)
 restored=out
 for a,b in reversed(edits()[name]):C.need(restored.count(b.encode())==1,'one16K inverse');restored=restored.replace(b.encode(),a.encode(),1)
 C.need(restored==raw,'whole607 default4K body held');compile(out,'<generic16k-'+name+'>','exec');return out

def emit(output,kernel):
 import adapter
 values=inputs(kernel);rows=adapter.emit(output);output=C.safe(output);parent_report=json.loads(C.read(output/'adapter.json'));out={}
 for name in adapter.NAMES:
  raw=C.read(output/name);out[name]=transform(raw,name);(output/name).write_bytes(out[name])
 for n,b in zip(EXTRA,values):(output/n).write_bytes(b)
 C.need(inputs(kernel)==values,'kernel DATA unchanged after finite candidate generation');report=dict(status='SOURCE_ONLY_EXPLICIT_GENERIC16K_WHOLE4K_INVERSE',default4k=rows,files={n:C.pin(b)for n,b in out.items()},kernel=descriptor(),clocks=C.profile()['clocks'],generic16k_fit='NOT_ESTABLISHED',actual=None,hardware='NOT_RUN');report['default4k_adapter']=parent_report;report['page_edits']=edits();(output/'adapter.json').write_bytes(C.enc(report));(output/'page-mode.json').write_bytes(C.enc(report));return rows
