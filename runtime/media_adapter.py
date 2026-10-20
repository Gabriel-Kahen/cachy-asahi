#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite KSM bootstrap derivative of whole held persistent574 media preparation."""
import argparse,ast,ctypes,errno,json,os,resource,stat,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
DONOR='media-source/scripts/ci/current604-public-pair-updater16k/'
BINDINGS=('/inputs','/out','/upgrade-code','/upgrade-config.json','/persistent_scope.py','/upgrade-signing')
PREPARE_MASK=0x8000001b # CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETFCAP; no SYS_ADMIN.
WORKER_MASK=sum(1<<n for n in(0,1,3,4,5,6,7,18,31)) # held nine-cap guest; no SYS_ADMIN.

def one(text,before,after):
 C.need(text.count(before)==1,'one exact KSM media source anchor');return text.replace(before,after)

def derived_disk(root):
 raw=C.read(Path(root)/DONOR/'disk.py',256*1024);text=raw.decode()
 # Complete copy/readback/maps/ELF/ext4 functions remain present. Only fixed
 # own source layout, bootstrap name/label and guest sysfs mount differ.
 for before,after in (("'/source/scripts/apps/file_capabilities.py'","'/source/media-source/scripts/apps/file_capabilities.py'"),("'/source/scripts/ci/managed-gui-generic16k/elf_audit.py'","'/source/media-source/scripts/ci/managed-gui-generic16k/elf_audit.py'"),("'/source/scripts/virtual/generic16k/fixture.py'","'/source/media-source/scripts/virtual/generic16k/fixture.py'"),("'mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys'","'mount -t sysfs -o rw,nosuid,nodev,noexec sysfs /sys'"),("'-L','APPS6_'","'-L','KSM2_'")):
  text=one(text,before,after)
 text=one(text,"('/out','/measurement','/upgrade-signing')","('/out','/measurement')")
 text=one(text,"elif dest=='/source':\n   target.mkdir()","elif dest=='/source':\n   target.mkdir();shutil.copyfile(source/'source-files.json',target/'source-files.json')")
 C.need(text.count('init-updater16k')==4,'four fixed bootstrap name references');text=text.replace('init-updater16k','init-ksm2');ast.parse(text);return text.encode()

def modules(root):
 root=Path(root);caps=C.load('cap_scope',root/DONOR/'cap_scope.py');m=types.ModuleType('_ksm2_owned_media');m.__file__=str(root/'media_adapter.py');exec(compile(derived_disk(root),'whole-held-ksm2-disk.py','exec'),m.__dict__);return m,caps

def source_nodes(root,seconds=600):
 disk,caps=modules(root);scope,roots,_,_=disk.apis();limits=disk.limits(roots,seconds);policy=scope.mount_policy(Path('/'),Path('/measurement/inspection'),scope.mounts(scope._mount_table()));nodes,_=scope.source_manifest(Path('/'),limits,roots,policy);observer=caps.derive(C.read(Path(root)/'media-source/scripts/apps/file_capabilities.py'),set(policy['observed_mounts'])|scope.RUNTIME)
 return nodes,observer.observe(Path('/'),caps.nodes(nodes),limits),observer,caps,roots,disk

def isolate(root):
 # Whole original guest isolation functions: nine exact capabilities, NNP,
 # cleared supplementary groups and existing mount/namespace seccomp fence.
 text=C.read(Path(root)/DONOR/'guest.py',256*1024).decode();text=one(text,"'/source/scripts/install/local_transaction.py'","'/source/media-source/scripts/install/local_transaction.py'");text=one(text,"'/source/scripts/ci/glibc-gnu-provider-installed16k/sandbox.py'","'/source/media-source/scripts/ci/glibc-gnu-provider-installed16k/sandbox.py'");tree=ast.parse(text);names=('facts','isolate');functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names];C.need(len(functions)==2,'two whole guest isolation functions');C.MASK=WORKER_MASK
 ns=dict(C=C,Path=Path,os=os,ast=ast,ctypes=ctypes,errno=errno);exec(compile(ast.Module(body=functions,type_ignores=[]),'held-nine-cap-guest-isolation','exec'),ns);return ns['isolate']()

def prepare(s):
 root=Path('/source');C.support(root);C.source_check(root);C.native_gate(s,'/inputs',root);C.actual_identity(s);C.need(s.get('media')is None,'preparation selection has no future self-referential media authority')
 K=C.load('_ksm_prepare_kernel',root/'kernel_input.py');profile,_,_,_=K.imported(s,'/inputs',root);C.need(s['kernel']==profile,'exact fresh selected kernel before media creation')
 C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CAA_KSM2_VM_PREPARE')==s['nonce']and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline ARM preparation PID1 only')
 fields=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
 C.need(all(int(fields[k],16)==PREPARE_MASK for k in('CapEff','CapPrm','CapBnd'))and int(fields['CapInh'],16)==int(fields['CapAmb'],16)==0 and fields['NoNewPrivs'].strip()=='1','exact five-cap NNP preparation profile')
 C.need(tuple(s['bindings'])==BINDINGS and s['source_files']==C.decode(C.read(root/'source-files.json',1024**2))['files'],'closed literal input/source mount roles')
 C.need(s['runner_files']==C.decode(C.read(root/'runner-files.json',65536))['files'],'whole fixed runner source files')
 base={p['name']:p['version']for p in C.decode(C.read(root/'borrowed/maintained574-inputs.json',4*1024**2))['packages']};L=C.load('_ksm_prepare_inventory',root/'borrowed/lifecycle.py');C.need(len(base)==574 and L.inventory()==base and C.decode(C.read('/source/borrowed/base574.json'))==base,'exact original maintained574 source inventory')
 disk,_=modules(root);disk.prepare(s)
 receipt=C.decode(C.read('/measurement/prepared.json'));C.need(receipt['status']=='PREPARED_NOT_EXECUTED'and not Path('/measurement/stage').exists(),'complete media and original staging retirement')
 value=dict(status='PREPARED_ORIGINAL574_KSM2_OWNED_MEDIA',nonce=s['nonce'],original574_preserved=True,staging_retired=True,source_caps_restoration='SOURCE_STAGE_RESTORED_GUEST_REQUIRES_EXACT_MAP',private_maps='KEPT_IN_READONLY_GUEST_INPUTS',source_nodes_sha256=receipt['source_nodes_sha256'],capabilities_sha256=receipt['capabilities_sha256'],files={'boot.raw':receipt['boot'],'data.raw':receipt['data']},source='EXACT_HELD_PERSISTENT_SCOPE_COPY_CAPABILITY_EXT4_ELF_PATH',sysfs='RW_IN_DISPOSABLE_GUEST_ONLY',selection_pin=C.pin(C.encoded(dict(s,capabilities_sha256=receipt['capabilities_sha256']))))
 C.save('/measurement/ksm2-media.json',value);os.chown('/measurement/ksm2-media.json',s['uid'],s['gid']);return value

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--selection',type=Path,default=Path('/workspace/selection.json'));a=p.parse_args();prepare(C.decode(C.read(a.selection)))
