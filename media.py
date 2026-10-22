# SPDX-License-Identifier: MIT
"""Whole original574 media copier with a finite real-systemd bootstrap inverse."""
import ast,json,os,stat,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,boot
DONOR='media-source/scripts/ci/current604-public-pair-updater16k/disk.py'

def replace(text,old,new):
 C.need(text.count(old)==1,'one whole media source anchor');return text.replace(old,new)

def derive(root):
 text=C.read(Path(root)/DONOR,256*1024).decode()
 for old,new in (("'/source/scripts/apps/file_capabilities.py'","'/source/media-source/scripts/apps/file_capabilities.py'"),("'/source/scripts/ci/managed-gui-generic16k/elf_audit.py'","'/source/media-source/scripts/ci/managed-gui-generic16k/elf_audit.py'"),("'/source/scripts/virtual/generic16k/fixture.py'","'/source/media-source/scripts/virtual/generic16k/fixture.py'")):
  text=replace(text,old,new)
 text=replace(text,"q=target/n;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,q)","q=target/n;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,q)")
 old="for n,pin in s['runner_files'].items():C.need(C.row(Path('/workspace')/n)==pin,'exact own source');shutil.copyfile(Path('/workspace')/n,target/n)"
 new="for n,pin in s['runner_files'].items():\n    C.need(C.row(Path('/workspace')/n)==pin,'exact own source');(target/n).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(Path('/workspace')/n,target/n)"
 text=replace(text,old,new)
 text=replace(text,"C.save(data/'workspace/selection.json',s)","C.save(data/'workspace/selection.json',C.decode(C.read('/workspace/selection.json')))")
 start=text.index(' # Recreate the original literal mounted infrastructure')
 end=text.index(" audit=C.load('elf_audit'",start)
 held=text[start:end]
 text=text[:start]+" overlay=BOOT.apply(boot,s['nonce']);C.save(data/'workspace/overlay.json',overlay)\n"+text[end:]
 # Full maps, capabilities, original hardlinks, ELF audit, ext4 images, original
 # lost+found check/removal and exact staging retirement remain byte-held.
 ast.parse(text);return text,held

def module(root):
 text,_=derive(root);m=types.ModuleType('_core_real_systemd_media');m.__file__=str(Path(root)/'media_adapter.py');m.__dict__['BOOT']=boot
 sys.path.insert(0,str(Path(root)));C.load('contract',Path(root)/'contract.py');C.load('cap_scope',Path(root)/DONOR.replace('disk.py','cap_scope.py'));exec(compile(text,'whole-held574-core-systemd-media','exec'),m.__dict__);return m

def prepare():
 s=C.decode(C.read('/workspace/media-selection.json'));selected=C.decode(C.read('/workspace/selection.json'));C.selection(selected)
 C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CAA_CORE7_PREPARE')==selected['nonce']and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline ARM preparer PID1')
 fields=dict(v.split(':',1)for v in Path('/proc/self/status').read_text().splitlines()if ':'in v);mask=0x8000001b
 C.need(all(int(fields[k],16)==mask for k in('CapEff','CapPrm','CapBnd'))and int(fields['CapInh'],16)==int(fields['CapAmb'],16)==0 and fields['NoNewPrivs'].strip()=='1','original exact five-cap NNP media preparer')
 root=Path('/source');K=C.load('_core_kernel_import',root/'kernel_input.py');K.imported(selected['kernel'],'/measurement-source',root)
 D=module(root);SC=D.C;SC.support(root);SC.source_check(root)
 C.need(s['nonce']==selected['nonce']and tuple(s['bindings'])==boot.ROLES[:6]and s['runner_files']==C.decode(C.read('/workspace/runner-files.json',4*1024**2)),'closed new guest and unchanged original role namespace')
 D.prepare(s);v=C.decode(C.read('/measurement/prepared.json'));C.need(v['status']=='PREPARED_NOT_EXECUTED'and not Path('/measurement/stage').exists(),'whole stage retirement before returning disks')
 record=dict(status='PREPARED_CORE7_REAL_SYSTEMD_MEDIA_NOT_BOOTED',nonce=s['nonce'],files={n:SC.row(Path('/measurement')/n)for n in('boot.raw','data.raw')},source_nodes_sha256=v['source_nodes_sha256'],capabilities_sha256=v['capabilities_sha256'],budgets=C.BUDGET,identities={n:[(Path('/measurement')/n).stat().st_dev,(Path('/measurement')/n).stat().st_ino,s['uid'],(Path('/measurement')/n).stat().st_size]for n in('boot.raw','data.raw')})
 Path('/measurement/core-media.json').write_bytes(C.encoded(record))
 for p in Path('/measurement').iterdir():os.chown(p,s['uid'],s['gid'])
 return record
def export_files(D,image,target,s,uid,gid):
 """Full source-owned file export, separately exercised at its debugfs boundary."""
 image=Path(image);target=Path(target);C.need(image==target.parent/'data.raw'and target.name=='guest-export'and not target.exists(),'fixed fresh owned data export')
 entries=D.image_directory(D.command(['/usr/bin/debugfs','-R','ls -p /out',image],60));names=set(entries)-{'.','..'}
 import re
 pattern=r'(?:phase[1234]-(?:[a-z0-9-]+(?:\.json|\.json\.gz|\.log)|(?:observer-)?command-[0-9]{3}\.(?:stdout|stderr))|baseline-automatic-root\.json\.gz|\.phase[1234]-(?:(?:observer-)?progress|custody|observer|retirement)\.json\.partial)'
 C.need(len(names)<=512 and all(re.fullmatch(pattern,n)for n in names),'finite literal public guest export filenames')
 target.mkdir(mode=0o700);files={};total=0
 for n in sorted(names):
  r=entries[n];C.need(stat.S_ISREG(r['mode'])and r['uid']==r['gid']==0 and type(r['size'])is int and 0<=r['size']<=64*1024**2,'bounded ordinary guest evidence nodes');total+=r['size'];C.need(total<=512*1024**2,'original aggregate guest evidence cap')
  D.command(['/usr/bin/debugfs','-R','dump /out/'+n+' '+str(target/n),image],120);C.need((target/n).stat().st_size==r['size'],'complete original evidence size');files[n]=D.C.row(target/n);os.chown(target/n,uid,gid)
 import gzip
 for source,name,compress,cap in(('/workspace/baseline-nodes.json','media-source-nodes.json.gz',True,256*1024**2),('/workspace/capabilities.json','media-source-capabilities.json',False,4*1024**2),('/workspace/overlay.json','media-overlay.json',False,65536)):
  scratch=target.parent/'fixed-source-map.tmp';C.need(not scratch.exists(),'fresh literal source-map export scratch')
  D.command(['/usr/bin/debugfs','-R','dump '+source+' '+str(scratch),image],120);raw=C.read(scratch,cap);C.decode(raw);scratch.unlink();payload=gzip.compress(raw,mtime=0)if compress else raw;total+=len(payload);C.need(len(payload)<=64*1024**2 and total<=512*1024**2,'unchanged complete evidence caps');(target/name).write_bytes(payload);os.chown(target/name,uid,gid);files[name]=C.pin(payload)
 receipt=target.parent/'guest-export.json';receipt.write_bytes(C.encoded(dict(status='EXACT_OWNED_GUEST_FILES_DATA_ONLY',nonce=s['nonce'],files=files,bytes=total)));os.chown(receipt,uid,gid);os.chown(target,uid,gid);return files

def export():
 s=C.decode(C.read('/workspace/selection.json'));C.selection(s)
 C.need(os.getpid()==1 and os.getuid()==0 and os.uname().machine=='aarch64'and os.environ.get('CAA_CORE7_PREPARE')==s['nonce'],'owned original-image exporter only')
 D=module('/source');lease=C.decode(C.read('/workspace/media-selection.json'));return export_files(D,Path('/measurement/data.raw'),Path('/measurement/guest-export'),s,lease['uid'],lease['gid'])

def main():
 import argparse,stat
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('role',choices=('prepare','export','scrub'));a=p.parse_args()
 if a.role=='prepare':return prepare()
 if a.role=='export':return export()
 s=C.decode(C.read('/workspace/selection.json'));C.selection(s);C.need(os.getpid()==1 and os.getuid()==0 and os.uname().machine=='aarch64'and os.environ.get('CAA_CORE7_PREPARE')==s['nonce'],'owned stage scrub only');D=module('/source');os.environ['CAA_APPS6_UPDATE16K_PREPARE']='1';saved=sys.argv;sys.argv=['media.py','scrub']
 try:return D.main()
 finally:sys.argv=saved
if __name__=='__main__':main()
