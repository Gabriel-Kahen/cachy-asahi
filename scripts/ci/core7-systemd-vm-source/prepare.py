#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce exact published Core7 two-boot source34; no actors or acceptance."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 9626, 'sha256': '3358391cb476548a4ecc44cb205ff5595f44a44d6f96155ae5fd1d6ef18c5cc2'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(path):
 path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'no source/output aliases or traversal');return path
def read(path,cap=16*1024**2):
 path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink source/support input');raw=bytearray()
  while block:=os.read(fd,1024**2):raw.extend(block);need(len(raw)<=a.st_size,'source grew during read')
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable atime-independent source identity');return bytes(raw)
 finally:os.close(fd)
def source(root,wanted,cap=16*1024**2):
 root=ordinary(root);need(root.is_dir(),'whole source/support directory required');expected_dirs={''}
 for n in wanted:
  p=Path(n);need(n and not p.is_absolute()and p.as_posix()==n and not set(p.parts)&{'.','..'}and'\\'not in n,'fixed canonical relative source path');expected_dirs.update(q.as_posix()if str(q)!='.'else''for q in p.parents)
 bodies={};directories={''}
 for p in sorted(root.rglob('*')):
  name=p.relative_to(root).as_posix()
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink(),'source/support symlink refused')
  if p.is_dir():directories.add(name)
  else:need(name in wanted,'extra source/support file');bodies[name]=read(p,cap)
 need(directories==expected_dirs and{n:pin(v)for n,v in bodies.items()}==wanted,'complete exact source/support closure including directories');return bodies

def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def inputs():
 need(not sys.flags.optimize,'optimized source checks refused');raw=read(HERE/'profile.json');need(pin(raw)==PROFILE,'whole pinned two-boot factory profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_REAL_SYSTEMD_TWO_BOOT_FACTORY'and p['actual']is None and p['result']['source']=='a74c54093bf8d09883e32b0d64b77f46223920e1'and p['result']['ref']=='codex/core7-host-qemu-v1','only exact source-only34 profile')
 expected=p['result']['files'];need(len(expected)==34 and len(p['templates'])==31 and p['derived']==dict(manifest='source-manifest.json',workflows=['.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml']),'finite31-readable/three-derived source closure')
 bodies=source(HERE/'templates',p['templates']);manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files=p['templates']));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 need(b'@ENTRY_SHA@'not in workflow and b'@MANIFEST_SHA@'not in workflow,'closed generated workflow stamps')
 for name in p['derived']['workflows']:bodies[name]=workflow
 need({n:pin(raw)for n,raw in bodies.items()}==expected,'all34 exact source bytes before writing');return p,bodies

def emit(output):
 p,bodies=inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint source-only output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,p['result']['files']).items()}==p['result']['files'],'all34 emitted bytes after writing');return result(p)

def result(p):return dict(status='SOURCE_ONLY_EXACT34_CORE7_TWO_BOOT_NOT_NATIVE_ACCEPTANCE',files=34,source=p['result']['source'],actual=None,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
VIRTIO20_PROFILE = {'bytes': 20331, 'sha256': '1e284deca83abf31b6fca663705f371b9642006e09c2f45840118b0c22e444db'}

def virtio20_inputs():
 original,bodies=inputs();raw=read(HERE/'virtio20-profile.json');need(pin(raw)==VIRTIO20_PROFILE,'whole pinned virtio20 correction profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_VIRTIO20_CORRECTION'and p['actual']is None and p['parent']['files']==original['result']['files']and p['parent']['source']==original['result']['source']and p['result']['source']=='bc9c55f9c245df31061aed7e49e636eeae0a018c'and p['result']['ref']=='codex/core7-virtio20-v1','exact unchanged34 parent and new34 source-only identity')
 need(set(p['payload'])=={'case.py','boot.py','host.py','guest_guard.py','controller.py','guest.py','validate.py','test_case.py','test_protocol.py'}and len(p['held'])==22,'nine readable correction leaves and22 held source leaves')
 bodies.update(source(HERE/'virtio20',p['payload']))
 manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(raw)for n,raw in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 for n in original['derived']['workflows']:bodies[n]=workflow
 need({n:pin(raw)for n,raw in bodies.items()}==p['result']['files']and len(bodies)==34 and all(p['parent']['files'][n]==p['result']['files'][n]==row for n,row in p['held'].items()),'all34 corrected source bytes before writing')
 return p,bodies

def emit_virtio20(output):
 p,bodies=virtio20_inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint source-only output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,p['result']['files']).items()}==p['result']['files'],'all34 emitted virtio20 bytes after writing');return result(p)

ROLLBACK_PROFILE = {'bytes': 22916, 'sha256': 'f7eaf9bba8f0abfeda42b78eba784db88aaa0686e35e9c948be0409d79f99673'}

def rollback_inputs():
 parent,bodies=virtio20_inputs();raw=read(HERE/'automatic-rollback-profile.json');need(pin(raw)==ROLLBACK_PROFILE,'whole pinned rollback factory profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_FOUR_BOOT_AUTOMATIC_ROLLBACK'and p['actual']is None and p['parent']==dict(source=parent['result']['source'],ref=parent['result']['ref'],files=parent['result']['files'])and p['result']['source']=='48dcc65b10641a7b92eb5577f9f7d328cd26ed61'and p['result']['ref']=='codex/core7-automatic-rollback-v1','exact public source-only rollback profile from whole virtio20 parent')
 need(len(p['payload'])==15 and len(p['held'])==18 and len(p['result']['files'])==36 and p['derived']==dict(manifest='source-manifest.json',workflows=['.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml']),'finite15-readable/18-held rollback closure')
 bodies.update(source(HERE/'automatic-rollback',p['payload']))
 manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(v)for n,v in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 for name in p['derived']['workflows']:bodies[name]=workflow
 need({n:pin(v)for n,v in bodies.items()}==p['result']['files']and all(parent['result']['files'][n]==p['result']['files'][n]==row for n,row in p['held'].items()),'whole exact36 rollback bytes before any output')
 return p,bodies

def rollback_result(p):return dict(status='SOURCE_ONLY_EXACT36_AUTOMATIC_ROLLBACK_NOT_NATIVE_ACCEPTANCE',files=36,source=p['result']['source'],actual=None,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def emit_rollback(output):
 p,bodies=rollback_inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint rollback source output');output.mkdir(mode=0o700)
 for name,raw in sorted(bodies.items()):
  path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(v)for n,v in source(output,p['result']['files']).items()}==p['result']['files'],'whole exact36 rollback output after write');return rollback_result(p)

HOST_CLOCK_PROFILE = {'bytes': 46974, 'sha256': '4659619a4d8938742504326ec2fa91ddacd09da3229b71f30b98bdf210292579'}

def host_clock_inputs(automatic_rollback=False):
 need(type(automatic_rollback)is bool,'explicit finite clock profile');parent,bodies=rollback_inputs()if automatic_rollback else virtio20_inputs();raw=read(HERE/'host-clock-profile.json');need(pin(raw)==HOST_CLOCK_PROFILE,'whole pinned host-clock factory profile');profile=json.loads(raw);mode='four-boot'if automatic_rollback else'two-boot';p=profile['profiles'][mode]
 need(profile['kind']=='SOURCE_ONLY_EXACT_CORE7_HOST_CLOCK_PROFILES'and profile['actual']is None and set(profile['profiles'])=={'two-boot','four-boot'}and p['parent']==dict(source=parent['result']['source'],ref=parent['result']['ref'],files=parent['result']['files']),'whole explicit original profile and source-only clock branch')
 wanted=('two-boot',35,'92ba829ca86c27b472a715c66e7d7ca5a17206e2','codex/core7-host-clock-v1',8)if not automatic_rollback else('four-boot',37,'4e961335b2336e978532e83f4d6a99a43cc38cc8','codex/core7-clock-rollback-v1',10)
 need((mode,len(p['result']['files']),p['result']['source'],p['result']['ref'],len(p['payload']))==wanted and len(p['held'])==24,'fixed genuine whole35/two-boot or37/four-boot clock source')
 payload=source(HERE/'host-clock',profile['payload']);prefix=mode+'/';selected={n[len(prefix):]:v for n,v in payload.items()if n.startswith(prefix)};need({n:pin(v)for n,v in selected.items()}==p['payload'],'whole exact readable selected clock payload');bodies.update(selected)
 manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(v)for n,v in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 for n in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'):bodies[n]=workflow
 need({n:pin(v)for n,v in bodies.items()}==p['result']['files']and all(p['parent']['files'][n]==p['result']['files'][n]==row for n,row in p['held'].items()),'whole exact clock source before any output')
 return p,bodies

def host_clock_result(p):return dict(status='SOURCE_ONLY_EXACT_HOST_CLOCK_NOT_NATIVE_ACCEPTANCE',files=len(p['result']['files']),source=p['result']['source'],actual=None,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def emit_host_clock(output,automatic_rollback=False):
 p,bodies=host_clock_inputs(automatic_rollback);output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint clock source output');output.mkdir(mode=0o700)
 for name,raw in sorted(bodies.items()):
  path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(v)for n,v in source(output,p['result']['files']).items()}==p['result']['files'],'whole exact clock source after writing');return host_clock_result(p)


MODULE_INDEX_PROFILE = {'bytes': 15378, 'sha256': '8bdf6e04128f39bb76cc0ca9d2ec5a49dcdc4b1cee5110b6751e7272b25e034c'}

def module_index_inputs():
 parent,bodies=host_clock_inputs(False);raw=read(HERE/'module-index-profile.json');need(pin(raw)==MODULE_INDEX_PROFILE,'whole fixed module-index profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_MODULE_INDEX_INITIALIZATION'and p['actual']is None and p['parent']==dict(source=parent['result']['source'],ref=parent['result']['ref'],files=parent['result']['files']),'whole genuine35 host-clock ancestor')
 need(len(p['payload'])==8 and len(p['held'])==26 and len(p['result']['files'])==37 and p['result']['source']=='0e5da6aab98018d00875548813c77a4f87eedcdf'and p['result']['ref']=='codex/core7-module-index-v1','finite genuine37 module-index successor')
 bodies.update(source(HERE/'module-indexes',p['payload']))
 manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(v)for n,v in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 for n in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'):bodies[n]=workflow
 need({n:pin(v)for n,v in bodies.items()}==p['result']['files']and all(p['parent']['files'][n]==p['result']['files'][n]==w for n,w in p['held'].items()),'all37 exact bytes before output, no prefix exemptions')
 return p,bodies

def emit_module_indexes(output):
 p,bodies=module_index_inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint module-index output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(v)for n,v in source(output,p['result']['files']).items()}==p['result']['files'],'whole37 emitted module-index source');return host_clock_result(p)


GZIP1_PROFILE={'bytes': 18537, 'sha256': '56fabf8f765fb39c00c834387043b20ecd244bda182a0b696f9557aa5e007242'}
def gzip1_inputs():
 parent,bodies=module_index_inputs();raw=read(HERE/'gzip1-profile.json');need(pin(raw)==GZIP1_PROFILE,'whole fixed VM-only gzip1 profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_VM_GZIP1'and p['actual']is None and p['parent']==dict(source=parent['result']['source'],ref=parent['result']['ref'],files=parent['result']['files'])and p['result']['source']=='4bfd24f3dcf4a3e633e2b3679c75a73a792fcebe'and p['result']['ref']=='codex/core7-initramfs-compression-v1','whole genuine37 and explicit source-only38 gzip branch')
 import ast
 text=read(HERE/'prepare.py').decode();tree=ast.parse(text);held={n.name:pin(ast.get_source_segment(text,n).encode())for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in p['held_function_bodies']};need(held==p['held_function_bodies'],'every pre-existing factory function body held')
 need(len(p['payload'])==5 and len(p['held'])==30 and len(p['result']['files'])==38,'finite five-readable/thirty-held gzip1 source')
 bodies.update(source(HERE/'gzip1',p['payload']))
 manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(v)for n,v in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 for n in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'):bodies[n]=workflow
 need({n:pin(v)for n,v in bodies.items()}==p['result']['files']and all(p['parent']['files'][n]==p['result']['files'][n]==w for n,w in p['held'].items()),'all38 exact bytes before writing')
 return p,bodies
def gzip1_result(p):return dict(status='SOURCE_ONLY_EXACT38_VM_GZIP1_NOT_NATIVE_ACCEPTANCE',files=38,source=p['result']['source'],actual=None,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
def emit_gzip1(output):
 p,bodies=gzip1_inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint gzip1 source output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  target=output/n;target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as stream:stream.write(raw)
 need({n:pin(v)for n,v in source(output,p['result']['files']).items()}==p['result']['files'],'all38 bytes after emission');return gzip1_result(p)


FRESH_GRAPH_PROFILE={'bytes': 19328, 'sha256': '6567ce38bbbb5134bda041e5727a73d607a4c24999ec36d436fbd582eb76102d'}

def fresh_graph_inputs():
 parent,bodies=gzip1_inputs();raw=read(HERE/'fresh-graph-profile.json');need(pin(raw)==FRESH_GRAPH_PROFILE,'whole pinned fresh descriptor graph profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_FRESH_DESCRIPTOR_GRAPHS'and p['actual']is None and p['parent']==parent['result']and p['result']['source']=='700fc849924866bfc2845ccd49e294fb914a9671'and p['result']['ref']=='codex/core7-fresh-graph-v1','whole genuine38 and explicit source-only39 branch')
 import ast
 text=read(HERE/'prepare.py').decode();tree=ast.parse(text);held={n.name:pin(ast.get_source_segment(text,n).encode())for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in p['held_function_bodies']};need(held==p['held_function_bodies'],'all22 prior factory function bodies held')
 need(set(p['payload'])=={'README.md','graph_api.py','guest.py','test_sources.py'}and len(p['held'])==32 and len(p['result']['files'])==39,'four readable correction leaves and32 held source leaves')
 bodies.update(source(HERE/'fresh-graph',p['payload']))
 manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(v)for n,v in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 for n in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'):bodies[n]=workflow
 need({n:pin(v)for n,v in bodies.items()}==p['result']['files']and all(p['parent']['files'][n]==p['result']['files'][n]==w for n,w in p['held'].items()),'all39 exact bytes before writing')
 return p,bodies

def fresh_graph_result(p):return dict(status='SOURCE_ONLY_EXACT39_FRESH_DESCRIPTOR_GRAPHS_NOT_NATIVE_ACCEPTANCE',files=39,source=p['result']['source'],actual=None,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def emit_fresh_graph(output):
 p,bodies=fresh_graph_inputs();output=Path(output).absolute();need(output==output.resolve(),'canonical normalized fresh graph output path');output=ordinary(output)
 need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint graph source output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  target=output/n;target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as stream:stream.write(raw)
 need({n:pin(v)for n,v in source(output,p['result']['files']).items()}==p['result']['files'],'all39 bytes after emission');return fresh_graph_result(p)

def tpm_acl_module():
 import types
 path=HERE/'tpm_acl.py';raw=read(path);need(pin(raw)=={'bytes': 8240, 'sha256': '30d387d5ac6e7a8276f0d50a6805081fbec5dd964adc6489d406f25518e3cfaa'},'whole fixed readable Core41 helper before loading');module=types.ModuleType('_explicit_Core41_factory');module.__file__=str(path);exec(compile(raw,str(path),'exec'),vars(module));return module

def tpm_acl_inputs():return tpm_acl_module().inputs(globals())
def emit_tpm_acl(output,unbound=False,authorization=None):return tpm_acl_module().emit(globals(),output,unbound,authorization)


def observer_module():
 import types
 path=HERE/'observer.py';raw=read(path);need(pin(raw)=={'bytes': 5761, 'sha256': 'eb985ed379b3c0ce9a8a0c3883cc6b31bf85ae26fb1f2a6980bc3fcfc490b20f'},'whole readable observer factory helper');module=types.ModuleType('_explicit_observer_efficient_factory');module.__file__=str(path);exec(compile(raw,str(path),'exec'),vars(module));return module

def observer_inputs():return observer_module().inputs(globals())
def emit_observer(output,unbound=False,authorization=None):return observer_module().emit(globals(),output,unbound,authorization)

def journal_acl1200_module():
 import types
 path=HERE/'journal_acl1200.py';raw=read(path);need(pin(raw)=={'bytes': 6869, 'sha256': '3be2dd788a5af164013ccbade07058a702d41c0ff4f4a79dff3eeb5e623dc3a8'},'whole readable journal44 factory helper');module=types.ModuleType('_explicit_journal44_factory');module.__file__=str(path);exec(compile(raw,str(path),'exec'),vars(module));return module

def journal_acl1200_inputs(predecessor):return journal_acl1200_module().inputs(globals(),predecessor)
def emit_journal_acl1200(predecessor,output,unbound=False,authorization=None):return journal_acl1200_module().emit(globals(),predecessor,output,unbound,authorization)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);parser.add_argument('--source-only',action='store_true',help='check all34 composed bytes without writing or actors');parser.add_argument('--virtio20',action='store_true',help='opt in to exact published20-byte serial/bootstrap correction');parser.add_argument('--automatic-rollback',action='store_true',help='explicit source-only four-boot rollback, no native acceptance');parser.add_argument('--host-clock',action='store_true',help='exact current-host UTC initialization; composes with automatic rollback, no native acceptance');parser.add_argument('--module-indexes',action='store_true',help='exact two-boot genuine kernel dependency-index initialization');parser.add_argument('--gzip1',action='store_true',help='exact VM-only gzip level1 profile over genuine module-index source; no clock changes');parser.add_argument('--fresh-graph',action='store_true',help='exact source39 with fresh descriptor graph queries; no clock changes');parser.add_argument('--tpm-default-acl',action='store_true',help='explicit typed TPM ACL source41; original positive graph schema changes');parser.add_argument('--unbound',action='store_true',help='only with --tpm-default-acl; identical41 bytes with NULL factory identity');parser.add_argument('--authorization',type=Path,help='optional fresh separate source-only receipt for --tpm-default-acl output');parser.add_argument('--observer-efficient',action='store_true',help='explicit source-only lexical observer41 successor; graph schema and clocks held');parser.add_argument('--journal-acl1200',action='store_true',help='exact source-only journal44 from pinned public43');parser.add_argument('--journal-acl1200-unbound',action='store_true',help='identical journal44 with NULL receipt source/ref');parser.add_argument('--predecessor-root',type=Path,help='required immutable public43 checkout only for journal44');a=parser.parse_args();need(a.output is not None or a.source_only,'explicit fresh output or source-only required');need(not(a.virtio20 and a.automatic_rollback),'one explicit source profile');need(not(a.host_clock and a.virtio20),'host-clock already selects the exact virtio20 ancestor');
 need(a.tpm_default_acl or a.observer_efficient or a.journal_acl1200 or a.journal_acl1200_unbound or not(a.unbound or a.authorization is not None),'unbound/authorization require an explicit Core41 profile')
 need(a.journal_acl1200 or a.journal_acl1200_unbound or a.predecessor_root is None,'predecessor-root requires an explicit journal44 route')
 if a.journal_acl1200 or a.journal_acl1200_unbound:
  need(not(a.journal_acl1200 and a.journal_acl1200_unbound)and not(a.unbound or a.observer_efficient or a.tpm_default_acl or a.fresh_graph or a.gzip1 or a.module_indexes or a.host_clock or a.virtio20 or a.automatic_rollback),'one explicit journal44 route');need(a.predecessor_root is not None and(a.output is not None or a.authorization is None),'journal44 requires pinned predecessor and output for authorization');module=journal_acl1200_module();print(json.dumps(emit_journal_acl1200(a.predecessor_root,a.output,a.journal_acl1200_unbound,a.authorization)if a.output is not None else module.result(journal_acl1200_inputs(a.predecessor_root)[0],a.journal_acl1200_unbound),sort_keys=True));return
 if a.observer_efficient:
  need(not(a.tpm_default_acl or a.fresh_graph or a.gzip1 or a.module_indexes or a.host_clock or a.virtio20 or a.automatic_rollback),'one explicit observer-efficient profile');need(a.output is not None or a.authorization is None,'authorization requires output');module=observer_module();print(json.dumps(emit_observer(a.output,a.unbound,a.authorization)if a.output is not None else module.result(observer_inputs()[0],a.unbound),sort_keys=True));return
 if a.tpm_default_acl:
  need(not(a.fresh_graph or a.gzip1 or a.module_indexes or a.host_clock or a.virtio20 or a.automatic_rollback),'one explicit typed TPM ACL profile');need(a.output is not None or a.authorization is None,'authorization requires output');module=tpm_acl_module();print(json.dumps(emit_tpm_acl(a.output,a.unbound,a.authorization)if a.output is not None else module.result(tpm_acl_inputs()[0],a.unbound),sort_keys=True));return
 if a.fresh_graph:
  need(not(a.gzip1 or a.module_indexes or a.host_clock or a.virtio20 or a.automatic_rollback),'one explicit fresh graph profile');print(json.dumps(emit_fresh_graph(a.output)if a.output is not None else fresh_graph_result(fresh_graph_inputs()[0]),sort_keys=True));return
 if a.gzip1:
  need(not(a.module_indexes or a.host_clock or a.virtio20 or a.automatic_rollback),'one explicit VM-only gzip1 profile');print(json.dumps(emit_gzip1(a.output)if a.output is not None else gzip1_result(gzip1_inputs()[0]),sort_keys=True));return
 if a.module_indexes:
  need(not(a.host_clock or a.virtio20 or a.automatic_rollback),'one explicit module-index two-boot profile');print(json.dumps(emit_module_indexes(a.output)if a.output is not None else host_clock_result(module_index_inputs()[0]),sort_keys=True));return
 if a.host_clock:print(json.dumps(emit_host_clock(a.output,a.automatic_rollback)if a.output is not None else host_clock_result(host_clock_inputs(a.automatic_rollback)[0]),sort_keys=True));return
 selected_emit=emit_rollback if a.automatic_rollback else emit_virtio20 if a.virtio20 else emit;selected_inputs=rollback_inputs if a.automatic_rollback else virtio20_inputs if a.virtio20 else inputs;selected_result=rollback_result if a.automatic_rollback else result;print(json.dumps(selected_emit(a.output)if a.output is not None else selected_result(selected_inputs()[0]),sort_keys=True))
if __name__=='__main__':main()
