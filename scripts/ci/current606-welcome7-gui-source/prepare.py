#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact current606 Welcome7 GUI source from whole published media536; no actors."""
import argparse,base64,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 2447858, 'sha256': '463f2457f26929c640a6cc4e9504a9d25714ba354beaa227ee1c249e637857f9'}
BUILDKIT_PROFILE={'bytes': 206903, 'sha256': 'a199a2959a6b2fca5254466cc809ae2e199ab6d9fa8c27d4f09b7a6cee8744b3'}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and Path(name).as_posix()==name and '\\'not in name and all(n not in('','.','..')for n in name.split('/')),'contained source path');return name

def ordinary(path,cap=16*1024**2):
 path=Path(path).absolute();need('..'not in path.parts,'ordinary source path');parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for part in path.parts[1:-1]:
   fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=fd
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  try:
   a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary single-link source');raw=bytearray()
   while len(raw)<=a.st_size:
    part=os.read(fd,min(65536,a.st_size-len(raw)+1))
    if not part:break
    raw.extend(part)
   b=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   need(key(a)==key(b)==key(os.stat(path.name,dir_fd=parent,follow_symlinks=False))and len(raw)==a.st_size,'source changed during read');return bytes(raw)
  finally:os.close(fd)
 finally:os.close(parent)

def files(root):
 need(root.is_absolute()and root.is_dir()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary explicit predecessor root');out={}
 for parent,dirs,names in os.walk(root):
  if Path(parent)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  for n in dirs:need(not(Path(parent)/n).is_symlink(),'source directory alias')
  for n in names:
   p=Path(parent)/n;out[p.relative_to(root).as_posix()]=ordinary(p)
 return out

def profile():
 raw=ordinary(HERE/'source.json');need(pin(raw)==PROFILE,'whole frozen GUI source authority');return json.loads(raw)


def prepare(predecessor,output):
 p=profile();before=files(predecessor);need(p['status']=='FINITE_CURRENT606_GUI540_SOURCE_FACTORY'and p['predecessor']['source']=='3ed3da9c3393cbc56522db7311005049413204f3'and len(before)==536 and {n:pin(b)for n,b in before.items()}==p['predecessor']['files'],'complete genuine media536 predecessor before output')
 wanted=p['output']['files'];need(len(wanted)==540 and set(before)<=set(wanted)and set(wanted)-set(before)==set(p['added'])and {n for n in before if pin(before[n])!=wanted[n]}==set(p['changed'])and len(p['changed'])==4 and len(p['added'])==4,'finite complete corrective540 source delta')
 result={}
 for name,row in wanted.items():
  relative(name);raw=before[name]if name in before and pin(before[name])==row else base64.b64decode(p['blobs'][row['sha256']],validate=True);need(pin(raw)==row,'whole exact proposed source body');result[name]=raw
 for name in('factory/context606.py','factory/install606.py','factory/factory.py','factory/hwcap_probe.c','factory/user_hwcap.py','factory/run.py','native.py','factory/kernel_stage.py','kernel-media-profile.json','bootstrap-plan.json'):
  need(result[name]==before[name],'both FDK operands, actual probes, independent modes and retirement held')
 media=json.loads(result['kernel-media-profile.json']);need(media['source']=='5a643db838759d7cf574e596efbcd45b1df96984'and media['ref']=='codex/current606-gui16-kernel-media-v1'and len(media['files'])==66 and media['actual']is None and media['ready']is True,'exact genuine media66 input profile without actual GUI authority')
 extension=json.loads(result['extension-input-profile.json']);need(extension['status']=='ORIGINAL13_26_FOUR_FIXED_INPUT_NAMESPACES_ONLY'and extension['actual']is None and len(extension['files'])==26 and set(extension['carriers'])=={'retained574','compiler6','official3','legacy2'},'exact original13/26 input routes without native authority')
 need({n:pin(b)for n,b in result.items()}==wanted,'whole540 equality before output');output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary source output')
 output.mkdir(mode=0o700)
 for name,raw in result.items():target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(b)for n,b in files(output).items()}==wanted,'whole540 emitted source equality');return dict(status='SOURCE_ONLY_CURRENT606_WELCOME7_GUI_NOT_NATIVE',files=540,source_authority=p['output']['source'],profiles=['minimal','overlay'],page_modes=['generic4k','generic16k'],guest_packages=606,controller_packages=590,actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED')

def prepare_welcome8(predecessor,output):
 p=profile();v=p['welcome8'];before=files(predecessor);need(v['predecessor']['source']=='bb72a0fc5e84af5621f0b783056137efdd780282'and len(before)==540 and {n:pin(b)for n,b in before.items()}==v['predecessor']['files'],'complete genuine corrective540 predecessor before Welcome8 output')
 wanted=v['output']['files'];need(len(wanted)==544 and set(wanted)-set(before)==set(v['added'])and set(before)-set(wanted)==set(v['removed'])and {n for n in before if n in wanted and pin(before[n])!=wanted[n]}==set(v['changed'])and(len(v['changed']),len(v['added']),len(v['removed']))==(13,5,1),'finite exact Welcome8 graph/Stop/metadata/cleanup successor')
 result={}
 for name,row in wanted.items():
  relative(name);raw=before[name]if name in before and pin(before[name])==row else base64.b64decode(p['blobs'][row['sha256']],validate=True);need(pin(raw)==row,'whole exact Welcome8 source body');result[name]=raw
 for name in('bootstrap2.py','bootstrap-plan.json','extension_inputs.py','extension-input-profile.json','factory/hwcap_probe.c','factory/user_hwcap.py','factory/kernel_stage.py','kernel-media-profile.json','factory/current_products.py'):
  need(result[name]==before[name],'original bootstrap, ALPM/input routes, media, actual probes and current product commands held')
 need({n:pin(b)for n,b in result.items()}==wanted,'whole544 equality before output');output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary source output')
 output.mkdir(mode=0o700)
 for name,raw in result.items():target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(b)for n,b in files(output).items()}==wanted,'whole544 emitted source equality');return dict(status='SOURCE_ONLY_WELCOME8_INSTALLED606_GUI_NOT_NATIVE',files=544,source_authority=v['output']['source'],profiles=['minimal','overlay'],page_modes=['generic4k','generic16k'],guest_packages=606,controller_packages=590,actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED')

def prepare_transport(predecessor,output):
 p=profile();v=p['transport'];before=files(predecessor);need(v['predecessor']['source']=='7b8be687a3562640d5f7d4a7c57f2e2d61d39dc1'and len(before)==544 and {n:pin(b)for n,b in before.items()}==v['predecessor']['files'],'complete genuine544 before transport output')
 wanted=v['output']['files'];need(v['output']['source']=='ac70245709f336d2c670b2b511bec40c99248370'and len(wanted)==546 and set(wanted)-set(before)==set(v['added'])and set(before)-set(wanted)==set(v['removed'])and {n for n in before if pin(before[n])!=wanted[n]}==set(v['changed'])and(len(v['changed']),len(v['added']),len(v['removed']))==(5,2,0),'finite transport-only546 delta')
 result={}
 for name,row in wanted.items():
  relative(name);raw=before[name]if name in before and pin(before[name])==row else base64.b64decode(p['blobs'][row['sha256']],validate=True);need(pin(raw)==row,'whole exact transport source body');result[name]=raw
 for name in set(before)-set(v['changed']):need(result[name]==before[name],'all539 original product/runtime/positive source leaves held')
 need({n:pin(b)for n,b in result.items()}==wanted,'whole546 equality before output');output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary source output')
 output.mkdir(mode=0o700)
 for name,raw in result.items():target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(b)for n,b in files(output).items()}==wanted,'whole546 emitted equality');return dict(status='SOURCE_ONLY_GUI_DIAGNOSTIC_TRANSPORT_NOT_NATIVE',files=546,source_authority=v['output']['source'],actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED',runtime_image_failure='UNRESOLVED_REQUIRES_GENUINE_ERROR_BYTES')

def buildkit_profile():
 raw=ordinary(HERE/'buildkit.json');need(pin(raw)==BUILDKIT_PROFILE,'whole frozen BuildKit source authority');return json.loads(raw)

def prepare_buildkit(predecessor,output):
 p=buildkit_profile();before=files(predecessor);prior=p['predecessor'];wanted=p['output']['files']
 need(p['status']=='FINITE_GUI548_BUILDKIT_SOURCE_ONLY'and p['actual']is None and prior['source']=='ac70245709f336d2c670b2b511bec40c99248370'and len(before)==546 and {n:pin(b)for n,b in before.items()}==prior['files'],'complete genuine546 before BuildKit output')
 need(p['output']['source']=='865cc33c8f114c15cef75b3472fbb8d1f4e8da06'and len(wanted)==548 and set(wanted)-set(before)==set(p['added'])and not(set(before)-set(wanted))and {n for n in before if pin(before[n])!=wanted[n]}==set(p['changed'])and(len(p['changed']),len(p['added']),len(p['removed']))==(8,2,0),'finite exact BuildKit548 source delta')
 names={'admission.py','factory/context606.py','factory/factory.py','factory/install606.py','factory/install_tooling.py','factory/qemu_context.py','native.py','factory/build_scope.py'};need(set(p['templates'])==names and set(p['added'])=={'build-parent.json','factory/build_scope.py'},'eight exact readable BuildKit source bodies')
 result=dict(before)
 for name,row in p['templates'].items():
  relative(name);relative(row['path']);raw=ordinary(HERE/row['path']);need(pin(raw)=={k:row[k]for k in('bytes','sha256')}==wanted[name],'whole exact readable BuildKit template');result[name]=raw
 result['build-parent.json']=encoded(dict(source=prior['source'],files=prior['files'],before_bodies={n:base64.b64encode(before[n]).decode()for n in p['changed']},actual=None))
 manifest=json.loads(before['source-manifest.json']);manifest.update(status='SOURCE_ONLY_CURRENT606_WELCOME8_BUILDKIT_SCOPE_NOT_ACCEPTED',files={n:pin(raw)for n,raw in result.items()if n!='source-manifest.json'});result['source-manifest.json']=encoded(manifest)
 need({n:pin(raw)for n,raw in result.items()}==wanted,'whole548 equality before output')
 for name in set(before)-set(p['changed']):need(result[name]==before[name],'all538 original source bodies held')
 output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary BuildKit output');output.mkdir(mode=0o700)
 for name,raw in result.items():target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(raw)for n,raw in files(output).items()}==wanted,'whole548 emitted equality');return dict(status='SOURCE_ONLY_GUI_BUILDKIT548_NOT_NATIVE',files=548,source_authority=p['output']['source'],actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED',native_GUI='NOT_RUN',default='UNCHANGED540')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--predecessor-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);group=p.add_mutually_exclusive_group();group.add_argument('--welcome8',action='store_true',help='exact544 from corrective540');group.add_argument('--transport',action='store_true',help='explicit exact546 diagnostic transport from whole544; default540 andWelcome8 outputs held');group.add_argument('--buildkit',action='store_true',help='explicit exact548 BuildKit scope from whole546; old540/544/546 outputs held');a=p.parse_args();emit=prepare_buildkit if a.buildkit else prepare_transport if a.transport else prepare_welcome8 if a.welcome8 else prepare;print(encoded(emit(a.predecessor_root.absolute(),a.output.absolute())).decode(),end='')
