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


LOADER_PROFILE={'bytes': 204239, 'sha256': '51b52f24201b48bd9d9123ea66b41bfd3a42e3cf49406c91aed6146078fbe7fd'}
def loader_profile():
 raw=ordinary(HERE/'loader.json');need(pin(raw)==LOADER_PROFILE,'whole finite GUI549 loader profile');return json.loads(raw)

def prepare_loader(predecessor,output):
 p=loader_profile();before=files(predecessor);prior=p['predecessor'];wanted=p['output']['files']
 need(p['status']=='FINITE_GUI549_DEFINED_GUEST_LOADER_SOURCE_ONLY'and p['actual']is None and prior['source']=='865cc33c8f114c15cef75b3472fbb8d1f4e8da06'and len(before)==548 and {n:pin(b)for n,b in before.items()}==prior['files'],'whole genuine548 before loader output')
 changed={'factory/factory.py','admission.py','source-manifest.json'};need(p['output']['source']=='4e63aa1c67898417d3a47335c0af1cc8e0b7fa3f'and len(wanted)==549 and set(wanted)-set(before)=={'loader-parent.json'}and not(set(before)-set(wanted))and {n for n in before if pin(before[n])!=wanted[n]}==set(p['changed'])==changed and set(p['templates'])==changed-{'source-manifest.json'},'one exact finite loader successor')
 result=dict(before)
 for n,row in p['templates'].items():
  relative(n);relative(row['path']);raw=ordinary(HERE/row['path']);need(pin(raw)=={k:row[k]for k in('bytes','sha256')}==wanted[n],'whole readable loader template');result[n]=raw
 result['loader-parent.json']=encoded(dict(source=prior['source'],files=prior['files'],before_bodies={n:base64.b64encode(before[n]).decode()for n in changed},actual=None))
 manifest=json.loads(before['source-manifest.json']);manifest.update(status='SOURCE_ONLY_CURRENT606_WELCOME8_GUEST_LOADER_NOT_ACCEPTED',files={n:pin(b)for n,b in result.items()if n!='source-manifest.json'});result['source-manifest.json']=encoded(manifest)
 need({n:pin(b)for n,b in result.items()}==wanted,'whole549 equality before output')
 output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint source-only loader output');output.mkdir(mode=0o700)
 for n,raw in result.items():target=output/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(b)for n,b in files(output).items()}==wanted,'whole549 emitted equality')
 return dict(status='SOURCE_ONLY_GUI549_DEFINED_GUEST_LOADER_NOT_NATIVE',files=549,source_authority=p['output']['source'],actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED',native_GUI='NOT_RUN',default='UNCHANGED540')


APPS8_PROFILE={'bytes': 229540, 'sha256': 'bb2bd1b42f045653742345e6d28cf7bc27c2141223f76fe534a3ecdf0099d87d'}
def apps8_profile():
 raw=ordinary(HERE/'apps8.json',256*1024);need(pin(raw)==APPS8_PROFILE,'whole exact accepted Apps8 GUI profile');return json.loads(raw)

def prepare_apps8(predecessor,output):
 p=apps8_profile();before=files(predecessor);prior=p['predecessor'];wanted=p['output']['files'];need(p['status']=='FINITE_GUI556_ALIAS_CORRECTED_ACCEPTED_APPS8_SOURCE_ONLY'and p['actual']is None and prior['source']=='4e63aa1c67898417d3a47335c0af1cc8e0b7fa3f'and len(before)==549 and {n:pin(b)for n,b in before.items()}==prior['files'],'whole genuine549 before Apps8 output')
 need(p['output']['source']=='a8304cecaee54141b42edd48f9482b9f4ab0700f'and len(wanted)==556 and set(wanted)-set(before)==set(p['added'])and not(set(before)-set(wanted))and {n for n in before if pin(before[n])!=wanted[n]}==set(p['changed'])and len(p['changed'])==11 and len(p['added'])==7,'finite exact alias-corrected Apps8 delta11changed538held7added')
 selection=p['selection'];s=selection['selection'];need(selection['status']=='ROOT_BOUND_ACCEPTED_APPS8_INPUTS_ONLY_NO_GUI_AUTHORITY'and s['source']=='979b2d6ec7417e607a911d8c25bef2f1f7f72dcb'and s['ref']=='codex/apps8-accepted-inputs-v1'and len(s['files'])==93 and s['pair_source']=='f1984a2481c541add7eb99b311a3ae3228307aa6'and s['pair_run']==39727987029 and s['recipe_source']=='98a0a6ab18355604683bee42c84c393940a690a1'and s['package']['version']=='0.1.0-8'and s['package']['size']==23528 and s['package']['sha256']=='d4d83458765d732ae78664143c9042dcc1159b7d3e19f4b7976f8499c2619f4a'and selection['actual_source']is selection['actual_ref']is selection['actual_run']is s['actual']is None,'exact accepted Apps8 pair input custody with no GUI authority')
 result=dict(before)
 for name,row in p['templates'].items():
  relative(name);relative(row['path']);raw=ordinary(HERE/row['path']);need(pin(raw)=={k:row[k]for k in('bytes','sha256')}==wanted[name],'whole readable Apps8 template before output');result[name]=raw
 result['.github/workflows/native-arm-build.yml']=result['.github/workflows/native-arm-current606-welcome8-gui.yml']
 result['apps8-selection.json']=encoded(selection);row=json.loads(before['input-policy33.json']);need(row['packages']['cachy-asahi-apps']['version']=='0.1.0-7','exact previous Apps7 policy');row['packages']['cachy-asahi-apps']=s['package'];result['input-policy33.json']=encoded(row)
 lock=before['factory/expected606.lock'];need(lock.count(b'cachy-asahi-apps 0.1.0-7\n')==1,'one exact original Apps7 graph operand');result['factory/expected606.lock']=lock.replace(b'cachy-asahi-apps 0.1.0-7\n',b'cachy-asahi-apps 0.1.0-8\n',1)
 profile=json.loads(before['factory/profile.json']);profile['versions']['cachy-asahi-apps']='0.1.0-8';profile['native_archives']['cachy-asahi-apps']=dict(bytes=s['package']['size'],sha256=s['package']['sha256']);profile['expected606']=pin(result['factory/expected606.lock']);result['factory/profile.json']=encoded(profile)
 result['apps8-parent.json']=encoded(dict(source=prior['source'],actual=None,files=prior['files'],before_bodies={n:base64.b64encode(before[n]).decode()for n in sorted(p['changed'])}));result['source-manifest.json']=encoded(dict(status='SOURCE_ONLY_CURRENT606_WELCOME8_APPS8_NO_NEW_GUI_ACCEPTANCE',files={n:pin(raw)for n,raw in sorted(result.items())if n!='source-manifest.json'},actual_source=None,actual_ref=None,actual_run=None))
 need({n:pin(raw)for n,raw in result.items()}==wanted,'whole556 exact Apps8 equality before output')
 for name in set(before)-set(p['changed']):need(result[name]==before[name],'all538 original source leaves held')
 output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary Apps8 output');output.mkdir(mode=0o700)
 for name,raw in result.items():target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(raw)for n,raw in files(output).items()}==wanted,'whole556 emitted equality');return dict(status='SOURCE_ONLY_GUI556_ACCEPTED_APPS8_INPUTS_NOT_NATIVE',files=556,source_authority=p['output']['source'],actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED',native_GUI='NOT_RUN',default='UNCHANGED540')

CORRECTION_PROFILE={'bytes': 2176, 'sha256': '7843972380cee4b459f26f90da0c7db33c0704fa3a6e3bc527a6ca801a719394'}
def correction_inputs():
 raw=ordinary(HERE/'correction-profile.json');need(pin(raw)==CORRECTION_PROFILE,'whole pinned installer-lock-correction profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_INSTALLER_LOCK_CORRECTION'and p['actual']is None and p['before_source']=='a8304cecaee54141b42edd48f9482b9f4ab0700f'and p['after_source']=='09f7758b20c638f302086374931e7e5ceb3ca6fd','exact published correction source case')
 raw=ordinary(HERE/'correction-maps.json');need(pin(raw)==p['maps'],'whole correction before/after map pins');maps=json.loads(raw);before,after=maps['before'],maps['after'];need(set(before)==set(after)and len(after)==p['files']==556 and {n for n in before if before[n]!=after[n]}==set(p['changed'])and len(p['changed'])==4 and p['held']==552,'finite exact correction operands')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'complete correction before/proposed operands')
 need(p['payload']=={n:after[n]for n in p['changed']},'exact readable correction payload set')
 payload=files((HERE/'correction-payload').absolute());need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole correction payload closure')
 return p,before,after,payload

def prepare_installer_lock(predecessor,output):
 variant,before,after,payload=correction_inputs();bodies=files(predecessor);need({n:pin(raw)for n,raw in bodies.items()}==before,'whole exact a830 Apps8 predecessor before installer correction');bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole corrected556 before any output');output=Path(output).absolute();need(not os.path.lexists(output)and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary installer-correction output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  target=output/n;target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in files(output).items()}==after,'whole corrected556 emitted equality');return dict(status='SOURCE_ONLY_EXACT556_INSTALLER_LOCK_NOT_NATIVE',files=556,source=variant['after_source'],previous_source=variant['before_source'],held=variant['held'],changed=len(payload),actual=None,native_GUI='NOT_RUN',hardware='NOT_RUN')


CLI_FAILURE_PROFILE={'bytes': 2802, 'sha256': '640b3cb65ea6ab772aaae2fb6e724d6622c26c8317aa54311973ee5e13e30a19'}
def cli_failure_inputs():
 raw=ordinary(HERE/'apps-cli-failure-profile.json');need(pin(raw)==CLI_FAILURE_PROFILE,'whole pinned apps-cli-failure profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_APPS_CLI_FAILURE'and p['actual']is None and p['before_source']=='09f7758b20c638f302086374931e7e5ceb3ca6fd'and p['after_source']=='51e7797ef639de8fbed96e51b5b12bf5a92c7cb7','exact published followup source case')
 raw=ordinary(HERE/'apps-cli-failure-maps.json');need(pin(raw)==p['maps'],'whole followup before/after map pins');m=json.loads(raw);before,after=m['before'],m['after'];need(before.keys()==after.keys()and len(after)==p['files']==556 and {n for n in before if before[n]!=after[n]}==set(p['changed'])and len(p['changed'])==5 and p['held']==551,'finite exact followup operands')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'complete followup source operands')
 need(p['payload']=={n:after[n]for n in p['changed']},'exact readable followup payload set');payload=files((HERE/'apps-cli-failure-payload').absolute());need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole readable followup payload closure');return p,before,after,payload

def prepare_cli_failure_data(predecessor,output):
 installer,before,installed,first=correction_inputs();p,previous,after,replacements=cli_failure_inputs();need(installed==previous,'whole installer correction feeds exact CLI diagnostic');bodies=files(predecessor);need({n:pin(raw)for n,raw in bodies.items()}==before,'whole alias-corrected a830 input before any output');bodies.update(first);need({n:pin(raw)for n,raw in bodies.items()}==installed,'whole09f installer correction in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole51e failure diagnostic in memory before output');output=Path(output).absolute();need(not os.path.lexists(output)and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary CLI diagnostic output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in files(output).items()}==after,'whole51e emitted source equality');return dict(status='SOURCE_ONLY_EXACT556_APPS_CLI_FAILURE_DATA_NOT_NATIVE',files=556,source=p['after_source'],previous_source=p['before_source'],held=p['held'],changed=len(replacements),actual=None,native_GUI='NOT_RUN',hardware='NOT_RUN')


def prepare_apps9(predecessor,output,unbound=False):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_Apps9_source_option',HERE/'apps9.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound)

def prepare_apps10_stage(predecessor,output,unbound=False):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_Apps10_stage_option',HERE/'apps10.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound)

def prepare_apps14_stage(predecessor,output,unbound=False):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_Apps14_source_option',HERE/'apps14.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound)


def prepare_failure_cleanup(predecessor,output):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_failure_cleanup',HERE/'failure_cleanup_source.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output)


def prepare_apps16(predecessor,output,unbound=False,carrier=None):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_Apps16_source_option',HERE/'apps16.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound,carrier)


def prepare_apps16_restore604(predecessor,output,unbound=False):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_Apps16_restore604',HERE/'apps16_restore604.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound)

def prepare_apps16_isolated_import(predecessor,output,unbound=False):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_Apps16_isolated_import',HERE/'apps16_isolated_import.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound)

def prepare_apps16_inventory_caller60(predecessor,output,unbound=False):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_inventory_caller60',HERE/'apps16_inventory_caller60.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--predecessor-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);group=p.add_mutually_exclusive_group();group.add_argument('--welcome8',action='store_true',help='exact544 from corrective540');group.add_argument('--transport',action='store_true',help='explicit exact546 diagnostic transport from whole544; default540 andWelcome8 outputs held');group.add_argument('--buildkit',action='store_true',help='explicit exact548 BuildKit scope from whole546; old540/544/546 outputs held');group.add_argument('--loader',action='store_true',help='explicit exact549 defined guest loader from whole548; old outputs held');group.add_argument('--apps8',action='store_true',help='explicit exact alias-corrected556 Apps8 input adoption from whole549; all old outputs held');group.add_argument('--installer-lock-correction',action='store_true',help='exact09f installer-lock correction from wholea830; all prior outputs held');group.add_argument('--apps-cli-failure-data',action='store_true',help='exact51e bounded CLI failure DATA after installer correction; all old outputs held');group.add_argument('--apps9',action='store_true',help='explicit exact557 qualified Apps9 input source from whole51e556; all old outputs held');group.add_argument('--apps9-unbound',action='store_true',help='strict NULL557 template, refuses actors; never dispatch');group.add_argument('--apps10-stage',action='store_true',help='exact genuine559 Apps10 optional stage diagnostics; every previous output held');group.add_argument('--apps10-stage-unbound',action='store_true',help='strict NULL559 source template, refuses actors');group.add_argument('--apps14-stage',action='store_true',help='exact genuine559 Apps14 single-encoding input; previous routes held');group.add_argument('--apps14-stage-unbound',action='store_true',help='strict NULL559 Apps14 source; refuses actors');group.add_argument('--failure-cleanup',action='store_true',help='exact561 late failed GUI ownership retirement from genuine Apps14 source559; positive15 unchanged');group.add_argument('--apps16',action='store_true',help='exact published561 Apps16 source from cleanup561 plus complete accepted carrier94');group.add_argument('--apps16-unbound',action='store_true',help='strict NULL561 Apps16 template; no carrier or actual authority');p.add_argument('--apps16-carrier-root',type=Path,help='required complete accepted Apps16 carrier94 for --apps16 only');group.add_argument('--apps16-restore604',action='store_true',help='exact published562 restore604 source from exact selected Apps16 GUI561');group.add_argument('--apps16-restore604-unbound',action='store_true',help='exact NULL562 restore604 template from exact NULL Apps16 GUI561');group.add_argument('--apps16-isolated-import',action='store_true',help='exact published565 isolated startup from restore562; all older routes held');group.add_argument('--apps16-isolated-import-unbound',action='store_true',help='exact NULL565 from NULL562; refuses actors');group.add_argument('--apps16-inventory-caller60',action='store_true',help='explicit TCG caller60 source570 from public restore562; product30/default35 held');group.add_argument('--apps16-inventory-caller60-unbound',action='store_true',help='strict NULL570 derived from public restore562; refuses actors');a=p.parse_args();emit=(lambda parent,out:prepare_apps16_inventory_caller60(parent,out,a.apps16_inventory_caller60_unbound)) if a.apps16_inventory_caller60 or a.apps16_inventory_caller60_unbound else (lambda parent,out:prepare_apps16_isolated_import(parent,out,a.apps16_isolated_import_unbound)) if a.apps16_isolated_import or a.apps16_isolated_import_unbound else (lambda parent,out:prepare_apps16_restore604(parent,out,a.apps16_restore604_unbound)) if a.apps16_restore604 or a.apps16_restore604_unbound else (lambda parent,out:prepare_apps16(parent,out,a.apps16_unbound,a.apps16_carrier_root)) if a.apps16 or a.apps16_unbound else prepare_failure_cleanup if a.failure_cleanup else (lambda parent,out:prepare_apps14_stage(parent,out,a.apps14_stage_unbound)) if a.apps14_stage or a.apps14_stage_unbound else (lambda parent,out:prepare_apps10_stage(parent,out,a.apps10_stage_unbound)) if a.apps10_stage or a.apps10_stage_unbound else (lambda parent,out:prepare_apps9(parent,out,a.apps9_unbound)) if a.apps9 or a.apps9_unbound else prepare_cli_failure_data if a.apps_cli_failure_data else prepare_installer_lock if a.installer_lock_correction else prepare_apps8 if a.apps8 else prepare_loader if a.loader else prepare_buildkit if a.buildkit else prepare_transport if a.transport else prepare_welcome8 if a.welcome8 else prepare;print(encoded(emit(a.predecessor_root.absolute(),a.output.absolute())).decode(),end='')
