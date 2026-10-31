#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact380 from complete348 and accepted carrier93; source-only, no actors."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 20243, 'sha256': '926cd8a673e8fd934893c0efa30dcbd8eb8616233c8d4355b06d8ea09395ade1'}

def need(ok,why):
 if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def ordinary(path):
 path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'no source/output aliases or traversal');return path

def read(path):
 path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'bounded singlelink source/support input');raw=bytearray()
  while block:=os.read(fd,1024**2):raw.extend(block);need(len(raw)<=a.st_size,'source grew during read')
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable atime-independent source identity');return bytes(raw)
 finally:os.close(fd)

def source(root,wanted):
 root=ordinary(root);need(root.is_dir(),'whole source/support directory required');expected_dirs={''}
 for n in wanted:
  p=Path(n);need(n and not p.is_absolute()and p.as_posix()==n and not set(p.parts)&{'.','..'}and'\\'not in n,'fixed canonical relative source path');expected_dirs.update(q.as_posix()if str(q)!='.'else''for q in p.parents)
 bodies={};directories={''}
 for p in sorted(root.rglob('*')):
  name=p.relative_to(root).as_posix()
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink(),'source/support symlink refused')
  if p.is_dir():directories.add(name)
  else:need(name in wanted,'extra source/support file');bodies[name]=read(p)
 need(directories==expected_dirs and{n:pin(v)for n,v in bodies.items()}==wanted,'complete exact source/support closure including directories');return bodies

def inputs():
 need(not sys.flags.optimize,'optimized source checks refused');raw=read(HERE/'profile.json');need(pin(raw)==PROFILE,'whole pinned Apps8/current606 factory profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_APPS8_CURRENT606_380_FACTORY'and p['actual']is None and p['parent']['source']=='3660e6cb87b4cb5591b1d295c62c8b02cca4b7e6'and p['carrier']['source']=='979b2d6ec7417e607a911d8c25bef2f1f7f72dcb'and p['carrier']['ref']=='codex/apps8-accepted-inputs-v1'and p['result']['source']=='c2b61b7089e41baed6b284bf0f3a55819f661c05','only exact published348/carrier93/result380 source case')
 maps=[]
 for name,row in(('parent348.json',p['parent']),('carrier93.json',p['carrier']),('expected380.json',p['result'])):
  raw=read(HERE/name);need(pin(raw)==row['map'],'whole hardpinned input/output map');maps.append(json.loads(raw))
 before,carrier,after=maps;need((len(before),len(carrier),len(after))==(348,93,380)and set(before)<=set(after)and set(after)-set(before)==set(p['added'])and {n for n in before if before[n]!=after[n]}==set(p['changed'])and(len(p['changed']),len(p['added']),p['held'])==(16,32,332),'finite16changed32added332held source closure')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'exact original and proposed source operands')
 need(p['payload']=={n:after[n]for n in set(p['changed'])|set(p['added'])},'exact48 source replacement/addition bodies')
 for name,w in p['legal'].items():need(name in('LICENSE','NOTICE.md')and pin(read(HERE/name))==w,'whole original source-factory license/notice')
 need(set(p['legal'])=={'LICENSE','NOTICE.md'},'complete factory legal closure');return p,before,carrier,after,source(HERE/'payload',p['payload'])

def emit(parent,carrier,output):
 p,before,input_map,after,payload=inputs();parent,carrier,output=map(ordinary,(parent,carrier,output));need(not os.path.lexists(output)and output.parent.is_dir()and all(not output.is_relative_to(root)and not root.is_relative_to(output)for root in(parent,carrier)),'fresh disjoint source-only output');bodies=source(parent,before);source(carrier,input_map)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole exact380 before any output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,after).items()}==after,'complete final380 output');return dict(status='SOURCE_ONLY_EXACT_APPS8_CURRENT606_380_NOT_NATIVE_ACCEPTANCE',files=380,source=p['result']['source'],parent=p['parent']['source'],carrier=p['carrier']['source'],held=332,changed=16,added=32,actual=None,native='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

CORRECTION_PROFILE={'bytes': 2854, 'sha256': '271e9c170590dd46247099f0cf4b4395ecd1ae20ed57697b2a1ce265560c3efb'}
def correction_inputs():
 raw=read(HERE/'correction-profile.json');need(pin(raw)==CORRECTION_PROFILE,'whole pinned carrier-env-correction profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_CARRIER_ENV_CORRECTION'and p['actual']is None and p['before_source']=='c2b61b7089e41baed6b284bf0f3a55819f661c05'and p['after_source']=='5c3c2d0ce5b4f6c2672c9367b722170687c7de69','exact published correction source case')
 raw=read(HERE/'correction-maps.json');need(pin(raw)==p['maps'],'whole correction before/after map pins');maps=json.loads(raw);before,after=maps['before'],maps['after'];need(set(before)==set(after)and len(after)==p['files']==380 and {n for n in before if before[n]!=after[n]}==set(p['changed'])and len(p['changed'])==5 and p['held']==375,'finite exact correction operands')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'complete correction before/proposed operands')
 need(p['payload']=={n:after[n]for n in p['changed']},'exact readable correction payload set')
 payload=source(HERE/'correction-payload',p['payload'])
 return p,before,after,payload

def emit_carrier_env(parent,carrier,output):
 p,before,input_map,old,payload=inputs();variant,previous,after,replacements=correction_inputs();need(old==previous,'whole original380 correction input');parent,carrier,output=map(ordinary,(parent,carrier,output));need(not os.path.lexists(output)and output.parent.is_dir()and all(not output.is_relative_to(root)and not root.is_relative_to(output)for root in(parent,carrier)),'fresh disjoint source-only correction output');bodies=source(parent,before);source(carrier,input_map)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==old,'whole original380 emission in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole corrected380 before any output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 source(output,after);return dict(status='SOURCE_ONLY_EXACT380_CARRIER_ENV_CORRECTION_NOT_NATIVE',files=380,source=variant['after_source'],previous_source=variant['before_source'],held=variant['held'],changed=len(replacements),actual=None,native='NOT_RUN',hardware='NOT_RUN')


APPS9_PROFILE={'bytes': 11688, 'sha256': 'b6ba7a62a0f4c88cf3a925f066fbc8673c01dbb99e621a5603fcb8a5472b917d'}
def apps9_inputs():
 raw=read(HERE/'apps9-profile.json');need(pin(raw)==APPS9_PROFILE,'whole hardpinned Apps9 source profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_APPS9_CURRENT606_389'and p['actual']is None and(p['before_source'],p['after_source'],p['carrier_source'],p['carrier_ref'])==('5c3c2d0ce5b4f6c2672c9367b722170687c7de69','51399738e2cb98551fbb84c930156022fd734029','128b9806c8e972a729d5c1ef4f2dc9e39e48fc42','codex/apps9-accepted-inputs-v1'),'exact published Apps9 source and accepted pair input')
 raw=read(HERE/'apps9-maps.json');need(pin(raw)==p['maps'],'whole Apps9 parent/carrier/result maps');maps=json.loads(raw);before,after,carrier=maps['before'],maps['after'],maps['carrier'];need((len(before),len(after),len(carrier))==(380,389,93)and set(before)<=set(after)and{n for n in before if before[n]!=after[n]}==set(p['changed'])and set(after)-set(before)==set(p['added'])and(len(p['changed']),len(p['added']),p['held'])==(16,9,364),'exact finite Apps9 delta')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'whole before/proposed Apps9 operand')
 need(p['payload']=={n:after[n]for n in set(p['changed'])|set(p['added'])},'exact25 readable Apps9 source payloads')
 need(set(p['legal'])=={'apps9-NOTICE.md','LICENSE'},'complete Apps9 legal closure')
 for n,w in p['legal'].items():need(pin(read(HERE/n))==w,'whole Apps9 source legal leaf')
 return p,before,carrier,after,source(HERE/'apps9-payload',p['payload'])

def emit_apps9(parent,carrier,apps9_carrier,output):
 p,before,input_map,old,payload=inputs();correction,previous,corrected,replacements=correction_inputs();variant,current,input9,after,selected=apps9_inputs();need(old==previous and corrected==current,'whole default and carrier-env corrected380 prerequisites');parent,carrier,apps9_carrier,output=map(ordinary,(parent,carrier,apps9_carrier,output));need(not os.path.lexists(output)and output.parent.is_dir()and all(not output.is_relative_to(root)and not root.is_relative_to(output)for root in(parent,carrier,apps9_carrier)),'fresh disjoint Apps9 source-only output');bodies=source(parent,before);source(carrier,input_map);source(apps9_carrier,input9)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==old,'entire original c2 source380 in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==current,'entire corrected5c3 source380 in memory');bodies.update(selected);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole exact389 before first output write');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 source(output,after);return dict(status='SOURCE_ONLY_EXACT_APPS9_CURRENT606_389_NOT_NATIVE_ACCEPTANCE',files=389,source=variant['after_source'],previous_source=variant['before_source'],carrier=variant['carrier_source'],held=364,changed=16,added=9,actual=None,native='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')


APPS10_PROFILE={'bytes': 11709, 'sha256': '306732e2d3b14e931c5baffd6b973e0d62a2537f8b07aae83b7ce8059032797d'}
def apps10_inputs():
 raw=read(HERE/'apps10-profile.json');need(pin(raw)==APPS10_PROFILE,'whole hardpinned Apps10 source profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_APPS10_CURRENT606_389'and p['actual']is None and(p['before_source'],p['after_source'],p['carrier_source'],p['carrier_ref'])==('5c3c2d0ce5b4f6c2672c9367b722170687c7de69','eeb7fc5c3bcaa5b152ca6eb97983f6c31f8d0cdb','a2bbf5edd57a7a31951a1e9060c83698f29302c4','codex/apps10-accepted-inputs-v1'),'exact published Apps10 source and accepted pair input')
 raw=read(HERE/'apps10-maps.json');need(pin(raw)==p['maps'],'whole Apps10 parent/carrier/result maps');maps=json.loads(raw);before,after,carrier=maps['before'],maps['after'],maps['carrier'];need((len(before),len(after),len(carrier))==(380,389,94)and set(before)<=set(after)and{n for n in before if before[n]!=after[n]}==set(p['changed'])and set(after)-set(before)==set(p['added'])and(len(p['changed']),len(p['added']),p['held'])==(16,9,364),'exact finite Apps10 delta')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'whole before/proposed Apps10 operand')
 need(p['payload']=={n:after[n]for n in set(p['changed'])|set(p['added'])},'exact25 readable Apps10 source payloads')
 need(set(p['legal'])=={'apps10-NOTICE.md','LICENSE'},'complete Apps10 legal closure')
 for n,w in p['legal'].items():need(pin(read(HERE/n))==w,'whole Apps10 source legal leaf')
 return p,before,carrier,after,source(HERE/'apps10-payload',p['payload'])

def emit_apps10(parent,carrier,apps10_carrier,output):
 p,before,input_map,old,payload=inputs();correction,previous,corrected,replacements=correction_inputs();variant,current,input10,after,selected=apps10_inputs();need(old==previous and corrected==current,'whole default and carrier-env corrected380 prerequisites');parent,carrier,apps10_carrier,output=map(ordinary,(parent,carrier,apps10_carrier,output));need(not os.path.lexists(output)and output.parent.is_dir()and all(not output.is_relative_to(root)and not root.is_relative_to(output)for root in(parent,carrier,apps10_carrier)),'fresh disjoint Apps10 source-only output');bodies=source(parent,before);source(carrier,input_map);source(apps10_carrier,input10)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==old,'entire original c2 source380 in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==current,'entire corrected5c3 source380 in memory');bodies.update(selected);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole exact389 before first output write');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 source(output,after);return dict(status='SOURCE_ONLY_EXACT_APPS10_CURRENT606_389_NOT_NATIVE_ACCEPTANCE',files=389,source=variant['after_source'],previous_source=variant['before_source'],carrier=variant['carrier_source'],held=364,changed=16,added=9,actual=None,native='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

APPS11_PROFILE={'bytes': 11670, 'sha256': '3db33260a945cc0756e39b1c800aac145a2395c761a9ab464847ac89a26a23fa'}
def apps11_inputs():
 raw=read(HERE/'apps11-profile.json');need(pin(raw)==APPS11_PROFILE,'whole hardpinned Apps11 source profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_APPS11_CURRENT606_389'and p['actual']is None and(p['before_source'],p['after_source'],p['carrier_source'],p['carrier_ref'])==('5c3c2d0ce5b4f6c2672c9367b722170687c7de69','7abbc5ca0c3a0cb132732b6d8e78fbbae48ab242','333e3e8680bcfb6cad6afb5c5dc6070e39e62a6e','codex/apps11-accepted-inputs-v1'),'exact published Apps11 source and accepted pair input')
 raw=read(HERE/'apps11-maps.json');need(pin(raw)==p['maps'],'whole Apps11 parent/carrier/result maps');maps=json.loads(raw);before,after,carrier=maps['before'],maps['after'],maps['carrier'];need((len(before),len(after),len(carrier))==(380,389,94)and set(before)<=set(after)and{n for n in before if before[n]!=after[n]}==set(p['changed'])and set(after)-set(before)==set(p['added'])and(len(p['changed']),len(p['added']),p['held'])==(16,9,364),'exact finite Apps11 delta')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'whole before/proposed Apps11 operand')
 need(p['payload']=={n:after[n]for n in set(p['changed'])|set(p['added'])},'exact25 readable Apps11 source payloads')
 need(set(p['legal'])=={'apps11-NOTICE.md','LICENSE'},'complete Apps11 legal closure')
 for n,w in p['legal'].items():need(pin(read(HERE/n))==w,'whole Apps11 source legal leaf')
 return p,before,carrier,after,source(HERE/'apps11-payload',p['payload'])

def emit_apps11(parent,carrier,apps11_carrier,output):
 p,before,input_map,old,payload=inputs();correction,previous,corrected,replacements=correction_inputs();variant,current,input11,after,selected=apps11_inputs();need(old==previous and corrected==current,'whole default and carrier-env corrected380 prerequisites');parent,carrier,apps11_carrier,output=map(ordinary,(parent,carrier,apps11_carrier,output));need(not os.path.lexists(output)and output.parent.is_dir()and all(not output.is_relative_to(root)and not root.is_relative_to(output)for root in(parent,carrier,apps11_carrier)),'fresh disjoint Apps11 source-only output');bodies=source(parent,before);source(carrier,input_map);source(apps11_carrier,input11)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==old,'entire original c2 source380 in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==current,'entire corrected5c3 source380 in memory');bodies.update(selected);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole exact389 before first output write');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 source(output,after);return dict(status='SOURCE_ONLY_EXACT_APPS11_CURRENT606_389_NOT_NATIVE_ACCEPTANCE',files=389,source=variant['after_source'],previous_source=variant['before_source'],carrier=variant['carrier_source'],held=364,changed=16,added=9,actual=None,native='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('parent','output'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--carrier',type=Path)
 parser.add_argument('--carrier-env-correction',action='store_true')
 for version in ('9','10','11','14','16'):
  parser.add_argument('--apps'+version,action='store_true')
  parser.add_argument('--apps'+version+'-carrier',type=Path)
 a=parser.parse_args()
 if sum((a.carrier_env_correction,a.apps9,a.apps10,a.apps11,a.apps14,a.apps16))>1:parser.error('select exactly one explicit variant')
 if a.apps16:
  if a.carrier is not None or any(v is not None for v in(a.apps9_carrier,a.apps10_carrier,a.apps11_carrier,a.apps14_carrier)):parser.error('--apps16 takes only --apps16-carrier; no original carrier or other candidate')
  import importlib.util
  spec=importlib.util.spec_from_file_location('_apps16_explicit_factory',HERE/'apps16.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result=module.emit(a.parent,a.apps16_carrier,a.output);print(json.dumps(result,sort_keys=True));return
 if a.apps16_carrier is not None:parser.error('--apps16-carrier requires --apps16')
 if a.apps14:
  if a.carrier is not None or any(v is not None for v in(a.apps9_carrier,a.apps10_carrier,a.apps11_carrier)):parser.error('--apps14 takes only --apps14-carrier; no original carrier or other candidate')
  import importlib.util
  spec=importlib.util.spec_from_file_location('_apps14_explicit_factory',HERE/'apps14.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result=module.emit(a.parent,a.apps14_carrier,a.output);print(json.dumps(result,sort_keys=True));return
 if a.carrier is None:parser.error('--carrier is required for every original route')
 if a.apps14_carrier is not None:parser.error('--apps14-carrier requires --apps14')
 if a.apps11:
  if a.apps11_carrier is None or a.apps9_carrier is not None or a.apps10_carrier is not None:parser.error('--apps11 requires only --apps11-carrier')
  result=emit_apps11(a.parent,a.carrier,a.apps11_carrier,a.output)
 elif a.apps10:
  if a.apps10_carrier is None or a.apps9_carrier is not None or a.apps11_carrier is not None:parser.error('--apps10 requires only --apps10-carrier')
  result=emit_apps10(a.parent,a.carrier,a.apps10_carrier,a.output)
 elif a.apps9:
  if a.apps9_carrier is None or a.apps10_carrier is not None or a.apps11_carrier is not None:parser.error('--apps9 requires only --apps9-carrier')
  result=emit_apps9(a.parent,a.carrier,a.apps9_carrier,a.output)
 else:
  if a.apps9_carrier is not None or a.apps10_carrier is not None or a.apps11_carrier is not None:parser.error('candidate carrier requires its explicit variant')
  result=(emit_carrier_env if a.carrier_env_correction else emit)(a.parent,a.carrier,a.output)
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
