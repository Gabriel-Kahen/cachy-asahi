#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact published698 from whole corrected676; no actors or acceptance."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 9293, 'sha256': '35b93473c7415d42fa405d224578eb4d3ae7d77c503cf08bd78b148922310daa'}

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
 need(not sys.flags.optimize,'optimized source checks refused');raw=read(HERE/'profile.json');need(pin(raw)==PROFILE,'whole pinned698 factory profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_FULL606_ONBOARDING698_FACTORY'and p['actual']is None and p['parent']['source']=='f9471acd0414c2f6abc53ee81111011df735430c'and p['result']['source']=='3b60dfffcc3ceb8cddce86b29d245cab01c2a772','only exact corrected676-to698 profile')
 before=read(HERE/'parent676.json');after=read(HERE/'expected698.json');need(pin(before)==p['parent']['map']and pin(after)==p['result']['map'],'whole before/after map pins');before,after=json.loads(before),json.loads(after);need(len(before)==676 and len(after)==698 and len(p['changed'])==4 and len(p['added'])==22 and set(after)==set(before)|set(p['added']),'finite four-replacement22-addition source closure')
 need({n for n in before if before[n]!=after[n]}==set(p['changed'])and{n for n in after if n not in before}==set(p['added'])and p['held']==672,'actual complete source delta')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'exact changed source operand')
 need(p['payload']=={n:after[n]for n in set(p['changed'])|set(p['added'])},'exact replacement/addition payload table');return p,before,after,source(HERE/'payload',p['payload'])

def emit(parent,output):
 p,before,after,payload=inputs();parent=ordinary(parent);output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(parent)and not parent.is_relative_to(output),'fresh disjoint source-only output');bodies=source(parent,before)  # Every676 byte is checked before any output.
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole exact698 source before writing');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,after).items()}==after,'complete final698 output');return dict(status='SOURCE_ONLY_EXACT698_ONBOARDING_NOT_NATIVE_ACCEPTANCE',files=698,source=p['result']['source'],parent=p['parent']['source'],held=672,changed=4,added=22,actual=None,native='NOT_RUN',hardware='NOT_RUN',independent_new_user_install='NOT_RUN',release='NOT_ADMITTED')


LOADER_PROFILE={'bytes': 2990, 'sha256': 'b667421f6729a092cc4f5585936945f1206ef32d47d3a927a6f068fba53a0a94'}
def loader_inputs(old):
 raw=read(HERE/'loader-profile.json');need(pin(raw)==LOADER_PROFILE,'whole pinned loader-correction profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_ONBOARDING698_LOADER_CORRECTION'and p['actual']is None and p['parent_source']=='f9471acd0414c2f6abc53ee81111011df735430c'and p['before_source']=='3b60dfffcc3ceb8cddce86b29d245cab01c2a772'and p['after_source']=='d0ed51fa626b9343321952277607718b900e90bc','exact published onboarding loader variant')
 need(pin(read(HERE/'expected698.json'))==p['before_map'],'whole original698 map held');raw=read(HERE/'loader-expected698.json');need(pin(raw)==p['after_map'],'whole corrected698 map pin');after=json.loads(raw);need(len(old)==len(after)==698 and set(old)==set(after)and {n for n in old if old[n]!=after[n]}==set(p['changed'])and len(p['changed'])==5 and p['held']==693,'finite loader-only five-replacement693-held delta')
 for n,row in p['changed'].items():need(row==dict(before=old[n],proposed=after[n]),'exact full changed source operands')
 need(p['payload']=={n:after[n]for n in p['changed']},'exact five readable loader-correction payloads');return p,after,source(HERE/'loader-payload',p['payload'])

def emit_loader(parent,output):
 p,before,old,payload=inputs();variant,after,replacements=loader_inputs(old);parent=ordinary(parent);output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(parent)and not parent.is_relative_to(output),'fresh disjoint source-only output');bodies=source(parent,before)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==old,'whole original698 emission in memory before loader correction');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole corrected698 before any output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,after).items()}==after,'complete corrected698 output');return dict(status='SOURCE_ONLY_EXACT698_LOADER_CORRECTION_NOT_NATIVE_ACCEPTANCE',files=698,source=variant['after_source'],parent=variant['parent_source'],previous_source=variant['before_source'],held=693,changed=5,added=0,actual=None,native='NOT_RUN',hardware='NOT_RUN',independent_new_user_install='NOT_RUN',release='NOT_ADMITTED')

CORRECTION_PROFILE={'bytes': 2796, 'sha256': '62d7ee2ef1b0d7b4e86089bc5a2982a5019d0aaa83c895573a1ba9674bc1b671'}
def correction_inputs():
 raw=read(HERE/'correction-profile.json');need(pin(raw)==CORRECTION_PROFILE,'whole pinned export-closure profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_EXPORT_CLOSURE'and p['actual']is None and p['before_source']=='d0ed51fa626b9343321952277607718b900e90bc'and p['after_source']=='3b90012ed1e248f803d15f5f765667b6a249fb8c','exact published correction source case')
 raw=read(HERE/'correction-maps.json');need(pin(raw)==p['maps'],'whole correction before/after map pins');maps=json.loads(raw);before,after=maps['before'],maps['after'];need(set(before)==set(after)and len(after)==p['files']==698 and {n for n in before if before[n]!=after[n]}==set(p['changed'])and len(p['changed'])==5 and p['held']==693,'finite exact correction operands')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'complete correction before/proposed operands')
 need(p['payload']=={n:after[n]for n in p['changed']},'exact readable correction payload set')
 payload=source(HERE/'correction-payload',p['payload'])
 return p,before,after,payload

def emit_export_closure(parent,output):
 p,before,original,payload=inputs();loader,old,loader_payload=loader_inputs(original);variant,previous,after,replacements=correction_inputs();need(old==previous,'whole d0ed loader input to export correction');parent=ordinary(parent);output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(parent)and not parent.is_relative_to(output),'fresh disjoint source-only correction output');bodies=source(parent,before)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==original,'whole original698 emission in memory');bodies.update(loader_payload);need({n:pin(raw)for n,raw in bodies.items()}==old,'whole d0ed loader emission in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole export-corrected698 before any output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 source(output,after);return dict(status='SOURCE_ONLY_EXACT698_EXPORT_CLOSURE_NOT_NATIVE',files=698,source=variant['after_source'],previous_source=variant['before_source'],held=variant['held'],changed=len(replacements),actual=None,native='NOT_RUN',hardware='NOT_RUN')


RAWDB_PROFILE={'bytes': 3303, 'sha256': '21af93e8890be6375a5897676dbfb8b0a203a32d930b14422f8df3d8dba156e0'}
def rawdb_inputs():
 raw=read(HERE/'rawdb-key-profile.json');need(pin(raw)==RAWDB_PROFILE,'whole pinned rawdb-key profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_RAWDB_KEY'and p['actual']is None and p['before_source']=='3b90012ed1e248f803d15f5f765667b6a249fb8c'and p['after_source']=='ed4fb355ff939bf269905592ba5d71517ffab373','exact published followup source case')
 raw=read(HERE/'rawdb-key-maps.json');need(pin(raw)==p['maps'],'whole followup before/after map pins');m=json.loads(raw);before,after=m['before'],m['after'];need(before.keys()==after.keys()and len(after)==p['files']==698 and {n for n in before if before[n]!=after[n]}==set(p['changed'])and len(p['changed'])==6 and p['held']==692,'finite exact followup operands')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'complete followup source operands')
 need(p['payload']=={n:after[n]for n in p['changed']},'exact readable followup payload set');payload=source(HERE/'rawdb-key-payload',p['payload']);return p,before,after,payload

def emit_rawdb_key_correction(parent,output):
 initial,before,original,payload=inputs();loader,loaded,loader_payload=loader_inputs(original);export,previous,exported,export_payload=correction_inputs();p,expected_exported,after,replacements=rawdb_inputs();need(loaded==previous and exported==expected_exported,'whole loader/export predecessor chain');parent=ordinary(parent);output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(parent)and not parent.is_relative_to(output),'fresh disjoint source-only rawDB correction output');bodies=source(parent,before)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==original,'whole original698 in memory');bodies.update(loader_payload);need({n:pin(raw)for n,raw in bodies.items()}==loaded,'whole loader698 in memory');bodies.update(export_payload);need({n:pin(raw)for n,raw in bodies.items()}==exported,'whole3b900 export closure in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole corrected698 before any output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 source(output,after);return dict(status='SOURCE_ONLY_EXACT698_RAWDB_KEY_CORRECTION_NOT_NATIVE',files=698,source=p['after_source'],previous_source=p['before_source'],held=p['held'],changed=len(replacements),actual=None,native='NOT_RUN',hardware='NOT_RUN')

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--parent',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);group=parser.add_mutually_exclusive_group();group.add_argument('--loader-correction',action='store_true',help='emit exact d0ed loader-corrected698; default3b60 unchanged');group.add_argument('--export-closure',action='store_true',help='exact3b900 export closure after d0ed; all prior outputs held');group.add_argument('--rawdb-key-correction',action='store_true',help='exacted4fb rawDB package binding after complete export closure; all old outputs held');a=parser.parse_args();print(json.dumps((emit_rawdb_key_correction if a.rawdb_key_correction else emit_export_closure if a.export_closure else emit_loader if a.loader_correction else emit)(a.parent,a.output),sort_keys=True))
if __name__=='__main__':main()
