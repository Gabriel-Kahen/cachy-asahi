#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce public GNU771 from explicit public766 DATA; execute no input."""
import argparse,copy,hashlib,json,os,stat,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_PIN={'bytes':525085,'sha256':'e62869fb58f66220bf8ccc11b1ffa64322224b26aecb905f4cb06daf2a45d389'}
PARENT='cc04fe3a57bac24a516004dfb670a172e76ac517';TARGET='4b2f8502655d2f4b65a20691247d1a54052089f3'
LANE='scripts/ci/gnu-immutable-source-native';MANIFEST=LANE+'/source-manifest.json';DEPLOY=LANE+'/deploy.py';PROFILE=LANE+'/candidate-extraction-profile.json';WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml')
PAYLOADS=('candidate_extraction.py','extraction_case.py','extraction_source.py','test_candidate_extraction.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def pins(values):return{n:pin(b)for n,b in values.items()}
def canonical(value):
 p=Path(value);need(p.is_absolute()and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'canonical absolute no-alias path');return p
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def stable_read(path,cap=16*1024**2):
 p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary singlelink DATA');raw=bytearray()
  while part:=os.read(fd,min(65536,a.st_size+1-len(raw))):raw.extend(part);need(len(raw)<=a.st_size,'input growth')
  need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'stable whole input FD/path');return bytes(raw),identity(a)
 finally:os.close(fd)
def read(path):return stable_read(path)[0]
def snapshot(root):
 root=canonical(root);need(root.is_dir(),'ordinary directory required');values={};ids={'.':identity(root.lstat())};dirs=set();total=0
 for p in sorted(root.rglob('*')):
  s=p.lstat();need(not p.is_symlink()and(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode)),'closed ordinary namespace');n=p.relative_to(root).as_posix()
  if stat.S_ISDIR(s.st_mode):dirs.add(n);ids[n+'/']=identity(s)
  else:values[n],ids[n]=stable_read(p);total+=len(values[n]);need(len(values)<=1024 and total<=128*1024**2,'bounded source namespace')
 need(dirs=={p.as_posix()for n in values for p in Path(n).parents if p.as_posix()!='.'},'foreign empty directory')
 for n,s in ids.items():need(identity((root if n=='.'else root/n.rstrip('/')).lstat())==s,'whole namespace identity drift')
 return values,ids

def profile():
 raw=read(HERE/'profile.json');need(pin(raw)==PROFILE_PIN,'entry-point pinned factory profile');v=json.loads(raw)
 need((v['parent_source'],v['expected_source'])==(PARENT,TARGET)and(len(v['before']),len(v['after']))==(766,771),'exact complete public766/771 contexts')
 need(v['held']=={n:w for n,w in v['before'].items()if v['after'].get(n)==w}and len(v['held'])==757 and len(v['changed'])==9 and len(v['added'])==5 and set(v['before'])<=set(v['after']),'complete757held/nine changed/five added closure')
 need(all(v[n]is None for n in('current_source','current_ref','current_run','Root_acceptance'))and v['supplied_source_execution']is False,'source-only NULL selectors');return v
def reseal(out):
 m=json.loads(out[MANIFEST]);m['files']=pins({n:b for n,b in out.items()if n not in(MANIFEST,*WFS)});out[MANIFEST]=enc(m);workflow=out[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',pin(out[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',pin(out[MANIFEST])['sha256']).encode()
 for n in WFS:out[n]=workflow
def footer(raw):return('\n# CANDIDATE_EXTRACTION_SOURCE\n_CANDIDATE_EXTRACTION_PROFILE_PIN='+repr(pin(raw))+"\ndef source(root=ROOT):\n return load('_candidate_extraction_source',Path(root)/LANE/'extraction_source.py').check(root)\n").encode()
def inverse(after,v):
 need(pins(after)==v['after'],'complete exact771 before inverse');q=json.loads(after[PROFILE]);need(q['parent_source']==PARENT and q['before']==v['before']and q['source_edits']==v['source_edits'],'source-owned complete parent/inverse operands');back={n:after[n]for n in v['before']}
 for n,steps in v['source_edits'].items():
  for row in reversed(steps):
   a,b=row['before'].encode(),row['after'].encode();need(b and back[n].count(b)==row['count'],'counted complete766 inverse');back[n]=back[n].replace(b,a,row['count'])
 tail=footer(after[PROFILE]);need(back[DEPLOY].endswith(tail),'exact candidate deploy footer');back[DEPLOY]=back[DEPLOY][:-len(tail)];reseal(back);need(pins(back)==v['before'],'every original766 byte recovered');return back
def transformed(before,payload,v):
 need(pins(before)==v['before']and pins(payload)==v['payload'],'complete pinned transformation operands');out=dict(before)
 for n,steps in v['source_edits'].items():
  for row in steps:
   a,b=row['before'].encode(),row['after'].encode();need(a and out[n].count(a)==row['count'],'counted public766 source seam '+n);out[n]=out[n].replace(a,b,row['count'])
 for n in PAYLOADS:out[LANE+'/'+n]=payload[n]
 q=copy.deepcopy(json.loads(payload['profile-operands.json']));q.update(before=pins(before),source_edits=v['source_edits'],added=pins({n:b for n,b in out.items()if n not in before}));out[PROFILE]=enc(q);out[DEPLOY]+=footer(out[PROFILE]);reseal(out);need(pins(out)==v['after'],'entire exact771 target before writes');need(inverse(out,v)==before,'whole766 byte inverse')
 need(all(out[n]==b for n,b in before.items()if n.startswith('runtime/')or n in(LANE+'/fixed_case.py',LANE+'/interruption_case.py',LANE+'/interruption_source.py',LANE+'/interruption-profile.json')),'all667 runtime leaves and normal/REMOVE helpers held');return out
def destination(parent,output):
 parent,output=map(canonical,(parent,output));need(parent.is_dir()and output.parent.is_dir()and not os.path.lexists(output),'fresh absent output with ordinary existing parent')
 need(not parent.is_relative_to(HERE)and not HERE.is_relative_to(parent),'disjoint parent/factory namespaces')
 for root in(parent,HERE):need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint parent/factory/output namespaces')
 return parent,output
def emit(parent,output,known=False):
 need(type(known)is bool,'literal known/NULL context selector');parent,output=destination(parent,output);v=profile();before,source_ids=snapshot(parent);payload,payload_ids=snapshot(HERE/'payload');profile_state=stable_read(HERE/'profile.json');entry_state=stable_read(HERE/'prepare.py');out=transformed(before,payload,v);need(pins(out)==v['after'],'entire exact771 target before staging')
 need(snapshot(parent)==(before,source_ids)and snapshot(HERE/'payload')==(payload,payload_ids)and stable_read(HERE/'profile.json')==profile_state and stable_read(HERE/'prepare.py')==entry_state,'late complete input/operand identity drift');destination(parent,output)
 with tempfile.TemporaryDirectory(prefix='gnu-candidate-source-',dir=output.parent)as td:
  staged=Path(td)/'source';staged.mkdir(mode=0o700)
  for n,b in sorted(out.items()):
   p=staged/n;p.parent.mkdir(parents=True,exist_ok=True)
   with p.open('xb')as stream:os.fchmod(stream.fileno(),0o644);stream.write(b)
  need(pins(snapshot(staged)[0])==v['after']and all(stat.S_IMODE(p.stat().st_mode)==0o644 for p in staged.rglob('*')if p.is_file()),'entire staged771 bytes/modes');destination(parent,output);os.rename(staged,output)
 return dict(status='SOURCE_ONLY_GNU_CANDIDATE_EXTRACTION_FACTORY',files=v['after'],parent_source=PARENT,expected_source=TARGET,known_parent_context=known,current_source=None,current_ref=None,current_run=None,Root_acceptance=None,native='NOT_RUN',hardware='NOT_RUN',supplied_source_execution=False)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--known-context',action='store_true');a=p.parse_args();print(json.dumps(emit(a.parent,a.output,a.known_context),sort_keys=True))
