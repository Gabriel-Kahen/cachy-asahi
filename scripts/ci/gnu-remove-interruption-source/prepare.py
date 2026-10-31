#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce GNU766 from explicit public749/public13 DATA; execute no input."""
import argparse,copy,hashlib,json,os,stat,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_PIN={'bytes':523115,'sha256':'8e8bae1f1b2d0cba752a7dc95ab971f876d55dfc1536b3816cf0beecae9c8311'}
PARENT='de1aab259df6bda8ad36f959392e3fc4eb35b622';RECORD='7ba9a2d8da09e17b0204546219d55cff414fcb8d';TARGET='cc04fe3a57bac24a516004dfb670a172e76ac517'
LANE='scripts/ci/gnu-immutable-source-native';MANIFEST=LANE+'/source-manifest.json';DEPLOY=LANE+'/deploy.py';PROFILE=LANE+'/interruption-profile.json'
WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml')

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
  while part:=os.read(fd,min(65536,a.st_size+1-len(raw))):
   raw.extend(part);need(len(raw)<=a.st_size,'input growth')
  need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'stable whole input FD/path');return bytes(raw),identity(a)
 finally:os.close(fd)
def read(path):return stable_read(path)[0]
def snapshot(root):
 root=canonical(root);need(root.is_dir(),'ordinary directory required');values={};ids={'.':identity(root.lstat())};dirs=set();total=0
 for p in sorted(root.rglob('*')):
  s=p.lstat();need(not p.is_symlink()and(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode)),'closed ordinary namespace');n=p.relative_to(root).as_posix()
  if stat.S_ISDIR(s.st_mode):dirs.add(n);ids[n+'/']=identity(s)
  else:
   values[n],ids[n]=stable_read(p);total+=len(values[n]);need(len(values)<=1024 and total<=128*1024**2,'bounded source namespace')
 need(dirs=={p.as_posix()for n in values for p in Path(n).parents if p.as_posix()!='.'},'foreign empty directory')
 for n,s in ids.items():need(identity((root if n=='.'else root/n.rstrip('/')).lstat())==s,'whole namespace identity drift')
 return values,ids

def profile():
 raw=read(HERE/'profile.json');need(pin(raw)==PROFILE_PIN,'entry-point pinned factory profile');v=json.loads(raw)
 need((v['parent_source'],v['normal_record_source'],v['expected_source'])==(PARENT,RECORD,TARGET),'exact public input/target identities')
 need((len(v['before']),len(v['after']),len(v['normal_record']))==(749,766,13),'complete public749/766/13 maps')
 need(v['held']=={n:w for n,w in v['before'].items()if v['after'].get(n)==w}and len(v['held'])==740 and len(v['changed'])==9 and len(v['added'])==17 and set(v['before'])<=set(v['after']),'complete740held/nine changed/17added closure')
 need(all(v[n]is None for n in('current_source','current_ref','current_run','Root_acceptance'))and v['supplied_source_execution']is False,'no new source/native/acceptance authority');return v

def reseal(out):
 m=json.loads(out[MANIFEST]);m['files']=pins({n:b for n,b in out.items()if n not in(MANIFEST,*WFS)});out[MANIFEST]=enc(m)
 workflow=out[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',pin(out[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',pin(out[MANIFEST])['sha256']).encode()
 for n in WFS:out[n]=workflow

def transformed(before,record,payload,v):
 need(pins(before)==v['before']and pins(record)==v['normal_record']and pins(payload)==v['payload'],'complete pinned transformation operands')
 out=dict(before)
 for n,steps in v['source_edits'].items():
  for row in steps:
   a,b=row['before'].encode(),row['after'].encode();need(a and out[n].count(a)==row['count'],'counted public749 source seam '+n);out[n]=out[n].replace(a,b,row['count'])
 for n in('interruption_case.py','interruption_source.py','test_interruption.py'):out[LANE+'/'+n]=payload[n]
 for n,b in record.items():out[LANE+'/normal-record/'+n]=b
 q=copy.deepcopy(json.loads(payload['profile-operands.json']));q.update(before=pins(before),added=pins({n:b for n,b in out.items()if n not in before}),source_edits=v['source_edits']);out[PROFILE]=enc(q)
 footer='\n# SELECTED_REMOVE_INTERRUPTION_SOURCE\n_REMOVE_INTERRUPTION_PROFILE_PIN='+repr(pin(out[PROFILE]))+"\ndef source(root=ROOT):\n return load('_gnu_remove_source',Path(root)/LANE/'interruption_source.py').check(root)\n"
 out[DEPLOY]+=footer.encode();reseal(out);need(pins(out)==v['after'],'entire exact766 target before writes')
 # Independently invert every route, remove additions, and regenerate old seals.
 back={n:out[n]for n in before}
 for n,steps in v['source_edits'].items():
  for row in reversed(steps):
   a,b=row['before'].encode(),row['after'].encode();need(b and back[n].count(b)==row['count'],'counted complete749 inverse');back[n]=back[n].replace(b,a,row['count'])
 need(back[DEPLOY].endswith(footer.encode()),'exact appended deploy footer');back[DEPLOY]=back[DEPLOY][:-len(footer.encode())];reseal(back);need(back==before,'whole exact749 inverse')
 need(all(out[n]==b for n,b in before.items()if n.startswith('runtime/')or n==LANE+'/fixed_case.py'),'all667 runtime leaves and normal helper held')
 return out

def destination(parent,record,output):
 parent,record,output=map(canonical,(parent,record,output));need(parent.is_dir()and record.is_dir()and output.parent.is_dir()and not os.path.lexists(output),'fresh absent output with existing ordinary parent')
 roots=(parent,record,HERE)
 for i,a in enumerate(roots):
  for b in roots[i+1:]:need(not a.is_relative_to(b)and not b.is_relative_to(a),'disjoint input/factory namespaces')
 for root in roots:need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint input/factory/output namespaces')
 return parent,record,output

def emit(parent,record,output,known=False):
 need(type(known)is bool,'literal known/NULL context selector');parent,record,output=destination(parent,record,output);v=profile()
 before,source_ids=snapshot(parent);records,record_ids=snapshot(record);payload,payload_ids=snapshot(HERE/'payload');profile_state=stable_read(HERE/'profile.json');entry_state=stable_read(HERE/'prepare.py')
 out=transformed(before,records,payload,v);need(pins(out)==v['after'],'entire exact766 target before staging')
 need(snapshot(parent)==(before,source_ids)and snapshot(record)==(records,record_ids)and snapshot(HERE/'payload')==(payload,payload_ids)and stable_read(HERE/'profile.json')==profile_state and stable_read(HERE/'prepare.py')==entry_state,'late complete input/operand identity drift')
 destination(parent,record,output)
 with tempfile.TemporaryDirectory(prefix='gnu-remove-source-',dir=output.parent)as td:
  staged=Path(td)/'source';staged.mkdir(mode=0o700)
  for n,b in sorted(out.items()):
   p=staged/n;p.parent.mkdir(parents=True,exist_ok=True)
   with p.open('xb')as stream:os.fchmod(stream.fileno(),0o644);stream.write(b)
  need(pins(snapshot(staged)[0])==v['after']and all(stat.S_IMODE(p.stat().st_mode)==0o644 for p in staged.rglob('*')if p.is_file()),'entire staged766 bytes/modes');destination(parent,record,output);os.rename(staged,output)
 return dict(status='SOURCE_ONLY_GNU_REMOVE_INTERRUPTION_FACTORY',files=v['after'],parent_source=PARENT,normal_record_source=RECORD,expected_source=TARGET,known_parent_context=known,current_source=None,current_ref=None,current_run=None,Root_acceptance=None,native='NOT_RUN',hardware='NOT_RUN',supplied_source_execution=False)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',required=True,type=Path);p.add_argument('--normal-record',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--known-context',action='store_true');a=p.parse_args();print(json.dumps(emit(a.parent,a.normal_record,a.output,a.known_context),sort_keys=True))
