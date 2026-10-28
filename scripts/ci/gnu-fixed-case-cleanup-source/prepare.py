#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce public GNU749 from public747; source only, no native authority."""
import argparse,base64,hashlib,json,os,stat,tempfile,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_PIN={'bytes':510997,'sha256':'4cc6b4173d571c54d86664f4b9465e95732adfdfb2f7af132a8de1ba3f1dcc2d'}
LANE='scripts/ci/gnu-immutable-source-native';PROFILE=LANE+'/lifetime-validation-profile.json';HELPER=LANE+'/fixed_case.py';DEPLOY=LANE+'/deploy.py';MANIFEST=LANE+'/source-manifest.json';WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml')
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def pins(values):return{n:pin(b)for n,b in values.items()}
def canonical(value):
 p=Path(value);need(p.is_absolute()and str(p)==os.path.normpath(str(p))and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'canonical absolute no-alias path');return p
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def stable_read(path,cap=16*1024**2):
 p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary singlelink input');raw=bytearray()
  while part:=os.read(fd,min(65536,a.st_size+1-len(raw))):raw.extend(part);need(len(raw)<=a.st_size,'source growth')
  need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'source identity/content drift');return bytes(raw),identity(a)
 finally:os.close(fd)
def read(path,cap=16*1024**2):return stable_read(path,cap)[0]
def snapshot(root):
 root=canonical(root);need(root.is_dir(),'ordinary directory required');values={};identities={'.':identity(root.lstat())};directories=set()
 for p in sorted(root.rglob('*')):
  s=p.lstat();need(not p.is_symlink()and(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode)),'closed ordinary namespace');n=p.relative_to(root).as_posix()
  if stat.S_ISDIR(s.st_mode):directories.add(n);identities[n+'/']=identity(s)
  else:values[n],identities[n]=stable_read(p)
 need(directories=={p.as_posix()for n in values for p in Path(n).parents if p.as_posix()!='.'},'foreign empty directory')
 for n,s in identities.items():
  p=root if n=='.'else root/n.rstrip('/');need(identity(p.lstat())==s,'whole namespace identity drift')
 return values,identities
def profile():
 raw=read(HERE/'profile.json');need(pin(raw)==PROFILE_PIN,'entry-point pinned fixed profile');v=json.loads(raw)
 need(v['parent_source']=='3d6f8f994c89d1ba55f31aed947ded987837d8cd'and v['expected_source']=='de1aab259df6bda8ad36f959392e3fc4eb35b622'and len(v['before'])==747 and len(v['after'])==749,'exact public747/749 contexts')
 need(v['held']=={n:w for n,w in v['before'].items()if v['after'].get(n)==w}and len(v['held'])==739 and len(v['changed'])==10 and set(v['before'])<=set(v['after']),'whole739held/eight changed/two added closure')
 need(v['actual']is v['Root_acceptance']is None and v['capacity_reserved']is False,'source-only no acceptance or reserved capacity');return v
def transformed(before,payload,v):
 q=dict(source_files=v['before'],publication=dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=v['parent_source'],ref='codex/gnu747-root7200-v1',files=747,git_joins=747,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED'),git=dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=v['parent_source'],ref='codex/gnu747-root7200-v1',files=v['before']));out=dict(before);edits={}
 def change(n,a,b):
  s=out[n].decode();need(s.count(a)==1,'one source747 seam '+n);s=s.replace(a,b,1);out[n]=s.encode();edits.setdefault(n,[]).append(dict(before=a,after=b))
 n=LANE+'/binding.py'
 change(n,'def build(root,output,env=os.environ):','def build(root,output,env=os.environ,case=\'both\'):\n import fixed_case;D.need(case in fixed_case.CASES,\'explicit fixed validation case before writes\')')
 change(n,"shutil.copytree(root/'runtime',selected);private=","shutil.copytree(root/'runtime',selected);case_proof=fixed_case.prepare(selected,case);private=")
 change(n,"D.write(out/'binding-proof.json',D.encoded(proof));return proof","\n if case!='both':proof['fixed_case_validation']=case_proof\n D.write(out/'binding-proof.json',D.encoded(proof));return proof")
 n=LANE+'/entry.py';change(n,"p.add_argument('--output',type=Path);a=p.parse_args()","p.add_argument('--output',type=Path);p.add_argument('--case',choices=('both','pristine','modified'),default='both');a=p.parse_args()")
 change(n,'value=binding.build(a.source,a.output)','value=binding.build(a.source,a.output,case=a.case)')
 n=LANE+'/pipeline.py'
 change(n,"C=D.load('_immutable_selected_native_controller',selected/'immutable/native_controller.py')", "__import__('fixed_case').verify_selected(root,selected,a.case);C=D.load('_immutable_selected_native_controller',selected/'immutable/native_controller.py')")
 change(n,"p.add_argument('--source',type=Path,default=D.ROOT)","p.add_argument('--source',type=Path,default=D.ROOT);p.add_argument('--case',choices=('both','pristine','modified'),default='both')")
 n=LANE+'/workflow.yml.in';anchor='        required: true\npermissions:';added='        required: true\n      validation_case:\n        description: Explicit validation case; both preserves original cleanup120; paired acceptance requires pristine AND modified same-source outcomes\n        type: choice\n        options: [both, pristine, modified]\n        default: both\n        required: true\npermissions:';change(n,anchor,added)
 change(n,'--output "$RUNNER_TEMP/gnu-immutable-parent/selection"','--output "$RUNNER_TEMP/gnu-immutable-parent/selection" --case "${{ inputs.validation_case }}"')
 change(n,'pipeline.py" consume --source "$GITHUB_WORKSPACE/immutable-source"','pipeline.py" consume --source "$GITHUB_WORKSPACE/immutable-source" --case "${{ inputs.validation_case }}"')
 out[HELPER]=payload['fixed_case.py'];import importlib.util
 helper=__import__('types').ModuleType('_pinned_factory_fixed_case');exec(compile(out[HELPER],'<pinned-readable-fixed-case-helper>','exec'),vars(helper));runtime={n[8:]:b for n,b in before.items()if n.startswith('runtime/')};profiles={case:{n:pin(b)for n,b in helper.render(runtime,case)[0].items()}for case in helper.CASES}
 changed={LANE+'/binding.py',LANE+'/entry.py',LANE+'/workflow.yml.in',LANE+'/pipeline.py',DEPLOY,MANIFEST,*WFS};guard=payload['guard-fragment.py'].decode();marker='# BEGIN_FIXED_CASE_CLEANUP600_SOURCE\n';need(guard.startswith(marker),'one readable fixed guard')
 packed=json.loads(payload['before-bodies-zlib.json']);need(set(packed)==changed,'exact eight compressed before operands')
 for n,value in packed.items():
  decoder=zlib.decompressobj();raw=decoder.decompress(base64.b64decode(value,validate=True),len(before[n])+1);need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and raw==before[n],'whole original before-body bytes')
 p=dict(scope='EXPLICIT_FIXED_CASE_CLEANUP600_DEFAULT_TWO_CASE120',before=q['source_files'],before_bodies_zlib=json.loads(payload['before-bodies-zlib.json']),authorization=q['source_files'],publication=q['publication'],git=q['git'],helper=pin(out[HELPER]),source_edits=edits,guard_fragment=pin(guard.removeprefix(marker).encode()),runtime_profiles=profiles,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None)
 out[PROFILE]=enc(p);need(len(out[PROFILE])<=4*1024**2,'original bounded4MiB profile');footer='\n_LIFETIME_VALIDATION_PIN='+repr(pin(out[PROFILE]))+'\ndef source(root=ROOT):\n return lifetime_validation_source(root)\n';out[DEPLOY]=before[DEPLOY]+b'\n'+guard.encode()+footer.encode()
 m=json.loads(before[MANIFEST]);m['files']={n:pin(b)for n,b in out.items()if n not in(MANIFEST,*WFS)};out[MANIFEST]=enc(m);workflow=out[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',pin(out[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',pin(out[MANIFEST])['sha256']).encode()
 for n in WFS:out[n]=workflow
 need(len(out)==749 and {n for n in before if before[n]!=out[n]}==changed,'exact whole749 source delta');need(all(out[n]==b for n,b in before.items()if n.startswith('runtime/')),'all667 public runtime leaves byteheld')
 for n in(HELPER,DEPLOY,LANE+'/entry.py',LANE+'/binding.py'):compile(out[n],n,'exec')
 return out

def destination(parent,output):
 parent,output=canonical(parent),canonical(output);need(parent.is_dir()and output.parent.is_dir()and not os.path.lexists(output),'fresh output with ordinary existing parent')
 for p in(parent,HERE):need(not output.is_relative_to(p)and not p.is_relative_to(output),'disjoint parent/factory/output')
 return parent,output

def emit(parent,output):
 parent,output=destination(parent,output);v=profile();before,source_ids=snapshot(parent);need(pins(before)==v['before'],'whole supplied public747 source')
 payload,payload_ids=snapshot(HERE/'payload');need(pins(payload)==v['payload'],'complete pinned readable/codec operands');profile_bytes,profile_id=stable_read(HERE/'profile.json');entry_bytes,entry_id=stable_read(HERE/'prepare.py')
 out=transformed(before,payload,v);need(pins(out)==v['after'],'entire exact749 namespace before writes')
 # No historical hash is returned for a new identity. Every input is reread
 # immediately before staging; same bytes with a replaced inode still refuses.
 need(snapshot(parent)==(before,source_ids)and snapshot(HERE/'payload')==(payload,payload_ids)and stable_read(HERE/'profile.json')==(profile_bytes,profile_id)and stable_read(HERE/'prepare.py')==(entry_bytes,entry_id),'late complete source/operand identity drift')
 destination(parent,output)
 with tempfile.TemporaryDirectory(prefix='gnu-fixed-case-',dir=output.parent)as td:
  staged=Path(td)/'source';staged.mkdir(mode=0o700)
  for n,b in sorted(out.items()):
   p=staged/n;p.parent.mkdir(parents=True,exist_ok=True)
   with p.open('xb')as stream:stream.write(b)
  need(pins(snapshot(staged)[0])==v['after'],'whole staged749 namespace');destination(parent,output);os.rename(staged,output)
 return dict(status='SOURCE_ONLY_GNU_FIXED_CASE_FACTORY',files=749,held=739,replaced=8,added=2,parent_source=v['parent_source'],expected_source=v['expected_source'],current_source=None,current_ref=None,current_run=None,Root_acceptance=None,cleanup600_fit='NOT_ESTABLISHED',hardware='NOT_RUN',performance='NOT_CLAIMED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.parent,a.output),sort_keys=True))
