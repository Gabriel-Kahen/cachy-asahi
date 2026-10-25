# SPDX-License-Identifier: MIT
"""Whole355 inverse and exact published1178 source guard, never installed authority."""
import json,sys
import common as C
CHANGED={'README.md','implementation/profile.json','implementation/baseline.py','implementation/source_guard.py','source-manifest.json'}
ADDED={'implementation/namespace_context.py','implementation/parent355.json'}
def data():return json.loads(C.read(C.HERE/'parent355.json'))
def one(raw,before,after):
 C.need(raw.count(before.encode())==1,'one exact source-context seam');return raw.replace(before.encode(),after.encode(),1)
def old_body(name,raw,p):
 if name=='implementation/profile.json':
  v=json.loads(raw);C.need({k:v[k]for k in p['profile_after']}==p['profile_after'],'closed exact public1178 source context');v.update(p['profile_before']);return C.enc(v)
 if name=='README.md':return one(one(raw,p['README_after'],p['README_before']),p['README_after2'],p['README_before2'])
 if name=='implementation/baseline.py':return one(raw,"fresh=C.safe(fresh);__import__('namespace_context').fresh(fresh);p=C.profile();",'fresh=C.safe(fresh);p=C.profile();')
 if name=='implementation/source_guard.py':return one(one(raw," __import__('namespace_context').verify()\n",''),'whole corrected1178 fixed-target installer source','whole corrected1176 fixed-target installer source')
 return raw

def verify():
 p=data();before=p['files'];C.need(C.pin(C.enc(before))==dict(bytes=61181,sha256='ff5d820dd825079b0f81c5a61c71ac93ebedb29b5003b0b0579d2b7b97b236f9'),'exact frozen355 before authorization');C.need(len(before)==355 and set(C.rows(C.ROOT))==set(before)|ADDED,'complete355 ancestor plus only two fixed source-context operands');restored={}
 for n,w in before.items():
  if n=='source-manifest.json':continue
  raw=C.read(C.ROOT/n);old=old_body(n,raw,p);C.need(C.pin(old)==w,'whole355 original body '+n);restored[n]=old
 m=json.loads(C.read(C.ROOT/'source-manifest.json'));m['files']={n:w for n,w in before.items()if n!='source-manifest.json'};C.need(C.pin(C.enc(m))==before['source-manifest.json'],'entire original355 manifest inverse');C.need({n for n in before if C.pin(C.read(C.ROOT/n))!=before[n]}==CHANGED,'only finite source-context changes; all208 runtime bodies held');q=C.profile();C.need(q['authorities']=={'fresh607':None,'baseline607':None}and q['authority_files']is None and q['actual_source']is q['actual_ref']is q['actual_run']is None,'all current installed/actual authority remains NULL');return dict(status='PASS_WHOLE355_SOURCE_CONTEXT_INVERSE',held=350,changed=5,added=2,actual=None)

def fresh(root):
 root=C.safe(root);p=data();expected=p['profile_after']['fresh_source_files'];C.need(p['profile_after']['fresh_source']=='af2f3946c5a83077c6234f618c3287ca1a873292'and p['profile_after']['fresh_ref']=='codex/latest607-fresh-ci-namespace-v1'and C.pin(C.enc(expected))==dict(bytes=218432,sha256='63272955cd7e449332dbd7858d30ff3e03bf1916d46844370e279c67e0801835'),'exact public1178 source input, never installed authority');C.need(C.rows(root)==expected and len(expected)==1178,'whole exact published1178 source, no baseline or other substitution');names=('common','loaders','source_controls','adapter','workflow','closure','ci_namespace','source_guard','accepted','materialize','run');missing=object();saved={n:sys.modules.get(n,missing)for n in names};path=list(sys.path);modules={}
 try:
  for n in names:modules[n]=C.load('_updater_published1178_'+n,root/('implementation/'+n+'.py'),modules)
  sys.modules.update(modules);fact=modules['source_guard'].verify();C.need(fact['files']==1178 and fact['fresh607']=='NOT_RUN','complete1178→1176→1098/274/853 guard, source only')
 finally:
  sys.path[:]=path
  for n,v in saved.items():
   if v is missing:sys.modules.pop(n,None)
   else:sys.modules[n]=v
 C.need(C.rows(root)==expected,'whole1178 source preserved after guard');return fact
