# SPDX-License-Identifier: MIT
"""Exact prefill operand paths; reconstruct and execute the whole published559 guard."""
import base64,hashlib,importlib.util,json,stat,sys,tempfile
from pathlib import Path

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def rows(root):
 v={}
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  s=p.lstat();need(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode),'ordinary source closure')
  if stat.S_ISREG(s.st_mode):
   need(s.st_nlink==1 and s.st_size<=16*1024**2,'bounded singlelink source');raw=p.read_bytes();key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns);need(key(s)==key(p.lstat())and len(raw)==s.st_size,'source identity/bytes held');v[p.relative_to(root).as_posix()]=pin(raw)
 return v
def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'whole pinned prefill-path successor');p=json.loads(raw);before=p['before'];actual=rows(root);changed=set(p['before_bodies']);added=set(p['added']);need(len(before)==559 and len(changed)==5 and len(added)==2 and set(actual)==set(before)|added and {n for n in before if before[n]!=actual[n]}==changed,'finite561 source membership;554 held5 changed2 added');need(all(actual[n]==v for n,v in p['helpers'].items()),'whole finite source guard helper');bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(root/n).read_bytes()for n in before};need(all(pin(bodies[n])==v for n,v in before.items()),'whole published559 inverse')
 for n,edits in p['edits'].items():
  text=(root/n).read_text()
  for old,new in reversed(edits):need(text.count(new)==1,'single exact prefill path/test-count operand');text=text.replace(new,old,1)
  if n in p['workflows']:text=text.replace(actual[p['manifest']]['sha256'],before[p['manifest']]['sha256'])
  need(text.encode()==bodies[n],'entire original workflow/CLI/timers outside corrected two paths and source stamp')
 marker='\n# BEGIN_EXACT_PREFILL_PATH_SUCCESSOR\n';parts=(root/p['guard']).read_text().split(marker);need(len(parts)==2 and parts[0].encode()==bodies[p['guard']]and parts[1]=='def verify():\n import prefill_path_successor\n return prefill_path_successor.verify(ROOT, '+repr(name)+', '+repr(want)+')\n','whole original guard plus mandatory finite appendix');mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:v for n,v in actual.items()if n not in{p['manifest'],*p['workflows']}},'whole new source manifest');restored=dict(mf,files={n:v for n,v in mf['files'].items()if n not in added})
 for n in changed-{p['manifest'],*p['workflows']}:restored['files'][n]=before[n]
 need(enc(restored)==bodies[p['manifest']],'whole original manifest inverse');pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='df5857720328e793f39e3912893939b37daa0670',ref='codex/current607-query-binding-v1',files=559,git_joins=559,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['source_authorization']==before and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'whole genuine original559 publication/source/Git joins')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='current607-prefill-original559-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,raw in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw)
   need(rows(old)==before,'all original559 source bytes before whole guard')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str((old/p['guard']).parent));s=importlib.util.spec_from_file_location('_prefill_whole_original559_guard',old/p['guard']);G=importlib.util.module_from_spec(s);sys.modules[s.name]=G;s.loader.exec_module(G);fact=G.verify()
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,files=len(actual),status='SOURCE_ONLY_EXACT_PREFILL_PATH_BINDING_NOT_ACCEPTED',prefill_original_source=pub['source'],prefill_original_files=559,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
