# SPDX-License-Identifier: MIT
"""Finite fresh ancestry/cost-DATA inverse; entire original563 guard mandatory."""
import base64,hashlib,importlib.util,json,stat,sys,tempfile
from pathlib import Path

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def rows(root):
 out={};key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 for q in Path(root).rglob('*'):
  if q.relative_to(root).parts[0]=='.git':continue
  before=q.lstat();need(stat.S_ISDIR(before.st_mode)or stat.S_ISREG(before.st_mode),'ordinary source closure')
  if stat.S_ISREG(before.st_mode):
   need(before.st_nlink==1 and before.st_size<=16*1024**2,'bounded singlelink source');raw=q.read_bytes();need(key(before)==key(q.lstat())and len(raw)==before.st_size,'complete stable source bytes');out[q.relative_to(root).as_posix()]=pin(raw)
 return out

def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'whole finite fresh ancestry proof');p=json.loads(raw);before=p['before'];actual=rows(root);changed=set(p['before_bodies']);added=set(p['added'])
 need(len(before)==563 and len(changed)==7 and len(added)==3 and set(actual)==set(before)|added and{n for n in before if before[n]!=actual[n]}==changed,'finite566 source;556 held7changed3added');need(all(actual[n]==v for n,v in p['helpers'].items()),'whole private ancestry/helper bodies')
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(root/n).read_bytes()for n in before};need(all(pin(bodies[n])==r for n,r in before.items()),'whole original563 source inverse')
 for n,edits in p['edits'].items():
  text=(root/n).read_text()
  for old,new in reversed(edits):need(text.count(new)==1,'one exact ancestry/timing/count seam');text=text.replace(new,old,1)
  need(text.encode()==bodies[n],'whole original body outside narrow seams')
 marker='\n# BEGIN_FRESH_ANCESTRY_COST_SUCCESSOR\n';parts=(root/p['guard']).read_text().split(marker);need(len(parts)==2 and parts[0].encode()==bodies[p['guard']]and parts[1]=='def verify():\n import lifecycle_cost_successor\n return lifecycle_cost_successor.verify(ROOT, '+repr(name)+', '+repr(want)+')\n','whole original guard and mandatory finite appendix')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:r for n,r in actual.items()if n not in{p['manifest'],*p['workflows']}},'whole new manifest');restored=dict(mf,files={n:r for n,r in mf['files'].items()if n not in added})
 for n in changed-{p['manifest'],*p['workflows']}:restored['files'][n]=before[n]
 need(enc(restored)==bodies[p['manifest']],'whole original manifest inverse')
 for n in p['workflows']:need((root/n).read_bytes().replace(actual[p['manifest']]['sha256'].encode(),before[p['manifest']]['sha256'].encode())==bodies[n],'all original workflow/clock bodies held')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='9c49f8d12e5aea864bcf6bca6ed836874c1f06e5',ref='codex/current607-failure-retention-v1',files=563,git_joins=563,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['source_authorization']==before and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'genuine original563 Git/source publication')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='current607-cost-original563-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,body in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(body)
   need(rows(old)==before,'complete original563 before mandatory original guard')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str((old/p['guard']).parent));spec=importlib.util.spec_from_file_location('_cost_complete_original563_guard',old/p['guard']);G=importlib.util.module_from_spec(spec);sys.modules[spec.name]=G;spec.loader.exec_module(G);fact=G.verify()
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,files=len(actual),status='SOURCE_ONLY_FRESH_ANCESTRY_COST_NOT_NATIVE_ACCEPTED',cost_original_source=pub['source'],cost_original_files=563,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
