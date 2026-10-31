# SPDX-License-Identifier: MIT
"""Finite lifecycle query/diagnostic inverse; complete predecessor source guard mandatory."""
import base64,hashlib,importlib.util,json,stat,sys,tempfile
from pathlib import Path

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def rows(root):
 result={}
 for p in sorted(root.rglob('*')):
  if p.relative_to(root).parts[0]=='.git':continue
  s=p.lstat();need(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode),'ordinary source closure')
  if stat.S_ISREG(s.st_mode):
   need(s.st_nlink==1 and s.st_size<=16*1024**2,'bounded singlelink source');raw=p.read_bytes();stable=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns);need(len(raw)==s.st_size and stable(p.lstat())==stable(s),'whole source identity/hash including stable atime-independent fields');result[p.relative_to(root).as_posix()]=pin(raw)
 return result

def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'hard-pinned whole lifecycle successor authority');p=json.loads(raw);before=p['before'];actual=rows(root);changed=set(p['before_bodies']);added=set(p['added']);need(len(before)==555 and len(changed)==7 and len(added)==4 and set(actual)==set(before)|added and not set(before)&added,'finite whole555 plus4 lifecycle source membership');need({n for n in before if actual[n]!=before[n]}==changed,'exact seven changed leaves, all548 others held')
 for n,w in p['helpers'].items():need(actual[n]==w,'exact fresh-query/diagnostic/guard helper')
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(root/n).read_bytes()for n in before};need(all(pin(bodies[n])==w for n,w in before.items()),'complete whole555 before reconstruction')
 for n,edits in p['edits'].items():
  text=(root/n).read_text()
  for old,new in reversed(edits):need(text.count(new)==1,'one exact private query/timing seam');text=text.replace(new,old,1)
  need(text.encode()==bodies[n],'whole original lifecycle outside fresh-query/timing insertions')
 guard=p['guard'];marker='\n# BEGIN_FINITE_LIFECYCLE_DESCRIPTOR_SUCCESSOR\n';parts=(root/guard).read_text().split(marker);need(len(parts)==2 and parts[0].encode()==bodies[guard],'entire preceding source guard body held')
 expected='def verify():\n import lifecycle_successor\n return lifecycle_successor.verify(ROOT, '+repr(name)+', '+repr(want)+')\n';need(parts[1]==expected,'exact required finite guard entrypoint')
 manifest=p['manifest'];workflows=p['workflows'];value=json.loads((root/manifest).read_bytes());need(value['files']=={n:v for n,v in actual.items()if n not in{manifest,*workflows}},'entire current source manifest');restored=dict(value,files={n:v for n,v in value['files'].items()if n not in added})
 for n in changed-{manifest,*workflows}:restored['files'][n]=before[n]
 need(encoded(restored)==bodies[manifest],'whole old manifest inverse')
 for n in workflows:need((root/n).read_bytes().replace(actual[manifest]['sha256'].encode(),before[manifest]['sha256'].encode())==bodies[n],'workflow clocks/security/body held outside exact source stamp')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='4c8a7046ce3a42deb6630229607f54d0e2b8cf63',ref='codex/current607-archive-prefill-v1',files=555,git_joins=555,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['source_authorization']==before and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'whole genuine prefill-ready555 authority')
 failure=p['failure_data'];need(failure['status']=='AUTHENTIC_COMPLETE_FAILURE_DATA_ONLY'and failure['source']=='a377c71d5a94d2ae8c63759d2dd4fbcb7ff43cf0'and failure['run']==39564515734 and failure['actual_report']['status']=='FAIL'and failure['actual_report']['error_type']=='TimeoutExpired'and len(failure['all_original_files'])==940 and len(failure['frames'])==10 and failure['acceptance']=='NOT_GRANTED','complete mandatory actual failed553 context, no positive credit')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='latest607-lifecycle-before-')as temp:
   old=Path(temp)/'source';old.mkdir()
   for n,body in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(body)
   need(rows(old)==before,'whole555 before original guard');stems={q.stem for q in old.rglob('*.py')}
   for stem in stems:sys.modules.pop(stem,None)
   sys.path.insert(0,str((old/guard).parent));spec=importlib.util.spec_from_file_location('_whole_lifecycle_predecessor_guard',old/guard);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);original=m.verify()
 finally:
  sys.path[:]=paths
  for stem in set(sys.modules)-set(saved):sys.modules.pop(stem,None)
  sys.modules.update(saved)
 return dict(original,status='SOURCE_ONLY_FRESH_DESCRIPTOR_GRAPH_DIAGNOSTICS_NOT_ACCEPTED',files=len(actual),lifecycle_original_source=pub['source'],lifecycle_original_files=555,lifecycle_changed=7,lifecycle_added=4,lifecycle_held=548,query_profile='LATEST607_FRESH_DESCRIPTOR_GRAPH_QUERY_V1',observation_cache='NONE',consumer_seconds=1800,owner_seconds=6600,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
