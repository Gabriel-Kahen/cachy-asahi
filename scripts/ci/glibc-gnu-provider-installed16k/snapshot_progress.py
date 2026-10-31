# SPDX-License-Identifier: MIT
"""Optional finite hooks in exact original capability/snapshot methods only."""
import ast,hashlib,inspect,json,sys,threading,time,types
SNAPSHOT_SHA='f4a1b8b24df17650a2aeeb6cc7f074071135f8a773c1ab1511a42194c834372a'
CAP_SHA='498a3beec0327b9335dcd6d80ed5919fa2edebebd3284e9ee8b97770328e26a2'
COUNTERS=('graph_nodes','walk_nodes','recheck_nodes','capability_entries','hashed_inodes','hashed_bytes','mount_queries','attribute_queries','json_bytes','compressed_bytes')
OPS=('capability','graph','walk','recheck','rebind','json','gzip','snapshot-write')
def need(ok,why):
 if not ok:raise ValueError(why)
def validate(v):
 need(type(v) is dict and set(v)=={'operation','elapsed_ms',*COUNTERS} and v['operation'] in OPS and all(type(v[k]) is int and 0<=v[k]<=2**63-1 for k in ('elapsed_ms',*COUNTERS)),'closed bounded postwalk counters');return v
COPY_WORK_PHASES=('SETUP','DIRECTORY_CREATE','FILE_COPY','SYMLINK_COPY','DIRECTORY_METADATA','VALIDATION')
COPY_WORK_CALLS=('_copy_internal','_parent','_write','_source_alias','_root_check','OTHER')
def validate_copy_work(value):
 fields={'phase','caller','line','nodes','scheduled_file_entries','source_parent_identities','destination_parent_identities','current_file_bytes','sampled_at_ms','omitted_samples'}
 need(type(value) is dict and set(value)==fields and value['phase'] in COPY_WORK_PHASES and value['caller'] in COPY_WORK_CALLS,'closed copy work DATA')
 need(all(type(value[k]) is int and 0<=value[k]<=2**63-1 for k in fields-{'phase','caller'}),'bounded copy work counters')
 need(94<=value['line']<=193 and value['scheduled_file_entries']<=value['nodes'] and value['source_parent_identities']<=value['nodes'] and value['destination_parent_identities']<=value['nodes'],'source-bound copy counters')
 line=value['line'];phase='SETUP' if line<119 else 'DIRECTORY_CREATE' if line<126 else 'FILE_COPY' if line<163 else 'SYMLINK_COPY' if line<172 else 'DIRECTORY_METADATA' if line<179 else 'VALIDATION'
 need(value['phase']==phase and (phase=='FILE_COPY' or value['current_file_bytes']==0),'copy work source-line/phase identity');return value

def copy_work():
 """Read only bounded scalar/length DATA from the pinned original copier frame.

 No path, payload, frame or mutable mapping escapes; no filesystem query/scan.
 The unchanged factory compiles exact measure_copy.py with one existing scope
 predicate substitution, preserving all line anchors and operations.
 """
 frame=sys._getframe(1);caller='OTHER'
 try:
  for _ in range(12):
   if frame is None:return None
   code=frame.f_code
   if code.co_filename.endswith('/scripts/update/measure_copy.py'):
    if caller=='OTHER' and code.co_name in COPY_WORK_CALLS:caller=code.co_name
    if code.co_name=='_copy_internal' and code.co_firstlineno==94 and 94<=frame.f_lineno<=193:
     line=frame.f_lineno;local=frame.f_locals
     phase='SETUP' if line<119 else 'DIRECTORY_CREATE' if line<126 else 'FILE_COPY' if line<163 else 'SYMLINK_COPY' if line<172 else 'DIRECTORY_METADATA' if line<179 else 'VALIDATION'
     nodes=local.get('nodes',{});copied=local.get('copied',set());source=local.get('source_dirs',{});destination=local.get('dest_dirs',{})
     if type(nodes) is not dict or type(copied) is not set or type(source) is not dict or type(destination) is not dict:return None
     return dict(phase=phase,caller=caller,line=line,nodes=len(nodes),scheduled_file_entries=len(copied),source_parent_identities=len(source),destination_parent_identities=len(destination),current_file_bytes=local.get('total',0) if phase=='FILE_COPY' else 0)
   frame=frame.f_back
  return None
 finally:del frame

COPY_OPERATIONS=('SELECTED_OBSERVE','COPY_DATA','COPIED_TREE','CAPABILITY_RESTORE')
def validate_copy(value):
 fields={'schema_version','operation','ordinal','elapsed_ms','phase_elapsed_ms','shared_remaining_ms','window_remaining_ms','expiry','acceptance'}
 need(type(value) is dict and set(value) in (fields,fields|{'work'}) and type(value['schema_version']) is int and value['schema_version']==1 and value['operation'] in COPY_OPERATIONS,'closed copy phase DATA')
 need(type(value['ordinal']) is int and 1<=value['ordinal']<=64 and all(type(value[k]) is int and 0<=value[k]<=2**63-1 for k in ('elapsed_ms','phase_elapsed_ms','shared_remaining_ms')),'bounded copy timing DATA')
 need(value['window_remaining_ms'] is None or type(value['window_remaining_ms']) is int and 0<=value['window_remaining_ms']<=600000,'bounded copy600 window DATA')
 need(value['expiry'] in ('NONE','PARENT2400','WINDOW600') and value['acceptance'] is False,'copy phase DATA cannot grant acceptance')
 if 'work' in value:
  need(value['operation']=='COPY_DATA','copy work DATA exclusive scope');validate_copy_work(value['work'])
 return value
class Journal:
 """Bounded diagnostic tail; repeated samples coalesce without losing current seam."""
 def __init__(self,selection):self.selection=selection;self.rows=[];self.sequence=0
 def push(self,stage,edge,context,metrics=None):
  self.sequence+=1
  row=dict(sequence=self.sequence,stage=stage,edge=edge,**context,**({} if metrics is None else {('observer' if stage=='observer' else 'copy_context' if stage=='copy' else 'postwalk'):metrics}))
  if edge=='sample' and self.rows and self.rows[-1]['edge']=='sample' and all(self.rows[-1][k]==row[k] for k in ('stage','case','phase')):self.rows.pop()
  self.rows.append(row)
  while True:
   value=dict(status='DIAGNOSTIC_CALL_BOUNDARIES_NO_ACCEPTANCE',nonce=self.selection['nonce'],source_sha=self.selection['source_sha'],records=self.rows,omitted_records=self.sequence-len(self.rows))
   raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
   if len(self.rows)<=256 and len(raw)<=65536:return raw
   need(len(self.rows)>1,'individual bounded progress row');self.rows.pop(0)
class Probe:
 def __init__(self,record):
  self.record=record;self.started=time.monotonic();self.operation='capability';self.values=dict.fromkeys(COUNTERS,0);self.views={};self.stop=threading.Event();self.disabled=False
 def metrics(self):
  v=dict(self.values)
  for name,view in self.views.items():v[name]=len(view)
  return validate(dict(operation=self.operation,elapsed_ms=int((time.monotonic()-self.started)*1000),**v))
 def event(self,operation,edge):
  if self.disabled:return
  try:self.operation=operation;self.record('postwalk',edge,self.metrics())
  except Exception:self.disabled=True
 def start(self):
  def sample():
   while not self.stop.wait(5):
    if self.disabled:return
    try:self.record('postwalk','sample',self.metrics())
    except Exception:self.disabled=True
  self.thread=None
  try:self.thread=threading.Thread(target=sample,name='bounded-original-capability-progress',daemon=True);self.thread.start()
  except Exception:self.disabled=True
 def close(self):
  self.stop.set()
  if self.thread is not None and self.thread.ident is not None:self.thread.join(timeout=1)

def capability_facade(original,record,*,mount_query=None):
 raw=inspect.getsource(original);need(hashlib.sha256(raw.encode()).hexdigest()==CAP_SHA,'exact original capability observer required');text=raw
 rules=(
  (' children,groups=_graph(nodes,limits);result={};identities={};inodes={};hashed=set()'," _p.event('graph','enter')\n children,groups=_graph(nodes,limits);result={};identities={};inodes={};hashed=set()\n _p.values['graph_nodes']=len(nodes)\n _p.views.update(walk_nodes=identities,capability_entries=result,hashed_inodes=hashed)\n _p.event('graph','leave')"),
  ('  walk(rootfd)',"  _p.event('walk','enter')\n  walk(rootfd)\n  _p.event('walk','leave')"),
  ('  recheck(rootfd)',"  _p.event('recheck','enter')\n  recheck(rootfd)\n  _p.event('recheck','leave')"),
  ('  with _root(root,limits) as rebound:',"  _p.event('rebind','enter')\n  with _root(root,limits) as rebound:"),
  (' return validate_map(nodes,result,limits),identities',"  _p.event('rebind','leave')\n return validate_map(nodes,result,limits),identities"),
  ('def _mount(fd,limits):',"def _mount(fd,limits):\n _p.values['mount_queries']+=1"),
  ('def _attrs(fd,kind,limits,parent=None,name=None):',"def _attrs(fd,kind,limits,parent=None,name=None):\n _p.values['attribute_queries']+=1"),
  ("   for name in children[prefix]:","   for name in children[prefix]:\n    _p.values['recheck_nodes']+=1"),
  ("  total+=len(raw);need(total<=row['bytes'],'capability file grew');hashed.update(raw)","  total+=len(raw);need(total<=row['bytes'],'capability file grew');hashed.update(raw)\n  _p.values['hashed_bytes']+=len(raw)"),
 )
 for before,after in rules:need(text.count(before)==1,'counted capability hook anchor');text=text.replace(before,after)
 restored=text
 for before,after in reversed(rules):restored=restored.replace(after,before)
 need(restored==raw,'all original capability/check/hash/cleanup bodies restored byte exact')
 namespace=dict(vars(original));exec(compile(text,'<exact-original-capability-progress>','exec'),namespace);observe=namespace['observe']
 if mount_query is not None:
  query=mount_query(original._mount)
  def mounted(fd,limits):
   namespace['_p'].values['mount_queries']+=1
   return query(fd,limits)
  namespace['_mount']=mounted
 def measured(*args,**kwargs):
  p=Probe(record);namespace['_p']=p;p.start();p.event('capability','enter')
  try:return observe(*args,**kwargs)
  finally:p.event('capability','leave');p.close();p.views.clear()
 return types.SimpleNamespace(**dict(vars(original),observe=measured))

def snapshot(module,record):
 raw=inspect.getsource(module);tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='snapshot');original=ast.get_source_segment(raw,node);need(hashlib.sha256(original.encode()).hexdigest()==SNAPSHOT_SHA,'exact original snapshot method required');text=original
 rules=(
  ("    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\\n').encode();", "    _s.event('json','enter')\n    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\\n').encode();"),
  ("    compressed=gzip.compress(raw,mtime=0);", "    _s.values['json_bytes']=len(raw)\n    _s.event('json','leave')\n    _s.event('gzip','enter')\n    compressed=gzip.compress(raw,mtime=0);"),
  ("    (OUT/(label+'-root.json.gz')).write_bytes(compressed)", "    _s.values['compressed_bytes']=len(compressed)\n    _s.event('gzip','leave')\n    _s.event('snapshot-write','enter')\n    (OUT/(label+'-root.json.gz')).write_bytes(compressed)\n    _s.event('snapshot-write','leave')"),
 )
 for before,after in rules:need(text.count(before)==1,'counted original snapshot hook anchor');text=text.replace(before,after)
 restored=text
 for before,after in reversed(rules):restored=restored.replace(after,before)
 need(restored==original,'complete original snapshot maps/caps/limits/serialization body restored byte exact')
 namespace=dict(vars(module));exec(compile(text,'<exact-original-snapshot-progress>','exec'),namespace);observe=namespace['snapshot']
 def measured(*args,**kwargs):
  p=Probe(record);namespace['_s']=p
  # The capability observer owns its own sampler. JSON/gzip/write have finite boundaries.
  return observe(*args,**kwargs)
 return measured
