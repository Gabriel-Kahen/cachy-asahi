# SPDX-License-Identifier: MIT
"""Normal604 diagnostic data only; no transaction or timeout authority."""
import ast,base64,hashlib,json,os,stat,time
from pathlib import Path
FILE='driver-progress.jsonl';CAP=32768;RECORDS=64;OUTPUT=1024**2
DRIVER='scripts/ci/full-root-upgrade/root_upgrade.py'
HOOK='scripts/ci/full-root-upgrade-caller/upgrade_hook.py'
SELF='scripts/ci/full-root-upgrade/driver_progress.py'
BASIS={'scripts/ci/full-root-upgrade/root_upgrade.py': {'bytes': 23555, 'sha256': 'ee8ceb257cdf45a841bb72de37cdbba67b175dedff835c986813a7f0ef0323fa'}, 'scripts/ci/full-root-upgrade-caller/upgrade_hook.py': {'bytes': 13943, 'sha256': '7797a893df3ad14323b3da32a6c168233ce161d4cfef3146ce070421486c7a99'}}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def directory(path):
 path=Path(path);need(path.is_absolute() and '..' not in path.parts,'ordinary diagnostic data directory required')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for part in path.parts[1:]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=child
  s=os.fstat(fd);need(s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,'owned private diagnostic directory required');return fd
 except BaseException:os.close(fd);raise
def regular(fd):
 s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=CAP,'owned bounded single-link diagnostic journal required');return s
def failure(error):return dict(error_type=type(error).__name__,error_sha256=pin(str(error).encode())['sha256'])
class Writer:
 def __init__(self,data):
  self.directory=directory(data);self.fd=None;self.count=0;self.started=time.monotonic();self.error=None
  try:self.fd=os.open(FILE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.directory);regular(self.fd)
  except BaseException:
   if self.fd is not None:os.close(self.fd)
   os.close(self.directory);raise
 def record(self,result):
  # Diagnostic failures never replace the algorithm's original result/exception.
  if self.error is not None:return
  try:
   row=dict(sequence=self.count,elapsed_ms=int((time.monotonic()-self.started)*1000),phase=result.get('phase'),authority='DIAGNOSTIC_ONLY_MAY_LAG_SIDE_EFFECTS')
   need(type(row['phase']) is str and 0<len(row['phase'])<=80 and row['phase'].isascii(),'bounded diagnostic phase required')
   for name in ('commit_started','packages_committed','checkpoint_changed'):
    value=result.get(name,'UNKNOWN');need(type(value) is bool or value=='UNKNOWN','qualified partial commit observation required');row[name]=value
   if 'error_type' in result:row['original_error_type']=str(result['error_type'])[:80]
   raw=encoded(row);s=regular(self.fd);named=os.stat(FILE,dir_fd=self.directory,follow_symlinks=False)
   need((s.st_dev,s.st_ino)==(named.st_dev,named.st_ino) and self.count<RECORDS and len(raw)<=512 and s.st_size+len(raw)<=CAP,'diagnostic identity/count/byte limit')
   view=memoryview(raw)
   while view:
    n=os.write(self.fd,view);need(n>0,'diagnostic write stopped');view=view[n:]
   self.count+=1
  except Exception as error:self.error=failure(error)
 def close(self):
  if self.fd is not None:os.close(self.fd);self.fd=None;os.close(self.directory)
def start(data,result):
 try:return Writer(data)
 except Exception as error:result['progress_diagnostic_error']=failure(error);return None
def note(writer,result):
 if writer is not None:
  writer.record(result)
  if writer.error is not None:result['progress_diagnostic_error']=writer.error

def capture(row,data):
 result=dict(scope='PARTIAL_DIAGNOSTICS_NOT_TRANSACTION_AUTHORITY',commit_inference='FORBIDDEN_FROM_PROGRESS',outputs={})
 total=0
 for name in ('stdout','stderr'):
  raw=row[name];need(type(raw) is bytes,'original supervised output bytes required');total+=len(raw);need(total<=OUTPUT,'unchanged combined worker output cap')
  result['outputs'][name]=dict(**pin(raw),base64=base64.b64encode(raw).decode(),capture='PRE_TERMINATION_PARTIAL_NO_POST_SIGNAL_DRAIN' if row.get('termination') else 'CAPTURED_BY_ORIGINAL_SUPERVISOR')
 try:
  d=directory(data)
  try:f=os.open(FILE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d)
  finally:os.close(d)
  try:
   before=regular(f);raw=os.read(f,CAP+1);after=regular(f)
   need(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'diagnostic journal changed during bounded read')
  finally:os.close(f)
  result['progress']=dict(status='RAW_OWNED_BOUNDED_BYTES_ONLY',**pin(raw),base64=base64.b64encode(raw).decode())
  def pairs(rows):
   out={}
   for key,value in rows:need(key not in out,'duplicate diagnostic field');out[key]=value
   return out
  lines=raw.splitlines(keepends=True);complete=lines if not lines or lines[-1].endswith(b'\n') else lines[:-1];fragment=b'' if len(complete)==len(lines) else lines[-1];records=[]
  for line in complete:
   need(len(line)<=512 and len(records)<RECORDS,'diagnostic record bounds');value=json.loads(line,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite diagnostic value'));need(type(value) is dict,'diagnostic object required')
   need(set(value)<=set(('sequence','elapsed_ms','phase','authority','commit_started','packages_committed','checkpoint_changed','original_error_type')) and value['sequence']==len(records) and type(value['elapsed_ms']) is int and value['elapsed_ms']>=0 and value['authority']=='DIAGNOSTIC_ONLY_MAY_LAG_SIDE_EFFECTS','diagnostic record shape')
   need(type(value['phase']) is str and 0<len(value['phase'])<=80 and value['phase'].isascii(),'bounded diagnostic phase')
   for name in ('commit_started','packages_committed','checkpoint_changed'):need(type(value[name]) is bool or value[name]=='UNKNOWN','partial diagnostic truth shape')
   need(not records or value['elapsed_ms']>=records[-1]['elapsed_ms'],'monotonic diagnostic sequence');records.append(value)
  result['progress']=dict(status='OBSERVED_COMPLETE_WRITES_ONLY',**pin(raw),base64=base64.b64encode(raw).decode(),records=records,trailing_fragment=dict(**pin(fragment),base64=base64.b64encode(fragment).decode()),last_completed_write=records[-1] if records else None,durability='NO_FSYNC_OR_POWER_LOSS_CLAIM',qualification='May precede actual side effects; never substitutes for driver result or commit/checkpoint proof')
 except Exception as error:result['progress']=dict(result.get('progress',{}),status='UNAVAILABLE_OR_REFUSED',**failure(error))
 return result

def transformed(raw,name):
 """Exact a29-derived normal inputs; additive diagnostics only, AST-proved."""
 need(name in BASIS and pin(raw)==BASIS[name],'exact original normal604 diagnostic basis required: '+name)
 text=raw.decode();anchors=[]
 def once(before,after):
  nonlocal text
  need(text.count(before)==1,'single diagnostic anchor required');text=text.replace(before,after);anchors.append(pin(before.encode()))
 if name==DRIVER:
  once('    copy_report, delegated = {}, False\n','    copy_report, delegated = {}, False\n    _trace = None\n')
  marker="        need(not any(data.iterdir()), 'fresh driver data directory required')\n"
  once(marker,marker+"        _progress = load('normal604_driver_progress', Path(__file__).with_name('driver_progress.py'))\n        _trace = _progress.start(data, result)\n        _progress.note(_trace, result)\n")
  # Match exactly seven existing phase assignments, preserving their AST nodes.
  tree=ast.parse(text);run=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run');lines=text.splitlines(keepends=True);edits=[]
  for n in ast.walk(run):
   if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Subscript) and isinstance(n.targets[0].value,ast.Name) and n.targets[0].value.id=='result' and isinstance(n.targets[0].slice,ast.Constant) and n.targets[0].slice.value=='phase':edits.append(n.end_lineno)
   if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=='result' and n.value.func.attr=='update' and any(k.arg=='phase' and isinstance(k.value,ast.Constant) and k.value.value=='update' for k in n.value.keywords):edits.append(n.end_lineno)
  need(len(edits)==7,'exact seven original driver phase boundaries required')
  for line in sorted(edits,reverse=True):lines.insert(line,' '*len(lines[line-1].removesuffix('\n').split('result',1)[0])+'_progress.note(_trace, result)\n')
  text=''.join(lines)
  once('    return result\n\n\ndef load(',"    finally:\n        if _trace is not None:\n            _progress.note(_trace, result)\n            _trace.close()\n    return result\n\n\ndef load(")
 else:
  once('        driver = driver_result(row)\n',"        result['worker_diagnostic'] = load('normal604_driver_progress', CODE / 'scripts/ci/full-root-upgrade/driver_progress.py').capture(row, control / 'data')\n        driver = driver_result(row)\n")
 output=text.encode();before=ast.parse(raw);after=ast.parse(output)
 class Remove(ast.NodeTransformer):
  def visit_Assign(self,node):
   if any(isinstance(t,ast.Name) and t.id in ('_trace','_progress') for t in node.targets):return None
   if name==HOOK and any(isinstance(t,ast.Subscript) and isinstance(t.value,ast.Name) and t.value.id=='result' and isinstance(t.slice,ast.Constant) and t.slice.value=='worker_diagnostic' for t in node.targets):return None
   return self.generic_visit(node)
  def visit_Expr(self,node):
   if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and isinstance(node.value.func.value,ast.Name) and node.value.func.value.id=='_progress' and node.value.func.attr=='note':return None
   return self.generic_visit(node)
  def visit_Try(self,node):
   if name==DRIVER and node.finalbody and len(node.finalbody)==1 and isinstance(node.finalbody[0],ast.If) and ast.unparse(node.finalbody[0].test)=='_trace is not None':node.finalbody=[]
   return self.generic_visit(node)
 need(ast.dump(before,include_attributes=False)==ast.dump(Remove().visit(after),include_attributes=False),'diagnostic-only AST delta required')
 compile(output,'<normal604-progress>','exec');return output,dict(before=pin(raw),after=pin(output),anchors=anchors,algorithm_ast='UNCHANGED_AFTER_REMOVING_EXACT_ADDITIVE_DIAGNOSTICS')

def prepare(target):
 target=Path(target);receipt={}
 for name in (DRIVER,HOOK):
  path=target/name;output,proof=transformed(path.read_bytes(),name);path.write_bytes(output);receipt[name]=proof
 path=target/SELF;need(not path.exists(),'fresh private diagnostic helper required');path.write_bytes(Path(__file__).read_bytes())
 return dict(scope='NORMAL604_DIAGNOSTIC_ONLY_NO_TRANSACTION_AUTHORITY',basis='a29d1987d909660feff4630b4a0e66d3073302ac',files=receipt,helper=dict(path=SELF,**pin(path.read_bytes())),worker_output_cap=OUTPUT,journal_cap=CAP,budgets='UNCHANGED',other_cases='UNCHANGED')
