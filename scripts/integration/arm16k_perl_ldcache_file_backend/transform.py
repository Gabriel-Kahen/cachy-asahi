"""Exact two-leaf passive transform and complete byte inverse. No actor entry."""
import ast,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
def need(v,why):
 if not v:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def function(raw,name):
 text=raw.decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name);lines=text.splitlines(keepends=True);return ''.join(lines[:node.lineno-1]),''.join(lines[node.lineno-1:node.end_lineno]),''.join(lines[node.end_lineno:])
def verify():
 v=json.loads((HERE/'source.lock.json').read_bytes());files=v['files'];need({p.name for p in HERE.iterdir()}==set(files)|{'source.lock.json'},'closed whole source family')
 for name,row in files.items():
  p=HERE/name;need(not p.is_symlink()and dict(**pin(p.read_bytes()),mode=stat.S_IMODE(p.stat().st_mode))==row,'whole source bytes/mode')
def apply(recovery,operation):
 verify();v=json.loads((HERE/'provenance.DATA.json').read_bytes())
 for name,body in(('recovery.py',recovery),('observe_initialized.py',operation)):
  need(pin(body)=={k:v['predecessor'][name][k]for k in('bytes','sha256')},'exact frozen predecessor operation leaves')
 head,_,tail=function(recovery,'chain');_,replacement,_=function((HERE/'chain.py').read_bytes(),'chain');new=(head+replacement+tail).encode()
 needle=b"if command['label']=='chain':R.chain(raw)";need(operation.count(needle)==1,'one exact chain call');op=operation.replace(needle,b"if command['label']=='chain':R.chain(raw,request['overlay']['pin']['bytes'])")
 compile(new,'corrected-recovery.py','exec');compile(op,'corrected-observation.py','exec');return new,op

def inverse(recovery,operation):
 old=(HERE/'predecessor-recovery.py').read_bytes(),(HERE/'predecessor-observe_initialized.py').read_bytes();need((recovery,operation)==apply(*old),'exact successor needed before complete inverse');return old
