# SPDX-License-Identifier: MIT
"""Six readable installer bodies; finite literal edits and a byte-exact inverse."""
import ast,json
from pathlib import Path
import common as C
NAMES=('profile.py','run.py','prepare.py','guest.py','installer.py','numeric_vm.py')

def transform(raw,name):
 C.need(name in NAMES,'one of six original installer bodies');before=json.loads(C.read(C.ROOT/'parent604-map.json'));C.need(C.pin(raw)==before[name],'whole original604 body before adaptation');profile=C.profile();text=raw.decode();tree=ast.parse(text);lines=text.splitlines(keepends=True);offset=[0]
 for line in lines:offset.append(offset[-1]+len(line.encode()))
 oldhash=profile['expected604_sha256'];newhash=profile['target']['sha256'];edits=[]
 for n in ast.walk(tree):
  if not isinstance(n,ast.Constant):continue
  v=n.value;after=v
  if type(v)is int and v==604:after=607
  elif type(v)is str:
   if v==oldhash:after=newhash
   elif v=='0.1.0-5'and name=='profile.py':after='0.1.0-6'
   elif '604'in v:
    # Every allowed operand is sealed in the six before bodies. String identity
    # edits affect only lane/protocol/diagnostic literals, never executable code.
    after=v.replace('604','607').replace('public-pair','latest-six')
  if after==v:continue
  a=offset[n.lineno-1]+n.col_offset;b=offset[n.end_lineno-1]+n.end_col_offset;edits.append(dict(start=a,end=b,before=text.encode()[a:b].decode(),after=repr(after)))
 C.need(edits,'finite counted installer operand edits');out=raw
 for r in sorted(edits,key=lambda r:r['start'],reverse=True):out=out[:r['start']]+r['after'].encode()+out[r['end']:]
 # Restore in increasing original offset, with cumulative new-length offsets.
 restored=out;shift=0
 for r in sorted(edits,key=lambda r:r['start']):
  a=r['start']+shift;b=a+len(r['after'].encode());C.need(restored[a:b]==r['after'].encode(),'exact inverse operand');restored=restored[:a]+r['before'].encode()+restored[b:]
 C.need(restored==raw,'whole original604 body inverse');compile(out,'<fresh607-'+name+'>','exec')
 return out,dict(before=C.pin(raw),after=C.pin(out),edits=edits,whole_inverse=True)

def emit(output):
 output,=C.fresh(output,protected=(C.ROOT,));parent=C.ROOT/'parent604';before=json.loads(C.read(C.ROOT/'parent604-map.json'));values={};ledger={}
 for n in NAMES:values[n],ledger[n]=transform(C.checked(parent/n,before[n]),n)
 output.mkdir(mode=0o700)
 for n,b in values.items():(output/n).write_bytes(b)
 (output/'adapter.json').write_bytes(C.enc(dict(status='SOURCE_ONLY_FINITE607_INSTALLER_WHOLE604_INVERSE',files=ledger,clocks=C.profile()['clocks'],native='NOT_RUN',hardware='NOT_RUN')))
 return ledger
