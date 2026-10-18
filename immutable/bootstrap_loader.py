"""Load exact bootstrap derivative without polluting legacy common/dm imports."""
import types
from pathlib import Path
import inputs
P,C,client,_=inputs.broker()

def load(leases,native):
 import runtime_context
 root=inputs.D.parent/'gnu-verity-bootstrap-development-20261018'
 def raw(name):
  path=root/name;row=inputs.check()['files'][str(path.relative_to(inputs.D.parent))];data=path.read_bytes();P.need(P.pin(data)==row,'whole bootstrap dependency');return path,data
 path,data=raw('common.py');common=types.ModuleType('_gnu_runtime_original_common');common.__file__=str(path);exec(compile(data,str(path),'exec'),vars(common))
 path,data=raw('dm.py');R=C.reader();space=dict(__name__='_gnu_runtime_original_dm',__file__=str(path),need=common.need,Header=R.Header,Target=R.Target,validate_table=R.validate_table,kernel_table=R.kernel_table)
 for anchor in(b'from common import need\n',b'from borrowed.reader import Header,Target,validate_table,kernel_table\n'):P.need(data.count(anchor)==1,'exact DM import seam');data=data.replace(anchor,b'')
 dm=types.ModuleType('_gnu_runtime_original_dm');vars(dm).update(space);exec(compile(data,str(path),'exec'),vars(dm))
 path,data=raw('bootstrap.py');import integration
 data=integration.derive(data)
 # integration is exact frozen broker's deriver; install explicit private globals.
 proxy=types.SimpleNamespace(selection=C.selection,Context=lambda value,source,work,limits:runtime_context.Context(value,source,work,limits,leases,native))
 module=types.ModuleType('_gnu_runtime_broker_bootstrap');module.__file__=str(path);vars(module).update(SOURCE_BROKER=proxy,SOURCE_CLIENT=client,dm=dm,R=R)
 for name in('need','obj','ordinary','encoded','pin','PROFILE','SOURCE'):vars(module)[name]=getattr(common,name)
 for anchor in(b'from common import need,obj,ordinary,encoded,pin,PROFILE,SOURCE\n',b'import dm\n',b'from borrowed import reader as R\n'):P.need(data.count(anchor)==1,'exact private bootstrap import seam');data=data.replace(anchor,b'')
 exec(compile(data,str(path),'exec'),vars(module));return module
