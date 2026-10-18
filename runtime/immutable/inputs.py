"""Whole frozen source inputs; no collected Python or ambient source fallback."""
import hashlib,importlib.util,json,sys
from pathlib import Path
D=Path(__file__).resolve().parent
B=D.parent/'gnu-immutable-source-broker-development-20261018'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)
def check():
 policy=json.loads((D/'source-pins.json').read_bytes())
 for n,row in policy['files'].items():need(pin((D.parent/n).read_bytes())==row,'whole frozen input '+n)
 return policy

def broker():
 check();sys.path.insert(0,str(B));import protocol,context,client,broker
 need(all(Path(m.__file__).parent==B for m in(protocol,context,client,broker)),'exact source-owned broker modules')
 return protocol,context,client,broker

def original(name,relative):
 P,C,_,_=broker();api,modules=C.source_api();root=Path(modules['full_root'].__file__).parents[2];path=root/relative
 policy=json.loads((D/'source-pins.json').read_bytes());key=str(path.relative_to(D.parent));need(key in policy['files']and pin(path.read_bytes())==policy['files'][key],'explicit original helper closure')
 if '/glibc-debian-maintained-installed16k/'in relative:return current_module(name,path)
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 if '/glibc-gnu-provider-installed16k/'in relative:
  need(Path(m.C.__file__)==path.parent/'contract.py','no ambient legacy contract substitution')
  if hasattr(m,'adapter'):need(Path(m.adapter.__file__)==path.parent/'adapter.py','no ambient legacy adapter substitution')
 return m

def current_module(name,path):
 # Source-owned import isolation only: every executable byte remains pinned.
 import types
 def plain(n,p):
  s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
 contract=plain('_immutable_current_contract',path.parent/'contract.py')
 if path.name=='contract.py':return contract
 raw=path.read_bytes();space=dict(__name__=name,__file__=str(path),C=contract);anchor=b'import contract as C\n';need(raw.count(anchor)==1,'one exact CURRENT contract import');raw=raw.replace(anchor,b'')
 if b'import adapter\n'in raw:
  a=current_module('_immutable_current_adapter',path.parent/'adapter.py');raw=raw.replace(b'import adapter\n',b'');space['adapter']=a
 for module,alias in(('snapshot_progress','S'),('observer_progress','O')):
  anchor=('import '+module+' as '+alias+'\n').encode()
  if anchor in raw:raw=raw.replace(anchor,b'');space[alias]=plain('_immutable_current_'+module,path.parent/(module+'.py'))
 m=types.ModuleType(name);vars(m).update(space);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),vars(m));return m
