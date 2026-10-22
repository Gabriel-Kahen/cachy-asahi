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
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 if '/glibc-gnu-provider-installed16k/'in relative:
  need(Path(m.C.__file__)==path.parent/'contract.py','no ambient legacy contract substitution')
  if hasattr(m,'adapter'):need(Path(m.adapter.__file__)==path.parent/'adapter.py','no ambient legacy adapter substitution')
 return m
