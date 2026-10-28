# SPDX-License-Identifier: MIT
"""Retain the complete original15600s owner/worker, add fixed607 authority gates."""
import ast,json,os,sys,types
from pathlib import Path
import common as C,authority,source_guard,runtime

def single(raw,before,after,count=1):
 text=raw.decode();C.need(text.count(before)==count,'counted outer wrapper seam');out=text.replace(before,after);C.need(out.count(after)==count and out.replace(after,before)==text,'complete outer wrapper inverse');return out

def context(held):
 source_guard.verify(held);authority.require_bound();parent=C.load('_latest607_whole_native4k_case',C.ROOT/'parent4k/case.py');parent.source_context(held);proxy=types.ModuleType('case');proxy.__dict__.update(vars(parent));proxy.HERE=C.ROOT;proxy.CASES=C.CASES
 def source_context(root):source_guard.verify(root);authority.require_bound();return C.profile()
 proxy.source_context=source_context;node=next(n for n in ast.parse(C.read(C.ROOT/'parent4k/case.py')).body if isinstance(n,ast.FunctionDef)and n.name=='authenticate');raw=ast.get_source_segment(C.read(C.ROOT/'parent4k/case.py').decode(),node).encode();text=single(raw,"'native-arm-updater604-recovery4k'","'native-arm-latest607-updater4k'");exec(compile(text,'<latest607-native-custody>','exec'),proxy.__dict__);return proxy

def wrapper(held):
 proxy=context(held);module=C.load('_latest607_complete_outer_owner',C.ROOT/'parent4k/entry.py',{'case':proxy,'runtime':runtime});prerequisites=module.prerequisites
 def require(held,mode,argv):
  if mode=='preflight':
   rc=prerequisites(held,mode,argv);p=C.profile();rows=dict(p['input_sources'],latest_installer=p['fresh_source']);C.need(all(type(v)is str and len(v)==40 for v in rows.values()),'all immutable new input publications remain UNBOUND')
   if os.environ.get('GITHUB_OUTPUT'):
    with Path(os.environ['GITHUB_OUTPUT']).open('a')as stream:
     for k,v in rows.items():stream.write(k+'='+v+'\n')
   return rc
  a,rest=runtime.extras(argv);authority.gates(a.latest_decisions);integration=runtime.Integration(held,a.latest_installer,a.six_public,a.six_record,{k:getattr(a,k)for k in('apps16','apps16qualification','apps16current606qualification')},os.environ['GITHUB_SHA']);integration.inputs();return prerequisites(held,mode,rest)
 module.prerequisites=require;return module

def main(argv=None):
 import argparse
 args=list(sys.argv[1:]if argv is None else argv)
 if args and args[0]=='--source-preflight':
  q=argparse.ArgumentParser();q.add_argument('--held',type=Path);q.add_argument('--latest-installer',type=Path);q.add_argument('--six-public',type=Path);a=q.parse_args(args[1:]);values=(a.held,a.latest_installer,a.six_public);C.need(all(v is None for v in values)or all(v is not None for v in values),'all three explicit source operands or none');fact=source_guard.inputs(*values)if all(v is not None for v in values)else source_guard.verify();print(json.dumps(fact,sort_keys=True));return 0
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--implementation',type=Path,required=True);a,_=p.parse_known_args(args);return wrapper(C.safe(a.implementation)).main(args)

def cleanup_main(argv=None):
 # The original whole cleanup/retention CLI remains finite and source-held.
 proxy=context(Path(os.environ['LATEST607_HELD_SOURCE']));raw=C.read(C.ROOT/'parent4k/cleanup.py');text=single(raw,"result['source']==C.HELD", "result['source']==proof['source'] and result['held_library_source']==C.HELD");m=types.ModuleType('__main__');m.__file__=str(C.ROOT/'parent4k/cleanup.py');saved=sys.modules.get('case');sys.modules['case']=proxy
 try:exec(compile(text,m.__file__,'exec'),vars(m))
 finally:
  if saved is None:sys.modules.pop('case',None)
  else:sys.modules['case']=saved

def retain_main(argv=None):
 proxy=context(Path(os.environ['LATEST607_HELD_SOURCE']));C.load('__main__',C.ROOT/'parent4k/retain.py',{'case':proxy})
