# SPDX-License-Identifier: MIT
"""Explicit TCG-only caller60 facade; installed Apps16 scan30 and default35 held."""
import ast,hashlib,json,os,stat,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC={'schema_version': 1, 'profile': 'GUI_TCG_INVENTORY_CALLER_60_V1', 'scope': 'OPT_IN_VM_FUNCTIONAL_VALIDATION_ONLY_NOT_PERFORMANCE', 'caller_seconds': 60, 'product_scan_seconds': 30, 'default_caller_seconds': 35, 'stage_elapsed_data_limit_seconds': 65, 'old35_fit': 'NOT_ESTABLISHED', 'M2_performance': 'NOT_RUN', 'native_hotspot': 'UNKNOWN', 'acceptance': False, 'source': None, 'ref': None, 'run': None, 'actual': None, 'original_helpers': {'apps16_diagnostic.py': {'bytes': 6163, 'sha256': '9a39513103a495329eeb3eded4564570ae02f3e41fe7d1f149de921eecf4c1b4'}, 'apps16_runtime.py': {'bytes': 1948, 'sha256': 'df9d658794732b4a54c5eaf83037f54e64e87dde9c6d26b28672181893c77750'}, 'current_products.py': {'bytes': 7085, 'sha256': '5c0955b254813537f6b87cfad718afb05768ae12e3a5d7765b101c3c124a005e'}}}
SHIM="\n# Explicit VM-test capacity only; all default35 functions above remain whole.\ndef _install_inventory_vm_capacity():\n    import importlib.util\n    path=Path(__file__).resolve().parent/'inventory_capacity.py'\n    spec=importlib.util.spec_from_file_location('_owned_tcg_inventory_capacity',path)\n    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n    module.install(globals())\n_install_inventory_vm_capacity()\n"

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=65536):
 need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary pinned VM harness ancestry')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded single-link VM profile helper')
  raw=os.read(fd,cap+1);need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'whole stable VM profile helper');return raw
 finally:os.close(fd)
def profile():
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate VM profile field');out[k]=v
  return out
 raw=read(HERE/'inventory-vm-profile.json',8192)
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite VM profile'))
 need(raw==(json.dumps(SPEC,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode(),'exact typed canonical VM profile')
 need(value==SPEC,'explicit fixed TCG caller60 profile only; no NULL/arbitrary/default override')
 return value
def annotation():
 p=profile();return{k:p[k]for k in('profile','scope','caller_seconds','product_scan_seconds','default_caller_seconds','old35_fit','M2_performance','native_hotspot','acceptance')}
def clone(name,edits):
 p=profile();need(name in p['original_helpers'],'fixed helper role only');raw=read(HERE/name);need(pin(raw)==p['original_helpers'][name],'whole default35 helper before VM-only facade')
 text=raw.decode()
 for before,after in edits:need(text.count(before)==1,'one finite profile literal');text=text.replace(before,after,1)
 back=text
 for before,after in reversed(edits):need(back.count(after)==1,'one exact profile inverse');back=back.replace(after,before,1)
 need(back.encode()==raw,'entire default35 source inverse')
 m=types.ModuleType('_private_tcg60_'+name.removesuffix('.py'));m.__file__=str(HERE/name);exec(compile(text,m.__file__,'exec'),vars(m));return m

def diagnostic():
 return clone('apps16_diagnostic.py',[('timeout=35','timeout=60'),("value['elapsed_seconds']<=40","value['elapsed_seconds']<=65")])
def runtime():
 m=clone('apps16_runtime.py',[('GUI_command_limit_seconds=35','GUI_command_limit_seconds=60'),("before['GUI_command_limit_seconds']==35","before['GUI_command_limit_seconds']==60")]);observe,validate=m.observe,m.validate
 def observed(root=Path('/')):
  value=observe(root);value['inventory_validation_profile']=annotation();return value
 def validated(before,after):
  need(before.get('inventory_validation_profile')==after.get('inventory_validation_profile')==annotation(),'mandatory exact VM-only capacity identity')
  return validate(before,after)
 m.observe,m.validate=observed,validated;return m

def install(namespace):
 p=profile();need(not namespace.get('_vm_inventory_capacity_installed'),'one finite VM harness installation')
 path=Path(namespace['__file__']);raw=read(path);need(raw.endswith(SHIM.encode()),'one source-owned capacity installation footer');old=raw[:-len(SHIM.encode())];need(pin(old)==p['original_helpers']['current_products.py'],'whole original product/command harness body')
 tree=ast.parse(old);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_apps16_command_failure');text=ast.get_source_segment(old.decode(),node)
 edits=[('command_timeout_seconds=35','command_timeout_seconds=60'),('OUTER_35_SECOND_TIMEOUT_INNER_CAUSE_UNKNOWN','OUTER_60_SECOND_VM_VALIDATION_TIMEOUT_INNER_CAUSE_UNKNOWN'),("    raw=json.dumps(value,", "    value['inventory_validation_profile']=_vm_inventory_profile()\n    raw=json.dumps(value,")]
 for before,after in edits:need(text.count(before)==1,'one fixed failure metadata seam');text=text.replace(before,after,1)
 back=text
 for before,after in reversed(edits):back=back.replace(after,before,1)
 need(back==ast.get_source_segment(old.decode(),node),'whole original failure DATA function inverse')
 space=dict(namespace,_vm_inventory_profile=annotation);exec(compile(text,str(path),'exec'),space)
 original_run=namespace['run']
 def run(*args,**kw):
  value=original_run(*args,**kw);value['inventory_validation_profile']=annotation();return value
 namespace.update(_apps16_diagnostic=diagnostic,_apps16_runtime=runtime,_apps16_command_failure=space['_apps16_command_failure'],run=run,_vm_inventory_capacity_installed=True)
