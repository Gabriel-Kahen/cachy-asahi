# SPDX-License-Identifier: MIT
"""Finite opt-in TCG service capacity; every original default route stays whole."""
import ast,hashlib,json,os,stat,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC={'M2_performance': 'NOT_RUN', 'acceptance': False, 'actual': None, 'cleanup_seconds': 450, 'current1800_fit': 'NOT_ESTABLISHED', 'default_loop_seconds': 1300, 'default_owner_wait_seconds': 2200, 'default_runtime_seconds': 1750, 'default_service_seconds': 1200, 'doctor_profile_seconds': 1080, 'inventory_caller_seconds': 60, 'loop_seconds': 1900, 'native_hotspot': 'UNKNOWN', 'native_owner_seconds': 6600, 'observation_seconds': 600, 'old1200_fit': 'NOT_ESTABLISHED', 'original_helpers': {'doctor_lifetime.py': {'bytes': 14227, 'sha256': '317f020b3b9e2a1bf15156d29399162915c8b3bd23531181921d7169ca4a21be'}, 'factory.py': {'bytes': 20766, 'sha256': 'b68cb2a5116cd3e67823ef08fcd567a05941adbd5bdbad372e45cbaeb6e655a3'}, 'run.py': {'bytes': 6065, 'sha256': 'ea3cc4132ddac813d78daac6219062556afd99b25012969f7fe12c74b606b4ca'}}, 'owner_wait_seconds': 2800, 'product_scan_seconds': 30, 'profile': 'GUI_TCG_SERVICE_1800_V1', 'ref': None, 'run': None, 'runtime_seconds': 2350, 'schema_version': 1, 'scope': 'OPT_IN_VM_FUNCTIONAL_VALIDATION_ONLY_NOT_PERFORMANCE', 'service_purpose': 'TCG_VALIDATION_FIXTURE_SERVICE_1800S', 'service_seconds': 1800, 'source': None}
PURPOSE='TCG_VALIDATION_FIXTURE_SERVICE_1800S'
FACTORY_FOOTER="\n# Explicit selected TCG route; every original factory function/default above is held.\ndef service1800():\n    return load('_owned_service1800_capacity',HERE/'service_capacity.py').factory(globals(),'tcg1800')\n"
RUN_FOOTER="\n# Explicit selected TCG route; original run/cleanup/default2200 remain whole.\ndef run_service1800(*args,**kwargs):\n    return F.load('_owned_service1800_owner',Path(__file__).resolve().parent/'service_capacity.py').owner(globals(),*args,**kwargs)\n"

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(p,cap=1024**2):
 p=Path(p);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary capacity input ancestry');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=cap,'bounded singlelink capacity input');raw=os.read(fd,cap+1);need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(p.lstat()),'stable whole capacity input');return raw
 finally:os.close(fd)
def profile():
 raw=read(HERE/'service-vm-profile.json',8192);need(raw==enc(SPEC),'exact canonical typed service1800 profile');return json.loads(raw)
def annotation():
 p=profile();return{k:v for k,v in p.items()if k!='original_helpers'}
def edited(raw,edits):
 text=raw.decode()
 for a,b,count in edits:need(text.count(a)==count,'exact finite service seam '+a);text=text.replace(a,b)
 back=text
 for a,b,count in reversed(edits):need(back.count(b)==count,'exact inverse service seam '+b);back=back.replace(b,a)
 need(back.encode()==raw,'whole service source inverse');return text.encode()
def lifetime(raw):
 p=profile();need(pin(raw)==p['original_helpers']['doctor_lifetime.py'],'whole original1200 lifetime helper');return edited(raw,[('SERVICE_SECONDS=1200','SERVICE_SECONDS=1800',1),('EXISTING_FIXTURE_SERVICE_1200S',PURPOSE,3)])
def apply(out):
 profile();out=Path(out);changes={}
 for name,fn in(('doctor_lifetime.py',lifetime),('desktop574_fixture.sh',lambda b:edited(b,[('TimeoutStartSec=1200','TimeoutStartSec=1800',1)])),('desktop574_runtime.py',lambda b:edited(b,[('deadline = time.monotonic() + 1300','deadline = time.monotonic() + 1900',1),('signal.setitimer(signal.ITIMER_REAL, 1750)','signal.setitimer(signal.ITIMER_REAL, 2350)',1)]))):
  p=out/name;before=read(p);after=fn(before);p.write_bytes(after);changes[name]=dict(before=pin(before),after=pin(after))
 (out/'service-vm-profile.json').write_bytes(enc(SPEC));(out/'service-capacity-proof.json').write_bytes(enc(dict(status='SOURCE_ONLY_EXPLICIT_TCG_SERVICE1800',profile=annotation(),derivatives=changes,actual=None)));return changes

def function_copy(fn,space):
 # Rebind the EXECUTING function globals, not merely a module attribute.
 value=types.FunctionType(fn.__code__,space,fn.__name__,fn.__defaults__,fn.__closure__);value.__kwdefaults__=fn.__kwdefaults__;return value

def factory(namespace,selected):
 p=profile();need(selected=='tcg1800','explicit fixed service profile only');raw=read(Path(namespace['__file__']));need(raw.endswith(FACTORY_FOOTER.encode())and pin(raw[:-len(FACTORY_FOOTER.encode())])==p['original_helpers']['factory.py'],'entire original factory before finite opt-in footer')
 space=dict(namespace);original_prepare=namespace['prepare_code'];original_seal=namespace['seal']
 def prepare_code(*args,**kwargs):
  result=original_prepare(*args,**kwargs);apply(args[2]if len(args)>2 else kwargs['out']);return result
 def seal(out,*args,**kwargs):
  result=original_seal(out,*args,**kwargs);result['service_validation_profile']=annotation();(Path(out)/'current606-proof.json').write_bytes(enc(result));return result
 space.update(prepare_code=prepare_code,seal=seal)
 space['emit']=function_copy(namespace['emit'],space)
 need(space['emit'].__globals__['prepare_code']is prepare_code and space['emit'].__globals__['seal']is seal,'actual emitter must resolve selected facade')
 module=types.ModuleType('_selected_service1800_factory');vars(module).update(space);return module

def owner(namespace,*args,**kwargs):
 p=profile();path=Path(namespace['__file__']);raw=read(path);need(raw.endswith(RUN_FOOTER.encode())and pin(raw[:-len(RUN_FOOTER.encode())])==p['original_helpers']['run.py'],'whole original2200 owner before selected facade');old=raw[:-len(RUN_FOOTER.encode())].decode();node=next(n for n in ast.parse(old).body if isinstance(n,ast.FunctionDef)and n.name=='run');body=ast.get_source_segment(old,node);text=edited(body.encode(),[('child.process.wait(timeout=2200)','child.process.wait(timeout=2800)',1)]);space=dict(namespace);exec(compile(text,str(path),'exec'),space)
 runner=Path(args[1]if len(args)>1 else kwargs['runner']);proof=json.loads(read(runner/'current606-proof.json'));need(proof.get('service_validation_profile')==annotation()and read(runner/'service-vm-profile.json')==enc(SPEC),'selected owner requires whole source-sealed1800 runner')
 return space['run'](*args,**kwargs)
