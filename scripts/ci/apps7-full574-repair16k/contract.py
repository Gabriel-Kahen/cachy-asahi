# SPDX-License-Identifier: MIT
"""Separate fail-closed generic16K case authority, never native/hardware credit."""
import ast,hashlib,importlib.util,json,re,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
SELF=sys.modules[__name__]  # Stable while the original native job temporarily owns 'contract'.
LANE='scripts/ci/apps7-full574-repair16k';NATIVE='scripts/ci/apps7-full574-repair-native'
CASES=('repair-bytes','repair-missing');CAPS=(0,1,3,4,31);MASK=sum(1<<n for n in CAPS)
PASS='PASS_GENERIC16K_VM_FULL574_AUTHENTICATED_SELECTED_REPAIR_CASE'
NATIVE_SOURCE='c89868439988f99d4179d208d1198f6f9c94d5d5'
NATIVE_MANIFEST='c37c946199b43052594ece0ac24ae89a5cc77aa615ccf0b0abda9f28e3950a65'
PACKET='54352850a57a7e34e75c3a021fa20525eee59bf6'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def decode(raw):
 def pairs(items):
  value={}
  for k,v in items:need(k not in value,'duplicate JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
def relative(n):need(type(n)is str and n and not n.startswith('/') and '\\' not in n and all(s not in ('','.','..') for s in n.split('/')),'safe finite source path');return n
def read(path,cap=4*1024**2):
 path=Path(path);need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary path');a=path.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded single-link input');raw=path.read_bytes();b=path.stat();identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(identity(a)==identity(b) and len(raw)==a.st_size,'input drift');return raw
def row(path):
 path=Path(path);need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary hashed path');a=path.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,'ordinary single-link object')
 with path.open('rb') as f:d=hashlib.file_digest(f,'sha256').hexdigest()
 b=path.stat();identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns);need(identity(a)==identity(b),'hashed object drift');return dict(bytes=a.st_size,sha256=d)
def tree(root):
 root=Path(root);need(root.is_dir() and not root.is_symlink(),'ordinary input tree');result={};total=0
 for p in [root,*sorted(root.rglob('*'))]:
  name=p.relative_to(root).as_posix();info=p.lstat();node=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid);need(len(result)<20000,'finite input nodes')
  if p.is_symlink():
   target=p.readlink().as_posix();need(name.startswith('release/bundle/repo/') and '/' not in target and target not in ('','.','..') and not (p.parent/target).is_symlink() and (p.parent/target).is_file(),'only exact internal signed repository alias');node.update(type='symlink',target=target)
  elif p.is_dir():node.update(type='directory')
  else:
   need(p.is_file() and info.st_nlink==1 and info.st_size<=1024**3,'ordinary bounded input leaf');node.update(type='file',**row(p));total+=info.st_size;need(total<=8*1024**3,'finite input bytes')
  need(name not in result,'duplicate input path');result[name]=node
 return result
def save(path,value):Path(path).write_bytes(encoded(value))
def load(name,path):
 spec=importlib.util.spec_from_file_location('_apps574_repair16k_'+name,path);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m
 own=Path(path).absolute().parent==HERE;prior=sys.modules.get('contract')
 if own:sys.modules['contract']=SELF
 try:spec.loader.exec_module(m)
 finally:
  if own:
   if prior is None:sys.modules.pop('contract',None)
   else:sys.modules['contract']=prior
 return m
def function(path,name,namespace):
 raw=read(path);tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name];need(len(nodes)==1,'one finite borrowed function');exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path)+':source-bound-function','exec'),namespace);return namespace[name]
def check_source(root):
 rows=decode(read(HERE/'source-manifest.json'))['files'];need(1<=len(rows)<=512,'closed source bound')
 for n,pin in rows.items():need(row(Path(root)/relative(n))==pin,'source differs: '+n)
 return rows
def gate(root,case):
 need(case in CASES,'one explicit repair case');p=decode(read(HERE/'input-policy.json'));need(p.get('status')=='ROOT_BOUND_FULL574_REPAIR16K_NATIVE_CASES_AND_KERNEL' and type(p.get('binding'))is dict,'UNBOUND16K: no output, secrets or actors');check_source(root);b=p['binding'];need(set(b)=={'native_source','native_manifest_sha256','native_decision_source','native_decisions','kernel_authority_source','kernel_authority'} and set(b['native_decisions'])==set(CASES),'exact both native-case and kernel authorities')
 for k in ('native_source','native_decision_source','kernel_authority_source'):need(re.fullmatch('[0-9a-f]{40}',b[k] or ''),'exact immutable native source/decision carrier')
 need(b['native_source']==NATIVE_SOURCE and b['native_manifest_sha256']==NATIVE_MANIFEST and row(Path(root)/NATIVE/'source-manifest.json')['sha256']==b['native_manifest_sha256'] and re.fullmatch('[0-9a-f]{64}',b['native_manifest_sha256'] or ''),'same actual native case source manifest');native=load('native_contract',Path(root)/NATIVE/'contract.py');held=native.source(root);native.case(case);need(held['packet_source']==PACKET,'same original current4 native packet');return native,b

def decisions(root,case,native_decisions):
 native,b=gate(root,case);actual=subprocess.check_output(['git','-C',str(native_decisions),'rev-parse','HEAD'],text=True,timeout=10).strip();need(actual==b['native_decision_source'],'exact Root native-case decision carrier');records={}
 for selected,pin in b['native_decisions'].items():
  need(type(pin)is dict and type(pin.get('bytes'))is int and 0<pin['bytes']<=65536,'bounded Root case decision')
  records[selected]=decode(native.checked(native_decisions,pin))
 qualified=load('native_qualification',HERE/'native_qualification.py')
 need((qualified.SOURCE,qualified.MANIFEST,qualified.PACKET,qualified.CASES,qualified.VERSIONS)==(NATIVE_SOURCE,NATIVE_MANIFEST,PACKET,CASES,native.VERSIONS),'source-owned exact Apps7 qualification schema')
 # Carrier/descriptor/bytes above are mandatory; this pure DATA validator cannot
 # create authority. Root must issue both actual finite decisions after replay.
 return native,qualified.validate(records),b


def prior_kernel(root,case,path):
 native,b=gate(root,case)
 ref=b['kernel_authority'];need(type(ref)is dict and set(ref)=={'path','bytes','sha256'} and type(ref['bytes'])is int and 0<ref['bytes']<=65536,'bounded immutable prior kernel authority reference');relative(ref['path']);authority_path=Path(path).absolute();parts=Path(ref['path']).parts;need(authority_path.parts[-len(parts):]==parts,'exact prior kernel authority relativepath');carrier=authority_path.parents[len(parts)-1]
 actual=subprocess.check_output(['git','-C',str(carrier),'rev-parse','HEAD'],text=True,timeout=10).strip();need(actual==b['kernel_authority_source'],'exact prior kernel authority carrier');raw=read(authority_path,65536);need(len(raw)==ref['bytes'] and sha(raw)==ref['sha256'],'Root-bound prior kernel authority bytes');authority=decode(raw)
 need(authority.get('status')=='ROOT_ACCEPTED_GENERIC16K_KERNEL_PROFILE' and authority.get('scope')=='MANAGED_GUI_KERNEL_BUILD_AND_BOOT_COMPONENT_ONLY' and authority.get('GNU_installed_lifecycle')=='NOT_ACCEPTED' and authority.get('hardware')=='NOT_RUN' and authority.get('release')=='NOT_ADMITTED' and re.fullmatch('[0-9a-f]{40}',authority.get('source_sha') or '') and re.fullmatch('[1-9][0-9]{0,19}',str(authority.get('run_id',''))),'actual prior Root kernel profile provenance')
 for name in ('retained_receipt','root_decision'):
  pin=authority[name];need(type(pin)is dict and set(pin)=={'bytes','sha256'} and type(pin['bytes'])is int and 0<pin['bytes']<=16*1024**2 and re.fullmatch('[0-9a-f]{64}',pin['sha256'] or ''),'actual prior retained authority hash reference')
 K=load('prior_profile_validator',Path(root)/'scripts/ci/managed-gui-generic16k/kernel_contract.py');return K.validate(authority['profile']),authority

def authorize(args):
 native,accepted,b=decisions(args.source,args.case,args.native_decisions);prior,authority=prior_kernel(args.source,args.case,args.kernel_authority)
 args.implementation=args.source;kernel=function(args.source/'scripts/ci/current604-apps6-updater16k/vm.py','kernel',dict(C=SELF,Path=Path));profile,image,config=kernel(args)
 immutable=set(profile)-{'Image'};need({n:profile[n] for n in immutable}=={n:prior[n] for n in immutable},'fresh kernel must match declared accepted source/helper/fragment/config/profile identities; Image is new evidence')
 return native,accepted,(profile,image,config)

def case(value):need(value in CASES,'one explicit repair case');return value
def source(root):return gate(root,__import__('os').environ.get('REPAIR_CASE'))[1]
