"""Counted deployment of frozen new-purpose mechanism onto actual current lane."""
import ast,hashlib,json
from pathlib import Path
import deploy as D
RULES=(('glibc-gnu-provider-installed16k','glibc-debian-maintained-installed16k'),('/installed16k','/debian-maintained-installed16k'),('init-installed16k','init-debian-maintained-installed16k'),('caa_gnu_installed16k=1','caa_debian_maintained_installed16k=1'),('CAA_INSTALLED16K_PREPARE','CAA_DEBIAN_MAINTAINED_INSTALLED16K_PREPARE'))
FILES=('native_controller.py','native_prepare.py','disk_adapter.py','stage.py','worker.py','owner.py','runtime_check.py','test_controls.py','bootstrap_loader.py')
def derive(raw,name):
 text=raw.decode();edits=[]
 for before,after in RULES:
  count=text.count(before)
  if count:text=text.replace(before,after);edits.append(dict(old=before,new=after,count=count))
 if name=='disk_adapter.py':
  before="init=/init-debian-maintained-installed16k caa_debian_maintained_installed16k=1'";after="init=/init-debian-maintained-installed16k caa_debian_maintained_installed16k=1 arm64.nomops'";D.need(text.count(before)==1,'one exact CURRENT nomops cmdline');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
 if name=='bootstrap_loader.py':
  before=" data=integration.derive(data)"
  after=before+"\n old=b\"need(value['producer_retirement']=={'status':'ROOT_VERIFIED_SOURCE_PRODUCERS_RETIRED','source':SOURCE},'source writer retirement authority required')\";new=b\"writer_retired(value['producer_retirement'])\";P.need(data.count(old)==1,'one exact new-purpose writer guard');data=data.replace(old,new)"
  D.need(text.count(before)==1,'one private bootstrap derivation');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
  before="vars(module).update(SOURCE_BROKER=proxy,SOURCE_CLIENT=client,dm=dm,R=R)"
  after="vars(module).update(SOURCE_BROKER=proxy,SOURCE_CLIENT=client,dm=dm,R=R,writer_retired=writer_retired)"
  D.need(text.count(before)==1,'one writer witness global');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
  before="def load(leases,native):"
  after="""def writer_retired(value):
 import re
 policy=P.decode((inputs.D/'policy.json').read_bytes())
 P.need(type(value)is dict and set(value)=={'status','source','token','owner_report','inner_report','prior_Root_decision'}and value['status']=='SOURCE_ENFORCED_CURRENT_NATIVE_WRITERS_RETIRED'and value['source']==policy['actual_source']and re.fullmatch('[a-f0-9]{40}',value['source']or'')and re.fullmatch('[a-f0-9]{32}',value['token'])and value['prior_Root_decision']=='INPUT_AUTHORITY_ONLY_NOT_CURRENT_NATIVE_ACCEPTANCE','fresh source-owned writer retirement witness, never Root acceptance')
 for n in('owner_report','inner_report'):
  r=value[n];P.need(type(r)is dict and set(r)=={'bytes','sha256'}and type(r['bytes'])is int and 0<r['bytes']<=4*1024**2 and re.fullmatch('[a-f0-9]{64}',r['sha256']),'whole retired native report identity')
 return value

"""+before
  D.need(text.count(before)==1,'one finite writer predicate');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
 if name=='stage.py':
  # Held fence reads its historical sandbox pathname. Preserve BOTH exact
  # namespaces rather than modifying filter source or pretending old CAA2 runs.
  before=" policy=boot/'immutable/policy.json';policy.write_bytes(P.encode(value))"
  after=" compat=boot/'installed16k';P.need(not compat.exists(),'fresh fixed source-only fence namespace');compat.mkdir(mode=0o755);sandbox=Path('/debian-maintained-installed16k/sandbox.py');held=P.decode((inputs.D.parent/'gnu-verity-bootstrap-development-20261018/runtime-pins.json').read_bytes())['/installed16k/sandbox.py'];P.need(P.pin(sandbox.read_bytes())==held,'identical whole old/current sandbox filter source');(compat/'sandbox.py').write_bytes(sandbox.read_bytes())\n"+before
  D.need(text.count(before)==1,'one declared readonly sandbox compatibility leaf');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
 for before,after in PATCHES.get(name,()):
  D.need(text.count(before)==1,'one exact runtime correction seam');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
 restored=text
 for e in reversed(edits):D.need(restored.count(e['new'])==e['count'],'inverse counted new-purpose namespace seam');restored=restored.replace(e['new'],e['old'])
 D.need(restored.encode()==raw,'whole frozen667 function/code inverse');compile(text,name,'exec');return text.encode(),edits
INPUT_APPEND='''
def current_module(name,path):
 # Source-owned import isolation only: every executable byte remains pinned.
 import types
 def plain(n,p):
  s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
 contract=plain('_immutable_current_contract',path.parent/'contract.py')
 if path.name=='contract.py':return contract
 raw=path.read_bytes();space=dict(__name__=name,__file__=str(path),C=contract);anchor=b'import contract as C\\n';need(raw.count(anchor)==1,'one exact CURRENT contract import');raw=raw.replace(anchor,b'')
 if b'import adapter\\n'in raw:
  a=current_module('_immutable_current_adapter',path.parent/'adapter.py');raw=raw.replace(b'import adapter\\n',b'');space['adapter']=a
 for module,alias in(('snapshot_progress','S'),('observer_progress','O')):
  anchor=('import '+module+' as '+alias+'\\n').encode()
  if anchor in raw:raw=raw.replace(anchor,b'');space[alias]=plain('_immutable_current_'+module,path.parent/(module+'.py'))
 m=types.ModuleType(name);vars(m).update(space);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),vars(m));return m
'''
def input_derivative(raw):
 text=raw.decode();anchor=" spec=importlib.util.spec_from_file_location(name,path);";D.need(text.count(anchor)==1,'one original owned helper import entry');replacement=" if '/glibc-debian-maintained-installed16k/'in relative:return current_module(name,path)\n"+anchor;text=text.replace(anchor,replacement)+INPUT_APPEND;D.need(text.removesuffix(INPUT_APPEND).replace(replacement,anchor).encode()==raw,'whole input loader inverse');compile(text,'inputs.py','exec');return text.encode()

DM_PATH='gnu-verity-bootstrap-development-20261018/dm.py'
DM_REQUEST_BEFORE="def request(self,cmd,*,payload=b'',count=0,flags=READONLY):\n  pid1();raw=bytearray(312+len(payload));h=Header.from_buffer(raw);h.version[:]=(4,0,0);h.data_size=len(raw);h.data_start=312;h.target_count=count;h.flags=flags;h.name=self.name.encode();h.uuid=self.uuid.encode()\n  if self.dev is not None:h.dev=self.dev\n  raw[312:]=payload;fd=os.open('/dev/mapper/control',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)\n  try:\n   info=os.fstat(fd);need(stat.S_ISCHR(info.st_mode)and info.st_rdev==os.makedev(10,236),'actual DM control node');fcntl.ioctl(fd,number(cmd),raw,True)\n  finally:os.close(fd)\n  need(h.version[0]==4 and not h.flags&BUFFER_FULL,'complete DM response');return h.dev"
DM_REQUEST_AFTER="def request(self,cmd,*,payload=b'',count=0,flags=READONLY):\n  pid1();number(cmd)\n  if cmd==3:need(not self.created and self.dev is None,'fresh owned DM create only')\n  else:\n   need(self.created and type(self.dev)is int and self.dev>0,'only original created DM identity')\n   if cmd in(4,6,9):self.request(7) # Refuse foreign name/UUID/dev before any mapping mutation.\n  raw=bytearray(312+len(payload));h=Header.from_buffer(raw);h.version[:]=(4,0,0);h.data_size=len(raw);h.data_start=312;h.target_count=count;h.flags=flags\n  if cmd==3:h.name=self.name.encode();h.uuid=self.uuid.encode()\n  else:h.dev=self.dev # Kernel lookup ABI permits exactly one of name, UUID, or dev.\n  raw[312:]=payload;fd=os.open('/dev/mapper/control',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)\n  try:\n   info=os.fstat(fd);need(stat.S_ISCHR(info.st_mode)and info.st_rdev==os.makedev(10,236),'actual DM control node');fcntl.ioctl(fd,number(cmd),raw,True)\n  finally:os.close(fd)\n  need(h.version[0]==4 and not h.flags&BUFFER_FULL,'complete DM response')\n  need(bytes(h.name)==self.name.encode()and bytes(h.uuid)==self.uuid.encode()and h.dev>0 and(self.dev is None or h.dev==self.dev),'exact owned DM name/UUID/device response; foreign mapping refused')\n  return h.dev"

def derive_dm(raw):
 text=raw.decode();old=DM_REQUEST_BEFORE;new=DM_REQUEST_AFTER
 D.need(text.count(old)==1,'exact original DM request source seam');changed=text.replace(old,new,1);D.need(changed.replace(new,old,1)==text,'whole original DM source inverse');compile(changed,'dm.py','exec');return changed.encode(),[dict(old=old,new=new,count=1)]

def apply(runtime):
 basis=D.obj(D.read(D.HERE/'runtime-basis.json',2*1024**2));before={n:D.pin(D.read(runtime/n,16*1024**2))for n in basis};D.need(before==basis,'whole frozen runtime667 before derivative');changes={}
 for name in FILES:
  p=runtime/'immutable'/name;old=p.read_bytes();new,edits=derive(old,name)
  if new!=old:p.write_bytes(new);changes['immutable/'+name]=dict(before=D.pin(old),after=D.pin(new),inverse=edits)
 p=runtime/'immutable/inputs.py';old=p.read_bytes();new=input_derivative(old);p.write_bytes(new);changes['immutable/inputs.py']=dict(before=D.pin(old),after=D.pin(new),inverse='ONE_CONTRACT_IMPORT_ENTRY_PLUS_SOURCE_OWNED_CURRENT_MODULE_IMPORT_ISOLATOR')
 # The complete original667 basis was checked above. Derive only the exact
 # DM request and its one source-pins row; all other input413 bodies stay held.
 p=runtime/DM_PATH;old=p.read_bytes();new,edits=derive_dm(old);p.write_bytes(new);changes[DM_PATH]=dict(before=D.pin(old),after=D.pin(new),inverse=edits)
 p=runtime/'immutable/source-pins.json';old=p.read_bytes();table=D.obj(old);D.need(table['files'][DM_PATH]==basis[DM_PATH],'exact original DM source row before derivative');table['files'][DM_PATH]=D.pin(new);new=D.encoded(table);p.write_bytes(new);changes['immutable/source-pins.json']=dict(before=D.pin(old),after=D.pin(new),inverse='EXACT_SINGLE_DM_REQUEST_SOURCE_PIN_ROW_ONLY')
 manifest=D.obj((runtime/'runtime-source.json').read_bytes())
 for n,row in changes.items():manifest['files'][n]=row['after']
 (runtime/'runtime-source.json').write_bytes(D.encoded(manifest));changes['runtime-source.json']=dict(before=basis['runtime-source.json'],after=D.pin((runtime/'runtime-source.json').read_bytes()),inverse='EXACT_DERIVED_OWN_ROWS_ONLY')
 after={n:D.pin((runtime/n).read_bytes())for n in basis};D.need({n for n in basis if before[n]!=after[n]}==set(changes),'only declared source derivatives')
 return dict(basis_files=667,changed=changes,held=len(basis)-len(changes),current_pair='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9',legacy_pair='NOT_SELECTED',scope='CURRENT_CAA3_FULL_LIFECYCLE_WITH_NEW_PID1_SOURCE_PURPOSE_NOT_NATIVE_ACCEPTANCE')

PATCHES={'native_controller.py': (("changes=((kernel,replacement),", "changes=((\"disks.mkdir();\",\"disks.mkdir(mode=0o700);\"),(kernel,replacement),"),), 'stage.py': (("  path=root/name;raw=path.read_bytes();space=dict(__name__='_runtime_stage_'+Path(name).stem,__file__=str(path),**replacements)\n  for a in anchors:P.need(raw.count(a)==1,'one explicit original offline import');raw=raw.replace(a,b'')\n  exec(compile(raw,str(path),'exec'),space);return types.SimpleNamespace(**space)", "  path=root/name;raw=path.read_bytes();value=types.ModuleType('_runtime_stage_'+Path(name).stem);space=vars(value);space.update(__file__=str(path),**replacements)\n  for a in anchors:P.need(raw.count(a)==1,'one explicit original offline import');raw=raw.replace(a,b'')\n  exec(compile(raw,str(path),'exec'),space);return value"),), 'native_prepare.py': (("if __name__=='__main__':\n value=P.decode(runtime_policy.read(Path('/runtime-selection/policy.json'),1024**2));runtime_policy.gate(value,preparing=True);load(value)['prepare']()", "def media_handoff(parent,uid,gid):\n # Fixed descriptor ownership handback, no traversal, content/mode edit or deletion.\n import os,stat\n parent=Path(parent)\n P.need(parent.is_absolute()and not any(p.is_symlink()for p in(parent,*parent.parents)),'ordinary anchored media parent')\n flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC\n pfd=os.open(parent,flags);fd=None\n identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_uid,s.st_gid,s.st_mtime_ns,s.st_ctime_ns)\n try:\n  base=os.fstat(pfd);P.need(stat.S_IMODE(base.st_mode)==0o700 and (base.st_uid,base.st_gid)==(uid,gid)and identity(base)==identity(parent.lstat()),'exact original private output owner')\n  try:fd=os.open('immutable-media',flags,dir_fd=pfd)\n  except FileNotFoundError:return\n  before=os.fstat(fd)\n  P.need(before.st_dev==base.st_dev and before.st_uid in(os.geteuid(),uid)and stat.S_IMODE(before.st_mode)==0o700 and before.st_nlink==2,'ordinary original media directory')\n  caps={'source.raw':8*1024**3,'source.hash':128*1024**2,'source-before.json':96*1024**2,'source-after.json':96*1024**2,'source-image.json':4*1024**2}\n  names=os.listdir(fd);P.need(set(names)<=set(caps),'finite exact media child paths')\n  entries={}\n  for name in names:\n   info=os.stat(name,dir_fd=fd,follow_symlinks=False)\n   P.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_uid in(os.geteuid(),uid)and not(info.st_mode&0o022)and info.st_dev==before.st_dev and 0<=info.st_size<=caps[name],'ordinary bounded single-link media child')\n   entries[name]=identity(info)\n  P.need(set(os.listdir(fd))==set(names)and all(identity(os.stat(n,dir_fd=fd,follow_symlinks=False))==v for n,v in entries.items())and identity(os.fstat(fd))==identity(before)==identity(os.stat('immutable-media',dir_fd=pfd,follow_symlinks=False)),'same anchored media directory and children before handoff')\n  # Only the two exact QEMU drive files need host-caller access (hash is0600).\n  for name in ('source.raw','source.hash'):\n   if name not in entries:continue\n   child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)\n   try:\n    held=os.fstat(child);P.need(identity(held)==entries[name]and stat.S_IMODE(held.st_mode)in(0o600,0o644),'same exact ordinary drive descriptor')\n    os.fchown(child,uid,gid);now=os.fstat(child)\n    P.need((now.st_uid,now.st_gid)==(uid,gid)and (now.st_dev,now.st_ino,now.st_mode,now.st_nlink,now.st_size,now.st_mtime_ns)==(held.st_dev,held.st_ino,held.st_mode,held.st_nlink,held.st_size,held.st_mtime_ns)and identity(now)==identity(os.stat(name,dir_fd=fd,follow_symlinks=False)),'same drive bytes/metadata handed only to output owner')\n    entries[name]=identity(now)\n   finally:os.close(child)\n  os.fchown(fd,uid,gid)\n  after=os.fstat(fd)\n  P.need((after.st_uid,after.st_gid)==(uid,gid)and (after.st_dev,after.st_ino,after.st_mode,after.st_nlink,after.st_size,after.st_mtime_ns)==(before.st_dev,before.st_ino,before.st_mode,before.st_nlink,before.st_size,before.st_mtime_ns)and identity(after)==identity(os.stat('immutable-media',dir_fd=pfd,follow_symlinks=False)),'same media inode handed only to original parent owner')\n  P.need(set(os.listdir(fd))==set(names)and all(identity(os.stat(n,dir_fd=fd,follow_symlinks=False))==v for n,v in entries.items()),'media child metadata held through handoff')\n finally:\n  if fd is not None:os.close(fd)\n  os.close(pfd)\n\ndef execute(value):\n runtime_policy.gate(value,preparing=True)\n try:return load(value)['prepare']()\n finally:\n  import os\n  media_handoff(Path('/out'),int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))\n\nif __name__=='__main__':\n value=P.decode(runtime_policy.read(Path('/runtime-selection/policy.json'),1024**2));execute(value)"),)}

# Failure-only diagnostic; original positive protocol is byte recoverable.
PATCHES['native_controller.py']=PATCHES.get('native_controller.py',())+(("v=P.decode(lines[0]);P.need(v['purpose']","v=P.decode(lines[0]);\n if type(v)is dict and v.get('purpose')=='GNU_IMMUTABLE_RUNTIME_V1'and v.get('status')=='FAIL':\n  P.need(set(v)=={'cleanup','error','error_type','purpose','status'}and v['cleanup']=='NOT_ACCEPTED_UNKNOWN_STATE_RETAIN_BACKING_FILES'and type(v['error'])is str and len(v['error'].encode())<=4096 and type(v['error_type'])is str and 0<len(v['error_type'].encode())<=128,'closed bounded guest failure DATA only')\n  raise ValueError('guest FAIL DATA only; nonce/lifecycle/cleanup NOT_ACCEPTED: '+json.dumps(v,sort_keys=True,separators=(',',':')))\n P.need(v['purpose']"),)
