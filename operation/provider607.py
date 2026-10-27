# SPDX-License-Identifier: MIT
"""Fresh signed607 installation, physical snapshot and exact owned retirement.

No acquisition occurs here. Native entry points require the independent owned
runtime, pinned public245/operation closure and exact fresh4K1197 source. The VM
installer stays immutable: a complete engine derivative has explicit native
admission seams, with its authentication/ALPM/payload/DB bodies unchanged.
"""
import ast,contextlib,ctypes,fcntl,gzip,hashlib,importlib.util,json,os,re,shutil,stat,sys,tarfile,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=Path('/source');FRESH=Path('/fresh-source');AUTH=Path('/fresh-authorization.json');BUNDLE=Path('/bundle');CODE=Path('/installer-code');CANDIDATE=Path('/candidate');WORK=Path('/work');OUT=Path('/out');DATA=Path('/data')
PROVIDER='fresh4k';PROVIDER_SOURCE='b9976eea34eaed4b6e56af3be21d4d652fa971d6'
INSTALL_SECONDS=4500;SNAPSHOT_SECONDS=600;MAX_NODES=500000;MAX_BYTES=8*1024**3;MAX_TAR=12*1024**3
BASE_CAPS=sum(1<<bit for bit in(0,1,3,4))
ROLE_CAPS=dict(install=BASE_CAPS|sum(1<<bit for bit in(6,7,18)),snapshot=BASE_CAPS|(1<<31),consumer=BASE_CAPS|(1<<31)|(1<<18),cleanup=BASE_CAPS)
NATIVE_CAPS=ROLE_CAPS['consumer']

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def digest(v):return pin(encoded(v))['sha256']
def identity(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def canonical(value):
 raw=os.fspath(value);need(os.path.isabs(raw)and raw==os.path.normpath(raw)and not raw.startswith('//'),'canonical absolute provider path');p=Path(raw);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary provider ancestry');return p

def read(path,limit=16*1024**2):
 p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=limit,'bounded ordinary provider DATA');out=bytearray()
  while b:=os.read(fd,1024**2):out.extend(b);need(len(out)<=s.st_size,'provider DATA growth')
  need(len(out)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(p.lstat()),'stable provider FD/path');return bytes(out)
 finally:os.close(fd)

def decode(raw):
 def pairs(rows):
  value={}
  for k,v in rows:need(k not in value,'duplicate provider DATA key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite provider DATA'))
def write(path,raw):
 p=canonical(path);need(type(raw)is bytes,'literal provider bytes');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
 return pin(raw)
def save(path,value):return write(path,encoded(value))
def load(name,path):
 spec=importlib.util.spec_from_file_location('_fresh_native607_'+name,path);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
@contextlib.contextmanager
def aliases(**modules):
 absent=object();old={k:sys.modules.get(k,absent)for k in modules};sys.modules.update(modules)
 try:yield
 finally:
  for k,v in old.items():
   if v is absent:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def current_identity():
 values={k:os.environ.get(k)for k in('SOURCE_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','OWNER_TOKEN','CACHY_ASAHI_APPS_TRANSACTION')}
 need(re.fullmatch('[0-9a-f]{40}',values['SOURCE_SHA']or'')and re.fullmatch('[1-9][0-9]*',values['GITHUB_RUN_ID']or'')and re.fullmatch('[1-9][0-9]*',values['GITHUB_RUN_ATTEMPT']or'')and re.fullmatch('[0-9a-f]{32}',values['OWNER_TOKEN']or'')and values['OWNER_TOKEN']==values['CACHY_ASAHI_APPS_TRANSACTION'],'independent actual native source/run/attempt/token')
 return dict(source=values['SOURCE_SHA'],run_id=int(values['GITHUB_RUN_ID']),attempt=int(values['GITHUB_RUN_ATTEMPT']),token=values['OWNER_TOKEN'])

def actor_guard(role):
 need(role in ROLE_CAPS,'fixed native provider role');who=current_identity()
 need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==4096 and Path('/.dockerenv').is_file()and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline native4K actor, never VM equivalence')
 need(os.environ.get('PATH')=='/usr/bin:/bin'and not any(k.startswith(('LD_','GPG_','ALPM_','PACMAN_'))for k in os.environ),'held clean command environment')
 status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if':'in line)
 need(status['NoNewPrivs'].strip()=='1'and all(int(status[k],16)==0 for k in('CapInh','CapAmb'))and all(int(status[k],16)==ROLE_CAPS[role] for k in('CapEff','CapPrm','CapBnd')),'exact declared filesystem capability set, no SYS_ADMIN or privileged substitute')
 for p in(SOURCE,HERE,OUT):need(p.is_mount()and not p.is_symlink(),'explicit owned actor mount: '+str(p))
 for p in(SOURCE,HERE):
  fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'actual readonly source mount')
  finally:os.close(fd)
 X=load('common',HERE/'common.py');X.verify(SOURCE,os.environ.get('APPS16_INTERRUPTION_PROFILE_SHA256'))
 return who

def _body(text,name):
 nodes=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name];need(len(nodes)==1,'one source function: '+name);return ast.get_source_segment(text,nodes[0])+'\n'
def derive_engine(raw):
 """Complete original signed engine with explicit native-only boundary seams."""
 before=_body(raw.decode(),'engine');after=before
 seams=[("c,profile,value,payload=checked_inputs(protected=False)","c,profile,value,payload=native_inputs()"),("workspace=base.isolate(spec); evidence=base.OWNED_OUTPUT","workspace,evidence=native_boundary(spec,base)"),("base.reduce_capabilities(fixture_identity_map=spec.get('fixture_identity_map'))","native_capabilities(base)"),("root=evidence.path/'target'","root=evidence.path/'root'"),("SHARED/'input'","BUNDLE"),("SHARED/'code/scripts/ci/full-development-composition/audio_aux.py'","CODE/'scripts/ci/full-development-composition/audio_aux.py'")]
 ledger=[]
 for a,b in seams:
  count=after.count(a);need(count==(4 if a=="SHARED/'input'"else 1),'exact complete native engine seam: '+a);after=after.replace(a,b);ledger.append(dict(before=a,after=b,count=count))
 inverse=after
 for row in reversed(ledger):need(inverse.count(row['after'])==row['count'],'unique complete native engine inverse');inverse=inverse.replace(row['after'],row['before'])
 need(inverse==before,'complete source-owned installer engine inverse');compile(after,'<complete-held607-native-engine>','exec')
 return after,dict(status='COMPLETE_SIGNED607_ENGINE_WITH_EXPLICIT_NATIVE_BOUNDARY',before=pin(before.encode()),after=pin(after.encode()),seams=ledger,whole_inverse=True,commit_prepare_auth_payload_database='UNCHANGED',seconds=INSTALL_SECONDS)

def derive_native_tools(raw):
 before=_body(raw.decode(),'ordinary_preflight');start=before.index("    tools=profile['tools']\n");end=before.index('    return c,profile,value,payload,roots,base,driver,aux\n');block=before[start:end]
 need(block.count("SHARED/'code/")==1,'one physical-tool source path seam');derived=block.replace("SHARED/'code/","CODE/'",1);need(derived.replace("CODE/'","SHARED/'code/",1)==block,'complete physical136-tool preflight inverse')
 return 'def native_tools(profile,roots,base):\n'+derived,dict(before=pin(block.encode()),after=pin(derived.encode()),physical_tool_files=136,all_alias_loader_library_and_preload_checks='HELD')

def _candidate():
 route=load('route',HERE/'route607.py');contract=route.source_contract(FRESH,AUTH,PROVIDER)
 c=load('accepted_common',FRESH/'implementation/common.py')
 with aliases(common=c):adapter=load('accepted_adapter',FRESH/'implementation/adapter.py')
 want={}
 for name in adapter.NAMES:
  raw,ledger=adapter.transform(read(FRESH/'parent604'/name),name);need(read(CANDIDATE/name)==raw,'exact emitted607 installer candidate');want[name]=pin(raw)
 need({p.name for p in CANDIDATE.iterdir()}==set(adapter.NAMES)|{'adapter.json'},'complete finite emitted candidate')
 for p in(FRESH,CANDIDATE,BUNDLE,CODE):
  fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'readonly accepted source/candidate/bundle')
  finally:os.close(fd)
 return contract,want

def install_actor():
 started=time.monotonic();who=actor_guard('install');contract,candidate=_candidate();p=load('installer_profile',CANDIDATE/'profile.py');numeric=load('installer_numeric',CANDIDATE/'numeric_vm.py')
 with aliases(profile=p,numeric_vm=numeric):original=load('accepted_installer',CANDIDATE/'installer.py')
 area=WORK/'installed607';area.mkdir(mode=0o700);inputs=WORK/'native607-inputs';inputs.mkdir(mode=0o700)
 owner=dict(schema_version=1,**who,work_identity=identity(WORK.stat())[:2],installed_identity=identity(area.stat())[:2],inputs_identity=identity(inputs.stat())[:2]);save(WORK/'native607-install-owner.json',owner)
 # This is the actual held profile builder: all archive/code/tool/SONAME checks.
 accepted=p.build(BUNDLE,CODE,inputs);accepted_raw=read(inputs/'installer-profile.json',96*1024**2);write(OUT/'accepted-installer-profile.json',accepted_raw)
 profile=dict(accepted);basis=profile.pop('numeric_vm');profile.update(native_identity_metadata_basis=basis,native_mode='OWNED_OFFLINE_NATIVE_CONTAINER',native_page_size=4096)
 (inputs/'installer-profile.json').unlink();write(inputs/'installer-profile.json',p.encoded(profile));payload=p.decode(read(inputs/'payload.json',96*1024**2));value,unused,expected=p.manifest(BUNDLE,protected=False)
 need(len(expected)==607 and expected['cachy-asahi-apps']=='0.1.0-16','exact signed607 with current Apps16');p.SHARED=inputs;original.SHARED=inputs;original.BUNDLE=BUNDLE;original.CODE=CODE
 sys.path.insert(0,str(CODE/'scripts/update'))
 roots=load('installer_full_root',CODE/'scripts/update/full_root.py');driver=load('installer_database',CODE/'scripts/ci/full-root-upgrade/root_upgrade.py');aux=load('installer_aux',CODE/'scripts/update/aux_checkpoint.py');base=roots.installer
 original.source_modules=lambda unused:(roots,base,driver,aux)
 tools,tools_ledger=derive_native_tools(read(CANDIDATE/'installer.py'));exec(compile(tools,'<held-native607-physical-tools>','exec'),vars(original));original.native_tools(profile,roots,base)
 context=dict(nonce=who['token'],source_commit=who['source'])
 original.native_inputs=lambda:(context,profile,value,payload)
 def boundary(spec,actual):
  need(actual is base and current_identity()==who and identity(WORK.stat())[:2]==owner['work_identity']and identity(area.stat())[:2]==owner['installed_identity'],'native installer workspace and owner drift')
  need('fixture_identity_map'not in spec and 'namespace_identity'not in spec,'no VM namespace admission in native profile')
  evidence=base.Evidence(area);base.TASK_DEADLINE=spec['deadline'];return WORK,evidence
 original.native_boundary=boundary
 def capabilities(actual):
  need(actual is base and base.capability_mask(basis)==ROLE_CAPS['install']and actor_guard('install')==who,'exact source-derived installer capability mask and independent native admission')
 original.native_capabilities=capabilities
 text,derivation=derive_engine(read(CANDIDATE/'installer.py'));exec(compile(text,'<whole-native607-engine>','exec'),vars(original));save(OUT/'native607-engine-derivation.json',dict(derivation,source=contract,candidate=candidate,physical_tools=tools_ledger,native_profile=pin(read(inputs/'installer-profile.json',96*1024**2))))
 spec=dict(deadline=started+INSTALL_SECONDS,nonce=who['token'],profile_sha256=p.sha(inputs/'installer-profile.json'))
 fd=os.memfd_create('native607-installer-spec',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);raw=p.encoded(spec);need(os.write(fd,raw)==len(raw),'complete native sealed spec');os.fchmod(fd,0o400);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
 try:code=original.engine(fd,pin(raw)['sha256'],-1)
 finally:
  try:os.close(fd)
  except OSError:pass
 result=decode(read(area/'result.json'));need(code==0 and result['status']=='PROVISIONAL_FULL_COMPOSITION_INSTALLER'and result['committed']is True and result['package_count']==607,'actual complete native signed607 installer')
 budget=roots.Limits(deadline=started+INSTALL_SECONDS,max_nodes=200000,max_bytes=6*p.GIB,max_file_bytes=p.GIB,max_package_files=500000,max_packages=607)
 observed=roots.observe(area/'root',limits=budget,hardlinks='generic-development-internal');original.compare_payload(observed,payload,derived_output_binding=profile.get('derived_output_binding'));db=driver.database(area/'root',max_packages=607,max_files=500000,max_nodes=1000000,observed=observed['nodes']);need({r['name']:r['version']for r in db}==profile['expected'],'independent final actual installed607 database')
 caps=load('installed_capabilities',SOURCE/'scripts/apps/file_capabilities.py').observe(area/'root',observed['nodes'],budget);raw=encoded(observed);compressed=gzip.compress(raw,mtime=0);need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'complete final installed607 observation bound')
 for destination in(area,OUT):write(destination/'installed-observation.json.gz',compressed);save(destination/'installed-capabilities.json',caps)
 receipt=dict(schema_version=1,status='INSTALLED_FRESH_NATIVE607_PENDING_PHYSICAL_SNAPSHOT',**who,result=result,installed_identity=identity((area/'root').stat())[:2],installed_observation=pin(compressed),installed_raw_observation=pin(raw),installed_capabilities=pin(encoded(caps)),signed_bundle_manifest=pin(read(BUNDLE/'manifest.json')),expected_lock=pin(read(BUNDLE/'expected-installed.lock')),native_page_size=4096,provider=PROVIDER,provider_source=PROVIDER_SOURCE,hardware='NOT_RUN',Root_acceptance=None)
 save(area/'installed-receipt.json',receipt);save(OUT/'native607-install.json',receipt)
 return 0

def _states(root,nodes,budget):
 states={'':identity(root.lstat())}
 for name in nodes:budget.tick();states[name]=identity((root/name).lstat())
 return states

def _stable(root,states,budget):
 children={n:set()for n,row in states.items()if stat.S_ISDIR(row[2])}
 for n in states:
  if n:children[n.rpartition('/')[0]].add(n.rpartition('/')[2])
 for n,want in states.items():
  budget.tick();path=root/n if n else root;need(identity(path.lstat())==want,'complete source namespace/identity drift')
  if stat.S_ISDIR(want[2]):
   fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
   try:need(identity(os.fstat(fd))==want and set(os.listdir(fd))==children[n],'complete source directory namespace drift')
   finally:os.close(fd)

def physical_snapshot(source,data,normal,budget,extractor):
 """Real bounded physical tar/extraction, capabilities and internal links held."""
 source=canonical(source);data=canonical(data);need(source!=data and not source.is_relative_to(data)and not data.is_relative_to(source),'disjoint physical snapshot')
 fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'physical snapshot source genuinely readonly')
 finally:os.close(fd)
 before=normal.measure(source,budget);need(before['complete']is True,'complete physical source map');caps=normal.capability_map(source,before,budget);states=_states(source,before['nodes'],budget);_stable(source,states,budget)
 archive=data/'source607.tar';fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:
  with tarfile.open(fileobj=stream,mode='w|',format=tarfile.PAX_FORMAT)as tar:
   for name,row in sorted(before['nodes'].items(),key=lambda item:(item[0].count('/'),item[0])):
    budget.tick();info=tarfile.TarInfo(name);state=states[name];info.uid=row['uid'];info.gid=row['gid'];info.mode=row['mode'];info.mtime=state[7]//10**9;info.pax_headers={'mtime':str(state[7]//10**9)+'.'+str(state[7]%10**9).zfill(9)}
    if row['type']=='directory':info.type=tarfile.DIRTYPE;tar.addfile(info)
    elif row['type']=='symlink':info.type=tarfile.SYMTYPE;info.linkname=row['target'];tar.addfile(info)
    elif row['type']=='file':
     tag=row.get('hardlink_group',name)
     if tag!=name:info.type=tarfile.LNKTYPE;info.linkname=tag;tar.addfile(info)
     else:
      info.size=row['bytes']
      if name in caps:info.pax_headers['SCHILY.xattr.security.capability']=bytes.fromhex(caps[name]).decode('utf8','surrogateescape')
      filefd=os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
      try:
       need(identity(os.fstat(filefd))==state,'physical source file identity');h=hashlib.sha256()
       with os.fdopen(os.dup(filefd),'rb')as body:
        while block:=body.read(1024**2):budget.tick();h.update(block)
        need(h.hexdigest()==row['sha256'],'physical source file hash');body.seek(0);tar.addfile(info,body)
       need(identity(os.fstat(filefd))==state==identity((source/name).lstat()),'physical source file late drift')
      finally:os.close(filefd)
    else:raise ValueError('ordinary physical source nodes only')
    need(stream.tell()<=MAX_TAR,'full snapshot tar bound')
  stream.flush();os.fsync(stream.fileno())
 _stable(source,states,budget);late=normal.measure(source,budget);need(all(late[k]==before[k]for k in('nodes','hardlink_groups','complete'))and normal.capability_map(source,late,budget,caps)==caps,'complete physical source held')
 archive_pin=hash_large(archive,budget);extractor.DATA=data;target=data/'source607';extraction=extractor.extract(archive,target,archive_pin['sha256']);after=normal.measure(target,budget);restored=normal.caps.restore(target,after['nodes'],extraction['security_capabilities'],budget)
 need(restored==caps==normal.capability_map(target,after,budget,caps)and all(after[k]==before[k]for k in('nodes','hardlink_groups','complete')),'physical extraction full node/capability/hardlink equality')
 _stable(source,states,budget);extraction.update(capability_restoration='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED',security_capabilities_sha256=normal.digest(caps));return dict(source=before,extracted=after,capabilities=caps,archive=archive_pin,extraction=extraction,source_states_sha256=digest(states),source_identity=states[''][:2],target_identity=identity(target.stat())[:2])

def hash_large(path,budget):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=MAX_TAR,'bounded full snapshot ordinary file');h=hashlib.sha256();size=0
  while raw:=os.read(fd,1024**2):budget.tick();h.update(raw);size+=len(raw)
  need(size==s.st_size and identity(s)==identity(os.fstat(fd))==identity(Path(path).lstat()),'stable complete full snapshot');return dict(bytes=size,sha256=h.hexdigest())
 finally:os.close(fd)

def observation(raw):
 import zlib
 decoder=zlib.decompressobj(31);body=decoder.decompress(raw,256*1024**2+1);need(len(body)<=256*1024**2 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'one complete bounded physical observation gzip');return decode(body)

def snapshot_actor():
 who=actor_guard('snapshot');C=load('contract',SOURCE/'scripts/ci/apps7-full574-repair-native/contract.py');normal=C.adapter(SOURCE);T=C.load('snapshot_transaction',SOURCE/'scripts/ci/apps7-full574-repair-native/transaction.py');budget=T.F.Limits(deadline=time.monotonic()+SNAPSHOT_SECONDS,max_packages=607)
 derivative=load('capability_extractor',SOURCE/'scripts/ci/apps-full574-native/export_extract.py');extractor=derivative.isolated(SOURCE,normal.caps,C.read)
 installed_raw=read(WORK/'installed607/installed-receipt.json');installed=decode(installed_raw);installed_map_raw=read(WORK/'installed607/installed-observation.json.gz',64*1024**2);installed_caps_raw=read(WORK/'installed607/installed-capabilities.json');need(all(installed[k]==v for k,v in who.items())and pin(installed_map_raw)==installed['installed_observation']and pin(installed_caps_raw)==installed['installed_capabilities'],'exact final installed607 source proof')
 installed_map=observation(installed_map_raw);installed_caps=decode(installed_caps_raw);need(pin(encoded(installed_map))==installed['installed_raw_observation'],'complete installed607 raw proof')
 value=physical_snapshot(Path('/installed'),DATA,normal,budget,extractor)
 need(all(value['source'][k]==installed_map[k]for k in('nodes','hardlink_groups','complete'))and value['capabilities']==installed_caps and value['source_identity']==installed['installed_identity'],'physical source exactly matches final authenticated607 installed bytes/caps/hardlinks')
 app=C.load('native_snapshot_apps',SOURCE/'packages/tools/cachy-asahi-apps16/apps.py');client,release,unused=app.helpers(SOURCE);inventory=app.inventory_reader().collect(DATA/'source607'/T.DB,client,lambda row:app.package(row,release));K=load('snapshot_backend607',HERE/'backend607.py');K.inventory_check(inventory,source=True);inventory_pin=save(OUT/'source-inventory.json',inventory)
 extraction_pin=save(OUT/'extraction.json',value['extraction']);raw=encoded(value['extracted']);compressed=gzip.compress(raw,mtime=0);need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'whole snapshot observation bounds');observation_pin=write(OUT/'source-observation.json.gz',compressed)
 receipt=dict(schema_version=1,status='PHYSICAL_NATIVE607_ROOT_SNAPSHOT_AND_EXTRACTION',**who,archive=value['archive'],extraction=extraction_pin,observation=observation_pin,raw_observation=pin(raw),root_nodes_sha256=digest(value['extracted']['nodes']),capabilities=value['capabilities'],capabilities_sha256=digest(value['capabilities']),hardlink_groups_sha256=digest(value['extracted']['hardlink_groups']),database_sha256=digest({n:r for n,r in value['extracted']['nodes'].items()if n=='var/lib/pacman'or n.startswith('var/lib/pacman/')}),source_identity=value['source_identity'],target_identity=value['target_identity'],source_states_sha256=value['source_states_sha256'],installed_receipt=pin(installed_raw),inventory=inventory_pin,source_packages_sha256=digest(inventory['packages']),provider=PROVIDER,provider_source=PROVIDER_SOURCE,hardware='NOT_RUN')
 save(OUT/'snapshot.json',receipt);save(DATA/'native607-source-owner.json',dict(schema_version=1,**who,root_identity=value['target_identity'],data_identity=identity(DATA.stat())[:2],snapshot_sha256=digest(receipt)))
 return 0

def tooling_selection(args,prepared):
 """Stage the exact held native tooling contract; no daemon or command here."""
 route=load('tooling_route',HERE/'route607.py');route.source_contract(prepared.fresh_source,args.fresh_authorization,PROVIDER)
 area=Path(args.runtime.output);candidate=area/'tooling-candidate';selection=area/'tooling-selection';candidate.mkdir(mode=0o700);selection.mkdir(mode=0o700)
 for name in('run.py','prepare.py','guest.py','installer.py','profile.py','numeric_vm.py'):
  raw=read(Path(prepared.candidate)/name);need(pin(raw)==prepared.runner_files[name],'held emitted tooling constructor source');write(candidate/name,raw)
 profile=load('tooling_profile',candidate/'profile.py');controller=load('tooling_controller',candidate/'run.py');preparation=load('tooling_preparation',candidate/'prepare.py');common=load('tooling_common',Path(prepared.installer_code)/'scripts/virtual/common.py')
 selected=profile.build(Path(prepared.bundle607),Path(prepared.installer_code),candidate);manifest=decode(read(Path(prepared.bundle607)/'manifest.json'));inputs=controller.input_files(Path(prepared.bundle607),manifest);base=common.inventory(read(Path(prepared.bundle607)/manifest['builder_lock']['path']).decode());lock=decode(read(Path(prepared.installer_code)/'scripts/virtual/tooling.lock.json'));expected=preparation.union_inventory(base,lock['packages'])
 code_files=selected['code_files']
 for name,want in code_files.items():need(pin(read(Path(prepared.installer_code)/name,16*1024**2))==want,'whole held installer runtime code closure')
 runner_files={name:pin(read(candidate/name,96*1024**2))for name in('run.py','prepare.py','guest.py','installer.py','profile.py','numeric_vm.py','installer-profile.json','payload.json')}
 text=read(candidate/'run.py').decode();host=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='host');rows=[n for n in host.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='c'for t in n.targets)]
 need(len(rows)==1 and isinstance(rows[0].value,ast.Call)and isinstance(rows[0].value.func,ast.Name)and rows[0].value.func.id=='dict','one complete held native tooling contract constructor')
 scope=dict(dict=dict,os=os,manifest=manifest,image=prepared.image,token=args.runtime.identity['token'],base=base,expected=expected,args=types.SimpleNamespace(code=Path(prepared.installer_code)),sha=controller.sha,code_files=code_files,runner_files=runner_files,inputs=inputs)
 contract=eval(compile(ast.Expression(rows[0].value),'<complete-held607-tooling-contract>','eval'),scope);contract_raw=encoded(contract);contract_pin=write(selection/'vm-contract.json',contract_raw)
 result=dict(schema_version=1,status='HELD_NATIVE607_TOOLING_SELECTION_READY',candidate=candidate,selection=selection,contract=contract,contract_pin=contract_pin,tooling_cache=Path(prepared.tooling_cache),installer_code=Path(prepared.installer_code),bundle=Path(prepared.bundle607),constructor=pin((ast.get_source_segment(text,rows[0])+'\n').encode()),source_mode='ORIGINAL_NATIVE_TOOLING_ONLY_NO_VM_DISK_OR_GUEST')
 save(area/'tooling-selection.json',{k:str(v)if isinstance(v,Path)else v for k,v in result.items()});return result


class Provided607:
 def __init__(self,args,prepared,installed,snapshot,context):self.args=args;self.prepared=prepared;self.installed=installed;self.snapshot=snapshot;self.context=context;self.context_sha256=digest(context);self.repair_inputs=prepared.repair_inputs;self.source_root=Path(snapshot['data_dir'])/'source607'
 def public_files(self):
  result={}
  for role,record in(('install',self.installed),('snapshot',self.snapshot)):
   for p in sorted(Path(record['public_dir']).iterdir()):read(p,96*1024**2);result[role+'/'+p.name]=p
  return result
 def close(self):return self.args.runtime.cleanup607()

def phase(record,role):
 need(type(record)is dict and record.get('status')=='ACTOR_EXITED_AND_ABSENCE_VERIFIED','original owned actor must be retired before next phase');actor=record.get('actor',{})
 need(role in('install','snapshot','consumer')and actor.get('role')==role and actor.get('status')=='PASS_ABSENCE_VERIFIED'and type(actor.get('exit'))is int and actor['exit']==0 and re.fullmatch('[0-9a-f]{64}',actor.get('id')or''),'original exact actor role/identity/successful exit and absence receipt');return record

def prepare(args,prepared):
 """Connected outer provider: actual retired install -> actual physical snapshot."""
 selection=tooling_selection(args,prepared);args.runtime.tooling607(prepared,selection)
 installed=phase(args.runtime.install607(prepared),'install');install=decode(read(Path(installed['public_dir'])/'native607-install.json'));who=args.runtime.identity;need(all(install[k]==v for k,v in who.items())and install['status']=='INSTALLED_FRESH_NATIVE607_PENDING_PHYSICAL_SNAPSHOT','actual complete607 install joins owner')
 snapshot=phase(args.runtime.snapshot607(installed),'snapshot');public=Path(snapshot['public_dir']);raw=read(public/'snapshot.json');s=decode(raw);extraction_raw=read(public/'extraction.json');observation_raw=read(public/'source-observation.json.gz',64*1024**2);inventory_raw=read(public/'source-inventory.json')
 need(s['inventory']==pin(inventory_raw),'physical actual normal607 inventory')
 need(s['status']=='PHYSICAL_NATIVE607_ROOT_SNAPSHOT_AND_EXTRACTION'and all(s[k]==v for k,v in who.items())and s['source_identity']==install['installed_identity']and s['installed_receipt']==pin(read(Path(installed['public_dir'])/'native607-install.json'))and s['extraction']==pin(extraction_raw)and s['observation']==pin(observation_raw),'physical installed root/snapshot/capability receipt joins')
 manifest=read(Path(prepared.bundle607)/'manifest.json');need(pin(manifest)==install['signed_bundle_manifest'],'fresh signed607 manifest held across install and snapshot');rows=decode(manifest)['packages'];candidates={r['name']:dict(version=r['version'],archive_sha256=r['sha256'])for r in rows if r['name']in('cachy-asahi-apps','cachy-asahi-repository-runtime','cachy-asahi-cache','cachy-asahi-orphans')};need(len(candidates)==4 and candidates['cachy-asahi-apps']['archive_sha256']=='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af','all four current exact native source candidates')
 context=dict(schema_version=1,status='FRESH607_NATIVE_CONSUMER_INPUT_CONTEXT',**who,provider=PROVIDER,provider_source=PROVIDER_SOURCE,installed=pin(read(Path(installed['public_dir'])/'native607-install.json')),snapshot=pin(raw),extraction=pin(extraction_raw),observation=pin(observation_raw),source_inventory=pin(inventory_raw),signed_bundle_manifest=pin(manifest),candidates=candidates)
 receipts=Path(args.runtime.receipts)
 for name,body in(('native607-install.json',read(Path(installed['public_dir'])/'native607-install.json')),('snapshot.json',raw),('extraction.json',extraction_raw),('source-observation.json.gz',observation_raw),('source-inventory.json',inventory_raw),('bundle-manifest.json',manifest),('native607-context.json',encoded(context))):write(receipts/name,body)
 return Provided607(args,prepared,installed,snapshot,context)

def empty_owned_roots(roots,expected,T,budget):
 """Unchanged bounded fd-relative lifetime helper; never a stale-lock API."""
 need(set(roots)==set(expected)=={'work','data','consumer-work','receipts','authority'},'closed whole-owned cleanup root set')
 need(all(type(v)is list and len(v)==2 and all(type(x)is int and x>=0 for x in v)for v in expected.values())and len({tuple(v)for v in expected.values()})==5,'distinct exact whole-root identities')
 spent=[0];done=[]
 for role in('consumer-work','data','work','receipts','authority'):
  path=canonical(roots[role]);need(path!=Path('/'),'host root disposal refused');fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   need(identity(os.fstat(fd))[:2]==expected[role]==identity(path.lstat())[:2],'exact owned cleanup FD/path identity');mount=T.F._mount_id(fd,budget)
   T.LIFETIME._empty(fd,mount,budget,spent,depth=-1)
   need(identity(os.fstat(fd))[:2]==expected[role]==identity(path.lstat())[:2]and T.F._mount_id(fd,budget)==mount and not os.listdir(fd),'original whole-tree cleanup and root identity held');os.fsync(fd);done.append(role)
  finally:os.close(fd)
 return dict(status='ORIGINAL_BOUNDED_WHOLE_OWNED_TREES_EMPTY',order=done,nodes=spent[0],identities=expected)

def cleanup_actor():
 # Only the independent outer inventory can authorize whole-root disposal.
 who=actor_guard('cleanup');absence_raw=read(Path('/authority/native607-absence.json'));need(pin(absence_raw)['sha256']==os.environ.get('NATIVE607_ABSENCE_SHA256'),'independent raw actor absence pin');absence=decode(absence_raw)
 need(absence.get('status')=='ALL_OWNED_NATIVE607_ACTORS_ABSENT'and all(absence.get(k)==v for k,v in who.items())and absence.get('all_absent')is True,'original owner inventory must establish complete actor absence')
 roots={name:Path('/'+name)for name in('work','data','consumer-work','receipts','authority')}
 need(all(path.is_mount()for path in roots.values()),'exact independently owned cleanup bind roots')
 C=load('cleanup_contract',SOURCE/'scripts/ci/apps7-full574-repair-native/contract.py');C.source(SOURCE);T=C.load('cleanup_transaction',SOURCE/'scripts/ci/apps7-full574-repair-native/transaction.py');budget=T.F.Limits(deadline=time.monotonic()+600)
 write(OUT/'native607-absence.json',absence_raw)
 receipt=empty_owned_roots(roots,absence['roots'],T,budget)
 for role,path in roots.items():
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   need(identity(os.fstat(fd))[:2]==absence['roots'][role]and not os.listdir(fd),'exact empty roots before ordinary owner handback');os.fchown(fd,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']));os.fchmod(fd,0o700);os.fsync(fd)
  finally:os.close(fd)
 save(OUT/'cleanup.json',dict(schema_version=1,status='PROVIDER607_WHOLE_OWNED_SOURCE_AND_INSTALL_ROOTS_DISPOSED',**who,all_actors_absent=True,actor_absence=pin(absence_raw),cleanup=receipt,producer_backing='ORIGINAL_PRODUCER_OWNER_NEXT',hardware='NOT_RUN'))
 return 0

def main(argv=None):
 argv=sys.argv[1:]if argv is None else argv;need(argv in(['--install'],['--snapshot'],['--cleanup']),'one fixed source-owned provider actor phase');actor_guard(argv[0][2:])
 try:return{'--install':install_actor,'--snapshot':snapshot_actor,'--cleanup':cleanup_actor}[argv[0]]()
 finally:
  for path in OUT.iterdir():
   need(path.is_file()and not path.is_symlink(),'ordinary finite provider evidence');os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
if __name__=='__main__':raise SystemExit(main())
