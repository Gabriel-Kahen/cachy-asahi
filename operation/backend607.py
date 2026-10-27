# SPDX-License-Identifier: MIT
"""Explicit live607 closure for held ordinary Apps16 reinstall code; no actors."""
import ast,dataclasses,hashlib,json,os,re,stat,sys,types
from pathlib import Path
APPS='cachy-asahi-apps';VERSION='0.1.0-16';PURPOSE='APPS_CURRENT607_READONLY_CLOSURE'
LOCK_SHA256='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'
OTHER606_SHA256='c587afe1bedf7d1d64dc15483400714ea725fc52ed3c7e64c69ecf86e7b40589'
ARCHIVE='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'
VERSIONS={APPS:VERSION,'cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2'}
BUDGET={'backend_seconds':600,'caller_seconds':610}
DOMAIN={'field':'max_packages','held':587,'current':607,'expected607_sha256':LOCK_SHA256,'other606_sha256':OTHER606_SHA256,'all_time_bytes_nodes_depth_output_hardlink_bounds':'HELD'}
PROVIDERS={'b9976eea34eaed4b6e56af3be21d4d652fa971d6':4096,'1e777ec5a0612af37305f93f87f2c7b2f7a36de8':16384}
PINS={'Adapter':{'bytes':10311,'sha256':'8fe8f79c47f3ec1f062d2008903ab64c9c68506fc018b655cee096eef2155133'},'reinstall_nodes':{'bytes':1543,'sha256':'6833588f40be82111c798d8e882fde4363d0eeed65badcc3dda9385739bf4121'}}
ADMISSION_KEYS={'provider','source_packages_sha256','snapshot_sha256','extraction_receipt_sha256','schema_version','status','provider_source','source','run_id','attempt','token','architecture','page_size','native_mode','expected607_sha256','source_identity','root_nodes_sha256','capabilities_sha256','hardlink_groups_sha256','inventory_sha256','other606_sha256','signed_bundle_manifest_sha256','readonly_source_fd_identity','commit_started','packages_committed','rollback','hardware'}
COMMON={'inventory_domain','schema_version','purpose','snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256','source_capabilities_sha256','execution_budget','admission_sha256','source_database_sha256','source_hardlinks_sha256','source_inventory_sha256','other606_sha256','provider_source','source_revision','run_id','attempt','owner_token','architecture','page_size','native_mode','signed_bundle_manifest_sha256'}
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def digest(v):return pin(encoded(v))['sha256']
def sha(v):return type(v)is str and re.fullmatch('[0-9a-f]{64}',v)is not None
def identity(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def db_nodes(nodes):return{n:r for n,r in nodes.items()if n=='var/lib/pacman'or n.startswith('var/lib/pacman/')}
def lock_bytes(rows,exclude=()):
 need(type(rows)is list and len(rows)==607,'complete607 inventory, never count-only admission');versions={}
 for row in rows:
  need(type(row)is dict and type(row.get('name'))is str and type(row.get('version'))is str and re.fullmatch('[A-Za-z0-9@_+][A-Za-z0-9@._+-]*',row['name'])and row['version']and not any(c.isspace()for c in row['version'])and row['name']not in versions,'exact unique607 package identities');versions[row['name']]=row['version']
 need(all(versions.get(n)==v for n,v in VERSIONS.items()),'exact installed current Apps16 four candidates')
 return ''.join(n+' '+versions[n]+'\n'for n in sorted(versions)if n not in exclude).encode()
def inventory_check(inventory,*,source=False):
 rows=inventory['packages'];need(pin(lock_bytes(rows))['sha256']==LOCK_SHA256 and pin(lock_bytes(rows,{APPS}))['sha256']==OTHER606_SHA256,'complete exact607 and other606 lock bytes')
def admission_check(v):
 need(type(v)is dict and set(v)==ADMISSION_KEYS and type(v['schema_version'])is int and v['schema_version']==1 and v['status']=='VALIDATED_FRESH_OWNED_NATIVE607_ROOT','closed fresh live607 provider admission')
 need(v['provider']in('fresh4k','storage16k')and v['provider_source']==dict(fresh4k='b9976eea34eaed4b6e56af3be21d4d652fa971d6',storage16k='1e777ec5a0612af37305f93f87f2c7b2f7a36de8')[v['provider']]and type(v['page_size'])is int and v['page_size']==PROVIDERS[v['provider_source']]and v['architecture']=='aarch64'and v['native_mode']=='OWNED_OFFLINE_NATIVE_CONTAINER','exact fresh provider native/page context; no VM handoff')
 need(type(v['source'])is str and re.fullmatch('[0-9a-f]{40}',v['source'])and type(v['run_id'])is int and v['run_id']>0 and type(v['attempt'])is int and v['attempt']>0 and type(v['token'])is str and re.fullmatch('[0-9a-f]{32}',v['token']),'new source/run/attempt/owner identity')
 need((v['source'],v['run_id'])not in{('b9976eea34eaed4b6e56af3be21d4d652fa971d6',40223603945),('1e777ec5a0612af37305f93f87f2c7b2f7a36de8',40390192017)},'retired VM cannot issue native607 lease')
 for name in('root_nodes_sha256','capabilities_sha256','hardlink_groups_sha256','inventory_sha256','source_packages_sha256','signed_bundle_manifest_sha256','snapshot_sha256','extraction_receipt_sha256'):need(sha(v[name]),'full live607 admission pin: '+name)
 need(v['expected607_sha256']==LOCK_SHA256 and v['other606_sha256']==OTHER606_SHA256,'fixed exact607/other606 lock admission')
 need(type(v['source_identity'])is list and len(v['source_identity'])==2 and all(type(x)is int and x>=0 for x in v['source_identity'])and type(v['readonly_source_fd_identity'])is list and len(v['readonly_source_fd_identity'])==9 and all(type(x)is int and x>=0 for x in v['readonly_source_fd_identity'])and v['readonly_source_fd_identity'][:2]==v['source_identity']and stat.S_ISDIR(v['readonly_source_fd_identity'][2])and v['readonly_source_fd_identity'][3:5]==[0,0],'complete live readonly source FD identity')
 need(v['commit_started']==v['packages_committed']=='UNKNOWN'and v['rollback']=='NOT_CLAIMED'and v['hardware']=='NOT_RUN','provider admission cannot claim interruption, repair or hardware')
 return v
def baseline_nodes(source,current,payloads):
 """Every original607 byte held, except authenticated eight ordinary Apps leaves."""
 selected=payloads[APPS];leaves={n for n,r in selected.items()if r['type']=='file'};need(len(leaves)==8,'finite Apps16 selected ordinary leaves')
 for name,row in source.items():
  if name in leaves:need(name not in current or current[name]==selected[name],'current selected effective payload differs')
  else:need(current.get(name)==row,'original607 DB/config/user/other606 node changed')
 for name,row in current.items():
  if name not in source:need(name=='var/lib/pacman/db.lck'and row.get('type')=='file'and row.get('bytes')==0,'unselected new607 node')
def _json(path,want,read):
 raw=read(Path(path).absolute(),1024**2);need(sha(want)and pin(raw)['sha256']==want,'explicit current607 policy/lease pin')
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate607 policy key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite607 policy'))
def policy_pair(args,backend):
 names=('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256');need(all(getattr(args,n,None)for n in names),'explicit607 policy/lease; no574 fallback')
 p=_json(args.full574_policy,args.full574_policy_sha256,backend.B.client.read_path);l=_json(args.full574_lease,args.full574_lease_sha256,backend.B.client.read_path)
 need(type(p)is type(l)is dict and set(p)==COMMON|{'baseline_lock_sha256','candidates','source_capabilities','admission'}and set(l)==COMMON|{'token','source','source_identity','readonly_source_fd_identity'},'closed607 policy and lease fields')
 need(all(p[k]==l[k]for k in COMMON)and type(p['schema_version'])is int and p['schema_version']==1 and p['purpose']==PURPOSE and p['inventory_domain']==DOMAIN and p['execution_budget']==BUDGET and all(type(n)is int for n in p['execution_budget'].values()),'current607 purpose/shared identity/exact held budgets')
 for k in COMMON-{'inventory_domain','schema_version','purpose','execution_budget','provider_source','source_revision','run_id','attempt','owner_token','architecture','page_size','native_mode'}:need(sha(p[k]),'typed607 policy pin: '+k)
 a=admission_check(p['admission']);need(digest(a)==p['admission_sha256'],'whole live607 admission pin')
 joins={'snapshot_sha256':'snapshot_sha256','extraction_receipt_sha256':'extraction_receipt_sha256','source_packages_sha256':'source_packages_sha256','source_tree_sha256':'root_nodes_sha256','source_capabilities_sha256':'capabilities_sha256','source_hardlinks_sha256':'hardlink_groups_sha256','source_inventory_sha256':'inventory_sha256','other606_sha256':'other606_sha256','signed_bundle_manifest_sha256':'signed_bundle_manifest_sha256','provider_source':'provider_source','source_revision':'source','run_id':'run_id','attempt':'attempt','owner_token':'token','architecture':'architecture','page_size':'page_size','native_mode':'native_mode'}
 need(all(p[k]==a[v]for k,v in joins.items())and p['baseline_lock_sha256']==LOCK_SHA256 and l['token']==a['token']and l['source_identity']==a['source_identity']and l['readonly_source_fd_identity']==a['readonly_source_fd_identity'],'every607 policy/provider/lease operand joined')
 return p,l
def native_context(policy,backend):
 backend.environment_guard()
 need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.sysconf('SC_PAGE_SIZE')==policy['page_size'],'fresh owned native607 container/page context; no VM equivalence waiver')

def configure(normal):
 """Compile exact held Adapter body into a private607 namespace; never collected code."""
 need(normal.VERSIONS==VERSIONS,'held normal Apps16 closure required')
 path=normal.ROOT/'scripts/apps/full574_closure.py';raw=normal.source_bytes(path).decode();tree=ast.parse(raw);parts={}
 for name,want in PINS.items():
  matches=[n for n in tree.body if getattr(n,'name',None)==name];need(len(matches)==1,'one held normal closure object');body=ast.get_source_segment(raw,matches[0])+'\n';need(pin(body.encode())==want,'whole held normal closure object: '+name);parts[name]=body
 old="name not in source and wanted['type']=='file'";new="name in source and source[name]==wanted and wanted['type']=='file'";body=parts['reinstall_nodes'];need(body.count(old)==1,'one complete607 repair source predicate seam');derived=body.replace(old,new,1);need(derived.replace(new,old,1)==body,'whole held repair predicate inverse')
 name='_apps607_closure_'+digest(dict(root=str(normal.ROOT)))[:16];module=types.ModuleType(name);namespace=module.__dict__;namespace.update(vars(normal));namespace['__name__']=name;namespace.update(PURPOSE=PURPOSE,LOCK_SHA256=LOCK_SHA256,inventory_check=inventory_check,baseline_nodes=baseline_nodes,policy_pair=policy_pair)
 sys.modules[name]=module;exec(compile(derived+'\n'+parts['Adapter'],'<held-normal-closure-with-explicit607-policy>','exec'),namespace)
 original_init=module.Adapter.__init__;original_source=module.Adapter.source_check;original_authorize=module.Adapter.authorize_reinstall
 def initialize(self,args,backend,budget):
  policy,unused=policy_pair(args,backend);native_context(policy,backend)
  original_init(self,args,backend,budget);self.binding.update(purpose=PURPOSE,expected607_sha256=LOCK_SHA256,other606_sha256=OTHER606_SHA256,admission_sha256=self.policy['admission_sha256'])
 def source_check(self):
  value,state=original_source(self);need(value.get('complete')is True,'complete607 source observation');fd=normal.roots._open_root(self.source)
  try:need(identity(os.fstat(fd))==self.lease['readonly_source_fd_identity']and os.fstatvfs(fd).f_flag&os.ST_RDONLY,'complete leased607 readonly FD identity')
  finally:os.close(fd)
  need(digest(value.get('hardlink_groups',{}))==self.policy['source_hardlinks_sha256']and digest(db_nodes(value['nodes']))==self.policy['source_database_sha256'],'exact source607 hardlink topology and raw DB map');return value,state
 def authorize(self,plan,inventory,context,plan_sha256):
  need(plan['operation']=='reinstall'and plan['requested_packages']==[APPS]and len(plan['reinstalls'])==1,'only explicit Apps16 same-version reinstall607')
  return original_authorize(self,plan,inventory,context,plan_sha256)
 module.Adapter.__init__=initialize;module.Adapter.source_check=source_check;module.Adapter.authorize_reinstall=authorize
 module.adapter_derivation=dict(status='EXACT_HELD_ADAPTER_PRIVATE607_GLOBALS_AND_FINITE_METHOD_GATES',held=PINS,repair_predicate_before=old,repair_predicate_after=new,held_commit_apply='UNCHANGED',root='SOURCE_OWNED_FRESH_NATIVE607_ONLY',inventory_domain=dict(DOMAIN))
 def connect(args,backend,budget):return module.Adapter(args,backend,budget)
 module.connect=connect;return module

def bind(backend,normal):
 """Only closure/budget and finite587-to607 inventory ceiling hooks change; apply is held."""
 module=configure(normal);unscoped_seconds=backend.execution_seconds;ordinary_limits=backend.limits
 def closure_for(args,budget):
  need(getattr(args,'action',None)!='apply'or getattr(args,'operation',None)=='reinstall','607 backend forbids install/remove')
  return module.connect(args,backend,budget)
 def execution_seconds(args=None):return unscoped_seconds(None)if args is None else policy_pair(args,backend)[0]['execution_budget']['backend_seconds']
 def limits(args=None):
  before=ordinary_limits(args);need(before.max_packages==587,'exact held normal587 inventory ceiling');after=dataclasses.replace(before,max_packages=607);need(dataclasses.asdict(after)==dict(dataclasses.asdict(before),max_packages=607),'all original timing/node/byte/hardlink budgets held');return after
 backend.closure_for=closure_for;backend.execution_seconds=execution_seconds;backend.limits=limits
 return module

def entry(kind,backend,normal,inspection=None):
 """Root child-entry seam; call only after independent operation/source verification."""
 need(kind in('transaction','inspection')and (kind=='transaction'or inspection is not None),'finite normal607 child role')
 backend.environment_guard();bind(backend,normal)
 if kind=='transaction':return backend.main()
 inspection.backend=lambda:backend
 return inspection.main()

def write_pair(output,source,token,admission,normal,backend,budget,app,c,r,candidates,snapshot_sha256,extraction_receipt_sha256):
 """Source-owned runtime writer; independently reobserve live readonly root, no actor launch."""
 a=admission_check(admission);source=Path(source);output=Path(output)
 need(source.is_absolute()and source!=Path('/')and source.resolve(strict=True)==source and not any(p.is_symlink()for p in(source,*source.parents)),'canonical fresh607 source')
 need(token==a['token']==os.environ.get('CACHY_ASAHI_APPS_TRANSACTION')and a['source']==os.environ.get('SOURCE_SHA')and str(a['run_id'])==os.environ.get('GITHUB_RUN_ID')and str(a['attempt'])==os.environ.get('GITHUB_RUN_ATTEMPT'),'independent actual actor source/run/attempt/token')
 native_context(a,backend)
 need(output.is_absolute()and output.resolve(strict=True)==output and not any(p.is_symlink()for p in(output,*output.parents))and stat.S_IMODE(output.stat().st_mode)==0o700 and output.stat().st_uid==0 and source!=output and source not in output.parents and output not in source.parents,'disjoint private607 policy destination')
 fd=normal.roots._open_root(source)
 try:need(identity(os.fstat(fd))==a['readonly_source_fd_identity']and os.fstatvfs(fd).f_flag&os.ST_RDONLY,'independent live readonly root FD')
 finally:os.close(fd)
 value,state=normal._measure(source,budget);need(value.get('complete')is True,'complete live607 source observation');caps=normal.capability_map(source,value,budget);inventory=app.inventory_reader().collect(source/backend.DB,c,lambda row:app.package(row,r));inventory_check(inventory,source=True)
 need(digest(value['nodes'])==a['root_nodes_sha256']and digest(caps)==a['capabilities_sha256']and digest(value.get('hardlink_groups',{}))==a['hardlink_groups_sha256']and digest(inventory)==a['inventory_sha256']and digest(inventory['packages'])==a['source_packages_sha256'],'independent complete live607 map/inventory/capability/hardlink joins')
 payloads=normal.current_payloads();need(all(value['nodes'].get(n)==row for payload in payloads.values()for n,row in payload.items()),'fresh source exact current signed candidates payload')
 need(type(candidates)is dict and set(candidates)==set(VERSIONS),'complete four source-owned signed candidate rows')
 for name,row in candidates.items():need(set(row)=={'version','archive_sha256','payload_sha256'}and row['version']==VERSIONS[name]and sha(row['archive_sha256'])and row['payload_sha256']==digest(payloads[name]),'candidate signed archive and exact source payload joins')
 need(candidates[APPS]['archive_sha256']==ARCHIVE and snapshot_sha256==a['snapshot_sha256']and extraction_receipt_sha256==a['extraction_receipt_sha256'],'exact Apps16 archive and fresh physical snapshot/extraction pins')
 shared=dict(inventory_domain=dict(DOMAIN),schema_version=1,purpose=PURPOSE,snapshot_sha256=snapshot_sha256,extraction_receipt_sha256=extraction_receipt_sha256,source_tree_sha256=digest(value['nodes']),source_packages_sha256=digest(inventory['packages']),source_closure_sha256=normal.digest(normal.canonical_state(state)),source_capabilities_sha256=digest(caps),execution_budget=dict(BUDGET),admission_sha256=digest(a),source_database_sha256=digest(db_nodes(value['nodes'])),source_hardlinks_sha256=digest(value.get('hardlink_groups',{})),source_inventory_sha256=digest(inventory),other606_sha256=OTHER606_SHA256,provider_source=a['provider_source'],source_revision=a['source'],run_id=a['run_id'],attempt=a['attempt'],owner_token=token,architecture=a['architecture'],page_size=a['page_size'],native_mode=a['native_mode'],signed_bundle_manifest_sha256=a['signed_bundle_manifest_sha256'])
 policy=dict(shared,baseline_lock_sha256=LOCK_SHA256,candidates=candidates,source_capabilities=caps,admission=a);lease=dict(shared,token=token,source=str(source),source_identity=a['source_identity'],readonly_source_fd_identity=a['readonly_source_fd_identity'])
 late,late_state=normal._measure(source,budget)
 need(all(late.get(k)==value.get(k)for k in('nodes','hardlink_groups','complete','unsupported_counts'))and normal.canonical_state(late_state)==normal.canonical_state(state)and backend.inode(source)==a['source_identity'],'complete live607 source stable throughout policy creation')
 need(normal.capability_map(source,late,budget)==caps and app.inventory_reader().collect(source/backend.DB,c,lambda row:app.package(row,r))==inventory,'late full607 inventory/capability stability')
 fd=normal.roots._open_root(source)
 try:need(identity(os.fstat(fd))==a['readonly_source_fd_identity']and os.fstatvfs(fd).f_flag&os.ST_RDONLY,'late readonly607 FD identity')
 finally:os.close(fd)
 refs={}
 for role,obj in(('policy',policy),('lease',lease)):
  path=output/('current607-'+role+'.json');raw=encoded(obj);need(len(raw)<=1024**2,'bounded607 policy');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  refs[role]=dict(path=str(path),**pin(raw))
 fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
 return dict(status='SOURCE_OWNED_FRESH607_POLICY_LEASE_WRITTEN',purpose=PURPOSE,files=refs,admission_sha256=digest(a),root_preserved=True,actual_repair='NOT_RUN',hardware='NOT_RUN')
