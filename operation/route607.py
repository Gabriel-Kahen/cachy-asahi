# SPDX-License-Identifier: MIT
"""Exact accepted607 source/bundle route and independently bound native operands.

The accepted VM roots were retired. Bundle preparation is a real callable held
materializer, including its fresh TEST signing and public verification gates.
Native root construction, FD observation and policy issuance belong to the owned
native provider; a retained VM decision cannot stand in for those operations.
"""
import ast,hashlib,json,os,re,shutil,stat,subprocess,types
from pathlib import Path

APPS='cachy-asahi-apps'
EXPECTED607=dict(bytes=12076,sha256='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5')
PROVIDERS={
 'fresh4k':dict(source='b9976eea34eaed4b6e56af3be21d4d652fa971d6',ref='codex/latest607-fresh-tooling-inputs-v1',run_id=40223603945,files=1197,page_size=4096,authorization=dict(bytes=221235,sha256='26902de45f63d4873a3be035adad610f9b2ad76cd2c798676424a2e3edf39a85'),decision=dict(bytes=4104,sha256='069b211075e40455b2ba7e65eb870acc73e0645b10d92079ea13f380e3bd1734'),decision_path='decision.json',record_source='5a0789405ded23f759f4a3aa545cf737c4ec3bde',record_ref='codex/latest607-fresh-accepted-v1',status='ROOT_ACCEPTED_SIGNED_LATEST607_FRESH_INSTALLER'),
 'storage16k':dict(source='1e777ec5a0612af37305f93f87f2c7b2f7a36de8',ref='codex/fresh607-storage-admission-v1',run_id=40390192017,files=1206,page_size=16384,authorization=dict(bytes=222551,sha256='b27ef97a2c6a32914990fa9208b96e8d2f710cc79f6252f4ccd3236510b91d94'),decision=dict(bytes=4199,sha256='3be4082e73dc56316f734d666596f992e80f770969c4978f54ec9147e1368dc8'),decision_path='decision/Root-acceptance-20261026.json',record_source='b58c925e49599493ffeb269ca10571dfc1c5ebd6',record_ref='codex/fresh607-storage-generic16k-accepted-v1',status='ROOT_ACCEPTED_SIGNED_LATEST607_STORAGE_ADMISSION_GENERIC16K')}
SHA=re.compile('[0-9a-f]{64}')

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate607 key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite607 JSON'))
def identity(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def canonical(value):
 raw=os.fspath(value);need(os.path.isabs(raw)and raw==os.path.normpath(raw)and not raw.startswith('//'),'absolute normalized607 operand');p=Path(raw);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary607 ancestry');return p

def read(path,cap=16*1024**2):
 p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded singlelink607 operand');out=bytearray()
  while raw:=os.read(fd,65536):out.extend(raw);need(len(out)<=before.st_size,'607 operand growth')
  need(len(out)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(p.lstat()),'complete stable607 FD/path');return bytes(out)
 finally:os.close(fd)

def hash_archive(path):return pin(read(path,256*1024**2))['sha256']
def provider(name):need(name in PROVIDERS,'explicit accepted607 provider');return PROVIDERS[name]
def lock_map(raw):
 need(type(raw)is bytes and pin(raw)==EXPECTED607,'exact accepted607 installed lock');out={}
 for line in raw.decode('ascii').splitlines():
  parts=line.split(' ');need(len(parts)==2 and all(parts)and parts[0]not in out,'unique607 name/version');out[parts[0]]=parts[1]
 need(len(out)==607 and out[APPS]=='0.1.0-16'and out['cachy-asahi-repository-runtime']=='0.1.0-1','actual607/Apps16/Runtime1 target');return out

def source_contract(root,authorization,name):
 p=provider(name);root=canonical(root);raw=read(authorization);need(pin(raw)==p['authorization'],'exact accepted607 whole source authorization');want=decode(raw);need(type(want)is dict and len(want)==p['files'],'entire607 source member map')
 actual={};dirs=set();total=0
 for path in sorted(root.rglob('*')):
  s=path.lstat();relative=path.relative_to(root).as_posix();need(not path.is_symlink(),'607 source alias')
  if stat.S_ISDIR(s.st_mode):dirs.add(relative)
  else:
   body=read(path);total+=len(body);need(total<=256*1024**2,'607 source aggregate cap');actual[relative]=pin(body)
 need(actual==want and dirs=={q.as_posix()for n in want for q in Path(n).parents if str(q)!='.'},'complete exact607 source closure')
 expected=lock_map(read(root/'implementation/expected607.lock'))
 return dict(schema_version=1,status='EXACT_ACCEPTED607_SOURCE_CONTRACT',provider=name,source=p['source'],source_files=p['files'],source_authorization=p['authorization'],expected607=EXPECTED607,expected_packages=expected,other606_sha256=pin(''.join(n+' '+v+'\n'for n,v in sorted(expected.items())if n!=APPS).encode())['sha256'],materializer=actual['implementation/materialize.py'],runtime_installer=actual['parent604/installer.py'],source_manifest=actual['source-manifest.json'],native='NOT_RUN',Root_acceptance=None)

def accepted_decision(record_root,name):
 p=provider(name);raw=read(canonical(record_root)/p['decision_path']);need(pin(raw)==p['decision'],'exact immutable accepted607 decision');v=decode(raw)
 need(v['status']==p['status']and v['source_sha']==p['source']and v['run_id']==p['run_id']and v['package_count']==607 and v['qemu_natural_exit']is True,'accepted607 VM identity/count/natural retirement')
 need(all(v['ordinary_and_root_flags'].values())and len(v['ordinary_and_root_flags'])==15 and v['root_observation']['complete']is True and v['root_observation']['observed_nodes']==124513 and v['root_observation']['missing_database_nodes']==0,'complete finite607 VM record')
 need(v['hardware']=='NOT_RUN'and v['release']=='NOT_ADMITTED'and v['native_container_P0']=='UNCHANGED_FAILED','607 VM scope remains finite')
 return dict(provider=name,source=p['source'],run_id=p['run_id'],record_source=p['record_source'],record_ref=p['record_ref'],decision=p['decision'],status=v['status'],page_size=p['page_size'],private_root_maps='SOURCE_CHECKED_NOT_EXPORTED',native_root_snapshot=None,native_lease=None,retired_vm=True,native_acceptance='NOT_ISSUED',hardware='NOT_RUN')

def _compile(raw,names,scope):
 tree=ast.parse(raw);parts=[]
 for name in names:
  nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name==name];need(len(nodes)==1,'one trusted607 source body: '+name);parts.append(ast.get_source_segment(raw,nodes[0]))
 exec(compile('\n\n'.join(parts),'trusted-complete607-source-bodies','exec'),scope);return types.SimpleNamespace(**{n:scope[n]for n in names})

def runtime_modules(root,authorization,name):
 """Compile exact source-owned bodies only, not provider supplied callbacks."""
 contract=source_contract(root,authorization,name);root=canonical(root);authorized=decode(read(authorization))
 need(pin(read(authorization))==provider(name)['authorization'],'runtime607 authorization recheck')
 def trusted(relative):
  raw=read(root/relative);need(pin(raw)==authorized[relative],'runtime607 source body pin: '+relative);return raw
 common=types.ModuleType('_exact607_common');common.__file__=str(root/'implementation/common.py');exec(compile(trusted('implementation/common.py'),common.__file__,'exec'),common.__dict__)
 original_read=common.read
 def source_bound_read(path,maximum=16*1024**2):
  raw=original_read(path,maximum);p=canonical(path)
  if p.is_relative_to(root):need(pin(raw)==authorized.get(p.relative_to(root).as_posix()),'unchanged exact runtime607 source operand')
  return raw
 common.read=source_bound_read
 scope=dict(C=common,Path=Path,json=json,os=os,re=re);materializer=_compile(trusted('implementation/materialize.py').decode(),('selection','inspect','prepare'),scope)
 # Preserve whole original sign/copy/verifier/parser/payload bodies. Facade only
 # supplies the original simple utility dependencies, with stronger bounded reads.
 facade=types.SimpleNamespace(need=need,safe=canonical,sha=hash_archive)
 helper=_compile(trusted('installer604/scripts/ci/expanded600-installer-vm/materializer.py').decode(),('copy_archive','sign'),dict(C=facade,Path=Path,re=re,shutil=shutil,subprocess=subprocess))
 verifier=_compile(trusted('installer604/scripts/ci/full-composition-installer-vm/producer.py').decode(),('valid_signer','PublicVerifier'),dict(need=need,re=re,subprocess=subprocess,shutil=shutil,Path=Path))
 checks=types.ModuleType('_exact607_package_checks');checks.__file__=str(root/'installer604/scripts/checks/package_checks.py');exec(compile(trusted('installer604/scripts/checks/package_checks.py'),checks.__file__,'exec'),checks.__dict__)
 payload=_compile(trusted('installer604/scripts/ci/full-development-composition/run.py').decode(),('payload',),{})
 accepted=_compile(trusted('implementation/accepted.py').decode(),('record','public'),dict(C=common,Path=Path,json=json))
 return types.SimpleNamespace(contract=contract,common=common,materializer=materializer,helper=helper,verifier=verifier,checks=checks,payload=payload,accepted=accepted)

def materialize607(root,authorization,name,ready604,public_six,owned_producer,target,*,six_record):
 """Real held607 preparation; caller must already own its future actor boundary.

 Performs original all604 archive/signature/key pin checks, exact incoming8
 metadata/payload checks, fresh8 TEST signatures and all607 public verification.
 It prepares a signed bundle; it neither installs a root nor issues a native lease.
 """
 runtime=runtime_modules(root,authorization,name)
 # A failed original604 metadata selection may refuse early; all original22/991
 # source-owned acceptance checks still complete before any output/signing.
 runtime.materializer.selection(decode(read(canonical(ready604)/'manifest.json')))
 runtime.accepted.public(six_record,public_six)
 result=runtime.materializer.prepare(ready604,public_six,owned_producer,target,helper=runtime.helper,verifier_api=runtime.verifier,checks=runtime.checks,payload_api=runtime.payload)
 need(result['status']=='READY_SIGNED_EXPANDED607'and len(result['packages'])==607,'real607 materializer result');lock=read(canonical(target)/'expected-installed.lock');expected=lock_map(lock)
 need({r['name']:r['version']for r in result['packages']}==expected,'real607 bundle complete target');source_contract(root,authorization,name)
 return dict(status='MATERIALIZED_SIGNED607_BUNDLE_NOT_NATIVE_ROOT',provider=name,provider_source=provider(name)['source'],manifest=pin(read(canonical(target)/'manifest.json')),expected607=pin(lock),signatures='ORIGINAL_FRESH607_PUBLIC_VERIFIER_COMPLETED',native_root='NOT_CREATED',native_lease='NOT_ISSUED',hardware='NOT_RUN',Root_acceptance=None)

ADMISSION_FIELDS={'schema_version','status','provider','provider_source','source','run_id','attempt','token','architecture','page_size','native_mode','expected607_sha256','source_identity','readonly_source_fd_identity','root_nodes_sha256','capabilities_sha256','hardlink_groups_sha256','inventory_sha256','source_packages_sha256','other606_sha256','signed_bundle_manifest_sha256','snapshot_sha256','extraction_receipt_sha256','commit_started','packages_committed','rollback','hardware'}

def validate_native607(admission,inventory,observation,capabilities,expected_lock,*,current_source,current_run,current_attempt,token):
 """Pure data binding, consumed only after backend independent live FD checks.

 This function is not a producer of live observation or Root acceptance. The
 backend must independently reopen/reobserve its exact current owned root.
 """
 a=admission;need(type(a)is dict and set(a)==ADMISSION_FIELDS,'closed native607 provider admission');p=provider(a['provider']);expected=lock_map(expected_lock)
 need(a['schema_version']==1 and a['status']=='VALIDATED_FRESH_OWNED_NATIVE607_ROOT'and a['provider_source']==p['source'],'exact native607 provider source')
 need(type(current_source)is str and re.fullmatch('[0-9a-f]{40}',current_source)and type(current_run)is int and current_run>0 and type(current_attempt)is int and current_attempt>0 and re.fullmatch('[0-9a-f]{32}',token),'explicit new607 actor identity')
 need((a['source'],a['run_id'],a['attempt'],a['token'])==(current_source,current_run,current_attempt,token),'new607 source/run/attempt/token join')
 need(not any((a['source'],a['run_id'])==(v['source'],v['run_id'])for v in PROVIDERS.values()),'retired VM run is not a new native607 root')
 need(a['architecture']=='aarch64'and type(a['page_size'])is int and a['page_size']==p['page_size']and a['native_mode']=='OWNED_OFFLINE_NATIVE_CONTAINER','actual independent native607 provider mode')
 need(a['commit_started']==a['packages_committed']=='UNKNOWN'and a['rollback']=='NOT_CLAIMED'and a['hardware']=='NOT_RUN','no607 recovery/hardware inference')
 fd=a['readonly_source_fd_identity'];need(type(fd)is list and len(fd)==9 and all(type(n)is int and n>=0 for n in fd)and fd[1]>0 and fd[5]>0 and stat.S_ISDIR(fd[2])and a['source_identity']==fd[:2]and fd[3]==fd[4]==0,'exact native607 source FD/stat data; backend must reobserve')
 rows=inventory['packages'];need(type(rows)is list and len(rows)==607 and len({r['name']for r in rows})==607 and {r['name']:r['version']for r in rows}==expected,'whole exact607 native inventory')
 need(observation['complete']is True and type(observation['nodes'])is dict and 0<len(observation['nodes'])<=500000,'complete bounded native607 nodes')
 nodes=observation['nodes'];need(type(capabilities)is dict and len(capabilities)<=4096 and all(n in nodes and nodes[n]['type']=='file'and type(v)is str and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{48}',v)for n,v in capabilities.items()),'complete native607 capability binding')
 other=''.join(n+' '+v+'\n'for n,v in sorted(expected.items())if n!=APPS).encode()
 values=dict(root_nodes_sha256=pin(encoded(nodes))['sha256'],capabilities_sha256=pin(encoded(capabilities))['sha256'],hardlink_groups_sha256=pin(encoded(observation.get('hardlink_groups',{})))['sha256'],inventory_sha256=pin(encoded(inventory))['sha256'],source_packages_sha256=pin(encoded(rows))['sha256'],other606_sha256=pin(other)['sha256'],expected607_sha256=EXPECTED607['sha256'])
 need(all(a[k]==v for k,v in values.items()),'independent607 raw maps/inventory/606 locks join')
 need(all(type(a[k])is str and SHA.fullmatch(a[k])for k in('signed_bundle_manifest_sha256','snapshot_sha256','extraction_receipt_sha256')),'explicit607 bundle/snapshot/extraction receipt pins')
 return dict(status='VALIDATED_NATIVE607_OPERAND_DATA_NOT_ROOT_ACCEPTANCE',provider=a['provider'],source=current_source,run_id=current_run,attempt=current_attempt,expected607=EXPECTED607,other606_sha256=values['other606_sha256'],live_observation='MUST_BE_INDEPENDENTLY_RECHECKED_BY_BACKEND',repair_success=False,Root_acceptance=None,hardware='NOT_RUN')


def plan607(root,authorization,record_root,name):
 c=source_contract(root,authorization,name);record=accepted_decision(record_root,name)
 return dict(schema_version=1,status='EXACT607_SIGNED_BUNDLE_MATERIALIZATION_AVAILABLE_NATIVE_ROOT_HANDOFF_REQUIRED',provider=c,accepted_vm=record,callable='route607.materialize607(root,authorization,provider,ready604,public_six,owned_producer,target,six_record=exact22_record)',live_validation='route607.validate_native607 plus backend independent readonly FD/source/map checks',missing_operands=[dict(field=n,status='REQUIRED_NEW_OWNED_NATIVE_OPERAND_NOT_EXPORTED_BY_ACCEPTED_VM')for n in('ready604_signed_bundle','public_six_payloads','fresh_owned_producer_signing_home','new_native607_root','native607_raw_snapshot','native607_inventory','native607_capability_map','native607_auxiliary_closure','new_native607_policy','new_native607_lease','new_actor_source_run_attempt_token')],native='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None)


def checkpoint_scope(path):
 """Select only the two named Root checkpoint entries; not runtime authority."""
 raw=read(path);all_entries=decode(raw)
 out={k:all_entries[k]for k in('fresh607_accepted_public','fresh607_storage_admission_20261026')}
 fresh=out['fresh607_accepted_public'];storage=out['fresh607_storage_admission_20261026']
 need(fresh['source']==PROVIDERS['fresh4k']['source']and fresh['run']==PROVIDERS['fresh4k']['run_id']and fresh['decision_public']==PROVIDERS['fresh4k']['record_source'],'exact Root accepted607 checkpoint key')
 need(storage['source']==PROVIDERS['storage16k']['source']and storage['run']==PROVIDERS['storage16k']['run_id'],'exact Root storage607 checkpoint key')
 return dict(checkpoint=pin(raw),entries=out,authority='EXACT_DECISION_BYTES_REQUIRED_STORAGE_CHECKPOINT_STATUS_MAY_BE_STALE')
