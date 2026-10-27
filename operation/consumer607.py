# SPDX-License-Identifier: MIT
"""Actual readonly-FD native607 lease, then the held607 recovery entry.

The host callable only accepts a retired owned actor. The actor independently
reobserves the physical snapshot and issues its own live readonly FD lease; no
retained VM map, producer boolean or host-generated lease can replace that gate.
"""
import gzip,os,re,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import provider607 as P
SOURCE=Path('/source');INPUTS=Path('/inputs');SEED=Path('/seed');OUT=Path('/out')

def bounded_observation(raw,want):
 P.need(P.pin(raw)==want,'exact physical snapshot observation bytes');decoder=__import__('zlib').decompressobj(31);body=decoder.decompress(raw,256*1024**2+1)
 P.need(len(body)<=256*1024**2 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'complete one bounded gzip snapshot observation');return P.decode(body)

def context_inputs():
 raw=P.read(INPUTS/'native607-context.json');P.need(P.pin(raw)['sha256']==os.environ.get('NATIVE607_CONTEXT_SHA256'),'independent native consumer context pin');context=P.decode(raw);who=P.current_identity()
 P.need(type(context)is dict and set(context)=={'schema_version','status','source','run_id','attempt','token','provider','provider_source','installed','snapshot','extraction','observation','source_inventory','signed_bundle_manifest','candidates'}and type(context['schema_version'])is int and context['schema_version']==1 and context['status']=='FRESH607_NATIVE_CONSUMER_INPUT_CONTEXT'and all(context[k]==v for k,v in who.items())and context['provider']==P.PROVIDER and context['provider_source']==P.PROVIDER_SOURCE,'exact actual fresh4K607 native consumer identity')
 values={}
 for role,name in(('installed','native607-install.json'),('snapshot','snapshot.json'),('extraction','extraction.json'),('signed_bundle_manifest','bundle-manifest.json'),('source_inventory','source-inventory.json')):
  body=P.read(INPUTS/name);P.need(P.pin(body)==context[role],'physical original native607 receipt: '+role);values[role]=P.decode(body)
 values['observation']=bounded_observation(P.read(INPUTS/'source-observation.json.gz',64*1024**2),context['observation'])
 snapshot=values['snapshot'];installed=values['installed'];P.need(snapshot['status']=='PHYSICAL_NATIVE607_ROOT_SNAPSHOT_AND_EXTRACTION'and installed['status']=='INSTALLED_FRESH_NATIVE607_PENDING_PHYSICAL_SNAPSHOT'and all(snapshot[k]==installed[k]==v for k,v in who.items()),'physical retired installation/snapshot owner join')
 P.need(snapshot['source_identity']==installed['installed_identity']and snapshot['installed_receipt']==context['installed']and snapshot['extraction']==context['extraction']and snapshot['observation']==context['observation']and snapshot['inventory']==context['source_inventory']and installed['signed_bundle_manifest']==context['signed_bundle_manifest'],'physical native root/extraction/archive body joins')
 P.need(snapshot['raw_observation']==P.pin(P.encoded(values['observation']))and snapshot['root_nodes_sha256']==P.digest(values['observation']['nodes'])and snapshot['capabilities_sha256']==P.digest(snapshot['capabilities'])and snapshot['hardlink_groups_sha256']==P.digest(values['observation']['hardlink_groups']),'complete raw physical snapshot pins')
 return context,values

def issue(C,T,normal,K,context,values):
 """Independently observe actual readonly /seed, then issue exact normal policy."""
 who=P.current_identity();K.native_context(dict(page_size=4096),T);budget=T.F.Limits(deadline=time.monotonic()+600,max_packages=607)
 fd=normal.roots._open_root(SEED)
 try:
  info=os.fstat(fd);P.need(os.fstatvfs(fd).f_flag&os.ST_RDONLY and stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0,'actual live readonly native607 source FD');fd_identity=K.identity(info)
 finally:os.close(fd)
 observed=normal.measure(SEED,budget);snapshot=values['snapshot'];P.need(observed['complete']is True and all(observed[k]==values['observation'][k]for k in('nodes','hardlink_groups','complete'))and fd_identity[:2]==snapshot['target_identity'],'independent readonly physical snapshot node/link/identity equality')
 caps=normal.capability_map(SEED,observed,budget,snapshot['capabilities']);P.need(P.digest(caps)==snapshot['capabilities_sha256'],'independent complete native capability map')
 app=C.load('fresh607_native_apps',INPUTS/'apps-source/apps.py');c,r,unused=app.helpers(INPUTS/'candidate/usr/share/cachy-asahi/repository-runtime');inventory=app.inventory_reader().collect(SEED/T.DB,c,lambda row:app.package(row,r));K.inventory_check(inventory,source=True)
 retained=dict(values['source_inventory'],observation=dict(values['source_inventory']['observation'],dbpath=str(SEED/T.DB)))
 P.need(retained==inventory and values['source_inventory']['observation']['dbpath']=='/data/source607/'+T.DB,'complete actual normal snapshot inventory with explicit source mount relocation only')
 P.need(P.digest(K.db_nodes(observed['nodes']))==snapshot['database_sha256'],'physical full raw607 DB map, never normalized')
 manifest=values['signed_bundle_manifest'];P.need(K.pin(K.lock_bytes(manifest['packages']))['sha256']==K.LOCK_SHA256,'complete exact607 signed manifest lock')
 wanted={row['name']:dict(version=row['version'],archive_sha256=row['sha256'])for row in manifest['packages']if row['name']in K.VERSIONS};P.need(context['candidates']==wanted,'every current candidate joins exact physical signed607 manifest')
 K.lock_bytes(inventory['packages']);P.need({row['name']:row['version']for row in manifest['packages']}=={row['name']:row['version']for row in inventory['packages']},'signed complete607 installed identities')
 payloads=normal.current_payloads();P.need(set(payloads)==set(K.VERSIONS)and all(observed['nodes'].get(n)==row for payload in payloads.values()for n,row in payload.items()),'all four exact current source payloads actually installed')
 candidates={name:dict(row,payload_sha256=K.digest(payloads[name]))for name,row in context['candidates'].items()};P.need(set(candidates)==set(K.VERSIONS)and all(candidates[n]['version']==v for n,v in K.VERSIONS.items())and candidates[K.APPS]['archive_sha256']==K.ARCHIVE,'exact four signed current candidates')
 admission=dict(schema_version=1,status='VALIDATED_FRESH_OWNED_NATIVE607_ROOT',provider=P.PROVIDER,provider_source=P.PROVIDER_SOURCE,**who,architecture='aarch64',page_size=4096,native_mode='OWNED_OFFLINE_NATIVE_CONTAINER',expected607_sha256=K.LOCK_SHA256,source_identity=fd_identity[:2],readonly_source_fd_identity=fd_identity,root_nodes_sha256=K.digest(observed['nodes']),capabilities_sha256=K.digest(caps),hardlink_groups_sha256=K.digest(observed.get('hardlink_groups',{})),inventory_sha256=K.digest(inventory),source_packages_sha256=K.digest(inventory['packages']),other606_sha256=K.OTHER606_SHA256,signed_bundle_manifest_sha256=context['signed_bundle_manifest']['sha256'],snapshot_sha256=context['snapshot']['sha256'],extraction_receipt_sha256=context['extraction']['sha256'],commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',hardware='NOT_RUN')
 K.admission_check(admission);P.save(INPUTS/'current607-admission.json',admission)
 receipt=K.write_pair(INPUTS,SEED,who['token'],admission,normal,T,budget,app,c,r,candidates,admission['snapshot_sha256'],admission['extraction_receipt_sha256'])
 P.save(OUT/'native607-readonly-admission.json',dict(schema_version=1,status='ISSUED_FROM_ACTUAL_READONLY_NATIVE607_FD',admission=P.pin(P.encoded(admission)),policy_receipt=receipt,provider_context_sha256=P.digest(context),native_repair='NOT_RUN',hardware='NOT_RUN'))
 return admission

def actor():
 # Source/body/independent actor gates run before any normal backend is loaded.
 P.actor_guard('consumer');context,values=context_inputs();X=P.load('common',P.HERE/'common.py');X.verify(SOURCE,os.environ.get('APPS16_INTERRUPTION_PROFILE_SHA256'))
 C=P.load('consumer_contract',SOURCE/X.LANE/'contract.py');C.source(SOURCE);T=C.load('consumer_transaction',SOURCE/X.LANE/'transaction.py');normal=C.adapter(SOURCE);K=P.load('backend607',P.HERE/'backend607.py')
 os.chown(INPUTS,0,0);INPUTS.chmod(0o700)
 P.need(INPUTS.is_mount()and stat.S_IMODE(INPUTS.stat().st_mode)==0o700 and INPUTS.stat().st_uid==0,'exact private generated receipt parent')
 for name in('apps-source','candidate','release'):
  path=INPUTS/name;fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:P.need(path.is_mount()and os.fstatvfs(fd).f_flag&os.ST_RDONLY,'all original source/signature inputs independently readonly')
  finally:os.close(fd)
 try:
  issue(C,T,normal,K,context,values)
  for role in('policy','lease'):P.write(INPUTS/('full574-'+role+'.json'),P.read(INPUTS/('current607-'+role+'.json')))
  # Whole immutable main: normal planner/backend, callback kernel trace, recovery,
 # raw restoration, loader/query and original ordered outer disposal semantics.
  entry=P.load('lifecycle_entry607',P.HERE/'lifecycle_entry607.py');return entry.main()
 finally:export_receipts()

def export_receipts():
 names=('native607-context.json','native607-install.json','snapshot.json','extraction.json','source-observation.json.gz','source-inventory.json','bundle-manifest.json','current607-admission.json','current607-policy.json','current607-lease.json','full574-policy.json','full574-lease.json')
 for name in names:
  path=INPUTS/name
  if not os.path.lexists(path):continue
  P.write(OUT/('receipt-'+name),P.read(path,64*1024**2 if name.endswith('.gz')else 16*1024**2))
 for path in OUT.iterdir():
  P.need(path.is_file()and not path.is_symlink(),'ordinary finite consumer exports');os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))


def run(args,provided):
 record=P.phase(args.runtime.consume607(provided),'consumer');directory=Path(record['public_dir']);raw=P.read(directory/'lifecycle.json',4*1024**2);value=P.decode(raw)
 P.need(value.get('operation')=='recover-apps16-reinstall607'and value.get('installed_count')==607 and value.get('repair_success')is True and value.get('packages_committed')=='UNKNOWN'and value.get('rollback')=='NOT_CLAIMED'and value.get('workspaces_retained_for_outer_disposal')is True,'actual607 lifecycle plus retired consumer, never producer success inference')
 # Reuse the real operation result and retention gates outside the container.
 root=Path(args.operation_root);C=P.load('host_consumer_contract',root.parent/'repair-source/scripts/ci/apps7-full574-repair-native/contract.py');L=P.load('host_lifecycle607',root/'lifecycle607.py')
 L.validate(C,value);files={'lifecycle-public/'+path.name:P.pin(P.read(path,96*1024**2))for path in directory.iterdir()};retained=L.retained(C,value,directory,files)
 return dict(schema_version=1,status='NATIVE607_RECOVERY_CONSUMER_RETIRED_RETAINED_VALIDATED',actor=record,lifecycle=P.pin(raw),retained=retained,repair_success=True,prior_commit_outcome='UNKNOWN',rollback='NOT_CLAIMED',hardware='NOT_RUN',Root_acceptance=None)

def main(argv=None):
 argv=sys.argv[1:]if argv is None else argv;P.need(argv==['--run'],'one fixed native607 consumer role');return actor()
if __name__=='__main__':raise SystemExit(main())
