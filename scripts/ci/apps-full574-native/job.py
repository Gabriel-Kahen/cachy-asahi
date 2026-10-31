#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Exact native574 Apps owner: stopped export, TEST release, copies and ordered teardown."""
import argparse,contextlib,fcntl,gzip,os,platform,re,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def owner_api(root):return C.load('held_owner_api',root/'scripts/ci/glibc-gnu-provider-lifecycle-owner/job.py')
def proof(args):
 binding=C.source(args.source);env=os.environ;source=env['SOURCE_SHA']
 C.need(env['RUNNER_ARCH']=='ARM64' and env['RUNNER_OS']=='Linux' and re.fullmatch('[0-9a-f]{40}',source) and env['GITHUB_SHA']==env['GITHUB_WORKFLOW_SHA']==source,'exact native source/workflow required')
 import subprocess
 actual=subprocess.check_output(['/usr/bin/git','-C',str(args.source),'rev-parse','HEAD'],text=True,timeout=10).strip();C.need(actual==source,'source checkout differs')
 identity=':'.join((env['GITHUB_RUN_ID'],env['GITHUB_RUN_ATTEMPT'],source));C.need(all(x.isdecimal() for x in identity.split(':')[:2]),'actual run identity')
 value=dict(status='SOURCE_PROOF_PASS',source_sha=source,job_token=C.sha(('apps574-producer:'+identity).encode())[:16],consumer_token=C.sha(('apps574-consumer:'+identity).encode())[:32],packet_source=binding['packet_source'],packet_index=binding['packet_index'])
 C.save(args.proof,value)
 with open(env['GITHUB_OUTPUT'],'a') as stream:
  for k in ('job_token','consumer_token','packet_source'):stream.write(k+'='+value[k]+'\n')
 return value

def check(args):
 binding=C.source(args.source)
 import subprocess
 actual=subprocess.check_output(['/usr/bin/git','-C',str(args.packet.parent),'rev-parse','HEAD'],text=True,timeout=10).strip();C.need(actual==binding['packet_source'],'actual input carrier checkout differs')
 value,payload,origins=C.inputs(args.source,args.packet);return dict(status='EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED',packages=sorted(value['packages']),payload_files=len(payload))

def reserve(report,output,role):
 C.need(role in ('export','extract','signer','lifecycle','interruption','source-verify','scrub','source-cleanup') and role not in {r['role'] for r in report['actors']} and len(report['actors'])<8,'finite unique actor roles')
 row=dict(role=role,name='caa-apps574-'+report['token']+'-'+role,id=None,status='RESERVED');report['actors'].append(row);C.save(output/'owner.json',report);return row

def actor(root,output,report,command,api,role,script,extra=()):
 row=reserve(report,output,role);C.need(api.inspect(row['name'],command) is None,'fresh actor name required')
 argv=['/usr/bin/docker','run','--name',row['name'],'--label',C.LABEL+'='+report['token'],'--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--ulimit=nofile=8192:8192']
 argv+=['--cap-add='+cap for cap in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID')]
 if role in ('extract','lifecycle','interruption'):argv+=['--cap-add=SETFCAP']
 argv+=['--tmpfs','/tmp:rw,nosuid,nodev,exec,size=1g,mode=1777','--env=PYTHONDONTWRITEBYTECODE=1','--env=CACHY_APPS574_SNAPSHOT=1','--env=CACHY_APPS574_FIXTURE=1','--env=CACHY_APPS574_LIFECYCLE=1','--env=OWNER_TOKEN='+report['token'],'--env=OUTPUT_UID='+str(os.getuid()),'--env=OUTPUT_GID='+str(os.getgid())]
 mounts=[(root,'/source',True),(output/'inputs','/inputs',True)]
 if role in ('extract','source-verify','source-cleanup'):
  mounts +=[(output/'data','/data',False),(output/'snapshot-public','/out',False)];argv+=['--env=SOURCE_TAR_SHA256='+report['snapshot_point']['archive_sha256']]
 elif role=='signer':mounts +=[(output/'authority','/authority',False),(output/'fixture-public','/out',False)]
 elif role=='scrub':mounts +=[(output/'work','/work',False),(output/'authority','/authority',False),(output/'lifecycle-public','/out',False)]
 else:
  target=output/('interruption-public' if role=='interruption' else 'lifecycle-public');mounts +=[(output/'data/original574','/seed',True),(output/'work','/work',False),(target,'/out',False)]
 for source,target,readonly in mounts:argv+=['--mount','type=bind,src='+str(source)+',dst='+target+(',readonly' if readonly else '')]
 argv+=['--entrypoint=/usr/bin/python3',report['image'],'-I','-B','/source/'+C.LANE+'/'+script,*extra]
 result=command(argv,False,3000 if role=='lifecycle' else 900 if role in ('extract','interruption','source-verify') else 240)
 observed=api.inspect(row['name'],command);C.need(observed is not None,'actor identity retained');row.update(id=api.verify_actor(observed,row['name'],report['image'],C.LABEL,report['token']),status='EXITED',exit=result['code']);C.save(output/'owner.json',report)
 C.need(result['code']==0,'owned actor failed: '+role)


def materialize(args,output,report):
 packet,payload,origins=C.inputs(args.source,args.packet);inputs=output/'inputs';inputs.mkdir(mode=0o755)
 for name,(mode,raw) in payload.items():
  target=inputs/'candidate'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(mode)
 apps=inputs/'apps-source';apps.mkdir()
 for name in ('apps.py','inventory.py','helper-pins.json','cachy-asahi-apps','source-provenance.json'):
  (apps/name).write_bytes(C.checked(args.packet,packet['packages']['cachy-asahi-apps']['source_files'][name]))
 (inputs/'native-index.json').write_bytes(C.checked(args.packet,C.policy()['packet_index']));(inputs/'archives').mkdir()
 for row in packet['packages'].values():
  name=Path(row['files']['a']['path']).name;target=inputs/'archives'/name;C.need(not target.exists(),'unique actual candidate archive basename');target.write_bytes(C.checked(args.packet,row['files']['a']))
 C.save(inputs/'control.json',dict(source_sha=report['source_sha'],token=report['token'],image=report['image'],packet_source=C.policy()['packet_source'],packet_index=C.policy()['packet_index']))
 for path in inputs.rglob('*'):
  if path.is_dir():path.chmod(0o755)
 return packet

def bind(root,output,report,packet):
 snap=C.decode(C.read(output/'snapshot-public/snapshot.json'));C.need(snap['status']=='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT','complete original574 snapshot required')
 extraction_raw=C.read(output/'snapshot-public/extraction.json');extraction=C.sha(extraction_raw);extract=C.decode(extraction_raw);module=C.adapter(root)
 C.need(extract['archive_sha256']==report['snapshot_point']['archive_sha256'] and extract['capability_restoration']=='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED' and extract['security_capabilities']==snap['source_capabilities'] and extract['security_capabilities_sha256']==snap['source_capabilities_sha256'],'actual archive/extracted capability map join')
 common=dict(schema_version=1,purpose=module.PURPOSE,execution_budget=dict(module.EXECUTION_BUDGET),snapshot_sha256=report['snapshot_point']['archive_sha256'],extraction_receipt_sha256=extraction,source_tree_sha256=snap['tree_sha256'],source_packages_sha256=snap['source_packages_sha256'],source_closure_sha256=snap['source_closure_sha256'],source_capabilities_sha256=snap['source_capabilities_sha256'])
 C.need(type(snap['source_capabilities']) is dict and module.digest(snap['source_capabilities'])==snap['source_capabilities_sha256'],'snapshot capability map binding')
 policy=dict(common,baseline_lock_sha256=C.BASE,source_capabilities=snap['source_capabilities'],candidates={n:dict(version=C.VERSIONS[n],archive_sha256=r['files']['a']['sha256'],payload_sha256=module.digest(module.current_payloads()[n])) for n,r in packet['packages'].items()})
 lease=dict(common,token=report['token'],source='/seed',source_identity=snap['source_inode']);C.need(len(C.encoded(policy))<=65536 and len(C.encoded(lease))<=65536,'original bounded adapter policy/lease size');C.save(output/'inputs/full574-policy.json',policy);C.save(output/'inputs/full574-lease.json',lease)
 shutil.copyfile(output/'snapshot-public/base.json',output/'inputs/base.json');report['binding']=dict(policy_sha256=C.sha(C.encoded(policy)),lease_sha256=C.sha(C.encoded(lease)));C.save(output/'owner.json',report)

def run(args):
 C.source(args.source);proof_value=C.decode(C.read(args.proof));C.need(platform.machine()=='aarch64' and platform.system()=='Linux' and os.getuid()==os.geteuid()>0 and not any(k.startswith('DOCKER_') for k in os.environ),'ordinary native ARM coordinator required')
 base=C.decode(C.read(args.base/'report.json'));image=C.read(args.base/'image-id').decode().strip();lock=C.read(args.base/'installed-packages.lock')
 C.need(base['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and base['image']==image and base['ownership']['token']==proof_value['job_token'] and C.sha(lock)==C.BASE,'exact fresh owned original574 producer required')
 C.need(not args.output.exists() and shutil.disk_usage(args.output.parent).free>=40*1024**3,'fresh disk workspace with40GiB free required');C.safe(args.output);C.need(all(not args.output.is_relative_to(p) and not p.is_relative_to(args.output) for p in (args.source,args.base,args.packet)),'separate owner directories required')
 api=owner_api(args.source);producer=C.load('original574_producer',args.source/'scripts/ci/maintained_desktop574.py');producer.inspect_image(image,proof_value['job_token'])
 args.output.mkdir(mode=0o700)
 for name in ('data','snapshot-public','fixture-public','lifecycle-public','interruption-public','authority','work'):(args.output/name).mkdir(mode=0o700)
 report=dict(status='FAIL',token=proof_value['consumer_token'],source_sha=proof_value['source_sha'],producer_token=proof_value['job_token'],image=image,actors=[],commands=[],producer_cleanup='NOT_ATTEMPTED',hardware='NOT_RUN',release_admission=False)
 with api.producer_lease(args.base),api.lease(args.output/'owner.lock',True):
  command=api.command_api(args.source,args.output,report);C.save(args.output/'owner.json',report)
  try:
   C.need(command(['/usr/bin/docker','context','show'])['out'].decode().strip()=='default' and command(['/usr/bin/docker','info','--format','{{.Architecture}}'])['out'].decode().strip() in ('aarch64','arm64') and command(['/usr/bin/docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])['out'].decode().strip()=='linux/arm64','local native ARM daemon/image required')
   import json
   C.need(json.loads(command(['/usr/bin/docker','context','inspect','default'])['out'])[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local daemon only')
   packet=materialize(args,args.output,report);row=reserve(report,args.output,'export');C.need(api.inspect(row['name'],command) is None,'fresh export actor')
   value=command(['/usr/bin/docker','create','--name',row['name'],'--label',C.LABEL+'='+report['token'],'--pull=never','--platform=linux/arm64','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--entrypoint=/usr/bin/false',image]);cid=value['out'].decode().strip();C.need(re.fullmatch('[0-9a-f]{64}',cid),'actual export CID');row['id']=cid;C.save(args.output/'owner.json',report)
   before=api.inspect(row['name'],command);api.verify_actor(before,row['name'],image,C.LABEL,report['token'],cid);api.never_started(before)
   archive=args.output/'data/source.tar';command(['/usr/bin/docker','export','--output',str(archive),cid],seconds=300);C.need(api.ordinary(archive,12*1024**3).st_size>0,'bounded export archive');after=api.inspect(row['name'],command);api.verify_actor(after,row['name'],image,C.LABEL,report['token'],cid);C.need(after['State']==before['State'],'source export actor never started')
   report['snapshot_point']=dict(kind='NEVER_STARTED_ORIGINAL574_IMAGE_ROOTFS',container=cid,image=image,state=before['State'],archive_bytes=archive.stat().st_size,archive_sha256=api.sha(archive));C.save(args.output/'owner.json',report);api.retire([row],image,C.LABEL,report['token'],command,args.output,report)
   actor(args.source,args.output,report,command,api,'extract','snapshot.py');bind(args.source,args.output,report,packet)
   actor(args.source,args.output,report,command,api,'signer','fixture.py');api.retire([r for r in report['actors'] if r['role']=='signer'],image,C.LABEL,report['token'],command,args.output,report)
   shutil.copytree(args.output/'fixture-public/release',args.output/'inputs/release',symlinks=True)
   actor(args.source,args.output,report,command,api,'lifecycle','lifecycle.py');life=C.result(C.decode(C.read(args.output/'lifecycle-public/lifecycle.json',4*1024**2)))
   actor(args.source,args.output,report,command,api,'interruption','lifecycle.py',('--interrupt',));interruption=C.decode(C.read(args.output/'interruption-public/interruption.json'))
   C.need(interruption['status']=='FAIL_INTERRUPTED_OWNED_COPY_RETAINED' and interruption['worker_group_absent'] is True and interruption['packages_committed']=='UNKNOWN' and interruption['rollback']=='NOT_CLAIMED','genuine interrupted uncertainty retained')
   api.retire(report['actors'],image,C.LABEL,report['token'],command,args.output,report)
   actor(args.source,args.output,report,command,api,'source-verify','snapshot.py',('--verify',));report.update(status='PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP',lifecycle=life,interruption=interruption)
  except BaseException as error:report.update(error=str(error)[:1024],error_type=type(error).__name__)
  finally:
   try:api.retire(report['actors'],image,C.LABEL,report['token'],command,args.output,report)
   except BaseException as error:report['actor_cleanup_error']=str(error)[:512]
   C.save(args.output/'owner.json',report)
 return report

def cleanup(args):
 C.source(args.source);proof_value=C.decode(C.read(args.proof));api=owner_api(args.source);result=dict(status='FAIL',consumer='UNKNOWN',producer='PRESERVED',authority='PRESERVED')
 try:
  C.need(args.base.is_dir() or not args.base.exists(),'ordinary producer directory or not-started state required')
  with api.producer_lease(args.base) if args.base.is_dir() else contextlib.nullcontext():
   if args.output.exists():
    with api.lease(args.output/'owner.lock'):
     report=C.decode(C.read(args.output/'owner.json',4*1024**2));C.need(report['token']==proof_value['consumer_token'] and report['producer_token']==proof_value['job_token'] and report['source_sha']==proof_value['source_sha'],'exact wrapper proof binding')
     command=api.command_api(args.source,args.output,report);api.retire(report['actors'],report['image'],C.LABEL,report['token'],command,args.output,report)
     # Never scrub uncertain clones, keys or source while any consumer may live.
     if (args.output/'inputs').is_dir():
      C.save(args.output/'inputs/scrub.json',dict(status='ALL_EARLIER_CONSUMERS_ABSENCE_VERIFIED',token=report['token'],actors=report['actors'],work=inode(args.output/'work'),authority=inode(args.output/'authority')))
      actor(args.source,args.output,report,command,api,'scrub','scrub.py');api.retire(report['actors'],report['image'],C.LABEL,report['token'],command,args.output,report)
      C.need(not list((args.output/'work').iterdir()) and not list((args.output/'authority').iterdir()),'private clones or TEST authority remain');result['authority']='PASS_REMOVED_AFTER_CONSUMER_ABSENCE'
     else:C.need(not any((args.output/n).exists() and list((args.output/n).iterdir()) for n in ('work','authority','data')),'anonymous private state preserved')
     if (args.output/'data/original574').exists():
      actor(args.source,args.output,report,command,api,'source-cleanup','snapshot.py',('--cleanup',));api.retire(report['actors'],report['image'],C.LABEL,report['token'],command,args.output,report)
     C.need(not (args.output/'data/original574').exists(),'owned source snapshot remains')
     archive=args.output/'data/source.tar'
     if archive.exists():
      api.ordinary(archive,12*1024**3);C.need(api.sha(archive)==report['snapshot_point']['archive_sha256'],'original export identity before disposal');archive.unlink()
     report['consumer_cleanup']='PASS_ALL_ACTORS_COPIES_KEYS_AND_SOURCE_RETIRED';C.save(args.output/'owner.json',report);result['consumer']=report['consumer_cleanup']
   else:result['consumer']='NOT_STARTED'
  # Existing no-prune producer cleanup runs only after every consumer/data gate.
  if (args.base/'report.json').exists():
   runtime=api.runtime(args.source);argv=['/usr/bin/python3','-I','-B',str(args.source/'scripts/ci/maintained_desktop574.py'),'cleanup','--inputs',str(args.source/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(args.base),'--job-token',proof_value['job_token']]
   row,out,err,error=runtime.run_command(argv,args.base,dict(runtime.ENV,HOME=str(args.base/'home')),240,1024**2)
   C.need(error is None and row['exit_code']==0 and row['group_absence_verified'],'guarded producer cleanup failed');producer=C.decode(C.read(args.base/'report.json'))['owned_cleanup'];C.need(producer['status']=='PASS' and producer['image']['absence_verified'] and producer['probe']['absence_verified'],'complete producer absence required');result['producer']=producer
  else:result['producer']='NOT_STARTED'
  result['status']='PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER'
 except BaseException as error:result.update(error=str(error)[:1024],error_type=type(error).__name__)
 C.save(args.receipt,result);return result

def inode(path):
 value=path.lstat();return [value.st_dev,value.st_ino]

def retain(args):
 C.source(args.source);C.need(not args.public.exists(),'fresh bounded public export');args.public.mkdir(mode=0o700)
 result=dict(status='FAIL_OR_INCOMPLETE',files={},bytes=0,errors=[],hardware='NOT_RUN',release_admission=False,scope='NATIVE_ARM_OWNED_OFFLINE_FULL574_COPIED_ROOT_ONLY')
 def copy(path,name,cap,required=True):
  try:
   if not required and not path.exists() and not path.is_symlink():return
   raw=C.read(path,cap);C.need(result['bytes']+len(raw)<=192*1024**2,'closed192MiB export bound');target=args.public/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);result['files'][name]=dict(bytes=len(raw),sha256=C.sha(raw));result['bytes']+=len(raw)
  except Exception as error:result['errors'].append(name+': '+str(error)[:256])
 copy(args.proof,'source-proof.json',65536);copy(args.receipt,'ordered-cleanup.json',65536)
 for name in ('report.json','installed-packages.lock'):copy(args.base/name,'base/'+name,2*1024**2)
 copy(args.output/'owner.json','runtime/owner.json',4*1024**2)
 try:
  commands=C.decode(C.read(args.output/'owner.json',4*1024**2))['commands'];C.need(len(commands)<=256,'finite original owner command set')
  for n,row in enumerate(commands):
   for side in ('stdout','stderr'):
    name='command-%03d.'%n+side;copy(args.output/name,'runtime/'+name,1024**2)
    pin=result['files']['runtime/'+name];C.need(pin['bytes']==row[side+'_bytes'] and pin['sha256']==row[side+'_sha256'],'original owner raw output differs')
 except Exception as error:result['errors'].append('owner raw commands: '+str(error)[:512])
 for relative in ('snapshot-public','lifecycle-public','interruption-public'):
  directory=args.output/relative
  if directory.exists():
   nodes=list(directory.iterdir());C.need(len(nodes)<=160,'bounded direct evidence set')
   for path in sorted(nodes):copy(path,relative+'/'+path.name,64*1024**2 if path.name.endswith('.gz') else 16*1024**2)
 for name in ('native-index.json','control.json','full574-policy.json','full574-lease.json','scrub.json'):copy(args.output/'inputs'/name,'inputs/'+name,2*1024**2)
 # Retain the exact immutable input packet closure, original source/decisions included.
 try:
  packet,_,_=C.inputs(args.source,args.packet);files={}
  def refs(node):
   if type(node) is dict:
    if set(node)=={'path','bytes','sha256'}:files[node['path']]=node
    else:
     for row in node.values():refs(row)
   elif type(node) is list:
    for row in node:refs(row)
  refs(packet);files[C.policy()['packet_index']['path']]=C.policy()['packet_index']
  for name,pin in files.items():copy(args.packet/name,'native-inputs/'+name,16*1024**2)
 except Exception as error:result['errors'].append('native packet: '+str(error)[:512])
 # TEST bundle files are exact signed bytes; aliases remain explicit link data.
 fixture=args.output/'fixture-public/release'
 if fixture.exists():
  nodes=list(fixture.rglob('*'));C.need(len(nodes)<=128,'finite TEST release nodes');links={}
  for path in sorted(nodes):
   if path.is_symlink():links[path.relative_to(fixture).as_posix()]=os.readlink(path)
   elif path.is_file():copy(path,'signed-TEST-release/'+path.relative_to(fixture).as_posix(),8*1024**2)
   else:C.need(path.is_dir(),'TEST release special node')
  target=args.public/'signed-TEST-release-links.json';target.write_bytes(C.encoded(links));result['files'][target.name]=dict(bytes=target.stat().st_size,sha256=C.sha(target.read_bytes()));result['bytes']+=target.stat().st_size
 for path in C.HERE.iterdir():
  if path.is_file():copy(path,'harness/'+path.name,2*1024**2)
 try:
  proof_value=C.decode(C.read(args.proof));original=C.decode(C.read(args.base/'report.json'));owner=C.decode(C.read(args.output/'owner.json',4*1024**2));ordered=C.decode(C.read(args.receipt));life=C.result(C.decode(C.read(args.output/'lifecycle-public/lifecycle.json',4*1024**2)));interruption=C.decode(C.read(args.output/'interruption-public/interruption.json'))
  C.need(owner['status']=='PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP' and owner['token']==proof_value['consumer_token'] and owner['source_sha']==proof_value['source_sha'] and owner['producer_token']==proof_value['job_token'] and owner['image']==original['image'] and original['ownership']['token']==proof_value['job_token'],'actual source/producer/lifecycle joins')
  C.need(ordered['status']=='PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER' and ordered['consumer']=='PASS_ALL_ACTORS_COPIES_KEYS_AND_SOURCE_RETIRED' and ordered['authority']=='PASS_REMOVED_AFTER_CONSUMER_ABSENCE' and ordered['producer']==original['owned_cleanup'] and original['owned_cleanup']['status']=='PASS' and all(r['status']=='PASS_ABSENCE_VERIFIED' for r in owner['actors']),'complete ordered teardown required')
  C.need(interruption['status']=='FAIL_INTERRUPTED_OWNED_COPY_RETAINED' and interruption['packages_committed']=='UNKNOWN' and interruption['rollback']=='NOT_CLAIMED' and interruption['worker_group_absent'] and interruption['direct_child_reaped'] and owner['interruption']==interruption and owner['lifecycle']==life,'original interruption uncertainty/result join required')
  C.need(interruption.get('security_capabilities')=='EXACT_SOURCE_MAP_PRESERVED_AFTER_GROUP_ABSENCE' and interruption.get('source_capabilities_sha256')==life['source_capabilities_sha256'],'interrupted physical copy capability map proof required')
  C.need(interruption['time_limit']==600 and interruption['reap_limit']==5 and interruption['seconds']<=605 and sum(row['bytes'] for row in interruption['outputs'].values())<=1024**2,'original interrupted worker bounds required')
  for side,pin in interruption['outputs'].items():
   C.need(side in ('stdout','stderr') and pin['path']=='interrupted-'+side and result['files']['interruption-public/'+pin['path']]=={k:pin[k] for k in ('bytes','sha256')},'original interrupted raw output join')
  snap=C.decode(C.read(args.output/'snapshot-public/snapshot.json'));after=C.decode(C.read(args.output/'snapshot-public/snapshot-after.json'));C.need(snap['status']==after['status']=='PASS_ORIGINAL574_APPS_CLOSURE_SNAPSHOT' and snap['tree_sha256']==after['tree_sha256']==life['source_tree_sha256'] and snap['extraction']['archive_sha256']==owner['snapshot_point']['archive_sha256'],'original snapshot/source preserved after all actual consumers')
  C.need(snap['source_capabilities']==after['source_capabilities'] and snap['source_capabilities_sha256']==after['source_capabilities_sha256']==life['source_capabilities_sha256'] and snap['extraction']['capability_restoration']=='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED' and snap['extraction']['security_capabilities']==snap['source_capabilities'] and snap['extraction']['security_capabilities_sha256']==snap['source_capabilities_sha256'],'actual extraction/source/lifecycle capability map joins')
  C.need(not result['errors'],'closed evidence incomplete');result['status']=C.STATUS
 except Exception as error:result['errors'].append(str(error)[:1024])
 C.save(args.public/'retention.json',result);return result

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('proof','check','run','cleanup','retain'))
 for name in ('source','packet','proof','base','output','receipt','public'):parser.add_argument('--'+name,type=Path)
 args=parser.parse_args();C.policy() # Before every secret/actor/partial-cleanup path.
 value=globals()[args.mode](args);print(C.encoded(dict(status=value['status'])).decode(),end='')
 raise SystemExit(0 if value['status'] in ('SOURCE_PROOF_PASS','EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED','PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP','PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',C.STATUS) else 1)
