# SPDX-License-Identifier: MIT
"""Replay only the concrete receipts emitted by the frozen Rust actor/producer."""
import re
S=None
LLVM='/opt/cachy-asahi/llvm23-source-reference'
PROBES=[['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','--print','sysroot'],['/stage0/bin/cargo','--version'],['/stage0/bin/rustdoc','--version'],[LLVM+'/bin/llvm-config','--version'],[LLVM+'/bin/llvm-config','--targets-built'],['/usr/bin/gcc','-dumpmachine'],[LLVM+'/bin/ld.lld','--version']]
BUILD=['/usr/bin/python','-I','-B','./x.py','--config','bootstrap.toml','install','-j','2']
OPERATIONAL_RESOURCES=dict(cpus=2,memory_bytes=8*1024**3,memory_swap_bytes=8*1024**3,swap_bytes=0,pids=512,prepare_actor_seconds=900,build_actor_seconds=16200,native_seconds=19800,cleanup_seconds=300,export_bytes=4*1024**3,package_bytes=2*1024**3,log_bytes=64*1024**2,job_minutes=360,minimum_host_memory_bytes=12*1024**3,minimum_host_disk_bytes=80*1024**3,minimum_host_available_inodes=1000000,active_host_memory_reserve_bytes=4*1024**3,active_host_disk_reserve_bytes=8*1024**3)
INIT_CODE_SHA256='fd88ed760b3a3f904a6eb33dfacf3d7e2b0988ba4c2e14ca39bb1118cd304109'
MAKEPKG=['/usr/bin/makepkg','--noextract','--noprepare','--nosign','--noconfirm','--log','--config','/source/actor/makepkg.conf']
def natural(row,zero=True):
 S.need(all(row.get(k)is True for k in('natural_exit','group_absent','leader_held_until_group_inspection','exit_observed_via_waitpid'))and row.get('forced_cleanup')is False and not row.get('cleanup_error')and row.get('ownership_lost')is False and row.get('retirement')=='REAPED'and type(row.get('exit'))is int and(row['exit']==0 if zero else row['exit']>=0),'CHILD_NATURAL_RETIREMENT')
def operations(rows,corpus,prefix,members):
 S.need(type(rows)is list and 1<=len(rows)<=1024,'OPERATIONS_COUNT')
 for index,row in enumerate(rows):
  natural(row['lifecycle'],False);S.need(row['lifecycle']['exit']==row['returncode']and type(row['argv'])is list,'OPERATIONS_EXIT_JOIN')
  for stream in('stdout','stderr'):
   r=row[stream];S.relative(r['file']);path=prefix+'/'+r['file'];S.need(r['file']==f'operations/{index:03}.'+stream and path in members.values()and members.get(r['file'])==path and corpus.rows.get(path)=={k:r[k]for k in('bytes','sha256')},'OPERATIONS_COMPLETE_CAPTURE')
 return len(rows)
def qualification(q,bootstrap,image):
 S.need(q['schema']==4 and q['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY'and q['binding']==bootstrap['source']and q['dispatch_sha256']==bootstrap['dispatch_sha256']and q['provider_phase_sha256']==S.pin(S.canonical(bootstrap))['sha256']and q['image_id']==image and q['native_acceptance']is False and q['holds_preserved']is True,'BOOTSTRAP_NATIVE_QUALIFICATION_BINDING')
 ro=q['readonly_stage0'];S.need(ro['paths']==['/stage0','/work/build/stage0']and all(ro[k]is True for k in('readonly','namespace_permissions_verified','write_attempts_denied','alias_write_attempts_denied'))and [r['errno']for r in ro['attempts']]==[30,30]and all(r['denied']is True and r['path']==path for r,path in zip(ro['attempts'],ro['paths'])),'QUALIFIED_BOTH_STAGE0_ALIASES_EROFS')
 S.need(len(q['probe_receipts'])==9,'QUALIFICATION_NINE_PROBES')
 for row,argv in zip(q['probe_receipts'],PROBES):S.need(row['argv']==argv and row['returncode']==0,'QUALIFICATION_PROBE_VECTOR');natural(row['lifecycle'])
 for key in('rootfs_tree_sha256','qualified_llvm_tree_sha256','stage0_tree_sha256','library_cargo_config_sha256','source_tree_sha256'):S.need(S.digest(q[key]),'QUALIFICATION_WHOLE_TREE_PIN')

def producer(p,a,selected,finished):
 S.need(p['schema']==1 and p['status']=='COMPLETED_EXPORTED_RETIRED'and p['operation']=='rust199-source-reference-native-v1'and p['source']==a['source']and p['image']==a['image']['id']and p['prepare_completed']is True and p['makepkg_completed']is True and p['owned_resources_absent']is True and p['errors']==[]and not p.get('cleanup_errors')and not p.get('forced_daemon_cleanup')and not p.get('diagnostic_export_only'),'PRODUCER_COMPLETE_NATURAL_ONLY')
 S.need(p['root_admission_sha256']==S.pin(S.canonical(a))['sha256']and all(p[k]is False for k in('native_acceptance','hardware_acceptance','release_acceptance')),'PRODUCER_OPERATIONAL_ADMISSION_NO_CREDIT');natural(p['export']['lifecycle'])
 S.need(p['source']['run']==selected['run']and p['source']['job']==selected['build_job'],'PRODUCER_CURRENT_BUILD_JOB')
 token=S.pin(S.canonical(a['source']))['sha256'][:24];base='rust199-'+token;owner=dict(source=a['source'],image=a['image']['id'],root_admission_sha256=p['root_admission_sha256'],token=token,init=base+'-init',prepare=base+'-prepare',makepkg=base+'-makepkg',volume=base+'-work',operation='rust199-source-reference-native-v1')
 S.need(p['volume_binding']==owner and p['actors']=={k:owner[k]for k in('init','prepare','makepkg')}and p['volume']==owner['volume'],'EXACT_DERIVED_OWNED_ACTORS_AND_VOLUME')
 for role in('init','prepare','makepkg'):
  row=finished[role];S.need(row['Name']=='/'+p['actors'][role]and row['Image']==p['image']and re.fullmatch('[0-9a-f]{64}',row['Id']),'FINISHED_SAME_OWNED_ACTOR');state=row['State']
  S.need(state['Status']=='exited'and state['ExitCode']==0 and state['Running']is False and state['OOMKilled']is False and not state.get('Restarting')and not state.get('Error'),'FINISHED_ACTOR_NATURAL_ZERO')
  labels=row['Config']['Labels'];S.need(labels['cachy-asahi.source']==selected['source']and labels['cachy-asahi.run']==selected['run']and labels['cachy-asahi.job']==selected['build_job']and labels['cachy-asahi.role']==role and labels['cachy-asahi.token']==p['volume_binding']['token']and labels['cachy-asahi.operation']=='rust199-source-reference-native-v1','FINISHED_ACTOR_LABEL_BINDING')

def actor_output(data,package_pin,a,source,q,volume_sha):
 phases={};commands=[];expected_root=S.pin(S.canonical(a))['sha256'];reference=S.pin(source['packages/port/rust199-source-reference/reference.py'][0])['sha256'];config=S.pin(source['packages/port/rust199-source-reference/bootstrap.toml'][0])['sha256']
 env=dict(PATH=f'/stage0/bin:{LLVM}/bin:/usr/bin:/bin',HOME='/work/build/home',CARGO_HOME='/work/build/cargo-home',LIBGIT2_NO_VENDOR='1',LIBSSH2_SYS_USE_PKG_CONFIG='1',LIBSQLITE3_SYS_USE_PKG_CONFIG='1',CARGO_NET_OFFLINE='true',CACHY_ASAHI_RUST199_STAGE0_SHA256=q['stage0_tree_sha256'],CACHY_ASAHI_RUST199_BUILD='1',CACHY_ASAHI_RUST199_ADMISSION='/inputs/candidate-admission.json',CACHY_ASAHI_RUST199_ADMISSION_SHA256=a['candidate_admission']['sha256'],LC_ALL='C',TZ='UTC',DESTDIR='/work/build/dest',MAKEFLAGS='-j2',ROOT_ADMISSION_SHA256=expected_root,SOURCE_MAP_SHA256=S.SOURCE['map_sha256'],CONTRACT_SHA256=S.pin(source['contract.json'][0])['sha256'],WORK_VOLUME_ADMISSION_SHA256=volume_sha,PYTHONDONTWRITEBYTECODE='1')
 environment_sha=S.pin(S.canonical(env))['sha256']
 for name,raw in data.items():
  if name.startswith('phase-')and name.endswith('.json'):
   r=S.decode(raw);action=r['action'];S.need(action in('prepare','build','package','makepkg')and action not in phases,'EXACT_FOUR_ACTOR_ACTIONS');S.need(r['schema']==1 and r['status']=='COMPLETED_ACTOR_ACTION_DATA'and r['root_admission_sha256']==expected_root and r['native_acceptance']is False and r['holds_preserved']is True and not r.get('error')and not r.get('finalization_error'),'ACTOR_ACTION_COMPLETE');phases[action]=r
  if name.startswith('cmd-')and name.endswith('.json'):
   r=S.decode(raw);natural(r['lifecycle']);S.need(r['schema']==1 and r['returncode']==0 and r['phase']in('prepare','build','package','makepkg')and r['environment_sha256']==environment_sha and r['cwd']==('/work/recipe'if r['phase']=='makepkg'else '/work/build'if r['phase']=='prepare'else '/work/build/rustc-1.99.0-src')and r['capture']is(r['phase']=='makepkg'and r['argv']==['/usr/bin/pacman','-Q']or r['argv']in PROBES),'ACTOR_COMMAND_RECEIPT')
   for stream in('stdout','stderr'):
    v=r[stream];S.need(v['file']in data and S.pin(data[v['file']])=={k:v[k]for k in('bytes','sha256')}and v['file']==name[:-5]+'.'+stream,'ACTOR_COMMAND_COMPLETE_LOG_PIN')
   commands.append(r)
 S.need(set(phases)=={'prepare','build','package','makepkg'},'EXACT_FOUR_ACTOR_ACTIONS')
 for action in('prepare','build','package'):
  r=phases[action]['phase'];S.need(r['status']=='COMPLETED_NATIVE_PHASE_DATA'and r['phase']==action and r['candidate_sha256']==reference and r['candidate_admission_sha256']==a['candidate_admission']['sha256']and r['stage0_tree_sha256']==q['stage0_tree_sha256']and r['native_acceptance']is False and r['holds_preserved']is True,'NATIVE_PHASE_SOURCE_AND_QUALIFICATION')
  counts=dict(extract=5,probe=0,build=0,project=0)if action=='prepare'else dict(extract=0,probe=9,build=1,project=2)if action=='build'else dict(extract=0,probe=0,build=0,project=0);S.need(r['commands']==counts,'EXACT_NATIVE_PHASE_COMMAND_COUNTS')
 S.need(phases['makepkg']['command']==0 and phases['makepkg']['package']==package_pin,'MAKEPKG_PACKAGE_WHOLE_PIN')
 prepared=S.decode(data['prepared.json']);built=S.decode(data['built.json']);S.need(prepared==dict(admission_sha256=a['candidate_admission']['sha256'],config_sha256=config)and built['admission_sha256']==prepared['admission_sha256']and built['config_sha256']==config and S.digest(built['staged_tree_sha256']),'PREPARED_BUILT_PROVENANCE')
 for key in('prepared.json','built.json','inventory'):
  field=phases['makepkg'][key];S.need(field['file']in data and S.pin(data[field['file']])=={k:field[k]for k in('bytes','sha256')},'MAKEPKG_RETAINED_PROVENANCE_PIN')
 materials=S.decode(source['packages/port/rust199-source-reference/inputs.json'][0])['archives'];extracts=[['/usr/bin/bsdtar','--no-same-owner','--no-same-permissions','-xf','/work/build/verified-materials/'+name,'-C','/work/build/stage0-unpack'if row['role']=='stage0'else'/work/build']for name,row in materials.items()]
 S.need(len(materials)==5 and sorted(map(str,[r['argv']for r in commands if r['phase']=='prepare']))==sorted(map(str,extracts))and not any(r['phase']=='package'for r in commands),'EXACT_FIVE_EXTRACTIONS_NO_PACKAGE_COMMAND')
 vectors=[r['argv']for r in commands if r['phase']=='build'];S.need(len(vectors)==10 and sorted(map(str,vectors))==sorted(map(str,[*PROBES,BUILD])),'NINE_STAGE0_PROBES_AND_ONE_BUILD')
 own=[r['argv']for r in commands if r['phase']=='makepkg'];S.need(sorted(map(str,own))==sorted(map(str,[['/usr/bin/pacman','-Q'],MAKEPKG])),'EXACT_MAKEPKG_AND_INVENTORY_COMMANDS')
 # No receipt timestamps/order are emitted. Do not invent command ordering evidence.
 return dict(actor_actions=4,commands=len(commands),built_stage_tree_sha256=built['staged_tree_sha256'],command_order='NOT_EMITTED',new_tool_runtime='NOT_EMITTED_NOT_QUALIFIED')

def inspected(row,final,role,p,a,source):
 S.need(row['Id']==final['Id']and row['Name']==final['Name']and row['Image']==p['image']and row['State']['Status']=='created'and row['State']['Running']is False,'INITIAL_SAME_UNSTARTED_ACTOR')
 config,host=row['Config'],row['HostConfig'];init=role=='init'
 S.need(config['User']==('0:0'if init else'1001:1001')and host['Memory']==host['MemorySwap']==(128*S.MIB if init else 8*S.GIB)and host['PidsLimit']==(32 if init else 512)and host['NanoCpus']==2000000000,'ACTOR_EXACT_USER_RESOURCES')
 S.need(host['ReadonlyRootfs']is True and host['NetworkMode']=='none'and host['CapDrop']==['ALL']and(host.get('CapAdd')in(['CHOWN'],['CAP_CHOWN'])if init else host.get('CapAdd')in(None,[]))and host['Privileged']is False and host['SecurityOpt']==['no-new-privileges']and host['Init']is True and host['IpcMode']=='private'and host['CgroupnsMode']=='private','ACTOR_EXACT_ISOLATED_DOMAIN')
 S.need(not any(host.get(k)for k in('Devices','DeviceRequests','Binds','VolumesFrom','Links','ExtraHosts','UsernsMode','PidMode'))and host['RestartPolicy']['Name']=='no'and host['LogConfig']==dict(Type='none',Config={})and {r['Name']:(r['Soft'],r['Hard'])for r in host['Ulimits']}==dict(nofile=(1024,1024),core=(0,0)),'ACTOR_NO_EXTRA_AUTHORITY')
 if init:
  S.need(config['Entrypoint']==['/usr/bin/python']and config['WorkingDir']=='/'and len(config['Cmd'])==5 and config['Cmd'][:3]==['-I','-B','-c']and S.pin(config['Cmd'][3].encode())['sha256']==INIT_CODE_SHA256 and S.decode(config['Cmd'][4].encode())==p['volume_binding']and not host.get('Tmpfs'),'INITIALIZER_FIXED_CHMOD_BEFORE_CHOWN')
 else:
  S.need(host['Tmpfs']=={'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'},'ACTOR_EXACT_BOUNDED_TMPFS')
 if init:
  actual=row['Mounts'];configured=host['Mounts'];S.need(len(actual)==len(configured)==1 and actual[0]['Destination']==configured[0]['Target']=='/work'and actual[0]['Type']==configured[0]['Type']=='volume'and actual[0]['RW']is True and configured[0].get('ReadOnly',False)is False and actual[0]['Name']==configured[0]['Source']==p['volume']and actual[0].get('Driver')=='local'and volume_options(configured[0].get('VolumeOptions'),dict(NoCopy=True)),'INITIALIZER_EXACT_OWNED_NOCOPY_VOLUME');return
 S.need(config['Hostname']=='rust199-native'and config['WorkingDir']=='/work'and config['Entrypoint']==['/usr/bin/python']and config['Cmd']==['-I','-B','/source/actor/entry.py',role],'ACTOR_EXACT_ENTRY_VECTOR')
 env=dict(item.split('=',1)for item in config['Env']);pins=dict(ROOT_ADMISSION_SHA256=S.pin(S.canonical(a))['sha256'],SOURCE_MAP_SHA256=S.SOURCE['map_sha256'],CONTRACT_SHA256=S.pin(source['contract.json'][0])['sha256'],WORK_VOLUME_ADMISSION_SHA256=p['volume_admission_sha256'])
 S.need(all(env.get(k)==v for k,v in pins.items())and not any(k.startswith(('LD_','DOCKER_','PYTHON','CACHY_OLD_','CACHY_RETAINED_'))for k in env),'ACTOR_EXACT_ADMISSION_ENVIRONMENT')
 actual={r['Destination']:r for r in row['Mounts']};configured={r['Target']:r for r in host['Mounts']};materials={r['name']:r for r in a['materials']};wanted={'/work','/inputs','/source'}|{'/materials/'+name for name in materials}
 if role=='makepkg':wanted|={'/stage0','/work/build/stage0'}
 S.need(set(actual)==set(configured)==wanted and len(actual)==len(row['Mounts'])==len(host['Mounts']),'ACTOR_EXACT_MOUNT_NAMESPACE')
 for target in wanted:
  r,c=actual[target],configured[target];volume=target in('/work','/stage0','/work/build/stage0');readonly=target!='/work'
  S.need(r['Type']==c['Type']==('volume'if volume else'bind')and r['RW']is not readonly and c.get('ReadOnly',False)is readonly and r.get('Propagation','')in('','rprivate'),'ACTOR_MOUNT_ACCESS')
  if volume:
   options=dict(NoCopy=True)
   if target!='/work':options['Subpath']='build/stage0'
   S.need(r['Name']==c['Source']==p['volume']and r.get('Driver')=='local'and volume_options(c.get('VolumeOptions'),options),'ACTOR_EXACT_NOCOPY_STAGE0_SUBPATH')
  else:
   S.need(c['Source']==r['Source']and not c.get('BindOptions'),'ACTOR_READONLY_BIND')
   if target.startswith('/materials/'):S.need(r['Source']==materials[target.rsplit('/',1)[1]]['local_path'],'ACTOR_WHOLE_MATERIAL_BIND')


def volume_options(raw,expected):
 # Docker's explicit empty default driver is the only admitted normalization.
 return (type(raw)is dict and type(expected)is dict and
  ('NoCopy'not in expected or raw.get('NoCopy')is expected['NoCopy'])and
  ('DriverConfig'not in raw or expected.get('NoCopy')is True and type(raw['DriverConfig'])is dict and raw['DriverConfig']=={})and
  {k:v for k,v in raw.items()if k!='DriverConfig'}==expected)

def custody_operations(rows,corpus,phase,selected,image):
 """Join acknowledged CIDs through ordered retained daemon observations only."""
 S.need(phase in('bootstrap','build')and re.fullmatch('sha256:[0-9a-f]{64}',image)is not None,'CUSTODY_PHASE_IMAGE')
 bootstrap=phase=='bootstrap';roles=('init','data','probe')if bootstrap else('init','prepare','makepkg')
 binding=dict(sha=selected['source'],ref=selected['ref'],run=selected['run'],job=selected['bootstrap_job'if bootstrap else'build_job'])
 if not bootstrap:binding.update(map_sha256=S.SOURCE['map_sha256'],approval=selected['source_review_sha256'])
 token=S.pin(S.canonical(binding))['sha256'][:24];base=('rust199-qual-'if bootstrap else'rust199-')+token
 names={base+'-'+role:role for role in roles};volume=base+'-work';ids={};last={};started=set();retired=set();volume_path=None
 rootfs_binding=dict(source=selected['source'],ref=selected['ref'],run=selected['run'],job=selected['bootstrap_job'],source_map_sha256=S.SOURCE['map_sha256'],approval=selected['source_review_sha256'])
 rootfs_token=S.pin(S.canonical(rootfs_binding))['sha256'][:24];rootfs_name='rust199-rootfs-'+rootfs_token;rootfs_id=None;rootfs_seen=False;rootfs_retired=False
 rootfs_labels={'cachy-asahi.rust199-bootstrap':rootfs_token,'cachy-asahi.rust199-bootstrap.source':selected['source']}
 def labels(role):return {'cachy-asahi.'+k:v for k,v in dict(operation='rust199-source-reference-native-v1',source=binding['sha'],run=binding['run'],job=binding['job'],token=token,role=('qualification-'if bootstrap else'')+role).items()}
 def stream(row):
  ref=row['stdout'];raw=corpus.member(phase+'/'+ref['file'],8*S.MIB);S.need(S.pin(raw)=={k:ref[k]for k in('bytes','sha256')},'CUSTODY_STREAM_WHOLE_PIN');return raw
 def one(row):
  value=S.decode(stream(row));S.need(type(value)is list and len(value)==1 and type(value[0])is dict,'CUSTODY_ONE_DAEMON_OBJECT');return value[0]
 def owned(row,role,name):
  S.need(row['Id']==ids[role]and row['Name']=='/'+name and row['Image']==image and all(row['Config']['Labels'].get(k)==v for k,v in labels(role).items()),'CUSTODY_SAME_ACKNOWLEDGED_OWNER_IMAGE')
  state=row['State'];S.need(state['Status']in('created','exited')and state['Running']is False and not state.get('OOMKilled')and not state.get('Restarting')and not state.get('Error'),'CUSTODY_NATURAL_STOPPED_ACTOR')
  if role in started:S.need(state['Status']=='exited'and type(state.get('ExitCode'))is int and state['ExitCode']==0,'CUSTODY_NATURAL_ZERO_AFTER_START')
  else:S.need(state['Status']=='created','CUSTODY_UNSTARTED_CREATED_ACTOR')
  configured=row['HostConfig']['Mounts'];actual=row['Mounts'];c={v['Target']:v for v in configured};a={v['Destination']:v for v in actual}
  S.need(volume_path is not None and len(c)==len(configured)==len(a)==len(actual)and set(c)==set(a)and '/work'in c,'CUSTODY_EXACT_MOUNT_NAMESPACE')
  wanted={'/work'}if role=='init'else{'/work','/inputs','/source'}|{'/materials/'+n for n in ('cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz','llvm-project-23.1.1.src.tar.xz','rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz','rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz','rustc-1.99.0-src.tar.xz')}
  if role in('probe','makepkg'):wanted|={'/stage0','/work/build/stage0'}
  S.need(set(c)==wanted,'CUSTODY_EXACT_ROLE_MOUNT_NAMESPACE')
  for target,want in c.items():
   S.need(set(want)<={'Type','Source','Target','ReadOnly','Consistency','BindOptions','VolumeOptions'}and not want.get('BindOptions')and want.get('Consistency','')in('','default'),'CUSTODY_FINITE_CONFIGURED_MOUNT_OPTIONS')
   observed=a[target];S.need(want['Type']==observed['Type']==('volume'if target in('/work','/stage0','/work/build/stage0')else'bind')and observed['RW']is(not want.get('ReadOnly',False))and observed.get('Propagation','')in('','rprivate'),'CUSTODY_MOUNT_ACCESS')
   if want['Type']=='volume':
    subpath='build/stage0'if target in('/stage0','/work/build/stage0')else''
    expected=dict(NoCopy=True)
    if subpath:expected['Subpath']=subpath
    S.need(target in('/work','/stage0','/work/build/stage0')and want['Source']==observed['Name']==volume and observed.get('Driver')=='local'and volume_options(want.get('VolumeOptions'),expected)and observed['Source']==volume_path+('/'+subpath if subpath else''),'CUSTODY_EXACT_VOLUME_SOURCE_SUBPATH')
    S.need(want.get('ReadOnly',False)is(target!='/work'),'CUSTODY_VOLUME_ACCESS')
   else:S.need(want['Type']=='bind'and want.get('ReadOnly')is True and observed['Source']==want['Source']and not want.get('BindOptions')and not want.get('VolumeOptions'),'CUSTODY_READONLY_BIND_SOURCE')
  last[role]=row
 for row in rows:
  natural(row['lifecycle'],False);S.need(type(row['returncode'])is int and row['lifecycle']['exit']==row['returncode'],'CUSTODY_OPERATION_EXIT_JOIN')
  argv=row['argv']
  if argv[:2]!=['/usr/bin/docker','--host=unix:///var/run/docker.sock']:continue
  args=argv[2:]
  # The separate unstarted bootstrap rootfs DATA exporter is not a qualifier.
  if bootstrap and args[:1]==['create']and '--name'in args and args[args.index('--name')+1]==rootfs_name:
   raw=stream(row);pairs=[args[i+1].split('=',1)for i,arg in enumerate(args)if arg=='--label'];given=dict(pairs)
   S.need(row['returncode']==0 and rootfs_id is None and args.count('--name')==1 and args.count(image)==1 and len(given)==len(pairs)and all(given.get(k)==v for k,v in rootfs_labels.items())and re.fullmatch(rb'[0-9a-f]{64}\n',raw)is not None,'CUSTODY_ROOTFS_DATA_CREATE');rootfs_id=raw[:-1].decode('ascii');S.need(rootfs_id not in ids.values(),'CUSTODY_NO_REUSED_ROLE_OR_CID');continue
  if bootstrap and args[:2]==['container','inspect']and args[-1]==rootfs_name:
   v=one(row);S.need(rootfs_id is not None and row['returncode']==0 and v['Id']==rootfs_id and v['Name']=='/'+rootfs_name and v['Image']==image and v['State']['Status']=='created'and v['State']['Running']is False and not v['Mounts']and not rootfs_retired and all(v['Config']['Labels'].get(k)==x for k,x in rootfs_labels.items()),'CUSTODY_ROOTFS_UNSTARTED_DATA_IDENTITY');rootfs_seen=True;continue
  if bootstrap and args==['container','rm',rootfs_id]:
   S.need(row['returncode']==0 and rootfs_seen and not rootfs_retired,'CUSTODY_ROOTFS_DATA_REMOVE');rootfs_retired=True;continue
  S.need(args[:1]not in(['stop'],['kill'])and args[:2]not in(['container','stop'],['container','kill']),'CUSTODY_NO_FORCED_ACTOR_OPERATION')
  if args[:2]==['volume','inspect']and args[-1]==volume:
   S.need(row['returncode']==0,'CUSTODY_VOLUME_INSPECT_EXIT');v=one(row)
   S.need(v['Name']==volume and v['Driver']=='local'and not v.get('Options')and all(v['Labels'].get(k)==x for k,x in labels('volume').items())and type(v['Mountpoint'])is str and v['Mountpoint'].startswith('/')and not v['Mountpoint'].endswith('/'),'CUSTODY_OWNED_VOLUME_OBSERVATION')
   S.need(volume_path in(None,v['Mountpoint']),'CUSTODY_STABLE_VOLUME_SOURCE');volume_path=v['Mountpoint']
  elif args[:1]==['create']:
   S.need(row['returncode']==0 and args.count('--name')==1,'CUSTODY_CREATE_NAME_EXIT');name=args[args.index('--name')+1]
   S.need(name in names and image in args and args.count(image)==1,'CUSTODY_EXACT_CREATE_NAME_IMAGE');role=names[name]
   pairs=[args[i+1].split('=',1)for i,arg in enumerate(args)if arg=='--label'];given=dict(pairs)
   S.need(len(given)==len(pairs)and all(given.get(k)==v for k,v in labels(role).items()),'CUSTODY_CREATE_OWNER_LABELS')
   raw=stream(row);S.need(re.fullmatch(rb'[0-9a-f]{64}\n',raw)is not None,'CUSTODY_FULL_CREATE_ACKNOWLEDGEMENT');cid=raw[:-1].decode('ascii')
   S.need(role not in ids and cid not in ids.values()and cid!=rootfs_id,'CUSTODY_NO_REUSED_ROLE_OR_CID');ids[role]=cid
  elif args[:2]==['container','inspect']:
   name=args[-1];S.need(name in names and names[name]in ids and names[name]not in retired and row['returncode']==0,'CUSTODY_INSPECT_ACKNOWLEDGED_NAME');owned(one(row),names[name],name)
  elif args[:1]==['start']:
   S.need(len(args)==3 and args[1]=='--attach'and args[2]in names and row['returncode']==0,'CUSTODY_EXACT_START');role=names[args[2]]
   S.need(role in last and role not in started and role not in retired,'CUSTODY_START_AFTER_IDENTITY');started.add(role);last.pop(role)
  elif args[:2]==['container','rm']:
   S.need(len(args)==3 and args[2]in ids.values()and row['returncode']==0,'CUSTODY_EXACT_CID_NATURAL_REMOVE');role=next(k for k,v in ids.items()if v==args[2])
   S.need(role in last and role in started and role not in retired and last[role]['State']['Status']=='exited','CUSTODY_REMOVE_AFTER_NATURAL_INSPECTION');retired.add(role);last.pop(role)
 S.need(rootfs_id is None or rootfs_retired,'CUSTODY_ROOTFS_DATA_RETIREMENT')
 S.need(set(ids)==started==retired==set(roles),'CUSTODY_COMPLETE_ACKNOWLEDGED_NATURAL_RETIREMENT')
 return ids
