# SPDX-License-Identifier: MIT
"""Replay only the concrete receipts emitted by the frozen Rust actor/producer."""
import re
S=None
LLVM='/opt/cachy-asahi/llvm23-source-reference'
PROBES=[['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','-vV'],['/stage0/bin/rustc','--print','sysroot'],['/stage0/bin/cargo','--version'],['/stage0/bin/rustdoc','--version'],[LLVM+'/bin/llvm-config','--version'],[LLVM+'/bin/llvm-config','--targets-built'],['/usr/bin/gcc','-dumpmachine'],[LLVM+'/bin/ld.lld','--version']]
BUILD=['/usr/bin/python','-I','-B','./x.py','--config','bootstrap.toml','install','-j','2']
OPERATIONAL_RESOURCES=dict(cpus=2,memory_bytes=8*1024**3,memory_swap_bytes=8*1024**3,swap_bytes=0,pids=512,prepare_actor_seconds=900,build_actor_seconds=16200,native_seconds=19800,cleanup_seconds=300,export_bytes=4*1024**3,package_bytes=2*1024**3,log_bytes=64*1024**2,job_minutes=360,minimum_host_memory_bytes=12*1024**3,minimum_host_disk_bytes=80*1024**3,minimum_host_available_inodes=1000000,active_host_memory_reserve_bytes=4*1024**3,active_host_disk_reserve_bytes=8*1024**3)
INIT_CODE_SHA256='e3da33c401407b1d0bc04caa5a67bde354a0ad54727450003cda5f57c611fc1a'
MAKEPKG=['/usr/bin/makepkg','--noextract','--noprepare','--nosign','--noconfirm','--log','--config','/source/actor/makepkg.conf']

def kernel_mountinfo(raw,profile):
 """Independently parse retained kernel DATA; never read a live proc filesystem."""
 S.need(type(raw)is bytes and 0<len(raw)<=S.MIB and raw.endswith(b'\n')and b'\r'not in raw and b'\0'not in raw,'MOUNTINFO_WHOLE_RAW_BOUNDS')
 S.need(profile in('work-only','stage0-aliases'),'MOUNTINFO_PROFILE')
 try:lines=raw.decode('ascii').splitlines()
 except UnicodeDecodeError:raise S.Hold('MOUNTINFO_ASCII')
 S.need(1<=len(lines)<=4096,'MOUNTINFO_ROW_BOUND')
 escape={'040':' ','011':'\t','012':'\n','134':'\\'}
 def decoded_path(text):
  S.need(type(text)is str and text.startswith('/')and len(text)<=16384,'MOUNTINFO_ABSOLUTE_PATH')
  parts=[];index=0
  while index<len(text):
   if text[index]=='\\':
    code=text[index+1:index+4];S.need(len(code)==3 and code in escape,'MOUNTINFO_UNAMBIGUOUS_ESCAPE');parts.append(escape[code]);index+=4
   else:parts.append(text[index]);index+=1
  value=''.join(parts)
  # No recursive unescaping, alias roots or alternate spellings of fixed paths.
  S.need('\\'not in value and not any(ord(c)<32 or ord(c)==127 for c in value)and
   (value=='/'or not value.endswith('/'))and '//'not in value and
   not any(p in('.','..')for p in value.split('/')),'MOUNTINFO_CANONICAL_PATH')
  return value
 rows={};ids=set()
 for line in lines:
  S.need(len(line)<=8192 and line.count(' - ')==1,'MOUNTINFO_TYPED_SEPARATOR')
  first,last=line.split(' - ');fields=first.split(' ');tail=last.split(' ')
  S.need(len(fields)>=6 and len(tail)==3 and all(fields+tail),'MOUNTINFO_TYPED_COLUMNS')
  mount_id,parent,device,root,target,options=fields[:6]
  S.need(re.fullmatch('[1-9][0-9]{0,19}',mount_id)is not None and re.fullmatch('[1-9][0-9]{0,19}',parent)is not None and
   re.fullmatch('(0|[1-9][0-9]{0,19}):(0|[1-9][0-9]{0,19})',device)is not None,'MOUNTINFO_IDS_DEVICE')
  root,target=decoded_path(root),decoded_path(target)
  S.need(int(mount_id)not in ids and target not in rows,'MOUNTINFO_UNIQUE_TARGETS_IDS');ids.add(int(mount_id))
  flags=options.split(',');super_flags=tail[2].split(',')
  S.need(len(flags)==len(set(flags))and len(super_flags)==len(set(super_flags))and
   ('ro'in flags)^('rw'in flags)and ('ro'in super_flags)^('rw'in super_flags)and all(re.fullmatch('[A-Za-z0-9_.:+/-]+(?:=[A-Za-z0-9_.:+/-]+)?',v)is not None for v in flags+super_flags),'MOUNTINFO_OPTION_SYNTAX')
  S.need(re.fullmatch('[A-Za-z0-9_.+-]+',tail[0])is not None and '\\'not in tail[1]and all(32<ord(c)<127 for c in tail[1]), 'MOUNTINFO_FILESYSTEM_SOURCE')
  S.need(all(re.fullmatch('[A-Za-z0-9_.+-]+(?::[0-9]+)?',v)is not None for v in fields[6:]),'MOUNTINFO_OPTIONAL_COLUMNS')
  rows[target]=dict(mount_id=int(mount_id),parent_id=int(parent),device=device,
   root=root,target=target,options=sorted(flags),fs_type=tail[0],source=tail[1],super_options=sorted(super_flags),optional=fields[6:])
 S.need('/'in rows and '/work'in rows,'MOUNTINFO_WORK_REQUIRED');work=rows['/work']
 S.need('ro'in rows['/']['options']and 'rw'not in rows['/']['options'],'MOUNTINFO_ROOT_FILESYSTEM_READONLY')
 S.need(work['parent_id']==rows['/']['mount_id'],'MOUNTINFO_WORK_VISIBLE_ROOT_PARENT')
 S.need('rw'in work['options']and 'ro'not in work['options'],'MOUNTINFO_WORK_WRITABLE')
 S.need('rw'in work['super_options']and 'ro'not in work['super_options'],'MOUNTINFO_WORK_SUPERBLOCK_WRITABLE')
 aliases=('/stage0','/work/build/stage0')
 expected=work['root'].rstrip('/')+'/build/stage0'
 if profile=='work-only':
  S.need(not any(p in rows for p in aliases),'MOUNTINFO_WORK_ONLY_NO_STAGE0_ALIASES')
 else:
  S.need(all(p in rows for p in aliases),'MOUNTINFO_BOTH_ALIAS_TARGETS')
  for target in aliases:
   row=rows[target]
   S.need(row['root']==expected and all(row[k]==work[k]for k in('device','fs_type','source','super_options')),
    'MOUNTINFO_EXACT_ALIAS_ROOT_DEVICE_FILESYSTEM')
   S.need('ro'in row['options']and 'rw'not in row['options'],'MOUNTINFO_ALIAS_READONLY')
  S.need(rows['/work/build/stage0']['parent_id']==work['mount_id'],'MOUNTINFO_NESTED_ALIAS_PARENT')
  S.need(rows['/stage0']['parent_id']==work['parent_id'],'MOUNTINFO_TOP_ALIAS_PARENT')
 # A nested bind could obscure a binary after a superficially correct alias row.
 for target in rows:
  S.need(not any(target.startswith(alias+'/')for alias in aliases),'MOUNTINFO_NO_ALIAS_SHADOW_MOUNT')
  S.need(not target.startswith('/work/')or target=='/work/build/stage0','MOUNTINFO_NO_WORK_SHADOW_MOUNT')
 selected={p:rows[p]for p in('/work',*aliases)if p in rows}
 S.need(all(not any(v.split(':',1)[0]in('shared','master','propagate_from','unbindable')for v in row['optional'])for row in selected.values()),'MOUNTINFO_SELECTED_PRIVATE_PROPAGATION')
 return dict(profile=profile,alias_root=expected if profile=='stage0-aliases'else None,mounts=selected)

def api_volume_source(observed,volume_path,subpath):
 """Representation check only; every new full Reader path also requires kernel proof."""
 S.need(type(volume_path)is str and volume_path.startswith('/')and not volume_path.endswith('/')and
  '//'not in volume_path and not any(p in('.','..')for p in volume_path.split('/'))and subpath in('','build/stage0'),'MOUNTINFO_API_VOLUME_PATH')
 wanted=volume_path+('/'+subpath if subpath else'')
 S.need(observed.get('Source')in({volume_path,wanted}if subpath else{volume_path})and
  ('Subpath'not in observed or observed['Subpath']==subpath),'MOUNTINFO_API_EXACT_VOLUME_SOURCE')
 return observed['Source']

def kernel_proof(envelope,read_member,context,profile,helper_sha256):
 """Replay whole retained raw/receipt and exact actor context; grants no authority."""
 S.need(type(envelope)is dict and set(envelope)=={'receipt','mountinfo'},'MOUNTINFO_EXACT_ENVELOPE')
 S.need(type(context)is dict and set(context)=={'source','dispatch_sha256','input_admission_sha256','image_id','volume_token','phase'},'MOUNTINFO_TYPED_CONTEXT')
 source=context['source'];S.need(type(source)is dict and set(source)=={'sha','ref','map_sha256','approval','run','job'}and
  re.fullmatch('[0-9a-f]{40}',source['sha']or'')is not None and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',source['ref']or'')is not None and
  all(S.digest(source[k])for k in('map_sha256','approval'))and all(S.numeric(source[k])for k in('run','job')),'MOUNTINFO_TYPED_SOURCE_CONTEXT')
 S.need(all(S.digest(context[k])for k in('dispatch_sha256','input_admission_sha256'))and
  re.fullmatch('sha256:[0-9a-f]{64}',context['image_id']or'')is not None and context['volume_token']==S.pin(S.canonical(source))['sha256'][:24],'MOUNTINFO_TYPED_IMAGE_ADMISSION_TOKEN')
 phase=context['phase'];S.need(phase in('qualification-data','qualification-probe','prepare','makepkg','build','package'),'MOUNTINFO_FIXED_PHASE')
 raw_ref,receipt_ref=envelope['mountinfo'],envelope['receipt']
 for ref in(raw_ref,receipt_ref):
  S.need(type(ref)is dict and set(ref)=={'file','bytes','sha256'}and type(ref['bytes'])is int and 0<ref['bytes']<=S.MIB and S.digest(ref['sha256']),'MOUNTINFO_TYPED_WHOLE_REF');S.relative(ref['file'])
 if phase.startswith('qualification-'):
  suffix=phase
  S.need(raw_ref['file']=='kernel-mountinfo-'+suffix+'.raw'and receipt_ref['file']=='kernel-mount-proof-'+suffix+'.json','MOUNTINFO_FIXED_QUALIFICATION_FILES')
 else:
  match=re.fullmatch(r'kernel-mountinfo-('+phase+r'-[1-9][0-9]{0,19}-[0-9a-f]{32})\.raw',raw_ref['file'])
  S.need(match is not None and receipt_ref['file']=='kernel-mount-proof-'+match.group(1)+'.json','MOUNTINFO_SAME_ACTOR_INVOCATION_FILES')
 try:raw,receipt_raw=read_member(raw_ref['file']),read_member(receipt_ref['file'])
 except(KeyError,FileNotFoundError):raise S.Hold('MOUNTINFO_RETAINED_FILE_MISSING')
 S.need(S.pin(raw)=={k:raw_ref[k]for k in('bytes','sha256')}and S.pin(receipt_raw)=={k:receipt_ref[k]for k in('bytes','sha256')},'MOUNTINFO_WHOLE_RETAINED_PROOF_RAW')
 doc=S.decode(receipt_raw)
 S.need(receipt_raw==S.canonical(doc)and set(doc)=={'schema','status','context','profile','helper_sha256','mountinfo','mounts','alias_root','order','native_acceptance','holds_preserved'},'MOUNTINFO_EXACT_RECEIPT_SCHEMA')
 S.need(type(doc['schema'])is int and doc['schema']==13 and doc['status']=='PASS_KERNEL_MOUNTINFO_PREENTRY_DATA_ONLY'and
  doc['context']==context and doc['profile']==profile and doc['helper_sha256']==helper_sha256 and S.digest(helper_sha256)and
  S.canonical(doc['mountinfo'])==S.canonical(raw_ref)and doc['native_acceptance']is False and doc['holds_preserved']is True,'MOUNTINFO_EXACT_SOURCE_HELPER_CONTEXT')
 expected_order=dict(stage='BEFORE_WORKSPACE_MUTATION_AND_TOOLS',commands_before=0,workspace_writes_before=0)
 S.need(doc['order']==expected_order and all(type(doc['order'][k])is int for k in('commands_before','workspace_writes_before')),'MOUNTINFO_SOURCE_ENFORCED_PREENTRY_ONLY')
 replay=kernel_mountinfo(raw,profile)
 S.need(S.canonical(doc['mounts'])==S.canonical(replay['mounts'])and doc['alias_root']==replay['alias_root'],'MOUNTINFO_INDEPENDENT_RAW_REPLAY')
 return dict(receipt_sha256=receipt_ref['sha256'],mountinfo_sha256=raw_ref['sha256'],
  mounts=replay['mounts'],profile=profile,context=context,order_scope='SOURCE_ENFORCED_NO_RETAINED_COMMAND_TIMESTAMPS')

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

def qualification_kernel(q,bootstrap,source,read_member):
 """Require both retained preentry proofs and all qualification child joins."""
 def body(ref,name):
  S.need(type(ref)is dict and set(ref)=={'file','bytes','sha256'}and ref['file']==name and
   type(ref['bytes'])is int and 0<ref['bytes']<=S.MIB and S.digest(ref['sha256']),'MOUNTINFO_QUALIFICATION_WHOLE_REF')
  raw=read_member(name);S.need(S.pin(raw)=={k:ref[k]for k in('bytes','sha256')},'MOUNTINFO_QUALIFICATION_WHOLE_BODY');return raw
 plan_raw=body(q.get('qualification_plan'),'qualification-plan.json');plan=S.decode(plan_raw)
 S.need(plan['schema']==4 and plan['status']=='ROOT_PREGRANTED_NATIVE_SOURCE_QUALIFICATION_ONLY'and
  plan['qualification_allowed']is True and plan['holds_preserved']is True and plan['provider']==bootstrap and
  plan['image_id']==q['image_id']and plan['rootfs_tree_sha256']==q['rootfs_tree_sha256']and plan['source_audit']==q['source_audit'],'MOUNTINFO_EXACT_QUALIFICATION_PLAN')
 proofs=q.get('kernel_mount_proofs');S.need(type(proofs)is dict and set(proofs)=={'qualification-data','qualification-probe'},'MOUNTINFO_BOTH_QUALIFICATION_PROOFS_REQUIRED')
 helper=S.pin(source['actor/mount_proof.py'][0])['sha256'];token=S.pin(S.canonical(bootstrap['source']))['sha256'][:24];kernels={}
 base='rust199-qual-'+token;owner=dict(source=bootstrap['source'],image=q['image_id'],root_admission_sha256=bootstrap['dispatch_sha256'],token=token,init=base+'-init',prepare=base+'-data',makepkg=base+'-probe',volume=base+'-work',operation='rust199-source-reference-native-v1')
 S.need(plan['volume_owner']==owner,'MOUNTINFO_QUALIFICATION_EXACT_VOLUME_OWNER')
 for phase,envelope in proofs.items():
  context=dict(source=bootstrap['source'],dispatch_sha256=bootstrap['dispatch_sha256'],input_admission_sha256=S.pin(plan_raw)['sha256'],image_id=q['image_id'],volume_token=token,phase=phase)
  kernels[phase]=kernel_proof(envelope,read_member,context,'work-only'if phase=='qualification-data'else'stage0-aliases',helper)
 assembly=S.decode(read_member('assembly.json'))
 S.need(assembly.get('status')=='PASS_SOURCE_STAGE0_ASSEMBLY_DATA_ONLY'and assembly.get('native_runtime_qualified')is False and
  all(assembly.get(k)==q[k]for k in('stage0_tree_sha256','source_tree_sha256','library_cargo_config_sha256'))and
  assembly.get('kernel_mount_proof')==proofs['qualification-data']and assembly.get('qualification_plan')==q['qualification_plan']and
  assembly.get('data_commands')==q.get('data_commands'),'MOUNTINFO_ASSEMBLY_PREENTRY_PROOF_JOIN')
 data=S.decode(body(q.get('data_commands'),'data-commands.json'))
 S.need(type(data)is list and len(data)==5,'MOUNTINFO_QUALIFICATION_FIVE_DATA_CHILDREN')
 initial=S.decode(source['packages/port/rust199-source-reference/inputs.json'][0])['archives']
 extracts=[['/usr/bin/bsdtar','--no-same-owner','--no-same-permissions','-xf','/materials/'+n,'-C','/work/build/stage0-unpack'if row['role']=='stage0'else'/work/build']for n,row in initial.items()]
 S.need(len(initial)==5 and sorted(map(str,[r['argv']for r in data]))==sorted(map(str,extracts)),'MOUNTINFO_QUALIFICATION_EXACT_DATA_VECTORS')
 probes=q['probe_receipts'];S.need(S.canonical(S.decode(read_member('probe-commands.json')))==S.canonical(probes),'MOUNTINFO_QUALIFICATION_PROBE_COMMAND_FILE_JOIN')
 for phase,commands in(('data',data),('probe',probes)):
  for index,row in enumerate(commands):
   natural(row['lifecycle']);S.need(type(row['returncode'])is int and row['returncode']==0 and
    row.get('kernel_mount_proof_sha256')==kernels['qualification-'+phase]['receipt_sha256'],'MOUNTINFO_EVERY_QUALIFICATION_COMMAND_PROOF_JOIN')
   for stream in('stdout','stderr'):
    S.need(row[stream]==phase+'-'+str(index)+'.'+stream,'MOUNTINFO_QUALIFICATION_FIXED_CHILD_CAPTURE');read_member(row[stream])
 return kernels

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
 phases={};phase_names={};commands=[];expected_root=S.pin(S.canonical(a))['sha256'];reference=S.pin(source['packages/port/rust199-source-reference/reference.py'][0])['sha256'];config=S.pin(source['packages/port/rust199-source-reference/bootstrap.toml'][0])['sha256']
 env=dict(PATH=f'/stage0/bin:{LLVM}/bin:/usr/bin:/bin',HOME='/work/build/home',CARGO_HOME='/work/build/cargo-home',LIBGIT2_NO_VENDOR='1',LIBSSH2_SYS_USE_PKG_CONFIG='1',LIBSQLITE3_SYS_USE_PKG_CONFIG='1',CARGO_NET_OFFLINE='true',CACHY_ASAHI_RUST199_STAGE0_SHA256=q['stage0_tree_sha256'],CACHY_ASAHI_RUST199_BUILD='1',CACHY_ASAHI_RUST199_ADMISSION='/inputs/candidate-admission.json',CACHY_ASAHI_RUST199_ADMISSION_SHA256=a['candidate_admission']['sha256'],LC_ALL='C',TZ='UTC',DESTDIR='/work/build/dest',MAKEFLAGS='-j2',ROOT_ADMISSION_SHA256=expected_root,SOURCE_MAP_SHA256=S.SOURCE['map_sha256'],CONTRACT_SHA256=S.pin(source['contract.json'][0])['sha256'],WORK_VOLUME_ADMISSION_SHA256=volume_sha,PYTHONDONTWRITEBYTECODE='1')
 environment_sha=S.pin(S.canonical(env))['sha256']
 for name,raw in data.items():
  if name.startswith('phase-')and name.endswith('.json'):
   r=S.decode(raw);action=r['action'];S.need(action in('prepare','build','package','makepkg')and action not in phases,'EXACT_FOUR_ACTOR_ACTIONS');S.need(r['schema']==1 and r['status']=='COMPLETED_ACTOR_ACTION_DATA'and r['root_admission_sha256']==expected_root and r['native_acceptance']is False and r['holds_preserved']is True and not r.get('error')and not r.get('finalization_error'),'ACTOR_ACTION_COMPLETE');phases[action]=r;phase_names[action]=name
  if name.startswith('cmd-')and name.endswith('.json'):
   r=S.decode(raw);natural(r['lifecycle']);S.need(r['schema']==1 and r['returncode']==0 and r['phase']in('prepare','build','package','makepkg')and r['environment_sha256']==environment_sha and r['cwd']==('/work/recipe'if r['phase']=='makepkg'else '/work/build'if r['phase']=='prepare'else '/work/build/rustc-1.99.0-src')and r['capture']is(r['phase']=='makepkg'and r['argv']==['/usr/bin/pacman','-Q']or r['argv']in PROBES),'ACTOR_COMMAND_RECEIPT')
   for stream in('stdout','stderr'):
    v=r[stream];S.need(v['file']in data and S.pin(data[v['file']])=={k:v[k]for k in('bytes','sha256')}and v['file']==name[:-5]+'.'+stream,'ACTOR_COMMAND_COMPLETE_LOG_PIN')
   commands.append(r)
 S.need(set(phases)=={'prepare','build','package','makepkg'},'EXACT_FOUR_ACTOR_ACTIONS')
 helper=S.pin(source['actor/mount_proof.py'][0])['sha256'];token=S.pin(S.canonical(a['source']))['sha256'][:24];kernels={};used=set()
 for action,row in phases.items():
  envelope=row.get('kernel_mount_proof');S.need(type(envelope)is dict,'MOUNTINFO_ACTOR_PHASE_PROOF_REQUIRED')
  context=dict(source=a['source'],dispatch_sha256=a['authorization']['dispatch']['sha256'],input_admission_sha256=expected_root,image_id=a['image']['id'],volume_token=token,phase=action)
  kernels[action]=kernel_proof(envelope,data.__getitem__,context,'work-only'if action=='prepare'else'stage0-aliases',helper)
  S.need(envelope['receipt']['file']=='kernel-mount-proof-'+phase_names[action].removeprefix('phase-'),'MOUNTINFO_SAME_PHASE_RECEIPT_INVOCATION')
  used.update(v['file']for v in envelope.values())
 S.need(used=={n for n in data if n.startswith(('kernel-mountinfo-','kernel-mount-proof-'))},'MOUNTINFO_EXACT_ACTOR_PROOF_NAMESPACE')
 for command in commands:S.need(command.get('kernel_mount_proof_sha256')==kernels[command['phase']]['receipt_sha256'],'MOUNTINFO_EVERY_ACTOR_COMMAND_PROOF_JOIN')
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
 return dict(actor_actions=4,commands=len(commands),built_stage_tree_sha256=built['staged_tree_sha256'],command_order='NOT_EMITTED',new_tool_runtime='NOT_EMITTED_NOT_QUALIFIED',kernel_mount_proofs=kernels)

def inspected(row,final,role,p,a,source,work_source):
 S.need(row['Id']==final['Id']and row['Name']==final['Name']and row['Image']==p['image']and row['State']['Status']=='created'and row['State']['Running']is False,'INITIAL_SAME_UNSTARTED_ACTOR')
 config,host=row['Config'],row['HostConfig'];init=role=='init'
 S.need(config['User']=='1001:1001'and host['Memory']==host['MemorySwap']==(128*S.MIB if init else 8*S.GIB)and host['PidsLimit']==(32 if init else 512)and host['NanoCpus']==2000000000,'ACTOR_EXACT_USER_RESOURCES')
 S.need(host['ReadonlyRootfs']is True and host['NetworkMode']=='none'and host['CapDrop']==['ALL']and host.get('CapAdd')in(None,[])and host['Privileged']is False and host['SecurityOpt']==['no-new-privileges']and host['Init']is True and host['IpcMode']=='private'and host['CgroupnsMode']=='private','ACTOR_EXACT_ISOLATED_DOMAIN')
 S.need(not any(host.get(k)for k in('Devices','DeviceRequests','Binds','VolumesFrom','Links','ExtraHosts','UsernsMode','PidMode'))and host['RestartPolicy']['Name']=='no'and host['LogConfig']==dict(Type='none',Config={})and {r['Name']:(r['Soft'],r['Hard'])for r in host['Ulimits']}==dict(nofile=(1024,1024),core=(0,0)),'ACTOR_NO_EXTRA_AUTHORITY')
 if init:
  S.need(config['Entrypoint']==['/usr/bin/python']and config['WorkingDir']=='/'and len(config['Cmd'])==5 and config['Cmd'][:3]==['-I','-B','-c']and S.pin(config['Cmd'][3].encode())['sha256']==INIT_CODE_SHA256 and S.decode(config['Cmd'][4].encode())==p['volume_binding']and not host.get('Tmpfs'),'INITIALIZER_FIXED_NONROOT_NO_CAPS_NO_MUTATION')
 else:
  S.need(host['Tmpfs']=={'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'},'ACTOR_EXACT_BOUNDED_TMPFS')
 if init:
  actual=row['Mounts'];configured=host['Mounts'];S.need(len(actual)==len(configured)==1,'INITIALIZER_EXACT_OWNED_PRIVATE_BIND');private_bind(configured[0],actual[0],'/work',work_source,False);return
 S.need(config['Hostname']=='rust199-native'and config['WorkingDir']=='/work'and config['Entrypoint']==['/usr/bin/python']and config['Cmd']==['-I','-B','/source/actor/entry.py',role],'ACTOR_EXACT_ENTRY_VECTOR')
 env=dict(item.split('=',1)for item in config['Env']);pins=dict(ROOT_ADMISSION_SHA256=S.pin(S.canonical(a))['sha256'],SOURCE_MAP_SHA256=S.SOURCE['map_sha256'],CONTRACT_SHA256=S.pin(source['contract.json'][0])['sha256'],WORK_VOLUME_ADMISSION_SHA256=p['volume_admission_sha256'])
 S.need(all(env.get(k)==v for k,v in pins.items())and not any(k.startswith(('LD_','DOCKER_','PYTHON','CACHY_OLD_','CACHY_RETAINED_'))for k in env),'ACTOR_EXACT_ADMISSION_ENVIRONMENT')
 actual={r['Destination']:r for r in row['Mounts']};configured={r['Target']:r for r in host['Mounts']};materials={r['name']:r for r in a['materials']};wanted={'/work','/inputs','/source'}|{'/materials/'+name for name in materials}
 if role=='makepkg':wanted|={'/stage0','/work/build/stage0'}
 S.need(set(actual)==set(configured)==wanted and len(actual)==len(row['Mounts'])==len(host['Mounts']),'ACTOR_EXACT_MOUNT_NAMESPACE')
 for target in wanted:
  r,c=actual[target],configured[target];owned=target in('/work','/stage0','/work/build/stage0');readonly=target!='/work'
  selected=work_source+('/build/stage0'if target!='/work'else'')if owned else c['Source']
  private_bind(c,r,target,selected,readonly)
  if target.startswith('/materials/'):S.need(r['Source']==materials[target.rsplit('/',1)[1]]['local_path'],'ACTOR_WHOLE_MATERIAL_BIND')


def volume_options(raw,expected):
 # Docker's explicit empty default driver is the only admitted normalization.
 return (type(raw)is dict and type(expected)is dict and
  ('NoCopy'not in expected or raw.get('NoCopy')is expected['NoCopy'])and
  ('DriverConfig'not in raw or expected.get('NoCopy')is True and type(raw['DriverConfig'])is dict and raw['DriverConfig']=={})and
  {k:v for k,v in raw.items()if k!='DriverConfig'}==expected)

DAEMON_FIELDS=('ID','DockerRootDir','OSType','Architecture','CgroupVersion','SecurityOptions','OperatingSystem')
DAEMON_FORMAT='{'+','.join('"'+key+'":{{json .'+key+'}}'for key in DAEMON_FIELDS)+'}'

def lexical_absolute(value):
 # These are API labels. Never stat/resolve/traverse the daemon-owned directory.
 S.need(type(value)is str and 1<len(value)<=4096 and value.startswith('/')and
  (value=='/'or not value.endswith('/'))and '//'not in value and '\\'not in value and
  all(32<ord(c)<127 and c not in ',:'for c in value)and not any(x in('.','..')for x in value.split('/')),'OWNED_BIND_LEXICAL_ABSOLUTE_PATH')
 return value

def daemon_identity(info):
 S.need(type(info)is dict and set(DAEMON_FIELDS)<=set(info),'OWNED_BIND_DAEMON_FIELDS')
 view={key:info[key]for key in DAEMON_FIELDS}
 S.need(type(view['ID'])is str and 0<len(view['ID'])<=256 and view['OSType']=='linux'and
  view['Architecture']in('aarch64','arm64')and view['CgroupVersion']=='2','OWNED_BIND_ROOTFUL_LINUX_ARM_DAEMON')
 security=view['SecurityOptions'];system=view['OperatingSystem']
 S.need(type(security)is list and len(security)<=32 and all(type(v)is str and len(v)<=1024 for v in security)and
  not any('rootless'in v.lower()for v in security)and type(system)is str and 0<len(system)<=512 and
  'docker desktop'not in system.lower()and 'dockerdesktop'not in system.lower(),'OWNED_BIND_NO_ROOTLESS_OR_DESKTOP')
 lexical_absolute(view['DockerRootDir']);return view

def owned_work_bind(record,binding,phase,daemon):
 S.need(phase in('bootstrap','build')and type(record)is dict and set(record)=={'schema','status','endpoint','daemon_inspect','daemon_root','volume','labels','job_root','job_root_node','job_root_mount_id','work_source','stage0_source','workspace_node','workspace_mount_id','nonce','producer','bind_propagation','native_acceptance','holds_preserved'},'OWNED_BIND_EXACT_RECORD_SCHEMA')
 S.need(type(record['schema'])is int and record['schema']==15 and record['status']=='OWNED_EXTERNAL_JOB_DIRECTORY_PRIVATE_BIND_ONLY'and record['endpoint']=='unix:///var/run/docker.sock'and record['bind_propagation']=='rprivate'and record['native_acceptance']is False and record['holds_preserved']is True,'OWNED_BIND_FINITE_EXTERNAL_DIRECTORY_SCOPE')
 snapshot=record['daemon_inspect'];S.need(type(snapshot)is dict and set(snapshot)=={'json','pin'}and type(snapshot['json'])is str,'OWNED_BIND_WHOLE_API_SNAPSHOT')
 raw=snapshot['json'].encode();S.need(0<len(raw)<=S.MIB and S.pin(raw)==snapshot['pin'],'OWNED_BIND_API_BODY_PIN');info=S.decode(raw)
 S.need(type(info)is dict and set(info)==set(DAEMON_FIELDS),'OWNED_BIND_ONLY_SAFE_DAEMON_PROJECTION')
 observed=daemon_identity(info);S.need(S.canonical(observed)==S.canonical(daemon_identity(daemon)),'OWNED_BIND_SAME_SELECTED_DAEMON')
 token=S.pin(S.canonical(binding))['sha256'][:24];name=('rust199-qual-'if phase=='bootstrap'else'rust199-')+token+'-work'
 labels={'cachy-asahi.'+k:v for k,v in dict(operation='rust199-source-reference-native-v1',source=binding['sha'],run=binding['run'],job=binding['job'],token=token,role=('qualification-'if phase=='bootstrap'else'')+'volume').items()}
 root=lexical_absolute(record['job_root']);storage=observed['DockerRootDir'];work=root+'/'+name
 S.need(root.endswith('/rust199-hosted'),'OWNED_BIND_FIXED_HOSTED_ENTRY_JOB_ROOT')
 def related(a,b):return a==b or a.startswith(b+'/')or b.startswith(a+'/')
 S.need(not related(root,storage),'OWNED_BIND_OUTSIDE_ACTUAL_DAEMON_ROOT')
 S.need(record['volume']==name and record['labels']==labels and record['daemon_root']==storage and record['work_source']==work and record['stage0_source']==work+'/build/stage0','OWNED_BIND_EXACT_DERIVED_SOURCES')
 for key in('job_root_node','workspace_node'):
  node=record[key];S.need(type(node)is dict and set(node)=={'device','inode','uid','gid','mode'}and all(type(v)is int for v in node.values())and node['device']>=0 and node['inode']>0 and node['uid']==node['gid']==1001 and node['mode']==0o700,'OWNED_BIND_EXACT_PRIVATE_DIRECTORY_NODE')
 S.need(record['job_root_node']['device']==record['workspace_node']['device']and record['job_root_node']['inode']!=record['workspace_node']['inode']and type(record['job_root_mount_id'])is int and type(record['workspace_mount_id'])is int and record['job_root_mount_id']>0 and record['job_root_mount_id']==record['workspace_mount_id'],'OWNED_BIND_SAME_MOUNT_DISTINCT_HELD_DIRECTORIES')
 S.need(record['producer']==dict(source=binding,token=token,operation='rust199-source-reference-native-v1')and S.digest(record['nonce']),'OWNED_BIND_EXACT_SOURCE_TOKEN_NONCE')
 return dict(volume=name,labels=labels,daemon=observed,work_source=work,stage0_source=work+'/build/stage0',job_root=root,workspace_node=record['workspace_node'],nonce=record['nonce'],daemon_inspect_pin=snapshot['pin'])


def workspace_lifecycle(record,facts,operations):
 S.need(type(record)is list and len(record)==2 and all(type(row)is dict for row in record),'OWNED_BIND_COMPLETE_WORKSPACE_LIFECYCLE')
 created,retired=record
 S.need(set(created)=={'status','after_operation_count','workspace_node','nonce'}and created['status']=='CREATED_HELD'and set(retired)=={'status','after_operation_count','workspace_node','nonce','nodes','fd_held_until_absence'}and retired['status']=='RETIRED_ABSENT','OWNED_BIND_EXACT_LIFECYCLE_SCHEMA')
 S.need(all(row['workspace_node']==facts['workspace_node']and row['nonce']==facts['nonce']and type(row['after_operation_count'])is int for row in record)and 1<=created['after_operation_count']<retired['after_operation_count']<=len(operations),'OWNED_BIND_SAME_HELD_WORKSPACE_LIFECYCLE')
 S.need(retired['fd_held_until_absence']is True and type(retired['nodes'])is int and 0<=retired['nodes']<=2000000,'OWNED_BIND_BOUNDED_FD_HELD_RETIREMENT')
 return created['after_operation_count'],retired['after_operation_count']

def private_bind(configured,actual,target,source,readonly):
 S.need(type(configured)is dict and {'Type','Source','Target'}<=set(configured)and set(configured)<={'Type','Source','Target','ReadOnly','Consistency','BindOptions'}and
  configured['Type']=='bind'and configured['Target']==target and configured['Source']==source and
  configured.get('ReadOnly',False)is readonly and configured.get('Consistency','')in('','default')and
  configured.get('BindOptions')=={'Propagation':'rprivate'},'OWNED_BIND_EXACT_CONFIGURED_PRIVATE_BIND')
 S.need(type(actual)is dict and {'Type','Destination','Source','Propagation','RW'}<=set(actual)and actual['Type']=='bind'and actual['Destination']==target and actual['Source']==source and
  actual['Propagation']=='rprivate'and actual['RW']is(not readonly)and not actual.get('Name')and not actual.get('Driver'),
  'OWNED_BIND_EXACT_REALIZED_PRIVATE_BIND')

def initialization(value,binding,node):
 S.need(type(value)is dict and set(value)=={'schema','status','binding','before','after','limits','capabilities','recursive'}and type(value['schema'])is int and value['schema']==1 and value['status']=='INITIALIZED_EMPTY_WORK_VOLUME'and value['binding']==binding and value['recursive']is False and value['capabilities']=='NO_CAPS_NO_MUTATION_OWNED_DIRECTORY','OWNED_BIND_EXACT_NONMUTATING_INITIALIZATION_RECEIPT')
 S.need(all(type(value[k])is dict and set(value[k])=={'device','inode','uid','gid','mode'}and all(type(v)is int for v in value[k].values())for k in('before','after')),'OWNED_BIND_TYPED_INITIALIZATION_NODES')
 S.need(value['limits']=={'cpu.max':'200000 100000','memory.max':'134217728','memory.swap.max':'0','pids.max':'32'}and value['before']==value['after']==node,'OWNED_BIND_SAME_UNMUTATED_DIRECTORY_INITIALIZATION')
 return value

def initializer_inspected(row,owner,image,work_source):
 final={'Id':row['Id'],'Name':row['Name']};initial=dict(row,State=dict(Status='created',Running=False))
 inspected(initial,final,'init',dict(image=image,volume_binding=owner),None,None,work_source)

def qualifier_inspected(row,role,admission_sha256):
 config,host=row['Config'],row['HostConfig']
 S.need(config['User']=='1001:1001'and config['Entrypoint']==['/usr/bin/python']and config['Cmd']==['-I','-B','/source/actor/qualify.py',role]and config['Hostname']=='rust199-qualification'and config['WorkingDir']=='/work','CUSTODY_TRUSTED_QUALIFIER_ENTRY_VECTOR')
 env=dict(item.split('=',1)for item in config['Env'])
 S.need(env.get('QUALIFICATION_SHA256')==admission_sha256 and not any(k.startswith(('LD_','PYTHON','GH_TOKEN','GITHUB_TOKEN'))for k in env),'CUSTODY_QUALIFIER_EXACT_PLAN_ENVIRONMENT')
 S.need(host['Memory']==host['MemorySwap']==8*S.GIB and host['PidsLimit']==512 and host['NanoCpus']==2000000000 and host['ReadonlyRootfs']is True and host['NetworkMode']=='none'and host['CapDrop']==['ALL']and host.get('CapAdd')in(None,[])and host['Privileged']is False and host['SecurityOpt']==['no-new-privileges']and host['Init']is True and host['IpcMode']=='private'and host['CgroupnsMode']=='private','CUSTODY_QUALIFIER_ISOLATED_DOMAIN')
 S.need(not any(host.get(k)for k in('Devices','DeviceRequests','Binds','VolumesFrom','Links','ExtraHosts','UsernsMode','PidMode'))and host['RestartPolicy']['Name']=='no'and host['LogConfig']==dict(Type='none',Config={})and {r['Name']:(r['Soft'],r['Hard'])for r in host['Ulimits']}==dict(nofile=(1024,1024),core=(0,0))and host['Tmpfs']=={'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'},'CUSTODY_QUALIFIER_NO_EXTRA_AUTHORITY')

def custody_operations(rows,corpus,phase,selected,image,kernels,work_bind,daemon,lifecycle):
 """Join acknowledged CIDs through ordered retained daemon observations only."""
 S.need(phase in('bootstrap','build')and re.fullmatch('sha256:[0-9a-f]{64}',image)is not None,'CUSTODY_PHASE_IMAGE')
 bootstrap=phase=='bootstrap';roles=('init','data','probe')if bootstrap else('init','prepare','makepkg')
 binding=dict(sha=selected['source'],ref=selected['ref'],run=selected['run'],job=selected['bootstrap_job'if bootstrap else'build_job'],map_sha256=S.SOURCE['map_sha256'],approval=selected['source_review_sha256'])
 token=S.pin(S.canonical(binding))['sha256'][:24];base=('rust199-qual-'if bootstrap else'rust199-')+token
 facts=owned_work_bind(work_bind,binding,phase,daemon)
 created_at,retired_at=workspace_lifecycle(lifecycle,facts,rows)
 expected_phases={'qualification-data','qualification-probe'}if bootstrap else{'prepare','makepkg','build','package'}
 S.need(type(kernels)is dict and set(kernels)==expected_phases,'CUSTODY_KERNEL_PROOFS_REQUIRED')
 init_root=selected['dispatch_sha256']if bootstrap else kernels['prepare']['context']['input_admission_sha256']
 init_owner=dict(source=binding,image=image,root_admission_sha256=init_root,token=token,init=base+'-init',prepare=base+('-data'if bootstrap else'-prepare'),makepkg=base+('-probe'if bootstrap else'-makepkg'),volume=base+'-work',operation='rust199-source-reference-native-v1')
 for action,proof in kernels.items():
  context=proof['context'];S.need(context['source']==binding and context['dispatch_sha256']==selected['dispatch_sha256']and context['image_id']==image and context['volume_token']==token and context['phase']==action and
   proof['profile']==('work-only'if action in('qualification-data','prepare')else'stage0-aliases')and S.digest(proof['receipt_sha256']),'CUSTODY_CURRENT_ACTOR_KERNEL_CONTEXT')
 work_identity=lambda proof:S.canonical({k:proof['mounts']['/work'][k]for k in('device','root','fs_type','source','super_options')})
 S.need(len({work_identity(v)for v in kernels.values()})==1,'CUSTODY_SAME_VOLUME_KERNEL_IDENTITY_ACROSS_PHASES')
 names={base+'-'+role:role for role in roles};volume=base+'-work';ids={};last={};started=set();retired=set();volume_path=facts['work_source']
 fresh_namespace=False;fresh_containers=False;daemon_seen=False;final_volume=False;final_containers=False;workspace_retired=False
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
  if bootstrap and role!='init':qualifier_inspected(row,role,kernels['qualification-'+role]['context']['input_admission_sha256'])
  if role=='init':initializer_inspected(row,init_owner,image,facts['work_source'])
  configured=row['HostConfig']['Mounts'];actual=row['Mounts'];c={v['Target']:v for v in configured};a={v['Destination']:v for v in actual}
  S.need(volume_path is not None and len(c)==len(configured)==len(a)==len(actual)and set(c)==set(a)and '/work'in c,'CUSTODY_EXACT_MOUNT_NAMESPACE')
  wanted={'/work'}if role=='init'else{'/work','/inputs','/source'}|{'/materials/'+n for n in ('cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz','llvm-project-23.1.1.src.tar.xz','rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz','rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz','rustc-1.99.0-src.tar.xz')}
  if role in('probe','makepkg'):wanted|={'/stage0','/work/build/stage0'}
  S.need(set(c)==wanted,'CUSTODY_EXACT_ROLE_MOUNT_NAMESPACE')
  for target,want in c.items():
   observed=a[target];owned=target in('/work','/stage0','/work/build/stage0')
   selected_source=facts['stage0_source']if target in('/stage0','/work/build/stage0')else facts['work_source']if target=='/work'else want['Source']
   private_bind(want,observed,target,selected_source,target!='/work')
  if role!='init':
   S.need(c['/inputs']['Source']==facts['job_root']+('/qualification/inputs'if bootstrap else'/rust-build/inputs'),'OWNED_BIND_FIXED_ADMITTED_JOB_INPUT_CHILD')
   source_root=lexical_absolute(c['/source']['Source']);job_root=facts['job_root']
   S.need(source_root!=job_root and not source_root.startswith(job_root+'/')and not job_root.startswith(source_root+'/'),'OWNED_BIND_SOURCE_JOB_ROOT_DISJOINT')
  last[role]=row
 for index,row in enumerate(rows):
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
  if args==['info','--format',DAEMON_FORMAT]:
   S.need(row['returncode']==0,'OWNED_BIND_DAEMON_INSPECT_EXIT');raw=stream(row);view=S.decode(raw)
   S.need(type(view)is dict and set(view)==set(DAEMON_FIELDS)and S.canonical(daemon_identity(view))==S.canonical(facts['daemon']),'OWNED_BIND_FRESH_SAFE_DAEMON_OBSERVATION')
   if index+1==created_at:
    S.need(raw==work_bind['daemon_inspect']['json'].encode()and fresh_namespace and fresh_containers and not ids,'OWNED_BIND_FRESH_DAEMON_BEFORE_DIRECTORY_AND_ACTORS');daemon_seen=True
  elif args==['container','ls','--all','--format','{{.Names}}']:
   S.need(row['returncode']==0,'OWNED_BIND_CONTAINER_NAMESPACE_QUERY');present=set(stream(row).decode('utf-8').splitlines())&set(names)
   if index<created_at:S.need(not present,'OWNED_BIND_FRESH_ACTOR_NAMESPACE');fresh_containers=True
   elif set(roles)==retired:S.need(not present,'OWNED_BIND_FINAL_ACTOR_ABSENCE');final_containers=True
  elif args==['volume','ls','--quiet']:
   S.need(row['returncode']==0 and volume not in stream(row).decode('utf-8').splitlines(),'OWNED_BIND_NO_DOCKER_VOLUME_NAMESPACE')
   if index<created_at:fresh_namespace=True
   elif set(roles)==retired:final_volume=True
  elif args[:2]in(['volume','create'],['volume','inspect'],['volume','rm']):
   S.need(False,'OWNED_BIND_NO_DOCKER_VOLUME_LIFECYCLE')
  elif args[:1]==['create']:
   S.need(daemon_seen and created_at<=index<retired_at,'OWNED_BIND_ACTOR_DURING_HELD_DIRECTORY_LIFETIME')
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
   if role=='init':initialization(S.decode(stream(row)),init_owner,facts['workspace_node'])
  elif args[:2]==['container','rm']:
   S.need(len(args)==3 and args[2]in ids.values()and row['returncode']==0,'CUSTODY_EXACT_CID_NATURAL_REMOVE');role=next(k for k,v in ids.items()if v==args[2])
   S.need(role in last and role in started and role not in retired and last[role]['State']['Status']=='exited','CUSTODY_REMOVE_AFTER_NATURAL_INSPECTION');retired.add(role);last.pop(role)
  if index+1==retired_at:
   S.need(set(ids)==started==retired==set(roles)and final_containers and final_volume and args==['volume','ls','--quiet'],'OWNED_BIND_DIRECTORY_RETIRED_AFTER_ACTUAL_ACTOR_ABSENCE');workspace_retired=True
 S.need(rootfs_id is None or rootfs_retired,'CUSTODY_ROOTFS_DATA_RETIREMENT')
 S.need(set(ids)==started==retired==set(roles),'CUSTODY_COMPLETE_ACKNOWLEDGED_NATURAL_RETIREMENT')
 S.need(daemon_seen and workspace_retired,'OWNED_BIND_COMPLETE_DIRECTORY_LIFECYCLE')
 return ids
