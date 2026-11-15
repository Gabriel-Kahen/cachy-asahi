# SPDX-License-Identifier: MIT
"""Distinct finite ARM283 UI authority/input gate. No actor or clone on import."""
import hashlib,importlib.util,json,os,posixpath,re,shutil,stat,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];OP='arm16k-first-login-ui-glib290-vm-v1'
BOOT_RESOURCES={'memory_bytes':5*1024**3,'memory_swap_bytes':5*1024**3,'guest_memory_MiB':2048,'overlay_bytes':2*1024**3,'cpus':2,'pids':256,'host_minimum_bytes':7*1024**3,'host_reserve_bytes':2*1024**3}
DISK_BUDGETS={'prepare_allocated_bytes':1536*1024**2,'overlay_allocated_bytes':2*1024**3,'future_diagnostic_bytes':2*1024**3,'reserve_bytes':2*1024**3,'boot_nonoverlay_bytes':32*1024**2}
OFFICIAL='68B3537F39A313B3E574D06777193F152BDBE6A6';POLICY='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'
PROJECT={'cachy-asahi-first-login-ui':'869fb4f1dcf7fc26ff87594398eba8d15d4a8051e6feaf96d4b8fe457ccb4ea4','cachy-asahi-first-login':'d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839','cachy-asahi-setup':'8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47'}
REQUIRED={'usr/bin/cachy-asahi-first-login-ui':'cachy-asahi-first-login-ui','usr/bin/cachy-asahi-first-login':'cachy-asahi-first-login','usr/bin/cachy-asahi-setup':'cachy-asahi-setup','usr/bin/python3':'python','usr/bin/Xvfb':'xorg-server-xvfb','usr/bin/xvfb-run':'xorg-server-xvfb','usr/bin/xauth':'xorg-xauth','usr/bin/fish':'fish','usr/bin/zsh':'zsh','usr/lib/python3.14/site-packages/gi/__init__.py':'python-gobject','usr/lib/girepository-1.0/Gtk-4.0.typelib':'gtk4','usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy':'networkmanager'}
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def pin(path):
 path=Path(path);assert path.is_file()and not path.is_symlink()
 with path.open('rb')as stream:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}
def checked(path,ref):
 if not isinstance(ref,dict)or set(ref)!={'bytes','sha256'}or type(ref['bytes'])is not int or not 0<ref['bytes']<=4*1024**3 or not re.fullmatch('[0-9a-f]{64}',ref.get('sha256',''))or pin(path)!=ref:raise ValueError('exact finite input pin required')
 return Path(path)
def read(path,maximum=8*1024**2):
 p=Path(path);assert p.is_file()and not p.is_symlink()and p.stat().st_size<=maximum;return json.loads(p.read_text())
def references():
 refs=read(HERE/'references.json');arm=ROOT/refs['arm_source']['path'];checked(arm/'source.lock.json',refs['arm_source']['source_lock']);checked(arm/'contracts.py',refs['arm_source']['contracts']);A=load('UI_ARM_lower_contracts',arm/'contracts.py');A.source();local_input=refs['arm_source']['local_input'];checked(arm/local_input['filename'],{k:local_input[k]for k in ['bytes','sha256']})
 checks=refs['arm_source']['observer_checks'];checked(arm/checks['filename'],{k:checks[k]for k in ['bytes','sha256']})
 x86=ROOT/refs['x86_source']['path']
 for n,r in refs['x86_source']['files'].items():checked(x86/n,r)
 for key in ['owned_process','elf_parser','public_packets','public_packets_dependency']:refs[key]['path']=str(ROOT/refs[key]['path'])
 owned=refs['owned_process'];checked(owned['path'],{k:owned[k]for k in ['bytes','sha256']});return refs,arm,x86,A
def source():
 lock=read(HERE/'source.lock.json')
 for n,r in lock['files'].items():checked(HERE/n,r)
 return pin(HERE/'source.lock.json')
def admission(value,phase):
 if not isinstance(value,dict)or value.get('kind')!='ARM16K_FIRST_LOGIN_UI_GLIB290_AUTHORITY_V1'or value.get('issued_by')!='Root'or value.get('operation')!=OP or value.get('allow_'+phase)is not True:raise ValueError('explicit distinct Root UI authority required')
 if value.get('allow_glib_runtime_upgrade')is not True:raise ValueError('explicit experimental GLib runtime change authority required')
 for field in ['tool_image_id','qemu_metadata','tool_qualification','kernel_bundle','additions_manifest','minimal155_report','minimal155_prepared','source_public','source_lock','resource_review']:
  if value.get(field)is None:raise ValueError('missing Root-admitted '+field)
 if not re.fullmatch('sha256:[0-9a-f]{64}',value['tool_image_id']):raise ValueError('actual qualified tool image ID required')
 public=value['source_public']
 if public.get('repository')!='https://github.com/Gabriel-Kahen/cachy-asahi'or not re.fullmatch('[0-9a-f]{40}',public.get('commit',''))or public.get('status')!='ROOT_REVIEWED_PUBLIC_SOURCE':raise ValueError('exact reviewed public Source required')
 if value['resource_review'].get('status')!='ROOT_REVIEWED_FINITE_RESOURCES'or value['resource_review'].get('reserve_bytes',0)<2*1024**3:raise ValueError('fresh finite Root resource review required')
 if value.get('disk_budgets')!=DISK_BUDGETS:raise ValueError('explicit staged disk budgets required')
 if phase=='boot'and value.get('boot_resources')!=BOOT_RESOURCES:raise ValueError('explicit exact5GiB no-swap boot resources required')
 if value.get('accept_unknown_runtime_ABI_for_bounded_VM')is not True:raise ValueError('explicit bounded runtime uncertainty scope required')
 return value
def qualified_tool(tool,image_id,qualification,producer):
 expected=['virtio-blk-device','virtio-keyboard-device','virtio-gpu-device']
 assert tool['kind']=='ROOT_OBSERVED_ARM_QEMU_DEVICE_HELP_V1'and tool['issued_by']=='Root'and tool['image_id']==image_id and tool['status']=='OBSERVED_DEVICE_HELP_ONLY'and tool['devices']==expected
 assert qualification['image_id']==image_id and qualification['owned_containers_absent']is True and set(qualification['required_devices'])==set(expected)and all(v is True for v in qualification['required_devices'].values())
 ref=read(HERE/'references.json')['tool_producer'];path=producer
 for name,p in ref['files'].items():checked(path/name,p)
 C=load('UI_qualified_original_tool_contract',path/'contract.py');C.qualified(qualification);assert C.tool_metadata(qualification)==tool
 return tool
def validate_prepare_proof(proof,rows):
 assert proof['status']=='PASS_EXPLICIT_METADATA_ONLY'and proof['baseline111_before_fixed']is True and proof['protected_versions']==110 and proof['touched_packages']==173 and proof['forward_total']==283 and proof['normal_rollback_after_count']==111
 for label,count,expected in [('forward',283,{n:r['version']for n,r in rows.items()}),('rollback_glib_after_modeled_172_removal',111,{'glib2':'2.88.3-1'})]:
  item=proof[label];assert item['final_count']==count and item['conflicts']==[]
  actual=item['prepare'];assert actual['libalpm_version']=='16.0.1'and actual['prepare_exit']==actual['prepare_errno']==0 and all(actual[k]==[]for k in ['errors','callback_errors','questions','remove'])
  assert {r['name']:r['version']for r in actual['add']}==expected
def payload_fields(value):return {k:value[k]for k in ['type','mode','uid','gid','bytes','sha256','link']}
def executable(payload,path):
 seen=set()
 for _ in range(16):
  assert path not in seen and path in payload and not path.startswith(('/', '../'));seen.add(path);row=payload[path]
  if row['type']=='0':assert row['mode']&0o111 and row['uid']==row['gid']==0;return row
  assert row['type']in ['1','2']
  link=row['link'];path=posixpath.normpath(link.lstrip('/')if link.startswith('/')or row['type']=='1'else posixpath.join(posixpath.dirname(path),link))
 raise ValueError('bounded executable namespace resolution refused')
def baseline_association(rows):
 normalized={n:{'version':v['version'],'directory':v['directory'],'provides':sorted(v['provides']),'files':sorted(v['files'])}for n,v in rows.items()};return hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def namespace(manifest,catalog,base):
 bm=manifest['baseline_metadata'];assert baseline_association(bm)==read(HERE/'actual-data.json')['baseline_metadata_association']['sha256'],'actual111 ownership/provides association differs';assert set(bm)=={r['name']for r in base['base_packages']}
 for row in base['base_packages']:assert bm[row['name']]['version']==row['version']and bm[row['name']]['directory']==row['directory']and isinstance(bm[row['name']]['provides'],list)and isinstance(bm[row['name']]['files'],list)
 for path,owner in REQUIRED.items():
  item=manifest['required_namespace'][path];assert item['owner']==owner and payload_fields(catalog[owner]['payload'][path])==payload_fields(item['payload'])and item['payload']['type']in ['0','1','2']
  if path.startswith('usr/bin/'):executable(catalog[owner]['payload'],path)
 for path in ['usr/lib/girepository-1.0/GLib-2.0.typelib','usr/lib/girepository-1.0/Gio-2.0.typelib']:
  row=manifest['required_namespace'][path];assert row['owner']=='glib2'and path in bm['glib2']['files']and row['payload']['type']=='0'and payload_fields(row['payload'])==payload_fields(catalog['glib2']['payload'][path])and manifest['original_file_pins']['/'+path]==read(HERE/'data/glib-materials.json')['old']['payload'][path]['sha256']
 assert catalog['networkmanager']['payload']['usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy']['sha256']==POLICY
 assert manifest['known_incompatibilities']==[],'known incompatibility must remain HOLD'
def complete_edges(edges,all_dependencies,providers,S):
 expected_relations=[(n,e)for n,values in all_dependencies.items()for e in values];assert sorted((e['package'],e['relation'])for e in edges)==sorted(expected_relations)
 for name,expressions in all_dependencies.items():
  for expression in expressions:
   symbol,op,wanted=S.atom(expression);chosen=[e['provider']for e in edges if e.get('package')==name and e.get('relation')==expression];assert len(chosen)==1 and any(n==chosen[0]and S.satisfies(v,op,wanted)for n,v in providers.get(symbol,[])),'all baseline/new dependency edges required'
def validate_edges(manifest,catalog,base,arm):
 S=load('UI283_frozen_version_relations',arm/'frozen/alpm_versions.py');all_rows={r['name']:{'version':r['version'],'provides':manifest['baseline_metadata'][r['name']]['provides']}for r in base['base_packages']};all_rows.update({n:{'version':r['metadata']['pkgver'][0],'provides':r['metadata'].get('provides',[])}for n,r in catalog.items()});providers={}
 for name,row in all_rows.items():
  providers.setdefault(name,[]).append((name,row['version']))
  for expression in row['provides']:
   symbol,op,version=S.atom(expression);assert op in [None,'='];providers.setdefault(symbol,[]).append((name,version))
 edges=manifest['metadata_prepare']['forward']['dependencies'];occupied={p for row in manifest['baseline_metadata'].values()for p in row['files']};glib_owned=set(manifest['baseline_metadata']['glib2']['files']);added={}
 baseline_relations=read(HERE/'data/baseline-relations.json');all_dependencies={n:r['depends']for n,r in baseline_relations.items()};all_dependencies.update({n:d['metadata'].get('depend',[])for n,d in catalog.items()})
 complete_edges(edges,all_dependencies,providers,S)
 for name,data in catalog.items():
  for expression in data['metadata'].get('depend',[]):
   symbol,op,wanted=S.atom(expression);chosen=[e['provider']for e in edges if e.get('package')==name and e.get('relation')==expression];assert len(chosen)==1 and any(n==chosen[0]and S.satisfies(v,op,wanted)for n,v in providers.get(symbol,[])),'selected ALPM provider edge differs'
  for expression in data['metadata'].get('conflict',[])+data['metadata'].get('replaces',[]):
   symbol,op,wanted=S.atom(expression);assert not any(n!=name and S.satisfies(v,op,wanted)for n,v in providers.get(symbol,[])),'actual selected conflict'
  for path,node in data['payload'].items():
   if node['type']=='5':continue
   assert (path not in occupied or(name=='glib2'and path in glib_owned and all(path not in r['files']for n,r in manifest['baseline_metadata'].items()if n!='glib2')))and path not in added,'only exact glib2-owned replacement paths allowed';added[path]=name

def minimal_seat_report(value):
 assert value['status']=='PASS_EMULATED_ARM16K_VIRTIO_SEAT_PAM_POLICY_ONLY'
 for key in ['normal_VT_PAM_logout_observed','owned_container_absence_verified','owned_container_removed','cleanup_ownership_verified','QMP_quit_requested']:assert value[key]is True
 assert value['cleanup_errors']==[]and value['installed_gate']['installed_count']==155
 retired=value['QEMU_retirement'];assert retired['passed']is True and retired['reaped']is True and retired['group_census']=='EMPTY_TWICE'and not retired.get('actor_cancelled')
 seat=value['seat'];assert seat['architecture']=='aarch64'and seat['pagesize']==16384 and seat['user']['sd_session_get_seat']=={'return':0,'seat':'seat0'}and seat['observed_stages']['password_ready_echo_off']is True
 checks=seat['independent_checks'];assert set(checks)=={'bus-credentials','logind-session','process-vt','keyboard-record','gpu-record','seat-status'}and all(row['passed']is True for row in checks.values())
 return value

def validate_glib_manifest(manifest,materials):
 facts=read(HERE/'data/glib-materials.json');anchor=read(HERE/'data/additions172-anchor.json')
 assert manifest['glib_material_contract']==pin(HERE/'data/glib-materials.json')
 assert {n:{k:r[k]for k in ['filename','version','archive','metadata']}for n,r in manifest['archives'].items()if n!='glib2'}==anchor
 for row,role in [(manifest['archives']['glib2'],'new'),(manifest['rollback'],'old')]:
  fixed=facts[role];assert row['version']==fixed['metadata']['pkgver'][0]and row['filename']=='glib2-'+row['version']+'-aarch64.pkg.tar.xz'and row['archive']==fixed['archive']and row['signature']==facts['signature_pins'][role]and row['metadata']==fixed['metadata']and row['signer_role']=='official'and row['expected_signer']==OFFICIAL
  checked(materials/row['filename'],row['archive']);checked(materials/(row['filename']+'.sig'),row['signature'])
 assert facts['symbol_join']['both_measured_missing_symbols_now_exported']is True and facts['symbol_join']['old_exports_lost']==[]and facts['symbol_join']['new_missing_GTK_GLib_prefix_symbols']==[]
def preflight(args,phase='prepare'):
 # Null admissions are checked before source imports/material scans/output/actors.
 checked(args.authority,{'bytes':args.authority.stat().st_size,'sha256':args.authority_sha256});authority=admission(read(args.authority),phase);assert authority['source_lock']==source();refs,arm,x86,A=references()
 checked(args.kernel_bundle/'bundle.json',authority['kernel_bundle']);kernel=A.kernel(args.kernel_bundle,authority)
 checked(args.qemu_metadata,authority['qemu_metadata']);tool=read(args.qemu_metadata)
 checked(args.tool_qualification,authority['tool_qualification']);qualification=read(args.tool_qualification);qualified_tool(tool,authority['tool_image_id'],qualification,ROOT/refs['tool_producer']['path']);assert qualification['Root_device_help_metadata']==pin(args.qemu_metadata)
 base,marker=A.baseline(args.base,args.base_first_boot_report)
 for field,path in [('minimal155_report',args.minimal155_report),('minimal155_prepared',args.minimal155_prepared)]:checked(path,authority[field])
 minimal=minimal_seat_report(read(args.minimal155_report));previous=read(args.minimal155_prepared);assert previous['kernel']==kernel and previous['lineage']['base_files']['guest.raw']==A.lock()['base_files']['guest.raw']
 assert previous['operation']=='arm16k-virtio-seat-vm-v1'and len(previous['lineage']['additions']['archives'])==44 and previous['authority']['tool_image_id']==authority['tool_image_id']and minimal['image_id']==authority['tool_image_id']
 checked(args.additions_manifest,authority['additions_manifest']);manifest=read(args.additions_manifest);rows=manifest['archives'];assert manifest['kind']=='ARM16K_FIRST_LOGIN_UI_GLIB290_ADDITIONS_V1'and manifest['status']=='ROOT_REVIEWED_COMPLETE_GLIB290_UI283_CLOSURE'and manifest['issued_by']=='Root'and len(rows)==173 and manifest['baseline_prepared']==A.lock()['base_prepared']and set(rows)&{r['name']for r in base['base_packages']}=={'glib2'};validate_prepare_proof(manifest['metadata_prepare'],rows);validate_glib_manifest(manifest,args.materials)
 assert rows['xorg-server-xvfb']['version']=='21.1.26-1'and rows['xorg-server-xvfb']['archive']['sha256']=='c4729aaf327fae3f19795f4fbcad8035798316d4c812c56953c32796f1cf916c'
 deadline=time.monotonic()+180;D=load('UI283_finite_packages',HERE/'package_data.py');elf_ref=refs['elf_parser'];checked(elf_ref['path'],{k:elf_ref[k]for k in ['bytes','sha256']});E=load('UI283_existing_ELF',Path(elf_ref['path']));catalog={};compressed=decoded=0
 for name,row in rows.items():
  assert time.monotonic()<deadline,'finite173 DATA deadline';assert re.fullmatch(r'[A-Za-z0-9@._+:-]+\.pkg\.tar\.(xz|zst)',row['filename'])and 0<row['archive']['bytes']<=64*1024**2 and 0<row['signature']['bytes']<=65536;path=checked(args.materials/row['filename'],row['archive']);checked(args.materials/(row['filename']+'.sig'),row['signature']);compressed+=row['archive']['bytes'];assert compressed<=256*1024**2
  data=D.package(path,E);meta=data['metadata'];assert meta==row['metadata']and meta['pkgname']==[name]and meta['pkgver']==[row['version']]and meta['arch']in [['aarch64'],['any']];decoded+=data['logical_bytes'];assert decoded<=2*1024**3
  if name in PROJECT:assert row['archive']['sha256']==PROJECT[name]and meta['arch']==['any']and row['signer_role']=='project'
  else:assert row['signer_role']=='official'and row['expected_signer']==OFFICIAL
  catalog[name]=data
  if name=='glib2':assert data['payload']==read(HERE/'data/glib-materials.json')['new']['payload']
 audit=load('UI_GLib290_fixed_ELF_DATA',HERE/'glib_data_audit.py');audit.check(args.materials/manifest['rollback']['filename'],args.materials/rows['glib2']['filename'],args.materials/rows['gtk4']['filename'],read(HERE/'data/glib-materials.json'),rows['gtk4']['archive'],E)
 namespace(manifest,catalog,base)
 validate_edges(manifest,catalog,base,arm)
 for role,row in manifest['trust']['keyrings'].items():assert role in ['official','project']and row['filename']==role+'-public.gpg'and 0<row['pin']['bytes']<=65536 and re.fullmatch('[0-9A-F]{40}',row['primary']);checked(args.materials/row['filename'],row['pin'])
 for key in ['public_packets','public_packets_dependency']:
  ref=refs[key];checked(ref['path'],{k:ref[k]for k in ['bytes','sha256']})
 packet_reader=load('UI_public_only_packets',Path(refs['public_packets']['path']))
 for role,row in manifest['trust']['keyrings'].items():
  path=args.materials/row['filename'];assert path.stat().st_size<=65536;packet_reader.packets(path.read_bytes())
 assert set(manifest['trust']['keyrings'])=={'official','project'}
 return {'authority':authority,'refs':refs,'arm':arm,'x86':x86,'lower':A,'kernel':kernel,'tool':tool,'tool_qualification':qualification,'base':base,'original_marker':marker,'manifest':manifest,'catalog':catalog,'compressed_bytes':compressed,'decoded_bytes':decoded}
def preparation_confinement(row,name,image_id,labels,mounts):
 assert row['Name']=='/'+name and row['Image']==image_id and row['Config']['Labels']==labels and row['Config']['Entrypoint']==['/usr/bin/python3']and row['Config']['Cmd']==['-I','-B','/code/prepare_image.py']
 assert len(row['Mounts'])==9 and {(x['Type'],x['Source'],x['Destination'],x['RW'])for x in row['Mounts']}==set(mounts)
 h=row['HostConfig'];assert h['NetworkMode']=='none'and h['ReadonlyRootfs']and h['CapDrop']==['ALL']and not h['CapAdd']and not h['Privileged']and not h['Devices']and not h.get('DeviceRequests')and h.get('PidMode','')==''and h.get('IpcMode','private')=='private'and h.get('UTSMode','')==''and h['Init']is False and h['SecurityOpt']==['no-new-privileges']and h['Memory']==h['MemorySwap']==3*1024**3 and h['NanoCpus']==2000000000 and h['PidsLimit']==256

def output_path(path,phase='prepare'):
 assert path.is_absolute()and not path.exists()and not path.is_symlink()and '..'not in path.parts and re.fullmatch('[A-Za-z0-9_/.:-]+',str(path));assert any(root in path.parents for root in [Path('/tmp'),Path('/dev/shm')]);assert path.parent.is_dir()and not any(p.is_symlink()for p in path.parents)
 root=next(r for r in [Path('/tmp'),Path('/dev/shm')]if r in path.parents);parent=path.parent
 while parent!=root:
  info=parent.stat();assert info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)&0o077==0,'private owned ancestors required';parent=parent.parent
 assert phase in ['prepare','boot'];allocation=DISK_BUDGETS['prepare_allocated_bytes']if phase=='prepare'else DISK_BUDGETS['overlay_allocated_bytes']+DISK_BUDGETS['future_diagnostic_bytes']+DISK_BUDGETS['boot_nonoverlay_bytes'];assert shutil.disk_usage(path.parent).free>=2*1024**3+allocation,'finiteallocation plus2GiBreserve required';return path
