#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite fail-closed ARM seat input contracts; no process/daemon/guest calls."""
import hashlib,importlib.util,json,os,re,shutil,stat,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
OP='arm16k-virtio-seat-vm-v1'
PARENT_IMAGE='sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207'
IMAGE='sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a'
POLICY='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'
RULE='b57a64ab6c973d0b734dea808e6caf9a49b40739c7c7649784d09bd6d90c36d3'
PAM=('/etc/pam.d/login','/etc/pam.d/system-login','/etc/pam.d/system-local-login','/etc/pam.d/system-auth')
REQUIRED={'usr/bin/python3':'python','usr/bin/pkaction':'polkit','usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy':'networkmanager'}

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def pin(path):
 path=Path(path)
 if path.is_symlink() or not path.is_file():raise ValueError('ordinary pinned file required')
 with path.open('rb') as f:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def reference_pin(ref):
 return isinstance(ref,dict) and set(ref)=={'bytes','sha256'} and type(ref['bytes']) is int and ref['bytes']>0 and bool(re.fullmatch('[0-9a-f]{64}',ref.get('sha256','')))

def checked(path,ref):
 if not isinstance(ref,dict) or set(ref)!={'bytes','sha256'} or type(ref['bytes']) is not int or ref['bytes']<1 or not re.fullmatch('[0-9a-f]{64}',ref.get('sha256','')) or pin(path)!=ref:raise ValueError('exact input bytes/hash required')
 return Path(path)
def read_json(path,cap=8*1024**2):
 if Path(path).stat().st_size>cap:raise ValueError('bounded JSON input required')
 return json.loads(Path(path).read_text())
def lock():return read_json(HERE/'inputs.lock.json')
def source():
 origin=read_json(HERE/'origin.json')
 for n,r in origin['frozen_files'].items():checked(HERE/n,r)
 # New source itself is sealed externally by Root through source.lock.
 sealed=read_json(HERE/'source.lock.json')
 expected={str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file() and p not in (HERE/'source.lock.json',HERE/'RESULTS.json')}
 if sealed.get('kind')!='ARM16K_VIRTIO_SEAT_SOURCE_LOCK_V1' or set(sealed.get('files',{}))!=expected:raise ValueError('complete exact new source namespace required')
 for n,r in sealed['files'].items():checked(HERE/n,r)
 tool_qualification()
 return pin(HERE/'source.lock.json')
def qualification_value(d):
 if d.get('kind')!='ARM16K_VIRTIO_TOOL_IMAGE_V1' or d.get('status')!='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST' or d.get('image_id')!=IMAGE or d.get('parent_image_id')!=PARENT_IMAGE or d.get('guest_boot')!='NOT RUN' or d.get('release_accepted') is not False or d.get('owned_containers_absent') is not True:raise ValueError('actual separately qualified derived image required')
 if d.get('required_devices')!={'virtio-blk-device':True,'virtio-keyboard-device':True,'virtio-gpu-device':True}:raise ValueError('all three actual device declarations required')
 cleanup=d.get('cleanup',[])
 if len(cleanup)!=2 or any(row.get('cleanup_errors')!=[] or not all(row.get(k) is True for k in ('cleanup_ownership_verified','owned_container_absence_verified','owned_container_removed')) for row in cleanup):raise ValueError('actual qualified tool ownership/absence required')
 package=d.get('package',{})
 if package.get('name')!='qemu-hw-display-virtio-gpu' or package.get('version')!='11.1.3-1' or package.get('filename')!='qemu-hw-display-virtio-gpu-11.1.3-1-x86_64.pkg.tar.zst':raise ValueError('single matching official GPU module package required')
 return d

def tool_qualification():
 ref=lock()['tool_qualification'];checked(HERE/ref['file'],ref['pin']);d=qualification_value(read_json(HERE/ref['file']))
 checked(HERE/ref['device_metadata_file'],ref['device_metadata_pin'])
 if d['Root_device_help_metadata']!=ref['device_metadata_pin']:raise ValueError('whole qualification/device help join differs')
 return d

def authority(path,sha,phase):
 checked(path,{'bytes':Path(path).stat().st_size,'sha256':sha});a=read_json(path)
 if a.get('kind')!='ARM16K_VIRTIO_SEAT_VM_AUTHORITY_V1' or a.get('issued_by')!='Root' or a.get('operation')!=OP or a.get('tool_image_id')!=IMAGE or a.get('allow_'+phase) is not True:raise ValueError('fresh explicit Root operation authority required')
 if a.get('tool_qualification')!=lock()['tool_qualification']['pin']:raise ValueError('whole actual derived-tool qualification pin required')
 if a.get('source_lock')!=source() or a.get('actor')!=pin(HERE/'seat_actor.py') or not isinstance(a.get('resource_review'),dict) or a['resource_review'].get('status')!='ROOT_REVIEWED_FINITE_RESOURCES':raise ValueError('source/actor/resource authority incomplete')
 for k in ('kernel_bundle','additions_manifest','qemu_metadata'):
  if not reference_pin(a.get(k)):raise ValueError('actual nonnull kernel/addition/tool pins required')
 return a

def kernel(directory,a):
 directory=Path(directory)
 if directory.is_symlink() or set(p.name for p in directory.iterdir())!={'Image','config','bundle.json'}:raise ValueError('exact distinct UI-seat kernel bundle required')
 checked(directory/'bundle.json',a['kernel_bundle']);b=read_json(directory/'bundle.json')
 if b.get('kind')!=lock()['kernel_kind'] or b.get('status')!=lock()['kernel_status'] or b.get('release_accepted') is not False:raise ValueError('built-only UI-seat kernel kind/status required')
 K=load('seat_ui_kernel',HERE/'frozen/arm16k_ui_seat_kernel/contract.py')
 if b['kernel_release']!=K.lock()['kernel_release']:raise ValueError('UI-seat release differs')
 for name in ('Image','config'):checked(directory/name,b['files'][name])
 proof=K.final_config((directory/'config').read_bytes(),b['config_proof']['compiler_facts']);K.header(directory/'Image')
 if proof!=b['config_proof']:raise ValueError('full kernel config proof differs')
 expected={'revision':K.lock()['upstream_revision'],'archive':{k:K.lock()['archive'][k] for k in ('bytes','sha256')},'original_source':K.lock()['original_native_source'],'original_run':K.lock()['original_run']}
 if b['source']!=expected:raise ValueError('original source lineage differs')
 return b

def tool_metadata(path,a):
 tool_qualification()
 checked(path,a['qemu_metadata']);d=read_json(path)
 if pin(path)!=lock()['tool_qualification']['device_metadata_pin']:raise ValueError('exact actual derived-image device metadata required')
 if d.get('kind')!='ROOT_OBSERVED_ARM_QEMU_DEVICE_HELP_V1' or d.get('issued_by')!='Root' or d.get('status')!='OBSERVED_DEVICE_HELP_ONLY' or d.get('image_id')!=IMAGE or d.get('qemu_path')!='/usr/bin/qemu-system-aarch64' or d.get('devices')!=['virtio-blk-device','virtio-keyboard-device','virtio-gpu-device'] or not reference_pin(d.get('actual_tool_pin')) or not reference_pin(d.get('actual_help_pin')) or not isinstance(d.get('actual_observed_utc'),str):raise ValueError('actual pinned ARM device-help metadata required')
 return d

def baseline(base,proof_path):
 s=lock();base=Path(base);checked(base/'prepared.json',s['base_prepared']);d=read_json(base/'prepared.json')
 for n,r in s['base_files'].items():checked(base/n,r)
 checked(proof_path,{k:s['required_base_first_boot'][k] for k in ('bytes','sha256')});p=read_json(proof_path)
 if p.get('status')!=s['required_base_first_boot']['status'] or p['session']['ARCH']!='aarch64' or p['session']['PAGESIZE']!='16384' or not p.get('normal_PAM_logout_observed') or not p.get('owned_container_absence_verified'):raise ValueError('genuine original ARM16K PAM/retirement proof required')
 if len(d['base_packages'])!=111 or len({r['name'] for r in d['base_packages']})!=111:raise ValueError('exact pristine111 package index required')
 marker=base/'arm16k-first-boot-attempt.json'
 return d,pin(marker)

def additions(path,materials,base,a):
 checked(path,a['additions_manifest']);d=read_json(path);materials=Path(materials);s=lock()
 if d.get('kind')!='ARM16K_VIRTIO_SEAT_ADDITIONS_V1' or d.get('status')!='ROOT_REVIEWED_COMPLETE_MINIMAL_SEAT_CLOSURE' or d.get('issued_by')!='Root' or d.get('baseline_prepared')!=s['base_prepared']:raise ValueError('explicit audited minimal additions closure required')
 rows=d.get('archives',{})
 if not 4<=len(rows)<=s['max_additions'] or not {'python','python-gobject','polkit','networkmanager'}<=rows.keys():raise ValueError('genuine minimal Python/GIR/Polkit/NM providers required')
 base_index={r['name']:r for r in base['base_packages']}
 bm=d['baseline_metadata']
 if set(bm)!=set(base_index) or not isinstance(d.get('baseline_metadata_provenance'),dict) or not d['baseline_metadata_provenance']:raise ValueError('audited original111 provides/file ownership metadata required')
 for name,row in bm.items():
  if row['version']!=base_index[name]['version'] or row['directory']!=base_index[name]['directory'] or not isinstance(row['provides'],list) or not isinstance(row['files'],list):raise ValueError('exact baseline metadata association differs')
 if set(rows)&base_index.keys():raise ValueError('baseline package replacement/upgrade forbidden')
 base_paths={p for row in bm.values() for p in row['files']}
 for tool in ('base64','bash','cat','cut','date','getconf','gpg','grep','head','install','pacman','sha256sum','sleep','sort','stat','sync','systemctl','timeout','uname','wc'):
  if 'usr/bin/'+tool not in base_paths:raise ValueError('fixed root-service tool absent in exact111 namespace: '+tool)
 deadline=time.monotonic()+120;decoded=0
 A=load('seat_package_data',HERE/'frozen/package_data.py');S=load('seat_alpm_versions',HERE/'frozen/alpm_versions.py');catalog={};compressed=0
 for name,row in sorted(rows.items()):
  file=row['filename']
  if not re.fullmatch(r'[A-Za-z0-9@._+:-]+\.pkg\.tar\.xz',file) or row.get('official_repository') is not True or not isinstance(row.get('source_provenance'),dict) or not row['source_provenance']:raise ValueError('pinned original official archive lineage required')
  checked(materials/file,row['archive']);checked(materials/(file+'.sig'),row['signature']);compressed+=row['archive']['bytes']+row['signature']['bytes']
  if compressed>s['archive_bytes_cap']:raise ValueError('finite minimal archive budget exceeded')
  if not re.fullmatch('[0-9A-F]{40}',row['expected_signer']):raise ValueError('exact original signer fingerprint required')
  if time.monotonic()>=deadline:raise TimeoutError('bounded package DATA preflight deadline')
  data=A.package(materials/file);decoded+=data['logical_bytes']
  if decoded>512*1024**2:raise ValueError('finite total decoded archive budget exceeded')
  meta=data['metadata']
  if meta!=row['metadata'] or meta.get('pkgname')!=[name] or meta.get('pkgver')!=[row['version']] or meta.get('arch') not in (['aarch64'],['any']):raise ValueError('actual archive metadata/architecture differs or replaces baseline')
  catalog[name]=data
 if d['keyring']['filename']!='archlinuxarm.gpg':raise ValueError('fixed original public ALARM keyring filename required')
 checked(materials/d['keyring']['filename'],d['keyring']['pin'])
 provides={}
 all_rows={name:{'version':r['version'],'provides':bm[name]['provides']} for name,r in base_index.items()}
 all_rows.update({name:{'version':row['version'],'provides':catalog[name]['metadata'].get('provides',[])} for name,row in rows.items()})
 for name,row in all_rows.items():
  provides.setdefault(name,[]).append((name,row['version']))
  for expression in row['provides']:
   symbol,op,version=S.atom(expression)
   if op not in (None,'='):raise ValueError('unhandled provides format')
   provides.setdefault(symbol,[]).append((name,version))
 metadata_prepare=d.get('metadata_prepare',{});selected_edges=metadata_prepare.get('dependencies',[])
 edges=[]
 for name,data in sorted(catalog.items()):
  if time.monotonic()>=deadline:raise TimeoutError('bounded dependency DATA preflight deadline')
  for expression in data['metadata'].get('depend',[]):
   symbol,op,wanted=S.atom(expression)
   chosen=[r['provider'] for r in selected_edges if r.get('package')==name and r.get('relation')==expression]
   if len(chosen)!=1:raise ValueError('exact actual ALPM dependency provider edge required')
   found=[(n,v) for n,v in provides.get(symbol,[]) if n==chosen[0] and S.satisfies(v,op,wanted)]
   if not found:raise ValueError('selected real ALPM provider does not satisfy: '+expression)
   found=sorted(set(found),key=lambda r:(r[0],r[1] or ''))
   provider,version=found[0];edges.append({'package':name,'dependency':expression,'provider':provider,'version':version})
  for expression in data['metadata'].get('conflict',[])+data['metadata'].get('replaces',[]):
   symbol,op,wanted=S.atom(expression)
   if any(n!=name and S.satisfies(v,op,wanted) for n,v in provides.get(symbol,[])):raise ValueError('actual selected conflict: '+expression)
 prepare=d.get('metadata_prepare',{})
 if prepare.get('status')!='PASS_EXPLICIT_FINITE_METADATA_PREPARE' or prepare.get('baseline_preserved')!=111 or prepare.get('final_count')!=111+len(rows) or prepare.get('conflicts')!=[]:raise ValueError('actual protected baseline ALPM metadata prepare proof required')
 actual=prepare.get('prepare',{})
 if actual.get('libalpm_version')!='16.0.1' or actual.get('prepare_exit')!=0 or actual.get('prepare_errno')!=0 or any(actual.get(k)!=[] for k in ('errors','callback_errors','questions','remove')):raise ValueError('zero-error/no-removal/no-question ALPM prepare required')
 if {x['name']:x['version'] for x in actual['add']}!={n:r['version'] for n,r in rows.items()}:raise ValueError('exact ALPM prepared addition set differs')
 namespace=d.get('required_namespace',{})
 def actual_payload(path,row):
  owner=row.get('owner')
  if owner in catalog:return catalog[owner]['payload'].get(path)
  if owner in bm and path in bm[owner]['files'] and d['original_file_pins'].get('/'+path)==row.get('payload',{}).get('sha256'):return row['payload']
  return None
 for path,owner in REQUIRED.items():
  row=namespace.get(path)
  if not row or row.get('owner')!=owner or actual_payload(path,row)!=row.get('payload'):raise ValueError('required namespace/policy has no actual provider ownership')
 pyver=rows['python']['version'].split(':')[-1].split('.')
 if len(pyver)<2 or pyver[:2]!=['3','14']:raise ValueError('reviewed Python3.14 namespace required')
 for path in ('usr/lib/python3.14/site-packages/gi/__init__.py','usr/lib/girepository-1.0/Gio-2.0.typelib','usr/lib/girepository-1.0/GLib-2.0.typelib'):
  row=namespace.get(path,{})
  if actual_payload(path,row)!=row.get('payload') or row.get('payload',{}).get('type')!='0':raise ValueError('actual Python/GIR runtime namespace missing')
 policy=catalog['networkmanager']['payload'][next(p for p in REQUIRED if p.endswith('.policy'))]
 if policy['type']!='0' or policy['sha256']!=POLICY:raise ValueError('genuine installed NM policy bytes required; no XML injection')
 for p in PAM:
  if p not in d.get('original_file_pins',{}) or not re.fullmatch('[0-9a-f]{64}',d['original_file_pins'][p]):raise ValueError('actual original ARM PAM file pins required')
 if d['original_file_pins'].get('/usr/lib/udev/rules.d/71-seat.rules')!=RULE:raise ValueError('stock seat rule pin required')
 return d,catalog,edges

def output_path(path):
 path=Path(path)
 if not path.is_absolute() or '..' in path.parts or not re.fullmatch('[A-Za-z0-9_/.:-]+',str(path)):raise ValueError('ordinary absolute output required')
 root=next((r for r in (Path('/tmp'),Path('/dev/shm')) if r in path.parents),None)
 if root is None or path.exists() or any(p.is_symlink() for p in (path,*path.parents)) or not path.parent.is_dir():raise ValueError('fresh private /tmp or /dev/shm output required')
 p=path.parent
 while p!=root:
  st=p.stat()
  if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:raise ValueError('private owned ancestors required')
  p=p.parent
 if shutil.disk_usage(path.parent).free<lock()['prep_allocated_cap']+lock()['reserve_bytes']:raise ValueError('actual parent filesystem cap/reserve unavailable')
 return path
