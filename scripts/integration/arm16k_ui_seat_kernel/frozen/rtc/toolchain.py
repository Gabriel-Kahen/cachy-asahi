#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate one explicitly pinned new tool environment; never infer LLVM18 parity."""
import hashlib,json,os,platform,re,shutil,subprocess
from pathlib import Path
TOOLS=('make','clang','clang++','ld.lld','llvm-ar','llvm-nm','llvm-strip','llvm-objcopy','llvm-objdump','llvm-readelf','bison','flex','bc','perl','sh','pahole','openssl','pkg-config')


def environment(p):
 fields={k:p[k] for k in ('mode','host_architecture','target_architecture','image_id','tools','runtime_files','packages')}
 fields.update({k:p.get(k) for k in ('runtime_domain','host_inventory','ld_cache')})
 return hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def profile(path,sha256,C,compile_stage=False):
 C.checked(path,{'bytes':path.stat().st_size,'sha256':sha256});p=json.loads(path.read_text())
 if p.get('schema_version')!=1 or p.get('operation')!=C.lock()['operation'] or p.get('status')!='ROOT_REVIEWED_NEW_TOOL_ENVIRONMENT':raise ValueError('pending/unreviewed tool profile')
 if p.get('mode') not in ('HOST_CROSS_ARM64','NATIVE_ARM64') or p.get('same_toolchain') is not False:raise ValueError('explicit new cross/native provenance required')
 if p.get('runtime_domain') not in ('HOST_USR_READONLY_BIND_V1','IMMUTABLE_IMAGE_TOOLCHAIN_V1'):raise ValueError('explicit reviewed runtime domain required; no fallback')
 expected='x86_64' if p['mode']=='HOST_CROSS_ARM64' else 'aarch64'
 if platform.machine()!=expected or p.get('host_architecture')!=expected or p.get('target_architecture')!='arm64':raise ValueError('build/target architecture mismatch')
 if not re.fullmatch('sha256:[0-9a-f]{64}',p.get('image_id','')):raise ValueError('exact reviewed isolated build-image identity required')
 if set(p.get('tools',{}))!=set(TOOLS) or not p.get('runtime_files') or not p.get('packages') or p.get('runtime_closure_reviewed') is not True:raise ValueError('complete actual compiler/package/library closure required')
 if p.get('environment_sha256')!=environment(p):raise ValueError('exact image/tool/package environment join differs')
 actual={}
 for name,row in p['tools'].items():
  located=shutil.which(name,path='/tools/bin:/usr/bin:/bin')
  if not located or str(Path(located).resolve())!=row['path']:raise ValueError('fixed actual tool resolution differs: '+name)
  C.checked(Path(row['path']),row);actual[name]=row
 for name,row in p['runtime_files'].items():
  if not name.startswith(('/usr/lib/','/usr/bin/')):raise ValueError('bounded tool runtime path required')
  C.checked(Path(name),row)
 if p.get('runtime_domain')=='HOST_USR_READONLY_BIND_V1':
  if p['mode']!='HOST_CROSS_ARM64' or not os.statvfs('/usr').f_flag&os.ST_RDONLY:raise ValueError('explicit readonly host-/usr cross domain required')
  C.checked(Path('/etc/ld.so.cache'),p['ld_cache']);C.checked(Path('/inputs/host-provenance.json'),p['host_provenance']);snapshot=json.loads(Path('/inputs/host-provenance.json').read_text())
  if snapshot.get('status')!='HOST_USR_BOUND_INPUTS_VERIFIED' or snapshot.get('source_inventory')!=p['host_inventory'] or snapshot.get('packages')!=p['packages']:raise ValueError('exact preflight host ALPM/source provenance differs')
 else:
  result=subprocess.run(['/usr/bin/pacman','-Q'],capture_output=True,timeout=10)
  if result.returncode or len(result.stdout)>1024**2:raise ValueError('bounded actual build package inventory required')
  actual_packages=dict(line.split() for line in result.stdout.decode().splitlines());wanted={name:(row['version'] if isinstance(row,dict) else row) for name,row in p['packages'].items()}
  if actual_packages!=wanted:raise ValueError('actual complete isolated package inventory differs')
 if compile_stage and (p.get('compiler_facts') is None or not re.fullmatch('[0-9a-f]{64}',p.get('configured_result_sha256',''))):raise ValueError('configure-only facts must be independently reviewed/pinned before compile')
 return p,actual


def confinement(C):
 if not Path('/.dockerenv').is_file():raise ValueError('admitted isolated container required')
 if os.geteuid()==0:
  mapping=Path('/proc/self/uid_map').read_text().splitlines()[0].split()
  if len(mapping)!=3 or mapping[0]!='0' or int(mapping[1])==0:raise ValueError('container root must map to an ordinary rootless host user')
 fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
 if any(int(fields[k].strip(),16) for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) or fields['NoNewPrivs'].strip()!='1':raise ValueError('zero caps and NNP required')
 import socket
 if {name for _,name in socket.if_nameindex()}!={'lo'} or Path('/dev/kvm').exists():raise ValueError('no network/devices/KVM allowed')
 if not os.statvfs('/').f_flag&os.ST_RDONLY:raise ValueError('read-only container root required')
 # Root admission also checks image, mounts and global capacity externally.
 lines=Path('/proc/self/mountinfo').read_text().splitlines();workspace=[line.split() for line in lines if line.split()[4]=='/work']
 if len(workspace)!=1 or workspace[0][workspace[0].index('-')+1]!='tmpfs':raise ValueError('private size-capped /work tmpfs required')
 row=workspace[0];options=','.join((row[5],row[-1])).split(',')
 if 'nodev' not in options or 'nosuid' not in options or 'noexec' in options:raise ValueError('workspace exec/nodev/nosuid required')
 total=os.statvfs('/work').f_blocks*os.statvfs('/work').f_frsize
 if not 8*1024**3<=total<=C.lock()['build']['workspace_bytes']:raise ValueError('8–16GiB workspace hard cap required')
 for filename,maximum in [('memory.max',C.lock()['build']['memory_bytes']),('pids.max',C.lock()['build']['pids'])]:
  value=Path('/sys/fs/cgroup',filename).read_text().strip()
  if not value.isdecimal() or not 0<int(value)<=maximum:raise ValueError('finite container resource limit differs: '+filename)
 quota,period=Path('/sys/fs/cgroup/cpu.max').read_text().split()
 if not quota.isdecimal() or int(quota)>2*int(period):raise ValueError('at most two CPUs required')
