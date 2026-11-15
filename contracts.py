# SPDX-License-Identifier: MIT
"""Finite offline input guards; no clone, process, daemon or authority creation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time

HERE = Path(__file__).resolve().parent
OP = 'arm16k-rust-stage0-vm-v1'
PREFIX = '/opt/cachy-asahi/rust-stage0'
IMAGE = 'sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a'
GIB = 1024**3
END = None
RESOURCES = dict(guest_cpus=2,guest_memory_bytes=2*GIB,owner_cpus=2,owner_memory_bytes=3*GIB,boot_owner_memory_bytes=4*GIB,owner_swap_bytes=0,pids=256,raw_cap_bytes=3*GIB,prepare_allocated_cap=2*GIB,boot_allocated_cap=2560*1024**2,overlay_cap_bytes=GIB,base_raw_allocated_cap=640*1024**2,prefix_allocated_cap=512*1024**2,extended_raw_allocated_cap=1280*1024**2,output_metadata_allocated_cap=128*1024**2,reserve_bytes=2*GIB,host_memory_reserve_bytes=2*GIB,prepare_seconds=600,boot_seconds=600,work_seconds=555,cleanup_seconds=45)
TOOLS = ('bash','uname','id','getconf','pacman','sort','sha256sum','readlink','cat','mkdir','grep','head','sed','stat','timeout','env','date','sleep','sync','cp','rm','ld')
GUEST_INPUT_KIND = 'ARM16K_RUST_STAGE0_BASE111_DYNAMIC_GCC_INPUTS_V2'
GCC_S_PATH = '/usr/lib/libgcc_s.so.1'
GCC_S_PIN = dict(bytes=133352,sha256='ac598673a4bf67c0295b6609e46b1fafd0d4adf3f80a513d61ac49ecff772e48',owner='libgcc',version='16.1.1+r12+g301eb08fa2c5-1',resolved=GCC_S_PATH)
REQUIRED_PATHS = ['/usr/bin/'+name for name in TOOLS]+['/usr/lib/Scrt1.o','/usr/lib/crti.o','/usr/lib/crtn.o','/lib/ld-linux-aarch64.so.1','/usr/lib/libc.so.6','/usr/lib/libdl.so.2','/usr/lib/libgcc_s.so.1','/usr/lib/libm.so.6','/usr/lib/libpthread.so.0','/usr/lib/librt.so.1','/usr/lib/libz.so.1']


def need(ok, why):
    if not ok:raise ValueError(why)
    if END is not None and time.monotonic() >= END:raise TimeoutError('finite Root operation budget exhausted')


def ordinary(value):
    p = Path(value)
    need(p.is_absolute() and '..' not in p.parts and not any(q.is_symlink() for q in (p,*p.parents)), 'ordinary absolute path required')
    return p


def pin(value):
    p = ordinary(value)
    fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before = os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'single-link regular DATA required')
        h = hashlib.sha256()
        while chunk := stream.read(1024**2):
            need(True,'bounded hashing');h.update(chunk)
        checksum = h.hexdigest();after = os.fstat(stream.fileno())
    key = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
    need(key(before) == key(after) == key(p.lstat()), 'input changed while hashed')
    return dict(bytes=before.st_size,sha256=checksum)


def checked(path, expected):
    need(type(expected) is dict and set(expected) == {'bytes','sha256'} and type(expected['bytes']) is int and expected['bytes'] > 0 and re.fullmatch('[0-9a-f]{64}',expected['sha256'] or ''), 'nonnull exact input pin required')
    need(pin(path) == expected, 'input bytes differ: '+str(path));return Path(path)


def load(path, cap=8*1024**2):
    p = ordinary(path);need(p.stat().st_size <= cap, 'JSON size bound')
    def pairs(rows):
        out = {}
        for key,value in rows:need(key not in out,'duplicate JSON key');out[key] = value
        return out
    return json.loads(p.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def helper(name):
    origin = load(HERE/'origin.json');file = HERE/'frozen'/name
    checked(file,{k:origin['files']['frozen/'+name][k] for k in ('bytes','sha256')})
    spec = importlib.util.spec_from_file_location('rust16k_'+name.replace('.','_'),file)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def source():
    s = load(HERE/'source.lock.json')
    need(s['kind'] == 'ARM16K_RUST_STAGE0_SOURCE_LOCK_V1' and all(v is None for v in s['actual'].values()), 'closed unpublished Source declaration required')
    found = set()
    for current,dirs,files in os.walk(HERE,followlinks=False):
        for name in dirs:need(not (Path(current)/name).is_symlink(), 'Source directory alias')
        found.update((Path(current)/name).relative_to(HERE).as_posix() for name in files)
    need(found == set(s['files'])|{'source.lock.json'}, 'complete Source membership differs')
    for name,row in s['files'].items():
        checked(HERE/name,{k:row[k] for k in ('bytes','sha256')})
        need(stat.S_IMODE((HERE/name).stat().st_mode) == row['mode'], 'Source file mode differs')
    return pin(HERE/'source.lock.json')


def authority(path, expected, phase, publication):
    p = ordinary(path);need(pin(p)['sha256'] == expected, 'external Root authority digest required');a = load(p)
    need(a.get('kind') == 'ARM16K_RUST_STAGE0_VM_AUTHORITY_V1' and a.get('issued_by') == 'Root' and a.get('operation') == OP and a.get('allow_'+phase) is True, 'fresh Root operation/phase authority required')
    need(a['source_lock'] == source() and a['tool_image_id'] == IMAGE and a['resources'] == RESOURCES, 'exact Source/tool/resource review required')
    need(a['resource_review']['status'] == 'ROOT_REVIEWED_FINITE_VM_RESOURCES', 'actual Root resource review missing')
    checked(publication,a['publication']);p = load(publication);s = a['public_source']
    need(p['issued_by'] == 'Root' and p['status'] == 'ROOT_PUBLISHED_AND_READ_BACK_EXACT_SOURCE' and p['operation'] == OP and p['source_lock'] == a['source_lock'] and p['repository'] == 'Gabriel-Kahen/cachy-asahi', 'genuine Root public Source readback required')
    for key in ('source','tree'):need(re.fullmatch('[0-9a-f]{40}',s.get(key) or '') and p[key] == s[key], 'actual public Source/tree required')
    need(re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',s.get('ref') or '') and p['ref'] == s['ref'], 'actual public Source ref required')
    return a


def baseline(base, report):
    expected = load(HERE/'data/base.json');base = ordinary(base)
    checked(base/'prepared.json',expected['prepared']);b = load(base/'prepared.json')
    for name,row in expected['files'].items():checked(base/name,row)
    checked(base/'arm16k-first-boot-attempt.json',expected['original_marker']);checked(report,expected['first_boot_report']);proof = load(report)
    need(proof['status'] == expected['first_boot_status'] and proof['normal_PAM_logout_observed'] is True and proof['owned_container_absence_verified'] is True and not proof['cleanup_errors'] and proof['session']['ARCH'] == 'aarch64' and proof['session']['PAGESIZE'] == '16384', 'original PAM/retirement prerequisite incomplete')
    need(b['base_packages'] == expected['base_packages'] and len(b['base_packages']) == 111 and b['nonce'] == expected['base_nonce'], 'exact original111 baseline required')
    return b,expected


def kernel(directory, a):
    directory = ordinary(directory);expected = load(HERE/'data/kernel.json')
    need({p.name for p in directory.iterdir()} == {'bundle.json','Image','config'}, 'exact kernel bundle membership required')
    checked(directory/'bundle.json',expected['bundle']);need(a['kernel_bundle'] == expected['bundle'], 'Root must select exact current RTC/UI-seat bundle')
    b = load(directory/'bundle.json')
    need(b['kind'] == expected['kind'] and b['kernel_release'] == expected['kernel_release'] and b['status'] == expected['status'] and b['release_accepted'] is False and b['files'] == expected['files'], 'exact built-only RTC bundle required')
    for name,row in b['files'].items():checked(directory/name,row)
    helper('rtc_contract.py').header(directory/'Image')
    config = helper('rtc_contract.py').values((directory/'config').read_bytes())
    for name in ('ARM64_16K_PAGES','RTC_DRV_PL031','RTC_HCTOSYS','RTC_INTF_SYSFS','EXT4_FS','VIRTIO_BLK','VIRTIO_MMIO','SERIAL_AMBA_PL011_CONSOLE'):
        need(config.get('CONFIG_'+name) == 'y', 'required built-in RTC/16K platform option missing')
    return b


def tools(metadata,a):
    expected = pin(HERE/'data/qemu-metadata.json');need(a['qemu_metadata'] == expected, 'Root must bind exact qualified tool metadata')
    checked(metadata,expected);m = load(metadata);q = load(HERE/'data/tool-qualification.json')
    need(m['image_id'] == q['image_id'] == IMAGE and q['owned_containers_absent'] is True and q['Root_device_help_metadata'] == expected, 'qualified tool image/provenance incomplete')
    need(m['status'] == 'OBSERVED_DEVICE_HELP_ONLY' and m['qemu_path'] == '/usr/bin/qemu-system-aarch64' and 'virtio-blk-device' in m['devices'], 'actual QEMU tool metadata missing')
    return m


def materials(directory,a):
    spec = load(HERE/'data/stage0.json');need(a['stage0_data'] == pin(HERE/'data/stage0.json'), 'Root stage0 DATA selection missing')
    for name,row in spec['archives'].items():checked(ordinary(directory)/name,{k:row[k] for k in ('bytes','sha256')})
    module_spec=importlib.util.spec_from_file_location('stage0_preflight_data',HERE/'stage0.py');m=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(m);m.verify_specs(HERE/'data',spec)
    return spec


def guest_inputs(path,a,base):
    checked(path,a['guest_inputs']);g = load(path)
    need(g['kind'] == GUEST_INPUT_KIND and g['issued_by'] == 'Root' and g['status'] == 'ROOT_REVIEWED_READONLY_BASE111_INPUTS' and g['base_raw'] == base['files']['guest.raw'] and g['expected111'] == pin(HERE/'data/expected111.lock'), 'Root readonly dynamic-gcc guest input inspection required before actor/clone')
    need(set(g['link_inputs']) == {'gcc_s','util','rt','pthread','m','dl','c'}, 'finite direct-ld library inputs incomplete')
    required = set(REQUIRED_PATHS)|set(g['link_inputs'].values())
    need(set(g['files']) == required, 'complete explicit linker/CRT/loader/tool file binding required')
    versions = {r['name']:r['version'] for r in base['base_packages']}
    for name,chosen in g['link_inputs'].items():need(chosen in ((GCC_S_PATH,) if name=='gcc_s' else ('/usr/lib/lib'+name+'.so','/usr/lib/lib'+name+'.a')), 'direct GNU ld search selection differs')
    need(g['files'][GCC_S_PATH] == GCC_S_PIN,'exact retained dynamic libgcc payload/owner/version pin required')
    for path,row in g['files'].items():
        need(path.startswith('/') and '..' not in Path(path).parts and set(row) == {'bytes','sha256','owner','version','resolved'} and type(row['bytes']) is int and row['bytes'] > 0 and re.fullmatch('[0-9a-f]{64}',row['sha256'] or '') and row['owner'] in versions and row['version'] == versions[row['owner']] and row['resolved'].startswith('/usr/'), 'genuine complete base111 file/owner pins required')
    return g


def quota_guard(auth,parent,phase):
    """Require Root's outer host-UID monitor, covering the entire actor lifetime.

    A static quota snapshot or df alone cannot reserve headroom. This adapter
    performs no quota syscall; Root owns the separate readonly host guard.
    """
    q=auth['resource_review'].get('quota_guard');parent=ordinary(parent)
    cap=RESOURCES['prepare_allocated_cap'] if phase=='prepare' else RESOURCES['boot_allocated_cap']
    if type(q) is dict and q.get('status')=='ROOT_REVIEWED_HOME_BTRFS_ENOSYS_CAPACITY_GUARD_FOR_ENTIRE_ACTOR':
        fields={'issued_by','status','uid','output_parent','device','phase','operation','source_lock','initial_headroom_bytes','live_reserve_bytes','method','on_unknown_or_exhausted','filesystem','unsupported_own_uid_quota','inode_counters','output_node_cap','other_quota_availability','capacity_reservation'}
        need(set(q)==fields and q.get('issued_by')=='Root' and q.get('method')=='READ_ONLY_Q_GETQUOTA_ENOSYS_AND_LIVE_FSTATVFS','explicit Root home-Btrfs whole-actor capacity guard required')
        need(type(q.get('uid')) is int and q['uid']==os.getuid()==1000 and type(q.get('device')) is int and q['device']==parent.stat().st_dev==54 and parent!=Path('/home/gabe') and parent.is_relative_to(Path('/home/gabe')) and q.get('output_parent')==str(parent) and phase in ('prepare','boot') and q.get('phase')==phase,'exact home-Btrfs host UID/device/descendant/phase whitelist required')
        filesystem=dict(root='/home/gabe',device=54,fstype='btrfs',subvolume='/@home',subvolid=257)
        unsupported=dict(query='Q_GETQUOTA',errno=38,status='UNSUPPORTED_OWN_UID_QUOTA')
        need(type(q.get('filesystem')) is dict and json.dumps(q['filesystem'],sort_keys=True,allow_nan=False)==json.dumps(filesystem,sort_keys=True) and type(q.get('unsupported_own_uid_quota')) is dict and json.dumps(q['unsupported_own_uid_quota'],sort_keys=True,allow_nan=False)==json.dumps(unsupported,sort_keys=True),'exact home-Btrfs filesystem and ENOSYS own-UID quota observation required')
        need(q.get('inode_counters')=='ZERO_MEANS_NOT_REPORTED' and type(q.get('output_node_cap')) is int and q['output_node_cap']==15000 and q.get('other_quota_availability')=='UNCLAIMED' and q.get('capacity_reservation') is False,'honest unreported inode/other-quota and non-reservation capacity scope required')
        need(q.get('operation')==OP and q.get('source_lock')==auth['source_lock'] and type(q.get('initial_headroom_bytes')) is int and q['initial_headroom_bytes']==cap+RESOURCES['reserve_bytes'] and type(q.get('live_reserve_bytes')) is int and q['live_reserve_bytes']==RESOURCES['reserve_bytes'] and q.get('on_unknown_or_exhausted')=='HOLD_AND_OWNED_CLEANUP','exact phase capacity headroom/live reserve/Source contract required')
        return q
    need(type(q) is dict and q.get('issued_by')=='Root' and q.get('status')=='ROOT_REVIEWED_OWN_UID_QUOTA_GUARD_FOR_ENTIRE_ACTOR','Root whole-actor own-UID quota guard required; df-only or startup-only check insufficient')
    need(q.get('uid')==os.getuid() and q.get('output_parent')==str(parent) and q.get('device')==parent.stat().st_dev and q.get('phase')==phase,'exact host UID/output filesystem/phase quota guard required')
    need(q.get('operation')==OP and q.get('source_lock')==auth['source_lock'] and q.get('initial_headroom_bytes')==cap+RESOURCES['reserve_bytes'] and q.get('live_reserve_bytes')==RESOURCES['reserve_bytes'] and q.get('method')=='READ_ONLY_Q_GETQUOTA' and q.get('on_unknown_or_exhausted')=='HOLD_AND_OWNED_CLEANUP','exact phase quota headroom/live reserve/Source contract required')
    return q


def capacity(parent, allocated, owner_memory=None):
    parent = ordinary(parent);need(parent.is_dir() and parent.stat().st_uid == os.getuid() and not parent.stat().st_mode & 0o022, 'owned private output parent required')
    space = os.statvfs(parent)
    need(space.f_bavail*space.f_frsize >= allocated+RESOURCES['reserve_bytes'], 'finite sparse allocation plus disk reserve unavailable')
    text = Path('/proc/meminfo').read_text();available = int(next(s.split()[1] for s in text.splitlines() if s.startswith('MemAvailable:')))*1024
    need(available >= (RESOURCES['owner_memory_bytes'] if owner_memory is None else owner_memory)+RESOURCES['host_memory_reserve_bytes'], 'phase owner memory plus 2GiB host reserve unavailable')


def endpoint(authority):
    daemon=authority['daemon'];host=daemon['host']
    need(daemon['status']=='ROOT_REVIEWED_LOCAL_ROOTLESS_ENDPOINT' and type(host) is str and host.startswith('unix:///') and not any(c in host.removeprefix('unix://') for c in '\n\r,:'), 'explicit Root local rootless endpoint required')
    socket=ordinary(host.removeprefix('unix://'));info=socket.lstat();expected=daemon['socket_identity']
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid() and {k:getattr(info,'st_'+k) for k in ('uid','gid','dev','ino')}==expected, 'actual Root-reviewed local daemon socket identity differs')
    return host


def preflight(a,phase):
    need(__debug__ and os.geteuid() == os.getuid() != 0, 'ordinary unoptimized Root-controlled host user required')
    auth = authority(a.authority,a.authority_sha256,phase,a.publication)
    quota_guard(auth,ordinary(a.output).parent,phase)
    base,reference = baseline(a.base,a.base_first_boot_report);k = kernel(a.kernel_bundle,auth);q = tools(a.qemu_metadata,auth);s = materials(a.materials,auth);g = guest_inputs(a.guest_inputs,auth,base)
    checked(a.base/'credentials.json',auth['credentials'])
    st = (a.base/'credentials.json').stat();need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600, 'private original PAM credentials required')
    out = ordinary(a.output);need(not out.exists(), 'fresh separate output required')
    for protected in (a.base,a.kernel_bundle,a.materials,HERE):
        p = ordinary(protected);need(p != out and p not in out.parents and out not in p.parents, 'disjoint immutable input/output paths required')
    capacity(out.parent,RESOURCES['prepare_allocated_cap'] if phase == 'prepare' else RESOURCES['boot_allocated_cap'],RESOURCES['owner_memory_bytes'] if phase=='prepare' else RESOURCES['boot_owner_memory_bytes'])
    endpoint(auth)
    return auth,base,reference,k,q,s,g
