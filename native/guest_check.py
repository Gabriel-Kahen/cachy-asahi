#!/usr/bin/python3 -IB
# SPDX-License-Identifier: MIT
"""Future owned ARM16K PID1 proof orchestration; fixtures never instantiate LinuxOps."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

BASE = Path('/support')
HELPER_SHA = '2cf8179a692bf8dc797c444f7cd4fc9cca33ec3cb86acec841f4d3b1029c738e'
PURPOSE = 'SUPPORT_ORIGINAL341_GUEST_CHECK_V1'
SCOPE = 'EMULATED_GENERIC_ARM16K_NOT_PHYSICAL_M2'
PROOF_FILES = ('proof-input.json', 'proof-result.json', 'check.log', 'commands.json', 'logs/inventory.log')

def need(ok, reason):
    if not ok: raise ValueError(reason)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def read(path, cap=16 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in path.parents), 'ordinary fixed path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'bounded regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(cap + 1)
        after = os.fstat(fd)
        stable = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_nlink)
        need(len(raw) == before.st_size and stable(before) == stable(after), 'stable complete file')
        return raw
    finally: os.close(fd)

def load(path):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key'); value[key] = item
        return value
    return json.loads(read(path), object_pairs_hook=pairs)

def selection(value):
    need(type(value) is dict and value.get('schema') == 1 and value.get('purpose') == PURPOSE, 'finite Support guest selection')
    need(re.fullmatch('[0-9a-f]{32}', value.get('nonce', '')), 'nonce')
    need(type(value.get('uid')) is int and type(value.get('gid')) is int
         and 1000 <= value['uid'] <= 60000 and 1000 <= value['gid'] <= 60000, 'ordinary selected IDs')
    for name in ('source_map_sha256', 'root_nodes_sha256', 'capabilities_sha256'):
        need(re.fullmatch('[0-9a-f]{64}', value.get(name, '')), 'selected hash: ' + name)
    need(re.fullmatch('sha256:[0-9a-f]{64}', value.get('image', '')), 'original341 image origin')
    binding = value['binding']
    need(re.fullmatch('[0-9a-f]{40}', binding.get('source_sha', '')) and binding.get('attempt') == 1
         and re.fullmatch('[1-9][0-9]*', binding.get('run_id', '')) and binding.get('ref', '').startswith('refs/heads/codex/'), 'actual source/run binding')
    need(value['kernel']['release'] == '7.1.13-generic16k-managed-gui', 'selected Core16K release')
    for row in (value['kernel']['Image'], value['kernel']['config']):
        need(type(row['bytes']) is int and row['bytes'] > 0 and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'Core kernel input pin')
    need(type(value.get('launcher_epoch_s')) is int and value['launcher_epoch_s'] > 0, 'actual launcher UTC')
    need(value['budgets'] == dict(media=1800, qemu=1800, export=300, cleanup=120), 'finite VM budgets')
    need(type(value['source_manifest']) is dict and 1 <= len(value['source_manifest']) <= 256
         and type(value['proof_files']) is dict and len(value['proof_files']) == 17, 'closed source and sealed recipe17')
    need(value['source_manifest']['native/private_check.py']['sha256'] == HELPER_SHA, 'held original helper')
    for name, row in value['source_manifest'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and Path(name).as_posix() == name, 'closed relative source name')
        need(type(row.get('bytes')) is int and 0 < row['bytes'] <= 16 * 1024**2
             and re.fullmatch('[0-9a-f]{64}', row.get('sha256', '')) and row.get('mode') == 0o644, 'finite source byte/mode pin')
    need(all(name in value['source_manifest'] and value['source_manifest'][name] == row for name, row in value['proof_files'].items()), 'recipe17 belongs to closed source')
    return value

def disk_serial(nonce, role):
    need(role in ('boot', 'data'), 'finite Core disk role')
    return base64.b85encode(hashlib.sha256(b'cachy-asahi/core7/virtio-blk/serial-v1\0' + role.encode() + b'\0' + bytes.fromhex(nonce)).digest()[:16]).decode()

def status_fields(text):
    rows = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    return dict(uid=[int(v) for v in rows['Uid'].split()], gid=[int(v) for v in rows['Gid'].split()],
        groups=[int(v) for v in rows['Groups'].split()],
        caps={name: rows[name].strip() for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')},
        nnp=int(rows['NoNewPrivs'].strip()))

def dropped_identity(value, uid, gid):
    need(value['uid'] == [uid] * 4 and value['gid'] == [gid] * 4 and value['groups'] == []
         and all(int(item, 16) == 0 for item in value['caps'].values()) and value['nnp'] == 1, 'actual IDs/groups/all capability sets/bounding/NNP')
    return value

def root_snapshot(root):
    """Shared data-only full descendant map; root directory metadata intentionally omitted."""
    root = Path(root).absolute()
    nodes, caps, hardlinks = {}, {}, {}
    total = attributes = 0; deadline = time.monotonic() + 600
    def walk(parent):
        nonlocal total, attributes
        for path in sorted(parent.iterdir(), key=lambda p: os.fsencode(p.name)):
            need(time.monotonic() < deadline and len(nodes) < 500000, 'full-root node/time bounds')
            name = path.relative_to(root).as_posix(); before = path.lstat()
            value = dict(mode=stat.S_IMODE(before.st_mode), uid=before.st_uid, gid=before.st_gid, mtime_ns=before.st_mtime_ns)
            xattrs = {}
            for key in sorted(os.listxattr(path, follow_symlinks=False)):
                raw = os.getxattr(path, key, follow_symlinks=False)
                attributes += len(raw); need(len(raw) <= 1024**2 and attributes <= 16 * 1024**2, 'bounded complete xattrs')
                xattrs[key] = raw.hex()
            caps[name] = xattrs
            if stat.S_ISDIR(before.st_mode): value['kind'] = 'directory'
            elif stat.S_ISREG(before.st_mode):
                total += before.st_size
                need(before.st_size <= 1024**3 and total <= 8 * 1024**3, 'full-root file/byte bounds')
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    digest = hashlib.sha256(); size = 0
                    while block := os.read(fd, 1024**2):
                        size += len(block); need(size <= before.st_size, 'stable root file size'); digest.update(block)
                    after = os.fstat(fd)
                    need(size == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'stable root file')
                finally: os.close(fd)
                key = (before.st_dev, before.st_ino)
                anchor = hardlinks.setdefault(key, name)
                value.update(kind='file', bytes=size, sha256=digest.hexdigest(), nlink=before.st_nlink, hardlink=anchor)
            elif stat.S_ISLNK(before.st_mode): value.update(kind='symlink', target=os.readlink(path))
            elif stat.S_ISCHR(before.st_mode) or stat.S_ISBLK(before.st_mode):
                value.update(kind='char' if stat.S_ISCHR(before.st_mode) else 'block', major=os.major(before.st_rdev), minor=os.minor(before.st_rdev))
            elif stat.S_ISFIFO(before.st_mode): value['kind'] = 'fifo'
            elif stat.S_ISSOCK(before.st_mode): value['kind'] = 'socket'
            else: raise ValueError('unknown root node type')
            nodes[name] = value
            if value['kind'] == 'directory': walk(path)
    need(root.is_dir() and not root.is_symlink(), 'ordinary private proof root')
    walk(root)
    return nodes, caps

def mount_rows(text):
    rows = []
    need(len(text) <= 1024**2, 'bounded real mount table')
    for line in text.splitlines():
        fields = line.split(); split = fields.index('-')
        rows.append(dict(path=fields[4], fs=fields[split + 1], device=fields[2], root=fields[3], options=fields[5].split(','), source=fields[split + 2]))
    return rows

def mount_privacy(rows):
    virtual = {'/proc': 'proc', '/sys': 'sysfs', '/dev': 'devtmpfs', '/dev/pts': 'devpts',
               '/run': 'tmpfs', '/tmp': 'tmpfs', '/sys/fs/cgroup': 'cgroup2'}
    roles = {'/support', '/support/proof-root', '/support/source', '/support/work'}
    actual = {}
    for row in rows:
        path = row['path']
        need(path not in actual, 'unique actual mount target'); actual[path] = row
        need(path == '/' and row['fs'] == 'ext4' or path in virtual and row['fs'] == virtual[path]
             or path in roles and row['fs'] == 'ext4', 'no host shares or foreign guest mounts')
    need('/support' in actual and actual['/support']['device'] != actual['/']['device'], 'distinct owned boot/data filesystems')
    for path in ('/support/proof-root', '/support/source'):
        need(path in actual and 'ro' in actual[path]['options'], 'actual readonly private input role')
    need('/support/work' in actual and 'rw' in actual['/support/work']['options'], 'actual writable work role')
    need(set(virtual) <= actual.keys(), 'all real guest virtual filesystems')
    need(all(actual[path]['device'] == actual['/support']['device'] for path in roles), 'one nonce-bound data filesystem for every proof role')
    return dict(rows=rows, no_host_mounts=True, input_roles_readonly=True, work_readwrite=True)

def proof_result(value, selected):
    need(value.get('status') == 'PASS_EXTERNAL_EXACT_CHECK_FUNCTION' and value['binding'] == selected['binding']
         and value['source_map_sha256'] == selected['source_map_sha256'] and value['image'] == selected['image'], 'original exact proof context')
    need(value['source_files'] == selected['proof_files'] and value['architecture'] == 'aarch64'
         and value['page_size'] == 16384 and value['uid'] == selected['uid'], 'actual EMU16K proof identity')
    need(value['checks']['count'] == 6 and value['checks']['skips'] == 0 and value['checks']['exit'] == 0
         and len(value['checks']['methods']) == 6, 'actual complete six-check proof')
    return value

def natural(state):
    need(state.get('exit') == 0 and state.get('natural_exit') is True and state.get('group_absent') is True
         and state.get('leader_held_until_group_inspection') is True and state.get('exit_observed_via_waitpid') is True
         and state.get('retirement') == 'REAPED' and state.get('ownership_lost') is False and state.get('forced_cleanup') is False,
         'natural directly reaped proof child')
    return state

def public_scope(names):
    """Only fixed proof artifacts are eligible; unrelated private trees never are."""
    allowed = set(PROOF_FILES)
    return sorted(set(names) & allowed), sorted(set(names) - allowed)

def run(value, ops):
    """Backend-free orchestration; fixtures supply only invented DATA operations."""
    s = selection(value)
    result = dict(schema=1, status='FAIL_EMU16K_PRIVATE_CHECK', binding=s['binding'], nonce=s['nonce'],
        selection=s, selection_pin=pin(encoded(s)), image=s['image'], source_map_sha256=s['source_map_sha256'], helper_sha256=HELPER_SHA,
        scope=SCOPE, acceptance=False, hardware='NOT_RUN', native_4K='NOT_QUALIFIED_BY_THIS_VM',
        boot=None, readback=None, mounts=None, child=None, proof=None, retirement=None)
    try:
        result['boot'] = ops.boot(s)
        need(result['boot']['pid'] == 1 and result['boot']['uid'] == 0 and result['boot']['architecture'] == 'aarch64'
             and result['boot']['page_size'] == 16384 and result['boot']['kernel_release'] == s['kernel']['release'], 'actual owned VM boot witness')
        need(result['boot']['kernel'] == s['kernel'] and result['boot']['serials'] == {role: disk_serial(s['nonce'], role) for role in ('boot', 'data')}
             and result['boot']['selectors'] == dict(support_vm=s['nonce'], caa_core_vm=s['nonce'], caa_core_phase='1',
                caa_core_realtime=str(s['launcher_epoch_s']), support_kernel_sha256=s['kernel']['Image']['sha256'])
             and result['boot']['lsm_disable_absent'] is True, 'whole kernel/nonce/serial witness')
        result['readback'] = ops.readback(s)
        need(result['readback']['root_nodes_sha256'] == s['root_nodes_sha256'] and
             result['readback']['capabilities_sha256'] == s['capabilities_sha256'] and result['readback']['proof_files'] == 17, 'complete original341 descendant/source readback')
        result['mounts'] = mount_privacy(ops.roles(s))
        child = ops.proof(s); natural(child['supervision'])
        boundary = child['boundary']
        need(boundary['nonce'] == s['nonce'] and boundary['source_map_sha256'] == s['source_map_sha256'], 'same selected child boundary')
        dropped_identity(boundary['identity'], s['uid'], s['gid'])
        need(boundary['no_raw_block_fds'] is True and boundary['readable_block_nodes'] == [] and boundary['interfaces'] == ['lo'], 'no raw disk authority or external network')
        need(boundary['outer_argv_held'] is True and boundary['helper_sha256'] == HELPER_SHA, 'unchanged original proof command')
        result['child'] = child
        proof = proof_result(ops.proof_result(s), s)
        result['proof'] = dict(path='proof/proof-result.json', **pin(encoded(proof)), checks=proof['checks'],
                               architecture='aarch64', page_size=16384, inventory=proof['inventory'])
        result['status'] = 'PASS_EMU16K_ORIGINAL341_PRIVATE_CHECK'
    except BaseException as error:
        result['error'] = dict(type=type(error).__name__, message=str(error)[:1024])
    finally:
        try:
            retired = ops.retire(s)
            need(retired['child_natural'] is True and retired['child_group_absent'] is True
                 and retired['role_bind_layers_retired'] is True, 'real guest retirement required')
            need(retired['readback_after']['root_nodes_sha256'] == s['root_nodes_sha256'] and
                 retired['readback_after']['capabilities_sha256'] == s['capabilities_sha256'], 'full original341 after proof preservation')
            result['retirement'] = retired
        except BaseException as error:
            result['status'] = 'FAIL_GUEST_RETIREMENT_UNKNOWN'
            result['retirement'] = dict(error=type(error).__name__, child_natural=False,
                child_group_absent=False, role_bind_layers_retired=False)
        try: ops.export(s, result)
        except BaseException as error:
            result['status'] = 'FAIL_GUEST_PUBLIC_EXPORT'
            result['error'] = dict(type=type(error).__name__, message=str(error)[:1024])
    return result

def import_module(path, name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value; spec.loader.exec_module(value)
    return value

class LinuxOps:
    def __init__(self):
        need(os.getpid() == 1 and os.getuid() == os.geteuid() == 0 and os.uname().machine == 'aarch64'
             and os.sysconf('SC_PAGE_SIZE') == 16384, 'only actual root PID1 in owned ARM16K guest may construct backend')
        import ctypes
        self.C = ctypes; self.lib = ctypes.CDLL(None, use_errno=True)
        self.lib.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
        self.lib.mount.restype = ctypes.c_int
        self.created, self.child = [], None

    def mount(self, source, target, flags=0, fs=None, data=None):
        wire = lambda value: None if value is None else str(value).encode()
        need(self.lib.mount(wire(source), wire(target), wire(fs), flags, wire(data)) == 0, 'owned guest mount failed')

    def virtuals(self):
        expected = (('/proc', 'proc', 'proc'), ('/sys', 'sysfs', 'sysfs'), ('/dev', 'devtmpfs', 'devtmpfs'),
            ('/dev/pts', 'devpts', 'devpts'), ('/run', 'tmpfs', 'tmpfs'), ('/tmp', 'tmpfs', 'tmpfs'), ('/sys/fs/cgroup', 'cgroup2', 'cgroup2'))
        current = {row['path']: row for row in mount_rows(Path('/proc/self/mountinfo').read_text())} if Path('/proc/self/mountinfo').is_file() else {}
        for path, source, fs in expected:
            if path in current:
                need(current[path]['fs'] == fs, 'existing virtual mount must have exact type'); continue
            Path(path).mkdir(parents=True, exist_ok=True)
            self.mount(source, path, 2 if path == '/dev' else 6, fs, 'mode=1777,size=1g' if path == '/tmp' else None)

    def mount_support(self):
        words = Path('/proc/cmdline').read_text().split()
        nonces = [word.split('=', 1)[1] for word in words if word.startswith('support_vm=')]
        need(len(nonces) == 1 and re.fullmatch('[0-9a-f]{32}', nonces[0]), 'owned support kernel nonce before data mount')
        need(Path('/sys/class/block/vdb/serial').read_text().strip() == disk_serial(nonces[0], 'data'), 'owned Core data serial before mount')
        rows = mount_rows(Path('/proc/self/mountinfo').read_text())
        if not any(row['path'] == '/support' for row in rows):
            volume = Path('/support-volume'); volume.mkdir(mode=0o700)
            self.mount('/dev/vdb', volume, 2 | 4, 'ext4')
            need((volume / 'support').is_dir() and not (volume / 'support').is_symlink(), 'one support data root')
            BASE.mkdir(mode=0o755, exist_ok=True)
            self.mount(volume / 'support', BASE, 4096)
            need(self.lib.umount2(str(volume).encode(), 0) == 0, 'retire temporary data exposure')

    def boot(self, s):
        self.virtuals(); self.mount_support()
        words = Path('/proc/cmdline').read_text().split()
        selected = dict(support_vm=s['nonce'], caa_core_vm=s['nonce'], caa_core_phase='1',
                        caa_core_realtime=str(s['launcher_epoch_s']), support_kernel_sha256=s['kernel']['Image']['sha256'])
        for key, value in selected.items():
            need([word for word in words if word.startswith(key + '=')] == [key + '=' + value], 'unique selected kernel context: ' + key)
        need(not set(words) & {'apparmor=0', 'selinux=0', 'enforcing=0', 'security=none', 'lsm=none'}, 'no LSM-disable route')
        serials = {role: Path('/sys/class/block/' + dev + '/serial').read_text().strip() for role, dev in (('boot', 'vda'), ('data', 'vdb'))}
        need(all(serials[role] == disk_serial(s['nonce'], role) for role in serials), 'both actual Core disk serials')
        need({p.name for p in Path('/sys/class/block').iterdir() if p.name.startswith('vd')} == {'vda', 'vdb'}, 'only two owned virtio disks')
        need(os.uname().release == s['kernel']['release'], 'actual selected kernel release')
        return dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid(), architecture=os.uname().machine,
            page_size=os.sysconf('SC_PAGE_SIZE'), kernel_release=os.uname().release, kernel=s['kernel'],
            kernel_pin_scope='CMDLINE_AND_HOST_PINNED_IMAGE_NOT_RUNNING_MEMORY_HASH', selectors=selected, serials=serials,
            boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), lsm_disable_absent=True)

    def readback(self, s):
        source = BASE / 'source'
        actual = set()
        for path in source.rglob('*'):
            need(not path.is_symlink(), 'closed source has no aliases')
            if path.is_file(): actual.add(path.relative_to(source).as_posix())
        need(actual == set(s['source_manifest']), 'complete closed current source namespace')
        for name, row in s['source_manifest'].items():
            path = source / name
            need(not Path(name).is_absolute() and '..' not in Path(name).parts and
                 dict(**pin(read(path)), mode=stat.S_IMODE(path.stat().st_mode)) == row, 'actual selected source file')
        need(pin(read(source / 'native/private_check.py'))['sha256'] == HELPER_SHA, 'exact unchanged private_check bytes')
        need(all(name in actual and s['source_manifest'][name] == row for name, row in s['proof_files'].items()), 'whole sealed recipe17')
        proof_input = load(BASE / 'work/proof-input.json')
        need(proof_input['binding'] == s['binding'] and proof_input['source_map_sha256'] == s['source_map_sha256']
             and proof_input['image'] == s['image'] and proof_input['source_files'] == s['proof_files'], 'prepared exact inner request')
        for path in (BASE / 'proof-root', source, BASE / 'work'):
            need(path.is_dir() and not path.is_symlink() and path.stat().st_uid == s['uid']
                 and path.stat().st_gid == s['gid'], 'caller-owned private proof role root')
        nodes, caps = root_snapshot(BASE / 'proof-root')
        return dict(root_nodes_sha256=pin(encoded(nodes))['sha256'], capabilities_sha256=pin(encoded(caps))['sha256'],
                    source_manifest_sha256=pin(encoded(s['source_manifest']))['sha256'], nodes=len(nodes),
                    source_files=len(actual), proof_files=len(s['proof_files']), original_rootdir_only_owner_override=True)

    def roles(self, s):
        table = {row['path']: row for row in mount_rows(Path('/proc/self/mountinfo').read_text())}
        for name, readonly in (('proof-root', True), ('source', True), ('work', False)):
            path = BASE / name
            if str(path) not in table:
                self.mount(path, path, 4096); self.created.append(path)
            self.mount(None, path, 4096 | 32 | 2 | 4 | (1 if readonly else 0))
        return mount_rows(Path('/proc/self/mountinfo').read_text())

    def proof(self, s):
        import subprocess
        need(not any((BASE / 'public').iterdir()), 'fresh finite guest public output')
        source = BASE / 'source'
        owned = import_module(source / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py', '_support_vm_owned')
        argv = ['/usr/bin/python3', '-I', '-B', '/support/source/native/guest_check.py', '--child', '--selection', '/support/selection.json']
        log = BASE / 'public/guest-child.log'; state = {}
        with log.open('xb') as stream:
            completed = owned.run(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                env=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'), timeout=1100,
                lifecycle=state, allowed_uids={0, s['uid']})
        self.child = state
        need(completed.returncode == state.get('exit'), 'exact direct child exit')
        body = read(log)
        prefix = ('SUPPORT135_CHILD ' + s['nonce'] + ' ').encode()
        frames = [line[len(prefix):] for line in body.splitlines() if line.startswith(prefix)]
        need(len(frames) == 1 and len(frames[0]) <= 65536, 'one bounded actual child boundary frame')
        return dict(argv=argv, log='guest-child.log', log_pin=pin(body), supervision=state, boundary=json.loads(frames[0]))

    def proof_result(self, s):
        return load(BASE / 'work/proof-result.json')

    def retire(self, s):
        natural(self.child or {})
        nodes, caps = root_snapshot(BASE / 'proof-root')
        for path in reversed(self.created):
            need(self.lib.umount2(str(path).encode(), 0) == 0, 'retire exact created role mount')
        self.created = []
        return dict(child_natural=True, child_group_absent=True, role_bind_layers_retired=True,
            readback_after=dict(root_nodes_sha256=pin(encoded(nodes))['sha256'], capabilities_sha256=pin(encoded(caps))['sha256']),
            shutdown='PID1_POWER_OFF_REQUEST_AFTER_PUBLIC_SYNC', host_qemu_retirement='PENDING_HOST_PROOF')

    def export(self, s, result):
        public, work = BASE / 'public', BASE / 'work'
        allowed = set(PROOF_FILES)
        actual = set()
        for path in work.rglob('*'):
            need(not path.is_symlink(), 'no work aliases exported')
            if path.is_file(): actual.add(path.relative_to(work).as_posix())
        selected, unknown = public_scope(actual)
        if unknown:
            result['status'] = 'FAIL_UNEXPECTED_PRIVATE_WORK_FILES'
            result['error'] = dict(type='PrivacyError', message='unknown work members excluded from public export')
        for name in selected:
            path = work / name
            if path.exists():
                raw = read(path); target = public / 'proof' / name
                target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw); target.chmod(0o600)
        (public / 'guest.json').write_bytes(encoded(result)); (public / 'guest.json').chmod(0o600)
        files, total = {}, 0
        for path in sorted(public.rglob('*')):
            need(not path.is_symlink(), 'no public aliases')
            if not path.is_file(): continue
            name = path.relative_to(public).as_posix()
            need(name in {'guest.json', 'guest-child.log'} | {'proof/' + n for n in PROOF_FILES}, 'finite public namespace only')
            body = read(path); total += len(body); need(total <= 32 * 1024**2, 'bounded public guest data')
            files[name] = pin(body)
        index = dict(schema=1, purpose='SUPPORT_GUEST_PUBLIC_INDEX_V1', nonce=s['nonce'], binding=s['binding'],
            status='GUEST_PUBLIC_DATA_ONLY', result_status=result['status'], files=files, bytes=total, acceptance=False)
        (public / 'index.json').write_bytes(encoded(index)); (public / 'index.json').chmod(0o600)
        os.sync()

    def shutdown(self):
        need(os.getpid() == 1 and os.getuid() == 0, 'only owned root PID1 may power off guest')
        os.sync(); sys.stdout.flush(); sys.stderr.flush()
        need(self.lib.reboot(0x4321fedc) == 0, 'real guest PID1 poweroff syscall')

def child(s):
    """Root launcher child drops authority before executing unchanged outer bwrap."""
    need(os.getppid() == 1 and os.getuid() == os.geteuid() == 0 and os.uname().machine == 'aarch64'
         and os.sysconf('SC_PAGE_SIZE') == 16384 and os.uname().release == s['kernel']['release'], 'owned root child before identity transition')
    need(all(Path('/sys/class/block/' + dev + '/serial').read_text().strip() == disk_serial(s['nonce'], role)
             for role, dev in (('boot', 'vda'), ('data', 'vdb'))), 'child actual nonce disk context')
    helper = BASE / 'source/native/private_check.py'
    need(pin(read(helper))['sha256'] == HELPER_SHA, 'held helper before import')
    original = import_module(helper, '_support_held_private_check')
    request = load(BASE / 'work/proof-input.json')
    need(request['binding'] == s['binding'] and request['source_map_sha256'] == s['source_map_sha256'], 'same future proof request')
    import ctypes as C
    lib = C.CDLL(None, use_errno=True)
    last = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
    need(0 <= last <= 63, 'finite actual capability range')
    os.setgroups([])
    for cap in range(last + 1): need(lib.prctl(24, cap, 0, 0, 0) == 0, 'clear every bounding capability')
    need(lib.prctl(47, 4, 0, 0, 0) == 0 and lib.prctl(8, 0, 0, 0, 0) == 0, 'clear ambient and keep-caps state')
    os.setresgid(s['gid'], s['gid'], s['gid']); os.setresuid(s['uid'], s['uid'], s['uid'])
    class Header(C.Structure): _fields_ = [('version', C.c_uint32), ('pid', C.c_int)]
    class Data(C.Structure): _fields_ = [('effective', C.c_uint32), ('permitted', C.c_uint32), ('inheritable', C.c_uint32)]
    header, data = Header(0x20080522, 0), (Data * 2)()
    need(lib.capset(C.byref(header), C.byref(data)) == 0 and lib.prctl(38, 1, 0, 0, 0) == 0, 'zero all cap sets and NNP1')
    identity = dropped_identity(status_fields(Path('/proc/self/status').read_text()), s['uid'], s['gid'])
    blocks = []
    for path in Path('/proc/self/fd').iterdir():
        try:
            if stat.S_ISBLK(path.stat().st_mode): blocks.append(path.name)
        except FileNotFoundError: pass
    readable = sorted(path.name for path in Path('/dev').iterdir() if path.is_block_device() and
                      (os.access(path, os.R_OK) or os.access(path, os.W_OK)))
    interfaces = sorted(line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:])
    need(not blocks and not readable and interfaces == ['lo'], 'no block authority or external network before held outer namespace')
    argv = original.proof_command(BASE / 'proof-root', BASE / 'source', BASE / 'work', request['recipe_root'])
    boundary = dict(schema=1, nonce=s['nonce'], source_map_sha256=s['source_map_sha256'], helper_sha256=HELPER_SHA,
        identity=identity, no_raw_block_fds=True, readable_block_nodes=readable, interfaces=interfaces,
        outer_argv=argv, outer_argv_held=True, scope=SCOPE,
        mounts=mount_privacy(mount_rows(Path('/proc/self/mountinfo').read_text())))
    wire = json.dumps(boundary, sort_keys=True, separators=(',', ':'), allow_nan=False)
    need(len(wire.encode()) <= 65536, 'bounded child witness')
    print('SUPPORT135_CHILD ' + s['nonce'] + ' ' + wire, flush=True)
    os.execve(argv[0], argv, dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'))

def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, default=BASE / 'selection.json')
    parser.add_argument('--child', action='store_true')
    args = parser.parse_args()
    if args.child:
        child(selection(load(args.selection))); return
    ops = LinuxOps()
    try:
        ops.virtuals(); ops.mount_support()
        selected = selection(load(args.selection))
        result = run(selected, ops)
        print('SUPPORT135_VM ' + selected['nonce'] + ' ' + json.dumps(dict(status=result['status'], acceptance=False), sort_keys=True), flush=True)
    except BaseException as error:
        print('SUPPORT135_VM_FAILURE ' + type(error).__name__, flush=True)
    finally: ops.shutdown()

if __name__ == '__main__': main()
