#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Future cap0 readonly image metadata probe. Import performs no observation."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MIB = 1024**2
METADATA_CAP = 16*MIB
HOOK_ROOTS = ('/builder-disabled-hooks', '/etc/pacman.d/hooks', '/usr/share/libalpm/hooks')
PUBLIC_FILES = ('/etc/pacman.d/gnupg/pubring.gpg', '/etc/pacman.d/gnupg/trustdb.gpg')
CAP_FIELDS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
LIMITS = {'cpu.max':'100000 100000', 'memory.max':'268435456', 'memory.swap.max':'0', 'pids.max':'32'}
EXPECTED349 = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
PUBLIC_POLICY = 'OBSERVE_FRESH_BOOTSTRAP_PUBLIC_FILES_NO_PREDICTED_LOCAL_KEY_BYTES'
KIND = 'ROOT_HOSTED_SIGNED349_IMAGE_METADATA_OBSERVATION'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def bounded(path, cap):
    # procfs/sysfs report zero sizes; this reader is only for fixed kernel paths.
    with Path(path).open('rb', buffering=0) as stream:
        raw = stream.read(cap+1)
    need(len(raw) <= cap, 'kernel observation exceeds bound')
    return raw


def key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_data(path, cap=METADATA_CAP, retain=False, budget=None):
    """Hash a regular file through one FD; no symlink or special-file traversal."""
    path = Path(path)
    need(not any(p.is_symlink() for p in path.parents), 'metadata ancestry alias refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, 'bounded regular metadata required')
        if budget is not None:
            budget['bytes'] += before.st_size
            need(budget['bytes'] <= METADATA_CAP, 'aggregate metadata file bytes exceed 16 MiB')
        h = hashlib.sha256()
        raw = bytearray() if retain else None
        size = 0
        while block := os.read(fd, min(65536, cap+1-size)):
            size += len(block)
            need(size <= cap, 'metadata byte cap exceeded')
            h.update(block)
            if retain:
                raw.extend(block)
        need(size == before.st_size and key(before) == key(os.fstat(fd)) == key(path.lstat()), 'metadata file changed during read')
        row = dict(type='file', mode=stat.S_IMODE(before.st_mode), bytes=size, sha256=h.hexdigest())
        return (row, bytes(raw)) if retain else row
    finally:
        os.close(fd)


def node(path, budget=None):
    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {'type':'absent'}
    mode = stat.S_IMODE(before.st_mode)
    if stat.S_ISDIR(before.st_mode):
        return dict(type='directory', mode=mode)
    if stat.S_ISLNK(before.st_mode):
        target = os.readlink(path)
        need(0 < len(target) <= 4096 and key(before) == key(path.lstat()), 'bounded stable symlink metadata required')
        return dict(type='symlink', mode=mode, target=target)
    need(stat.S_ISREG(before.st_mode), 'special metadata entry refused')
    return file_data(path, budget=budget)


def snapshot(root, budget=None):
    """Snapshot one hook root without following any symlink, including its root."""
    root = Path(root)
    budget = {'bytes':0} if budget is None else budget
    result = {'.':node(root,budget)}
    if result['.']['type'] == 'absent':
        return result
    need(result['.']['type'] == 'directory', 'hook snapshot root must be a real directory or absent')
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            name = path.relative_to(root).as_posix()
            need(len(name) <= 4096 and len(result) < 4096, 'hook snapshot path/count bound')
            row = node(path,budget)
            need(row['type'] != 'absent', 'hook entry changed during observation')
            result[name] = row
            if row['type'] == 'directory':
                pending.append(path)
    return result


def readonly_root(mountinfo):
    found = []
    for line in mountinfo.splitlines():
        left, sep, right = line.partition(' - ')
        fields = left.split()
        need(sep and len(fields) >= 6 and len(right.split()) >= 3, 'complete mountinfo required')
        if fields[4] == '/':
            found.append(set(fields[5].split(',')))
    need(len(found) == 1 and 'ro' in found[0] and 'rw' not in found[0], 'unique readonly metadata-probe root required')


def validate_domain(runtime):
    need(all(type(runtime.get(k)) is int and runtime[k] == 0 for k in ('uid','euid','gid','egid')), 'real Root metadata credentials required')
    status = runtime['status']
    need(status['Uid'].split() == ['0']*4 and status['Gid'].split() == ['0']*4, 'kernel Root credentials required')
    need(all(re.fullmatch('[0-9a-fA-F]{1,16}', status[k]) and int(status[k],16) == 0 for k in CAP_FIELDS) and status['NoNewPrivs'] == '1', 'all cap0 and NNP required before metadata')
    need(runtime['cgroup'] == LIMITS and runtime['interfaces'] == ['lo'], 'exact finite metadata cgroup and loopback-only domain required')
    readonly_root(runtime['mountinfo'])


def runtime_context():
    before = bounded('/proc/self/stat',4096).decode().rpartition(') ')[2].split()
    raw = bounded('/proc/self/status',16384).decode()
    rows = dict(line.split(':',1) for line in raw.splitlines() if ':' in line)
    result = dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
        status={k:rows[k].strip() for k in ('Uid','Gid',*CAP_FIELDS,'NoNewPrivs')},
        cgroup={k:bounded(Path('/sys/fs/cgroup')/k,128).decode().strip() for k in LIMITS},
        cgroup_membership=bounded('/proc/self/cgroup',4096).decode(),
        mountinfo=bounded('/proc/self/mountinfo',128*1024).decode(),
        interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir()),
        namespaces={k:os.readlink('/proc/self/ns/'+k) for k in ('user','mnt','net','pid','cgroup')},
        pid=os.getpid(), ppid=os.getppid(), starttime=int(before[19]))
    after = bounded('/proc/self/stat',4096).decode().rpartition(') ')[2].split()
    need(before[19] == after[19] and before[1] == after[1], 'metadata process identity changed')
    validate_domain(result)
    return result


def inventory_data(raw):
    rows = raw.decode().splitlines()
    need(pin(raw)['sha256'] == EXPECTED349 and len(rows) == 349 and rows == sorted(set(rows)), 'exact observed signed349 builder lock required')
    packages = dict(row.split(' ',1) for row in rows)
    need(len(packages) == 349 and packages.get('perl') == '5.42.3-1', 'exact baseline Perl349 inventory required')
    return dict(**pin(raw), lock=raw.decode(), packages=349, perl='5.42.3-1')


def observe():
    runtime = runtime_context()  # Guard before touching image config/hook/trust metadata.
    machine, page = os.uname().machine, os.sysconf('SC_PAGE_SIZE')
    need(machine == 'aarch64' and page == 4096, 'native ARM4K metadata observation required')
    budget = {'bytes':0}
    _, lock = file_data(Path('/builder-packages.lock'),64*1024,retain=True,budget=budget)
    configs = {'/etc/pacman.conf':file_data(Path('/etc/pacman.conf'),budget=budget)}
    hooks = {root:snapshot(Path(root),budget) for root in HOOK_ROOTS}
    need(sum(len(rows) for rows in hooks.values()) <= 8192, 'aggregate hook path bound')
    public = {name:file_data(Path(name),budget=budget) for name in PUBLIC_FILES}
    need(all(row['bytes'] > 0 for row in public.values()), 'actual fresh public baseline trust files required')
    value = dict(schema=1,kind=KIND,machine=machine,page_bytes=page,runtime=runtime,
        package_inventory=inventory_data(lock),config_files=configs,hook_snapshots=hooks,
        baseline_public_trust=public,baseline_public_trust_policy=PUBLIC_POLICY,
        observed_metadata_file_bytes=budget['bytes'],
        scope='CALLER_MUST_BIND_FRESH_SIGNED349_IMAGE_AND_SIGNATURE_PROOF; READONLY_CAP0_METADATA_ONLY',
        root_rw_lifecycle_qualification='NOT_ISSUED_BY_THIS_PROBE')
    encoded(value)
    return value


def encoded(value):
    raw = (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(len(raw) <= METADATA_CAP, 'aggregate metadata JSON exceeds 16 MiB')
    return raw


def compare(observed, expectations):
    need(observed['schema'] == 1 and observed['kind'] == KIND and observed['machine'] == 'aarch64' and observed['page_bytes'] == 4096, 'fixed actual ARM4K image observation required')
    validate_domain(observed['runtime'])
    inventory = inventory_data(observed['package_inventory']['lock'].encode())
    need(inventory == observed['package_inventory'], 'observed inventory metadata differs')
    need(expectations.get('reviewed') is True and expectations.get('complete_hook_snapshots') is True and expectations['baseline_public_trust'] == PUBLIC_POLICY, 'independent Root-reviewed image expectations required')
    need(set(expectations['config_files']) == {'/etc/pacman.conf'} and set(expectations['hook_snapshots']) == set(HOOK_ROOTS), 'complete reviewed config/hook roots required')
    need(observed['config_files'] == expectations['config_files'] and observed['hook_snapshots'] == expectations['hook_snapshots'], 'actual config/hooks differ from Root-reviewed expectations')
    public = observed['baseline_public_trust']
    need(set(public) == set(PUBLIC_FILES) and observed['baseline_public_trust_policy'] == PUBLIC_POLICY, 'both fresh public baseline trust facts required')
    for row in public.values():
        need(type(row) is dict and set(row) == {'type','mode','bytes','sha256'} and row['type'] == 'file' and type(row['mode']) is int and 0 <= row['mode'] <= 0o7777 and type(row['bytes']) is int and 0 < row['bytes'] <= METADATA_CAP and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'bounded actual public trust file facts required')
    need(all(len(rows) <= 4096 for rows in observed['hook_snapshots'].values()) and sum(len(rows) for rows in observed['hook_snapshots'].values()) <= 8192, 'actual hook snapshot count bounds')
    files = [*observed['config_files'].values(), *public.values(), *[row for rows in observed['hook_snapshots'].values() for row in rows.values() if row['type'] == 'file']]
    total = inventory['bytes']+sum(row['bytes'] for row in files)
    need(total <= METADATA_CAP and type(observed.get('observed_metadata_file_bytes')) is int and observed['observed_metadata_file_bytes'] == total, 'exact aggregate observed metadata byte bound')
    encoded(observed)
    return dict(status='EXACT_ROOT_REVIEWED_IMAGE_METADATA_DATA_JOINED',root_rw_lifecycle_qualification='NOT_ISSUED_BY_THIS_PROBE',baseline_public_trust='OBSERVED_FRESH_BYTES; TRUST_POLICY_AND_SIGNATURES_REQUIRE_EXTERNAL_ROOT_BINDING')


if __name__ == '__main__':
    need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized metadata entry required')
    sys.stdout.buffer.write(encoded(observe()))
