#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only verification of a newly committed, private native baseline image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

INPUTS = Path('/inputs')
BIND_FS = {'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'fuse-overlayfs'}
DEVICE_NODES = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
                '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0),
                '/dev/pts/ptmx': (5, 2)}
EXPOSURE_LIMIT = 250000

STANDARD_FS = {'/proc': ('proc', 'rw'), '/sys': ('sysfs', 'ro'), '/sys/fs/cgroup': ('cgroup2', 'ro'),
               '/dev': ('tmpfs', 'rw'), '/dev/pts': ('devpts', 'rw'), '/dev/shm': ('tmpfs', 'rw'), '/dev/mqueue': ('mqueue', 'rw')}
for point in ('/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'):
    STANDARD_FS[point] = ('proc', 'ro')
for point in ('/proc/acpi', '/proc/asound', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap'):
    STANDARD_FS[point] = ('tmpfs', 'ro')
for point in ('/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug'):
    STANDARD_FS[point] = ('tmpfs', None)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def runtime_exposure():
    """Inspect ordinary filesystem metadata only, after mount validation.

    Kernel pseudo trees have their separate exact mount/mask checks. Do not
    follow symlinks or open nodes. This is a point-in-time namespace check,
    not proof against a malicious daemon, inherited FDs or abstract sockets.
    """
    def failed(_error):
        raise ValueError('runtime exposure inventory could not be completed')

    count = 0
    try:
        for current, dirs, files in os.walk('/', topdown=True, followlinks=False, onerror=failed):
            if current == '/':
                dirs[:] = [name for name in dirs if name not in ('proc', 'sys')]
            directory_names = set(dirs)
            retained = []
            for name in dirs + files:
                count += 1
                need(count <= EXPOSURE_LIMIT, 'runtime exposure inventory exceeds bound')
                path = Path(current) / name
                info = path.lstat()
                need(not stat.S_ISSOCK(info.st_mode), 'runtime sockets refused')
                if stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
                    identity = (os.major(info.st_rdev), os.minor(info.st_rdev))
                    match = re.fullmatch(r'/dev/pts/([0-9]{1,4})', str(path))
                    number = int(match[1]) if match else -1
                    pty = 0 <= number < 2048 and identity == (136 + number // 256, number % 256)
                    need(stat.S_ISCHR(info.st_mode) and
                         (DEVICE_NODES.get(str(path)) == identity or pty), 'unexpected runtime device refused')
                if name in directory_names and stat.S_ISDIR(info.st_mode):
                    retained.append(name)
            dirs[:] = retained
    except OSError:
        failed(None)


def guard():
    marker = Path('/.dockerenv')
    need(platform.machine() == 'aarch64' and os.geteuid() == 0 and marker.is_file() and
         not marker.is_symlink() and marker.stat().st_uid == 0, 'actual native root container required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(status['NoNewPrivs'].strip() == '1' and all(not int(status[name].strip(), 16) & ~0xcb
         for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')),
         'restricted capabilities/no-new-privileges required')
    need(sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'], 'no-network namespace required')
    table = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split(); index = fields.index('-'); point = fields[4]
        table[point] = {'fs': fields[index + 1], 'options': fields[5].split(','), 'root': fields[3]}
    validate_mounts(table)
    for point in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'):
        info = Path(point).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'safe runtime file required')
    for point, expected in STANDARD_FS.items():
        if point in table and expected == ('tmpfs', None):
            info = Path(point).lstat()
            need(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 3), 'real null device mask required')
        elif point in table and expected == ('tmpfs', 'ro'):
            need(Path(point).is_dir() and not Path(point).is_symlink() and not any(Path(point).iterdir()), 'empty readonly kernel mask required')
    need(not any(Path(p).exists() for p in ('/dev/dri', '/dev/snd', '/dev/input', '/dev/kvm', '/run/docker.sock', '/var/run/docker.sock')), 'devices/host sockets refused')
    runtime_exposure()


def validate_mounts(table):
    for row in table.values():
        need(set(row.get('options', [])) & {'ro', 'rw'} in ({'ro'}, {'rw'}), 'unambiguous mount access required')
    need(table.get('/', {}).get('fs') in ('overlay', 'fuse-overlayfs') and 'ro' in table['/']['options'], 'read-only image required')
    for point, mode in (('/inputs', 'ro'), ('/runner', 'ro'), ('/out', 'rw')):
        row = table.get(point, {})
        need(row.get('fs') in BIND_FS and mode in row.get('options', []), 'explicit data filesystem mounts required')
    need('/tmp' not in table and not any(p.startswith('/tmp/') for p in table), 'underlying image tmp view required')
    for point, row in table.items():
        ordinary = point in ('/', '/inputs', '/runner', '/out', '/etc/hosts', '/etc/hostname', '/etc/resolv.conf')
        if point in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'):
            need(row['fs'] in BIND_FS, 'Docker metadata must use a data filesystem')
        expected = STANDARD_FS.get(point)
        kernel = expected and row['fs'] == expected[0] and (expected[1] is None or expected[1] in row['options'])
        need(ordinary or kernel, 'unexpected image-verifier mount')
        if expected:
            flags = ({'nosuid'} if point == '/dev' or expected[1] is None else
                     {'nosuid', 'noexec'} if point == '/dev/pts' else
                     set() if expected == ('tmpfs', 'ro') else {'nosuid', 'nodev', 'noexec'})
            # Read-only masks are tmpfs directories or the real /dev/null file.
            need(flags <= set(row['options']), 'runtime mount security flags missing')
            if point in ('/proc', '/sys', '/sys/fs/cgroup', '/dev', '/dev/pts', '/dev/shm', '/dev/mqueue'):
                need(row.get('root') == '/', 'runtime subtree bind refused')
            elif row['fs'] == 'proc':
                need(row.get('root') == point.removeprefix('/proc'), 'unexpected proc mask source')
            elif expected[1] is None:
                need(row.get('root') == '/null', 'real null mask source required')
            else:
                need(row.get('root') == '/', 'unexpected readonly mask subtree')


def command(args):
    result = subprocess.run(args, capture_output=True, timeout=60,
                            env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'})
    need(result.returncode == 0 and len(result.stdout) <= 4 * 1024**2, 'read-only query failed')
    return result.stdout.decode()


def real_parents(path, system):
    need(path.is_relative_to(system) and all(not p.is_symlink() and p.is_dir()
         for p in path.parents if p.is_relative_to(system)), 'private view ancestor must be a real directory')


def verify(contract, system=Path('/')):
    need(sha(Path(__file__)) == contract['script_sha256'], 'verified image-check source required')
    lock = INPUTS / 'installed-packages.lock'
    need(sha(lock) == contract['installed_packages_sha256'], 'installed lock changed')
    need(''.join(sorted(command(['/usr/bin/pacman', '-Q']).splitlines(keepends=True))) == lock.read_text(), 'committed inventory differs')
    for row in contract['baseline']:
        owned = {line.split(' ', 1)[1].lstrip('/') for line in command(['/usr/bin/pacman', '-Ql', row['name']]).splitlines() if not line.endswith('/')}
        need(owned == set(row['payload_sha256']), 'committed ownership differs')
        for name, checksum in row['payload_sha256'].items():
            need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'unsafe payload path')
            path = system / name; info = path.lstat()
            need(all(not p.is_symlink() for p in (path, *path.parents)) and stat.S_ISREG(info.st_mode) and
                 info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and sha(path) == checksum, 'committed baseline payload differs')
    for name in ('root', 'tmp', 'var/cache/pacman/pkg'):
        path = system / name
        real_parents(path, system)
        need(path.is_dir() and not path.is_symlink() and not any(path.iterdir()), 'committed private/temporary view not empty')
    for name in ('etc/pacman.d/gnupg', 'var/lib/gnupg', 'var/log/pacman.log'):
        path = system / name
        real_parents(path, system)
        need(not path.exists() and not path.is_symlink(), 'committed private state remains')
    home = system / 'home/alarm'
    real_parents(home, system)
    need(list((system / 'home').iterdir()) == [home] and home.is_dir() and not home.is_symlink() and not any(home.iterdir()), 'committed homes not sanitized')
    return {'status': 'PASS', 'image_id': contract['image_id'], 'source_commit': contract['source_commit'],
            'installed_packages_sha256': contract['installed_packages_sha256'], 'baseline': contract['baseline'],
            'verification': 'fresh read-only committed image; actual underlying tmp and payloads',
            'parent_layer_erasure': 'NOT CLAIMED', 'hardware_validation': 'NOT RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract-sha256', required=True)
    args = parser.parse_args(); guard()
    path = Path('/inputs/verify.json')
    need(re.fullmatch(r'[0-9a-f]{64}', args.contract_sha256) and sha(path) == args.contract_sha256, 'pinned verifier contract required')
    result = {'status': 'FAIL', 'hardware_validation': 'NOT RUN'}
    try:
        result = verify(json.loads(path.read_text()))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        result['error'] = 'committed image read-side verification failed'
        return 1
    finally:
        Path('/out/result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
