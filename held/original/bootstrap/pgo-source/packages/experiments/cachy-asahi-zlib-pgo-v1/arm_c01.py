#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated zlib baseline/LTO or O3 correctness trial; never install packages."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib

sys.dont_write_bytecode = True
import corpus

EXPERIMENTS = {'ARM-C01': 'lto', 'ARM-C02': 'o3', 'ARM-C03': 'pgo', 'ARM-C04': 'm2'}
EXPERIMENT = 'ARM-C01'
CANDIDATE = 'lto'
PURPOSE = 'ARM-C01-native-correctness-only'
MARKER = 'CACHY_ASAHI_ARM_C01'


def select_experiment(name):
    """Closed caller selection; never infer acceptance rules from a receipt."""
    global EXPERIMENT, CANDIDATE, PURPOSE, MARKER
    if name not in EXPERIMENTS:
        raise ValueError('unknown experiment')
    EXPERIMENT, CANDIDATE = name, EXPERIMENTS[name]
    PURPOSE = name + '-native-correctness-only'
    MARKER = 'CACHY_ASAHI_' + name.replace('-', '_')


def variants():
    return ('baseline', CANDIDATE)


def build_names():
    return tuple(f'{variant}-{attempt}' for variant in variants() for attempt in (1, 2))


def container_prefix():
    return 'cachy-asahi-' + EXPERIMENT.lower() + '-'


def profile_adapter():
    if EXPERIMENT == 'ARM-C03':
        import pgo
        return pgo
    return None


def tool_names():
    return TOOLS + (('gcov-tool',) if EXPERIMENT == 'ARM-C03' else ())

SOURCE_SHA = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
LIMIT = 4 * 1024**2
PIN = re.compile(r'[0-9a-f]{64}')
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
KERNEL = {'/proc': 'proc', '/sys': 'sysfs', '/sys/fs/cgroup': 'cgroup2',
          '/dev': 'tmpfs', '/dev/pts': 'devpts', '/dev/shm': 'tmpfs', '/dev/mqueue': 'mqueue'}
MASKS = set(('/proc/bus /proc/fs /proc/irq /proc/sys /proc/sysrq-trigger /proc/acpi '
             '/proc/asound /proc/interrupts /proc/kcore /proc/keys /proc/latency_stats '
             '/proc/timer_list /proc/timer_stats /proc/sched_debug /proc/scsi '
             '/sys/firmware /sys/devices/virtual/powercap').split())
NULL_MASKS = {'/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats',
              '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug'}
DEVICES = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
           '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0), '/dev/pts/ptmx': (5, 2)}
# configure preserves literal $@ in its log and recursive Makefile CFLAGS.
# GNU make expands it per output target, giving unique, repeat-stable GCC seeds.
# This is a common experimental control, not a native reproducibility result.
RANDOM_SEED_FLAG = '-frandom-seed=$@'
BASE_FLAGS = '-O2 -g -march=armv8-a -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE ' + RANDOM_SEED_FLAG
LINK_FLAGS = '-pie -Wl,-z,relro,-z,now,-z,max-page-size=65536,-z,common-page-size=16384'
BIND_FS = {'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'fuse-overlayfs'}
PROC_MASKS = {'/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'}
TOOLS = ('gcc', 'ld', 'gcc-ar', 'gcc-ranlib', 'readelf', 'gcc-nm', 'make', 'python3', 'lscpu', 'ldd')
CONFIG_FILES = ('Makefile', 'zconf.h', 'configure.log', 'LICENSE')
FEATURE_FLAGS = {'-fPIC', '-D_LARGEFILE64_SOURCE=1', '-DNO_FSEEKO', '-DNO_STRERROR', '-DHAVE_HIDDEN',
                 '-DHAS_vsnprintf_void', '-DNO_vsnprintf', '-DHAS_vsprintf_void', '-DHAS_snprintf_void',
                 '-DNO_snprintf', '-DHAS_sprintf_void'}
STRICT_DRIVER = b'''/* SPDX-License-Identifier: MIT
 * Original bounded single-member gzip completeness test, not a gzip utility.
 * Only exit 2 means invalid input; resource, I/O and internal failures are 3.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"
#define INPUT_CAP (16U * 1024U * 1024U)
#define OUTPUT_CAP (32U * 1024U * 1024U)
int main(void) {
    unsigned char *input = malloc(INPUT_CAP + 1U), output[16384];
    z_stream stream = {0};
    size_t size, total = 0;
    int status = 2, initialized = 0;
    if (!input || strcmp(zlibVersion(), ZLIB_VERSION) != 0) {
        free(input); fputs("strict gzip: allocation or version failure\\n", stderr); return 3;
    }
    size = fread(input, 1, INPUT_CAP + 1U, stdin);
    if (ferror(stdin) || size > INPUT_CAP) { status = 3; goto done; }
    if (inflateInit2(&stream, 31) != Z_OK) { status = 3; goto done; }
    initialized = 1;
    stream.next_in = input; stream.avail_in = (uInt)size;
    for (;;) {
        int result;
        size_t produced;
        stream.next_out = output; stream.avail_out = sizeof(output);
        result = inflate(&stream, Z_NO_FLUSH);
        produced = sizeof(output) - stream.avail_out;
        if (produced > OUTPUT_CAP - total) { status = 3; break; }
        total += produced;
        if (fwrite(output, 1, produced, stdout) != produced) { status = 3; break; }
        if (result == Z_STREAM_END) {
            if (stream.avail_in == 0) status = fflush(stdout) == 0 ? 0 : 3;
            break;
        }
        if (result != Z_OK) {
            status = (result == Z_DATA_ERROR || result == Z_BUF_ERROR) ? 2 : 3;
            break;
        }
        if (produced == 0 && stream.avail_in == 0) break;
    }
done:
    if (initialized && inflateEnd(&stream) != Z_OK) status = 3;
    free(input);
    if (status == 2) fputs("strict gzip: incomplete or invalid single gzip member\\n", stderr);
    if (status == 3) fputs("strict gzip: resource, I/O or internal failure\\n", stderr);
    return status;
}
'''
STRICT_SHA = hashlib.sha256(STRICT_DRIVER).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def regular(path, bound=LIMIT, single_link=True):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and (not single_link or info.st_nlink == 1) and info.st_size <= bound,
         'bounded regular single-link file required')
    need(not any(p.is_symlink() for p in path.parents), 'symlink ancestor refused')


def inventory(data):
    rows = {}
    for line in data.decode('utf-8').splitlines():
        fields = line.split()
        need(len(fields) == 2 and fields[0] not in rows, 'invalid/duplicate package inventory')
        rows[fields[0]] = fields[1]
    need(bool(rows), 'empty package inventory')
    return rows


def mounts(text):
    result = {}
    for line in text.splitlines():
        fields = line.split(); separator = fields.index('-')
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        need(point not in result, 'duplicate mount refused')
        root = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[3])
        result[point] = {'fs': fields[separator + 1], 'options': fields[5].split(','), 'root': root}
    return result


def observed():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    marker = Path('/.dockerenv')
    table = mounts(Path('/proc/self/mountinfo').read_text())
    devices, sockets = [], []
    count = 0
    for directory in ('/dev', '/run', '/inputs'):
        for path in Path(directory).rglob('*'):
            count += 1; need(count <= 8192, 'runtime resource inventory bound exceeded')
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode):
                sockets.append(str(path))
            if directory == '/dev' and (stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode)):
                if not stat.S_ISCHR(info.st_mode) or DEVICES.get(str(path)) != (os.major(info.st_rdev), os.minor(info.st_rdev)):
                    devices.append(str(path))
    return {'arch': platform.machine(), 'uid': os.geteuid(), 'gid': os.getegid(),
            'docker': marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()),
            'caps': {key: int(status.get(key, '-1').strip(), 16) for key in CAPS},
            'nnp': int(status.get('NoNewPrivs', '0')),
            'sockets': sockets + [p for p in ('/run/docker.sock', '/var/run/docker.sock', '/run/podman/podman.sock') if Path(p).exists()],
            'devices': devices, 'mounts': table,
            'owners': {p: {'uid': Path(p).stat().st_uid, 'gid': Path(p).stat().st_gid,
                           'mode': stat.S_IMODE(Path(p).stat().st_mode),
                           'safe': Path(p).is_dir() and not Path(p).is_symlink()} for p in ('/tmp', '/out')},
            'runtime_files': {p: stat.S_ISREG(Path(p).lstat().st_mode) and Path(p).stat().st_uid == 0
                              and not Path(p).stat().st_mode & 0o022
                              for p in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf') if p in table},
            'null_masks': {p: stat.S_ISCHR(Path(p).lstat().st_mode) and
                           os.major(Path(p).stat().st_rdev) == 1 and os.minor(Path(p).stat().st_rdev) == 3
                           for p in NULL_MASKS if p in table},
            'directory_masks': {p: Path(p).is_dir() and not Path(p).is_symlink() and not any(Path(p).iterdir())
                                for p in MASKS - NULL_MASKS - PROC_MASKS if p in table},
            'home': os.environ.get('HOME'), 'nonce': os.environ.get(MARKER)}


def guard(record, nonce):
    need(record['arch'] in ('aarch64', 'arm64') and record['uid'] > 0 and record['docker'], 'native nonroot Docker required')
    need(record['interfaces'] == ['lo'] and not record['sockets'] and not record['devices'], 'network/socket/device exposure refused')
    need(set(record['caps']) == set(CAPS) and all(v == 0 for v in record['caps'].values()) and record['nnp'] == 1,
         'all capabilities dropped/no-new-privileges required')
    need(record['nonce'] == nonce and re.fullmatch(r'[0-9a-f]{32}', nonce or '') and record['home'] == '/tmp/home',
         'private HOME/fresh nonce required')
    table = record['mounts']
    for entry in table.values():
        need(set(entry['options']) & {'ro', 'rw'} in ({'ro'}, {'rw'}), 'ambiguous mount access refused')
    for point, mode in (('/', 'ro'), ('/inputs', 'ro'), ('/out', 'rw'), ('/tmp', 'rw')):
        need(mode in table.get(point, {}).get('options', []), 'required mount mode differs')
    need(table['/']['fs'] in ('overlay', 'fuse-overlayfs') and table['/tmp']['fs'] == 'tmpfs', 'disposable root/private tmpfs required')
    need(table['/'].get('root') == table['/tmp'].get('root') == '/', 'root/tmp subtree bind refused')
    need(all(table[p]['fs'] in BIND_FS for p in ('/inputs', '/out')), 'ordinary data filesystem required')
    need({'nosuid', 'nodev'} <= set(table['/tmp']['options']), 'private tmpfs flags required')
    need(set(record['owners']) == {'/tmp', '/out'} and
         all(owner['uid'] == record['uid'] and owner['gid'] == record['gid'] and owner['safe'] and not owner['mode'] & 0o022
             for owner in record['owners'].values()), 'private owned temporary/output directories required')
    for point, entry in table.items():
        if point in ('/', '/inputs', '/out', '/tmp'):
            continue
        if point in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'):
            need(entry['fs'] in ('ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'fuse-overlayfs') and
                 bool({'ro', 'rw'} & set(entry['options'])) and record['runtime_files'].get(point) is True,
                 'invalid Docker metadata file mount')
        elif point in KERNEL:
            need(entry['fs'] == KERNEL[point], 'kernel/device filesystem substituted')
            need(('ro' if point.startswith('/sys') else 'rw') in entry['options'], 'runtime mount access differs')
            flags = {'nosuid'} if point == '/dev' else {'nosuid', 'noexec'} if point == '/dev/pts' else {'nosuid', 'nodev', 'noexec'}
            need(flags <= set(entry['options']) and entry.get('root') == '/', 'runtime flags/subtree bind refused')
        elif point in MASKS:
            if point in NULL_MASKS:
                need(entry['fs'] == 'tmpfs' and entry.get('root') == '/null' and 'nosuid' in entry['options']
                     and record['null_masks'].get(point) is True, 'kernel file must be masked by /dev/null')
            elif point in PROC_MASKS:
                need(entry['fs'] == 'proc' and 'ro' in entry['options']
                     and {'nosuid', 'nodev', 'noexec'} <= set(entry['options'])
                     and entry.get('root') == point.removeprefix('/proc'), 'invalid readonly proc subtree')
            else:
                need(entry['fs'] == 'tmpfs' and 'ro' in entry['options'] and entry.get('root') == '/'
                     and record['directory_masks'].get(point) is True, 'invalid empty masked kernel mount')
        else:
            raise ValueError('unexpected host/resource mount refused')


class Cancelled(Exception):
    pass


class Commands:
    def __init__(self, output, seconds=None):
        if seconds is None:
            seconds = 1140 if EXPERIMENT == 'ARM-C03' else 840
        self.output, self.deadline, self.child = output, time.monotonic() + seconds, None
        self.records = []
        self.log_bytes = 0

    def cancel(self, *_):
        raise Cancelled()

    def stop(self):
        child, self.child = self.child, None
        if child is None:
            return True
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            return False
        for _ in range(20):
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.05)
        return False

    def run(self, name, argv, cwd=None, env=None, source=None, target=None, timeout=180, allowed=(0,)):
        remaining = min(timeout, self.deadline - time.monotonic())
        need(remaining > 0, 'trial deadline exhausted')
        row = {'name': name, 'argv': argv, 'cwd': str(cwd) if cwd is not None else None,
               'environment': env, 'stdin': None, 'stdout': None, 'status': 'FAIL',
               'allowed_exit_codes': list(allowed),
               'timeout_seconds': remaining, 'started_unix_seconds': time.time()}
        self.records.append(row)
        log = self.output / (f'{len(self.records):03d}-' + name + '.log')
        started = time.monotonic()
        try:
            with log.open('xb') as stream:
                stdin = subprocess.DEVNULL
                stdout = stream
                try:
                    if source:
                        regular(source, 32 * 1024**2)
                        row['stdin'] = {'path': str(source), 'sha256': sha(source), 'bytes': source.stat().st_size}
                        stdin = source.open('rb')
                    if target:
                        stdout = target.open('xb')
                    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
                    try:
                        self.child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin, stdout=stdout,
                                                      stderr=stream, start_new_session=True,
                                                      # This single-threaded Linux runner must not leave
                                                      # cancellation signals blocked in its exec'd child.
                                                      preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous))
                    finally:
                        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                    end = started + remaining
                    while True:
                        try:
                            code = self.child.wait(timeout=min(1, max(0.001, end - time.monotonic())))
                            break
                        except subprocess.TimeoutExpired:
                            need(time.monotonic() < end, 'command timeout')
                            need(log.stat().st_size <= LIMIT and (not target or target.stat().st_size <= 32 * 1024**2),
                                 'command output exceeds bound')
                finally:
                    if source and stdin is not subprocess.DEVNULL:
                        stdin.close()
                    if target and stdout is not stream:
                        stdout.close()
            regular(log)
            self.log_bytes += log.stat().st_size
            need(self.log_bytes <= 12 * 1024**2, 'aggregate command log bound exceeded')
            if target:
                regular(target, 32 * 1024**2)
                row['stdout'] = {'path': str(target), 'sha256': sha(target), 'bytes': target.stat().st_size}
            row.update(exit_code=code, log=log.name, log_sha256=sha(log), log_bytes=log.stat().st_size)
            need(code in allowed, 'command exit differs')
            row['status'] = 'PASS'
            return log.read_bytes() if target is None else code
        except (Cancelled, KeyboardInterrupt, OSError, ValueError, subprocess.SubprocessError) as error:
            row['failure_kind'] = type(error).__name__
            row['failure_reason'] = str(error) if isinstance(error, ValueError) else 'command interrupted or failed before exit validation'
            raise
        finally:
            cancelled = []
            previous = {sig: signal.signal(sig, lambda signum, _: cancelled.append(signum)) for sig in (signal.SIGTERM, signal.SIGINT)}
            try:
                row['cleanup'] = 'PASS' if self.stop() else 'FAIL'
                if log.exists() and not log.is_symlink() and log.stat().st_size <= LIMIT:
                    regular(log)
                    row.update(log=log.name, log_sha256=sha(log), log_bytes=log.stat().st_size)
                if target and target.exists() and not target.is_symlink() and target.stat().st_size <= 32 * 1024**2:
                    regular(target, 32 * 1024**2)
                    row['stdout'] = {'path': str(target), 'sha256': sha(target), 'bytes': target.stat().st_size}
                row['elapsed_seconds'] = time.monotonic() - started
                row['finished_unix_seconds'] = time.time()
                if cancelled:
                    row.update(status='FAIL', cancelled=True)
                save(self.output / 'commands.json', self.records)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
            need(row['cleanup'] == 'PASS', 'tracked process group cleanup failed')
            if cancelled:
                row.update(status='FAIL', cancelled=True)
                save(self.output / 'commands.json', self.records)
                raise Cancelled()


def extract(source, output):
    """Bounded manual extraction: no symlinks, hardlinks, devices or traversal."""
    regular(source, 8 * 1024**2); need(sha(source) == SOURCE_SHA, 'pinned zlib source changed')
    seen, total = set(), 0
    with tarfile.open(source, 'r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and '..' not in path.parts and path.parts[0] == 'zlib-1.3.2', 'unsafe source archive path')
            need(member.name not in seen and len(seen) < 2048 and (member.isdir() or member.isfile()), 'unsupported/duplicate source member')
            seen.add(member.name); total += member.size
            need(member.size <= 8 * 1024**2 and total <= 64 * 1024**2, 'source extraction bound')
            dest = output.joinpath(*path.parts[1:])
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as stream, dest.open('xb') as target:
                    shutil.copyfileobj(stream, target)
                dest.chmod(0o755 if member.mode & 0o111 else 0o644)


def artifacts(root):
    for name in ('libz.a', 'example', 'minigzip'):
        regular(root / name, 8 * 1024**2)
    return {name: sha(root / name) for name in ('libz.a', 'example', 'minigzip')}


def elf_layout(data):
    text = data.decode('utf-8')
    need(re.search(r'Machine:\s+AArch64\b', text) and re.search(r'Class:\s+ELF64\b', text), 'final binary must be AArch64 ELF64')
    loads = []
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == 'LOAD':
            offset, address, alignment = int(fields[1], 16), int(fields[2], 16), int(fields[-1], 16)
            need(alignment >= 16384 and alignment & (alignment - 1) == 0 and offset % 16384 == address % 16384,
                 'ELF load layout cannot satisfy 16K alignment')
            need(not {'W', 'E'} <= set(''.join(fields[6:-1])), 'writable executable segment refused')
            loads.append({'offset': offset, 'virtual_address': address, 'alignment': alignment})
    need(bool(loads), 'ELF load segments missing')
    return {'loads': loads, 'needed': re.findall(r'\(NEEDED\).*?\[(.*?)\]', text),
            'interpreter': re.findall(r'Requesting program interpreter: (.*?)\]', text),
            '16k_execution': 'NOT RUN'}


def late_cancellation(report, events, path):
    if events:
        report.update(status='FAIL', cancelled=True)
        save(path, report)


def trial_env():
    return {'PATH': '/usr/bin:/bin', 'HOME': '/tmp/home', 'TMPDIR': '/tmp', 'LC_ALL': 'C',
            'SOURCE_DATE_EPOCH': '1791748800', 'QEMU_RUN': '', 'CC': 'gcc', 'AR': 'gcc-ar', 'RANLIB': 'gcc-ranlib'}


def build_flags(variant):
    need(variant in variants(), 'variant differs from selected experiment')
    flags = BASE_FLAGS.replace('-O2 ', '-O3 ', 1) if variant == 'o3' else BASE_FLAGS
    if variant == 'm2':
        flags = flags.replace('-mtune=generic ', '-mtune=apple-m2 ', 1)
    if variant == 'pgo':
        use = ' -fprofile-use=/tmp/profile -Werror=missing-profile -Werror=coverage-mismatch'
        return flags + ' -fno-lto' + use, LINK_FLAGS + ' -fno-lto' + use
    return (flags + (' -flto=2 -Werror=lto-type-mismatch' if variant == 'lto' else ' -fno-lto'),
            LINK_FLAGS + (' -flto=2' if variant == 'lto' else ' -fno-lto'))


def configure_flags(variant):
    # Configure's temporary probes have no retained profiles. Final C03 object
    # compilations receive the fatal profile policy after those probes finish.
    return build_flags('baseline' if variant == 'pgo' else variant)


def strict_flags(prefix):
    # The independent oracle has no training TU/profile; keep it fixed in C03.
    return build_flags('baseline' if EXPERIMENT == 'ARM-C03' else prefix.split('-')[0])


def strict_compile(prefix):
    cflags, ldflags = strict_flags(prefix)
    return ['gcc', *shlex.split(cflags.replace('$@', 'strict-gzip')), '-I/tmp/build', '/out/strict-gzip.c',
            '/out/' + prefix + '/libz.a', '-o', '/out/' + prefix + '/strict-gzip', *shlex.split(ldflags)]


def configured_flags(makefile, configure_log, variant):
    """Validate the final assignments written by pinned GNU/Linux configure.

    configure appends -fPIC and feature-probe defines to the supplied CFLAGS.
    It retains LDFLAGS on ARM/Linux. Extra optimization, LTO or ISA choices are
    refused rather than treating declared environment flags as effective flags.
    """
    keys = ('CC', 'AR', 'RANLIB', 'CFLAGS', 'LDFLAGS')
    values = []
    for data in (makefile, configure_log):
        record = {}
        for key in keys:
            found = re.findall(r'^' + key + r'[ \t]*=[ \t]*([^\n]*)$', data.decode('utf-8'), re.MULTILINE)
            need(len(found) == 1, 'one final configured assignment required: ' + key)
            record[key] = ' '.join(shlex.split(found[0]))
        values.append(record)
    if variant == 'pgo':
        probe = configured_flags(configure_log, configure_log, 'baseline')
        suffix = shlex.split(probe['CFLAGS'])[len(shlex.split(build_flags('baseline')[0])):]
        cflags, ldflags = build_flags(variant)
        expected = {**probe, 'CFLAGS': ' '.join(shlex.split(cflags) + suffix), 'LDFLAGS': ldflags}
        need(values[0] == expected, 'profile-use Makefile differs from validated configure probes')
        return {**values[0], 'configure_probe': probe}
    need(values[0] == values[1], 'Makefile/configure.log effective flags differ')
    record = values[0]
    need(all(record[key] == value for key, value in (('CC', 'gcc'), ('AR', 'gcc-ar'), ('RANLIB', 'gcc-ranlib'))),
         'configured tool overrides refused')
    cflags, ldflags = build_flags(variant)
    expected, actual = shlex.split(cflags), shlex.split(record['CFLAGS'])
    suffix = actual[len(expected):]
    need(actual[:len(expected)] == expected and suffix and suffix[0] == '-fPIC'
         and len(suffix) == len(set(suffix)) and all(flag in FEATURE_FLAGS for flag in suffix),
         'configured compiler flags contradict declared experiment')
    need(record['LDFLAGS'] == ldflags, 'configured linker flags contradict declared experiment')
    return record


def command_plan(manifest):
    """Exact native command/dataflow graph; stdout bytes remain producer evidence."""
    rows, env = [], trial_env()
    names = list(build_names())
    def add(name, argv, cwd=None, environment=None, source=None, target=None, reject=False, sample=False, observe=False):
        rows.append({'name': name, 'argv': argv, 'cwd': cwd, 'environment': environment or env,
                     'source': source, 'target': target, 'reject': reject, 'sample': sample, 'observe': observe})
    add('inventory', ['/usr/bin/pacman', '-Q'])
    for name, argv in [('gcc', ['gcc', '-v']), ('ld', ['ld', '--version']), ('ar', ['gcc-ar', '--version']), ('cpu', ['lscpu', '--json'])]:
        add('tool-' + name, argv)
    if profile_adapter():
        rows.extend(profile_adapter().command_plan(sys.modules[__name__], manifest))
    for prefix in names:
        cflags, ldflags = build_flags(prefix.split('-')[0])
        build_env = {**env, 'CFLAGS': cflags, 'LDFLAGS': ldflags}
        for label, argv in [('configure', ['./configure', '--static']), ('build', ['make', '-j2', 'static']), ('test', ['make', 'teststatic'])]:
            probe_c, probe_l = configure_flags(prefix.split('-')[0])
            selected_env = {**env, 'CFLAGS': probe_c, 'LDFLAGS': probe_l} if label == 'configure' else build_env
            add(prefix + '-' + label, argv, '/tmp/build', selected_env)
        binary = '/out/' + prefix + '/minigzip'
        for label, argv in [('elf', ['readelf', '-W', '-h', '-l', '-d', binary]),
                            ('dependencies', ['ldd', binary]), ('symbols', ['gcc-nm', '/tmp/build/libz.a']),
                            ('archive-sections', ['readelf', '-W', '-S', '/tmp/build/libz.a'])]:
            add(prefix + '-' + label, argv)
        add(prefix + '-strict-compile', strict_compile(prefix), '/tmp/build')
        add(prefix + '-strict-elf', ['readelf', '-W', '-h', '-l', '-d', '/out/' + prefix + '/strict-gzip'])
    for prefix in names:
        binary = '/out/' + prefix + '/minigzip'
        for row in manifest['files']:
            stem, source = Path(row['path']).stem, '/tmp/corpus/' + row['path']
            if row['kind'] == 'corrupt':
                for decoder in names:
                    name = prefix + '-reject-' + stem + '-' + decoder
                    add(name, ['/out/' + decoder + '/strict-gzip'], source=source, target='/out/' + name + '.bin', reject=True)
            else:
                for level in (1, 6, 9):
                    name = f'{prefix}-{stem}-{level}'
                    encoded = '/out/' + name + '.gz'
                    add(name + '-encode', [binary, '-' + str(level)], source=source, target=encoded)
                    for decoder in names:
                        add(name + '-decode-' + decoder, ['/out/' + decoder + '/minigzip', '-d'],
                            source=encoded, target='/out/' + name + '-' + decoder + '.decoded')
    for prefix in names:
        add(prefix + '-strict-valid', ['/out/' + prefix + '/strict-gzip'], source='/tmp/corpus/gzip-reference.gz',
            target='/out/' + prefix + '-strict-valid.bin')
        add(prefix + '-sample-crc', ['/out/' + prefix + '/minigzip', '-d'], source='/tmp/corpus/corrupt-crc.gz',
            target='/out/' + prefix + '-sample-crc.bin', sample=True)
        add(prefix + '-sample-truncation', ['/out/' + prefix + '/minigzip', '-d'], source='/tmp/corpus/truncated-trailer.gz',
            target='/out/' + prefix + '-sample-truncation.bin', observe=True)
    return rows


def input_bytes(value, default, bound=8 * 1024**2):
    if value is None:
        value = default
    if isinstance(value, bytes):
        need(len(value) <= bound, 'receiver input exceeds bound')
        return value
    value = Path(value); regular(value, bound)
    return value.read_bytes()


def source_material(data):
    need(hashlib.sha256(data).hexdigest() == SOURCE_SHA, 'receiver source archive pin differs')
    seen, total, material = set(), 0, {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            need(path.parts and not path.is_absolute() and '..' not in path.parts and path.parts[0] == 'zlib-1.3.2'
                 and member.name not in seen and len(seen) < 2048 and (member.isdir() or member.isfile()), 'unsafe receiver source archive')
            seen.add(member.name); total += member.size
            need(0 <= member.size <= 8 * 1024**2 and total <= 64 * 1024**2, 'receiver source extraction bound')
            if path.as_posix() in ('zlib-1.3.2/LICENSE', 'zlib-1.3.2/README'):
                need(member.isfile(), 'source notice/README must be regular')
                material[path.name] = archive.extractfile(member).read()
    need(set(material) == {'LICENSE', 'README'} and all(material.values()), 'source license and README required')
    return material


def verify_result(raw, contract, expected_packages=None, source=None):
    """Check pinned source, retained bytes and the complete graph; never replay commands.

    Optional inputs are bytes or Paths. Defaults use the host's immutable input
    snapshot adjacent to raw. Missing source/package evidence always refuses.
    Unsigned producer records are not cryptographic execution attestation.
    """
    raw = Path(raw)
    packages = input_bytes(expected_packages, raw.parent / 'inputs/packages.lock')
    need(hashlib.sha256(packages).hexdigest() == contract['packages_sha256'], 'receiver package inventory pin differs')
    source_bytes = input_bytes(source, raw.parent / 'inputs/zlib.tar.gz')
    need(contract.get('purpose') == PURPOSE and contract['source_sha256'] == SOURCE_SHA, 'receiver source contract differs')
    need(sha(Path(__file__).resolve()) == contract['runner_sha256']
         and sha(Path(corpus.__file__).resolve()) == contract['corpus_sha256'], 'receiver helper source pins differ')
    if profile_adapter():
        need(sha(Path(profile_adapter().__file__).resolve()) == contract.get('pgo_sha256'), 'profile adapter source differs')
    material = source_material(source_bytes)
    regular(raw / 'result.json')
    report = json.loads((raw / 'result.json').read_text())
    need(report.get('status') == 'PASS' and report.get('purpose') == PURPOSE and report.get('contract') == contract
         and report.get('cleanup') == 'PASS' and report.get('selected_for_release') is False
         and report.get('hardware_validation') == report.get('performance_acceptance') == 'NOT RUN', 'bound software-only receipt required')
    regular(raw / 'environment.json')
    environment = json.loads((raw / 'environment.json').read_text())
    need(report.get('environment_sha256') == sha(raw / 'environment.json'), 'environment receipt binding differs')
    guard(environment['observed'], contract['nonce'])
    need(isinstance(environment.get('page_size'), int) and not isinstance(environment['page_size'], bool)
         and environment['page_size'] >= 4096 and not environment['page_size'] & (environment['page_size'] - 1), 'native page-size observation required')
    kernel = environment.get('kernel', {})
    need(kernel.get('system') == 'Linux' and kernel.get('machine') in ('aarch64', 'arm64')
         and isinstance(kernel.get('release'), str) and kernel['release']
         and isinstance(environment.get('python'), str) and environment['python']
         and isinstance(environment.get('zlib_runtime'), str) and environment['zlib_runtime'], 'native environment fields required')
    tools = environment.get('tool_files', {})
    need(set(tools) == set(tool_names()), 'complete native tool file pins required')
    for row in tools.values():
        path = PurePosixPath(row['path'])
        need(set(row) == {'path', 'sha256'} and path.is_absolute() and path.is_relative_to('/usr')
             and '..' not in path.parts and PIN.fullmatch(row['sha256']), 'native tool path/hash required')
    regular(raw / 'corpus-manifest.json')
    manifest = json.loads((raw / 'corpus-manifest.json').read_text())
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-receiver-corpus-') as temporary:
        expected_root = Path(temporary) / 'corpus'
        expected_manifest = corpus.create(expected_root, material['README'])
        need(manifest == expected_manifest, 'corpus differs from independent source derivation')
        need((raw / 'corpus').is_dir() and not (raw / 'corpus').is_symlink()
             and {p.name for p in (raw / 'corpus').iterdir()} == {p.name for p in expected_root.iterdir()}, 'complete exact corpus files required')
        for path in expected_root.iterdir():
            retained = raw / 'corpus' / path.name; regular(retained, corpus.LIMIT)
            need(retained.read_bytes() == path.read_bytes(), 'retained corpus differs from source derivation')
    need(report.get('corpus_manifest_sha256') == sha(raw / 'corpus-manifest.json'), 'corpus receipt binding differs')
    regular(raw / 'strict-gzip.c')
    need((raw / 'strict-gzip.c').read_bytes() == STRICT_DRIVER and report.get('strict_driver_source_sha256') == STRICT_SHA,
         'strict driver source binding differs')
    builds = report.get('builds', [])
    expected_builds = [(v, n) for v in variants() for n in (1, 2)]
    need([(b['variant'], b['attempt']) for b in builds] == expected_builds, 'all four ordered build receipts required')
    for build in builds:
        root = raw / f"{build['variant']}-{build['attempt']}"
        need(artifacts(root) == build['artifacts'], 'retained artifacts differ from receipt')
        for name in ('example', 'minigzip'):
            need(stat.S_IMODE((root / name).stat().st_mode) == 0o755, 'retained binary must remain executable')
        cflags, ldflags = build_flags(build['variant'])
        need(build.get('cflags') == cflags and build.get('ldflags') == ldflags, 'declared build flags differ')
        generated = build.get('generated_configuration_sha256', {})
        need(set(generated) == set(CONFIG_FILES), 'all generated configuration and license pins required')
        for name in CONFIG_FILES:
            path = root / (name + '.txt'); regular(path)
            need(sha(path) == generated[name], 'retained configuration hash differs')
        need((root / 'LICENSE.txt').read_bytes() == material['LICENSE'], 'retained license differs from pinned source')
        effective = configured_flags((root / 'Makefile.txt').read_bytes(), (root / 'configure.log.txt').read_bytes(), build['variant'])
        need(build.get('configured_flags') == effective, 'effective configured flag receipt differs')
        driver = root / 'strict-gzip'; regular(driver, 8 * 1024**2)
        need(stat.S_IMODE(driver.stat().st_mode) == 0o755 and build.get('strict_driver', {}).get('binary_sha256') == sha(driver)
             and build['strict_driver'].get('source_sha256') == STRICT_SHA, 'strict driver binary/source binding differs')
    suffixes = [shlex.split(b['configured_flags']['CFLAGS'])[len(shlex.split(build_flags(b['variant'])[0])):] for b in builds]
    need(all(value == suffixes[0] for value in suffixes), 'configure feature flags differ between builds/variants')
    need(report.get('reproducibility') == {variant: 'PASS' for variant in variants()}, 'both rebuild pairs required')
    for variant in variants():
        pair = [b['artifacts'] for b in builds if b['variant'] == variant]
        need(pair[0] == pair[1], 'retained rebuild pair bytes differ')
        drivers = [b['strict_driver']['binary_sha256'] for b in builds if b['variant'] == variant]
        need(drivers[0] == drivers[1], 'strict driver rebuild pair differs')
    regular(raw / 'commands.json')
    commands = json.loads((raw / 'commands.json').read_text())
    planned = command_plan(manifest)
    need(len(commands) == len(planned) and [r.get('name') for r in commands] == [r['name'] for r in planned], 'complete exact ordered command graph required')
    logs, output_bindings, by_name = set(), {}, {}
    corpus_bindings = {'/tmp/corpus/' + r['path']: {'path': '/tmp/corpus/' + r['path'], 'sha256': r['sha256'], 'bytes': r['bytes']}
                       for r in manifest['files']}
    for index, (row, plan) in enumerate(zip(commands, planned), 1):
        need(row.get('status') == row.get('cleanup') == 'PASS' and not row.get('cancelled'), 'successful cleaned commands required')
        need(all(row.get(key) == plan[key] for key in ('argv', 'cwd', 'environment')), 'command argv/cwd/environment differs')
        code = row.get('exit_code')
        need(isinstance(code, int) and not isinstance(code, bool), 'integer command exit required')
        allowed = code == 2 if plan['reject'] else 1 <= code <= 255 if plan['sample'] else code in (0, 1) if plan['observe'] else code == 0
        need(allowed, 'command exit differs')
        expected_codes = [2] if plan['reject'] else list(range(1, 256)) if plan['sample'] else [0, 1] if plan['observe'] else [0]
        need(row.get('allowed_exit_codes') == expected_codes, 'declared command exit criterion differs')
        name = f"{index:03d}-" + plan['name'] + '.log'
        need(row.get('log') == name and name not in logs, 'unique exact command log required')
        path = raw / name; regular(path)
        need(sha(path) == row.get('log_sha256') and path.stat().st_size == row.get('log_bytes'), 'retained command log differs')
        logs.add(name); by_name[plan['name']] = row
        if plan['source'] is None:
            need(row.get('stdin') is None, 'unexpected command stdin')
        else:
            expected = corpus_bindings.get(plan['source'], output_bindings.get(plan['source']))
            need(expected is not None and row.get('stdin') == expected, 'command stdin dataflow differs')
        if plan['target'] is None:
            need(row.get('stdout') is None, 'unexpected command stdout file')
        else:
            binding = row.get('stdout', {})
            need(set(binding) == {'path', 'sha256', 'bytes'} and binding['path'] == plan['target']
                 and PIN.fullmatch(binding['sha256']) and isinstance(binding['bytes'], int)
                 and not isinstance(binding['bytes'], bool) and 0 <= binding['bytes'] <= 32 * 1024**2, 'command stdout binding differs')
            need(plan['target'] not in output_bindings, 'duplicate streamed output')
            output_bindings[plan['target']] = binding
            if plan['reject'] or plan['sample'] or plan['observe'] or plan['name'].endswith('-strict-valid'):
                path = raw / Path(plan['target']).name; regular(path, 32 * 1024**2)
                need(path.stat().st_size == binding['bytes'] and sha(path) == binding['sha256'], 'retained rejection output differs')
    need({p.name for p in raw.glob('*.log')} == logs, 'unrecorded command logs refused')
    need(inventory((raw / by_name['inventory']['log']).read_bytes()) == inventory(packages), 'observed inventory log differs from pinned package input')
    for build in builds:
        prefix = f"{build['variant']}-{build['attempt']}"
        data = (raw / by_name[prefix + '-elf']['log']).read_bytes()
        need(build.get('elf') == elf_layout(data), 'ELF receipt differs from actual retained log')
        data = (raw / by_name[prefix + '-archive-sections']['log']).read_bytes()
        need((b'.gnu.lto_' in data) == (build['variant'] == 'lto'), 'retained archive LTO evidence differs')
        data = (raw / by_name[prefix + '-strict-elf']['log']).read_bytes()
        need(build['strict_driver'].get('elf') == elf_layout(data), 'strict driver ELF evidence differs')
    checks, names = report.get('correctness', []), [f'{v}-{n}' for v, n in expected_builds]
    expected = {(b, r['path'], level, d) for b in names for r in manifest['files'] if r['kind'] == 'input' for level in (1, 6, 9) for d in names}
    positives = [r for r in checks if 'level' in r]
    need(len(positives) == len(expected) and {(r['build'], r['input'], r['level'], r['decoder']) for r in positives} == expected, 'complete cross-decoder checks required')
    inputs = {r['path']: r for r in manifest['files']}
    for row in positives:
        wanted = inputs[row['input']]
        name = f"{row['build']}-{Path(row['input']).stem}-{row['level']}-decode-{row['decoder']}"
        observed_output = by_name[name]['stdout']
        need(row.get('status') == 'PASS' and row.get('decoded_sha256') == wanted['sha256']
             and observed_output['sha256'] == wanted['sha256'] and observed_output['bytes'] == wanted['bytes'], 'correct decoded hashes/dataflow required')
    rejected = [r for r in checks if 'rejected_exit' in r]
    expected_rejections = {(b, r['path'], d) for b in names for r in manifest['files'] if r['kind'] == 'corrupt' for d in names}
    need(len(checks) == len(positives) + len(rejected) and len(rejected) == len(expected_rejections)
         and {(r['build'], r['input'], r['decoder']) for r in rejected} == expected_rejections, 'all corruption rejections required')
    for row in rejected:
        name = row['build'] + '-reject-' + Path(row['input']).stem + '-' + row['decoder']
        need(row['rejected_exit'] == by_name[name]['exit_code'], 'corruption exit differs from command record')
        need(row.get('driver') == 'strict-zlib-inflate', 'sample CLI cannot substitute for strict rejection')
    valid = report.get('strict_valid', [])
    need(len(valid) == 4 and {r['decoder'] for r in valid} == set(names), 'all strict valid-stream checks required')
    payload_sha = hashlib.sha256(corpus.GZIP_PAYLOAD).hexdigest()
    for row in valid:
        output = by_name[row['decoder'] + '-strict-valid']['stdout']
        need(row.get('status') == 'PASS' and row.get('decoded_sha256') == payload_sha
             and output['sha256'] == payload_sha and output['bytes'] == len(corpus.GZIP_PAYLOAD), 'strict valid-stream payload differs')
    sample_crc, observations = report.get('sample_crc', []), report.get('sample_truncation', [])
    for rows, key in ((sample_crc, 'sample-crc'), (observations, 'sample-truncation')):
        need(len(rows) == 4 and {r['decoder'] for r in rows} == set(names), 'complete sample behavior records required')
        for row in rows:
            need(row.get('exit_code') == by_name[row['decoder'] + '-' + key]['exit_code'], 'sample behavior exit differs')
            if key == 'sample-crc':
                need(row.get('status') == 'PASS', 'sample CRC rejection required')
            else:
                need(row.get('status') == 'OBSERVED' and row.get('rejection_acceptance') == 'NOT CLAIMED',
                     'sample truncation observation must not become rejection acceptance')
    if profile_adapter():
        report['profile_verification'] = profile_adapter().verify(sys.modules[__name__], raw, report.get('profile'), manifest, source_bytes, commands)
    return {**report, 'receiver_verification': {
        'status': 'PASS', 'command_count': len(commands), 'build_count': len(builds),
        'cross_decode_count': len(positives), 'rejection_count': len(rejected),
        'strict_valid_count': len(valid), 'sample_crc_count': len(sample_crc), 'sample_truncation_observation_count': len(observations),
        'environment_sha256': sha(raw / 'environment.json'), 'source_sha256': SOURCE_SHA,
        'packages_sha256': hashlib.sha256(packages).hexdigest(),
        'scope': 'Independent pinned source/corpus/license derivation, retained artifact/config/log/ELF/LTO and full recorded command/dataflow graph checks; no execution replay or attestation.',
        'hardware_validation': 'NOT RUN', 'performance_acceptance': 'NOT RUN'}}


def inside():
    inputs, out = Path('/inputs'), Path('/out')
    # Real guard precedes contract/file reads and all output writes.
    guard(observed(), os.environ.get(MARKER))
    regular(inputs / 'contract.json')
    need(sha(inputs / 'contract.json') == os.environ.get(MARKER + '_CONTRACT'), 'contract pin differs')
    contract = json.loads((inputs / 'contract.json').read_text())
    expected_keys = {'purpose', 'nonce', 'image', 'source_commit', 'source_sha256', 'packages_sha256', 'runner_sha256', 'corpus_sha256'}
    if profile_adapter():
        expected_keys.add('pgo_sha256')
    need(set(contract) == expected_keys, 'unexpected contract fields')
    need(contract['purpose'] == PURPOSE and contract['nonce'] == os.environ.get(MARKER), 'contract identity differs')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', contract['image']) and re.fullmatch(r'[0-9a-f]{40}', contract['source_commit']), 'image/commit identity required')
    for name, pin in [('arm_c01.py', 'runner_sha256'), ('corpus.py', 'corpus_sha256'), ('packages.lock', 'packages_sha256'), ('zlib.tar.gz', 'source_sha256')]:
        regular(inputs / name, 8 * 1024**2)
        need(PIN.fullmatch(contract[pin]) and sha(inputs / name) == contract[pin], 'input/source pin differs')
    if profile_adapter():
        regular(inputs / 'pgo.py', 8 * 1024**2)
        need(sha(inputs / 'pgo.py') == contract['pgo_sha256'] and Path(profile_adapter().__file__).resolve() == inputs / 'pgo.py', 'profile adapter input differs')
    need(contract['source_sha256'] == SOURCE_SHA and Path(__file__).resolve() == inputs / 'arm_c01.py', 'entry/source differs')
    need(out.is_dir() and not out.is_symlink() and not list(out.iterdir()), 'empty real evidence mount required')
    report = {'purpose': PURPOSE, 'status': 'FAIL', 'contract': contract, 'hardware_validation': 'NOT RUN',
              'performance_acceptance': 'NOT RUN', 'selected_for_release': False, 'builds': [], 'correctness': [],
              'strict_driver_source_sha256': STRICT_SHA, 'strict_valid': [], 'sample_crc': [], 'sample_truncation': [],
              'random_seed_control': {'flag': RANDOM_SEED_FLAG, 'policy': 'GNU make output target; shared by baseline and LTO',
                                      'native_reproducibility': 'Requires exact rebuilt artifact comparisons; not inferred from seed choice'}}
    runner = Commands(out, 1080 if EXPERIMENT == 'ARM-C03' else 780)
    previous = {sig: signal.signal(sig, runner.cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        Path('/tmp/home').mkdir(mode=0o700)
        env = trial_env()
        actual = runner.run('inventory', ['/usr/bin/pacman', '-Q'], env=env)
        need(inventory(actual) == inventory((inputs / 'packages.lock').read_bytes()), 'runtime inventory differs')
        tools = {}
        for name in tool_names():
            path = Path('/usr/bin', name).resolve()
            need(path.is_relative_to('/usr'), 'tool escapes immutable system tree')
            regular(path, 64 * 1024**2, single_link=False)
            tools[name] = {'path': str(path), 'sha256': sha(path)}
        save(out / 'environment.json', {'observed': observed(), 'page_size': os.sysconf('SC_PAGE_SIZE'),
                                       'kernel': platform.uname()._asdict(), 'tool_files': tools,
                                       'python': sys.version, 'zlib_runtime': zlib.ZLIB_RUNTIME_VERSION})
        report['environment_sha256'] = sha(out / 'environment.json')
        for name, argv in [('gcc', ['gcc', '-v']), ('ld', ['ld', '--version']), ('ar', ['gcc-ar', '--version']), ('cpu', ['lscpu', '--json'])]:
            runner.run('tool-' + name, argv, env=env)
        work = Path('/tmp/build'); work.mkdir()
        extract(inputs / 'zlib.tar.gz', work)
        source_heldout = (work / 'README').read_bytes()
        shutil.rmtree(work)
        corpus_root = Path('/tmp/corpus')
        manifest = corpus.create(corpus_root, source_heldout)
        save(out / 'corpus-manifest.json', manifest)
        report['corpus_manifest_sha256'] = sha(out / 'corpus-manifest.json')
        # Retain corpus bytes as exact retrievable experiment inputs.
        shutil.copytree(corpus_root, out / 'corpus')
        (out / 'strict-gzip.c').write_bytes(STRICT_DRIVER)
        if profile_adapter():
            report['profile'] = profile_adapter().prepare(sys.modules[__name__], runner, inputs, out, env, corpus_root, manifest)
        for variant in variants():
            for attempt in (1, 2):
                guard(observed(), contract['nonce'])
                work.mkdir(); extract(inputs / 'zlib.tar.gz', work)
                prefix = f'{variant}-{attempt}'
                if variant == 'pgo':
                    report['profile']['restores'].append(profile_adapter().restore(sys.modules[__name__], out, attempt))
                flags, ldflags = build_flags(variant)
                build_env = {**env, 'CFLAGS': flags, 'LDFLAGS': ldflags}
                for label, argv in [('configure', ['./configure', '--static']), ('build', ['make', '-j2', 'static']), ('test', ['make', 'teststatic'])]:
                    probe_c, probe_l = configure_flags(variant)
                    selected_env = {**env, 'CFLAGS': probe_c, 'LDFLAGS': probe_l} if label == 'configure' else build_env
                    runner.run(prefix + '-' + label, argv, cwd=work, env=selected_env)
                    if variant == 'pgo' and label == 'configure':
                        profile_adapter().apply_use_flags(sys.modules[__name__], work)
                hashes = artifacts(work)
                dest = out / prefix; dest.mkdir()
                for name in hashes:
                    shutil.copyfile(work / name, dest / name)
                    (dest / name).chmod(0o644 if name == 'libz.a' else 0o755)
                    need(sha(dest / name) == hashes[name], 'artifact changed during copy')
                generated = {}
                for name in CONFIG_FILES:
                    regular(work / name)
                    shutil.copyfile(work / name, dest / (name + '.txt'))
                    generated[name] = sha(dest / (name + '.txt'))
                effective = configured_flags((work / 'Makefile').read_bytes(), (work / 'configure.log').read_bytes(), variant)
                elf = runner.run(prefix + '-elf', ['readelf', '-W', '-h', '-l', '-d', str(dest / 'minigzip')], env=env)
                layout = elf_layout(elf)
                runner.run(prefix + '-dependencies', ['ldd', str(dest / 'minigzip')], env=env)
                runner.run(prefix + '-symbols', ['gcc-nm', str(work / 'libz.a')], env=env)
                sections = runner.run(prefix + '-archive-sections', ['readelf', '-W', '-S', str(work / 'libz.a')], env=env)
                need((b'.gnu.lto_' in sections) == (variant == 'lto'), 'archive LTO intermediate representation differs from variant')
                runner.run(prefix + '-strict-compile', strict_compile(prefix), cwd=work, env=env)
                regular(dest / 'strict-gzip', 8 * 1024**2); (dest / 'strict-gzip').chmod(0o755)
                strict_elf = runner.run(prefix + '-strict-elf', ['readelf', '-W', '-h', '-l', '-d', str(dest / 'strict-gzip')], env=env)
                strict = {'source_sha256': STRICT_SHA, 'binary_sha256': sha(dest / 'strict-gzip'), 'elf': elf_layout(strict_elf)}
                if variant == 'pgo':
                    report['profile']['unchanged_after_build'].append(profile_adapter().assert_unchanged(sys.modules[__name__], out, attempt))
                report['builds'].append({'variant': variant, 'attempt': attempt, 'artifacts': hashes, 'cflags': flags,
                                       'ldflags': build_env['LDFLAGS'], 'configured_flags': effective,
                                       'strict_driver': strict,
                                       'generated_configuration_sha256': generated, 'elf': layout})
                shutil.rmtree(work)
                save(out / 'result.json', report)
        decoders = [(f"{b['variant']}-{b['attempt']}", out / f"{b['variant']}-{b['attempt']}" / 'minigzip')
                    for b in report['builds']]
        for build in report['builds']:
            prefix = f"{build['variant']}-{build['attempt']}"
            binary = out / prefix / 'minigzip'
            for row in manifest['files']:
                path = corpus_root / row['path']; need(sha(path) == row['sha256'], 'corpus changed')
                if row['kind'] == 'corrupt':
                    # The sample minigzip clears some truncation errors; strict
                    # inflate completion, not its CLI exit, supplies this gate.
                    for label, _ in decoders:
                        decoder = out / label / 'strict-gzip'
                        code = runner.run(prefix + '-reject-' + path.stem + '-' + label,
                                          [str(decoder)], env=env, source=path,
                                          target=out / (prefix + '-reject-' + path.stem + '-' + label + '.bin'), timeout=30, allowed=(2,))
                        report['correctness'].append({'build': prefix, 'input': row['path'], 'decoder': label,
                                                      'driver': 'strict-zlib-inflate', 'rejected_exit': code})
                    continue
                for level in (1, 6, 9):
                    stem = f'{prefix}-{path.stem}-{level}'
                    encoded = out / (stem + '.gz')
                    runner.run(stem + '-encode', [str(binary), '-' + str(level)], env=env, source=path, target=encoded, timeout=30)
                    for label, decoder in decoders:
                        decoded = out / (stem + '-' + label + '.decoded')
                        runner.run(stem + '-decode-' + label, [str(decoder), '-d'], env=env, source=encoded, target=decoded, timeout=30)
                        need(decoded.stat().st_size == row['bytes'] and sha(decoded) == row['sha256'], 'decoded bytes differ')
                        report['correctness'].append({'build': prefix, 'input': row['path'], 'level': level, 'decoder': label, 'decoded_sha256': sha(decoded), 'status': 'PASS'})
                        decoded.unlink()
                    encoded.unlink()
        for label, decoder in decoders:
            strict_output = out / (label + '-strict-valid.bin')
            runner.run(label + '-strict-valid', [str(out / label / 'strict-gzip')], env=env,
                       source=corpus_root / 'gzip-reference.gz', target=strict_output, timeout=30)
            need(strict_output.read_bytes() == corpus.GZIP_PAYLOAD, 'strict valid gzip payload differs')
            report['strict_valid'].append({'decoder': label, 'status': 'PASS', 'decoded_sha256': sha(strict_output)})
            code = runner.run(label + '-sample-crc', [str(decoder), '-d'], env=env, source=corpus_root / 'corrupt-crc.gz',
                              target=out / (label + '-sample-crc.bin'), timeout=30, allowed=tuple(range(1, 256)))
            report['sample_crc'].append({'decoder': label, 'exit_code': code, 'status': 'PASS'})
            code = runner.run(label + '-sample-truncation', [str(decoder), '-d'], env=env,
                              source=corpus_root / 'truncated-trailer.gz', target=out / (label + '-sample-truncation.bin'), timeout=30, allowed=(0, 1))
            report['sample_truncation'].append({'decoder': label, 'exit_code': code, 'status': 'OBSERVED',
                                                'rejection_acceptance': 'NOT CLAIMED'})
        if profile_adapter():
            profile_adapter().assert_unchanged(sys.modules[__name__], out, 2)
        report['reproducibility'] = {}
        for variant in variants():
            pair = [b for b in report['builds'] if b['variant'] == variant]
            report['reproducibility'][variant] = 'PASS' if (pair[0]['artifacts'] == pair[1]['artifacts']
                and pair[0]['strict_driver']['binary_sha256'] == pair[1]['strict_driver']['binary_sha256']) else 'FAIL'
        need(all(v == 'PASS' for v in report['reproducibility'].values()), 'within-variant artifact bytes differ')
        report['status'] = 'PASS'
    except (Cancelled, KeyboardInterrupt, OSError, ValueError, KeyError, subprocess.SubprocessError):
        report['error'] = 'trial failed; review bounded command, output and correctness records'
    finally:
        cancelled = []
        for sig in previous:
            signal.signal(sig, lambda signum, _: cancelled.append(signum))
        try:
            report['cleanup'] = 'PASS' if runner.stop() else 'FAIL'
            if report['cleanup'] != 'PASS' or cancelled:
                report['status'] = 'FAIL'
            if cancelled:
                report['cancelled'] = True
            save(out / 'result.json', report)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    late_cancellation(report, cancelled, out / 'result.json')
    return 0 if report['status'] == 'PASS' else 1


def host(args):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid(),
         'native ARM ordinary nonroot controller required')
    need(not any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION')),
         'Docker endpoint/API overrides refused')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image or '') and re.fullmatch(r'[0-9a-f]{40}', args.source_commit or ''), 'immutable image/accepted commit required')
    for path, pin in ((args.source, SOURCE_SHA), (args.expected_packages, args.expected_packages_sha256)):
        regular(path, 8 * 1024**2)
        need(PIN.fullmatch(pin or '') and sha(path) == pin, 'reviewed input hash differs')
    inventory(args.expected_packages.read_bytes())
    need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(), 'new absolute evidence output required')
    need(not any(c in str(args.output) for c in ',\n\r') and '..' not in args.output.parts, 'unsafe Docker mount output path')
    need(not any(p.is_symlink() for p in args.output.parents), 'output parent symlink refused')
    args.output.mkdir(mode=0o700)
    out = args.output; runner = Commands(out)
    report = {'purpose': PURPOSE, 'status': 'FAIL', 'hardware_validation': 'NOT RUN', 'performance_acceptance': 'NOT RUN', 'selected_for_release': False}
    name = None
    previous = {sig: signal.signal(sig, runner.cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        context = json.loads(runner.run('context', ['docker', 'context', 'inspect']))
        endpoint = context[0]['Endpoints']['docker']['Host']
        need(endpoint in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock', f'unix:///run/user/{os.getuid()}/docker.sock'), 'local Docker daemon required')
        docker = ['docker', '--host=' + endpoint]
        daemon = json.loads(runner.run('daemon', docker + ['info', '--format', '{{json .}}']))
        need(daemon['Architecture'] in ('aarch64', 'arm64') and daemon['OSType'] == 'linux', 'native Linux ARM daemon required')
        image = json.loads(runner.run('image', docker + ['image', 'inspect', args.image]))[0]
        need(image['Id'] == args.image and image['Architecture'] == 'arm64' and not image['Config'].get('Volumes'), 'exact ARM image/no implicit volumes required')
        inputs = out / 'inputs'; inputs.mkdir(mode=0o700)
        for source, filename in ((args.source, 'zlib.tar.gz'), (args.expected_packages, 'packages.lock'), (Path(__file__).resolve(), 'arm_c01.py'), (Path(corpus.__file__).resolve(), 'corpus.py')):
            regular(source, 8 * 1024**2); shutil.copyfile(source, inputs / filename)
        need(sha(inputs / 'zlib.tar.gz') == SOURCE_SHA and sha(inputs / 'packages.lock') == args.expected_packages_sha256,
             'reviewed input changed during snapshot')
        if profile_adapter():
            regular(Path(profile_adapter().__file__).resolve(), 8 * 1024**2)
            shutil.copyfile(profile_adapter().__file__, inputs / 'pgo.py')
        nonce = os.urandom(16).hex(); name = container_prefix() + nonce
        contract = {'purpose': PURPOSE, 'nonce': nonce, 'image': args.image, 'source_commit': args.source_commit,
                    'source_sha256': SOURCE_SHA, 'packages_sha256': args.expected_packages_sha256,
                    'runner_sha256': sha(inputs / 'arm_c01.py'), 'corpus_sha256': sha(inputs / 'corpus.py')}
        if profile_adapter():
            contract['pgo_sha256'] = sha(inputs / 'pgo.py')
        save(inputs / 'contract.json', contract)
        raw = out / 'raw'; raw.mkdir(mode=0o700)
        command = docker + ['run', '--name', name, '--pull=never', '--platform=linux/arm64',
                   '--cgroupns=private',
                   '--user', f'{os.getuid()}:{os.getgid()}', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--read-only', '--pids-limit=256', '--memory=4g', '--cpus=2',
                   '--tmpfs', f'/tmp:rw,nosuid,nodev,exec,size=2g,mode=0700,uid={os.getuid()},gid={os.getgid()}',
                   '--mount', f'type=bind,src={inputs},dst=/inputs,readonly', '--mount', f'type=bind,src={raw},dst=/out',
                   '--env', 'HOME=/tmp/home', '--env', f'{MARKER}={nonce}',
                   '--env', f'{MARKER}_CONTRACT={sha(inputs / "contract.json")}',
                   '--entrypoint=/usr/bin/python3', args.image, '-B', '/inputs/arm_c01.py', '--inside']
        if EXPERIMENT != 'ARM-C01':
            command += ['--experiment', EXPERIMENT]
        report.update(contract=contract, command=command, image=image['Id'], daemon_arch=daemon['Architecture'])
        runner.run('container', command, timeout=1100 if EXPERIMENT == 'ARM-C03' else 800)
        verified = verify_result(raw, contract, inputs / 'packages.lock', inputs / 'zlib.tar.gz')
        report['receiver_verification'] = verified['receiver_verification']
        report['status'] = 'PASS'
    except (Cancelled, KeyboardInterrupt, OSError, ValueError, KeyError, subprocess.SubprocessError):
        report['error'] = 'native trial failed; review retained command and container records'
    finally:
        cancelled = []
        for sig in previous:
            signal.signal(sig, lambda signum, _: cancelled.append(signum))
        try:
            report['controller_group_cleanup'] = 'PASS' if runner.stop() else 'FAIL'
            if name:
                try:
                    removed = subprocess.run(docker + ['rm', '-f', name], stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL, timeout=20)
                    report['container_removal_exit'] = removed.returncode
                    report['container_cleanup'] = 'PASS' if removed.returncode == 0 else 'FAIL'
                except (OSError, subprocess.SubprocessError):
                    report['container_cleanup'] = 'FAIL'
            else:
                report['container_cleanup'] = 'NOT CREATED'
            if report['controller_group_cleanup'] != 'PASS' or report['container_cleanup'] == 'FAIL' or cancelled:
                report['status'] = 'FAIL'
            if cancelled:
                report['cancelled'] = True
            save(out / 'result.json', report)
            print(json.dumps({'result_file': 'result.json', 'purpose': PURPOSE, 'hardware_validation': 'NOT RUN'}))
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    late_cancellation(report, cancelled, out / 'result.json')
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment', choices=tuple(EXPERIMENTS), default='ARM-C01')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--image'); parser.add_argument('--source', type=Path)
    parser.add_argument('--source-commit'); parser.add_argument('--expected-packages', type=Path)
    parser.add_argument('--expected-packages-sha256'); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    select_experiment(args.experiment)
    try:
        if args.inside:
            return inside()
        need(args.source and args.expected_packages and args.output, 'explicit reviewed source/packages/new output required')
        code = host(args)
        receipt = json.loads((args.output / 'result.json').read_text())
        return code if receipt['status'] == 'PASS' else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(EXPERIMENT + ' refused; native reviewed disposable inputs required', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
