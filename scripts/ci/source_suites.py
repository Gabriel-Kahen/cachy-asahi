#!/usr/bin/env python3
"""Run reviewed source suites inside a disposable native ARM container only."""
import argparse
import importlib.util
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata

sys.dont_write_bytecode = True
UNIT_DIRS = ('tests', 'scripts/hardware', 'scripts/release', 'scripts/benchmarks',
             'scripts/setup', 'scripts/ci', 'scripts/integration')
CHECKS = ('packages/settings/cachy-asahi-setup/test-sync.py',
          'packages/settings/cachy-asahi-setup/check-sync.py',
          'packages/settings/cachy-asahi-setup/check-packaged.py',
          'packages/shells/cachy-asahi-fish-config/check-config.py',
          'packages/shells/cachy-asahi-zsh-config/check-config.py')
STANDARD_TYPES = {
    '/proc': ({'proc'}, {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/sys': ({'sysfs'}, {'ro', 'nosuid', 'nodev', 'noexec'}),
    '/sys/fs/cgroup': ({'cgroup', 'cgroup2'}, {'ro', 'nosuid', 'nodev', 'noexec'}),
    '/dev': ({'tmpfs'}, {'rw', 'nosuid'}),
    '/dev/pts': ({'devpts'}, {'rw', 'nosuid', 'noexec'}),
    '/dev/shm': ({'tmpfs'}, {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/dev/mqueue': ({'mqueue'}, {'rw', 'nosuid', 'nodev', 'noexec'}),
}
READONLY_PROC = set('/proc/bus /proc/fs /proc/irq /proc/sys /proc/sysrq-trigger'.split())
EMPTY_MASKS = set('/proc/acpi /proc/asound /proc/scsi /sys/firmware /sys/devices/virtual/powercap'.split())
NULL_MASKS = set('/proc/interrupts /proc/kcore /proc/keys /proc/latency_stats /proc/timer_list /proc/timer_stats /proc/sched_debug'.split())
RUNTIME_FILES = {'/etc/hostname', '/etc/hosts', '/etc/resolv.conf'}
DATA_FILESYSTEMS = {'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'fuse-overlayfs'}
STANDARD_MOUNTS = set(STANDARD_TYPES) | READONLY_PROC | EMPTY_MASKS | NULL_MASKS | RUNTIME_FILES
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
LOG_LIMIT = 4 * 1024**2
ACTIVE = {}
DESKTOP_LOGS = {f'source-check-{n}.txt' for n in range(1, 6)}
DESKTOP_LOGS |= {f'host-package-{n}{suffix}.txt' for n in (1, 2) for suffix in ('', '-PKGINFO', '-BUILDINFO')}
ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])')


class Cancelled(Exception):
    pass


class StopSuites(Exception):
    pass


def interrupt(_signum, _frame):
    raise Cancelled()


@contextmanager
def defer_cancellation():
    events = []
    previous = {sig: signal.signal(sig, lambda *_: events.append(True)) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield events
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def spawn(command, **options):
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        process = subprocess.Popen(command, **options,
            preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous))
        ACTIVE[process.pid] = process
    finally:
        # A pending cancellation can raise here; its child has already been tracked.
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    return process


def cleanup_groups():
    report = {'status': 'PASS', 'groups': []}
    for pid, process in list(ACTIVE.items()):
        row = {'pid': pid, 'status': 'PASS'}
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(pid, signum)
            except ProcessLookupError:
                pass
            except (OSError, Cancelled, KeyboardInterrupt):
                row['status'] = 'FAIL'
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if signum == signal.SIGKILL:
                    row['status'] = 'FAIL'
            except (OSError, subprocess.SubprocessError, Cancelled, KeyboardInterrupt):
                row['status'] = 'FAIL'
        if row['status'] == 'PASS':
            ACTIVE.pop(pid, None)
        else:
            report['status'] = 'FAIL'
        report['groups'].append(row)
    return report


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def desktop_projection(path, output):
    """Known terminal receipts only: escaped public text, never original bytes.

    The raw digest is provenance, not authentication. Check the same credential
    policy before creating either public file, including terminal-hidden markers.
    """
    if (path.name not in DESKTOP_LOGS or path.is_symlink() or not path.is_file()
            or path.stat().st_nlink != 1 or any(p.is_symlink() for p in path.parents)):
        raise ValueError('unreviewed/nonregular desktop terminal receipt')
    if path.stat().st_size > LOG_LIMIT:
        raise ValueError('desktop terminal receipt exceeds raw byte bound')
    with path.open('rb') as stream:
        data = stream.read(LOG_LIMIT + 1)
    if len(data) > LOG_LIMIT:
        raise ValueError('desktop terminal receipt exceeds raw byte bound')
    # Lazy load from the reviewed read-only CI source snapshot; no path search.
    spec = importlib.util.spec_from_file_location('desktop_export_policy', Path(__file__).with_name('integration_export.py'))
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    text = data.decode('utf-8', errors='surrogateescape')
    screen = ''.join(char for char in ANSI.sub('', text)
                     if char in '\n\r\t' or not (unicodedata.category(char) in ('Cc', 'Cf', 'Cs')))
    if policy.PRIVATE_CONTENT.search(text) or policy.PRIVATE_CONTENT.search(screen):
        raise ValueError('desktop terminal receipt contains private-key/credential marker')
    parts, size = [], 0
    for char in text:
        value = ord(char)
        if char == '\\':
            part = '\\\\'
        elif 0xdc80 <= value <= 0xdcff:
            part = f'\\x{value - 0xdc00:02x}'
        elif (value < 32 and char not in '\n\t') or value == 127:
            part = f'\\x{value:02x}'
        elif unicodedata.category(char) in ('Cc', 'Cf') and char not in '\n\t':
            part = f'\\u{value:04x}' if value <= 0xffff else f'\\U{value:08x}'
        else:
            part = char
        size += len(part.encode('utf-8'))
        if size > LOG_LIMIT:
            raise ValueError('escaped desktop terminal receipt exceeds public byte bound; no truncation')
        parts.append(part)
    projected = ''.join(parts).encode('utf-8')
    target = output / ('desktop-' + path.name)
    metadata = target.with_suffix('.projection.json')
    if target.exists() or target.is_symlink() or metadata.exists() or metadata.is_symlink():
        raise ValueError('fresh desktop projection outputs required')
    with target.open('xb') as stream:
        stream.write(projected)
    save(metadata, {'schema_version': 1, 'record_type': 'desktop-terminal-log-projection',
                    'source_log': path.name, 'raw_sha256': hashlib.sha256(data).hexdigest(), 'raw_bytes': len(data),
                    'projected_sha256': hashlib.sha256(projected).hexdigest(), 'projected_bytes': len(projected),
                    'projection': 'UTF-8; backslashes doubled; C0/DEL/invalid bytes use \\xHH; Unicode controls/formats use \\uHHHH or \\UHHHHHHHH; LF/TAB preserved',
                    'raw_bytes_exported': False})


def private_runtime(home):
    if (not home.is_absolute() or not home.is_relative_to('/tmp') or '..' in home.parts
            or not home.is_dir() or any(p.is_symlink() for p in (home, *home.parents))):
        raise ValueError('runtime directory requires the guarded real tmpfs HOME')
    root = home / 'runtime'
    root.mkdir(mode=0o700, exist_ok=False)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('owned mode0700 runtime directory required')
    return root


def mount_table(text):
    rows = {}
    for line in text.splitlines():
        fields = line.split()
        index = fields.index('-')
        point = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
        if point in rows:
            raise ValueError('duplicate mount point refused')
        rows[point] = {'fs': fields[index + 1], 'options': fields[5].split(',')}
    return rows


def runtime_exposure():
    permitted = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
                 '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0), '/dev/pts/ptmx': (5, 2)}
    devices, sockets = [], []
    for root in ('/dev', '/run', '/source', '/out'):
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
            for name in files:
                path = Path(current) / name
                item = path.lstat()
                if stat.S_ISSOCK(item.st_mode):
                    sockets.append(str(path))
                if stat.S_ISBLK(item.st_mode) or stat.S_ISCHR(item.st_mode):
                    identity = (os.major(item.st_rdev), os.minor(item.st_rdev))
                    pty = re.fullmatch(r'/dev/pts/[0-9]+', str(path)) and stat.S_ISCHR(item.st_mode) and 136 <= identity[0] <= 143
                    if stat.S_ISBLK(item.st_mode) or not (permitted.get(str(path)) == identity or pty):
                        devices.append(str(path))
    devices += [p for p in ('/dev/dri', '/dev/snd', '/dev/input', '/dev/mem', '/dev/kvm', '/dev/fuse') if Path(p).exists()]
    return sorted(set(devices)), sorted(set(sockets))


def environment(source, output):
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    marker = Path('/.dockerenv')
    home = Path(os.environ.get('HOME', '/'))
    safe = all(path.is_dir() and not any(p.is_symlink() for p in (path, *path.parents))
               for path in (source, output))
    devices, sockets = runtime_exposure()
    mounts = mount_table(Path('/proc/self/mountinfo').read_text())
    runtime_files = {p: {'regular': stat.S_ISREG(Path(p).lstat().st_mode), 'uid': Path(p).stat().st_uid,
                        'mode': stat.S_IMODE(Path(p).stat().st_mode)} for p in RUNTIME_FILES}
    null_masks = {p: stat.S_ISCHR(Path(p).lstat().st_mode) and
                 (os.major(Path(p).stat().st_rdev), os.minor(Path(p).stat().st_rdev)) == (1, 3)
                  for p in NULL_MASKS if p in mounts}
    return {'arch': platform.machine(), 'uid': os.geteuid(), 'kernel': platform.uname()._asdict(),
            'docker_marker': marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            'interfaces': sorted(path.name for path in Path('/sys/class/net').iterdir()),
            'sockets': sockets, 'unexpected_devices': devices, 'runtime_files': runtime_files, 'null_masks': null_masks,
            'capabilities': {name: int(status.get(name, '-1').strip(), 16) for name in CAPS},
            'no_new_privs': int(status.get('NoNewPrivs', '0').strip()),
            'mounts': mounts,
            'source': str(source), 'output': str(output), 'paths_safe': safe,
            'home': str(home), 'home_safe': not any(p.is_symlink() for p in (home, *home.parents)),
            'python': sys.version, 'native_build': 'NOT RUN', 'hardware_validation': 'NOT RUN'}


def guard(record):
    if record['arch'] not in ('aarch64', 'arm64') or record['uid'] == 0 or not record['docker_marker']:
        raise ValueError('native ARM non-root Docker container required')
    if record['interfaces'] != ['lo'] or record['sockets'] or record['unexpected_devices']:
        raise ValueError('loopback-only network and no host sockets/devices required')
    if set(record['capabilities']) != set(CAPS) or any(value != 0 for value in record['capabilities'].values()) or record['no_new_privs'] != 1:
        raise ValueError('all capabilities dropped and no-new-privileges required')
    if record['source'] != '/source' or record['output'] != '/out' or not record['paths_safe']:
        raise ValueError('real nonsymlink /source and /out directories required')
    home = Path(record['home'])
    if not home.is_absolute() or '..' in home.parts or not home.is_relative_to('/tmp') or not record['home_safe']:
        raise ValueError('private tmpfs HOME under /tmp required')
    mounts = record['mounts']
    for point, (kinds, flags) in STANDARD_TYPES.items():
        entry = mounts.get(point, {})
        if entry.get('fs') not in kinds or not flags <= set(entry.get('options', [])):
            raise ValueError('standard runtime mount type/options differ')
        if {'ro', 'rw'} <= set(entry['options']):
            raise ValueError('conflicting runtime mount modes')
    if mounts.get('/', {}).get('fs') not in ('overlay', 'fuse-overlayfs') or set(mounts['/']['options']) & {'ro', 'rw'} != {'ro'}:
        raise ValueError('read-only disposable root required')
    for path, mode in (('/source', 'ro'), ('/out', 'rw')):
        if mounts.get(path, {}).get('fs') not in DATA_FILESYSTEMS or set(mounts[path]['options']) & {'ro', 'rw'} != {mode}:
            raise ValueError(f'{path} mount must be {mode}')
    if mounts.get('/tmp', {}).get('fs') != 'tmpfs' or not {'rw', 'nosuid', 'nodev'} <= set(mounts['/tmp']['options']) or {'ro', 'noexec'} & set(mounts['/tmp']['options']):
        raise ValueError('writable private /tmp tmpfs required')
    if set(mounts) - (STANDARD_MOUNTS | {'/', '/source', '/out', '/tmp'}):
        raise ValueError('unexpected mount; host homes and sockets are forbidden')
    for point in READONLY_PROC & set(mounts):
        entry = mounts[point]
        if entry['fs'] != 'proc' or not {'ro', 'nosuid', 'nodev', 'noexec'} <= set(entry['options']) or 'rw' in entry['options']:
            raise ValueError('protected proc mount differs')
    for point in EMPTY_MASKS & set(mounts):
        if mounts[point]['fs'] != 'tmpfs' or 'ro' not in mounts[point]['options'] or 'rw' in mounts[point]['options']:
            raise ValueError('kernel path must use a read-only empty tmpfs mask')
    for point in NULL_MASKS & set(mounts):
        if mounts[point]['fs'] != 'tmpfs' or record['null_masks'].get(point) is not True:
            raise ValueError('kernel path must be masked by the real null device')
    for point in RUNTIME_FILES:
        entry, info = mounts.get(point, {}), record['runtime_files'].get(point, {})
        if entry.get('fs') not in DATA_FILESYSTEMS or set(entry.get('options', [])) & {'ro', 'rw'} not in ({'ro'}, {'rw'}):
            raise ValueError('runtime file mount differs')
        if info.get('regular') is not True or info.get('uid') != 0 or info.get('mode', 0o777) & 0o022:
            raise ValueError('runtime file must be root-owned regular and not writable by other users')


def unittest_counts(text):
    runs = re.findall(r'^Ran (\d+) tests? in [^\n]+$', text, re.M)
    endings = re.findall(r'^(OK|FAILED)(?: \(([^\n]*)\))?$', text, re.M)
    if not runs or not endings:
        raise ValueError('unittest summary missing')
    status, fields = endings[-1]
    skipped = re.search(r'(?:^|, )skipped=(\d+)(?:,|$)', fields)
    return {'tests': int(runs[-1]), 'skipped': int(skipped[1]) if skipped else 0, 'unittest_status': status}


def run_suite(name, command, source, output, env, unit=False, timeout=300):
    log = output / (name + '.log')
    record = {'name': name, 'command': command, 'cwd': str(source), 'status': 'FAIL',
              'tests': None, 'skipped': None, 'timeout_seconds': timeout}
    started = time.monotonic()
    cancelled = False
    try:
        with log.open('xb') as stream:
            process = spawn(command, cwd=source, env=env, stdout=stream,
                            stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record['error'] = 'suite exceeded timeout; cleanup required'
                raise ValueError()
        record['exit_code'] = code
        if log.stat().st_size > LOG_LIMIT:
            record['error'] = 'suite log exceeds 4 MiB'
            raise ValueError()
        text = log.read_text(errors='replace')
        if unit:
            try:
                record.update(unittest_counts(text))
            except ValueError:
                record['error'] = 'unittest summary missing'
                raise
            passed = code == 0 and record['unittest_status'] == 'OK' and record['tests'] > 0 and record['skipped'] == 0
            record['status'] = 'PASS' if passed else ('INCOMPLETE' if code == 0 and record['skipped'] else 'FAIL')
        else:
            record['status'] = 'PASS' if code == 0 else 'FAIL'
    except (Cancelled, KeyboardInterrupt):
        cancelled = True
        record.update(status='FAIL', error='suite cancelled')
    except (OSError, ValueError, subprocess.SubprocessError):
        record.setdefault('error', 'suite command or evidence failed; exception details suppressed')
    finally:
        if isinstance(sys.exc_info()[1], (Cancelled, KeyboardInterrupt)):
            cancelled = True
            record.update(status='FAIL', error='suite cancelled')
        with defer_cancellation() as events:
            record['cleanup'] = cleanup_groups()
            if record['cleanup']['status'] != 'PASS':
                record.update(status='FAIL', error='suite process cleanup failed; exception details suppressed')
            if events:
                cancelled = True
                record.update(status='FAIL', error='suite cancelled during cleanup')
            record['elapsed_seconds'] = round(time.monotonic() - started, 3)
            try:
                if log.is_file():
                    with log.open('rb') as stream:
                        record['log_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            except OSError:
                record.update(status='FAIL', error='suite log could not be hashed')
            # Cleanup failures cannot bypass a sanitized failure receipt.
            save(output / (name + '.json'), record)
            if events:
                cancelled = True
                record.update(status='FAIL', error='suite cancelled during finalization')
                save(output / (name + '.json'), record)
    if cancelled:
        raise Cancelled()
    if record['cleanup']['status'] != 'PASS':
        raise StopSuites()
    return record


def suites(source, output, home, results=None):
    runtime = private_runtime(home)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': '/tmp', 'LANG': 'C.UTF-8',
           'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'TERM': 'dumb',
           'XDG_CONFIG_HOME': str(home / '.config'), 'XDG_CACHE_HOME': str(home / '.cache'),
           'XDG_DATA_HOME': str(home / '.local/share'), 'XDG_RUNTIME_DIR': str(runtime)}
    if results is None:
        results = []
    for directory in UNIT_DIRS:
        results.append(run_suite(directory.replace('/', '-'),
            [sys.executable, '-m', 'unittest', 'discover', '-s', directory, '-p', 'test_*.py', '-v'],
            source, output, env, unit=True))
    for path in CHECKS:
        name = Path(path).parent.name + '-' + Path(path).stem
        results.append(run_suite(name, [sys.executable, str(source / path)], source, output, env,
                                 unit=Path(path).name == 'test-sync.py'))
    # check-local writes beside its source; the reviewed desktop copy lives only in tmpfs.
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-source-desktop-', dir='/tmp') as temporary:
        desktop = Path(temporary) / 'desktop'
        shutil.copytree(source / 'packages/desktop', desktop,
                        ignore=shutil.ignore_patterns('evidence', '__pycache__'))
        try:
            results.append(run_suite('desktop-local', [sys.executable, str(desktop / 'check-local.py')],
                                     desktop, output, env))
        finally:
            for name in sorted({'host-packaging.json', *DESKTOP_LOGS}):
                path = desktop / 'evidence' / name
                if path.exists() or path.is_symlink():
                    if name in DESKTOP_LOGS:
                        desktop_projection(path, output)
                    elif path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 and path.stat().st_size <= LOG_LIMIT:
                        shutil.copyfile(path, output / ('desktop-' + name))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    accepted = False
    result = {'source_suites': 'FAIL', 'native_build': 'NOT RUN', 'installation': 'NOT RUN',
              'hardware_validation': 'NOT RUN', 'suites': []}
    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGTERM, signal.SIGINT)}
    exit_code = 1
    try:
        observed = environment(args.source, args.output)
        guard(observed)
        if any(args.output.iterdir()):
            raise ValueError('source-suite output must be empty')
        accepted = True
        save(args.output / 'environment.json', observed)
        home = Path(observed['home'])
        home.mkdir(parents=True, exist_ok=True)
        suites(args.source, args.output, home, result['suites'])
        result['source_suites'] = 'PASS' if all(row['status'] == 'PASS' for row in result['suites']) else 'FAIL'
        exit_code = 0 if result['source_suites'] == 'PASS' else 1
    except (Cancelled, KeyboardInterrupt):
        result.update(source_suites='FAIL', error='source suites cancelled')
    except StopSuites:
        result.update(source_suites='FAIL', error='source-suite process cleanup failed')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        result.update(source_suites='FAIL', error='source-suite guard, command or evidence failed; exception details suppressed')
    finally:
        with defer_cancellation() as events:
            result['cleanup'] = cleanup_groups()
            if events or result['cleanup']['status'] != 'PASS':
                result.update(source_suites='FAIL', error='source-suite cancellation or process cleanup failed')
                exit_code = 1
            result['tests'] = sum(row['tests'] or 0 for row in result['suites'])
            result['skipped'] = sum(row['skipped'] or 0 for row in result['suites'])
            if accepted:
                try:
                    save(args.output / 'result.json', result)
                    if events:
                        result.update(source_suites='FAIL', error='source suites cancelled during finalization')
                        exit_code = 1
                        save(args.output / 'result.json', result)
                except OSError:
                    exit_code = 1
                    print('source-suite result could not be retained', file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if exit_code:
        print('source suites failed; inspect sanitized result and bounded public logs', file=sys.stderr)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
