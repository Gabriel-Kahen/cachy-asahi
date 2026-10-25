#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview/enroll/disable one operator-selected repository; never fetch or install."""
import argparse
from contextlib import contextmanager
import glob
import fnmatch
import itertools
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

REPO = 'cachy-asahi'
INCLUDE = '/etc/pacman.d/cachy-asahi.conf'
BLOCK = ('\n# BEGIN cachy-asahi repository enrollment v1\nInclude = ' + INCLUDE +
         '\n# END cachy-asahi repository enrollment v1\n').encode()
HEADER = '# Managed by cachy-asahi repository enrollment v1\n'
SIGLEVEL = 'PackageRequired DatabaseRequired TrustedOnly'
HEX = re.compile(r'[0-9a-f]{64}\Z')
FPR = re.compile(r'(?:[0-9A-F]{40}|[0-9A-F]{64})\Z')


class Error(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Error(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot_url(value):
    parsed = urlsplit(value)
    need(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password and
         not parsed.query and not parsed.fragment and parsed.netloc == parsed.hostname and
         re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', parsed.hostname), 'canonical HTTPS hostname required; no credentials/port/query/fragment')
    need(re.fullmatch(r'(?:/[A-Za-z0-9_-]+)*/generations/[0-9a-f]{64}/release/repo', parsed.path),
         'use an explicit generations/<64 lowercase hex>/release/repo location')
    return value


def identity(row):
    return tuple(getattr(row, 'st_' + name) for name in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns'))


def canonical(value):
    path = Path(value)
    need(path.is_absolute() and str(path) == str(value) and '..' not in path.parts and
         not str(path).startswith('//') and not any(char in str(path) for char in '\n\r\0'), 'canonical absolute path required')
    need(all(stat.S_ISDIR(parent.lstat().st_mode) for parent in path.parents), 'directory aliases/symlinks refused')
    return path


def directory(path, owner):
    row = path.lstat()
    need(stat.S_ISDIR(row.st_mode) and row.st_uid == owner and not row.st_mode & 0o022, 'unsafe directory ownership/mode: ' + str(path))


def parents(path, root, owner):
    canonical(str(path))
    need(path.is_relative_to(root), 'path escapes selected root')
    directory(root, owner)
    current = root
    for part in path.parent.relative_to(root).parts:
        current /= part
        directory(current, owner)


def read(path, owner, optional=False):
    try:
        before = path.lstat()
    except FileNotFoundError:
        need(optional, 'required file missing: ' + str(path))
        return None
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == owner and
         not before.st_mode & 0o022 and before.st_size <= 4 * 1024**2, 'unsafe file ownership/type/mode: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        need(identity(os.fstat(fd)) == identity(before), 'file changed while opening')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(4 * 1024**2 + 1)
        need(len(data) == before.st_size and identity(os.fstat(fd)) == identity(before) == identity(path.lstat()), 'file changed while reading')
    finally:
        os.close(fd)
    return data, identity(before)


def config(url, fingerprint, key_sha256):
    return (HEADER + '# fingerprint: ' + fingerprint + '\n# key-sha256: ' + key_sha256 +
            '\n[' + REPO + ']\nSigLevel = ' + SIGLEVEL + '\nServer = ' + url + '\n').encode()


def managed(raw):
    if raw is None:
        return None
    lines = raw.decode('utf-8').splitlines()
    need(len(lines) == 6 and lines[0] + '\n' == HEADER and lines[1].startswith('# fingerprint: ') and
         lines[2].startswith('# key-sha256: ') and lines[5].startswith('Server = '), 'unknown/edited managed include; preserve it for manual resolution')
    fingerprint, key_sha256, url = lines[1][15:], lines[2][14:], lines[5][9:]
    need(FPR.fullmatch(fingerprint) and HEX.fullmatch(key_sha256), 'invalid managed key description')
    snapshot_url(url)
    need(raw == config(url, fingerprint, key_sha256), 'managed include differs from strict signature configuration')
    return {'url': url, 'fingerprint': fingerprint, 'key_sha256': key_sha256}


def state(root, action):
    root = canonical(str(root))
    owner = root.lstat().st_uid
    directory(root, owner)
    main, include = root / 'etc/pacman.conf', root / INCLUDE.lstrip('/')
    for path in (main, include):
        parents(path, root, owner)
    main_data, main_id = read(main, owner)
    included = read(include, owner, optional=True)
    info = managed(included[0] if included else None)
    need(main_data.count(BLOCK) <= 1, 'duplicate managed block')
    enabled = BLOCK in main_data
    without = main_data.replace(BLOCK, b'')
    need(b'cachy-asahi repository enrollment' not in without, 'unknown/edited managed block; preserve it for manual resolution')
    need(not enabled or included is not None, 'managed block selects a missing include; manual repair required')
    observed = {main: (main_data, main_id), include: included}
    section, visits, options, project, total = '', 0, 0, 0, 0
    def scan(path, stack=()):
        nonlocal section, visits, options, project, total
        visits += 1
        need(visits <= 256 and path not in stack, 'include graph bound/cycle')
        parents(path, root, owner)
        value = read(path, owner)
        total += len(value[0])
        need(total <= 16 * 1024**2, 'configuration byte bound')
        need(path not in observed or observed[path] == value, 'configuration changed during inspection')
        observed[path] = value
        for raw_line in value[0].decode('utf-8').splitlines():
            line = raw_line.split('#', 1)[0].strip()
            if not line:
                continue
            if line.startswith('['):
                match = re.fullmatch(r'\[([A-Za-z0-9@._+-]+)\]', line)
                need(match, 'malformed pacman section')
                section = match[1]
                if section == 'options': options += 1
                if section == REPO:
                    project += 1
                    need(path == include and enabled, 'unowned project repository section')
                continue
            need(section, 'incomplete pacman configuration: no section')
            key, sep, val = line.partition('=')
            key, val = key.strip(), val.strip()
            if key == 'Include':
                need(sep and val.startswith('/') and '$' not in val and '..' not in Path(val).parts,
                     'only absolute, non-variable Include paths are supported')
                logical = INCLUDE
                pattern = str(root / val.lstrip('/'))
                if fnmatch.fnmatch(logical, val):
                    need(path == main and val == INCLUDE and enabled, 'unowned/glob selection of managed include')
                matches = sorted(Path(item) for item in glob.glob(pattern))
                need(matches and len(matches) <= 256, 'missing/oversized Include match')
                for child in matches: scan(child, (*stack, path))
            elif section == REPO:
                need(path == include, 'project configuration outside owned include')
            elif section == 'options' and key == 'GPGDir' and action == 'enroll':
                need(val.rstrip('/') == '/etc/pacman.d/gnupg', 'custom GPGDir requires a separate supported integration')
    scan(main)
    need(options == 1 and project == int(enabled), 'incomplete/duplicate options or repository selection')
    return {'root': root, 'owner': owner, 'main': main, 'include': include, 'observed': observed,
            'main_bytes': main_data, 'enabled': enabled, 'managed': info}


def stable(selection, ignore=()):
    for path, value in selection['observed'].items():
        parents(path, selection['root'], selection['owner']) if path.is_relative_to(selection['root']) else canonical(str(path))
        if path not in ignore:
            need(read(path, selection['owner'], optional=value is None) == value, 'input changed since inspection: ' + str(path))


def run(argv, home):
    result = subprocess.run(argv, env={'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LANG': 'C.UTF-8'},
                            capture_output=True, timeout=45)
    need(len(result.stdout) + len(result.stderr) <= 8 * 1024**2, 'command output bound')
    need(result.returncode == 0, Path(argv[0]).name + ' failed: ' + result.stderr.decode(errors='replace')[-1000:])
    return result.stdout.decode('utf-8')


def inspect_key(path, fingerprint, home):
    text = run(['/usr/bin/gpg', '--no-options', '--homedir', str(home), '--batch', '--no-autostart',
                '--auto-key-locate', 'clear', '--no-auto-key-retrieve', '--with-colons', '--fingerprint',
                '--import-options', 'show-only', '--dry-run', '--import', str(path)], home)
    rows = [line.split(':') for line in text.splitlines()]
    need(not any(row[0] in ('sec', 'ssb') for row in rows), 'public certificate only; secret material refused')
    primaries = [i for i, row in enumerate(rows) if row[0] == 'pub']
    need(len(primaries) == 1, 'exactly one public primary certificate required')
    index = primaries[0]
    need(index + 1 < len(rows) and rows[index + 1][0] == 'fpr' and rows[index + 1][9] == fingerprint,
         'public primary fingerprint differs from independently authenticated expected value')
    usable = lambda row: row[1] not in ('r', 'e', 'd') and (not row[6] or int(row[6]) > time.time())
    need(usable(rows[index]) and any(row[0] in ('pub', 'sub') and usable(row) and 's' in row[11].lower() for row in rows),
         'revoked/expired/disabled certificate or no usable signing key')


def trusted(ring, fingerprint, home):
    try:
        text = run(['/usr/bin/gpg', '--no-options', '--homedir', str(ring), '--batch', '--no-autostart',
                    '--auto-key-locate', 'clear', '--no-auto-key-retrieve', '--no-auto-check-trustdb', '--lock-never',
                    '--with-colons', '--fingerprint', '--list-keys', fingerprint], home)
    except Error:
        return False
    rows = [line.split(':') for line in text.splitlines()]
    for index, row in enumerate(rows):
        if row[0] == 'pub':
            return row[1] in ('f', 'u') and (not row[6] or int(row[6]) > time.time()) and rows[index + 1][9] == fingerprint
    return False


def keyring_safe(ring, owner):
    count = 0
    for path in itertools.chain((ring,), ring.rglob('*')):
        count += 1
        need(count <= 4096, 'keyring member bound')
        row = path.lstat()
        need(row.st_uid == owner and not row.st_mode & 0o022 and
             (stat.S_ISDIR(row.st_mode) or stat.S_ISREG(row.st_mode) and row.st_nlink == 1 or
              stat.S_ISSOCK(row.st_mode) and path.parent == ring and path.name in
              {'S.gpg-agent', 'S.gpg-agent.extra', 'S.gpg-agent.browser', 'S.gpg-agent.ssh',
               'S.scdaemon', 'S.dirmngr', 'S.keyboxd'}),
             'unsafe keyring member: ' + str(path))


def sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def replace(path, data, before, owner):
    need(read(path, owner, optional=before is None) == before, 'configuration changed before atomic edit')
    fd, temporary = tempfile.mkstemp(prefix='.cachy-asahi-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            if before:
                os.fchown(stream.fileno(), before[1][3], before[1][4])
            os.fchmod(stream.fileno(), stat.S_IMODE(before[1][2]) if before else 0o644)
            os.fsync(stream.fileno())
        need(read(path, owner, optional=before is None) == before, 'configuration changed before replacement')
        os.replace(temporary, path)
        sync(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def lock(selection):
    path = selection['root'] / 'var/lib/pacman/db.lck'
    parents(path, selection['root'], selection['owner'])
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    initial = os.fstat(fd)
    try:
        os.write(fd, (str(os.getpid()) + '\n').encode())
        yield
    finally:
        os.close(fd)
        row = path.lstat()
        need((row.st_dev, row.st_ino) == (initial.st_dev, initial.st_ino), 'transaction lock replaced; preserved foreign lock')
        path.unlink()


def execute(root, action, url=None, key=None, fingerprint=None, apply=False):
    need(action in ('enroll', 'disable'), 'unknown enrollment operation')
    selection = state(root, action)
    report = {'status': 'preview', 'operation': action, 'config_changed': False, 'config_may_have_changed': False,
              'keyring_may_have_changed': False,
              'keys_removed': False, 'packages_installed': False, 'network_used': False, 'production_accepted': False}
    changed = []
    try:
        with tempfile.TemporaryDirectory(prefix='cachy-asahi-enroll-') as temporary:
            home = Path(temporary)
            if action == 'enroll':
                snapshot_url(url)
                need(isinstance(fingerprint, str) and FPR.fullmatch(fingerprint), 'full uppercase primary fingerprint required')
                key = canonical(str(key))
                parents(key, selection['root'], selection['owner'])
                need(not key.is_relative_to(selection['root'] / 'etc/pacman.d/gnupg'),
                     'provide a separate public certificate export, not a live keyring file')
                public = read(key, selection['owner'])
                selection['observed'][key] = public
                copied = home / 'public.gpg'; copied.write_bytes(public[0]); copied.chmod(0o400)
                inspect_key(copied, fingerprint, home)
                desired = config(url, fingerprint, sha(public[0]))
                previous = selection['managed']
                need(previous is None or (previous['fingerprint'], previous['key_sha256']) == (fingerprint, sha(public[0])),
                     'key/certificate changes require separately reviewed rotation; disable first')
                ring = selection['root'] / 'etc/pacman.d/gnupg'
                parents(ring / 'trustdb.gpg', selection['root'], selection['owner'])
                keyring_safe(ring, selection['owner'])
                need((ring / 'trustdb.gpg').is_file() and (ring / 'trustdb.gpg').stat().st_size > 0 and
                     any((ring / name).is_file() and (ring / name).stat().st_size > 0 for name in ('pubring.gpg', 'pubring.kbx')),
                     'existing initialized pacman keyring required')
                report.update(snapshot_url=url, fingerprint=fingerprint, key_sha256=sha(public[0]), managed_include=desired.decode(),
                              currently_enabled=selection['enabled'])
            else:
                desired = None
                report.update(currently_enabled=selection['enabled'], public_trust_retained=True)
            if not apply:
                stable(selection)
                return report
            need(os.geteuid() == 0, '--apply requires root; tests may use a disposable user-namespace root')
            with lock(selection):
                stable(selection)
                if action == 'enroll':
                    same = selection['observed'][selection['include']] is not None and selection['observed'][selection['include']][0] == desired
                    if not (same and selection['enabled'] and trusted(ring, fingerprint, home)):
                        report['keyring_may_have_changed'] = True
                        command = ['/usr/bin/pacman-key', '--config', str(selection['main']), '--gpgdir', str(ring)]
                        run(command + ['--add', str(copied)], home)
                        run(command + ['--lsign-key', fingerprint], home)
                        need(trusted(ring, fingerprint, home), 'imported certificate not valid and fully trusted afterward')
                    stable(selection)
                    if not same:
                        report['config_may_have_changed'] = True
                        replace(selection['include'], desired, selection['observed'][selection['include']], selection['owner'])
                        changed.append(selection['include'])
                    stable(selection, changed)
                    if not selection['enabled']:
                        report['config_may_have_changed'] = True
                        replace(selection['main'], selection['main_bytes'] + BLOCK, selection['observed'][selection['main']], selection['owner'])
                        changed.append(selection['main'])
                    report['status'] = 'enabled'
                else:
                    if selection['enabled']:
                        report['config_may_have_changed'] = True
                        replace(selection['main'], selection['main_bytes'].replace(BLOCK, b''), selection['observed'][selection['main']], selection['owner'])
                        changed.append(selection['main'])
                    stable(selection, changed)
                    if selection['managed']:
                        report['config_may_have_changed'] = True
                        need(read(selection['include'], selection['owner']) == selection['observed'][selection['include']], 'managed include changed before removal')
                        selection['include'].unlink(); sync(selection['include'].parent)
                        changed.append(selection['include'])
                    report['status'] = 'disabled'
            report['config_changed'] = bool(changed)
            return report
    except BaseException as error:
        report.update(status='failed', config_changed=bool(changed), error=str(error) or type(error).__name__,
                      recovery='Configuration may be partially changed; rerun the same enroll or disable. Public key import/local signing is never automatically undone.')
        error.enrollment_result = report
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'), help='existing filesystem root; alternate roots are for disposable tests')
    parser.add_argument('--apply', action='store_true', help='change only selected root repository configuration/trust')
    commands = parser.add_subparsers(dest='action', required=True)
    enroll = commands.add_parser('enroll')
    enroll.add_argument('--snapshot-url', required=True)
    enroll.add_argument('--public-key', type=Path, required=True)
    enroll.add_argument('--fingerprint', required=True)
    commands.add_parser('disable')
    args = parser.parse_args(argv)
    try:
        result = execute(args.root, args.action, getattr(args, 'snapshot_url', None), getattr(args, 'public_key', None),
                         getattr(args, 'fingerprint', None), args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Error, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps(getattr(error, 'enrollment_result', {'status': 'failed', 'error': str(error)}), sort_keys=True))
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('interrupted by SIGTERM')))
    sys_exit = main()
    raise SystemExit(sys_exit)
