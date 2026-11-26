#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One installed updater transaction in a separately admitted offline guest."""

from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import time

INPUT = Path('/updater-input')
CLIENT = Path('/updater-code/client.py')
CLIENT_SHA = '48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7'
TRUST = Path('/updater-trust')
WORK = Path('/updater16k')
DB = Path('/var/lib/pacman/local')
NAME = 'cachy-asahi-check-fixture'
OLD, NEW = '0.1.0-1', '0.1.1-1'
OLD_ARCHIVE = f'{NAME}-{OLD}-any.pkg.tar.gz'
PAYLOAD = Path('/usr/share') / NAME / 'value'
UPDATER = '44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc'
Q3_LOCK = 'e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9'
REPO = ('fixture.db', 'fixture.db.sig', f'{NAME}-{NEW}-any.pkg.tar.gz',
        f'{NAME}-{NEW}-any.pkg.tar.gz.sig')
PKGINFO = {
    OLD: 'ee9816e45a9157fb3bbb375f23c4633469fbf2abe43d947c8aaeead288ce77d7',
    NEW: '25aaa306aac45d9925ebac8fe8dab3c25d8fad9bd2e1e79fe5544940a8d17ab6',
}
POLICIES = {'policy.json', 'pre.json', 'post.json', 'protected-policy.json', 'protected-pre.json'}
FILES = {'q3.lock', 'before.lock', 'updater.pkg', 'updater.pkg.sig', OLD_ARCHIVE, OLD_ARCHIVE + '.sig', 'hooks.list',
         *POLICIES, *(f'repo/{name}' for name in REPO)}
SHA = re.compile('[0-9a-f]{64}')
FINGERPRINT = re.compile('[0-9A-F]{40}')
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
PACMAN = ('/usr/bin/pacman', '--config', str(WORK / 'pacman.conf'))
UPGRADE = (*PACMAN, '--noconfirm', '--color', 'never', '-Syu')
SUDOERS = ('Defaults env_reset\nalarm ALL=(root) NOPASSWD: ' + ' '.join(UPGRADE) + '\n').encode()
OPTIONS = 'NoAUR\nNoFlatpak\nNoNotification\nNoALHPCheck\nNoColor\nPrivilegeElevationCommand=sudo\n'
SUPPLEMENTS = {
    'archlinux-contrib': '20261009-1', 'htmlq': '0.4.0-3', 'pacman-contrib': '1.13.1-1',
    'pyalpm': '0.12.0-1', 'xdg-utils': '1.2.1-2', 'cachy-asahi-update': '4.4.2-3',
    NAME: OLD,
}
SERVICES = ('checkservices -F -P -R -i gdm.service -i plasmalogin.service -i sddm.service '
            '-i lightdm.service -i lxdm.service -i slim.service -i xdm.service -i greetd.service '
            '-i nodm.service -i ly.service -i lemurs.service')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit):
    need(path.resolve(strict=True) == path, 'ordinary input path required')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
             'bounded regular input required')
        data = stream.read(limit + 1)
        need(len(data) == info.st_size, 'input size changed')
        return data


def boot_pin(uid, machine, pages, network, cmdline, readonly_inputs, model):
    need(uid == 0 and machine == 'aarch64' and pages == 16384 and network == {'lo'}
         and readonly_inputs and model == b'linux,dummy-virt\0', 'offline AArch64 16 KiB guest required')
    pins = [arg.split('=', 1)[1] for arg in cmdline.split() if arg.startswith('cachy_updater16k=')]
    need(len(pins) == 1 and SHA.fullmatch(pins[0]), 'boot admission pin required')
    return pins[0]


def plan(pin, now):
    raw = read(INPUT / 'plan.json', 16384)
    need(digest(raw) == pin, 'boot plan digest differs')
    data = json.loads(raw)
    need(set(data) == {'kind', 'valid_from', 'expires', 'signer', 'files'}
         and data['kind'] == 'cachy-asahi-updater16k-disposable-v1'
         and type(data['valid_from']) is type(data['expires']) is int
         and type(data['signer']) is str and FINGERPRINT.fullmatch(data['signer'])
         and data['valid_from'] <= now < data['expires']
         and data['expires'] - data['valid_from'] <= 86400, 'invalid or expired trial plan')
    files = data['files']
    need(type(files) is dict and files.keys() == FILES and files['updater.pkg'] == UPDATER
         and files['q3.lock'] == Q3_LOCK, 'exact media selection required')
    need({p.name for p in (INPUT / 'repo').iterdir()} == set(REPO), 'fixture-only repository required')
    for name, sha in files.items():
        limit = 64 << 20 if name == 'updater.pkg' else 1 << 20
        need(type(sha) is str and SHA.fullmatch(sha) and digest(read(INPUT / name, limit)) == sha,
             'media digest differs')
    need(INPUT.stat().st_mode & 0o001
         and all((INPUT / name).stat().st_mode & 0o004 for name in POLICIES),
         'ordinary guest user must be able to read policy media')
    verify_fixture_archive(read(INPUT / OLD_ARCHIVE, 1 << 20), OLD)
    verify_fixture_archive(read(INPUT / 'repo' / REPO[2], 1 << 20), NEW)
    return files, data['signer']


def inventory(data):
    rows = data.decode('ascii').splitlines()
    need(rows == sorted(rows) and all(re.fullmatch(r'[a-z0-9][a-z0-9+_.-]* [!-~]+', row)
                                     for row in rows), 'invalid inventory lock')
    packages = dict(row.split(' ') for row in rows)
    need(len(rows) == len(packages), 'duplicate package')
    return packages


def expected_inventories(q3, before):
    base, old = inventory(q3), inventory(before)
    need(len(base) == 356 and all(old.get(name) == version for name, version in base.items())
         and old.keys() == base.keys() | SUPPLEMENTS.keys() | {'sudo'}
         and all(old.get(name) == version for name, version in SUPPLEMENTS.items()),
         'Q3 and exact runtime closure required')
    return old, old | {NAME: NEW}


def sudo_boundary(uid, mode, mount_flags, policy):
    need(uid == 0 and stat.S_ISREG(mode) and mode & stat.S_ISUID
         and not mode & 0o022 and not mount_flags & os.ST_NOSUID and policy == SUDOERS,
         'scoped guest sudo boundary required')


def run(argv, *, env=ENV, uid=None, input_text=None):
    user = {'user': uid, 'group': uid, 'extra_groups': []} if uid is not None else {}
    result = subprocess.run(argv, env=env, input=input_text, text=True, capture_output=True,
                            timeout=180, **user)
    need(len(result.stdout) + len(result.stderr) <= 262144, 'command output limit exceeded')
    return result


def checked(argv, **kwargs):
    result = run(argv, **kwargs)
    need(result.returncode == 0, 'guest command failed')
    return result.stdout


def local_db(*, skip_fixture=False):
    paths = sorted([DB / 'ALPM_DB_VERSION', *DB.glob('*/*')])
    need(0 < len(paths) <= 4096, 'local database scope differs')
    return {str(p.relative_to(DB)): digest(read(p, 4 << 20)) for p in paths
            if not (skip_fixture and p.parent.name in {f'{NAME}-{OLD}', f'{NAME}-{NEW}'})}


def actual_inventory():
    return inventory(('\n'.join(sorted(checked((*PACMAN, '-Q')).splitlines())) + '\n').encode())


def fixture_payload(version):
    return f'inert Check fixture {version}\n'.encode()


def verify_fixture_archive(data, version):
    # These are the exact two members from the existing Check fixture writer.
    members = {'.PKGINFO': PKGINFO[version], str(PAYLOAD).lstrip('/'): digest(fixture_payload(version))}
    found = {}
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        raw = compressed.read(tarfile.RECORDSIZE + 1)
    need(len(raw) == tarfile.RECORDSIZE, 'unexpected fixture archive size')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            need(member.name in members and member.type == tarfile.REGTYPE
                 and not member.pax_headers and not archive.pax_headers and member.mode == 0o644
                 and member.uid == member.gid == 0 and 0 < member.size <= 4096,
                 'unexpected fixture archive member')
            with archive.extractfile(member) as stream:
                body = stream.read(4097)
                need(digest(body) == members[member.name] and member.name not in found,
                     'fixture member bytes differ')
                found[member.name] = body
    need(found.keys() == members.keys(), 'incomplete fixture archive')
    canonical = io.BytesIO()
    with tarfile.open(fileobj=canonical, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in members:
            member = tarfile.TarInfo(name)
            member.mode, member.mtime, member.size = 0o644, 1, len(found[name])
            archive.addfile(member, io.BytesIO(found[name]))
    need(raw == canonical.getvalue(), 'fixture archive differs from the inert format')


def prepare_config():
    names = read(INPUT / 'hooks.list', 8192).decode('ascii').splitlines()
    installed = {p.name for base in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks')
                 for p in Path(base).glob('*.hook')}
    need(len(set(names)) == len(names) <= 128 and set(names) == installed and all(
        re.fullmatch(r'[a-zA-Z0-9_.@+-]+\.hook', name) for name in names), 'complete hook mask required')
    (WORK / 'hooks').mkdir()
    for name in names:
        (WORK / 'hooks' / name).symlink_to('/dev/null')
    (WORK / 'cache').mkdir(mode=0o700)
    (WORK / 'pacman.conf').write_text(
        '[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
        f'LocalFileSigLevel = Required TrustedOnly\nGPGDir = {TRUST}\n'
        f'CacheDir = {WORK}/cache\nLogFile = {WORK}/alpm.log\nHookDir = {WORK}/hooks\n'
        f'[fixture]\nSigLevel = Required TrustedOnly\nServer = file://{INPUT}/repo\n')


def write_shims():
    bins = WORK / 'bin'
    bins.mkdir()
    scripts = {
        'checkupdates': f"printf '%s\\n' '{NAME} {OLD} -> {NEW}'",
        'curl': 'exit 22',
        'paccache': '[[ $# == 1 && ( $1 == -dk3 || $1 == -duk0 ) ]]',
        'pacman': '[[ $# == 1 && $1 == -Qtdq ]] && exit 0\nexit 99',
        'sudo': "printf '%s\\n' \"$*\" >> \"$HOME/sudo.calls\"\n"
                "if [[ $# == 4 && $1 == pacman && $2 == --color && $3 == never && $4 == -Syu ]]; then\n"
                "    [[ \"$HOME\" == /updater16k/update ]] || exit 99\n"
                "    (set -o noclobber; : > \"$HOME/sudo.upgrade\") || exit 99\n"
                f"    exec /usr/bin/sudo -n -- {shlex.join(UPGRADE)}\n"
                "fi\n"
                "if [[ $# == 26 && $1 == checkservices && $2 == -F && $3 == -P && $4 == -R ]]; then exit 0; fi\n"
                "exit 99",
    }
    for name, script in scripts.items():
        path = bins / name
        path.write_text('#!/usr/bin/bash\n' + script + '\n')
        path.chmod(0o755)
    bins.chmod(0o755)
    return bins


def installed_entry(case, files, bins):
    home = WORK / case
    folders = [home / 'config/arch-update', home / 'state/arch-update', home / 'runtime/arch-update']
    for folder in folders:
        folder.mkdir(parents=True, mode=0o700)
    (home / 'runtime').chmod(0o700)
    (folders[0] / 'arch-update.conf').write_text(OPTIONS)
    pending = f'{NAME} {OLD} -> {NEW}\n'.encode()
    for name in ('last_updates_check', 'last_updates_check_packages'):
        (folders[1] / name).write_bytes(pending)
    for path in [home, *home.rglob('*')]:
        os.chown(path, 1000, 1000)
    env = ENV | {'PATH': f'{bins}:/usr/bin:/bin', 'HOME': str(home), 'TERM': 'dumb',
                 'USER': 'alarm', 'LOGNAME': 'alarm', 'XDG_CONFIG_HOME': str(home / 'config'),
                 'XDG_RUNTIME_DIR': str(home / 'runtime'), 'XDG_STATE_HOME': str(home / 'state'),
                 'XDG_DATA_HOME': str(home / 'data'), 'XDG_DATA_DIRS': str(home / 'data'),
                 'ARCH_UPDATE_LIBDIR': '/usr/share/arch-update/lib'}
    if case != 'unconfigured':
        prefix = 'protected-' if case == 'protected' else ''
        for role, name in (('POLICY', prefix+'policy.json'), ('PRE_OBSERVATION', prefix+'pre.json'),
                           ('POST_OBSERVATION', 'post.json')):
            env[f'CACHY_ASAHI_{role}_FILE'] = str(INPUT / name)
            env[f'CACHY_ASAHI_{role}_SHA256'] = files[name]
    result = run(['/usr/bin/arch-update'], env=env, uid=1000, input_text='Y\n\n')
    log = home / 'sudo.calls'
    calls = read(log, 4096).decode().splitlines() if log.exists() else []
    state = [(folders[1] / name).read_bytes() for name in ('last_updates_check', 'last_updates_check_packages')]
    return result.returncode, calls, state


def verify_actions(log):
    actions = re.findall(r'\[ALPM\] (installed|upgraded|reinstalled|downgraded|removed) (.+)$', log, re.M)
    need(actions == [('upgraded', f'{NAME} ({OLD} -> {NEW})')], 'exactly one fixture upgrade required')


def verify_installed_entry():
    archive = str(INPUT / 'updater.pkg')
    entries = checked(('/usr/bin/bsdtar', '-tf', archive)).splitlines()
    libraries = Path('/usr/share/arch-update/lib')
    wanted = {str(libraries / path.name).lstrip('/') for path in libraries.iterdir()}
    wanted |= {'usr/bin/arch-update', 'usr/lib/cachy-asahi-update/asahi-policy'}
    selected = {name.removeprefix('./'): name for name in entries if not name.endswith('/')
                and (name.removeprefix('./').startswith(str(libraries).lstrip('/') + '/')
                     or name.removeprefix('./') in wanted)}
    need(len(wanted) > 2 and selected.keys() == wanted, 'installed updater file set differs')
    for relative, member in selected.items():
        data = checked(('/usr/bin/bsdtar', '-xOf', archive, member)).encode()
        need(data == read(Path('/') / relative, 1 << 20), 'installed updater bytes differ')


def verify_trust(signer, gpg):
    need(TRUST.resolve(strict=True) == TRUST and TRUST.is_dir() and TRUST.stat().st_uid == 0
         and stat.S_IMODE(TRUST.stat().st_mode) == 0o700, 'private guest trust required')
    private_keys = TRUST / 'private-keys-v1.d'
    need(not private_keys.exists() or not any(private_keys.iterdir()), 'public-only guest trust required')
    rows = checked((*gpg, '--with-colons', '--fingerprint', '--list-keys')).splitlines()
    keys = [line.split(':')[9] for line in rows if line.startswith('fpr:')]
    need(keys == [signer], 'exact disposable TEST signer required')


def verify_bootstrap(signer, now):
    source = read(CLIENT, 64 << 10)
    need(digest(source) == CLIENT_SHA, 'pinned detached signature verifier required')
    client = {'__name__': 'updater_detached_client', '__file__': str(CLIENT)}
    exec(compile(source, str(CLIENT), 'exec'), client)
    gpg = ('/usr/bin/gpg', '--batch', '--no-tty', '--no-options', '--homedir', str(TRUST),
           '--no-auto-key-retrieve', '--no-auto-key-import', '--auto-key-locate', 'clear',
           '--disable-dirmngr', '--no-autostart', '--no-auto-check-trustdb', '--lock-never')
    verify_trust(signer, gpg)
    for name in ('updater.pkg', OLD_ARCHIVE):
        result = run((*gpg, '--status-fd', '1', '--verify', '--', str(INPUT / (name + '.sig')), str(INPUT / name)))
        need(result.returncode == 0, 'bootstrap detached signature verification failed')
        try:
            proof = client['signature_status'](result.stdout.encode(), signer,
                                                datetime.fromtimestamp(now, timezone.utc))
        except client['Error'] as error:
            raise ValueError('bootstrap detached signature status refused') from error
        need(proof['signing_fingerprint'] == signer, 'bootstrap signature requires the exact TEST key')

    installed = DB / f'{NAME}-{OLD}'
    files = f"%FILES%\n{str(PAYLOAD).lstrip('/')}\n\n".encode()
    need(read(installed / 'files', 4096) == files and not os.path.lexists(installed / 'install')
         and read(PAYLOAD, 4096) == fixture_payload(OLD), 'installed old fixture paths or payload differ')


def trial(files, results):
    old, new = expected_inventories(read(INPUT / 'q3.lock', 16384), read(INPUT / 'before.lock', 16384))
    verify_installed_entry()
    prepare_config()
    checked(('/usr/bin/sudo', '-n', '-l', '--', *UPGRADE), uid=1000)
    need(run(('/usr/bin/sudo', '-n', '-l', '--', '/usr/bin/pacman', '-R', NAME), uid=1000).returncode != 0,
         'guest sudo admits a removal command')
    preview = checked((*PACMAN, '-Syup', '--print-format', 'UPDATER_SELECTION %n %v %h %l'))
    candidate = f"UPDATER_SELECTION {NAME} {NEW} {files['repo/' + REPO[2]]} file://{INPUT}/repo/{REPO[2]}"
    need([row for row in preview.splitlines() if row.startswith('UPDATER_SELECTION ')]
         == [candidate], 'fixture transaction preview differs')
    need(actual_inventory() == old and read(PAYLOAD, 4096) == fixture_payload(OLD), 'wrong installed baseline')
    state, other = local_db(), local_db(skip_fixture=True)
    bins = write_shims()
    pending = f'{NAME} {OLD} -> {NEW}\n'.encode()
    for case, code in (('unconfigured', 21), ('protected', 22), ('update', 0)):
        observed, calls, record = installed_entry(case, files, bins)
        results[case] = observed
        need(observed == code, 'installed updater exit differs')
        if case != 'update':
            need(not calls and record == [pending, pending] and local_db() == state
                 and actual_inventory() == old and read(PAYLOAD, 4096) == fixture_payload(OLD),
                 'refusal did not preserve the checkpoint')
        else:
            need(calls == ['pacman --color never -Syu', SERVICES]
                 and record == [b'', b''], 'scoped update or state observation differs')
    need(actual_inventory() == new and local_db(skip_fixture=True) == other
         and read(PAYLOAD, 4096) == fixture_payload(NEW), 'fixture upgrade postcondition differs')
    verify_actions(read(WORK / 'alpm.log', 256 << 10).decode())
    checked((*PACMAN, '-Dk'))
    return {'sudo_upgrade_calls': 1, 'alpm_upgrades': 1, 'refusal_checkpoint_preserved': True}


def run_trial(files):
    results = {}
    verified = {}
    passed = removed = timed_out = False
    WORK.mkdir(mode=0o755)
    try:
        WORK.chmod(0o755)
        verified = trial(files, results)
        passed = True
    except subprocess.TimeoutExpired:
        timed_out = True
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    finally:
        installed = None
        if not timed_out:
            installed = [version for version in (OLD, NEW) if (DB / f'{NAME}-{version}').is_dir()]
            try:
                shutil.rmtree(WORK)
                removed = True
            except OSError:
                pass
    return {'status': 'PASS' if passed and removed and installed == [NEW] else 'HOLD', 'case_exits': results,
            'pages': 16384, 'private_state_removed': removed, 'fixture_db_versions': installed,
            'command_timed_out': timed_out, 'guest_disposal': 'REQUIRES_OWNER_RECEIPT', **verified}


def admit_guest():
    pin = boot_pin(os.geteuid(), platform.machine(), os.sysconf('SC_PAGE_SIZE'),
                   {p.name for p in Path('/sys/class/net').iterdir()},
                   Path('/proc/cmdline').read_text(), os.statvfs(INPUT).f_flag & os.ST_RDONLY,
                   Path('/sys/firmware/devicetree/base/model').read_bytes())
    now = int(time.time())
    files, signer = plan(pin, now)
    user = pwd.getpwnam('alarm')
    need(user.pw_uid == user.pw_gid == 1000, 'exact ordinary guest user required')
    info = Path('/usr/bin/sudo').lstat()
    sudoers = Path('/etc/sudoers')
    rule_info = sudoers.lstat()
    need(rule_info.st_uid == 0 and stat.S_IMODE(rule_info.st_mode) == 0o440,
         'root-owned sudoers rule required')
    sudo_boundary(info.st_uid, info.st_mode, os.statvfs('/usr/bin/sudo').f_flag,
                  read(sudoers, 4096))
    return files, signer, now


def main():
    files, signer, now = admit_guest()
    verify_bootstrap(signer, now)
    receipt = run_trial(files)
    print(json.dumps(receipt, sort_keys=True))
    return int(receipt['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
