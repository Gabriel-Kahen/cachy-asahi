#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Fixed disposable-image TEST signing/install/remove operations; never host use."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

WORK = Path('/work')
PUBLIC = WORK / 'public'
CONFIG = '/opt/ui-integration/local-pacman.conf'
GPG = ['gpg', '--homedir', '/signing/key', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
PACKAGES = ('cachy-asahi-first-login-ui', 'cachy-asahi-first-login', 'cachy-asahi-setup')


def call(argv, expected=(0,), timeout=60):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    print(json.dumps({'argv': argv, 'code': result.returncode, 'stdout': result.stdout[-12000:], 'stderr': result.stderr[-6000:]}), flush=True)
    if result.returncode not in expected:
        raise ValueError('disposable owner command failed')
    return result


def pacman(*args, expected=(0,)):
    return call(['pacman', '--config', CONFIG, '--noconfirm', *args], expected)


def payloads():
    return json.loads((PUBLIC / 'payloads.json').read_text())


def verify(rows, absent=False):
    for name, row in rows.items():
        path = Path('/') / name
        if absent:
            if path.exists() or path.is_symlink(): raise ValueError('package path not restored to absent')
            continue
        item = path.lstat()
        if (not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_gid != 0
                or stat.S_IMODE(item.st_mode) != row['mode']
                or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']):
            raise ValueError('installed payload identity mismatch')


def sign(path):
    call([*GPG, '--detach-sign', str(path)])
    call([*GPG, '--verify', str(path) + '.sig', str(path)])


def backend():
    WORK.chmod(0o1777)
    PUBLIC.mkdir(mode=0o755)
    shutil.copyfile('/inputs/payloads.json', PUBLIC / 'payloads.json')
    expected = payloads()
    verify({**expected['first_login'], **expected['setup'], **expected['ui']}, absent=True)
    secret = Path('/signing/key'); secret.mkdir(mode=0o700)
    call([*GPG, '--quick-generate-key', 'Cachy-Asahi UI disposable TEST <ui-test@invalid>', 'rsa2048', 'sign', '1d'])
    listing = call([*GPG, '--with-colons', '--list-keys']).stdout
    fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
    (PUBLIC / 'TEST-fingerprint.txt').write_text(fingerprint + '\n')
    exported = call([*GPG, '--armor', '--export', fingerprint]).stdout
    (PUBLIC / 'TEST-public.asc').write_text(exported)
    call(['pacman-key', '--init'])
    call(['pacman-key', '--add', str(PUBLIC / 'TEST-public.asc')])
    call(['pacman-key', '--lsign-key', fingerprint])
    target = Path('/opt/ui-integration/packages'); target.mkdir()
    profile = json.loads(Path('/inputs/inputs.json').read_text())
    archives = []
    for name in ('setup', 'first_login'):
        archive = target / profile['archives'][name]['name']
        shutil.copyfile(Path('/inputs/materials') / archive.name, archive)
        sign(archive); archives.append(str(archive))
        shutil.copyfile(str(archive) + '.sig', PUBLIC / (archive.name + '.sig'))
    pacman('-U', *archives)
    verify({**expected['first_login'], **expected['setup']})
    call(['gpgconf', '--homedir', '/signing/key', '--kill', 'all'])
    call(['gpgconf', '--homedir', '/etc/pacman.d/gnupg', '--kill', 'all'])
    call(['pacman', '-Qkk', 'cachy-asahi-first-login', 'cachy-asahi-setup'])
    # Actual delivered shell templates are data inputs, not installed packages.
    shutil.copytree('/inputs/templates', '/opt/ui-integration/templates')


def install():
    expected = payloads()
    output = WORK / 'build/output'
    matches = list(output.glob('cachy-asahi-first-login-ui-*.pkg.tar.zst'))
    if len(matches) != 1: raise ValueError('actual UI build archive missing')
    folder = Path('/root/ui-package'); folder.mkdir()
    archive = folder / matches[0].name; shutil.copyfile(matches[0], archive)
    rejected = pacman('-U', str(archive), expected=(1,))
    verify(expected['ui'], absent=True)
    sign(archive)
    pacman('-U', str(archive))
    verify({**expected['first_login'], **expected['setup'], **expected['ui']})
    call(['pacman', '-Qkk', *PACKAGES])
    for package, rows in zip(PACKAGES, (expected['ui'], expected['first_login'], expected['setup'])):
        listing = call(['pacman', '-Qlq', package]).stdout.splitlines()
        observed = {line.lstrip('/') for line in listing if (Path(line).is_file() and not Path(line).is_symlink())}
        if observed != set(rows): raise ValueError('ALPM complete ownership mismatch')
    shutil.copyfile(str(archive) + '.sig', PUBLIC / (archive.name + '.sig'))
    extracted = WORK / 'extracted'; extracted.mkdir(mode=0o755)
    for path in (*Path('/opt/ui-integration/packages').glob('*.pkg.tar.*'), archive):
        if path.name.endswith('.sig'): continue
        call(['bsdtar', '-xpf', str(path), '--no-same-owner', '-C', str(extracted), 'usr'])
    target = WORK / 'lifecycle'; target.mkdir(mode=0o1777); target.chmod(0o1777)
    call(['gpgconf', '--homedir', '/signing/key', '--kill', 'all'])
    call(['gpgconf', '--homedir', '/etc/pacman.d/gnupg', '--kill', 'all'])
    (PUBLIC / 'installed.json').write_text(json.dumps({'unsigned_refused': rejected.returncode,
        'project_packages': list(PACKAGES), 'ordinary_files': sum(len(r) for r in expected.values()),
        'signatures': 'fresh disposable TEST only', 'ownership': 'PASS full24', 'native_ARM': 'NOT RUN'}))


def remove():
    rows = payloads()
    pacman('-R', *PACKAGES)
    verify({**rows['first_login'], **rows['setup'], **rows['ui']}, absent=True)
    baseline = Path('/opt/ui-integration/baseline-packages.txt').read_text()
    restored = call(['pacman', '-Q']).stdout
    if restored != baseline: raise ValueError('base package inventory not restored')
    (PUBLIC / 'removed.json').write_text(json.dumps({'status': 'PASS exact base inventory and 24 owned paths restored',
        'native_ARM': 'NOT RUN', 'M2': 'NOT RUN'}))


if __name__ == '__main__':
    os.umask(0o022)
    if os.geteuid() != 0 or not sys.flags.isolated or not Path(CONFIG).is_file():
        raise SystemExit('Disposable image owner only')
    {'backend': backend, 'install': install, 'remove': remove}[sys.argv[1]]()
