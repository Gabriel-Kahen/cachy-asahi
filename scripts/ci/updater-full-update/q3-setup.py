# SPDX-License-Identifier: MIT
"""Install the six pinned additions inside the separately admitted Q3 child."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import runpy
import stat
import time


CODE = Path('/updater-code')
INPUT = Path('/updater-input')
BOOTSTRAP = Path('/run/updater-bootstrap')
OFFICIAL = '68B3537F39A313B3E574D06777193F152BDBE6A6'
BEFORE_SHA = '7a5779caafed704a109debcf207b040e32565b5102c889809eb33d9bbbe8680b'


def gpg(home):
    return ('/usr/bin/gpg', '--batch', '--no-tty', '--no-options', '--homedir', str(home),
            '--no-auto-key-retrieve', '--no-auto-key-import', '--auto-key-locate', 'clear',
            '--disable-dirmngr', '--no-autostart', '--no-auto-check-trustdb', '--lock-never')


def selected_test_key(text, signer, now):
    records = [line.split(':') for line in text.splitlines()]
    if any(len(row) < 10 for row in records if row[0] in {'pub', 'uid', 'fpr'}):
        return False
    primary = [row for row in records if row[0] == 'pub']
    uids = [row for row in records if row[0] == 'uid']
    if (len(primary) != 1 or len(uids) != 1 or 'TEST' not in uids[0][9]
            or any(row[0] in {'sec', 'ssb', 'sub'} for row in records)
            or [row[9] for row in records if row[0] == 'fpr'] != [signer]):
        return False
    pub = primary[0]
    if pub[1] in {'e', 'r', 'd', 'i'} or not pub[5].isdecimal() or not pub[6].isdecimal():
        return False
    created, expires = int(pub[5]), int(pub[6])
    return 0 < created <= now < expires and expires - created <= 86400


def main():
    guest = runpy.run_path(str(CODE / 'guest.py'))
    need, read, digest, checked = (guest[key] for key in ('need', 'read', 'digest', 'checked'))
    cmdline = Path('/proc/cmdline').read_text()
    pin = guest['boot_pin'](os.geteuid(), os.uname().machine, os.sysconf('SC_PAGE_SIZE'),
                            {p.name for p in Path('/sys/class/net').iterdir()},
                            cmdline, os.statvfs(INPUT).f_flag & os.ST_RDONLY,
                            Path('/sys/firmware/devicetree/base/model').read_bytes())
    need(os.statvfs(CODE).f_flag & os.ST_RDONLY, 'read-only updater code required')
    now = int(time.time())
    _, signer = guest['plan'](pin, now, guest['selected_case'](cmdline))
    need(signer != OFFICIAL, 'disposable signer must be distinct')
    before_raw = read(INPUT / 'before.lock', 16384)
    need(digest(before_raw) == BEFORE_SHA, 'exact Q3 successor inventory required')
    base_raw = read(INPUT / 'q3.lock', 16384)
    base = guest['inventory'](base_raw)
    before, _ = guest['expected_inventories'](base_raw, before_raw)

    pacman = '/usr/bin/pacman'
    def inventory():
        return dict(row.split() for row in checked((pacman, '-Q')).splitlines())

    need(len(before) == 362 and inventory() == base, 'original Q3 installed inventory required')
    need(base['sudo'] == '1.9.17.p2-6' and base['xdg-utils'] == '1.2.1-2', 'Q3 sudo and xdg versions required')
    pins = json.loads(read(CODE / 'vendor.json', 8192))
    vendor = INPUT / 'vendor'
    need({entry.name for entry in vendor.iterdir()} == pins.keys(), 'exact vendor media set required')
    vendor_archives = sorted(name for name in pins if name.endswith('.pkg.tar.xz'))
    need(len(vendor_archives) == 4, 'four vendor archives required')
    for name, record in pins.items():
        need(re.fullmatch(r'[A-Za-z0-9_.+-]+', name), 'bounded vendor leaf required')
        data = read(vendor / name, 1 << 20)
        need(len(data) == record['bytes'] and digest(data) == record['sha256'], 'vendor media pin differs')

    client_path = CODE / 'client.py'
    need(digest(read(client_path, 64 << 10)) == guest['CLIENT_SHA'], 'exact detached verifier required')
    client = runpy.run_path(str(client_path))
    trust = guest['TRUST']
    BOOTSTRAP.mkdir(mode=0o700)
    need(os.path.ismount(trust) and not any(trust.iterdir()), 'fresh private trust mount required')
    official_home, alpm_home = (BOOTSTRAP / leaf for leaf in ('official', 'alpm'))
    for home in (official_home, alpm_home):
        home.mkdir(mode=0o700)
    test_key, official_key = INPUT / 'TEST-public.gpg', vendor / 'archlinuxarm.gpg'
    read(test_key, 8192)
    keys = checked((*gpg(trust), '--with-colons', '--fingerprint', '--show-keys', str(test_key)))
    need(selected_test_key(keys, signer, now), 'one current public TEST primary required')
    checked((*gpg(trust), '--import', str(test_key)))
    guest['verify_trust'](signer, gpg(trust))
    checked((*gpg(official_home), '--import', str(official_key)))
    install = [*(vendor / name for name in vendor_archives), INPUT / 'updater.pkg', INPUT / guest['OLD_ARCHIVE']]
    for archive in install:
        home, fingerprint = (official_home, OFFICIAL) if archive.parent == vendor else (trust, signer)
        signature = checked((*gpg(home), '--status-fd', '1', '--verify', '--', f'{archive}.sig', str(archive)))
        proof = client['signature_status'](signature.encode(), fingerprint, datetime.fromtimestamp(now, timezone.utc))
        need(proof['signing_fingerprint'] == fingerprint, 'bootstrap signature signer differs')

    checked((*gpg(alpm_home), '--import', str(official_key), str(test_key)))
    checked((*gpg(alpm_home), '--import-ownertrust'), input_text=f'{OFFICIAL}:6:\n{signer}:6:\n')
    checked((*gpg(trust), '--import-ownertrust'), input_text=f'{signer}:6:\n')
    hooks = BOOTSTRAP / 'hooks'
    hooks.mkdir()
    names = read(INPUT / 'hooks.list', 8192).decode('ascii').splitlines()
    installed_hooks = {p.name for base in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks')
                       for p in Path(base).glob('*.hook')}
    need(len(names) == len(installed_hooks) <= 128 and set(names) == installed_hooks
         and all(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook', name) for name in names), 'exact Q3 hook mask required')
    for name in names:
        (hooks / name).symlink_to('/dev/null')
    config = BOOTSTRAP / 'pacman.conf'
    config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
                      f'LocalFileSigLevel = Required TrustedOnly\nGPGDir = {alpm_home}\nHookDir = {hooks}\n')
    checked((pacman, '--config', str(config), '-U', '--noconfirm', '--noscriptlet', *map(str, install)))
    checked((pacman, '--config', str(config), '-Dk'))
    need(inventory() == before, 'installed 362-package closure differs')
    for home in (official_home, alpm_home):
        checked(('/usr/bin/gpgconf', '--homedir', str(home), '--kill', 'all'))
    sudoers = Path('/etc/sudoers')
    info = sudoers.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1, 'ordinary Q3 sudoers required')
    replacement = sudoers.with_name('.updater-sudoers')
    with replacement.open('xb') as stream:
        stream.write(guest['SUDOERS'])
        os.fchmod(stream.fileno(), 0o440)
    checked(('/usr/bin/visudo', '-c', '-f', str(replacement)))
    replacement.replace(sudoers)
    print(json.dumps({'q3_bootstrap': 'PASS', 'before_packages': 362}, sort_keys=True))


if __name__ == '__main__':
    main()
