# SPDX-License-Identifier: MIT
"""Drive the actual installed Check using inert, logged optional commands."""
import os
import time

OPTIONAL_STUB = r"""#!/usr/bin/bash
set -eu
tool=${0##*/}
printf '%s\t%s\n' "$tool" "$*" >> "$FIXTURE_LOG"
case "$tool:$*" in
    'paru:-Qua')
        case "$FIXTURE_MODE" in
            aur-failure) printf '%s\n' 'fixture AUR error' >&2; exit 3 ;;
            empty) exit 1 ;;
            *) printf '%s\n' 'fixture-aur 1 -> 2' ;;
        esac ;;
    'flatpak:list --user')
        case "$FIXTURE_MODE" in
            user-discovery-failure) exit 3 ;;
            empty|system-discovery-failure) ;;
            *) printf '%s\n' 'org.fixture.App' ;;
        esac ;;
    'flatpak:list --system')
        if [[ $FIXTURE_MODE == system-discovery-failure ]]; then exit 3; fi ;;
    'flatpak:update --appstream')
        if [[ $FIXTURE_MODE == appstream-failure ]]; then exit 3; fi ;;
    'flatpak:mask')
        if [[ $FIXTURE_MODE == mask-failure ]]; then exit 3; fi ;;
    'flatpak:remote-ls --updates --columns=name,version')
        if [[ $FIXTURE_MODE == remote-failure ]]; then exit 3; fi
        printf 'Fixture App\t2\n' ;;
    *) exit 127 ;;
esac
"""

AUR = ('paru\t-Qua',)
USER = AUR + ('flatpak\tlist --user',)
DISCOVERY = USER + ('flatpak\tlist --system',)
APPSTREAM = DISCOVERY + ('flatpak\tupdate --appstream',)
MASK = APPSTREAM + ('flatpak\tmask',)
REMOTE = MASK + ('flatpak\tremote-ls --updates --columns=name,version',)
FAILURES = {
    'aur-failure': ('AUR', AUR),
    'user-discovery-failure': ('Flatpak', USER),
    'system-discovery-failure': ('Flatpak', DISCOVERY),
    'appstream-failure': ('Flatpak', APPSTREAM),
    'mask-failure': ('Flatpak', MASK),
    'remote-failure': ('Flatpak', REMOTE),
}


def exercise(home, config, result, run, user_command, snapshot, need):
    """The caller has selected the signed no-updates repository in its container."""
    state = home / 'state/arch-update'
    fixture_bin = home / 'optional-bin'
    fixture_bin.mkdir(mode=0o755)
    for name in ('paru', 'flatpak'):
        stub = fixture_bin / name
        stub.write_text(OPTIONAL_STUB)
        stub.chmod(0o755)
    log = home / 'optional-calls'
    log.touch(mode=0o600)
    user = home.stat()
    os.chown(log, user.st_uid, user.st_gid)
    config.write_text('NoNotification\nNoALHPCheck\nNoColor\n')

    def check(mode, expected_calls, *, failure=None):
        result['phase'] = 'optional-' + mode
        log.write_bytes(b'')
        before = snapshot(state, metadata=True)
        started = int(time.time())
        argv = user_command(home, [])
        path = argv.index('PATH=/usr/bin:/bin')
        argv[path] = f'PATH={fixture_bin}:/usr/bin:/bin'
        argv += [f'FIXTURE_MODE={mode}', f'FIXTURE_LOG={log}', '/usr/bin/arch-update', '--check']
        process = run(argv, expected=None)
        row = {'exit': process.returncode}
        result['cases'][result['phase']] = row
        need(tuple(log.read_text().splitlines()) == expected_calls, 'optional invocation sequence differs')
        if failure:
            need(process.returncode == 20 and f'({failure})'.encode() in process.stderr
                 and b'previous check state has been preserved' in process.stderr,
                 'optional failure was not reported by installed Check')
            need(snapshot(state, metadata=True) == before, 'optional failure changed check state')
            row['state_preserved'] = 'PASS-bytes-mode-mtime'
            return

        need(process.returncode == 0, 'installed optional Check failed')
        pending = mode == 'pending'
        aur = b'fixture-aur 1 -> 2\n' if pending else b''
        flatpak = b'Fixture App 2\n' if pending else b''
        need((state / 'last_updates_check_aur').read_bytes() == aur
             and (state / 'last_updates_check_flatpak').read_bytes() == flatpak
             and (state / 'last_updates_check_packages').read_bytes() == b''
             and (state / 'last_updates_check').read_bytes() == (aur + flatpak or b'\n'),
             'installed optional Check state differs')
        icon = 'cachy-update_updates-available-blue\n' if pending else 'cachy-update-blue\n'
        need((state / 'tray_icon').read_text() == icon, 'installed optional Check icon differs')
        timestamp = (state / 'last_updates_check_time').read_text().splitlines()
        need(len(timestamp) == 2 and timestamp[0].isdigit()
             and started <= int(timestamp[0]) <= int(time.time())
             and not (state / 'current_updates_check').exists(), 'optional Check timestamp/state differs')
        row['state'] = 'PASS-real-installed-Check-inert-optional-commands'

    check('pending', REMOTE)
    for mode, (backend, calls) in FAILURES.items():
        check(mode, calls, failure=backend)
    check('empty', DISCOVERY)
