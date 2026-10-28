#!/usr/bin/env python3
"""Bounded ten-package lifecycle in the caller's disposable ARM container."""
import hashlib
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace, MethodType

LIBRARIES = ('/usr/lib/libfdk-aac.so.2', '/usr/lib/libfdk-xhe-aac.so.0')
COMPONENTS = ('fish', 'zsh', 'hyprland')
FDK = 'cachy-asahi-fdk-aac'


def baseline(pacman, composition, provider):
    composition.guard()
    return {path: provider.library_identity(path, 'libfdk-aac') for path in LIBRARIES}


def fixtures(work, composition, core):
    """Reuse existing fixture/recovery operations without creating system accounts."""
    work.chmod(0o755)
    homes = work / 'lifecycle-homes'
    homes.mkdir(mode=0o755)
    adapter = SimpleNamespace(work=homes, checks=[])
    adapter.guard = composition.guard

    def command(argv, user=None, allowed=(0,), stdin=None):
        composition.guard()
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'TERM': 'dumb',
               'PYTHONDONTWRITEBYTECODE': '1', 'HOME': '/root'}
        preexec = None
        if user:
            env.update(HOME=str(user['home']), ZDOTDIR=str(user['home']),
                       XDG_CONFIG_HOME=str(user['home'] / '.config'),
                       XDG_DATA_HOME=str(user['home'] / '.local/share'),
                       XDG_STATE_HOME=str(user['home'] / '.local/state'))
            def preexec():
                os.setgroups([]); os.setgid(user['gid']); os.setuid(user['uid'])
        print('$ fixture', ' '.join(map(str, argv)), flush=True)
        result = core.bounded_process(argv, timeout=45, stdout_limit=524288, stderr_limit=524288,
                                      env=env, preexec_fn=preexec, stdin=stdin)
        text = result['stdout'].decode(errors='replace')
        print(text[-8192:], result['stderr'].decode(errors='replace')[-8192:], flush=True)
        composition.need(result['reason'] == 'exit' and result['returncode'] in allowed,
                         'fixture command failed: ' + str(result['reason']) + '/' + str(result['returncode']))
        return text

    def check(name, condition):
        composition.need(condition, 'lifecycle check failed: ' + name)
        adapter.checks.append(name)

    adapter.command, adapter.check = command, check
    for name in ('fixture', 'helper', 'paths', 'snapshot', 'interrupt'):
        setattr(adapter, name, MethodType(getattr(core.Lifecycle, name), adapter))
    users = []
    for label in ('fresh', 'existing'):
        home = homes / label
        home.mkdir(mode=0o700)
        os.chown(home, 65534, 65534)
        users.append({'home': home, 'uid': 65534, 'gid': 65534})
    return adapter, users


def payloads(pacman, projects, composition):
    composition.run(pacman + ['-Qkk', *sorted(p['name'] for p in projects)])
    for project in projects:
        for item in project['payload']:
            path = Path(item['path'])
            info = path.lstat()
            composition.need(info.st_uid == info.st_gid == 0, 'payload ownership uid/gid differs')
            if item['type'] == 'symlink':
                valid = stat.S_ISLNK(info.st_mode) and os.readlink(path) == item['target']
            else:
                valid = (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == item['mode']
                         and hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'])
            composition.need(valid, 'installed payload differs: ' + str(path))
            composition.need(composition.run(pacman + ['-Qqo', str(path)]).strip() == project['name'],
                             'installed package owner differs: ' + str(path))


def upgrade_inputs(plan, source, composition, core):
    rows = plan['lifecycle']['upgrades']
    composition.need(len(rows) == 4 and {r['name'] for r in rows} == set(core.PACKAGES),
                     'exact original-four upgrade fixtures required')
    originals = {p['name']: p for p in plan['projects']}
    for row in rows:
        composition.need(row['version'] == '0.1.1-1' and
                         re.fullmatch(r'[A-Za-z0-9+_.:@-]+\.pkg\.tar\.(?:xz|zst|gz)', row['filename']),
                         'invalid development upgrade fixture')
        composition.pin(source / row['filename'], row['sha256'], row['size'])
        composition.pin(source / (row['filename'] + '.sig'), row['signature_sha256'], row['signature_size'])
        fields = composition.archive_metadata(row, source)
        original = originals[row['name']]
        for expected, actual in (('depends', 'depend'), ('provides', 'provides'), ('conflicts', 'conflict')):
            composition.need(sorted(original[expected]) == sorted(fields.get(actual, [])),
                             'upgrade fixture changed dependency/provider policy')
        listing = composition.run(['pacman', '-Qqlp', str(source / row['filename'])]).splitlines()
        composition.need({p for p in listing if not p.endswith('/')} == {p['path'] for p in row['payload']},
                         'upgrade fixture payload list differs')
    return rows


def restore(pacman, plan, base, current, source, composition, provider, upstream_before, projects):
    """Remove projects normally, replace FDK, then remove the four runtime additions."""
    composition.run(pacman + ['--noconfirm', '--noscriptlet', '-R', *sorted(composition.PROJECTS - {FDK})])
    remaining = {k: v for k, v in current.items() if k not in composition.PROJECTS - {FDK}}
    composition.need(composition.inventory() == remaining, 'project removal changed unrelated inventory')
    row = plan['lifecycle']['upstream']
    composition.need(row['name'] == 'libfdk-aac' and row['version'] == base['libfdk-aac'] and
                     re.fullmatch(r'[A-Za-z0-9+_.:@-]+\.pkg\.tar\.(?:xz|zst|gz)', row['filename']),
                     'upstream restore archive differs from base')
    composition.pin(source / row['filename'], row['sha256'], row['size'])
    composition.pin(source / (row['filename'] + '.sig'), row['signature_sha256'], row['signature_size'])
    composition.archive_metadata(row, source)
    composition.run(pacman + ['--noconfirm', '--noscriptlet', '--ask', '4', '-U', str(source / row['filename'])])
    del remaining[FDK]
    remaining['libfdk-aac'] = base['libfdk-aac']
    composition.need(composition.inventory() == remaining, 'FDK restoration changed unrelated inventory')
    composition.run(pacman + ['--noconfirm', '--noscriptlet', '-R', *sorted(composition.EXTRAS)])
    composition.need(composition.inventory() == base, 'exact 574-package base was not restored')
    composition.run(pacman + ['-Dk'])
    shared = {p for p in composition.run(['pacman', '-Qqlp', str(source / row['filename'])]).splitlines()
              if not p.endswith('/')}
    for project in projects:
        for item in project['payload']:
            path = Path(item['path'])
            if path.exists() or path.is_symlink():
                composition.need(project['name'] == FDK and str(path) in shared and
                                 composition.run(pacman + ['-Qqo', str(path)]).strip() == 'libfdk-aac',
                                 'project payload remains after restoration: ' + str(path))
    for path in LIBRARIES:
        provider.library_identity(path, 'libfdk-aac', upstream_before[path])


def run(pacman, plan, base, expected, source, work, composition, core, provider, upstream_before):
    composition.guard()
    phase = 'initial-payloads'
    try:
        composition.need(composition.inventory() == expected, 'lifecycle requires frozen v1 exact587')
        payloads(pacman, plan['projects'], composition)
        upgrades = upgrade_inputs(plan, source, composition, core)
        upgraded_projects = [{**p, **next((u for u in upgrades if u['name'] == p['name']), {})}
                             for p in plan['projects']]
        upgraded = expected | {r['name']: r['version'] for r in upgrades}
        dependencies = sorted({d for p in plan['projects'] for d in p['depends']})
        adapter, (fresh, existing) = fixtures(work, composition, core)
        phase = 'setup-preview-repeat-and-existing-config'
        before = adapter.snapshot(fresh)
        adapter.helper(fresh, 'activate', COMPONENTS, apply=False)
        adapter.check('fresh-preview-readonly', adapter.snapshot(fresh) == before)
        adapter.helper(fresh, 'activate', COMPONENTS)
        before = adapter.snapshot(fresh)
        adapter.helper(fresh, 'activate', COMPONENTS)
        adapter.check('fresh-repeat-idempotent', adapter.snapshot(fresh) == before)
        originals = {'fish': b'# existing fish\n', 'zsh': b'# existing zsh\n'}
        for name, data in originals.items():
            adapter.fixture(existing, str(adapter.paths(existing)[name].relative_to(existing['home'])), data)
        base_rc = adapter.fixture(existing, '.config/hypr/hyprland.lua', b'-- existing base\n')
        adapter.helper(existing, 'activate', COMPONENTS)
        before = adapter.snapshot(existing)
        adapter.helper(existing, 'activate', COMPONENTS)
        adapter.check('existing-repeat-idempotent', adapter.snapshot(existing) == before)
        expected_shells = {}
        for name, data in originals.items():
            path = adapter.paths(existing)[name]
            adapter.check('existing-prefix-mode-' + name, path.read_bytes().startswith(data)
                          and stat.S_IMODE(path.stat().st_mode) == 0o640)
            path.write_bytes(b'# before\n' + path.read_bytes() + b'# after\n')
            expected_shells[name] = b'# before\n' + data + b'# after\n'
        desktop = adapter.paths(existing)['hyprland']
        desktop.write_bytes(desktop.read_bytes() + b'\n-- retain user edit\n')
        edited_desktop = desktop.read_bytes()
        old_desktop_sha = core.sha(adapter.paths(fresh)['hyprland'])
        phase = 'signed-four-package-upgrade'
        composition.run(pacman + ['--noconfirm', '--noscriptlet', '-U', *[str(source / r['filename']) for r in upgrades]])
        composition.need(composition.inventory() == upgraded, 'upgrade changed exact composition inventory')
        composition.run(pacman + ['-Dk'])
        composition.run(pacman + ['-T', *dependencies])
        payloads(pacman, upgraded_projects, composition)
        adapter.helper(fresh, 'activate', COMPONENTS)
        adapter.helper(existing, 'activate', COMPONENTS, allowed=(2,))
        adapter.check('upgrade-refreshes-unmodified-copy', core.sha(adapter.paths(fresh)['hyprland']) ==
                      core.sha('/usr/share/cachy-asahi/hyprland/hyprland.lua')
                      and core.sha(adapter.paths(fresh)['hyprland']) != old_desktop_sha)
        adapter.check('upgrade-preserves-edited-copy', desktop.read_bytes() == edited_desktop)
        phase = 'first-removal-and-upstream-restoration'
        homes = [adapter.snapshot(u) for u in (fresh, existing)]
        restore(pacman, plan, base, upgraded, source, composition, provider, upstream_before, upgraded_projects)
        adapter.check('package-removal-preserves-user-files', homes == [adapter.snapshot(u) for u in (fresh, existing)])
        phase = 'original-v1-reinstallation'
        composition.install(pacman, [str(source / r['filename']) for r in plan['packages']], expected)
        composition.run(pacman + ['-Dk'])
        composition.run(pacman + ['-T', *dependencies])
        payloads(pacman, plan['projects'], composition)
        phase = 'setup-deactivation-and-deterministic-interruption-recovery'
        adapter.helper(fresh, 'remove')
        adapter.check('fresh-deactivation-removes-owned-files', all(not p.exists() for p in adapter.paths(fresh).values()))
        adapter.helper(existing, 'remove', allowed=(2,))
        adapter.check('existing-deactivation-surgical', all(adapter.paths(existing)[c].read_bytes() == data
                      and stat.S_IMODE(adapter.paths(existing)[c].stat().st_mode) == 0o640 for c, data in expected_shells.items()))
        adapter.check('existing-edited-desktop-remains', desktop.read_bytes() == edited_desktop)
        adapter.interrupt(fresh, 'activate')
        adapter.check('interrupted-activation-restored', all(p.exists() for p in adapter.paths(fresh).values()))
        adapter.interrupt(fresh, 'remove')
        adapter.check('interrupted-removal-restored', all(not p.exists() for p in adapter.paths(fresh).values()))
        adapter.check('base-session-config-preserved', base_rc.read_bytes() == b'-- existing base\n')
        phase = 'final-removal-and-upstream-restoration'
        homes = [adapter.snapshot(u) for u in (fresh, existing)]
        restore(pacman, plan, base, expected, source, composition, provider, upstream_before,
                plan['projects'] + upgraded_projects)
        adapter.check('final-removal-preserves-user-files', homes == [adapter.snapshot(u) for u in (fresh, existing)])
        final_inventory = composition.inventory()
        composition.need(final_inventory == base, 'final inventory changed after restoration')
        final_sha = hashlib.sha256(''.join(k + ' ' + v + '\n' for k, v in sorted(final_inventory.items())).encode()).hexdigest()
        return {'status': 'PASS', 'checks': adapter.checks, 'initial_count': 587, 'upgrade_count': 587,
                'final_package_count': len(final_inventory), 'final_inventory_sha256': final_sha,
                'restored_count': 574, 'reinstalled_count': 587, 'upstream_libraries_restored': upstream_before,
                'upgrade_versions': {r['name']: r['version'] for r in upgrades},
                'interruption': 'deterministic installed-helper os._exit(75), not power-loss testing',
                'interactive_shell_pty': 'NOT RUN', 'hardware': 'NOT RUN', 'target_recovery': 'NOT RUN'}
    except Exception as error:
        raise RuntimeError('composition lifecycle failed at ' + phase + ': ' + str(error)) from error
