#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Held Setup7 gates followed by installed Setup7→8 private migrations."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as C
import baseline_lifecycle

COMPONENTS = ('fish', 'hyprland', 'zsh', 'fish-bang-bang', 'fish-autopair', 'fish-done',
              'zsh-autosuggestions', 'zsh-syntax-highlighting', 'zsh-history-substring-search')
TEMPLATES = {'fish': 'fish/config.fish', 'zsh': 'zsh/config.zsh', 'hyprland': 'hyprland/hyprland.lua',
             **{name: name + ('/opt-in.fish' if name.startswith('fish-') else '/opt-in.zsh')
                for name in COMPONENTS[3:]}}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def snapshot(root):
    """Bounded content/metadata observations, without following symbolic links."""
    if not os.path.lexists(root):
        return None
    paths = [root]
    if stat.S_ISDIR(root.lstat().st_mode):
        paths += sorted(root.rglob('*'))
    C.need(len(paths) <= 512, 'preservation observation exceeds finite path budget')
    result = {}
    for path in paths:
        item = path.lstat()
        C.need(stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode),
               'unexpected special preservation path')
        content = (sha(path.read_bytes()) if stat.S_ISREG(item.st_mode) else
                   sha(os.fsencode(os.readlink(path))) if stat.S_ISLNK(item.st_mode) else None)
        result[str(path.relative_to(root))] = dict(mode=stat.S_IMODE(item.st_mode), uid=item.st_uid,
            gid=item.st_gid, inode=item.st_ino, links=item.st_nlink, size=item.st_size,
            mtime_ns=item.st_mtime_ns, ctime_ns=item.st_ctime_ns, sha256=content,
            xattrs={key: sha(os.getxattr(path, key, follow_symlinks=False))
                    for key in os.listxattr(path, follow_symlinks=False)})
    return result


def identity(path):
    item = path.lstat()
    return item.st_dev, item.st_ino, item.st_uid, item.st_gid


def retire(paths, identities=None):
    """Retire only three exact new disposable roots, refusing links and mounts."""
    expected = {'/tmp/setup8-upgrade-inputs', '/tmp/setup8-old7-owned-home', '/tmp/setup8-delivery-work'}
    C.need({str(path) for path in paths} == expected, 'exact new fixture retirement set required')
    C.need(isinstance(identities, dict) and set(identities) == set(paths), 'creation identities required for fixture retirement')
    observed = {}
    for root in paths:
        C.need(root.parent == Path('/tmp') and root.is_dir() and not root.is_symlink()
               and identity(root) == identities[root], 'ordinary original owned fixture root required')
        items = [root, *root.rglob('*')]
        C.need(len(items) <= 512 and all(not p.is_symlink() and not os.path.ismount(p)
               and p.lstat().st_dev == root.lstat().st_dev for p in items), 'fixture retirement link/mount/size refusal')
        observed[root] = snapshot(root)
    for root in paths:
        C.need(identity(root) == identities[root] and snapshot(root) == observed[root], 'fixture changed before retirement')
        shutil.rmtree(root)
        C.need(not os.path.lexists(root), 'private fixture retirement incomplete')
    return True


def main():
    C.need(os.getuid() == os.geteuid() == 0 and os.getpid() == 1 and Path('/.dockerenv').is_file()
           and os.uname().machine == 'aarch64' and os.environ.get('CACHY_ASAHI_SETUP8_LIFECYCLE') == '1'
           and os.environ.get('CACHY_ASAHI_SETUP7_LIFECYCLE') == '1',
           'dedicated native ARM Setup8 container PID1 required')
    source, inputs, output = Path('/source'), Path('/inputs'), Path('/out')
    C.verify_source(source)
    L = C.load('setup8_accepted_preservation', Path('/accepted/lifecycle.py'))
    original = json.loads((inputs / 'base.json').read_text())
    products = json.loads((inputs / 'products.json').read_text())
    C.need(len(original) == 574 and C.PACKAGE not in original and L.inventory() == original
           and set(products) == set(C.NAMES), 'exact574 and both fresh setup profiles required')
    archives = {}
    for name in C.NAMES:
        product = products[name]; archive = inputs / product['archive']
        C.need(archive.parent == inputs and archive.is_file() and not archive.is_symlink()
               and re.fullmatch('[0-9a-f]{64}', product['sha256']) and L.sha(archive) == product['sha256']
               and product['version'] == C.VERSIONS[name] and set(product['payload']) == set(C.files(name)),
               'exact fresh profile archive/version/payload required')
        for relative, (leaf, mode) in C.files(name).items():
            row = product['payload'][relative]
            C.need(row['mode'] == mode and row['sha256'] == C.digest(source / C.recipe_path(name) / leaf),
                   'source-pinned fresh product payload differs')
        archives[name] = archive
    protected_paths = tuple(map(Path, ('/etc/pacman.conf', '/etc/pacman.d', '/etc/fish', '/etc/zsh', '/etc/skel')))
    def system():
        return {str(path): snapshot(path) for path in protected_paths}
    protected = system()
    baseline_lifecycle.run()
    baseline_raw = (output / 'lifecycle.json').read_bytes(); baseline = json.loads(baseline_raw)
    C.baseline(source).validate_lifecycle(baseline)
    C.need(L.inventory() == original and system() == protected, 'held baseline did not restore exact574/protected configuration')
    (output / 'baseline7-lifecycle.json').write_bytes(baseline_raw)

    hooks = Path('/tmp/setup8-hooks'); hooks.mkdir(mode=0o755)
    masked = set()
    for parent in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks', '/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:
                (hooks / path.name).symlink_to('/dev/null'); masked.add(path.name)
    config = Path('/tmp/setup8-pacman.conf')
    config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = ' + str(hooks) + '\n')
    pacman = ['/usr/bin/pacman', '--config', str(config), '--noconfirm']
    account = pwd.getpwnam('alarm')
    C.need(account.pw_uid > 0 and account.pw_gid > 0, 'ordinary fixture account required')
    fixture = Path('/tmp/setup8-upgrade-inputs'); fixture.mkdir(mode=0o755)
    old, new = fixture / 'old-1.0-1', fixture / 'new-2.0-1'
    manifest = dict(schema_version=1, id='setup8-old7-owned-fixture', package='cachy-asahi-fixture-config',
                    from_version='1.0-1', to_version='2.0-1', entries=[])
    for root, version in ((old, 'old'), (new, 'new')):
        root.mkdir(mode=0o755)
        for name, relative in TEMPLATES.items():
            path = root / relative; path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            path.write_text(('--' if name == 'hyprland' else '#') + ' inert private ' + version + ' ' + name + '; never executed\n')
            path.chmod(0o644)
    for name in COMPONENTS:
        manifest['entries'].append(dict(component=name, old=dict(root=str(old), sha256=L.sha(old / TEMPLATES[name])),
                                        new=dict(root=str(new), sha256=L.sha(new / TEMPLATES[name]))))
    manifest_path = fixture / 'migration.json'; manifest_path.write_bytes(encode(manifest)); manifest_path.chmod(0o644)
    manifest_sha = L.sha(manifest_path); fixture_before = snapshot(fixture)
    home = Path('/tmp/setup8-old7-owned-home'); home.mkdir(mode=0o700)
    outside = {'fish': b'# PRIVATE_FIXTURE_CANARY original Fish\n', 'zsh': b'# PRIVATE_FIXTURE_CANARY original Zsh\n'}
    shell_paths = {'fish': '.config/fish/config.fish', 'zsh': '.zshrc'}
    for name, relative in shell_paths.items():
        path = home / relative; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(outside[name]); path.chmod(0o640); os.setxattr(path, 'user.setup8-upgrade', b'preserved')
    sentinel = home / 'outside-sentinel'; sentinel.write_bytes(b'preserve unrelated private fixture\n'); sentinel.chmod(0o600)
    for path in (home, *home.rglob('*')):
        os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
    created = {path: identity(path) for path in (fixture, home)}
    sentinel_before = snapshot(sentinel); work = Path('/tmp/setup8-delivery-work')
    baseline_homes = [Path('/tmp') / ('setup7-user-' + profile) for profile in (*C.LEGACY, 'new-grouped-journal')]
    C.need(all(path.is_dir() for path in baseline_homes) and not work.exists(), 'held homes and fresh delivery fixture required')
    home_roots = [*baseline_homes, home, work]; events, observations = [], []

    def homes():
        return {str(path): snapshot(path) for path in home_roots}

    def preserved_system():
        C.need(system() == protected and snapshot(fixture) == fixture_before,
               'system configuration or pinned inert manifest/templates changed')

    def installed(name):
        product = products[name]
        C.need(L.inventory() == original | {C.PACKAGE: product['version']}, 'exact575 profile inventory differs')
        L.command(pacman + ['-Dk']); L.command(pacman + ['-T', 'python>=3.11', 'gnupg', 'pacman'])
        L.command(pacman + ['-Qkk', C.PACKAGE]); owned = L.command(pacman + ['-Qql', C.PACKAGE]).splitlines()
        C.need({p for p in owned if not p.endswith('/')} == {'/' + p for p in C.files(name)}, 'exact six/ten-file ALPM ownership differs')
        for relative, row in product['payload'].items():
            path = Path('/') / relative; item = path.lstat()
            C.need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and item.st_uid == item.st_gid == 0
                   and stat.S_IMODE(item.st_mode) == row['mode'] and L.sha(path) == row['sha256'],
                   'installed payload bytes/owner/mode differ')

    def transition(phase, name=None):
        before = homes(); preserved_system()
        L.command(pacman + ['--noscriptlet'] + (['-U', str(archives[name])] if name else ['-R', C.PACKAGE]))
        if name:
            installed(name)
        else:
            C.need(L.inventory() == original, 'full574 inventory not restored'); L.command(pacman + ['-Dk'])
            C.need(all(not os.path.lexists('/' + relative) for relative in C.files(C.CANDIDATE)), 'removed setup8 payload remains')
        preserved_system(); C.need(homes() == before, 'ALPM transition changed held/new private homes or journals')
        events.append(dict(phase=phase, status='PASS', inventory_count=575 if name else 574,
                           homes_preserved=True, database_check=True,
                           installed_payload_sha256={p: r['sha256'] for p, r in products[name]['payload'].items()} if name else {}))

    def user(argv, *, expected=0, timeout=60):
        env = dict(PATH='/usr/bin:/bin', HOME=str(home), LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1',
                   XDG_CONFIG_HOME='/must-not-be-used', XDG_STATE_HOME='/must-not-be-used', ZDOTDIR='/must-not-be-used')
        return L.command(['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', '-i',
                          *(key + '=' + value for key, value in env.items()), *argv], expected=expected, timeout=timeout)

    def setup(operation, root, apply=False):
        argv = ['/usr/bin/python3', '-I', '-B', '/usr/bin/cachy-asahi-setup', operation,
                '--home', str(home), '--template-root', str(root), '--components', *COMPONENTS]
        value = json.loads(user(argv + (['--apply'] if apply else [])))
        C.need(value['operation'] == operation and value['mode'] == ('applied' if apply else 'read-only'),
               'ordinary installed setup operation/mode differs')
        return value

    def migrate(operation):
        value = json.loads(user(['/usr/bin/python3', '-I', '-B', '/usr/bin/cachy-asahi-config-migrate', operation,
            '--home', str(home), '--manifest', str(manifest_path), '--sha256', manifest_sha]))
        C.need(value['operation'] == operation and value.get('manifest_sha256') == manifest_sha,
               'ordinary installed migration operation/manifest differs')
        observations.append(dict(operation=operation, status=value['status'], uid=account.pw_uid, manifest_sha256=manifest_sha))
        return value

    def ownership(root):
        state = json.loads((home / '.local/state/cachy-asahi/setup/state.json').read_bytes())
        C.need(state['schema_version'] == 1 and set(state['components']) == set(COMPONENTS), 'exact nine owned components required')
        for name, record in state['components'].items():
            if name == 'hyprland':
                C.need(record['sha256'] == L.sha(root / TEMPLATES[name]) == L.sha(home / record['path']), 'whole-file owned template differs')
            else:
                C.need(record['source_root'] == str(root) and (home / record['path']).read_bytes().count(record['block'].encode()) == 1,
                       'guarded owned source block differs')
        return state

    def outside_bytes(state):
        for name, relative in shell_paths.items():
            path = home / relative; raw = path.read_bytes()
            for record in state['components'].values():
                if record['path'] == relative:
                    raw = raw.replace(record['block'].encode(), b'', 1)
            item = path.stat()
            C.need(raw == outside[name] and stat.S_IMODE(item.st_mode) == 0o640
                   and item.st_uid == account.pw_uid and item.st_gid == account.pw_gid
                   and os.getxattr(path, 'user.setup8-upgrade') == b'preserved', 'outside user bytes/mode/owner/xattr changed')
        C.need(snapshot(sentinel) == sentinel_before, 'unrelated user sentinel changed')

    def delivery(reinstall=False):
        if reinstall:
            C.need(identity(work) == created[work], 'persistent delivery fixture root replaced')
        driver = inputs / 'setup8-delivery.py'
        C.need(driver.is_file() and not driver.is_symlink() and L.sha(driver) == C.digest(source / C.recipe_path(C.CANDIDATE) / 'test_delivery.py'),
               'ordinary staged delivery driver differs from pinned source')
        argv = ['/usr/bin/python3', '-I', '-B', str(driver),
                '--root', '/', '--work', str(work), '--verify-reinstall' if reinstall else '--keep-fixtures']
        value = json.loads(user(argv, timeout=180))
        C.need(value['uid'] == account.pw_uid and value['architecture'] == 'aarch64'
               and value['actual_page_size'] == os.sysconf('SC_PAGE_SIZE') and value['fixture_work'] == str(work)
               and value['private_fixtures_retired'] is False, 'actual ordinary installed delivery fixture identity differs')
        if not reinstall:
            C.need(work.stat().st_uid == account.pw_uid and work.stat().st_gid == account.pw_gid,
                   'ordinary delivery fixture ownership differs')
            created[work] = identity(work)
        (output / ('migration-reinstall.json' if reinstall else 'migration-delivery.json')).write_bytes(encode(value))
        preserved_system()
        return value

    upgrade = dict(uid=account.pw_uid, manifest_sha256=manifest_sha, manifest=manifest, components=list(COMPONENTS),
                   baseline_package_version=C.VERSIONS[C.BASELINE], candidate_package_version=C.VERSIONS[C.CANDIDATE])
    transition('install-setup7-for-migration', C.BASELINE)
    setup('activate', old, True); ownership(old)
    for name, relative in shell_paths.items():
        tail = b'# PRIVATE_FIXTURE_CANARY outside old7 managed blocks\n'
        with (home / relative).open('ab') as stream:
            stream.write(tail)
        outside[name] += tail
    outside_bytes(ownership(old)); upgrade['old7_owned_before_upgrade'] = True
    transition('upgrade-setup8', C.CANDIDATE)
    before = snapshot(home)
    C.need(migrate('preview')['status'] == migrate('status')['status'] == 'ready', 'old7-owned migration not ready')
    C.need(snapshot(home) == before, 'old7-owned preview/status changed home'); upgrade['preview_readonly'] = True
    C.need(migrate('apply')['status'] == 'applied', 'old7-owned installed migration not applied')
    state = ownership(new); outside_bytes(state)
    ledger_path = home / '.local/state/cachy-asahi/setup/migrations.json'
    ledger_raw = ledger_path.read_bytes(); ledger = json.loads(ledger_raw)
    C.need(set(ledger['components']) == set(COMPONENTS) and all(
        ledger['components'][entry['component']] == dict(entry['new'], package=manifest['package'], version=manifest['to_version'])
        for entry in manifest['entries']), 'exact per-component configuration version ledger differs')
    upgrade.update(applied=True, outside_user_bytes_preserved=True, ledger_sha256=sha(ledger_raw))
    before = snapshot(home)
    C.need(migrate('apply')['status'] == migrate('status')['status'] == 'already-applied', 'completed upgrade repeat differs')
    C.need(snapshot(home) == before, 'completed upgrade repeat/status changed home'); upgrade['repeat_readonly'] = True
    initial_delivery = delivery()
    transition('repeat-setup8', C.CANDIDATE)
    transition('remove-setup8')
    C.need(ledger_path.read_bytes() == ledger_raw, 'ALPM removal erased configuration version ledger')
    transition('reinstall-setup8', C.CANDIDATE)
    C.need(ledger_path.read_bytes() == ledger_raw, 'ALPM reinstall changed configuration version ledger')
    before = snapshot(home)
    C.need(migrate('status')['status'] == migrate('apply')['status'] == 'already-applied', 'reinstalled CLI lost exact completed upgrade')
    C.need(snapshot(home) == before, 'reinstalled CLI changed completed upgrade'); upgrade['ledger_preserved_on_package_reinstall'] = True
    reinstalled_delivery = delivery(True)
    setup('remove', new, True)
    state = json.loads((home / '.local/state/cachy-asahi/setup/state.json').read_bytes())
    C.need(state['components'] == {} and not (home / '.config/cachy-asahi/hyprland.lua').exists()
           and ledger_path.read_bytes() == ledger_raw, 'new CLI removal changed retained history or kept owned config')
    outside_bytes(state); upgrade.update(new_cli_removal_preserved_user_bytes=True, status='PASS', observations=observations)
    (output / 'upgrade-home.json').write_bytes(encode(upgrade))
    transition('final-remove-setup8')
    private_retired = retire([fixture, home, work], created)
    C.need(L.inventory() == original and system() == protected, 'fixture retirement changed restored base/configuration')
    result = dict(status='PASS_SETUP8_INSTALLED_MIGRATION_AND_HELD_SETUP7_BASELINE', baseline7=baseline, events=events,
        system_config_preserved=True, user_state_preserved_on_alpm=True, full574_restored=True,
        native_architecture=os.uname().machine, actual_page_size=os.sysconf('SC_PAGE_SIZE'), hardware='NOT_RUN',
        upgrade_home=upgrade, migration_delivery=initial_delivery, migration_reinstall=reinstalled_delivery,
        private_fixtures_scope='EXPLICIT_DISPOSABLE_USER_HOMES_AND_PINNED_INERT_MANIFEST', private_fixtures_retired=private_retired,
        baseline_fixture_retirement='DISPOSABLE_CONTAINER_CLEANUP_REQUIRED',
        fixture_retirement_scope='THREE_NEW_SETUP8_ROOTS_ONLY; HELD_SETUP7_BASELINE_HOMES_UNCHANGED',
        trust='UNSIGNED_LOCAL_CANDIDATES_ONLY', masked_hooks=len(masked), performance='NOT_MEASURED', release='NOT_ADMITTED')
    C.validate_lifecycle(result)
    (output / 'lifecycle.json').write_bytes(encode(result))


if __name__ == '__main__':
    main()
