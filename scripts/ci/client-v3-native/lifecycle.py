#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Two signed packages in the owned native root; no historical v3 upgrade fiction."""
import json
import os
from pathlib import Path
import pwd
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installed as I

def main():
    C = I.load('client_v3_installed_contract', '/runner/contract.py')
    L, driver = I.apis()
    I.guard(L, 'lifecycle')
    base = json.loads(Path('/inputs/base.json').read_bytes())
    products = json.loads(Path('/inputs/products.json').read_bytes())
    L.need(len(base) == 574 and L.inventory() == base and set(products) == set(C.NAMES), 'exact574/two products required')
    L.need(not any(Path(p).exists() for p in ('/source', '/repository-source', '/.git', '/workspace')), 'installed CLI cannot use mounted checkout')
    control = json.loads(Path('/inputs/control.json').read_bytes())
    pacman = I.pacman(L, control['signer'])
    query = pacman[:-2]
    held = I.base_state(L, driver)
    base_digest = I.preserve_base(L, held)
    archives = []
    for name in C.NAMES:
        row = products[name]
        path = Path('/inputs') / row['archive']
        L.need(path.parent == Path('/inputs') and path.is_file() and not path.is_symlink() and L.sha(path) == row['sha256'] and
               set(row['payload']) == set(C.files(name)), 'exact accepted pair archive/payload required')
        archives.append(str(path))
    selected = {name: row['version'] for name, row in products.items()}
    account = pwd.getpwnam('alarm')
    homes = []
    outputs = {}
    events = []
    for kind in ('fresh', 'existing'):
        home = Path('/tmp') / ('client-v3-home-' + kind)
        home.mkdir(mode=0o700)
        if kind == 'existing':
            for name in ('.config/cachy-asahi/preferences', '.zshrc', '.cache/user-owned'):
                path = home / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('preserve ' + name + '\n')
                path.chmod(0o600)
            (home / '.config/alias').symlink_to('cachy-asahi/preferences')
        output = Path('/tmp') / ('client-v3-output-' + kind)
        output.mkdir(mode=0o700)
        (output / 'outside').write_text('preserve outside\n')
        session = L.session_paths(home, output)
        for path in (home, *home.rglob('*'), output, *output.rglob('*')):
            os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
        homes.append((home, L.snapshot(home), output, L.entry(output / 'outside'), session))

    def preserve():
        L.need(I.preserve_base(L, held) == base_digest, 'original574 payload/raw database changed')
        for home, before, output, outside, _ in homes:
            L.preservation_check(home, before, output, outside)
        for path, before in outputs.items():
            L.need(L.entry(path) == before, 'previously generated ordinary-user evidence changed')

    def installed(phase):
        L.need(L.inventory() == base | selected, 'exact576 installed inventory required')
        I.payloads(L, products)
        L.command(query + ['-Dk'])
        for name, digest in C.HELPERS.items():
            L.need(L.sha(C.RUNTIME / name) == digest, 'unchanged installed Runtime helper differs')
        observations = []
        for home, _, output, _, session in homes:
            work = output / phase
            work.mkdir(mode=0o700)
            os.chown(work, account.pw_uid, account.pw_gid)
            environment = L.user_environment(home, session)
            argv = ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', '-i', *(k + '=' + v for k, v in environment.items()),
                    '/usr/bin/python3', '-I', '-B', '/runner/installed_v3.py', '--work', str(work)]
            result = json.loads(L.command(argv, timeout=60))
            observations.append(dict(home=home.name, client_v3=result))
            for path in work.rglob('*'):
                if path.is_file() or path.is_symlink():
                    outputs[path] = L.entry(path)
        preserve()
        events.append(dict(phase=phase, count=576, base574_preserved=True, user_preserved=True, observations=observations))

    def absent(phase):
        L.need(L.inventory() == base, 'exact574 inventory must be restored')
        for row in products.values():
            for name in row['payload']:
                L.need(not os.path.lexists(Path('/') / name), 'removed package-owned file remains')
        preserve()
        events.append(dict(phase=phase, count=574, base574_preserved=True, user_preserved=True, payloads_absent=True))

    removal = [C.ROLES['client'], C.ROLES['runtime']]
    L.command(pacman + ['-U', *archives], timeout=90)
    installed('install')
    L.command(pacman + ['-U', *archives], timeout=90)
    installed('same-version-reinstall')
    L.command(pacman + ['-R', *removal], timeout=90)
    absent('remove')
    L.command(pacman + ['-U', *archives], timeout=90)
    installed('reinstall-after-removal')
    L.command(pacman + ['-R', *removal], timeout=90)
    absent('final-remove')
    result = dict(status='PASS_RUNTIME_CLIENT_V3_FRESH_LIFECYCLE', base_count=574, installed_count=576,
                  base574_preserved=True, base_manifest_sha256=base_digest, user_preserved=True, events=events,
                  removal_order=removal, architecture=os.uname().machine, page_size=os.sysconf('SC_PAGE_SIZE'),
                  hardware='NOT_RUN', release='NOT_ADMITTED', version_upgrade='NOT_RUN')
    C.validate_lifecycle(result)
    Path('/out/lifecycle.json').write_text(json.dumps(result, sort_keys=True) + '\n')
    L.command(['/usr/bin/gpgconf', '--homedir', '/tmp/apps-cache-trust', '--kill', 'all'])

if __name__ == '__main__':
    main()
