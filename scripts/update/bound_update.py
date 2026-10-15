#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Commit one authenticated development snapshot in a tiny disposable copied root."""
import argparse
import ctypes as C
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


install = module('bound_installer', ROOT / 'scripts/install/local_transaction.py')
client = module('bound_client', ROOT / 'scripts/client/client.py')
POLICY_PATH = ROOT / 'packages/tools/cachy-asahi-update/asahi-policy.py'
TRUST = ('etc/pacman.conf', 'etc/pacman.d')
BLOCKED = ('boot', 'efi', 'proc', 'sys', 'dev', 'run', 'usr/lib/modules', 'usr/lib/firmware',
           'usr/share/libalpm/hooks', 'etc/pacman.d/hooks')
SETTINGS = {'schema_version', 'purpose', 'namespace', 'signer', 'minimum_sequence', 'release_id',
            'repo_name', 'metadata_sha256', 'release_sha256', 'public_keyring_sha256',
            'base_trust_sha256', 'model', 'running_kernel_release', 'operations'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def configuration(path, pin):
    raw = client.read_path(path, client.MAX_JSON)
    need(hashlib.sha256(raw).hexdigest() == pin, 'update configuration changed')
    value = client.decode(raw)
    need(set(value) == SETTINGS and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['purpose'] == 'disposable-generic-bound-update', 'explicit disposable release configuration required')
    need(value['operations'] == ['repository-update'], 'unsupported update operations')
    need(client.NAMESPACE.fullmatch(value['namespace']) and client.NAME.fullmatch(value['release_id'])
         and client.NAME.fullmatch(value['repo_name']), 'invalid release identity')
    need(client.fingerprint(value['signer']) == value['signer'] and len(value['signer']) == 40,
         'full supported primary signer required')
    client.sequence(value['minimum_sequence'])
    for key in ('metadata_sha256', 'release_sha256', 'public_keyring_sha256', 'base_trust_sha256'):
        need(type(value[key]) is str and client.HEX.fullmatch(value[key]), 'full configuration digest required')
    return value


def guard(root, workspace):
    need(os.getuid() == os.geteuid() == 0 and os.uname().machine in ('x86_64', 'aarch64'),
         'mapped disposable Linux root required')
    mapping = Path('/proc/self/uid_map').read_text().split()
    mapped = len(mapping) == 3 and mapping[0] == '0' and mapping[1].isdigit() and int(mapping[1]) > 0 and mapping[2] == '1'
    docker = Path('/.dockerenv').is_file() and re.fullmatch('[0-9a-f]{32}', os.environ.get('CACHY_ASAHI_BOUND_UPDATE', ''))
    need(mapped or docker, 'explicit disposable namespace/container required')
    interfaces = {line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
    need(interfaces == {'lo'}, 'network-isolated disposable caller required')
    need(os.environ.get('PATH') == '/usr/bin:/bin' and not any(key.startswith(('LD_', 'GPG_', 'ALPM_', 'PACMAN_'))
         for key in os.environ), 'clean standard command environment required')
    workspace = install.private(workspace, 0)
    need(root == workspace / 'root' and root.resolve(strict=True) == root and root.is_dir()
         and not any(p.is_symlink() for p in (root, *root.parents)), 'owned copied root required')
    need((root / 'var/lib/pacman/local').is_dir(), 'existing copied package database required')


def trust_rows(rows):
    result = {name: row for name, row in rows.items()
              if any(name == prefix or name.startswith(prefix + '/') for prefix in TRUST)}
    need(result.get(TRUST[0], {}).get('type') == 'file'
         and result.get(TRUST[1], {}).get('type') == 'directory', 'base pacman configuration/trust required')
    return result


def trust_digest(rows):
    return hashlib.sha256(client.encoded(trust_rows(rows))).hexdigest()


def protected_payload(payload, policy, seed):
    units = set().union(*map(set, policy['protected_units'].values()))
    for name, value in payload.items():
        protected = any(name == p or name.startswith(p + '/') for p in TRUST + BLOCKED)
        need(not protected or value['type'] == 'directory' and seed.get(name) == value,
             'package writes protected platform/trust path')
        need(Path(name).name not in units, 'package writes protected service')


def files(alpm, policy):
    return {name: sorted('/' + path for path in alpm.owned_files([name])
                         if path.endswith(('.ko', '.ko.xz', '.ko.zst', '.ko.gz')))
            for name in policy['platform_roles']['kernel']}


def expected_base(snapshot, before):
    base = client.decode((snapshot['bundle'] / 'base.json').read_bytes())
    expected = install.package_map({row['name']: row['version'] for row in base['packages']})
    selected = {row['name']: row['version'] for row in snapshot['release']['packages']}
    need(set(before) - set(selected) == set(expected) - set(selected)
         and all(before.get(name) == version for name, version in expected.items() if name not in selected),
         'actual copied base differs from authenticated release')
    need(all(name not in before or before[name] in {expected.get(name), version}
             for name, version in selected.items()), 'selected installed version differs from release baseline')
    return selected


def public_keys(snapshot, work, signer):
    home = work / 'alpm-public'
    home.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'GNUPGHOME': str(home), 'LC_ALL': 'C'}
    (home / 'gpg.conf').write_text('no-auto-key-retrieve\nno-auto-key-import\nauto-key-locate clear\n'
                                 'disable-dirmngr\nno-autostart\nno-auto-check-trustdb\n')
    argv = ['/usr/bin/gpg', '--batch', '--no-options', '--no-autostart', '--homedir', str(home),
            '--no-auto-key-retrieve', '--disable-dirmngr']
    for extra, data in ((['--import', str(snapshot['keyring'])], None),
                        (['--import-ownertrust'], (signer + ':6:\n').encode()), (['--check-trustdb'], None)):
        result = subprocess.run(argv + extra, input=data, capture_output=True, timeout=30, env=env)
        need(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= 65536,
             'isolated public transaction keyring failed')
    secret = home / 'private-keys-v1.d'
    need(not secret.exists() or not any(secret.iterdir()), 'private key material refused')
    return home


@contextmanager
def transaction(root, keys, work):
    alpm = install.Alpm(root, keys, work / 'alpm.log', os.uname().machine)
    try:
        alpm.ok(alpm.alpm_trans_init(alpm.handle, install.FLAGS), 'transaction lock')
        alpm.started = True
        yield alpm
    finally:
        try:
            if alpm.started:
                code = alpm.alpm_trans_release(alpm.handle)
                need(code == 0, 'package-manager transaction lock release failed')
                alpm.started = False
        finally:
            if alpm.handle:
                code = alpm.alpm_release(alpm.handle)
                alpm.handle = None
                need(code == 0, 'package-manager handle release failed')


def apply(args):
    result = {'status': 'FAIL', 'phase': 'configuration', 'commit_started': False, 'packages_committed': False,
              'checkpoint_changed': False, 'scope': 'tiny-disposable-generic-root', 'target_safety': 'NOT ESTABLISHED'}
    try:
        workspace, root = Path(args.workspace), Path(args.root)
        guard(root, workspace)
        need(args.operation == 'repository-update', 'unsupported update operation')
        settings = configuration(args.settings, args.settings_sha256)
        policy_module = module('bound_platform', ROOT / 'scripts/update/platform_policy.py')
        policy = policy_module.read_policy(args.policy, args.policy_sha256)
        snapshot_module = module('bound_snapshot', ROOT / 'scripts/update/snapshot.py')
        with tempfile.TemporaryDirectory(prefix='bound-update-', dir=workspace) as temporary:
            work = Path(temporary)
            with snapshot_module.authenticated(args, work, settings) as snapshot:
                result['phase'] = 'checkpoint-lock'
                with client.state_directory(args.state_dir, True) as checkpoint:
                    now = datetime.now(timezone.utc)
                    client.validate_envelope(snapshot['metadata'], now)
                    previous_checkpoint = client.checkpoint(checkpoint)
                    client.against_state(previous_checkpoint, snapshot['metadata'],
                                         snapshot['metadata_sha256'], now, settings['minimum_sequence'])
                    keys = public_keys(snapshot, work, settings['signer'])
                    result['phase'] = 'package-manager-lock'
                    with transaction(root, keys, work) as alpm:
                        result['phase'] = 'observe-before'
                        before = alpm.inventory()
                        seed = install.tree(root)
                        need(trust_digest(seed) == settings['base_trust_sha256'], 'actual base trust differs from pinned configuration')
                        desired = expected_base(snapshot, before)
                        protected = policy_module.protected_names(policy)
                        need(not set(desired) & protected, 'release selects protected platform package')
                        preserved = {path: install.node(root / path) for path in alpm.owned_files(protected)}
                        before_files = files(alpm, policy)
                        old_paths = alpm.owned_files(set(desired) & set(before))
                        protected_paths = set(preserved) | {install.resolve_nodes(seed, path) for path in preserved}
                        old_payload = {path: install.node(root / path) for path in old_paths}
                        need(all(target not in protected_paths or node['type'] == 'directory' and seed.get(target) == node
                                 for path, node in old_payload.items()
                                 for target in {path, install.resolve_nodes(seed, path)}), 'selected package removes actual protected ownership')
                        protected_payload(old_payload, policy, seed)
                        protected_payload({install.resolve_nodes(seed, path): value
                                           for path, value in old_payload.items()}, policy, seed)
                        compare = alpm.lib.alpm_pkg_vercmp
                        compare.restype, compare.argtypes = C.c_int, [C.c_char_p, C.c_char_p]
                        need(all(name not in before or compare(version.encode(), before[name].encode()) >= 0
                                 for name, version in desired.items()), 'package downgrade refused')
                        accounting = {'bytes': 0, 'nodes': 0}
                        payload, added = {}, {}
                        result['phase'] = 'prepare'
                        rows = snapshot['release']['packages']
                        need(len(rows) <= install.MAX_PACKAGES, 'release exceeds tiny-root package limit')
                        need(sum((snapshot['bundle'] / 'repo' / row['filename']).stat().st_size
                                 + (snapshot['bundle'] / 'repo' / (row['filename'] + '.sig')).stat().st_size
                                 for row in rows) <= install.MAX_INPUTS, 'aggregate package inputs exceed tiny-root limit')
                        for row in rows:
                            path = snapshot['bundle'] / 'repo' / row['filename']
                            need(path.stat().st_size <= install.MAX_ARCHIVE, 'archive exceeds tiny-root caller limit')
                            nodes = install.archive_payload(path, accounting)
                            protected_payload(nodes, policy, seed)
                            for name, node in nodes.items():
                                need(name not in payload or node['type'] == payload[name]['type'] == 'directory', 'package payload overlap')
                                payload[name] = node
                            if before.get(row['name']) == row['version']:
                                continue
                            package = C.c_void_p()
                            alpm.ok(alpm.alpm_pkg_load(alpm.handle, os.fsencode(path), 1, 1, C.byref(package)), 'signed package load')
                            need(alpm.alpm_pkg_get_name(package).decode() == row['name']
                                 and alpm.alpm_pkg_get_version(package).decode() == row['version']
                                 and alpm.alpm_pkg_get_arch(package) in (b'any', os.uname().machine.encode()),
                                 'loaded package identity differs')
                            alpm.ok(alpm.alpm_add_pkg(alpm.handle, package), 'add authenticated package')
                            added[row['name']] = row['version']
                        projected = install.projected_paths(seed, payload)
                        protected_payload({install.resolve_nodes(projected, path): value
                                           for path, value in payload.items()}, policy, seed)
                        need(all(target not in protected_paths or node['type'] == 'directory' and seed.get(target) == node
                                 for path, node in payload.items()
                                 for target in {path, install.resolve_nodes(projected, path)}), 'selected package writes actual protected ownership')
                        need(shutil.disk_usage(workspace).free >= sum(row.get('bytes', 0) for row in projected.values())
                             + 8 * 1024**2, 'insufficient disposable transaction capacity')
                        details = install.Ptr()
                        alpm.ok(alpm.alpm_trans_prepare(alpm.handle, C.byref(details)), 'prepare immutable transaction')
                        install.check_prepared(alpm.packages(alpm.alpm_trans_get_add(alpm.handle)),
                                               alpm.packages(alpm.alpm_trans_get_remove(alpm.handle)), added, {})
                        after_expected = dict(before, **desired)
                        policy_module.authorize(policy, settings, snapshot, before, after_expected,
                                                before_files, before_files, phase='pre-transaction')
                        need(trust_rows(install.tree(root)) == trust_rows(seed), 'base trust changed before commit')
                        for path, value in preserved.items():
                            need(install.node(root / path) == value, 'protected payload changed before commit')
                        configuration(args.settings, args.settings_sha256)
                        policy_module.read_policy(args.policy, args.policy_sha256)
                        snapshot['recheck']()
                        client.validate_envelope(snapshot['metadata'], datetime.now(timezone.utc))
                        result['phase'] = 'commit'
                        result['commit_started'] = bool(added)
                        if added:
                            result['packages_committed'] = 'UNKNOWN'
                            details = install.Ptr()
                            alpm.ok(alpm.alpm_trans_commit(alpm.handle, C.byref(details)), 'commit prepared transaction')
                            result['packages_committed'] = True
                        result['phase'] = 'observe-after'
                        after = alpm.inventory()
                        install.check_inventory(after, after_expected, 'actual post-commit')
                        policy_module.authorize(policy, settings, snapshot, before, after,
                                                before_files, files(alpm, policy), phase='post-transaction')
                        need(trust_rows(install.tree(root)) == trust_rows(seed), 'base trust changed after commit')
                        for path, value in preserved.items():
                            need(install.node(root / path) == value, 'protected payload changed after commit')
                        for path, value in payload.items():
                            need(install.node(root / path) == value, 'installed payload differs')
                        result.update(before=before, after=after, phase='checkpoint')
                        metadata = snapshot['metadata']
                        value = {key: metadata[key] for key in ('scope', 'namespace', 'signer', 'sequence', 'issued_utc')}
                        value.update(schema_version=1, metadata_sha256=snapshot['metadata_sha256'],
                                     release_sha256=snapshot['release_sha256'], verified_utc=client.utc(datetime.now(timezone.utc)))
                        result['checkpoint_changed'] = 'UNKNOWN'
                        try:
                            durable = client.commit(checkpoint, value)
                        except BaseException:
                            try:
                                observed_checkpoint = client.checkpoint(checkpoint)
                                result['checkpoint_changed'] = (True if observed_checkpoint == value else
                                    False if observed_checkpoint == previous_checkpoint else 'UNKNOWN')
                            except BaseException:
                                pass
                            raise
                        result.update(checkpoint_changed=True, checkpoint_directory_synced=durable)
                        need(durable, 'packages committed but checkpoint durability uncertain')
                        result.update(status='PASS', phase='completed', prepared_add=added, prepared_remove={},
                                      release_id=settings['release_id'], release_sha256=snapshot['release_sha256'],
                                      hooks='NOT RUN', scriptlets='NOT RUN', other_operations='REFUSED')
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:256])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'workspace', 'settings', 'settings-sha256', 'policy', 'policy-sha256',
                 'bundle', 'metadata', 'signature', 'public-keyring', 'state-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--operation', default='repository-update')
    result = apply(parser.parse_args())
    print(json.dumps(result, sort_keys=True))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
