#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One real setup3→setup4 update in a complete owned copy; never a target test."""
import argparse
from contextlib import contextmanager
from functools import partial
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
from types import SimpleNamespace

NAME = 'cachy-asahi-setup'
DB = 'var/lib/pacman/local'
BEFORE = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
AFTER = 'dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'
PACKAGE = 'c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
LABEL = re.compile(r'[a-z0-9][a-z0-9+_.-]{0,127}\Z')


def need(ok, reason):
    if not ok: raise ValueError(reason)


def encoded(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
def sha(data): return hashlib.sha256(data).hexdigest()
def inventory_sha(rows): return sha(''.join(k + ' ' + v + '\n' for k, v in sorted(rows.items())).encode())


def selection(source):
    directory = Path(source) / 'scripts/ci/full-development-composition'
    values = []
    for name, pin in [('expected-updater-v2.lock', BEFORE), ('expected-setup4-v2.lock', AFTER)]:
        raw = (directory / name).read_bytes(); need(sha(raw) == pin, 'exact setup/updater-v2 lock required')
        lines = [line.split() for line in raw.decode('ascii').splitlines()]
        need(len(lines) == 587 and all(len(line) == 2 for line in lines), 'complete587 lock required')
        value = dict(lines); need(len(value) == 587, 'duplicate installed package')
        values.append(value)
    before, after = values
    need(before[NAME] == '0.1.0-3' and after == dict(before, **{NAME: '0.1.0-4'}), 'only retained setup3→4 permitted')
    need(before['cachy-asahi-update'] == after['cachy-asahi-update'] == '4.4.2-2', 'updater-v2 baseline required')
    return before, after


def relative(name):
    need(type(name) is str and bool(name) and '\0' not in name, 'invalid package path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and not {'.', '..'} & set(path.parts), 'unsafe package path')
    return name


@contextmanager
def directory(root, name):
    """Read-only database traversal; no symlink or mount substitution is accepted."""
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts, 'absolute database root required')
    need(root.resolve(strict=True) == root and not any(p.is_symlink() for p in (root, *root.parents)), 'database root alias refused')
    fds = [os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)]
    device = os.fstat(fds[0]).st_dev
    try:
        for component in relative(name).split('/'):
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
            fds.append(fd); need(os.fstat(fd).st_dev == device, 'database mount crossing refused')
        yield fds[-1]
    finally:
        for fd in reversed(fds): os.close(fd)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_ctime_ns, info.st_mtime_ns)


def read_record(parent, name, maximum=4 * 1024**2, expected=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 'bounded ordinary database record required')
        raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
             == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'database record changed')
        if expected is not None:
            actual = dict(type='file', mode=stat.S_IMODE(before.st_mode), uid=before.st_uid,
                          gid=before.st_gid, bytes=len(raw), sha256=sha(raw))
            need(actual == expected, 'database record differs from root observation')
        return raw


def fields(raw):
    result, current = {}, None
    for line in raw.decode('utf-8').splitlines():
        if not line: current = None; continue
        if re.fullmatch(r'%[A-Z0-9_]+%', line):
            current = line[1:-1]; need(current not in result, 'duplicate database field')
            result[current] = []
        else:
            need(current is not None, 'malformed database field')
            result[current].append(line)
    return result


def database(root, *, max_packages=587, max_files=1000000, max_nodes=4000000, observed=None):
    """Observe real installed desc/files records; never manufacture an inventory."""
    rows, spent = [], 0
    with directory(root, 'var/lib/pacman') as parent:
        try: os.stat('db.lck', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise ValueError('existing package-manager lock refused')
    with directory(root, DB) as local:
        before = identity(os.fstat(local)); names = sorted(os.listdir(local))
        def expected(path):
            if observed is None: return None
            need(DB + '/' + path in observed, 'database record absent from root observation')
            return observed[DB + '/' + path]
        need(len(names) <= max_packages + 1 and 'ALPM_DB_VERSION' in names, 'bounded existing local database required')
        need(read_record(local, 'ALPM_DB_VERSION', expected=expected('ALPM_DB_VERSION')) == b'9\n', 'unsupported local database version')
        for name in names:
            if name == 'ALPM_DB_VERSION': continue
            need('/' not in name and name not in ('.', '..'), 'unsafe package database directory')
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=local)
            try:
                initial = identity(os.fstat(fd))
                desc = fields(read_record(fd, 'desc', expected=expected(name + '/desc')))
                ownership_raw = read_record(fd, 'files', expected=expected(name + '/files'))
                owned = fields(ownership_raw)
                need(all(len(desc.get(key, [])) == 1 for key in ('NAME', 'VERSION', 'ARCH')), 'installed package identity missing')
                package, version, arch = (desc[key][0] for key in ('NAME', 'VERSION', 'ARCH'))
                need(LABEL.fullmatch(package) and 0 < len(version) <= 128 and not any(c.isspace() or c == '\0' for c in version), 'invalid installed identity')
                need(name == package + '-' + version and arch in ('aarch64', 'any'), 'installed directory/architecture differs')
                # ALPM writes a present, zero-byte files record for metapackages.
                paths = owned.get('FILES', [] if ownership_raw == b'' else None)
                need(type(paths) is list, 'installed ownership missing: ' + package)
                need(len(paths) <= max_files, 'package ownership bound')
                need(len(paths) == len(set(paths)), 'duplicate installed ownership')
                for path in paths: relative(path[:-1] if path.endswith('/') else path)
                files = [path for path in paths if not path.endswith('/')]
                spent += len(files); need(spent <= max_nodes, 'aggregate package ownership bound')
                rows.append(dict(name=package, version=version, arch=arch, depend=desc.get('DEPENDS', []),
                                 provides=desc.get('PROVIDES', []), conflict=desc.get('CONFLICTS', []), files=files))
                need(initial == identity(os.fstat(fd)) == identity(os.stat(name, dir_fd=local, follow_symlinks=False)), 'database package directory changed')
            finally: os.close(fd)
        need(before == identity(os.fstat(local)) and names == sorted(os.listdir(local)), 'database changed during observation')
    need(len({row['name'] for row in rows}) == len(rows), 'duplicate installed package')
    return sorted(rows, key=lambda row: row['name'])


def ownership(packages, nodes, runtime):
    owners, protected, kernels = {}, set(), []
    for package in packages:
        module_paths = []
        for name in package['files']:
            need(name not in owners, 'overlapping installed file ownership')
            owners[name] = package['name']
            parent, _, leaf = name.rpartition('/')
            resolved = runtime.resolve_nodes(nodes, parent)
            actual = resolved + '/' + leaf if resolved else leaf
            need(actual in nodes and nodes[actual]['type'] != 'directory', 'package-owned payload absent from supplied root: ' + name)
            if package['name'] != NAME: protected.add(actual)
            if name.startswith('usr/lib/modules/') and name.endswith(('.ko', '.ko.xz', '.ko.zst', '.ko.gz')): module_paths.append('/' + name)
        if module_paths: kernels.append(package['name'])
    need(kernels, 'actual package-owned kernel modules required')
    return protected, sorted(kernels)


def preserved(before, after, protected):
    old, new = DB + '/' + NAME + '-0.1.0-3', DB + '/' + NAME + '-0.1.0-4'
    def prefix(name, base): return name == base or name.startswith(base + '/')
    def held_db(nodes): return {n: v for n, v in nodes.items() if prefix(n, DB) and not any(prefix(n, x) for x in (old, new))}
    def users(nodes): return {n: v for n, v in nodes.items() if any(prefix(n, x) for x in ('home', 'root'))}
    need(any(v.get('type') == 'file' for v in users(before).values()), 'actual user-file baseline not exercised')
    need(held_db(before) == held_db(after), 'nonselected database changed')
    need(users(before) == users(after), 'user files changed')
    need({n: before[n] for n in protected} == {n: after.get(n) for n in protected}, 'protected package file changed')
    return {'nonselected_database': 'PRESERVED', 'user_files': 'PRESERVED', 'protected_payload': 'PRESERVED',
            'protected_nodes': len(protected), 'user_nodes': len(users(before))}


def committed(result, before, after):
    need(result.get('status') == 'PASS', 'existing bound/runtime update did not pass')
    need(all(result.get(key) is True for key in ('commit_started', 'packages_committed', 'checkpoint_changed', 'checkpoint_directory_synced')), 'real committed durable update required')
    need(result.get('before') == before and result.get('after') == after, 'actual before/after inventory differs')
    need(result.get('prepared_add') == {NAME: '0.1.0-4'} and result.get('prepared_remove') == {}, 'exact single prepared setup upgrade required')


def write(path, value):
    with Path(path).open('xb') as stream: stream.write(encoded(value))


def run(args, *, runtime_module, copy_module, constructor, prepare_copy=None):
    """One owned copy lifetime; Root supplies reviewed/frozen implementation paths."""
    scale, bound = runtime_module.scale, runtime_module.scale.bound
    result = dict(status='FAIL', phase='selection', commit_started=False, packages_committed=False,
                  checkpoint_changed=False, scope='actual-copied-root-generic-setup-upgrade', hardware='NOT RUN',
                  apple_acceptance='NOT ESTABLISHED', copy_cleanup='NOT RUN')
    copy_report, delegated = {}, False
    try:
        before, after = selection(args.source_root)
        config = scale.configuration(args.scale, args.scale_sha256)
        need(config['platform_mode'] == 'generic-development' and config['before_lock_sha256'] == BEFORE
             and config['after_lock_sha256'] == AFTER, 'explicit actual updater-v2→setup4 scale selection required')
        data = bound.install.private(Path(args.data), os.geteuid())
        need(not any(data.iterdir()), 'fresh driver data directory required')
        workspace, source = Path(args.workspace), Path(args.source)
        need(not data.is_relative_to(workspace) and not workspace.is_relative_to(data)
             and not data.is_relative_to(source) and not source.is_relative_to(data), 'driver data/copy/source overlap refused')
        need(type(args.copy_seconds) is int and 0 < args.copy_seconds <= 3600, 'finite copy deadline required')
        limits = config['limits']
        copy_limits = scale.roots.Limits(deadline=time.monotonic() + args.copy_seconds,
            max_nodes=limits['root_nodes'], max_bytes=limits['root_bytes'], max_file_bytes=limits['file_bytes'],
            max_package_files=limits['package_files'])
        result['phase'] = 'copy'
        with copy_module.copied_root(source, workspace, limits=copy_limits) as (root, copy_report):
            need(copy_report['copy']['copy_complete'] is True and copy_report['copy']['excluded'] == []
                 and copy_report['copy'].get('copy_byte_identical_before_initialization') is True,
                 'complete byte-identical supplied-source copy required')
            result['copy'] = dict(copy_report['copy'])
            result['initial_copy_byte_identical'] = copy_report['copy']['copy_byte_identical_before_initialization']
            args.root = str(root); bound.guard(root, workspace)
            need(prepare_copy is not None, 'reviewed copied-root initialization API required before updater baseline')
            # Root supplies Tools' separately reviewed one-time initialization.
            # It runs after byte-preserving copy and before ANY update baseline.
            result['phase'] = 'copied-root-initialization'
            result['initialization'] = prepare_copy(args, config)
            need(type(result['initialization']) is dict and result['initialization'].get('status') == 'PASS'
                 and result['initialization'].get('root_initialized') is True
                 and result['initialization'].get('source_preserved') is True,
                 'one-shot copied-root initialization did not pass')
            runtime = runtime_module.Runtime(args, config)
            result['phase'] = 'baseline'
            nodes = runtime.tree(root)  # The selected Runtime's eligibility stays enforced.
            result['prepared_root_baseline'] = 'ESTABLISHED-after-one-shot-initialization'
            need(any((name.startswith('home/') or name.startswith('root/')) and node['type'] == 'file'
                     for name, node in nodes.items()), 'actual user-file baseline required before commit')
            packages = database(root, max_files=limits['package_files'], max_nodes=limits['root_nodes'], observed=nodes)
            actual = {p['name']: p['version'] for p in packages}
            need(actual == before, 'actual root is not initial signed587/updater-v2 checkpoint')
            protected, kernels = ownership(packages, nodes, runtime)
            base = data / 'base.json'
            write(base, dict(schema_version=1, snapshot_id='inventory-sha256:' + BEFORE,
                             target_arch='aarch64', kind='complete-target-transaction', packages=packages))
            result['phase'] = 'construct-test-repository'
            release = constructor.construct(args, base=base, protected=sorted(set(before) - {NAME}), output=data / 'release-inputs')
            need(release.get('status') not in ('REFUSED_API_CONTRACT', 'FAIL'),
                 'TEST repository construction refused: ' + str(release.get('stage_blockers', release.get('error', 'unknown'))))
            for field in ('bundle', 'metadata', 'signature', 'public_keyring'): setattr(args, field, str(release[field]))
            generic = runtime.policy_module
            policy = dict(schema_version=1, purpose='cachy-asahi-generic-development-update-policy',
                release_id=release['release_id'], protected_packages=sorted(set(before) - {NAME}),
                protected_versions={k: v for k, v in before.items() if k != NAME}, platform_roles={'kernel': kernels},
                protected_units={k: sorted(v) for k, v in generic.asahi.REQUIRED_UNITS.items()},
                before_lock_sha256=BEFORE, after_lock_sha256=AFTER)
            args.policy = str(data / 'policy.json'); write(args.policy, policy); args.policy_sha256 = sha(Path(args.policy).read_bytes())
            generic.read_policy(args.policy, args.policy_sha256)
            args.state_dir = str(data / 'state'); Path(args.state_dir).mkdir(mode=0o700)
            settings = dict(schema_version=1, purpose='disposable-generic-bound-update', namespace=args.namespace,
                release_synthetic=False,
                signer=release['signer'], minimum_sequence=args.sequence, release_id=release['release_id'],
                repo_name=release['repo_name'], metadata_sha256=sha(Path(args.metadata).read_bytes()),
                release_sha256=sha((Path(args.bundle) / 'release.json').read_bytes()),
                public_keyring_sha256=sha(Path(args.public_keyring).read_bytes()), base_trust_sha256=bound.trust_digest(nodes),
                model='generic-development-only', running_kernel_release='NOT-HARDWARE-OBSERVED', operations=['repository-update'])
            args.settings = str(data / 'settings.json'); write(args.settings, settings); args.settings_sha256 = sha(Path(args.settings).read_bytes())
            args.operation = 'repository-update'; args.measure_only = False
            need(runtime.tree(root) == nodes, 'root changed while constructing TEST repository')
            result['prepared_root_preserved_during_repository_construction'] = True
            result.update(phase='update', commit_started='UNKNOWN', packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN')
            delegated = True
            update = runtime_module.apply(args)  # Checked scale/schema/guard/bound entry.
            result['update'] = update
            for key in ('commit_started', 'packages_committed', 'checkpoint_changed'): result[key] = update.get(key, 'UNKNOWN')
            committed(update, before, after)
            result['phase'] = 'preservation'
            observer = runtime_module.Runtime(args, config)
            final = observer.tree(root)
            need({p['name']: p['version'] for p in database(root, max_files=limits['package_files'],
                 max_nodes=limits['root_nodes'], observed=final)} == after, 'postcommit actual database differs')
            result['preservation'] = preserved(nodes, final, protected)
            result['restoration'] = 'DISPOSAL-selected; no downgrade or live-root restoration attempted'
            result['phase'] = 'copy-cleanup'
        result['copy_cleanup'] = copy_report.get('cleanup', 'UNKNOWN')
        need(result['copy_cleanup'] == 'PASS-owned-workspace-removed', 'owned copy disposal not confirmed')
        result.update(status='PASS', phase='completed', committed_transactions=1,
                      before_sha256=BEFORE, after_sha256=AFTER, selected_archive_sha256=PACKAGE)
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:512],
                      copy_cleanup=copy_report.get('cleanup', 'UNKNOWN' if result['phase'] != 'selection' else 'NOT RUN'))
        if delegated: result['recovery'] = 'dispose outer owned container on any cleanup/worker uncertainty'
    return result


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module


def connect(runtime, initializer, comparator_path, *, auxiliary_runtime=False):
    """Bind the exact supplied Tools APIs; strict Runtime remains an explicit route."""
    comparator = Path(comparator_path)
    need(comparator.is_absolute() and '..' not in comparator.parts, 'explicit comparator path required')
    kwargs = {'comparator_path': comparator} if auxiliary_runtime else {}
    api = SimpleNamespace(scale=runtime.scale, Runtime=partial(runtime.Runtime, **kwargs),
                          apply=partial(runtime.apply, **kwargs))
    def prepare_copy(args, config):
        return initializer.initialize(args, Path(args.source), comparator_path=comparator)
    return api, prepare_copy


def worker_result(row):
    if row['termination'] is None and row['returncode'] in (0, 1):
        try:
            value = json.loads(row['stdout'])
            need(type(value) is dict and value.get('status') in ('PASS', 'FAIL')
                 and all(key in value for key in ('commit_started', 'packages_committed', 'checkpoint_changed')),
                 'incomplete worker result')
            return value
        except (ValueError, TypeError): pass
    return dict(status='FAIL', phase='driver-worker', termination=row['termination'],
        commit_started='UNKNOWN', packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN',
        recovery='dispose outer owned container; no rollback or lock-file removal attempted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'runtime', 'runtime-sha256', 'initializer', 'initializer-sha256', 'comparator',
                 'source', 'workspace', 'data', 'scale', 'scale-sha256',
                 'setup4-pair', 'package', 'provenance', 'gpg-home', 'signer', 'release-id', 'repo-name', 'namespace',
                 'issued-utc', 'expires-utc'):
        parser.add_argument('--' + name, required=True)
    for name in ('copy-seconds', 'seconds', 'sequence'): parser.add_argument('--' + name, type=int, required=True)
    parser.add_argument('--supported-models', nargs='*', default=[])
    parser.add_argument('--auxiliary-runtime', action='store_true', help='Use selected aux_runtime Runtime/apply with the pinned comparator')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    for name in ('source_root', 'runtime', 'initializer', 'comparator', 'source', 'workspace', 'data', 'scale',
                 'setup4_pair', 'package', 'provenance', 'gpg_home'):
        path = Path(getattr(args, name))
        need(path.is_absolute() and '..' not in path.parts, 'explicit absolute driver paths required')
    root = Path(args.source_root).resolve(strict=True)
    sys.path.insert(0, str(root / 'scripts/update'))
    modules = []
    for label in ('runtime', 'initializer'):
        path = Path(getattr(args, label))
        need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024
             and sha(path.read_bytes()) == getattr(args, label + '_sha256'), 'exact selected ' + label + ' source required')
        modules.append(load('root_upgrade_' + label, path))
    runtime, initialize = connect(*modules, args.comparator, auxiliary_runtime=args.auxiliary_runtime)
    if args.worker:
        copy = load('root_upgrade_copy', root / 'scripts/update/aux_copy.py')
        constructor = load('root_upgrade_constructor', Path(__file__).with_name('construct_repository.py'))
        value = run(args, runtime_module=runtime, copy_module=copy, constructor=constructor, prepare_copy=initialize)
    else:
        need(0 < args.seconds <= 7200, 'finite total driver deadline required')
        row = runtime.scale.supervision.run([sys.executable, '-B', str(Path(__file__).resolve()), *sys.argv[1:], '--worker'],
            env=dict(os.environ), cwd=str(root), timeout=args.seconds, output_limit=2 * 1024**2)
        value = worker_result(row)
    print(json.dumps(value, sort_keys=True))
    return int(value['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
