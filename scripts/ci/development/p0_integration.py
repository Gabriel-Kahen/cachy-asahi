#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze and orchestrate development-only integration in disposable native ARM containers."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import types
import tempfile

import native_arm as native
from integration_export import export_evidence, SENSITIVE_PATH, PRIVATE_CONTENT
import lifecycle_inventory
import repository_projection
import desktop_projection
from commit_image import commit_image
from package_checks import package

ROOT = native.ROOT
SOURCE_ROOTS = ('scripts', 'tests', 'packages', 'examples')
SOURCE_FILES = ('LICENSE', 'AGENTS.md', 'README.md', '.github/workflows/native-arm-build.yml')
LOCK = 'scripts/ci/integration.lock.json'
PURPOSE = 'frozen-development-only-native-integration'
CAPS = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID')
LIMIT = 64 * 1024**2
REPOSITORY_PUBLIC_LOGS = {
    'gpg-untrusted-A-status': 'signature-untrusted-A-status',
    'gpg-tampered-package-status': 'signature-tampered-package-status',
    'gpg-tampered-database-status': 'signature-tampered-database-status',
    'gpg-revoked-A-status': 'signature-revoked-A-status',
    'revoke-A-signing-home': 'revoke-A-signing-context',
    'revoke-A-verification-home': 'revoke-A-verification-context',
}
CANCEL_REQUESTED = False


class Cancelled(ValueError):
    pass


HANDOFF_CODES = {'handoff-ready', 'handoff-contract', 'handoff-container', 'handoff-originals',
                 'handoff-cleanup', 'handoff-checks', 'handoff-required-checks', 'handoff-inventory',
                 'lifecycle-stopped-container', 'lifecycle-derived-identity', 'lifecycle-config',
                 'lifecycle-test-env', 'lifecycle-derived-verification', 'lifecycle-base-user', 'lifecycle-base-workdir',
                 'handoff-installed-lock-regular', 'handoff-base-lock-regular'}
HANDOFF_CODES |= {'handoff-input-' + key.replace('_', '-') for key in
                 ('source_commit', 'lifecycle_contract_sha256', 'lifecycle_script_sha256', 'base_packages_sha256')}


class HandoffRefusal(ValueError):
    def __init__(self, code):
        need(code in HANDOFF_CODES, 'unreviewed handoff refusal code')
        self.code = code
        super().__init__(code)


def handoff_need(condition, code):
    if not condition:
        raise HandoffRefusal(code)


def interrupt(signum, frame):
    global CANCEL_REQUESTED
    CANCEL_REQUESTED = True
    raise Cancelled('integration interrupted')


@contextmanager
def defer_signals():
    def remember(signum, frame):
        global CANCEL_REQUESTED
        CANCEL_REQUESTED = True
    previous = {sig: signal.signal(sig, remember) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def terminate(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def guarded_run(cmd, log, timeout):
    process = None
    try:
        with log.open('wb') as stream:
            with defer_signals():
                process = subprocess.Popen(cmd, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            if CANCEL_REQUESTED:
                raise Cancelled('integration interrupted')
            code = process.wait(timeout=timeout)
            need(code == 0, 'component command failed; review public command log')
    finally:
        if process is not None:
            original = sys.exc_info()[0]
            cleanup = {'status': 'PASS', 'operation_error_type': original.__name__ if original else None}
            with defer_signals():
                try:
                    terminate(process)
                except (OSError, subprocess.SubprocessError, ValueError) as error:
                    cleanup.update(status='FAIL', error_type=type(error).__name__)
                native.save(log.with_suffix('.launcher.json'), cleanup)
            if original is None:
                need(cleanup['status'] == 'PASS', 'launcher process cleanup failed')


def remove_container(name):
    """Removal plus daemon-confirmed absence; failures never satisfy cleanup."""
    need(re.fullmatch(r'cachy-asahi-[a-z0-9-]+', name), 'unsafe cleanup container name')
    outcome = {'container': name, 'status': 'FAIL', 'attempts': []}
    with defer_signals():
        for _ in range(2):
            row = {}
            try:
                query = ['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']
                before = subprocess.run(query, capture_output=True, timeout=15)
                row['before_exit'] = before.returncode
                if before.returncode == 0 and before.stdout == b'':
                    row['already_absent'] = True
                    outcome.update(status='PASS' if not outcome['attempts'] else 'FAIL', absence_verified=True)
                    outcome['attempts'].append(row)
                    break
                removed = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=15)
                row['remove_exit'] = removed.returncode
                observed = subprocess.run(query, capture_output=True, timeout=15)
                row['list_exit'] = observed.returncode
                row['absence_verified'] = observed.returncode == 0 and observed.stdout == b''
                if row['absence_verified']:
                    outcome.update(status='PASS' if removed.returncode == 0 and not outcome['attempts'] else 'FAIL', absence_verified=True)
            except (OSError, subprocess.SubprocessError) as error:
                row['error_type'] = type(error).__name__
            outcome['attempts'].append(row)
            if outcome.get('absence_verified'):
                break
    return outcome


def image_config(config):
    keys = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Labels', 'Volumes', 'ExposedPorts',
            'StopSignal', 'Shell', 'Healthcheck', 'ArgsEscaped')
    result = {key: config.get(key) for key in keys}
    for key in ('Env', 'Entrypoint', 'Cmd', 'Shell'):
        result[key] = result[key] or []
    # Docker's documented empty-entrypoint reset sentinel has no executable.
    if result['Entrypoint'] == ['']:
        result['Entrypoint'] = []
    if result['Labels'] is None:
        result['Labels'] = {}
    result['WorkingDir'] = result['WorkingDir'] or '/'
    result['ArgsEscaped'] = bool(result['ArgsEscaped'])
    return result


def remove_derivative(owned, base_image):
    """Remove only this handoff's registered image/tag; ambiguous commits fail."""
    report = {'status': 'FAIL', 'absence_verified': False, 'cleanup_uncertain': not owned['reply_valid']}
    tag, image = owned.get('tag'), owned.get('image_id')
    if tag is None and image is None:
        return {'status': 'PASS', 'absence_verified': True, 'owned_image_created': False}
    need(tag is None or re.fullmatch(r'cachy-asahi-private-installed:[0-9a-f]{32}', tag), 'unreviewed recovery tag')
    need(image is None or re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'unreviewed owned image ID')
    def query(args):
        result = subprocess.run(args, capture_output=True, timeout=30)
        need(result.returncode == 0 and len(result.stdout) <= 1024**2, 'owned image query/removal failed')
        return result.stdout.decode('ascii').splitlines()
    with defer_signals():
        try:
            tagged = query(['docker', 'image', 'ls', '--no-trunc', '--quiet', '--filter', 'reference=' + tag]) if tag else []
            need(len(tagged) <= 1 and all(re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in tagged), 'owned recovery lookup invalid')
            need(base_image not in tagged and image != base_image, 'base image removal refused')
            need(not image or not tagged or tagged == [image], 'owned image/tag identity conflict')
            image = image or (tagged[0] if tagged else None)
            available = query(['docker', 'image', 'ls', '--no-trunc', '--quiet'])
            need(all(re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in available), 'image ownership query invalid')
            if image and image in available:
                # Exact ID removal removes only this derivative's private tag.
                query(['docker', 'image', 'rm', image])
                report['owned_image_id'] = image
            remaining = query(['docker', 'image', 'ls', '--no-trunc', '--quiet'])
            need(all(re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in remaining), 'image absence query invalid')
            tagged_after = query(['docker', 'image', 'ls', '--no-trunc', '--quiet', '--filter', 'reference=' + tag]) if tag else []
            report['absence_verified'] = image not in remaining and not tagged_after
            report['status'] = 'PASS' if report['absence_verified'] and not report['cleanup_uncertain'] else 'FAIL'
        except (OSError, ValueError, subprocess.SubprocessError):
            report['error'] = 'owned derivative cleanup or absence could not be verified'
    return report


def export_material(root, output, approved, metadata):
    """Explicit receipt-bound public binaries; never a generic tree exporter."""
    import sign_fixture
    total, records = 0, {}
    output.mkdir()
    for name, digest in sorted(approved.items()):
        relative(name)
        need(not any(SENSITIVE_PATH.search(part) for part in Path(name).parts), 'sensitive artifact path refused')
        source = root / name; info = regular(source)
        need(info.st_size <= 8 * 1024**2, 'public artifact too large')
        total += info.st_size; need(total <= 12 * 1024**2, 'public artifact bundle exceeds bound')
        need(native.sha(source) == native.check_pin(digest), 'public artifact differs from successful verified receipt')
        if name.endswith('.asc'):
            sign_fixture.public_certificate(source.read_bytes())
        elif name.endswith('.sig'):
            need(info.st_size <= 8192 and info.st_size > 0, 'bounded detached signature required')
            header = source.read_bytes()[0]
            need(header & 0x80 and (header & 63 if header & 0x40 else (header >> 2) & 15) == 2, 'signature packet required')
        dest = output / name; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, dest)
        need(native.sha(dest) == digest, 'public artifact changed during export')
        records[name] = {'sha256': digest, 'bytes': info.st_size}
    native.save(output / 'public-artifact-manifest.json', {'development_only': True, 'selected_for_release': False,
                'production_credentials_used': False, 'files': records, **metadata})


def need(condition, message):
    if not condition:
        raise ValueError(message)


def relative(value):
    need(isinstance(value, str) and value and '\\' not in value and
         not any(ord(c) < 32 or ord(c) > 126 for c in value), 'invalid relative source path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == value, 'unsafe relative source path')
    return path


def regular(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, f'nonregular/hardlinked input: {path.name}')
    for parent in path.parents:
        need(not parent.is_symlink(), 'symlink source ancestor')
    return info


def scan(root):
    recipe_lock = root / 'scripts/ci/recipes.lock.json'
    need(regular(recipe_lock).st_size <= 8 * 1024**2, 'recipe source lock exceeds bound')
    recipes = json.loads(recipe_lock.read_text())
    need(isinstance(recipes, dict), 'recipe source map required')
    locked = set()
    for directory, inputs in recipes.items():
        need(relative(directory).parts[0] == 'packages' and isinstance(inputs, dict), 'invalid recipe source map')
        for name, digest in inputs.items():
            relative(name); native.check_pin(digest)
            locked.add((relative(directory) / relative(name)).as_posix())
    paths = [root / name for name in SOURCE_FILES]
    for name in SOURCE_ROOTS:
        need((root / name).is_dir() and not (root / name).is_symlink(), f'missing source subtree: {name}')
        for current, dirs, files in os.walk(root / name, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != '__pycache__' and
                             not (Path(current) == root / 'scripts' and d in ('virtual', 'client', 'experiments', 'port', 'platform')) and
                             not (Path(current) == root / 'scripts/ci' and d == 'development') and
                             not (Path(current) == root / 'packages' and d in ('tools', 'libraries')))
            for directory in dirs:
                need(not (Path(current) / directory).is_symlink(), 'symlink source directory')
            for filename in sorted(files):
                path = Path(current) / filename
                name = path.relative_to(root).as_posix()
                # Archives are generated build outputs. Force-tracked historical
                # logs are inputs only when the reviewed recipe lock names them.
                if name not in locked and (filename.endswith(('.pyc', '.log')) or '.pkg.tar.' in filename):
                    continue
                paths.append(path)
    result, size = {}, 0
    for path in sorted(paths):
        name = path.relative_to(root).as_posix()
        if name == LOCK:
            continue
        relative(name)
        need(not any(p in {'.git', '.env', '.gnupg', 'private-keys-v1.d'} for p in path.relative_to(root).parts), 'private source path refused')
        info = regular(path); size += info.st_size
        need(size <= LIMIT and info.st_size <= 8 * 1024**2, 'source snapshot exceeds bound')
        result[name] = {'sha256': native.sha(path), 'mode': stat.S_IMODE(info.st_mode)}
    for name in ('fixtures', 'lifecycle', 'repository', 'onboarding', 'desktop'):
        need(f'scripts/integration/{name}.py' in result and f'scripts/integration/test_{name}.py' in result,
             f'missing integration source/tests: {name}')
    for name in ('integration', 'integration_export', 'sign_fixture', 'installed_handoff', 'source_suites', 'verify_derived', 'lifecycle_inventory', 'commit_image', 'repository_projection', 'desktop_projection'):
        need(f'scripts/ci/{name}.py' in result and f'scripts/ci/test_{name}.py' in result,
             f'missing CI adapter/source tests: {name}')
    need(locked <= result.keys(), 'reviewed recipe inputs missing from source snapshot')
    return result


def files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        need(not path.is_symlink(), 'symlink generated fixture')
        if path.is_file():
            regular(path)
            result[path.relative_to(root).as_posix()] = {'sha256': native.sha(path), 'mode': stat.S_IMODE(path.stat().st_mode)}
    return result


def require_source_snapshot(actual, expected, message):
    need(isinstance(expected, dict), 'reviewed source map required')
    if actual == expected:
        return
    groups = {'missing': sorted(set(expected) - set(actual)), 'extra': sorted(set(actual) - set(expected)),
              'changed': sorted(name for name in set(actual) & set(expected) if actual[name] != expected[name])}
    # Names only, no file contents, hashes, or absolute/private state paths.
    summary = {'counts': {key: len(names) for key, names in groups.items()}, 'path_limit': 20}
    for key, names in groups.items():
        summary[key] = []
        for name in names[:20]:
            try:
                path = relative(name)
                allowed = path.parts[0] in SOURCE_ROOTS or name in SOURCE_FILES
            except ValueError:
                allowed = False
            summary[key].append(name if allowed and len(name) <= 256 else '[unreported-path]')
    raise ValueError(message + ': ' + json.dumps(summary, sort_keys=True))


def generate(root, out, recipe_pin, source_commit, epoch):
    native.run([sys.executable, '-B', str(root / 'scripts/integration/fixtures.py'),
                '--repo', str(root), '--lock', str(root / 'scripts/ci/recipes.lock.json'),
                '--lock-sha256', recipe_pin, '--source-commit', source_commit,
                '--source-date-epoch', str(epoch), '--output', str(out)], timeout=120)


def freeze(root, output, recipe_pin, source_commit, epoch):
    native.check_pin(recipe_pin)
    need(re.fullmatch(r'[0-9a-f]{40}', source_commit or ''), 'original recipe source commit required')
    need(epoch >= 0 and not output.exists(), 'new lock and nonnegative epoch required')
    source = scan(root)
    need(source['scripts/ci/recipes.lock.json']['sha256'] == recipe_pin, 'reviewed recipe lock changed')
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-freeze-') as temporary:
        copied = Path(temporary) / 'source'
        snapshot(root, copied, source)
        generated = Path(temporary) / 'fixtures'
        generate(copied, generated, recipe_pin, source_commit, epoch)
        fixture_files = files(generated)
    need(scan(root) == source, 'integration source changed while freezing')
    native.save(output, {'schema_version': 1, 'purpose': PURPOSE, 'development_only': True,
                         'selected_for_release': False, 'recipe_source_commit': source_commit,
                         'recipes_sha256': recipe_pin, 'source_date_epoch': epoch,
                         'source_files': source, 'generated_fixture_files': fixture_files,
                         'hardware_validation': 'NOT RUN'})
    return native.sha(output)


def preflight(root, lock_path, digest, recipe_pin, epoch):
    lock = native.load_pinned(lock_path, digest)
    need(lock.get('schema_version') == 1 and lock.get('purpose') == PURPOSE and
         lock.get('development_only') is True and lock.get('selected_for_release') is False,
         'development-only integration lock required')
    need(lock.get('recipes_sha256') == recipe_pin and lock.get('source_date_epoch') == epoch,
         'integration recipe/epoch pins differ')
    need(re.fullmatch(r'[0-9a-f]{40}', lock.get('recipe_source_commit', '')), 'original recipe commit missing')
    require_source_snapshot(scan(root), lock.get('source_files'), 'integration source differs from reviewed full snapshot')
    need(isinstance(lock.get('generated_fixture_files'), dict) and bool(lock['generated_fixture_files']), 'fixture pins missing')
    for name, row in lock['generated_fixture_files'].items():
        relative(name); native.check_pin(row['sha256'])
        need(row['mode'] in (0o644, 0o755), 'unreviewed generated fixture mode')
    # All generated inputs are re-derived before any native build/system mutation.
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-preflight-') as temporary:
        copied = Path(temporary) / 'source'
        snapshot(root, copied, lock['source_files'])
        generated = Path(temporary) / 'fixtures'
        generate(copied, generated, recipe_pin, lock['recipe_source_commit'], epoch)
        need(files(generated) == lock['generated_fixture_files'], 'reviewed generated fixtures differ')
    return lock


def snapshot(root, target, source):
    target.mkdir()
    for name, row in source.items():
        relative(name)
        original = root / name; regular(original)
        need(native.sha(original) == row['sha256'], 'source drift before snapshot')
        dest = target / name; dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, dest); dest.chmod(row['mode'])
        need(native.sha(dest) == row['sha256'], 'source drift during snapshot')
    require_source_snapshot(scan(target), source, 'copied source differs')


def output_boundaries(source, native_out, cache, integration_out):
    paths = [Path(path).resolve() for path in (source, native_out, cache, integration_out)]
    need(not integration_out.exists() and not integration_out.is_symlink(), 'new integration output required')
    for index, path in enumerate(paths):
        for other in paths[index + 1:]:
            need(not path.is_relative_to(other) and not other.is_relative_to(path),
                 'source, native evidence, input cache and integration outputs must be disjoint')


def artifact(directory, name):
    receipt = json.loads((directory / 'provenance.json').read_text())
    need(receipt.get('status') == 'built-package-static-pass' and len(receipt.get('artifacts', {})) == 1,
         'successful single native artifact receipt required')
    filename, expected = next(iter(receipt['artifacts'].items()))
    need(Path(filename).name == filename, 'unsafe artifact name')
    path = directory / 'artifacts' / filename; regular(path)
    need(native.sha(path) == expected, 'native archive changed')
    report = package(path)
    need(not report['errors'] and not report['elf'] and '.INSTALL' not in report['members'], 'invalid config-only archive')
    info = report['metadata']['.PKGINFO']
    need(info.get('pkgname') == [name] and info.get('arch') == ['any'] and info.get('license') == ['MIT'], 'native archive identity differs')
    # The read-only inspector hashes regular members without filesystem extraction.
    need(all(row['type'] in ('0', '5') for row in report['members'].values()), 'nonregular overlay payload')
    payload = {member: row['sha256'] for member, row in report['members'].items()
               if row['type'] == '0' and not member.startswith('.')}
    for member in payload:
        relative(member)
    need(bool(payload), 'empty archive payload')
    return path, {'name': name, 'version': info['pkgver'][0], 'sha256': expected, 'payload_sha256': payload}


def command(image, name, binds, *, root=False, writable=False, tmpfs=None, env=None, rootcaps=None,
            repository_ldconfig=False):
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', image or ''), 'immutable local image required')
    need(type(repository_ldconfig) is bool and (not repository_ldconfig or
         (root and rootcaps is None and re.fullmatch(r'cachy-asahi-repository-[0-9a-f]{32}', name))),
         'repository ldconfig requires its dedicated root launch')
    args = ['docker', 'run', '--name', name, '--pull=never', '--platform=linux/arm64',
            '--user', '0:0' if root else f'{os.getuid()}:{os.getgid()}',
            '--network=none', '--cgroupns=private', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--pids-limit=512', '--memory=8g' if root else '--memory=4g', '--cpus=4']
    if root:
        capabilities = tuple(CAPS if rootcaps is None else rootcaps)
        need(len(capabilities) == len(set(capabilities)) and set(capabilities) <= set((*CAPS, 'KILL')), 'unreviewed root capabilities')
        if repository_ldconfig:
            capabilities += ('SYS_CHROOT',)
        for capability in capabilities:
            args += ['--cap-add=' + capability]
    if not writable:
        args.append('--read-only')
    for dest, options in (tmpfs or {}).items():
        args += ['--tmpfs', dest + ':' + options]
    for source, dest, readonly in binds:
        need(source.is_absolute() and ',' not in str(source) and '\n' not in str(source), 'unsafe mount source')
        need(dest in ('/inputs', '/runner', '/source', '/out'), 'unreviewed bind destination')
        args += ['--mount', f'type=bind,src={source},dst={dest}' + (',readonly' if readonly else '')]
    for key, value in (env or {}).items():
        args += ['--env', f'{key}={value}']
    return args + ['--entrypoint=/usr/bin/python3', image]


def execute_container(cmd, log, timeout=1800, keep=False):
    name = cmd[cmd.index('--name') + 1]
    failed = False
    cleanup = None
    try:
        guarded_run(cmd, log, timeout)
    except BaseException:
        failed = True
        raise
    finally:
        if not keep or failed:
            cleanup = remove_container(name)
            native.save(log.with_suffix('.cleanup.json'), cleanup)
            if not failed:
                need(cleanup['status'] == 'PASS', 'owned container cleanup not verified')
            if failed and cleanup['status'] != 'PASS':
                # Preserve the original exception; the separate cleanup FAIL
                # receipt records the second failure without private diagnostics.
                pass


def retain_outer_log(log, raw):
    for source, name in ((log, 'container.log'), (log.with_suffix('.cleanup.json'), 'container-cleanup.json'),
                         (log.with_suffix('.launcher.json'), 'container-launcher.json')):
        if source.is_file():
            regular(source); need(source.stat().st_size <= 4 * 1024**2, 'outer diagnostic exceeds public bound')
            shutil.copyfile(source, raw / name)


def repository_public_logs(raw, *, captured=None):
    """Bind six deliberately public producer logs; never allow a GPG state tree."""
    receipt = raw / 'result.json'
    if not receipt.exists():
        return {}
    regular(receipt)
    need(receipt.stat().st_size <= 4 * 1024**2, 'repository receipt exceeds public bound')
    result = repository_projection.strict_json(receipt.read_bytes())
    if not isinstance(result, dict) or result.get('purpose') != 'disposable-generic-repository-test':
        return {}
    projected = {}
    for row in result.get('commands', []):
        label = row.get('label')
        if label not in REPOSITORY_PUBLIC_LOGS:
            continue
        filename = row.get('log', '')
        match = re.fullmatch(r'([0-9]{3,4})-' + re.escape(label) + r'\.txt', filename)
        need(match is not None and int(match[1]) < 2048 and filename not in projected,
             'public repository status log binding invalid')
        data = repository_projection.read_public(raw, filename, native.check_pin(row.get('sha256')))
        projected[filename] = match[1] + '-' + REPOSITORY_PUBLIC_LOGS[label] + '.txt'
        if captured is not None:
            captured[filename] = (projected[filename], data)
    return projected


def safe_public(raw, public, work, *, lifecycle_authority=None, repository_authority=None, desktop_authority=None):
    """Select deliberately public owner receipts; identify every excluded binary."""
    selected = work / 'selected'; selected.mkdir()
    excluded = []
    repository_value = repository_bytes = repository_projected_bytes = None
    if repository_authority is not None:
        result_path = raw / 'result.json'; regular(result_path)
        need(result_path.stat().st_size <= 4 * 1024**2, 'repository result exceeds public bound')
        repository_bytes = result_path.read_bytes()
        repository_value = repository_projection.project(repository_bytes, *repository_authority)
    repository_captures = {}
    projections = repository_public_logs(raw, captured=repository_captures)
    operations, operation_index = ({}, None) if repository_value is None else repository_projection.operation_files(
        raw, repository_value, repository_authority[1])
    if operation_index:
        index_path = raw / 'repository-operation-aliases.json'
        need(not index_path.exists() and not index_path.is_symlink(), 'repository operation index collision')
    for name, (alias, _data) in operations.items():
        need(name not in projections and alias not in projections.values() and not (raw / alias).exists()
             and not (raw / alias).is_symlink(), 'repository public operation alias collision')
        projections[name] = alias
    repository_captures.update(operations)
    for alias, _data in repository_captures.values():
        need(not (raw / alias).exists() and not (raw / alias).is_symlink(),
             'repository projected log alias collision')
    inventories = lifecycle_inventory.projections(raw, *lifecycle_authority) if lifecycle_authority is not None else {}
    inventory_receipt = {}
    repository_receipt = None
    desktop_logs, desktop_index = desktop_projection.project(raw, desktop_authority) if desktop_authority is not None else ({}, None)
    count, total = 0, 0
    # Captures, rather than a later directory listing, define the complete set.
    # Charge every capture and every observed entry; disappearing paths receive
    # no entry refund and never suppress their validated public bytes.
    for alias, data in repository_captures.values():
        count += 1; total += len(data)
        need(count <= 2048 and len(data) <= 4 * 1024**2 and total <= 16 * 1024**2,
             'captured repository operations exceed component bounds')
        (selected / alias).write_bytes(data)
    for current, dirs, names in os.walk(raw, followlinks=False):
        for name in sorted(dirs.copy()):
            path = Path(current) / name
            need(not path.is_symlink(), 'symlink component evidence refused')
            if SENSITIVE_PATH.search(name):
                # A zero-content placeholder lets the exporter report the exact
                # refusal without enumerating/reading/hashing private contents.
                dirs.remove(name)
                (selected / path.relative_to(raw)).mkdir(parents=True, exist_ok=True)
        for name in sorted(names):
            path = Path(current) / name
            count += 1; need(count <= 2048, 'component evidence entry limit exceeded')
            relative_name = path.relative_to(raw).as_posix(); relative(relative_name)
            need(not path.is_symlink(), 'symlink component evidence refused')
            if relative_name in repository_captures:
                continue
            dest = selected / relative_name; dest.parent.mkdir(parents=True, exist_ok=True)
            if relative_name in projections:
                dest = selected / projections[relative_name]
            elif SENSITIVE_PATH.search(name):
                dest.write_bytes(b'')
                continue
            regular(path)
            if path.suffix not in ('.json', '.log', '.txt'):
                excluded.append({'path': relative_name, 'reason': 'binary test material excluded from text evidence'})
                continue
            size = path.stat().st_size; total += size
            need(size <= 4 * 1024**2 and total <= 16 * 1024**2, 'component receipt exceeds public bound')
            data = (desktop_logs[relative_name] if relative_name in desktop_logs else
                    inventories[relative_name] if relative_name in inventories else path.read_bytes())
            if relative_name == 'desktop/desktop.json' and desktop_index is not None:
                data = desktop_projection._read(raw, relative_name)
                need(len(data) == desktop_index['receipt_bytes'] and
                     hashlib.sha256(data).hexdigest() == desktop_index['receipt_sha256'], 'bound desktop receipt changed before export')
            if relative_name in desktop_logs:
                total += len(data) - size
                need(total <= 16 * 1024**2, 'projected component receipt exceeds public bound')
            if relative_name in inventories:
                row = json.loads(data)
                inventory_receipt[relative_name] = {key: row[key] for key in ('stage', 'authority', 'original_sha256', 'original_bytes', 'package_count')}
                inventory_receipt[relative_name].update(projected_sha256=hashlib.sha256(data).hexdigest(), projected_bytes=len(data))
                total += len(data) - size
                need(total <= 16 * 1024**2, 'projected component receipt exceeds public bound')
            if path.suffix == '.json':
                repository_input = relative_name == 'result.json' and repository_authority is not None
                if repository_input:
                    value = repository_value
                else:
                    value = json.loads(data)
                # Repository command args contain ephemeral TEST passphrase options.
                # Retain command identity/hash/status, never that raw keygen argv.
                if isinstance(value, dict) and value.get('purpose') == 'disposable-generic-repository-test':
                    for row in value.get('commands', []):
                        if row.get('log') in projections:
                            row['public_log'] = projections[row['log']]
                        if row.get('stderr_log') in operations:
                            row['public_stderr_log'] = projections[row['stderr_log']]
                        if 'argv' in row:
                            row['argv_sha256'] = hashlib.sha256(json.dumps(row.pop('argv'), sort_keys=True).encode()).hexdigest()
                    if operation_index:
                        value['sync_cache_reset']['public_receipt'] = projections[value['sync_cache_reset']['receipt']]
                        value['public_operation_index'] = 'repository-operation-aliases.json'
                    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
                    if relative_name == 'result.json':
                        repository_projected_bytes = data
                    if repository_input and 'base_versions' in value and not PRIVATE_CONTENT.search(data.decode('utf-8')):
                        repository_receipt = {'schema_version': 1, 'purpose': 'validated-repository-inventory-projection',
                                              'original_sha256': hashlib.sha256(repository_bytes).hexdigest(), 'original_bytes': len(repository_bytes),
                                              'projected_sha256': hashlib.sha256(data).hexdigest(), 'projected_bytes': len(data),
                                              'package_count': len(value['base_versions']), 'status_preserved': value.get('status'),
                                              'generic_content_guard': 'UNCHANGED'}
            # Rejected text remains rejected by the generic exporter, with diagnostics.
            dest.write_bytes(data)
    excluded_receipt = {'excluded': excluded, 'public_log_projection': projections, 'private_state_exported': False}
    native.save(selected / 'excluded-public-material.json', excluded_receipt)
    if inventory_receipt:
        native.save(selected / 'inventory-projections.json', {'schema_version': 1,
                    'purpose': 'validated-lifecycle-package-inventories', 'files': inventory_receipt,
                    'generic_content_guard': 'UNCHANGED', 'raw_inventory_bytes_exported': False})
    if repository_receipt:
        native.save(selected / 'repository-inventory-projection.json', repository_receipt)
    if operation_index:
        native.save(selected / 'repository-operation-aliases.json', operation_index)
    if desktop_index:
        native.save(selected / 'desktop-terminal-projections.json', desktop_index)
    operation_public = {}
    if repository_captures:
        need(repository_projected_bytes is not None, 'captured repository result missing from selected evidence')
        operation_public = {alias: data for alias, data in repository_captures.values()}
        operation_public['result.json'] = repository_projected_bytes
        operation_public['excluded-public-material.json'] = (json.dumps(excluded_receipt, indent=2, sort_keys=True) + '\n').encode()
        if operation_index:
            operation_public['repository-operation-aliases.json'] = (
                json.dumps(operation_index, indent=2, sort_keys=True) + '\n').encode()
        for alias, data in operation_public.items():
            need(repository_projection.read_public(selected, alias, hashlib.sha256(data).hexdigest()) == data,
                 'selected repository operation references incomplete')
    receipt = export_evidence(selected, public)
    need(receipt['evidence_export'] == 'PASS', 'public evidence exporter rejected component output')
    if operation_public:
        accepted = {row['path']: row for row in receipt['accepted']}
        for alias, data in operation_public.items():
            row = accepted.get(alias)
            need(row == {'path': alias, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
                 'exported repository operation reference missing from manifest')
            need(repository_projection.read_public(public, alias, row['sha256']) == data,
                 'exported repository operation reference missing or changed')


class Controller:
    def __init__(self, image, native_out, output, lock, source_commit):
        need(os.getuid() != 0 and re.fullmatch(r'[0-9a-f]{40}', source_commit or ''), 'non-root controller/accepted commit required')
        self.image, self.native_out, self.out, self.lock, self.commit = image, native_out, output, lock, source_commit
        output.mkdir()
        self.work = output / 'work'; self.work.mkdir()
        self.public = output / 'public'; self.public.mkdir()
        self.source = self.work / 'source'; snapshot(ROOT, self.source, lock['source_files'])
        self.report = {'schema_version': 1, 'purpose': PURPOSE, 'status': 'FAIL', 'source_commit': source_commit,
                       'base_image': image, 'development_only': True, 'selected_for_release': False,
                       'hardware_validation': 'NOT RUN', 'production_trust': 'NOT RUN', 'stages': {}}
        self.installed = None
        self.installed_owned = None
        self.desktop_contract = None
        self.cancelled = False

    def stage(self, name, action):
        raw = self.work / (name + '-raw'); raw.mkdir()
        staging = self.work / (name + '-export'); staging.mkdir()
        status = {'status': 'FAIL'}
        try:
            action(raw)
            if CANCEL_REQUESTED:
                raise Cancelled('integration interrupted')
            status['status'] = 'PASS'
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
            if isinstance(error, (Cancelled, KeyboardInterrupt)):
                self.cancelled = True
            status.update(error='component command or verification failed; review sanitized check records',
                          error_type=type(error).__name__)
            if isinstance(error, HandoffRefusal):
                status['refusal_code'] = error.code
        finally:
            with defer_signals():
                self.finalize_stage(name, raw, staging, status)
        return status['status'] == 'PASS'

    def finalize_stage(self, name, raw, staging, status):
        if CANCEL_REQUESTED:
            self.cancelled = True
            status.update(status='FAIL', cancelled=True)
        try:
            native.save(raw / 'component-status.json', status.copy())
            try:
                authority = None
                repository_authority = None
                if (name == 'lifecycle' and (raw / 'lifecycle').is_dir()) or (name == 'repository' and (raw / 'result.json').exists()):
                    base_lock = self.native_out / 'packages.lock'; regular(base_lock)
                    base = {}
                    for line in base_lock.read_text().splitlines():
                        columns = line.split(' ')
                        need(len(columns) == 2 and columns[0] not in base, 'invalid accepted base inventory')
                        base[columns[0]] = columns[1]
                    if name == 'lifecycle':
                        authority = (base, self.rows['baseline'], self.rows['upgrade'])
                    else:
                        repository_authority = (base, self.repository_contract)
                desktop_authority = self.desktop_contract if name == 'desktop' and (raw / 'desktop/desktop.json').exists() else None
                safe_public(raw, self.public / name, staging, lifecycle_authority=authority, repository_authority=repository_authority,
                            desktop_authority=desktop_authority)
                if name == 'fixtures' and status['status'] == 'PASS':
                    self.export_archives()
                if name == 'signer' and status['status'] == 'PASS':
                    self.export_signatures()
                if name == 'repository' and status['status'] == 'PASS':
                    self.export_repository(raw)
            except (OSError, ValueError, KeyError) as error:
                status.update(status='FAIL', export_error='public evidence selection/export failed; review rejection manifest',
                              export_error_type=type(error).__name__)
            # This controller result is separate from the manifest-bound component
            # files and states exporter failure without rewriting accepted hashes.
            if CANCEL_REQUESTED:
                self.cancelled = True
                status.update(status='FAIL', cancelled=True)
            if (self.public / name).is_dir():
                status_raw = self.work / (name + '-status'); status_raw.mkdir()
                native.save(status_raw / 'stage-status.json', status)
                need(export_evidence(status_raw, self.public / name / 'control')['evidence_export'] == 'PASS', 'controller status export failed')
            self.report['stages'][name] = status
            if name == 'lifecycle' and status['status'] != 'PASS':
                self.installed = None
            native.save(self.out / 'result.json', self.report)
        finally:
            if CANCEL_REQUESTED:
                self.cancelled = True
                status.update(status='FAIL', cancelled=True)
            self.report['stages'][name] = status
            native.save(self.out / 'result.json', self.report)

    def export_archives(self):
        # These four MIT config-only outputs were independently inspected above;
        # arbitrary binary component state never enters this explicit exporter.
        output = self.public / 'fixture-archives'; output.mkdir()
        exported = {}
        for row in self.rows['upgrade']:
            source = self.archives / row['archive']; regular(source)
            need(source.stat().st_size <= 8 * 1024**2 and native.sha(source) == row['sha256'], 'reviewed fixture archive changed before export')
            dest = output / source.name; shutil.copyfile(source, dest)
            need(native.sha(dest) == row['sha256'], 'exported fixture archive differs')
            exported[dest.name] = row['sha256']
        native.save(output / 'archive-manifest.json', {'development_only': True, 'selected_for_release': False,
                    'source_commit': self.commit, 'archives': exported, 'production_signing': 'NOT RUN'})

    def export_signatures(self):
        expected = {'public-key.asc': self.sign_receipt['public_certificate_sha256']}
        archive_bindings = {}
        for stage in ('baseline', 'upgrade'):
            for row in self.rows[stage]:
                receipt = self.sign_receipt['signatures'][row['archive']]
                need(receipt['archive_sha256'] == row['sha256'], 'verified TEST archive binding differs')
                native.valid_signature(receipt['status'], self.sign_receipt['fingerprint'])
                expected['signatures/' + row['archive'] + '.sig'] = receipt['signature_sha256']
                archive_bindings[row['archive']] = row['sha256']
        need(len(expected) == 9, 'exact TEST public certificate and eight signatures required')
        export_material(self.signed / 'public', self.public / 'signer-public-artifacts', expected,
                        {'source_commit': self.commit, 'purpose': 'TEST-ONLY-offline-signature-verification',
                         'fingerprint': self.sign_receipt['fingerprint'], 'expiry': self.sign_receipt['expiry'],
                         'archives': archive_bindings})

    def export_repository(self, raw):
        receipt = json.loads((raw / 'result.json').read_text())
        need(receipt.get('status') == 'PASS' and receipt.get('purpose') == 'disposable-generic-repository-test', 'successful TEST repository receipt required')
        labels = {'baseline-A', 'updated-B', 'tampered-package-B', 'tampered-database-B',
                  'missing-database-signature-B', 'missing-package-signature-B'}
        certs = {'TEST-signer-A-public.asc', 'TEST-signer-B-public.asc', 'TEST-verifier-public.asc',
                 'TEST-signer-A-revoked-public.asc'}
        approved = {}
        for name, digest in receipt.get('evidence_sha256', {}).items():
            path = relative(name)
            allowed = name in certs or name in ('TEST-repository-aliases.json', 'TEST-repository-aliases.json.sig', 'TEST-pacman.conf')
            if len(path.parts) == 3 and path.parts[0] == 'TEST-repositories' and path.parts[1] in labels:
                file = path.name
                db = re.fullmatch(r'integration\.(?:db|files)(?:\.tar\.(?:gz|xz|zst))?(?:\.sig)?', file)
                package = re.fullmatch(r'(?:' + '|'.join(map(re.escape, (*native.RECIPES, 'cachy-asahi-repository-test-fixture'))) +
                                      r')-[A-Za-z0-9._+:-]+\.pkg\.tar\.(?:gz|xz|zst)(?:\.sig)?', file)
                allowed = bool(db or package)
            if allowed:
                approved[name] = digest
        need(certs <= approved.keys() and 'TEST-repository-aliases.json' in approved and
             any(name.startswith('TEST-repositories/baseline-A/') for name in approved) and
             any(name.startswith('TEST-repositories/updated-B/') for name in approved), 'required offline repository public artifacts missing')
        export_material(raw, self.public / 'repository-public-artifacts', approved,
                        {'source_commit': self.commit, 'purpose': 'TEST-ONLY-offline-repository-case-verification',
                         'cases': receipt.get('cases', []), 'expected_negative_cases_retained': True})

    def fixtures(self, raw):
        self.generated = self.work / 'fixtures'
        generate(self.source, self.generated, self.lock['recipes_sha256'], self.lock['recipe_source_commit'], self.lock['source_date_epoch'])
        need(files(self.generated) == self.lock['generated_fixture_files'], 'generated fixture bytes differ from reviewed freeze')
        manifest = json.loads((self.generated / 'fixture-manifest.json').read_text())
        native.save(raw / 'fixture-manifest.json', manifest)
        self.rows, self.archives = {'baseline': [], 'upgrade': []}, self.work / 'archive-inputs'
        self.archives.mkdir()
        for name in sorted(native.RECIPES):
            record = manifest['packages'][name]
            for attempt in (1, 2):
                output = self.work / (name + f'-fixture-{attempt}')
                try:
                    guarded_run([sys.executable, '-B', str(self.source / 'scripts/build/build.py'),
                            str(self.generated / record['upgrade_recipe']), '--image', self.image, '--mode', 'native',
                            '--source-date-epoch', str(self.lock['source_date_epoch']), '--expected-packages', str(self.native_out / 'packages.lock'),
                            '--reviewed-inputs', str(self.generated / record['reviewed_inputs']['upgrade']),
                            '--timeout', '300', '--output', str(output)], raw / (name + f'-{attempt}.log'), 360)
                finally:
                    # Preserve diagnostics even when makepkg/build checks failed.
                    for filename in ('provenance.json', 'validation.json', 'build.log'):
                        path = output / filename
                        if path.exists():
                            regular(path); need(path.stat().st_size <= 4 * 1024**2, 'fixture diagnostic exceeds public bound')
                            shutil.copyfile(path, raw / (name + f'-{attempt}-' + filename))
                    if CANCEL_REQUESTED and (output / 'provenance.json').is_file():
                        provenance = json.loads((output / 'provenance.json').read_text())
                        name_owned = provenance.get('clean_environment_id')
                        if name_owned and re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name_owned):
                            native.save(raw / (name + f'-{attempt}-cleanup.json'), remove_container(name_owned))
            native.run([sys.executable, '-B', str(self.source / 'scripts/build/compare.py'),
                        str(self.work / (name + '-fixture-1')), str(self.work / (name + '-fixture-2')), '--require-bytes'],
                       raw / (name + '-compare.json'), 120)
            for stage, directory in [('baseline', self.native_out / (name + '-1')),
                                     ('upgrade', self.work / (name + '-fixture-1'))]:
                path, row = artifact(directory, name)
                expected_version = record['base_version' if stage == 'baseline' else 'upgrade_version']
                need(row['version'] == expected_version, 'fixture archive version differs from frozen manifest')
                target = self.archives / stage / path.name; target.parent.mkdir(exist_ok=True)
                shutil.copyfile(path, target); need(native.sha(target) == row['sha256'], 'archive copy drift')
                row['archive'] = target.relative_to(self.archives).as_posix(); self.rows[stage].append(row)
            old, new = self.rows['baseline'][-1], self.rows['upgrade'][-1]
            need(old['payload_sha256'] != new['payload_sha256'] and old['sha256'] != new['sha256'], 'fixture did not change installed payload')
            for expectation in record['payload_expectations']:
                need(old['payload_sha256'].get(expectation['path']) == expectation['base_sha256'] and
                     new['payload_sha256'].get(expectation['path']) == expectation['fixture_sha256'], 'fixture marker differs from reviewed expected payload')
        native.save(raw / 'archives.json', self.rows)

    def signing(self, raw):
        manifest = self.archives / 'archive-manifest.json'
        native.save(manifest, {'schema_version': 1, 'purpose': 'TEST-ONLY-integration-signatures', 'source_commit': self.commit,
                              'archives': [{k: row[k] for k in ('name', 'version', 'sha256')} |
                                           {'path': row['archive'], 'role': 'original' if stage == 'baseline' else 'upgrade-fixture'}
                                           for stage in ('baseline', 'upgrade') for row in self.rows[stage]]})
        self.signed = self.work / 'test-signatures'
        try:
            guarded_run([sys.executable, '-B', str(self.source / 'scripts/ci/sign_fixture.py'), '--image', self.image,
                    '--manifest', str(manifest), '--manifest-sha256', native.sha(manifest), '--output', str(self.signed)], raw / 'driver.log', 240)
        finally:
            for path, name in [(self.signed / 'provenance.json', 'signer-provenance.json'),
                               (self.signed / 'public/result.json', 'test-signature-receipt.json')]:
                if path.is_file():
                    shutil.copyfile(path, raw / name)
        self.sign_receipt = json.loads((self.signed / 'public/result.json').read_text())
        shutil.copyfile(self.signed / 'public/result.json', raw / 'test-signature-receipt.json')

    def lifecycle(self, raw):
        diagnostic = {'status': 'FAIL', 'phase': 'base-config-query'}
        def phase(name):
            diagnostic['phase'] = name
            native.save(raw / 'handoff-controller.json', diagnostic)
        phase('base-config-query')
        base_config = json.loads(native.run(['docker', 'image', 'inspect', self.image], timeout=60))[0]['Config']
        inputs = self.work / 'lifecycle-inputs'; shutil.copytree(self.archives, inputs)
        runner = self.work / 'lifecycle-runner'; runner.mkdir()
        for name, directory in [('lifecycle.py', 'integration'), ('installed_handoff.py', 'ci')]:
            shutil.copyfile(self.source / 'scripts' / directory / name, runner / name)
        signing = inputs / 'signing'; signing.mkdir()
        certificate = self.signed / 'public/public-key.asc'
        shutil.copyfile(certificate, signing / 'test-key.asc')
        nonce = os.urandom(16).hex()
        for stage in ('baseline', 'upgrade'):
            for row in self.rows[stage]:
                source = self.signed / 'public/signatures' / (row['archive'] + '.sig')
                target = inputs / (row['archive'] + '.sig'); shutil.copyfile(source, target)
                row['signature_sha256'] = native.sha(target)
        conf = inputs / 'pacman.conf'
        conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n'
                        f'GPGDir = /tmp/cachy-asahi-lifecycle-keyring-{nonce}\n')
        shutil.copyfile(self.native_out / 'packages.lock', inputs / 'base-packages.lock')
        contract = {'schema_version': 1, 'execution': 'native-aarch64-disposable-docker', 'allow_system_mutation': True,
                    'daemon_arch': 'aarch64', 'nonce': nonce, 'image_id': self.image, 'source_commit': self.commit,
                    'baseline_handoff': True, 'baseline': self.rows['baseline'], 'upgrade': self.rows['upgrade'],
                    'pacman_conf': 'pacman.conf', 'pacman_conf_sha256': native.sha(conf),
                    'public_cert': 'signing/test-key.asc', 'public_cert_sha256': native.sha(signing / 'test-key.asc'),
                    'signing_key_fingerprint': self.sign_receipt['fingerprint']}
        native.save(inputs / 'lifecycle.json', contract)
        commit = {'schema_version': 1, 'purpose': 'sanitized-baseline-image-handoff', 'source_commit': self.commit,
                  'lifecycle_contract_sha256': native.sha(inputs / 'lifecycle.json'), 'lifecycle_script_sha256': native.sha(runner / 'lifecycle.py'),
                  'base_packages_sha256': native.sha(inputs / 'base-packages.lock'), 'baseline': contract['baseline']}
        native.save(inputs / 'commit.json', commit)
        cmd = command(self.image, 'cachy-asahi-handoff-' + nonce,
                      [(inputs, '/inputs', True), (runner, '/runner', True), (raw, '/out', False)],
                      root=True, writable=True, rootcaps=(*CAPS, 'KILL'))
        cmd[cmd.index('--entrypoint=/usr/bin/python3')] = '--entrypoint=/usr/bin/env'
        # Identity belongs to the process environment, never committed Config.Env.
        cmd += [f'CACHY_ASAHI_DISPOSABLE_LIFECYCLE={nonce}', f'CACHY_ASAHI_IMAGE_ID={self.image}',
                '/usr/bin/python3', '-B', '/runner/installed_handoff.py', '--contract', '/inputs/commit.json',
                '--contract-sha256', native.sha(inputs / 'commit.json')]
        container = 'cachy-asahi-handoff-' + nonce
        owned = {'tag': None, 'image_id': None, 'reply_valid': False}
        self.installed_owned = owned
        def submitted(tag):
            owned['tag'] = tag
            native.save(raw / 'derivative-ownership.json', owned)
        try:
            phase('lifecycle-container')
            execute_container(cmd, raw / 'container.log', keep=True)
            receipt = json.loads((raw / 'commit-receipt.json').read_text())
            phase('handoff-receipt-verification')
            verify_commit(receipt, commit, contract, raw / 'installed-packages.lock', inputs / 'base-packages.lock')
            phase('stopped-container-query')
            observed = json.loads(native.run(['docker', 'container', 'inspect', container], timeout=60))[0]
            handoff_need(observed['State']['Status'] == 'exited' and observed['State']['ExitCode'] == 0 and observed['Image'] == self.image,
                         'lifecycle-stopped-container')
            phase('image-commit')
            derived = commit_image(container, base_config, on_submit=submitted)
            owned['reply_valid'] = True
            handoff_need(derived != self.image and re.fullmatch(r'sha256:[0-9a-f]{64}', derived), 'lifecycle-derived-identity')
            owned['image_id'] = derived
            native.save(raw / 'derivative-ownership.json', owned)
            phase('derived-image-query')
            inspect = json.loads(native.run(['docker', 'image', 'inspect', derived], timeout=60))[0]
            handoff_need(re.fullmatch(r'sha256:[0-9a-f]{64}', derived) and inspect['Id'] == derived and inspect['Architecture'] == 'arm64',
                         'lifecycle-derived-identity')
            accepted, actual = image_config(base_config), image_config(inspect['Config'])
            diagnostic['config_difference_fields'] = sorted(key for key in accepted if accepted[key] != actual[key])
            phase('derived-config-verification')
            handoff_need(not diagnostic['config_difference_fields'], 'lifecycle-config')
            handoff_need(not any(row.startswith(('CACHY_ASAHI_DISPOSABLE_LIFECYCLE=', 'CACHY_ASAHI_IMAGE_ID='))
                         for row in (inspect['Config'].get('Env') or [])), 'lifecycle-test-env')
            native.save(raw / 'committed-config.json', {'status': 'PASS', 'base_image': self.image, 'image_id': derived,
                        'accepted_base_config': image_config(base_config), 'committed_config': image_config(inspect['Config']),
                        'test_identity_in_image_env': False})
            verify_inputs = self.work / 'derived-verification-inputs'; verify_inputs.mkdir()
            shutil.copyfile(raw / 'installed-packages.lock', verify_inputs / 'installed-packages.lock')
            shutil.copyfile(self.source / 'scripts/ci/verify_derived.py', runner / 'verify_derived.py')
            native.save(verify_inputs / 'verify.json', {'image_id': derived, 'source_commit': self.commit,
                        'installed_packages_sha256': native.sha(verify_inputs / 'installed-packages.lock'),
                        'script_sha256': native.sha(runner / 'verify_derived.py'), 'baseline': contract['baseline']})
            verify_out = raw / 'committed-image'; verify_out.mkdir()
            verify_cmd = command(derived, 'cachy-asahi-derived-verify-' + nonce,
                                 [(verify_inputs, '/inputs', True), (runner, '/runner', True), (verify_out, '/out', False)],
                                 root=True)
            verify_cmd += ['-B', '/runner/verify_derived.py', '--contract-sha256', native.sha(verify_inputs / 'verify.json')]
            phase('fresh-derived-verification')
            execute_container(verify_cmd, raw / 'committed-image.log', 300)
            verified = json.loads((verify_out / 'result.json').read_text())
            handoff_need(verified.get('status') == 'PASS' and verified.get('image_id') == derived and
                         verified.get('installed_packages_sha256') == receipt['installed_packages_sha256'], 'lifecycle-derived-verification')
            self.installed = derived; self.installed_lock = raw / 'installed-packages.lock'
            shutil.copyfile(self.installed_lock, raw / 'installed-packages.txt')
            native.save(raw / 'installed-image.json', {'image_id': derived, 'base_image': self.image, 'container': container,
                                                     'owned_recovery_tag': owned['tag'],
                                                     'source_commit': self.commit, 'lock_sha256': native.sha(self.installed_lock),
                                                     'commit_receipt_sha256': native.sha(raw / 'commit-receipt.json'), 'hardware_validation': 'NOT RUN'})
            diagnostic.update(status='PASS', phase='accepted-installed-image')
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            diagnostic['error_type'] = type(error).__name__
            if isinstance(error, HandoffRefusal):
                diagnostic['refusal_code'] = error.code
            raise
        finally:
            original_failure = sys.exc_info()[0] is not None
            cleanup = remove_container(container)
            native.save(raw / 'container-removal.json', cleanup)
            if cleanup['status'] != 'PASS':
                self.installed = None
                diagnostic.update(status='FAIL', cleanup='FAIL')
            if original_failure or cleanup['status'] != 'PASS' or CANCEL_REQUESTED:
                self.installed = None
                derivative_cleanup = remove_derivative(owned, self.image)
                diagnostic.update(status='FAIL', derivative_cleanup=derivative_cleanup['status'])
            else:
                derivative_cleanup = {'status': 'RETAINED', 'image_id': owned['image_id'],
                                      'recovery_tag': owned['tag'], 'requires_final_owned_cleanup': True}
            native.save(raw / 'derivative-cleanup.json', derivative_cleanup)
            native.save(raw / 'handoff-controller.json', diagnostic)
            if cleanup['status'] != 'PASS' and not original_failure:
                need(False, 'lifecycle container removal not verified')

    def repository(self, raw):
        inputs = self.work / 'repository-inputs'; shutil.copytree(self.archives, inputs)
        runner = self.work / 'repository-runner'; runner.mkdir()
        shutil.copyfile(self.source / 'scripts/integration/repository.py', runner / 'repository.py')
        nonce = os.urandom(16).hex()
        self.repository_contract = {'schema_version': 1, 'purpose': 'disposable-generic-repository-test',
                    'execution': 'native-aarch64-disposable-docker', 'allow_system_mutation': True, 'daemon_arch': 'aarch64',
                    'nonce': nonce, 'image_id': self.image, 'source_commit': self.commit,
                    'script_sha256': native.sha(runner / 'repository.py'), 'upgrade_kind': 'synthetic-changed-package-fixtures', **self.rows}
        native.save(inputs / 'manifest.json', self.repository_contract)
        cmd = command(self.image, 'cachy-asahi-repository-' + nonce,
                      [(inputs, '/inputs', True), (runner, '/runner', True), (raw, '/out', False)], root=True,
                      repository_ldconfig=True,
                      tmpfs={'/scratch': 'rw,nosuid,nodev,exec,size=6g,mode=0700', '/test-home': 'rw,nosuid,nodev,exec,size=128m,mode=0700'},
                      env={'CACHY_ASAHI_REPOSITORY_CONTAINER': '1', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY': nonce, 'CACHY_ASAHI_IMAGE_ID': self.image})
        cmd += ['-B', '/runner/repository.py', '--inputs', '/inputs/manifest.json', '--inputs-sha256', native.sha(inputs / 'manifest.json'), '--allow-disposable-repository-test']
        try:
            execute_container(cmd, self.work / 'repository-container.log')  # /out must start empty for owner guard.
        finally:
            retain_outer_log(self.work / 'repository-container.log', raw)
        base = dict(line.split(' ', 1) for line in (self.native_out / 'packages.lock').read_text().splitlines())
        result = repository_projection.project((raw / 'result.json').read_bytes(), base, self.repository_contract)
        need(result.get('status') == 'PASS', 'repository result did not pass')

    def onboarding(self, raw):
        output = self.work / 'onboarding-owner'
        source = self.source / 'examples/development/hello.c'
        manifest = self.work / 'onboarding-baseline.json'; native.save(manifest, {'baseline': self.rows['baseline']})
        try:
            guarded_run([sys.executable, '-B', str(self.source / 'scripts/integration/onboarding.py'), '--image', self.installed,
                    '--expected-packages', str(self.installed_lock), '--expected-packages-sha256', native.sha(self.installed_lock),
                    '--baseline-manifest', str(manifest), '--baseline-manifest-sha256', native.sha(manifest),
                    '--source', str(source), '--source-sha256', native.sha(source), '--output', str(output)], raw / 'driver.log', 180)
        finally:
            for name in ('provenance.json', 'container.log'):
                if (output / name).is_file():
                    shutil.copyfile(output / name, raw / name)
            # Owner's public journey output only; private inputs/tmpfs never exported.
            if (output / 'artifacts').is_dir():
                shutil.copytree(output / 'artifacts', raw / 'artifacts')

    def desktop(self, raw):
        inputs = self.work / 'desktop-inputs'; inputs.mkdir()
        row = next(r for r in self.rows['baseline'] if r['name'] == 'cachy-asahi-hyprland-settings')
        archive = inputs / Path(row['archive']).name; shutil.copyfile(self.archives / row['archive'], archive)
        shutil.copyfile(self.native_out / 'packages.lock', inputs / 'base-packages.lock')
        runner = self.work / 'desktop-runner'; runner.mkdir()
        shutil.copyfile(self.source / 'scripts/integration/desktop.py', runner / 'desktop.py')
        nonce = os.urandom(16).hex()
        self.desktop_contract = {'source_commit': self.commit, 'image_id': self.installed, 'nonce': nonce,
                                 'archive_sha256': row['sha256'], 'runtime_lock_sha256': native.sha(self.native_out / 'packages.lock')}
        cmd = command(self.installed, 'cachy-asahi-desktop-' + nonce,
                      [(inputs, '/inputs', True), (runner, '/runner', True), (raw, '/out', False)],
                      tmpfs={'/tmp': owned_tmpfs('512m')}, env={'CACHY_ASAHI_INTEGRATION_CONTAINER': '1',
                      'CACHY_ASAHI_DISPOSABLE_DESKTOP': nonce, 'CACHY_ASAHI_IMAGE_ID': self.installed,
                      'HOME': '/tmp', 'TMPDIR': '/tmp', 'XDG_RUNTIME_DIR': '/tmp'})
        cmd += ['-B', '/runner/desktop.py', '--package', '/inputs/' + archive.name, '--package-sha256', row['sha256'],
                '--runtime-lock', '/inputs/base-packages.lock', '--output', '/out/desktop']
        execute_container(cmd, raw / 'container.log', 300)
        receipt = json.loads((raw / 'desktop/desktop.json').read_text())
        need(receipt.get('status') == 'desktop-container-verifier-pass', 'desktop software receipt did not pass')

    def suites(self, raw):
        nonce = os.urandom(16).hex()
        cmd = command(self.image, 'cachy-asahi-source-suites-' + nonce,
                      [(self.source, '/source', True), (raw, '/out', False)], tmpfs={'/tmp': owned_tmpfs('2g')},
                      env={'HOME': '/tmp/home', 'TMPDIR': '/tmp', 'XDG_RUNTIME_DIR': '/tmp', 'PYTHONDONTWRITEBYTECODE': '1'})
        cmd += ['-B', '/source/scripts/ci/source_suites.py', '--source', '/source', '--output', '/out']
        try:
            execute_container(cmd, self.work / 'source-suites-container.log')
        finally:
            retain_outer_log(self.work / 'source-suites-container.log', raw)
        receipt = json.loads((raw / 'result.json').read_text())
        need(receipt.get('source_suites') == 'PASS' and receipt.get('skipped') == 0, 'complete native source suites did not pass')

    def run(self, consumers=None, *, installer_p0_owner=None):
        """Run optional same-job consumers before final owned-image removal."""
        if installer_p0_owner is not None:
            return self.run_installer_p0(consumers,installer_p0_owner)
        previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.run_stages()
            if consumers is not None and not self.cancelled and not CANCEL_REQUESTED:
                consumers(self)
        except (Cancelled, KeyboardInterrupt):
            self.cancelled = True
        except Exception:
            self.report['controller_execution'] = 'FAIL'
        finally:
            try:
                with defer_signals():
                    self.report['owned_image_cleanup'] = remove_derivative(
                        getattr(self, 'installed_owned', None) or {'tag':None,'image_id':None,'reply_valid':True}, self.image)
                    self.installed = None
                    result = self.finish()
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
        return result

    def run_installer_p0(self, consumers, owner):
        """Real run/main frames; no broad stages or derived image mutation."""
        issuer = sys.modules.get('development_repository_handoff')
        need(type(issuer) is types.ModuleType and type(owner) is issuer.Session and
             consumers is not None,'P0-live-owner-required')
        issuer.Session.p0_controller(owner,self)
        previous = {}; first = None; result = False; cleanup_uncertain = False
        try:
            for sig in (signal.SIGTERM,signal.SIGINT):
                previous[sig] = signal.getsignal(sig)
                signal.signal(sig,interrupt)
            if self.cancelled or CANCEL_REQUESTED:raise KeyboardInterrupt()
            consumers(self)
            result = issuer.Session.p0_complete(owner,self)
        except BaseException as error:
            first = error
            if isinstance(error,KeyboardInterrupt):self.cancelled = True
        finally:
            for sig,handler in previous.items():
                try:signal.signal(sig,handler)
                except BaseException as error:
                    cleanup_uncertain = True
                    if isinstance(error,KeyboardInterrupt):self.cancelled = True
                    if first is None:first = error
            if self.cancelled or CANCEL_REQUESTED:
                if first is None:first = KeyboardInterrupt()
                else:BaseException.__setattr__(first,'native_preflight_cancelled',True)
        if first is not None:
            if cleanup_uncertain:BaseException.__setattr__(first,'native_preflight_cleanup_uncertain',True)
            raise first
        return result

    def run_stages(self):
        fixture_ok = self.stage('fixtures', self.fixtures)
        sign_ok = fixture_ok and self.stage('signer', self.signing)
        life_ok = sign_ok and self.stage('lifecycle', self.lifecycle)
        if fixture_ok and not self.cancelled:
            self.stage('repository', self.repository)
        if life_ok and self.installed and not self.cancelled:
            self.stage('onboarding', self.onboarding)
            if not self.cancelled:
                self.stage('desktop', self.desktop)
        if not self.cancelled:
            self.stage('source-suites', self.suites)
        return None

    def finish(self):
        for stage in ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites'):
            if stage not in self.report['stages']:
                self.report['stages'][stage] = {'status': 'NOT RUN', 'reason': 'required preceding stage failed'}
        self.report['status'] = 'PASS' if (not self.cancelled and not CANCEL_REQUESTED
            and self.report.get('controller_execution') != 'FAIL'
            and self.report.get('owned_image_cleanup', {}).get('status', 'PASS') == 'PASS'
            and all(r['status'] == 'PASS' for r in self.report['stages'].values())) else 'FAIL'
        self.report['cancelled'] = self.cancelled or CANCEL_REQUESTED
        native.save(self.out / 'result.json', self.report)
        summary = self.work / 'summary'; summary.mkdir(); native.save(summary / 'result.json', self.report)
        try:
            need(export_evidence(summary, self.public / 'summary')['evidence_export'] == 'PASS', 'final summary export failed')
        except (OSError, ValueError, KeyError):
            self.report.update(status='FAIL', summary_publication='FAIL',
                               error='final summary publication failed; no aggregate success accepted')
            native.save(self.out / 'result.json', self.report)
            native.save(summary / 'result.json', self.report)
            # Replace only this controller-created summary with failed contents.
            # A second infrastructure failure still leaves the private result FAIL.
            target = self.public / 'summary'
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            try:
                export_evidence(summary, target)
            except (OSError, ValueError, KeyError):
                pass
            return False
        if CANCEL_REQUESTED and self.report['status'] != 'FAIL':
            self.cancelled = True
            self.report.update(status='FAIL', cancelled=True)
            native.save(self.out / 'result.json', self.report)
            native.save(summary / 'result.json', self.report)
            replacement = self.public / 'summary-cancelled'
            need(export_evidence(summary, replacement)['evidence_export'] == 'PASS', 'cancelled summary export failed')
            shutil.rmtree(self.public / 'summary')
            replacement.rename(self.public / 'summary')
        return self.report['status'] == 'PASS'


def owned_tmpfs(size):
    return f'rw,nosuid,nodev,exec,size={size},mode=0700,uid={os.getuid()},gid={os.getgid()}'


def verify_commit(receipt, commit, contract, installed_lock, base_lock):
    """No image commit is authorized by a mere zero process exit."""
    handoff_need(receipt.get('schema_version') == 1 and receipt.get('purpose') == commit['purpose'] and receipt.get('status') == 'READY', 'handoff-ready')
    for field in ('source_commit', 'lifecycle_contract_sha256', 'lifecycle_script_sha256', 'base_packages_sha256'):
        handoff_need(receipt.get(field) == commit[field], 'handoff-input-' + field.replace('_', '-'))
    handoff_need(receipt.get('commit_contract_sha256') == hashlib.sha256((json.dumps(commit, indent=2, sort_keys=True) + '\n').encode()).hexdigest(), 'handoff-contract')
    handoff_need(receipt.get('image_id') == contract['image_id'] and receipt.get('nonce') == contract['nonce'], 'handoff-container')
    versions = {r['name']: r['version'] for r in contract['baseline']}
    payload = {r['name']: r['payload_sha256'] for r in contract['baseline']}
    handoff_need(receipt.get('package_versions') == versions and receipt.get('payload_sha256') == payload, 'handoff-originals')
    handoff_need(receipt.get('private_cleanup') == 'PASS; no private contents or hashes recorded', 'handoff-cleanup')
    checks = receipt.get('checks')
    handoff_need(isinstance(checks, list) and bool(checks) and all(r.get('status') == 'PASS' for r in checks), 'handoff-checks')
    required = {'successful-lifecycle-handoff', 'lifecycle-receipt-binding', 'exact-base-plus-originals-inventory',
                'complete-pacman-owned-payload', 'original-payload-hash', 'private-keyring-removed',
                'only-empty-alarm-home', 'system-gnupg-state-removed', 'image-tmp-view-empty'}
    handoff_need(required <= {row.get('check') for row in checks}, 'handoff-required-checks')
    for path, code in ((installed_lock, 'handoff-installed-lock-regular'), (base_lock, 'handoff-base-lock-regular')):
        try:
            regular(path)
        except (OSError, ValueError):
            raise HandoffRefusal(code) from None
    rows = dict(line.split(' ', 1) for line in base_lock.read_text().splitlines()) | versions
    expected = ''.join(f'{name} {value}\n' for name, value in sorted(rows.items()))
    handoff_need(installed_lock.read_text() == expected and receipt.get('installed_packages_sha256') == native.sha(installed_lock)
         and receipt.get('installed_package_count') == len(rows), 'handoff-inventory')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--recipes-sha256', required=True)
    parser.add_argument('--recipe-source-commit', required=True)
    parser.add_argument('--source-date-epoch', type=int, required=True)
    args = parser.parse_args()
    need(args.freeze, 'integration execution is available only through reviewed native_arm integration mode')
    print(freeze(ROOT, args.output, args.recipes_sha256, args.recipe_source_commit, args.source_date_epoch))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
