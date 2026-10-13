#!/usr/bin/env python3
"""Independent development consumers of the accepted native 341-package builder.

These adapters never install onto the host or change initial integration status.
Only explicit owner receipts and reviewed GPL/package/experiment material are
public. Native/hardware acceptance requires actual execution, never these tests.
"""
import gzip
import hashlib
import io
import importlib.util
import json
import math
import os
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import re
import signal
import shlex
import stat
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import urllib.request

from common import (base_prerequisite, check_deadline, command, copy_regular, digest,
                    read_json, read_regular, require, save as common_save, CleanupFailure)

KSM = 'cachy-asahi-ksmctl'
KSM_PIN = 'f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44'
ARM_PIN = '8e0d982e136f8f1c79bebbeca8448f48a8466e95dbb8695042e7528a26f731ca'
EXPORT_PIN = '1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c'
ZLIB_URL = 'https://zlib.net/zlib-1.3.2.tar.gz'
ZLIB_SHA = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
ZLIB_SIZE = 1502830
# Selected bytes independently audited from the exact ZLIB_SHA archive.
ARM_README_SHA = '4026d921213bb2e311d8d42b44ef53361c102d5d45ae32f93f8e52eaee8d068f'
ARM_LICENSE_SHA = 'e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2'
EPOCH = 1791748800
PIN = re.compile(r'[0-9a-f]{64}\Z')
TEXT_LIMIT = 4 * 1024**2
PAYLOAD = {'usr/bin/' + KSM: 'cachy-asahi-ksmctl',
           'usr/share/doc/' + KSM + '/README.md': 'README.md',
           'usr/share/doc/' + KSM + '/source-provenance.json': 'source-provenance.json',
           'usr/share/licenses/' + KSM + '/NOTICE': 'NOTICE',
           'usr/share/licenses/' + KSM + '/LICENSE': 'LICENSE'}
PACMAN_METADATA = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
ARM_FILES = {'arm_c01.py', 'corpus.py', 'test_arm_c01.py', 'test_corpus.py', 'stage.py', 'test_stage.py'}


def deadline_options(deadline):
    return {} if deadline is None else {'deadline': deadline}


def failed(result, code, **fields):
    result.update(status='FAIL', **fields)
    result.setdefault('error_code', code)


def retain(output, result, *, deadline=None):
    try:
        finish(output, result, **deadline_options(deadline))
    except Exception:
        failed(result, 'adapter-retention-failed')


def stream_bytes(source, maximum, *, deadline=None):
    chunks, size = [], 0
    while size <= maximum:
        check_deadline(deadline)
        data = source.read(min(65536, maximum + 1 - size))
        check_deadline(deadline)
        if not data:
            break
        chunks.append(data); size += len(data)
    return b''.join(chunks)


def regular(path, limit=TEXT_LIMIT, *, deadline=None):
    check_deadline(deadline); path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit
            and all(not p.is_symlink() for p in path.parents), 'nonregular-or-unbounded-input')
    return info


def relative(name):
    require(isinstance(name, str) and name and '\\' not in name and len(name) <= 256, 'unsafe-receipt-path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name and name != '.'
            and all(32 <= ord(c) < 127 for c in name), 'unsafe-receipt-path')
    return path


def load_module(path, name, *, deadline=None):
    check_deadline(deadline); regular(path, **deadline_options(deadline))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    check_deadline(deadline)
    return module


def checker(root, *, deadline=None):
    check_deadline(deadline); return load_module(root / 'scripts/checks/package_checks.py', 'development_package_checks', **deadline_options(deadline))


def start(controller, root, output, stage, *, deadline=None):
    check_deadline(deadline); root, output = Path(root), Path(output)
    require(root.is_absolute() and root.is_dir() and all(not p.is_symlink() for p in (root, *root.parents)), 'unsafe-source-root')
    require(output.is_absolute() and '..' not in output.parts and not output.exists() and not output.is_symlink()
            and all(not p.is_symlink() for p in output.parents), 'new-safe-output-required')
    for other in (root, Path(controller.native_out)):
        check_deadline(deadline); require(not output.is_relative_to(other) and not other.is_relative_to(output), 'output-boundary-overlap')
    prerequisite = base_prerequisite(controller, **deadline_options(deadline))
    require(prerequisite.get('status') == 'PASS' and prerequisite.get('package_count') == 341
            and prerequisite.get('image_id') == controller.image, 'accepted-native-base-required')
    output.mkdir(mode=0o700, parents=True)
    return root, output, {'stage': stage, 'status': 'FAIL', 'prerequisite': prerequisite, 'public': [],
                          'hardware_validation': 'NOT RUN', 'performance_acceptance': 'NOT RUN',
                          'selected_for_release': False, 'installation': 'NOT RUN'}


def save(path, value, *, deadline=None):
    if deadline is None:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    else:
        common_save(path, value, deadline=deadline)


def finish(output, result, *, deadline=None):
    check_deadline(deadline)
    if output is not None:
        status = output / 'adapter-status'; status.mkdir(exist_ok=True)
        result['public'] = list(dict.fromkeys([*result['public'], str(status)]))
        save(status / 'result.json', result, **deadline_options(deadline))
        save(output / 'result.json', result, **deadline_options(deadline))
    return result


def verify_export(directory, allow_failure=False, *, deadline=None):
    check_deadline(deadline); regular(directory / 'export-manifest.json', **deadline_options(deadline))
    manifest = read_json(directory / 'export-manifest.json', **deadline_options(deadline))
    require(manifest.get('evidence_export') in ('PASS', 'FAIL') and isinstance(manifest.get('rejected'), list), 'owner-public-export-failed')
    if not allow_failure:
        require(manifest['evidence_export'] == 'PASS' and manifest['rejected'] == [], 'owner-public-export-failed')
    rows = manifest.get('accepted')
    require(isinstance(rows, list) and len(rows) <= 2048, 'owner-public-manifest-invalid')
    names = set()
    policy = public_policy(**deadline_options(deadline))
    require(not policy.PRIVATE_CONTENT.search(json.dumps(manifest, sort_keys=True)), 'owner-public-manifest-refused')
    for row in rows:
        check_deadline(deadline); name = str(relative(row['path']))
        require(not any(policy.SENSITIVE_PATH.search(part) for part in PurePosixPath(name).parts)
                and Path(name).suffix.lower() in policy.SUFFIXES, 'owner-public-path-refused')
        require(name not in names and name != 'export-manifest.json' and PIN.fullmatch(row['sha256']), 'owner-public-manifest-invalid')
        path = directory / name
        data = read_regular(path, TEXT_LIMIT, **deadline_options(deadline))
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'owner-public-file-drift')
        text = data.decode('utf-8')
        require(not policy.PRIVATE_CONTENT.search(text) and not any(ord(c) < 32 and c not in '\n\r\t' for c in text),
                'owner-public-content-refused')
        names.add(name)
    actual = set()
    for path in directory.rglob('*'):
        check_deadline(deadline); require(not path.is_symlink(), 'owner-public-symlink')
        if path.is_file():
            regular(path, **deadline_options(deadline))
            actual.add(path.relative_to(directory).as_posix())
        else:
            require(path.is_dir(), 'owner-public-special-file')
    require(actual == names | {'export-manifest.json'}, 'owner-public-extra-or-missing-file')
    return manifest


def public_policy(*, deadline=None):
    check_deadline(deadline); exporter = Path(__file__).resolve().parents[3] / 'scripts/ci/integration_export.py'
    require(digest(exporter, **deadline_options(deadline)) == EXPORT_PIN, 'public-exporter-drift')
    return load_module(exporter, 'development_public_policy', **deadline_options(deadline))


def text_public(root, selected, output, *, deadline=None):
    check_deadline(deadline); exporter = root / 'scripts/ci/integration_export.py'
    require(digest(exporter, **deadline_options(deadline)) == EXPORT_PIN, 'public-exporter-drift')
    result = load_module(exporter, 'development_text_exporter', **deadline_options(deadline)).export_evidence(selected, output)
    verify_export(output, allow_failure=True, **deadline_options(deadline))
    return result['evidence_export'] == 'PASS'


def ksm_recipe(root, *, deadline=None):
    check_deadline(deadline); path = root / 'manifests/reviewed/ksmctl.json'; regular(path, **deadline_options(deadline))
    require(digest(path, **deadline_options(deadline)) == KSM_PIN, 'ksm-reviewed-map-drift')
    reviewed = read_json(path, **deadline_options(deadline))
    require(isinstance(reviewed, dict) and len(reviewed) == 15, 'ksm-map-invalid')
    recipe = root / 'packages/tools' / KSM
    report = checker(root, **deadline_options(deadline)).recipe(recipe / 'PKGBUILD')
    require(not report['errors'] and report['input_sha256'] == reviewed, 'ksm-recipe-drift')
    for name, pin in reviewed.items():
        check_deadline(deadline); relative(name); require(PIN.fullmatch(pin), 'ksm-map-invalid')
        regular(recipe / name, **deadline_options(deadline))
        require(digest(recipe / name, **deadline_options(deadline)) == pin, 'ksm-recipe-drift')
    return recipe, reviewed


def verify_ksm_attempt(root, attempt, reviewed, prerequisite, *, deadline=None):
    check_deadline(deadline); record = read_json(attempt / 'provenance.json', **deadline_options(deadline))
    require(record.get('status') == 'built-package-static-pass' and record.get('mode') == 'native'
            and record.get('image') == record.get('image_id') == prerequisite['image_id']
            and record.get('recipe_inputs') == reviewed and record.get('source_date_epoch') == EPOCH
            and record.get('expected_packages_sha256') == prerequisite['packages_sha256'], 'ksm-build-binding-failed')
    validation = read_json(attempt / 'validation.json', **deadline_options(deadline))
    require(validation.get('errors') == [] and len(validation.get('artifacts', [])) == 1, 'ksm-static-validation-failed')
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    files = record.get('files', {})
    require(isinstance(files, dict) and required <= files.keys(), 'ksm-build-evidence-missing')
    for name, pin in files.items():
        check_deadline(deadline); path = attempt / str(relative(name)); regular(path, 8 * 1024**2, **deadline_options(deadline))
        require(PIN.fullmatch(pin) and digest(path, **deadline_options(deadline)) == pin, 'ksm-build-evidence-drift')
    for name in ('expected-packages.lock', 'artifacts/packages.lock'):
        check_deadline(deadline); require(digest(attempt / name, **deadline_options(deadline)) == prerequisite['packages_sha256'], 'ksm-inventory-drift')
    for name, pin in reviewed.items():
        check_deadline(deadline); path = attempt / 'inputs' / name; regular(path, **deadline_options(deadline))
        require(digest(path, **deadline_options(deadline)) == pin, 'ksm-recipe-snapshot-drift')
    artifacts = record.get('artifacts', {})
    require(isinstance(artifacts, dict) and len(artifacts) == 1, 'ksm-single-archive-required')
    name, pin = next(iter(artifacts.items()))
    require(re.fullmatch(r'cachy-asahi-ksmctl-0\.1\.0-1-any\.pkg\.tar\.(?:xz|zst|gz)', name), 'ksm-archive-name-refused')
    archive = attempt / 'artifacts' / name; regular(archive, 8 * 1024**2, **deadline_options(deadline))
    require(digest(archive, **deadline_options(deadline)) == pin, 'ksm-archive-drift')
    actual = {p.name for p in (attempt / 'artifacts').glob('*.pkg.tar.*')}
    require(actual == {name}, 'ksm-extra-archive-refused')
    validate_ksm_package(root, archive, reviewed, **deadline_options(deadline))
    return archive.name, pin


def validate_ksm_package(root, archive, reviewed, *, deadline=None):
    check_deadline(deadline); package = checker(root, **deadline_options(deadline)).package(archive)
    check_deadline(deadline)
    require(not package['errors'] and not package['elf'], 'ksm-package-inspection-failed')
    info, buildinfo = package['metadata']['.PKGINFO'], package['metadata']['.BUILDINFO']
    for key, value in {'pkgname': [KSM], 'pkgver': ['0.1.0-1'], 'arch': ['any'],
                       'license': ['GPL-2.0-or-later'], 'depend': ['python>=3.11']}.items():
        check_deadline(deadline); require(info.get(key) == value, 'ksm-package-metadata-failed')
    require(buildinfo.get('pkgbuild_sha256sum') == [reviewed['PKGBUILD']], 'ksm-package-recipe-binding-failed')
    members = package['members']
    require('.INSTALL' not in members and all(row['type'] in ('0', '5') and row['uid'] == row['gid'] == 0
                                             for row in members.values()), 'ksm-package-node-refused')
    files = {name for name, row in members.items() if row['type'] == '0'}
    require(files == set(PAYLOAD) | PACMAN_METADATA, 'ksm-package-file-allowlist-failed')
    directories = {str(parent) for name in files for parent in PurePosixPath(name).parents}
    for name, row in members.items():
        check_deadline(deadline)
        if row['type'] == '5':
            require(name in directories and row['mode'] == 0o755, 'ksm-package-directory-refused')
        elif name in PACMAN_METADATA:
            require(row['mode'] == 0o644, 'ksm-package-metadata-mode-refused')
    payload = {name: members[name] for name in PAYLOAD}
    for name, row in payload.items():
        check_deadline(deadline); require(row['sha256'] == reviewed[PAYLOAD[name]] and row['mode'] == (0o755 if name.startswith('usr/bin/') else 0o644), 'ksm-package-payload-failed')


def build_container_command(root, attempt, image, name):
    return ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform', 'linux/arm64',
            '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--read-only', '--pids-limit', '512', '--memory', '4g', '--cpus', '4', '--network', 'none',
            '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g', '--env', 'CACHY_ASAHI_CONTAINER=1',
            '--env', 'SOURCE_DATE_EPOCH=' + str(EPOCH),
            '--mount', f'type=bind,src={attempt / "inputs"},dst=/inputs,readonly',
            '--mount', f'type=bind,src={attempt / "artifacts"},dst=/out',
            '--mount', f'type=bind,src={root / "scripts/build/container-entry.sh"},dst=/builder-entry.sh,readonly',
            '--mount', f'type=bind,src={attempt / "expected-packages.lock"},dst=/expected-packages.lock,readonly',
            '--entrypoint', '/bin/bash', image, '/builder-entry.sh']


def cleanup_endpoint(root, *, deadline=None):
    check_deadline(deadline); return 'unix://' + load_module(root / 'scripts/ci/commit_image.py', 'development_local_endpoint', **deadline_options(deadline)).local_endpoint()


@contextmanager
def defer_cleanup(first_failure=None, cleanup_errors=None):
    events = []
    signals = {signal.SIGTERM, signal.SIGINT}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    previous = {}
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, lambda *_: events.append(True))
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield events
    finally:
        original, errors = sys.exc_info()[1], []
        def attempt(call):
            try:
                call()
            except BaseException as error:
                errors.append(error)
        attempt(lambda: signal.pthread_sigmask(signal.SIG_BLOCK, signals))
        for sig, handler in previous.items():
            attempt(lambda sig=sig, handler=handler: signal.signal(sig, handler))
        try:
            pending = (signal.sigpending() & signals) - mask
        except BaseException as error:
            errors.append(error); pending = set()
        for sig in pending:
            try:
                signal.sigwait({sig}); events.append(True)
            except BaseException as error:
                errors.append(error)
        attempt(lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
        if cleanup_errors is not None:
            cleanup_errors.extend(errors)
        if errors and original is None and first_failure is None:
            if not isinstance(errors[0], Exception):
                raise errors[0]
            if cleanup_errors is None:
                raise CleanupFailure() from errors[0]


def cleanup_ksm(root, output, image, *, deadline=None):
    """Bind recorded owner argv and observed identity before deleting a container.

    The owner writes provenance before Docker run. No provenance means no
    submitted container. Cleanup never derives ownership from a loose prefix.
    """
    check_deadline(deadline)
    report = {'status': 'PASS', 'containers': [], 'phase_seconds_limit': 120}
    phase_end = time.monotonic() + 120
    if deadline is not None:
        phase_end = min(phase_end, deadline)
    endpoint = None
    directory = output / 'cleanup'
    directory.mkdir()
    for number in (1, 2):
        row = {'attempt': number, 'status': 'FAIL', 'absence_verified': False}
        query, listing = None, None
        try:
            check_deadline(deadline)
            attempt = output / ('attempt-' + str(number))
            path = attempt / 'provenance.json'
            if not path.exists() and not path.is_symlink():
                row.update(status='PASS', absence_verified=True, submitted=False)
                report['containers'].append(row)
                continue
            record = read_json(path, **deadline_options(deadline))
            name = record.get('clean_environment_id')
            require(isinstance(name, str) and re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'ksm-cleanup-ownership-invalid')
            require(record.get('image_id') == image and record.get('image') == image
                    and record.get('command') == build_container_command(root, attempt, image, name), 'ksm-cleanup-ownership-invalid')
            row.update(container=name, submitted=True)
            if endpoint is None:
                endpoint = cleanup_endpoint(root, **deadline_options(deadline))
                require(endpoint in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock'), 'ksm-cleanup-endpoint-invalid')
            prefix = ['docker', '--host', endpoint]
            def query(label, args):
                check_deadline(deadline)
                remaining = phase_end - time.monotonic()
                # Reserve common's five-second drain grace and ten-second reap.
                require(remaining > 15, 'ksm-cleanup-deadline')
                log = directory / (str(number) + '-' + label + '.json')
                require(command(prefix + args, log, min(15, remaining - 15), cleanup_grace=5, **deadline_options(deadline)) == 0, 'ksm-cleanup-query-failed')
                regular(log, **deadline_options(deadline))
                return log
            listing = ['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']
            before = read_regular(query('before', listing), **deadline_options(deadline)).decode().strip()
            if not before:
                row.update(status='PASS', absence_verified=True)
            else:
                require(re.fullmatch(r'[0-9a-f]{12,64}', before), 'ksm-cleanup-list-invalid')
                observed = read_json(query('inspect', ['container', 'inspect', name, '--format',
                    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"mounts":{{json .Mounts}}}']), **deadline_options(deadline))
                identity = observed.get('id')
                require(isinstance(identity, str) and re.fullmatch(r'[0-9a-f]{64}', identity)
                        and identity.startswith(before) and observed.get('name') == '/' + name and observed.get('image') == image,
                        'ksm-cleanup-identity-invalid')
                expected = {'/inputs': (str(attempt / 'inputs'), False), '/out': (str(attempt / 'artifacts'), True),
                            '/builder-entry.sh': (str(root / 'scripts/build/container-entry.sh'), False),
                            '/expected-packages.lock': (str(attempt / 'expected-packages.lock'), False)}
                actual, targets = {}, set()
                for mount in observed.get('mounts', []):
                    check_deadline(deadline); target = mount.get('Destination')
                    require(target not in targets, 'ksm-cleanup-mount-invalid'); targets.add(target)
                    if mount.get('Type') == 'tmpfs' and target == '/tmp' and mount.get('RW') is True:
                        continue
                    require(mount.get('Type') == 'bind' and type(mount.get('RW')) is bool, 'ksm-cleanup-mount-invalid')
                    actual[target] = (mount.get('Source'), mount['RW'])
                require(actual == expected, 'ksm-cleanup-mount-invalid')
                removal_ok = False
                try:
                    removed = query('remove', ['container', 'rm', '-f', identity])
                    removal_ok = read_regular(removed, **deadline_options(deadline)).decode().strip() == identity
                finally:
                    row['absence_verified'] = read_regular(query('after', listing), **deadline_options(deadline)).decode().strip() == ''
                require(removal_ok and row['absence_verified'], 'ksm-cleanup-removal-or-absence-failed')
                row.update(status='PASS', container_id=identity)
        except Exception:
            row['error_code'] = 'ksm-owned-cleanup-failed'
            if endpoint is not None and row.get('submitted') and query is not None and listing is not None:
                try:
                    row['absence_verified'] = read_regular(query('final-absence', listing), **deadline_options(deadline)).decode().strip() == ''
                except Exception:
                    pass
        report['containers'].append(row)
        if row['status'] != 'PASS':
            report['status'] = 'FAIL'
    return report


def run_ksm(controller, root, output, *, deadline=None):
    result = {'stage': 'ksm', 'status': 'FAIL', 'prerequisite': {'status': 'NOT RUN'}, 'public': []}
    owned, first_failure = None, None
    try:
        root, owned, result = start(controller, root, output, 'ksm', **deadline_options(deadline))
        recipe, reviewed = ksm_recipe(root, **deadline_options(deadline))
        inputs = owned / 'inputs'; inputs.mkdir()
        review = inputs / 'reviewed-inputs.json'; save(review, reviewed, **deadline_options(deadline))
        public_material = owned / 'public-material'; public_material.mkdir()
        source = public_material / 'source'; source.mkdir()
        for name, pin in reviewed.items():
            check_deadline(deadline); copy_regular(recipe / name, source / name, **deadline_options(deadline))
            require(digest(source / name, **deadline_options(deadline)) == pin, 'ksm-public-source-drift')
        artifacts = {}
        def material_receipt():
            save(public_material / 'manifest.json', {'license': 'GPL-2.0-or-later', 'reviewed_sources': reviewed,
                 'artifacts': artifacts, 'image_id': controller.image, 'source_commit': controller.commit,
                 'source_date_epoch': EPOCH, 'development_only': True, 'selected_for_release': False}, **deadline_options(deadline))
        material_receipt()
        result['public'].append(str(public_material))
        selected = owned / 'selected'; selected.mkdir()
        environments = []
        for number in (1, 2):
            check_deadline(deadline); attempt = owned / ('attempt-' + str(number))
            code = command([sys.executable, '-B', str(root / 'scripts/build/build.py'), str(recipe),
                     '--image', controller.image, '--mode', 'native', '--network', 'none',
                     '--source-date-epoch', str(EPOCH), '--expected-packages', result['prerequisite']['packages_lock'],
                     '--reviewed-inputs', str(review), '--timeout', '300', '--output', str(attempt)],
                    owned / ('attempt-' + str(number) + '-driver.log'), 360, **deadline_options(deadline))
            require(code == 0, 'ksm-build-command-failed')
            name, pin = verify_ksm_attempt(root, attempt, reviewed, result['prerequisite'], **deadline_options(deadline))
            environments.append(read_json(attempt / 'provenance.json', **deadline_options(deadline))['clean_environment_id'])
            dest = public_material / ('attempt-' + str(number)); dest.mkdir()
            copy_regular(attempt / 'artifacts' / name, dest / name, **deadline_options(deadline))
            require(digest(dest / name, **deadline_options(deadline)) == pin, 'ksm-public-archive-drift')
            artifacts[str(number)] = {'filename': name, 'sha256': pin}
            material_receipt()
        require(environments[0] and environments[0] != environments[1], 'ksm-independent-environments-required')
        comparison = owned / 'compare.json'
        code = command([sys.executable, '-B', str(root / 'scripts/build/compare.py'), str(owned / 'attempt-1'),
                 str(owned / 'attempt-2'), '--require-bytes'], comparison, 120, **deadline_options(deadline))
        require(code == 0, 'ksm-comparison-command-failed')
        compared = read_json(comparison, **deadline_options(deadline))
        require(compared.get('status') == 'contents-reproduced' and compared.get('errors') == []
                and set(compared.get('packages', {})) == {artifacts['1']['filename']}, 'ksm-rebuild-comparison-failed')
        require(all(compared['packages'][artifacts['1']['filename']].get(key) is True for key in
                    ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')), 'ksm-rebuild-comparison-failed')
        require(artifacts['1'] == artifacts['2'], 'ksm-rebuilt-bytes-differ')
        result['status'] = 'PASS'
    except KeyboardInterrupt as error:
        first_failure = error
        failed(result, 'ksm-cancelled', cancelled=True)
        raise
    except Exception as error:
        first_failure = error
        failed(result, 'stage-deadline-exceeded' if str(error) == 'stage-deadline-exceeded' else 'ksm-stage-failed')
    finally:
        if owned is not None:
            cleanup_errors = []
            with defer_cleanup(first_failure, cleanup_errors) as events:
                try:
                    cleanup = cleanup_ksm(root, owned, controller.image, **deadline_options(deadline))
                except Exception:
                    cleanup = {'status': 'FAIL', 'error_code': 'ksm-owned-cleanup-failed', 'absence_verified': False}
                if events:
                    cleanup.update(status='FAIL', cancelled=True)
                result['cleanup'] = cleanup
                if cleanup['status'] != 'PASS':
                    failed(result, 'ksm-owned-cleanup-failed')
                try:
                    save(owned / 'cleanup-result.json', cleanup, **deadline_options(deadline))
                except Exception:
                    failed(result, 'ksm-publication-failed')
                # Retain explicit partial driver/build diagnostics even after failure.
                try:
                    selected = owned / 'selected'; selected.mkdir(exist_ok=True)
                    for number in (1, 2):
                        check_deadline(deadline); attempt = owned / ('attempt-' + str(number))
                        for name in ('provenance.json', 'validation.json', 'build.log'):
                            check_deadline(deadline); path = attempt / name
                            if path.exists():
                                copy_regular(path, selected / ('attempt-' + str(number) + '-' + name), **deadline_options(deadline))
                        path = owned / ('attempt-' + str(number) + '-driver.log')
                        if path.exists():
                            copy_regular(path, selected / path.name, **deadline_options(deadline))
                    if (owned / 'compare.json').exists():
                        copy_regular(owned / 'compare.json', selected / 'compare.json', **deadline_options(deadline))
                    copy_regular(owned / 'cleanup-result.json', selected / 'cleanup-result.json', **deadline_options(deadline))
                    public = owned / 'public'; exported = text_public(root, selected, public, **deadline_options(deadline))
                    result['public'].append(str(public))
                    if not exported:
                        failed(result, 'ksm-publication-failed')
                except Exception:
                    failed(result, 'ksm-publication-failed')
                retain(owned, result, deadline=deadline)
                if events:
                    failed(result, 'ksm-cancelled', cancelled=True)
                    retain(owned, result, deadline=deadline)
            if cleanup_errors:
                result['cleanup'].update(status='FAIL', error_code='stage-cleanup-failed')
                failed(result, 'stage-cleanup-failed')
                retain(owned, result, deadline=deadline)
            try:
                check_deadline(deadline)
            except Exception:
                failed(result, 'stage-deadline-exceeded')
                retain(owned, result, deadline=deadline)
            if events:
                failed(result, 'ksm-cancelled', cancelled=True)
                retain(owned, result, deadline=deadline)
                if first_failure is not None and not isinstance(first_failure, Exception):
                    raise first_failure
                raise KeyboardInterrupt()
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise ValueError('zlib-redirect-refused')


def open_zlib(url, timeout):
    return urllib.request.build_opener(NoRedirect()).open(url, timeout=timeout)


@contextmanager
def fetch_registration():
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
    original = None
    try:
        yield
    except BaseException as error:
        original = error
        raise
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        except BaseException:
            if original is None:
                raise


@contextmanager
def zlib_clock(started, deadline):
    """Bound DNS/headers/stream framing by the existing fetch90 and caller J."""
    if deadline is None:
        yield
        return
    check_deadline(deadline)
    require(signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, []), 'zlib-fetch-alarm-unavailable')
    prior_timer = signal.getitimer(signal.ITIMER_REAL)
    prior_handler = signal.getsignal(signal.SIGALRM)
    entered = time.monotonic()
    end = min(started + 90, deadline)
    prior_end = entered + prior_timer[0] if prior_timer[0] else None
    if prior_end is not None and prior_handler != signal.SIG_IGN:
        end = min(end, prior_end)
    def expired(signum, frame):
        now = time.monotonic()
        if prior_end is not None and now >= prior_end and callable(prior_handler):
            prior_handler(signum, frame)
        raise ValueError('stage-deadline-exceeded' if now >= deadline else 'zlib-fetch-timeout')
    require(end > time.monotonic(), 'zlib-fetch-timeout')
    signal.signal(signal.SIGALRM, expired)
    body_error = None
    try:
        signal.setitimer(signal.ITIMER_REAL, max(.000001, end - time.monotonic()))
        check_deadline(deadline)
        yield
        check_deadline(deadline)
    except BaseException as error:
        body_error = error
        raise
    finally:
        errors = []
        for restore in (lambda: signal.setitimer(signal.ITIMER_REAL, 0),
                        lambda: signal.signal(signal.SIGALRM, prior_handler)):
            try:
                restore()
            except BaseException as error:
                errors.append(error)
        if prior_timer[0]:
            remaining = prior_end - time.monotonic()
            if remaining <= 0 and prior_timer[1]:
                remaining = prior_timer[1] - (-remaining % prior_timer[1])
            try:
                signal.setitimer(signal.ITIMER_REAL, max(.000001, remaining), prior_timer[1])
            except BaseException as error:
                errors.append(error)
        if errors and body_error is None:
            raise errors[0]


def fetch_zlib(cache, *, deadline=None):
    check_deadline(deadline); cache = Path(cache)
    require(cache.is_absolute() and cache.is_dir() and all(not p.is_symlink() for p in (cache, *cache.parents)), 'unsafe-zlib-cache')
    cached = cache / 'zlib-1.3.2.tar.gz'
    if cached.exists() or cached.is_symlink():
        require(regular(cached, ZLIB_SIZE, **deadline_options(deadline)).st_size == ZLIB_SIZE and digest(cached, **deadline_options(deadline)) == ZLIB_SHA, 'cached-zlib-drift')
        return cached
    descriptor, path, target, identity = None, None, None, None
    try:
        with fetch_registration():
            check_deadline(deadline)
            descriptor, name = tempfile.mkstemp(prefix='zlib-1.3.2-', suffix='.tar.gz', dir=cache)
            path = Path(name)
            created = os.fstat(descriptor)
            identity = (created.st_dev, created.st_ino)
        started = time.monotonic()
        remaining = check_deadline(deadline)
        with fetch_registration():
            check_deadline(deadline)
            target = os.fdopen(descriptor, 'wb')
            descriptor = None  # Transfer once, while owner signals are blocked.
        with zlib_clock(started, deadline):
            source, body_error = None, None
            try:
                source = open_zlib(ZLIB_URL, timeout=min(15, remaining) if remaining is not None else 15)
                require(source.geturl() == ZLIB_URL and source.status == 200, 'zlib-origin-refused')
                length = source.headers.get('Content-Length')
                require(length is None or length == str(ZLIB_SIZE), 'zlib-size-refused')
                size = 0
                while True:
                    check_deadline(deadline); require(time.monotonic() - started <= 90, 'zlib-fetch-timeout')
                    if deadline is not None:
                        timeout = min(15, 90 - (time.monotonic() - started), check_deadline(deadline))
                        require(timeout > 0, 'zlib-fetch-timeout')
                        # The selected urllib HTTP response's socket; inert fixtures use the same shape.
                        source.fp.raw._sock.settimeout(timeout)
                    read = source.read if deadline is None else source.read1
                    data = read(min(65536, ZLIB_SIZE + 1 - size))
                    check_deadline(deadline)
                    if not data:
                        break
                    size += len(data); require(size <= ZLIB_SIZE, 'zlib-size-refused')
                    target.write(data)
            except BaseException as error:
                body_error = error
                raise
            finally:
                errors = []
                resources, target = (source, target), None
                for resource in resources:
                    if resource is not None:
                        try:
                            resource.close()
                        except BaseException as error:
                            errors.append(error)
                if errors and body_error is None:
                    if not isinstance(errors[0], Exception):
                        raise errors[0]
                    raise CleanupFailure() from errors[0]
        require(regular(path, ZLIB_SIZE, **deadline_options(deadline)).st_size == ZLIB_SIZE and digest(path, **deadline_options(deadline)) == ZLIB_SHA, 'zlib-pin-refused')
        return path
    except BaseException:
        # Keep the first business/control refusal and attempt each owned disposal.
        if target is not None:
            try:
                target.close()
            except BaseException:
                pass
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException:
                pass
        if path is not None and identity is not None:
            try:
                observed = path.lstat()
                if (observed.st_dev, observed.st_ino) == identity:
                    path.unlink()
            except BaseException:
                pass
        raise


def arm_lock(root, *, deadline=None):
    check_deadline(deadline); path = root / 'scripts/experiments/stage.lock.json'; regular(path, **deadline_options(deadline))
    require(digest(path, **deadline_options(deadline)) == ARM_PIN, 'arm-source-lock-drift')
    lock = read_json(path, **deadline_options(deadline))
    require(set(lock.get('source_files', {})) == ARM_FILES and lock.get('source_sha256') == ZLIB_SHA,
            'arm-source-envelope-invalid')
    for name, row in lock['source_files'].items():
        check_deadline(deadline); path = root / 'scripts/experiments' / name
        require(regular(path, **deadline_options(deadline)).st_mode & 0o777 == row['mode'] and digest(path, **deadline_options(deadline)) == row['sha256'], 'arm-source-drift')
    exporter = lock['exporter']
    require(exporter == {'path': 'scripts/ci/integration_export.py', 'sha256': EXPORT_PIN, 'mode': 0o644}
            and digest(root / exporter['path'], **deadline_options(deadline)) == EXPORT_PIN and regular(root / exporter['path'], **deadline_options(deadline)).st_mode & 0o777 == 0o644,
            'arm-exporter-drift')
    return root / 'scripts/experiments/stage.lock.json'



def arm_policy(*, deadline=None):
    """Import only the exact reviewed ARM helper and corpus; never execute a trial."""
    check_deadline(deadline); root = Path(__file__).resolve().parents[3]
    lock = read_json(arm_lock(root, **deadline_options(deadline)), **deadline_options(deadline))
    previous = sys.modules.get('corpus')
    try:
        sys.modules['corpus'] = load_module(root / 'scripts/experiments/corpus.py', 'development_arm_corpus', **deadline_options(deadline))
        return load_module(root / 'scripts/experiments/arm_c01.py', 'development_arm_policy', **deadline_options(deadline)), lock
    finally:
        if previous is None:
            sys.modules.pop('corpus', None)
        else:
            sys.modules['corpus'] = previous


def arm_json(data):
    def unique(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'arm-duplicate-json-field'); value[key] = item
        return value
    def finite(value):
        number = float(value)
        require(math.isfinite(number), 'arm-nonfinite-json'); return number
    return json.loads(data, object_pairs_hook=unique, parse_float=finite,
                      parse_constant=lambda _: require(False, 'arm-nonfinite-json'))


def arm_read_json(path, *, deadline=None):
    check_deadline(deadline); value = arm_json(read_regular(path, **deadline_options(deadline)))
    check_deadline(deadline)
    require(isinstance(value, dict), 'arm-json-object-required')
    return value


def verify_arm_evidence(public, manifest, retained, controller, prerequisite, receiver, *, deadline=None):
    """Check the public recorded graph and retained strict bytes, without replay."""
    check_deadline(deadline); arm, lock = arm_policy(**deadline_options(deadline))
    native = arm_read_json(public / 'native-result.json', **deadline_options(deadline))
    contract = native.get('contract', {})
    launcher = arm_read_json(public / 'launcher-result.json', **deadline_options(deadline))
    require(launcher.get('purpose') == arm.PURPOSE and launcher.get('status') == 'PASS'
            and launcher.get('image') == controller.image and launcher.get('contract') == contract
            and launcher.get('controller_group_cleanup') == launcher.get('container_cleanup') == 'PASS'
            and launcher.get('receiver_verification') == receiver and not launcher.get('cancelled')
            and launcher.get('hardware_validation') == launcher.get('performance_acceptance') == 'NOT RUN'
            and launcher.get('selected_for_release') is False, 'arm-launcher-receipt-failed')
    require(contract.get('purpose') == arm.PURPOSE and contract.get('source_commit') == controller.commit
            and contract.get('image') == controller.image and contract.get('source_sha256') == ZLIB_SHA
            and contract.get('packages_sha256') == prerequisite['packages_sha256']
            and contract.get('runner_sha256') == lock['source_files']['arm_c01.py']['sha256']
            and contract.get('corpus_sha256') == lock['source_files']['corpus.py']['sha256'], 'arm-native-contract-failed')
    require(native.get('status') == 'PASS' and native.get('purpose') == arm.PURPOSE
            and native.get('cleanup') == 'PASS' and native.get('selected_for_release') is False
            and native.get('hardware_validation') == native.get('performance_acceptance') == 'NOT RUN'
            and native.get('reproducibility') == {'baseline': 'PASS', 'lto': 'PASS'}, 'arm-native-result-failed')
    require(set(manifest) == {'purpose', 'development_only', 'selected_for_release', 'source_commit', 'source_sha256',
            'image_id', 'hardware_validation', 'performance_acceptance', 'scope', 'files', 'member_count',
            'strict_driver_evidence', 'uncompressed_bytes', 'bundle_sha256', 'bundle_bytes'}, 'arm-artifact-fields-failed')
    require(manifest.get('purpose') == 'ARM-C01-same-job-followup' and manifest.get('development_only') is True
            and manifest.get('selected_for_release') is False
            and manifest.get('hardware_validation') == manifest.get('performance_acceptance') == 'NOT RUN', 'arm-artifact-scope-failed')
    require(retained['strict-gzip.c'] == arm.STRICT_DRIVER
            and native.get('strict_driver_source_sha256') == arm.STRICT_SHA, 'arm-strict-source-failed')
    environment = arm_read_json(public / 'environment.json', **deadline_options(deadline))
    require(digest(public / 'environment.json', **deadline_options(deadline)) == native.get('environment_sha256') == receiver.get('environment_sha256'), 'arm-environment-binding-failed')
    arm.guard(environment['observed'], contract['nonce'])
    require(environment.get('kernel', {}).get('system') == 'Linux'
            and environment['kernel'].get('machine') in ('aarch64', 'arm64')
            and type(environment.get('page_size')) is int and environment['page_size'] >= 4096
            and not environment['page_size'] & (environment['page_size'] - 1), 'arm-native-environment-failed')
    require(isinstance(environment.get('kernel', {}).get('release'), str) and environment['kernel']['release']
            and isinstance(environment.get('python'), str) and environment['python']
            and isinstance(environment.get('zlib_runtime'), str) and environment['zlib_runtime'], 'arm-environment-fields-failed')
    tools = environment.get('tool_files', {})
    require(set(tools) == set(arm.TOOLS), 'arm-environment-tools-failed')
    for row in tools.values():
        check_deadline(deadline); path = PurePosixPath(row['path'])
        require(set(row) == {'path', 'sha256'} and path.is_absolute() and path.is_relative_to('/usr')
                and '..' not in path.parts and PIN.fullmatch(row['sha256']), 'arm-environment-tool-pin-failed')
    require(hashlib.sha256(retained['corpus/heldout-source.bin']).hexdigest() == ARM_README_SHA, 'arm-source-readme-failed')
    for prefix in ('baseline-1', 'baseline-2', 'lto-1', 'lto-2'):
        check_deadline(deadline); require(hashlib.sha256(retained[prefix + '/LICENSE.txt']).hexdigest() == ARM_LICENSE_SHA, 'arm-source-license-failed')
    corpus = arm_read_json(public / 'corpus-manifest.json', **deadline_options(deadline))
    require(retained['corpus/manifest.json'] == read_regular(public / 'corpus-manifest.json', **deadline_options(deadline))
            and manifest['files']['corpus/manifest.json'] == native.get('corpus_manifest_sha256'), 'arm-corpus-binding-failed')
    with tempfile.TemporaryDirectory(prefix='cachy-arm-public-corpus-') as temporary:
        expected = arm.corpus.create(Path(temporary) / 'corpus', retained['corpus/heldout-source.bin'])
        check_deadline(deadline)
        require(corpus == expected, 'arm-corpus-generator-failed')
        for path in (Path(temporary) / 'corpus').iterdir():
            check_deadline(deadline); require(retained['corpus/' + path.name] == read_regular(path, **deadline_options(deadline)), 'arm-corpus-bytes-failed')
    plans = arm.command_plan(corpus)
    commands = arm_json(read_regular(public / 'commands.json', **deadline_options(deadline)))
    require(isinstance(commands, list) and len(commands) == len(plans) == 505, 'arm-command-count-failed')
    bindings = {'/tmp/corpus/' + row['path']: {'path': '/tmp/corpus/' + row['path'], 'sha256': row['sha256'], 'bytes': row['bytes']} for row in corpus['files']}
    by_name, original = {}, {}
    for number, (row, plan) in enumerate(zip(commands, plans), 1):
        check_deadline(deadline); require(all(row.get(key) == plan[key] for key in ('name', 'argv', 'cwd', 'environment'))
                and row.get('status') == row.get('cleanup') == 'PASS' and not row.get('cancelled'), 'arm-command-plan-failed')
        code = row.get('exit_code')
        codes = [2] if plan['reject'] else list(range(1, 256)) if plan['sample'] else [0, 1] if plan['observe'] else [0]
        require(type(code) is int and code in codes and row.get('allowed_exit_codes') == codes, 'arm-command-exit-failed')
        name = f"{number:03d}-" + plan['name'] + '.log'
        projected = name.replace('-dependencies.log', '-link-inputs.log')
        require(row.get('producer_log') == name and row.get('log') == projected, 'arm-command-log-name-failed')
        data = read_regular(public / projected, TEXT_LIMIT, **deadline_options(deadline))
        require(type(row.get('log_bytes')) is int and len(data) == row['log_bytes']
                and hashlib.sha256(data).hexdigest() == row.get('log_sha256'), 'arm-command-log-failed')
        require(row.get('stdin') == (None if plan['source'] is None else bindings.get(plan['source']))
                and (plan['source'] is None or plan['source'] in bindings), 'arm-command-stdin-failed')
        output = row.get('stdout')
        if plan['target'] is None:
            require(output is None, 'arm-command-stdout-failed')
        else:
            require(isinstance(output, dict) and set(output) == {'path', 'sha256', 'bytes'}
                    and output['path'] == plan['target'] and PIN.fullmatch(output['sha256'])
                    and type(output['bytes']) is int and 0 <= output['bytes'] <= 32 * 1024**2
                    and plan['target'] not in bindings, 'arm-command-stdout-failed')
            bindings[plan['target']] = output
            if plan['reject'] or plan['name'].endswith('-strict-valid'):
                data = retained[Path(plan['target']).name]
                require(len(data) == output['bytes'] and hashlib.sha256(data).hexdigest() == output['sha256'], 'arm-strict-output-failed')
        by_name[plan['name']] = row
        original[plan['name']] = {**row, 'log': name}
    expected = {'launcher-result.json', 'launcher-container.log', 'native-result.json', 'environment.json', 'corpus-manifest.json'}
    expected |= {row['log'] for row in commands}
    configs = {prefix + '/' + name for prefix in ('baseline-1', 'baseline-2', 'lto-1', 'lto-2')
               for name in ('LICENSE.txt', 'Makefile.txt', 'zconf.h.txt', 'configure.log.txt')}
    expected |= configs
    projection = arm_read_json(public / 'projection.json', **deadline_options(deadline))
    require(projection == {'purpose': 'ARM-C01-same-job-followup', 'raw_binary_and_corpus_exported': False,
            'files': {name: digest(public / name, **deadline_options(deadline)) for name in expected}}, 'arm-projection-binding-failed')
    require({path.relative_to(public).as_posix() for path in public.rglob('*') if path.is_file()}
            == expected | {'commands.json', 'projection.json', 'export-manifest.json'}, 'arm-public-selector-failed')
    for name in configs:
        check_deadline(deadline); require(read_regular(public / name, **deadline_options(deadline)) == retained[name], 'arm-public-config-drift')
    require(hashlib.sha256(read_regular(public / by_name['inventory']['log'], **deadline_options(deadline))).hexdigest() == prerequisite['packages_sha256'], 'arm-observed-inventory-failed')
    builds = native.get('builds', [])
    require([(row['variant'], row['attempt']) for row in builds] == [(v, n) for v in ('baseline', 'lto') for n in (1, 2)], 'arm-build-set-failed')
    drivers = []
    keys = ('name', 'argv', 'cwd', 'environment', 'exit_code', 'log', 'log_sha256', 'log_bytes')
    for build in builds:
        check_deadline(deadline); prefix = f"{build['variant']}-{build['attempt']}"
        cflags, ldflags = arm.build_flags(build['variant'])
        effective = arm.configured_flags(retained[prefix + '/Makefile.txt'], retained[prefix + '/configure.log.txt'], build['variant'])
        require((build.get('cflags'), build.get('ldflags')) == (cflags, ldflags) and build.get('configured_flags') == effective, 'arm-build-flags-failed')
        require(build.get('artifacts') == {name: manifest['files'][prefix + '/' + name] for name in ('libz.a', 'example', 'minigzip')}
                and build.get('generated_configuration_sha256') == {name: manifest['files'][prefix + '/' + name + '.txt'] for name in arm.CONFIG_FILES}, 'arm-build-hashes-failed')
        elf = arm.elf_layout(read_regular(public / by_name[prefix + '-strict-elf']['log'], **deadline_options(deadline)))
        require(build.get('strict_driver') == {'source_sha256': arm.STRICT_SHA, 'binary_sha256': manifest['files'][prefix + '/strict-gzip'], 'elf': elf}
                and build.get('elf') == arm.elf_layout(read_regular(public / by_name[prefix + '-elf']['log'], **deadline_options(deadline))), 'arm-build-elf-failed')
        sections = read_regular(public / by_name[prefix + '-archive-sections']['log'], **deadline_options(deadline))
        require((b'.gnu.lto_' in sections) == (build['variant'] == 'lto'), 'arm-build-lto-failed')
        drivers.append({'binary': prefix + '/strict-gzip', 'sha256': manifest['files'][prefix + '/strict-gzip'],
            'source': 'strict-gzip.c', 'source_sha256': arm.STRICT_SHA, 'archive': prefix + '/libz.a',
            'cflags': cflags, 'ldflags': ldflags, 'configured_flags': effective, 'elf': elf,
            'compile': {key: original[prefix + '-strict-compile'][key] for key in keys},
            'elf_command': {key: original[prefix + '-strict-elf'][key] for key in keys}})
    features = [shlex.split(row['configured_flags']['CFLAGS'])[len(shlex.split(arm.build_flags(row['variant'])[0])):] for row in builds]
    require(all(flags == features[0] for flags in features), 'arm-configured-feature-flags-failed')
    for variant in ('baseline', 'lto'):
        check_deadline(deadline); pair = [row for row in builds if row['variant'] == variant]
        require(pair[0]['artifacts'] == pair[1]['artifacts'] and pair[0]['strict_driver'] == pair[1]['strict_driver'], 'arm-rebuild-pair-failed')
    outputs = [{'member': Path(plan['target']).name,
        'role': 'strict-rejection-partial-output' if plan['reject'] else 'strict-valid-output',
        'driver': str(PurePosixPath(plan['argv'][0]).relative_to('/out')),
        'input': 'corpus/' + Path(plan['source']).name,
        'stdin': by_name[plan['name']]['stdin'], 'stdout': by_name[plan['name']]['stdout'],
        'command': {key: original[plan['name']][key] for key in keys}}
        for plan in plans if plan['reject'] or plan['name'].endswith('-strict-valid')]
    require(manifest.get('strict_driver_evidence') == {'source': 'strict-gzip.c', 'source_sha256': arm.STRICT_SHA,
        'license': 'MIT', 'builds': drivers, 'outputs': outputs,
        'command_log_location': 'separate public evidence archive',
        'cross_decode_bytes': 'not retained; producer hash checks in public receipt'}, 'arm-strict-manifest-failed')
    positive, rejected = [row for row in native['correctness'] if 'level' in row], [row for row in native['correctness'] if 'rejected_exit' in row]
    prefixes = [row['binary'].split('/')[0] for row in drivers]
    wanted = {(prefix, row['path'], level, decoder) for prefix in prefixes for row in corpus['files'] if row['kind'] == 'input' for level in (1, 6, 9) for decoder in prefixes}
    require(len(positive) == 336 and {(r['build'], r['input'], r['level'], r['decoder']) for r in positive} == wanted
            and len(native['correctness']) == 368 and len(rejected) == 32, 'arm-correctness-set-failed')
    inputs = {row['path']: row for row in corpus['files']}
    for row in positive:
        check_deadline(deadline); output = by_name[f"{row['build']}-{Path(row['input']).stem}-{row['level']}-decode-{row['decoder']}"]['stdout']
        require(row.get('status') == 'PASS' and row.get('decoded_sha256') == output['sha256'] == inputs[row['input']]['sha256']
                and output['bytes'] == inputs[row['input']]['bytes'], 'arm-cross-decode-failed')
    wanted = {(prefix, row['path'], decoder) for prefix in prefixes for row in corpus['files'] if row['kind'] == 'corrupt' for decoder in prefixes}
    require({(r['build'], r['input'], r['decoder']) for r in rejected} == wanted, 'arm-rejection-set-failed')
    for row in rejected:
        check_deadline(deadline); name = row['build'] + '-reject-' + Path(row['input']).stem + '-' + row['decoder']
        require(row.get('driver') == 'strict-zlib-inflate' and row.get('rejected_exit') == by_name[name]['exit_code'] == 2, 'arm-strict-rejection-failed')
    for key, suffix in (('strict_valid', 'strict-valid'), ('sample_crc', 'sample-crc'), ('sample_truncation', 'sample-truncation')):
        check_deadline(deadline); rows = native.get(key, [])
        require(len(rows) == 4 and {row['decoder'] for row in rows} == set(prefixes), 'arm-sample-set-failed')
        for row in rows:
            check_deadline(deadline); command = by_name[row['decoder'] + '-' + suffix]
            if key == 'strict_valid':
                require(row.get('status') == 'PASS' and row.get('decoded_sha256') == command['stdout']['sha256'] == hashlib.sha256(arm.corpus.GZIP_PAYLOAD).hexdigest()
                        and command['stdout']['bytes'] == len(arm.corpus.GZIP_PAYLOAD), 'arm-strict-valid-failed')
            elif key == 'sample_crc':
                require(row.get('status') == 'PASS' and row.get('exit_code') == command['exit_code'], 'arm-sample-crc-failed')
            else:
                require(row.get('status') == 'OBSERVED' and row.get('rejection_acceptance') == 'NOT CLAIMED'
                        and row.get('exit_code') == command['exit_code'], 'arm-sample-observation-failed')


def verify_arm(owner, controller, prerequisite, *, deadline=None):
    check_deadline(deadline); result = arm_read_json(owner / 'result.json', **deadline_options(deadline))
    require(result.get('status') == 'PASS' and result.get('purpose') == 'ARM-C01-same-job-followup'
            and result.get('source_commit') == controller.commit and result.get('source_lock_sha256') == ARM_PIN
            and result.get('source_sha256') == ZLIB_SHA and result.get('evidence_export') == 'PASS'
            and result.get('launcher_cleanup') == 'PASS' and not result.get('cancelled'), 'arm-owner-result-failed')
    require(result.get('image_handoff') == {'kind': 'accepted-base-image', 'image_id': controller.image, 'package_count': 341}, 'arm-base-envelope-failed')
    cleanup = result.get('container_cleanup', {})
    require(cleanup.get('status') == 'PASS' and cleanup.get('absence_verified') is True
            and not cleanup.get('cancelled') and not cleanup.get('cleanup_uncertain'), 'arm-owner-cleanup-failed')
    receiver = result.get('receiver_verification', {})
    require(receiver.get('status') == 'PASS' and receiver.get('command_count') == 505 and receiver.get('build_count') == 4
            and receiver.get('cross_decode_count') == 336 and receiver.get('rejection_count') == 32 and receiver.get('strict_valid_count') == 4
            and receiver.get('sample_crc_count') == receiver.get('sample_truncation_observation_count') == 4
            and receiver.get('source_sha256') == ZLIB_SHA and receiver.get('packages_sha256') == prerequisite['packages_sha256'], 'arm-owner-receiver-failed')
    for directory in (owner / 'public', owner / 'public-status'):
        check_deadline(deadline); exported = verify_export(directory, **deadline_options(deadline))
        arm_read_json(directory / 'export-manifest.json', **deadline_options(deadline))
        for row in exported['accepted']:
            check_deadline(deadline)
            if Path(row['path']).suffix == '.json':
                arm_json(read_regular(directory / row['path'], TEXT_LIMIT, **deadline_options(deadline)))
    require(arm_read_json(owner / 'public-status/result.json', **deadline_options(deadline)) == result, 'arm-public-status-drift')
    artifacts = owner / 'public-artifacts'
    require({p.name for p in artifacts.iterdir()} == {'development-ARM-C01-outputs.tar.gz', 'archive-manifest.json'}, 'arm-artifact-directory-invalid')
    manifest = arm_read_json(artifacts / 'archive-manifest.json', **deadline_options(deadline))
    require(manifest == result.get('development_artifacts') and manifest.get('image_id') == controller.image
            and manifest.get('source_commit') == controller.commit and manifest.get('source_sha256') == ZLIB_SHA,
            'arm-artifact-binding-failed')
    approved = manifest.get('files', {})
    names = {f'{variant}-{attempt}/{name}' for variant in ('baseline', 'lto') for attempt in (1, 2)
             for name in ('libz.a', 'example', 'minigzip', 'strict-gzip', 'Makefile.txt', 'zconf.h.txt', 'configure.log.txt', 'LICENSE.txt')}
    names |= {'corpus/' + name for name in ('empty.bin', 'onebyte.bin', 'repeated.txt', 'allbytes.bin', 'incompressible.bin',
                                          'heldout-source.bin', 'gzip-reference.gz', 'corrupt-crc.gz', 'truncated-trailer.gz', 'manifest.json')}
    names |= {'strict-gzip.c'} | {f'{producer}-reject-{fixture}-{decoder}.bin'
        for producer in ('baseline-1', 'baseline-2', 'lto-1', 'lto-2')
        for fixture in ('corrupt-crc', 'truncated-trailer')
        for decoder in ('baseline-1', 'baseline-2', 'lto-1', 'lto-2')}
    names |= {prefix + '-strict-valid.bin' for prefix in ('baseline-1', 'baseline-2', 'lto-1', 'lto-2')}
    require(manifest.get('member_count') == 79 and len(names) == 79, 'arm-artifact-count-failed')
    require(set(approved) == names and all(PIN.fullmatch(value) for value in approved.values()), 'arm-artifact-allowlist-failed')
    archive = artifacts / 'development-ARM-C01-outputs.tar.gz'; info = regular(archive, 8 * 1024**2, **deadline_options(deadline))
    require(info.st_size == manifest.get('bundle_bytes') and digest(archive, **deadline_options(deadline)) == manifest.get('bundle_sha256'), 'arm-artifact-archive-drift')
    total, seen, retained = 0, set(), {}
    limit = 64 * 1024**2 + 128 * 1024  # finite member headers/padding in addition to payload
    with gzip.GzipFile(fileobj=io.BytesIO(read_regular(archive, 8 * 1024**2, **deadline_options(deadline)))) as compressed:
        expanded = stream_bytes(compressed, limit, **deadline_options(deadline))
    require(len(expanded) <= limit, 'arm-artifact-expanded-bound')
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r|') as stream:
        for member in stream:
            check_deadline(deadline); require(not stream.pax_headers, 'arm-artifact-global-metadata-refused')
            require(member.name in names and member.name not in seen and member.isfile()
                    and member.uid == member.gid == 0 and member.mtime == 0 and not member.uname and not member.gname
                    and not member.pax_headers and 0 <= member.size <= (32 * 1024**2 if member.name.endswith('.bin') else 8 * 1024**2),
                    'arm-artifact-member-refused')
            require(member.mode == (0o755 if member.name.endswith(('/example', '/minigzip', '/strict-gzip')) else 0o644),
                    'arm-artifact-member-mode-refused')
            total += member.size; require(total <= 64 * 1024**2, 'arm-artifact-byte-bound')
            with stream.extractfile(member) as source:
                data = stream_bytes(source, member.size, **deadline_options(deadline))
            require(len(data) == member.size and hashlib.sha256(data).hexdigest() == approved[member.name], 'arm-artifact-member-drift')
            seen.add(member.name); retained[member.name] = data
    require(seen == names and total == manifest.get('uncompressed_bytes'), 'arm-artifact-incomplete')
    verify_arm_evidence(owner / 'public', manifest, retained, controller, prerequisite, receiver, **deadline_options(deadline))
    return result


def run_arm(controller, root, output, cache, *, deadline=None):
    result = {'stage': 'arm-c01-base', 'status': 'FAIL', 'prerequisite': {'status': 'NOT RUN'}, 'public': []}
    owned, first_failure = None, None
    try:
        root, owned, result = start(controller, root, output, 'arm-c01-base', **deadline_options(deadline))
        lock = arm_lock(root, **deadline_options(deadline))
        for other in (owned, root, Path(controller.native_out)):
            check_deadline(deadline); require(not Path(cache).is_relative_to(other) and not other.is_relative_to(Path(cache)), 'cache-input-output-overlap')
        source = fetch_zlib(cache, **deadline_options(deadline))
        inputs = owned / 'inputs'; inputs.mkdir()
        save(inputs / 'source-input.json', {'url': ZLIB_URL, 'sha256': ZLIB_SHA, 'bytes': ZLIB_SIZE,
                                          'verification': 'reviewed exact bytes; HTTPS transport, no release-signature claim'}, **deadline_options(deadline))
        lock_copy = inputs / 'source.lock.json'; copy_regular(lock, lock_copy, **deadline_options(deadline))
        require(digest(lock_copy, **deadline_options(deadline)) == ARM_PIN, 'arm-source-lock-copy-drift')
        owner = owned / 'owner'
        prerequisite = result['prerequisite']
        code = command([sys.executable, '-B', str(root / 'scripts/experiments/stage.py'), '--source-root', str(root),
                 '--lock', str(lock_copy), '--lock-sha256', ARM_PIN, '--source', str(source), '--source-commit', controller.commit,
                 '--image', controller.image, '--base-packages', prerequisite['packages_lock'],
                 '--base-packages-sha256', prerequisite['packages_sha256'], '--expected-packages', prerequisite['packages_lock'],
                 '--expected-packages-sha256', prerequisite['packages_sha256'], '--output', str(owner)], owned / 'driver.log', 1000, **deadline_options(deadline))
        require(code == 0, 'arm-owner-command-failed')
        verify_arm(owner, controller, prerequisite, **deadline_options(deadline))
        result.update(status='PASS', execution='base-only-correctness', installed_handoff='NOT CLAIMED')
    except KeyboardInterrupt as error:
        first_failure = error
        failed(result, 'arm-cancelled', cancelled=True)
        raise
    except Exception as error:
        first_failure = error
        failed(result, 'stage-deadline-exceeded' if str(error) == 'stage-deadline-exceeded' else 'arm-stage-failed')
    finally:
        if owned is not None:
            cleanup_errors = []
            with defer_cleanup(first_failure, cleanup_errors) as events:
                owner = owned / 'owner'
                for name in ('public', 'public-status'):
                    path = owner / name
                    if path.exists():
                        try:
                            verify_export(path, allow_failure=True, **deadline_options(deadline)); result['public'].append(str(path))
                        except Exception:
                            failed(result, 'arm-publication-failed')
                if result['status'] == 'PASS':
                    result['public'].append(str(owner / 'public-artifacts'))
                try:
                    selected = owned / 'selected'; selected.mkdir()
                    for path in (owned / 'driver.log', owned / 'inputs/source-input.json'):
                        check_deadline(deadline)
                        if path.exists():
                            copy_regular(path, selected / path.name, **deadline_options(deadline))
                    public = owned / 'public'; exported = text_public(root, selected, public, **deadline_options(deadline))
                    result['public'].append(str(public))
                    if not exported:
                        failed(result, 'arm-publication-failed')
                except Exception:
                    failed(result, 'arm-publication-failed')
                if events:
                    failed(result, 'arm-cancelled', cancelled=True)
                retain(owned, result, deadline=deadline)
                if events:
                    failed(result, 'arm-cancelled', cancelled=True)
                    retain(owned, result, deadline=deadline)
            if cleanup_errors:
                failed(result, 'stage-cleanup-failed')
                retain(owned, result, deadline=deadline)
            try:
                check_deadline(deadline)
            except Exception:
                failed(result, 'stage-deadline-exceeded')
                retain(owned, result, deadline=deadline)
            if events:
                failed(result, 'arm-cancelled', cancelled=True)
                retain(owned, result, deadline=deadline)
                if first_failure is not None and not isinstance(first_failure, Exception):
                    raise first_failure
                raise KeyboardInterrupt()
    return result


def verify_ksm_material(directory, *, deadline=None):
    """Recheck the fixed GPL source/archive bundle before recovery publication."""
    check_deadline(deadline); manifest = read_json(directory / 'manifest.json', **deadline_options(deadline))
    require(set(manifest) == {'license', 'reviewed_sources', 'artifacts', 'image_id', 'source_commit',
                             'source_date_epoch', 'development_only', 'selected_for_release'}, 'ksm-recovery-envelope-invalid')
    reviewed = manifest.get('reviewed_sources')
    require(isinstance(reviewed, dict) and hashlib.sha256(
        (json.dumps(reviewed, indent=2, sort_keys=True) + '\n').encode()).hexdigest() == KSM_PIN,
        'ksm-recovery-source-map-invalid')
    require(manifest.get('license') == 'GPL-2.0-or-later' and manifest.get('development_only') is True
            and manifest.get('selected_for_release') is False and manifest.get('source_date_epoch') == EPOCH,
            'ksm-recovery-envelope-invalid')
    expected = {'manifest.json'}
    for name, pin in reviewed.items():
        check_deadline(deadline); relative(name); path = directory / 'source' / name; regular(path, **deadline_options(deadline))
        require(digest(path, **deadline_options(deadline)) == pin, 'ksm-recovery-source-drift')
        expected.add('source/' + name)
    artifacts = manifest.get('artifacts')
    require(isinstance(artifacts, dict) and set(artifacts) <= {'1', '2'}, 'ksm-recovery-artifacts-invalid')
    for number, row in artifacts.items():
        check_deadline(deadline); require(isinstance(row, dict) and set(row) == {'filename', 'sha256'}, 'ksm-recovery-artifacts-invalid')
        name = row['filename']
        require(re.fullmatch(r'cachy-asahi-ksmctl-0\.1\.0-1-any\.pkg\.tar\.(?:xz|zst|gz)', name), 'ksm-recovery-archive-invalid')
        path = directory / ('attempt-' + number) / name; regular(path, 8 * 1024**2, **deadline_options(deadline))
        require(PIN.fullmatch(row['sha256']) and digest(path, **deadline_options(deadline)) == row['sha256'], 'ksm-recovery-archive-drift')
        validate_ksm_package(Path(__file__).resolve().parents[3], path, reviewed, **deadline_options(deadline))
        expected.add('attempt-' + number + '/' + name)
    actual = set()
    for path in directory.rglob('*'):
        check_deadline(deadline); require(not path.is_symlink(), 'ksm-recovery-symlink')
        if path.is_file():
            regular(path, 8 * 1024**2, **deadline_options(deadline)); actual.add(path.relative_to(directory).as_posix())
        else:
            require(path.is_dir(), 'ksm-recovery-special-file')
    require(actual == expected, 'ksm-recovery-extra-or-missing-file')


def recovery_public(stage, output, *, deadline=None):
    """Fixed validated directories only; never enumerate private owner trees."""
    check_deadline(deadline); require(stage in ('ksm', 'arm-c01-base'), 'unknown-recovery-stage')
    output = Path(output)
    require(output.is_absolute() and output.is_dir() and all(not p.is_symlink() for p in (output, *output.parents)), 'unsafe-recovery-output')
    policy = public_policy(**deadline_options(deadline))
    paths, refused, value = [], [], None
    status = output / 'adapter-status'
    try:
        value = read_json(status / 'result.json', **deadline_options(deadline))
        require(value.get('stage') == stage and value.get('status') in ('PASS', 'FAIL', 'NOT RUN')
                and set(value) <= {'stage', 'status', 'prerequisite', 'public', 'hardware_validation', 'performance_acceptance',
                                  'selected_for_release', 'installation', 'error_code', 'execution', 'installed_handoff', 'cleanup', 'cancelled'},
                'invalid-recovery-adapter-status')
        require({path.name for path in status.iterdir()} == {'result.json'}, 'invalid-recovery-adapter-files')
        require(not policy.PRIVATE_CONTENT.search(json.dumps(value, sort_keys=True)), 'private-recovery-status-refused')
        paths.append(str(status))
    except Exception:
        value = None
        refused.append({'bundle': 'adapter-status', 'error_code': 'adapter-status-refused'})
    text = [output / 'public']
    if stage == 'arm-c01-base':
        text += [output / 'owner' / name for name in ('public', 'public-status')]
    for path in text:
        check_deadline(deadline)
        if path.exists() or path.is_symlink():
            try:
                verify_export(path, allow_failure=True, **deadline_options(deadline)); paths.append(str(path))
            except Exception:
                refused.append({'bundle': path.relative_to(output).as_posix(), 'error_code': 'public-bundle-refused'})
    material = output / ('public-material' if stage == 'ksm' else 'owner/public-artifacts')
    if material.exists() or material.is_symlink():
        try:
            if stage == 'ksm':
                verify_ksm_material(material, **deadline_options(deadline))
            else:
                prerequisite = value['prerequisite']
                require(prerequisite.get('status') == 'PASS' and prerequisite.get('package_count') == 341, 'arm-recovery-prerequisite-invalid')
                verify_arm(output / 'owner', SimpleNamespace(image=prerequisite['image_id'], commit=prerequisite['source_commit']), prerequisite, **deadline_options(deadline))
            paths.append(str(material))
        except Exception:
            refused.append({'bundle': material.relative_to(output).as_posix(), 'error_code': 'material-bundle-refused'})
    if refused:
        report = output / 'recovery-status'
        if report.exists():
            require(not report.is_symlink() and report.is_dir() and {p.name for p in report.iterdir()} == {'failure-retention.json'}, 'unsafe-recovery-report')
            regular(report / 'failure-retention.json', **deadline_options(deadline))
        else:
            report.mkdir(mode=0o700)
        save(report / 'failure-retention.json', {'purpose': 'development-adapter-failure-retention', 'stage': stage,
             'status': 'FAIL', 'failure_retention': 'FAIL', 'bundle_rejections': refused,
             'hardware_validation': 'NOT RUN', 'private_trees_examined': False}, **deadline_options(deadline))
        paths.append(str(report))
    return paths
