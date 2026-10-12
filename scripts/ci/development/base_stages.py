#!/usr/bin/env python3
"""Independent development consumers of the accepted native 341-package builder.

These adapters never install onto the host or change initial integration status.
Only explicit owner receipts and reviewed GPL/package/experiment material are
public. Native/hardware acceptance requires actual execution, never these tests.
"""
import hashlib
import importlib.util
import json
import os
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import urllib.request

from common import base_prerequisite, command, copy_regular, digest, read_json, read_regular, require

KSM = 'cachy-asahi-ksmctl'
KSM_PIN = 'f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44'
ARM_PIN = '98617adc3dd70fb71a9734d7f38840f553b795ce05322d5b95598f20d5aec4a5'
EXPORT_PIN = '1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c'
ZLIB_URL = 'https://zlib.net/zlib-1.3.2.tar.gz'
ZLIB_SHA = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
ZLIB_SIZE = 1502830
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


def regular(path, limit=TEXT_LIMIT):
    path = Path(path)
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


def load_module(path, name):
    regular(path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checker(root):
    return load_module(root / 'scripts/checks/package_checks.py', 'development_package_checks')


def start(controller, root, output, stage):
    root, output = Path(root), Path(output)
    require(root.is_absolute() and root.is_dir() and all(not p.is_symlink() for p in (root, *root.parents)), 'unsafe-source-root')
    require(output.is_absolute() and '..' not in output.parts and not output.exists() and not output.is_symlink()
            and all(not p.is_symlink() for p in output.parents), 'new-safe-output-required')
    for other in (root, Path(controller.native_out)):
        require(not output.is_relative_to(other) and not other.is_relative_to(output), 'output-boundary-overlap')
    prerequisite = base_prerequisite(controller)
    require(prerequisite.get('status') == 'PASS' and prerequisite.get('package_count') == 341
            and prerequisite.get('image_id') == controller.image, 'accepted-native-base-required')
    output.mkdir(mode=0o700, parents=True)
    return root, output, {'stage': stage, 'status': 'FAIL', 'prerequisite': prerequisite, 'public': [],
                          'hardware_validation': 'NOT RUN', 'performance_acceptance': 'NOT RUN',
                          'selected_for_release': False, 'installation': 'NOT RUN'}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def finish(output, result):
    if output is not None:
        status = output / 'adapter-status'; status.mkdir(exist_ok=True)
        result['public'] = list(dict.fromkeys([*result['public'], str(status)]))
        save(status / 'result.json', result)
        save(output / 'result.json', result)
    return result


def verify_export(directory, allow_failure=False):
    regular(directory / 'export-manifest.json')
    manifest = read_json(directory / 'export-manifest.json')
    require(manifest.get('evidence_export') in ('PASS', 'FAIL') and isinstance(manifest.get('rejected'), list), 'owner-public-export-failed')
    if not allow_failure:
        require(manifest['evidence_export'] == 'PASS' and manifest['rejected'] == [], 'owner-public-export-failed')
    rows = manifest.get('accepted')
    require(isinstance(rows, list) and len(rows) <= 2048, 'owner-public-manifest-invalid')
    names = set()
    policy = public_policy()
    require(not policy.PRIVATE_CONTENT.search(json.dumps(manifest, sort_keys=True)), 'owner-public-manifest-refused')
    for row in rows:
        name = str(relative(row['path']))
        require(not any(policy.SENSITIVE_PATH.search(part) for part in PurePosixPath(name).parts)
                and Path(name).suffix.lower() in policy.SUFFIXES, 'owner-public-path-refused')
        require(name not in names and name != 'export-manifest.json' and PIN.fullmatch(row['sha256']), 'owner-public-manifest-invalid')
        path = directory / name
        data = read_regular(path, TEXT_LIMIT)
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'owner-public-file-drift')
        text = data.decode('utf-8')
        require(not policy.PRIVATE_CONTENT.search(text) and not any(ord(c) < 32 and c not in '\n\r\t' for c in text),
                'owner-public-content-refused')
        names.add(name)
    actual = set()
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'owner-public-symlink')
        if path.is_file():
            regular(path)
            actual.add(path.relative_to(directory).as_posix())
        else:
            require(path.is_dir(), 'owner-public-special-file')
    require(actual == names | {'export-manifest.json'}, 'owner-public-extra-or-missing-file')
    return manifest


def public_policy():
    exporter = Path(__file__).resolve().parents[3] / 'scripts/ci/integration_export.py'
    require(digest(exporter) == EXPORT_PIN, 'public-exporter-drift')
    return load_module(exporter, 'development_public_policy')


def text_public(root, selected, output):
    exporter = root / 'scripts/ci/integration_export.py'
    require(digest(exporter) == EXPORT_PIN, 'public-exporter-drift')
    result = load_module(exporter, 'development_text_exporter').export_evidence(selected, output)
    verify_export(output, allow_failure=True)
    return result['evidence_export'] == 'PASS'


def ksm_recipe(root):
    path = root / 'manifests/reviewed/ksmctl.json'; regular(path)
    require(digest(path) == KSM_PIN, 'ksm-reviewed-map-drift')
    reviewed = read_json(path)
    require(isinstance(reviewed, dict) and len(reviewed) == 15, 'ksm-map-invalid')
    recipe = root / 'packages/tools' / KSM
    report = checker(root).recipe(recipe / 'PKGBUILD')
    require(not report['errors'] and report['input_sha256'] == reviewed, 'ksm-recipe-drift')
    for name, pin in reviewed.items():
        relative(name); require(PIN.fullmatch(pin), 'ksm-map-invalid')
        regular(recipe / name)
        require(digest(recipe / name) == pin, 'ksm-recipe-drift')
    return recipe, reviewed


def verify_ksm_attempt(root, attempt, reviewed, prerequisite):
    record = read_json(attempt / 'provenance.json')
    require(record.get('status') == 'built-package-static-pass' and record.get('mode') == 'native'
            and record.get('image') == record.get('image_id') == prerequisite['image_id']
            and record.get('recipe_inputs') == reviewed and record.get('source_date_epoch') == EPOCH
            and record.get('expected_packages_sha256') == prerequisite['packages_sha256'], 'ksm-build-binding-failed')
    validation = read_json(attempt / 'validation.json')
    require(validation.get('errors') == [] and len(validation.get('artifacts', [])) == 1, 'ksm-static-validation-failed')
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    files = record.get('files', {})
    require(isinstance(files, dict) and required <= files.keys(), 'ksm-build-evidence-missing')
    for name, pin in files.items():
        path = attempt / str(relative(name)); regular(path, 8 * 1024**2)
        require(PIN.fullmatch(pin) and digest(path) == pin, 'ksm-build-evidence-drift')
    for name in ('expected-packages.lock', 'artifacts/packages.lock'):
        require(digest(attempt / name) == prerequisite['packages_sha256'], 'ksm-inventory-drift')
    for name, pin in reviewed.items():
        path = attempt / 'inputs' / name; regular(path)
        require(digest(path) == pin, 'ksm-recipe-snapshot-drift')
    artifacts = record.get('artifacts', {})
    require(isinstance(artifacts, dict) and len(artifacts) == 1, 'ksm-single-archive-required')
    name, pin = next(iter(artifacts.items()))
    require(re.fullmatch(r'cachy-asahi-ksmctl-0\.1\.0-1-any\.pkg\.tar\.(?:xz|zst|gz)', name), 'ksm-archive-name-refused')
    archive = attempt / 'artifacts' / name; regular(archive, 8 * 1024**2)
    require(digest(archive) == pin, 'ksm-archive-drift')
    actual = {p.name for p in (attempt / 'artifacts').glob('*.pkg.tar.*')}
    require(actual == {name}, 'ksm-extra-archive-refused')
    validate_ksm_package(root, archive, reviewed)
    return archive.name, pin


def validate_ksm_package(root, archive, reviewed):
    package = checker(root).package(archive)
    require(not package['errors'] and not package['elf'], 'ksm-package-inspection-failed')
    info, buildinfo = package['metadata']['.PKGINFO'], package['metadata']['.BUILDINFO']
    for key, value in {'pkgname': [KSM], 'pkgver': ['0.1.0-1'], 'arch': ['any'],
                       'license': ['GPL-2.0-or-later'], 'depend': ['python>=3.11']}.items():
        require(info.get(key) == value, 'ksm-package-metadata-failed')
    require(buildinfo.get('pkgbuild_sha256sum') == [reviewed['PKGBUILD']], 'ksm-package-recipe-binding-failed')
    members = package['members']
    require('.INSTALL' not in members and all(row['type'] in ('0', '5') and row['uid'] == row['gid'] == 0
                                             for row in members.values()), 'ksm-package-node-refused')
    files = {name for name, row in members.items() if row['type'] == '0'}
    require(files == set(PAYLOAD) | PACMAN_METADATA, 'ksm-package-file-allowlist-failed')
    directories = {str(parent) for name in files for parent in PurePosixPath(name).parents}
    for name, row in members.items():
        if row['type'] == '5':
            require(name in directories and row['mode'] == 0o755, 'ksm-package-directory-refused')
        elif name in PACMAN_METADATA:
            require(row['mode'] == 0o644, 'ksm-package-metadata-mode-refused')
    payload = {name: members[name] for name in PAYLOAD}
    for name, row in payload.items():
        require(row['sha256'] == reviewed[PAYLOAD[name]] and row['mode'] == (0o755 if name.startswith('usr/bin/') else 0o644), 'ksm-package-payload-failed')


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


def cleanup_endpoint(root):
    return 'unix://' + load_module(root / 'scripts/ci/commit_image.py', 'development_local_endpoint').local_endpoint()


@contextmanager
def defer_cleanup():
    events = []
    previous = {sig: signal.signal(sig, lambda *_: events.append(True)) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield events
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def cleanup_ksm(root, output, image):
    """Bind recorded owner argv and observed identity before deleting a container.

    The owner writes provenance before Docker run. No provenance means no
    submitted container. Cleanup never derives ownership from a loose prefix.
    """
    directory = output / 'cleanup'; directory.mkdir()
    report = {'status': 'PASS', 'containers': [], 'phase_seconds_limit': 120}
    deadline, endpoint = time.monotonic() + 120, None
    for number in (1, 2):
        row = {'attempt': number, 'status': 'FAIL', 'absence_verified': False}
        try:
            attempt = output / ('attempt-' + str(number))
            path = attempt / 'provenance.json'
            if not path.exists() and not path.is_symlink():
                row.update(status='PASS', absence_verified=True, submitted=False)
                report['containers'].append(row)
                continue
            record = read_json(path)
            name = record.get('clean_environment_id')
            require(isinstance(name, str) and re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'ksm-cleanup-ownership-invalid')
            require(record.get('image_id') == image and record.get('image') == image
                    and record.get('command') == build_container_command(root, attempt, image, name), 'ksm-cleanup-ownership-invalid')
            row.update(container=name, submitted=True)
            if endpoint is None:
                endpoint = cleanup_endpoint(root)
                require(endpoint in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock'), 'ksm-cleanup-endpoint-invalid')
            prefix = ['docker', '--host', endpoint]
            def query(label, args):
                remaining = deadline - time.monotonic()
                # Reserve common's five-second drain grace and ten-second reap.
                require(remaining > 15, 'ksm-cleanup-deadline')
                log = directory / (str(number) + '-' + label + '.json')
                require(command(prefix + args, log, min(15, remaining - 15), cleanup_grace=5) == 0, 'ksm-cleanup-query-failed')
                regular(log)
                return log
            listing = ['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']
            before = query('before', listing).read_text().strip()
            if not before:
                row.update(status='PASS', absence_verified=True)
            else:
                require(re.fullmatch(r'[0-9a-f]{12,64}', before), 'ksm-cleanup-list-invalid')
                observed = read_json(query('inspect', ['container', 'inspect', name, '--format',
                    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"mounts":{{json .Mounts}}}']))
                identity = observed.get('id')
                require(isinstance(identity, str) and re.fullmatch(r'[0-9a-f]{64}', identity)
                        and identity.startswith(before) and observed.get('name') == '/' + name and observed.get('image') == image,
                        'ksm-cleanup-identity-invalid')
                expected = {'/inputs': (str(attempt / 'inputs'), False), '/out': (str(attempt / 'artifacts'), True),
                            '/builder-entry.sh': (str(root / 'scripts/build/container-entry.sh'), False),
                            '/expected-packages.lock': (str(attempt / 'expected-packages.lock'), False)}
                actual, targets = {}, set()
                for mount in observed.get('mounts', []):
                    target = mount.get('Destination')
                    require(target not in targets, 'ksm-cleanup-mount-invalid'); targets.add(target)
                    if mount.get('Type') == 'tmpfs' and target == '/tmp' and mount.get('RW') is True:
                        continue
                    require(mount.get('Type') == 'bind' and type(mount.get('RW')) is bool, 'ksm-cleanup-mount-invalid')
                    actual[target] = (mount.get('Source'), mount['RW'])
                require(actual == expected, 'ksm-cleanup-mount-invalid')
                removal_ok = False
                try:
                    removed = query('remove', ['container', 'rm', '-f', identity])
                    removal_ok = removed.read_text().strip() == identity
                finally:
                    row['absence_verified'] = query('after', listing).read_text().strip() == ''
                require(removal_ok and row['absence_verified'], 'ksm-cleanup-removal-or-absence-failed')
                row.update(status='PASS', container_id=identity)
        except Exception:
            row['error_code'] = 'ksm-owned-cleanup-failed'
            if endpoint is not None and row.get('submitted'):
                try:
                    row['absence_verified'] = query('final-absence', listing).read_text().strip() == ''
                except Exception:
                    pass
        report['containers'].append(row)
        if row['status'] != 'PASS':
            report['status'] = 'FAIL'
    return report


def run_ksm(controller, root, output):
    result = {'stage': 'ksm', 'status': 'FAIL', 'prerequisite': {'status': 'NOT RUN'}, 'public': []}
    owned = None
    try:
        root, owned, result = start(controller, root, output, 'ksm')
        recipe, reviewed = ksm_recipe(root)
        inputs = owned / 'inputs'; inputs.mkdir()
        review = inputs / 'reviewed-inputs.json'; save(review, reviewed)
        public_material = owned / 'public-material'; public_material.mkdir()
        source = public_material / 'source'; source.mkdir()
        for name, pin in reviewed.items():
            copy_regular(recipe / name, source / name)
            require(digest(source / name) == pin, 'ksm-public-source-drift')
        artifacts = {}
        def material_receipt():
            save(public_material / 'manifest.json', {'license': 'GPL-2.0-or-later', 'reviewed_sources': reviewed,
                 'artifacts': artifacts, 'image_id': controller.image, 'source_commit': controller.commit,
                 'source_date_epoch': EPOCH, 'development_only': True, 'selected_for_release': False})
        material_receipt()
        result['public'].append(str(public_material))
        selected = owned / 'selected'; selected.mkdir()
        environments = []
        for number in (1, 2):
            attempt = owned / ('attempt-' + str(number))
            code = command([sys.executable, '-B', str(root / 'scripts/build/build.py'), str(recipe),
                     '--image', controller.image, '--mode', 'native', '--network', 'none',
                     '--source-date-epoch', str(EPOCH), '--expected-packages', result['prerequisite']['packages_lock'],
                     '--reviewed-inputs', str(review), '--timeout', '300', '--output', str(attempt)],
                    owned / ('attempt-' + str(number) + '-driver.log'), 360)
            require(code == 0, 'ksm-build-command-failed')
            name, pin = verify_ksm_attempt(root, attempt, reviewed, result['prerequisite'])
            environments.append(read_json(attempt / 'provenance.json')['clean_environment_id'])
            dest = public_material / ('attempt-' + str(number)); dest.mkdir()
            copy_regular(attempt / 'artifacts' / name, dest / name)
            require(digest(dest / name) == pin, 'ksm-public-archive-drift')
            artifacts[str(number)] = {'filename': name, 'sha256': pin}
            material_receipt()
        require(environments[0] and environments[0] != environments[1], 'ksm-independent-environments-required')
        comparison = owned / 'compare.json'
        code = command([sys.executable, '-B', str(root / 'scripts/build/compare.py'), str(owned / 'attempt-1'),
                 str(owned / 'attempt-2'), '--require-bytes'], comparison, 120)
        require(code == 0, 'ksm-comparison-command-failed')
        compared = read_json(comparison)
        require(compared.get('status') == 'contents-reproduced' and compared.get('errors') == []
                and set(compared.get('packages', {})) == {artifacts['1']['filename']}, 'ksm-rebuild-comparison-failed')
        require(all(compared['packages'][artifacts['1']['filename']].get(key) is True for key in
                    ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')), 'ksm-rebuild-comparison-failed')
        require(artifacts['1'] == artifacts['2'], 'ksm-rebuilt-bytes-differ')
        result['status'] = 'PASS'
    except KeyboardInterrupt:
        result.update(status='FAIL', cancelled=True, error_code='ksm-cancelled')
        raise
    except Exception:
        result.update(status='FAIL', error_code='ksm-stage-failed')
    finally:
        if owned is not None:
            with defer_cleanup() as events:
                try:
                    cleanup = cleanup_ksm(root, owned, controller.image)
                except Exception:
                    cleanup = {'status': 'FAIL', 'error_code': 'ksm-owned-cleanup-failed', 'absence_verified': False}
                if events:
                    cleanup.update(status='FAIL', cancelled=True)
                result['cleanup'] = cleanup
                if cleanup['status'] != 'PASS':
                    result.update(status='FAIL', error_code='ksm-owned-cleanup-failed')
                save(owned / 'cleanup-result.json', cleanup)
                # Retain explicit partial driver/build diagnostics even after failure.
                try:
                    selected = owned / 'selected'; selected.mkdir(exist_ok=True)
                    for number in (1, 2):
                        attempt = owned / ('attempt-' + str(number))
                        for name in ('provenance.json', 'validation.json', 'build.log'):
                            path = attempt / name
                            if path.exists():
                                copy_regular(path, selected / ('attempt-' + str(number) + '-' + name))
                        path = owned / ('attempt-' + str(number) + '-driver.log')
                        if path.exists():
                            copy_regular(path, selected / path.name)
                    if (owned / 'compare.json').exists():
                        copy_regular(owned / 'compare.json', selected / 'compare.json')
                    copy_regular(owned / 'cleanup-result.json', selected / 'cleanup-result.json')
                    public = owned / 'public'; exported = text_public(root, selected, public)
                    result['public'].append(str(public))
                    if not exported:
                        result.update(status='FAIL', error_code='ksm-publication-failed')
                except Exception:
                    result.update(status='FAIL', error_code='ksm-publication-failed')
                finish(owned, result)
                if events:
                    result.update(status='FAIL', cancelled=True, error_code='ksm-cancelled')
                    finish(owned, result)
            if events:
                raise KeyboardInterrupt()
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise ValueError('zlib-redirect-refused')


def open_zlib(url, timeout):
    return urllib.request.build_opener(NoRedirect()).open(url, timeout=timeout)


def fetch_zlib(cache):
    cache = Path(cache)
    require(cache.is_absolute() and cache.is_dir() and all(not p.is_symlink() for p in (cache, *cache.parents)), 'unsafe-zlib-cache')
    cached = cache / 'zlib-1.3.2.tar.gz'
    if cached.exists() or cached.is_symlink():
        require(regular(cached, ZLIB_SIZE).st_size == ZLIB_SIZE and digest(cached) == ZLIB_SHA, 'cached-zlib-drift')
        return cached
    descriptor, name = tempfile.mkstemp(prefix='zlib-1.3.2-', suffix='.tar.gz', dir=cache)
    path = Path(name)
    try:
        started = time.monotonic()
        with os.fdopen(descriptor, 'wb') as target, open_zlib(ZLIB_URL, timeout=15) as source:
            require(source.geturl() == ZLIB_URL and source.status == 200, 'zlib-origin-refused')
            length = source.headers.get('Content-Length')
            require(length is None or length == str(ZLIB_SIZE), 'zlib-size-refused')
            size = 0
            while True:
                require(time.monotonic() - started <= 90, 'zlib-fetch-timeout')
                data = source.read(min(65536, ZLIB_SIZE + 1 - size))
                if not data:
                    break
                size += len(data); require(size <= ZLIB_SIZE, 'zlib-size-refused')
                target.write(data)
        require(regular(path, ZLIB_SIZE).st_size == ZLIB_SIZE and digest(path) == ZLIB_SHA, 'zlib-pin-refused')
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def arm_lock(root):
    path = root / 'scripts/experiments/stage.lock.json'; regular(path)
    require(digest(path) == ARM_PIN, 'arm-source-lock-drift')
    lock = read_json(path)
    require(set(lock.get('source_files', {})) == ARM_FILES and lock.get('source_sha256') == ZLIB_SHA,
            'arm-source-envelope-invalid')
    for name, row in lock['source_files'].items():
        path = root / 'scripts/experiments' / name
        require(regular(path).st_mode & 0o777 == row['mode'] and digest(path) == row['sha256'], 'arm-source-drift')
    exporter = lock['exporter']
    require(exporter == {'path': 'scripts/ci/integration_export.py', 'sha256': EXPORT_PIN, 'mode': 0o644}
            and digest(root / exporter['path']) == EXPORT_PIN and regular(root / exporter['path']).st_mode & 0o777 == 0o644,
            'arm-exporter-drift')
    return root / 'scripts/experiments/stage.lock.json'


def verify_arm(owner, controller, prerequisite):
    result = read_json(owner / 'result.json')
    require(result.get('status') == 'PASS' and result.get('purpose') == 'ARM-C01-same-job-followup'
            and result.get('source_commit') == controller.commit and result.get('source_lock_sha256') == ARM_PIN
            and result.get('source_sha256') == ZLIB_SHA and result.get('evidence_export') == 'PASS'
            and result.get('launcher_cleanup') == 'PASS' and not result.get('cancelled'), 'arm-owner-result-failed')
    require(result.get('image_handoff') == {'kind': 'accepted-base-image', 'image_id': controller.image, 'package_count': 341}, 'arm-base-envelope-failed')
    cleanup = result.get('container_cleanup', {})
    require(cleanup.get('status') == 'PASS' and cleanup.get('absence_verified') is True
            and not cleanup.get('cancelled') and not cleanup.get('cleanup_uncertain'), 'arm-owner-cleanup-failed')
    receiver = result.get('receiver_verification', {})
    require(receiver.get('status') == 'PASS' and receiver.get('command_count') == 485 and receiver.get('build_count') == 4
            and receiver.get('cross_decode_count') == 336 and receiver.get('rejection_count') == 32
            and receiver.get('source_sha256') == ZLIB_SHA and receiver.get('packages_sha256') == prerequisite['packages_sha256'], 'arm-owner-receiver-failed')
    verify_export(owner / 'public'); verify_export(owner / 'public-status')
    require(read_json(owner / 'public-status/result.json') == result, 'arm-public-status-drift')
    artifacts = owner / 'public-artifacts'
    require({p.name for p in artifacts.iterdir()} == {'development-ARM-C01-outputs.tar.gz', 'archive-manifest.json'}, 'arm-artifact-directory-invalid')
    manifest = read_json(artifacts / 'archive-manifest.json')
    require(manifest == result.get('development_artifacts') and manifest.get('image_id') == controller.image
            and manifest.get('source_commit') == controller.commit and manifest.get('source_sha256') == ZLIB_SHA,
            'arm-artifact-binding-failed')
    approved = manifest.get('files', {})
    names = {f'{variant}-{attempt}/{name}' for variant in ('baseline', 'lto') for attempt in (1, 2)
             for name in ('libz.a', 'example', 'minigzip', 'Makefile.txt', 'zconf.h.txt', 'configure.log.txt', 'LICENSE.txt')}
    names |= {'corpus/' + name for name in ('empty.bin', 'onebyte.bin', 'repeated.txt', 'allbytes.bin', 'incompressible.bin',
                                          'heldout-source.bin', 'gzip-reference.gz', 'corrupt-crc.gz', 'truncated-trailer.gz', 'manifest.json')}
    require(set(approved) == names and all(PIN.fullmatch(value) for value in approved.values()), 'arm-artifact-allowlist-failed')
    archive = artifacts / 'development-ARM-C01-outputs.tar.gz'; info = regular(archive, 8 * 1024**2)
    require(info.st_size == manifest.get('bundle_bytes') and digest(archive) == manifest.get('bundle_sha256'), 'arm-artifact-archive-drift')
    total, seen = 0, set()
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            require(member.name in names and member.name not in seen and member.isfile()
                    and member.uid == member.gid == 0 and 0 <= member.size <= 8 * 1024**2,
                    'arm-artifact-member-refused')
            require(member.mode == (0o755 if member.name.endswith(('/example', '/minigzip')) else 0o644),
                    'arm-artifact-member-mode-refused')
            total += member.size; require(total <= 64 * 1024**2, 'arm-artifact-byte-bound')
            data = stream.extractfile(member).read(member.size + 1)
            require(len(data) == member.size and hashlib.sha256(data).hexdigest() == approved[member.name], 'arm-artifact-member-drift')
            seen.add(member.name)
    require(seen == names and total == manifest.get('uncompressed_bytes'), 'arm-artifact-incomplete')
    return result


def run_arm(controller, root, output, cache):
    result = {'stage': 'arm-c01-base', 'status': 'FAIL', 'prerequisite': {'status': 'NOT RUN'}, 'public': []}
    owned = None
    try:
        root, owned, result = start(controller, root, output, 'arm-c01-base')
        lock = arm_lock(root)
        for other in (owned, root, Path(controller.native_out)):
            require(not Path(cache).is_relative_to(other) and not other.is_relative_to(Path(cache)), 'cache-input-output-overlap')
        source = fetch_zlib(cache)
        inputs = owned / 'inputs'; inputs.mkdir()
        save(inputs / 'source-input.json', {'url': ZLIB_URL, 'sha256': ZLIB_SHA, 'bytes': ZLIB_SIZE,
                                          'verification': 'reviewed exact bytes; HTTPS transport, no release-signature claim'})
        lock_copy = inputs / 'source.lock.json'; copy_regular(lock, lock_copy)
        require(digest(lock_copy) == ARM_PIN, 'arm-source-lock-copy-drift')
        owner = owned / 'owner'
        prerequisite = result['prerequisite']
        code = command([sys.executable, '-B', str(root / 'scripts/experiments/stage.py'), '--source-root', str(root),
                 '--lock', str(lock_copy), '--lock-sha256', ARM_PIN, '--source', str(source), '--source-commit', controller.commit,
                 '--image', controller.image, '--base-packages', prerequisite['packages_lock'],
                 '--base-packages-sha256', prerequisite['packages_sha256'], '--expected-packages', prerequisite['packages_lock'],
                 '--expected-packages-sha256', prerequisite['packages_sha256'], '--output', str(owner)], owned / 'driver.log', 1000)
        require(code == 0, 'arm-owner-command-failed')
        verify_arm(owner, controller, prerequisite)
        result.update(status='PASS', execution='base-only-correctness', installed_handoff='NOT CLAIMED')
    except KeyboardInterrupt:
        result.update(status='FAIL', cancelled=True, error_code='arm-cancelled')
        raise
    except Exception:
        result.update(status='FAIL', error_code='arm-stage-failed')
    finally:
        if owned is not None:
            with defer_cleanup() as events:
                owner = owned / 'owner'
                for name in ('public', 'public-status'):
                    path = owner / name
                    if path.exists():
                        try:
                            verify_export(path, allow_failure=True); result['public'].append(str(path))
                        except Exception:
                            result.update(status='FAIL', error_code='arm-publication-failed')
                if result['status'] == 'PASS':
                    result['public'].append(str(owner / 'public-artifacts'))
                try:
                    selected = owned / 'selected'; selected.mkdir()
                    for path in (owned / 'driver.log', owned / 'inputs/source-input.json'):
                        if path.exists():
                            copy_regular(path, selected / path.name)
                    public = owned / 'public'; exported = text_public(root, selected, public)
                    result['public'].append(str(public))
                    if not exported:
                        result.update(status='FAIL', error_code='arm-publication-failed')
                except Exception:
                    result.update(status='FAIL', error_code='arm-publication-failed')
                if events:
                    result.update(status='FAIL', cancelled=True, error_code='arm-cancelled')
                finish(owned, result)
                if events:
                    result.update(status='FAIL', cancelled=True, error_code='arm-cancelled')
                    finish(owned, result)
            if events:
                raise KeyboardInterrupt()
    return result


def verify_ksm_material(directory):
    """Recheck the fixed GPL source/archive bundle before recovery publication."""
    manifest = read_json(directory / 'manifest.json')
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
        relative(name); path = directory / 'source' / name; regular(path)
        require(digest(path) == pin, 'ksm-recovery-source-drift')
        expected.add('source/' + name)
    artifacts = manifest.get('artifacts')
    require(isinstance(artifacts, dict) and set(artifacts) <= {'1', '2'}, 'ksm-recovery-artifacts-invalid')
    for number, row in artifacts.items():
        require(isinstance(row, dict) and set(row) == {'filename', 'sha256'}, 'ksm-recovery-artifacts-invalid')
        name = row['filename']
        require(re.fullmatch(r'cachy-asahi-ksmctl-0\.1\.0-1-any\.pkg\.tar\.(?:xz|zst|gz)', name), 'ksm-recovery-archive-invalid')
        path = directory / ('attempt-' + number) / name; regular(path, 8 * 1024**2)
        require(PIN.fullmatch(row['sha256']) and digest(path) == row['sha256'], 'ksm-recovery-archive-drift')
        validate_ksm_package(Path(__file__).resolve().parents[3], path, reviewed)
        expected.add('attempt-' + number + '/' + name)
    actual = set()
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'ksm-recovery-symlink')
        if path.is_file():
            regular(path, 8 * 1024**2); actual.add(path.relative_to(directory).as_posix())
        else:
            require(path.is_dir(), 'ksm-recovery-special-file')
    require(actual == expected, 'ksm-recovery-extra-or-missing-file')


def recovery_public(stage, output):
    """Fixed validated directories only; never enumerate private owner trees."""
    require(stage in ('ksm', 'arm-c01-base'), 'unknown-recovery-stage')
    output = Path(output)
    require(output.is_absolute() and output.is_dir() and all(not p.is_symlink() for p in (output, *output.parents)), 'unsafe-recovery-output')
    policy = public_policy()
    paths, refused, value = [], [], None
    status = output / 'adapter-status'
    try:
        value = read_json(status / 'result.json')
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
        if path.exists() or path.is_symlink():
            try:
                verify_export(path, allow_failure=True); paths.append(str(path))
            except Exception:
                refused.append({'bundle': path.relative_to(output).as_posix(), 'error_code': 'public-bundle-refused'})
    material = output / ('public-material' if stage == 'ksm' else 'owner/public-artifacts')
    if material.exists() or material.is_symlink():
        try:
            if stage == 'ksm':
                verify_ksm_material(material)
            else:
                prerequisite = value['prerequisite']
                require(prerequisite.get('status') == 'PASS' and prerequisite.get('package_count') == 341, 'arm-recovery-prerequisite-invalid')
                verify_arm(output / 'owner', SimpleNamespace(image=prerequisite['image_id'], commit=prerequisite['source_commit']), prerequisite)
            paths.append(str(material))
        except Exception:
            refused.append({'bundle': material.relative_to(output).as_posix(), 'error_code': 'material-bundle-refused'})
    if refused:
        report = output / 'recovery-status'
        if report.exists():
            require(not report.is_symlink() and report.is_dir() and {p.name for p in report.iterdir()} == {'failure-retention.json'}, 'unsafe-recovery-report')
            regular(report / 'failure-retention.json')
        else:
            report.mkdir(mode=0o700)
        save(report / 'failure-retention.json', {'purpose': 'development-adapter-failure-retention', 'stage': stage,
             'status': 'FAIL', 'failure_retention': 'FAIL', 'bundle_rejections': refused,
             'hardware_validation': 'NOT RUN', 'private_trees_examined': False})
        paths.append(str(report))
    return paths
