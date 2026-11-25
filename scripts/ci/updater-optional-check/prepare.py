#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the 4.4.2-3 installed Check capsule from a private native build pair."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HISTORICAL = HERE / 'historical'  # Exact bytes from 480053c0866a922138d85af2b9880fb0e10d7b2c.
PACKAGE = 'packages/tools/cachy-asahi-update/'
BUILDER_LOCK = 'scripts/port/updater-extension/expected-packages.lock'
BUILDER_SHA = '5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee'
PKGBUILD_SHA = '6e8b65f396510d59a1196949b062bad924ea0af4e38b58b4dfe0e47f74e16d60'
ADAPTER_SHA = '0b65eb3ce5eea5e537dbcf4bfe9da41a662f5ce5690cbac5c3f7a8b03d2d285b'
CHECKER = 'scripts/checks/package_checks.py'
CHECKER_SHA = '314e8b4a0920b3f6d93619fc74ad1d63a6210d1b17b925618451b493d2610a1a'
# Worker provenance indexes the retained source closure. Match the public evidence reader.
PROVENANCE_LIMIT = 4 * 1024**2
RESULT_LIMIT = 16 * 1024
EXPECTED_CASE_EXITS = {
    'pending-versioned': 0,
    'invalid-signature-preserves-pending': 20,
    'missing-signature-preserves-pending': 20,
    'no-updates-clears-pending': 0,
    'pending-no-version': 0,
    'missing-signature-preserves-no-version': 20,
    'optional-pending': 0,
    'optional-aur-failure': 20,
    'optional-user-discovery-failure': 20,
    'optional-system-discovery-failure': 20,
    'optional-appstream-failure': 20,
    'optional-mask-failure': 20,
    'optional-remote-failure': 20,
    'optional-empty': 0,
    'unconfigured-full-update': 21,
}
PINS = {
    'inside.py': '64a969ea0dc79ae3488d9ede3ced4195676aaf5bde314c55bcbc439cb7ef0591',
    'real-check/real-check.py': '1ac6cc2e9fab5ac3249f2ff4c6691ced389ea35e04be80b7a73b5aafb57a7b41',
    'dependencies/expected-installed-packages.lock': '1b8e0653fd0063d09f5818d86cb3b77fdc7f667f2aa78c2eca4a29c6209ae5ad',
    'dependencies/inputs.lock.json': '9a8064cde23ad90c2352395bdd1f6f5a8e843b3db3468cd2cc5a90829dc32704',
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit, expected=None):
    need(path.resolve(strict=True) == path, 'canonical input path required')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
             'bounded ordinary input required')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
         and len(raw) == before.st_size, 'input changed while reading')
    need(expected is None or digest(raw) == expected, 'input digest differs: ' + path.name)
    return raw


def historical(path):
    return read(HISTORICAL / path, 64 * 1024, PINS[path])


def replace(data, old, new):
    need(data.count(old) == 1, 'one exact historical transform seam required')
    return data.replace(old, new)


def inventory(raw):
    rows = [line.split() for line in raw.decode('ascii').splitlines()]
    need(all(len(row) == 2 for row in rows) and len(dict(rows)) == len(rows), 'invalid inventory')
    return dict(rows)


def preflight():
    read(ROOT / PACKAGE / 'PKGBUILD', 64 * 1024, PKGBUILD_SHA)
    read(ROOT / PACKAGE / 'updater-native.py', 64 * 1024, ADAPTER_SHA)
    read(ROOT / CHECKER, 64 * 1024, CHECKER_SHA)
    builder = read(ROOT / BUILDER_LOCK, 64 * 1024, BUILDER_SHA)
    dependencies = json.loads(historical('dependencies/inputs.lock.json'))
    prior = historical('dependencies/expected-installed-packages.lock')
    installed = replace(prior, b'cachy-asahi-update 4.4.2-2\n', b'cachy-asahi-update 4.4.2-3\n')
    base = inventory(builder)
    additions = {row['name']: row['version'] for row in dependencies['packages']}
    need(len(base) == 354 and len(additions) == 5 and not (base.keys() & additions.keys())
         and inventory(installed) == base | additions | {'cachy-asahi-update': '4.4.2-3'},
         'exact compiler and runtime inventories differ')
    inside = replace(
        historical('inside.py'),
        b"        result['check_cases'] = checks.exercise(work, signing, fingerprints[0])",
        b"        optional_spec = importlib.util.spec_from_file_location(\n"
        b"            'installed_optional_cases', inputs / 'real-check/optional_cases.py')\n"
        b"        optional = importlib.util.module_from_spec(optional_spec)\n"
        b"        optional_spec.loader.exec_module(optional)\n"
        b"        result['check_cases'] = checks.exercise(work, signing, fingerprints[0], optional.exercise)",
    )
    inside = replace(inside, b"    inputs, output = Path('/inputs'), Path('/out/result.json')",
                     b"    inputs = Path('/inputs')")
    inside = replace(
        inside, b'def main():',
        b"def complete_cases(check):\n"
        b"    expected = " + repr(EXPECTED_CASE_EXITS).encode('ascii') + b"\n"
        b"    cases = check['cases']\n"
        b"    return (check['status'] == 'PASS' and cases.keys() == expected.keys()\n"
        b"            and all(type(cases[name].get('exit')) is int and cases[name]['exit'] == code\n"
        b"                    for name, code in expected.items()))\n\n\n"
        b"def emit_result(result):\n"
        b"    receipt = json.dumps(result, separators=(',', ':'), sort_keys=True, allow_nan=False)\n"
        b"    need(len(receipt.encode('ascii')) + 1 <= " + str(RESULT_LIMIT).encode('ascii')
        + b", 'installed receipt exceeds bound')\n"
        b"    print(receipt, flush=True)\n\n\n"
        b"def main():",
    )
    inside = replace(
        inside, b"        need(result['check_cases']['status'] == 'PASS', 'installed real Check cases failed')",
        b"        need(complete_cases(result['check_cases']), 'installed real Check cases failed')",
    )
    inside = replace(
        inside, rb"        output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')",
        b"        emit_result(result)",
    )
    real_check = replace(historical('real-check/real-check.py'), b'cachy-asahi-update 4.4.2-2',
                         b'cachy-asahi-update 4.4.2-3')
    real_check = replace(real_check, b'def exercise(work, signing, fingerprint):',
                         b'def exercise(work, signing, fingerprint, optional_cases):')
    real_check = replace(
        real_check, b"        result['phase'] = 'unconfigured-full-update-refusal'",
        b"        repository('0.1.0-1')\n"
        b"        optional_cases(home, config_file, result, run, user_command, snapshot, need)\n"
        b"        result['phase'] = 'unconfigured-full-update-refusal'",
    )
    optional = read(HERE / 'optional_cases.py', 64 * 1024)
    files = {'inside.py': inside, 'real-check/real-check.py': real_check,
             'real-check/optional_cases.py': optional, 'compiler-packages.lock': builder,
             'expected-installed-packages.lock': installed}
    for name, data in files.items():
        if name.endswith('.py'):
            compile(data, name, 'exec')
    return files, dependencies


def load(name, path, expected):
    raw = read(path, 64 * 1024, expected)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), vars(module))
    return module


def select_archive(artifacts):
    archives = sorted(artifacts.glob('*.pkg.tar.*'))
    need(len(archives) == 1 and archives[0].suffix in {'.xz', '.zst'},
         'one supported native package required')
    return archives[0]


def stage(native, cache, output, progress=lambda _phase: None):
    progress('source-closure')
    files, dependencies = preflight()
    progress('directories')
    native, cache, output = (path.absolute() for path in (native, cache, output))
    need(output.is_relative_to('/tmp') and output.parent.resolve(strict=True) == output.parent
         and not output.exists() and not output.is_symlink()
         and output.parent.stat().st_uid == os.getuid() > 0
         and stat.S_IMODE(output.parent.stat().st_mode) == 0o700
         and not any(c in str(output) for c in ',\n'), 'fresh private output required')
    need(all(path.resolve(strict=True) == path and path.is_dir() and path.stat().st_uid == os.getuid()
             for path in (native, cache)), 'canonical owned pair and cache directories required')
    progress('pair-comparison')
    adapter = load('private_build_pair', ROOT / PACKAGE / 'updater-native.py', ADAPTER_SHA)
    checker = load('private_package_checks', ROOT / CHECKER, CHECKER_SHA)
    first, second = native / 'build-1', native / 'build-2'
    comparison = adapter.compare_pair(first, second, checker)
    need(not comparison['errors'], 'exact clean pair required')
    progress('builder-receipt')
    raw_result = json.loads(read(native / 'result.json', 64 * 1024))
    image = read(native / 'image-id', 256).decode().strip()
    need(raw_result['native_pair'] == 'PASS' and raw_result['inventory_sha256'] == BUILDER_SHA
         and raw_result['image_id'] == image and re.fullmatch(r'sha256:[0-9a-f]{64}', image)
         and read(native / 'packages.lock', 64 * 1024, BUILDER_SHA) == files['compiler-packages.lock'],
         'native build result or image differs')
    progress('archive-selection')
    archive = select_archive(first / 'artifacts')
    progress('archive-inspection')
    report = checker.package(archive)
    need(not report['errors'], 'native archive inspection failed')
    progress('archive-controller')
    controller = json.loads(read(first / 'inputs/controller-input.json', 1024**2))
    need(controller['recipe_input_sha256']['PKGBUILD'] == PKGBUILD_SHA
         and controller['image_id'] == image and controller['builder_inventory_sha256'] == BUILDER_SHA,
         'wrong recipe, build image or builder inventory')
    progress('archive-metadata')
    metadata = report['metadata']['.PKGINFO']
    need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum'] == [PKGBUILD_SHA]
         and metadata['pkgname'] == ['cachy-asahi-update'] and metadata['pkgver'] == ['4.4.2-3']
         and metadata['arch'] == ['aarch64'] and len(metadata['depend']) == 18,
         'wrong archive metadata')
    progress('archive-provenance')
    recorded = json.loads(read(first / 'provenance.json', PROVENANCE_LIMIT))['package_sha256']
    need(report['sha256'] == recorded, 'archive inspection digest differs from native provenance')
    progress('archive-copy')
    files['updater.pkg.tar.xz'] = read(archive, 64 * 1024**2, recorded)
    progress('runtime-inputs')
    for row in dependencies['packages']:
        for name, size, checksum in (
            (row['filename'], row['size'], row['sha256']),
            (row['filename'] + '.sig', row['signature_size'], row['signature_sha256']),
        ):
            need(Path(name).name == name, 'invalid dependency archive name')
            data = read(cache / name, size, checksum)
            need(len(data) == size, 'dependency size differs')
            files['dependencies/' + name] = data
    key, = [row for row in dependencies['keyring_files'] if row['filename'] == 'archlinuxarm.gpg']
    files[key['filename']] = read(cache / key['filename'], key['size'], key['sha256'])
    files['runtime.json'] = (json.dumps({'package_sha256': recorded, 'packages': dependencies['packages'],
                                       'runtime_dependencies': metadata['depend'],
                                       'signer_fingerprint': dependencies['signer_fingerprint']},
                                      sort_keys=True) + '\n').encode()
    progress('capsule-write')
    output.mkdir(mode=0o700)
    for name, data in files.items():
        target = output / name
        target.parent.mkdir(mode=0o700, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    return {'source_preflight': 'PASS', 'private_inputs': 'PASS', 'native_image': image,
            'package_sha256': recorded, 'installation': 'NOT RUN'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-output', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    phase = 'source-closure'

    def progress(value):
        nonlocal phase
        phase = value

    try:
        if any((args.native_output, args.cache, args.output)):
            if not all((args.native_output, args.cache, args.output)):
                parser.error('provide all three native staging operands')
            result = stage(args.native_output, args.cache, args.output, progress)
        else:
            files, dependencies = preflight()
            result = {'source_preflight': 'PASS', 'expected_package_count': 360,
                      'staged_dependency_count': len(dependencies['packages']),
                      'capsule_source_sha256': {name: digest(data) for name, data in files.items()},
                      'installation': 'NOT RUN'}
    except Exception as error:
        if isinstance(error, FileNotFoundError):
            problem = 'missing-input'
        elif isinstance(error, PermissionError):
            problem = 'permission'
        elif isinstance(error, OSError):
            problem = 'io-error'
        elif isinstance(error, (KeyError, TypeError, ValueError)):
            problem = 'invalid-input'
        else:
            problem = 'unexpected'
        print(json.dumps({'status': 'FAIL', 'phase': phase, 'problem': problem}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
