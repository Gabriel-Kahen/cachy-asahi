#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Finite input/receipt bindings for the separate FDK native development stage."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

INVENTORY_SHA = '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f'
INPUTS_SHA = '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
ORIGINALS_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
TEMPLATE_SHA = 'bbe7ca8746ac142ef90d25dbec58a116e59d9dbea3a193fa9b2a725c37aaeb9c'
RECIPE_SHA = '6d5927fbeddcfe21af0e212abbe029e48805bc0927968f6c913a8c94de1f8dea'
ENTRY_SHA = '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24'
EPOCH = 1791748800
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
PIN = re.compile(r'[0-9a-f]{64}\Z')
PACKAGE = re.compile(r'cachy-asahi-fdk-aac-3\.0\.0-1-aarch64\.pkg\.tar\.(?:zst|xz|gz)\Z')


def need(ok, code):
    if not ok:
        raise ValueError(code)


def read(path, limit=8 * 1024 ** 2):
    path = Path(path).absolute()
    need('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'input-parent')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'input-file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'input-race')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        need(len(data) <= limit and (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input-race')
        need((path.lstat().st_dev, path.lstat().st_ino) == (opened.st_dev, opened.st_ino), 'input-race')
        return data
    finally:
        os.close(fd)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path, limit=64 * 1024 ** 2):
    return sha(read(path, limit))


def decode(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json')
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique,
                        parse_constant=lambda _: need(False, 'nonfinite-json'))
    need(type(result) is dict, 'object-required')
    return result


def load(path, pin=None, limit=8 * 1024 ** 2):
    data = read(path, limit)
    if pin is not None:
        need(PIN.fullmatch(pin or '') and sha(data) == pin, 'file-pin')
    return decode(data)


def save(path, value):
    path = Path(path)
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def inventory(data):
    need(sha(data) == INVENTORY_SHA, 'inventory-pin')
    text = data.decode('utf-8')
    rows = text.splitlines(keepends=True)
    need(len(rows) == 341 and rows == sorted(rows) and all(r.endswith('\n') for r in rows), 'inventory-format')
    result = {}
    for row in rows:
        fields = row.strip().split(' ')
        need(len(fields) == 2 and all(fields) and fields[0] not in result, 'inventory-format')
        result[fields[0]] = fields[1]
    return result


def accepted_base(bootstrap, lockbytes, inputbytes, result, image, commit, native_script_sha):
    need(IMAGE.fullmatch(image or '') and re.fullmatch(r'[0-9a-f]{40}', commit or ''), 'image-commit-pin')
    packages = inventory(lockbytes)
    need(sha(inputbytes) == INPUTS_SHA, 'base-inputs-pin')
    inputs = decode(inputbytes)
    expected = {r['name'][0]: r['version'][0] for r in inputs['rootfs_packages']}
    expected.update({r['name']: r['version'] for r in inputs['packages']})
    need(packages == expected and inputs['source_date_epoch'] == EPOCH, 'base-inputs-inventory')
    need(bootstrap.get('status') == 'image-provisioned' and bootstrap.get('image_id') == image and
         bootstrap.get('packages_lock_sha256') == INVENTORY_SHA and bootstrap.get('inputs_sha256') == INPUTS_SHA,
         'bootstrap-binding')
    need(result.get('native_build') == 'PASS' and result.get('reviewed_inputs_sha256') == INPUTS_SHA and
         result.get('reviewed_recipes_sha256') == ORIGINALS_SHA and
         result.get('bootstrap_script_sha256') == native_script_sha, 'accepted-original-builds')
    # The original result has no commit field; the controller binds checkout/GITHUB_SHA.
    return {'status': 'PASS', 'image_id': image, 'source_commit': commit,
            'package_count': 341, 'packages_sha256': INVENTORY_SHA, 'inputs_sha256': INPUTS_SHA,
            'original_lifecycle_acceptance': 'NOT INFERRED'}


def validate_receipt(record, reviewed, image, inventory_sha=INVENTORY_SHA):
    need(record.get('status') == 'built-package-static-pass' and record.get('mode') == 'native' and
         record.get('network') == 'none' and record.get('image') == record.get('image_id') == image and
         record.get('source_date_epoch') == EPOCH and record.get('recipe_inputs') == reviewed and
         record.get('expected_packages_sha256') == inventory_sha, 'build-receipt-binding')
    need(type(record.get('exit_code')) is int and record['exit_code'] == 0 and
         record.get('builder_host_arch') in ('aarch64', 'arm64') and
         record.get('entry_script_sha256') == ENTRY_SHA, 'build-native-exit')
    name = record.get('clean_environment_id', '')
    need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'build-container-name')
    command = record.get('command', [])
    need(type(command) is list and len(command) == 39 and all(type(v) is str for v in command), 'build-command')
    need(re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*', command[9]), 'build-command-user')
    prefix = ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform', 'linux/arm64',
              '--user', command[9], '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
              '--pids-limit', '512', '--memory', '4g', '--cpus', '4', '--network', 'none',
              '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g', '--env', 'CACHY_ASAHI_CONTAINER=1',
              '--env', 'SOURCE_DATE_EPOCH=' + str(EPOCH)]
    need(command[:27] == prefix and command[-4:] == ['--entrypoint', '/bin/bash', image, '/builder-entry.sh'], 'build-command')
    for index, dest, suffix in ((27, '/inputs', ',readonly'), (29, '/out', ''),
                                 (31, '/builder-entry.sh', ',readonly'), (33, '/expected-packages.lock', ',readonly')):
        need(command[index] == '--mount', 'build-command-mount')
        value = command[index + 1]
        end = ',dst=' + dest + suffix
        need(value.startswith('type=bind,src=/') and value.endswith(end), 'build-command-mount')
        source = value[len('type=bind,src='):-len(end)]
        need(',' not in source and '\n' not in source and '..' not in Path(source).parts, 'build-command-mount')
    artifacts = record.get('artifacts', {})
    need(type(artifacts) is dict and len(artifacts) == 1, 'build-single-artifact')
    filename, checksum = next(iter(artifacts.items()))
    need(PACKAGE.fullmatch(filename) and PIN.fullmatch(checksum or ''), 'build-artifact-pin')
    files = record.get('files', {})
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf', 'artifacts/fdk-build-commands.json'}
    need(type(files) is dict and required <= set(files), 'build-evidence-missing')
    return {'filename': filename, 'sha256': checksum, 'container_name': name}


def safe_relative(name):
    need(type(name) is str and name and '\\' not in name and
         all(32 <= ord(c) < 127 for c in name), 'evidence-path')
    path = Path(name)
    need(not path.is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')), 'evidence-path')
    return path


def verify_attempt(directory, reviewed, image, inspect_package, inspect_recipe, bind_artifact):
    directory = Path(directory)
    record = load(directory / 'provenance.json')
    result = validate_receipt(record, reviewed, image)
    for name, checksum in record['files'].items():
        need(PIN.fullmatch(checksum or '') and digest(directory / safe_relative(name)) == checksum, 'evidence-file-drift')
    for name, checksum in reviewed.items():
        need(digest(directory / 'inputs' / safe_relative(name)) == checksum, 'recipe-snapshot-drift')
    recipe = inspect_recipe(directory / 'inputs/PKGBUILD')
    need(recipe.get('errors') == [] and recipe.get('input_sha256') == reviewed and
         record.get('recipe_metadata') == recipe.get('metadata'), 'recipe-metadata-reparse')
    archive = directory / 'artifacts' / result['filename']
    need(digest(archive) == result['sha256'], 'archive-drift')
    need({p.name for p in (directory / 'artifacts').glob('*.pkg.tar.*')} == {result['filename']}, 'artifact-set')
    need(digest(directory / 'expected-packages.lock') == digest(directory / 'artifacts/packages.lock') == INVENTORY_SHA,
         'build-inventory-drift')
    validation = load(directory / 'validation.json')
    need(validation.get('errors') == [] and len(validation.get('artifacts', [])) == 1, 'artifact-validation')
    package = validation['artifacts'][0]
    need(package == inspect_package(archive), 'artifact-validation-reparse')
    need(bind_artifact(recipe['metadata'], package, reviewed['PKGBUILD']) == [], 'artifact-metadata-reparse')
    need(package.get('errors') == [] and package.get('sha256') == result['sha256'] and len(package.get('elf', {})) == 2,
         'artifact-ELF-validation')
    need(package['metadata']['.BUILDINFO']['pkgbuild_sha256sum'] == [reviewed['PKGBUILD']], 'artifact-recipe-binding')
    base = inventory(read(directory / 'expected-packages.lock'))
    installed = package['metadata']['.BUILDINFO']['installed']
    need(all(type(v) is str and v.endswith(('-aarch64', '-any')) for v in installed) and
         sorted(v.rsplit('-', 1)[0] for v in installed) == sorted(n + '-' + v for n, v in base.items()),
         'artifact-buildinfo-inventory')
    log = read(directory / 'build.log').decode('utf-8')
    abi = [decode(line.encode()) for line in log.splitlines() if line.startswith('{') and 'native-ELF-ABI-pass' in line]
    need(len(abi) == 1 and abi[0].get('status') == 'native-ELF-ABI-pass', 'native-ABI-receipt')
    libraries = abi[0].get('libraries', {})
    need(set(libraries) == {'libfdk-aac', 'libfdk-xhe-aac'}, 'native-ABI-receipt')
    for name, soname, count in [('libfdk-aac', 'libfdk-aac.so.2', 18), ('libfdk-xhe-aac', 'libfdk-xhe-aac.so.0', 63)]:
        row = libraries[name]
        need(row.get('soname') == soname and row.get('exports') == count and row.get('elf_16k_geometry') == 'PASS' and
             type(row.get('needed')) is list and set(row['needed']) <= {'libc.so.6', 'libm.so.6', 'ld-linux-aarch64.so.1'},
             'native-ABI-receipt')
    frames = re.findall(r'^PASS: classic AAC-LC ADTS roundtrip; ([0-9]+) decoded mono frames at 48000 Hz$', log, re.M)
    need(len(frames) == 1 and 24 <= int(frames[0]) <= 40 and
         log.splitlines().count('PASS: xHE API 1.0AOSP configuration lifecycle; encoding/roundtrip NOT RUN') == 1,
         'native-smoke-receipt')
    result.update(abi=libraries, classic_decoded_frames=int(frames[0]), xhe_scope='configuration-only', hardware='NOT RUN')
    return result


def compare_result(record, filename, names):
    need(len(names) == 2 and names[0] != names[1], 'independent-containers')
    need(record.get('status') == 'contents-reproduced' and record.get('errors') == [] and
         set(record.get('packages', {})) == {filename}, 'rebuild-comparison')
    need(all(record['packages'][filename].get(k) is True for k in
             ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')), 'rebuild-comparison')
    return {'status': 'PASS', 'bytes': True, 'payload': True, 'PKGINFO': True, 'BUILDINFO': True}


def finalstatus_public(report):
    cleanup = report.get('cleanup', {})
    passed = (report.get('status') == 'PASS' and report.get('phase') == 'complete' and
        report.get('cancelled') is False and cleanup.get('absence_verified') is True and
        cleanup.get('status') == 'PASS' and report.get('comparison', {}).get('status') == 'PASS' and
        all(report.get(k, {}).get('status') == 'PASS' for k in ('accepted_base', 'live_base', 'source', 'build-1', 'build-2')) and
        all(report[k].get('cleanup', {}).get('status') == 'PASS' and
            report[k]['cleanup'].get('absence_verified') is True for k in ('build-1', 'build-2')))
    return {'schema_version': 1, 'stage': 'fdk-native-development', 'status': 'PASS' if passed else 'FAIL',
            'phase': report.get('phase') if report.get('phase') in {'preflight', 'base-probe', 'source', 'build-1', 'build-2', 'compare', 'complete'} else 'preflight',
            'error_code': None if passed else 'fdk-stage-failed', 'cancelled': report.get('cancelled') is True,
            'owned_container_absence': cleanup.get('absence_verified') is True,
            'native_build': 'PASS' if passed else 'NOT ACCEPTED', 'hardware': 'NOT RUN',
            'installation': 'NOT RUN', 'selected_for_release': False, 'binary_publication': 'NOT RUN'}
