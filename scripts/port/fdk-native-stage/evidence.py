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

INVENTORY_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
ORIGINALS_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
TEMPLATE_SHA = '271473fefbce924b437dbd8d34757fb4b0d0626bef7ea63313617c80b229b4b9'
RECIPE_SHA = '1e0010aef08294051de95554baf8b85bddd507285ac6d697b16b4ad09f16bf93'
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


def verify_attempt(directory, reviewed, image, inspect_package, inspect_recipe, bind_artifact, *, record=None, log_bytes=None):
    directory = Path(directory)
    record = load(directory / 'provenance.json') if record is None else record
    result = validate_receipt(record, reviewed, image)
    log_data = read(directory / 'build.log') if log_bytes is None else log_bytes
    need(type(log_data) is bytes and len(log_data) <= 8 * 1024**2, 'captured-build-log-bound')
    for name, checksum in record['files'].items():
        safe_relative(name)
        actual = sha(log_data) if name == 'build.log' else digest(directory / name)
        need(PIN.fullmatch(checksum or '') and actual == checksum, 'evidence-file-drift')
    for name, checksum in reviewed.items():
        need(digest(directory / 'inputs' / safe_relative(name)) == checksum, 'recipe-snapshot-drift')
    recipe = inspect_recipe(directory / 'inputs/PKGBUILD')
    need(recipe.get('errors') == [] and recipe.get('input_sha256') == reviewed and
         record.get('recipe_metadata') == recipe.get('metadata'), 'recipe-metadata-reparse')
    archive = directory / 'artifacts' / result['filename']
    archive_raw = read(archive, 64 * 1024**2)  # Same read and cap as the prior digest call.
    archive_bytes = len(archive_raw)
    need(sha(archive_raw) == result['sha256'], 'archive-drift')
    del archive_raw
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
    log = log_data.decode('utf-8')
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
    result.update(abi=libraries, classic_decoded_frames=int(frames[0]), xhe_scope='configuration-only', hardware='NOT RUN',
                  accepted_output=project_accepted_output(package, reviewed, archive_bytes))
    return result


def compare_result(record, filename, names):
    need(len(names) == 2 and names[0] != names[1], 'independent-containers')
    need(record.get('status') == 'contents-reproduced' and record.get('errors') == [] and
         set(record.get('packages', {})) == {filename}, 'rebuild-comparison')
    need(all(record['packages'][filename].get(k) is True for k in
             ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')), 'rebuild-comparison')
    return {'status': 'PASS', 'bytes': True, 'payload': True, 'PKGINFO': True, 'BUILDINFO': True}


def finalstatus_public(report):
    # FDK-only lazy dependency: standalone kernel accepted_base loading uses none
    # of this helper, and keeps its original function/dependency contract.
    import worker_evidence as worker_diagnostic
    workers = report.get('worker_diagnostics', {name: worker_diagnostic.worker_row() for name in worker_diagnostic.ACTIONS})
    workers = worker_diagnostic.validate_workers(workers)
    cleanup = report.get('cleanup', {})
    passed = (report.get('status') == 'PASS' and report.get('phase') == 'complete' and
        report.get('cancelled') is False and cleanup.get('absence_verified') is True and
        cleanup.get('status') == 'PASS' and report.get('comparison', {}).get('status') == 'PASS' and
        all(report.get(k, {}).get('status') == 'PASS' for k in ('accepted_base', 'live_base', 'source', 'build-1', 'build-2')) and
        all(report[k].get('cleanup', {}).get('status') == 'PASS' and
            report[k]['cleanup'].get('absence_verified') is True for k in ('build-1', 'build-2')) and
        all(row['availability'] == 'VERIFIED' and row['exit'] == worker_diagnostic.exit_record(0) and
            row['observation']['current_predicate'] == 'COMPLETE' for row in workers.values()))
    if passed:
        workers = worker_diagnostic.validate_workers(workers, require_complete=True)
    accepted_outputs = accepted_outputs_public(report) if passed else None
    return {'schema_version': 3, 'stage': 'fdk-native-development', 'status': 'PASS' if passed else 'FAIL',
            'phase': report.get('phase') if report.get('phase') in {'preflight', 'base-probe', 'source', 'build-1', 'build-2', 'compare', 'complete'} else 'preflight',
            'error_code': None if passed else 'fdk-stage-failed', 'cancelled': report.get('cancelled') is True,
            'owned_container_absence': cleanup.get('absence_verified') is True,
            'native_build': 'PASS' if passed else 'NOT ACCEPTED', 'hardware': 'NOT RUN',
            'installation': 'NOT RUN', 'selected_for_release': False, 'binary_publication': 'NOT RUN',
            'worker_diagnostics': workers, 'accepted_outputs': accepted_outputs}


OUTPUT_SOURCE_NAMES = {
    'recipe_sha256': 'PKGBUILD',
    'selected_archive_sha256': 'fdk-aac-3.0.0-selected-source.tar',
    'source_provenance_sha256': 'source-provenance.json',
    'selected_manifest_sha256': 'selected-source-manifest.json',
    'notice_classic_sha256': 'NOTICE.classic',
    'notice_xhe_sha256': 'NOTICE.xhe-aac',
    'copyrights_sha256': 'COPYRIGHTS-and-LICENSES',
    'project_license_sha256': 'LICENSE.MIT',
    'source_delivery_instructions_sha256': 'PUBLICATION.md',
}
# Populated from the existing independently pinned reviewed-input map.
OUTPUT_SOURCE_PINS = {'recipe_sha256': '15766490a8efbcedbfe116ae6fae166fd7a78c02ae66ab7f0739e26a0b5035a5', 'selected_archive_sha256': '1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4', 'source_provenance_sha256': '2f5d3c3124bdc564e9183aac8a534e51ac03c078f8312395370b8454b435cae3', 'selected_manifest_sha256': '3eb66e2e1632cf65044f9250c7460b1effe0de3217f83b573b4e23885772fc29', 'notice_classic_sha256': '95ec80da40b4af12ad4c4f3158c9cfb80f2479f3246e4260cb600827cc8c7836', 'notice_xhe_sha256': 'bf3e762249027586195def2b2e904901b42c8b7fab455fc66bf365f70d08de6d', 'copyrights_sha256': 'a0a52a99bef6dea5c370711f17ed1c02e8b0989a4c167f4e54a36368987428c0', 'project_license_sha256': '4d263ff2b095160e3b9244a132d248234241b83eed71b849decef6a3ba3fa795', 'source_delivery_instructions_sha256': '0db09f321999befabe795066a388c271db786377d312a3f60c84424cb7685efa'}


def output_keys(value, keys):
    need(type(value) is dict and all(type(k) is str for k in value) and
         set(value) == set(keys), 'accepted-output-keys')


def validate_accepted_output(value):
    output_keys(value, {'schema_version', 'archive', 'package', 'metadata', 'source'})
    need(type(value['schema_version']) is int and value['schema_version'] == 1, 'accepted-output-schema')
    archive = value['archive']
    output_keys(archive, {'name', 'bytes', 'sha256'})
    need(type(archive['name']) is str and PACKAGE.fullmatch(archive['name']) and
         type(archive['bytes']) is int and 0 < archive['bytes'] <= 64 * 1024**2 and
         type(archive['sha256']) is str and PIN.fullmatch(archive['sha256']), 'accepted-output-archive')
    package = value['package']
    output_keys(package, {'name', 'version', 'architecture'})
    need(all(type(v) is str for v in package.values()) and
         package == {'name': 'cachy-asahi-fdk-aac', 'version': '3.0.0-1', 'architecture': 'aarch64'},
         'accepted-output-package')
    metadata = value['metadata']
    output_keys(metadata, {'PKGINFO', 'BUILDINFO'})
    for row in metadata.values():
        output_keys(row, {'bytes', 'sha256'})
        need(type(row['bytes']) is int and 0 < row['bytes'] <= 128 * 1024**2 and
             type(row['sha256']) is str and PIN.fullmatch(row['sha256']), 'accepted-output-metadata')
    source = value['source']
    output_keys(source, OUTPUT_SOURCE_NAMES)
    need(all(type(v) is str and PIN.fullmatch(v) for v in source.values()) and
         source == OUTPUT_SOURCE_PINS, 'accepted-output-source')
    need(len(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()) <= 2048,
         'accepted-output-bound')
    return json.loads(json.dumps(value, allow_nan=False))


def project_accepted_output(package, reviewed, archive_bytes):
    """Inputs have passed verify_attempt; no read/stat/archive parsing here."""
    need(type(package) is dict and all(type(k) is str for k in package) and type(reviewed) is dict and
         all(type(k) is str for k in reviewed), 'accepted-output-input')
    metadata, members = package['metadata'], package['members']
    need(type(metadata) is dict and all(type(k) is str for k in metadata) and
         type(members) is dict and all(type(k) is str for k in members), 'accepted-output-input')
    pkg, build = metadata['.PKGINFO'], metadata['.BUILDINFO']
    need(type(pkg) is dict and all(type(k) is str for k in pkg) and
         type(build) is dict and all(type(k) is str for k in build), 'accepted-output-input')
    identity = {}
    for source, target in (('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'architecture')):
        values = pkg[source]
        need(type(values) is list and len(values) == 1 and type(values[0]) is str, 'accepted-output-identity')
        identity[target] = values[0]
    need(type(build['pkgbuild_sha256sum']) is list and all(type(v) is str for v in build['pkgbuild_sha256sum']) and
         build['pkgbuild_sha256sum'] == [reviewed['PKGBUILD']],
         'accepted-output-recipe')
    stamps = {}
    for name in ('PKGINFO', 'BUILDINFO'):
        member = members['.' + name]
        need(type(member) is dict and all(type(k) is str for k in member) and
             type(member['type']) is str and member['type'] in ('0', '\x00'),
             'accepted-output-member')
        stamps[name] = {'bytes': member['size'], 'sha256': member['sha256']}
    return validate_accepted_output({'schema_version': 1,
        'archive': {'name': package['artifact'], 'bytes': archive_bytes, 'sha256': package['sha256']},
        'package': identity, 'metadata': stamps,
        'source': {key: reviewed[name] for key, name in OUTPUT_SOURCE_NAMES.items()}})


def validate_accepted_outputs(value):
    output_keys(value, {'schema_version', 'builds', 'comparison'})
    need(type(value['schema_version']) is int and value['schema_version'] == 1, 'accepted-outputs-schema')
    output_keys(value['builds'], {'build-1', 'build-2'})
    rows = [validate_accepted_output(value['builds'][name]) for name in ('build-1', 'build-2')]
    comparison = value['comparison']
    output_keys(comparison, {'status', 'bytes', 'payload', 'PKGINFO', 'BUILDINFO'})
    need(type(comparison['status']) is str and comparison['status'] == 'PASS' and
         all(comparison[k] is True for k in ('bytes', 'payload', 'PKGINFO', 'BUILDINFO')),
         'accepted-outputs-comparison')
    need(rows[0] == rows[1], 'accepted-outputs-equality')
    need(len(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()) <= 4096,
         'accepted-outputs-bound')
    return {'schema_version': 1, 'builds': {'build-1': rows[0], 'build-2': rows[1]},
            'comparison': {'status': 'PASS', 'bytes': True, 'payload': True, 'PKGINFO': True, 'BUILDINFO': True}}


def accepted_outputs_public(report):
    """Join two accepted workers with the comparator's revalidated attempts."""
    rows = {}
    for name in ('build-1', 'build-2'):
        worker = report[name]
        need(type(worker) is dict and worker['status'] == 'PASS' and worker['cancelled'] is False,
             'accepted-outputs-worker')
        rows[name] = validate_accepted_output(worker['artifact']['accepted_output'])
    attempts = report['comparison_attempts']
    need(type(attempts) is list and len(attempts) == 2, 'accepted-outputs-attempts')
    for index, name in enumerate(('build-1', 'build-2')):
        need(type(attempts[index]) is dict and
             validate_accepted_output(attempts[index]['accepted_output']) == rows[name],
             'accepted-outputs-revalidation')
    return validate_accepted_outputs({'schema_version': 1, 'builds': rows,
                                     'comparison': report['comparison']})
