#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare five package-input DATA operands; never construct or run a Source."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('current_package_data', HERE / 'current_package_inputs.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
SOURCE419 = '419d27f1d519dc91789a322385eb603bd1ca1f09'
OUTPUTS = ('source-tools-sources-v2.tar', 'source-tools-inputs-v2.json',
    'source-tools-makepkg-v2.conf', 'source_tools_current_check_v2.py',
    'source_tools_current_package_v2.py')
CHECK_FIELDS = ('sources', 'files', 'payload_files')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def read(path, cap=package.MAX_FILE):
    path = Path(path).absolute()
    package.need(path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)),
                 'ordinary canonical input path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        package.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
                     'finite single-link input')
        chunks, total = [], 0
        while block := os.read(fd, min(65536, cap + 1 - total)):
            chunks.append(block); total += len(block)
            package.need(total <= cap, 'input byte cap')
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        package.need(total == before.st_size and key(before) == key(os.fstat(fd)) == key(path.lstat()),
                     'input changed while reading')
        return b''.join(chunks)
    finally:
        os.close(fd)


def policy(selection, value):
    """Reject stale native policies and any inferred execution authority."""
    package.selection(selection)
    package.need(set(value) == {'schema', 'purpose', 'operation', 'package', 'recipe', 'checks',
        'dependencies', 'actual', 'admission', 'retained_v1', 'build_pair', 'signed_ALPM',
        'installed_workflow', 'future_integration', 'makepkg_config', 'current_check_module',
        'current_package_module', 'failure_retention'}, 'closed integration fields')
    package.need(value['schema'] == 2 and type(value['schema']) is int
        and value['purpose'] == 'source-tools-current-package-native-inputs'
        and value['operation'] == 'source-tools-alpm-v2', 'current integration identity')
    package.need(value['package'] == selection['package'] and value['checks'] == selection['checks']
        and all(type(n) is int for n in value['checks'].values())
        and value['dependencies'] == selection['dependencies'], 'current package/check/dependency bindings')
    package.need({key: value['recipe'][key] for key in CHECK_FIELDS} == selection['recipe'],
                 'exact current16 sources and18 payload')
    package.need(set(value['recipe']) == {*CHECK_FIELDS, 'bundle', 'archive', 'expected_pkginfo'}
        and value['recipe']['archive'] == 'cachy-asahi-source-tools-0.2.0-1-any.pkg.tar.zst'
        and value['recipe']['expected_pkginfo'] == dict(pkgname=['cachy-asahi-source-tools'],
            pkgbase=['cachy-asahi-source-tools'], pkgver=['0.2.0-1'], arch=['any'], license=['MIT'],
            depend=['python>=3.14', 'xz', 'zstd']), 'current archive and PKGINFO identity')
    actual = value['actual']
    package.need(set(actual) == {'source', 'ref', 'run', 'job', 'artifact', 'image', 'inventory', 'signer'}
        and all(item is None for item in actual.values()), 'all actual native selectors must stay NULL')
    admission = value['admission']
    package.need(admission['status'] == 'HOLD_ROOT_GENUINE_CAUSE_AND_RESOURCE_CLASSIFICATION'
        and admission['namespace_cause'] == 'UNKNOWN'
        and all(admission[key] == 'NOT_RUN' for key in ('native', 'ALPM', 'hardware'))
        and admission['performance'] == 'NOT_MEASURED' and admission['release'] == 'NOT_ADMITTED',
        'Root classification hold cannot be waived')
    old = value['retained_v1']
    package.need(old['Source419'] == SOURCE419 and old['tree'] == 'ee92fee27e320016c151de1abd4ea529508255a4'
        and old['map_sha256'] == '11ec9193b418c922d8e63889795cb4fafa01e309328cff93f70e68560f5a5adf'
        and old['recipe_version'] == '0.1.0-1' and old['recipe_members'] == 13 and old['payload_files'] == 17
        and old['identity_status'] == 'FROZEN_BASELINE_ONLY_NOT_CURRENT_BUILD_EVIDENCE', 'retained v1 identity')
    package.need(old['expected349']['count'] == 349 and len(old['buildinfo_installed']) == 349
        and len(set(old['buildinfo_installed'])) == 349
        and old['dependencies']['python'] == '3.14.8-1', 'held full349 baseline, not a new image assertion')
    pair = value['build_pair']
    package.need(pair['labels'] == ['a', 'b'] and pair['separate_clean_sources'] is True
        and pair['logical_build_directory'] == '/opt/native-source-tools-alpm-v2/build-current'
        and pair['ordinary_build_user'] == 'alarm'
        and pair['target_os'] == 'Linux' and pair['target_architecture'] == 'aarch64'
        and pair['namespace_policy'] == 'ORDINARY_ALARM_BUBBLEWRAP_REQUIRED_NO_FALLBACK'
        and pair['makepkg_flags'] == ['--cleanbuild', '--nodeps', '--nosign', '--noconfirm']
        and pair['makepkg_config'] == 'native/source-tools-makepkg-v2.conf'
        and pair['packager'] == 'cachy-asahi native TEST builder'
        and re.fullmatch('[0-9]{10}', pair['source_date_epoch'])
        and pair['check_policy'] == 'POSITIVE_CHECK_NO_NOCHECK'
        and type(pair['expected_check_rows']) is int and pair['expected_check_rows'] == 5
        and pair['check_result_format'] == 'FIVE_ORDERED_JSON_OBJECTS_MULTILINE_SUPPORTED'
        and pair['new_environment_requires_fresh_Root_inventory_binding'] is True,
        'two independent ordinary-user positive-check builds required')
    package.need(pair['compare'] == ['ARCHIVE_BYTES', 'PAYLOAD_BYTES_MODES_OWNERSHIP', 'PKGINFO',
        'BUILDINFO_FULL_INVENTORY_AND_ARCH', 'MTREE'], 'complete build-pair comparison')
    signed = value['signed_ALPM']
    package.need(signed['SigLevel'] == signed['LocalFileSigLevel'] == 'Required'
        and signed['target'] == 'DISPOSABLE_NATIVE_IMAGE_ONLY' and signed['architecture'] == 'aarch64'
        and signed['hook_policy'] == 'DISABLED_OWNED_TEST_IMAGE_HOOK_DIRECTORY'
        and signed['signer_scope'] == 'TEST_ONLY_EPHEMERAL_PRIMARY_EXPLICIT_TRUST'
        and signed['release_key_use'] is False and signed['verify_both_archives'] is True
        and signed['required_negative_controls'] == ['UNKNOWN_KEY', 'TAMPERED_ARCHIVE']
        and signed['install_options'] == ['--noconfirm', '--noscriptlet', '-U']
        and signed['remove_options'] == ['--noconfirm', '--noscriptlet', '-R']
        and signed['restore'] == ['PACKAGE_DB_INVENTORY', 'EXPLICIT_DEPENDENCY_REASONS', 'HOME',
            'TRUST', 'CACHE', 'USER_EXPORTS', 'ALL_18_PAYLOAD_PATHS_ABSENT'], 'signed disposable ALPM policy')
    workflow = value['installed_workflow']
    package.need(workflow['locations'] == ['system', 'moved'] and workflow['original_controls'] == 17
        and workflow['global_version'] == 'cachy-asahi-source-tools 0.2.0'
        and workflow['additional_catalog_commands'] == ['LIST_LEGACY', 'LIST_CURRENT',
            'MATERIALIZE_LISTED_PINS_FOUR', 'VERIFY_CONTEXT_FOUR', 'REFUSE_WRONG_CATALOG_PIN']
        and workflow['additional_command_count_per_location'] == 11
        and workflow['native_selectors'] == 'ALL_NULL' and workflow['retained_code_execution'] == 'FORBIDDEN',
        'current system/moved catalog lifecycle inputs')
    future = value['future_integration']
    package.need(future['kind'] == 'PACKAGE_INPUT_COMPONENT_ONLY_NOT_DISPATCHABLE_SOURCE'
        and future['Root_genuine_base_required'] is True and future['Source_constructor_executed'] is False
        and future['v1_actors_unchanged'] is True and future['dispatch_allowed'] is False
        and future['allowed_new_native_inputs'] == ['native/' + name for name in OUTPUTS]
        and future['required_versioned_actor_seams'] == ['OWNER_OPERATION_ADMISSION',
            'INVOCATION_AND_WORKFLOW_PROVENANCE', 'BUILD_PAIR16_SOURCE_AND_FIVE_CHECK_ROWS',
            '18_PAYLOAD_AND_0_2_0_METADATA_COMPARISON', 'SYSTEM_AND_MOVED_CATALOG_PROBE',
            'FAILED_RESULT_PROJECTION_AND_READER_WITH_NO_FALSE_CREDIT', 'CLOSED_SOURCE_MAP_AND_ROOT_REVIEW'],
        'finite input component must not pretend to be a dispatchable Source')
    package.need(value['failure_retention'] == 'RETAIN_ORIGINAL_FAILURE_COMMAND_LOG_AND_OWNED_RETIREMENT; '
        'NO_PASS_FROM_CARRIER_EXIT; NO_AUTOMATIC_RETRY', 'original failure stays authoritative')
    for key, path in (('makepkg_config', 'native/source-tools-makepkg-v2.conf'),
                      ('current_check_module', 'native/source_tools_current_check_v2.py'),
                      ('current_package_module', 'native/source_tools_current_package_v2.py')):
        row = value[key]
        package.need(set(row) == {'path', 'pin'} and row['path'] == path
            and set(row['pin']) == {'bytes', 'sha256'} and type(row['pin']['bytes']) is int
            and 0 < row['pin']['bytes'] <= package.MAX_FILE
            and re.fullmatch('[0-9a-f]{64}', row['pin']['sha256']), 'finite integration operand ' + key)
    return value


def prepare(recipe_root, selection_raw, selection_sha256, integration_raw, directory=HERE):
    package.need(pin(selection_raw)['sha256'] == selection_sha256, 'caller-authenticated selection pin')
    chosen = package.decode(selection_raw)
    contract = policy(chosen, package.decode(integration_raw))
    files = package.validate_recipe(recipe_root, chosen)
    bundle = package.recipe_bundle(files, chosen)
    package.need(package.verify_bundle(bundle, chosen) == files, 'complete canonical package bundle roundtrip')
    package.need(contract['recipe']['bundle'] == dict(path='native/source-tools-sources-v2.tar',
        members=16, max_bytes=package.MAX_TOTAL, **pin(bundle)), 'exact package bundle descriptor')
    directory = Path(directory)
    config = read(directory / 'makepkg-v2.conf')
    checker = read(directory / 'check_current_makepkg.py')
    binder = read(directory / 'current_package_inputs.py')
    for key, raw in (('makepkg_config', config), ('current_check_module', checker), ('current_package_module', binder)):
        package.need(contract[key]['pin'] == pin(raw), 'integration operand bytes differ: ' + key)
    package.need(b'BUILDENV=(!distcc !color !ccache check !sign)' in config
        and b'!check' not in config and b"CARCH='aarch64'" in config, 'mandatory ordinary native check configuration')
    return dict(zip(OUTPUTS, (bundle, integration_raw, config, checker, binder)))


def write_component(output, bodies):
    output = Path(output).absolute()
    package.need(output == output.resolve() and output.parent.is_dir()
        and not any(path.is_symlink() for path in (output, *output.parents)), 'canonical fresh component path')
    parent = output.parent.stat()
    package.need(parent.st_uid == os.getuid() and not stat.S_IMODE(parent.st_mode) & 0o022,
                 'owned non-writable-by-others output parent')
    package.need(set(bodies) == set(OUTPUTS), 'closed five-file package component')
    package.need(all(type(raw) is bytes and 0 < len(raw) <= package.MAX_TOTAL for raw in bodies.values())
        and sum(map(len, bodies.values())) <= 32*1024**2, 'finite component byte bounds')
    output.mkdir(mode=0o700)
    for name, raw in bodies.items():
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), 0o644)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bodies = prepare(args.recipe_root, read(HERE / 'selection-v2.json'), args.selection_sha256,
                     read(HERE / 'native-integration-v2.json'))
    write_component(args.output, bodies)
    print(json.dumps(dict(status='PREPARED_CURRENT_PACKAGE_INPUTS_ONLY', files=len(bodies),
        recipe_files=16, recipe_sources=14, payload_files=18, Source_constructor=False,
        dispatch_allowed=False, native='NOT_RUN', ALPM='NOT_RUN', namespace_cause='UNKNOWN'), sort_keys=True))
