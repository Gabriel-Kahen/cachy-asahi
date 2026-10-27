# SPDX-License-Identifier: MIT
"""Frozen maintenance package, private module closure and finite native acceptance."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
NAMES = ('cachy-asahi-maintenance',)
NAME = 'NO_COMPILED_PRODUCT_IN_THIS_LANE'
LABEL = 'org.cachy-asahi.maintenance-native.job'
LANE = 'scripts/ci/maintenance-native'
ACTOR = '.github/workflows/native-arm-maintenance-candidate.yml'
ALIAS = '.github/workflows/native-arm-build.yml'
PACKAGE_MANIFEST_SHA256 = '1fd5404cc12fe29d446d3eb7d1b4cf9fb4e397cc56af626c9b88eb212eb07a64'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path required')
    return path


def frozen_files():
    manifest = HERE / 'package-manifest.json'
    need(digest(manifest) == PACKAGE_MANIFEST_SHA256, 'frozen package manifest differs')
    rows = json.loads(manifest.read_bytes())['files']
    prefix = 'packages/tools/' + NAMES[0] + '/'
    need(len(rows) == 20 and all(row['destination'].startswith(prefix) and
         Path(row['destination']).parent.as_posix() == prefix.rstrip('/') for row in rows), 'exact 20 package files required')
    return {Path(row['destination']).name: dict(bytes=row['bytes'], sha256=row['sha256']) for row in rows}


def verify_package(root):
    expected = frozen_files()
    need({p.name for p in root.iterdir()} == set(expected), 'closed frozen package input set required')
    for name, row in expected.items():
        path = safe(root / name)
        need(path.is_file() and path.stat().st_size == row['bytes'] and digest(path) == row['sha256'],
             'frozen package byte drift: ' + name)


def verify_source(source):
    safe(source)
    pins = json.loads((HERE / 'source-pins.json').read_bytes())
    need(type(pins) is dict and 32 <= len(pins) <= 128 and ACTOR in pins and ALIAS in pins,
         'complete source pins including registered alias required')
    for name, pin in pins.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and
             re.fullmatch('[0-9a-f]{64}', pin), 'safe source pin required')
        path = safe(source / name)
        need(path.is_file() and path.stat().st_size <= 16 * 1024**2 and digest(path) == pin,
             'source dependency differs: ' + name)
    need((source / ACTOR).read_bytes() == (source / ALIAS).read_bytes(), 'registered workflow alias differs')
    verify_package(source / 'packages/tools' / NAMES[0])


def recipe(source, name):
    need(name in NAMES, 'unknown product')
    root = source / 'packages/tools' / name
    verify_package(root)
    checks = load('maintenance_static_recipe', source / 'scripts/checks/package_checks.py')
    result = checks.recipe(root / 'PKGBUILD')
    need(not result['errors'], 'recipe static failure: ' + str(result['errors']))
    meta = result['metadata']
    need(meta.get('pkgname') == [name] and meta.get('pkgver') == ['0.1.0'] and meta.get('pkgrel') == ['2'] and
         meta.get('arch') == ['any'] and meta.get('license') == ['MIT'] and
         meta.get('depends') == ['python>=3.11', 'gnupg', 'libarchive', 'pacman'] and
         not any(meta.get(key) for key in ('install', 'backup', 'provides', 'conflicts', 'replaces', 'makedepends')) and
         len(meta['source']) == len(meta['sha256sums']) == 18, 'frozen standalone package metadata required')
    return dict(metadata=meta, input_sha256=result['input_sha256'])


def version(source, name):
    meta = recipe(source, name)['metadata']
    return meta['pkgver'][0] + '-' + meta['pkgrel'][0]


def files(name):
    need(name in NAMES, 'unknown payload')
    value = json.loads((HERE / 'product-spec.json').read_bytes())
    need(value['status'] == 'FROZEN_PACKAGE_BYTES_REVIEWED' and set(value['products']) == set(NAMES), 'frozen product map required')
    rows = value['products'][name]['payload']
    need(type(rows) is dict and len(rows) == 16, 'exact 16 installed files required')
    for relative, row in rows.items():
        need(not Path(relative).is_absolute() and '..' not in Path(relative).parts and
             relative.startswith(('usr/bin/', 'usr/lib/cachy-asahi/maintenance/scripts/', 'usr/share/doc/', 'usr/share/licenses/')) and
             type(row) is list and len(row) == 2 and Path(row[0]).name == row[0] and row[1] in (0o644, 0o755),
             'reviewed private installed payload map required')
    return rows


def payload(report, source, name):
    need(not report['errors'] and not report['elf'], 'script/data-only archive required')
    expected = files(name)
    rows = {n: row for n, row in report['members'].items() if row['type'] != '5' and n not in ('.PKGINFO', '.BUILDINFO', '.MTREE')}
    need(set(rows) == set(expected), 'exact maintenance payload differs')
    parents = {str(p) for member in expected for p in Path(member).parents if str(p) != '.'}
    for name, row in report['members'].items():
        if row['type'] == '5':
            need(name in parents, 'unexpected empty package directory')
    for relative, (original, mode) in expected.items():
        row = rows[relative]
        need(row['type'] == '0' and row['mode'] == mode and row['uid'] == row['gid'] == 0 and
             row['sha256'] == digest(source / 'packages/tools' / NAMES[0] / original), 'source/payload join differs: ' + relative)
    return rows


def check_log(path, name):
    need(name in NAMES and path.stat().st_size <= 16 * 1024**2, 'bounded package check log required')
    text = path.read_text(errors='replace')
    need(all(marker in text for marker in ('Starting check()', 'PASS_EXACT_PRIVATE_RUNTIME', 'Ran 18 tests', '\nOK')),
         'complete native package check() output required')
    return dict(status='PASS_CHECK_EXIT', package_controls=18, method='real makepkg check() exit0')


def validate_fixture(value, architecture, page_size):
    need(value.get('status') == 'PASS_MAINTENANCE_INSTALLED_SIGNED_TEST_CONTROLS' and
         value.get('architecture') == architecture and value.get('page_size') == page_size and value.get('uid', 0) > 0 and
         value.get('all_five_observations_replayed') is True and value.get('input_data_preserved') is True and
         value.get('public_home_preserved') is True and value.get('installed_payload_preserved') is True and
         value.get('signing_secret_removed') is True and value.get('fake_signature_time_used') is False and
         value.get('certificate_evaluation') == 'PACKAGED_EXPLICIT_AS_OF_INSPECTION_ONLY' and
         value.get('physical_m2') == 'NOT_RUN' and value.get('release') == 'NOT_ADMITTED' and
         value.get('arm_security_status') == 'UNKNOWN', 'complete actual-time ordinary signed TEST review required')
    need(type(value.get('controls')) is list and len(value['controls']) == 12 and
         type(value.get('source_files')) is dict and len(value['source_files']) == 9,
         'complete CLI controls and nine private source receipts required')
    labels = ('authenticated-context', 'health-json-one', 'health-json-two', 'health-text-one', 'health-text-two',
              'all-observations-unavailable', 'wrong-signer', 'wrong-release-digest', 'wrong-observations-digest',
              'wrong-observation-generation', 'symlink-index', 'tampered-signed-payload')
    need(tuple(row.get('case') for row in value['controls']) == labels and
         [row.get('returncode') for row in value['controls']] == [0] * 6 + [2] * 6 and
         all(row.get('returncode') == row.get('expected_returncode') for row in value['controls']),
         'complete ordered positive and refusal receipts required')
    epochs = [value.get(name) for name in ('started_epoch', 'key_created_epoch', 'evaluation_epoch', 'finished_epoch')]
    need(all(type(epoch) is int and epoch > 0 for epoch in epochs) and epochs == sorted(epochs) and
         value.get('signature_verification') == dict(fingerprint=value.get('signer'), clock='ACTUAL_SYSTEM_TIME') and
         re.fullmatch('[A-F0-9]{40}', value.get('signer', '')), 'actual-time TEST signature identity/epochs required')
    product = json.loads((HERE / 'product-spec.json').read_bytes())['products'][NAMES[0]]
    need(value['source_files'] == product['module_sources'] and value.get('cli_sha256') == product['cli_sha256'],
         'installed CLI/private source closure differs from frozen package')


def validate_lifecycle(value):
    need(value.get('status') == 'PASS_MAINTENANCE_INSTALLED_LIFECYCLE' and value.get('base_count') == 574 and
         value.get('installed_count') == 575 and value.get('user_config_preserved') is True and
         value.get('system_config_preserved') is True and value.get('user_outputs_preserved') is True and
         value.get('hardware') == 'NOT_RUN' and value.get('native_architecture') == 'aarch64' and
         type(value.get('actual_page_size')) is int and value['actual_page_size'] > 0,
         'native lifecycle and preservation observations required')
    signing = value.get('package_test_signing', {})
    need(signing.get('signature_verified_at_actual_time') is True and signing.get('private_key_removed') is True and
         signing.get('alpm_local_signature_policy') == 'Required' and signing.get('production_trust') == 'UNTOUCHED' and
         signing.get('fake_signature_time_used') is False and re.fullmatch('[A-F0-9]{40}', signing.get('fingerprint', '')) and
         type(signing.get('created_epoch')) is int and type(signing.get('verified_epoch')) is int and
         0 < signing['created_epoch'] <= signing['verified_epoch'],
         'private actual-time TEST package signature and cleanup required')
    staged = value.get('staged_observations')
    need(type(staged) is list and len(staged) == 2 and {r.get('home') for r in staged} ==
         {'maintenance-home-fresh', 'maintenance-home-existing'}, 'both staged ordinary user contexts required')
    for row in staged:
        validate_fixture(row['maintenance'], 'aarch64', value['actual_page_size'])
    events = value.get('events')
    need(type(events) is list and len(events) == 5, 'five real ALPM transitions required')
    for event, (phase, count) in zip(events, (('install', 575), ('same-version-reinstall', 575), ('remove', 574),
                                             ('reinstall-after-removal', 575), ('final-remove', 574))):
        need(event.get('phase') == phase and event.get('status') == 'PASS' and
             event.get('inventory_count') == count and event.get('config_preserved') is True, 'ALPM transition differs')
        if count == 575:
            rows = event.get('observations')
            need(type(rows) is list and len(rows) == 2 and {r.get('home') for r in rows} ==
                 {'maintenance-home-fresh', 'maintenance-home-existing'}, 'both ordinary user contexts required')
            need(len({r.get('uid') for r in rows}) == 2 and all(r.get('uid') == r['maintenance'].get('uid') for r in rows),
                 'two distinct ordinary fixture accounts required')
            for row in rows:
                validate_fixture(row['maintenance'], 'aarch64', value['actual_page_size'])
        else:
            need(event.get('removed_payload_absent') is True, 'removed payload absence required')
