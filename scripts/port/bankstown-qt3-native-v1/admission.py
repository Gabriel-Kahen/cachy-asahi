#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Validate an externally selected Root trial; never issue authority."""
import hashlib
import json
import math
import re

KIND = 'ROOT_REVIEWED_BANKSTOWN_QT3_PRIVATE_TEST_V1'
TOOLS = {'cargo': '/usr/bin/cargo', 'rustc': '/usr/bin/rustc',
         'cc': '/usr/bin/cc', 'ld': '/usr/bin/ld'}
PREFIX = 'scripts/port/bankstown-qt3-native-v1/'
RECIPE = 'packages/port/bankstown-source-candidate'
REQUIRED_MATERIALS = {
    PREFIX + name for name in ('admission.py', 'profile.py', 'builder.py', 'entry.sh')
} | {
    'scripts/port/arm-rust-toolchain-inputs/' + name for name in (
        'inputs.lock.json', 'catalog.py', 'rust-137-files.json',
        'qtbase-successor/candidate.py', 'qtbase-successor/candidate.lock.json',
        'qtbase-successor/parent-binding.json', 'qtbase-successor/elf_versions.py',
        'qtbase-successor/source-facts.json', 'CLOSURE.md', 'README.md', 'SUPPLEMENT.md',
        'acquire_qt.py', 'alarm-public.gpg', 'history/inputs-271.lock.json',
        'history/inputs-84.lock.json', 'history/remaining-inputs-271.json',
        'history/result-271.json', 'history/result-84.json', 'loader-semantics.json',
        'loader-source/COPYING.LIB', 'loader-source/dl-load.c', 'qt-acquisition-evidence.json',
        'qt-frozen-inputs.json', 'remaining-inputs.json', 'source-facts.json',
        'supplemental-inputs.json', 'test_catalog.py')
} | {RECIPE + '/' + name for name in (
    'PKGBUILD', '.SRCINFO', 'build_guard.py', 'native-rust-inputs.json',
    'native-toolchain-requirements.json', 'COMPONENTS.json', 'SOURCE-CANDIDATE.md',
    'PACKAGING.LICENSE', 'bankstown-1.1.0.tar.gz', 'cargo-vendor-117.tar.xz',
    'audio-rust-notices-v1.tar.xz')} | {
    'scripts/checks/package_checks.py', 'scripts/build/build.py',
    'scripts/build/container-entry.sh'}
FINAL = {'Root_acceptance': None, 'native_component_acceptance': False,
         'hardware_acceptance': False, 'release_acceptance': False}


def need(value, code):
    if not value:
        raise ValueError(code)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _pairs(rows):
    value = {}
    for key, item in rows:
        need(key not in value, 'DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def decoded(raw, limit=2 * 1024**2):
    need(type(raw) is bytes and 0 < len(raw) <= limit, 'JSON_BYTE_BOUND')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE_JSON'))


def sha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256_REQUIRED')
    return value


def descriptor(value, cap=64 * 1024**2, *, empty=False):
    need(type(value) is dict and set(value) == {'bytes', 'sha256'}, 'WHOLE_PIN_REQUIRED')
    need(type(value['bytes']) is int and (0 if empty else 1) <= value['bytes'] <= cap,
         'PIN_BYTE_BOUND')
    sha(value['sha256'])
    return value


def logical(value):
    need(type(value) is str and value.startswith('/') and len(value.encode()) <= 4096
         and all(ord(c) >= 32 and ord(c) != 127 for c in value)
         and all(p not in ('', '.', '..') for p in value[1:].split('/')),
         'CANONICAL_LOGICAL_PATH_REQUIRED')
    return value


def relative(value):
    need(type(value) is str and not value.startswith('/'), 'SOURCE_RELATIVE_PATH_REQUIRED')
    logical('/' + value)
    return value


def validate_trial(raw, expected_sha256, *, now):
    """The caller must obtain expected_sha256 through genuine external Root custody."""
    need(pin(raw)['sha256'] == sha(expected_sha256), 'ROOT_TRIAL_PIN_DIFFERS')
    d = decoded(raw)
    keys = {'schema', 'kind', 'issuer', 'approved', 'purpose', 'issued_at', 'expires_at',
            'source', 'materials', 'catalog', 'image', 'recipe', 'resources',
            'selected_files', 'tool_paths', 'closure', 'owned_executor', 'legal', 'key_freshness'} | set(FINAL)
    need(type(d) is dict and set(d) == keys, 'ROOT_TRIAL_SCHEMA')
    need(type(d['schema']) is int and d['schema'] == 1 and d['kind'] == KIND
         and d['issuer'] == 'Root' and d['approved'] is True
         and d['purpose'] == 'PRIVATE_TEST_NATIVE_BUILD_ONLY', 'ROOT_PRIVATE_TEST_REQUIRED')
    need(type(now) in (int, float) and math.isfinite(now)
         and type(d['issued_at']) is int and type(d['expires_at']) is int
         and 0 <= d['issued_at'] <= now < d['expires_at'] <= d['issued_at'] + 86400,
         'FRESH_FINITE_ROOT_TRIAL_REQUIRED')
    need(type(d['source']) is dict and set(d['source']) == {'commit', 'ref'}
         and type(d['source']['commit']) is str
         and re.fullmatch('[0-9a-f]{40}', d['source']['commit'])
         and type(d['source']['ref']) is str
         and re.fullmatch(r'refs/heads/[A-Za-z0-9_./-]{1,200}', d['source']['ref'])
         and '..' not in d['source']['ref'], 'EXACT_SOURCE_REQUIRED')
    need(d['recipe'] == {'path': RECIPE, 'version': '1.1.0-5'}, 'EXACT_RECIPE_REQUIRED')
    need(type(d['materials']) is dict and REQUIRED_MATERIALS <= set(d['materials'])
         and len(d['materials']) <= 256, 'CLOSED_MATERIALS_REQUIRED')
    for path, row in d['materials'].items():
        relative(path)
        descriptor(row)
    need(sum(row['bytes'] for row in d['materials'].values()) <= 128 * 1024**2,
         'CONTROL_SOURCE_BYTE_BOUND')
    descriptor(d['catalog'])
    need(type(d['image']) is dict and set(d['image']) == {'id', 'inventory'}
         and type(d['image']['id']) is str
         and re.fullmatch('sha256:[0-9a-f]{64}', d['image']['id']), 'EXACT_IMAGE_REQUIRED')
    descriptor(d['image']['inventory'], 2 * 1024**2)
    executor = d['owned_executor']
    need(type(executor) is dict and set(executor) == {'code_pin', 'docker_endpoint', 'engine_id'},
         'ROOT_OWNED_EXECUTOR_REQUIRED')
    descriptor(executor['code_pin'], 2 * 1024**2)
    need(type(executor['docker_endpoint']) is str
         and executor['docker_endpoint'].startswith('unix:///')
         and len(executor['docker_endpoint']) <= 256
         and all(ord(c) > 32 and ord(c) != 127 for c in executor['docker_endpoint'])
         and '..' not in executor['docker_endpoint'].split('/')
         and type(executor['engine_id']) is str and 1 <= len(executor['engine_id']) <= 256
         and all(ord(c) > 32 and ord(c) != 127 for c in executor['engine_id']),
         'ROOT_OWNED_ENGINE_REQUIRED')
    for row in (d['catalog'], d['image']['inventory']):
        need(sum(item == row for item in d['materials'].values()) == 1,
             'UNIQUE_MATERIAL_BINDING_REQUIRED')
    caps = {'wall_seconds': 600, 'command_seconds': 300, 'cpus': 4,
            'memory_bytes': 4 * 1024**3, 'pids': 512, 'max_output_bytes': 4 * 1024**2}
    need(type(d['resources']) is dict and set(d['resources']) == set(caps), 'FINITE_RESOURCES_REQUIRED')
    for key, cap in caps.items():
        need(type(d['resources'][key]) is int and 0 < d['resources'][key] <= cap,
             'FINITE_RESOURCE_BOUND')
    need(d['resources']['command_seconds'] <= d['resources']['wall_seconds'], 'COMMAND_WALL_BOUND')
    need(d['tool_paths'] == TOOLS, 'FIXED_NATIVE_TOOL_ROLES_REQUIRED')
    files = d['selected_files']
    need(type(files) is dict and 4 <= len(files) <= 4096, 'SELECTED_FILE_BOUND')
    for path, row in files.items():
        logical(path)
        descriptor(row, 256 * 1024**2, empty=True)
    need(sum(row['bytes'] for row in files.values()) <= 2 * 1024**3, 'SELECTED_BYTE_BOUND')
    closure = d['closure']
    need(type(closure) is dict and set(closure) == {'status', 'non_elf_support'}
         and closure['status'] == 'ROOT_REVIEWED_COMPLETE_TOOL_SUPPORT_CLOSURE'
         and type(closure['non_elf_support']) is list and closure['non_elf_support']
         and all(type(p) is str for p in closure['non_elf_support'])
         and len(set(closure['non_elf_support'])) == len(closure['non_elf_support'])
         and set(closure['non_elf_support']) <= set(files), 'EXPLICIT_SUPPORT_CLOSURE_REQUIRED')
    need(d['legal'] == d['key_freshness'] == 'HELD'
         and all(d[k] is v for k, v in FINAL.items()), 'ACCEPTANCE_REMAINS_HELD')
    return d
