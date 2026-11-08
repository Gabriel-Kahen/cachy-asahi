# SPDX-License-Identifier: MIT
"""Bind output to a caller-authenticated contract; grants no native acceptance."""
import hashlib
import json
import re

MAX_LOG = 1024**2
FILES = frozenset(('PKGBUILD', '.SRCINFO', 'private-source.tar.gz', 'fixtures.tar.gz',
    'cachy-asahi-source-tools', 'check_package.py', 'test_package.py', 'multi_package_roundtrip.py',
    'README.md', 'source-provenance.json', 'payload-map.json', 'NOTICE', 'LICENSE',
    'test_cli_input_refusal.py', 'source_mirror_catalog.py', 'test_source_mirror_catalog.py'))
CHECKS = dict(cli_tests=9, duplicate_cases=132, catalog_tests=9, catalog_contexts=4,
    original_workflow_controls=17, private_helpers=11, payload_files=18)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def count(row, key, expected):
    need(type(row.get(key)) is int and row[key] == expected, 'incorrect integer ' + key)


def contract_files(contract):
    need(type(contract) is dict and type(contract.get('checks')) is dict, 'current check contract required')
    need(set(contract['checks']) == set(CHECKS), 'exact current check fields required')
    for key, value in CHECKS.items():
        count(contract['checks'], key, value)
    need(type(contract.get('recipe')) is dict, 'recipe contract object required')
    files = contract['recipe'].get('files')
    need(type(files) is dict and set(files) == FILES, 'exact current16-file recipe required')
    for row in files.values():
        need(type(row) is dict and type(row.get('bytes')) is int and 0 < row['bytes'] <= 64*1024**2
             and type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
             and type(row.get('mode')) is int and row['mode'] in (0o644, 0o755),
             'ordinary bounded recipe file pin required')
    return files


def rows(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_LOG, 'bounded check-output bytes required')
    marker = b'Starting check()'
    need(raw.count(marker) == 1, 'one actual makepkg check marker required')
    text = raw.decode('utf-8')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate check JSON key')
            result[key] = value
        return result
    def invalid(_value):
        raise ValueError('noninteger check JSON value')
    decoder = json.JSONDecoder(object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    result = []
    # The CLI report is pretty-printed across lines. Decode complete top-level
    # objects, never individual lines or arbitrary brace substrings inside logs.
    positions = [match.start() for match in re.finditer(r'(?m)^[\[{]', text)]
    need(len(positions) == 5 and positions[0] > text.index('Starting check()'), 'exact ordered five check JSON rows required')
    for position in positions:
        value, end = decoder.raw_decode(text, position)
        need(type(value) is dict and (end == len(text) or text[end] in '\r\n'),
             'whole object check row required')
        need(all(not (position < other < end) for other in positions), 'overlapping check rows')
        result.append(value)
    return result


def check_result(raw, contract):
    files = contract_files(contract)
    cli, catalog, source, staged, packaged = results = rows(raw)
    need(cli.get('status') == catalog.get('status') == 'PASS', 'current focused check failure')
    for result in (cli, catalog):
        count(result, 'tests', 9)
        count(result, 'failures', 0)
        count(result, 'errors', 0)
        if 'skipped' in result:
            count(result, 'skipped', 0)
    need(cli.get('evidence') == 'PURE_DATA_FOCUSED_CLI_CONTROLS'
         and cli.get('current_launcher_sha256') == files['cachy-asahi-source-tools']['sha256']
         and cli.get('packed_private_source_sha256') == files['private-source.tar.gz']['sha256'],
         'current launcher/private source check binding differs')
    need(all(cli.get(key) == 'NOT_RUN' for key in ('native_build', 'alpm_installation', 'namespace_probe', 'hardware'))
         and cli.get('performance') == 'NOT_MEASURED' and cli.get('release') == 'NOT_ADMITTED',
         'CLI check evidence boundary changed')
    need(catalog.get('helper_sha256') == files['source_mirror_catalog.py']['sha256']
         and catalog.get('fixtures') == 'TWO_PACKAGES_LEGACY_CURRENT_SYNTHETIC_ARCHIVES_REAL_ORIGINAL_RECIPE_BYTES',
         'current catalog helper/fixture binding differs')
    count(catalog, 'skipped', 0)
    count(catalog, 'exact_materialized_contexts', 4)
    need(all(catalog.get(key) == 'NOT_RUN' for key in ('native', 'installation', 'hardware'))
         and catalog.get('release') == 'NOT_ADMITTED', 'catalog evidence boundary changed')
    need(source == dict(status='PASS', payload_files=None, private_source_files=11)
         and staged == dict(status='PASS', payload_files=18, private_source_files=11),
         'exact current source/payload checker rows required')
    workflow = packaged.get('workflow', {})
    need(type(workflow) is dict and packaged.get('status') == workflow.get('status') == 'PASS'
         and packaged.get('checkout_hidden') is True and packaged.get('moved_prefix') is True
         and packaged.get('network_namespace') == 'loopback-only'
         and packaged.get('removal') == 'EXACT_FILE_INVERSE_USER_CONTENT_PRESERVED'
         and packaged.get('alpm_installation') == packaged.get('native_build') == 'NOT_RUN'
         and workflow.get('source_execution') == 'NOT_RUN', 'complete original moved/offline package check required')
    count(packaged, 'staged_payload_files', 18)
    for key, expected in (('controls', 17), ('exact_contexts', 4), ('packages_per_release', 2), ('retained_releases', 2)):
        count(workflow, key, expected)
    need(type(workflow.get('commands')) is list and len(workflow['commands']) == 17
         and all(type(command) is dict for command in workflow['commands']), 'all17 original workflow observations required')
    return dict(status='BOUND_CURRENT_CHECK_OUTPUT_DATA', check_rows=5,
        check_output_sha256=hashlib.sha256(raw).hexdigest(), results=results,
        native_acceptance='NOT_GRANTED', actual_native_execution='NOT_ASSERTED')
