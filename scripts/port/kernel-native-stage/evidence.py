# SPDX-License-Identifier: MIT
"""Finite child diagnostics; hashes bind private inputs, never publish their paths."""
import hashlib
import json
import re

LIMIT = 4096
ACTIONS = ('provision', 'probe', 'baseline', 'candidate')
PREDICATES = frozenset(('SNAPSHOT', 'ACCEPTED_BASE', 'DEPENDENCY_PACKET',
    'PROVISION_INITIALIZE', 'PROVISION_COMMAND', 'PROVISION_RECEIPT', 'DERIVED_IMAGE',
    'BUILD_INITIALIZE', 'PROBE_COMMAND', 'PROBE_RECEIPT', 'BASELINE_COMMAND',
    'BASELINE_RECEIPT', 'BASELINE_CONFIG', 'CANDIDATE_COMMAND', 'CANDIDATE_RECEIPT',
    'PAIR_ACCEPTANCE', 'CLEANUP', 'FINALIZATION', 'COMPLETE'))
CATEGORIES = frozenset(('NONE', 'CANCELLED', 'DEADLINE', 'TIMEOUT', 'OUTPUT_BOUND',
    'IO', 'INVALID_DATA', 'COMMAND_NONZERO', 'UNCLASSIFIED'))
CLEANUP_CATEGORIES = CATEGORIES | {'ABSENCE_UNVERIFIED', 'UNCERTAIN_MUTATION'}
BINDING_KEYS = frozenset(('source_commit', 'stage_lock_sha256', 'output_name_sha256',
    'run_id', 'run_attempt', 'nonce', 'accepted_result_sha256', 'bootstrap_sha256',
    'inputs_sha256', 'base_inventory_sha256'))
KEYS = frozenset(('schema_version', 'current_predicate', 'first_failed_predicate',
    'failure_category', 'commands', 'cleanup'))


def need(ok):
    if not ok:
        raise ValueError('kernel-child-diagnostics-refused')


def encoded(value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    need(len(data) <= LIMIT)
    return data


def exit_record(code):
    need(type(code) is int and -64 <= code <= 255)
    return {'kind': 'EXIT_SIGNAL' if code < 0 else 'EXIT_NONZERO' if code else 'EXIT_ZERO', 'code': code}


def validate_exit(row):
    need(type(row) is dict and set(row) == {'kind', 'code'} and type(row['kind']) is str)
    if row['kind'] in ('NOT_RUN', 'UNOBSERVED'):
        need(row['code'] is None)
    else:
        need(row == exit_record(row['code']))
    return row


def validate_fields(row):
    need(type(row['schema_version']) is int and row['schema_version'] == 1)
    need(type(row['current_predicate']) is str and row['current_predicate'] in PREDICATES)
    need(type(row['first_failed_predicate']) is str and row['first_failed_predicate'] in PREDICATES | {'NONE'})
    need(type(row['failure_category']) is str and row['failure_category'] in CATEGORIES)
    need((row['first_failed_predicate'] == 'NONE') == (row['failure_category'] == 'NONE'))
    need(type(row['commands']) is dict and set(row['commands']) == set(ACTIONS))
    for value in row['commands'].values():
        validate_exit(value)
    clean = row['cleanup']
    need(type(clean) is dict and set(clean) == {'status', 'category'})
    need(type(clean['status']) is str and clean['status'] in ('NOT_RUN', 'PASS', 'FAIL'))
    need(type(clean['category']) is str and clean['category'] in CLEANUP_CATEGORIES)
    need((clean['status'] != 'FAIL') == (clean['category'] == 'NONE'))
    if row['current_predicate'] == 'COMPLETE':
        need(row['first_failed_predicate'] == 'NONE' and clean['status'] == 'PASS' and
             all(value == exit_record(0) for value in row['commands'].values()))


def validate_public(row):
    need(type(row) is dict and set(row) == KEYS | {'binding_sha256'})
    need(type(row['binding_sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['binding_sha256']))
    encoded(row); validate_fields(row)
    return row


def project(row):
    need(type(row) is dict and set(row) == KEYS | {'binding'})
    encoded(row); validate_fields(row)
    binding = row['binding']
    need(type(binding) is dict and set(binding) == BINDING_KEYS)
    for name in BINDING_KEYS - {'source_commit', 'run_id', 'run_attempt', 'nonce'}:
        need(type(binding[name]) is str and re.fullmatch('[0-9a-f]{64}', binding[name]))
    need(type(binding['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', binding['source_commit']))
    need(type(binding['nonce']) is str and re.fullmatch('[0-9a-f]{32}', binding['nonce']))
    for name in ('run_id', 'run_attempt'):
        need(binding[name] is None or type(binding[name]) is str and re.fullmatch('[0-9]{1,20}', binding[name]))
    result = {key: row[key] for key in KEYS}
    result['binding_sha256'] = hashlib.sha256(encoded(binding)).hexdigest()
    return validate_public(result)


def initial(binding):
    row = {'schema_version': 1, 'binding': binding, 'current_predicate': 'SNAPSHOT',
        'first_failed_predicate': 'NONE', 'failure_category': 'NONE',
        'commands': {name: {'kind': 'NOT_RUN', 'code': None} for name in ACTIONS},
        'cleanup': {'status': 'NOT_RUN', 'category': 'NONE'}}
    project(row)
    return row


def failure(row, category, predicate=None):
    need(category in CATEGORIES - {'NONE'})
    if predicate is not None:
        row['current_predicate'] = predicate
    elif row['current_predicate'] == 'COMPLETE':
        row['current_predicate'] = 'FINALIZATION'
    if row['first_failed_predicate'] == 'NONE':
        row['first_failed_predicate'] = predicate or row['current_predicate']
        row['failure_category'] = category
    project(row)


def error_category(error, cancelled=False):
    if cancelled or isinstance(error, KeyboardInterrupt):
        return 'CANCELLED'
    if type(error) is ValueError and len(error.args) == 1:
        exact = {'deadline-exhausted': 'DEADLINE', 'command-timeout': 'TIMEOUT', 'output-bound': 'OUTPUT_BOUND'}
        if type(error.args[0]) is str and error.args[0] in exact:
            return exact[error.args[0]]
    if isinstance(error, OSError):
        return 'IO'
    if isinstance(error, (ValueError, KeyError, TypeError)):
        return 'INVALID_DATA'
    return 'UNCLASSIFIED'


def cleanup_category(rows):
    if any(row.get('cancelled') is True for row in rows):
        return 'CANCELLED'
    if any(row.get('uncertain_commit') is True for row in rows):
        return 'UNCERTAIN_MUTATION'
    return 'ABSENCE_UNVERIFIED'
