# SPDX-License-Identifier: MIT
"""Finite, data-only projection of the authenticated worker's original calls."""
import hashlib
import json
import math
import re

from runtime import Cancelled

LIMIT = 2048
REPORT_LIMIT = 4 * 1024**2
PHASES = frozenset(('NONE', 'PRECHECK', 'PROFILE', 'INVENTORY', 'TOOLS', 'SOURCE', 'CONFIG',
    'CONFIG_DELTA', 'PAIRED_CONFIG', 'GENERATED_CONFIG', 'KERNEL', 'OUTPUTS', 'FINALIZATION', 'COMPLETE'))
COMMANDS = frozenset(('NONE', 'INVENTORY', 'CONFIG', 'KERNEL', *(f'TOOL_{i}' for i in range(18))))
ERRORS = frozenset(('DATA_REFUSAL', 'IO', 'IMPORT', 'TIMEOUT', 'DEADLINE', 'OUTPUT_BOUND',
    'PROCESS_CLEANUP', 'CANCELLED', 'OTHER'))
BINDING_KEYS = frozenset(('nonce', 'action', 'contract_sha256', 'worker_sha256'))
KEYS = frozenset(('schema_version', 'binding', 'phase', 'command', 'attempt', 'natural_return',
    'first_failure', 'cleanup_failure', 'cancelled', 'write_failed'))
PUBLIC_KEYS = (KEYS - {'binding'}) | {'binding_sha256'}
GROUP_KEYS = frozenset(('availability', 'reason', 'raw_sha256', 'diagnostic'))


def _need(value):
    if not value: raise ValueError('invalid inner diagnostic')


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _binding(value):
    _need(type(value) is dict and value.keys() == BINDING_KEYS)
    _need(type(value['nonce']) is str and re.fullmatch('[0-9a-f]{32}', value['nonce']))
    _need(type(value['action']) is str and value['action'] in ('probe', 'baseline', 'candidate'))
    _need(_sha(value['contract_sha256']) and _sha(value['worker_sha256']))


def initial(binding):
    _binding(binding)
    return {'schema_version': 1, 'binding': dict(binding), 'phase': 'PRECHECK', 'command': 'NONE',
        'attempt': 'NOT_ISSUED', 'natural_return': {'kind': 'UNOBSERVED', 'code': None},
        'first_failure': None, 'cleanup_failure': None, 'cancelled': False, 'write_failed': False}


def phase(row, name):
    _need(type(name) is str and name in PHASES)
    row['phase'] = name
    return row


def issued(row, command):
    _need(type(command) is str and command in COMMANDS - {'NONE'})
    row.update(command=command, attempt='ISSUED', natural_return={'kind': 'UNOBSERVED', 'code': None})
    return row


def returned(row, code):
    _need(row['attempt'] == 'ISSUED' and type(code) is int and -64 <= code <= 255)
    row['natural_return'] = {'kind': 'RETURNED', 'code': code}
    return row


def _kind(error):
    if isinstance(error, (Cancelled, KeyboardInterrupt, SystemExit)): return 'CANCELLED'
    if isinstance(error, ImportError): return 'IMPORT'
    if isinstance(error, OSError): return 'IO'
    if type(error) is ValueError:
        return {'command-timeout': 'TIMEOUT', 'deadline-exhausted': 'DEADLINE',
            'output-bound': 'OUTPUT_BOUND', 'process-cleanup': 'PROCESS_CLEANUP'}.get(
                error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else '', 'DATA_REFUSAL')
    return 'OTHER'


def failure(row, error, cleanup=False):
    _need(type(cleanup) is bool)
    kind = _kind(error)
    if kind == 'CANCELLED': row['cancelled'] = True
    key = 'cleanup_failure' if cleanup else 'first_failure'
    if row[key] is None: row[key] = {'phase': row['phase'], 'command': row['command'], 'error_kind': kind}
    return row


def invalidate(row):
    row['write_failed'] = True
    return row


def _body(row):
    _need(type(row['schema_version']) is int and row['schema_version'] == 1)
    _need(type(row['phase']) is str and row['phase'] in PHASES)
    _need(type(row['command']) is str and row['command'] in COMMANDS)
    _need(type(row['attempt']) is str and row['attempt'] in ('NOT_ISSUED', 'ISSUED'))
    natural = row['natural_return']
    _need(type(natural) is dict and natural.keys() == {'kind', 'code'})
    _need(type(natural['kind']) is str and natural['kind'] in ('UNOBSERVED', 'RETURNED'))
    _need((natural['kind'] == 'UNOBSERVED' and natural['code'] is None) or
        (natural['kind'] == 'RETURNED' and type(natural['code']) is int and -64 <= natural['code'] <= 255))
    _need((row['attempt'] == 'NOT_ISSUED' and row['command'] == 'NONE' and natural['kind'] == 'UNOBSERVED') or
        (row['attempt'] == 'ISSUED' and row['command'] != 'NONE'))
    for key in ('first_failure', 'cleanup_failure'):
        item = row[key]
        if item is None: continue
        _need(type(item) is dict and item.keys() == {'phase', 'command', 'error_kind'})
        _need(type(item['phase']) is str and item['phase'] in PHASES)
        _need(type(item['command']) is str and item['command'] in COMMANDS)
        _need(type(item['error_kind']) is str and item['error_kind'] in ERRORS)
    _need(type(row['cancelled']) is bool and type(row['write_failed']) is bool)
    _need(not any(row[k] and row[k]['error_kind'] == 'CANCELLED' for k in ('first_failure', 'cleanup_failure')) or row['cancelled'])
    _need(len(_encoded(row)) <= LIMIT)


def validate(row, expected=None):
    _need(type(row) is dict and row.keys() == KEYS)
    _binding(row['binding']); _body(row)
    if expected is not None:
        _binding(expected); _need(row['binding'] == expected)
    return row


def _unique(items):
    result = {}
    for key, value in items:
        _need(key not in result); result[key] = value
    return result


def _finite(value):
    number = float(value)
    _need(math.isfinite(number))
    return number


def capture(raw, expected):
    group = {'availability': 'UNAVAILABLE', 'reason': 'MISSING', 'raw_sha256': None, 'diagnostic': None}
    if raw is None: return group
    _need(type(raw) is bytes)
    group.update(availability='REFUSED', reason='INVALID', raw_sha256=hashlib.sha256(raw).hexdigest())
    try:
        _need(len(raw) <= REPORT_LIMIT)
        report = json.loads(raw, object_pairs_hook=_unique, parse_float=_finite,
                            parse_constant=lambda _: _need(False))
        _need(type(report) is dict)
        row = validate(report['inner_diagnostic'], expected)
        _need(report['action'] == expected['action'] and report['nonce'] == expected['nonce'])
        _need(type(report['status']) is str and report['status'] == 'FAIL')
        _need(type(report['cancelled']) is bool and report['cancelled'] == row['cancelled'])
        _need(not row['write_failed'])
        public = {k: v for k, v in row.items() if k != 'binding'}
        public['binding_sha256'] = hashlib.sha256(_encoded(row['binding'])).hexdigest()
        group.update(availability='VERIFIED', reason='OBSERVED', diagnostic=public)
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError, UnicodeError):
        pass
    return group


def validate_group(group):
    _need(type(group) is dict and group.keys() == GROUP_KEYS)
    _need(type(group['availability']) is str and type(group['reason']) is str)
    pair = (group['availability'], group['reason'])
    _need(pair in (('NOT_RUN', 'NOT_RUN'), ('UNAVAILABLE', 'MISSING'), ('REFUSED', 'INVALID'), ('VERIFIED', 'OBSERVED')))
    if pair in (('NOT_RUN', 'NOT_RUN'), ('UNAVAILABLE', 'MISSING')):
        _need(group['raw_sha256'] is None and group['diagnostic'] is None)
    else:
        _need(_sha(group['raw_sha256']) or (pair == ('REFUSED', 'INVALID') and group['raw_sha256'] is None))
        if pair == ('REFUSED', 'INVALID'): _need(group['diagnostic'] is None)
        else:
            row = group['diagnostic']
            _need(type(row) is dict and row.keys() == PUBLIC_KEYS and _sha(row['binding_sha256']))
            _body(row); _need(not row['write_failed'])
    return group
