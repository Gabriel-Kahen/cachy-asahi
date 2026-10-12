# SPDX-License-Identifier: MIT
"""Closed, bounded observations; raw provenance and output remain private."""
import json
import os
from pathlib import Path
import re
import stat

from evidence import EPOCH, ENTRY_SHA, INPUTS_SHA, INVENTORY_SHA, RECIPE_SHA, TEMPLATE_SHA, decode, load, need, read, sha

LIMIT = 4096
PROVENANCE_LIMIT = 32 * 1024**2
LOG_LIMIT = 8 * 1024**2
ACTIONS = ('build-1', 'build-2', 'compare')
PREDICATES = frozenset(('CONFIG', 'REVIEWED_INPUTS', 'BUILDER_IMPORT', 'BROKER_INITIALIZE',
    'BUILDER_CALL', 'CONTAINER_CREATE', 'CONTAINER_ATTACH', 'BUILDER_PROVENANCE', 'ARTIFACT_VERIFY',
    'COMPARE_INPUTS', 'COMPARE_CALL', 'COMPARE_VERIFY', 'CLEANUP', 'FINALIZATION', 'COMPLETE'))
REASONS = frozenset(('NONE', 'CANCELLED', 'DEADLINE', 'TIMEOUT', 'OUTPUT_BOUND', 'IO',
    'INVALID_DATA', 'COMMAND_NONZERO', 'UNKNOWN'))
BUILDER_REASONS = frozenset(('NONE', 'RECIPE_REVIEW', 'RECIPE_INPUTS', 'INVENTORY', 'IMAGE', 'MODE',
    'RECIPE_SNAPSHOT', 'CONTAINER_EXIT', 'TIMEOUT', 'BUILDER_OUTPUT', 'GENERATED_METADATA',
    'ARTIFACT_VALIDATION', 'UNKNOWN'))
BINDING_KEYS = frozenset(('source_commit', 'stage_lock_sha256', 'run_id', 'run_attempt', 'action',
    'nonce', 'config_sha256', 'inputs_sha256', 'inventory_sha256', 'recipe_sha256', 'template_sha256'))
FIELDS = frozenset(('schema_version', 'current_predicate', 'first_failed_predicate', 'failure_reason',
    'cancelled', 'builder', 'commands', 'cleanup'))


def encoded(value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    need(len(data) <= LIMIT, 'worker-diagnostic-bound')
    return data


def exit_record(code):
    need(type(code) is int and -64 <= code <= 255, 'worker-exit-type')
    return {'kind': 'EXIT_SIGNAL' if code < 0 else 'EXIT_NONZERO' if code else 'EXIT_ZERO', 'code': code}


def no_exit(kind='NOT_RUN'):
    return {'kind': kind, 'code': None}


def validate_exit(row):
    need(type(row) is dict and set(row) == {'kind', 'code'} and type(row['kind']) is str, 'worker-exit')
    if row['kind'] in ('NOT_RUN', 'UNOBSERVED'):
        need(row['code'] is None, 'worker-exit')
    else:
        need(row == exit_record(row['code']), 'worker-exit')


def binding(config, config_sha):
    return {key: config[key] for key in ('source_commit', 'stage_lock_sha256', 'run_id', 'run_attempt', 'action', 'nonce')} | {
        'config_sha256': config_sha, 'inputs_sha256': INPUTS_SHA, 'inventory_sha256': INVENTORY_SHA,
        'recipe_sha256': RECIPE_SHA, 'template_sha256': TEMPLATE_SHA}


def validate_fields(row):
    need(type(row['schema_version']) is int and row['schema_version'] == 1 and
         type(row['cancelled']) is bool, 'worker-diagnostic-header')
    for name, allowed in (('current_predicate', PREDICATES), ('first_failed_predicate', PREDICATES | {'NONE'}),
                          ('failure_reason', REASONS)):
        need(type(row[name]) is str and row[name] in allowed, 'worker-diagnostic-code')
    need((row['first_failed_predicate'] == 'NONE') == (row['failure_reason'] == 'NONE'), 'worker-first-failure')
    builder = row['builder']
    need(type(builder) is dict and set(builder) == {'exit', 'status', 'reason', 'provenance', 'log'}, 'worker-builder')
    validate_exit(builder['exit'])
    need(type(builder['status']) is str and builder['status'] in ('NOT_RUN', 'UNAVAILABLE', 'UNVERIFIED', 'FAILED', 'STATIC_PASS') and
         type(builder['reason']) is str and builder['reason'] in BUILDER_REASONS, 'worker-builder')
    need((builder['status'] == 'FAILED') == (builder['reason'] != 'NONE'), 'worker-builder-reason')
    for key, limit in (('provenance', PROVENANCE_LIMIT), ('log', LOG_LIMIT)):
        value = builder[key]
        need(value is None or type(value) is dict and set(value) == {'sha256', 'bytes'} and
            type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']) and
            type(value['bytes']) is int and 0 <= value['bytes'] <= limit, 'worker-data-digest')
    if builder['status'] in ('FAILED', 'STATIC_PASS'):
        need(builder['provenance'] is not None, 'worker-provenance-required')
    if builder['status'] == 'STATIC_PASS':
        need(builder['exit'] == exit_record(0) and builder['log'] is not None, 'worker-builder-return')
    if builder['status'] == 'NOT_RUN':
        need(builder['exit'] == no_exit() and builder['provenance'] is None and builder['log'] is None,
             'worker-builder-not-run')
    commands = row['commands']
    need(type(commands) is dict and set(commands) == {'create', 'attach', 'container'}, 'worker-commands')
    for value in commands.values(): validate_exit(value)
    # These are actual daemon State codes, never shell signal return codes.
    need(commands['container']['kind'] != 'EXIT_SIGNAL', 'worker-container-state')
    clean = row['cleanup']
    need(type(clean) is dict and set(clean) == {'status', 'absence', 'reason'} and
         type(clean['status']) is str and clean['status'] in ('NOT_RUN', 'PASS', 'FAIL') and
         type(clean['absence']) is str and clean['absence'] in ('NOT_RUN', 'PASS', 'UNVERIFIED') and
         type(clean['reason']) is str and clean['reason'] in ('NONE', 'CANCELLED', 'IO', 'INVALID_DATA', 'UNVERIFIED'), 'worker-cleanup')
    need((clean['status'], clean['absence'], clean['reason']) in
         {('NOT_RUN', 'NOT_RUN', 'NONE'), ('PASS', 'PASS', 'NONE')} or
         clean['status'] == 'FAIL' and clean['absence'] == 'UNVERIFIED' and clean['reason'] != 'NONE', 'worker-cleanup')
    if row['current_predicate'] == 'COMPLETE':
        need(row['first_failed_predicate'] == 'NONE' and not row['cancelled'], 'worker-completion')


def project(row):
    need(type(row) is dict and set(row) == FIELDS | {'binding'}, 'worker-diagnostic-shape')
    encoded(row); validate_fields(row)
    bound = row['binding']
    need(type(bound) is dict and set(bound) == BINDING_KEYS, 'worker-binding')
    for name in BINDING_KEYS - {'source_commit', 'run_id', 'run_attempt', 'action', 'nonce'}:
        need(type(bound[name]) is str and re.fullmatch('[0-9a-f]{64}', bound[name]), 'worker-binding-pin')
    need(type(bound['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', bound['source_commit']) and
         type(bound['nonce']) is str and re.fullmatch('[0-9a-f]{32}', bound['nonce']) and
         type(bound['action']) is str and bound['action'] in ACTIONS, 'worker-binding-identity')
    for name in ('run_id', 'run_attempt'):
        need(bound[name] is None or type(bound[name]) is str and re.fullmatch('[0-9]{1,20}', bound[name]), 'worker-binding-run')
    need(all(bound[name] == value for name, value in (('inputs_sha256', INPUTS_SHA), ('inventory_sha256', INVENTORY_SHA),
         ('recipe_sha256', RECIPE_SHA), ('template_sha256', TEMPLATE_SHA))), 'worker-binding-source')
    completion(row, bound['action'])
    result = {key: row[key] for key in FIELDS}
    result['binding_sha256'] = sha(encoded(bound))
    encoded(result)
    return result


def completion(row, action):
    if row['current_predicate'] == 'COMPLETE':
        if action != 'compare':
            need(row['builder']['status'] == 'STATIC_PASS' and row['cleanup']['status'] == 'PASS' and
                 row['commands']['create'] == row['commands']['attach'] == exit_record(0) and
                 row['commands']['container'] in (no_exit('UNOBSERVED'), exit_record(0)), 'worker-build-completion')
        else:
            need(row['builder']['status'] == 'NOT_RUN' and row['cleanup']['status'] == 'NOT_RUN' and
                 all(value == no_exit() for value in row['commands'].values()), 'worker-compare-completion')


def validate_public(row, action):
    need(type(action) is str and action in ACTIONS, 'worker-public-action')
    need(type(row) is dict and set(row) == FIELDS | {'binding_sha256'} and
         type(row['binding_sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['binding_sha256']), 'worker-public-shape')
    encoded(row); validate_fields(row); completion(row, action)


def validate_worker_row(row, action):
    need(type(action) is str and action in ACTIONS, 'worker-public-action')
    need(type(row) is dict and set(row) == {'availability', 'exit', 'observation'} and
         type(row['availability']) is str and row['availability'] in
         ('NOT_RUN', 'UNAVAILABLE', 'UNVERIFIED', 'VERIFIED'), 'worker-receiver-shape')
    validate_exit(row['exit'])
    if row['availability'] == 'VERIFIED':
        need(row['exit']['kind'] != 'NOT_RUN', 'worker-receiver-exit')
        validate_public(row['observation'], action)
    else:
        need(row['observation'] is None, 'worker-receiver-unverified')
        need((row['availability'] == 'NOT_RUN') == (row['exit'] == no_exit()), 'worker-receiver-exit')


def validate_workers(rows, *, require_complete=False):
    """Pure public-vector boundary, shared with the authenticated outer consumer."""
    need(type(require_complete) is bool and type(rows) is dict and set(rows) == set(ACTIONS), 'worker-public-set')
    for action, row in rows.items(): validate_worker_row(row, action)
    bindings = [row['observation']['binding_sha256'] for row in rows.values() if row['availability'] == 'VERIFIED']
    need(len(bindings) == len(set(bindings)), 'worker-public-distinct-bindings')
    if require_complete:
        need(all(row['availability'] == 'VERIFIED' and row['exit'] == exit_record(0) and
                 row['observation']['current_predicate'] == 'COMPLETE' for row in rows.values()), 'worker-public-incomplete')
    return json.loads(json.dumps(rows, allow_nan=False))


def initial(config, config_sha):
    row = {'schema_version': 1, 'binding': binding(config, config_sha), 'current_predicate': 'CONFIG',
        'first_failed_predicate': 'NONE', 'failure_reason': 'NONE', 'cancelled': False,
        'builder': {'exit': no_exit(), 'status': 'NOT_RUN', 'reason': 'NONE', 'provenance': None, 'log': None},
        'commands': {name: no_exit() for name in ('create', 'attach', 'container')},
        'cleanup': {'status': 'NOT_RUN', 'absence': 'NOT_RUN', 'reason': 'NONE'}}
    project(row)
    return row


def failure(row, reason, predicate=None):
    need(reason in REASONS - {'NONE'}, 'worker-failure-reason')
    if predicate is not None: row['current_predicate'] = predicate
    elif row['current_predicate'] == 'COMPLETE': row['current_predicate'] = 'FINALIZATION'
    if reason == 'CANCELLED': row['cancelled'] = True
    if row['first_failed_predicate'] == 'NONE':
        row['first_failed_predicate'], row['failure_reason'] = row['current_predicate'], reason


def error_reason(error, cancelled=False):
    if cancelled or isinstance(error, KeyboardInterrupt): return 'CANCELLED'
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        known = {'deadline-exhausted': 'DEADLINE', 'command-timeout': 'TIMEOUT', 'output-bound': 'OUTPUT_BOUND'}
        if error.args[0] in known: return known[error.args[0]]
    if isinstance(error, OSError): return 'IO'
    if isinstance(error, (ValueError, KeyError, TypeError)): return 'INVALID_DATA'
    return 'UNKNOWN'


def capture(path, limit):
    info = Path(path).lstat()
    need(info.st_uid == os.getuid() and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) in (0o600, 0o644), 'worker-data-owner')
    raw = read(path, limit)
    after = Path(path).lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                           s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(info) == identity(after), 'worker-data-race')
    return raw, {'sha256': sha(raw), 'bytes': len(raw)}


def builder_reason(error):
    if type(error) is not str: return 'UNKNOWN'
    exact = {'recipe inputs differ from independently reviewed digest set': 'RECIPE_INPUTS',
        'expected package lock must be nonempty and sorted': 'INVENTORY', 'builder image is not linux/arm64': 'IMAGE',
        'recipe inputs changed during snapshot': 'RECIPE_SNAPSHOT',
        'builder timeout; this build container was removed': 'TIMEOUT',
        'missing required builder environment/config/metadata evidence': 'BUILDER_OUTPUT',
        'symlink builder output forbidden': 'BUILDER_OUTPUT',
        'builder package inventory differs from approved lock': 'INVENTORY',
        'builder produced no packages': 'BUILDER_OUTPUT',
        'single-package recipe must produce exactly one artifact': 'ARTIFACT_VALIDATION'}
    if error in exact: return exact[error]
    if re.fullmatch(r'container build exited (?:[1-9][0-9]{0,2}|-[1-9][0-9]?); see build\.log', error): return 'CONTAINER_EXIT'
    if error in ('mode native contradicts Docker server architecture x86_64',
                 'mode native contradicts Docker server architecture amd64'): return 'MODE'
    if re.fullmatch(r'isolated generated metadata differs from reviewed [A-Za-z0-9_]+', error): return 'GENERATED_METADATA'
    if re.fullmatch(r'artifact metadata differs from reviewed (?:pkgname|pkgbase|pkgver|arch|license|depend|makedepend|checkdepend|optdepend|provides|conflict|replaces|backup)', error): return 'ARTIFACT_VALIDATION'
    return 'UNKNOWN'


def observe_builder(row, directory, config, reviewed):
    """Capture fixed provenance/log files once; no recursive export or raw text."""
    result = row['builder']; result.update(status='UNAVAILABLE', reason='NONE')
    captured = None
    try:
        raw, stamp = capture(Path(directory) / 'provenance.json', PROVENANCE_LIMIT)
        captured = decode(raw)
        need(captured.get('schema_version') == 1 and type(captured['schema_version']) is int and
             captured.get('mode') == 'native' and captured.get('network') == 'none' and
             captured.get('image') == config['image'] and type(captured.get('source_date_epoch')) is int and
             captured['source_date_epoch'] == EPOCH and
             (not 'recipe_inputs' in captured or captured['recipe_inputs'] == reviewed) and
             (not 'image_id' in captured or captured['image_id'] == config['image']) and
             (not 'expected_packages_sha256' in captured or captured['expected_packages_sha256'] == INVENTORY_SHA),
             'worker-builder-binding')
        if 'exit_code' in captured:
            exit_record(captured['exit_code'])
            observed = next((row['commands'][key] for key in ('attach', 'create')
                             if row['commands'][key]['kind'].startswith('EXIT_')), None)
            need(observed is None or observed == exit_record(captured['exit_code']), 'worker-builder-command-exit')
        if captured.get('status') == 'failed':
            result.update(status='FAILED', reason=builder_reason(captured.get('error')), provenance=stamp)
        elif captured.get('status') == 'built-package-static-pass':
            need(result['exit'] == exit_record(0) and type(captured.get('exit_code')) is int and
                 captured['exit_code'] == 0 and captured.get('recipe_inputs') == reviewed and
                 captured.get('image_id') == config['image'] and
                 captured.get('expected_packages_sha256') == INVENTORY_SHA and
                 captured.get('builder_host_arch') in ('aarch64', 'arm64') and
                 captured.get('entry_script_sha256') == ENTRY_SHA, 'worker-builder-return')
            result.update(status='STATIC_PASS', reason='NONE', provenance=stamp)
        else:
            need(captured.get('status') in ('preflight-failed', 'building'), 'worker-builder-status')
            result.update(status='UNVERIFIED', reason='NONE', provenance=stamp)
    except FileNotFoundError:
        captured = None
    except Exception:
        captured = None; result.update(status='UNVERIFIED', reason='NONE', provenance=None)
    log_bytes = None
    try:
        log_bytes, result['log'] = capture(Path(directory) / 'build.log', LOG_LIMIT)
    except Exception:
        result['log'] = None
    if result['status'] == 'STATIC_PASS' and result['log'] is None:
        result.update(status='UNVERIFIED', reason='NONE')
    return captured, log_bytes


def worker_row(kind='NOT_RUN'):
    return {'availability': kind, 'exit': no_exit() if kind == 'NOT_RUN' else no_exit('UNOBSERVED'), 'observation': None}


def receive(config, config_sha, row):
    """One receipt/provenance/log capture per receiver, matched to this config."""
    path = Path(config['private']) / (config['action'] + '-receipt.json')
    try:
        need(stat.S_IMODE(path.lstat().st_mode) == 0o600, 'worker-receipt-mode')
        raw, _ = capture(path, 65536)
        receipt = decode(raw)
        need(set(receipt) <= {'status', 'action', 'hardware', 'cancelled', 'diagnostics', 'cleanup',
                             'artifact', 'comparison', 'attempts'} and
             receipt.get('status') in ('PASS', 'FAIL') and receipt.get('action') == config['action'] and
             receipt.get('hardware') == 'NOT RUN' and type(receipt.get('cancelled')) is bool, 'worker-receipt-header')
        observed = receipt['diagnostics']
        projected = project(observed)
        need(observed['binding'] == binding(config, config_sha) and
             receipt['cancelled'] == observed['cancelled'] and
             (receipt['status'] == 'PASS') == (observed['current_predicate'] == 'COMPLETE'), 'worker-receipt-binding')
        if config['action'] != 'compare':
            clean = receipt.get('cleanup')
            if clean is None:
                need(observed['cleanup']['status'] == 'NOT_RUN', 'worker-cleanup-binding')
            else:
                positive = (clean.get('status') == 'PASS' and clean.get('absence_verified') is True and
                            clean.get('cancelled', False) is False)
                need(positive == (observed['cleanup']['status'] == 'PASS'), 'worker-cleanup-binding')
            # Match independently captured bytes to the worker's source-bound stamp.
            if observed['builder']['status'] != 'NOT_RUN':
                current = json.loads(json.dumps(observed))
                observe_builder(current, Path(config['private']) / config['action'], config,
                                load(Path(config['snapshot']) / 'scripts/port/fdk-native-stage/reviewed-inputs.json', RECIPE_SHA))
                need(current['builder'] == observed['builder'], 'worker-provenance-receiver')
        row.update(availability='VERIFIED', observation=projected)
        return receipt
    except FileNotFoundError:
        row.update(availability='UNAVAILABLE', observation=None)
    except Exception:
        row.update(availability='UNVERIFIED', observation=None)
    return None
