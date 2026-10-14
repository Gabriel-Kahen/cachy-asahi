# SPDX-License-Identifier: MIT
"""Finite child diagnostics; hashes bind private inputs, never publish their paths."""
from contextlib import contextmanager, nullcontext
import hashlib
import json
import re
from runtime import Cancelled

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

OP_ACTIONS = frozenset(('NONE', 'provision', 'probe', 'baseline', 'candidate', 'derive', 'cleanup'))
GATES = frozenset(('NONE', 'UNKNOWN', 'CHECKPOINT_WRITE', 'LAUNCH_VALIDATE', 'JOURNAL_READ', 'JOURNAL_WRITE', 'NAME_RESERVE', 'FIND_NAME', 'FIND_ID', 'CREATE_ATTEMPT', 'CREATE_ID', 'CREATE_JOURNAL', 'INSPECT_OWNERSHIP', 'INSPECT_RESOURCES', 'INSPECT_MOUNTS', 'INSPECT_COMMAND', 'LOCAL_PRE', 'DAEMON_PRE', 'QUERY_EXEC', 'QUERY_RETURN', 'LOCAL_POST', 'DAEMON_POST', 'DAEMON_CONNECT', 'DAEMON_RESPONSE', 'DAEMON_METADATA', 'START_ATTEMPT', 'IMAGE_JOURNAL', 'IMAGE_INVENTORY', 'IMAGE_COMMIT', 'IMAGE_INSPECT', 'IMAGE_CONFIG', 'IMAGE_REMOVE', 'CLEANUP_RESOLVE', 'CLEANUP_REMOVE', 'CLEANUP_ABSENCE', 'FINALIZATION'))
QUERIES = frozenset(('NONE', 'UNKNOWN', 'INFO', 'IMAGE_INSPECT', 'FIND_NAME', 'FIND_ID', 'CREATE', 'CONTAINER_INSPECT', 'START', 'REMOVE', 'IMAGE_INVENTORY', 'IMAGE_TAG_INSPECT', 'IMAGE_ID_INSPECT', 'IMAGE_COMMIT', 'IMAGE_REMOVE'))
OBS_KEYS = frozenset(('action', 'gate', 'predicate', 'category', 'query', 'query_return', 'daemon_return', 'create', 'start'))
RESOURCE_REQUIRED = frozenset(('AutoRemove', 'Privileged', 'ReadonlyRootfs', 'NetworkMode',
    'IpcMode', 'PidMode', 'CgroupnsMode', 'Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit',
    'CapDrop', 'SecurityOpt', 'Tmpfs', 'CapAdd'))
RESOURCE_FORBIDDEN = frozenset(('Devices', 'DeviceRequests', 'Binds', 'VolumesFrom', 'Links', 'PortBindings', 'GroupAdd'))
RESOURCE_KINDS = frozenset(('MISSING', 'TYPE', 'VALUE', 'PRESENT'))
REFUSALS = frozenset(('API HTTP framing differs', 'API aggregate timeout', 'API connect failed', 'API content length differs', 'API send failed', 'API socket failed', 'API wire budget exceeded', 'accepted base missing from protected inventory', 'base image query failed', 'bounded API JSON response required', 'bounded API request required', 'command-timeout', 'deadline-exhausted', 'derived image ID was already protected', 'derived image config/identity differs', 'derived image query failed', 'derived layer size exceeds3GiB budget', 'docker-binary-drift', 'docker-binary-path', 'docker-binary-pin', 'docker-capture-command', 'docker-cleanup-failed', 'docker-config', 'docker-container-command', 'docker-container-mounts', 'docker-container-ownership', 'docker-container-resources', 'docker-create-absence-uncertain', 'docker-create-unknown', 'docker-daemon-chunk-framing', 'docker-daemon-connect', 'docker-daemon-drift', 'docker-daemon-http-framing', 'docker-daemon-http-invalid', 'docker-daemon-http-status', 'docker-daemon-http-trailing', 'docker-daemon-http-truncated', 'docker-daemon-output-bound', 'docker-daemon-send', 'docker-daemon-timeout', 'docker-duplicate-json-key', 'docker-endpoint', 'docker-environment', 'docker-expected-daemon', 'docker-home', 'docker-host-uid-mapping-required', 'docker-image-binding', 'docker-image-drift', 'docker-image-pin', 'docker-image-query', 'docker-image-volumes', 'docker-input-size', 'docker-journal-binding', 'docker-journal-container', 'docker-journal-path', 'docker-journal-size', 'docker-kernel-action', 'docker-kernel-environment', 'docker-kernel-mount-map', 'docker-kernel-mount-path', 'docker-kernel-timeout', 'docker-local-pin-drift', 'docker-name-reservation', 'docker-native-daemon', 'docker-nonce', 'docker-ordinary-user', 'docker-owned-absence', 'docker-owned-inspect', 'docker-owned-list', 'docker-owned-remove', 'docker-regular-input', 'docker-reserved-name-exists', 'docker-role', 'docker-rootful-socket', 'docker-uninitialized', 'immutable derived image response required', 'invalid-argv', 'invalid-environment', 'invalid-output-bound', 'invalid-time-bound', 'journal build command differs', 'journal mount ownership differs', 'journal name is not nonce-owned', 'journal provision command differs', 'journal role/action differs', 'kernel probe requires bound worker and exact input map', 'kernel worker exit failed', 'new owned image journal required', 'new private image tag required', 'nonfinite owned image journal', 'one derived layer on exact accepted image required', 'one exact image required', 'one exact provision container required', 'output-bound', 'owned image ID absence unverified', 'owned image ID removal failed', 'owned image absence query failed', 'owned image accepted config differs', 'owned image identity differs', 'owned image journal changed during capture', 'owned image journal differs', 'owned image journal exceeded bound', 'owned image journal file differs', 'owned image journal path differs', 'owned image journal schema differs', 'owned image query differs', 'owned image removal failed', 'owned private tag still present', 'owned provision broker required', 'private image journal parent required', 'process-cleanup', 'protected image inventory changed before commit', 'protected image inventory malformed or oversized', 'protected image inventory query failed or exceeded bound', 'protected image journal differs', 'threaded-runner', 'unsafe-log-directory', 'unsafe-log-path'))


def diagnostic_keys(row):
    need(type(row) is dict and type(row.get('schema_version')) is int and row['schema_version'] in (1, 2, 3, 4))
    return KEYS | ({'operation'} if row['schema_version'] >= 2 else set()) | ({'inner'} if row['schema_version'] == 4 else set())


INNER_ACTIONS = ('probe', 'baseline', 'candidate')
INNER_PHASES = frozenset(('NONE', 'PRECHECK', 'PROFILE', 'INVENTORY', 'TOOLS', 'SOURCE',
    'CONFIG', 'CONFIG_DELTA', 'PAIRED_CONFIG', 'GENERATED_CONFIG', 'KERNEL', 'OUTPUTS', 'FINALIZATION', 'COMPLETE'))
INNER_COMMANDS = frozenset(('NONE', 'INVENTORY', 'CONFIG', 'KERNEL', *(f'TOOL_{n}' for n in range(18))))
INNER_ERRORS = frozenset(('DATA_REFUSAL', 'IO', 'IMPORT', 'TIMEOUT', 'DEADLINE', 'OUTPUT_BOUND',
    'PROCESS_CLEANUP', 'CANCELLED', 'OTHER'))
INNER_PUBLIC_KEYS = frozenset(('schema_version', 'binding_sha256', 'phase', 'command', 'attempt',
    'natural_return', 'first_failure', 'cleanup_failure', 'cancelled', 'write_failed'))




CONFIG_STAGES = frozenset(('BEFORE_CONFIG_PARSE', 'AFTER_CONFIG_PARSE', 'DELTA_COMPARE'))


def config_sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_config_fact(value):
    keys = {'stage', 'before_parsed_sha256', 'after_parsed_sha256', 'difference_count',
            'unexpected_count', 'difference_keys_sha256', 'first_unexpected', 'rust_capability_mismatch'}
    need(type(value) is dict and set(value) == keys and type(value['stage']) is str and value['stage'] in CONFIG_STAGES)
    for name in ('before_parsed_sha256', 'after_parsed_sha256', 'difference_keys_sha256'):
        need(value[name] is None or config_sha(value[name]))
    if value['stage'] != 'DELTA_COMPARE':
        need(value['after_parsed_sha256'] is None and value['difference_keys_sha256'] is None and
              value['difference_count'] is value['unexpected_count'] is value['first_unexpected'] is
              value['rust_capability_mismatch'] is None)
        need(value['before_parsed_sha256'] is None if value['stage'] == 'BEFORE_CONFIG_PARSE'
              else config_sha(value['before_parsed_sha256']))
        return value
    need(config_sha(value['before_parsed_sha256']) and config_sha(value['after_parsed_sha256']) and
          config_sha(value['difference_keys_sha256']) and type(value['difference_count']) is int and
          type(value['unexpected_count']) is int and 0 <= value['unexpected_count'] <= value['difference_count'] <= 131072 and
          type(value['rust_capability_mismatch']) is bool)
    first = value['first_unexpected']
    if value['unexpected_count'] == 0:
        need(first is None)
        return value
    need(type(first) is dict and set(first) == {'key', 'key_sha256', 'before', 'after',
          'before_present', 'after_present', 'truncated'} and config_sha(first['key_sha256']))
    need(all(type(first[name]) is bool for name in ('before_present', 'after_present', 'truncated')))
    key = first['key']
    need(key is None and first['truncated'] or type(key) is str and len(key) <= 128 and
          re.fullmatch('CONFIG_[A-Za-z0-9_]+', key) and hashlib.sha256(key.encode()).hexdigest() == first['key_sha256'])
    for name in ('before', 'after'):
        item = first[name]
        need(item is None or type(item) is str and len(item) <= 96 and all(32 <= ord(c) < 127 for c in item))
        need(item is None if not first[name + '_present'] else item is not None or first['truncated'])
    return value


def validate_inner_group(group):
    need(type(group) is dict and set(group) == {'availability', 'reason', 'raw_sha256', 'diagnostic'})
    availability = group['availability']
    need(type(availability) is str and availability in ('NOT_RUN', 'UNAVAILABLE', 'REFUSED', 'VERIFIED'))
    need(type(group['reason']) is str and group['reason'] == {'NOT_RUN': 'NOT_RUN', 'UNAVAILABLE': 'MISSING', 'REFUSED': 'INVALID', 'VERIFIED': 'OBSERVED'}[availability])
    pin = group['raw_sha256']
    need(pin is None or type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin))
    if availability != 'VERIFIED':
        need(group['diagnostic'] is None and (availability == 'REFUSED' or pin is None))
        return group
    need(pin is not None)
    row = group['diagnostic']
    need(type(row) is dict and type(row.get('schema_version')) is int and row['schema_version'] in (1, 2))
    need(set(row) == INNER_PUBLIC_KEYS | ({'config_failure'} if row['schema_version'] == 2 else set()))
    need(type(row['binding_sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['binding_sha256']))
    need(type(row['phase']) is str and row['phase'] in INNER_PHASES and type(row['command']) is str and row['command'] in INNER_COMMANDS)
    need(type(row['attempt']) is str and row['attempt'] in ('NOT_ISSUED', 'ISSUED'))
    natural = row['natural_return']
    need(type(natural) is dict and set(natural) == {'kind', 'code'} and type(natural['kind']) is str)
    need(natural == {'kind': 'UNOBSERVED', 'code': None} or natural['kind'] == 'RETURNED' and
         type(natural['code']) is int and -64 <= natural['code'] <= 255 and row['attempt'] == 'ISSUED')
    need((row['command'] == 'NONE') == (row['attempt'] == 'NOT_ISSUED'))
    need(type(row['cancelled']) is bool and row['write_failed'] is False)
    for name in ('first_failure', 'cleanup_failure'):
        failure = row[name]
        if failure is not None:
            need(type(failure) is dict and set(failure) == {'phase', 'command', 'error_kind'} and
                type(failure['phase']) is str and failure['phase'] in INNER_PHASES and
                type(failure['command']) is str and failure['command'] in INNER_COMMANDS and
                type(failure['error_kind']) is str and failure['error_kind'] in INNER_ERRORS)
            need(failure['error_kind'] != 'CANCELLED' or row['cancelled'])
    if row['schema_version'] == 2:
        validate_config_fact(row['config_failure'])
        need(row['first_failure'] is not None and row['first_failure']['phase'] == 'CONFIG_DELTA' and
             row['first_failure']['command'] == row['command'] == 'CONFIG' and row['attempt'] == 'ISSUED' and
             row['natural_return'] == {'kind': 'RETURNED', 'code': 0})
    need(len(json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()) <= 2048)
    return group


def inner_failure(row, action, group):
    """Add diagnostic-only data after the original nonzero command cause is frozen."""
    need(action in INNER_ACTIONS and row['schema_version'] in (3, 4) and
         row['first_failed_predicate'] != 'NONE' and row['commands'][action]['code'] not in (None, 0))
    validate_inner_group(group); need(group['availability'] != 'NOT_RUN')
    value = clone(row)
    if value['schema_version'] == 3:
        value.update(schema_version=4, inner={name: {'availability': 'NOT_RUN', 'reason': 'NOT_RUN',
            'raw_sha256': None, 'diagnostic': None} for name in INNER_ACTIONS})
    value['inner'][action] = clone(group)
    project(value)
    row.update(value)


def validate_return(row):
    if type(row) is dict and set(row) == {'kind', 'code'} and row['kind'] == 'HTTP_STATUS':
        need(type(row['kind']) is str and type(row['code']) is int and 100 <= row['code'] <= 599)
    else:
        validate_exit(row)


def validate_observation(row, version=3):
    need(type(row) is dict and set(row) == OBS_KEYS | ({'resource_mismatch'} if version == 3 else set()))
    for key, values in (('action', OP_ACTIONS), ('gate', GATES), ('query', QUERIES),
                        ('predicate', REFUSALS | {'NONE', 'UNKNOWN'}), ('category', CLEANUP_CATEGORIES),
                        ('create', {'NOT_ATTEMPTED', 'UNKNOWN', 'CID_OBSERVED'}),
                        ('start', {'NOT_ATTEMPTED', 'UNKNOWN', 'EXIT_OBSERVED'})):
        need(type(row[key]) is str and row[key] in values)
    need(row['category'] in CATEGORIES or row['action'] == 'cleanup')
    need((row['predicate'] == 'NONE') == (row['category'] == 'NONE'))
    validate_return(row['query_return']); validate_return(row['daemon_return'])
    need(row['daemon_return']['kind'] in ('NOT_RUN', 'UNOBSERVED', 'HTTP_STATUS'))
    need(row['query_return']['kind'] != 'HTTP_STATUS' or row['query'] in ('IMAGE_COMMIT', 'IMAGE_TAG_INSPECT'))
    need(row['query'] not in ('IMAGE_COMMIT', 'IMAGE_TAG_INSPECT') or
         row['query_return']['kind'] in ('NOT_RUN', 'UNOBSERVED', 'HTTP_STATUS'))
    if version == 3 and row['resource_mismatch'] is not None:
        mismatch = row['resource_mismatch']
        need(type(mismatch) is dict and set(mismatch) == {'field', 'kind'} and
             type(mismatch['field']) is str and mismatch['field'] in RESOURCE_REQUIRED | RESOURCE_FORBIDDEN and
             type(mismatch['kind']) is str and mismatch['kind'] in RESOURCE_KINDS)
        need((mismatch['kind'] == 'PRESENT' and mismatch['field'] in RESOURCE_FORBIDDEN | {'CapAdd'}) or
             (mismatch['kind'] != 'PRESENT' and mismatch['field'] in RESOURCE_REQUIRED))
        need(row['gate'] == 'INSPECT_RESOURCES' and row['predicate'] == 'docker-container-resources' and row['category'] != 'NONE')


def validate_operation(row, version=3):
    need(type(row) is dict and set(row) == {'current', 'first_failure', 'cleanup_failure'})
    validate_observation(row['current'], version)
    for name in ('first_failure', 'cleanup_failure'):
        if row[name] is not None:
            validate_observation(row[name], version); need(row[name]['category'] != 'NONE')
    if row['cleanup_failure'] is not None:
        need(row['cleanup_failure']['action'] == 'cleanup')


def observation():
    return dict(action='NONE', gate='NONE', predicate='NONE', category='NONE', query='NONE',
        query_return={'kind': 'NOT_RUN', 'code': None}, daemon_return={'kind': 'NOT_RUN', 'code': None},
        create='NOT_ATTEMPTED', start='NOT_ATTEMPTED', resource_mismatch=None)


def clone(value):
    return json.loads(encoded(value))


class Trace:
    """In-memory observations only. An exception is recorded before a scope unwinds."""
    def __init__(self):
        self.current = observation()
        self.first_failure = self.cleanup_failure = None
        self.stack = []

    @contextmanager
    def scope(self, gate, action=None):
        need(gate in GATES and (action is None or action in OP_ACTIONS))
        old_action = self.current['action']
        if action is not None: self.current['action'] = action
        self.current.update(gate=gate, predicate='NONE', category='NONE', resource_mismatch=None)
        self.stack.append((gate, self.current['action']))
        try:
            yield
        except BaseException as error:
            self.fail(error)
            raise
        finally:
            self.stack.pop()
            if action is not None and self.current['category'] == 'NONE':
                self.current['action'] = old_action

    def action(self, action):
        need(action in OP_ACTIONS)
        self.current = observation()
        self.current['action'] = action

    def begin(self, query):
        need(query in QUERIES)
        self.current.update(query=query, query_return={'kind': 'UNOBSERVED', 'code': None})
        if query == 'CREATE': self.current.update(create='UNKNOWN', start='NOT_ATTEMPTED')
        if query == 'START': self.current['start'] = 'UNKNOWN'

    def returned(self, code, *, daemon=False, http=False):
        row = {'kind': 'HTTP_STATUS', 'code': code} if http else exit_record(code)
        validate_return(row)
        self.current['daemon_return' if daemon else 'query_return'] = row
        if not daemon and self.current['query'] == 'START': self.current['start'] = 'EXIT_OBSERVED'

    def resources_refused(self, host, required, forbidden):
        """Only annotate an already refused immutable decoded profile; never accept it."""
        for field, expected in required.items():
            if field in RESOURCE_REQUIRED and host.get(field) != expected:
                kind = 'MISSING' if field not in host else 'TYPE' if type(host[field]) is not type(expected) else 'VALUE'
                self.current['resource_mismatch'] = {'field': field, 'kind': kind}
                return
        for field in forbidden:
            if field in RESOURCE_FORBIDDEN | {'CapAdd'} and host.get(field):
                self.current['resource_mismatch'] = {'field': field, 'kind': 'PRESENT'}
                return

    def fail(self, error, category=None):
        row = clone(self.current)
        row['gate'], row['action'] = self.stack[-1] if self.stack else ('UNKNOWN', row['action'])
        row['predicate'] = (error.args[0] if type(error) is ValueError and len(error.args) == 1 and
                            type(error.args[0]) is str and error.args[0] in REFUSALS else 'UNKNOWN')
        row['category'] = category or error_category(error)
        if row['gate'] != 'INSPECT_RESOURCES' or row['predicate'] != 'docker-container-resources':
            row['resource_mismatch'] = None
        target = 'cleanup_failure' if row['action'] == 'cleanup' else 'first_failure'
        if getattr(self, target) is None: setattr(self, target, clone(row))
        self.current = row

    def snapshot(self):
        result = clone(dict(current=self.current, first_failure=self.first_failure, cleanup_failure=self.cleanup_failure))
        validate_operation(result)
        return result


def scope(observer, gate, action=None):
    return observer.scope(gate, action) if isinstance(observer, Trace) else nullcontext()


def observed(gate, action=None):
    """Scope an existing broker/image function without altering its operation sequence."""
    def decorate(function):
        def wrapped(owner, *args, **kwargs):
            with scope(getattr(owner, 'observer', None), gate, action):
                return function(owner, *args, **kwargs)
        return wrapped
    return decorate


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
    diagnostic_keys(row)
    if row['schema_version'] >= 2:
        validate_operation(row['operation'], min(row['schema_version'], 3))
    if row['schema_version'] == 4:
        need(type(row['inner']) is dict and set(row['inner']) == set(INNER_ACTIONS) and
             row['current_predicate'] != 'COMPLETE' and row['first_failed_predicate'] != 'NONE')
        for group in row['inner'].values(): validate_inner_group(group)
        active = [name for name in INNER_ACTIONS if row['inner'][name]['availability'] != 'NOT_RUN']
        need(len(active) == 1)
        for name, group in row['inner'].items():
            validate_inner_group(group)
            if name in active: need(row['commands'][name]['code'] not in (None, 0))
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
        need((row['schema_version'] == 1 or row['operation']['first_failure'] is None and
              row['operation']['cleanup_failure'] is None) and
             row['first_failed_predicate'] == 'NONE' and clean['status'] == 'PASS' and
             all(value == exit_record(0) for value in row['commands'].values()))
        if row['schema_version'] == 3: need(row['operation']['current']['resource_mismatch'] is None)


def validate_public(row):
    need(type(row) is dict and set(row) == diagnostic_keys(row) | {'binding_sha256'})
    need(type(row['binding_sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['binding_sha256']))
    encoded(row); validate_fields(row)
    return row


def project(row):
    need(type(row) is dict and set(row) == diagnostic_keys(row) | {'binding'})
    encoded(row); validate_fields(row)
    binding = row['binding']
    need(type(binding) is dict and set(binding) == BINDING_KEYS)
    for name in BINDING_KEYS - {'source_commit', 'run_id', 'run_attempt', 'nonce'}:
        need(type(binding[name]) is str and re.fullmatch('[0-9a-f]{64}', binding[name]))
    need(type(binding['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', binding['source_commit']))
    need(type(binding['nonce']) is str and re.fullmatch('[0-9a-f]{32}', binding['nonce']))
    for name in ('run_id', 'run_attempt'):
        need(binding[name] is None or type(binding[name]) is str and re.fullmatch('[0-9]{1,20}', binding[name]))
    result = {key: clone(row[key]) for key in diagnostic_keys(row)}
    result['binding_sha256'] = hashlib.sha256(encoded(binding)).hexdigest()
    return validate_public(result)


def initial(binding, observer=None):
    row = {'schema_version': 1, 'binding': binding, 'current_predicate': 'SNAPSHOT',
        'first_failed_predicate': 'NONE', 'failure_category': 'NONE',
        'commands': {name: {'kind': 'NOT_RUN', 'code': None} for name in ACTIONS},
        'cleanup': {'status': 'NOT_RUN', 'category': 'NONE'}}
    if observer is not None:
        need(isinstance(observer, Trace))
        row.update(schema_version=3, operation=observer.snapshot())
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
    if row['schema_version'] >= 2:
        value = clone(row['operation']['current'])
        if value['category'] == 'NONE': value.update(gate='FINALIZATION' if row['current_predicate'] == 'FINALIZATION' else 'UNKNOWN',
                     predicate='UNKNOWN', category=category)
        key = 'cleanup_failure' if value['action'] == 'cleanup' else 'first_failure'
        if row['operation'][key] is None: row['operation'][key] = clone(value)
        row['operation']['current'] = value
    project(row)


def error_category(error, cancelled=False):
    if cancelled or isinstance(error, (KeyboardInterrupt, Cancelled)):
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
