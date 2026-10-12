#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Publish one finite status record; never traverse or publish build evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 16 * 1024
LEGACY_KEYS = {'schema_version', 'stage', 'status', 'phase', 'cancelled', 'source_commit',
        'packet_sha256', 'producer', 'kernel_probe', 'baseline', 'candidate', 'cleanup',
        'native_compilation', 'kernel_runtime', 'hardware', 'installation', 'performance',
        'binary_publication', 'selected_for_release', 'first_failed_phase', 'failure_reason',
        'producer_exit', 'acquisition_exit', 'resources', 'daemon_baseline'}
KEYS = LEGACY_KEYS | {'kernel_child'}
REASONS = {
    'NONE': {'NONE'},
    'preflight': {'PREFLIGHT_REJECTED', 'HOST_CAPABILITIES', 'HOST_MEMORY_RESERVE',
                  'HOST_DISK_RESERVE', 'HOST_TOOL_UNAVAILABLE', 'CANCELLED'},
    'source': {'SOURCE_REJECTED', 'DOCKER_REJECTED', 'DAEMON_OCCUPIED',
               'PRODUCER_TIME_RESERVE', 'CANCELLED', 'DAEMON_CONTAINERS_PRESENT',
               'DAEMON_BASELINE_UNVERIFIED'},
    'parallel': {'PRODUCER_EXIT', 'ACQUISITION_EXIT', 'BOTH_CHILDREN_EXIT', 'PARALLEL_TIMEOUT',
                 'PARALLEL_OUTPUT_BOUND', 'PARALLEL_RUN_FAILED', 'CANCELLED'},
    'producer': {'PRODUCER_RECEIPT_REJECTED', 'CANCELLED', 'PRODUCER_BASELINE_ID_COLLISION',
                 'DAEMON_BASELINE_CHANGED', 'DAEMON_BASELINE_UNVERIFIED'},
    'acquisition': {'ACQUISITION_RECEIPT_REJECTED', 'CANCELLED'},
    'kernel': {'KERNEL_TIME_RESERVE', 'KERNEL_DISK_RESERVE', 'KERNEL_OUTPUT_REJECTED',
               'KERNEL_EXIT', 'KERNEL_TIMEOUT', 'KERNEL_OUTPUT_BOUND', 'KERNEL_RUN_FAILED',
               'KERNEL_RECEIPT_REJECTED', 'CANCELLED'},
    'cleanup': {'CLEANUP_FAILED', 'CANCELLED', 'DAEMON_BASELINE_CHANGED',
                'DAEMON_BASELINE_UNVERIFIED', 'OWNED_ABSENCE_UNVERIFIED'},
    'finalization': {'CANCELLED', 'PUBLICATION_FAILED'},
    'outcome': {'NATIVE_FAILURE', 'NATIVE_CANCELLED', 'NATIVE_SKIPPED', 'NATIVE_UNAVAILABLE'},
}
FIRST_PHASES = set(REASONS)
PHASES = {'preflight', 'source', 'producer', 'kernel', 'cleanup', 'complete'}
RESOURCE_KEYS = {'mem_total_bytes', 'mem_available_bytes', 'initial_free_disk_bytes',
                 'pre_kernel_free_disk_bytes'}
DAEMON_BASELINE_KEYS = {'initial_container_count', 'initial_image_id_count',
                        'pre_identity_sha256', 'post_identity_sha256', 'preservation',
                        'owned_absence', 'producer_mutation', 'legacy_build_cache'}
CHILDREN = ('producer', 'kernel_probe', 'baseline', 'candidate')


def need(value):
    if not value:
        raise ValueError('public-boundary')


def failure_pair(phase, reason):
    need(type(phase) is str and type(reason) is str and
         phase in FIRST_PHASES and reason in REASONS[phase])


def record_failure(value, phase, reason):
    failure_pair(phase, reason)
    failure_pair(value['first_failed_phase'], value['failure_reason'])
    value['status'] = 'FAIL'
    if value['first_failed_phase'] == 'NONE':
        value['first_failed_phase'], value['failure_reason'] = phase, reason


def exit_record(code):
    need(type(code) is int and -64 <= code <= 255)
    return {'kind': 'EXIT_SIGNAL' if code < 0 else 'EXIT_NONZERO' if code else 'EXIT_ZERO',
            'code': code}


def diagnostics(value):
    failure_pair(value['first_failed_phase'], value['failure_reason'])
    for name in ('producer_exit', 'acquisition_exit'):
        row = value[name]
        need(type(row) is dict and set(row) == {'kind', 'code'} and type(row['kind']) is str)
        if row['kind'] in {'NOT_RUN', 'UNOBSERVED'}:
            need(row['code'] is None)
        else:
            need(row == exit_record(row['code']))
    exits = tuple(value[name]['kind'] for name in ('producer_exit', 'acquisition_exit'))
    failed = tuple(kind in {'EXIT_NONZERO', 'EXIT_SIGNAL'} for kind in exits)
    if value['first_failed_phase'] == 'NONE':
        need(not any(failed))
    if value['first_failed_phase'] == 'parallel':
        expected = {'PRODUCER_EXIT': (True, False), 'ACQUISITION_EXIT': (False, True),
                    'BOTH_CHILDREN_EXIT': (True, True)}.get(value['failure_reason'])
        if expected is not None:
            need(failed == expected and all(fail or kind == 'EXIT_ZERO'
                                           for fail, kind in zip(failed, exits)))
    resources = value['resources']
    need(type(resources) is dict and set(resources) == RESOURCE_KEYS and
         all(item is None or type(item) is int and 0 <= item <= 2**60
             for item in resources.values()))
    need(not value['cancelled'] or value['first_failed_phase'] != 'NONE')


def daemon_baseline(value):
    row = value['daemon_baseline']
    need(type(row) is dict and set(row) == DAEMON_BASELINE_KEYS)
    for name in ('initial_container_count', 'initial_image_id_count'):
        item = row[name]
        need(item is None or type(item) is int and 0 <= item <= 256)
    for name in ('pre_identity_sha256', 'post_identity_sha256'):
        item = row[name]
        need(item is None or type(item) is str and re.fullmatch('[0-9a-f]{64}', item))
    for name in ('preservation', 'owned_absence'):
        need(type(row[name]) is str and row[name] in {'NOT_RUN', 'PASS', 'FAIL', 'UNVERIFIED'})
    need(type(row['producer_mutation']) is str and row['producer_mutation'] in
         {'NOT_STARTED', 'COMPLETE_ACCEPTED', 'COMPLETE_REJECTED', 'UNCERTAIN'} and
         row['legacy_build_cache'] == 'NOT_ESTABLISHED')
    pre, post = row['pre_identity_sha256'], row['post_identity_sha256']
    initial = row['initial_container_count'] == 0 and row['initial_image_id_count'] is not None
    need(pre is None or initial)
    need(post is None or pre is not None)
    if row['preservation'] in {'PASS', 'FAIL'}:
        need(initial and pre is not None and post is not None and
             (pre == post) == (row['preservation'] == 'PASS'))
    else:
        need(post is None)
    if row['producer_mutation'] == 'NOT_STARTED':
        need(value['producer'] == 'NOT RUN' and
             value['producer_exit'] == {'kind': 'NOT_RUN', 'code': None})
    if row['producer_mutation'] == 'COMPLETE_ACCEPTED':
        need(initial and pre is not None and value['producer'] == 'PASS' and
             value['producer_exit'] == exit_record(0))
    if row['producer_mutation'] == 'COMPLETE_REJECTED':
        need(value['producer'] == 'FAIL' and value['producer_exit'] == exit_record(0))
    if row['producer_mutation'] == 'UNCERTAIN':
        need(value['producer'] != 'PASS')
    if value['first_failed_phase'] == 'source':
        if value['failure_reason'] == 'DAEMON_CONTAINERS_PRESENT':
            need(type(row['initial_container_count']) is int and row['initial_container_count'] > 0 and
                 row['producer_mutation'] == 'NOT_STARTED')
        if value['failure_reason'] == 'DAEMON_BASELINE_UNVERIFIED':
            need(row['preservation'] == 'UNVERIFIED' and row['producer_mutation'] == 'NOT_STARTED')
    if (value['first_failed_phase'], value['failure_reason']) == ('producer', 'PRODUCER_BASELINE_ID_COLLISION'):
        need(initial and pre is not None and row['producer_mutation'] == 'COMPLETE_REJECTED' and
             value['producer_exit'] == exit_record(0))
    if value['cleanup'] == 'PASS':
        need(row['preservation'] == 'PASS' and row['owned_absence'] == 'PASS' and
             row['producer_mutation'] == 'COMPLETE_ACCEPTED')



# Pure duplicated schema: cross-boundary tests keep the child/receiver agreement exact.
CHILD_LIMIT = 4096
CHILD_ACTIONS = ('provision', 'probe', 'baseline', 'candidate')
CHILD_PREDICATES = frozenset(('SNAPSHOT', 'ACCEPTED_BASE', 'DEPENDENCY_PACKET', 'PROVISION_INITIALIZE', 'PROVISION_COMMAND', 'PROVISION_RECEIPT', 'DERIVED_IMAGE', 'BUILD_INITIALIZE', 'PROBE_COMMAND', 'PROBE_RECEIPT', 'BASELINE_COMMAND', 'BASELINE_RECEIPT', 'BASELINE_CONFIG', 'CANDIDATE_COMMAND', 'CANDIDATE_RECEIPT', 'PAIR_ACCEPTANCE', 'CLEANUP', 'FINALIZATION', 'COMPLETE'))
CHILD_CATEGORIES = frozenset(('NONE', 'CANCELLED', 'DEADLINE', 'TIMEOUT', 'OUTPUT_BOUND', 'IO', 'INVALID_DATA', 'COMMAND_NONZERO', 'UNCLASSIFIED'))
CHILD_CLEANUP_CATEGORIES = CHILD_CATEGORIES | {'ABSENCE_UNVERIFIED', 'UNCERTAIN_MUTATION'}
CHILD_BINDING_KEYS = frozenset(('source_commit', 'stage_lock_sha256', 'output_name_sha256', 'run_id', 'run_attempt', 'nonce', 'accepted_result_sha256', 'bootstrap_sha256', 'inputs_sha256', 'base_inventory_sha256'))
CHILD_DIAG_KEYS = frozenset(('schema_version', 'current_predicate', 'first_failed_predicate', 'failure_category', 'commands', 'cleanup'))
CHILD_OP_ACTIONS = frozenset(('NONE', 'provision', 'probe', 'baseline', 'candidate', 'derive', 'cleanup'))
CHILD_GATES = frozenset(('NONE', 'UNKNOWN', 'CHECKPOINT_WRITE', 'LAUNCH_VALIDATE', 'JOURNAL_READ', 'JOURNAL_WRITE', 'NAME_RESERVE', 'FIND_NAME', 'FIND_ID', 'CREATE_ATTEMPT', 'CREATE_ID', 'CREATE_JOURNAL', 'INSPECT_OWNERSHIP', 'INSPECT_RESOURCES', 'INSPECT_MOUNTS', 'INSPECT_COMMAND', 'LOCAL_PRE', 'DAEMON_PRE', 'QUERY_EXEC', 'QUERY_RETURN', 'LOCAL_POST', 'DAEMON_POST', 'DAEMON_CONNECT', 'DAEMON_RESPONSE', 'DAEMON_METADATA', 'START_ATTEMPT', 'IMAGE_JOURNAL', 'IMAGE_INVENTORY', 'IMAGE_COMMIT', 'IMAGE_INSPECT', 'IMAGE_CONFIG', 'IMAGE_REMOVE', 'CLEANUP_RESOLVE', 'CLEANUP_REMOVE', 'CLEANUP_ABSENCE', 'FINALIZATION'))
CHILD_QUERIES = frozenset(('NONE', 'UNKNOWN', 'INFO', 'IMAGE_INSPECT', 'FIND_NAME', 'FIND_ID', 'CREATE', 'CONTAINER_INSPECT', 'START', 'REMOVE', 'IMAGE_INVENTORY', 'IMAGE_TAG_INSPECT', 'IMAGE_ID_INSPECT', 'IMAGE_COMMIT', 'IMAGE_REMOVE'))
CHILD_OBS_KEYS = frozenset(('action', 'gate', 'predicate', 'category', 'query', 'query_return', 'daemon_return', 'create', 'start'))
CHILD_REFUSALS = frozenset(('API HTTP framing differs', 'API aggregate timeout', 'API connect failed', 'API content length differs', 'API send failed', 'API socket failed', 'API wire budget exceeded', 'accepted base missing from protected inventory', 'base image query failed', 'bounded API JSON response required', 'bounded API request required', 'command-timeout', 'deadline-exhausted', 'derived image ID was already protected', 'derived image config/identity differs', 'derived image query failed', 'derived layer size exceeds3GiB budget', 'docker-binary-drift', 'docker-binary-path', 'docker-binary-pin', 'docker-capture-command', 'docker-cleanup-failed', 'docker-config', 'docker-container-command', 'docker-container-mounts', 'docker-container-ownership', 'docker-container-resources', 'docker-create-absence-uncertain', 'docker-create-unknown', 'docker-daemon-chunk-framing', 'docker-daemon-connect', 'docker-daemon-drift', 'docker-daemon-http-framing', 'docker-daemon-http-invalid', 'docker-daemon-http-status', 'docker-daemon-http-trailing', 'docker-daemon-http-truncated', 'docker-daemon-output-bound', 'docker-daemon-send', 'docker-daemon-timeout', 'docker-duplicate-json-key', 'docker-endpoint', 'docker-environment', 'docker-expected-daemon', 'docker-home', 'docker-host-uid-mapping-required', 'docker-image-binding', 'docker-image-drift', 'docker-image-pin', 'docker-image-query', 'docker-image-volumes', 'docker-input-size', 'docker-journal-binding', 'docker-journal-container', 'docker-journal-path', 'docker-journal-size', 'docker-kernel-action', 'docker-kernel-environment', 'docker-kernel-mount-map', 'docker-kernel-mount-path', 'docker-kernel-timeout', 'docker-local-pin-drift', 'docker-name-reservation', 'docker-native-daemon', 'docker-nonce', 'docker-ordinary-user', 'docker-owned-absence', 'docker-owned-inspect', 'docker-owned-list', 'docker-owned-remove', 'docker-regular-input', 'docker-reserved-name-exists', 'docker-role', 'docker-rootful-socket', 'docker-uninitialized', 'immutable derived image response required', 'invalid-argv', 'invalid-environment', 'invalid-output-bound', 'invalid-time-bound', 'journal build command differs', 'journal mount ownership differs', 'journal name is not nonce-owned', 'journal provision command differs', 'journal role/action differs', 'kernel probe requires bound worker and exact input map', 'kernel worker exit failed', 'new owned image journal required', 'new private image tag required', 'nonfinite owned image journal', 'one derived layer on exact accepted image required', 'one exact image required', 'one exact provision container required', 'output-bound', 'owned image ID absence unverified', 'owned image ID removal failed', 'owned image absence query failed', 'owned image accepted config differs', 'owned image identity differs', 'owned image journal changed during capture', 'owned image journal differs', 'owned image journal exceeded bound', 'owned image journal file differs', 'owned image journal path differs', 'owned image journal schema differs', 'owned image query differs', 'owned image removal failed', 'owned private tag still present', 'owned provision broker required', 'private image journal parent required', 'process-cleanup', 'protected image inventory changed before commit', 'protected image inventory malformed or oversized', 'protected image inventory query failed or exceeded bound', 'protected image journal differs', 'threaded-runner', 'unsafe-log-directory', 'unsafe-log-path'))

def child_diagnostic_keys(row):
    need(type(row) is dict and type(row.get('schema_version')) is int and (row['schema_version'] in (1, 2)))
    return CHILD_DIAG_KEYS | ({'operation'} if row['schema_version'] == 2 else set())

def child_validate_return(row):
    if type(row) is dict and set(row) == {'kind', 'code'} and (row['kind'] == 'HTTP_STATUS'):
        need(type(row['kind']) is str and type(row['code']) is int and (100 <= row['code'] <= 599))
    else:
        child_validate_exit(row)

def child_validate_observation(row):
    need(type(row) is dict and set(row) == CHILD_OBS_KEYS)
    for key, values in (('action', CHILD_OP_ACTIONS), ('gate', CHILD_GATES), ('query', CHILD_QUERIES), ('predicate', CHILD_REFUSALS | {'NONE', 'UNKNOWN'}), ('category', CHILD_CLEANUP_CATEGORIES), ('create', {'NOT_ATTEMPTED', 'UNKNOWN', 'CID_OBSERVED'}), ('start', {'NOT_ATTEMPTED', 'UNKNOWN', 'EXIT_OBSERVED'})):
        need(type(row[key]) is str and row[key] in values)
    need(row['category'] in CHILD_CATEGORIES or row['action'] == 'cleanup')
    need((row['predicate'] == 'NONE') == (row['category'] == 'NONE'))
    child_validate_return(row['query_return'])
    child_validate_return(row['daemon_return'])
    need(row['daemon_return']['kind'] in ('NOT_RUN', 'UNOBSERVED', 'HTTP_STATUS'))
    need(row['query_return']['kind'] != 'HTTP_STATUS' or row['query'] in ('IMAGE_COMMIT', 'IMAGE_TAG_INSPECT'))
    need(row['query'] not in ('IMAGE_COMMIT', 'IMAGE_TAG_INSPECT') or row['query_return']['kind'] in ('NOT_RUN', 'UNOBSERVED', 'HTTP_STATUS'))

def child_validate_operation(row):
    need(type(row) is dict and set(row) == {'current', 'first_failure', 'cleanup_failure'})
    child_validate_observation(row['current'])
    for name in ('first_failure', 'cleanup_failure'):
        if row[name] is not None:
            child_validate_observation(row[name])
            need(row[name]['category'] != 'NONE')
    if row['cleanup_failure'] is not None:
        need(row['cleanup_failure']['action'] == 'cleanup')

def child_clone(value):
    return json.loads(child_encoded(value))

def child_encoded(value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    need(len(data) <= CHILD_LIMIT)
    return data

def child_validate_exit(row):
    need(type(row) is dict and set(row) == {'kind', 'code'} and (type(row['kind']) is str))
    if row['kind'] in ('NOT_RUN', 'UNOBSERVED'):
        need(row['code'] is None)
    else:
        need(row == exit_record(row['code']))
    return row

def child_validate_fields(row):
    child_diagnostic_keys(row)
    if row['schema_version'] == 2:
        child_validate_operation(row['operation'])
    need(type(row['current_predicate']) is str and row['current_predicate'] in CHILD_PREDICATES)
    need(type(row['first_failed_predicate']) is str and row['first_failed_predicate'] in CHILD_PREDICATES | {'NONE'})
    need(type(row['failure_category']) is str and row['failure_category'] in CHILD_CATEGORIES)
    need((row['first_failed_predicate'] == 'NONE') == (row['failure_category'] == 'NONE'))
    need(type(row['commands']) is dict and set(row['commands']) == set(CHILD_ACTIONS))
    for value in row['commands'].values():
        child_validate_exit(value)
    clean = row['cleanup']
    need(type(clean) is dict and set(clean) == {'status', 'category'})
    need(type(clean['status']) is str and clean['status'] in ('NOT_RUN', 'PASS', 'FAIL'))
    need(type(clean['category']) is str and clean['category'] in CHILD_CLEANUP_CATEGORIES)
    need((clean['status'] != 'FAIL') == (clean['category'] == 'NONE'))
    if row['current_predicate'] == 'COMPLETE':
        need((row['schema_version'] == 1 or (row['operation']['first_failure'] is None and row['operation']['cleanup_failure'] is None)) and row['first_failed_predicate'] == 'NONE' and (clean['status'] == 'PASS') and all((value == exit_record(0) for value in row['commands'].values())))

def child_validate_public(row):
    need(type(row) is dict and set(row) == child_diagnostic_keys(row) | {'binding_sha256'})
    need(type(row['binding_sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['binding_sha256']))
    child_encoded(row)
    child_validate_fields(row)
    return row

def child_project(row):
    need(type(row) is dict and set(row) == child_diagnostic_keys(row) | {'binding'})
    child_encoded(row)
    child_validate_fields(row)
    binding = row['binding']
    need(type(binding) is dict and set(binding) == CHILD_BINDING_KEYS)
    for name in CHILD_BINDING_KEYS - {'source_commit', 'run_id', 'run_attempt', 'nonce'}:
        need(type(binding[name]) is str and re.fullmatch('[0-9a-f]{64}', binding[name]))
    need(type(binding['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', binding['source_commit']))
    need(type(binding['nonce']) is str and re.fullmatch('[0-9a-f]{32}', binding['nonce']))
    for name in ('run_id', 'run_attempt'):
        need(binding[name] is None or (type(binding[name]) is str and re.fullmatch('[0-9]{1,20}', binding[name])))
    result = {key: child_clone(row[key]) for key in child_diagnostic_keys(row)}
    result['binding_sha256'] = hashlib.sha256(child_encoded(binding)).hexdigest()
    return child_validate_public(result)

def kernel_child(row):
    need(type(row) is dict and set(row) == {'availability', 'exit', 'diagnostics'})
    need(type(row['availability']) is str and row['availability'] in
         {'NOT_RUN', 'UNAVAILABLE', 'UNVERIFIED', 'VERIFIED'})
    child_validate_exit(row['exit'])
    if row['availability'] == 'VERIFIED':
        child_validate_public(row['diagnostics'])
        need(row['exit']['kind'] != 'NOT_RUN')
    else:
        need(row['diagnostics'] is None)
    if row['availability'] == 'NOT_RUN':
        need(row['exit'] == {'kind': 'NOT_RUN', 'code': None})
    else:
        need(row['exit']['kind'] != 'NOT_RUN')


def read(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         all(stat.S_ISDIR(parent.lstat().st_mode) for parent in path.parents))
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         before.st_uid == os.getuid() and before.st_size <= MAX_BYTES)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        need(len(data) <= MAX_BYTES and
             (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
             (path.lstat().st_dev, path.lstat().st_ino) == (opened.st_dev, opened.st_ino))
        return data
    finally:
        os.close(fd)


def decode(data):
    need(len(data) <= MAX_BYTES)
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result)
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique,
                        parse_constant=lambda _: need(False))
    need(type(result) is dict)
    return result


def project(data, commit, pin, outcome):
    need(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit) and
         type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) and
         outcome in {'success', 'failure', 'cancelled', 'skipped', ''})
    value = decode(data)
    need(type(value['schema_version']) is int and
         ((value['schema_version'] == 3 and set(value) == LEGACY_KEYS) or
          (value['schema_version'] == 4 and set(value) == KEYS)) and value['stage'] == 'kernel-native-development-job' and
         type(value['cancelled']) is bool and value['selected_for_release'] is False and
         value['source_commit'] == commit and value['packet_sha256'] == pin)
    need(value['status'] in {'PASS', 'FAIL'} and value['phase'] in PHASES and
         value['cleanup'] in {'PASS', 'FAIL'} and
         value['native_compilation'] in {'PASS', 'NOT ACCEPTED', 'NOT RUN'} and
         all(value[name] in {'PASS', 'FAIL', 'NOT RUN'} for name in CHILDREN))
    need(all(value[name] == 'NOT RUN' for name in
             ('kernel_runtime', 'hardware', 'installation', 'binary_publication')) and
         value['performance'] == 'NOT MEASURED')
    diagnostics(value)
    daemon_baseline(value)
    if value['schema_version'] == 4:
        kernel_child(value['kernel_child'])
    accepted = (value['phase'] == 'complete' and not value['cancelled'] and
                value['first_failed_phase'] == 'NONE' and value['failure_reason'] == 'NONE' and
                all(value[name] == exit_record(0) for name in ('producer_exit', 'acquisition_exit')) and
                value['cleanup'] == 'PASS' and
                all(value[name] == 'PASS' for name in CHILDREN) and
                value['native_compilation'] == 'PASS')
    if value['schema_version'] == 4 and value['status'] == 'PASS':
        child = value['kernel_child']
        need(child['availability'] == 'VERIFIED' and child['exit'] == exit_record(0) and
             child['diagnostics']['current_predicate'] == 'COMPLETE')
    need(value['status'] != 'PASS' or accepted)
    # A stale PASS left before cancellation or a later step failure is not accepted.
    if outcome != 'success' or value['status'] != 'PASS':
        if outcome != 'success':
            record_failure(value, 'outcome', {'failure': 'NATIVE_FAILURE', 'cancelled': 'NATIVE_CANCELLED',
                           'skipped': 'NATIVE_SKIPPED', '': 'NATIVE_UNAVAILABLE'}[outcome])
        value['status'] = 'FAIL'
        value['cancelled'] = value['cancelled'] or outcome == 'cancelled'
        value['native_compilation'] = ('NOT ACCEPTED' if any(
            value[name] != 'NOT RUN' for name in ('baseline', 'candidate')) else 'NOT RUN')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--status', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--native-outcome', required=True)
    args = parser.parse_args(argv)
    try:
        data = read(args.status)
    except FileNotFoundError:
        print('KERNEL_PUBLIC_RECEIPT_MISSING')
        return 1
    except Exception:
        print('KERNEL_PUBLIC_EVIDENCE_REFUSED')
        return 1
    try:
        value = project(data, args.source_commit, args.packet_sha256, args.native_outcome)
        print(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
        return int(args.native_outcome == 'success' and value['status'] != 'PASS')
    except Exception:
        print('KERNEL_PUBLIC_EVIDENCE_REFUSED')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
