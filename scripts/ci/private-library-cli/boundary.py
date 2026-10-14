"""Closed private-library records, original budgets and durable resource intents.

Record validation is not process, daemon or artifact authentication. The selected
parent/runner must obtain and independently check those observations.
"""
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

LANE = 'project-libraries-cli-v1'
INPUT_FD, RECEIPT_FD = 3, 4
RECORD_LIMIT = 1024 * 1024
CHUNK = 65536
COMMAND_LIMIT, WORK_COMMAND_LIMIT = 128, 122
LOG_LIMIT, LOG_TOTAL = 4 * 1024**2, 512 * 1024**2
FETCH_LIMIT, FETCH_TOTAL, FETCH_EACH = 14, 64 * 1024**2, 32 * 1024**2
BUILDS = ('jbigkit-1', 'jbigkit-2', 'libtiff-1', 'libtiff-2')
PROBES = tuple('probe-' + role + '-' + str(n) for role in BUILDS for n in (1, 2))
ROLES = (*BUILDS, *PROBES, 'layer-provision', 'layer-lock', 'layer-dependencies', 'layer-image')
GATES = ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')
PRIVATE_CHECKS = ('source_inputs', 'tool_runtime', 'baseline', 'artifacts', 'signatures', 'providers', 'corresponding_sources')
DERIVED_LOCK = '6c1d2c33b1d80b1ddfa8eb50327c724ba6ffa13dfb5c8dca19133d4676b1b5bd'
INPUT_KEYS = frozenset(('schema_version', 'lane', 'identity', 'clock', 'entry_monotonic', 'cutoff_monotonic',
    'nonce', 'runtime', 'sources', 'inputs', 'baseline', 'output', 'credentials', 'environment', 'budget'))
IDENTITY_KEYS = frozenset(('repository', 'workflow', 'ref', 'code_commit', 'source_commit', 'data_commit',
    'packet_sha256', 'peer_sha256', 'plan_sha256', 'run_id', 'run_attempt'))
CLOCK_KEYS = frozenset(('schema_version', 'purpose', 'source_commit', 'run_id', 'run_attempt', 'nonce',
    'issued_monotonic', 'deadline_monotonic', 'allowance_seconds', 'clock_domain',
    'issuer_source_sha256', 'issuer_workflow_commit'))
TERMINAL_KEYS = frozenset(('schema_version', 'lane', 'identity', 'nonce', 'status', 'clock', 'cutoff_monotonic',
    'first_cause', 'cancelled', 'cleanup_errors', 'budget', 'resources', 'attempts', 'comparisons',
    'baseline', 'derived', 'evidence', 'child', 'private_checks', 'publication_allowed'))
ENV_KEYS = frozenset(('PATH', 'HOME', 'DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_BUILDKIT', 'LC_ALL',
    'TMPDIR', 'GITHUB_SHA', 'PYTHONDONTWRITEBYTECODE'))
ROW_KEYS = frozenset(('kind', 'name', 'image', 'nonce', 'state', 'identifier', 'creation_completed',
    'inspection_sha256', 'retirement_sha256', 'reason'))
STATES = frozenset(('RESERVED', 'SUBMITTED', 'AMBIGUOUS', 'OBSERVED', 'REMOVAL_RESERVED', 'RETIRED', 'ABSENT', 'UNSUBMITTED'))
REASONS = frozenset(('CREATE_UNRETURNED', 'CREATE_FAILED', 'INSPECT_UNCERTAIN', 'REMOVE_UNCERTAIN', 'ABSENCE_UNCERTAIN'))


def need(value, reason):
    if not value:
        raise ValueError(reason)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'closed-record-keys')


def pin(value, width=64):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(width) + '}', value), 'full-pin-required')
    return value


def image(value):
    need(type(value) is str and re.fullmatch('sha256:[0-9a-f]{64}', value), 'full-image-required')
    return value


def integer(value, low=0, high=2**63-1):
    need(type(value) is int and low <= value <= high, 'integer-bound')


def finite(value):
    need(type(value) in (int, float), 'finite-clock-required')
    try: valid = math.isfinite(value) and value > 0
    except OverflowError: valid = False
    need(valid, 'finite-clock-required')


def path(value):
    need(type(value) is str and 0 < len(value) <= 4096 and not any(c in value for c in '\0\r\n') and
         Path(value).is_absolute() and '..' not in Path(value).parts, 'absolute-path-required')
    return Path(value)


def relative(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*', value) and
         all(p not in ('.', '..') for p in value.split('/')), 'relative-path-required')


def node(info):
    return [getattr(info, field) for field in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def identity(value, length=9):
    need(type(value) is list and len(value) == length and all(type(n) is int and n >= 0 for n in value), 'identity-required')
    need(value[1] > 0, 'identity-required')


def encoded(value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(0 < len(raw) <= RECORD_LIMIT, 'record-byte-bound')
    return raw


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= RECORD_LIMIT, 'record-byte-bound')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-key'); result[key] = value
        return result
    def constant(_):
        raise ValueError('nonfinite-json')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def file_ref(value):
    exact(value, ('path', 'sha256', 'bytes', 'identity'))
    path(value['path']); pin(value['sha256']); integer(value['bytes'], 0, 8*1024**2); identity(value['identity'])
    need(stat.S_ISREG(value['identity'][2]) and value['identity'][3] == 1 and
         value['identity'][6] == value['bytes'], 'file-reference-shape')


def validate_domain(value):
    exact(value, ('clock_id', 'boot_id', 'time_namespace_device', 'time_namespace_inode'))
    need(value['clock_id'] == 'CLOCK_MONOTONIC' and type(value['boot_id']) is str and
         re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']), 'clock-domain')
    integer(value['time_namespace_device']); integer(value['time_namespace_inode'], 1)


def validate_clock(value, job, observed_domain):
    exact(value, CLOCK_KEYS); validate_domain(value['clock_domain']); validate_domain(observed_domain)
    need(value['clock_domain'] == observed_domain and type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['purpose'] == 'development-workflow-clock' and type(value['allowance_seconds']) is int and
         value['allowance_seconds'] == 10800, 'original-clock')
    for field in ('source_commit', 'run_id', 'run_attempt'):
        need(value[field] == job[field], 'clock-job-binding')
    need(value['issuer_workflow_commit'] == job['source_commit'], 'clock-job-binding')
    pin(value['nonce'], 32); pin(value['issuer_source_sha256'])
    finite(value['issued_monotonic']); finite(value['deadline_monotonic'])
    need(value['deadline_monotonic'] == value['issued_monotonic'] + 10800, 'original-clock')


def validate_lease(value, job, runtime, nonce):
    exact(value, ('schema_version', 'kind', 'image_id', 'socket_identity', 'packages_lock', 'evidence',
        'run_id', 'run_attempt', 'nonce', 'parent', 'gates', 'cleanup_owner', 'cache'))
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['kind'] == 'borrowed-baseline' and value['cleanup_owner'] == 'parent', 'borrowed-lease')
    image(value['image_id']); identity(value['socket_identity'], 6)
    need(value['socket_identity'] == runtime['socket']['identity'] and value['nonce'] == nonce and
         all(value[k] == job[k] for k in ('run_id', 'run_attempt')), 'lease-job-binding')
    file_ref(value['packages_lock']); file_ref(value['evidence'])
    exact(value['cache'], ('archlinuxarm_keyring',)); file_ref(value['cache']['archlinuxarm_keyring'])
    parent = value['parent']; exact(parent, ('pid', 'session_id', 'start_time_ticks', 'pidfd_held'))
    for k in ('pid', 'session_id', 'start_time_ticks'): integer(parent[k], 1)
    need(parent['pidfd_held'] is True, 'parent-process-observation-required')
    gates = value['gates']; exact(gates, ('packages', 'acquired_objects', 'signature_decisions', 'builds',
        'comparisons', 'native_linux_arm64', 'integration'))
    for k, n in (('packages', 341), ('acquired_objects', 501), ('signature_decisions', 249), ('builds', 8), ('comparisons', 4)):
        need(type(gates[k]) is int and gates[k] == n, 'baseline-gate')
    need(gates['native_linux_arm64'] is True and gates['integration'] == 'PASS', 'baseline-gate')
    return deepcopy(value)


def validate_input(value, *, observed_domain):
    exact(value, INPUT_KEYS)
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and value['lane'] == LANE, 'input-schema')
    job = value['identity']; exact(job, IDENTITY_KEYS)
    need(job['repository'] == 'Gabriel-Kahen/cachy-asahi' and type(job['workflow']) is str and
         re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.yml', job['workflow']) and
         type(job['ref']) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9_.-]+', job['ref']), 'job-identity')
    for k in ('code_commit', 'source_commit', 'data_commit'): pin(job[k], 40)
    need(len({job[k] for k in ('code_commit', 'source_commit', 'data_commit')}) == 3, 'distinct-commits')
    for k in ('packet_sha256', 'peer_sha256', 'plan_sha256'): pin(job[k])
    for k, digits in (('run_id', 20), ('run_attempt', 10)):
        need(type(job[k]) is str and re.fullmatch('[1-9][0-9]{0,' + str(digits-1) + '}', job[k]), 'job-identity')
    pin(value['nonce'], 32); validate_clock(value['clock'], job, observed_domain)
    issued, end = value['clock']['issued_monotonic'], value['clock']['deadline_monotonic']
    finite(value['entry_monotonic']); finite(value['cutoff_monotonic'])
    need(issued <= value['entry_monotonic'] < value['cutoff_monotonic'] and
         value['cutoff_monotonic'] == min(end-120, value['entry_monotonic']+10080), 'original-cutoff')
    runtime = value['runtime']; exact(runtime, ('interpreter', 'docker', 'gpgv', 'socket'))
    for name in ('interpreter', 'docker', 'gpgv'):
        tool = runtime[name]; exact(tool, ('path', 'sha256', 'identity'))
        p = path(tool['path']); pin(tool['sha256']); identity(tool['identity'])
        need(stat.S_ISREG(tool['identity'][2]) and tool['identity'][3] == 1 and tool['identity'][4] == 0 and
             stat.S_IMODE(tool['identity'][2]) == 0o755, 'tool-descriptor')
        if name != 'interpreter': need(str(p) == '/usr/bin/'+name, 'fixed-tool-path')
        else: need(p.parent == Path('/usr/bin') and re.fullmatch(r'python3(?:\.[0-9]+)?', p.name), 'fixed-interpreter-path')
    exact(runtime['socket'], ('path', 'identity')); identity(runtime['socket']['identity'], 6)
    need(runtime['socket']['path'] == '/run/docker.sock' and stat.S_ISSOCK(runtime['socket']['identity'][2]) and
         runtime['socket']['identity'][3] == 0, 'fixed-socket')
    source = value['sources']; exact(source, ('root', 'manifest_sha256', 'files'))
    path(source['root']); pin(source['manifest_sha256'])
    need(type(source['files']) is dict and 8 <= len(source['files']) <= 512, 'source-closure')
    total = 0
    for name, row in source['files'].items():
        relative(name); exact(row, ('sha256', 'bytes', 'mode')); pin(row['sha256']); integer(row['bytes'], 0, 8*1024**2)
        need(type(row['mode']) is int and row['mode'] in (0o444, 0o555), 'source-mode'); total += row['bytes']
    need(hashlib.sha256(encoded(source['files'])).hexdigest() == source['manifest_sha256'], 'source-manifest-binding')
    need(total <= 64*1024**2 and all('scripts/ci/private-library-cli/'+name+'.py' in source['files']
         for name in ('parent_bridge', 'entry', 'boundary', 'operations', 'owned_build', 'baseline_bridge', 'evidence', 'consumer_adapter')), 'source-closure')
    exact(value['inputs'], ('contract_sha256', 'materialization_plan_sha256', 'jbigkit_inputs_sha256', 'libtiff_inputs_sha256'))
    for p in value['inputs'].values(): pin(p)
    need(value['inputs']['materialization_plan_sha256'] == '557214038227f80762cec07a2b98cbb66d4a6ea9a0bc12ee3679a842fa6ddb96', 'materialization-plan')
    credentials = value['credentials']; exact(credentials, ('uid', 'gid'))
    integer(credentials['uid'], 1); integer(credentials['gid'], 1)
    output = value['output']; exact(output, ('path', 'identity')); path(output['path']); identity(output['identity'])
    need(stat.S_ISDIR(output['identity'][2]) and stat.S_IMODE(output['identity'][2]) == 0o700 and
         output['identity'][4:6] == [credentials['uid'], credentials['gid']], 'private-output')
    a, b = path(output['path']), path(source['root'])
    need(not a.is_relative_to(b) and not b.is_relative_to(a), 'disjoint-private-roots')
    env = value['environment']; exact(env, ENV_KEYS)
    need(all(type(s) is str and len(s) <= 4096 and '\0' not in s for s in env.values()) and
         env['PATH'] == '/usr/bin:/bin' and env['DOCKER_HOST'] == 'unix:///run/docker.sock' and
         env['DOCKER_BUILDKIT'] == '0' and env['LC_ALL'] == 'C' and env['GITHUB_SHA'] == job['source_commit'] and
         env['PYTHONDONTWRITEBYTECODE'] == '1', 'fixed-environment')
    for k in ('HOME', 'DOCKER_CONFIG', 'TMPDIR'): path(env[k])
    validate_lease(value['baseline'], job, runtime, value['nonce'])
    validate_budget(value['budget'])
    budget = value['budget']
    need(budget['commands'] in (1, 3) and budget['command_log_bytes']['1'] == 0 and
         budget['fetches'] == budget['fetch_bytes'] == 0 and
         (budget['commands'] == 3 or budget['log_bytes'] == 0), 'issued-budget-prefix')
    encoded(value)
    return deepcopy(value)


def failure_record(error):
    raw = str(error).encode('utf-8', 'backslashreplace')
    return {'exception_type': type(error).__name__[:128], 'message': raw.decode() if len(raw) <= 65536 else None,
            'detail_sha256': hashlib.sha256(raw).hexdigest(), 'detail_bytes': len(raw)}


class Boundary:
    def __init__(self, record, *, observed_domain, clock=time.monotonic):
        self.record = validate_input(record, observed_domain=observed_domain)
        self.clock = clock; self.last = record['entry_monotonic']; self.cutoff = record['cutoff_monotonic']
        self.first_cause = None; self.cancelled = False; self.cleanup_errors = []
        # Slot1 is reserved for the one actual parent-supervised child launch.
        budget = record['budget']
        self.commands = budget['commands']; self.command_logs = dict(budget['command_log_bytes'])
        self.log_total, self.fetches, self.fetch_total = (budget[k] for k in ('log_bytes', 'fetches', 'fetch_bytes'))
        self.inherited_prefix = deepcopy(budget) if self.commands == 3 else None
        self.budget_known = True; self.child_budget_merged = False
        self.cleanup_reservations = {}; self.parent_checks_remaining = 4

    def fail(self, error, *, cleanup=False, cancel=False):
        need(isinstance(error, BaseException) and type(cleanup) is bool and type(cancel) is bool, 'failure-type')
        if cleanup:
            need(len(self.cleanup_errors) < 128, 'cleanup-error-cap'); self.cleanup_errors.append(error)
        elif self.first_cause is None: self.first_cause = error
        self.cancelled = self.cancelled or cancel or isinstance(error, KeyboardInterrupt)

    def check(self, *, cleanup=False):
        need(type(cleanup) is bool, 'cleanup-mode')
        now = self.clock(); finite(now)
        need(self.last <= now < self.cutoff, 'original-cutoff')
        self.last = now
        if not cleanup:
            if self.first_cause is not None: raise self.first_cause
            need(not self.cancelled, 'cancelled')
        return now

    def command(self, *, cleanup=False):
        self.check(cleanup=cleanup)
        need(self.budget_known, 'unknown-child-budget-no-capacity')
        need(self.commands < (COMMAND_LIMIT if cleanup else WORK_COMMAND_LIMIT), 'command-cap')
        if not cleanup:
            need(self.commands+1+sum(self.cleanup_reservations.values())+self.parent_checks_remaining <= COMMAND_LIMIT, 'cleanup-command-reserve')
        self.commands += 1; self.command_logs[str(self.commands)] = 0
        return self.commands

    def log_bytes(self, command_id, n):
        self.check(cleanup=True)
        integer(command_id, 1, self.commands); integer(n, 0, CHUNK)
        key = str(command_id)
        need(self.inherited_prefix is None or command_id > self.inherited_prefix['commands'], 'child-prefix-is-readonly')
        need(self.command_logs[key]+n <= LOG_LIMIT and self.log_total+n <= LOG_TOTAL, 'log-cap')
        self.command_logs[key] += n; self.log_total += n

    def fetch(self, size):
        self.check(); integer(size, 1, FETCH_EACH)
        need(self.fetches < FETCH_LIMIT and self.fetch_total+size <= FETCH_TOTAL, 'fetch-cap')
        self.fetches += 1; self.fetch_total += size

    def adopt_budget(self, value):
        validate_budget(value)
        if self.inherited_prefix is not None: validate_budget_prefix(value, self.inherited_prefix)
        need(value['commands'] >= self.commands and value['fetches'] >= self.fetches and
             value['fetch_bytes'] >= self.fetch_total and all(value['command_log_bytes'].get(k, -1) >= n
                 for k, n in self.command_logs.items()), 'budget-cannot-reset')
        self.commands = value['commands']; self.command_logs = dict(value['command_log_bytes'])
        self.log_total = value['log_bytes']; self.fetches = value['fetches']; self.fetch_total = value['fetch_bytes']

    def merge_child_budget(self, issued, child):
        """Join immutable issued prefix, child suffix and actual parent token1."""
        need(self.budget_known and not self.child_budget_merged and self.inherited_prefix is None,
             'child-budget-already-merged-or-unknown')
        validate_budget(issued); validate_budget(child)
        need(issued['commands'] == self.commands == 3 and issued['fetches'] == issued['fetch_bytes'] == 0,
             'parent-issued-budget-three')
        validate_budget_prefix(child, issued)
        current = self.snapshot()
        need(current['fetches'] == issued['fetches'] and current['fetch_bytes'] == issued['fetch_bytes'] and
             all(current['command_log_bytes'][k] == n for k,n in issued['command_log_bytes'].items() if k != '1') and
             current['command_log_bytes']['1'] >= issued['command_log_bytes']['1'], 'parent-budget-concurrent-drift')
        merged = deepcopy(child)
        merged['command_log_bytes']['1'] = current['command_log_bytes']['1']
        merged['log_bytes'] = sum(merged['command_log_bytes'].values())
        validate_budget(merged)
        self.adopt_budget(merged)
        self.child_budget_merged = True
        return self.snapshot()

    def snapshot(self):
        return {'commands': self.commands, 'command_log_bytes': dict(self.command_logs), 'log_bytes': self.log_total,
                'fetches': self.fetches, 'fetch_bytes': self.fetch_total}

    def terminal(self, *, ledger=None, attempts=None, comparisons=None, derived=None, evidence=None,
                 child=None, private_checks=None, status='INCOMPLETE'):
        if status in ('CHILD_COMPLETE', 'PRIVATE_CHECKED'): self.check(cleanup=True)
        r = self.record
        value = {'schema_version': 1, 'lane': LANE, 'identity': deepcopy(r['identity']), 'nonce': r['nonce'],
            'status': status, 'clock': deepcopy(r['clock']), 'cutoff_monotonic': self.cutoff,
            'first_cause': failure_record(self.first_cause) if self.first_cause is not None else None,
            'cancelled': self.cancelled, 'cleanup_errors': [failure_record(e) for e in self.cleanup_errors],
            'budget': self.snapshot(), 'resources': ledger.snapshot() if ledger else None,
            'attempts': deepcopy(attempts or {}), 'comparisons': deepcopy(comparisons or {}),
            'baseline': deepcopy(r['baseline']), 'derived': deepcopy(derived), 'evidence': deepcopy(evidence or {}),
            'child': deepcopy(child), 'private_checks': dict(private_checks or {k: False for k in PRIVATE_CHECKS}),
            'publication_allowed': False}
        return validate_terminal(value, r, parent_checked=self.inherited_prefix is None)


def validate_budget(value):
    exact(value, ('commands', 'command_log_bytes', 'log_bytes', 'fetches', 'fetch_bytes'))
    integer(value['commands'], 1, COMMAND_LIMIT); integer(value['log_bytes'], 0, LOG_TOTAL)
    integer(value['fetches'], 0, FETCH_LIMIT); integer(value['fetch_bytes'], 0, FETCH_TOTAL)
    rows = value['command_log_bytes']
    need(type(rows) is dict and set(rows) == {str(i) for i in range(1, value['commands']+1)}, 'command-log-tokens')
    for count in rows.values(): integer(count, 0, LOG_LIMIT)
    need(sum(rows.values()) == value['log_bytes'] and
         (value['fetches'] > 0 or value['fetch_bytes'] == 0) and value['fetches'] <= value['fetch_bytes'] <= value['fetches']*FETCH_EACH, 'budget-total')


def validate_budget_prefix(value, issued, *, parent_checked=False):
    validate_budget(value); validate_budget(issued)
    need(value['commands'] >= issued['commands'] and value['fetches'] >= issued['fetches'] and
         value['fetch_bytes'] >= issued['fetch_bytes'], 'child-budget-reset')
    for key, count in issued['command_log_bytes'].items():
        observed = value['command_log_bytes'][key]
        need(observed >= count if parent_checked and key == '1' else observed == count,
             'child-budget-prefix-mutated')


def validate_resources(value, nonce, baseline):
    exact(value, ('schema_version', 'nonce', 'baseline_id', 'sequence', 'journal_sha256', 'uncertain', 'roles'))
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and value['nonce'] == nonce and
         value['baseline_id'] == baseline and type(value['uncertain']) is bool, 'resource-ledger')
    integer(value['sequence'], 0, 256); pin(value['journal_sha256'])
    need(type(value['roles']) is dict and set(value['roles']) <= set(ROLES), 'fixed-resource-role')
    seen = set()
    for role, row in value['roles'].items():
        exact(row, ROW_KEYS); image(row['image'])
        need(row['kind'] == ('image' if role == 'layer-image' else 'container') and
             row['name'] == 'cachy-library-cli-'+nonce+'-'+role and row['nonce'] == nonce and
             row['state'] in STATES and type(row['creation_completed']) is bool, 'resource-row')
        identifier = row['identifier']
        if identifier is not None:
            image(identifier) if row['kind'] == 'image' else pin(identifier)
            need(identifier != baseline and identifier not in seen, 'borrowed-or-reused-resource'); seen.add(identifier)
        for field in ('inspection_sha256', 'retirement_sha256'):
            if row[field] is not None: pin(row[field])
        need(row['reason'] is None or row['reason'] in REASONS, 'resource-reason')
        if row['state'] in ('OBSERVED', 'REMOVAL_RESERVED', 'RETIRED'):
            need(identifier is not None and row['creation_completed'] and row['inspection_sha256'] is not None, 'resource-positive-observation')
        if row['state'] in ('RETIRED', 'ABSENT'):
            need(row['creation_completed'] and row['retirement_sha256'] is not None, 'resource-retirement')
        if row['state'] in ('RESERVED', 'SUBMITTED', 'UNSUBMITTED'):
            need(identifier is None and not row['creation_completed'] and row['inspection_sha256'] is None and
                 row['retirement_sha256'] is None, 'unobserved-resource-shape')
        if row['state'] == 'ABSENT':
            need(identifier is None and row['inspection_sha256'] is None, 'absent-resource-shape')
        if row['state'] == 'AMBIGUOUS':
            need(row['reason'] in REASONS and row['retirement_sha256'] is None and
                 (identifier is None and not row['creation_completed'] and row['inspection_sha256'] is None or
                  identifier is not None and row['creation_completed'] and row['inspection_sha256'] is not None), 'ambiguous-resource-shape')


def validate_journal(raw, *, nonce, baseline_id):
    """Replay bounded complete durable rows; the caller authenticates file custody."""
    need(type(raw) is bytes and len(raw) <= RECORD_LIMIT and (not raw or raw.endswith(b'\n')), 'journal-bound')
    pin(nonce, 32); image(baseline_id)
    rows = {}; events = raw.splitlines()
    need(len(events) <= 256 and all(0 < len(line) < CHUNK for line in events), 'journal-event-bound')
    for number, line in enumerate(events, 1):
        event = decode(line); exact(event, ('sequence', 'event', 'role', 'row'))
        need(type(event['sequence']) is int and event['sequence'] == number and type(event['role']) is str and event['role'] in ROLES, 'journal-sequence')
        role, row, action = event['role'], event['row'], event['event']
        need(type(role) is str and type(action) is str, 'journal-event')
        exact(row, ROW_KEYS)
        before = rows.get(role)
        if action == 'reserve':
            need(before is None and row['state'] == 'RESERVED', 'journal-transition'); changes = set(ROW_KEYS)
        else:
            need(before is not None, 'journal-unreserved-role')
            allowed = {
                'submit': ({'RESERVED'}, 'SUBMITTED', {'state'}),
                'ambiguous': ({'SUBMITTED', 'AMBIGUOUS', 'OBSERVED', 'REMOVAL_RESERVED'}, 'AMBIGUOUS', {'state', 'reason'}),
                'observe': ({'SUBMITTED', 'AMBIGUOUS', 'OBSERVED'}, 'OBSERVED',
                            {'state', 'identifier', 'creation_completed', 'inspection_sha256', 'reason'}),
                'removal-intent': ({'OBSERVED'}, 'REMOVAL_RESERVED', {'state'}),
                'retire': ({'REMOVAL_RESERVED'}, 'RETIRED', {'state', 'retirement_sha256'}),
                'absent': ({'SUBMITTED', 'AMBIGUOUS'}, 'ABSENT', {'state', 'creation_completed', 'retirement_sha256'}),
                'unsubmitted': ({'RESERVED'}, 'UNSUBMITTED', {'state'}),
            }
            need(action in allowed, 'journal-event')
            previous, target, changes = allowed[action]
            need(before['state'] in previous and row['state'] == target and
                 all(encoded(row[key]) == encoded(before[key]) for key in ROW_KEYS-changes), 'journal-transition')
            if action == 'observe':
                need(before['identifier'] is None or before['identifier'] == row['identifier'], 'journal-id-replaced')
        rows[role] = row
        snapshot = {'schema_version': 1, 'nonce': nonce, 'baseline_id': baseline_id, 'sequence': number,
                    'journal_sha256': hashlib.sha256(raw).hexdigest(), 'uncertain': False, 'roles': rows}
        validate_resources(snapshot, nonce, baseline_id)
    return {'schema_version': 1, 'nonce': nonce, 'baseline_id': baseline_id, 'sequence': len(events),
            'journal_sha256': hashlib.sha256(raw).hexdigest(), 'uncertain': False, 'roles': deepcopy(rows)}


def validate_failure(value):
    exact(value, ('exception_type', 'message', 'detail_sha256', 'detail_bytes'))
    need(type(value['exception_type']) is str and 0 < len(value['exception_type']) <= 128, 'failure-record')
    pin(value['detail_sha256']); integer(value['detail_bytes'])
    if value['message'] is not None:
        need(type(value['message']) is str and len(value['message'].encode()) <= 65536 and
             len(value['message'].encode()) == value['detail_bytes'] and
             hashlib.sha256(value['message'].encode()).hexdigest() == value['detail_sha256'], 'failure-record')
    else: need(value['detail_bytes'] > 65536, 'failure-record')


def output_ref(value, input_record):
    file_ref(value)
    parent = Path(input_record['output']['path']); target = Path(value['path'])
    need(target != parent and target.is_relative_to(parent), 'private-output-reference')


def validate_terminal(value, input_record, *, parent_checked=False):
    exact(value, TERMINAL_KEYS)
    need(type(parent_checked) is bool and type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['lane'] == LANE and value['status'] in ('FAIL', 'INCOMPLETE', 'CHILD_COMPLETE', 'PRIVATE_CHECKED') and
         value['publication_allowed'] is False and type(value['cancelled']) is bool, 'terminal-schema')
    for key in ('identity', 'nonce', 'clock', 'cutoff_monotonic', 'baseline'):
        need(encoded(value[key]) == encoded(input_record[key]), 'terminal-input-binding')
    if value['first_cause'] is not None: validate_failure(value['first_cause'])
    need(type(value['cleanup_errors']) is list and len(value['cleanup_errors']) <= 128, 'cleanup-error-cap')
    for error in value['cleanup_errors']: validate_failure(error)
    validate_budget_prefix(value['budget'], input_record['budget'], parent_checked=parent_checked)
    if value['resources'] is not None: validate_resources(value['resources'], value['nonce'], value['baseline']['image_id'])
    exact(value['private_checks'], PRIVATE_CHECKS)
    need(all(type(v) is bool for v in value['private_checks'].values()), 'private-check-shape')
    need(type(value['evidence']) is dict and len(value['evidence']) <= 64, 'evidence-bound')
    for name, ref in value['evidence'].items(): relative(name); output_ref(ref, input_record)
    need(type(value['attempts']) is dict and set(value['attempts']) <= set(BUILDS), 'attempt-shape')
    cids = set()
    for role, row in value['attempts'].items():
        exact(row, ('container_id', 'artifact_sha256', 'evidence')); pin(row['container_id']); pin(row['artifact_sha256']); output_ref(row['evidence'], input_record)
        need(row['container_id'] not in cids, 'four-distinct-attempts'); cids.add(row['container_id'])
    need(type(value['comparisons']) is dict and set(value['comparisons']) <= {'jbigkit', 'libtiff'}, 'comparison-shape')
    for row in value['comparisons'].values():
        exact(row, (*GATES, 'evidence')); output_ref(row['evidence'], input_record)
        need(all(type(row[k]) is bool for k in GATES), 'comparison-shape')
    if value['derived'] is not None:
        row = value['derived']; exact(row, ('image_id', 'packages', 'lock_sha256', 'dependency_check', 'evidence'))
        image(row['image_id']); pin(row['lock_sha256']); output_ref(row['evidence'], input_record)
        need(type(row['packages']) is int and row['packages'] == 346 and row['lock_sha256'] == DERIVED_LOCK and
             type(row['dependency_check']) is bool and row['image_id'] != value['baseline']['image_id'], 'derived-builder')
    if value['child'] is not None:
        child = value['child']; exact(child, ('pid', 'session_id', 'start_time_ticks', 'pidfd_held', 'reaped', 'exit_code', 'natural'))
        for k in ('pid', 'session_id', 'start_time_ticks'): integer(child[k], 1)
        need(type(child['pidfd_held']) is bool and type(child['reaped']) is bool and type(child['natural']) is bool and
             (child['exit_code'] is None or type(child['exit_code']) is int and -64 <= child['exit_code'] <= 255), 'child-observation')
    if value['status'] in ('CHILD_COMPLETE', 'PRIVATE_CHECKED'):
        need(value['first_cause'] is None and not value['cancelled'] and not value['cleanup_errors'] and
             all(value['private_checks'].values()) and set(value['evidence']) == set(PRIVATE_CHECKS) and
             value['budget']['fetches'] == 14 and value['budget']['commands'] >= 118 and
             set(value['attempts']) == set(BUILDS) and set(value['comparisons']) == {'jbigkit', 'libtiff'} and
             all(all(row[k] is True for k in GATES) for row in value['comparisons'].values()) and
             all(value['attempts'][key+'-1']['artifact_sha256'] == value['attempts'][key+'-2']['artifact_sha256']
                 for key in ('jbigkit', 'libtiff')) and
             value['derived'] is not None and value['derived']['dependency_check'] is True and value['child'] is not None,
             'incomplete-positive-terminal')
        need(value['child']['pid'] == value['child']['session_id'], 'child-private-session')
        ledger = value['resources']
        need(ledger is not None and ledger['uncertain'] is False and ledger['sequence'] >= 80 and set(ledger['roles']) == set(ROLES) and
             all(row['state'] == 'RETIRED' for row in ledger['roles'].values()) and
             all(value['attempts'][role]['container_id'] == ledger['roles'][role]['identifier'] for role in BUILDS) and
             value['derived']['image_id'] == ledger['roles']['layer-image']['identifier'] and
             all(row['image'] == (value['derived']['image_id'] if role.startswith('libtiff-') or
                 role.startswith('probe-libtiff-') or role in ('layer-lock', 'layer-dependencies') else
                 value['baseline']['image_id']) for role, row in ledger['roles'].items()), 'incomplete-positive-ledger')
    if value['status'] == 'PRIVATE_CHECKED':
        need(parent_checked and value['budget']['commands'] >= 122 and value['child']['pidfd_held'] is True and value['child']['reaped'] is True and
             value['child']['exit_code'] == 0 and value['child']['natural'] is True, 'parent-terminal-check-required')
    encoded(value)
    return deepcopy(value)


class ResourceLedger:
    """Append+fsync intent before submission; mutation targets are observed IDs."""
    def __init__(self, path_value, boundary):
        boundary.check()
        self.boundary = boundary; self.path = path(str(path_value)); self.rows = {}; self.sequence = 0
        self.sha = hashlib.sha256(); self.uncertain = False; self.closed = False
        output = boundary.record['output']; parent = self.path.parent
        need(parent == Path(output['path']) and self.path.name == 'resource-ledger.jsonl', 'fixed-ledger-path')
        actual = node(parent.lstat()); expected = output['identity']
        stable = lambda row: (row[0], row[1], row[2], row[4], row[5])
        need(stable(actual) == stable(expected), 'owned-output-drift')
        self.parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.fd = None
        try:
            need(stable(node(os.fstat(self.parent_fd))) == stable(actual), 'owned-output-drift')
            self.fd = os.open(self.path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=self.parent_fd)
            self.file_node = node(os.fstat(self.fd))
            os.fsync(self.fd); os.fsync(self.parent_fd)
            boundary.check()
        except BaseException as first:
            self.uncertain = True
            for descriptor in (self.fd, self.parent_fd):
                if descriptor is not None:
                    try: os.close(descriptor)
                    except BaseException as cleanup_error:
                        first.add_note('ledger initialization close uncertain: '+type(cleanup_error).__name__)
            raise

    def _event(self, event, role, row, *, cleanup=False):
        self.boundary.check(cleanup=cleanup)
        need(not self.closed and not self.uncertain and self.sequence < 256, 'ledger-not-durable')
        data = (json.dumps({'sequence': self.sequence+1, 'event': event, 'role': role, 'row': row}, sort_keys=True,
                           separators=(',', ':'), allow_nan=False)+'\n').encode()
        need(len(data) <= CHUNK, 'ledger-event-bound')
        try:
            current = os.fstat(self.fd); named = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            need(node(current) == node(named) and (current.st_dev, current.st_ino) == tuple(self.file_node[:2]) and
                 stat.S_IMODE(current.st_mode) == 0o600 and current.st_nlink == 1, 'ledger-custody')
            offset = 0
            while offset < len(data):
                self.boundary.check(cleanup=cleanup)
                count = os.write(self.fd, data[offset:]); need(count > 0, 'ledger-write-progress'); offset += count
            os.fsync(self.fd)
            self.boundary.check(cleanup=cleanup)
            self.sha.update(data); self.sequence += 1; self.rows[role] = deepcopy(row)
            self.boundary.cleanup_reservations[role] = 3 if row['state'] in ('SUBMITTED', 'AMBIGUOUS', 'OBSERVED', 'REMOVAL_RESERVED') else 0
        except BaseException:
            self.uncertain = True
            raise

    def reserve(self, role, image_id):
        need(role in ROLES and role not in self.rows and len(self.rows) < 16, 'fixed-resource-role'); image(image_id)
        row = {'kind': 'image' if role == 'layer-image' else 'container',
            'name': 'cachy-library-cli-'+self.boundary.record['nonce']+'-'+role, 'image': image_id,
            'nonce': self.boundary.record['nonce'], 'state': 'RESERVED', 'identifier': None,
            'creation_completed': False, 'inspection_sha256': None, 'retirement_sha256': None, 'reason': None}
        self._event('reserve', role, row)
        return deepcopy(row)

    def submit(self, role):
        need(role in self.rows and self.rows[role]['state'] == 'RESERVED', 'unreserved-submission')
        row = {**self.rows[role], 'state': 'SUBMITTED'}; self._event('submit', role, row)

    def ambiguous(self, role, reason):
        need(role in self.rows and reason in REASONS and
             self.rows[role]['state'] in ('SUBMITTED', 'AMBIGUOUS', 'OBSERVED', 'REMOVAL_RESERVED'), 'ambiguity-state')
        self._event('ambiguous', role, {**self.rows[role], 'state': 'AMBIGUOUS', 'reason': reason}, cleanup=True)

    def observe(self, role, *, identifier, name, image, nonce, creation_completed, receipt_sha256):
        need(role in self.rows and self.rows[role]['state'] in ('SUBMITTED', 'AMBIGUOUS', 'OBSERVED'), 'unissued-observation')
        row = self.rows[role]; pin(receipt_sha256)
        need((name, image, nonce) == (row['name'], row['image'], row['nonce']) and creation_completed is True, 'positive-owned-inspect')
        globals()['image'](identifier) if row['kind'] == 'image' else pin(identifier)
        need(identifier != self.boundary.record['baseline']['image_id'] and
             (row['identifier'] is None or row['identifier'] == identifier) and
             all(identifier != other['identifier'] for key, other in self.rows.items() if key != role), 'borrowed-or-reused-resource')
        self._event('observe', role, {**row, 'state': 'OBSERVED', 'identifier': identifier,
            'creation_completed': True, 'inspection_sha256': receipt_sha256, 'reason': None}, cleanup=True)

    def removal_target(self, role):
        need(role in self.rows and self.rows[role]['state'] == 'OBSERVED', 'unconfirmed-removal')
        row = {**self.rows[role], 'state': 'REMOVAL_RESERVED'}; self._event('removal-intent', role, row, cleanup=True)
        return row['identifier']

    def retire(self, role, *, identifier, remove_completed, absent, receipt_sha256):
        need(role in self.rows and self.rows[role]['state'] == 'REMOVAL_RESERVED', 'unreserved-removal')
        row = self.rows[role]; pin(receipt_sha256)
        need(identifier == row['identifier'] and remove_completed is True and absent is True, 'retirement-uncertain')
        self._event('retire', role, {**row, 'state': 'RETIRED', 'retirement_sha256': receipt_sha256}, cleanup=True)

    def absent(self, role, *, receipt_sha256, creation_completed):
        need(role in self.rows and self.rows[role]['state'] in ('SUBMITTED', 'AMBIGUOUS') and
             self.rows[role]['identifier'] is None and creation_completed is True, 'creation-absence-uncertain')
        pin(receipt_sha256)
        self._event('absent', role, {**self.rows[role], 'state': 'ABSENT', 'creation_completed': True,
            'retirement_sha256': receipt_sha256}, cleanup=True)

    def abandon(self, role):
        need(role in self.rows and self.rows[role]['state'] == 'RESERVED', 'submitted-reservation')
        self._event('unsubmitted', role, {**self.rows[role], 'state': 'UNSUBMITTED'}, cleanup=True)

    def snapshot(self):
        return {'schema_version': 1, 'nonce': self.boundary.record['nonce'],
            'baseline_id': self.boundary.record['baseline']['image_id'], 'sequence': self.sequence,
            'journal_sha256': self.sha.hexdigest(), 'uncertain': self.uncertain, 'roles': deepcopy(self.rows)}

    def close(self):
        if self.closed: return
        first = None
        for fd in (self.fd, self.parent_fd):
            try: os.close(fd)
            except BaseException as error:
                self.uncertain = True; self.boundary.fail(error, cleanup=True)
                if first is None: first = error
        self.closed = True
        if first is not None: raise first
