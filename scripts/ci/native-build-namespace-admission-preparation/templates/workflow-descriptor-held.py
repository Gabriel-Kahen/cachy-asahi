"""Strict JSON workflow descriptors: DATA only, never admission authority.

No YAML interpretation, expression evaluator, I/O, subprocess or Source import.
The caller must retain the exact raw bytes and independently qualify resources,
operation, actual jobs, hosted VM identities and every admission prerequisite.
"""
from dataclasses import dataclass
import hashlib
import json
import math
import re

MAX_BYTES = 256 * 1024
MAX_DEPTH = 64
MAX_NODES = 50_000
MAX_JOBS = 32
MAX_STEPS = 512
HOSTED_RUNNERS = frozenset(('ubuntu-24.04-arm', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-latest'))
D91_GROUP = 'updater607-generic16k-${{ inputs.source }}-${{ inputs.case }}'
D91_CASES = ('normal', 'precommit-exit86', 'postcommit-exit87')
ROOT_KEYS = frozenset(('name', 'on', 'permissions', 'concurrency', 'jobs'))
JOB_KEYS = frozenset(('name', 'env', 'if', 'runs-on', 'steps', 'timeout-minutes'))
INPUT_KEYS = frozenset(('description', 'required', 'type', 'default', 'options'))
PERMISSION_KEYS = frozenset(('actions', 'attestations', 'checks', 'contents', 'deployments', 'discussions', 'id-token', 'issues', 'models', 'packages', 'pages', 'pull-requests', 'security-events', 'statuses'))


class DescriptorRefused(ValueError):
    """Fixed refusal reason; never include workflow scripts or input values."""


def _need(condition, reason):
    if not condition:
        raise DescriptorRefused(reason)


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def _nonfinite(_):
    raise DescriptorRefused('nonfinite-json-number')


def _float(value):
    result = float(value)
    _need(math.isfinite(result), 'nonfinite-json-number')
    return result


def _integer(value):
    _need(len(value.lstrip('-')) <= 64, 'json-integer-cap')
    return int(value)


def _shape(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        _need(count <= MAX_NODES and depth <= MAX_DEPTH, 'json-structure-cap')
        if type(node) is dict:
            pending.extend((key, depth + 1) for key in node)
            pending.extend((item, depth + 1) for item in node.values())
        elif type(node) is list:
            pending.extend((item, depth + 1) for item in node)
        elif type(node) is str:
            _need(not any(0xD800 <= ord(c) <= 0xDFFF for c in node), 'json-surrogate')
        else:
            _need(type(node) in (type(None), bool, int, float), 'json-value-type')


def _fields(value, allowed, required, reason):
    _need(type(value) is dict and set(value) <= allowed and required <= set(value), reason)


def _permissions(value):
    _fields(value, PERMISSION_KEYS, set(), 'permissions-fields')
    _need(all(type(v) is str and v in ('read', 'write', 'none') for v in value.values()), 'permissions-value')


def _input_definitions(events):
    _fields(events, {'workflow_dispatch'}, {'workflow_dispatch'}, 'event-scope')
    _fields(events['workflow_dispatch'], {'inputs'}, set(), 'dispatch-fields')
    definitions = events['workflow_dispatch'].get('inputs', {})
    _need(type(definitions) is dict and len(definitions) <= 32, 'input-definitions')
    for name, row in definitions.items():
        _need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name) is not None, 'input-name')
        _fields(row, INPUT_KEYS, {'type'}, 'input-definition-fields')
        _need(type(row['type']) is str and row['type'] in ('string', 'choice'), 'input-definition-type')
        _need('required' not in row or type(row['required']) is bool, 'input-required-type')
        _need('description' not in row or type(row['description']) is str, 'input-description-type')
        _need('default' not in row or type(row['default']) is str, 'input-default-type')
        if row['type'] == 'choice':
            options = row.get('options')
            _need(type(options) is list and 0 < len(options) <= 32
                  and all(type(v) is str for v in options) and len(set(options)) == len(options), 'input-choice-options')
            _need('default' not in row or row['default'] in options, 'input-default-choice')
        else:
            _need('options' not in row, 'string-input-options')
    return definitions


def _dispatch_inputs(value, definitions):
    # No guessed defaults, coercion or ignored extras: this is the full exact
    # caller-supplied dispatch input dictionary, not an API acquisition.
    _need(type(value) is dict and all(type(k) is str for k in value), 'exact-dispatch-input-fields')
    _need(set(value) == set(definitions), 'exact-dispatch-input-fields')
    _need(all(type(v) is str and len(v) <= 200 and '\x00' not in v for v in value.values()), 'dispatch-input-value')
    for name, row in definitions.items():
        if row['type'] == 'choice':
            _need(value[name] in row['options'], 'dispatch-input-choice')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class WorkflowDescriptor:
    workflow_bytes: int
    workflow_sha256: str
    job_runners: tuple[tuple[str, str], ...]
    runner_selector: str
    concurrency_expression: str
    concurrency_group: str
    cancel_in_progress: bool
    resolution: str
    resolution_bindings: tuple[tuple[str, str], ...]
    dispatch_inputs_sha256: str
    format: str = 'json'
    authority: str = 'DATA_ONLY_NO_RESOURCE_NATIVE_OR_COEXISTENCE_AUTHORITY'


def describe_workflow(raw, *, dispatch_inputs=None):
    """Describe the reviewed JSON subset; refuse unsupported or unresolved data.

    ``workflow_sha256`` hashes the original bytes, including JSON formatting.
    ``concurrency_expression`` preserves the decoded JSON string exactly.
    The sole supported expression is D91_GROUP with its reviewed Source/case
    definitions and a full typed dispatch-input dictionary supplied by caller.
    Literal YAML is deliberately unsupported; callers keep their existing path.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'workflow-byte-cap')
    if dispatch_inputs is not None:
        _need(type(dispatch_inputs) is dict, 'exact-dispatch-input-fields')
        dispatch_inputs = dispatch_inputs.copy()  # one caller snapshot; no coercion
    _need(raw.lstrip().startswith(b'{'), 'unsupported-format')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_object_pairs,
                           parse_constant=_nonfinite, parse_float=_float, parse_int=_integer)
    except DescriptorRefused:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise DescriptorRefused('invalid-json') from None
    _shape(value)
    _fields(value, ROOT_KEYS, {'name', 'on', 'permissions', 'concurrency', 'jobs'}, 'workflow-fields')
    _need(type(value['name']) is str and 0 < len(value['name']) <= 255, 'workflow-name')
    _permissions(value['permissions'])
    definitions = _input_definitions(value['on'])
    concurrency = value['concurrency']
    _fields(concurrency, {'group', 'cancel-in-progress'}, {'group', 'cancel-in-progress'}, 'concurrency-fields')
    group, cancel = concurrency['group'], concurrency['cancel-in-progress']
    _need(type(group) is str and 0 < len(group) <= 200 and type(cancel) is bool, 'concurrency-types')
    jobs = value['jobs']
    _need(type(jobs) is dict and 0 < len(jobs) <= MAX_JOBS, 'jobs-cap')
    runners = []
    for name, job in jobs.items():
        _need(re.fullmatch('[A-Za-z_][A-Za-z0-9_-]*', name) is not None, 'job-name')
        _fields(job, JOB_KEYS, {'runs-on', 'steps'}, 'job-fields')
        runner = job['runs-on']
        _need(type(runner) is str and runner in HOSTED_RUNNERS, 'runner-selector')
        _need(type(job['steps']) is list and 0 < len(job['steps']) <= MAX_STEPS
              and all(type(step) is dict for step in job['steps']), 'steps-shape')
        _need('env' not in job or type(job['env']) is dict, 'job-env-type')
        _need('if' not in job or type(job['if']) is str, 'job-if-type')
        _need('name' not in job or type(job['name']) is str, 'job-label-type')
        _need('timeout-minutes' not in job or type(job['timeout-minutes']) is int
              and 0 < job['timeout-minutes'] <= 1440, 'job-timeout-type')
        runners.append((name, runner))
    _need(len({r for _, r in runners}) == 1, 'mixed-runner-selectors')
    fingerprint = '' if dispatch_inputs is None else _dispatch_inputs(dispatch_inputs, definitions)
    if group == D91_GROUP:
        _need(dispatch_inputs is not None, 'dispatch-inputs-required')
        source, case = definitions.get('source'), definitions.get('case')
        _need(source is not None and source['type'] == 'string' and source.get('required') is True,
              'reviewed-source-input-definition')
        _need(case is not None and case['type'] == 'choice' and case.get('required') is True
              and case.get('options') == list(D91_CASES) and case.get('default') == 'normal', 'reviewed-case-input-definition')
        selected_source, selected_case = dispatch_inputs['source'], dispatch_inputs['case']
        _need(re.fullmatch('[0-9a-f]{40}', selected_source) is not None, 'source-input-sha')
        _need(selected_case in D91_CASES, 'reviewed-case-input')
        resolved = 'updater607-generic16k-' + selected_source + '-' + selected_case
        resolution, bindings = 'EXACT_D91_SOURCE_CASE_V1', (('source', selected_source), ('case', selected_case))
    else:
        _need(re.fullmatch('[A-Za-z0-9_-]{1,200}', group) is not None, 'unreviewed-concurrency-expression')
        resolved, resolution, bindings = group, 'LITERAL', ()
    return WorkflowDescriptor(len(raw), hashlib.sha256(raw).hexdigest(), tuple(runners), runners[0][1],
                              group, resolved, cancel, resolution, bindings, fingerprint)
