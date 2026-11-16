# SPDX-License-Identifier: MIT
"""Versioned Source-bound context DATA and explicit completed-component adoption.

Root authentication is the caller's external whole-grant admission boundary.
No provider request, GPG operation, signing or native actor runs here. The exact
v3 predecessor below is immutable; the finite reversible adaptation gives v4
its own schema, issuer and whole program identity. No v3 context is relabelled.
"""
import types
import os

PREDECESSOR_PIN = dict(bytes=21460, sha256='efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b')
_PREDECESSOR = r'''# SPDX-License-Identifier: MIT
"""Pinned private delegation and provisional poststart DATA; no network or actors.

The expected delegation hash is supplied by the existing Root trust/admission
boundary. Hash equality alone does not authenticate Root or GitHub. In particular,
the jobs-response abstraction must be filled by the reviewed metadata caller.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

OPERATION = 'first-login-enrollment-ui-current-v2'
DELEGATION = 'ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'
CONTEXT = 'DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3'
ISSUER = 'DELEGATED_CONTEXT_PROGRAM_V3'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64*1024**2, 128*1024**2, 256
LIMITS = ('max_command_seconds', 'total_seconds', 'builder_cpus',
          'builder_memory_bytes', 'builder_pids', 'command_rows')
ENV = ('GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_REF',
       'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_WORKFLOW_REF',
       'GITHUB_WORKFLOW_SHA', 'GITHUB_WORKSPACE', 'RUNNER_ENVIRONMENT',
       'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_NAME')
FINAL = dict(Root_final_acceptance=None, independent_component_acceptance=False,
             hardware_acceptance=False, release_acceptance=False)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw, cap=1024**2):
    need(type(raw) is bytes and 0 < len(raw) <= cap, 'bounded whole JSON bytes')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=pairs,
                        parse_constant=lambda _: need(False, 'nonfinite JSON'))
    need(type(result) is dict, 'JSON object required')
    # Also refuses numeric overflow (for example 1e999) and non-JSON objects.
    encoded(result)
    return result


def integer(value, low=1, high=2**63-1):
    need(type(value) is int and low <= value <= high, 'bounded integer required')
    return value


def whole(value):
    need(type(value) is dict and set(value) == {'bytes', 'sha256'}, 'whole bytes/hash pin')
    integer(value['bytes'], high=MAX_TOTAL)
    need(type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'SHA256 pin')
    return value


def relative(value):
    need(type(value) is str and 0 < len(value) <= 240 and '\\' not in value, 'Source-relative member')
    path = PurePosixPath(value)
    need(not path.is_absolute() and str(path) == value and len(path.parts) <= 16
         and all(re.fullmatch('[A-Za-z0-9._+-]+', p) and p not in ('.', '..') for p in path.parts),
         'closed safe Source member')
    return value


def descriptor(row):
    need(type(row) is dict and set(row) == {'member', 'bytes', 'sha256'}, 'Source-relative whole descriptor')
    relative(row['member'])
    return whole({k: row[k] for k in ('bytes', 'sha256')})


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, cap=MAX_FILE):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(), 'canonical ordinary DATA path')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd = None
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap
             and not before.st_mode & 0o022, 'bounded single-link ordinary DATA')
        parts, size = [], 0
        while block := os.read(fd, min(1024**2, cap+1-size)):
            parts.append(block)
            size += len(block)
            need(size <= cap, 'whole DATA cap')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'DATA changed while reading')
        return b''.join(parts), stat.S_IMODE(before.st_mode)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def validate_delegation(raw, expected_sha256, now=None):
    """Validate a Root-selected contract; does not verify its external signature."""
    now = int(time.time()) if now is None else integer(now, 0)
    need(pin(raw)['sha256'] == expected_sha256, 'external Root-selected delegation hash')
    d = decode(raw)
    need(raw == encoded(d), 'canonical complete delegation bytes')
    need(d['schema'] == 3 and d['kind'] == DELEGATION and d['issuer'] == 'Root'
         and d['approved'] is True and d['scope'] == 'CURRENT_PRIVATE_STAGE_ONLY', 'explicit private Root delegation')
    b = d['binding']
    need(set(b) == {'source', 'ref', 'run', 'job', 'attempt', 'source_lock'}
         and re.fullmatch('[0-9a-f]{40}', b['source'] or '')
         and re.fullmatch(r'refs/heads/[A-Za-z0-9._+/-]+', b['ref'] or '')
         and b['run'] is None and b['job'] is None and type(b['attempt']) is int and b['attempt'] == 1,
         'Source/ref fixed; future run/job unobserved; first attempt only')
    whole(b['source_lock'])
    need(d['stage'] in ('backend', 'ui', 'lifecycle') and re.fullmatch('[0-9a-f]{64}', d['nonce'] or ''),
         'fixed stage and nonce')
    integer(d['issued_epoch'], 0)
    integer(d['expires_epoch'], 0)
    need(d['issued_epoch'] <= now <= d['expires_epoch'], 'fresh delegation')
    need(d['image_ids'] == dict(backend=None, ui=None, lifecycle=None), 'future images unobserved')
    for group in ('programs', 'materials'):
        need(type(d[group]) is dict and 0 < len(d[group]) <= MAX_FILES, 'finite reviewed Source descriptors')
        for role, row in d[group].items():
            need(re.fullmatch('[a-z][a-z0-9_]{0,63}', role), 'bounded descriptor role')
            descriptor(row)
    need({'context', 'owner', 'image', 'image_executor'} <= set(d['programs']), 'reviewed context/owner/image/executor programs')
    descriptor(d['policy'])
    c = d['capability']
    need(c['operation'] == OPERATION and c['stage'] == d['stage']
         and c['allow_provisional_context'] is True and c['allow_provisional_image_checks'] is True
         and type(c['allow_pair_adoption']) is bool, 'explicit bounded private stage capability')
    for key in LIMITS:
        integer(c[key])
    need(c['max_command_seconds'] <= c['total_seconds'], 'command within finite total budget')
    limits = d['context_limits']
    need(set(limits) == {'metadata_query_seconds', 'metadata_max_bytes', 'max_context_age_seconds', 'max_delegation_seconds'},
         'explicit context-only limits')
    integer(limits['metadata_query_seconds'], high=30)
    integer(limits['metadata_max_bytes'], high=1024**2)
    integer(limits['max_context_age_seconds'])
    integer(limits['max_delegation_seconds'])
    need(0 < d['expires_epoch']-d['issued_epoch'] <= limits['max_delegation_seconds']
         and limits['max_context_age_seconds'] <= limits['max_delegation_seconds'], 'finite delegation/context lifetime')
    h = d['hosted']
    need(set(h) == {'repository', 'workflow_ref', 'workflow_sha', 'job_key', 'job_name', 'runner_environment', 'runner_os', 'runner_arch'},
         'explicit reviewed hosted selectors')
    need(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', h['repository'] or '')
         and h['workflow_ref'].startswith(h['repository']+'/.github/workflows/')
         and re.fullmatch('[0-9a-f]{40}', h['workflow_sha'] or '')
         and re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,99}', h['job_key'] or '')
         and type(h['job_name']) is str and 0 < len(h['job_name']) <= 200
         and h['runner_environment'] == 'github-hosted' and h['runner_os'] == 'Linux'
         and h['runner_arch'] == 'ARM64', 'fixed native hosted selectors')
    if c['allow_pair_adoption']:
        p = d['pair_policy']
        whole(p['producer_delegation_pin'])
        need(re.fullmatch('[0-9A-F]{40}', p['test_fingerprint'] or '')
             and p['test_public_key_role'] in d['materials'], 'Root-selected TEST key policy')
    need(all(d.get(k) == v and type(d.get(k)) is type(v) for k, v in FINAL.items()), 'delegation grants no final acceptance')
    return d


def source(d, root):
    """Rejoin the complete closed v3 map without importing any Source program."""
    root = Path(root)
    need(root.is_absolute() and root == root.resolve() and root.is_dir(), 'actual canonical Source root')
    raw, mode = read(root/'source-map.json', 1024**2)
    need(pin(raw) == d['binding']['source_lock'] and mode == 0o644, 'Root-pinned Source map')
    alias, alias_mode = read(root/'source.lock.json', 1024**2)
    need(alias == raw and alias_mode == 0o644, 'ordinary byte-identical Source lock alias')
    value = decode(raw)
    need(value['schema'] == 1 and value['kind'] == 'CURRENT_ONBOARDING_CLOSED_SOURCE_V3'
         and value['operation'] == OPERATION and type(value['actual']) is dict
         and value['actual'] and all(v is None for v in value['actual'].values()), 'unissued v3 Source map')
    rows = value['files']
    need(type(rows) is dict and len(rows)+2 <= MAX_FILES, 'finite Source file map')
    found = set()
    for parent, dirs, files in os.walk(root, followlinks=False):
        if Path(parent) == root:
            dirs[:] = [name for name in dirs if name != '.git']
            files = [name for name in files if name != '.git']
        for name in dirs:
            need(stat.S_ISDIR((Path(parent)/name).lstat().st_mode), 'ordinary Source directories')
        found.update(str((Path(parent)/name).relative_to(root)) for name in files)
    need(found == set(rows) | {'source-map.json', 'source.lock.json'}, 'closed Source namespace')
    total = 2*len(raw)
    for name, row in rows.items():
        relative(name)
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'}, 'whole Source row')
        whole({k: row[k] for k in ('bytes', 'sha256')})
        need(row['bytes'] <= MAX_FILE and total+row['bytes'] <= MAX_TOTAL, 'finite Source bytes before read')
        body, mode = read(root/name)
        need(row == dict(pin(body), mode=mode) and mode in (0o644, 0o755), 'exact Source body/mode: '+name)
        total += len(body)
    need(total <= MAX_TOTAL, 'whole Source size cap')
    for row in [d['policy'], *d['programs'].values(), *d['materials'].values()]:
        need(row['member'] in rows and {k: rows[row['member']][k] for k in ('bytes', 'sha256')} == descriptor(row),
             'reviewed descriptor is a closed Source member')
    own, _ = read(Path(__file__).resolve())
    need(pin(own) == descriptor(d['programs']['context']), 'executing context program is reviewed whole body')
    policy = decode(read(root/d['policy']['member'], 1024**2)[0])
    need(policy['context'] == d['context_limits'], 'exact reviewed metadata policy')
    ceiling = policy['stage_capabilities'][d['stage']]
    for key in LIMITS:
        need(integer(d['capability'][key]) <= integer(ceiling[key]), 'requested capability exceeds reviewed policy: '+key)
    return root, rows


def resolve_material(delegation, source_root, role):
    root, _ = source(delegation, source_root)
    need(role in delegation['materials'], 'closed reviewed material role')
    return root/delegation['materials'][role]['member']


def material_reference(delegation, source_root, role):
    path = resolve_material(delegation, source_root, role)
    return dict(path=str(path), **descriptor(delegation['materials'][role]))


def _binding(d, root, hosted, response, observed):
    need(type(hosted) is dict and set(hosted) == set(ENV), 'only allowlisted hosted fields')
    h, b, limits = d['hosted'], d['binding'], d['context_limits']
    expected = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY=h['repository'], GITHUB_SHA=b['source'],
                    GITHUB_REF=b['ref'], GITHUB_RUN_ATTEMPT='1', GITHUB_JOB=h['job_key'],
                    GITHUB_WORKFLOW_REF=h['workflow_ref'], GITHUB_WORKFLOW_SHA=h['workflow_sha'],
                    GITHUB_WORKSPACE=str(root), RUNNER_ENVIRONMENT=h['runner_environment'],
                    RUNNER_OS=h['runner_os'], RUNNER_ARCH=h['runner_arch'])
    need(all(hosted.get(k) == v for k, v in expected.items()), 'actual hosted Source/ref/workflow/stage/runner selectors')
    run = hosted['GITHUB_RUN_ID']
    need(type(run) is str and re.fullmatch('[1-9][0-9]{0,19}', run), 'actual numeric hosted run ID')
    runner = hosted['RUNNER_NAME']
    need(type(runner) is str and 0 < len(runner) <= 200 and '\n' not in runner, 'actual hosted runner name')
    url = 'https://api.github.com/repos/'+h['repository']+'/actions/runs/'+run+'/jobs?filter=latest&per_page=100'
    need(type(response) is dict and set(response) == {'url', 'status', 'body', 'received_epoch', 'elapsed_ms'}
         and response['url'] == url and type(response['status']) is int and response['status'] == 200,
         'fixed public GitHub jobs endpoint and successful bounded response')
    received = integer(response['received_epoch'], 0)
    need(0 <= observed-received <= limits['metadata_query_seconds']
         and integer(response['elapsed_ms'], 0) <= 1000*limits['metadata_query_seconds'], 'fresh bounded metadata query')
    body = response['body']
    need(type(body) is bytes, 'whole jobs response bytes')
    value = decode(body, limits['metadata_max_bytes'])
    jobs = value['jobs']
    need(type(jobs) is list and integer(value['total_count'], 1, 100) == len(jobs), 'complete single-page jobs response')
    selected = [j for j in jobs if type(j) is dict and j.get('name') == h['job_name'] and j.get('runner_name') == runner]
    need(len(selected) == 1, 'one actual named job on this runner')
    job = selected[0]
    job_id = str(integer(job['id']))
    need(type(job['run_id']) is int and str(job['run_id']) == run and type(job['run_attempt']) is int
         and job['run_attempt'] == 1 and job['head_sha'] == b['source'] and job['status'] == 'in_progress'
         and job['conclusion'] is None and job['run_url'] == url.split('/jobs?')[0]
         and job['url'] == 'https://api.github.com/repos/'+h['repository']+'/actions/jobs/'+job_id
         and job['html_url'] == 'https://github.com/'+h['repository']+'/actions/runs/'+run+'/job/'+job_id,
         'genuine response joins Source/run/attempt/job/provider URLs')
    return dict(source=b['source'], ref=b['ref'], run=run, job=job_id, attempt=1, source_lock=b['source_lock'])


def capture_context(raw, sha256, source_root, *, environ=None, jobs_response=None, now=None):
    now = int(time.time()) if now is None else integer(now, 0)
    d = validate_delegation(raw, sha256, now)
    root, _ = source(d, source_root)
    environ = os.environ if environ is None else environ
    hosted = {key: environ.get(key) for key in ENV}  # Never inspect tokens or unrelated environment.
    binding = _binding(d, root, hosted, jobs_response, now)
    response = dict(jobs_response, body=jobs_response['body'].decode('utf-8'))
    return dict(schema=3, kind=CONTEXT, issuer=ISSUER, operation=OPERATION, stage=d['stage'],
                nonce=d['nonce'], delegation_pin=pin(raw), program_pin=descriptor(d['programs']['context']),
                policy_pin=descriptor(d['policy']), source_root=str(root), binding=binding, hosted=hosted,
                jobs_response=response, jobs_response_pin=pin(jobs_response['body']), observed_epoch=now, **FINAL)


def validate_context(delegation, context, *, now=None):
    """Replay observation joins, including the original bounded response body."""
    now = int(time.time()) if now is None else integer(now, 0)
    raw = encoded(delegation)
    d = validate_delegation(raw, context['delegation_pin']['sha256'], now)
    need(context['delegation_pin'] == pin(raw), 'complete delegation pin')
    observed = integer(context['observed_epoch'], 0)
    need(d['issued_epoch'] <= observed <= now and now-observed <= d['context_limits']['max_context_age_seconds'],
         'fresh poststart observation')
    response = dict(context['jobs_response'])
    need(type(response['body']) is str, 'retained UTF-8 provider response')
    response['body'] = response['body'].encode('utf-8')
    replay = capture_context(raw, pin(raw)['sha256'], context['source_root'], environ=context['hosted'],
                             jobs_response=response, now=observed)
    need(context == replay, 'exact replayed delegated context; no forged acceptance or binding fields')
    return context


def adopt_pair(delegation, context, *, producer_delegation_raw, producer_context, pair_raw, test_raw, now=None):
    """Adopt reviewed-program observations for private use, never Root issuance.

    Detached signature verification remains the actual owner's strict GPG/trust
    operation. This joins that program's retained DATA receipt, not a new GPG run.
    """
    validate_context(delegation, context, now=now)
    need(delegation['capability']['allow_pair_adoption'] is True, 'explicit pair adoption capability')
    policy = delegation['pair_policy']
    need(pin(producer_delegation_raw) == policy['producer_delegation_pin'], 'Root-selected producer delegation')
    producer = validate_delegation(producer_delegation_raw, policy['producer_delegation_pin']['sha256'], now)
    validate_context(producer, producer_context, now=now)
    need(producer['stage'] == 'backend', 'backend producer stage')
    for key in ('source', 'ref', 'run', 'attempt', 'source_lock'):
        need(context['binding'][key] == producer_context['binding'][key], 'same actual Source/run pair producer')
    pair, proof = decode(pair_raw), decode(test_raw)
    owner_pin = descriptor(producer['programs']['owner'])
    for value, kind in ((pair, 'DELEGATED_CURRENT_ONBOARDING_PAIR_V3'), (proof, 'DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V3')):
        need(value['schema'] == 3 and value['kind'] == kind and value['issuer'] == 'DELEGATED_CURRENT_OWNER_V3'
             and value['binding'] == producer_context['binding'] and value['nonce'] == producer['nonce']
             and value['program_pin'] == owner_pin and value['policy_pin'] == descriptor(producer['policy'])
             and all(value.get(k) == v and type(value.get(k)) is type(v) for k, v in FINAL.items()),
             'producer actual binding/reviewed owner/policy; final acceptance unset')
    archives = pair['archives']
    need(type(archives) is list and len(archives) == 2 and pair['matching_pair'] is True, 'whole matching pair')
    for row in archives:
        whole(row)
    need(archives[0] == archives[1] and proof['pair_pin'] == pin(pair_raw), 'byte-identical pair and whole proof join')
    key = descriptor(delegation['materials'][policy['test_public_key_role']])
    need(proof['public_test_key_pin'] == key and proof['fingerprint'] == policy['test_fingerprint']
         and proof['trust_scope'] == 'TEST_ONLY', 'Root-selected public TEST key, no release trust')
    rows = proof['verifications']
    need(type(rows) is list and len(rows) == 2, 'both actual TEST verification receipts')
    for index, row in enumerate(rows):
        need(row['archive'] == archives[index], 'verification whole archive join')
        whole(row['signature'])
        natural = row['supervision']
        need(natural['reaped'] is True and natural['ownership'] == 'REAPED' and natural['group_census'] == 'EMPTY_TWICE'
             and natural['output_complete'] is True and natural['timeout'] is False and natural['signals'] == []
             and natural['error'] is None and type(natural['exit']) is int and natural['exit'] == 0,
             'natural actual owner TEST verification retirement')
        status = row['status']
        need(type(status) is str and 0 < len(status) <= 65536, 'bounded retained GPG status')
        lines = [line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
        forbidden = {'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'KEYEXPIRED',
                     'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'NODATA', 'TRUST_NEVER', 'TRUST_UNDEFINED'}
        valid = [line for line in lines if line and line[0] == 'VALIDSIG']
        need(not any(line and line[0] in forbidden for line in lines) and len(valid) == 1 and len(valid[0]) == 11
             and valid[0][1] == valid[0][-1] == policy['test_fingerprint']
             and any(line and line[0] == 'TRUST_ULTIMATE' for line in lines), 'strict retained TEST primary status')
    return dict(schema=3, kind='DELEGATED_CURRENT_ONBOARDING_PAIR_ADOPTION_V3', issuer=ISSUER,
                binding=context['binding'], producer_binding=producer_context['binding'],
                nonce=delegation['nonce'], delegation_pin=context['delegation_pin'],
                producer_delegation_pin=policy['producer_delegation_pin'], pair_pin=pin(pair_raw),
                test_proof_pin=pin(test_raw), archives=archives, trust_scope='TEST_ONLY', **FINAL)
'''.encode('utf-8')
_EDITS = (
    ("ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3", "ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4"),
    ("DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3", "DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4"),
    ("DELEGATED_CONTEXT_PROGRAM_V3", "DELEGATED_CONTEXT_PROGRAM_V4"),
    ("DELEGATED_CURRENT_ONBOARDING_PAIR_V3", "DELEGATED_CURRENT_ONBOARDING_PAIR_V4"),
    ("DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V3", "DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V4"),
    ("DELEGATED_CURRENT_OWNER_V3", "DELEGATED_CURRENT_OWNER_V4"),
    ("DELEGATED_CURRENT_ONBOARDING_PAIR_ADOPTION_V3", "DELEGATED_CURRENT_ONBOARDING_PAIR_ADOPTION_V4"),
    ("['schema'] == 3", "['schema'] == 4"),
    ("schema=3", "schema=4"),
)


def _implementation():
    import hashlib
    if dict(bytes=len(_PREDECESSOR), sha256=hashlib.sha256(_PREDECESSOR).hexdigest()) != PREDECESSOR_PIN:
        raise ValueError('exact immutable v3 predecessor closure')
    original = _PREDECESSOR.decode('utf-8')
    adapted = original
    for before, after in _EDITS:
        if before not in adapted or after in adapted:
            raise ValueError('unique finite v4 adaptation seam')
        adapted = adapted.replace(before, after)
    inverse = adapted
    for before, after in reversed(_EDITS):
        inverse = inverse.replace(after, before)
    if inverse != original:
        raise ValueError('complete v4-to-v3 byte inverse')
    scope = dict(__file__=__file__, __name__=__name__+'.v4_core')
    exec(compile(adapted, __file__, 'exec'), scope)
    return types.SimpleNamespace(**scope)


_CORE = _implementation()
for _name in ('OPERATION', 'DELEGATION', 'CONTEXT', 'ISSUER', 'FINAL', 'ENV', 'LIMITS',
              'MAX_FILE', 'MAX_TOTAL', 'MAX_FILES', 'need', 'pin', 'encoded', 'decode',
              'integer', 'whole', 'relative', 'descriptor', 'read', 'identity'):
    globals()[_name] = getattr(_CORE, _name)
SELECTION = 'ROOT_EXPLICIT_COMPLETED_COMPONENT_SELECTION_V4'
COMPONENT_DECISION = 'ROOT_SELECTED_CURRENT_ONBOARDING_COMPONENT_V4'
TEST_DECISION = 'ROOT_SELECTED_CURRENT_ONBOARDING_TEST_V4'
# Exact current identities from e8034dab owner_delegated_v3.compare() and
# held successor_v2/profile.json (SHA256 8ad36416...bc171). Setup8 stays separate.
COMPONENT_PRODUCER_STAGES = {
    ('cachy-asahi-repository-enrollment', '0.4.0-1', 'any'): 'backend',
    ('cachy-asahi-first-login', '0.1.0-3', 'any'): 'backend',
    ('cachy-asahi-first-login-ui', '0.2.0-2', 'any'): 'ui',
}


def _binding(value):
    need(type(value) is dict and set(value) == {'source', 'ref', 'run', 'job', 'attempt', 'source_lock'},
         'complete selected producer tuple')
    need(type(value['source']) is str and re.fullmatch('[0-9a-f]{40}', value['source'])
         and type(value['ref']) is str and re.fullmatch(r'refs/heads/[A-Za-z0-9._+/-]+', value['ref'])
         and type(value['attempt']) is int and value['attempt'] == 1, 'selected fixed Source/ref/attempt')
    for key in ('run', 'job'):
        need(type(value[key]) is str and re.fullmatch('[1-9][0-9]{0,19}', value[key]), 'known observed producer ID')
    whole(value['source_lock'])


def _component(value):
    need(type(value) is dict and set(value) == {'name', 'version', 'architecture'}, 'exact selected component identity')
    for key in ('name', 'version'):
        need(type(value[key]) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}', value[key]),
             'bounded component identity')
    need(value['architecture'] in ('any', 'aarch64'), 'native ARM or architecture-neutral package')


def _producer_stage(component):
    _component(component)
    key = tuple(component[k] for k in ('name', 'version', 'architecture'))
    need(key in COMPONENT_PRODUCER_STAGES, 'exact current component/version/architecture with reviewed producer stage')
    return COMPONENT_PRODUCER_STAGES[key]


def _single_selection(d):
    c = d['capability']
    need(type(c.get('allow_selected_pair_adoption', False)) is bool, 'explicit selected-pair capability type')
    if c.get('allow_selected_pair_adoption', False) is False:
        need('pair_selection' not in d, 'no ungranted cross-run selection')
        return None
    need(d['stage'] in ('ui', 'lifecycle') and c['allow_pair_adoption'] is False,
         'separate selected-component consumer capability')
    s = d['pair_selection']
    pins = ('producer_delegation_pin', 'producer_context_pin', 'completion_pin', 'pair_pin',
            'root_component_decision_pin', 'root_test_decision_pin', 'public_test_key_pin')
    need(type(s) is dict and set(s) == {'schema', 'kind', 'producer_binding', 'component',
         'archives', 'signatures', 'test_fingerprint', 'max_producer_age_seconds', *pins}, 'complete explicit Root selection')
    need(type(s['schema']) is int and s['schema'] == 1 and s['kind'] == SELECTION, 'separate selection schema')
    _binding(s['producer_binding'])
    for key in ('source', 'ref', 'source_lock'):
        need(s['producer_binding'][key] == d['binding'][key], 'same closed Source/ref/map selection')
    expected_stage = _producer_stage(s['component'])
    need(expected_stage != 'ui' or d['stage'] == 'lifecycle', 'completed UI component is lifecycle input only')
    for key in pins:
        whole(s[key])
    for key in ('archives', 'signatures'):
        need(type(s[key]) is list and len(s[key]) == 2, 'exact two selected '+key)
        for row in s[key]:
            whole(row)
    need(s['archives'][0] == s['archives'][1], 'selected byte-identical native pair')
    need(type(s['test_fingerprint']) is str and re.fullmatch('[0-9A-F]{40}', s['test_fingerprint']), 'selected primary TEST key')
    integer(s['max_producer_age_seconds'], high=30*86400)
    return s



def _validate_selections(d):
    if 'pair_selections' not in d:
        value = _single_selection(d)
        return {} if value is None else {'component': value}
    need('pair_selection' not in d and d['capability'].get('allow_selected_pair_adoption') is True,
         'one explicitly granted selection representation')
    values = d['pair_selections']
    need(type(values) is dict and 0 < len(values) <= 8, 'finite explicit component selection roles')
    for role, value in values.items():
        need(type(role) is str and re.fullmatch('[a-z][a-z0-9_]{0,63}', role), 'bounded selected component role')
        one = dict(d, pair_selection=value)
        del one['pair_selections']
        _single_selection(one)
    return values


def _selection(d, selection_role=None):
    values = _validate_selections(d)
    if selection_role is None:
        need(len(values) == 1, 'one selected component or explicit selection_role required')
        return next(iter(values.values()))
    need(type(selection_role) is str and selection_role in values, 'explicit Root-selected component role')
    return values[selection_role]

def validate_delegation(raw, expected_sha256, now=None):
    d = _CORE.validate_delegation(raw, expected_sha256, now)
    _validate_selections(d)
    return d


def source(d, root):
    _validate_selections(d)
    return _CORE.source(d, root)


def resolve_material(delegation, source_root, role):
    root, _ = source(delegation, source_root)
    need(role in delegation['materials'], 'closed reviewed material role')
    return root/delegation['materials'][role]['member']


def material_reference(delegation, source_root, role):
    return dict(path=str(resolve_material(delegation, source_root, role)),
                **descriptor(delegation['materials'][role]))


def capture_context(raw, sha256, source_root, *, environ=None, jobs_response=None, now=None):
    validate_delegation(raw, sha256, now)
    return _CORE.capture_context(raw, sha256, source_root, environ=environ, jobs_response=jobs_response, now=now)


def validate_context(delegation, context, *, now=None):
    validate_delegation(encoded(delegation), context['delegation_pin']['sha256'], now)
    return _CORE.validate_context(delegation, context, now=now)


def adopt_pair(delegation, context, *, producer_delegation_raw, producer_context, pair_raw, test_raw, now=None):
    """Strict same-run v4 counterpart; selected-run authority cannot enter here."""
    validate_context(delegation, context, now=now)
    need(not delegation['capability'].get('allow_selected_pair_adoption', False), 'same-run capability only')
    return _CORE.adopt_pair(delegation, context, producer_delegation_raw=producer_delegation_raw,
                            producer_context=producer_context, pair_raw=pair_raw, test_raw=test_raw, now=now)


# Explicit imports keep helpers visible without changing the pinned predecessor.
import re
from pathlib import Path
import time


def _historical_producer(d, context, selection, root, rows):
    """Replay original observation at its own epoch, without old-path reads.

    The current exact Source closure is already rejoined. Historical workspace
    paths remain historical strings. Neither an expired producer delegation nor
    its context becomes a current execution grant.
    """
    observed = integer(context['observed_epoch'], 0)
    need(context['binding'] == selection['producer_binding'], 'exact selected producer observation')
    version = d['schema']
    need(type(version) is int and version in (3, 4), 'explicit producer context version')
    if version == 3:
        scope = dict(__file__=str(root/d['programs']['context']['member']), __name__=__name__+'.v3_producer')
        exec(compile(_PREDECESSOR, scope['__file__'], 'exec'), scope)
        core = types.SimpleNamespace(**scope)
    else:
        core = _CORE
    core.validate_delegation(encoded(d), selection['producer_delegation_pin']['sha256'], observed)
    need(d['stage'] == _producer_stage(selection['component'])
         and context['delegation_pin'] == selection['producer_delegation_pin'],
         'selected component maps to exact observed producer stage and whole delegation')
    for desc in [d['policy'], *d['programs'].values(), *d['materials'].values()]:
        descriptor(desc)
        need(desc['member'] in rows
             and {k: rows[desc['member']][k] for k in ('bytes', 'sha256')} == descriptor(desc),
             'historical producer descriptor is in the current exact closed map')
        body, _ = read(root/desc['member'])
        need(pin(body) == descriptor(desc), 'historical producer descriptor joins same closed Source')
    program = read(root/d['programs']['context']['member'])[0]
    expected_program = PREDECESSOR_PIN if version == 3 else pin(read(Path(__file__).resolve())[0])
    need(pin(program) == expected_program, 'exact pinned producer context version')
    policy = decode(read(root/d['policy']['member'], 1024**2)[0])
    need(policy['context'] == d['context_limits'], 'historical exact metadata policy')
    for key in LIMITS:
        need(integer(d['capability'][key]) <= integer(policy['stage_capabilities'][d['stage']][key]),
             'historical producer capability within reviewed Source policy')
    response = dict(context['jobs_response'])
    need(type(response['body']) is str, 'retained historical provider body')
    response['body'] = response['body'].encode('utf-8')
    oldroot = Path(context['source_root'])
    need(oldroot.is_absolute() and str(oldroot) == context['source_root']
         and '..' not in oldroot.parts, 'ordinary historical workspace spelling')
    binding = core._binding(d, oldroot, context['hosted'], response, observed)
    replay = dict(schema=version, kind=core.CONTEXT, issuer=core.ISSUER, operation=OPERATION, stage=d['stage'],
                  nonce=d['nonce'], delegation_pin=pin(encoded(d)), program_pin=descriptor(d['programs']['context']),
                  policy_pin=descriptor(d['policy']), source_root=str(oldroot), binding=binding,
                  hosted=context['hosted'], jobs_response=context['jobs_response'],
                  jobs_response_pin=pin(response['body']), observed_epoch=observed, **FINAL)
    need(context == replay, 'exact historical producer replay; no relabelled time, path, identity or acceptance')
    return version


def _completion(raw, s, d, producer, producer_context):
    need(pin(raw) == s['completion_pin'], 'selected whole completed-producer proof')
    value = decode(raw)
    need(type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == 'CURRENT_ONBOARDING_COMPLETED_PRODUCER_V4'
         and value['producer_binding'] == s['producer_binding']
         and value['producer_delegation_pin'] == s['producer_delegation_pin']
         and value['producer_context_pin'] == s['producer_context_pin'], 'completed producer exact tuple and context')
    observed = integer(value['observed_epoch'], 0)
    need(producer_context['observed_epoch'] <= observed <= d['issued_epoch']
         and d['issued_epoch']-observed <= s['max_producer_age_seconds'], 'producer observed completed before consumer grant')
    response = value['jobs_response']
    run, job = s['producer_binding']['run'], s['producer_binding']['job']
    repo = producer['hosted']['repository']
    base = 'https://api.github.com/repos/'+repo+'/actions/runs/'+run
    need(set(response) == {'url', 'status', 'body', 'received_epoch', 'elapsed_ms'}
         and response['url'] == base+'/jobs?filter=latest&per_page=100'
         and type(response['status']) is int and response['status'] == 200
         and type(response['body']) is str, 'whole completed provider jobs response')
    limits = d['context_limits']
    need(0 <= observed-integer(response['received_epoch'], 0) <= limits['metadata_query_seconds']
         and integer(response['elapsed_ms'], 0) <= 1000*limits['metadata_query_seconds'], 'bounded completion observation')
    body = decode(response['body'].encode('utf-8'), limits['metadata_max_bytes'])
    jobs = body['jobs']
    need(type(jobs) is list and integer(body['total_count'], 1, 100) == len(jobs), 'complete completion jobs page')
    selected = [row for row in jobs if type(row) is dict and type(row.get('id')) is int and str(row['id']) == job]
    need(len(selected) == 1, 'one selected completed producer job')
    row = selected[0]
    need(type(row['run_id']) is int and str(row['run_id']) == run
         and type(row['run_attempt']) is int and row['run_attempt'] == s['producer_binding']['attempt']
         and row['head_sha'] == s['producer_binding']['source']
         and row['name'] == producer['hosted']['job_name']
         and row['runner_name'] == producer_context['hosted']['RUNNER_NAME']
         and row['status'] == 'completed' and row['conclusion'] == 'success'
         and row['run_url'] == base
         and row['url'] == 'https://api.github.com/repos/'+repo+'/actions/jobs/'+job
         and row['html_url'] == 'https://github.com/'+repo+'/actions/runs/'+run+'/job/'+job,
         'selected actual completed successful producer tuple and provider URLs')
    from datetime import datetime
    timestamps = []
    for key in ('started_at', 'completed_at'):
        need(type(row[key]) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', row[key]), 'provider UTC completion timestamp')
        timestamps.append(int(datetime.fromisoformat(row[key].replace('Z', '+00:00')).timestamp()))
    need(timestamps[0] <= producer_context['observed_epoch'] <= timestamps[1] <= observed,
         'observed producer in progress before genuine completion')
    return observed


def _decision(raw, selected_pin, kind, s, d, completed, now):
    need(pin(raw) == selected_pin, 'externally selected authentic Root decision bytes')
    value = decode(raw)
    need(type(value['schema']) is int and value['schema'] == 4 and value['kind'] == kind
         and value['issuer'] == 'Root' and value['approved'] is True
         and value['operation'] == OPERATION and value['scope'] == 'CURRENT_PRIVATE_COMPONENT_ONLY',
         'independent explicit Root component/TEST decision')
    for key in ('producer_binding', 'producer_delegation_pin', 'producer_context_pin', 'completion_pin',
                'component', 'pair_pin', 'archives'):
        need(value[key] == s[key], 'exact Root decision selection join: '+key)
    issued, expires = integer(value['issued_epoch'], 0), integer(value['expires_epoch'], 0)
    need(completed <= issued <= d['issued_epoch'] <= now <= expires
         and 0 < expires-issued <= d['context_limits']['max_delegation_seconds'], 'fresh finite Root decision')
    need(value.get('Root_final_acceptance') is None
         and value.get('hardware_acceptance') is False and value.get('release_acceptance') is False,
         'component decision grants no final/hardware/release acceptance')
    return value


def adopt_selected_pair(delegation, context, *, producer_delegation_raw, producer_context,
                        completion_raw, pair_raw, root_component_raw, root_test_raw,
                        archive_bodies, signature_bodies, public_test_key_raw, selection_role=None, now=None):
    """Join explicitly Root-selected completed native component; DATA only.

    Every body/pin is mandatory. Authentic Root decisions are returned only as
    pins, never rewritten or issued here. The actual owner must still perform
    current-stage offline GPG verification and expiry checks before use.
    """
    now = int(time.time()) if now is None else integer(now, 0)
    validate_context(delegation, context, now=now)
    s = _selection(delegation, selection_role)
    need(s is not None, 'explicit completed-component selection required')
    root, rows = source(delegation, context['source_root'])
    need(context['binding']['run'] != s['producer_binding']['run'], 'explicit cross-run route; same-run stays strict')
    need(pin(producer_delegation_raw) == s['producer_delegation_pin']
         and pin(encoded(producer_context)) == s['producer_context_pin'], 'selected whole producer delegation/context')
    producer = decode(producer_delegation_raw)
    need(encoded(producer) == producer_delegation_raw, 'original canonical producer delegation')
    for key in ('source', 'ref', 'source_lock'):
        need(producer['binding'][key] == delegation['binding'][key], 'same closed Source/ref/map producer')
    version = _historical_producer(producer, producer_context, s, root, rows)
    completed = _completion(completion_raw, s, delegation, producer, producer_context)
    need(pin(pair_raw) == s['pair_pin'], 'selected exact native pair proof')
    pair = decode(pair_raw)
    need(type(pair['schema']) is int and pair['schema'] == version
         and pair['kind'] == 'DELEGATED_CURRENT_ONBOARDING_PAIR_V'+str(version)
         and pair['issuer'] == 'DELEGATED_CURRENT_OWNER_V'+str(version)
         and pair['binding'] == s['producer_binding'] and pair['nonce'] == producer['nonce']
         and pair['program_pin'] == descriptor(producer['programs']['owner'])
         and pair['policy_pin'] == descriptor(producer['policy']) and pair['component'] == s['component']
         and pair['package'] == s['component']['name'] and pair['version'] == s['component']['version']
         and pair['archives'] == s['archives'] and pair['matching_pair'] is True
         and all(pair.get(k) == v and type(pair.get(k)) is type(v) for k, v in FINAL.items()),
         'exact native producer component/pair/program/policy proof without acceptance')
    total = 0
    for bodies, pins in ((archive_bodies, s['archives']), (signature_bodies, s['signatures'])):
        need(type(bodies) in (list, tuple) and len(bodies) == 2, 'both actual selected bodies required')
        for body, expected in zip(bodies, pins):
            need(type(body) is bytes and 0 < len(body) <= MAX_FILE and pin(body) == expected, 'exact selected archive/signature bytes')
            total += len(body)
            need(total <= MAX_TOTAL, 'finite combined selected archive/signature bodies')
    need(type(public_test_key_raw) is bytes and 0 < len(public_test_key_raw) <= 1024**2
         and pin(public_test_key_raw) == s['public_test_key_pin'], 'exact selected public TEST key bytes')
    _decision(root_component_raw, s['root_component_decision_pin'], COMPONENT_DECISION, s, delegation, completed, now)
    test = _decision(root_test_raw, s['root_test_decision_pin'], TEST_DECISION, s, delegation, completed, now)
    need(test['signatures'] == s['signatures'] and test['public_test_key_pin'] == s['public_test_key_pin']
         and test['test_fingerprint'] == s['test_fingerprint'] and test['trust_scope'] == 'TEST_ONLY',
         'separate fresh authentic Root TEST signature/archive/key decision')
    return dict(schema=4, kind='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4', issuer=ISSUER,
                binding=context['binding'], producer_binding=s['producer_binding'], component=s['component'],
                nonce=delegation['nonce'], delegation_pin=context['delegation_pin'],
                selection_pin=pin(encoded(s)), producer_delegation_pin=s['producer_delegation_pin'],
                producer_context_pin=s['producer_context_pin'], completion_pin=s['completion_pin'],
                pair_pin=s['pair_pin'], root_component_decision_pin=s['root_component_decision_pin'],
                root_test_decision_pin=s['root_test_decision_pin'], archives=s['archives'], signatures=s['signatures'],
                public_test_key_pin=s['public_test_key_pin'], test_fingerprint=s['test_fingerprint'],
                trust_scope='TEST_ONLY', current_stage_gpg_required=True, **FINAL)
