# SPDX-License-Identifier: MIT
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
