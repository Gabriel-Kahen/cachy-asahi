# SPDX-License-Identifier: MIT
"""Explicit delegated evidence selection, never Root qualification or an actor.

Selectors describe committed owner9fa3201a and its v4 route. Only the fresh
public namespace is traversed; private stage trees are never discovered/copied.
"""
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat

API = 'CURRENT_ONBOARDING_DELEGATED_RETENTION_V4'
ISSUER = 'DELEGATED_RETENTION_PROGRAM_V4'
KIND = 'DELEGATED_CURRENT_STAGE_RETENTION_V4'
FAMILY = 'scripts/ci/first-login-enrollment-native-source'
LEGACY = FAMILY+'/payload/native/retention_current_v3.py'
LEGACY_SHA = '738360745901f1938be1e6a893ce45131c3f1f825421991522cfee3c66ed8c6a'
ENCODER_SHA = 'a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5'
PROFILE_PIN = dict(bytes=21679, sha256='8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171')
OWNER_BASIS = dict(commit='9fa3201a28d3981fd05013d4244fbb406739cbc5',
    owner=dict(bytes=68320, sha256='4196aa414d7711a5e56c0a73f63282db712fffdfccdd9206e5b4e69f9605c7ad'),
    route=dict(bytes=16196, sha256='78be10c869556ecc0cd07e7ddc0b94016c3fae0cc02b1470420861808289cdee'))
FINAL = dict(Root_final_acceptance=None, independent_component_acceptance=False,
             hardware_acceptance=False, release_acceptance=False)
KINDS = dict(backend=('enrollment', 'first-login'), ui=('ui',), lifecycle=())
MAX_FILE, MAX_TOTAL, MAX_MEMBERS, MAX_COMPRESSED = 8*1024**2, 16*1024**2, 512, 8*1024**2


def need(ok, why):
    if not ok:
        raise ValueError(why)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def bootstrap_read(path):
    """Small bootstrap read before the whole-pinned pure reader is available."""
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary closed Source helper')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= 1024**2 and not before.st_mode & 0o022, 'bounded closed helper')
        body = b''
        while block := os.read(fd, 65536):
            body += block
            need(len(body) <= 1024**2, 'helper size cap')
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        identity = lambda s: tuple(getattr(s, k) for k in fields)
        need(len(body) == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(path.lstat()), 'whole helper drift')
        return body
    finally:
        os.close(fd)


def load_body(raw, name, path=None):
    # Import only bytes already whole-joined to the closed Source. No actor runs.
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    filename = str(path) if path is not None else '<closed-'+name+'>'
    module.__file__ = filename
    exec(compile(raw, filename, 'exec'), module.__dict__)
    return module


def request(source_root, delegation, context, inputs, profile):
    source = Path(source_root)
    raw = bootstrap_read(source/LEGACY)
    need(pin(raw)['sha256'] == LEGACY_SHA, 'whole immutable pure retention helpers')
    R = load_body(raw, 'delegated_retention_pure_reader')
    mapping = R.decode(R.read_file(source/'source-map.json', 1024**2))['files']

    def program(row, name, expected=None):
        member = R.relative(row['member']).as_posix()
        body = R.read_file(source/member, 1024**2)
        whole = {k: row[k] for k in ('bytes', 'sha256')}
        need(pin(body) == whole == {k: mapping[member][k] for k in whole}, 'closed program whole join: '+name)
        if expected is not None:
            need(whole == expected, 'reviewed selector basis: '+name)
        return load_body(body, 'delegated_retention_'+name, source/member)

    H = program(delegation['programs']['context'], 'context')
    raw_d = encode(delegation)
    d = H.validate_delegation(raw_d, pin(raw_d)['sha256'])
    H.source(d, source)
    H.validate_context(d, context)
    profile_raw = R.read_file(source/(FAMILY+'/successor_v2/profile.json'))
    need(pin(profile_raw) == PROFILE_PIN and R.decode(profile_raw) == profile, 'whole frozen current profile')
    need(context['issuer'] in ('DELEGATED_CONTEXT_PROGRAM_V3', 'DELEGATED_CONTEXT_PROGRAM_V4'),
         'genuine selected delegated context, never Root observation')
    for name in ('owner', 'route'):
        row = d['programs'][name]
        member = R.relative(row['member']).as_posix()
        need({k: row[k] for k in ('bytes', 'sha256')} == OWNER_BASIS[name] and
             pin(R.read_file(source/member)) == OWNER_BASIS[name], 'exact committed owner/route selector basis')
    own = d['programs']['retention']
    need(own['member'] == FAMILY+'/payload/native/retention_delegated_v4.py' and
         pin(R.read_file(source/own['member'])) == {k: own[k] for k in ('bytes', 'sha256')}, 'selected new retention body')
    V = program(d['programs']['inputs_assembler'], 'inputs_validator')
    need(callable(getattr(V, 'validate_owner_inputs_v3', None)), 'explicit shared inner-input validation API required')
    valid = V.validate_owner_inputs_v3(inputs=inputs, delegation=d, source_root=source)
    need(valid['valid'] is True and type(valid['required_refs']) is list, 'shared semantic public input validation')
    encoder = program(d['programs']['encoder'], 'encoder',
                      dict(bytes=mapping[d['programs']['encoder']['member']]['bytes'], sha256=ENCODER_SHA))
    return R, encoder.bundle, valid['required_refs']


def final(value):
    need(all(k in value and value[k] == v and type(value[k]) is type(v) for k, v in FINAL.items()),
         'delegated observations cannot assert final acceptance')


def natural(row, expected=0):
    need(type(row) is dict and all(row.get(k) == v and type(row.get(k)) is type(v) for k, v in
         dict(reaped=True, ownership='REAPED', group_census='EMPTY_TWICE', output_complete=True,
              timeout=False, signals=[], error=None, exit=expected).items()) and
         not any(row.get(k) for k in ('forced_cleanup', 'ownership_lost', 'emergency_retirement')),
         'natural complete command retirement required')


def command_observations(row, maximum):
    """Project actual scalar observations, with no inferred success/timing defaults."""
    expected = row['expected']; supervision = row['supervision']
    natural(supervision, expected)
    for key in ('seconds', 'passed'):
        need(key in supervision, 'HOLD_MISSING_ORIGINAL_SUPERVISION_'+key.upper())
    need(type(supervision['passed']) is bool and supervision['passed'] is (expected == 0),
         'actual supervisor zero-exit pass flag must match natural expected status')
    for key in ('timeout_seconds', 'supervision_cap_seconds'):
        need(key in row, 'HOLD_MISSING_ORIGINAL_COMMAND_BOUND:'+key)
    elapsed, cap, timeout = supervision['seconds'], row['supervision_cap_seconds'], row['timeout_seconds']
    need(all(type(v) in (int, float) and math.isfinite(v) for v in (elapsed, cap, timeout, maximum)) and
         0 <= elapsed < cap <= timeout <= maximum and cap > 1, 'actual finite elapsed/command/delegation bound join')
    fields = ('reaped', 'ownership', 'group_census', 'output_complete', 'timeout', 'signals', 'error', 'exit',
              'seconds', 'passed', 'forced_cleanup', 'ownership_lost', 'emergency_retirement')
    for key in ('forced_cleanup', 'ownership_lost', 'emergency_retirement'):
        if key in supervision:
            need(type(supervision[key]) is bool and supervision[key] is False, 'actual natural retirement flag:'+key)
    value = dict(expected=expected, timeout_seconds=timeout, supervision_cap_seconds=cap,
                 supervision={k: supervision[k] for k in fields if k in supervision})
    if 'exit' in row:
        need(type(row['exit']) is int and row['exit'] == expected == supervision['exit'], 'actual emitted exit association')
        value['exit'] = row['exit']
    if 'success' in row:
        need(type(row['success']) is bool and row['success'] is True, 'actual emitted command success required')
        value['success'] = row['success']
    if 'expected_policy' in row:
        need(row['expected_policy'] == 'OBSERVE_STATUS_ONLY', 'known emitted exit-observation policy')
        value['expected_policy'] = row['expected_policy']
    if 'channels' in row:
        need(row['channels'] in ('stdout with separately pinned stderr', 'stdout+stderr combined in pipe order'),
             'actual emitted channel contract')
        value['channels'] = row['channels']
    if any(key in row for key in ('retirement_seconds', 'grace_seconds', 'max_output_bytes')):
        need(all(key in row for key in ('retirement_seconds', 'grace_seconds', 'max_output_bytes')),
             'complete actual emitted retirement/output arguments')
        retirement, grace, output = (row[k] for k in ('retirement_seconds', 'grace_seconds', 'max_output_bytes'))
        need(all(type(v) in (int, float) and math.isfinite(v) for v in (retirement, grace)) and
             0 <= grace < retirement < cap and type(output) is int and 0 <= output <= 1024**2,
             'actual bounded retirement/grace/output arguments')
        value.update(retirement_seconds=retirement, grace_seconds=grace, max_output_bytes=output)
    return value


def base_provenance_public(value, image_inputs):
    """Preserve actual consumed input pins, never original host/staging paths."""
    need(type(value) is dict and set(value) == {'base_lock', 'bootstrap_profile', 'baseline_inventory',
         'factory_profile_pin', 'original_package_count', 'supplemental_package_count', 'final_package_count', 'materials'},
         'exact emitted base input provenance')
    for key, expected in (('original_package_count', 341), ('supplemental_package_count', 8), ('final_package_count', 349)):
        need(type(value[key]) is int and value[key] == expected, 'actual original341/fixed8/final349 counts')
    def descriptor(row):
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and type(row['bytes']) is int and
             row['bytes'] >= 0 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'whole emitted input reference')
        return {k: row[k] for k in ('bytes', 'sha256')}
    def whole(row):
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and row['bytes'] > 0 and
             type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'whole emitted metadata pin')
    whole(value['factory_profile_pin'])
    result = {k: value[k] for k in ('factory_profile_pin', 'original_package_count', 'supplemental_package_count', 'final_package_count')}
    for key in ('base_lock', 'bootstrap_profile', 'baseline_inventory'):
        need(value[key] == image_inputs[key], 'same actual image input provenance reference')
        result[key] = descriptor(value[key])
    rows = value['materials'];need(type(rows) is list and len(rows) == 257, 'all original and supplemental material records')
    names, groups, public = set(), {'base_materials':0, 'supplemental_materials':0}, []
    operands = {key:set() for key in groups}
    for row in rows:
        need(set(row) == {'name', 'version', 'arch', 'filename', 'archive', 'signature', 'source_group', 'metadata_pin'} and
             row['source_group'] in groups and type(row['filename']) is str and
             re.fullmatch('[A-Za-z0-9._+@:-]+', row['filename']) and row['filename'] not in names, 'exact unique original material provenance')
        group, filename = row['source_group'], row['filename'];names.add(filename);groups[group] += 1
        operands[group].update((filename, filename+'.sig'));whole(row['metadata_pin'])
        need(all(row[k] is None or type(row[k]) is str for k in ('name', 'version', 'arch')), 'typed emitted package metadata identity')
        need(row['archive'] == image_inputs[group][filename] and row['signature'] == image_inputs[group][filename+'.sig'],
             'actual original archive/signature reference association')
        kept = {k:row[k] for k in ('name', 'version', 'arch', 'filename', 'source_group', 'metadata_pin')}
        kept.update(archive=descriptor(row['archive']), signature=descriptor(row['signature']));public.append(kept)
    need(groups == {'base_materials':249, 'supplemental_materials':8}, 'complete original249 and fixed8 source groups')
    need(all(set(image_inputs[group]) == wanted for group, wanted in operands.items()), 'complete canonical original514 operand roster')
    result['materials'] = public
    return result


def signature(raw, fingerprint):
    rows = [line.split()[1:] for line in raw.decode().splitlines() if line.startswith('[GNUPG:] ')]
    bad = {'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'KEYEXPIRED',
           'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'NODATA', 'TRUST_NEVER', 'TRUST_UNDEFINED', 'BADARMOR'}
    valid = [r for r in rows if r and r[0] == 'VALIDSIG']
    need(re.fullmatch('[0-9A-F]{40}', fingerprint) and len(valid) == 1 and len(valid[0]) == 11 and
         valid[0][1] == valid[0][-1] == fingerprint and any(r and r[0] == 'TRUST_ULTIMATE' for r in rows) and
         not any(r and r[0] in bad for r in rows), 'complete original current trusted TEST status')


def collect(R, *, stage, output, source_root, delegation, context, image_report,
            stage_report, profile, inputs, executor_facts, approved_refs):
    """Pure finite selection over authentic caller reports and exact output names."""
    need(stage in KINDS and context['stage'] == delegation['stage'] == stage, 'exact current stage')
    binding, nonce = context['binding'], context['nonce']
    need(type(binding) is dict and set(binding) == {'source', 'ref', 'run', 'job', 'attempt', 'source_lock'} and
         all(type(binding[k]) is str and re.fullmatch('[1-9][0-9]*', binding[k]) for k in ('run', 'job')) and
         binding['attempt'] == 1, 'actual observed run/job required')
    need(context['delegation_pin'] == pin(encode(delegation)) and nonce == delegation['nonce'], 'same genuine delegation/context')
    output, source = R.absolute(output), R.absolute(source_root)
    bodies, origins = {}, {}
    policy_raw = R.read_file(source/delegation['policy']['member'])
    need(pin(policy_raw) == {k: delegation['policy'][k] for k in ('bytes', 'sha256')}, 'whole current private policy')
    test = R.decode(policy_raw)['private_stage']['test']

    def public_bytes(raw):
        # Inspect receipt-shaped JSON before base64 transport can hide its keys.
        if raw.lstrip().startswith((b'{', b'[')):
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return  # E.g. literal [GNUPG:] or normal ALPM text, not JSON.
            if type(value) in (dict, list):
                R.decode(raw, object_required=type(value) is dict)

    def add(name, raw, origin=None):
        R.relative(name)
        need(type(raw) is bytes and len(raw) <= MAX_FILE and name not in bodies and
             len(bodies) < MAX_MEMBERS and sum(map(len, bodies.values()))+len(raw) <= MAX_TOTAL,
             'finite unique public evidence namespace')
        # JSON receipt fields are checked before any projection or encoding.
        if name.endswith('.json') or raw.lstrip().startswith(b'{'):
            R.decode(raw)
        public_bytes(raw)
        bodies[name] = raw
        if origin is not None:
            origins[name] = origin

    def file(name, root, member, expected=None):
        R.relative(member)
        raw = R.read_file(root/member)
        if expected is not None:
            need(pin(raw) == expected, 'whole selected body mismatch: '+name)
        add(name, raw, dict(member=member, pin=pin(raw)))
        return raw

    def projection(name, value, keys):
        R.decode(encode(value))
        add(name, encode({k: value[k] for k in keys if k in value}), dict(pin=pin(encode(value)), projection=True))

    route_raw = R.read_file(output/'route.json', 4*1024**2)
    route = R.decode(route_raw)
    need(route == stage_report and route['schema'] == 4 and
         route['kind'] == 'DELEGATED_CURRENT_PRIVATE_STAGE_REPORT_V4' and
         route['issuer'] == 'DELEGATED_CURRENT_OWNER_V3' and
         route['status'] == 'PROVISIONAL_CURRENT_'+stage.upper()+'_DATA_ONLY' and
         route['binding'] == binding and route['nonce'] == nonce and
         route['context_pin'] == pin(encode(context)) and route['delegation_pin'] == context['delegation_pin'] and
         route['image_pin'] == pin(encode(image_report)), 'exact original delegated stage report')
    final(route)
    cleanup = route['owner_cleanup']
    final(cleanup)
    need(cleanup['status'] == 'PASS_DELEGATED_CURRENT_STAGE_RETIREMENT' and cleanup['binding'] == binding and
         cleanup['stage'] == stage and cleanup['nonce'] == nonce and all(cleanup[k] is True for k in
         ('natural_retirement', 'owned_container_absence_verified', 'protected_state_unchanged')),
         'uncertain or pending owner cleanup is HOLD')
    image_root = output.parent/('image') if stage != 'lifecycle' else output.parent.parent/'image'
    image_raw = R.read_file(image_root/'image-provisional.json', 4*1024**2)
    need(R.decode(image_raw) == image_report,
         'exact original image report')
    need(image_report['status'] == 'PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY' and
         image_report['binding'] == binding and image_report['stage'] == stage and
         image_report['delegation_pin'] == context['delegation_pin'] and
         image_report['Root_final_acceptance'] is None and image_report['independent_image_qualification'] is None and
         image_report['owner_executor_facts'] == executor_facts and not image_report['cleanup']['errors'] and
         image_report['protected_before'] == image_report['protected_after'], 'same unqualified image and genuine executor facts')
    retirement = image_report['private_retirement']
    need(all(retirement.get(k) is True for k in ('homes_retired', 'no_sockets', 'private_directory_absent')) and
         not retirement.get('failures'), 'actual image private-trust retirement')
    need(executor_facts['api'] == 'CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3' and
         executor_facts['binding'] == binding and executor_facts['stage'] == stage and
         executor_facts['nonce'] == nonce and executor_facts['native_architecture'] == 'aarch64' and
         all(executor_facts[k] is True for k in ('daemon_pidfd_held', 'whole_owner_deadline_enforced',
             'daemon_deadline_enforced', 'exclusive_daemon')), 'actual finite executor domain observations required')
    final(executor_facts)
    add('delegation.json', encode(delegation))
    add('context.json', encode(context))
    projection('image.public.json', image_report, ('status', 'operation', 'stage', 'binding', 'delegation_pin',
        'image_id', 'packages', 'payload_files', 'cleanup', 'private_retirement', 'protected_before',
        'protected_after', 'selected_pair_adoptions_v4', 'Root_final_acceptance', 'independent_image_qualification', 'native16K', 'M2', 'release'))
    if 'base_input_provenance' in image_report:
        original = image_report['base_input_provenance']
        add('image/base-inputs.public.json', encode(base_provenance_public(original, inputs['image_inputs'])),
            dict(pin=pin(encode(original)), projection=True))
    # Storage/tool path strings and daemon endpoint are not public launch inputs.
    domains = {k: executor_facts[k] for k in ('api', 'binding', 'stage', 'nonce', 'code_pin', 'domain_policy_pin',
        'native_architecture', 'owner_domain', 'daemon_domain', 'daemon_pidfd_held', 'whole_owner_deadline_enforced',
        'daemon_deadline_enforced', 'exclusive_daemon', 'engine_id', 'supervision_program_pin', *FINAL)}
    for role in ('owner_domain', 'daemon_domain'):
        row = domains[role]
        need(type(row) is dict and {'pid', 'starttime', 'cgroup', 'limits'} <= set(row), 'actual PID/start/cgroup/limits body')
        domains[role] = {k: row[k] for k in ('pid', 'starttime', 'cgroup', 'limits')}
        need(type(row['pid']) is int and row['pid'] > 0 and type(row['starttime']) is int and row['starttime'] > 0 and
             type(row['cgroup']) is str and row['cgroup'].startswith('/'), 'actual domain identity')
        limits = row['limits']; memory, pids, cpus = (2*1024**3, 256, 1) if role == 'owner_domain' else (6*1024**3, 768, 4)
        quota, period = limits['cpu.max'].split()
        need(limits['memory.max'] == str(memory) and limits['memory.swap.max'] == '0' and
             limits['pids.max'] == str(pids) and quota.isdecimal() and period.isdecimal() and
             int(period) > 0 and int(quota) == cpus*int(period), 'unchanged observed owner/aggregate daemon caps')
    storage = executor_facts['storage']
    need(storage['kernel_enforced'] is True and storage['scope'] == 'ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES' and
         type(storage['quota_bytes']) is int and 0 < storage['quota_bytes'] <= 32*1024**3, 'actual bounded storage facts')
    domains['storage'] = {k: storage[k] for k in ('kernel_enforced', 'scope', 'quota_bytes', 'device')}
    add('domain.public.json', encode(domains))
    projection('route.public.json', route, ('schema', 'kind', 'issuer', 'operation', 'stage', 'binding', 'nonce',
        'delegation_pin', 'context_pin', 'image_pin', 'image', 'status', 'body_status', 'owner_facts', 'owner_cleanup',
        'builds', 'lifecycle', 'protected_before', 'protected_after', 'signature_config_pin', *FINAL))
    inventory = image_report['inventory_pin']
    file('image/inventory.lock', image_root, 'facts-'+stage+'/inventory.lock', {k: inventory[k] for k in ('bytes', 'sha256')})
    need(inventory['path'] == str(image_root/('facts-'+stage)/'inventory.lock'), 'fixed actual image inventory location')

    def commands(label, rows, root, style):
        need(type(rows) is list and 0 < len(rows) <= 512, 'complete finite original command index')
        if style in ('owner', 'local'):
            index_raw = R.read_file(root/'commands.json')
            need(R.decode(index_raw, object_required=False) == rows,
                 'original complete owner command index')
            index_source = dict(kind='ORIGINAL_COMMAND_INDEX_BODY', pin=pin(index_raw), canonical_rows_pin=pin(encode(rows)))
        else:
            index_source = dict(kind='ORIGINAL_IMAGE_REPORT_FIELD', report_pin=pin(image_raw), field='commands',
                                canonical_rows_pin=pin(encode(rows)))
        result, seen, public, frames, invocations = [], set(), {}, [], []
        frame_number = invocation_number = 0

        def flush():
            nonlocal frames, frame_number
            if frames:
                add('streams/'+label+'/bodies-%03d.json' % frame_number,
                    encode(dict(schema=4, kind='EXACT_PUBLIC_COMMAND_STREAMS_V4', streams=frames)))
                frames = []; frame_number += 1

        def flush_invocations():
            nonlocal invocations, invocation_number
            if invocations:
                add('streams/'+label+'/invocations-%03d.json' % invocation_number,
                    encode(dict(schema=1, kind='EXACT_LOCAL_INVOCATION_BODIES_V1', rows=invocations)))
                invocations = []; invocation_number += 1
        for i, row in enumerate(rows):
            R.decode(encode(row))
            step = row['step']
            need(type(step) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', step) and step not in seen,
                 'unique literal command step')
            seen.add(step)
            if style == 'owner':
                need(R.decode(R.read_file(root/(step+'.json'))) == row, 'original per-command owner receipt index')
            expected = row['expected']
            need(type(expected) is int and expected in (0, 2) and (expected == 0 or step.startswith('no-agent-private-')),
                 'only explicit no-agent nonzero command')
            observed = command_observations(row, delegation['capability']['max_command_seconds'])
            output_pin = row.get('output_pin', row.get('log_pin'))
            if 'executor_receipt' in row:
                original = row['executor_receipt']
                need(original['step'] == step and original['argv'] == row['argv'] and
                     original['output_pin'] == output_pin and original['supervision'] == row['supervision'] and
                     all(original[k] == row[k] and type(original[k]) is type(row[k]) for k in
                         ('expected', 'exit', 'timeout_seconds', 'supervision_cap_seconds', 'stderr_pin')),
                     'original executor command/timing/channel association')
            item = dict(step=step, ordinal=i, output_pin=output_pin,
                        original_receipt_pin=pin(encode(row)), **observed)
            if 'executor_receipt' in row:
                item['original_executor_receipt_pin'] = pin(encode(row['executor_receipt']))
            if style == 'local':
                proof, held = row.get('local_invocation_v1'), row.get('held_receipt')
                need(type(proof) is dict and type(held) is dict, 'HOLD_MISSING_ORIGINAL_LOCAL_INVOCATION')
                need(set(proof) == {'schema', 'kind', 'request', 'request_pin', 'supervision_request',
                     'supervision_request_pin', 'held_receipt_pin', 'supervision_result_pin'} and proof['schema'] == 1 and
                     proof['kind'] == 'DELEGATED_LOCAL_COMMAND_INVOCATION_V1', 'exact actual local invocation proof')
                request, selected = proof['request'], proof['supervision_request']
                need(set(request) == {'schema', 'kind', 'step', 'argv_pin', 'timeout_seconds', 'deadline_monotonic', 'max_output_bytes'} and
                     request['schema'] == 1 and request['kind'] == 'DELEGATED_LOCAL_COMMAND_INVOCATION_REQUEST_V1' and
                     request['step'] == step and request['argv_pin'] == pin(encode(row['argv'])) and
                     type(request['deadline_monotonic']) in (int, float) and math.isfinite(request['deadline_monotonic']) and
                     request['deadline_monotonic'] > 0, 'actual public local request observations')
                need(set(selected) == {'schema', 'kind', 'step', 'request_pin', 'cap_seconds', 'retirement_seconds', 'grace_seconds', 'max_output_bytes'} and
                     selected['schema'] == 1 and selected['kind'] == 'DELEGATED_LOCAL_SUPERVISION_REQUEST_V1' and
                     selected['step'] == step and selected['request_pin'] == proof['request_pin'] == pin(encode(request)) and
                     proof['supervision_request_pin'] == pin(encode(selected)) and
                     proof['held_receipt_pin'] == pin(encode(held)) and
                     proof['supervision_result_pin'] == pin(encode(row['supervision'])) and
                     selected['cap_seconds'] == row['supervision_cap_seconds'] and request['timeout_seconds'] == row['timeout_seconds'] and
                     request['max_output_bytes'] == selected['max_output_bytes'] == row['max_output_bytes'] and
                     selected['retirement_seconds'] == row['retirement_seconds'] and selected['grace_seconds'] == row['grace_seconds'],
                     'whole original local request/cap/retirement/result associations')
                need(all(type(selected[k]) is type(row[target]) for k, target in (
                     ('cap_seconds', 'supervision_cap_seconds'), ('retirement_seconds', 'retirement_seconds'),
                     ('grace_seconds', 'grace_seconds'), ('max_output_bytes', 'max_output_bytes'))) and
                     type(request['timeout_seconds']) is type(row['timeout_seconds']), 'exact observed local scalar types')
                need(all(held.get(k) == row[k] and type(held.get(k)) is type(row[k]) for k in
                     ('step', 'argv', 'cwd', 'expected', 'success', 'log', 'log_pin', 'supervision', 'channels')),
                     'unchanged original held local receipt')
                item['local_invocation_v1'] = proof
                invocation = dict(step=step)
                for role, suffix, body, expected_pin in (
                        ('request', '.invocation-request.json', request, proof['request_pin']),
                        ('supervision_request', '.supervision-request.json', selected, proof['supervision_request_pin'])):
                    original_raw = R.read_file(root/(step+suffix), 16384)
                    need(original_raw == encode(body) and pin(original_raw) == expected_pin, 'exact original local invocation request body')
                    invocation[role] = dict(pin=pin(original_raw), base64=base64.b64encode(original_raw).decode())
                if invocations and len(encode(dict(rows=invocations+[invocation]))) > 4*1024**2:
                    flush_invocations()
                invocations.append(invocation)
                item['invocation_frame'] = 'streams/'+label+'/invocations-%03d.json' % invocation_number
            # No inspect/create/daemon/config/key import/listing output is ever opened.
            safe = bool(re.fullmatch(r'(?:verify-[0-9]+|verify-selected-[0-9]+-1|pkginfo-[0-9]+|start-(?:base|backend|ui|lifecycle|probe)|'
                r'build-(?:enrollment|first-login|ui)-[ab]-attach|validate-(?:enrollment|first-login|ui)-[ab]|'
                r'current-[A-Za-z0-9_.-]+|private-signature-[A-Za-z0-9_.-]+|adopted-pkginfo-[A-Za-z0-9_.-]+|'
                r'(?:no-agent-private|private-no-agent)-[0-9]+)', step))
            if safe:
                if style == 'image':
                    name, errors = step+'.log', step+'.stderr.log'
                elif style == 'owner':
                    name, errors = step+'.stdout', step+'.stderr'
                else:
                    name, errors = row['log'], None
                    need(name == '%03d-%s.log' % (i, step), 'exact held local command log association')
                if style in ('image', 'local'):
                    raw = R.read_file(root/name, 1024**2)
                    need(pin(raw) == output_pin, 'whole original public command stream body')
                    public_bytes(raw)
                    frame = dict(step=step)
                    frame['stdout' if style == 'image' else 'combined'] = dict(pin=pin(raw), base64=base64.b64encode(raw).decode())
                    if style == 'image':
                        errors_raw = R.read_file(root/errors, 1024**2)
                        need(pin(errors_raw) == row['stderr_pin'], 'whole image stderr body')
                        public_bytes(errors_raw)
                        frame['stderr'] = dict(pin=pin(errors_raw), base64=base64.b64encode(errors_raw).decode())
                    if frames and len(encode(dict(streams=frames+[frame]))) > 4*1024**2:
                        flush()
                    frames.append(frame)
                    item['body_frame'] = 'streams/'+label+'/bodies-%03d.json' % frame_number
                else:
                    raw = file('streams/'+label+'/'+name, root, name, output_pin)
                    item['body_members'] = {('stdout' if errors is not None else 'combined'): 'streams/'+label+'/'+name}
                public[step] = raw
                if errors is not None and style != 'image':
                    need('stderr_pin' in row, 'complete separate stderr pin')
                    file('streams/'+label+'/'+errors, root, errors, row['stderr_pin'])
                    item['body_members']['stderr'] = 'streams/'+label+'/'+errors
                elif errors is None and row.get('channels') != 'stdout+stderr combined in pipe order':
                    need(False, 'explicit complete held local channel contract')
            else:
                item['private_body_excluded_before_open'] = True
            if 'stderr_pin' in row:
                item['stderr_pin'] = row['stderr_pin']
            result.append(item)
        flush()
        flush_invocations()
        add('streams/'+label+'/commands.public.json', encode(dict(schema=4, kind='DELEGATED_PUBLIC_COMMAND_INDEX_V4',
            source=index_source, count=len(rows), rows=result)))
        return public

    image_streams = commands('image', image_report['commands'], image_root, 'image')
    if stage == 'lifecycle':
        need(R.decode(R.read_file(output/'commands/commands.json'), object_required=False) == route['commands'],
             'original complete held lifecycle command index')
    streams = commands('stage', route['commands'], output/'commands', 'local' if stage == 'lifecycle' else 'owner')
    if stage in ('backend', 'ui'):
        clean = R.decode(R.read_file(output/'owner-cleanup.json'))
        need(clean['binding'] == binding and clean['stage'] == stage and clean['nonce'] == nonce and
             not clean['failures'] and clean['protected_before'] == clean['protected_after'], 'actual unchanged host owner cleanup')
        need(type(clean['retired']) is list and len(clean['retired']) == 1+2*len(KINDS[stage]), 'every probe/build actor retired')
        retired = []
        for row in clean['retired']:
            need(row['status'] == 'REMOVED_AND_ABSENT' and re.fullmatch('[0-9a-f]{64}', row['cid']) and
                 row['inspection']['Id'] == row['cid'] and row['inspection']['State']['Running'] is False and
                 row['inspection']['State']['ExitCode'] == 0 and row['inspection']['State']['OOMKilled'] is False,
                 'natural exact-CID terminal/removal observation')
            retired.append({k: row[k] for k in ('status', 'cid', 'name')})
        add('owner-retirement.public.json', encode(dict(rows=retired)))
        verifications = clean['signature_verifications']
        want = {'setup8'} if stage == 'backend' else {'setup8', 'first-login-selected-0', 'first-login-selected-1'}
        # V3 same-run adoption has one verified signature; selected V4 has both.
        if stage == 'ui' and not delegation['capability'].get('allow_selected_pair_adoption', False):
            want = {'setup8', 'first-login'}
        need(set(verifications) == want, 'complete current-stage package GPG roles')
        for key, row in verifications.items():
            need(row['status'].encode() == streams['private-signature-'+key] and
                 row['command'] in route['commands'], 'current GPG body and command join')
            need(row['fingerprint'] == test['fingerprint'], 'same selected TEST primary')
            signature(row['status'].encode(), test['fingerprint'])
            projection('signatures/'+key+'.json', row, ('archive', 'signature', 'fingerprint', 'status', 'trust_scope'))
        projection('owner-cleanup.public.json', clean, ('operation', 'stage', 'binding', 'nonce', 'protected_before', 'protected_after', *FINAL))
        need(set(route['builds']) == {'pairs', 'artifacts'} and set(route['builds']['pairs']) == set(KINDS[stage]), 'exact pair kinds')
        for kind in KINDS[stage]:
            recipe = profile['packages'][kind]
            R.relative(recipe['archive'])
            need('/' not in recipe['archive'], 'archive basename')
            archives = []
            for label in ('a', 'b'):
                prefix = 'builds/'+kind+'-'+label
                provenance = R.decode(R.read_file(output/prefix/'provenance.json'))
                need(provenance['status'] == 'built-package-static-pass' and provenance['mode'] == 'native' and
                     provenance['builder_host_arch'] == 'aarch64' and provenance['network'] == 'none' and
                     provenance['exit_code'] == 0, 'actual static build provenance')
                allowed = R.BUILD_FILES | {'build-log-components.json', 'artifacts/'+recipe['archive']}
                need(R.BUILD_FILES | {'build-log-components.json'} <= set(provenance['files']) <= allowed and
                     set(provenance['recipe_inputs']) == set(recipe['files']), 'complete exact build output/recipe roles')
                projection(prefix+'/provenance.public.json', provenance,
                    ('schema_version', 'status', 'hardware_status', 'mode', 'image', 'image_id', 'source_date_epoch',
                     'network', 'builder_host_arch', 'exit_code', 'clean_environment_id', 'expected_packages_sha256',
                     'recipe_inputs', 'recipe_metadata', 'entry_script_sha256', 'artifacts', 'files'))
                for name, digest in provenance['files'].items():
                    body = file(prefix+'/'+name, output, prefix+'/'+name)
                    need(pin(body)['sha256'] == digest, 'whole provenance file')
                validation_raw = bodies[prefix+'/validation.json']
                validation = R.decode(validation_raw)
                static = R.decode(streams['validate-'+kind+'-'+label])
                need(static['status'] == 'PASS_DELEGATED_BUILD_STATIC_VALIDATION' and
                     static['validation_pin'] == pin(validation_raw) and validation['errors'] == [] and
                     len(validation['artifacts']) == 1 and validation['artifacts'][0]['artifact'] == recipe['archive'] and
                     not validation['artifacts'][0]['errors'], 'actual validator stdout joins original package validation body')
                log = bodies[prefix+'/build.log']
                need(log.count(b'Starting check()') == 1 and not re.search(br'FAILED|ERROR:|\bskipped\b', log, re.I), 'real non-skipped check log')
                step = 'build-'+kind+'-'+label+'-attach'
                errors = bodies['streams/stage/'+step+'.stderr']
                need(streams[step]+errors == log, 'complete actual build stdout followed by stderr')
                components = R.decode(bodies[prefix+'/build-log-components.json'])
                need(components == dict(stdout=pin(streams[step]), stderr=pin(errors),
                    composition='stdout followed by stderr; no cross-channel ordering claim'), 'separate build channel association')
                name = prefix+'/artifacts/'+recipe['archive']
                if name not in bodies:
                    file(name, output, name)
                archives.append(bodies[name])
                need(pin(bodies[name]) == route['builds']['artifacts'][kind][label], 'actual pair archive pin')
                need(validation['artifacts'][0]['sha256'] == pin(bodies[name])['sha256'] and
                     provenance['artifacts'] == static['artifacts'] == {recipe['archive']: pin(bodies[name])['sha256']}, 'static artifact archive join')
                for name, row in recipe['files'].items():
                    need(provenance['recipe_inputs'][name] == row['sha256'], 'whole recipe input')
                    file(prefix+'/inputs/'+name, output, prefix+'/inputs/'+name, {k: row[k] for k in ('bytes', 'sha256')})
            need(archives[0] == archives[1], 'both complete compressed pair bodies')
            comparison = route['builds']['pairs'][kind]
            need(R.decode(streams['current-'+kind+'-compare']) == comparison and comparison['status'] == 'contents-reproduced' and
                 comparison['errors'] == [] and comparison['packages'] == {recipe['archive']:dict(installed_contents_equal=True,
                 pkginfo_equal=True, bytes_equal=True, buildinfo_equal=True)}, 'complete actual byte comparison')
            pair = R.decode(R.read_file(output/(kind+'-pair.json')))
            final(pair)
            need(pair['binding'] == binding and pair['nonce'] == nonce and pair['archives'] == [pin(b) for b in archives] and
                 pair['matching_pair'] is True and pair['comparison_receipt'] in route['commands'], 'same actual producer pair receipt')
            projection(kind+'-pair.public.json', pair, ('schema', 'kind', 'issuer', 'binding', 'nonce', 'program_pin',
                'policy_pin', 'package', 'version', 'component', 'archives', 'matching_pair', *FINAL))
    else:
        need(set(route['signed']) == {'setup8', 'enrollment', 'first-login', 'ui'}, 'all four lifecycle signed packages')
        for kind, row in route['signed'].items():
            for field in ('archive', 'signature'):
                file('signed/'+kind+'.'+field, output, 'signed/'+kind+'.'+field, row[field+'_pin'])
        need(route['protected_before'] == route['protected_after'] and route['lifecycle']['status'] ==
             'PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY', 'actual complete lifecycle and preservation')
        outer = route['outer_retirement']
        need(outer['retired'] is True and outer['retirement']['status'] == 'REMOVED_AND_ABSENT' and
             outer['retirement']['cid'] == outer['cid'], 'actual outer natural retirement/absence')
        need([r['step'] for r in outer['command_receipts']] ==
             ['private-lifecycle-'+s for s in ('fresh', 'create', 'created', 'attach', 'terminal')]+
             ['retire-5-'+s for s in ('query', 'inspect', 'remove', 'after-0', 'after-1')], 'complete actual outer actor command roles')
        for field in ('created', 'terminal'):
            need(outer[field]['Id'] == outer['cid'], 'same actually inspected outer CID')
        need(outer['terminal']['State']['Running'] is False and outer['terminal']['State']['ExitCode'] == 0 and
             outer['terminal']['State']['OOMKilled'] is False, 'natural actual outer terminal body')
        commands('outer', outer['command_receipts'], output/'outer-owner/commands', 'owner')
        projection('outer-retirement.public.json', outer['retirement'], ('status', 'cid', 'name'))
        local = R.decode(R.read_file(output/'owner-local.json'))
        need(local['body_success'] is True and local['protected_state_unchanged'] is True and not local['failures'] and
             all(local['private_retirement'].get(k) is True for k in ('homes_retired', 'no_sockets', 'private_directory_absent')),
             'actual local restoration and private trust retirement')
        projection('owner-local.public.json', local, ('status', 'operation', 'stage', 'binding', 'body_success', 'protected_state_unchanged'))
        # No private administrative key import/listing/config output is read.
        admin = R.decode(R.read_file(output/'owner-admin/commands/commands.json'), object_required=False)
        commands('administrative', admin, output/'owner-admin/commands', 'local')
        life = route['lifecycle']
        steps = ('current-baseline', 'current-dependency-inventory', 'current-install-inventory',
                 'current-after-remove-install', 'current-reinstall-inventory', 'current-after-remove-reinstall', 'current-final-inventory')
        need(set(life['inventories']) == set(steps[1:]) and set(life['payloads']) == {'setup8', 'install', 'reinstall'}, 'complete lifecycle inventories and payloads')
        for step, count in zip(steps, (372, 373, 376, 373, 376, 373, 372)):
            body = streams[step]
            rows = body.decode('ascii').splitlines()
            need(len(rows) == count and len({r.split(' ')[0] for r in rows}) == count and all(len(r.split(' ')) == 2 for r in rows), 'actual complete lifecycle inventory')
            if step != 'current-baseline':
                need(pin(body) == life['inventories'][step], 'whole lifecycle inventory')
        for kind in ('setup8', 'enrollment', 'first-login', 'ui'):
            need('current-signature-'+kind in streams and 'current-pkginfo-'+kind in streams, 'actual current lifecycle GPG/metadata bodies')
            signature(streams['current-signature-'+kind], test['fingerprint'])
        need('current-remove-setup8' in streams and 'current-install-setup8' in streams, 'actual normal Setup8 dependency lifecycle bodies')
        payloads = [('current-setup8', life['payloads']['setup8'], profile['setup8'])]
        for cycle in ('install', 'reinstall'):
            need(set(life['payloads'][cycle]) == {'enrollment', 'first-login', 'ui'}, 'all installed/reinstalled payloads')
            need(all('current-'+step in streams for step in (cycle, 'remove-'+cycle)), 'actual normal install/remove bodies')
            for kind in ('enrollment', 'first-login', 'ui'):
                need('current-'+cycle+'-help-'+kind in streams, 'actual ordinary-user help body')
                payloads.append(('current-'+cycle+'-'+kind, life['payloads'][cycle][kind], profile['packages'][kind]))
        for label, row, recipe in payloads:
            need(row == dict(verified=True, files=recipe['payload_files']), 'complete actual payload ownership receipt')
            wanted = [label+'-file-list']+[label+'-'+field+'-'+str(i) for field in ('owner', 'stat', 'sha256') for i in range(len(recipe['payload_files']))]
            need(all(step in streams for step in wanted), 'complete actual file-list/owner/stat/hash bodies')
        for label, kinds in (('install', ('enrollment', 'first-login', 'ui')), ('reinstall', ('enrollment', 'first-login', 'ui')), ('setup8', ('setup8',))):
            files = {name for kind in kinds for name in (profile['setup8'] if kind == 'setup8' else profile['packages'][kind])['payload_files']}
            need(all('current-absent-'+label+'-'+str(i)+flag in streams and streams['current-absent-'+label+'-'+str(i)+flag] == b''
                     for i in range(len(files)) for flag in ('-e', '-L')), 'actual removed-file absence bodies')
        previous = inputs['stage_inputs'].get('retention')
        need(type(previous) is dict and set(previous) == {'prior_backend', 'prior_ui'}, 'explicit genuine prior public capsules required')
        for role, ref in previous.items():
            need(ref in approved_refs, 'shared semantic validator must approve prior public capsule')
            add('prior/'+role+'.capsule', R.reference(ref), dict(pin={k: ref[k] for k in ('bytes', 'sha256')}))
    # Complete public Source-role material bodies (Setup8 decisions/key/signature)
    # and explicitly approved producer bodies are selected; never a host tree walk.
    stage_inputs = inputs['stage_inputs']
    wanted_products = set() if stage == 'backend' else {'first-login'} if stage == 'ui' else {'enrollment', 'first-login', 'ui'}
    need(set(stage_inputs['products']) == wanted_products, 'complete current prerequisite product kinds')
    key = delegation['materials'][test['public_key_role']]
    file('setup8/public-key.asc', source, key['member'], {k: key[k] for k in ('bytes', 'sha256')})
    for field in ('archive', 'signature', 'decision', 'verification'):
        alias = stage_inputs['setup8'][field+'_role']
        row = delegation['materials'][alias]
        file('setup8/'+field+('.json' if field in ('decision', 'verification') else '.data'), source,
             row['member'], {k: row[k] for k in ('bytes', 'sha256')})
    if stage != 'lifecycle':
        setup = clean['signature_verifications']['setup8']
        need(setup['archive'] == pin(bodies['setup8/archive.data']) and setup['signature'] == pin(bodies['setup8/signature.data']),
             'current Setup8 GPG input bodies')

    def selected_adoption(value, kind, product):
        final(value)
        recipe = profile['packages'][kind]
        descriptor = lambda ref: {k: ref[k] for k in ('bytes', 'sha256')}
        need(value['schema'] == 4 and value['kind'] == 'DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4' and
             value['issuer'] == 'DELEGATED_CONTEXT_PROGRAM_V4' and value['binding'] == binding and value['nonce'] == nonce and
             value['delegation_pin'] == context['delegation_pin'] and value['current_stage_gpg_required'] is True and
             value['component'] == dict(name=recipe['name'], version=recipe['version'], architecture='any') and
             value['archives'] == [descriptor(ref) for ref in product['archives']] and
             value['signatures'] == [descriptor(ref) for ref in product['signatures']] and
             value['pair_pin'] == descriptor(product['pair']) and value['completion_pin'] == descriptor(product['completion']) and
             value['root_component_decision_pin'] == descriptor(product['root_component']) and
             value['root_test_decision_pin'] == descriptor(product['root_test']) and
             value['public_test_key_pin'] == descriptor(key) and value['test_fingerprint'] == test['fingerprint'],
             'same actual selected adoption and original public pair/decision/key bodies')

    for kind, product in stage_inputs['products'].items():
        selected = delegation['capability'].get('allow_selected_pair_adoption', False)
        fields = {'producer_delegation', 'producer_context', 'pair', 'archives'}
        fields |= {'kind', 'selection_role', 'completion', 'root_component', 'root_test', 'signatures'} if selected else {
            'Root_decision', 'Root_verification', 'signature', 'test'}
        need(set(product) == fields and (not selected or product['kind'] == 'ROOT_SELECTED_PRODUCT_INPUT_REFS_V4') and type(product['archives']) is list and
             len(product['archives']) == 2, 'complete actual prerequisite producer pair and decision bodies')
        if selected:
            need(type(product['signatures']) is list and len(product['signatures']) == 2, 'both selected pair signatures')
        def keep(value, suffix):
            if type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}:
                need(value in approved_refs, 'explicit approved public product reference')
                add('products/'+kind+'/'+suffix+'.data', R.reference(value), dict(pin={k: value[k] for k in ('bytes', 'sha256')}))
            elif type(value) is list:
                for i, item in enumerate(value):
                    keep(item, suffix+'-'+str(i))
            elif type(value) is bytes:
                need(False, 'retention requires original approved public product references, never guessed paths')
            elif type(value) is dict:
                need(False, 'canonical serialized product reference required')
        for field, value in product.items():
            keep(value, field)
        if selected:
            receipt = R.decode(file('products/'+kind+'/adoption.json', output, 'adopted/'+kind+'-selected-adoption.json'))
            selected_adoption(receipt, kind, product)
    image_adoptions = image_report.get('selected_pair_adoptions_v4')
    need(type(image_adoptions) is list and len(image_adoptions) == (1 if stage == 'ui' and
         delegation['capability'].get('allow_selected_pair_adoption', False) else 0), 'complete actual selected image adoption receipts')
    for row in image_adoptions:
        selected_adoption(row['adoption'], 'first-login', stage_inputs['products']['first-login'])
        steps = row['current_stage_gpg_steps']
        need(type(steps) is list and len(steps) == 2 and re.fullmatch('verify-[0-9]+', steps[0]) and
             steps[1] == 'verify-selected-'+steps[0].split('-')[1]+'-1', 'both actual selected image GPG command roles')
        for step in steps:
            signature(image_streams[step], test['fingerprint'])
    return bodies, origins


def publish(R, encoder, destination, bodies, manifest):
    """Encode only a fresh closed DATA namespace using the immutable encoder."""
    destination = R.absolute(destination)
    need(not destination.exists(), 'fresh public destination')
    fd = R.directory_fd(destination.parent)
    try:
        os.mkdir(destination.name, 0o700, dir_fd=fd)
    finally:
        os.close(fd)
    root = destination/('delegated-'+manifest['stage']+'-public-v4')
    root.mkdir(mode=0o700)
    root_identity = (root.stat().st_dev, root.stat().st_ino)
    all_bodies = dict(bodies, **{'retention-manifest.json': encode(manifest)})
    need(len(all_bodies) <= MAX_MEMBERS and sum(map(len, all_bodies.values())) <= MAX_TOTAL,
         'unchanged complete public evidence caps including manifest')
    for name, raw in sorted(all_bodies.items()):
        parts = R.relative(name).parts
        node = R.directory_fd(root)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=node)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
                os.close(node); node = child
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=node)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
        finally:
            os.close(node)

    def stable():
        # Only the newly generated public namespace is traversed.
        fd = R.directory_fd(root)
        try:
            need((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == root_identity, 'public staging root identity')
        finally:
            os.close(fd)
        found, directories = set(), set()
        for parent, dirs, files in os.walk(root, followlinks=False):
            need(not any((Path(parent)/n).is_symlink() for n in dirs), 'public staging directory alias')
            directories.update((Path(parent)/n).relative_to(root).as_posix() for n in dirs)
            for name in files:
                path = Path(parent)/name
                member = path.relative_to(root).as_posix()
                need(member in all_bodies and R.read_file(path) == all_bodies[member], 'closed public staging drift')
                found.add(member)
        wanted = {p.as_posix() for name in all_bodies for p in Path(name).parents if p.as_posix() != '.'}
        need(found == set(all_bodies) and directories == wanted, 'closed public staging members')
    stable()
    capsule = encoder(root)
    need(type(capsule) is bytes and 0 < len(capsule) <= MAX_COMPRESSED, 'bounded whole existing capsule encoder')
    stable()
    capsule_path = destination/('delegated-'+manifest['stage']+'-public-v4.tar.gz')
    with capsule_path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o444)
        stream.write(capsule)
    return dict(directory=str(root), manifest=manifest, capsule=capsule, capsule_pin=pin(capsule),
                capsule_path=str(capsule_path), evidence_state='COMPLETE', **FINAL)


def retain_delegated_stage(*, stage, output, destination, source_root, delegation, context,
                           image_report, stage_report, profile, inputs, executor):
    R, encoder, refs = request(source_root, delegation, context, inputs, profile)
    output, destination, source = map(R.absolute, (output, destination, source_root))
    need(not any(a == b or a in b.parents or b in a.parents for a, b in
         ((output, destination), (source, destination))), 'fresh disjoint public destination')
    bodies, origins = collect(R, stage=stage, output=output, source_root=source, delegation=delegation,
        context=context, image_report=image_report, stage_report=stage_report, profile=profile,
        inputs=inputs, executor_facts=executor.facts, approved_refs=refs)
    manifest = dict(schema=4, kind=KIND, issuer=ISSUER, operation='first-login-enrollment-ui-current-v2',
        stage=stage, binding=context['binding'], nonce=context['nonce'], delegation_pin=pin(encode(delegation)),
        context_pin=pin(encode(context)), stage_report_pin=pin(encode(stage_report)),
        image_report_pin=pin(encode(image_report)), selector_basis=OWNER_BASIS, evidence_state='COMPLETE',
        holds=[], files={n: pin(b) for n, b in sorted(bodies.items())}, origins=origins,
        legacy_private_launch_replay=False, provisional_observations_only=True, **FINAL)
    return publish(R, encoder, destination, bodies, manifest)


if __name__ == '__main__':
    raise SystemExit('Internal delegated DATA retention callback; no actor or Root authority')
