# SPDX-License-Identifier: MIT
"""Historical audio result DATA composition; no native authority or live role.

``qualify(state, records, reader_pin=..., now_monotonic=...)`` consumes the
coordinator's validated Source/request/context/input state. ``records`` has the
fixed roles in RECORDS, each an externally selected {path,bytes,sha256} reference.
The observation is schema1 BANKSTOWN_QT3_RESULT_OBSERVATION_V1, with the exact
OBSERVATION keys below. Its launcher_window has started_monotonic and
finished_monotonic; retained_input_retirement has path,mount_id,absent_twice and
observed_monotonic. expected_image is {id,inventory}; expected_executor is the
complete image receipt executor. record_pins binds every other role to whole
bytes. All selectors and observations require external trusted custody.

Image/file predicates are replayed at the selected historical image observation,
while their unchanged finite file-verification deadline must still be live.
Expired/destroyed original references HOLD; no receipt relocation is invented.
No replay reconstructs a live executor. Complete retained image references
and a complete build_root are mandatory; current producer public-only retention
is insufficient. Static package replay copies bounded DATA into private scratch
because the existing zstd validator writes a temporary tar. Source code is never
imported: helper code comes exclusively from this trusted Main checkout.
"""
import importlib.util
import math
from pathlib import Path
import re
import tempfile
import time

HERE = Path(__file__).resolve().parent
MAIN = HERE.parents[2]


def load(member):
    path = MAIN / member
    spec = importlib.util.spec_from_file_location('qt3_result_' + path.stem, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


H = load('scripts/ci/bankstown-qt3-native-source/handoff.py')
P = load('scripts/ci/bankstown-qt3-native-profile-v1/passive.py')
R = load('scripts/ci/bankstown-qt3-native-profile-v1/receipt.py')
I = load('scripts/ci/bankstown-qt3-native-profile-v1/inventory.py')
A = load('scripts/port/bankstown-qt3-native-v1/admission.py')
B = load('scripts/port/bankstown-qt3-native-v1/builder.py')
O = load('scripts/ci/bankstown-qt3-native-source/owner.py')
RECORDS = {'image', 'profile', 'profile_receipt', 'admission', 'build', 'pipeline',
           'owner', 'executor', 'launcher', 'observation'}
OBSERVATION = {'schema', 'kind', 'binding', 'nonce', 'request_pin', 'context_pin',
               'source_lock', 'reader_pin', 'owner_pin', 'record_pins',
               'expected_image', 'expected_executor', 'launcher_window',
               'image_observed_monotonic', 'stage_window', 'build_root', 'retained_input_retirement'} | set(H.FINAL)
STEPS = ('image', 'daemon', 'fresh-name', 'create', 'inspect-created', 'attach',
         'inspect-terminal', 'retire-query', 'retire-inspect', 'retire-remove',
         'retire-after-name', 'retire-after-cid')


def need(value, why):
    H.need(value, 'HOLD_AUDIO_RESULT_' + why)


def exact(value, keys, why):
    need(type(value) is dict and set(value) == set(keys), why)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def final(value, wanted=H.FINAL):
    need(all(value.get(k) is v for k, v in wanted.items()), 'ACCEPTANCE_HOLDS')


def whole(row):
    return {k: row[k] for k in ('bytes', 'sha256')}


def retained_commands(build_root, trial, build, facts, profile_pin):
    """Join retained command DATA to the exact admitted intent and inspections."""
    root = H.ordinary(str(build_root)); intent = build['intent']; resources = trial['resources']
    exact(intent, {'name', 'image', 'user', 'entry', 'labels', 'mounts', 'env', 'memory', 'cpus', 'pids', 'cid'}, 'BUILD_INTENT_KEYS')
    name = 'bankstown-qt3-' + build['admission_pin']['sha256'][:24]
    labels = {'org.cachy-asahi.operation': 'bankstown-qt3-private-test-v1',
              'org.cachy-asahi.admission': build['admission_pin']['sha256'], 'org.cachy-asahi.source': trial['source']['commit']}
    env = {'CACHY_ASAHI_CONTAINER': '1', 'SOURCE_DATE_EPOCH': '1791748800', 'PATH': '/usr/bin:/bin',
           'BASH_ENV': '/dev/null', 'ENV': '/dev/null', 'PYTHONPATH': '', 'PYTHONHOME': '', 'LD_PRELOAD': '', 'LD_LIBRARY_PATH': '',
           'PYTHONDONTWRITEBYTECODE': '1', 'BANKSTOWN_NATIVE_TOOLS_PROFILE': '/bankstown-qt3-control/profile.json',
           'BANKSTOWN_NATIVE_TOOLS_SHA256': profile_pin['sha256']}
    inventory_name = next(n for n, row in trial['materials'].items() if row == trial['image']['inventory'])
    mounts = [[str(a), b, c] for a, b, c in B.mounts(root / 'control/source', root / 'inputs', root / 'artifacts', root / 'control', root / 'control/source' / inventory_name)]
    need(all(type(facts.get(k)) is int and facts[k] > 0 for k in ('uid', 'gid'))
         and intent['name'] == name and intent['image'] == trial['image']['id']
         and intent['user'] == f"{facts['uid']}:{facts['gid']}" and intent['entry'] == '/bankstown-qt3-source/' + B.PREFIX + 'entry.sh'
         and intent['labels'] == labels and intent['env'] == env and intent['mounts'] == mounts
         and all(type(intent[k]) is int and intent[k] == resources[r] for k, r in (('memory', 'memory_bytes'), ('cpus', 'cpus'), ('pids', 'pids')))
         and type(intent['cid']) is str and re.fullmatch('[0-9a-f]{64}', intent['cid']), 'EXACT_ADMITTED_BUILD_INTENT')
    cid = intent['cid']; endpoint = trial['owned_executor']['docker_endpoint']
    create = ['create', '--name', name, '--pull=never', '--platform', 'linux/arm64', '--user', intent['user'],
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--pids-limit', str(resources['pids']),
        '--memory', str(resources['memory_bytes']), '--memory-swap', str(resources['memory_bytes']), '--cpus', str(resources['cpus']),
        '--network', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g']
    for key, value in labels.items(): create += ['--label', key + '=' + value]
    for key, value in env.items(): create += ['--env', key + '=' + value]
    for src, dst, readonly in mounts: create += ['--mount', f'type=bind,src={src},dst={dst}' + (',readonly' if readonly else '')]
    create += ['--entrypoint', '/bin/bash', intent['image'], intent['entry']]
    expected = (['image', 'inspect', intent['image']], ['info', '--format', '{{json .}}'],
        ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'], create, ['inspect', cid], ['start', '--attach', cid],
        ['inspect', cid], ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'], ['inspect', cid], ['rm', cid],
        ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'], ['ps', '-aq', '--no-trunc', '--filter', 'id=' + cid])
    rows = build['commands']; need(type(rows) is list and tuple(v.get('step') for v in rows) == STEPS, 'COMPLETE_COMMANDS')
    need(P.read(root / 'result.json') == H.encoded(build)
         and P.decoded(P.read(root / 'commands/commands.json')) == rows, 'COMPLETE_RETAINED_COMMAND_RESULT')
    outputs = {}; seconds = 0
    for row, args in zip(rows, expected):
        need(row.get('argv') == ['/usr/bin/docker', '--host=' + endpoint, *args]
             and type(row.get('expected')) is int and row['expected'] == 0 and row.get('passed') is True
             and type(row.get('exit')) is int and row['exit'] == 0, 'EXACT_RETAINED_COMMAND_ARGV')
        B.natural(row, 0); sup = row['supervision']
        need(finite(row.get('timeout_seconds')) and finite(row.get('supervision_cap_seconds'))
             and row['supervision_cap_seconds'] <= row['timeout_seconds'] <= resources['command_seconds']
             and type(sup.get('seconds')) in (int, float) and math.isfinite(sup['seconds'])
             and 0 <= sup['seconds'] < row['supervision_cap_seconds'] and type(sup.get('exit')) is int, 'ACTUAL_COMMAND_BOUNDS')
        seconds += sup['seconds']; output = {}
        for suffix, key in (('stdout', 'output_pin'), ('stderr', 'stderr_pin')):
            output[suffix] = B.read(root / 'commands' / (row['step'] + '.' + suffix), resources['max_output_bytes'], row[key])
        need(sum(map(len, output.values())) <= resources['max_output_bytes'], 'COMMAND_OUTPUT_BOUND')
        outputs[row['step']] = output['stdout']
    need(seconds <= resources['wall_seconds'], 'COMMAND_WALL_BOUND')
    image = P.decoded(outputs['image']); daemon = P.decoded(outputs['daemon'])
    need(type(image) is list and len(image) == 1 and image[0]['Id'] == intent['image']
         and image[0]['Architecture'] == 'arm64' and image[0]['Os'] == 'linux', 'ACTUAL_IMAGE_INSPECT')
    need(daemon.get('ID') == trial['owned_executor']['engine_id'] and daemon.get('OSType') == 'linux'
         and daemon.get('Architecture') in ('arm64', 'aarch64') and daemon.get('CgroupVersion') == '2'
         and type(daemon.get('NCPU')) is int and daemon['NCPU'] >= resources['cpus']
         and type(daemon.get('MemTotal')) is int and daemon['MemTotal'] >= resources['memory_bytes']
         and all(daemon.get(k) is True for k in ('MemoryLimit', 'SwapLimit', 'PidsLimit')), 'ACTUAL_DAEMON_INSPECT')
    need(not outputs['fresh-name'].strip() and outputs['create'].decode().strip() == cid
         and outputs['retire-query'].decode().split() == [cid]
         and not outputs['retire-after-name'].strip() and not outputs['retire-after-cid'].strip(), 'ACTUAL_CONTAINER_ID_AND_ABSENCE')
    for step in ('inspect-created', 'inspect-terminal', 'retire-inspect'):
        data = P.decoded(outputs[step]); need(type(data) is list and len(data) == 1, 'SINGLE_CONTAINER_INSPECTION')
        # The maintained producer receives tuples; JSON retention uses lists.
        B.inspect_container(data[0], dict(intent, mounts=[tuple(row) for row in mounts]))
        if step != 'inspect-created':
            need(data[0]['State']['Running'] is False and type(data[0]['State']['ExitCode']) is int
                 and data[0]['State']['ExitCode'] == 0 and data[0]['State']['OOMKilled'] is False, 'NATURAL_CONTAINER_RETIREMENT')


def static_artifacts(build_root, source, trial, profile_pin, expected, commands, deadline):
    """Replay the existing complete package validator, without executing Source."""
    build_root = H.ordinary(str(build_root))
    need(build_root.is_dir() and build_root != Path('/') and build_root != source
         and not build_root.is_relative_to(source) and not source.is_relative_to(build_root), 'COMPLETE_EXTERNAL_BUILD_ROOT')
    snapshot, inputs, artifacts = (build_root / n for n in ('control/source', 'inputs', 'artifacts'))
    need(all(p.is_dir() for p in (snapshot, inputs, artifacts)), 'COMPLETE_RETAINED_BUILD_REQUIRED')
    need(not (build_root / 'cleanup-HOLD.json').exists(), 'BUILD_CLEANUP_HOLD')
    retained = P.decoded(P.read(build_root / 'result.json'))
    need(retained.get('artifact') == expected and retained.get('profile_pin') == profile_pin
         and retained.get('commands') == commands, 'RETAINED_BUILD_RESULT_DIFFERS')
    need(P.decoded(P.read(build_root / 'commands/commands.json')) == commands, 'RETAINED_COMMANDS_DIFFER')
    for row in commands:
        for suffix, key in (('stdout', 'output_pin'), ('stderr', 'stderr_pin')):
            body = B.read(build_root / 'commands' / (row['step'] + '.' + suffix), 4 * 1024**2, row[key])
            need(H.pin(body) == row[key], 'RETAINED_COMMAND_STREAM_DIFFERS')
    for name, row in trial['materials'].items():
        raw = H.verify_reference(dict(path=str(snapshot / name), **row), cap=64 * 1024**2, deadline=deadline, body=True)
        need(raw == H.verify_reference(dict(path=str(source / name), **row), cap=64 * 1024**2, deadline=deadline, body=True), 'RETAINED_TRIAL_SOURCE_DIFFERS')
    for name in B.HELD:
        need(H.pin((MAIN / name).read_bytes()) == trial['materials'][name], 'TRUSTED_MAIN_STATIC_HELPER_DIFFERS')
    need({p.name for p in inputs.iterdir()} == B.RECIPE_FILES, 'COMPLETE_RETAINED_RECIPE_REQUIRED')
    for name in B.RECIPE_FILES:
        need(H.verify_reference(dict(path=str(inputs / name), **trial['materials'][B.RECIPE + name]),
             cap=64 * 1024**2, body=True) == (source / B.RECIPE / name).read_bytes(), 'RETAINED_RECIPE_DIFFERS')
    checks, helpers, guard = B.static_helpers(MAIN, trial)
    reviewed = checks.recipe(inputs / 'PKGBUILD')
    need(not reviewed['errors'], 'REVIEWED_RECIPE')
    inventory_name = next(n for n, r in trial['materials'].items() if r == trial['image']['inventory'])
    inventory = H.verify_reference(dict(path=str(snapshot / inventory_name), **trial['image']['inventory']), body=True)
    required = {'packages.lock', 'environment.txt', 'config.sha256', 'makepkg.conf', 'pacman.conf', 'generated.SRCINFO'}
    need(required <= {p.name for p in artifacts.iterdir()}, 'PARTIAL_PUBLIC_OUTPUT_IS_NOT_COMPLETE_BUILD')
    files = list(artifacts.iterdir()); need(len(files) <= 128, 'ARTIFACT_COUNT')
    bodies = {p.name: P.read(p, cap=64 * 1024**2) for p in files}
    need(sum(map(len, bodies.values())) <= 128 * 1024**2, 'ARTIFACT_BYTES')
    with tempfile.TemporaryDirectory(prefix='qt3-result-static-DATA-') as temporary:
        scratch = Path(temporary); (scratch / 'artifacts').mkdir(); (scratch / 'inputs').mkdir()
        for name, raw in bodies.items(): (scratch / 'artifacts' / name).write_bytes(raw)
        for name in B.RECIPE_FILES:
            (scratch / 'inputs' / name).write_bytes(P.read(inputs / name, cap=64 * 1024**2))
        report = B.validate_outputs(scratch / 'artifacts', inventory, reviewed, checks, helpers, guard,
                                    profile_pin['sha256'], deadline)
    need(report == expected, 'STATIC_PACKAGE_REPORT_DIFFERS')
    return report


def qualify(state, records, *, reader_pin, now_monotonic):
    exact(records, RECORDS, 'FIXED_RECORDS')
    raw = {k: H.verify_reference(v, cap=2 * 1024**2, body=True) for k, v in records.items()}
    values = {k: P.decoded(v) for k, v in raw.items()}
    o = values['observation']; exact(o, OBSERVATION, 'OBSERVATION_SCHEMA'); final(o)
    need(type(o['schema']) is int and o['schema'] == 1
         and o['kind'] == 'BANKSTOWN_QT3_RESULT_OBSERVATION_V1', 'OBSERVATION_KIND')
    c, d, r, source = (state[k] for k in ('context', 'delegation', 'request', 'root'))
    binding, nonce = c['binding'], c['nonce']
    need(o['binding'] == binding and o['nonce'] == nonce and o['source_lock'] == binding['source_lock']
         and o['request_pin'] == H.pin(H.encoded(r)) and o['context_pin'] == H.pin(H.encoded(c))
         and o['reader_pin'] == H.whole(reader_pin) and o['owner_pin'] == whole(d['programs']['owner'])
         and o['record_pins'] == {k: H.pin(v) for k, v in raw.items() if k != 'observation'}, 'EXTERNAL_READER_OWNER_BINDINGS')
    window = o['launcher_window']; exact(window, {'started_monotonic', 'finished_monotonic'}, 'LAUNCHER_WINDOW')
    start, finish, observed = window['started_monotonic'], window['finished_monotonic'], o['image_observed_monotonic']
    need(all(finite(v) for v in (start, finish, observed, now_monotonic))
         and start <= observed < finish <= now_monotonic and finish - start <= 4170, 'ACTUAL_4170_WINDOW')
    image = H.validate_image_receipt(raw['image'], records['image']['sha256'], now_monotonic=observed, verify_files=True)
    R.validate(image, P, now=observed)
    need(image['binding'] == binding and image['nonce'] == nonce and image['delegation_pin'] == r['delegation_pin']
         and Path(image['source']['root']) == source
         and image['catalog'] == state['inputs']['owner_inputs']['catalog']
         and o['expected_image'] == {'id': image['image']['id'], 'inventory': whole(image['image']['inventory'])}
         and o['expected_executor'] == image['executor']
         and image['executor']['code_pin'] == whole(d['programs']['image_executor'])
         and image['executor']['docker_endpoint'] == state['policy']['image_endpoint_template'].format(nonce=nonce)
         and observed <= finish <= now_monotonic < image['lifetime']['work_deadline_monotonic'], 'SELECTED_IMAGE_EXECUTOR')
    catalog = H.verify_reference(image['catalog'], cap=64 * 1024**2, body=True)
    inventory = H.verify_reference(image['image']['inventory'], body=True)
    joins = I.check(inventory, (MAIN / 'scripts/ci/bankstown-qt3-native-profile-v1/expected349.lock').read_bytes(), catalog)
    profile = values['profile_receipt']
    keys = {'schema', 'kind', 'status', 'image_receipt', 'admission', 'source', 'binding', 'nonce', 'delegation_pin',
            'image', 'catalog', 'filesystem', 'executor', 'lifetime', 'inventory_joins', 'frozen_consumers', 'profile', 'legal', 'key_freshness'} | set(H.FINAL)
    exact(profile, keys, 'PROFILE_RECEIPT'); final(profile)
    need(type(profile['schema']) is int and profile['schema'] == 1 and profile['kind'] == 'BANKSTOWN_QT3_PROFILE_DATA_V1'
         and profile['status'] == 'PASS_PASSIVE_PROFILE_DATA_ONLY' and profile['legal'] == profile['key_freshness'] == 'HELD'
         and profile['image_receipt'] == H.pin(raw['image']) and profile['admission'] == H.pin(raw['admission'])
         and whole(profile['profile']) == H.pin(raw['profile']) and profile['inventory_joins'] == joins
         and profile['frozen_consumers'] == {n: dict(bytes=v[0], sha256=v[1]) for n, v in P.PINS.items()}
         and all(profile[k] == image[k] for k in ('source', 'binding', 'nonce', 'delegation_pin', 'image', 'catalog', 'filesystem', 'executor', 'lifetime')), 'IMAGE_PROFILE_JOIN')
    stage = o['stage_window']
    exact(stage, {'profile_verified_monotonic', 'build_started_monotonic', 'build_finished_monotonic', 'admission_observed_epoch'}, 'STAGE_WINDOW')
    need(all(finite(v) for v in stage.values()) and type(stage['admission_observed_epoch']) is int
         and c['observed_epoch'] <= stage['admission_observed_epoch'] <= d['expires_epoch']
         and observed <= stage['profile_verified_monotonic'] <= stage['build_started_monotonic']
         <= stage['build_finished_monotonic'] <= finish, 'SAME_STAGE_LIFETIME')
    trial = A.validate_trial(raw['admission'], records['admission']['sha256'], now=stage['admission_observed_epoch'])
    need(trial['source'] == {k: image['source'][k] for k in ('commit', 'ref')}
         and trial['image'] == o['expected_image'] and trial['catalog'] == whole(image['catalog'])
         and trial['owned_executor'] == {k: image['executor'][k] for k in ('code_pin', 'docker_endpoint', 'engine_id')}
         and stage['build_started_monotonic'] + trial['resources']['wall_seconds'] + 90 < image['lifetime']['work_deadline_monotonic']
         and stage['build_finished_monotonic'] - stage['build_started_monotonic'] <= trial['resources']['wall_seconds'], 'TRIAL_IMAGE_EXECUTOR_JOIN')
    expected_profile = dict(schema=1, purpose='bankstown-1.1.0-5-native-toolchain', compiler_version='1.99.0',
        target='aarch64-unknown-linux-gnu', tools=trial['tool_paths'], files=trial['selected_files'], admission_pin=H.pin(raw['admission']),
        catalog_pin=trial['catalog'], image=trial['image'], legal='HELD', key_freshness='HELD', **B.FINAL)
    need(values['profile'] == expected_profile, 'FROZEN_PROFILE_TRIAL_JOIN')
    build = values['build']; final(build, B.FINAL)
    need(type(build.get('schema')) is int and build['schema'] == 1 and build['status'] == 'PASS_PRIVATE_TEST_BUILD_DATA_ONLY'
         and build['source'] == trial['source'] and build['image'] == trial['image']
         and build['admission_pin'] == H.pin(raw['admission']) and build['profile_pin'] == H.pin(raw['profile'])
         and build['owned_container_absence_verified'] is True and build['legal'] == build['key_freshness'] == 'HELD'
         and build['hardware_status'] == 'NOT RUN', 'COMPLETE_PRIVATE_BUILD')
    commands = build['commands']; need(type(commands) is list and tuple(v.get('step') for v in commands) == STEPS, 'COMPLETE_COMMANDS')
    for row in commands:
        need(type(row.get('exit')) is int and row['exit'] == 0 and row.get('argv', [])[:2] == ['/usr/bin/docker', '--host=' + image['executor']['docker_endpoint']], 'COMMAND_BINDING')
        B.natural(row, 0)
    pipeline, owner, executor, launcher = (values[k] for k in ('pipeline', 'owner', 'executor', 'launcher'))
    for value in (pipeline, owner, executor, launcher): final(value)
    need(type(pipeline.get('schema')) is int and pipeline['schema'] == 1 and pipeline.get('kind') == 'BANKSTOWN_QT3_OWNED_PIPELINE_DATA_V1'
         and pipeline.get('completed') is True and pipeline.get('binding') == binding and pipeline.get('nonce') == nonce
         and pipeline.get('image_receipt') == H.pin(raw['image']) and pipeline.get('profile_receipt') == H.pin(raw['profile_receipt'])
         and pipeline.get('profile') == profile['profile'] and pipeline.get('private_build_status') == build['status']
         and pipeline.get('image_lifetime') == 'EPHEMERAL_SAME_OWNED_DAEMON_UNTIL_CONTROLLER_RETIREMENT'
         and pipeline.get('legal') == pipeline.get('key_freshness') == 'HELD', 'OWNER_PIPELINE')
    builder_raw = (MAIN / O.BUILDER_MEMBER).read_bytes()
    need(H.pin(builder_raw) == O.BUILDER_PIN and builder_raw.count(O.DOCKER_BEFORE) == 1
         and pipeline.get('builder_projection') == dict(original=O.BUILDER_PIN,
             projected=H.pin(builder_raw.replace(O.DOCKER_BEFORE, O.DOCKER_AFTER)),
             seam='one Docker --host=<endpoint> argument; no receipt rewriting'), 'FROZEN_BUILDER_PROJECTION')
    facts = owner.get('executor_facts', {}); final(facts)
    need(owner.get('status') == 'DELEGATED_OWNER_RETURNED_DATA_ONLY' and owner.get('binding') == binding and owner.get('result') == pipeline
         and facts.get('api') == 'CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'
         and facts.get('binding') == binding and facts.get('nonce') == nonce and facts.get('stage') == 'qt3'
         and facts.get('domain_policy_pin') == c['policy_pin'] and facts.get('supervision_program_pin') == whole(d['programs']['owned_process'])
         and facts.get('native_architecture') == 'aarch64'
         and all(type(facts.get(k)) is int and facts[k] > 0 for k in ('uid', 'gid'))
         and all(facts.get(k) == image['executor'][k] for k in ('code_pin', 'engine_id', 'docker_endpoint'))
         and facts.get('owner_domain', {}).get('pid') == image['executor']['owner_pid']
         and facts.get('daemon_domain', {}).get('pid') == image['executor']['daemon_pid']
         and all(facts.get(k) is True for k in ('daemon_pidfd_held', 'whole_owner_deadline_enforced', 'daemon_deadline_enforced', 'exclusive_daemon')), 'OWNER_EXECUTOR_FACTS')
    cleanup = executor.get('cleanup', {})
    need(executor.get('status') == 'DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY' and executor.get('binding') == binding
         and executor.get('owner') == owner and executor.get('delegation_pin') == r['delegation_pin']
         and executor.get('policy_pin') == c['policy_pin'] and cleanup.get('errors') == []
         and cleanup.get('owned_storage_absent') is True and set(cleanup.get('services', {})) == {'owner', 'daemon'}, 'CONTROLLER_RETIREMENT')
    for role, row in cleanup['services'].items():
        need(row.get('unit') == 'cachy-current-' + nonce + '-' + role + '.service'
             and all(row.get(k) is True for k in ('empty_twice', 'pidfd_exited', 'natural'))
             and row.get('owner_residue_before_stop') is False, 'OWNED_SERVICE_ABSENCE')
    retirement = launcher.get('controller_retirement', {})
    need(launcher.get('status') == 'DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY' and launcher.get('binding') == binding
         and launcher.get('request_pin') == o['request_pin'] and launcher.get('cleanup') == dict(owned_storage_absent=True, error_count=0)
         and launcher.get('scope_absence') == dict(scope='cachy-current-controller-' + nonce + '.scope', empty_twice=True)
         and type(retirement.get('exit')) is int and retirement['exit'] == 0 and retirement.get('group_census') == 'EMPTY_TWICE'
         and retirement.get('reaped') is retirement.get('natural') is True, 'LAUNCHER_RETIREMENT')
    mount, retired = launcher.get('retained_input_custody', {}), o['retained_input_retirement']
    exact(retired, {'path', 'mount_id', 'absent_twice', 'observed_monotonic'}, 'INPUT_RETIREMENT')
    need(mount.get('path') == retired['path'] == r['staged_root'] and mount.get('mount_id') == retired['mount_id']
         and type(retired['mount_id']) is str and re.fullmatch('[1-9][0-9]*', retired['mount_id'])
         and mount.get('retirement_owner') == 'Root' and mount.get('retirement_observed_here') is False
         and mount.get('Root_acceptance') is None and retired['absent_twice'] is True
         and finite(retired['observed_monotonic']) and finish <= retired['observed_monotonic'] <= now_monotonic, 'EXTERNAL_INPUT_RETIREMENT')
    retained_commands(o['build_root'], trial, build, facts, H.pin(raw['profile']))
    static_artifacts(o['build_root'], source, trial, H.pin(raw['profile']), build['artifact'], commands,
                     min(time.monotonic() + 300, image['lifetime']['work_deadline_monotonic']))
    need(time.monotonic() < image['lifetime']['work_deadline_monotonic'], 'EVIDENCE_LIFETIME_EXPIRED')
    return dict(schema=1, kind='BANKSTOWN_QT3_HISTORICAL_RESULT_DATA_V1', status='PASS_COMPOSED_RESULT_DATA_ONLY',
                binding=binding, nonce=nonce, records={k: H.pin(v) for k, v in raw.items()}, inventory_joins=joins,
                native_acceptance=False, source='HELD', legal='HELD', key_freshness='HELD',
                exact_Qt_recipe_correspondence='HELD', platform='NOT_RUN', M2='NOT_RUN', **H.FINAL)
