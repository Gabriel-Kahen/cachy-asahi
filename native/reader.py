# SPDX-License-Identifier: MIT
"""Passive capsule DATA reader; refuse NULL selectors before opening capsule.

Symlink targets are ordinary DATA payloads. No capsule member is extracted,
imported or followed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import consumer_contract, load, need, pin, uv_policy
from capsule import open_capsule


def retained_failure_data(view, files, value, binding, map_sha256):
    """Cross-check bounded causal DATA only; success grants no native credit."""
    names = {'acquisition.json', 'key-import.log', 'bootstrap.log', 'signatures.json'}
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('status') == 'PASS_BOUNDED_BOOTSTRAP_FAILURE_DATA'
         and value.get('guard_code') == 'PUBLIC_SOURCE_VALIDATED'
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256,
         'same-source successful bounded bootstrap DATA retention required')
    authority = 'bootstrap-failure-retention.json'
    need(authority in files and files[authority]['kind'] == 'file'
         and pin(view.read(authority)) == {k: files[authority][k] for k in ('bytes', 'sha256')}
         and view.load(authority) == value, 'same authoritative retention receipt in actual capsule DATA')
    rows = value.get('files')
    need(type(rows) is dict and set(rows) == names and value.get('blocked_actor_logs') == [],
         'exact causal DATA allowlist; refused streams cannot qualify')
    retained = set()
    for name, row in rows.items():
        need(type(row) is dict and row.get('status') == 'RETAINED'
             and row.get('code') == 'PUBLIC_DATA_VALIDATED',
             'all four causal DATA files required for positive native matching')
        target = 'bootstrap-proof/bootstrap-' + name
        need(set(row) == {'status', 'code', 'public_path', 'kind', 'mode', 'source_mode', 'bytes', 'sha256'}
             and row['public_path'] == target and row['kind'] == 'file' and row['mode'] == 0o600
             and type(row['source_mode']) is int and 0 <= row['source_mode'] <= 0o777
             and type(row['bytes']) is int and 0 <= row['bytes'] <= (1024**2 if name == 'acquisition.json' else 16*1024**2)
             and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''),
             'exact bounded causal DATA target, source/public modes and pin')
        need(target in files and files[target]['kind'] == 'file' and files[target]['mode'] == row['mode']
             and {k: files[target][k] for k in ('bytes', 'sha256')} == {k: row[k] for k in ('bytes', 'sha256')}
             and pin(view.read(target)) == {k: row[k] for k in ('bytes', 'sha256')},
             'causal DATA receipt must match manifest and actual capsule bytes')
        retained.add(target)
    need({n for n in files if n in {'bootstrap-proof/bootstrap-' + name for name in names}} == retained,
         'complete exact retained causal DATA target set')
    acquired = view.load('bootstrap-proof/bootstrap-acquisition.json')
    need(type(acquired) is dict and type(acquired.get('schema_version')) is int and acquired['schema_version'] == 1
         and acquired.get('acquisition') == 'PASS' and acquired.get('signature_authentication') == 'NOT RUN'
         and acquired.get('counts') == {'total': 501, 'pass': 501, 'fail': 0, 'pending': 0}
         and all(type(n) is int for n in acquired['counts'].values())
         and type(acquired.get('inputs')) is dict and len(acquired['inputs']) == 501
         and all(type(row) is dict and row.get('status') == 'PASS' for row in acquired['inputs'].values()),
         'positive native matching requires original PASS acquisition for all501 inputs')


def retained_image_lifecycle(view, files, receipt, cleanup, binding, map_sha256):
    """Match local image/daemon observations to retained naturally retired actors."""
    ledger = receipt.get('image_ledger'); retirement = cleanup.get('image_retirement')
    for name, value in [('image-ledger.json', ledger), ('image-retirement.json', retirement)]:
        need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
             and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256,
             'same-source image lifecycle receipts required')
        need(name in files and files[name]['kind'] == 'file'
             and pin(view.read(name)) == {k: files[name][k] for k in ('bytes', 'sha256')}
             and view.load(name) == value, 'authoritative image lifecycle DATA differs')
    roles = ('base', 'tools'); label = 'org.cachy-asahi.native-developer'
    docker = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
    aliases = {role: 'native-developer-' + role + ':' + binding['token'] for role in roles}
    need(ledger.get('status') == 'PASS_FRESH_LOCAL_ALIAS_BASELINE' and ledger.get('actor_scope') == 'owner'
         and ledger.get('aliases') == aliases
         and ledger.get('baseline') == dict(aliases={role: [] for role in roles}, owned_image_ids=[])
         and type(ledger.get('created')) is dict and set(ledger['created']) == set(roles),
         'fresh two-role source-owned image baseline required')
    need(retirement.get('status') == 'PASS_EXACT_OWNED_IMAGE_ALIASES_RETIRED'
         and retirement.get('actor_scope') == 'retirement' and retirement.get('ledger') == ledger
         and retirement.get('final') == dict(aliases={role: [] for role in roles}, owned_image_ids=[])
         and retirement.get('codes') == [], 'actual final source-owned image retirement required')
    actors = {'owner': receipt.get('actors'), 'retirement': cleanup.get('actors')}
    need(all(type(rows) is list for rows in actors.values()), 'actual image actor scopes required')

    def actor_output(scope, index, argv):
        need(scope in actors and type(index) is int and 0 <= index < len(actors[scope]), 'exact image actor index required')
        row = actors[scope][index]
        need(type(row) is dict and row.get('argv') == argv and row.get('status') == 'PASS'
             and type(row.get('exit')) is int and row['exit'] == 0
             and all(row.get(key) is True for key in ('natural_exit', 'group_absent', 'exit_observed_via_waitpid', 'leader_held_until_group_inspection'))
             and row.get('ownership_lost') is False and row.get('forced_cleanup') is False
             and row.get('retirement') == 'REAPED', 'image observation requires source-owned naturally retired actor')
        name = row.get('public_log')
        need(name in files and files[name]['kind'] == 'file'
             and pin(view.read(name)) == row.get('log_pin')
             and row['log_pin'] == {k: files[name][k] for k in ('bytes', 'sha256')},
             'image observation requires actual retained actor log')
        return row, view.read(name).decode().strip()

    def query(context, index, args):
        checks = context.get('query_checks')
        need(type(checks) is list and type(index) is int and 0 <= index < len(checks), 'exact image query index required')
        check = checks[index]; argv = docker + args
        need(type(check) is dict and check.get('actor_scope') == context['actor_scope']
             and check.get('argv') == argv and check.get('status') == 'PASS'
             and check.get('code') == 'EXACT_RETIRED_ACTOR_STDOUT', 'successful exact image query reference required')
        actor, text = actor_output(context['actor_scope'], check.get('actor_index'), argv)
        need(check.get('log') == actor.get('log') and type(check.get('stdout_bytes')) is int
             and {'bytes': check['stdout_bytes'], 'sha256': check.get('stdout_sha256')} == pin(text.encode()),
             'image query stdout must match actual retained actor DATA')
        return text, check['actor_index']

    def listed(context, index, selector, expected):
        text, actor_index = query(context, index, ['image', 'ls', '--no-trunc', '-q', '--filter', selector])
        values = text.split()
        need(len(text.encode()) <= 4096 and len(values) <= 16 and len(set(values)) == len(values)
             and all(re.fullmatch('sha256:[0-9a-f]{64}', value) for value in values)
             and sorted(values) == expected, 'actual exact image query result differs')
        return actor_index

    def proof(context, value, role, allowed=None):
        expected = ledger['created'][role]['image_id']; alias = aliases[role]; indexes = value.get('query_indexes')
        need(type(indexes) is list and len(indexes) == 3 and all(type(i) is int for i in indexes)
             and indexes == list(range(indexes[0], indexes[0] + 3)), 'three ordered exact image proof queries required')
        observed = [listed(context, indexes[0], 'reference=' + alias, [expected])]; tags = None
        for index, selector in zip(indexes[1:], (alias, expected)):
            text, actor_index = query(context, index, ['image', 'inspect', selector]); observed.append(actor_index)
            need(len(text.encode()) <= 1024**2, 'bounded actual image inspect DATA required')
            rows = json.loads(text)
            need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'one actual image inspect row required')
            row = rows[0]; current = row.get('RepoTags'); labels = row.get('Config', {}).get('Labels')
            need(row.get('Id') == expected and row.get('Architecture') == 'arm64' and row.get('Os') == 'linux'
                 and type(labels) is dict and labels.get(label) == binding['token']
                 and labels.get(label + '.source') == binding['source'] and type(current) is list
                 and all(type(tag) is str for tag in current) and len(set(current)) == len(current)
                 and alias in current and set(current) <= (set(aliases.values()) if allowed is None else allowed),
                 'actual alias and ID inspections require owned identity without foreign tags')
            need(tags is None or tags == sorted(current), 'alias and immutable ID inspections differ'); tags = sorted(current)
        need(observed == sorted(set(observed)) and value.get('alias') == alias and value.get('image_id') == expected
             and value.get('repo_tags') == tags and value.get('token') == binding['token']
             and value.get('source') == binding['source'], 'image proof differs from actual ordered observations')
        return observed

    baseline = ledger.get('baseline_query_indexes')
    need(baseline == [0, 1, 2], 'all three initial image queries required')
    initial = [listed(ledger, baseline[i], 'reference=' + aliases[role], []) for i, role in enumerate(roles)]
    initial.append(listed(ledger, baseline[2], 'label=' + label + '=' + binding['token'], []))
    builds = {}; registrations = {}
    build_keys = ('argv', 'log', 'status', 'exit', 'natural_exit', 'group_absent', 'exit_observed_via_waitpid',
                  'leader_held_until_group_inspection', 'ownership_lost', 'forced_cleanup', 'retirement')
    for role, value in ledger['created'].items():
        need(value.get('alias') == aliases[role] and re.fullmatch('sha256:[0-9a-f]{64}', value.get('image_id') or ''),
             'registered exact source-built image identity required')
        index = value.get('build_actor_index'); argv = value.get('build', {}).get('argv')
        need(type(argv) is list and len(argv) == 16, 'exact source-owned image build argv required')
        prefix = (docker + ['build', '--no-cache', '--tag', aliases[role], '--label', label+'='+binding['token'],
                  '--label', label+'.source='+binding['source'], '--network=none', '--pull=false', '--platform=linux/arm64'] if role == 'base' else
                  docker + ['build', '--network=none', '--pull=false', '--no-cache', '--platform=linux/arm64', '--tag', aliases[role],
                  '--label', label+'='+binding['token'], '--label', label+'.source='+binding['source']])
        iid = Path(argv[-2]); directory = 'bootstrap' if role == 'base' else 'overlay'
        need(argv[:-3] == prefix and argv[-3] == '--iidfile' and iid.is_absolute() and '..' not in iid.parts
             and str(iid) == argv[-2] and iid.name == 'image-id' and iid.parent.name == directory
             and argv[-1] == str(iid.parent / 'context'), 'exact bounded source-owned image build command required')
        row, _ = actor_output('owner', index, argv)
        need(value['build'] == {k: row[k] for k in build_keys}
             and (role != 'base' or row['log'] == str(iid.parent / 'bootstrap.log')),
             'image registration must bind actual successful build actor')
        builds[role] = index; registrations[role] = proof(ledger, value.get('registration', {}), role,
                                                      {aliases['base']} if role == 'base' else None)
    checks = ledger.get('base_checks')
    need(type(checks) is list and len(checks) == 2
         and [row.get('phase') for row in checks] == ['before_overlay', 'after_overlay']
         and all(row.get('status') == 'PASS' for row in checks), 'local base proof before and after overlay required')
    before = proof(ledger, checks[0], 'base', {aliases['base']}); after = proof(ledger, checks[1], 'base')
    need(max(initial) < builds['base'] < min(registrations['base'])
         and max(registrations['base']) < min(before) and max(before) < builds['tools']
         and builds['tools'] < min(after) and builds['tools'] < min(registrations['tools']),
         'actual base alias proofs must bracket the actual overlay build')
    dockerfile = 'bootstrap-proof/overlay-Dockerfile'
    need(dockerfile in files and files[dockerfile]['kind'] == 'file'
         and pin(view.read(dockerfile)) == {k: files[dockerfile][k] for k in ('bytes', 'sha256')}
         and view.read(dockerfile).splitlines()[:1] == [('FROM ' + aliases['base']).encode()],
         'actual overlay Dockerfile must use verified local base alias')
    need(receipt.get('bootstrap', {}).get('image') == ledger['created']['base']['image_id']
         and receipt.get('consumer', {}).get('image') == ledger['created']['tools']['image_id'],
         'bootstrap and consumer must use source-registered image IDs')
    preflight = retirement.get('preflight_query_indexes')
    need(preflight == [0, 1, 2] and retirement.get('preflight') == dict(
         aliases={role: [ledger['created'][role]['image_id']] for role in roles},
         owned_image_ids=sorted({row['image_id'] for row in ledger['created'].values()})),
         'retirement must first observe exactly registered aliases and image IDs')
    for i, role in enumerate(roles):
        listed(retirement, preflight[i], 'reference=' + aliases[role], [ledger['created'][role]['image_id']])
    listed(retirement, preflight[2], 'label=' + label + '=' + binding['token'], retirement['preflight']['owned_image_ids'])
    removals = retirement.get('removals')
    need(type(removals) is list and len(removals) == 2
         and retirement.get('removed_aliases') == [aliases[role] for role in reversed(roles)],
         'both exact source-owned aliases must retire without force')
    removed_indexes = []
    for role, value in zip(reversed(roles), removals):
        observed = proof(retirement, value, role)
        _, removed = query(retirement, value.get('removal_query_index'), ['image', 'rm', aliases[role]])
        need(max(observed) < removed, 'alias removal must follow its exact ownership proof'); removed_indexes.append(removed)
    final = retirement.get('final_query_indexes')
    need(type(final) is dict and set(final) == {*roles, 'owned_image_ids'}, 'three independent final image observations required')
    final_rows = [listed(retirement, final[role], 'reference=' + aliases[role], []) for role in roles]
    final_rows.append(listed(retirement, final['owned_image_ids'], 'label=' + label + '=' + binding['token'], []))
    need(max(removed_indexes) < min(final_rows) and final_rows == sorted(set(final_rows)),
         'final image absence requires actual post-removal queries')
    selectors = set(aliases.values()) | {row['image_id'] for row in ledger['created'].values()}
    for context in (ledger, retirement):
        need(type(context.get('query_checks')) is list and len(context['query_checks']) <= 32,
             'finite image lifecycle query records required')
        indexes = []
        for i, check in enumerate(context['query_checks']):
            argv = check.get('argv'); need(type(argv) is list and argv[:2] == docker, 'fixed local image daemon required')
            args = argv[2:]
            allowed = (len(args) == 3 and args[:2] == ['image', 'inspect'] and args[2] in selectors
                       or len(args) == 3 and args[:2] == ['image', 'rm'] and args[2] in aliases.values()
                       or args[:6] == ['image', 'ls', '--no-trunc', '-q', '--filter', 'label='+label+'='+binding['token']] and len(args) == 6
                       or len(args) == 6 and args[:5] == ['image', 'ls', '--no-trunc', '-q', '--filter']
                       and args[5] in {'reference=' + value for value in aliases.values()})
            need(allowed, 'finite source-owned image query or no-force alias removal only')
            _, index = query(context, i, args); indexes.append(index)
        need(indexes == sorted(set(indexes)), 'each image check requires a distinct ordered actual actor')
    operations = cleanup.get('build_operations')
    need(type(operations) is list and len(operations) == 2
         and [row.get('role') for row in operations] == list(roles)
         and all(row.get('terminal') is True and row.get('actor') == actors['owner'][builds[row['role']]] for row in operations),
         'both source-owned builds require actual terminal actor evidence')

    def referenced(value, argv):
        indexes = [i for i, row in enumerate(actors['retirement']) if row == value]
        need(len(indexes) == 1, 'cleanup observation must reference one actual retirement actor')
        _, text = actor_output('retirement', indexes[0], argv)
        return text, indexes[0]

    containers = cleanup.get('container_retirement'); consumer = receipt.get('consumer', {}).get('container')
    need(type(containers) is list and 1 <= len(containers) <= 2 and re.fullmatch('[0-9a-f]{64}', consumer or ''),
         'actual stopped consumer retirement required')
    removed_containers = []; removal_rows = []
    for value in containers:
        ident = value.get('container'); before = value.get('before'); creation = value.get('creation')
        need(re.fullmatch('[0-9a-f]{64}', ident or '') and type(before) is dict and before.get('Id') == ident
             and type(creation) is dict and value.get('name') == before.get('Name')
             and before.get('Config', {}).get('Labels', {}).get(label) == binding['token']
             and before.get('Config', {}).get('Labels', {}).get(label + '.source') == binding['source']
             and before.get('State', {}).get('Running') is False, 'only exact owned inspected stopped containers may retire')
        text, inspected = referenced(value.get('inspect_actor'), docker + ['inspect', ident])
        need(json.loads(text) == [before], 'retirement container inspection must match actual retained DATA')
        if ident == consumer:
            need(creation == dict(kind='developer-id', proof=consumer)
                 and before['Name'] == '/developer-' + binding['token']
                 and before.get('Image') == ledger['created']['tools']['image_id'], 'exact source-created developer ID required')
            created = [i for i, row in enumerate(actors['owner']) if type(row.get('argv')) is list
                       and row['argv'][:5] == docker + ['create', '--name', 'developer-' + binding['token']]
                       and '--pull=never' in row['argv'] and '--network=none' in row['argv']
                       and ledger['created']['tools']['image_id'] in row['argv']]
            need(len(created) == 1, 'sole source-owned consumer create actor required')
            _, output = actor_output('owner', created[0], actors['owner'][created[0]]['argv'])
            need(output == consumer, 'consumer ID must be actual source-owned create output')
        else:
            expected = docker + ['run', '--name', 'probe-' + binding['token'], '--label', label+'='+binding['token'],
                '--label', label+'.source='+binding['source'], '--cpus=1', '--memory=128m', '--pids-limit=32',
                '--rm', '--pull=never', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--read-only', '--entrypoint=/bin/cat', ledger['created']['base']['image_id'], '/builder-packages.lock']
            need(creation.get('kind') == 'probe-command' and before['Name'] == '/probe-' + binding['token']
                 and before.get('Image') == ledger['created']['base']['image_id'], 'source-created probe identity required')
            indexes = [i for i, row in enumerate(actors['owner']) if row == creation.get('proof')]
            need(len(indexes) == 1, 'sole actual source-owned probe proof required'); actor_output('owner', indexes[0], expected)
        _, removed = referenced(value.get('remove_actor'), docker + ['rm', ident])
        need(inspected < removed, 'no-force removal requires prior stopped-container observation')
        removed_containers.append(ident); removal_rows.append(removed)
    need(len(set(removed_containers)) == len(removed_containers) and consumer in removed_containers,
         'actual consumer must retire once')
    absence = cleanup.get('daemon_absence')
    need(type(absence) is dict and set(absence) == {'containers', 'images'}, 'independent final daemon observations required')
    final_daemon = []
    for key, args in [('containers', ['ps', '-aq', '--no-trunc', '--filter', 'label='+label+'='+binding['token']]),
                      ('images', ['image', 'ls', '--no-trunc', '-q', '--filter', 'label='+label+'='+binding['token']])]:
        value = absence[key]
        need(type(value) is dict and value.get('output') == '', 'final daemon observation must report empty output')
        text, index = referenced(value.get('actor'), docker + args)
        need(text == '', 'final daemon absence must be actual empty retained output'); final_daemon.append(index)
    need(max(removal_rows + final_rows) < min(final_daemon) and final_daemon == sorted(set(final_daemon)),
         'final daemon absence must follow actual container and image retirements')


def validate(capsule_path, expected):
    need(type(expected) is dict and set(expected) == {'source', 'ref', 'run', 'map_sha256'}
         and re.fullmatch('[0-9a-f]{40}', expected.get('source') or '')
         and isinstance(expected.get('ref'), str) and expected['ref'].startswith('refs/heads/codex/')
         and re.fullmatch('[1-9][0-9]*', expected.get('run') or '')
         and re.fullmatch('[0-9a-f]{64}', expected.get('map_sha256') or ''), 'NULL/unbound actual native evidence refused before reading')
    view = open_capsule(capsule_path)
    binding = {k: expected[k] for k in ('source', 'ref', 'run')}
    binding.update(attempt=1, token=hashlib.sha256((binding['source'] + ':' + binding['ref'] + ':' + binding['run']).encode()).hexdigest()[:24])
    manifest = view.load('artifacts.json')
    need(manifest['schema'] == 1 and manifest['binding'] == binding
         and manifest['source_map_sha256'] == expected['map_sha256'], 'actual binding differs')
    files = manifest['files']
    need(type(files) is dict and all(type(row.get('bytes')) is int and row['bytes'] >= 0
         and re.fullmatch('[0-9a-f]{64}', row.get('sha256') or '') for row in files.values()), 'typed artifact pins')
    need(0 < len(files) <= 3000 and sum(row['bytes'] for row in files.values()) <= 32*1024**2, 'bounded artifact namespace')
    view.verify_manifest(manifest)
    if 'provision-diagnostic.json' in files:
        diagnostic = view.load('provision-diagnostic.json')
        need(diagnostic['binding'] == binding and diagnostic['source_map_sha256'] == expected['map_sha256']
             and diagnostic['status'] == 'DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY'
             and diagnostic['native'] == diagnostic['GPG'] == diagnostic['ALPM'] == 'NOT_RUN', 'actual DATA diagnostic only')
        return dict(status='VALIDATED_INPUT_PROVISIONING_DIAGNOSTIC_NOT_NATIVE', binding=binding, native='NOT_RUN', physical_M2='NOT_RUN')
    receipt = view.load('receipt.json'); cleanup = view.load('cleanup.json')
    retained_failure_data(view, files, receipt.get('bootstrap_failure_data'), binding, expected['map_sha256'])
    retained_image_lifecycle(view, files, receipt, cleanup, binding, expected['map_sha256'])
    need(receipt['binding'] == binding and receipt['source_map_sha256'] == expected['map_sha256']
         and receipt['status'] == 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY'
         and cleanup['status'] == 'PASS_EXACT_OWNED_RESOURCES_RETIRED', 'all native components plus actual resource retirement required')
    runner = view.load('bootstrap-proof/bootstrap-runner.json')
    need(runner['kernel']['machine'] in ('aarch64', 'arm64') and runner['docker_server_arch'] in ('aarch64', 'arm64')
         and runner['commit'] == binding['source'] and runner['run_id'] == binding['run']
         and runner['docker_endpoint'] in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
         and type(runner['page_size']) is int and runner['page_size'] > 0, 'actual native host/local daemon provenance')
    before = view.load('consumer-inspect.json'); after = view.load('consumer-after.json')
    for row in (before, after):
        need(row['Id'] == receipt['consumer']['container'], 'retained exact consumer ID')
        consumer_contract(row, binding, receipt['consumer']['image'], receipt['source_root'], receipt['output_root'], runner['uid'], runner['gid'])
    need(after['State'] == receipt['consumer']['state'] and after['State']['Running'] is False
         and after['State']['ExitCode'] == 0 and after['State']['Status'] == 'exited', 'actual completed consumer daemon state')
    phases = receipt['provisioning']
    need(phases['proof']['status'] == 'PASS_EXACT_PUBLISHED_SOURCE_PROOF_ONLY'
         and phases['transport']['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and phases['cache']['status'] == 'PASS_EIGHT_INPUT_CACHE_DATA_ONLY', 'complete hosted source and input DATA provisioning')
    for phase in phases.values():
        need(phase['binding'] == binding and phase['source_map_sha256'] == expected['map_sha256'], 'all provisioning same exact source and run')
    for row in phases['proof']['actors'] + phases['transport']['actors'] + receipt['actors'] + cleanup['actors']:
        need(row.get('public_log') in files and files[row['public_log']]['kind'] == 'file', 'actor log must be a retained ordinary artifact')
        need(row['status'] == 'PASS' and row['exit'] == 0 and row['natural_exit'] is True
             and row['group_absent'] is True and row['retirement'] == 'REAPED'
             and row['exit_observed_via_waitpid'] is True and row['ownership_lost'] is False
             and row['forced_cleanup'] is False and row['leader_held_until_group_inspection'] is True
             and pin(view.read(row['public_log'])) == row['log_pin'], 'direct owned wait and retained actor output required')
    guest = view.load('journey/result.json')
    need(guest['status'] == receipt['status'] and guest['architecture'] == 'aarch64'
         and guest['packages'] == receipt['input_inventory'] and guest['physical_M2'] == 'NOT_RUN'
         and guest['native_16K'] == 'NOT_QUALIFIED', 'actual guest identity and non-hardware boundary')
    need(guest['python']['status'] == 'PASS_LOCAL_PYTHON_PEP517_WORKFLOW'
         and guest['python']['build_protocol'] == 'FORCE_PEP517_PRIVATE_PINNED_UV_BUILD_NO_BUILD_ISOLATION_NO_INDEX'
         and guest['extension']['status'] == 'PASS_LOCAL_COMPILED_PYTHON_WORKFLOW'
         and set(guest['build_systems']['project_workflows']) == {'cmake', 'meson'}
         and {r['status'] for r in guest['build_systems']['project_workflows'].values()} == {'PASS_REAL_PROJECT_WORKFLOW'}, 'all component outcomes including actual PEP517')
    for name, feature in [('python', guest['python']), ('extension', guest['extension']), ('build-systems', guest['build_systems'])]:
        need(feature['commands'], 'actual feature commands')
        for row in feature['commands']:
            log = 'journey/' + name + '/' + row['log']
            need(log in files and files[log]['kind'] == 'file' and pin(view.read(log)) == row['log_pin'], 'raw feature command log pin differs')
            state = row['supervision']
            need(row['success'] is True and state['reaped'] is True and state['ownership'] == 'REAPED'
                 and state['group_census'] == 'EMPTY_TWICE' and state['output_complete'] is True
                 and state['error'] is None and not state['timeout'] and not state['signals'], 'feature owned retirement required')
    builds = [row['argv'] for row in guest['python']['commands'] if 'build' in row['argv']]
    need(builds and all('--force-pep517' in row and '--no-build-isolation' in row and '--offline' in row and '--no-index' in row for row in builds), 'actual forced offline PEP517 argv')
    need(guest['python']['installed_backend']['identity']['version'] == '0.11.28'
         and guest['python']['installed_backend']['identity']['builtin_frontend'] is False, 'real separate backend import identity')
    policy = uv_policy(Path(__file__).resolve().parents[1])
    frontend = next(row for row in policy['artifacts'] if row['role'] == 'frontend')
    backend = next(row for row in policy['artifacts'] if row['role'] == 'backend')
    need(guest['python']['frontend']['file'] == {k:frontend['member'][k] for k in ('bytes','sha256')}
         and guest['python']['backend'] == backend, 'exact source-pinned frontend and separate backend receipt')
    installed = guest['python']['installed_backend']
    for name, expected_file in installed['files'].items():
        need(name.startswith('/out/journey/python/venv/'), 'backend receipt path confined to private venv')
        relative = name.removeprefix('/out/')
        need(relative in files and files[relative]['kind'] == 'file'
             and {k:files[relative][k] for k in ('bytes','sha256')} == expected_file, 'retained backend installation bytes')
    for member in backend['verified_members']:
        target = installed['identity']['backend'] if member['name'].endswith('.data/scripts/uv-build') else str(Path(installed['identity']['module']).parent / member['name'].removeprefix('uv_build/'))
        need(installed['files'].get(target) == {k:member[k] for k in ('bytes','sha256')}, 'actual backend binary/shim equals original wheel payload')
    return dict(status='VALIDATED_NATIVE_DEVELOPER_COMPONENT_EVIDENCE_ONLY', binding=binding,
                python_wheel='ACTUAL_PEP517_COMPONENT_PASS', native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', release='NOT_ADMITTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule', type=Path, required=True, help='ordinary public-tree.tar; directory ingress is unsupported')
    parser.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.capsule, load(args.binding)), sort_keys=True))
