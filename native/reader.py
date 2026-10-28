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
from privacy_diagnostics import validate_refusal
from safe_diagnostic import check_consumer


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
         and view.read(dockerfile).splitlines()[:1] == [('FROM ' + aliases['base'] + (' AS security-dependencies' if receipt.get('operation') == 'security-alpm-v1' else '')).encode()],
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


def retained_consumer_diagnostic(view, files, receipt, binding, map_sha256, positive=False):
    """Match original consumer actor DATA; failure/refusal grants no native credit."""
    value = receipt.get('consumer_diagnostic'); name = 'consumer-diagnostic.json'
    if value is None:
        need(not positive and name not in files, 'positive native matching requires original consumer diagnostic')
        return dict(status='ABSENT_CONSUMER_DIAGNOSTIC_DATA_ONLY', positive_candidate=False)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256
         and value.get('native') == 'NOT_ADMITTED' and value.get('physical_M2') == 'NOT_RUN',
         'same-source original consumer diagnostic required')
    need(name in files and files[name]['kind'] == 'file' and files[name]['bytes'] <= 512*1024
         and pin(view.read(name)) == {key: files[name][key] for key in ('bytes', 'sha256')}
         and view.load(name) == value, 'authoritative consumer diagnostic DATA differs')
    if value.get('status') == 'REFUSED_CONSUMER_ACTOR_DATA_GUARD':
        need(not positive and set(value) == {'schema', 'status', 'binding', 'source_map_sha256', 'actor_index',
             'container', 'reason', 'native', 'physical_M2'}
             and value.get('reason') == 'ORIGINAL_CONSUMER_DIAGNOSTIC_UNAVAILABLE_OR_PRIVATE',
             'consumer diagnostic refusal is fixed metadata only')
        return dict(status='REFUSED_CONSUMER_DIAGNOSTIC_DATA_ONLY', positive_candidate=False)
    need(value.get('status') == 'ORIGINAL_CONSUMER_ACTOR_DATA_ONLY'
         and set(value) == {'schema', 'status', 'binding', 'source_map_sha256', 'actor_index', 'container', 'argv',
                           'actor', 'original_error', 'log', 'native', 'physical_M2'},
         'exact original consumer diagnostic schema required')
    rows = receipt.get('actors'); index = value.get('actor_index'); container = value.get('container')
    need(type(rows) is list and type(index) is int and 0 <= index < len(rows)
         and re.fullmatch('[0-9a-f]{64}', container or ''), 'exact original consumer actor selection required')
    row = rows[index]; argv = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'start', '-a', container]
    fields = ('status', 'exit', 'natural_exit', 'group_absent', 'retirement', 'exit_observed_via_waitpid',
              'ownership_lost', 'forced_cleanup', 'leader_held_until_group_inspection')
    work = Path(receipt['output_root']).parent
    need(type(row) is dict and row.get('argv') == argv and value.get('argv') == argv
         and work.is_absolute() and '..' not in work.parts and row.get('log') == str(work / 'actors' / ('%04d.log' % index))
         and value.get('actor') == {key: row.get(key) for key in fields},
         'consumer diagnostic must match exact source-owned original start actor')
    log = value.get('log'); target = row.get('public_log')
    need(type(log) is dict and set(log) == {'original_pin', 'offset', 'complete', 'bytes', 'sha256', 'text'}
         and target in files and files[target]['kind'] == 'file' and files[target]['bytes'] <= 16*1024**2,
         'consumer diagnostic requires bounded retained original actor log')
    raw = view.read(target)
    need(pin(raw) == log['original_pin'] == row.get('log_pin') == {key: files[target][key] for key in ('bytes', 'sha256')},
         'consumer diagnostic original log pin differs from actual DATA')
    private = (b'-----BEGIN', b'PRIVATE KEY', b'OPENSSH PRIVATE', b'CACHY_OLD_FOUR_', b'CACHY_RETAINED_',
               b'Authorization:', b'authorization:', b'ghp_', b'github_pat_')
    private_marker = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)

    def safe(raw):
        need(not any(marker in raw for marker in private) and not private_marker.search(raw),
             'private consumer diagnostic DATA refused')
        text = raw.decode('utf-8')
        need(not any(ord(c) < 32 and c not in '\n\r\t' for c in text), 'control consumer diagnostic DATA refused')
        return text

    safe(raw); offset = max(0, len(raw) - 64*1024)
    while offset < len(raw) and raw[offset] & 0xc0 == 0x80:
        offset += 1
    window = raw[offset:]
    need(type(log['offset']) is int and log['offset'] == offset and type(log['complete']) is bool
         and log['complete'] is (offset == 0) and type(log['bytes']) is int
         and {key: log[key] for key in ('bytes', 'sha256')} == pin(window) and log['text'] == safe(window),
         'consumer diagnostic must be exact bounded UTF-8 original suffix')
    error = value['original_error']
    need(error is None or type(error) is dict and set(error) == {'type', 'message'}
         and type(error['type']) is str and 0 < len(error['type']) <= 128
         and type(error['message']) is str and len(error['message']) <= 2048,
         'bounded original consumer exception metadata required')
    if error is not None:
        safe(error['message'].encode())
    candidate = (error is None and row.get('status') == 'PASS' and type(row.get('exit')) is int and row['exit'] == 0
                 and all(row.get(key) is True for key in ('natural_exit', 'group_absent', 'exit_observed_via_waitpid', 'leader_held_until_group_inspection'))
                 and row.get('retirement') == 'REAPED' and row.get('ownership_lost') is False and row.get('forced_cleanup') is False)
    need(not positive or candidate and receipt.get('consumer', {}).get('container') == container,
         'positive consumer matching requires original zero-exit natural retirement without exception')
    return dict(status='VALIDATED_ORIGINAL_CONSUMER_ACTOR_DATA_ONLY', positive_candidate=candidate,
                actor_exit=row.get('exit'), container=container)


def retained_public_projection(view, files, binding, map_sha256):
    """Require a closed finite DATA projection, preserving every reader-required leaf."""
    name = 'public-projection.json'
    need(name in files and files[name]['kind'] == 'file', 'source-owned finite projection receipt required')
    value = view.load(name)
    producers = {
        'native/python_backend.py': 'ef300afa53a9480dd2605ee58d0bd18df6569acb6483d55494c6b9c696a96a31',
        'scripts/workflows/python_development.py': '3587267a38e77e9ca93301accf7fe0c6d73f5664320ee11635b0c17734e3004b',
        'scripts/workflows/python_extension.py': 'cdb46ca82ec8d45923361cb190cf2cc426b1bf3587eb4c9fd4cef76d91dd5b36',
        'scripts/workflows/developer_build_systems.py': '8c5025f3d748fb2e5aebb304310852158ebaac0bcaf9ef44cad8676ed5963fbc',
        'scripts/workflows/developer_workflow.py': '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba',
        'native/uv-inputs.json': 'b61aaff24cc354fc5946af07afc7a088587d52987081ea993e847270cfda94d3'}
    host = {'transport-diagnostic.json', 'transport-proof.json', 'receipt.json', 'cleanup.json', 'source-proof.json', 'consumer-inspect.json', 'consumer-after.json',
            'consumer-diagnostic.json', 'image-ledger.json', 'image-retirement.json', 'bootstrap-failure-retention.json', 'provision-diagnostic.json', 'build-summary.json'}
    bootstrap = {phase + '-' + leaf for phase in ('bootstrap', 'overlay') for leaf in
                 ('packages.lock', 'signatures.json', 'bootstrap.json', 'cache-checksums.json', 'Dockerfile', 'runner.json')}
    bootstrap |= {'bootstrap-acquisition.json', 'bootstrap-key-import.log', 'bootstrap-bootstrap.log'}
    reports = {'python': {'result.json', 'project.json', 'commands.json'},
               'extension': {'result.json', 'project.json', 'commands.json'},
               'build-systems': {'result.json', 'project-cmake.json', 'project-meson.json', 'installed-cmake.json', 'installed-meson.json', 'commands.json'}}
    private = {'python': {'home', 'tmp', 'project', 'venv', 'cache', 'dist', 'snapshots'},
               'extension': {'home', 'tmp', 'extension-project', 'snapshots'},
               'build-systems': {'home', 'tmp', 'cmake-project', 'meson-project', 'sources'}}
    site = 'lib/python3.14/site-packages/'; dist = 'uv_build-0.11.28.dist-info/'
    backend = {'bin/uv-build'} | {site + 'uv_build/' + leaf for leaf in ('__init__.py', '__main__.py', 'py.typed')}
    backend |= {site + dist + leaf for leaf in ('METADATA', 'WHEEL', 'RECORD', 'INSTALLER', 'REQUESTED', 'direct_url.json',
                'uv_cache.json', 'licenses/LICENSE-APACHE', 'licenses/LICENSE-MIT', 'sboms/uv-build.cyclonedx.json')}
    log_pattern = r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log'
    private_marker = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('status') == 'PASS_FINITE_SOURCE_PUBLIC_DATA_PROJECTION'
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256
         and value.get('source_producers') == producers
         and value.get('omitted_private_scopes') == sorted('journey/' + feature + '/' + part for feature, parts in private.items() for part in parts)
         and value.get('original_output_unchanged') is True and value.get('omitted_private_trees_walked') is False
         and value.get('privacy') == 'Selected text/JSON/log ASCII private-key,SSH,token,secret-env marker refusal; exact source-pinned backend executable exempt from text scanning'
         and value.get('scope') == 'Fixed reports, raw referenced command logs and exact backend files only; raw snapshots and remaining private project/build/home/tmp/venv/cache trees not retained',
         'same-source exact finite projection and explicit omission scope required')
    need(pin(view.read(name)) == {key: files[name][key] for key in ('bytes', 'sha256')}, 'projection receipt actual bytes differ')
    selected = value.get('selected')
    need(type(selected) is dict and 0 < len(selected) <= 2998 and set(files) == set(selected) | {name}
         and ('receipt.json' in selected) != ('provision-diagnostic.json' in selected),
         'closed finite projection leaf set and sole authority required')
    for target, row in selected.items():
        parts = target.split('/'); allowed = target in host or target in {'journey/result.json', 'journey/build-summary.json'}
        if len(parts) == 2:
            allowed |= (parts[0] == 'actor-logs' and re.fullmatch(r'[0-9]{4}\.log', parts[1]) is not None
                        or parts[0] == 'provision-logs' and re.fullmatch(r'(?:proof\.json|input-transport-owner\.json|input-cache-owner\.json)-[0-9]{3}\.log', parts[1]) is not None
                        or parts[0] == 'bootstrap-proof' and parts[1] in bootstrap
                        or parts[0] == 'transport-proof' and re.fullmatch(r'receipt\.json|[0-9]{4}\.(stdout|stderr)', parts[1]) is not None)
        if len(parts) == 3 and parts[0] == 'journey' and parts[1] in reports:
            allowed |= parts[2] in reports[parts[1]] or re.fullmatch(log_pattern, parts[2]) is not None
        if target.startswith('journey/python/venv/'):
            allowed |= target.removeprefix('journey/python/venv/') in backend
        need(allowed and type(row) is dict and set(row) == {'kind', 'mode', 'source_mode', 'bytes', 'sha256'}
             and row['kind'] == 'file' and type(row['mode']) is int and row['mode'] == 0o600
             and type(row['source_mode']) is int and 0 <= row['source_mode'] <= 0o777
             and type(row['bytes']) is int and 0 <= row['bytes'] <= 16*1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'finite ordinary projected evidence leaf required')
        need(files[target] == {key: row[key] for key in ('kind', 'mode', 'bytes', 'sha256')}
             and pin(view.read(target)) == {key: row[key] for key in ('bytes', 'sha256')},
             'projection selected pin and modes must match manifest and actual DATA')
        if target == 'journey/python/venv/bin/uv-build':
            need(pin(view.read(target)) == dict(bytes=3310128, sha256='82cf8b50be166cf5aab7eddddd0c27535b59cf9b34c4abc9443acacb1256f10c'),
                 'only exact source-pinned backend executable may bypass text scanning')
        else:
            need(not private_marker.search(view.read(target)), 'private marker in projected public DATA refused')
    guest = view.load('journey/result.json') if 'journey/result.json' in selected else None
    for feature in reports:
        prefix = 'journey/' + feature + '/'; report_name = prefix + 'result.json'
        actual_logs = {target for target in selected if target.startswith(prefix) and re.fullmatch(log_pattern, target[len(prefix):])}
        if report_name not in selected:
            need(not actual_logs, 'projected feature logs require original feature result')
            continue
        report = view.load(report_name); commands = report.get('commands', [])
        need(type(commands) is list and len(commands) <= 1000, 'finite projected original feature command list required')
        wanted = set()
        for command in commands:
            leaf = command.get('log')
            need(type(leaf) is str and re.fullmatch(log_pattern, leaf) and prefix + leaf not in wanted,
                 'finite unique projected feature log names required')
            target = prefix + leaf; wanted.add(target)
            need(target in selected and {key: selected[target][key] for key in ('bytes', 'sha256')} == command.get('log_pin'),
                 'all original feature raw command logs must be projected')
        need(actual_logs == wanted, 'closed original feature log projection required')
        command_file = prefix + 'commands.json'
        need(not commands or command_file in selected, 'actual feature command list receipt must be projected')
        if command_file in selected:
            need(view.load(command_file) == commands, 'projected standalone and feature command lists differ')
        if type(guest) is dict and guest.get('status') == 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY':
            need(guest.get('build_systems' if feature == 'build-systems' else feature) == report,
                 'positive guest and separately retained feature results differ')
        if feature == 'python':
            installed = report.get('installed_backend', {}).get('files', {})
            need(type(installed) is dict and len(installed) <= len(backend), 'finite projected installed backend map required')
            wanted_backend = set()
            for path, expected_file in installed.items():
                need(type(path) is str and path.startswith('/out/journey/python/venv/')
                     and path.removeprefix('/out/journey/python/venv/') in backend, 'source wheel layout backend leaf required')
                target = path.removeprefix('/out/'); wanted_backend.add(target)
                need(target in selected and {key: selected[target][key] for key in ('bytes', 'sha256')} == expected_file,
                     'every original installed backend file must be projected')
            need({target for target in selected if target.startswith('journey/python/venv/')} == wanted_backend,
                 'exact installed backend evidence projection required')
    return dict(status='VALIDATED_FINITE_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))



def build_summary_document(value, map_sha256):
    """Fixed map-bound scalar DATA only; never accept raw unknown result values."""
    tools = ('cmake', 'ctest', 'meson', 'ninja', 'cc', 'c++'); projects = ('cmake', 'meson')
    aggregate = {'PASS_AVAILABLE_LOCAL_WORKFLOWS', 'NOT_RUN_NO_BUILD_SYSTEM', 'FAIL', 'UNKNOWN', 'ABSENT'}
    project_status = {'PASS_REAL_PROJECT_WORKFLOW', 'NOT_RUN', 'FAIL', 'RUNNING', 'UNKNOWN', 'ABSENT'}
    tool_status = {'PRESENT', 'MISSING', 'UNKNOWN', 'ABSENT'}
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('source_map_sha256') == map_sha256, 'build summary exact map binding required')
    if value.get('status') == 'REFUSED_BUILD_SYSTEM_SUMMARY_DATA':
        need(set(value) == {'schema', 'status', 'source_map_sha256', 'reason'}
             and value['reason'] == 'BOUNDED_BUILD_STATUS_DATA_UNAVAILABLE', 'fixed build summary refusal only')
        return False
    need(set(value) == {'schema', 'status', 'source_map_sha256', 'aggregate', 'projects', 'tools', 'observed_projects',
                       'unexpected_project_keys', 'original_result_pin', 'command_logs'}
         and value['status'] == 'BUILD_SYSTEM_SUMMARY_DATA_ONLY' and type(value['aggregate']) is str
         and value['aggregate'] in aggregate and type(value['projects']) is dict and set(value['projects']) == set(projects)
         and type(value['tools']) is dict and set(value['tools']) == set(tools)
         and all(type(status) is str and status in tool_status for status in value['tools'].values()),
         'fixed build summary scalar schema required')
    need(type(value['observed_projects']) is dict and set(value['observed_projects']) == set(projects)
         and all(type(flag) is bool for flag in value['observed_projects'].values())
         and type(value['unexpected_project_keys']) is bool, 'fixed build summary project presence flags required')
    for row in value['projects'].values():
        need(type(row) is dict and set(row) == {'status', 'missing', 'missing_unknown'}
             and type(row['status']) is str and row['status'] in project_status
             and type(row['missing']) is dict and set(row['missing']) == set(tools)
             and all(type(flag) is bool for flag in row['missing'].values()) and type(row['missing_unknown']) is bool,
             'fixed build project status and missing-tool flags required')
    def typed_pin(row, cap):
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int
             and 0 <= row['bytes'] <= cap and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'bounded original build diagnostic pin required')
    typed_pin(value['original_result_pin'], 16*1024**2)
    need(type(value['command_logs']) is list and len(value['command_logs']) <= 1000, 'finite original build log pins required')
    names = set()
    for row in value['command_logs']:
        need(type(row) is dict and set(row) == {'log', 'pin'} and type(row['log']) is str
             and re.fullmatch(r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log', row['log'])
             and row['log'] not in names, 'fixed unique source build log names required')
        names.add(row['log']); typed_pin(row['pin'], 256*1024)
    raw = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    private = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
    need(len(raw) <= 512*1024 and not private.search(raw) and not any(marker in raw for marker in
         (b'-----BEGIN', b'PRIVATE KEY', b'OPENSSH PRIVATE', b'CACHY_OLD_FOUR_', b'CACHY_RETAINED_', b'Authorization:', b'authorization:', b'ghp_', b'github_pat_')),
         'bounded privacy-safe build whitelist DATA required')
    return True


def bound_build_summary(value, binding, map_sha256):
    need(type(value) is dict and set(value) == {'schema', 'status', 'binding', 'source_map_sha256', 'guest_summary_pin', 'guest_summary'}
         and type(value['schema']) is int and value['schema'] == 1 and value['status'] == 'BOUND_BUILD_SUMMARY_DATA_ONLY'
         and value['binding'] == binding and value['source_map_sha256'] == map_sha256, 'same-source bound build summary required')
    row = value['guest_summary_pin']
    need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int
         and 0 <= row['bytes'] <= 512*1024 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'bounded original guest build-summary pin required')
    return build_summary_document(value['guest_summary'], map_sha256)


def retained_build_summary(view, files, binding, map_sha256, positive=False):
    names = {'build-summary.json', 'journey/build-summary.json'}
    if not names & set(files):
        need(not positive, 'positive native matching requires build summary')
        return dict(status='ABSENT_BUILD_SUMMARY_DATA_ONLY', positive_candidate=False)
    need(names <= set(files) and all(files[name]['kind'] == 'file' and files[name]['bytes'] <= 512*1024 for name in names),
         'both exact original and host-bound build summaries required')
    value = view.load('build-summary.json'); available = bound_build_summary(value, binding, map_sha256)
    for name in names:
        need(pin(view.read(name)) == {key: files[name][key] for key in ('bytes', 'sha256')}, 'actual retained build-summary bytes differ')
    summary = value['guest_summary']
    need(pin(view.read('journey/build-summary.json')) == value['guest_summary_pin']
         and view.load('journey/build-summary.json') == summary, 'bound summary must match unchanged original guest DATA')
    if not available:
        need(not positive, 'refused build summary grants no native credit')
        return dict(status='REFUSED_BUILD_SUMMARY_DATA_ONLY', positive_candidate=False)
    result_name = 'journey/build-systems/result.json'
    need(result_name in files and files[result_name]['kind'] == 'file'
         and pin(view.read(result_name)) == summary['original_result_pin']
         and summary['original_result_pin'] == {key: files[result_name][key] for key in ('bytes', 'sha256')},
         'original build result pin must match actual retained bytes')
    result = view.load(result_name); tools = ('cmake', 'ctest', 'meson', 'ninja', 'cc', 'c++'); projects = ('cmake', 'meson')
    rows = result.get('project_workflows', {}); tool_rows = result.get('tools', {})
    need(type(rows) is dict and type(tool_rows) is dict, 'original build result project/tool maps required')
    def status(value, allowed, present=True):
        return value if type(value) is str and value in allowed else 'UNKNOWN' if present else 'ABSENT'
    normalized = {}
    for name in projects:
        row = rows.get(name, {}); row = row if type(row) is dict else {}
        missing = row.get('missing', []); valid = type(missing) is list and all(type(item) is str for item in missing)
        normalized[name] = dict(status=status(row.get('status'), {'PASS_REAL_PROJECT_WORKFLOW', 'NOT_RUN', 'FAIL', 'RUNNING', 'UNKNOWN', 'ABSENT'}, name in rows),
            missing={tool: bool(valid and tool in missing) for tool in tools},
            missing_unknown=not valid or any(item not in tools for item in missing))
    commands = result.get('commands', [])
    need(type(commands) is list and len(commands) <= 1000, 'finite original build command list required')
    expected_logs = []
    for row in commands:
        need(type(row) is dict and type(row.get('log')) is str, 'original build command reference required')
        name = 'journey/build-systems/' + row['log']; expected = row.get('log_pin')
        need(name in files and files[name]['kind'] == 'file' and files[name]['bytes'] <= 256*1024
             and pin(view.read(name)) == expected == {key: files[name][key] for key in ('bytes', 'sha256')},
             'original build command pins must match actual retained raw logs')
        expected_logs.append(dict(log=row['log'], pin=expected))
    expected = dict(schema=1, status='BUILD_SYSTEM_SUMMARY_DATA_ONLY', source_map_sha256=map_sha256,
        aggregate=status(result.get('status'), {'PASS_AVAILABLE_LOCAL_WORKFLOWS', 'NOT_RUN_NO_BUILD_SYSTEM', 'FAIL', 'UNKNOWN', 'ABSENT'}, 'status' in result),
        projects=normalized, tools={tool: status(tool_rows[tool].get('status') if type(tool_rows.get(tool)) is dict else None,
          {'PRESENT', 'MISSING', 'UNKNOWN', 'ABSENT'}, tool in tool_rows) for tool in tools},
        observed_projects={name: name in rows for name in projects}, unexpected_project_keys=any(name not in projects for name in rows),
        original_result_pin=summary['original_result_pin'], command_logs=expected_logs)
    need(summary == expected, 'build summary must preserve exact whitelist normalization of original result')
    candidate = (summary['aggregate'] == 'PASS_AVAILABLE_LOCAL_WORKFLOWS'
                 and all(summary['observed_projects'].values()) and not summary['unexpected_project_keys']
                 and all(row['status'] == 'PASS_REAL_PROJECT_WORKFLOW' and not any(row['missing'].values())
                         and row['missing_unknown'] is False for row in summary['projects'].values())
                 and all(value == 'PRESENT' for value in summary['tools'].values()))
    need(not positive or candidate, 'original aggregate and both build journeys remain required for native matching')
    return dict(status='VALIDATED_BOUND_BUILD_SUMMARY_DATA_ONLY', positive_candidate=candidate,
                original_result_and_feature_logs='VERIFIED_ACTUAL_RETAINED_BYTES')


def retained_safe_diagnostic(view, files, binding, map_sha256):
    """Explicit fresh safe DATA route; absent original bodies cannot be verified."""
    name = 'safe-diagnostic.json'; optional = {'consumer-diagnostic.json', 'build-summary.json', 'projection-refusal.json'}
    need(name in files and files[name]['kind'] == 'file' and files[name]['mode'] == 0o600,
         'safe failure authority must be ordinary private DATA')
    value = view.load(name)
    need(type(value) is dict and set(value) == {'schema', 'status', 'binding', 'source_map_sha256', 'native', 'physical_M2',
         'release', 'original_public', 'original_projection', 'reason', 'original_result_and_feature_logs', 'files'}
         and type(value['schema']) is int and value['schema'] == 1
         and value['status'] == 'NATIVE_FAILURE_SAFE_DIAGNOSTIC_DATA_ONLY' and value['binding'] == binding
         and value['source_map_sha256'] == map_sha256 and value['native'] == 'NOT_ADMITTED'
         and value['physical_M2'] == 'NOT_RUN' and value['release'] == 'NOT_ADMITTED'
         and value['original_public'] == value['original_projection'] == 'PRESERVED_UNTRAVERSED'
         and value['reason'] == 'EXISTING_PUBLIC_WITHOUT_COMPLETED_PROJECTION'
         and value['original_result_and_feature_logs'] == 'NOT_AVAILABLE_PIN_VERIFICATION_NOT_PERFORMED'
         and type(value['files']) is dict and set(value['files']) == optional,
         'exact source-bound safe failure DATA authority required')
    retained = set()
    for target, row in value['files'].items():
        need(type(row) is dict, 'fixed safe diagnostic retention row required')
        if row.get('status') == 'ABSENT':
            need(row == dict(status='ABSENT', code='SOURCE_DIAGNOSTIC_NOT_PRESENT'), 'fixed absent safe diagnostic metadata required')
            continue
        if row.get('status') == 'REFUSED':
            need(set(row) == {'status', 'code'} and row['code'] in
                 {'SOURCE_DIAGNOSTIC_UNAVAILABLE_OR_ALIASED', 'SOURCE_DIAGNOSTIC_SCHEMA_OR_PRIVACY_REFUSED'},
                 'fixed refused safe diagnostic metadata required')
            continue
        cap = 32*1024 if target == 'projection-refusal.json' else 512*1024
        need(set(row) == {'status', 'bytes', 'sha256'} and row['status'] == 'RETAINED'
             and type(row['bytes']) is int and 0 <= row['bytes'] <= cap
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
             and target in files and files[target] == dict(kind='file', mode=0o600, **{key: row[key] for key in ('bytes', 'sha256')})
             and pin(view.read(target)) == {key: row[key] for key in ('bytes', 'sha256')},
             'retained safe diagnostic must match actual ordinary capsule bytes')
        retained.add(target); document = view.load(target)
        if target == 'consumer-diagnostic.json':
            check_consumer(document, binding, map_sha256)
        elif target == 'build-summary.json':
            bound_build_summary(document, binding, map_sha256)
        else:
            need(type(document) is dict and set(document) == {'schema', 'binding', 'source_map_sha256', 'diagnostic'}
                 and type(document['schema']) is int and document['schema'] == 1 and document['binding'] == binding
                 and document['source_map_sha256'] == map_sha256, 'same-source projection refusal metadata required')
            validate_refusal(document['diagnostic'])
    need(set(files) == retained | {name} and sum(row['bytes'] for row in files.values()) <= 1024**2
         and pin(view.read(name)) == {key: files[name][key] for key in ('bytes', 'sha256')}
         and view.root_mode == 0o700 and set(view.entries) == set(files) | {'artifacts.json'}
         and all(row['kind'] == 'file' and row['mode'] == 0o600 for row in view.entries.values()),
         'closed fresh safe diagnostic namespace only; no raw or native evidence mixing')
    return dict(status='VALIDATED_NATIVE_FAILURE_SAFE_DIAGNOSTIC_DATA_ONLY', binding=binding,
                retained=sorted(retained), native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED',
                original_result_and_feature_logs='NOT_AVAILABLE_PIN_VERIFICATION_NOT_PERFORMED')


def retained_transport_diagnostic(view, files, phase, binding, map_sha256):
    value = phase.get('transport_diagnostic')
    if value is None:
        need('transport-diagnostic.json' not in files, 'unexpected transport diagnostic')
        return
    name = 'transport-diagnostic.json'
    need(name in files and files[name]['kind'] == 'file' and files[name]['bytes'] <= 1024**2
         and view.load(name) == value, 'standalone original transport diagnostic required')
    from transport_retention import validate as validate_transport_diagnostic
    validate_transport_diagnostic(value, binding, map_sha256, phase['work'])


def retained_transport_proof(view, files, phase, binding, map_sha256):
    """Actual canonical supervision and all complete carrier/object proof DATA."""
    need(phase['binding'] == binding and phase['source_map_sha256'] == map_sha256
         and phase['actors'] == [] and phase['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and phase['carrier_source'] == 'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
         and phase['profile_sha256'] == '4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
         and phase['expected_carrier_files'] == 1154 and phase['expected_carrier_bytes'] == 1046432165
         and phase['budget_seconds'] == 480 and phase['retry'] is False,
         'same-source complete canonical transport, original clocks and whole profile required')
    name = 'transport-proof.json'
    need(name in files and files[name]['kind'] == 'file' and view.load(name) == phase['transport_proof'],
         'standalone canonical transport certificate required')
    from transport_proof import validate as validate_transport
    profile = load(Path(__file__).resolve().parents[1] / 'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json')
    validate_transport(view.load(name), phase['canonical_transport'], profile, binding, map_sha256, view.read)
    return dict(status='VALIDATED_COMPLETE_CANONICAL_TRANSPORT_DATA_ONLY', files=1154,
                native='NOT_ADMITTED')


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
    if 'safe-diagnostic.json' in files:
        return retained_safe_diagnostic(view, files, binding, expected['map_sha256'])
    retained_public_projection(view, files, binding, expected['map_sha256'])
    if 'provision-diagnostic.json' in files:
        transport_phase = view.load('provision-diagnostic.json').get('phases', {}).get('input-transport-owner.json')
        if transport_phase is not None:
            retained_transport_diagnostic(view, files, transport_phase, binding, expected['map_sha256'])
    if 'provision-diagnostic.json' in files:
        diagnostic = view.load('provision-diagnostic.json')
        need(diagnostic['binding'] == binding and diagnostic['source_map_sha256'] == expected['map_sha256']
             and diagnostic['status'] == 'DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY'
             and diagnostic['native'] == diagnostic['GPG'] == diagnostic['ALPM'] == 'NOT_RUN', 'actual DATA diagnostic only')
        return dict(status='VALIDATED_INPUT_PROVISIONING_DIAGNOSTIC_NOT_NATIVE', binding=binding, native='NOT_RUN', physical_M2='NOT_RUN')
    receipt = view.load('receipt.json'); cleanup = view.load('cleanup.json')
    need(receipt.get('binding') == binding and receipt.get('source_map_sha256') == expected['map_sha256']
         and type(receipt.get('status')) is str and type(cleanup.get('status')) is str,
         'same-source owner and explicit cleanup outcome required')
    if receipt.get('operation') == 'security-alpm-v1':
        from security_reader_v1 import validate_component
        return validate_component(view, files, receipt, cleanup, binding, expected, sys.modules[__name__])
    consumer_diagnostic = retained_consumer_diagnostic(view, files, receipt, binding, expected['map_sha256'])
    build_summary = retained_build_summary(view, files, binding, expected['map_sha256'])
    failed = (receipt['status'] != 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY'
              or cleanup['status'] != 'PASS_EXACT_OWNED_RESOURCES_RETIRED')
    need(failed or consumer_diagnostic['status'] != 'ABSENT_CONSUMER_DIAGNOSTIC_DATA_ONLY',
         'successful owner cannot omit original consumer diagnostic')
    need(failed or build_summary['status'] != 'ABSENT_BUILD_SUMMARY_DATA_ONLY',
         'successful owner cannot omit original build summary')
    if failed or not build_summary['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_FAILURE_DATA_ONLY', binding=binding,
                    owner_status=receipt['status'], cleanup_status=cleanup['status'],
                    consumer_diagnostic=consumer_diagnostic, build_summary=build_summary, native='NOT_ADMITTED', physical_M2='NOT_RUN')
    if failed or not consumer_diagnostic['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_FAILURE_DATA_ONLY', binding=binding,
                    owner_status=receipt['status'], cleanup_status=cleanup['status'],
                    consumer_diagnostic=consumer_diagnostic, native='NOT_ADMITTED', physical_M2='NOT_RUN')
    retained_consumer_diagnostic(view, files, receipt, binding, expected['map_sha256'], positive=True)
    retained_build_summary(view, files, binding, expected['map_sha256'], positive=True)
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
    retained_transport_proof(view, files, phases['transport'], binding, expected['map_sha256'])
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
