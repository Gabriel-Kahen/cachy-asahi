# SPDX-License-Identifier: MIT
"""Passive capsule DATA reader; refuse NULL selectors before opening capsule.

Symlink targets are ordinary DATA payloads. No capsule member is extracted,
imported or followed.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import consumer_contract, load, need, pin, uv_policy, read
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


PRODUCERS = {
    'native/source_tools_alpm_v1.py': 'c332fbef08d7e03be918b45a67c1eb705eaa41425e02bd84111a50058eed0279',
    'native/source_tools_tools_v1.py': 'c43ca5ec8cb81ec78e7d6a0a224eb9272dad9bb831af3d6a8755d4d8db83c1c5',
    'native/source_tools_guest_v1.py': 'e93e6b6dd0e717305b29236718339a448794808052f65e8279bbca37d40272e1',
    'native/source_tools_probe_v1.py': 'bc7645b39df4b0fe39c0eda7da1ad46f9603786b3ec18aeafdd04b8d8f5563e2',
    'native/source-tools-contract-v1.json': '5fe189406b40a16f08955df642781c22bba106507731ff33b4734bf43210d3cb',
}

PASS = 'PASS_SOURCE_TOOLS_NATIVE_ALPM_COMPONENT'
OPERATION = 'source-tools-alpm-v1'


def retained_public_projection(view, files, binding, map_sha256):
    """Closed new component DATA seam; no original187 feature credit."""
    name = 'public-projection.json'
    need(name in files and files[name]['kind'] == 'file', 'source-owned finite projection receipt required')
    value = view.load(name)
    host = {'transport-diagnostic.json', 'transport-proof.json', 'receipt.json', 'cleanup.json', 'source-proof.json', 'consumer-inspect.json', 'consumer-after.json',
            'consumer-diagnostic.json', 'image-ledger.json', 'image-retirement.json', 'bootstrap-failure-retention.json',
            'provision-diagnostic.json', 'build-summary.json'}
    bootstrap = {phase + '-' + leaf for phase in ('bootstrap', 'overlay') for leaf in
                 ('packages.lock', 'signatures.json', 'bootstrap.json', 'cache-checksums.json', 'Dockerfile', 'runner.json')}
    bootstrap |= {'bootstrap-acquisition.json', 'bootstrap-key-import.log', 'bootstrap-bootstrap.log'}
    prefix = 'journey/source-tools-alpm-v1/'
    log_pattern = r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log'
    private_marker = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('status') == 'PASS_FINITE_SOURCE_TOOLS_ALPM_PUBLIC_DATA_PROJECTION'
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256
         and value.get('source_producers') == PRODUCERS
         and value.get('omitted_private_scopes') == ['journey/source-tools-alpm-v1/home']
         and value.get('original_output_unchanged') is True and value.get('omitted_private_trees_walked') is False
         and value.get('privacy') == 'Selected text/JSON/log ASCII private-key,SSH,token,secret-env marker refusal; no payload exemption'
         and value.get('scope') == 'Fixed source-tools-alpm-v1 result, commands and raw referenced logs only; private home trees not retained',
         'same-source exact finite release projection and explicit omission scope required')
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
        if target.startswith(prefix):
            leaf = target[len(prefix):]
            allowed |= leaf in {'result.json', 'commands.json'} or re.fullmatch(log_pattern, leaf) is not None
        need(allowed and type(row) is dict and set(row) == {'kind', 'mode', 'source_mode', 'bytes', 'sha256'}
             and row['kind'] == 'file' and type(row['mode']) is int and row['mode'] == 0o600
             and type(row['source_mode']) is int and 0 <= row['source_mode'] <= 0o777
             and type(row['bytes']) is int and 0 <= row['bytes'] <= 16*1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'finite ordinary projected evidence leaf required')
        need(files[target] == {key: row[key] for key in ('kind', 'mode', 'bytes', 'sha256')}
             and pin(view.read(target)) == {key: row[key] for key in ('bytes', 'sha256')},
             'projection selected pin and modes must match manifest and actual DATA')
        need(not private_marker.search(view.read(target)), 'private marker in projected public DATA refused')
    result_name = prefix + 'result.json'
    actual_logs = {target for target in selected if target.startswith(prefix) and re.fullmatch(log_pattern, target[len(prefix):])}
    if result_name not in selected:
        need(not actual_logs, 'projected release logs require original component result')
        return dict(status='VALIDATED_FINITE_SOURCE_TOOLS_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))
    report = view.load(result_name); commands = report.get('commands', [])
    need(type(commands) is list and len(commands) <= 1000, 'finite projected component command list required')
    wanted = set()
    for command in commands:
        leaf = command.get('log')
        need(type(leaf) is str and re.fullmatch(log_pattern, leaf) and prefix + leaf not in wanted,
             'finite unique projected release log names required')
        target = prefix + leaf; wanted.add(target)
        need(target in selected and {key: selected[target][key] for key in ('bytes', 'sha256')} == command.get('log_pin'),
             'all original release raw command logs must be projected')
    need(actual_logs == wanted, 'closed original release log projection required')
    command_file = prefix + 'commands.json'
    need(not commands or command_file in selected, 'actual component command list must be projected')
    if command_file in selected:
        need(view.load(command_file) == commands, 'projected standalone and release command lists differ')
    guest = view.load('journey/result.json') if 'journey/result.json' in selected else None
    if type(guest) is dict and guest.get('status') == PASS:
        need(guest.get('source_tools_alpm') == report, 'positive guest and separately retained release results differ')
    return dict(status='VALIDATED_FINITE_SOURCE_TOOLS_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))



def retained_191_provision_projection(view, files, binding, map_sha256):
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


def source_tools_contract():
    path = Path(__file__).resolve().with_name('source-tools-contract-v1.json')
    raw = read(path)
    need(pin(raw)['sha256'] == PRODUCERS['native/source-tools-contract-v1.json'], 'exact source_tools contract producer pin required')
    value = json.loads(raw)
    need(value.get('schema') == 1 and value.get('operation') == OPERATION
         and type(value.get('actual')) is dict and set(value['actual']) == {'source','ref','run','job','artifact'} and all(item is None for item in value['actual'].values())
         and value.get('recipe', {}).get('version') == '0.1.0-1'
         and len(value['recipe'].get('payload_files', {})) == 17 and len(value['recipe'].get('source_files', {})) == 13, 'exact unexecuted source_tools source contract')
    return value


def strict_test_signature(status, signer):
    need(type(status) is str and len(status.encode()) <= 65536
         and re.fullmatch('[0-9A-F]{40}', signer or ''), 'bounded exact TEST signer status required')
    rows = [line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    forbidden = {'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'KEYEXPIRED',
                 'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'NODATA', 'TRUST_NEVER', 'TRUST_UNDEFINED'}
    need(not any(row and row[0] in forbidden for row in rows), 'bad/expired/revoked/unknown TEST signature refused')
    valid = [row for row in rows if row and row[0] == 'VALIDSIG']
    need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == signer,
         'exact TEST primary signer required')
    need(any(row and row[0] == 'TRUST_ULTIMATE' for row in rows), 'explicitly trusted TEST primary required')


def source_tools_commands(view, files, prefix, commands):
    need(type(commands) is list and 0 < len(commands) <= 160 and view.load(prefix + 'commands.json') == commands,
         'actual finite standalone source_tools command list required')
    for index, command in enumerate(commands):
        need(type(command) is dict, 'typed source_tools command row required')
        step = command.get('step'); log = command.get('log'); state = command.get('supervision')
        need(type(step) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}', step)
             and log == '%03d-%s.log' % (index, step), 'ordered source-owned command log namespace required')
        target = prefix + log
        need(target in files and files[target]['kind'] == 'file'
             and pin(view.read(target)) == command.get('log_pin') == {k: files[target][k] for k in ('bytes', 'sha256')}, 'complete raw source_tools command log required')
        expected = command.get('expected'); code = state.get('exit') if type(state) is dict else None
        matched = type(code) is int and (code > 0 if expected == 'nonzero' else type(expected) is int and code == expected)
        need(command.get('success') is True and type(state) is dict and matched
             and state.get('reaped') is True and state.get('ownership') == 'REAPED'
             and state.get('group_census') == 'EMPTY_TWICE' and state.get('output_complete') is True
             and state.get('error') is None and state.get('timeout') is False and state.get('signals') == [], 'actual original owned natural retirement required')
        need(type(command.get('argv')) is list and 0 < len(command['argv']) <= 128
             and all(type(arg) is str and len(arg) <= 8192 for arg in command['argv']) and Path(command['argv'][0]).is_absolute(), 'bounded explicit source_tools argv required')
    def selected(step):
        rows = [(i, row) for i, row in enumerate(commands) if row['step'] == step]
        need(len(rows) == 1, 'sole exact source_tools command reference required')
        return rows[0]
    return selected


def source_tools_metadata(raw):
    need(type(raw) is bytes and len(raw) <= 2*1024**2, 'bounded package metadata text required')
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'): continue
        need(' = ' in line, 'exact makepkg metadata separator required')
        key, value = line.split(' = ', 1); result.setdefault(key, []).append(value)
    return result


def source_tools_check_output(raw):
    """Match the frozen recipe's positive checker and real 17-command JSON."""
    if type(raw) is not bytes or b'Starting check()' not in raw:
        return False
    rows = []
    for line in raw.splitlines():
        if line.startswith(b'{'):
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError):
                return False
            if type(row) is not dict:
                return False
            rows.append(row)
    if len(rows) != 3:
        return False
    first, staged, report = rows
    workflow = report.get('workflow')
    return (first == dict(status='PASS', private_source_files=11, payload_files=None)
        and staged == dict(status='PASS', private_source_files=11, payload_files=17)
        and report.get('status') == 'PASS' and type(report.get('staged_payload_files')) is int
        and report['staged_payload_files'] == 17 and report.get('checkout_hidden') is True
        and report.get('moved_prefix') is True and report.get('network_namespace') == 'loopback-only'
        and report.get('removal') == 'EXACT_FILE_INVERSE_USER_CONTENT_PRESERVED'
        and report.get('alpm_installation') == report.get('native_build') == 'NOT_RUN'
        and type(workflow) is dict and workflow.get('status') == 'PASS'
        and type(workflow.get('controls')) is int and workflow['controls'] == 17
        and workflow.get('packages_per_release') == workflow.get('retained_releases') == 2
        and workflow.get('exact_contexts') == 4
        and type(workflow.get('commands')) is list and len(workflow['commands']) == 17
        and workflow.get('native_build') == workflow.get('alpm_installation') == workflow.get('hardware') == 'NOT_RUN'
        and workflow.get('source_execution') == 'NOT_RUN')


def source_tools_build_pair(view, prefix, report, contract, selected, map_sha256):
    import io
    import tarfile
    recipe = contract['recipe']; builds = report.get('builds'); comparison = report.get('comparison')
    need(type(builds) is dict and set(builds) == {'a', 'b'} and type(comparison) is dict, 'two separate actual native builds/comparison required')
    need(comparison.get('status') == 'PASS_EXACT_NATIVE_BUILD_PAIR'
         and comparison.get('equality') == {key: True for key in ('archive', 'payload', 'pkginfo', 'buildinfo', 'mtree')}
         and comparison.get('source_map_sha256') == map_sha256 and comparison.get('payload_files') == 17
         and comparison.get('base_inventory_count') == 349
         and comparison.get('pkgbuild_sha256') == recipe['source_files']['PKGBUILD']['sha256'], 'exact native build-pair/provenance comparison required')
    expected = recipe['payload_files']; indexes = []; decoded = {}; archives = {}; identities = []
    fixed = Path(contract['invocation']['source']).parent; slot = fixed / 'build-current'
    for label in ('a', 'b'):
        build = builds[label]; archive = build.get('archive'); directory = build.get('build_directory')
        need(build.get('version') == '0.1.0-1' and build.get('recipe_sha256') == recipe['source_files']['PKGBUILD']['sha256']
             and build.get('check_invoked') is True and build.get('check_tests') == recipe['expected_test_count'] == 17
             and build.get('check_policy') == 'POSITIVE_CHECK_NO_NOCHECK', 'exact recipe and positive17 makepkg checks required')
        need(type(directory) is dict and directory.get('logical') == str(slot) and directory.get('retained') == str(fixed/'build-inputs'/label)
             and directory.get('initial_files') == sorted(recipe['source_files']) and type(directory.get('identity')) is dict
             and set(directory['identity']) == {'device', 'inode'}
             and all(type(value) is int and value >= 0 for value in directory['identity'].values()), 'distinct fresh exact source directories required')
        identities.append(directory['identity'])
        need(type(archive) is dict and archive.get('filename') == recipe['archive'] and type(archive.get('bytes')) is int
             and 0 < archive['bytes'] <= 2*1024**2 and re.fullmatch('[0-9a-f]{64}', archive.get('sha256') or ''), 'bounded actual native archive pin required')
        archives[label] = {key: archive[key] for key in ('bytes', 'sha256')}
        index, command = selected(build.get('build_step')); indexes.append(index)
        argv = command['argv']; raw = view.read(prefix + command['log'])
        wanted = ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', 'HOME=' + str(slot),
                  'PKGDEST=' + str(slot), 'SRCDEST=' + str(slot), 'BUILDDIR=' + str(slot),
                  'SOURCE_DATE_EPOCH=1793145600', 'PACKAGER=cachy-asahi native TEST builder',
                  '/usr/bin/makepkg', '--cleanbuild', '--nodeps', '--nosign', '--noconfirm', '--config',
                  str(Path(contract['invocation']['source']) / contract['makepkg_config']['path'])]
        need(argv == wanted and command.get('cwd') == str(slot) and command['expected'] == 0
             and source_tools_check_output(raw) and build.get('check_result') == pin((json.dumps(next(json.loads(line) for line in raw.splitlines() if line.startswith(b'{') and 'workflow' in json.loads(line)), sort_keys=True, indent=2, allow_nan=False) + '\n').encode()), 'ordinary separate clean builds must run actual17 check() controls')
        decode_index, decode = selected('archive-' + label)
        need(decode['argv'] == ['/usr/bin/zstd', '-dc', str(fixed/'build-inputs'/label/recipe['archive'])]
             and decode['expected'] == 0 and decode_index > indexes[-1], 'raw actual archive decoder command required')
        raw_tar = view.read(prefix + decode['log']); need(len(raw_tar) <= 2*1024**2, 'bounded actual decoded package DATA')
        payload = {}; metadata = {}; seen = set(); directories = set()
        ancestors = {str(parent) for leaf in expected for parent in Path(leaf).parents if str(parent) != '.'}
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:') as archive_data:
            for member in archive_data:
                name = member.name
                need(name not in seen and member.uid == member.gid == 0 and not member.pax_headers, 'unique root-owned archive members'); seen.add(name)
                if member.isdir():
                    need(member.mode == 0o755 and name.rstrip('/') in ancestors, 'finite root-owned package directory')
                    directories.add(name.rstrip('/')); continue
                need(member.isfile() and member.size <= 1024**2, 'ordinary bounded package member')
                body = archive_data.extractfile(member).read(); need(len(body) == member.size, 'complete actual archive member')
                if name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
                    need(member.mode == 0o644, 'ordinary makepkg metadata mode'); metadata[name] = body
                else:
                    need(name in expected and member.mode == expected[name]['mode'] and pin(body) == {key: expected[name][key] for key in ('bytes', 'sha256')}, 'exact source-bound payload bytes/mode')
                    payload[name] = dict(mode=member.mode, **pin(body))
        need(set(payload) == set(expected) and directories == ancestors and set(metadata) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'complete seventeen-file archive namespace required')
        info = source_tools_metadata(metadata['.PKGINFO']); provenance = source_tools_metadata(metadata['.BUILDINFO'])
        need(info.get('pkgname') == ['cachy-asahi-source-tools'] and info.get('pkgver') == ['0.1.0-1'] and info.get('arch') == ['any']
             and info.get('license') == ['MIT'] and info.get('depend') == ['python>=3.14', 'xz', 'zstd'] and info.get('checkdepend') == ['bubblewrap'], 'exact package identity and runtime dependency metadata')
        need(provenance.get('pkgname') == ['cachy-asahi-source-tools'] and provenance.get('pkgver') == ['0.1.0-1'] and provenance.get('pkgarch') == ['any']
             and provenance.get('pkgbuild_sha256sum') == [recipe['source_files']['PKGBUILD']['sha256']]
             and sorted(provenance.get('installed', [])) == contract['buildinfo_installed'] and len(provenance.get('installed', [])) == 349
             and 'check' in provenance.get('buildenv', []) and '!check' not in provenance.get('buildenv', []), 'full349 build provenance and checks required')
        actual = dict(archive=archives[label], pkginfo=pin(metadata['.PKGINFO']), buildinfo=pin(metadata['.BUILDINFO']), mtree=pin(metadata['.MTREE']), payload=payload)
        need(comparison.get('builds', {}).get(label) == actual, 'comparison must join every raw actual archive member')
        decoded[label] = (payload, metadata)
    need(indexes == sorted(set(indexes)) and identities[0] != identities[1] and decoded['a'] == decoded['b']
         and archives['a'] == archives['b'] == comparison.get('archive'), 'two distinct ordered builds with exact archive/metadata/payload equality')
    need(comparison.get('pkginfo_text') == decoded['a'][1]['.PKGINFO'].decode() and comparison.get('buildinfo_text') == decoded['a'][1]['.BUILDINFO'].decode()
         and base64.b64decode(comparison.get('mtree_base64', ''), validate=True) == decoded['a'][1]['.MTREE'], 'complete raw provenance DATA must match')
    return indexes, archives


def source_tools_restoration(report):
    restore = report.get('restore'); keys = {'alpm_db', 'alarm_home', 'root_home', 'global_trust', 'global_config', 'package_cache'}
    need(type(restore) is dict and set(restore) == keys, 'complete DB/home/trust/config/cache restoration scope required')
    for scope in keys:
        row = restore[scope]
        need(type(row) is dict and set(row) == {'before', 'after', 'unchanged'} and row['unchanged'] is True
             and type(row['before']) is dict and row['before'] == row['after'] and type(row['before'].get('files')) is int
             and row['before']['files'] >= 0 and type(row['before'].get('bytes')) is int and row['before']['bytes'] >= 0
             and re.fullmatch('[0-9a-f]{64}', row['before'].get('sha256') or ''), 'exact full protected snapshot must restore: ' + scope)
    need(report.get('payload_absent') is True and report.get('private_roots_absent') is True and report.get('exports_preserved') is True
         and type(report.get('exports_before')) is dict and report['exports_before'] == report.get('exports_after')
         and report['exports_before'].get('files', 0) > 0, 'all owned payload/private roots absent and operator outputs preserved')


def source_tools_failure_data(view, files, map_sha256):
    """Read only source-bound first-failure observations; never acceptance."""
    prefix = 'journey/source-tools-alpm-v1/'; name = prefix + 'result.json'
    result = dict(status='UNKNOWN', reason='COMPONENT_REPORT_ABSENT', result=None,
                  first_failure=None, command=None, supervision=None,
                  supervision_status='UNKNOWN', log=None, cleanup={},
                  native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    if name not in files:
        return result
    row = files[name]
    need(type(row) is dict and row.get('kind') == 'file' and type(row.get('bytes')) is int
         and 0 <= row['bytes'] <= 4*1024**2, 'bounded ordinary source-tools failure result required')
    raw = view.read(name)
    need(type(raw) is bytes and pin(raw) == {key:row.get(key) for key in ('bytes','sha256')}, 'source-tools failure result pin differs')
    report = json.loads(raw); contract = source_tools_contract()
    contract_raw = read(Path(__file__).resolve().with_name('source-tools-contract-v1.json'))
    need(type(report) is dict and type(report.get('schema_version')) is int and report['schema_version'] == 1
         and report.get('operation') == OPERATION and report.get('source_map_sha256') == map_sha256
         and report.get('contract') == pin(contract_raw)
         and pin(contract_raw)['sha256'] == PRODUCERS['native/source-tools-contract-v1.json']
         and contract.get('operation') == OPERATION, 'same-map exact failure result/producer contract required')
    result.update(reason='FIRST_FAILURE_UNAVAILABLE', result=pin(raw))
    cleanup = report.get('cleanup')
    if type(cleanup) is dict:
        for key in ('homes_retired','no_sockets','private_directory_absent'):
            result['cleanup'][key] = cleanup.get(key) if type(cleanup.get(key)) is bool else 'UNKNOWN'
        failures = cleanup.get('failures')
        if type(failures) is list and len(failures) <= 160:
            need(all(type(item) is str and len(item.encode()) <= 1024 for item in failures), 'bounded observed cleanup failures required')
            result['cleanup']['failures'] = failures
        else:
            result['cleanup']['failures'] = 'UNKNOWN'
    failure = report.get('first_failure')
    if failure is None:
        return result
    need(type(failure) is dict and set(failure) == {'phase','type','message','command_index'}
         and all(type(failure[key]) is str and len(failure[key].encode()) <= 1024 for key in ('phase','type','message')),
         'bounded original first-failure phase/type/message required')
    index = failure['command_index']; commands = report.get('commands')
    need(type(commands) is list and len(commands) <= 160, 'finite original failure command index required')
    need(index is None or type(index) is int and -1 <= index < len(commands), 'exact integer first-failure command index required')
    result['first_failure'] = failure
    evidence = report.get('first_failure_data')
    if index is None or index == -1:
        need(type(evidence) is not dict or evidence.get('status') != 'RETAINED_ORIGINAL_COMMAND_DATA', 'retained failure row requires a valid original index')
        result['reason'] = 'NO_ORIGINAL_COMMAND_ROW'
        return result
    if type(evidence) is not dict or evidence.get('status') != 'RETAINED_ORIGINAL_COMMAND_DATA':
        need(evidence is None or type(evidence) is dict and evidence.get('status') == 'UNKNOWN', 'unknown source failure evidence status refused')
        result['reason'] = 'SOURCE_COMMAND_DATA_UNAVAILABLE'
        return result
    need(set(evidence) == {'status','command_index','command','supervision','log'}
         and type(evidence.get('command_index')) is int and evidence['command_index'] == index,
         'retained original failure index differs')
    command = commands[index]
    need(type(command) is dict and evidence['command'] == command and command.get('success') is False
         and evidence['supervision'] == command.get('supervision'), 'retained failed row/supervision must equal original command index')
    command_raw = (json.dumps(command,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(len(command_raw) <= 16*1024, 'failed command row16KiB bound')
    step = command.get('step'); leaf = command.get('log')
    need(type(step) is str and re.fullmatch('[A-Za-z0-9._+-]{1,96}',step)
         and leaf == '%03d-%s.log' % (index,step), 'fixed original failed command log role required')
    command_file = prefix + 'commands.json'
    need(command_file in files and files[command_file].get('kind') == 'file'
         and pin(view.read(command_file)) == {key:files[command_file].get(key) for key in ('bytes','sha256')}
         and view.load(command_file) == commands, 'standalone original failed command index differs')
    target = prefix + leaf; log = evidence.get('log')
    need(type(log) is dict and set(log) == {'name','bytes','sha256'} and log['name'] == leaf
         and type(log['bytes']) is int and 0 <= log['bytes'] <= 1024**2
         and re.fullmatch('[0-9a-f]{64}',log.get('sha256') or '')
         and target in files and files[target].get('kind') == 'file'
         and {key:log[key] for key in ('bytes','sha256')} == command.get('log_pin')
         == {key:files[target].get(key) for key in ('bytes','sha256')}, 'same original failed command/log/capsule pin required')
    raw_log = view.read(target)
    need(type(raw_log) is bytes and len(raw_log) <= 1024**2 and pin(raw_log) == command['log_pin'], 'original failed raw log bytes differ')
    supervision = command.get('supervision')
    need(supervision is None or type(supervision) is dict, 'observed failure supervision object or unavailable only')
    result.update(status='VALIDATED_SOURCE_TOOLS_FAILURE_DATA_ONLY', reason='ORIGINAL_FAILED_COMMAND_OBSERVED',
                  command=dict(index=index,pin=pin(command_raw),row=command), supervision=supervision,
                  supervision_status='UNKNOWN' if supervision is None else 'OBSERVED_DATA_ONLY',
                  log=dict(name=target,**pin(raw_log)))
    return result


def source_tools_positive_state(report):
    """A persisted PASS cannot override a later observation/retention failure."""
    need(type(report) is dict and report.get('retention_failures', []) == []
         and report.get('first_failure') is None and report.get('failure') is None,
         'positive source-tools evidence refuses retention or primary failure state')


def retained_source_tools_alpm(view, files, guest, map_sha256):
    contract = source_tools_contract(); prefix = 'journey/source-tools-alpm-v1/'; report = guest.get('source_tools_alpm')
    source_tools_positive_state(report)
    need(type(report) is dict and type(report.get('schema_version')) is int and report['schema_version'] == 1
         and report.get('operation') == OPERATION and report.get('status') == PASS and report.get('source_map_sha256') == map_sha256
         and report.get('version') == '0.1.0-1' and report.get('contract') == pin(read(Path(__file__).resolve().with_name('source-tools-contract-v1.json')))
         and view.load(prefix + 'result.json') == report, 'same-map exact actual source_tools component result required')
    need(report.get('stages') == ['build-a', 'build-b', 'compare', 'sign', 'install', 'commands-system', 'commands-moved', 'remove', 'restore', 'cleanup'],
         'complete ordered source_tools lifecycle stages required')
    commands = report.get('commands'); selected = source_tools_commands(view, files, prefix, commands)
    build_indexes, archives = source_tools_build_pair(view, prefix, report, contract, selected, map_sha256)
    recipe = contract['recipe']; fixed = Path(contract['invocation']['source']).parent
    archive_paths = {label: str(fixed / 'build-inputs' / label / recipe['archive']) for label in ('a', 'b')}
    base = read(Path(__file__).resolve().with_name('expected349.lock'))
    need(pin(base) == {key: contract['expected349'][key] for key in ('bytes', 'sha256')} and len(base.splitlines()) == 349, 'exact retained349 baseline required')
    inventory = report.get('inventory'); indexes = {}
    need(type(inventory) is dict and set(inventory) == {'baseline', 'installed', 'removed'}, 'complete349/350/349 inventory map required')
    for key, version, count in [('baseline', None, 349), ('installed', '0.1.0-1', 350), ('removed', None, 349)]:
        rows = base.splitlines(keepends=True)
        if version is not None: rows.append(b'cachy-asahi-source-tools 0.1.0-1\n')
        expected = pin(b''.join(sorted(rows))); row = inventory[key]; index, command = selected(key + '-inventory'); indexes[key] = index
        need(type(row) is dict and type(row.get('count')) is int and row['count'] == count and row.get('version') == version
             and {k: row.get(k) for k in ('bytes', 'sha256')} == expected and command['argv'] == ['/usr/bin/pacman', '-Q']
             and pin(b''.join(sorted(view.read(prefix + command['log']).splitlines(keepends=True)))) == expected, 'exact raw ALPM inventory must restore')
    need(guest.get('packages') == pin(base), 'guest exact349 baseline required')
    payload = report.get('payloads', {}).get('installed')
    need(payload == dict(version='0.1.0-1', count=17, verified=True, stale_absent=True,
                         files={name:{key:item[key] for key in ('bytes','sha256','mode')} for name,item in recipe['payload_files'].items()})
         and payload.get('verified') is True, 'actual ALPM installed seventeen-file source-bound payload required')
    signatures = report.get('signatures')
    need(type(signatures) is dict and set(signatures) == {'a', 'b'}, 'both actual native archive signatures required')
    verify_indexes = []; signers = set()
    for label in ('a', 'b'):
        signature = signatures[label]; signer = signature.get('signer'); signers.add(signer); strict_test_signature(signature.get('status'), signer)
        encoded = signature.get('signature')
        need(type(encoded) is dict and type(encoded.get('base64')) is str and len(encoded['base64']) <= 131072, 'bounded detached TEST signature DATA required')
        raw = base64.b64decode(encoded['base64'], validate=True)
        need(0 < len(raw) <= 65536 and pin(raw) == {key: encoded.get(key) for key in ('bytes', 'sha256')}, 'exact TEST signature bytes required')
        index, command = selected(signature.get('verify_step')); verify_indexes.append(index)
        need(command['expected'] == 0 and command['argv'][0] == '/usr/bin/gpg' and '--status-fd=1' in command['argv']
             and command['argv'][-3:] == ['--verify', archive_paths[label] + '.sig', archive_paths[label]]
             and view.read(prefix + command['log']).decode().strip() == signature['status'].strip(), 'actual raw detached signature verification required')
    need(build_indexes == sorted(set(build_indexes)) and max(build_indexes) < min(verify_indexes)
         and verify_indexes == sorted(set(verify_indexes)) and len(signers) == 1, 'both builds precede ordered verification under sole TEST primary')
    signer, = signers; need(report.get('fingerprint') == signer, 'same explicit TEST primary fingerprint')
    public = report.get('public_key')
    need(type(public) is dict and type(public.get('text')) is str and len(public['text'].encode()) <= 65536
         and public['text'].startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and 'PRIVATE KEY' not in public['text']
         and pin(public['text'].encode()) == {key: public.get(key) for key in ('bytes', 'sha256')}, 'bounded TEST public key only')
    need(report.get('signature_policy') == dict(SigLevel='Required', LocalFileSigLevel='Required'), 'Required/Required isolated TEST policy required')
    config_index, command = selected('required-signature-config')
    need(command['argv'][:1] == ['/usr/bin/cat'] and len(command['argv']) == 2, 'actual isolated ALPM config command required')
    config_path = command['argv'][1]; trust = Path(config_path).with_name('trust'); raw = view.read(prefix + command['log'])
    need(Path(config_path).name == 'pacman.conf' and trust.parent.parent == Path('/tmp') and trust.parent.name.startswith('source-tools-test-')
         and raw == ('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = ' + str(trust) + '\nHookDir = /builder-disabled-hooks\n').encode()
         and pin(raw) == report.get('signature_config'), 'exact private TEST Required/Required config required')
    verifier = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(trust), '--no-auto-key-retrieve']
    for label in ('a', 'b'):
        _, command = selected(signatures[label]['verify_step'])
        need(command['argv'] == verifier + ['--status-fd=1', '--verify', archive_paths[label] + '.sig', archive_paths[label]], 'exact private TEST verifier argv')
    for step in ('test-primary-fingerprint', 'trust-key-membership'):
        _, command = selected(step)
        actual = [line.split(':')[9] for line in view.read(prefix + command['log']).decode().splitlines() if line.startswith('fpr:')]
        need(actual == [signer], 'signing and trust contain only exact TEST primary')
    _, command = selected('export-only-test-public')
    need(view.read(prefix + command['log']) == public['text'].encode() and command['argv'][-3:] == ['--armor', '--export', signer], 'actual public-only TEST key export')
    for step, marker in [('untrusted-signature-control', b'NO_PUBKEY'), ('tampered-signature-control', None)]:
        index, command = selected(step); raw = view.read(prefix + command['log'])
        need(command['expected'] == 'nonzero' and '--verify' in command['argv']
             and (marker in raw if marker else b'BADSIG' in raw or b'ERRSIG' in raw), 'actual unknown/tamper TEST refusal required')
        need(max(build_indexes) < index < min(verify_indexes) if marker else max(verify_indexes) < index < config_index, 'TEST refusal ordering required')
    transactions = []
    for step, tail in [('install', ['-U', archive_paths['a']]), ('remove', ['-R', 'cachy-asahi-source-tools'])]:
        index, command = selected(step); transactions.append(index)
        need(command['argv'] == ['/usr/bin/pacman', '--config', config_path, '--noconfirm', '--noscriptlet', *tail] and command['expected'] == 0,
             'finite Required-policy ALPM transaction argv')
    need(indexes['baseline'] < min(build_indexes) and max(verify_indexes) < config_index < transactions[0]
         < indexes['installed'] < transactions[1] < indexes['removed'], 'actual build/sign/install/probe/remove order required')
    owners = []
    for command in commands:
        if command['step'] != 'owner-cachy-asahi-source-tools': continue
        need(command['argv'][:4] == ['/usr/bin/pacman', '--config', config_path, '-Qoq'] and len(command['argv']) == 5
             and view.read(prefix + command['log']).strip() == b'cachy-asahi-source-tools', 'actual ALPM file ownership query required')
        owners.append(command['argv'][4].removeprefix('/'))
    need(sorted(owners) == sorted(recipe['payload_files']), 'all seventeen payload leaves require actual ALPM ownership joins')
    _, command = selected('owned-files-cachy-asahi-source-tools'); names = view.read(prefix + command['log']).decode().splitlines()
    need(command['argv'] == ['/usr/bin/pacman', '--config', config_path, '-Qlq', 'cachy-asahi-source-tools'] and len(names) == len(set(names))
         and all(name.startswith('/') and '..' not in Path(name).parts and name.rstrip('/') == Path(name.rstrip('/')).as_posix() for name in names)
         and {name.lstrip('/') for name in names if not name.endswith('/')} == set(recipe['payload_files'])
         and {name.lstrip('/').rstrip('/') for name in names if name.endswith('/')} == {str(parent) for name in recipe['payload_files'] for parent in Path(name).parents if str(parent) != '.'},
         'actual exact ALPM file/directory inventory required')
    for key, flag in [('explicit', '-Qqe'), ('dependencies', '-Qqd')]:
        pins = []
        for phase, target in [('baseline-reasons', 'install_reasons_before'), ('restored-reasons', 'install_reasons_after')]:
            _, command = selected(phase + '-' + key); raw = view.read(prefix + command['log'])
            need(command['argv'] == ['/usr/bin/pacman', flag] and command['expected'] == 0, 'actual installation-reason query required')
            current = pin(b''.join(sorted(raw.splitlines(keepends=True)))); need(report.get(target, {}).get(key) == current, 'reasons join original raw ALPM query'); pins.append(current)
        need(pins[0] == pins[1], 'exact original installation reasons restored')
    source_tools_business(view, prefix, report, selected, fixed, indexes['installed'], transactions[1], contract)
    source_tools_restoration(report)
    cleanup = report.get('cleanup')
    need(cleanup == dict(homes_retired=True, no_sockets=True, private_directory_absent=True, failures=[])
         and all(cleanup.get(key) is True for key in ('homes_retired', 'no_sockets', 'private_directory_absent')), 'all scoped TEST homes/sockets/private directory retire')
    for home in ('signing', 'trust'):
        index, command = selected('retire-' + home)
        need(command['argv'] == ['/usr/bin/gpgconf', '--homedir', str(trust.parent / home), '--kill', 'all'] and command['expected'] == 0
             and index > indexes['removed'], 'exact TEST home retirement after remove')
        after, command = selected('no-autostart-' + home)
        need(command['argv'] == ['/usr/bin/gpg-connect-agent', '--homedir', str(trust.parent / home), '--no-autostart', '/bye']
             and command['expected'] == 0 and after > index
             and view.read(prefix + command['log']) == b'gpg-connect-agent: no gpg-agent running in this session\n',
             'complete exact no-autostart absence after each TEST retirement')
    native = report.get('native')
    need(type(native) is dict and native.get('architecture') == 'aarch64' and type(native.get('page_bytes')) is int and native['page_bytes'] == guest.get('page_size')
         and native['page_bytes'] > 0 and native.get('execution') == 'OWNED_IMAGE_BUILD_STAGE' and native.get('physical_M2') == 'NOT_RUN' and native.get('release') == 'NOT_ADMITTED',
         'actual native image-stage identity without M2/release inference')
    return dict(status='MATCHED_SOURCE_TOOLS_ALPM_COMPONENT_DATA_ONLY', version='0.1.0-1',
                native='NOT_ADMITTED', native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', release='NOT_ADMITTED')



def source_tools_business(view, prefix, report, selected, fixed, installed_index, remove_index, contract):
    """Join all installed/moved finite CLI outputs to original owned raw logs."""
    business = report.get('business')
    need(type(business) is dict and set(business) == {'system', 'moved'}, 'both actual installed and moved source-tools probes required')
    keys = ('export', 'repeat', 'successor', 'legacy-verify', 'legacy-0-context', 'legacy-0-verify-context',
            'legacy-1-context', 'legacy-1-verify-context', 'current-verify', 'current-0-context',
            'current-0-verify-context', 'current-1-context', 'current-1-verify-context',
            'tampered', 'incomplete', 'incomplete-successor', 'incomplete-release')
    last = installed_index
    for label, home in (('system', fixed/'user-data/system'), ('moved', fixed/'user-data/relocated')):
        value = business[label]; work = home/'workflow'; fixtures = home/'fixtures'
        cli = '/usr/bin/cachy-asahi-source-tools' if label == 'system' else str(fixed/'user-data/moved-prefix/usr/bin/cachy-asahi-source-tools')
        need(type(value) is dict and value.get('status') == 'PASS_SOURCE_TOOLS_FINITE_INSTALLED_PROBE'
             and value.get('version') == '0.1.0-1' and value.get('scope') == value.get('label') == label
             and value.get('cli') == cli and value.get('fixture_root') == str(fixtures) and value.get('work_root') == str(work)
             and type(value.get('controls')) is int and value['controls'] == 17
             and value.get('packages_per_release') == value.get('retained_release_count') == 2 and value.get('exact_contexts') == 4
             and value.get('no_pruning') is True and value.get('actual_selectors') == 'ALL_NULL'
             and value.get('retained_code_execution') == value.get('source_execution') == 'FORBIDDEN'
             and value.get('native_build') == 'NOT_ESTABLISHED_BY_PROBE'
             and value.get('alpm_installation') == 'NOT_ESTABLISHED_BY_PROBE' and value.get('hardware') == 'NOT_RUN' and value.get('release') == 'NOT_ADMITTED',
             'exact17 finite data-only probe scope and NULL native selectors required')
        info = value.get('fixture_info')
        need(type(info) is dict and info.get('purpose') == 'source-tools-synthetic-two-package-roundtrip'
             and info.get('source_execution') == 'FORBIDDEN' and info.get('native_build') == 'NOT_RUN', 'exact inert fixture info required')
        info_raw = (json.dumps(info, sort_keys=True, indent=2) + '\n').encode()
        need(pin(info_raw) == value.get('fixture') and pin(info_raw)['sha256'] == value.get('fixture_data_sha256') == 'fc4b8f4fa1709a4054d2dccf97c961a3e9ab3d6f687c1f1c28110cbdb5844b83'
             and value.get('source_fixture') == {k: contract['recipe']['source_files']['fixtures.tar.gz'][k] for k in ('bytes','sha256')},
             'frozen exact two-package recipe/archive fixture pins required')
        old, current = info['fixtures']
        need([old['label'], current['label']] == ['legacy','current']
             and all([p['name'] for p in fixture['packages']] == ['cachy-asahi-maintenance','cachy-asahi-session-diagnostics'] for fixture in (old,current)), 'exact two packages in each old/current release required')
        retained = sorted([old['release_sha256'], current['release_sha256']])
        need(value.get('retained_releases') == retained, 'both retained releases required without pruning')
        payload = contract['recipe']['payload_files']; map_name = 'usr/share/doc/cachy-asahi-source-tools/payload-map.json'
        need(value.get('installed') == dict(files=17, payload_map={k:payload[map_name][k] for k in ('bytes','sha256')},
            launcher={k:payload['usr/bin/cachy-asahi-source-tools'][k] for k in ('bytes','sha256')}), 'same exact17 installed/moved payload identity required')
        need(type(value.get('steps')) is dict and set(value['steps']) == set(keys)
             and type(value.get('reports')) is dict and set(value['reports']) == set(keys)
             and type(value.get('commands')) is list and len(value['commands']) == 17, 'all17 raw owned CLI command references required')
        observations = {}; positions = []; source_commands = []
        def checked(key, arguments, expected=0):
            step = label + '-' + key
            need(value['steps'][key] == step, 'fixed finite source-tools step reference')
            index, command = selected(step); positions.append(index); raw = view.read(prefix + command['log'])
            argv = ['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(work),'PATH=/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1',cli,*map(str,arguments)]
            need(command['argv'] == argv and command.get('cwd') == str(work) and command['expected'] == expected
                 and pin(raw) == value['reports'][key], 'exact ordinary-user source-tools argv/cwd/raw report pin required')
            data = json.loads(raw); need(type(data) is dict, 'actual source-tools JSON object required')
            source_commands.append(dict(step=key,argv=argv,expected=expected,stdout=pin(raw))); observations[key] = data
            return data
        first = checked('export', ['mirror-export','--release-dir',fixtures/old['label'],'--release-sha256',old['release_sha256'],'--output',work/'first'])
        repeat = checked('repeat', ['mirror-export','--release-dir',fixtures/old['label'],'--release-sha256',old['release_sha256'],'--output',work/'repeat'])
        need(first.get('status') == repeat.get('status') == 'EXPORTED_SOURCE_MIRROR' and first.get('packages') == repeat.get('packages') == 2
             and first.get('release_sha256') == repeat.get('release_sha256') == old['release_sha256']
             and re.fullmatch('[0-9a-f]{64}',first.get('mirror_sha256') or '')
             and first['mirror_sha256'] == repeat.get('mirror_sha256') and first.get('bytes') == repeat.get('bytes'), 'raw deterministic two-package mirror exports required')
        successor = checked('successor',['mirror-successor','--previous-bundle',work/'first/mirror.tar','--previous-sha256',first['mirror_sha256'],
            '--previous-release-sha256',old['release_sha256'],'--release-dir',fixtures/current['label'],'--release-sha256',current['release_sha256'],'--output',work/'history'])
        need(successor.get('status') == 'UPDATED_SOURCE_MIRROR' and successor.get('packages') == 2 and sorted(successor.get('retained_releases',[])) == retained
             and type(successor.get('stats')) is dict and successor['stats'].get('pruned_objects') == 0
             and type(value.get('mirror_bytes')) is int and value['mirror_bytes'] > 0 and re.fullmatch('[0-9a-f]{64}', value.get('mirror_sha256') or '')
             and value.get('mirror') == dict(bytes=value['mirror_bytes'],sha256=value.get('mirror_sha256'))
             and successor.get('mirror_sha256') == value.get('mirror_sha256') and successor.get('bytes') == value['mirror_bytes'], 'raw complete no-pruning history and mirror pin required')
        mirror = work/'history/mirror.tar'; mirror_sha = successor['mirror_sha256']; contexts = []
        for fixture in (old,current):
            stem = fixture['label']; checked_history = checked(stem+'-verify',['mirror-verify','--bundle',mirror,'--sha256',mirror_sha,'--release-sha256',fixture['release_sha256']])
            need(checked_history.get('status') == 'VERIFIED_OFFLINE_SOURCE_MIRROR_HISTORY'
                 and checked_history.get('release_sha256') == fixture['release_sha256'] and sorted(checked_history.get('retained_releases',[])) == retained
                 and checked_history.get('mirror_sha256') == mirror_sha, 'raw offline historical release verification required')
            for index, package in enumerate(fixture['packages']):
                dest = work/(stem+'-'+package['name']); key = stem+'-'+str(index)
                receipt = checked(key+'-context',['build-context','--bundle',mirror,'--mirror-sha256',mirror_sha,'--release-sha256',fixture['release_sha256'],
                    '--package',package['name'],'--version',package['version'],'--arch',package['arch'],'--package-sha256',package['package_sha256'],
                    '--recipe-sha256',package['recipe_sha256'],'--srcinfo-sha256',package['srcinfo_sha256'],'--output',dest])
                identity = dict(name=package['name'],version=package['version'],arch=package['arch'],sha256=package['package_sha256'])
                need(receipt.get('status') == 'MATERIALIZED_MIRROR_BUILDER_CONTEXT' and receipt.get('package') == identity
                     and receipt.get('mirror_sha256') == mirror_sha and receipt.get('release_sha256') == fixture['release_sha256']
                     and re.fullmatch('[0-9a-f]{64}',receipt.get('selection_sha256') or '') and receipt.get('native_build') == receipt.get('hardware') == 'NOT_RUN'
                     and receipt.get('release') == 'NOT_ADMITTED', 'raw exact source/recipe/archive package context without native credit required')
                verified = checked(key+'-verify-context',['verify-context','--context',dest.with_name(dest.name+'-moved'),'--selection-sha256',receipt['selection_sha256']])
                need(verified.get('status') == 'VERIFIED_MIRROR_BUILDER_CONTEXT' and verified.get('package') == identity
                     and verified.get('selection_sha256') == receipt['selection_sha256'] and verified.get('native_build') == verified.get('hardware') == 'NOT_RUN'
                     and verified.get('release') == 'NOT_ADMITTED', 'raw moved-context exact selection verification required')
                sources = package['sources']; source_raw = (json.dumps(sources,sort_keys=True,indent=2)+'\n').encode()
                contexts.append(dict(label=stem,package=package['name'],source_files=len(sources),source_map=pin(source_raw),selection_sha256=receipt['selection_sha256'],
                    license_sha256=sources['LICENSE'],notice_sha256=sources['NOTICE'],actual_selectors='ALL_NULL'))
        need(value.get('contexts') == contexts, 'four exact original source/license maps and held actual selectors required')
        tampered = checked('tampered',['mirror-verify','--bundle',work/'tampered.tar','--sha256',mirror_sha,'--release-sha256',current['release_sha256']],1)
        # Recomputed incomplete digest is observed from the original owned argv,
        # then cross-bound to both refusal commands; no new mirror is acquired.
        _, incomplete_command = selected(label+'-incomplete'); incomplete_args = incomplete_command.get('argv',[])
        need(len(incomplete_args) == 16 and incomplete_args[12] == '--sha256' and re.fullmatch('[0-9a-f]{64}',incomplete_args[13]), 'raw recomputed incomplete mirror pin required')
        incomplete_sha = incomplete_args[13]
        incomplete = checked('incomplete',['mirror-verify','--bundle',work/'incomplete.tar','--sha256',incomplete_sha,'--release-sha256',current['release_sha256']],1)
        prior = checked('incomplete-successor',['mirror-successor','--previous-bundle',work/'incomplete.tar','--previous-sha256',incomplete_sha,'--previous-release-sha256',current['release_sha256'],
            '--release-dir',fixtures/current['label'],'--release-sha256',current['release_sha256'],'--output',work/'must-not-exist'],1)
        absent = checked('incomplete-release',['mirror-export','--release-dir',work/'incomplete-release','--release-sha256',current['release_sha256'],'--output',work/'must-not-exist'],1)
        need(all(row.get('status') == 'REFUSED' and type(row.get('reason')) is str and row['reason'] for row in (tampered,incomplete,prior,absent))
             and tampered['reason'] == 'mirror checksum/bound mismatch'
             and incomplete['reason'] == prior['reason'] == 'history object set mismatch'
             and 'cachy-asahi-maintenance-source.tar' in absent['reason'] and 'No such file or directory' in absent['reason'],
             'all four real tamper/incomplete refusals required; permission failures cannot qualify')
        need(source_commands == value['commands'] and last < min(positions) and positions == sorted(set(positions)) and max(positions) < remove_index,
             'complete ordered installed/moved original command index before remove required')
        last = max(positions)



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
    if 'provision-diagnostic.json' in files:
        # The unchanged191 provisioning retainer uses its original projector.
        # Restrict that validator to the actual closed diagnostic DATA route;
        # no receipt or native journey may enter through its feature rules.
        need(all(name in {'provision-diagnostic.json', 'public-projection.json', 'transport-diagnostic.json', 'transport-proof.json'}
                 or re.fullmatch(r'provision-logs/(?:proof\.json|input-transport-owner\.json|input-cache-owner\.json)-[0-9]{3}\.log', name)
                 or re.fullmatch(r'transport-proof/(?:receipt\.json|[0-9]{4}\.(stdout|stderr))', name)
                 for name in files), 'closed provisioning diagnostic DATA-only namespace required')
        retained_191_provision_projection(view, files, binding, expected['map_sha256'])
        transport_phase = view.load('provision-diagnostic.json').get('phases', {}).get('input-transport-owner.json')
        if transport_phase is not None:
            retained_transport_diagnostic(view, files, transport_phase, binding, expected['map_sha256'])
        diagnostic = view.load('provision-diagnostic.json')
        need(diagnostic['binding'] == binding and diagnostic['source_map_sha256'] == expected['map_sha256']
             and diagnostic['status'] == 'DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY'
             and diagnostic['native'] == diagnostic['GPG'] == diagnostic['ALPM'] == 'NOT_RUN', 'actual DATA diagnostic only')
        return dict(status='VALIDATED_INPUT_PROVISIONING_DIAGNOSTIC_NOT_NATIVE', binding=binding, native='NOT_RUN', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    retained_public_projection(view, files, binding, expected['map_sha256'])
    receipt = view.load('receipt.json'); cleanup = view.load('cleanup.json')
    need(receipt.get('binding') == binding and receipt.get('source_map_sha256') == expected['map_sha256']
         and type(receipt.get('status')) is str and type(cleanup.get('status')) is str,
         'same-source owner and explicit cleanup outcome required')
    consumer_diagnostic = retained_consumer_diagnostic(view, files, receipt, binding, expected['map_sha256'])
    build_summary = retained_build_summary(view, files, binding, expected['map_sha256'])
    failed = (receipt['status'] != PASS or cleanup['status'] != 'PASS_EXACT_OWNED_RESOURCES_RETIRED')
    need(failed or consumer_diagnostic['status'] != 'ABSENT_CONSUMER_DIAGNOSTIC_DATA_ONLY',
         'successful release owner cannot omit original consumer diagnostic')
    if failed or not consumer_diagnostic['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_FAILURE_DATA_ONLY', binding=binding,
                    owner_status=receipt['status'], cleanup_status=cleanup['status'],
                    consumer_diagnostic=consumer_diagnostic, build_summary=build_summary,
                    component_failure=source_tools_failure_data(view, files, expected['map_sha256']),
                    native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    retained_consumer_diagnostic(view, files, receipt, binding, expected['map_sha256'], positive=True)
    retained_failure_data(view, files, receipt.get('bootstrap_failure_data'), binding, expected['map_sha256'])
    retained_image_lifecycle(view, files, receipt, cleanup, binding, expected['map_sha256'])
    need(receipt['binding'] == binding and receipt['source_map_sha256'] == expected['map_sha256']
         and receipt['status'] == PASS
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
    need(guest.get('operation') == OPERATION and guest.get('source_map_sha256') == expected['map_sha256']
         and guest.get('system_install') == 'IMAGE_STAGE_ALPM_ONLY' and guest.get('release') == 'NOT_ADMITTED',
         'selected release operation and no target/release inference required')
    component = retained_source_tools_alpm(view, files, guest, expected['map_sha256'])
    return dict(status='VALIDATED_NATIVE_SOURCE_TOOLS_ALPM_COMPONENT_EVIDENCE_ONLY', binding=binding,
                source_tools=component, native='NOT_ADMITTED', native_16K='NOT_QUALIFIED',
                physical_M2='NOT_RUN', release='NOT_ADMITTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule', type=Path, required=True, help='ordinary public-tree.tar; directory ingress is unsupported')
    parser.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.capsule, load(args.binding)), sort_keys=True))
