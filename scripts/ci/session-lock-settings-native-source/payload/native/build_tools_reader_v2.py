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
from common import consumer_contract, load, need, pin, read
from capsule import open_capsule
from privacy_diagnostics import validate_refusal
from safe_diagnostic import check_consumer, check_pair


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
                  docker + ['build', '--quiet', '--network=none', '--pull=false', '--no-cache', '--platform=linux/arm64', '--tag', aliases[role],
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


PRODUCERS = {'native/build_tools_alpm_v2.py': 'beb5fb4145860e6d71e3f11ff300a31af5ee88c779acd4f790b6ed0787eb2104', 'native/build_tools_tools_v2.py': '9a862c88f459801ae6b9a2e97d277db1ddf9db46b905ab1a0b6ec81b0b7745b9', 'native/build_tools_guest_v2.py': 'bf7fe40f8fa0db133260164707b87cdb1da0f269f669606e6a51e491268a1f1d', 'native/build-tools-contract-v2.json': 'a96327c43772bcb401100e00100c35f1e4942ecc8cefeb9336cbfdc257866aa7'}

PASS = 'PASS_SESSION_LOCK_SETTINGS_NATIVE_ALPM_COMPONENT'
OPERATION = 'session-lock-settings-alpm-v1'


def hyprland_archive_custody(raw, command, contract, index, private_marker):
    """Independently parse exact public source bodies and every tar byte boundary."""
    import io
    import tarfile
    need(type(raw) is bytes and 0<len(raw)<=2*1024**2 and len(raw)%512==0,
         'bounded block-aligned package tar required')
    match=re.fullmatch(r'archive-([ab])-(helper|settings)',command.get('step',''));label=match[1] if match else None;package_kind=match[2] if match else None
    recipe=contract['recipes'][package_kind] if package_kind is not None else {};fixed=Path(contract['invocation']['source']).parent
    need(label is not None and type(index) is int and index>=0
         and command.get('log')=='%03d-archive-%s-%s.log'%(index,label,package_kind)
         and command.get('argv')==['/usr/bin/zstd','-dc',str(fixed/'build-inputs'/label/package_kind/recipe['archive'])]
         and type(command.get('expected')) is int and command['expected']==0
         and command.get('log_pin')==pin(raw), 'exact source-owned archive decoder command and raw pin required')
    expected=recipe['payload_files'];need(len(expected)==(4 if package_kind=='helper' else 9),'exact source source-bound package payload required')
    ancestors={str(parent) for leaf in expected for parent in Path(leaf).parents if str(parent)!='.'}
    payload={};metadata={};seen=set();directories=set();cursor=0;headers=0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            for member in archive:
                name=member.name.rstrip('/')
                need(member.offset==cursor and member.offset_data==cursor+512 and not member.pax_headers
                     and member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE),
                     'contiguous single-header ordinary tar member required; hidden headers refused')
                header=raw[cursor:cursor+512]
                need(len(header)==512 and not private_marker.search(header),'private marker in package tar header refused')
                need(name not in seen and member.uid==member.gid==0 and name==Path(name).as_posix()
                     and '..' not in Path(name).parts,'unique canonical root-owned package members required')
                need(type(member.size) is int and 0<=member.size<=1024**2,'finite nonnegative package member size required')
                seen.add(name);start=member.offset_data;end=start+member.size;padded=start+((member.size+511)//512)*512
                need(end<=padded<=len(raw) and not any(raw[end:padded]),'package tar padding must be zero')
                if member.isdir():
                    need(name in ancestors and member.mode==0o755 and member.size==0,'exact zero-body package directory required')
                    directories.add(name)
                else:
                    need(member.isfile() and member.size<=1024**2,'ordinary finite package body required')
                    body=raw[start:end];need(len(body)==member.size,'complete raw package body required')
                    if name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                        need(member.mode==0o644 and not private_marker.search(body),'private marker or wrong mode in package metadata refused')
                        metadata[name]=body
                    else:
                        need(name in expected and member.mode==expected[name]['mode']
                             and pin(body)=={key:expected[name][key] for key in ('bytes','sha256')},'exact source-bound public package body required')
                        payload[name]=dict(mode=member.mode,**pin(body))
                cursor=padded;headers+=1
    except (tarfile.TarError,UnicodeError,EOFError):
        raise ValueError('bounded source-bound package tar structure refused') from None
    need(set(payload)==set(expected) and directories==ancestors and set(metadata)=={'.PKGINFO','.BUILDINFO','.MTREE'},
         'complete finite package payload and metadata namespace required')
    need(len(raw)-cursor>=1024 and not any(raw[cursor:]),'complete zero package tar trailer required')
    for name in ('.PKGINFO','.BUILDINFO'):
        need(len(metadata[name])<=256*1024,'bounded textual package metadata required')
    pkg=build_tools_metadata(metadata['.PKGINFO']);build=build_tools_metadata(metadata['.BUILDINFO'])
    need(all(re.fullmatch('[a-z][a-z0-9_]*',key) and all(len(value)<=8192 for value in values)
         for doc in (pkg,build) for key,values in doc.items()),'bounded canonical makepkg metadata fields required')
    for key,value in (('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('arch','any')):
        need(pkg.get(key)==[value],'exact package identity required')
    need({k:v for k,v in pkg.items() if k not in ('builddate','packager','size')}==recipe['metadata'],'exact MIT package/runtime dependency metadata required')
    for key,value in (('format','2'),('pkgname',recipe['name']),('pkgbase',recipe['name']),
                      ('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['source_files']['PKGBUILD']['sha256'])):
        need(build.get(key)==[value],'exact package BUILDINFO identity required')
    installed=build.get('installed',[])
    need(len(installed)==len(set(installed))==len(recipe['buildinfo_installed']) and sorted(installed)==recipe['buildinfo_installed']
         and 'check' in build.get('buildenv',[]) and '!check' not in build['buildenv'],'exact349 provenance and checks required')
    return dict(kind='exact-source-bound-session-lock-settings-package-tar-v1',label=label,package=package_kind,step=command['step'],argv=command['argv'],
        raw_pin=pin(raw),contract_sha256=PRODUCERS['native/build-tools-contract-v2.json'],payload_files=len(payload),
        metadata={name:pin(body) for name,body in metadata.items()},
        framing=dict(headers=headers,blocks=len(raw)//512,zero_padding=True,zero_trailer_bytes=len(raw)-cursor),
        privacy='Exact source bound public payload bodies; every raw header and metadata body scanned; padding and trailer zero')

def retained_public_projection(view, files, binding, map_sha256, *, retirement_selection="legacy834"):
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
    prefix = 'journey/session-lock-settings-alpm-v1/'
    log_pattern = r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log'
    private_marker = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('status') == 'PASS_FINITE_SESSION_LOCK_SETTINGS_PUBLIC_DATA_PROJECTION'
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256
         and value.get('source_producers') == PRODUCERS
         and value.get('omitted_private_scopes') == ['journey/session-lock-settings-alpm-v1/home']
         and value.get('original_output_unchanged') is True and value.get('omitted_private_trees_walked') is False
         and value.get('privacy') == 'Ordinary DATA marker refusal; only exact source-bound package tar custody permits bound public source identifiers'
         and value.get('scope') == 'Fixed session-lock-settings-alpm-v1 result, commands and raw referenced logs only; private home trees not retained',
         'same-source exact finite release projection and explicit omission scope required')
    need(pin(view.read(name)) == {key: files[name][key] for key in ('bytes', 'sha256')}, 'projection receipt actual bytes differ')
    selected = value.get('selected')
    need(type(selected) is dict and 0 < len(selected) <= 2998 and set(files) == set(selected) | {name}
         and ('receipt.json' in selected) != ('provision-diagnostic.json' in selected),
         'closed finite projection leaf set and sole authority required')
    custody=value.get('archive_custody');need(type(custody) is dict and len(custody)<=4,'finite exact archive custody map required')
    result_name=prefix+'result.json';archive_commands={}
    if result_name in selected:
        source_report=view.load(result_name);source_commands=source_report.get('commands',[])
        need(type(source_commands) is list and len(source_commands)<=1000,'finite source command records required')
        for index,command in enumerate(source_commands):
            need(type(command) is dict,'typed original command row required')
            if re.fullmatch(r'archive-[ab]-(helper|settings)',command.get('step','')) is not None:
                leaf=command.get('log');need(type(leaf) is str and re.fullmatch(log_pattern,leaf),'exact archive log name required')
                target=prefix+leaf;need(target not in archive_commands,'duplicate archive custody target refused')
                archive_commands[target]=(index,command)
    checked_custody={}
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
        if target in archive_commands:
            index,command=archive_commands[target]
            checked_custody[target]=hyprland_archive_custody(view.read(target),command,build_tools_contract(),index,private_marker)
        else:
            need(not private_marker.search(view.read(target)), 'private marker in projected public DATA refused')
    need(custody==checked_custody,'complete independently parsed source-bound archive custody required')
    result_name = prefix + 'result.json'
    actual_logs = {target for target in selected if target.startswith(prefix) and re.fullmatch(log_pattern, target[len(prefix):])}
    if result_name not in selected:
        need(not actual_logs, 'projected release logs require original component result')
        return dict(status='VALIDATED_FINITE_DESKTOP_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))
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
        need(guest.get('build_tools_alpm') == report, 'positive guest and separately retained release results differ')
    return dict(status='VALIDATED_FINITE_DESKTOP_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))




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
    name = 'safe-diagnostic.json'; optional = {'consumer-diagnostic.json', 'build-summary.json', 'projection-refusal.json', 'pair-failure.json'}
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
        cap = 32*1024 if target in ('projection-refusal.json','pair-failure.json') else 512*1024
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
        elif target == 'pair-failure.json':
            check_pair(document,binding,map_sha256)
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


def build_tools_commands(view, files, prefix, commands):
    need(type(commands) is list and 0 < len(commands) <= 160 and view.load(prefix + 'commands.json') == commands,
         'actual finite standalone build_tools command list required')
    for index, command in enumerate(commands):
        need(type(command) is dict, 'typed build_tools command row required')
        step = command.get('step'); log = command.get('log'); state = command.get('supervision')
        need(type(step) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}', step)
             and log == '%03d-%s.log' % (index, step), 'ordered source-owned command log namespace required')
        target = prefix + log
        need(target in files and files[target]['kind'] == 'file'
             and pin(view.read(target)) == command.get('log_pin') == {k: files[target][k] for k in ('bytes', 'sha256')}, 'complete raw build_tools command log required')
        expected = command.get('expected'); code = state.get('exit') if type(state) is dict else None
        matched = type(code) is int and (code > 0 if expected == 'nonzero' else type(expected) is int and code == expected)
        need(command.get('success') is True and type(state) is dict and matched
             and state.get('reaped') is True and state.get('ownership') == 'REAPED'
             and state.get('group_census') == 'EMPTY_TWICE' and state.get('output_complete') is True
             and state.get('error') is None and state.get('timeout') is False and state.get('signals') == [], 'actual original owned natural retirement required')
        need(type(command.get('argv')) is list and 0 < len(command['argv']) <= 128
             and all(type(arg) is str and len(arg) <= 8192 for arg in command['argv']) and Path(command['argv'][0]).is_absolute(), 'bounded explicit build_tools argv required')
    def selected(step):
        rows = [(i, row) for i, row in enumerate(commands) if row['step'] == step]
        need(len(rows) == 1, 'sole exact build_tools command reference required')
        return rows[0]
    return selected


def build_tools_metadata(raw):
    need(type(raw) is bytes and len(raw) <= 2*1024**2, 'bounded package metadata text required')
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'): continue
        need(' = ' in line, 'exact makepkg metadata separator required')
        key, value = line.split(' = ', 1); result.setdefault(key, []).append(value)
    return result









def build_tools_restoration(report):
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




def build_tools_failure_data(view, files, map_sha256):
    """Read only source-bound first-failure observations; never acceptance."""
    prefix = 'journey/session-lock-settings-alpm-v1/'; name = prefix + 'result.json'
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
    report = json.loads(raw); contract = build_tools_contract()
    contract_raw = read(Path(__file__).resolve().with_name('build-tools-contract-v2.json'))
    need(type(report) is dict and type(report.get('schema_version')) is int and report['schema_version'] == 1
         and report.get('operation') == OPERATION and report.get('source_map_sha256') == map_sha256
         and report.get('contract') == pin(contract_raw)
         and pin(contract_raw)['sha256'] == PRODUCERS['native/build-tools-contract-v2.json']
         and contract.get('operation') == OPERATION, 'same-map exact failure result/producer contract required')
    result['process_layout']=build_tools_process_layout(report)
    result.update(reason='FIRST_FAILURE_UNAVAILABLE', result=pin(raw), namespace_observations=build_tools_namespace_data(view,files,report,map_sha256))
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
    result.update(status='VALIDATED_BUILD_TOOLS_FAILURE_DATA_ONLY', reason='ORIGINAL_FAILED_COMMAND_OBSERVED',
                  command=dict(index=index,pin=pin(command_raw),row=command), supervision=supervision,
                  supervision_status='UNKNOWN' if supervision is None else 'OBSERVED_DATA_ONLY',
                  log=dict(name=target,**pin(raw_log)))
    return result


def build_tools_process_layout(report):
    """Typed observation only; it does not prove adoption, reaping or group absence."""
    layout=report.get('process_layout') if type(report) is dict else None
    need(type(layout) is dict and set(layout)=={'schema','contract','python_pid','python_ppid','status'}
         and type(layout['schema']) is int and layout['schema']==1
         and layout['contract']=='bash-pid1-direct-python-child-v1'
         and type(layout['python_pid']) is int and 1<layout['python_pid']<2**31
         and type(layout['python_ppid']) is int and layout['python_ppid']==1
         and layout['status']=='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD',
         'explicit observed non-PID1 Python directly parented by namespace init required')
    return layout


def build_tools_positive_state(report):
    """A persisted PASS cannot override a later observation/retention failure."""
    build_tools_process_layout(report)
    need(type(report) is dict and report.get('retention_failures', []) == []
         and report.get('first_failure') is None and report.get('failure') is None,
         'positive source-tools evidence refuses retention or primary failure state')









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



def build_policy_declared(argv):
    """Describe existing Docker build arguments; no effective-policy inference."""
    need(type(argv) is list and 3 <= len(argv) <= 96
         and all(type(v) is str and 0 < len(v.encode()) <= 4096 for v in argv)
         and len(json.dumps(argv, allow_nan=False).encode()) <= 16*1024
         and argv[:3] == ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'build'],
         'bounded original Docker build argv required')
    def values(option):
        result = []; index = 3
        while index < len(argv):
            item = argv[index]
            if item == option:
                need(index+1 < len(argv) and not argv[index+1].startswith('--'), 'declared build option value required')
                result.append(argv[index+1]); index += 2; continue
            if item.startswith(option+'='):
                value = item[len(option)+1:]; need(value, 'empty declared build option refused'); result.append(value)
            index += 1
        return result
    caches = [v for v in argv[3:] if v == '--no-cache' or v.startswith('--no-cache=')]
    need(len(caches) <= 1 and all(v in ('--no-cache','--no-cache=true','--no-cache=false') for v in caches),
         'single boolean no-cache declaration required')
    result = dict(daemon_endpoint='unix:///var/run/docker.sock', no_cache=bool(caches) and caches[0] != '--no-cache=false')
    for key in ('network', 'pull', 'platform', 'builder'):
        rows = values('--'+key); need(len(rows) <= 1, 'duplicate singleton build declaration refused')
        result[key] = rows[0] if rows else None
    options = values('--security-opt')
    need(len(options) <= 4 and all(len(v.encode()) <= 256 for v in options), 'bounded declared security options required')
    result.update(security_options=options, security_options_status='DECLARED' if options else 'NOT_DECLARED',
                  builder_status='DECLARED' if result['builder'] is not None else 'NOT_DECLARED')
    return result


def build_tools_build_policy_data(view, files, receipt, binding, map_hash):
    """Join original build-launcher/context DATA; unavailable rules stay UNKNOWN."""
    def same(left, right):
        return json.dumps(left,sort_keys=True,allow_nan=False,separators=(',',':')) == json.dumps(right,sort_keys=True,allow_nan=False,separators=(',',':'))
    need(type(binding) is dict and set(binding) == {'source','ref','run','attempt','token'}
         and re.fullmatch('[0-9a-f]{40}', binding.get('source') or '')
         and type(binding.get('ref')) is str and binding['ref'].startswith('refs/heads/codex/')
         and re.fullmatch('[1-9][0-9]*', binding.get('run') or '')
         and type(binding.get('attempt')) is int and binding['attempt'] == 1
         and binding.get('token') == hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
         and type(map_hash) is str and re.fullmatch('[0-9a-f]{64}', map_hash), 'exact build policy source/run/token/map binding required')
    need(type(receipt) is dict and same(receipt.get('binding'), binding)
         and receipt.get('source_map_sha256') == map_hash, 'original owner receipt source binding differs')
    value = receipt.get('image_build_policy')
    keys = {'schema','status','binding','source_map_sha256','domain','reason','build_actor','declared','context','policy_provenance','native_acceptance'}
    need(type(value) is dict and set(value) == keys and type(value['schema']) is int and value['schema'] == 1
         and type(value['binding']) is dict and type(value['binding'].get('attempt')) is int
         and same(value['binding'], binding) and value['source_map_sha256'] == map_hash
         and value['domain'] == 'IMAGE_BUILD_STAGE' and value['native_acceptance'] == 'NOT_ADMITTED'
         and len(json.dumps(value, sort_keys=True, allow_nan=False).encode()) <= 64*1024,
         'typed bounded image-build policy receipt required')
    provenance = value['policy_provenance']
    need(type(provenance) is dict and set(provenance) == {'declared_source','context_source','effective_seccomp_rules','matched_lsm_denial','bwrap_exec_boundary','daemon_policy'}
         and all(provenance[k] == 'UNKNOWN' for k in ('effective_seccomp_rules','matched_lsm_denial','bwrap_exec_boundary','daemon_policy')),
         'receipt cannot claim effective policy/rule/denial/exec attribution')
    projection = view.load('public-projection.json').get('selected')
    need(type(projection) is dict, 'original public projection required for build policy')
    def projected(name, cap=16*1024**2):
        need(type(name) is str and name in files and name in projection and files[name].get('kind') == 'file'
             and type(files[name].get('bytes')) is int and 0 <= files[name]['bytes'] <= cap
             and type(projection[name]) is dict and type(projection[name].get('bytes')) is int,
             'retained ordinary bounded build policy DATA required')
        body = view.read(name); digest = pin(body)
        need(digest == {k:files[name][k] for k in ('bytes','sha256')}
             == {k:projection[name][k] for k in ('bytes','sha256')}, 'build policy manifest/projection/body pin differs')
        return body
    need(same(json.loads(projected('receipt.json')), receipt), 'original receipt DATA differs')
    if value['status'] == 'UNKNOWN_IMAGE_BUILD_LAUNCHER_POLICY_DATA_ONLY':
        need(value['reason'] in ('NO_RETAINED_BUILD_ACTOR','NO_RETAINED_BUILD_LOG','RECEIPT_DATA_REFUSED')
             and value['build_actor'] is value['declared'] is value['context'] is None
             and provenance['declared_source'] == provenance['context_source'] == 'UNKNOWN',
             'unavailable build policy must carry explicit UNKNOWN only')
        return dict(status='VALIDATED_IMAGE_BUILD_LAUNCHER_POLICY_DATA_ONLY', receipt=value, native='NOT_ADMITTED')
    need(value['status'] == 'BOUND_IMAGE_BUILD_LAUNCHER_POLICY_DATA_ONLY' and value['reason'] is None
         and provenance['declared_source'] == 'ORIGINAL_BUILD_ACTOR_ARGV', 'bound original build policy required')
    actor = value['build_actor']; rows = receipt.get('actors')
    need(type(actor) is dict and set(actor) == {'index','argv','public_log','log_pin'}
         and type(actor['index']) is int and type(rows) is list and len(rows) <= 1000 and 0 <= actor['index'] < len(rows),
         'exact original build actor selector required')
    row = rows[actor['index']]
    need(type(row) is dict and all(k in row for k in ('argv','public_log','log_pin'))
         and [index for index,item in enumerate(rows) if same(item, row)] == [actor['index']]
         and same(actor, dict(index=actor['index'], **{k:row[k] for k in ('argv','public_log','log_pin')})),
         'build actor fields must equal its original owner row')
    cleanup = json.loads(projected('cleanup.json')); operations = cleanup.get('build_operations')
    need(type(operations) is list and len(operations) <= 2, 'bounded original build operations required')
    tools = [item for item in operations if type(item) is dict and item.get('role') == 'tools']
    need(len(tools) == 1 and tools[0].get('terminal') is True and same(tools[0].get('actor'), row),
         'sole terminal tools build operation must select original actor')
    declared = build_policy_declared(actor['argv'])
    need(type(value['declared']) is dict and set(value['declared']) == set(declared)
         and type(value['declared'].get('no_cache')) is bool
         and type(value['declared'].get('security_options')) is list
         and same(value['declared'], declared), 'declared policy must describe exact original build argv')
    def options(option):
        argv = actor['argv']; result = []
        for index, part in enumerate(argv[3:], 3):
            if part == option:
                need(index+1 < len(argv), 'missing original build identity option'); result.append(argv[index+1])
            elif part.startswith(option+'='): result.append(part[len(option)+1:])
        return result
    label = 'org.cachy-asahi.native-developer'; labels = options('--label')
    need(options('--tag') == ['native-developer-tools:'+binding['token']]
         and [v for v in labels if v.startswith(label+'=')] == [label+'='+binding['token']]
         and [v for v in labels if v.startswith(label+'.source=')] == [label+'.source='+binding['source']],
         'actual tools tag/source/token labels required')
    need(type(actor['log_pin']) is dict and set(actor['log_pin']) == {'bytes','sha256'}
         and type(actor['log_pin']['bytes']) is int and type(actor['log_pin']['sha256']) is str
         and type(actor['public_log']) is str and re.fullmatch(r'actor-logs/[0-9]{4}\.log', actor['public_log'])
         and pin(projected(actor['public_log'])) == actor['log_pin'],
         'actual build public_log/body required; actor index is not a filename')
    context = value['context']; report_name = 'journey/session-lock-settings-alpm-v1/result.json'
    report = json.loads(projected(report_name,4*1024**2)) if report_name in files else None
    need(report is None or type(report) is dict and type(report.get('image_build_context')) is dict, 'exported image-stage result context field required')
    need(same(context, report.get('image_build_context') if type(report) is dict else None),
         'policy context must equal original exported image-stage result')
    if context is None:
        need(provenance['context_source'] == 'UNKNOWN', 'absent build context cannot claim provenance')
        return dict(status='VALIDATED_IMAGE_BUILD_LAUNCHER_POLICY_DATA_ONLY', receipt=value, native='NOT_ADMITTED')
    need(provenance['context_source'] == 'EXPORTED_IMAGE_STAGE_RESULT'
         and type(report) is dict and report.get('source_map_sha256') == map_hash
         and report.get('operation') == OPERATION and type(context) is dict
         and set(context) == {'schema','status','domain','source_map_sha256','reason','evidence','values','native_acceptance'}
         and type(context['schema']) is int and context['schema'] == 1
         and context['domain'] == 'IMAGE_BUILD_STAGE' and context['source_map_sha256'] == map_hash
         and context['native_acceptance'] == 'NOT_ADMITTED', 'typed exact image-stage context required')
    if context['status'] == 'UNKNOWN':
        need(context['reason'] in ('NO_RETAINED_CONTEXT','CONTEXT_DATA_REFUSED')
             and context['evidence'] is context['values'] is None, 'unavailable context must be explicit UNKNOWN')
        return dict(status='VALIDATED_IMAGE_BUILD_LAUNCHER_POLICY_DATA_ONLY', receipt=value, native='NOT_ADMITTED')
    need(context['status'] == 'OBSERVED' and context['reason'] is None, 'only existing observed context allowed')
    evidence = context['evidence']; commands = report.get('commands')
    need(type(evidence) is dict and set(evidence) == {'command_index','log','log_pin'}
         and type(evidence['command_index']) is int and type(commands) is list and len(commands) <= 160
         and 0 <= evidence['command_index'] < len(commands), 'original context command selector required')
    command = commands[evidence['command_index']]
    need(type(command) is dict and command.get('log') == evidence['log'] and command.get('log_pin') == evidence['log_pin']
         and type(evidence['log']) is str and re.fullmatch(r'[0-9]{3}-namespace-[ab]-context\.log', evidence['log'])
         and evidence['log'].startswith('%03d-'%evidence['command_index'])
         and type(evidence['log_pin']) is dict and set(evidence['log_pin']) == {'bytes','sha256'}
         and type(evidence['log_pin']['bytes']) is int and 0 < evidence['log_pin']['bytes'] <= 32768
         and type(evidence['log_pin']['sha256']) is str and re.fullmatch('[0-9a-f]{64}', evidence['log_pin']['sha256']),
         'original context log selector/pin required')
    observations = report.get('namespace_observations'); need(type(observations) is dict, 'existing namespace observations required')
    need(all(type(group) is dict and type(group.get('observations')) is list for group in observations.values()),
         'typed original context observation groups required')
    matches = [entry for group in observations.values() if type(group) is dict
               for entry in group.get('observations',[]) if type(entry) is dict and entry.get('mode') == 'context'
               and entry.get('command_index') == evidence['command_index'] and entry.get('output') == evidence['log_pin']]
    need(len(matches) == 1, 'sole existing context observation/output pin required')
    body = projected('journey/session-lock-settings-alpm-v1/'+evidence['log'],32768); observed = json.loads(body)
    need(pin(body) == evidence['log_pin'] and type(observed) is dict
         and set(observed) == {'schema','status','mode','source_map_sha256','before','syscall','after','scope','namespace_acceptance','native_acceptance'}
         and type(observed.get('schema')) is int and observed.get('schema') == 1 and observed.get('status') == 'NAMESPACE_PREREQUISITE_DATA_ONLY'
         and observed.get('mode') == 'context' and observed.get('source_map_sha256') == map_hash
         and observed.get('syscall') is None and same(observed.get('before'), observed.get('after'))
         and same(observed.get('before'), context['values'])
         and observed.get('scope') == 'OWN_BUILD_ACTOR_SELF_ONLY_NO_CHILD_OR_GLOBAL_MUTATION'
         and observed.get('namespace_acceptance') == 'NOT_ESTABLISHED' and observed.get('native_acceptance') == 'NOT_ADMITTED',
         'context must copy exact same-map existing namespace DATA, not later consumer metadata')
    need(type(context['values']) is dict and set(context['values']) == {'uid','euid','gid','egid','cwd','groups',
         'group_count','groups_truncated','status_fields','status_state','namespaces','maps','policy','lsm','mounts','bwrap'}
         and len(json.dumps(context['values'],sort_keys=True,allow_nan=False).encode()) <= 32768,
         'bounded complete retained launcher context required')
    return dict(status='VALIDATED_IMAGE_BUILD_LAUNCHER_POLICY_DATA_ONLY', receipt=value, native='NOT_ADMITTED')


def build_tools_local_binding(expected_map):
    """Authenticate the exact trusted local closed200 before capsule ingress and package-probe imports."""
    import os
    import stat
    root=Path(__file__).resolve().parents[1];map_path=root/'native/source-map.json'
    def whole(path,cap):
        need(path==path.resolve()and not any(q.is_symlink()for q in(path,*path.parents)),'trusted local Source cannot alias')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=cap,'bounded local Source leaf')
            with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(cap+1)
            identity=lambda q:(q.st_dev,q.st_ino,q.st_mode,q.st_nlink,q.st_size,q.st_mtime_ns,q.st_ctime_ns)
            need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable exact local Source leaf');return raw,stat.S_IMODE(before.st_mode)
        finally:os.close(fd)
    raw,_=whole(map_path,1024**2);need(pin(raw)['sha256']==expected_map,'Root-bound local SourceMap hash before public capsule')
    manifest=json.loads(raw);rows=manifest['files'];need(type(rows)is dict and len(rows)==199 and 'native/source-map.json'not in rows and manifest.get('actual')==dict(source=None,ref=None,run=None),'exact nonrecursive199-row new closed200 namespace')
    actual=set();actual_dirs=set();total=0;nodes=0
    for path in root.rglob('*'):
        nodes+=1;need(nodes<=1024 and len(path.relative_to(root).parts)<=16,'held local Source node/depth caps')
        info=path.lstat();need(not path.is_symlink()and(stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode)),'ordinary complete trusted local Source')
        if stat.S_ISREG(info.st_mode):actual.add(path.relative_to(root).as_posix())
        else:actual_dirs.add(path.relative_to(root).as_posix())
    expected_dirs={str(q)for n in set(rows)|{'native/source-map.json'}for q in Path(n).parents if str(q)!='.'}
    need(actual==set(rows)|{'native/source-map.json'}and actual_dirs==expected_dirs,'complete local Source200 without unlisted nodes or empty directories')
    for name,row in rows.items():
        q=Path(name);need(type(name)is str and q.as_posix()==name and not q.is_absolute()and '..'not in q.parts and 0<len(q.parts)<=16,'closed local Source relative path')
        need(type(row)is dict and set(row)=={'bytes','sha256','mode'}and type(row['bytes'])is int and 0<row['bytes']<=64*1024**2 and type(row['mode'])is int and row['mode']in(0o644,0o755),'held local Source per-file descriptor caps')
        body,mode=whole(root/name,row['bytes']);total+=len(body);need(total<=128*1024**2 and pin(body)=={k:row[k]for k in('bytes','sha256')}and mode==row['mode'],'every local Source200 body/mode held')
    for name,digest in PRODUCERS.items():need(rows[name]['sha256']==digest,'all package producer pins must match external Root-bound Source map')
    need(rows['native/build_tools_reader_v2.py']['sha256']==pin(whole(Path(__file__).resolve(),1024**2)[0])['sha256'],'matching reader self joins Root-bound Source')
    need(manifest.get('session_lock_settings_operation')==OPERATION,'exact Hyprland03 operation in Root-bound local Source map')
    return manifest


def build_tools_contract():
    raw=read(Path(__file__).resolve().with_name('build-tools-contract-v2.json'))
    need(pin(raw)['sha256']==PRODUCERS['native/build-tools-contract-v2.json'],'closed pair contract producer pin')
    value=json.loads(raw)
    need(value.get('schema')==1 and value.get('operation')==OPERATION and value.get('pair')=='settings011-session-lock010'
         and set(value.get('actual',{}))=={'source','ref','run','job','artifact'} and all(v is None for v in value['actual'].values())
         and set(value.get('recipes',{}))=={'helper','settings'},'unexecuted exact pair contract')
    for kind,name,version,count,blocks in [('helper','cachy-asahi-session-lock','0.1.0-1',4,[24,2]),('settings','cachy-asahi-hyprland-settings','0.1.1-1',9,[5,2])]:
        recipe=value['recipes'][kind]
        need(recipe['name']==name and recipe['version']==version and len(recipe['payload_files'])==count and recipe['test_blocks']==blocks
             and len(recipe['buildinfo_installed'])==(349 if kind=='helper' else 350),'finite exact pair recipe inputs')
    return value


def build_tools_namespace_data(view,files,report,map_sha256):
    need(not report.get('namespace_observations') and not report.get('namespace_observation_failures'),'unsupported namespace observations cannot qualify this pair')
    return {}


def pair_check_result(raw,recipe):
    text=raw.decode('utf-8','strict')
    need(raw.count(b'Starting check()')==1 and ('Finished making: '+recipe['name']+' '+recipe['version'])in text
         and not any(word in text for word in ('ERROR:','Skipping','FAILED','Traceback','SyntaxError','skipped=','expected failures=','unexpected successes=')),'successful actual dependency-checked makepkg stage')
    blocks=list(map(int,re.findall(r'Ran ([1-9][0-9]*) tests? in [0-9.]+s\n\nOK\b',text)))
    need(blocks==recipe['test_blocks'],'actual complete recipe test blocks')
    return dict(status='PASS_EXACT_RECIPE_CHECK_STAGE',tests=sum(blocks),blocks=blocks)


def pair_builds(view,prefix,report,contract,selected,map_hash):
    builds=report.get('builds');comparison=report.get('comparison');fixed=Path(contract['invocation']['source']).parent
    need(type(builds)is dict and set(builds)=={'a-helper','a-settings','b-helper','b-settings'}
         and comparison.get('status')=='PASS_EXACT_NATIVE_PAIR_OF_PACKAGES' and comparison.get('source_map_sha256')==map_hash,'complete exact pair of clean native pairs')
    identities=set();archives={};indexes=[];private_marker=re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b',re.I)
    for kind in ('helper','settings'):
        recipe=contract['recipes'][kind];pair=comparison['packages'][kind];decoded={};pins={}
        need(pair['status']=='PASS_EXACT_NATIVE_BUILD_PAIR' and pair['payload_files']==len(recipe['payload_files'])
             and pair['buildinfo_count']==len(recipe['buildinfo_installed']),'exact per-package provenance comparison')
        for label in ('a','b'):
            key=label+'-'+kind;item=builds[key];index,command=selected('build-'+key);indexes.append(index)
            slot=str(fixed/'build-current');expected=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+slot,'PKGDEST='+slot,'SRCDEST='+slot,'BUILDDIR='+slot,
                'SOURCE_DATE_EPOCH='+contract['build_pair']['source_date_epoch'],'PACKAGER='+contract['build_pair']['packager'],'/usr/bin/makepkg','--cleanbuild','--nosign','--noconfirm','--config',str(Path(contract['invocation']['source'])/contract['makepkg_config']['path'])]
            need(command['argv']==expected and command['cwd']==slot and command['expected']==0,'exact dependency-checking enabled makepkg argv')
            check=pair_check_result(view.read(prefix+command['log']),recipe)
            directory=item['build_directory'];identity=directory['identity'];token=(identity.get('device'),identity.get('inode'))
            need(all(type(v)is int and v>=0 for v in token) and token not in identities and directory['logical']==slot
                 and directory['initial_files']==sorted(recipe['source_files']) and item['check_result']==check
                 and item['version']==recipe['version'] and item['recipe_sha256']==recipe['source_files']['PKGBUILD']['sha256'],'fresh exact independent source inode/check identity')
            identities.add(token);archive=item['archive'];path=str(fixed/'build-inputs'/label/kind/recipe['archive'])
            need(archive['filename']==recipe['archive'] and type(archive['bytes'])is int and 0<archive['bytes']<=1024**2
                 and re.fullmatch('[0-9a-f]{64}',archive['sha256']),'exact actual built archive pin')
            archives[key]=dict(path=path,pin={k:archive[k]for k in ('bytes','sha256')})
            _,decode=selected('archive-'+key);raw=view.read(prefix+decode['log'])
            custody=hyprland_archive_custody(raw,decode,contract,selected('archive-'+key)[0],private_marker)
            files={}
            import io,tarfile
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as stream:
                for member in stream:
                    if member.isfile():files[member.name]=stream.extractfile(member).read()
            archives[key]['pkginfo']=build_tools_metadata(files['.PKGINFO'])
            decoded[label]=files;pins[label]=archive
            need(pair['builds'][label]==dict(archive=archives[key]['pin'],metadata={n:pin(files[n])for n in ('.PKGINFO','.BUILDINFO','.MTREE')},payload={n:pin(files[n])for n in recipe['payload_files']}),'independently decoded exact metadata/payload comparison joins')
        need(pins['a']==pins['b'] and decoded['a']==decoded['b'],'exact archive and full metadata/payload equality')
    need([selected('build-a-helper')[0],selected('build-a-settings')[0],selected('build-b-helper')[0],selected('build-b-settings')[0]]==sorted(set(indexes)),'four builds in strict independent-iteration order')
    return archives


def retained_build_tools_alpm(view,files,guest,map_sha256):
    contract=build_tools_contract();prefix='journey/'+OPERATION+'/';report=guest.get('build_tools_alpm');build_tools_positive_state(report)
    need(report.get('schema_version')==1 and report.get('operation')==OPERATION and report.get('status')==PASS and report.get('pair')==contract['pair']
         and report.get('source_map_sha256')==map_sha256 and report.get('contract')==pin(read(Path(__file__).resolve().with_name('build-tools-contract-v2.json')))
         and view.load(prefix+'result.json')==report,'same-source actual original pair result')
    stages=['sign','build-a-helper','bootstrap-a-install','build-a-settings','bootstrap-a-remove','build-b-helper','bootstrap-b-install','build-b-settings','bootstrap-b-remove','compare','install','remove','reinstall','remove-again','restore','cleanup']
    need(report.get('stages')==stages,'complete ordered pair/bootstrap lifecycle')
    selected=build_tools_commands(view,files,prefix,report['commands']);archives=pair_builds(view,prefix,report,contract,selected,map_sha256)
    base=read(Path(__file__).resolve().with_name('expected349.lock'))
    need(pin(base)=={k:contract['expected349'][k]for k in ('bytes','sha256')} and len(base.splitlines())==349 and guest.get('packages')==pin(base),'actual genuine349 baseline')
    wanted={'baseline':()}
    for label in ('a','b'):
        wanted['bootstrap-'+label+'-installed']=('helper',);wanted['bootstrap-'+label+'-removed']=()
    wanted.update(installed=('helper','settings'),removed=(),reinstalled=('helper','settings'))
    wanted['removed-again']=();need(set(report['inventory'])==set(wanted),'all349/350 bootstrap/351 pair inventory states')
    indexes={}
    for state,kinds in wanted.items():
        rows=base.splitlines(keepends=True)+[(contract['recipes'][k]['name']+' '+contract['recipes'][k]['version']+'\n').encode()for k in kinds]
        expected=pin(b''.join(sorted(rows)));index,command=selected(state+'-inventory');indexes[state]=index
        need(report['inventory'][state]==dict(**expected,count=349+len(kinds)) and command['argv']==['/usr/bin/pacman','-Q']
             and pin(b''.join(sorted(view.read(prefix+command['log']).splitlines(keepends=True))))==expected,'actual exact ALPM inventory raw joins')
    config_index,command=selected('required-signature-config');need(command['argv'][0]=='/usr/bin/cat' and len(command['argv'])==2,'actual Required config read')
    config=command['argv'][1];trust=Path(config).with_name('trust')
    need(trust.parent.parent==Path('/tmp') and trust.parent.name.startswith('build-tools-test-') and Path(config).name=='pacman.conf','owned isolated TEST trust path')
    raw=('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n').encode()
    need(view.read(prefix+command['log'])==raw and report['signature_config']==pin(raw)
         and report['signature_policy']==dict(SigLevel='Required',LocalFileSigLevel='Required'),'actual Required/Required exact policy')
    signatures=report['signatures'];need(set(signatures)==set(archives),'all four detached native archive signatures')
    signer=report['fingerprint'];verify_indexes={}
    verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
    for key,archive in archives.items():
        entry=signatures[key];strict_test_signature(entry['status'],signer);encoded=entry['signature'];signature=base64.b64decode(encoded['base64'],validate=True)
        need(0<len(signature)<=65536 and entry['signer']==signer and pin(signature)=={k:encoded[k]for k in ('bytes','sha256')},'bounded actual detached TEST signature')
        index,command=selected(entry['verify_step']);verify_indexes[key]=index
        need(command['argv']==verifier+['--status-fd=1','--verify',archive['path']+'.sig',archive['path']]
             and view.read(prefix+command['log']).decode().strip()==entry['status'].strip()
             and selected('build-'+key)[0]<index,'actual signed archive status and command join')
    public=report['public_key'];need(public['text'].startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----')and 'PRIVATE KEY'not in public['text']
         and pin(public['text'].encode())=={k:public[k]for k in ('bytes','sha256')},'TEST public key only')
    for step in ('test-primary-fingerprint','trust-key-membership'):
        _,command=selected(step);need([line.split(':')[9]for line in view.read(prefix+command['log']).decode().splitlines()if line.startswith('fpr:')]==[signer],'sole exact signing/trust TEST primary')
    _,command=selected('export-only-test-public');need(view.read(prefix+command['log'])==public['text'].encode()and command['argv'][-3:]==['--armor','--export',signer],'exact public-only TEST key export')
    for step,marker in [('untrusted-signature-control',b'NO_PUBKEY'),('tampered-signature-control',None)]:
        index,command=selected(step);raw=view.read(prefix+command['log']);need(command['expected']=='nonzero'and '--verify'in command['argv']
             and(marker in raw if marker else b'BADSIG'in raw or b'ERRSIG'in raw),'actual unknown-key/tamper refusal')
        target=archives['a-helper']['path']if marker else str(trust.parent/'tampered.pkg.tar.zst')
        need(command['argv']==verifier+['--status-fd=1','--verify',archives['a-helper']['path']+'.sig',target]
             and(selected('build-a-helper')[0]<index<verify_indexes['a-helper']if marker else max(verify_indexes.values())<index<selected('install')[0]),'exact artifact-bound unknown/tamper command chronology')
    for label in ('a','b'):
        install,command=selected('bootstrap-'+label+'-install');remove,removal=selected('bootstrap-'+label+'-remove')
        need(command['argv']==['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-U',archives[label+'-helper']['path']]
             and removal['argv']==['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-R',contract['recipes']['helper']['name']]
             and verify_indexes[label+'-helper']<install<indexes['bootstrap-'+label+'-installed']<selected('build-'+label+'-settings')[0]
             <verify_indexes[label+'-settings']<remove<indexes['bootstrap-'+label+'-removed'],'real signed local dependency bootstrap ordering')
    fixed=Path(contract['invocation']['source']).parent;expected_hashes={n:item['sha256']for recipe in contract['recipes'].values()for n,item in recipe['payload_files'].items()}
    need(set(report['verification'])=={'build-a','build-b','installed','reinstalled'},'all four actual source-prefix verifications')
    for phase,label in [('build-a','a'),('build-b','b'),('installed','a'),('reinstalled','b')]:
        index,command=selected('verify-prefix-'+phase);value=json.loads(view.read(prefix+command['log']))
        expected=['/usr/bin/python3','-I','-B',str(fixed/'verification/desktop_session_lock.py'),'--profile',str(fixed/'verification/desktop-session-lock011.json'),'--profile-sha256',contract['verification']['profile_sha256'],
         '--settings-package',archives[label+'-settings']['path'],'--settings-sha256',archives[label+'-settings']['pin']['sha256'],'--session-lock-package',archives[label+'-helper']['path'],'--session-lock-sha256',archives[label+'-helper']['pin']['sha256'],'--prefix',str(fixed/('verified-prefix-'+phase))]
        need(command['argv']==expected and value==report['verification'][phase] and value.get('status')=='desktop-session-lock-prefix-pass'
             and value.get('payload_files')==13 and value.get('payload_sha256')==expected_hashes and value.get('profile_sha256')==contract['verification']['profile_sha256']
             and value.get('payload_executed')is False and value.get('read_only')is True,'actual matching profile verification with all13 source bytes')
        expected_packages={recipe['name']:dict(sha256=archives[label+'-'+kind]['pin']['sha256'],bytes=archives[label+'-'+kind]['pin']['bytes'],
            volatile_metadata={key:archives[label+'-'+kind]['pkginfo'][key]for key in ('builddate','packager','size')})for kind,recipe in contract['recipes'].items()}
        need(type(value.get('schema'))is int and value['schema']==1 and value.get('record_type')=='offline-desktop-session-lock-prefix-verification'
             and value.get('profile')=='hyprland011-session-lock010' and value.get('packages')==expected_packages and value.get('host_arch')=='aarch64'
             and value.get('checks')==dict(exact_archives_metadata_payload='PASS',audited_Lua_binding_delta='PASS',exact_assembled_prefix='PASS')
             and all(value.get(key)=='NOT RUN'for key in ('native_build','installed_database_ownership','dependency_resolution','session_runtime','hardware_validation')),'complete bounded source verifier result and scope')
        if phase.startswith('build-'):
            need(max(selected('archive-'+key)[0]for key in archives)<index<selected('install')[0],'profile verification follows archive comparison and precedes install')
        else:
            need(selected('install'if phase=='installed'else'reinstall')[0]<index<selected('remove'if phase=='installed'else'remove-again')[0],'installed prefix verification inside its transaction')
    need(set(report['payloads'])=={'installed','reinstalled'} and set(report['business'])=={'installed','reinstalled'},'both installed observations required')
    for label,phase,install,remove,removed in [('a','installed','install','remove','removed'),('b','reinstalled','reinstall','remove-again','removed-again')]:
        start,command=selected(install);end,removal=selected(remove)
        need(command['argv']==['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-U',archives[label+'-helper']['path'],archives[label+'-settings']['path']]
             and removal['argv']==['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-R',contract['recipes']['settings']['name'],contract['recipes']['helper']['name']]
             and start<indexes[phase]<end<indexes[removed] and max(verify_indexes.values())<selected('install')[0],'signed pair install/remove chronology')
        payload=report['payloads'][phase];need(payload==dict(count=13,verified=True,packages={kind:dict(name=recipe['name'],version=recipe['version'],files=recipe['payload_files'])for kind,recipe in contract['recipes'].items()}),'actual13 source-bound ALPM payload observation')
        tag='reinstall-'if label=='b'else ''
        for kind,recipe in contract['recipes'].items():
            owners=[]
            for index,row in enumerate(report['commands']):
                if row['step']==tag+'owner-'+recipe['name']:
                    need(start<index<end and row['argv'][:4]==['/usr/bin/pacman','--config',config,'-Qoq']and len(row['argv'])==5
                         and view.read(prefix+row['log']).strip()==recipe['name'].encode(),'actual installed owner query inside transaction')
                    owners.append(row['argv'][4].removeprefix('/'))
            need(sorted(owners)==sorted(recipe['payload_files']),'every actual payload owner accounted')
            index,row=selected(tag+'owned-files-'+recipe['name']);names=view.read(prefix+row['log']).decode().splitlines()
            need(start<index<end and row['argv']==['/usr/bin/pacman','--config',config,'-Qlq',recipe['name']]and len(names)==len(set(names))
                 and {n.lstrip('/')for n in names if not n.endswith('/')}==set(recipe['payload_files'])
                 and {n.strip('/')for n in names if n.endswith('/')}=={str(p)for n in recipe['payload_files']for p in Path(n).parents if str(p)!='.'},'complete installed file/directory ALPM inventory')
        business=report['business'][phase];need(set(business)=={'helper-help','screenshot-help','config-verify'},'finite no-lock/no-suspend installed behavior')
        env=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(fixed/'business-home'),'XDG_RUNTIME_DIR='+str(fixed/'business-home')]
        targets={'helper-help':['/usr/bin/cachy-asahi-session-lock','--help'],'screenshot-help':['/usr/bin/cachy-asahi-screenshot','--help'],
                 'config-verify':['/usr/bin/Hyprland','--verify-config','--config','/usr/share/cachy-asahi/hyprland/hyprland.lua']}
        for key,argv in targets.items():
            index,row=selected(phase+'-'+key);raw=view.read(prefix+row['log'])
            need(start<index<end and row['argv']==env+argv and business[key]==dict(argv=row['argv'],output=pin(raw))
                 and(b'config ok'in raw if key=='config-verify'else b'usage:'in raw),'actual installed help/parser only')
    for key,flag in [('explicit','-Qqe'),('dependencies','-Qqd')]:
        pins=[]
        for phase,target in [('baseline-reasons','install_reasons_before'),('restored-reasons','install_reasons_after')]:
            _,command=selected(phase+'-'+key);value=pin(b''.join(sorted(view.read(prefix+command['log']).splitlines(keepends=True))))
            need(command['argv']==['/usr/bin/pacman',flag]and report[target][key]==value,'actual raw install-reason query');pins.append(value)
        need(pins[0]==pins[1],'original reasons restored')
    build_tools_restoration(report)
    need(report['cleanup']==dict(homes_retired=True,no_sockets=True,private_directory_absent=True,failures=[]),'complete scoped signing/trust cleanup')
    for home in ('signing','trust'):
        index,row=selected('retire-'+home);after,check=selected('no-autostart-'+home)
        need(index>indexes['removed-again'] and row['argv']==['/usr/bin/gpgconf','--homedir',str(trust.parent/home),'--kill','all']
             and after>index and check['argv']==['/usr/bin/gpg-connect-agent','--homedir',str(trust.parent/home),'--no-autostart','/bye']
             and view.read(prefix+check['log'])==b'gpg-connect-agent: no gpg-agent running in this session\n','exact complete scoped agent retirement')
    native=report['native'];need(native.get('architecture')=='aarch64'and type(native.get('page_bytes'))is int and native['page_bytes']==guest['page_size']
         and native['page_bytes']>0 and native.get('execution')=='OWNED_IMAGE_BUILD_STAGE'and native.get('physical_M2')=='NOT_RUN'and native.get('release')=='NOT_ADMITTED','actual native component only')
    return dict(status='MATCHED_SESSION_LOCK_SETTINGS_ALPM_COMPONENT_DATA_ONLY',pair=contract['pair'],native='NOT_ADMITTED',native_16K='NOT_QUALIFIED',physical_M2='NOT_RUN',release='NOT_ADMITTED')


def validate(capsule_path, expected):
    need(type(expected) is dict and set(expected) == {'source', 'ref', 'run', 'map_sha256'}
         and re.fullmatch('[0-9a-f]{40}', expected.get('source') or '')
         and isinstance(expected.get('ref'), str) and expected['ref'].startswith('refs/heads/codex/')
         and re.fullmatch('[1-9][0-9]*', expected.get('run') or '')
         and re.fullmatch('[0-9a-f]{64}', expected.get('map_sha256') or ''), 'NULL/unbound actual native evidence refused before reading')
    build_tools_local_binding(expected['map_sha256'])
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
    image_build_policy = build_tools_build_policy_data(view, files, receipt, binding, expected['map_sha256'])
    failed = (receipt['status'] != PASS or cleanup['status'] != 'PASS_EXACT_OWNED_RESOURCES_RETIRED')
    need(failed or consumer_diagnostic['status'] != 'ABSENT_CONSUMER_DIAGNOSTIC_DATA_ONLY',
         'successful release owner cannot omit original consumer diagnostic')
    if failed or not consumer_diagnostic['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_FAILURE_DATA_ONLY', binding=binding,
                    owner_status=receipt['status'], cleanup_status=cleanup['status'],
                    consumer_diagnostic=consumer_diagnostic, build_summary=build_summary, image_build_policy=image_build_policy,
                    component_failure=build_tools_failure_data(view, files, expected['map_sha256']),
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
    component = retained_build_tools_alpm(view, files, guest, expected['map_sha256'])
    return dict(status='VALIDATED_NATIVE_SESSION_LOCK_SETTINGS_ALPM_COMPONENT_EVIDENCE_ONLY', binding=binding,
                build_tools=component, image_build_policy=image_build_policy, native='NOT_ADMITTED', native_16K='NOT_QUALIFIED',
                physical_M2='NOT_RUN', release='NOT_ADMITTED')



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule', type=Path, required=True, help='ordinary public-tree.tar; directory ingress is unsupported')
    parser.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.capsule, load(args.binding)), sort_keys=True))
