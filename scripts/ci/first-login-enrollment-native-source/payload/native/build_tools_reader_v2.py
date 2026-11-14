# SPDX-License-Identifier: MIT
"""Passive capsule DATA reader; refuse NULL selectors before opening capsule.

Symlink targets are ordinary DATA payloads. No capsule member is extracted,
imported or followed.
"""
import argparse
import base64
import hashlib
import io
import json
import math
from pathlib import Path
import re
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import consumer_contract, load, need, pin, read
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


PRODUCERS = {'native/build_tools_alpm_v2.py': 'd4197495e0281aecfd590e76ed908cd1fcf46b1934bc02709e47a7dac49abb73', 'native/build_tools_tools_v2.py': 'eb1ff0ee8aefc2c0e32b38520e1bf0dabcbb9308081a24e2f9c378366a3cab13', 'native/build_tools_guest_v2.py': 'a212f79640d6873dc59639d97da262f4e02fe9bb5d23d55eaf68d936c56a5383', 'native/build-tools-contract-v2.json': 'b38f63e2b2a4d3af501540da4251d29db65d9b1226052429df6e428d418dde33'}

PASS = 'PASS_FIRST_LOGIN_ENROLLMENT_NATIVE_ALPM_COMPONENT'
OPERATION = 'first-login-enrollment-alpm-v1'



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
    prefix = 'journey/first-login-enrollment-alpm-v1/'
    log_pattern = r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log'
    private_marker = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('status') == 'PASS_FINITE_FIRST_LOGIN_ENROLLMENT_PUBLIC_DATA_PROJECTION'
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256
         and value.get('source_producers') == PRODUCERS
         and value.get('omitted_private_scopes') == ['journey/first-login-enrollment-alpm-v1/home']
         and value.get('original_output_unchanged') is True and value.get('omitted_private_trees_walked') is False
         and value.get('privacy') == 'Ordinary DATA marker refusal; only exact source-bound package tar custody permits bound public source identifiers'
         and value.get('scope') == 'Fixed first-login-enrollment-alpm-v1 result, commands and raw referenced logs only; private home trees not retained',
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
            if command.get('step') in ('archive-first-login-a','archive-first-login-b','archive-enrollment-a','archive-enrollment-b'):
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
        return dict(status='VALIDATED_FINITE_FIRST_LOGIN_ENROLLMENT_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))
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
    return dict(status='VALIDATED_FINITE_FIRST_LOGIN_ENROLLMENT_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))




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
    context = value['context']; report_name = 'journey/first-login-enrollment-alpm-v1/result.json'
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
         and type(evidence['command_index']) is int and type(commands) is list and len(commands) <= 320
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
    body = projected('journey/first-login-enrollment-alpm-v1/'+evidence['log'],32768); observed = json.loads(body)
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
    need(manifest.get('first_login_enrollment_operation')==OPERATION,'exact Hyprland03 operation in Root-bound local Source map')
    return manifest


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
    return dict(status='VALIDATED_NATIVE_FIRST_LOGIN_ENROLLMENT_ALPM_COMPONENT_EVIDENCE_ONLY', binding=binding,
                build_tools=component, image_build_policy=image_build_policy, native='NOT_ADMITTED', native_16K='NOT_QUALIFIED',
                physical_M2='NOT_RUN', release='NOT_ADMITTED')




# Independent retained-byte validation; producer modules are never imported.

def data_pin(raw): return pin(raw)

def _metadata(raw):
    need(len(raw) <= 256 * 1024, 'metadata byte cap')
    rows = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'canonical makepkg metadata field')
        key, value = line.split(' = ', 1)
        need(re.fullmatch('[a-z][a-z0-9_]*', key) and len(value) <= 8192, 'bounded makepkg metadata field')
        rows.setdefault(key, []).append(value)
    return rows

def archive_data(raw,recipe,installed):
    need(type(raw) is bytes and 0<len(raw)<=2*1024**2 and len(raw)%512==0, 'finite complete decoded package')
    expected=recipe['payload_files'];ancestors={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
    seen=set();directories=set();payload={};metadata={};cursor=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name=member.name.rstrip('/');need(name not in seen and member.offset==cursor and
                member.offset_data==cursor+512 and not member.pax_headers and member.uid==member.gid==0 and
                member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE) and
                name==Path(name).as_posix() and '..' not in Path(name).parts,'canonical single-header package framing')
            seen.add(name);end=member.offset_data+member.size;padded=member.offset_data+((member.size+511)//512)*512
            need(0<=member.size<=1024**2 and padded<=len(raw) and not any(raw[end:padded]), 'bounded zero padding')
            cursor=padded
            if member.isdir():
                need(name in ancestors and member.mode==0o755 and member.size==0,'exact directory namespace/mode')
                directories.add(name);continue
            need(member.isfile(),'no links/special files/install hooks')
            body=raw[member.offset_data:end]
            if name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                need(member.mode==0o644,'metadata mode');metadata[name]=body
            else:
                need(name in expected and dict(mode=member.mode,**data_pin(body))==expected[name], 'exact source-bound package payload')
                payload[name]=expected[name]
    need(not any(raw[cursor:]) and len(raw)-cursor>=1024 and directories==ancestors and
         set(payload)==set(expected) and set(metadata)=={'.PKGINFO','.BUILDINFO','.MTREE'}, 'complete payload/metadata/trailer')
    pkg,build=_metadata(metadata['.PKGINFO']),_metadata(metadata['.BUILDINFO'])
    for key,value in (('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('arch','any')):
        need(pkg.get(key)==[value],'exact PKGINFO '+key)
    for key,field in (('depend','depends'),('makedepend','makedepends'),('checkdepend','checkdepends'),('optdepend','optdepends')):
        need(pkg.get(key,[])==recipe[field],'exact PKGINFO dependencies '+key)
    need(pkg.get('license')==['MIT'],'original MIT package license')
    for key,value in (('format','2'),('pkgname',recipe['name']),('pkgbase',recipe['name']),
                      ('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['source_files']['PKGBUILD']['sha256'])):
        need(build.get(key)==[value],'exact BUILDINFO '+key)
    need(sorted(build.get('installed',[]))==installed and len(installed)==len(set(build['installed']))==350 and
         'check' in build.get('buildenv',[]) and '!check' not in build['buildenv'],'all350 exact dependency/check provenance')
    return dict(metadata=metadata,payload=payload)

def check_result(raw,kind,policy):
    need(type(raw) is bytes and 0<len(raw)<=1024**2 and raw.count(b'Starting check()')==1,
         'one actual makepkg check() per clean build')
    text=raw.decode();recipe=policy['recipes'][kind]
    need(not any(token in text for token in ('FAILED (','ERROR:','skipped=','expected failures=')),
         'package check failures/skips refused')
    if kind=='first-login':
        names=re.findall(r'^(test_[A-Za-z0-9_]+) \(__main__\.[A-Za-z]+Tests\.[A-Za-z0-9_]+\) \.\.\. ok$',text,re.M)
        need(sorted(names)==sorted(recipe['check_names']) and len(names)==len(set(names))==14 and
             re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$',text,re.M)==['11','3'] and
             text.splitlines().count('OK')==2, 'all actual FirstLogin11 plus delivery3 checks')
        return dict(status='PASS_ACTUAL_FIRST_LOGIN_CHECKS',tests=14,names=names)
    reports=[]
    for line in text.splitlines():
        if line.startswith('{'):
            try:reports.append(json.loads(line))
            except ValueError:pass
    need(len(reports)==1 and reports[0]==recipe['check_report'], 'actual full relocated signed/zstd/bwrap check report')
    return dict(status='PASS_ACTUAL_ENROLLMENT_PACKAGE_WORKFLOW',report=reports[0])


def build_tools_contract():
    raw=read(Path(__file__).resolve().with_name('build-tools-contract-v2.json'))
    need(pin(raw)['sha256']==PRODUCERS['native/build-tools-contract-v2.json'],'Root-bound new pair contract')
    value=json.loads(raw)
    need(type(value['schema']) is int and value['schema']==1 and value['operation']==OPERATION and
         value['actual']==dict(source=None,ref=None,run=None,job=None,artifact=None),'unbound pair contract')
    need({kind:row['version'] for kind,row in value['recipes'].items()}==
         {'first-login':'0.1.0-2','enrollment':'0.3.0-1'} and
         {kind:len(row['payload_files']) for kind,row in value['recipes'].items()}==
         {'first-login':6,'enrollment':15},'exact new pair identities and payload counts')
    need(len(value['buildinfo_installed'])==len(set(value['buildinfo_installed']))==350 and
         'cachy-asahi-setup-0.3.0-1-any' in value['buildinfo_installed'],'full350 real dependency provenance')
    return value


def hyprland_archive_custody(raw,command,contract,index,private_marker):
    # Role filename is retained solely to keep the finite200 source namespace.
    # This parser accepts only the NEW operation's explicit four archive roles.
    match=re.fullmatch(r'archive-(first-login|enrollment)-([ab])',command.get('step',''))
    need(match is not None and type(index) is int,'exact new archive custody role')
    kind,label=match.groups();recipe=contract['recipes'][kind]
    path=Path('/opt/native-first-login-enrollment-alpm-v1/build-inputs')/(kind+'-'+label)/recipe['archive']
    need(command['argv']==['/usr/bin/zstd','-dc',str(path)] and command['expected']==0 and
         command['log']=='%03d-%s.log'%(index,command['step']) and pin(raw)==command['log_pin'],'exact decoder command/raw log')
    data=archive_data(raw,recipe,contract['buildinfo_installed'])
    # Bound public source bodies may contain literal refusal fixtures. Headers
    # and metadata remain scanned; padding/trailers were independently checked.
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            need(not private_marker.search(raw[member.offset:member.offset_data]),'private package header refused')
    for body in data['metadata'].values():need(not private_marker.search(body),'private package metadata refused')
    return dict(kind='exact-source-bound-pair-package-tar-v1',package=kind,label=label,step=command['step'],
                argv=command['argv'],raw_pin=pin(raw),contract_sha256=PRODUCERS['native/build-tools-contract-v2.json'],
                payload_files=len(data['payload']),metadata={name:pin(body) for name,body in data['metadata'].items()},
                framing='CONTIGUOUS_HEADERS_ZERO_PADDING_AND_TRAILER_EXACT_SOURCE_PAYLOAD')


def strict_test_signature(status,signer):
    need(type(status) is str and re.fullmatch('[0-9A-F]{40}',signer or ''),'explicit TEST signer')
    rows=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    bad={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    need(not any(row and row[0] in bad for row in rows),'invalid TEST signature/key state')
    valid=[row for row in rows if row and row[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==signer and
         any(row and row[0]=='TRUST_ULTIMATE' for row in rows),'one exact trusted TEST primary')


def pair_commands(view,files,prefix,commands,positive):
    need(type(commands) is list and 0<len(commands)<=320 and view.load(prefix+'commands.json')==commands,
         'complete finite original command index')
    selected={};seconds={'operation':0.0,'cleanup':0.0}
    for index,row in enumerate(commands):
        need(type(row) is dict and type(row.get('step')) is str and re.fullmatch('[A-Za-z0-9._+-]{1,96}',row['step']) and
             row['step'] not in selected and row.get('log')=='%03d-%s.log'%(index,row['step']),'unique exact command/log index')
        name=prefix+row['log'];need(name in files and files[name]['kind']=='file' and
             pin(view.read(name))==row.get('log_pin')=={k:files[name][k] for k in ('bytes','sha256')},'every retained original raw log')
        need(type(row.get('argv')) is list and row['argv'] and len(row['argv'])<=128 and
             all(type(arg) is str and len(arg)<=16384 for arg in row['argv']) and Path(row['argv'][0]).is_absolute(),
             'bounded explicit original command argv')
        if positive:
            observed=row.get('supervision')
            need(row.get('success') is True and type(observed) is dict and observed.get('reaped') is True and
                 observed.get('ownership')=='REAPED' and observed.get('group_census')=='EMPTY_TWICE' and
                 observed.get('output_complete') is True and observed.get('timeout') is False and
                 observed.get('signals')==[] and observed.get('error') is None,'natural owned command reaping/output/group absence')
            expected=row.get('expected');code=observed.get('exit')
            need(type(code) is int and ((expected=='nonzero' and code>0) or type(expected) is int and code==expected),
                 'actual expected command exit including controlled75/2 and refusals')
            cleanup=row['step'].startswith(('cleanup-','retire-private-','no-agent-private-'))
            elapsed=observed.get('seconds');cap=20 if cleanup else 180
            need(type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<=elapsed<cap,'held finite owned command clock')
            seconds['cleanup' if cleanup else 'operation']+=elapsed
        selected[row['step']]=(index,row,view.read(name))
    need(not positive or seconds['operation']<450 and seconds['cleanup']<90,'held aggregate operation/cleanup observation budgets')
    return selected


def build_tools_failure_data(view,files,map_hash):
    prefix='journey/'+OPERATION+'/';name=prefix+'result.json'
    if name not in files:return dict(status='ABSENT_PAIR_FAILURE_DATA',native='NOT_ADMITTED')
    report=view.load(name)
    need(type(report) is dict and report.get('operation')==OPERATION and report.get('source_map_sha256')==map_hash,
         'same-map pair failure DATA only')
    if report.get('commands'):pair_commands(view,files,prefix,report['commands'],False)
    return dict(status='VALIDATED_PAIR_FAILURE_DATA_ONLY',first_failure=report.get('first_failure'),
                failure=report.get('failure'),cleanup=report.get('cleanup'),native='NOT_ADMITTED')


def retained_build_tools_alpm(view,files,guest,map_hash):
    contract=build_tools_contract();prefix='journey/'+OPERATION+'/'
    report=guest.get('build_tools_alpm');build_tools_positive_state(report)
    need(type(report) is dict and report.get('status')==PASS and report.get('operation')==OPERATION and
         report.get('source_map_sha256')==map_hash and view.load(prefix+'result.json')==report,'same-source actual new pair result')
    need(report['stages']==contract['stages'],'complete exact dependency/pairs/lifecycle/journey stages')
    selected=pair_commands(view,files,prefix,report['commands'],True)
    def entry(step):
        need(step in selected,'required actual command missing: '+step);return selected[step]
    fixed=Path('/opt/native-first-login-enrollment-alpm-v1');slot=fixed/'build-current'
    indexes=[];pairs={};all_inodes=set()
    for kind in ('first-login','enrollment'):
        recipe=contract['recipes'][kind];comparison=report['comparisons'][kind];compressed={};decoded={};inodes=set()
        for label in ('a','b'):
            build=report['builds'][kind][label];step='build-'+kind+'-'+label
            index,row,raw=entry(step);indexes.append(index)
            expected=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(slot),'PKGDEST='+str(slot),
                      'SRCDEST='+str(slot),'BUILDDIR='+str(slot),'SOURCE_DATE_EPOCH='+contract['build_pair']['source_date_epoch'],
                      'PACKAGER='+contract['build_pair']['packager'],'/usr/bin/makepkg','--cleanbuild','--nosign','--noconfirm',
                      '--config',str(fixed/'source'/contract['makepkg_config']['path'])]
            need(row['argv']==expected and row['cwd']==str(slot) and row['expected']==0 and
                 build['dependency_checking'] is True and build['check_invoked'] is True and build['check']==check_result(raw,kind,contract) and
                 build['initial_files']==sorted(recipe['source_files']) and build['version']==recipe['version'],
                 'ordinary fresh dependency-checked makepkg and exact real package check report')
            identity=build['directory'];need(type(identity['device']) is int and type(identity['inode']) is int,'actual source directory identity')
            inodes.add((identity['device'],identity['inode']))
            all_inodes.add((identity['device'],identity['inode']))
            path=fixed/'build-inputs'/(kind+'-'+label)/recipe['archive']
            _,cat,body=entry('compressed-'+kind+'-'+label)
            need(cat['argv']==['/usr/bin/cat',str(path)] and pin(body)==build['archive'],'complete compressed package body custody')
            compressed[label]=body
            _,decoder,raw_tar=entry('archive-'+kind+'-'+label)
            need(decoder['argv']==['/usr/bin/zstd','-dc',str(path)],'actual matching decoder path')
            decoded[label]=archive_data(raw_tar,recipe,contract['buildinfo_installed'])
            wanted=dict(archive=pin(body),metadata={n:pin(b) for n,b in decoded[label]['metadata'].items()},payload=decoded[label]['payload'])
            need(comparison['builds'][label]==wanted,'recomputed exact pair metadata/payload/compressed hashes')
        need(len(inodes)==2 and compressed['a']==compressed['b'] and decoded['a']==decoded['b'] and
             comparison['status']=='PASS_EXACT_NATIVE_BUILD_PAIR' and comparison['archive']==pin(compressed['a']) and
             comparison['base_inventory_count']==350 and comparison['source_map_sha256']==map_hash and
             comparison['equality']==dict(archive=True,payload=True,pkginfo=True,buildinfo=True,mtree=True),
             'two genuinely separate clean sources with exact archive/metadata/payload equality')
        pairs[kind]=dict(archive=pin(compressed['a']),payload_files=len(recipe['payload_files']),base_inventory=350)
    need(indexes==sorted(indexes) and len(set(indexes))==4 and len(all_inodes)==4,'all four distinct clean sources in declared build order')
    base=read(Path(__file__).resolve().with_name('expected349.lock'))
    need(pin(base)==contract['baseline'] and len(base.splitlines())==349,'genuine baseline349')
    base_rows=dict(line.split(' ',1) for line in base.decode().splitlines())
    dep={'cachy-asahi-setup':'0.3.0-1'};both={**dep,**{r['name']:r['version'] for r in contract['recipes'].values()}}
    order=[]
    for step,versions in [('baseline-inventory',{}),('dependency-inventory',dep),('install-inventory',both),
                          ('remove-inventory',dep),('reinstall-inventory',both),('remove-again-inventory',dep),('final-inventory',{})]:
        index,row,raw=entry(step);order.append(index)
        expected=''.join(name+' '+version+'\n' for name,version in sorted({**base_rows,**versions}.items())).encode()
        need(raw==expected and report['inventory'][step]==dict(**pin(raw),count=len(expected.splitlines()),versions=versions),
             'exact349/350/352 lifecycle inventory and recorded bytes')
    need(order==sorted(order) and order[1]<indexes[0]<indexes[-1]<order[2],'dependency installed before all four builds and candidate lifecycle')
    config=entry('required-signature-config')[2].decode()
    match=re.fullmatch(r'\[options\]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = (/tmp/build-tools-test-[A-Za-z0-9_+-]+/trust)\nHookDir = /builder-disabled-hooks\n',config)
    need(match is not None and pin(config.encode())==report['signature_config'],'Required/Required isolated TEST trust configuration')
    work=Path(match[1]).parent;pacman=['--config',str(work/'pacman.conf')]
    for stage,label in [('install','a'),('reinstall','b')]:
        _,row,_=entry(stage)
        expected=['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-U',
                  *[str(fixed/'build-inputs'/(kind+'-'+label)/contract['recipes'][kind]['archive']) for kind in ('first-login','enrollment')]]
        need(row['argv']==expected,'real normal dependency-aware signed installation/reinstallation')
        for kind,recipe in contract['recipes'].items():
            payload=report['payloads'][stage][kind]
            need(payload==dict(verified=True,files=recipe['payload_files']),'all actual ALPM source-bound payload leaves')
            _,query,raw=entry(stage+'-'+kind+'-file-list')
            need(query['argv']==['/usr/bin/pacman',*pacman,'-Qlq',recipe['name']] and
                 {name.lstrip('/') for name in raw.decode().splitlines() if not name.endswith('/')}==set(recipe['payload_files']),
                 'exact observed ALPM package-owned file list')
            for number,name in enumerate(sorted(recipe['payload_files'])):
                _,owner,raw=entry(stage+'-'+kind+'-owner-'+str(number))
                need(owner['argv']==['/usr/bin/pacman',*pacman,'-Qqo','/'+name] and raw.decode().strip()==recipe['name'],'every actual payload ownership query')
    for stage in ('remove','remove-again'):
        need(entry(stage)[1]['argv']==['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R',
             *[contract['recipes'][kind]['name'] for kind in ('first-login','enrollment')]],'real candidate package removal')
    need(entry('install-setup8')[1]['argv']==['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-U',str(fixed/'build-inputs'/contract['dependency']['archive'])] and
         entry('remove-setup8')[1]['argv']==['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R','cachy-asahi-setup'],'authentic explicit Setup8 dependency lifecycle')
    signer=report['fingerprint']
    strict_test_signature(entry('verify-setup8')[2].decode(),signer)
    need(report['signatures']['setup8']['archive']==contract['dependency']['archive_pin'] and
         report['signatures']['setup8']['status']==entry('verify-setup8')[2].decode(),'actual TEST verification of exact retained Setup8 input')
    need('NO_PUBKEY' in entry('untrusted-signature-control')[2].decode() and
         any(token in entry('tampered-signature-control')[2] for token in (b'BADSIG',b'ERRSIG')),'unknown-key and altered-byte refusals')
    for kind in ('first-login','enrollment'):
        for label in ('a','b'):
            _,row,raw=entry('verify-'+kind+'-'+label);strict_test_signature(raw.decode(),signer)
            need(report['signatures'][kind][label]['status']==raw.decode() and
                 report['signatures'][kind][label]['archive']==pairs[kind]['archive'],'actual source-bound TEST signature verification')
    for label in ('installed','moved'):
        user=report['business']['install']['first_login'][label]
        need(user['status']=='PASS' and user['command_count']==len(user['ordered_steps'])==27 and
             user['shell_startups']==10 and user['pty']=='NOT RUN' and user['hardware']=='NOT RUN' and
             user['template_and_program_preservation'] is True and user['recovery_confirmed'] is True and
             user['final_components_deactivated'] is True,'actual installed/moved user shell and journal journey without PTY/hardware inference')
        prefix_path=Path('/') if label=='installed' else fixed/'moved-install'
        first_path=prefix_path/'usr/bin/cachy-asahi-first-login'
        need(user['path_pins']['first_login']['path']==str(first_path) and
             user['path_pins']['first_login']['sha256']==contract['recipes']['first-login']['payload_files']['usr/bin/cachy-asahi-first-login']['sha256'] and
             user['path_pins']['setup']['path']=='/usr/bin/cachy-asahi-setup' and
             user['path_pins']['setup']['sha256']==contract['dependency']['payload_files']['usr/bin/cachy-asahi-setup']['sha256'],
             'actual candidate CLI and authentic installed Setup8 helper, never recipe fixture')
        indexes=[entry(step)[0] for step in user['ordered_steps']]
        need(indexes==sorted(indexes) and order[2]<indexes[0]<=indexes[-1]<order[3],'user journey bracketed by real installation/removal')
        for step in user['ordered_steps']:
            argv=entry(step)[1]['argv'];need(argv[:6]==['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i'],'actual ordinary-user boundary for every delivered user command')
        observed_identity=json.loads(entry('install-'+label+'-identity')[2])
        need(observed_identity==dict(uid=user['uid'],gid=user['gid']) and type(user['uid']) is int and user['uid']>0 and
             type(user['gid']) is int and user['gid']>0,'actual non-root user identity proof')
        for phase,active in [('first',True),('edited',True),('removed',False),('recovered',True),('final',False)]:
            for shell in ('fish','zsh'):
                step='install-'+label+'-'+phase+'-'+shell;_,command,body=entry(step)
                marker=('CAA_'+shell.upper()+('_ACTIVE' if active else '_REMOVED')).encode()
                need('/usr/bin/'+shell in command['argv'] and marker in body,'actual delivered scripted interactive shell marker')
        for suffix,expected in [('interrupted-setup',75),('pending-inspect',2),('pending-new-selection-refused',2),('recover-preview',2),('recover',0)]:
            need(entry('install-'+label+'-'+suffix)[1]['expected']==expected,'actual interrupted/journal-recovery exit semantics')
        for operation in ('transition-preview','transition-apply','transition-stale','revoke-preview','revoke-apply'):
            step='install-'+label+'-'+operation;_,row,raw=entry(step);value=json.loads(raw)
            need(row['argv'][0]==str(prefix_path/'usr/bin/cachy-asahi-repository-enrollment') and
                 ('transition' in row['argv'] or 'revoke' in row['argv']),'actual installed/moved enrolled CLI command dispatch')
            wanted={'transition-preview':'preview','transition-apply':'rotated','transition-stale':'failed','revoke-preview':'preview','revoke-apply':'quarantined-revoked'}[operation]
            need(value['status']==wanted,'actual signed trust/revocation outcome')
            if operation=='transition-apply':need(value['snapshot_url_retained'] is True and value['snapshot_upgrade_accepted'] is False,'trust rotation is not snapshot upgrade acceptance')
            if operation=='revoke-apply':need(value['repository_enabled'] is False and value['revocation_confirmed'] is True and value['keys_removed'] is False,'real primary revocation with disabled selection and retained keys')
    need(report['business']['reinstall']['status']=='PASS_REINSTALLED_AND_MOVED_CLI_SMOKE_ONLY','honest limited reinstall smoke scope')
    need(report['install_reasons_before']==report['install_reasons_after'],'original package reasons restored')
    roots={'alpm_db','alarm_home','root_home','global_trust','global_config','package_cache'}
    need(set(report['restore'])==roots and all(row['before']==row['after'] and row['unchanged'] is True for row in report['restore'].values()),
         'complete protected DB/home/trust/config/cache restoration')
    cleanup=report['cleanup']
    need(cleanup['failures']==[] and all(cleanup[key] is True for key in ('homes_retired','no_sockets','private_directory_absent')),'complete scoped key-home/agent/private-tree retirement')
    return dict(status='VALIDATED_FINITE_FIRST_LOGIN_ENROLLMENT_COMPONENT',pairs=pairs,
                baseline_count=349,dependency_count=350,installed_count=352,first_login_user_commands=54,
                actual_scripted_shell_startups=20,pty='NOT_RUN',reinstall='SMOKE_ONLY',native_16K='NOT_QUALIFIED',physical_M2='NOT_RUN',release='NOT_ADMITTED')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule', type=Path, required=True, help='ordinary public-tree.tar; directory ingress is unsupported')
    parser.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.capsule, load(args.binding)), sort_keys=True))
