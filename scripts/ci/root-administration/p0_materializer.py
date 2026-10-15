"""Post-adoption Root data binding. This module never starts preparation or P0."""
import argparse
import base64
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import zlib

OWN = 'scripts/ci/development/p0_ci.py'
WORKFLOW = '.github/workflows/native-arm-p0.yml'
INPUTS = '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
PREFIXES = {'runtime': 'scripts/port/repository-native-handoff',
            'collector': 'scripts/port/repository-client-native',
            'phase': 'scripts/port/repository-client-phase-stage'}
MAPS = {role: prefix + '/source-map.json' for role, prefix in PREFIXES.items()}
OVERLAY = {'scripts/ci/native_arm.py': 'scripts/ci/development/p0_native_arm.py',
           'scripts/ci/integration.py': 'scripts/ci/development/p0_integration.py'}
P0_CURRENT_CONTRACT = {'schema_version': 1, 'product': 'installer-P0-vim-9.2.1178-1-input-successor-v1', 'lineage': 'CURRENT_PRODUCT_SUCCESSOR_NOT_HISTORICAL_EVIDENCE', 'historical_inputs_sha256': '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650', 'historical_packages_sha256': '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f', 'inputs_sha256': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f', 'packages_sha256': 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25', 'inputs_bytes': 328101, 'packages_bytes': 6674, 'acquisitions': 501, 'packages': 341, 'recipe_source_commit': 'ebd5812640b0b69f5c09a47752b739e37e338754', 'source_epoch': 1791748800}
QUARANTINE = []  # Root process retains unknown descriptor custody until exit.


def need(value, code):
    if not value:
        raise ValueError(code)


def validate_input_successor(value):
    need(type(value) is dict and len(value) == len(P0_CURRENT_CONTRACT) and
         all(type(key) is str for key in value) and set(value) == set(P0_CURRENT_CONTRACT) and
         all(type(value[key]) is type(wanted) and value[key] == wanted
             for key, wanted in P0_CURRENT_CONTRACT.items()), 'held-template-schema')
    return dict(value)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pipeline_environment(data):
    """Exact existing launcher keys; no secret chunks or image facts are supplied."""
    need(set(data) == {'preparation-template.json', 'P0-template.json'}, 'template-output-set')
    result = {}
    for name, prefix in (('preparation-template.json', 'PREPARATION_BUNDLE'), ('P0-template.json', 'P0_PRIVATE_BUNDLE')):
        raw = data[name]; compressed = zlib.compress(raw)
        need(type(raw) is bytes and len(raw) <= 2 * 1024**2 and len(compressed) <= 65536, 'packed-template-cap')
        result[prefix + '_ZLIB_B64'] = base64.b64encode(compressed).decode('ascii')
        result[prefix + '_SHA256'] = digest(raw)
    return result


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate-key')
            value[key] = item
        return value
    need(type(raw) is bytes and 0 < len(raw) <= 2 * 1024**2, 'json-bound')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite-json'))
    need(type(value) is dict, 'json-object')
    return value


def pin(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'hash-pin')
    return value


def relative(value):
    need(type(value) is str and len(value) <= 512 and re.fullmatch(r'[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*', value)
         and all(part not in ('.', '..') for part in value.split('/')), 'source-path')
    return value


def live(end):
    need(type(end) in (int, float) and math.isfinite(end) and time.monotonic() < end, 'original-end')


def identity(node):
    return tuple(getattr(node, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                  'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def merge(first, error):
    target = error if first is None else first
    target.__dict__['native_preflight_cleanup_uncertain'] = True
    if isinstance(error, KeyboardInterrupt) or error.__dict__.get('native_preflight_cancelled') is True:
        target.__dict__['native_preflight_cancelled'] = True
    return target


def file_bytes(path, end, *, limit=8 * 1024**2, private=False, executable=False):
    """NoFollow read with held/named/parent identity and proved one-shot close."""
    live(end)
    before = path.lstat(); parent = identity(path.parent.lstat())
    mode = 0o755 if executable else (0o600 if private else None)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit
         and (not private and not executable or before.st_size > 0)
         and (mode is None or stat.S_IMODE(before.st_mode) == mode)
         and (not executable or before.st_uid == before.st_gid == 0), 'file-shape')
    fd = None; held = None; opening = False; first = None; raw = None
    try:
        opening = True
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        candidate = identity(os.fstat(fd)); need(candidate == identity(before), 'file-replaced'); held = candidate
        parts = []; total = 0
        while True:
            live(end); part = os.read(fd, min(65536, limit + 1 - total))
            if not part:
                break
            total += len(part); need(total <= limit, 'file-cap'); parts.append(part)
        raw = b''.join(parts)
        need(len(raw) == before.st_size and identity(os.fstat(fd)) == held and identity(path.lstat()) == held
             and identity(path.parent.lstat()) == parent, 'file-drift')
    except BaseException as error:
        first = error
        if isinstance(error, KeyboardInterrupt):
            first.__dict__['native_preflight_cancelled'] = True
        if opening and fd is None:
            first = merge(first, error)
    finally:
        if fd is not None:
            try:
                need(held is not None and identity(os.fstat(fd)) == held, 'close-custody')
            except BaseException as error:
                QUARANTINE.append(fd); first = merge(first, error)
            else:
                try:
                    os.close(fd)
                except BaseException as error:
                    first = merge(first, error)
    if first is not None:
        raise first
    live(end)
    return raw, {'bytes': len(raw), 'mode': stat.S_IMODE(before.st_mode), 'sha256': digest(raw)}


def native_observation(selection, end):
    """Observe files/socket only; never invoke Docker, GPG, or a provider."""
    result = {}
    for role, name in (('docker', '/usr/bin/docker'), ('gpg', '/usr/bin/gpg')):
        _, row = file_bytes(Path(name), end, executable=True, limit=64 * 1024**2)
        need(row == selection['runtime_rows'][role], 'independent-runtime-pin')
        result[role] = row
    live(end); path = Path('/run/docker.sock'); parent = identity(path.parent.lstat())
    before = path.lstat(); full = identity(before)
    need(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1,
         'docker-socket-shape')
    need(identity(path.lstat()) == full and identity(path.parent.lstat()) == parent, 'docker-socket-drift')
    result['endpoint_identity'] = list(full[:6])
    need(result['endpoint_identity'] == selection['socket_identity'], 'independent-socket-selection')
    live(end)
    return result


def selection_contract(value, environment):
    need(set(value) == {'schema_version', 'purpose', 'source_commit', 'recipe_source_commit', 'packet_sha256',
         'publication_sha256', 'preparation_template_sha256', 'P0_template_sha256', 'source_review_sha256',
         'runtime_rows', 'socket_identity', 'materializer_row', 'source_rows'} and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['purpose'] == 'Root-selected-post-adoption-P0-materialization', 'Root-selection')
    commit = value['source_commit']
    need(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit) and commit == environment.get('GITHUB_SHA')
         == environment.get('GITHUB_WORKFLOW_SHA') and environment.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
         and environment.get('GITHUB_WORKFLOW_REF') == 'Gabriel-Kahen/cachy-asahi/' + WORKFLOW
         + '@refs/heads/codex/signer-native-runtime-v1', 'published-job-Source')
    need(type(value['recipe_source_commit']) is str and value['recipe_source_commit'] == P0_CURRENT_CONTRACT['recipe_source_commit'], 'recipe-Source')
    for key in ('packet_sha256', 'publication_sha256', 'preparation_template_sha256', 'P0_template_sha256', 'source_review_sha256'):
        pin(value[key])
    need(type(value['runtime_rows']) is dict and set(value['runtime_rows']) == {'docker', 'gpg'}, 'runtime-selection')
    for row in value['runtime_rows'].values():
        need(type(row) is dict and set(row) == {'bytes', 'mode', 'sha256'} and type(row['bytes']) is int
             and 0 < row['bytes'] <= 64 * 1024**2 and row['mode'] == 0o755, 'runtime-row'); pin(row['sha256'])
    socket = value['socket_identity']
    need(type(socket) is list and len(socket) == 6 and all(type(v) is int and v >= 0 for v in socket)
         and stat.S_ISSOCK(socket[2]) and socket[3] == 0 and socket[5] == 1, 'Root-socket-selection')
    code = value['materializer_row']
    need(type(code) is dict and set(code) == {'bytes', 'mode', 'sha256'} and type(code['bytes']) is int
         and 0 < code['bytes'] <= 1024**2 and code['mode'] == 0o644, 'Root-materializer-row'); pin(code['sha256'])
    need(type(value['source_rows']) is dict and len(value['source_rows']) == 270
         and WORKFLOW in value['source_rows'] and OWN in value['source_rows'], 'published-270-rows')
    for name, row in value['source_rows'].items():
        relative(name)
        need(type(row) is dict and set(row) == {'bytes', 'mode', 'sha256'} and type(row['bytes']) is int
             and 0 <= row['bytes'] <= 8 * 1024**2 and type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'Source-row')
        pin(row['sha256'])
    return commit


def source_transfer_selection(value,binding=None):
    """Explicit conduct premise, never a filesystem immutability assertion."""
    flags=('Root_selected','trusted_host','exclusive_writer_interval','read_only_actors')
    slots=('source_commit','source_root','source_rows_sha256','grant_sha256','run_id','run_attempt')
    need(type(value) is dict and set(value)=={'schema_version','purpose','selected','scope',*flags,*slots} and
         type(value['schema_version']) is int and value['schema_version']==1 and value['purpose']=='fetch-interior-only' and
         value['scope']=='same-UID-and-privileged-writers-alternate-path-FD-mmap-leaf-ancestor-and-code-namespace-excluded' and
         type(value['selected']) is bool and all(type(value[key]) is bool and value[key] is value['selected'] for key in flags),
         'prep-source-owner')
    if binding is None or value['selected'] is False:
        need(all(value[key] is None for key in slots),'prep-source-owner')
    else:
        need(type(binding) is dict and set(binding)==set(slots) and
             all(type(value[key]) is str and value[key]==binding[key] for key in slots), 'prep-source-owner')
    return value['selected']


def bind(selection, packet, publication, preparation, p0, bodies, observation):
    """Pure exact metadata closure; Root selection precedes this call."""
    rows = selection['source_rows']; commit = selection['source_commit']
    need(type(packet.get('source_files')) is dict and len(packet['source_files']) == 269
         and set(packet['source_files']) == set(rows) - {WORKFLOW} and packet.get('composition') == 'installer-preflight'
         and packet.get('purpose') == 'frozen-development-only-native-arm-source-packet'
         and packet.get('schema_version') == 2, 'actual-packet269')
    need(set(bodies) == set(rows), 'Source-body-set')
    for name, raw in bodies.items():
        need(type(raw) is bytes and digest(raw) == rows[name]['sha256'] and len(raw) == rows[name]['bytes'], 'Source-body-pin')
        if name != WORKFLOW:
            need(packet['source_files'][name] == {key: rows[name][key] for key in ('mode', 'sha256')}, 'packet-row-join')
    need(set(publication) == {'Source', 'remote', 'branch', 'files'} and publication['Source'] == publication['remote'] == commit
         and publication['branch'] == 'codex/signer-native-runtime-v1' and type(publication['files']) is list,
         'actual-publication')
    published = {}
    for row in publication['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'mode', 'sha256'} and row['path'] not in published
             and row['path'] in rows and {key: row[key] for key in ('bytes', 'mode', 'sha256')} == rows[row['path']]
             and row['mode'] == 0o644, 'pipeline-publication-row')
        published[row['path']] = row
    required = {OWN, WORKFLOW, 'scripts/install/p0_entry.py', 'scripts/ci/development/p0_native_arm.py',
        'scripts/port/repository-native-handoff/transport.py', 'scripts/port/repository-native-handoff/source-map.json',
        'scripts/ci/development/common.py', 'scripts/ci/development/controller.py',
        'scripts/ci/development/packet.py', 'scripts/ci/development/repository_handoff.py'}
    need(required <= published.keys(), 'pipeline-publication-closure')
    need(digest(bodies['scripts/ci/inputs.lock.json']) == INPUTS, 'original3c16')
    for name, wanted in packet['metadata_pins'].items():
        need(name in bodies and digest(bodies[name]) == wanted, 'metadata-pin')
    original = decode(bodies['scripts/ci/integration.lock.json'])['source_files']
    need(len(original) == 159 and all(packet['source_files'].get(name) == row for name, row in original.items()), 'held-original159')
    overlay = {name: packet['source_files'][variant] for name, variant in OVERLAY.items()}
    view_rows = {**original, **overlay}
    maps = {}
    for role, path in MAPS.items():
        mapping = decode(bodies[path])
        need(all(packet['source_files'].get(PREFIXES[role] + '/' + name) == row for name, row in mapping.items()), 'narrow-map-join')
        maps[role] = {'path': path, 'sha256': digest(bodies[path])}
    need(observation['docker'] == selection['runtime_rows']['docker'] and observation['gpg'] == selection['runtime_rows']['gpg'], 'observed-runtime-pin')
    endpoint = observation['endpoint_identity']
    need(type(endpoint) is list and len(endpoint) == 6 and all(type(v) is int and v >= 0 for v in endpoint)
         and stat.S_ISSOCK(endpoint[2]) and endpoint[3] == 0 and endpoint[5] == 1
         and endpoint == selection['socket_identity'], 'observed-endpoint6')
    prep = copy.deepcopy(preparation); future_p0 = copy.deepcopy(p0)
    need(set(prep) == {'schema_version', 'purpose', 'plan', 'packet', 'grant', 'runtime', 'publication', 'source_transfer_interval'}
         and prep['schema_version'] == 1 and prep['purpose'] == 'Root-selected-P0-preparation-template'
         and set(future_p0) == {'schema_version', 'purpose', 'plan', 'packet', 'grant', 'runtime', 'publication', 'prepared_image', 'packages_b64', 'current_inputs_b64'}
         and future_p0['schema_version'] == 1 and future_p0['purpose'] == 'Root-selected-P0-private-input-template', 'held-template-schema')
    source_transfer_selection(prep['source_transfer_interval'])
    for target in (prep['plan'], prep['grant'], future_p0['plan'], future_p0['grant'], future_p0['prepared_image']):
        validate_input_successor(target.get('input_successor'))
    need(future_p0['current_inputs_b64'] is None and
         future_p0['prepared_image'].get('inputs_sha256') == P0_CURRENT_CONTRACT['inputs_sha256'] and
         future_p0['prepared_image'].get('packages_sha256') == P0_CURRENT_CONTRACT['packages_sha256'], 'held-template-schema')
    for plan in (prep['plan'], future_p0['plan']):
        for key in ('source_commit', 'run_id', 'run_attempt', 'nonce'):
            need(plan.get(key, 'ABSENT') is None, 'pipeline-plan-null-slot')
    for key in ('outer_end', 'input_pins', 'preparation_plan_sha256', 'preparation_source_rows_sha256'):
        need(future_p0['plan'].get(key, 'ABSENT') is None, 'pipeline-P0-null-slot')
    for key in ('source_commit', 'run_id', 'run_attempt', 'image', 'preparation_plan_sha256', 'preparation_source_rows_sha256'):
        need(future_p0['prepared_image'].get(key, 'ABSENT') is None, 'pipeline-image-null-slot')
    for runtime in (prep['runtime']['docker'], future_p0['runtime']):
        env = runtime['env']
        need(set(env) == {'PATH', 'LC_ALL', 'DOCKER_HOST', 'DOCKER_BUILDKIT', 'HOME', 'DOCKER_CONFIG', 'TMPDIR'}
             and env['PATH'] == '/usr/bin:/bin' and env['LC_ALL'] == 'C' and env['DOCKER_HOST'] == 'unix:///run/docker.sock'
             and env['DOCKER_BUILDKIT'] == '0' and all(env[key] is None for key in ('HOME', 'DOCKER_CONFIG', 'TMPDIR')),
             'pipeline-private-env-null')
    gpg_env = prep['runtime']['gpg_env']
    need(set(gpg_env) == {'PATH', 'LC_ALL', 'HOME', 'TMPDIR'} and gpg_env['PATH'] == '/usr/bin:/bin'
         and gpg_env['LC_ALL'] == 'C' and gpg_env['HOME'] is None and gpg_env['TMPDIR'] is None, 'pipeline-gpg-env-null')
    for bundle, purpose in ((prep, 'reviewed-installer-P0-preparation'), (future_p0, 'reviewed-installer-P0-execution')):
        grant = bundle['grant']
        need(grant['purpose'] == purpose and type(grant['added_seconds']) is int and grant['added_seconds'] == 0,
             'distinct-purpose0')
        callback = {'path': OWN, 'module': 'development_p0_ci', 'qualname': 'Preparation.prepare'} if bundle is prep else {
            'path': 'scripts/ci/development/controller.py', 'module': 'development_p0_controller', 'qualname': 'Development.consume_p0'}
        need(grant['callbacks']['existing_consumers'] == callback and grant['development_only'] is True
             and grant['policy_path'] == 'manifests/reviewed/repository-generic-policy.json' and grant['license_path'] == 'LICENSE', 'held-scope')
        for key in ('source_commit', 'run_id', 'run_attempt', 'actor_contract_sha256', 'initial_invocation_sha256'):
            need(grant[key] is None, 'pipeline-owned-slot')
        need(grant['source_files'] is None and grant['maps'] is None and grant['original_view'] is None
             and grant['source_peer_preflight'] == 'PASS' and grant['recipe_source_commit'] is None, 'explicit-Root-review-decision')
        grant.update(source_files=copy.deepcopy(packet['source_files']), maps=copy.deepcopy(maps),
                     recipe_source_commit=selection['recipe_source_commit'])
        grant['original_view'] = {'schema_version': 1, 'purpose': 'P0-157-held-2-overlay-copy-view',
            'root': None, 'full_source_root': None, 'integration_lock_sha256': digest(bodies['scripts/ci/integration.lock.json']),
            'source_rows_sha256': digest(encoded(view_rows)), 'file_count': 160, 'argv_mode': 'absolute-P0-overlay-metadata',
            'source_overlay': overlay}
        for role in ('public_receiver', 'authority_provider'):
            need(grant['callbacks'][role] is None, 'Root-callback-slot')
            grant['callbacks'][role] = {'path': 'scripts/ci/development/repository_authority.py',
                'module': 'development_repository_authority', 'qualname': 'RootCallbacks.' + role}
        bundle['packet'] = copy.deepcopy(packet); bundle['publication'] = copy.deepcopy(publication)
    need(prep['plan']['cache_mode'] == 'selected-HTTPS' and prep['plan']['url_overrides'] == {}
         and prep['plan']['work_seconds'] == 1800 and prep['plan']['cleanup_seconds'] == 1890, 'fixed-preparation-selection')
    need(future_p0['prepared_image']['image'] is None and future_p0['packages_b64'] is None, 'no-fabricated-image')
    for runtime in (prep['runtime']['docker'], future_p0['runtime']):
        need(runtime['cli_sha256'] is None and runtime['endpoint_identity'] is None, 'unfilled-runtime')
        runtime['cli_sha256'] = observation['docker']['sha256']; runtime['endpoint_identity'] = endpoint
    need(prep['runtime']['gpg_sha256'] is None, 'unfilled-gpg')
    prep['runtime']['gpg_sha256'] = observation['gpg']['sha256']
    # Actual frame/path hashes are intentionally filled by the unchanged pipeline,
    # after its first entry and fresh P0 entry; early filling would violate it.
    return {'preparation-template.json': encoded(prep), 'P0-template.json': encoded(future_p0)}


def write_private(path, raw, end):
    live(end); parent = identity(path.parent.lstat())
    fd = None; held = None; first = None; opening = False
    try:
        opening = True
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        candidate = identity(os.fstat(fd))[:6]
        need(stat.S_ISREG(candidate[2]) and candidate[3] == os.geteuid() and candidate[5] == 1
             and stat.S_IMODE(candidate[2]) == 0o600 and identity(path.lstat())[:6] == candidate,
             'private-write-shape'); held = candidate
        offset = 0
        while offset < len(raw):
            live(end); need(identity(os.fstat(fd))[:6] == held, 'private-write-custody')
            size = os.write(fd, raw[offset:]); need(size > 0, 'private-write-progress'); offset += size
        need(identity(os.fstat(fd))[:6] == held and identity(path.lstat())[:6] == held
             and path.stat().st_size == len(raw) and identity(path.parent.lstat())[:6] == parent[:6], 'private-write-drift')
    except BaseException as error:
        first = error
        if isinstance(error, KeyboardInterrupt):
            first.__dict__['native_preflight_cancelled'] = True
        if opening and fd is None:
            first = merge(first, error)
    finally:
        if fd is not None:
            try:
                need(held is not None and identity(os.fstat(fd))[:6] == held, 'private-close-custody')
            except BaseException as error:
                QUARANTINE.append(fd); first = merge(first, error)
            else:
                try:
                    os.close(fd)
                except BaseException as error:
                    first = merge(first, error)
    if first is not None:
        raise first
    observed, _ = file_bytes(path, end, private=True, limit=2 * 1024**2)
    need(observed == raw, 'private-readback')


def root_materialize(*, entry, outer_end, selection_raw, selection_sha256, packet_raw, publication_raw,
                     preparation_raw, P0_raw, review_raw, root, destination, environment):
    need(type(entry) in (int, float) and math.isfinite(entry) and type(outer_end) in (int, float)
         and math.isfinite(outer_end) and entry <= time.monotonic(), 'first-entry')
    end = min(entry + 60, outer_end); live(end)
    need(not QUARANTINE and digest(selection_raw) == pin(selection_sha256), 'Root-selected-data')
    selection = decode(selection_raw); selection_contract(selection, environment)
    _, own_row = file_bytes(Path(__file__), end)
    need(own_row == selection['materializer_row'], 'Root-selected-helper-code')
    for raw, key in ((packet_raw, 'packet_sha256'), (publication_raw, 'publication_sha256'),
                     (preparation_raw, 'preparation_template_sha256'), (P0_raw, 'P0_template_sha256'),
                     (review_raw, 'source_review_sha256')):
        need(digest(raw) == selection[key], 'Root-input-pin')
    root = Path(root); destination = Path(destination)
    need(root.is_absolute() and root == root.resolve() and destination.is_absolute() and '..' not in destination.parts
         and not destination.is_relative_to(root) and not destination.exists() and not destination.is_symlink(), 'materializer-paths')
    bodies = {}; total = 0
    for name, wanted in selection['source_rows'].items():
        raw, row = file_bytes(root / name, end)
        need(row == wanted, 'actual-adopted-Source-row'); bodies[name] = raw; total += len(raw)
        need(total <= 64 * 1024**2, 'Source-total')
    # Root selection is an independently authenticated input. No loaded project
    # code, callback, issuer, provider or grant object is created here.
    packet, publication = decode(packet_raw), decode(publication_raw)
    preparation, p0 = decode(preparation_raw), decode(P0_raw)
    # Pure prevalidation uses explicitly selected EXPECTED rows, never labels them
    # observed and never writes them. Source/template refusals precede native reads.
    expected_runtime = {**selection['runtime_rows'], 'endpoint_identity': selection['socket_identity']}
    bind(selection, packet, publication, preparation, p0, bodies, expected_runtime)
    observation = native_observation(selection, end)
    data = bind(selection, packet, publication, preparation, p0, bodies, observation)
    live(end); destination.mkdir(mode=0o700)
    node = destination.lstat(); need(stat.S_ISDIR(node.st_mode) and node.st_uid == os.geteuid()
                                    and stat.S_IMODE(node.st_mode) == 0o700, 'private-directory')
    for name, raw in data.items():
        write_private(destination / name, raw, end)
    write_private(destination / 'pipeline-environment.json', encoded(pipeline_environment(data)), end)
    result = {'schema_version': 1, 'purpose': 'ROOT_POST_ADOPTION_PRIVATE_TEMPLATES',
              'Source': selection['source_commit'], 'template_pins': {name: digest(raw) for name, raw in data.items()},
              'publication_sha256': selection['publication_sha256'], 'packet_sha256': selection['packet_sha256'],
              'runtime_observation': observation, 'actual_preparation': 'NOT_RUN', 'actual_P0': 'NOT_RUN'}
    write_private(destination / 'materialization.json', encoded(result), end)
    return result


def main():
    entry = time.monotonic()  # Before selection/template/packet reads or decoding.
    parser = argparse.ArgumentParser()
    for name in ('selection', 'selection-sha256', 'packet', 'publication', 'preparation-template', 'P0-template',
                 'review', 'root', 'destination', 'outer-end'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(); end = min(entry + 60, float(args.outer_end)); live(end)
    raw = {name: file_bytes(Path(getattr(args, name.replace('-', '_'))), end,
                           private=name in ('selection', 'preparation-template', 'P0-template'), limit=2 * 1024**2)[0]
           for name in ('selection', 'packet', 'publication', 'preparation-template', 'P0-template', 'review')}
    result = root_materialize(entry=entry, outer_end=float(args.outer_end), selection_raw=raw['selection'],
        selection_sha256=args.selection_sha256, packet_raw=raw['packet'], publication_raw=raw['publication'],
        preparation_raw=raw['preparation-template'], P0_raw=raw['P0-template'], review_raw=raw['review'],
        root=args.root, destination=args.destination, environment=os.environ)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
