#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unregistered Root bootstrap proposal. No imports of checkout code or actors.

Root supplies literal pins through a separately reviewed trusted launcher. A
matching local file or PASS string cannot select those pins. This module emits
only the existing grant17/runtime3 contracts; it never issues a clock.
"""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

INITIAL = 'scripts/ci/integration.lock.json'
INITIAL_SHA = '9c5cca5c9b69c59ca44cd677ed49111e03fe1edadc8abd52aaa2f8ced1a5d9ed'
INPUTS_SHA = 'a86261268cac80a20cbaeb122d49dbb55b3380ca1c5e53ce1f630c066ab64046'
INVENTORY = 'scripts/port/refreshed-desktop/proposed-builder-inventory.lock'
INVENTORY_SHA = '9901d32a48dc4d85874a3c3f85e34f201b6b21d3614c3549c16b9d835eb28705'
BASELINE = 'manifests/reviewed/maintained-composed-v1.json'
BASELINE_SHA = '0e2dd01cdb47488699364c41aaa91169a0e8653fd82e88155122c223e26b0512'
BASELINE_ID = 'maintained-native-baseline-v1-vim-9.2.1178-1'
LINEAGE = 'SUCCESSOR_NOT_HISTORICAL_ORIGINAL'
PURPOSE = 'root-selected-maintained-v1-development-source'
MODES = {'repository-svg-maintained-v1':259, 'installer-preflight-maintained-v1':266}
BASELINE_DECLARATION = {'baseline_id': 'maintained-native-baseline-v1-vim-9.2.1178-1', 'changed_view_sources': ['scripts/ci/inputs.lock.json'], 'generated_fixtures': 125, 'hardware_validation': 'NOT RUN', 'historical_inputs_sha256': '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650', 'historical_integration_sha256': 'd4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31', 'inputs_sha256': 'a86261268cac80a20cbaeb122d49dbb55b3380ca1c5e53ce1f630c066ab64046', 'installation': 'NOT RUN', 'integration_sha256': '9c5cca5c9b69c59ca44cd677ed49111e03fe1edadc8abd52aaa2f8ced1a5d9ed', 'inventory_sha256': '9901d32a48dc4d85874a3c3f85e34f201b6b21d3614c3549c16b9d835eb28705', 'lineage': 'SUCCESSOR_NOT_HISTORICAL_ORIGINAL', 'native_sha256': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898', 'original_producers': 1, 'recipe_source_commit': 'ebd5812640b0b69f5c09a47752b739e37e338754', 'recipes_sha256': '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63', 'schema_version': 1, 'selected_for_release': False, 'source_captures': 2, 'source_date_epoch': 1791748800, 'unchanged_view_sources': 158, 'view_files': 160, 'view_sources': 159}
POLICY = 'manifests/reviewed/repository-generic-policy.json'
POLICY_SHA = 'ff424921c5be38799f64e5c6264bb098cf71737d7be83608a4c91dee83f0365e'
LICENSE_SHA = '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'
PREFIXES = {'runtime': 'scripts/port/repository-native-handoff',
            'collector': 'scripts/port/repository-client-native',
            'phase': 'scripts/port/repository-client-phase-stage'}
MAP_NAMES = {'runtime': {'entry', 'capture', 'producer', 'launch', 'transport', 'supervisor', 'broker'},
             'collector': {'entry', 'common', 'base', 'worker', 'provenance', 'crypto', 'orchestrator'},
             'phase': {'entry', 'dependencies', 'phases', 'gate', 'adapter'}}
METADATA = {INITIAL, BASELINE, INVENTORY, 'scripts/ci/inputs.lock.json', 'scripts/ci/recipes.lock.json',
            'scripts/virtual/tooling.lock.json', 'scripts/virtual/tooling-audit.json',
            'scripts/experiments/stage.lock.json', 'manifests/reviewed/ksmctl.json', POLICY,
            'scripts/port/repository-client-phase-stage/dependencies.py',
            *(prefix + '/source-map.json' for prefix in PREFIXES.values())}
CALLBACKS = {
    'existing_consumers': {'path': 'scripts/ci/development/controller.py', 'module': '__main__',
                           'qualname': 'Development.consume'},
    **{name: {'path': 'scripts/ci/development/repository_authority.py',
              'module': 'development_repository_authority', 'qualname': 'RootCallbacks.' + name}
       for name in ('public_receiver', 'authority_provider')},
}
PIN_KEYS = {'selection_sha256', 'peer_receipt_sha256', 'source_rows_sha256',
            'source_commit', 'cli_sha256'}
SELECTION_KEYS = {'source_commit', 'source_files', 'metadata_pins', 'metadata_hex',
                  'maps', 'callbacks', 'peer_receipt_sha256', 'schema_version', 'purpose',
                  'composition', 'baseline_id', 'lineage', 'source_packet_sha256'}
CLI, SOCKET = Path('/usr/bin/docker'), Path('/run/docker.sock')
LIMIT, TOTAL = 8 * 1024**2, 64 * 1024**2
PREPARATION_SECONDS = 60


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def check(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline) and
         0 < time.monotonic() < deadline, 'deadline')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw, limit=LIMIT):
    need(type(raw) is bytes and 0 < len(raw) <= limit, 'bounded-json')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    def invalid(value):
        raise Refused('noninteger-json-number')
    result = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(result) is dict, 'json-object')
    return result


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def relative(value):
    need(type(value) is str and len(value) <= 512 and
         re.fullmatch(r'[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*', value) and
         all(part not in ('.', '..') for part in value.split('/')), 'relative-path')
    return value


def absolute(value):
    need(type(value) is str and value.startswith('/') and len(value) <= 4096 and
         str(Path(value)) == value and '..' not in Path(value).parts and
         not any(character in value for character in ('\0', '\n', '\r')),
         'absolute-path')
    return Path(value)


def identity(info):
    return tuple(getattr(info, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


def stable(info):
    return identity(info) + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def directory(path):
    path = absolute(str(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    # Creating a child legitimately changes a directory's link count. Keep
    # ancestor inode/type/mode/owner/group custody, not its mutable child count.
    seen = [(Path('/'), identity(os.fstat(fd))[:5])]
    try:
        current = Path('/')
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = new
            current /= part
            seen.append((current, identity(os.fstat(fd))[:5]))
        yield fd
        need(all(identity(node.lstat())[:5] == before for node, before in seen), 'ancestor-drift')
    finally:
        os.close(fd)


def read(path, deadline, *, limit=LIMIT, owner=None, mode=None, keep=False):
    """Bounded no-follow read; named/opened bytes and metadata must stay stable."""
    check(deadline)
    path = absolute(str(path))
    fd = None
    try:
        with directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 <= before.st_size <= limit and (owner is None or before.st_uid == owner) and
                 (mode is None or stat.S_IMODE(before.st_mode) == mode), 'file-custody')
            raw = bytearray()
            while chunk := os.read(fd, 65536):
                check(deadline)
                raw.extend(chunk)
                need(len(raw) <= limit, 'file-bound')
            check(deadline)
            need(stable(before) == stable(os.fstat(fd)) ==
                 stable(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) and
                 len(raw) == before.st_size, 'file-drift')
        result = (bytes(raw), identity(before), fd if keep else None)
        if keep:
            fd = None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def observe_runtime(cli_sha256, deadline):
    """Fixed root-owned CLI read + socket lstat only; never connect or execute."""
    raw, cli_identity, _ = read(CLI, deadline, limit=128 * 1024**2, owner=0, mode=0o755)
    need(digest(raw) == cli_sha256, 'cli-pin')
    with directory(SOCKET.parent) as parent:
        before = os.stat(SOCKET.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0, 'socket-custody')
        endpoint = identity(before)
        check(deadline)
        need(identity(os.stat(SOCKET.name, dir_fd=parent, follow_symlinks=False)) == endpoint,
             'socket-drift')
    return cli_identity, endpoint


def selection(raw, peer_raw, root_pins, deadline):
    """Root's external literal tuple is the trust input, never file self-PASS."""
    check(deadline)
    need(type(root_pins) is dict and set(root_pins) == PIN_KEYS and
         all(pin(root_pins[key]) for key in PIN_KEYS - {'source_commit'}) and
         type(root_pins['source_commit']) is str and
         re.fullmatch('[0-9a-f]{40}', root_pins['source_commit']), 'root-pins')
    need(type(peer_raw) is bytes and 0 < len(peer_raw) <= LIMIT and
         digest(peer_raw) == root_pins['peer_receipt_sha256'] and
         type(raw) is bytes and digest(raw) == root_pins['selection_sha256'], 'external-provenance')
    value = decode(raw)
    need(set(value) == SELECTION_KEYS and type(value['schema_version']) is int and
         value['schema_version'] == 3 and value['purpose'] == PURPOSE and
         type(value['composition']) is str and value['composition'] in MODES and
         value['baseline_id'] == BASELINE_ID and value['lineage'] == LINEAGE and
         pin(value['source_packet_sha256']) and value['source_commit'] == root_pins['source_commit'] and
         value['peer_receipt_sha256'] == root_pins['peer_receipt_sha256'], 'selection-provenance')
    rows = value['source_files']
    need(type(rows) is dict and len(rows) == MODES[value['composition']] and
         digest(encoded(rows)) == root_pins['source_rows_sha256'], 'selected-rows')
    for name, row in rows.items():
        relative(name)
        need(type(row) is dict and set(row) == {'sha256', 'mode'} and pin(row['sha256']) and
             type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'source-row')
    pins, hexes = value['metadata_pins'], value['metadata_hex']
    need(type(pins) is dict and set(pins) == METADATA and
         type(hexes) is dict and set(hexes) == METADATA and
         value['callbacks'] == CALLBACKS and type(value['maps']) is dict and
         set(value['maps']) == set(PREFIXES), 'selection-closure')
    metadata = {}
    for name in sorted(METADATA):
        check(deadline)
        need(pin(pins[name]) and type(hexes[name]) is str and
             len(hexes[name]) <= 2 * LIMIT and len(hexes[name]) % 2 == 0 and
             re.fullmatch('[0-9a-f]*', hexes[name]), 'metadata-encoding')
        data = bytes.fromhex(hexes[name])
        need(name in rows and digest(data) == pins[name] == rows[name]['sha256'], 'metadata-pin')
        metadata[name] = data
    need(sum(map(len, metadata.values())) <= TOTAL and pins[INITIAL] == INITIAL_SHA and
         pins[POLICY] == POLICY_SHA and pins[BASELINE] == BASELINE_SHA and
         pins['scripts/ci/inputs.lock.json'] == INPUTS_SHA and pins[INVENTORY] == INVENTORY_SHA and
         rows.get('LICENSE', {}).get('sha256') == LICENSE_SHA,
         'immutable-pins')
    need(decode(metadata[BASELINE]) == BASELINE_DECLARATION, 'maintained-baseline')
    tooling = decode(metadata['scripts/virtual/tooling.lock.json'])
    audit = decode(metadata['scripts/virtual/tooling-audit.json'])
    need(tooling.get('base_inputs_lock_sha256') == INPUTS_SHA and
         audit.get('tooling_lock_sha256') == pins['scripts/virtual/tooling.lock.json'], 'virtual-binding')
    lock = decode(metadata[INITIAL])
    original = lock['source_files']
    need(type(original) is dict and len(original) == 159 and len(lock['generated_fixture_files']) == 125 and
         all(rows.get(name) == row for name, row in original.items()) and
         lock['recipes_sha256'] == pins['scripts/ci/recipes.lock.json'] and
         len(decode(metadata['scripts/ci/recipes.lock.json'])) == 4 and
         type(lock['recipe_source_commit']) is str and
         re.fullmatch('[0-9a-f]{40}', lock['recipe_source_commit']), 'original-159')
    for role, prefix in PREFIXES.items():
        path = prefix + '/source-map.json'
        need(value['maps'][role] == {'path': path, 'sha256': pins[path]}, 'selected-map')
        mapping = decode(metadata[path])
        need(set(mapping) == {name + '.py' for name in MAP_NAMES[role]} and
             all(rows.get(prefix + '/' + name) == row for name, row in mapping.items()), 'map-closure')
    policy = decode(metadata[POLICY])
    need(policy.get('supported_models') == [] and policy.get('platform_scope') == 'generic-builder-only'
         and policy.get('review_status') == 'ACCEPTED', 'policy')
    check(deadline)
    return value, lock


def paths(environment, root_pins):
    need(type(environment) is dict, 'job-environment')
    for key, pattern in (('GITHUB_RUN_ID', '[1-9][0-9]{0,19}'),
                         ('GITHUB_RUN_ATTEMPT', '[1-9][0-9]{0,9}')):
        need(type(environment.get(key)) is str and re.fullmatch(pattern, environment[key]), 'job-id')
    need(environment.get('GITHUB_SHA') == environment.get('GITHUB_WORKFLOW_SHA') ==
         root_pins['source_commit'], 'job-source')
    workspace = absolute(environment.get('GITHUB_WORKSPACE'))
    temporary = absolute(environment.get('RUNNER_TEMP'))
    need(not workspace.is_relative_to(temporary) and not temporary.is_relative_to(workspace), 'path-overlap')
    token = environment['GITHUB_RUN_ID'] + '-' + environment['GITHUB_RUN_ATTEMPT']
    result = {'workspace': workspace, 'temporary': temporary,
              'bootstrap': temporary / ('development-bootstrap-' + token),
              'tools': temporary / ('development-toolstate-' + token),
              'output': temporary / ('development-output-' + token),
              'cache': temporary / ('development-cache-' + token)}
    with directory(temporary) as parent:
        need(os.fstat(parent).st_uid == os.getuid(), 'runner-temp-owner')
        for key in ('bootstrap', 'tools', 'output', 'cache'):
            try:
                os.stat(result[key].name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise Refused('fresh-path-required')
    return result


def original_argv(output, cache, pins):
    view = output / 'repository-handoff/maintained-view'
    result = ['integration']
    for flag in ('inputs', 'recipes', 'integration'):
        name = 'scripts/ci/' + flag + '.lock.json'
        result.extend(('--' + flag, str(view / name), '--' + flag + '-sha256', pins[name]))
    result.extend(('--cache', str(cache), '--output', str(output / 'native'),
                   '--integration-output', str(output / 'integration')))
    return result


class Owned:
    """Retain inode custody for owned disposal, refusing foreign substitutions.

    Modes/inodes are cooperative custody checks, not protection from hostile
    same-UID writers. A failed disposal is recorded without replacing first cause.
    """
    def __init__(self):
        self.nodes = []
        self.cleanup_errors = []

    def mkdir(self, path, deadline):
        check(deadline)
        with directory(path.parent) as parent:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            self.nodes.append((path, None, identity(named), True))
            fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            before = os.fstat(fd)
            self.nodes[-1] = (path, fd, identity(named), True)
            need(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o700 and
                 identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) ==
                 identity(before) == identity(named), 'private-dir')
        check(deadline)

    def write(self, path, raw, deadline, limit):
        check(deadline)
        need(type(raw) is bytes and 0 < len(raw) <= limit, 'contract-size')
        with directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
            before = os.fstat(fd)
            self.nodes.append((path, fd, identity(before), False))
            need(before.st_uid == os.getuid() and stat.S_ISREG(before.st_mode) and
                 before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600, 'private-file')
            offset = 0
            while offset < len(raw):
                check(deadline)
                written = os.write(fd, raw[offset:])
                need(written > 0, 'short-write')
                offset += written
            os.fsync(fd)
            check(deadline)
            need(identity(os.fstat(fd)) == identity(before) ==
                 identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'private-file-drift')
        captured, _, _ = read(path, deadline, owner=os.getuid(), mode=0o600, limit=limit)
        need(captured == raw, 'private-bytes')
        return str(path), digest(raw)

    def dispose(self):
        """No recursive delete: only retained owned nodes, in reverse order."""
        for path, fd, before, is_directory in reversed(self.nodes):
            try:
                with directory(path.parent) as parent:
                    live = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                    need(identity(live) == before and (fd is None or identity(os.fstat(fd)) == before) and
                         live.st_uid == os.getuid(), 'disposal-custody')
                    if is_directory:
                        if fd is None:
                            with directory(path) as opened:
                                need(identity(os.fstat(opened)) == before and not os.listdir(opened), 'disposal-not-empty')
                        else:
                            need(not os.listdir(fd), 'disposal-not-empty')
                        os.rmdir(path.name, dir_fd=parent)
                    else:
                        os.unlink(path.name, dir_fd=parent)
            except BaseException as error:
                self.cleanup_errors.append(type(error).__name__)
            finally:
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        # A close error can follow an actual close: record the
                        # unknown descriptor outcome and never retry this fd.
                        self.cleanup_errors.append(type(error).__name__)
        self.nodes.clear()
        return not self.cleanup_errors

    def verify(self, deadline):
        need(bool(self.nodes), 'closed-private-custody')
        for path, fd, before, is_directory in self.nodes:
            check(deadline)
            with directory(path.parent) as parent:
                current = identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                held = identity(os.fstat(fd)) if fd is not None else current
                bound = 5 if is_directory else 6
                need(current[:bound] == held[:bound] == before[:bound] and
                     current[3] == os.getuid(), 'retained-private-custody')

    def close(self):
        """Release held descriptors after controller custody transfer; retain files."""
        for _, fd, _, _ in self.nodes:
            if fd is not None:
                os.close(fd)
        self.nodes.clear()


def prepare(selection_raw, peer_raw, root_pins, environment, *, preparation_deadline):
    """Precheckout: return exact issuer refs and retained private custody.

    Caller owns a finite preissuance preparation bound. It is NOT workflow J or
    an extension of an issued clock. Root must explicitly register this phase.
    """
    entry = time.monotonic()
    check(preparation_deadline)
    need(preparation_deadline <= entry + PREPARATION_SECONDS, 'preparation-bound')
    value, lock = selection(selection_raw, peer_raw, root_pins, preparation_deadline)
    layout = paths(environment, root_pins)
    owned = Owned()
    try:
        owned.mkdir(layout['bootstrap'], preparation_deadline)
        owned.mkdir(layout['tools'], preparation_deadline)
        for name in ('home', 'config', 'tmp'):
            owned.mkdir(layout['tools'] / name, preparation_deadline)
        cli_before, endpoint = observe_runtime(root_pins['cli_sha256'], preparation_deadline)
        runtime = {'cli_sha256': root_pins['cli_sha256'], 'endpoint_identity': list(endpoint),
                   'env': {'PATH': '/usr/bin:/bin', 'HOME': str(layout['tools'] / 'home'),
                           'DOCKER_CONFIG': str(layout['tools'] / 'config'),
                           'DOCKER_HOST': 'unix:///run/docker.sock', 'DOCKER_BUILDKIT': '0',
                           'LC_ALL': 'C', 'TMPDIR': str(layout['tools'] / 'tmp')}}
        runtime_raw = encoded(runtime)
        adapter = layout['output'] / 'repository-handoff'
        view = adapter / 'maintained-view'
        grant = {'schema_version': 2, 'purpose': 'reviewed-same-job-handoff-execution',
                 'source_peer_preflight': 'PASS', 'development_only': True, 'added_seconds': 1200,
                 'source_commit': value['source_commit'], 'recipe_source_commit': lock['recipe_source_commit'],
                 'run_id': environment['GITHUB_RUN_ID'], 'run_attempt': environment['GITHUB_RUN_ATTEMPT'],
                 'source_files': value['source_files'], 'maps': value['maps'], 'callbacks': value['callbacks'],
                 'policy_path': POLICY, 'license_path': 'LICENSE', 'actor_contract_sha256': digest(runtime_raw),
                 'initial_invocation_sha256': digest(encoded({'argv': original_argv(layout['output'], layout['cache'],
                                                   value['metadata_pins']), 'output': str(adapter)})),
                 'baseline_view': {'schema_version': 2, 'purpose': 'maintained-v1-159-copy-view',
                                   'baseline_id': BASELINE_ID,
                                   'full_source_root': str(layout['workspace']), 'root': str(view),
                                   'integration_lock_sha256': INITIAL_SHA,
                                   'source_rows_sha256': digest(encoded(lock['source_files'])),
                                   'file_count': 160, 'argv_mode': 'absolute-view-metadata'}}
        runtime_ref = owned.write(layout['bootstrap'] / 'runtime.json', runtime_raw, preparation_deadline, 16 * 1024)
        grant_ref = owned.write(layout['bootstrap'] / 'grant.json', encoded(grant), preparation_deadline, LIMIT)
        # Fixed Root-selected envelope retained separately from empty tool state.
        source_ref = owned.write(layout['bootstrap'] / 'selection.json', selection_raw, preparation_deadline, LIMIT)
        cli_after, endpoint_after = observe_runtime(root_pins['cli_sha256'], preparation_deadline)
        need((cli_before, endpoint) == (cli_after, endpoint_after), 'runtime-identity-drift')
        owned.verify(preparation_deadline)
        check(preparation_deadline)
        return {'execution_grant': grant_ref, 'runtime_contract': runtime_ref, 'selection': source_ref,
                'paths': layout, 'owned': owned}
    except BaseException as first:
        owned.dispose()
        # Attach only fixed cleanup result, preserving the exact original exception.
        if type(first) is Refused:
            first.cleanup_complete = not owned.cleanup_errors
        raise


def verify_checkout(prepared, root_pins, environment, *, deadline):
    """After issuer/checkout: no reissue, no new selection, no project execution.

    Deadline is the retained issuer/controller-selected endpoint. Controller
    still owns full packet/closure verification and actual callback admission.
    """
    check(deadline)
    layout = prepared['paths']
    prepared['owned'].verify(deadline)
    need(environment.get('GITHUB_SHA') == environment.get('GITHUB_WORKFLOW_SHA') == root_pins['source_commit'] and
         layout['workspace'] == absolute(environment.get('GITHUB_WORKSPACE')), 'checkout-job')
    # Compare actual run/attempt to names and grant, without reusing paths() which
    # correctly requires precreation paths to be absent in its earlier phase.
    grant_raw, _, _ = read(Path(prepared['execution_grant'][0]), deadline, owner=os.getuid(), mode=0o600)
    runtime_raw, _, _ = read(Path(prepared['runtime_contract'][0]), deadline, owner=os.getuid(), mode=0o600,
                            limit=16 * 1024)
    selection_raw, _, _ = read(Path(prepared['selection'][0]), deadline, owner=os.getuid(), mode=0o600)
    for ref, raw in ((prepared['execution_grant'], grant_raw), (prepared['runtime_contract'], runtime_raw),
                     (prepared['selection'], selection_raw)):
        need(digest(raw) == ref[1], 'retained-reference-drift')
    need(digest(selection_raw) == root_pins['selection_sha256'], 'retained-selection')
    value, grant, runtime = decode(selection_raw), decode(grant_raw), decode(runtime_raw, 16 * 1024)
    need(set(value) == SELECTION_KEYS and type(value['schema_version']) is int and
         value['schema_version'] == 3 and value['purpose'] == PURPOSE and
         type(value['composition']) is str and value['composition'] in MODES and
         len(value['source_files']) == MODES[value['composition']] and
         value['baseline_id'] == BASELINE_ID and value['lineage'] == LINEAGE and
         pin(value['source_packet_sha256']) and value['source_commit'] == root_pins['source_commit'] and
         value['peer_receipt_sha256'] == root_pins['peer_receipt_sha256'] and
         set(value['metadata_pins']) == METADATA and set(value['metadata_hex']) == METADATA,
         'checkout-selection')
    lock = decode(bytes.fromhex(value['metadata_hex'][INITIAL]))
    expected_view = {'schema_version': 2, 'purpose': 'maintained-v1-159-copy-view',
        'baseline_id': BASELINE_ID, 'full_source_root': str(layout['workspace']),
        'root': str(layout['output'] / 'repository-handoff/maintained-view'),
        'integration_lock_sha256': INITIAL_SHA,
        'source_rows_sha256': digest(encoded(lock['source_files'])),
        'file_count': 160, 'argv_mode': 'absolute-view-metadata'}
    need(set(grant) == {'schema_version', 'purpose', 'source_peer_preflight', 'development_only',
         'added_seconds', 'source_commit', 'recipe_source_commit', 'run_id', 'run_attempt',
         'source_files', 'maps', 'callbacks', 'policy_path', 'license_path', 'actor_contract_sha256',
         'initial_invocation_sha256', 'baseline_view'} and type(grant['schema_version']) is int and
         grant['schema_version'] == 2 and grant['purpose'] == 'reviewed-same-job-handoff-execution' and
         grant['source_peer_preflight'] == 'PASS' and grant['development_only'] is True and
         type(grant['added_seconds']) is int and grant['added_seconds'] == 1200 and
         grant['source_commit'] == root_pins['source_commit'] and
         grant['recipe_source_commit'] == lock['recipe_source_commit'] and
         grant['maps'] == value['maps'] and grant['callbacks'] == value['callbacks'] and
         grant['policy_path'] == POLICY and grant['license_path'] == 'LICENSE' and
         grant['baseline_view'] == expected_view and
         grant['initial_invocation_sha256'] == digest(encoded({'argv': original_argv(
             layout['output'], layout['cache'], value['metadata_pins']),
             'output': str(layout['output'] / 'repository-handoff')})) and
         set(runtime) == {'cli_sha256', 'endpoint_identity', 'env'} and
         runtime['cli_sha256'] == root_pins['cli_sha256'], 'checkout-contract')
    need(grant['run_id'] == environment.get('GITHUB_RUN_ID') and
         grant['run_attempt'] == environment.get('GITHUB_RUN_ATTEMPT') and
         grant['source_files'] == value['source_files'] and
         digest(encoded(value['source_files'])) == root_pins['source_rows_sha256'] and
         grant['actor_contract_sha256'] == digest(runtime_raw), 'checkout-bindings')
    count = 0
    for name, row in value['source_files'].items():
        raw, found, _ = read(layout['workspace'] / relative(name), deadline, limit=LIMIT, mode=row['mode'])
        count += len(raw)
        need(count <= TOTAL and digest(raw) == row['sha256'], 'checkout-source')
    for key, path in runtime['env'].items():
        if key in ('HOME', 'DOCKER_CONFIG', 'TMPDIR'):
            with directory(path) as fd:
                need(os.fstat(fd).st_uid == os.getuid() and stat.S_IMODE(os.fstat(fd).st_mode) == 0o700 and
                     not os.listdir(fd), 'tool-state')
    _, endpoint = observe_runtime(root_pins['cli_sha256'], deadline)
    need(list(endpoint) == runtime['endpoint_identity'], 'runtime-endpoint-drift')
    for path in (layout['output'], layout['cache']):
        need(not os.path.lexists(path), 'premature-controller-path')
    check(deadline)
    return {'selected_rows_verified': len(value['source_files']), 'metadata_pins': dict(value['metadata_pins'])}
