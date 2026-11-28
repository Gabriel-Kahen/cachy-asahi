#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unregistered dual-root bootstrap. Root supplies the trusted input pins."""

import base64
import binascii
import os
from pathlib import Path
import re
import stat
import time


ORIGINAL_SOURCE = {
    'source_commit': 'bcf0cee981ee4b7f7b082f636922c859dc7e0abc',
    'integration_lock_sha256': 'd4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31',
    'source_rows_sha256': 'e7a8d8c0a5ea037d648c2a40eb0e66a57cbb88b64c847bfac8ca725dc510b2e4',
    'runner_sha256': '49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940',
}
RUNNER = 'scripts/integration/repository.py'
INVOCATION_METADATA = ('scripts/ci/inputs.lock.json', 'scripts/ci/recipes.lock.json')


def selection(legacy, raw, peer_raw, root_pins, deadline):
    legacy.check(deadline)
    fields = legacy.PIN_KEYS | {'original_source_sha256'}
    legacy.need(type(root_pins) is dict and set(root_pins) == fields and
                all(legacy.pin(root_pins[key]) for key in fields - {'source_commit'}) and
                type(root_pins['source_commit']) is str and
                re.fullmatch('[0-9a-f]{40}', root_pins['source_commit']), 'root-pins')
    legacy.need(type(peer_raw) is bytes and 0 < len(peer_raw) <= legacy.LIMIT and
                legacy.digest(peer_raw) == root_pins['peer_receipt_sha256'] and
                type(raw) is bytes and 0 < len(raw) <= legacy.LIMIT and
                legacy.digest(raw) == root_pins['selection_sha256'], 'external-provenance')
    value = legacy.decode(raw)
    legacy.need(set(value) == legacy.SELECTION_KEYS | {'original_source', 'packet_sha256'} and
                value['source_commit'] == root_pins['source_commit'] and
                value['peer_receipt_sha256'] == root_pins['peer_receipt_sha256'] and
                value['original_source'] == ORIGINAL_SOURCE and legacy.pin(value['packet_sha256']),
                'selection-provenance')
    rows = value['source_files']
    legacy.need(type(rows) is dict and 240 <= len(rows) <= 20000 and
                legacy.digest(legacy.encoded(rows)) == root_pins['source_rows_sha256'], 'selected-rows')
    for name, row in rows.items():
        legacy.relative(name)
        legacy.need(type(row) is dict and set(row) == {'sha256', 'mode'} and
                    legacy.pin(row['sha256']) and type(row['mode']) is int and
                    row['mode'] in (0o644, 0o755), 'source-row')
    pins, hexes = value['metadata_pins'], value['metadata_hex']
    legacy.need(type(pins) is dict and set(pins) == legacy.METADATA and
                type(hexes) is dict and set(hexes) == legacy.METADATA and
                value['callbacks'] == legacy.CALLBACKS and type(value['maps']) is dict and
                set(value['maps']) == set(legacy.PREFIXES), 'selection-closure')
    metadata = {}
    for name in sorted(legacy.METADATA):
        legacy.check(deadline)
        item = hexes[name]
        legacy.need(legacy.pin(pins[name]) and type(item) is str and len(item) <= 2 * legacy.LIMIT and
                    len(item) % 2 == 0 and re.fullmatch('[0-9a-f]*', item), 'metadata-encoding')
        data = bytes.fromhex(item)
        legacy.need(name in rows and legacy.digest(data) == pins[name] == rows[name]['sha256'], 'metadata-pin')
        metadata[name] = data
    legacy.need(sum(map(len, metadata.values())) <= legacy.TOTAL and
                pins[legacy.POLICY] == legacy.POLICY_SHA and
                rows.get('LICENSE', {}).get('sha256') == legacy.LICENSE_SHA, 'immutable-pins')
    for role, prefix in legacy.PREFIXES.items():
        path = prefix + '/source-map.json'
        legacy.need(value['maps'][role] == {'path': path, 'sha256': pins[path]}, 'selected-map')
        mapping = legacy.decode(metadata[path])
        legacy.need(set(mapping) == {name + '.py' for name in legacy.MAP_NAMES[role]} and
                    all(rows.get(prefix + '/' + name) == row for name, row in mapping.items()), 'map-closure')
    policy = legacy.decode(metadata[legacy.POLICY])
    legacy.need(policy.get('supported_models') == [] and policy.get('platform_scope') == 'generic-builder-only' and
                policy.get('review_status') == 'ACCEPTED', 'policy')
    legacy.check(deadline)
    return value


def historical_specs(legacy, lock_raw):
    lock_pin = ORIGINAL_SOURCE['integration_lock_sha256']
    legacy.need(legacy.digest(lock_raw) == lock_pin, 'historical-lock-pin')
    lock = legacy.decode(lock_raw)
    rows = lock['source_files']
    legacy.need(type(rows) is dict and len(rows) == 159 and legacy.INITIAL not in rows and
                type(lock['generated_fixture_files']) is dict and len(lock['generated_fixture_files']) == 125 and
                legacy.digest(legacy.encoded(rows)) == ORIGINAL_SOURCE['source_rows_sha256'] and
                rows.get(RUNNER) == {'mode': 0o644, 'sha256': ORIGINAL_SOURCE['runner_sha256']} and
                type(lock['recipe_source_commit']) is str and re.fullmatch('[0-9a-f]{40}', lock['recipe_source_commit']),
                'historical-lock-contract')
    invocation = {legacy.INITIAL: lock_pin, **{name: rows[name]['sha256'] for name in INVOCATION_METADATA}}
    legacy.need(invocation[INVOCATION_METADATA[1]] == lock['recipes_sha256'], 'historical-recipe-pin')
    return lock, {**rows, legacy.INITIAL: {'mode': 0o644, 'sha256': lock_pin}}, invocation


def decode_file(legacy, row):
    legacy.need(type(row) is dict and set(row) == {'mode', 'base64'} and
                type(row['mode']) is int and row['mode'] in (0o644, 0o755) and
                type(row['base64']) is str, 'historical-row')
    try:
        raw = base64.b64decode(row['base64'], validate=True)
    except (ValueError, binascii.Error):
        raise legacy.Refused('historical-base64') from None
    legacy.need(len(raw) <= legacy.LIMIT and base64.b64encode(raw).decode('ascii') == row['base64'],
                'historical-base64')
    return raw


def historical_source(legacy, raw, root_pins, deadline):
    legacy.check(deadline)
    legacy.need(type(raw) is bytes and 0 < len(raw) <= legacy.LIMIT and
                legacy.digest(raw) == root_pins['original_source_sha256'], 'historical-bundle-pin')
    value = legacy.decode(raw)
    legacy.need(set(value) == {'schema_version', 'source_commit', 'files'} and
                type(value['schema_version']) is int and value['schema_version'] == 1 and
                value['source_commit'] == ORIGINAL_SOURCE['source_commit'] and
                type(value['files']) is dict and len(value['files']) == 160 and
                legacy.INITIAL in value['files'], 'historical-bundle-contract')
    files = value['files']
    lock, specs, invocation = historical_specs(legacy, decode_file(legacy, files[legacy.INITIAL]))
    legacy.need(set(files) == set(specs), 'historical-path-set')
    captures = {}
    total = 0
    for name, expected in sorted(specs.items()):
        legacy.check(deadline)
        legacy.relative(name)
        row = files[name]
        data = decode_file(legacy, row)
        total += len(data)
        legacy.need(total <= legacy.TOTAL and row['mode'] == expected['mode'] and
                    legacy.digest(data) == expected['sha256'], 'historical-source-pin')
        captures[name] = (data, expected['mode'])
    return lock, captures, invocation


def stage_historical(legacy, owned, root, captures, deadline):
    owned.mkdir(root, deadline)
    directories = {root}
    for name, (raw, mode) in sorted(captures.items()):
        path = root / name
        for directory in reversed(path.parents):
            if directory.is_relative_to(root) and directory not in directories:
                owned.mkdir(directory, deadline)
                directories.add(directory)
        if raw:
            owned.write(path, raw, deadline, legacy.LIMIT)
        else:
            legacy.check(deadline)
            with legacy.directory(path.parent) as parent:
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
                fd = os.open(path.name, flags, 0o600, dir_fd=parent)
                opened = os.fstat(fd)
                node = legacy.identity(opened)
                owned.nodes.append((path, fd, node, False))
                legacy.need(stat.S_ISREG(opened.st_mode) and stat.S_IMODE(opened.st_mode) == 0o600 and
                            opened.st_uid == os.getuid() and opened.st_nlink == 1 and opened.st_size == 0 and
                            node == legacy.identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                            'historical-stage-drift')
        target, fd, before, directory = owned.nodes[-1]
        legacy.need(target == path and not directory, 'historical-owned-file')
        with legacy.directory(path.parent) as parent:
            legacy.need(legacy.identity(os.fstat(fd)) == before ==
                        legacy.identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'historical-stage-drift')
            try:
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                after = legacy.identity(os.fstat(fd))
                legacy.need(after[:2] == before[:2] and after[3:] == before[3:], 'historical-stage-drift')
                owned.nodes[-1] = (path, fd, after, False)
        staged, node, _ = legacy.read(path, deadline, owner=os.getuid(), mode=mode)
        legacy.need(staged == raw and node == after, 'historical-stage-drift')


def grant_contract(legacy, value, lock, layout, invocation, environment, runtime_raw):
    adapter = layout['output'] / 'repository-handoff'
    return {
        'schema_version': 3, 'purpose': 'reviewed-same-job-handoff-execution',
        'source_peer_preflight': 'PASS', 'development_only': True, 'added_seconds': 1200,
        'source_commit': value['source_commit'], 'recipe_source_commit': lock['recipe_source_commit'],
        'run_id': environment['GITHUB_RUN_ID'], 'run_attempt': environment['GITHUB_RUN_ATTEMPT'],
        'source_files': value['source_files'], 'maps': value['maps'], 'callbacks': value['callbacks'],
        'policy_path': legacy.POLICY, 'license_path': 'LICENSE', 'actor_contract_sha256': legacy.digest(runtime_raw),
        'initial_invocation_sha256': legacy.digest(legacy.encoded({
            'argv': legacy.original_argv(layout['output'], layout['cache'], invocation), 'output': str(adapter)})),
        'original_view': {
            'schema_version': 2, 'purpose': 'original-159-copy-view',
            'full_source_root': str(layout['workspace']), 'source_root': str(layout['original']),
            'root': str(adapter / 'original-view'), 'file_count': 160, 'argv_mode': 'absolute-view-metadata',
            **value['original_source'],
        },
    }


def prepare(legacy, selection_raw, peer_raw, historical_raw, root_pins, environment, *, preparation_deadline):
    entry = time.monotonic()
    legacy.check(preparation_deadline)
    legacy.need(preparation_deadline <= entry + legacy.PREPARATION_SECONDS, 'preparation-bound')
    value = selection(legacy, selection_raw, peer_raw, root_pins, preparation_deadline)
    lock, captures, invocation = historical_source(legacy, historical_raw, root_pins, preparation_deadline)
    layout = legacy.paths(environment, root_pins)
    layout['original'] = layout['bootstrap'] / 'historical-source'
    owned = legacy.Owned()
    try:
        owned.mkdir(layout['bootstrap'], preparation_deadline)
        stage_historical(legacy, owned, layout['original'], captures, preparation_deadline)
        owned.mkdir(layout['tools'], preparation_deadline)
        for name in ('home', 'config', 'tmp'):
            owned.mkdir(layout['tools'] / name, preparation_deadline)
        cli_before, endpoint = legacy.observe_runtime(root_pins['cli_sha256'], preparation_deadline)
        runtime = {'cli_sha256': root_pins['cli_sha256'], 'endpoint_identity': list(endpoint),
                   'env': {'PATH': '/usr/bin:/bin', 'HOME': str(layout['tools'] / 'home'),
                           'DOCKER_CONFIG': str(layout['tools'] / 'config'),
                           'DOCKER_HOST': 'unix:///run/docker.sock', 'DOCKER_BUILDKIT': '0',
                           'LC_ALL': 'C', 'TMPDIR': str(layout['tools'] / 'tmp')}}
        runtime_raw = legacy.encoded(runtime)
        grant = grant_contract(legacy, value, lock, layout, invocation, environment, runtime_raw)
        runtime_ref = owned.write(layout['bootstrap'] / 'runtime.json', runtime_raw, preparation_deadline, 16 * 1024)
        grant_ref = owned.write(layout['bootstrap'] / 'grant.json', legacy.encoded(grant), preparation_deadline, legacy.LIMIT)
        source_ref = owned.write(layout['bootstrap'] / 'selection.json', selection_raw, preparation_deadline, legacy.LIMIT)
        cli_after, endpoint_after = legacy.observe_runtime(root_pins['cli_sha256'], preparation_deadline)
        legacy.need((cli_before, endpoint) == (cli_after, endpoint_after), 'runtime-identity-drift')
        owned.verify(preparation_deadline)
        legacy.check(preparation_deadline)
        return {'execution_grant': grant_ref, 'runtime_contract': runtime_ref, 'selection': source_ref,
                'paths': layout, 'owned': owned}
    except BaseException as first:
        owned.dispose()
        if type(first) is legacy.Refused:
            first.cleanup_complete = not owned.cleanup_errors
        raise


def verify_checkout(legacy, prepared, root_pins, environment, *, deadline):
    legacy.check(deadline)
    layout = prepared['paths']
    original = layout['original']
    legacy.need(original == layout['bootstrap'] / 'historical-source', 'historical-root-binding')
    prepared['owned'].verify(deadline)
    lock_raw, _, _ = legacy.read(original / legacy.INITIAL, deadline, owner=os.getuid(), mode=0o644)
    lock, specs, invocation = historical_specs(legacy, lock_raw)
    total = 0
    entries = {}
    for name, expected in specs.items():
        path = original / legacy.relative(name)
        raw, _, _ = legacy.read(path, deadline, owner=os.getuid(), mode=expected['mode'])
        total += len(raw)
        legacy.need(total <= legacy.TOTAL and legacy.digest(raw) == expected['sha256'], 'historical-source-drift')
        while path != original:
            entries.setdefault(path.parent, set()).add(path.name)
            path = path.parent
    for path, names in entries.items():
        legacy.check(deadline)
        with legacy.directory(path) as fd:
            with os.scandir(fd) as discovered:
                for entry in discovered:
                    legacy.check(deadline)
                    legacy.need(entry.name in names, 'historical-path-drift')
                    names.remove(entry.name)
            legacy.need(not names, 'historical-path-drift')
    verified = legacy.verify_checkout(prepared, root_pins, environment, deadline=deadline)
    slots = {}
    for name, limit in (('selection', legacy.LIMIT), ('execution_grant', legacy.LIMIT), ('runtime_contract', 16 * 1024)):
        path, expected = prepared[name]
        raw, _, _ = legacy.read(Path(path), deadline, owner=os.getuid(), mode=0o600, limit=limit)
        legacy.need(legacy.digest(raw) == expected, 'retained-reference-drift')
        slots[name] = raw
    legacy.need(legacy.digest(slots['selection']) == root_pins['selection_sha256'], 'retained-selection')
    value = legacy.decode(slots['selection'])
    expected = grant_contract(legacy, value, lock, layout, invocation, environment, slots['runtime_contract'])
    legacy.need(slots['execution_grant'] == legacy.encoded(expected), 'checkout-v3-grant')
    prepared['owned'].verify(deadline)
    legacy.check(deadline)
    return {'selected_rows_verified': verified['selected_rows_verified'], 'metadata_pins': invocation,
            'packet_sha256': value['packet_sha256']}
