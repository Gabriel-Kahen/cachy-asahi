#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hash-pinned per-user migrations. Preview/status read only; apply/recover write."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
import uuid

import setup as contract

Error = contract.Error
checksum = contract.checksum
MAX_MANIFEST = 128 * 1024


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected.split()):
        raise Error('Invalid migration fields')


def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise Error('A lowercase SHA-256 is required')
    return value


def word(value, pattern=r'[A-Za-z0-9][A-Za-z0-9_.:+~-]{0,127}'):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise Error('Invalid migration identity/version')
    return value


def load_manifest(path, expected):
    digest(expected)
    path = Path(path)
    contract.parts(path, absolute=True)
    fs = contract.Files(path.parent, source=True)
    try:
        raw = fs.read(path.name)['data']
    finally:
        fs.close()
    if raw is None or len(raw) > MAX_MANIFEST or checksum(raw) != expected:
        raise Error('Migration manifest missing, oversized or hash differs')
    try:
        manifest = contract.recovery_json(raw)
        keys(manifest, 'schema_version id package from_version to_version entries')
        if type(manifest['schema_version']) is not int or manifest['schema_version'] != 1:
            raise Error('Unsupported migration schema')
        for field in ('id', 'package', 'from_version', 'to_version'):
            word(manifest[field])
        if manifest['from_version'] == manifest['to_version']:
            raise Error('Migration versions must differ')
        entries = manifest['entries']
        if not isinstance(entries, list) or not 1 <= len(entries) <= len(contract.ALL_COMPONENTS):
            raise Error('Select a finite nonempty component set')
        seen = set()
        for entry in entries:
            keys(entry, 'component old new')
            component = entry['component']
            if component not in contract.ALL_COMPONENTS or component in seen:
                raise Error('Unknown/duplicate migration component')
            seen.add(component)
            for side in ('old', 'new'):
                keys(entry[side], 'root sha256')
                root = entry[side]['root']
                if not isinstance(root, str) or str(Path(root)) != root:
                    raise Error('Template roots must be normalized absolute paths')
                contract.parts(root, absolute=True)
                digest(entry[side]['sha256'])
        entries.sort(key=lambda e: contract.ORDER.index(e['component']))
        return manifest
    except (ValueError, TypeError, KeyError):
        raise Error('Invalid migration manifest; no contents printed') from None


class Migration:
    def __init__(self, home, manifest_path, manifest_sha256, config='.config', zsh='.',
                 state='.local/state/cachy-asahi/setup'):
        self.manifest = load_manifest(manifest_path, manifest_sha256)
        self.manifest_sha256 = manifest_sha256
        self.setup = contract.Setup(home, config=config, zsh=zsh, state=state)
        self.fs = self.setup.fs
        self.ledger_path = str(Path(state) / 'migrations.json')

    def close(self):
        self.setup.close()

    def empty_state(self):
        return {'schema_version': 1, 'roots': self.setup.roots, 'components': {}}

    def empty_ledger(self):
        return {'schema_version': 1, 'roots': self.setup.roots, 'components': {}}

    def read_json(self, path, default=None):
        value = self.setup.load(path, default)
        return value

    def state_valid(self, state):
        keys(state, 'schema_version roots components')
        if type(state['schema_version']) is not int or state['schema_version'] != 1 or state['roots'] != self.setup.roots or not isinstance(state['components'], dict):
            raise Error('Invalid migration setup state')
        for name, record in state['components'].items():
            keys(record, 'path kind sha256' if name == 'hyprland' else 'path kind block created_file source_root')
            self.setup.validate_record(name, record)

    def ledger_valid(self, ledger):
        keys(ledger, 'schema_version roots components')
        if type(ledger['schema_version']) is not int or ledger['schema_version'] != 1 or ledger['roots'] != self.setup.roots or not isinstance(ledger['components'], dict):
            raise Error('Invalid migration version ledger')
        for name, record in ledger['components'].items():
            keys(record, 'package version root sha256')
            if name not in contract.ALL_COMPONENTS:
                raise Error('Unknown version-ledger component')
            word(record['package']); word(record['version'])
            contract.parts(record['root'], absolute=True)
            digest(record['sha256'])

    def version(self, entry, side):
        return dict(entry[side], package=self.manifest['package'],
                    version=self.manifest['from_version' if side == 'old' else 'to_version'])

    def sources(self):
        result = {}
        for entry in self.manifest['entries']:
            name = entry['component']
            result[name] = {}
            for side in ('old', 'new'):
                fs = contract.Files(entry[side]['root'], source=True)
                try:
                    data = fs.read(contract.TEMPLATES[name])['data']
                finally:
                    fs.close()
                if data is None or checksum(data) != entry[side]['sha256']:
                    raise Error('Pinned template missing or hash differs: ' + name + '/' + side)
                if Path(entry[side]['root']) / contract.TEMPLATES[name] == self.setup.home / self.setup.targets[name]:
                    raise Error('A template cannot be the managed target')
                result[name][side] = data
        return result

    def desired_record(self, entry, old_record):
        name = entry['component']
        self.setup.validate_record(name, old_record)
        if name == 'hyprland':
            if old_record['sha256'] != entry['old']['sha256']:
                raise Error('Old file ownership differs from the pinned input')
            return dict(old_record, sha256=entry['new']['sha256'])
        if old_record['source_root'] != entry['old']['root']:
            raise Error('Old source root differs from owned block')
        prefix = '\n' if old_record['block'].startswith('\n') else ''
        block = prefix + contract.block(name, Path(entry['new']['root']) / contract.TEMPLATES[name])
        return dict(old_record, block=block, source_root=entry['new']['root'])

    def transform(self, path, data, old_state, new_state, sources, reverse=False):
        entries = [e for e in self.manifest['entries'] if self.setup.targets[e['component']] == path]
        for entry in reversed(entries) if reverse else entries:
            name = entry['component']
            old, new = old_state['components'][name], new_state['components'][name]
            if name == 'hyprland':
                side, other = ('new', 'old') if reverse else ('old', 'new')
                if checksum(data) != entry[side]['sha256']:
                    raise Error('Managed file edited or absent; preserved: ' + name)
                data = sources[name][other]
            else:
                before, after = (new, old) if reverse else (old, new)
                text = (data or b'').decode('utf-8')
                if any(text.count(marker) != 1 for marker in contract.markers(name)):
                    raise Error('Managed markers edited or duplicated; preserved: ' + name)
                data = contract.splice(data, before['block'], after['block'])
            contract.check_size(data)
        self.setup.check_order(data, old_state['components'] if reverse else new_state['components'], path)
        return data

    def derive(self, old_state, old_ledger):
        self.state_valid(old_state); self.ledger_valid(old_ledger)
        new_state, new_ledger = copy.deepcopy(old_state), copy.deepcopy(old_ledger)
        for entry in self.manifest['entries']:
            name = entry['component']
            if name not in old_state['components']:
                raise Error('Component is not owned; activate the exact old template first: ' + name)
            prior = old_ledger['components'].get(name)
            if prior is not None and prior != self.version(entry, 'old'):
                raise Error('Recorded version differs from the exact old version: ' + name)
            new_state['components'][name] = self.desired_record(entry, old_state['components'][name])
            new_ledger['components'][name] = self.version(entry, 'new')
        return new_state, new_ledger

    def completed(self, state, ledger):
        if not all(ledger['components'].get(e['component']) == self.version(e, 'new') for e in self.manifest['entries']):
            return False
        for entry in self.manifest['entries']:
            name = entry['component']
            record = state['components'].get(name)
            if record is None:
                raise Error('Previously migrated component was removed; no activation inferred: ' + name)
            if name == 'hyprland':
                if record['sha256'] != entry['new']['sha256'] or checksum(self.fs.read(record['path'])['data']) != record['sha256']:
                    raise Error('Migrated file changed; preserved: ' + name)
            else:
                expected = contract.block(name, Path(entry['new']['root']) / contract.TEMPLATES[name])
                if record['source_root'] != entry['new']['root'] or record['block'] not in (expected, '\n' + expected):
                    raise Error('Migrated block ownership changed: ' + name)
                data = self.fs.read(record['path'])['data']
                if data is None or data.count(record['block'].encode()) != 1 or any(data.decode().count(m) != 1 for m in contract.markers(name)):
                    raise Error('Migrated block changed; preserved: ' + name)
                self.setup.check_order(data, state['components'], record['path'])
        return True

    def plan(self, sources):
        state_raw = self.fs.read(self.setup.state_path)['data']
        ledger_raw = self.fs.read(self.ledger_path)['data']
        old_state = self.read_json(self.setup.state_path, self.empty_state())
        ledger = self.read_json(self.ledger_path, self.empty_ledger())
        self.state_valid(old_state); self.ledger_valid(ledger)
        if self.completed(old_state, ledger):
            return None
        new_state, new_ledger = self.derive(old_state, ledger)
        files = []
        for path in dict.fromkeys(self.setup.targets[e['component']] for e in self.manifest['entries']):
            before = self.fs.read(path)['data']
            after = self.transform(path, before, old_state, new_state, sources)
            files.append({'path': path, 'before': checksum(before), 'after': checksum(after)})
        return {'schema_version': 1, 'roots': self.setup.roots,
                # Legacy setup rejects this identity and cannot remove mid-transaction.
                'id': 'migration-' + uuid.uuid4().hex, 'kind': 'config-migration-v1',
                'manifest_sha256': self.manifest_sha256, 'old_state': old_state,
                'old_ledger': ledger, 'state_before': checksum(state_raw),
                'ledger_before': checksum(ledger_raw), 'files': files}

    def prepare(self, journal, sources):
        keys(journal, 'schema_version roots id kind manifest_sha256 old_state old_ledger state_before ledger_before files')
        if type(journal['schema_version']) is not int or journal['schema_version'] != 1 or journal['roots'] != self.setup.roots or journal['kind'] != 'config-migration-v1' or not re.fullmatch(r'migration-[0-9a-f]{32}', journal['id']) or journal['manifest_sha256'] != self.manifest_sha256:
            raise Error('Pending migration needs its exact manifest, hash and roots')
        for key in ('state_before', 'ledger_before'):
            if journal[key] is not None:
                digest(journal[key])
        old_state, old_ledger = journal['old_state'], journal['old_ledger']
        new_state, new_ledger = self.derive(old_state, old_ledger)
        metadata = ((self.setup.state_path, journal['state_before'], new_state, old_state),
                    (self.ledger_path, journal['ledger_before'], new_ledger, old_ledger))
        ready_metadata = []
        for path, before, new, old in metadata:
            current = self.fs.read(path)
            if current['data'] is not None and current['mode'] & 0o077:
                raise Error('Migration metadata must be private')
            actual = checksum(current['data'])
            if actual not in (before, checksum(encode(new))):
                raise Error('Metadata changed during interrupted migration; journal retained')
            if actual == before and self.read_json(path, self.empty_state()) != old:
                raise Error('Pending old metadata differs')
            ready_metadata.append((path, new, actual))
        files = journal['files']
        paths = list(dict.fromkeys(self.setup.targets[e['component']] for e in self.manifest['entries']))
        if not isinstance(files, list) or len(files) != len(paths):
            raise Error('Invalid pending migration file set')
        prepared = []
        for item, path in zip(files, paths):
            keys(item, 'path before after')
            if item['path'] != path:
                raise Error('Pending migration path differs from finite manifest')
            digest(item['before']); digest(item['after'])
            current = self.fs.read(path)['data']
            actual = checksum(current)
            if actual == item['before']:
                before = current
                after = self.transform(path, before, old_state, new_state, sources)
            elif actual == item['after']:
                after = current
                before = self.transform(path, after, old_state, new_state, sources, reverse=True)
            else:
                raise Error('Configuration changed during interrupted migration; journal retained, user edits preserved')
            if checksum(before) != item['before'] or checksum(after) != item['after']:
                raise Error('Pending migration delta/hash differs')
            prepared.append((path, after, actual))
        return prepared, ready_metadata

    def replay(self, journal, sources):
        prepared, metadata = self.prepare(journal, sources)
        for path, data, expected in prepared:
            if checksum(data) != expected:
                self.fs.atomic(path, data, expected)
        for path, data, _expected in prepared:
            if checksum(self.fs.read(path)['data']) != checksum(data):
                raise Error('Configuration changed before metadata commit; journal retained')
        for path, new, expected in metadata:
            if expected != checksum(encode(new)):
                self.fs.atomic(path, encode(new), expected, private=True)
            elif checksum(self.fs.read(path)['data']) != expected:
                raise Error('Metadata changed before commit; journal retained')
        current = self.fs.read(self.setup.journal_path)['data']
        if current != encode(journal):
            raise Error('Journal changed; retained for review')
        self.fs.atomic(self.setup.journal_path, None, checksum(current), private=True)

    def run(self, operation):
        if operation not in ('preview', 'apply', 'status', 'recover'):
            raise Error('Unrecognized migration operation')
        lock = self.fs.lock(self.setup.lock_path) if operation in ('apply', 'recover') else None
        try:
            sources = self.sources()
            pending = self.read_json(self.setup.journal_path)
            if pending is not None:
                if pending.get('kind') != 'config-migration-v1':
                    raise Error('Setup has a pending transaction; recover it with setup.py first')
                prepared, _ = self.prepare(pending, sources)
                if operation == 'apply':
                    raise Error('Pending migration requires explicit recover')
                if operation == 'recover':
                    self.replay(pending, sources)
                return {'operation': operation, 'status': 'recovered' if operation == 'recover' else 'pending',
                        'manifest_sha256': self.manifest_sha256,
                        'actions': [{'path': path, 'status': 'recovered' if operation == 'recover' else 'already-applied' if checksum(data) == actual else 'pending'}
                                    for path, data, actual in prepared]}
            if operation == 'recover':
                return {'operation': operation, 'status': 'no-pending-transaction', 'actions': []}
            journal = self.plan(sources)
            if operation == 'apply' and journal:
                # Check size before recording intent or touching any managed file.
                contract.check_size(encode(journal))
                self.fs.atomic(self.setup.journal_path, encode(journal), None, private=True)
                self.replay(journal, sources)
            return {'operation': operation, 'status': 'already-applied' if journal is None else 'applied' if operation == 'apply' else 'ready',
                    'manifest_sha256': self.manifest_sha256,
                    'package': self.manifest['package'], 'from_version': self.manifest['from_version'],
                    'to_version': self.manifest['to_version'],
                    'actions': [] if journal is None else journal['files']}
        finally:
            if lock is not None:
                os.close(lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('preview', 'apply', 'status', 'recover'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True, help='expected digest from the reviewed release record')
    parser.add_argument('--home', type=Path)
    parser.add_argument('--config-home', type=Path)
    parser.add_argument('--zdotdir', type=Path)
    parser.add_argument('--state-dir', type=Path)
    args = parser.parse_args(argv)
    engine = None
    try:
        if os.geteuid() == 0:
            raise Error('Run configuration migration as the intended non-root user')
        home = args.home or Path.home()
        config = args.config_home or (os.environ.get('XDG_CONFIG_HOME') if args.home is None else None)
        zsh = args.zdotdir or (os.environ.get('ZDOTDIR') if args.home is None else None)
        state = args.state_dir
        if state is None and args.home is None and os.environ.get('XDG_STATE_HOME'):
            state = Path(os.environ['XDG_STATE_HOME']) / 'cachy-asahi/setup'
        engine = Migration(home, args.manifest, args.sha256,
                           contract.relative_directory(home, config, '.config'),
                           contract.relative_directory(home, zsh, '.'),
                           contract.relative_directory(home, state, '.local/state/cachy-asahi/setup'))
        result = engine.run(args.operation)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 2 if result['status'] == 'pending' else 0
    except (Error, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        message = str(error) if isinstance(error, Error) else 'Unsafe/unavailable path or invalid migration metadata; no contents printed'
        print(json.dumps({'status': 'error', 'error': message}), file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.close()


if __name__ == '__main__':
    sys.exit(main())
