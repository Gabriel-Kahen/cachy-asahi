#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview-first, per-user overlay activation/removal. No package/session operations."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import uuid
from pathlib import Path, PurePosixPath

MAX_BYTES = 2 * 1024 * 1024
COMPONENTS = ('fish', 'zsh', 'hyprland')
TEMPLATES = {'fish': 'fish/config.fish', 'zsh': 'zsh/config.zsh',
             'hyprland': 'hyprland/hyprland.lua'}
MODULES = ('fish-bang-bang', 'fish-autopair', 'fish-done', 'zsh-autosuggestions',
           'zsh-syntax-highlighting', 'zsh-history-substring-search')
ALL_COMPONENTS = COMPONENTS + MODULES
ORDER = ('fish', 'hyprland', 'zsh') + MODULES
TEMPLATES.update({name: name + ('/opt-in.fish' if name.startswith('fish-') else '/opt-in.zsh')
                  for name in MODULES})


class Error(Exception):
    """Messages deliberately omit file contents and credential-bearing exceptions."""


def recovery_json(raw):
    """Reject ambiguous object fields and noninteger recovery JSON numbers."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate recovery JSON field')
            result[key] = value
        return result
    def noninteger(_value):
        raise ValueError('Noninteger recovery JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=noninteger, parse_constant=noninteger)


def checksum(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def check_size(data):
    if data is not None and len(data) > MAX_BYTES:
        raise Error('Proposed configuration exceeds size limit; no write performed')


def parts(path, absolute=False):
    value = str(path)
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Error('Invalid path characters')
    parsed = PurePosixPath(value)
    if parsed.is_absolute() != absolute or '..' in parsed.parts:
        raise Error('Paths must be normalized and remain inside the selected home')
    result = parsed.parts[1:] if absolute else parsed.parts
    if not absolute and not result:
        raise Error('A file path is required')
    return result


def absolute_directory(path):
    """Open each component without following symlinks, retaining a directory FD."""
    names = parts(path, absolute=True)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in names:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class Files:
    def __init__(self, root, source=False):
        self.root = Path(root)
        self.fd = absolute_directory(self.root)
        self.source = source
        try:
            self.check_directory(self.fd)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    def check_directory(self, fd):
        item = os.fstat(fd)
        owners = (0, os.geteuid()) if self.source else (os.geteuid(),)
        if item.st_uid not in owners or item.st_mode & 0o022:
            raise Error('Directory ownership/permissions are unsafe')

    def parent(self, path, create=False):
        names = parts(path)
        fd = os.dup(self.fd)
        try:
            for name in names[:-1]:
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        os.close(fd)
                        return None, names[-1]
                    try:
                        os.mkdir(name, 0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    self.check_directory(child)
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            return fd, names[-1]
        except BaseException:
            os.close(fd)
            raise

    def read_at(self, parent, name):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            return {'data': None, 'mode': 0o600, 'gid': os.getegid(), 'xattrs': {}}
        try:
            item = os.fstat(fd)
            owners = (0, os.geteuid()) if self.source else (os.geteuid(),)
            if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or item.st_uid not in owners:
                raise Error('Only singly linked, user-owned regular configuration files are supported')
            if item.st_mode & 0o6022 or item.st_size > MAX_BYTES:
                raise Error('File permissions/size are unsafe')
            blocks, length = [], 0
            while block := os.read(fd, 65536):
                length += len(block)
                if length > MAX_BYTES:
                    raise Error('Configuration file exceeds size limit')
                blocks.append(block)
            data = b''.join(blocks)
            data.decode('utf-8')
            return {'data': data, 'mode': stat.S_IMODE(item.st_mode), 'gid': item.st_gid,
                    'identity': (item.st_dev, item.st_ino),
                    'xattrs': {key: os.getxattr(fd, key) for key in os.listxattr(fd)}}
        finally:
            os.close(fd)

    def read(self, path):
        fd, name = self.parent(path)
        if fd is None:
            return {'data': None, 'mode': 0o600, 'gid': os.getegid(), 'xattrs': {}}
        try:
            return self.read_at(fd, name)
        finally:
            os.close(fd)

    def atomic(self, path, data, expected, private=False):
        """Compare, write/fsync a private sibling, recheck, then atomically replace."""
        check_size(data)
        parent, name = self.parent(path, create=data is not None)
        if parent is None:
            if expected is not None:
                raise Error('Configuration changed during operation')
            return
        temporary = '.cachy-asahi-' + uuid.uuid4().hex + '.tmp'
        created = False
        try:
            before = self.read_at(parent, name)
            if checksum(before['data']) != expected:
                raise Error('Configuration changed during operation')
            if data is None:
                if before['data'] is not None:
                    os.unlink(name, dir_fd=parent)
                    os.fsync(parent)
                return
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
            created = True
            try:
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                os.fchown(fd, -1, before['gid'])
                for key, value in before['xattrs'].items():
                    os.setxattr(fd, key, value)
                os.fchmod(fd, 0o600 if private else before['mode'])
                os.fsync(fd)
            finally:
                os.close(fd)
            current = self.read_at(parent, name)
            if checksum(current['data']) != expected or current.get('identity') != before.get('identity'):
                raise Error('Configuration changed before atomic replacement')
            if before['data'] is None:
                # Atomic no-clobber creation: another writer's new file wins.
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.unlink(temporary, dir_fd=parent)
            else:
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            created = False
            os.fsync(parent)
        finally:
            if created:
                os.unlink(temporary, dir_fd=parent)
            os.close(parent)

    def lock(self, path):
        parent, name = self.parent(path, create=True)
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        item = os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or item.st_uid != os.geteuid() or item.st_mode & 0o077:
            os.close(fd)
            raise Error('Unsafe setup lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise Error('Another setup command is active; no configuration changed') from None
        return fd


def markers(component):
    return (f'# >>> cachy-asahi setup {component} v1 >>>',
            f'# <<< cachy-asahi setup {component} v1 <<<')


def block(component, source):
    begin, end = markers(component)
    quoted = shlex.quote(str(source))
    if component == 'fish' or component.startswith('fish-'):
        body = f'if status is-interactive; and test -r {quoted}\n    source {quoted}\nend'
    else:
        body = f'if [[ -o interactive && -r {quoted} ]]; then\n    source {quoted}\nfi'
    return f'{begin}\n{body}\n{end}\n'


def has_marker(data, component):
    text = (data or b'').decode('utf-8')
    return any(marker in text for marker in markers(component))


def splice(data, old, new):
    old, new = old.encode(), new.encode()
    if data is None or data.count(old) != 1:
        raise Error('Managed block was edited or duplicated; preserved')
    return data.replace(old, new, 1)


class Setup:
    def __init__(self, home, template_root='/usr/share/cachy-asahi', config='.config', zsh='.',
                 state='.local/state/cachy-asahi/setup'):
        self.home = Path(home)
        self.templates = Path(template_root)
        parts(self.templates, absolute=True)
        self.roots = {'config': str(PurePosixPath(config)), 'zsh': str(PurePosixPath(zsh))}
        # Directory roots may be '.'; every actual file path is still constrained.
        for directory in (config, zsh, state):
            parsed = PurePosixPath(directory)
            if parsed.is_absolute() or '..' in parsed.parts or any(ord(c) < 32 for c in str(directory)):
                raise Error('Configuration/state roots must stay inside the selected home')
        self.targets = {'fish': str(PurePosixPath(config) / 'fish/config.fish'),
                        'zsh': str(PurePosixPath(zsh) / '.zshrc'),
                        'hyprland': str(PurePosixPath(config) / 'cachy-asahi/hyprland.lua')}
        self.targets.update({name: self.targets['fish' if name.startswith('fish-') else 'zsh'] for name in MODULES})
        self.state_path = str(PurePosixPath(state) / 'state.json')
        self.journal_path = str(PurePosixPath(state) / 'journal.json')
        self.lock_path = str(PurePosixPath(state) / 'lock')
        state_dir = PurePosixPath(state)
        if not state_dir.parts or any(state_dir == PurePosixPath(p) or state_dir in PurePosixPath(p).parents for p in self.targets.values()):
            raise Error('State storage must be separate from managed configuration files')
        self.fs = Files(home)

    def close(self):
        self.fs.close()

    def load(self, path, default=None):
        snapshot = self.fs.read(path)
        if snapshot['data'] is None:
            return default
        if snapshot['mode'] & 0o077:
            raise Error('Setup state/journal must be private')
        try:
            data = recovery_json(snapshot['data'])
        except ValueError:
            raise Error('Invalid setup state/journal; no contents printed') from None
        if not isinstance(data, dict) or type(data.get('schema_version')) is not int or data.get('schema_version') != 1 or data.get('roots') != self.roots:
            raise Error('Setup state roots/schema differ; use the original configuration-root options')
        return data

    def save(self, path, data):
        before = self.fs.read(path)['data']
        encoded = (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
        self.fs.atomic(path, encoded, checksum(before), private=True)

    def source(self, component, root=None):
        directory = self.templates if root is None else Path(root)
        fs = Files(directory, source=True)
        try:
            data = fs.read(TEMPLATES[component])['data']
            if data is None:
                raise Error('Selected installed template is missing: ' + component)
            target = self.home / self.targets[component]
            if directory / TEMPLATES[component] == target:
                raise Error('A shell source template cannot be its own activation target')
            return data
        finally:
            fs.close()

    def validate_record(self, component, record):
        if component not in ALL_COMPONENTS or not isinstance(record, dict) or record.get('path') != self.targets[component]:
            raise Error('Unrecognized managed component/path in setup state')
        if component == 'hyprland':
            if record.get('kind') != 'file' or not isinstance(record.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', record['sha256']):
                raise Error('Invalid managed file record')
        else:
            if record.get('kind') != 'block' or not isinstance(record.get('block'), str) or not isinstance(record.get('created_file'), bool):
                raise Error('Invalid managed block record')
            parts(record.get('source_root', ''), absolute=True)
            expected = block(component, Path(record['source_root']) / TEMPLATES[component])
            if record['block'] not in (expected, '\n' + expected):
                raise Error('Managed block is not the canonical guarded setup block')

    def check_order(self, data, records, path):
        visible = [(ORDER.index(name), data.index(record['block'].encode()))
                   for name, record in records.items() if record['path'] == path and record['kind'] == 'block'
                   and data is not None and data.count(record['block'].encode()) == 1]
        positions = [position for _, position in sorted(visible)]
        if positions != sorted(positions):
            raise Error('Managed shell source order was changed; user configuration preserved')

    def plan(self, operation, components, state):
        records = dict(state['components'])
        for component, record in records.items():
            self.validate_record(component, record)
        entries, actions, staged = [], [], {}
        for component in components:
            path = self.targets[component]
            before = staged[path] if path in staged else self.fs.read(path)['data']
            record = records.get(component)
            action = {'component': component, 'path': path, 'status': 'unchanged'}
            change, after = None, before
            if operation == 'activate':
                source = self.source(component)
                if component == 'hyprland':
                    if before is not None and (record is None or checksum(before) != record['sha256']):
                        action['status'] = 'preserved-edited' if record else 'preserved-existing'
                    elif checksum(before) != checksum(source):
                        after = source
                        change = {'type': 'file', 'source': TEMPLATES[component], 'source_sha256': checksum(source)}
                        records[component] = {'path': path, 'kind': 'file', 'sha256': checksum(source)}
                        action['status'] = 'would-update' if before is not None else 'would-add'
                else:
                    desired = block(component, self.templates / TEMPLATES[component])
                    if record and before is not None and before.count(record['block'].encode()) == 1:
                        prefix = '\n' if record['block'].startswith('\n') else ''
                        desired = prefix + desired
                        if desired != record['block']:
                            change = {'type': 'splice', 'old': record['block'], 'new': desired}
                            after = splice(before, record['block'], desired)
                            records[component] = dict(record, block=desired, source_root=str(self.templates))
                            action['status'] = 'would-update'
                    elif has_marker(before, component):
                        action['status'] = 'preserved-edited' if record else 'preserved-existing'
                    else:
                        desired = ('\n' if before and not before.endswith(b'\n') else '') + desired
                        later = [(name, value) for name, value in records.items()
                                 if value['path'] == path and name != component and ORDER.index(name) > ORDER.index(component)]
                        anchor = min(later, key=lambda pair: ORDER.index(pair[0])) if later else None
                        if anchor:
                            name, value = anchor
                            after = splice(before, value['block'], desired + value['block'])
                            change = {'type': 'insert', 'new': desired, 'anchor_component': name, 'anchor_record': value}
                        else:
                            after = (before or b'') + desired.encode()
                            change = {'type': 'append', 'new': desired}
                        created = before is None or any(value['path'] == path and value.get('created_file') for value in records.values())
                        records[component] = {'path': path, 'kind': 'block', 'block': desired,
                                              'created_file': created, 'source_root': str(self.templates)}
                        action['status'] = 'would-add'
            else:
                if record is None:
                    action['status'] = 'unmanaged'
                elif before is None:
                    records.pop(component)
                    action['status'] = 'already-absent'
                elif component == 'hyprland':
                    if checksum(before) == record['sha256']:
                        after = None
                        change = {'type': 'delete'}
                        records.pop(component)
                        action['status'] = 'would-remove'
                    else:
                        action['status'] = 'preserved-edited'
                elif before.count(record['block'].encode()) == 1:
                    old = record['block']
                    start = before.index(old.encode())
                    left, right = before[:start], before[start + len(old.encode()):]
                    # Retain a separator when later user code would otherwise join a line.
                    replacement = '\n' if left and right and not left.endswith(b'\n') and not right.startswith(b'\n') else ''
                    after = splice(before, old, replacement)
                    if not after and record['created_file']:
                        after = None
                    change = {'type': 'splice', 'old': old, 'new': replacement, 'delete_empty': after is None}
                    records.pop(component)
                    action['status'] = 'would-remove'
                elif not has_marker(before, component):
                    records.pop(component)
                    action['status'] = 'already-absent'
                else:
                    action['status'] = 'preserved-edited'
            if change:
                staged[path] = after
                check_size(after)
                entries.append({'component': component, 'path': path, 'before': checksum(before),
                                'after': checksum(after), 'change': change, 'old_record': record,
                                'new_record': records.get(component)})
            actions.append(action)
        if operation == 'activate':
            for path in {self.targets[c] for c in components}:
                self.check_order(staged[path] if path in staged else self.fs.read(path)['data'], records, path)
        new_state = dict(state, components=records)
        grouped = {}
        for entry in entries:
            grouped.setdefault(entry['path'], []).append(entry)
        entries = [chain[0] if len(chain) == 1 else
                   {'path': path, 'before': chain[0]['before'], 'after': chain[-1]['after'], 'chain': chain}
                   for path, chain in grouped.items()]
        return entries, actions, new_state

    def validate_journal(self, journal):
        if not re.fullmatch(r'[0-9a-f]{32}', journal.get('id', '')):
            raise Error('Invalid pending transaction identity')
        if journal.get('template_root') != str(self.templates) or not isinstance(journal.get('entries'), list):
            raise Error('Pending transaction needs its original template-root option')
        new_state = journal.get('new_state', {})
        if not isinstance(new_state, dict) or type(new_state.get('schema_version')) is not int or new_state.get('schema_version') != 1 or new_state.get('roots') != self.roots or not isinstance(new_state.get('components'), dict):
            raise Error('Invalid pending state')
        prior_state = self.load(self.state_path, {'schema_version': 1, 'roots': self.roots, 'components': {}})
        prior_records = prior_state.get('components', {})
        if not isinstance(prior_records, dict):
            raise Error('Invalid prior component state')
        for component, record in new_state['components'].items():
            self.validate_record(component, record)
            # An untouched previously approved record can retain its old root.
            # Every newly introduced/changed record must use this transaction's root.
            if component != 'hyprland' and record['source_root'] != str(self.templates):
                if record != prior_records.get(component):
                    raise Error('Pending shell record differs from the approved template root')
        paths, flat = set(), []
        for group in journal['entries']:
            if not isinstance(group, dict):
                raise Error('Invalid pending configuration group')
            path = group.get('path')
            if not isinstance(path, str):
                raise Error('Invalid pending configuration path')
            if path in paths:
                raise Error('Unrecognized/duplicate pending configuration path')
            paths.add(path)
            if 'chain' not in group:
                flat.append(group)
                continue
            chain = group['chain']
            if not isinstance(chain, list) or not 2 <= len(chain) <= len(ALL_COMPONENTS) or not all(isinstance(e, dict) for e in chain):
                raise Error('Invalid pending shared-file chain')
            if set(group) != {'path', 'before', 'after', 'chain'} or group['before'] != chain[0].get('before') or group['after'] != chain[-1].get('after'):
                raise Error('Pending shared-file endpoints differ')
            for index, entry in enumerate(chain):
                if not isinstance(entry, dict):
                    raise Error('Invalid pending shared-file delta')
                if entry.get('path') != path or 'chain' in entry or (index and entry.get('before') != chain[index-1].get('after')):
                    raise Error('Pending shared-file deltas do not join')
            flat.extend(chain)
        seen = set()
        for entry in flat:
            component = entry.get('component')
            if component not in ALL_COMPONENTS or entry.get('path') != self.targets[component] or component in seen:
                raise Error('Unrecognized/duplicate pending configuration path')
            seen.add(component)
            for key in ('before', 'after'):
                if key not in entry or (entry[key] is not None and not re.fullmatch(r'[0-9a-f]{64}', entry[key])):
                    raise Error('Invalid pending file checksum')
            old, new = entry.get('old_record'), entry.get('new_record')
            for record in (old, new):
                if record is not None:
                    self.validate_record(component, record)
            if component != 'hyprland' and new is not None and new['source_root'] != str(self.templates):
                raise Error('Pending shell addition/update differs from the approved template root')
            if new != new_state['components'].get(component):
                raise Error('Pending component state differs from its operation')
            change = entry['change']
            kind = change['type']
            if kind == 'file':
                if component != 'hyprland' or not new or change.get('source') != TEMPLATES[component] or change.get('source_sha256') != new['sha256'] or entry['after'] != new['sha256']:
                    raise Error('Invalid pending template copy')
                if entry['before'] is not None and (not old or entry['before'] != old['sha256']):
                    raise Error('Pending file update lacks ownership')
            elif kind == 'delete':
                if component != 'hyprland' or not old or entry['before'] != old['sha256'] or new is not None or entry['after'] is not None:
                    raise Error('Pending file removal lacks ownership')
            elif kind == 'insert':
                anchor = change.get('anchor_component')
                anchor_record = change.get('anchor_record')
                if component == 'hyprland' or anchor not in ALL_COMPONENTS or anchor == 'hyprland':
                    raise Error('Invalid pending insertion anchor')
                self.validate_record(anchor, anchor_record)
                approved = [prior_records.get(anchor)] + [e.get(key) for e in flat if e.get('component') == anchor for key in ('old_record', 'new_record')]
                if anchor_record not in approved or self.targets[anchor] != entry['path'] or ORDER.index(anchor) <= ORDER.index(component):
                    raise Error('Pending insertion anchor lacks ordered ownership')
                if not new or change.get('new') != new['block']:
                    raise Error('Invalid pending guarded insertion')
            elif kind == 'append':
                if component == 'hyprland' or not new or change.get('new') != new['block']:
                    raise Error('Invalid pending guarded block')
            elif kind == 'splice':
                if component == 'hyprland' or not old or change.get('old') != old['block']:
                    raise Error('Pending block removal/update lacks ownership')
                if change.get('new') != (new['block'] if new else '') and not (new is None and change.get('new') == '\n'):
                    raise Error('Invalid pending block replacement')
                if change.get('delete_empty') and (new is not None or not old['created_file']):
                    raise Error('Pending file deletion lacks ownership')
            else:
                raise Error('Unknown pending operation')
        for component, record in new_state['components'].items():
            if record != prior_records.get(component) and not any(
                    entry['component'] == component and entry.get('new_record') == record for entry in flat):
                raise Error('Pending ownership change lacks a validated operation')

    def prepare_replay(self, journal):
        self.validate_journal(journal)
        new_state = journal['new_state']
        # Prepare every delta first; a missing/upgraded template cannot cause a new partial run.
        prepared, actions = [], []
        for group in journal['entries']:
            before = self.fs.read(group['path'])['data']
            actual = checksum(before)
            for entry in group.get('chain', [group]):
                action = 'remove' if entry.get('new_record') is None else 'add' if entry.get('old_record') is None else 'update'
                actions.append({'component': entry['component'], 'path': group['path'],
                                'status': 'already-applied' if actual == group['after'] else 'would-' + action})
            if actual == group['after']:
                self.check_order(before, new_state['components'], group['path'])
                continue
            if actual != group['before']:
                raise Error('Configuration changed during interrupted setup; pending journal retained, user edits preserved')
            after = before
            for entry in group.get('chain', [group]):
                if checksum(after) != entry['before']:
                    raise Error('Pending shared-file input checksum differs')
                change = entry['change']
                if change['type'] == 'file':
                    after = self.source(entry['component'])
                    if checksum(after) != change['source_sha256']:
                        raise Error('Pending template changed; journal retained')
                elif change['type'] == 'append':
                    after = (after or b'') + change['new'].encode()
                elif change['type'] == 'insert':
                    anchor = change['anchor_record']['block']
                    after = splice(after, anchor, change['new'] + anchor)
                elif change['type'] == 'splice':
                    after = splice(after, change['old'], change['new'])
                    if change.get('delete_empty') and not after:
                        after = None
                else:  # validate_journal permits only a file deletion here.
                    after = None
                check_size(after)
                if checksum(after) != entry['after']:
                    raise Error('Pending operation checksum differs')
            self.check_order(after, new_state['components'], group['path'])
            prepared.append((group, after))
        return prepared, actions

    def replay(self, journal):
        prepared, _ = self.prepare_replay(journal)
        new_state = journal['new_state']
        for group, after in prepared:
            self.fs.atomic(group['path'], after, group['before'])
        self.save(self.state_path, new_state)
        old = self.fs.read(self.journal_path)['data']
        self.fs.atomic(self.journal_path, None, checksum(old), private=True)

    def status(self, components=()):
        """Observe ownership/replay readiness without locking, writing or exposing contents."""
        failures = (Error, OSError, UnicodeError, ValueError, KeyError, TypeError)
        records = None
        try:
            state = self.load(self.state_path)
            if state is None:
                records = {}
                state_status = 'missing'
            else:
                if not isinstance(state.get('components'), dict):
                    raise Error('Invalid component state')
                for component, record in state['components'].items():
                    self.validate_record(component, record)
                records = state['components']
                state_status = 'valid'
        except failures:
            state_status = 'unknown'

        pending = {'status': 'none', 'can_resume': False, 'actions': []}
        try:
            journal = self.load(self.journal_path)
            if journal is not None:
                if journal.get('operation') not in ('activate', 'remove'):
                    raise Error('Invalid pending operation')
                self.validate_journal(journal)
                pending.update(status='blocked', transaction=journal['id'])
                try:
                    _, actions = self.prepare_replay(journal)
                    # Unknown prior ownership must never be presented as safe recovery.
                    if records is None:
                        raise Error('Invalid prior component state')
                    pending.update(status='resumable', can_resume=True, actions=actions)
                except failures:
                    pending['reason'] = 'replay-check-failed'
        except failures:
            pending.update(status='unknown', can_resume=None, reason='journal-unreadable-or-invalid')

        actions = []
        for component in sorted(set(components or ALL_COMPONENTS), key=ORDER.index):
            record = records.get(component) if records is not None else None
            item = {'component': component, 'path': self.targets[component],
                    'ownership': 'unknown' if records is None else 'managed' if record else 'unmanaged',
                    'status': 'unknown', 'reason': 'state-unreadable-or-invalid'}
            if records is not None:
                try:
                    data = self.fs.read(item['path'])['data']
                    if record is None:
                        conflict = data is not None if component == 'hyprland' else has_marker(data, component)
                        item.update(status='conflicting' if conflict else 'unmanaged',
                                    reason='unrecorded-content' if conflict else 'no-ownership-record')
                    elif data is None:
                        item.update(status='missing', reason='target-missing')
                    elif component == 'hyprland':
                        clean = checksum(data) == record['sha256']
                        item.update(status='clean' if clean else 'drifted',
                                    reason='owned-file-matches' if clean else 'owned-file-changed')
                    else:
                        text = data.decode('utf-8')
                        counts = [text.count(marker) for marker in markers(component)]
                        if any(count > 1 for count in counts):
                            item.update(status='conflicting', reason='duplicate-markers')
                        elif data.count(record['block'].encode()) != 1:
                            item.update(status='drifted' if any(counts) else 'missing',
                                        reason='owned-block-changed' if any(counts) else 'owned-block-missing')
                        else:
                            item.update(status='clean', reason='owned-block-matches')
                            try:
                                self.check_order(data, records, item['path'])
                            except Error:
                                item.update(status='conflicting', reason='owned-block-order-changed')
                except failures:
                    item.update(status='unknown', reason='target-unreadable-or-unsafe')
            # Shells source the recorded root, which may differ from today's CLI option.
            root = record['source_root'] if record and component != 'hyprland' else self.templates
            try:
                source = self.source(component, root)
                item['template'] = ('changed' if record and component == 'hyprland'
                                    and checksum(source) != record['sha256'] else 'available')
            except FileNotFoundError:
                item['template'] = 'missing'
            except Error as error:
                item['template'] = ('missing' if str(error).startswith('Selected installed template is missing:')
                                    else 'unknown')
            except failures:
                item['template'] = 'unknown'
            actions.append(item)

        incomplete = (state_status == 'unknown' or pending['status'] in ('unknown', 'blocked')
                      or any(a['status'] == 'unknown' or a['template'] == 'unknown' for a in actions))
        attention = (pending['status'] == 'resumable' or any(
            a['status'] in ('drifted', 'missing', 'conflicting')
            or (a['ownership'] == 'managed' and a['template'] != 'available') for a in actions))
        guidance = ['Status is a read-only observation; other writers can change files. Apply repeats its checks.']
        if pending['status'] == 'resumable':
            guidance.append('Review recover, then run recover --apply with the same home/config/ZDOTDIR/state/template-root options.')
        elif pending['status'] != 'none':
            guidance.append('Keep the pending journal. Review recover with the original root options and reconcile errors before applying.')
        if state_status == 'unknown':
            guidance.append('Review state ownership, permissions and original root options; no ownership was inferred from unreadable or invalid state.')
        if attention:
            guidance.append('Review affected components and template packages. Preserve user edits; preview activate or remove with explicit components after resolving pending recovery.')
        return {'schema_version': 1, 'mode': 'read-only', 'operation': 'status',
                'state': {'status': state_status}, 'pending': pending, 'actions': actions,
                'guidance': guidance, 'exit_code': 1 if incomplete else 2 if attention else 0}

    def run(self, operation, components=(), apply=False):
        if operation not in ('activate', 'remove', 'recover', 'status') or not set(components) <= set(ALL_COMPONENTS):
            raise Error('Unrecognized operation/components')
        if operation == 'status':
            if apply:
                raise Error('Status is read-only; --apply is not supported')
            return self.status(components)
        if operation == 'activate' and not components:
            raise Error('Select at least one activation component')
        if operation == 'activate':
            # Missing selected modules fail before even creating a lock/state directory.
            for component in components:
                self.source(component)
        lock = self.fs.lock(self.lock_path) if apply else None
        try:
            journal = self.load(self.journal_path)
            recovered = False
            if journal:
                self.validate_journal(journal)
                if not apply:
                    _, actions = self.prepare_replay(journal)
                    return {'mode': 'preview', 'operation': operation, 'pending_transaction': journal['id'],
                            'actions': actions, 'guidance': ['Review these recovery actions, then run recover --apply with the same home/config/template-root options. No files were changed.']}
                self.replay(journal)
                recovered = True
            state = self.load(self.state_path, {'schema_version': 1, 'roots': self.roots, 'components': {}})
            if not isinstance(state.get('components'), dict):
                raise Error('Invalid component state')
            if operation == 'recover':
                return {'mode': 'applied' if apply else 'preview', 'operation': operation,
                        'recovered_transaction': recovered, 'actions': []}
            selected = sorted(set(components or state['components']), key=ORDER.index)
            entries, actions, new_state = self.plan(operation, selected, state)
            if apply and (entries or new_state != state):
                journal = {'schema_version': 1, 'roots': self.roots, 'id': uuid.uuid4().hex,
                           'template_root': str(self.templates), 'operation': operation,
                           'entries': entries, 'new_state': new_state}
                self.save(self.journal_path, journal)
                self.replay(journal)
                for action in actions:
                    action['status'] = action['status'].removeprefix('would-')
            guidance = ['Start fresh shells after activation/removal; already-running shells keep their existing state.']
            if 'hyprland' in selected and operation == 'activate':
                config = shlex.quote(str(self.home / self.targets['hyprland']))
                guidance += [f'Configuration parser check (run separately): Hyprland --verify-config --config {config}',
                             'Select this explicit config through your existing validated base launcher; preserve UWSM handling.',
                             f'Only on a base validated for the standalone wrapper: start-hyprland -- --config {config}',
                             'No compositor is launched or session registered. Switch to your prior config before removal.']
            if 'hyprland' in selected and operation == 'remove':
                guidance += ['Return to your previous base launcher/configuration before deactivation; this tool never stops a running compositor.']
            return {'mode': 'applied' if apply else 'preview', 'operation': operation,
                    'recovered_transaction': recovered, 'actions': actions, 'guidance': guidance,
                    'preserved_conflicts': any(a['status'].startswith('preserved-') for a in actions)}
        finally:
            if lock is not None:
                os.close(lock)


def relative_directory(home, value, default):
    path = Path(value) if value else home / default
    parts(path, absolute=True)
    try:
        return str(path.relative_to(home))
    except ValueError:
        raise Error('XDG/ZDOTDIR/state directories must be inside the selected home') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('activate', 'remove', 'recover', 'status'))
    parser.add_argument('--components', nargs='+', choices=ALL_COMPONENTS)
    parser.add_argument('--apply', action='store_true', help='perform the previewed operation; default is read-only')
    parser.add_argument('--home', type=Path, help='explicit user home; tests use temporary homes')
    parser.add_argument('--template-root', type=Path, default=Path('/usr/share/cachy-asahi'))
    parser.add_argument('--config-home', type=Path)
    parser.add_argument('--zdotdir', type=Path)
    parser.add_argument('--state-dir', type=Path)
    args = parser.parse_args()
    setup = None
    try:
        if os.geteuid() == 0:
            raise Error('Run user setup as the intended non-root user')
        home = args.home or Path.home()
        parts(home, absolute=True)
        # Explicit --home isolates fixtures from the caller's real XDG/ZDOTDIR values.
        config = args.config_home or (os.environ.get('XDG_CONFIG_HOME') if args.home is None else None)
        zsh = args.zdotdir or (os.environ.get('ZDOTDIR') if args.home is None else None)
        state = args.state_dir
        if state is None and args.home is None and os.environ.get('XDG_STATE_HOME'):
            state = Path(os.environ['XDG_STATE_HOME']) / 'cachy-asahi/setup'
        setup = Setup(home, args.template_root,
                      relative_directory(home, config, '.config'), relative_directory(home, zsh, '.'),
                      relative_directory(home, state, '.local/state/cachy-asahi/setup'))
        result = setup.run(args.operation, args.components or (), args.apply)
        print(json.dumps(result, indent=2, sort_keys=True))
        return result.get('exit_code', 2 if result.get('preserved_conflicts') or result.get('pending_transaction') else 0)
    except (Error, OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        message = str(error) if isinstance(error, Error) else 'Unsafe/unavailable path or invalid state; no configuration contents printed'
        print(json.dumps({'status': 'error', 'error': message}), file=sys.stderr)
        return 1
    finally:
        if setup:
            setup.close()


if __name__ == '__main__':
    sys.exit(main())
