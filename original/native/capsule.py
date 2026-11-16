# SPDX-License-Identifier: MIT
"""Bounded canonical USTAR public DATA capsule. Never extract or follow links."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

CAP = 32 * 1024**2
PAYLOAD_CAP = 16 * 1024**2
INDEX_CAP = 1024**2
LEAF_CAP = 3001
DIR_CAP = 3000
DEPTH_CAP = 128
EMPTY = hashlib.sha256(b'').hexdigest()
PRIVATE_PARTS = {'.git', '.gnupg', '.ssh', 'alarm-cache', 'pgo-hosted-retained', 'private-cache'}
PRIVATE_NAMES = {'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'secring.gpg', 'private.key', 'private.pem'}
PRIVATE_SUFFIXES = {'.key', '.pem', '.p8', '.p12', '.pfx'}


class CapsuleRefusal(ValueError):
    """A fixed guard code and bounded relative context, never captured material."""
    def __init__(self, reason, phase=None, path=None, member=None):
        super().__init__(reason)
        self.code = re.sub('[^A-Z0-9]+', '_', reason.upper()).strip('_')[:128]
        self.phase = phase; self.path = None; self.path_sha256 = None
        if type(path) is str:
            raw = path.encode('utf-8', errors='surrogatepass')
            candidate = PurePosixPath(path)
            if (path and len(raw) <= 4096 and not candidate.is_absolute() and '..' not in candidate.parts
                and candidate.as_posix() == path and '\\' not in path
                and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in path)):
                self.path = path
            else:
                self.path_sha256 = hashlib.sha256(raw).hexdigest()
        self.member = member if type(member) is str and re.fullmatch(r'index\.json|data/[0-9]{6}', member) else None
        self.emitted = False

    def diagnostic(self):
        value = dict(schema=1, status='REFUSED_PUBLIC_DATA', phase=self.phase or 'guard',
                     code=self.code, path=self.path, path_sha256=self.path_sha256, member=self.member)
        if hasattr(self, 'privacy_context'):
            value['privacy_context'] = self.privacy_context
        return value


@contextmanager
def refusal_context(phase, path=None, member=None):
    try:
        yield
    except CapsuleRefusal as error:
        if error.phase is None:
            contextual = CapsuleRefusal(str(error), phase, path, member)
            contextual.emitted = error.emitted
            raise contextual from None
        raise
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise CapsuleRefusal('bounded DATA access or structure refused', phase, path, member) from None


def emit_refusal(error):
    if not error.emitted:
        print(json.dumps(error.diagnostic(), sort_keys=True), flush=True)
        error.emitted = True


def need(value, reason):
    if not value:
        raise CapsuleRefusal(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('utf-8')


def _pairs(rows):
    result = {}
    for name, value in rows:
        need(name not in result, 'duplicate JSON key')
        result[name] = value
    return result


def _load(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid bounded JSON DATA') from error


def _name(name):
    need(type(name) is str and name and len(name.encode('utf-8')) <= 4096
         and '\\' not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name), 'invalid DATA path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name and len(path.parts) <= DEPTH_CAP
         and all(len(p.encode('utf-8')) <= 255 for p in path.parts), 'noncanonical DATA path')
    for part in path.parts:
        lowered = part.casefold()
        need(lowered not in PRIVATE_PARTS and lowered not in PRIVATE_NAMES
             and PurePosixPath(lowered).suffix not in PRIVATE_SUFFIXES, 'private material path refused')
    return path


def _mode(mode):
    need(type(mode) is int and 0 <= mode <= 0o777, 'ordinary permission mode required')
    return mode


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _absolute(path):
    path = Path(path).absolute()
    need('..' not in path.parts, 'host path aliases refused')
    return path


@contextmanager
def _directory(path, mutable=False):
    """Open every component with no-follow, retaining ancestor descriptors."""
    path = _absolute(path); fds = []; states = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        fds.append(fd); states.append(_identity(os.fstat(fd)))
        for part in path.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            fds.append(fd); states.append(_identity(os.fstat(fd)))
        yield fd
        for number, (descriptor, before) in enumerate(zip(fds, states)):
            after = _identity(os.fstat(descriptor))
            stable = after[:5] == before[:5] if mutable or number != len(fds)-1 else after == before
            need(stable, 'directory changed during DATA access')
    finally:
        for descriptor in reversed(fds):
            os.close(descriptor)


def _read_at(directory, name, info, cap):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= cap,
         'bounded unaliased ordinary DATA required')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        need(_identity(os.fstat(fd)) == _identity(info), 'DATA changed before open')
        chunks = []; size = 0
        while True:
            raw = os.read(fd, min(1024**2, cap + 1 - size))
            if not raw:
                break
            size += len(raw); need(size <= cap, 'DATA byte cap'); chunks.append(raw)
        need(_identity(os.fstat(fd)) == _identity(info)
             and _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == _identity(info),
             'DATA changed during read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def _ordinary(path, cap):
    path = _absolute(path)
    with _directory(path.parent) as directory:
        return _read_at(directory, path.name, os.stat(path.name, dir_fd=directory, follow_symlinks=False), cap)


def _capture(directory, prefix='', collect=True, states=None, entries=None, payloads=None):
    states = {} if states is None else states
    entries = {} if entries is None else entries
    payloads = {} if payloads is None else payloads
    before = _identity(os.fstat(directory)); states[prefix] = before
    names = sorted(os.listdir(directory))
    for name in names:
        relative = prefix + '/' + name if prefix else name
        with refusal_context('capture', relative):
            _name(relative)
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            states[relative] = _identity(info); mode = _mode(stat.S_IMODE(info.st_mode))
            if stat.S_ISDIR(info.st_mode):
                if collect:
                    entries[relative] = dict(kind='directory', mode=mode, bytes=0, sha256=EMPTY)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    need(_identity(os.fstat(fd)) == _identity(info), 'directory changed before open')
                    _capture(fd, relative, collect, states, entries, payloads)
                finally:
                    os.close(fd)
            elif stat.S_ISREG(info.st_mode):
                need(info.st_nlink == 1, 'hardlinked public DATA refused')
                if collect:
                    raw = _read_at(directory, name, info, PAYLOAD_CAP)
                    entries[relative] = dict(kind='file', mode=mode, **pin(raw)); payloads[relative] = raw
            elif stat.S_ISLNK(info.st_mode):
                need(info.st_nlink == 1, 'hardlinked link-target DATA refused')
                if collect:
                    target = os.readlink(name, dir_fd=directory); raw = target.encode('utf-8')
                    need(0 < len(raw) <= PAYLOAD_CAP and b'\0' not in raw, 'bounded UTF-8 link-target DATA required')
                    need(_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == _identity(info),
                         'link-target DATA changed during readlink')
                    entries[relative] = dict(kind='symlink', mode=mode, target=target, **pin(raw)); payloads[relative] = raw
            else:
                raise ValueError('special public node refused')
            if collect:
                need(sum(r['kind'] != 'directory' for r in entries.values()) <= LEAF_CAP
                     and sum(r['kind'] == 'directory' for r in entries.values()) + 1 <= DIR_CAP, 'public tree count cap')
                need(sum(len(v) for v in payloads.values()) <= CAP, 'public payload aggregate cap')
    need(sorted(os.listdir(directory)) == names and _identity(os.fstat(directory)) == before,
         'public directory changed during capture')
    return states, entries, payloads


def _validate(entries):
    need(type(entries) is dict, 'index entries object required')
    leaves = set(); directories = set()
    for name, row in entries.items():
        with refusal_context('validate', name):
            path = _name(name); need(type(row) is dict, 'index row object required')
            kind = row.get('kind'); need(kind in ('file', 'symlink', 'directory'), 'index DATA kind')
            keys = {'kind', 'mode', 'bytes', 'sha256'} | ({'target'} if kind == 'symlink' else set())
            need(set(row) == keys, 'index row fields')
            _mode(row['mode']); need(type(row['bytes']) is int and 0 <= row['bytes'] <= PAYLOAD_CAP, 'index DATA size')
            need(type(row['sha256']) is str and len(row['sha256']) == 64
                 and all(c in '0123456789abcdef' for c in row['sha256']), 'index DATA hash')
            if kind == 'directory':
                need(row['bytes'] == 0 and row['sha256'] == EMPTY, 'directory carries no payload')
                directories.add(name)
            else:
                leaves.add(name)
            if kind == 'symlink':
                need(type(row['target']) is str and row['target'] and '\0' not in row['target']
                     and pin(row['target'].encode('utf-8')) == {k: row[k] for k in ('bytes', 'sha256')}, 'link-target DATA hash')
            for parent in path.parents:
                if parent != PurePosixPath('.'):
                    need(parent.as_posix() in entries and entries[parent.as_posix()]['kind'] == 'directory',
                         'missing explicit directory or leaf parent collision')
    need(len(leaves) <= LEAF_CAP and len(directories) + 1 <= DIR_CAP, 'capsule count cap')
    return leaves, directories


def _header(name, size):
    info = tarfile.TarInfo(name)
    info.mode = 0o644; info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ''; info.size = size; info.type = tarfile.REGTYPE
    return info.tobuf(format=tarfile.USTAR_FORMAT, encoding='ascii', errors='strict')


def _member(name, raw):
    return _header(name, len(raw)) + raw + bytes((-len(raw)) % 512)


def _encode(entries, payloads, root_mode):
    leaves, _ = _validate(entries); records = {}; number = 0
    for name in sorted(entries):
        row = dict(entries[name])
        if name in leaves:
            with refusal_context('encode', name, 'data/%06d' % number):
                need(pin(payloads[name]) == {k: row[k] for k in ('bytes', 'sha256')}, 'captured payload binding')
            row['payload'] = 'data/%06d' % number; number += 1
        records[name] = row
    with refusal_context('encode', member='index.json'):
        index = _json(dict(schema=1, root_mode=_mode(root_mode), entries=records))
        need(len(index) <= INDEX_CAP, 'capsule index byte cap')
    chunks = [_member('index.json', index)]
    for name in sorted(leaves):
        chunks.append(_member(records[name]['payload'], payloads[name]))
    size = sum(map(len, chunks)) + 1024
    total = ((size + 10239) // 10240) * 10240
    need(total <= CAP, 'inclusive capsule byte cap')
    chunks.append(bytes(total - (size - 1024)))
    return b''.join(chunks)


class View:
    def __init__(self, entries, payloads, root_mode):
        self.entries = entries; self.root_mode = _mode(root_mode)
        self.leaves, self.directories = _validate(entries)
        self._payloads = payloads

    def read(self, name):
        _name(name); need(name in self.leaves, 'retained DATA leaf required')
        return self._payloads[name]

    def load(self, name):
        _name(name); need(name in self.entries and self.entries[name]['kind'] == 'file', 'JSON requires ordinary file DATA')
        return _load(self.read(name))

    def verify_manifest(self, manifest):
        need(type(manifest) is dict and type(manifest.get('files')) is dict, 'artifact manifest files object required')
        need('artifacts.json' in self.entries and self.entries['artifacts.json']['kind'] == 'file', 'regular artifact manifest required')
        need(manifest == self.load('artifacts.json'), 'caller manifest differs from retained manifest DATA')
        files = manifest['files']; need(len(files) <= 3000 and 'artifacts.json' not in files, 'artifact manifest count/self-entry')
        need(self.leaves == set(files) | {'artifacts.json'}, 'closed artifact manifest namespace differs')
        for name, row in files.items():
            with refusal_context('manifest', name):
                _name(name); need(type(row) is dict, 'artifact row object required')
                kind = row.get('kind'); need(kind in ('file', 'symlink'), 'artifact DATA kind')
                _mode(row.get('mode')); need(type(row.get('bytes')) is int, 'artifact DATA size integer required')
                keys = {'kind', 'mode', 'bytes', 'sha256'} | ({'target'} if kind == 'symlink' else set())
                need(set(row) == keys and row == self.entries[name], 'artifact DATA kind/mode/bytes/hash/target differs')
        return True


def _pack(public_root, capsule_path):
    root, output = _absolute(public_root), _absolute(capsule_path)
    need(not output.is_relative_to(root), 'capsule output must be outside public root')
    with _directory(root) as directory:
        root_mode = _mode(stat.S_IMODE(os.fstat(directory).st_mode))
        states, entries, payloads = _capture(directory)
        after, _, _ = _capture(directory, collect=False)
        need(states == after, 'public tree changed before capsule publication')
    with refusal_context('manifest', 'artifacts.json'):
        view = View(entries, payloads, root_mode); view.verify_manifest(view.load('artifacts.json'))
    with refusal_context('encode'):
        raw = _encode(entries, payloads, root_mode)
    with refusal_context('publish'):
        with _directory(output.parent, mutable=True) as directory:
            fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                offset = 0
                while offset < len(raw):
                    count = os.write(fd, raw[offset:]); need(count > 0, 'capsule write made no progress'); offset += count
                os.fsync(fd)
            finally:
                os.close(fd)
        need(_ordinary(output, CAP) == raw, 'published capsule changed')
    return dict(**pin(raw), leaves=len(view.leaves), directories=len(view.directories)+1)


def pack(public_root, capsule_path):
    try:
        with refusal_context('pack'):
            return _pack(public_root, capsule_path)
    except CapsuleRefusal as error:
        emit_refusal(error)
        raise


def _take(raw, offset, name, cap):
    need(offset + 512 <= len(raw), 'truncated USTAR header')
    header = raw[offset:offset+512]
    try:
        info = tarfile.TarInfo.frombuf(header, encoding='ascii', errors='strict')
    except (tarfile.TarError, UnicodeError, ValueError) as error:
        raise ValueError('invalid USTAR header') from error
    need(info.name == name and 0 <= info.size <= cap and header == _header(name, info.size), 'noncanonical USTAR header/type/name')
    start = offset + 512; end = start + info.size; following = end + (-info.size) % 512
    need(following <= len(raw), 'truncated USTAR payload')
    need(not any(raw[end:following]), 'nonzero USTAR member padding')
    return raw[start:end], following


def open_capsule(path):
    raw = _ordinary(path, CAP)
    need(len(raw) >= 10240 and len(raw) % 10240 == 0, 'truncated/noncanonical USTAR record length')
    index, offset = _take(raw, 0, 'index.json', INDEX_CAP)
    document = _load(index)
    need(type(document) is dict and set(document) == {'schema', 'root_mode', 'entries'}
         and type(document['schema']) is int and document['schema'] == 1 and _json(document) == index, 'noncanonical capsule index')
    root_mode = _mode(document['root_mode'])
    records = document['entries']; need(type(records) is dict and len(records) <= LEAF_CAP + DIR_CAP - 1, 'bounded capsule entry map')
    entries = {}; references = {}
    for name, record in records.items():
        need(type(record) is dict, 'capsule index row')
        row = dict(record)
        if row.get('kind') != 'directory':
            need('payload' in row, 'capsule payload reference required')
            references[name] = row.pop('payload')
        entries[name] = row
    leaves, _ = _validate(entries); payloads = {}
    for number, name in enumerate(sorted(leaves)):
        expected = 'data/%06d' % number
        need(references[name] == expected, 'canonical unique payload reference required')
        payload, offset = _take(raw, offset, expected, PAYLOAD_CAP)
        row = entries[name]; need(pin(payload) == {k: row[k] for k in ('bytes', 'sha256')}, 'retained payload bytes/hash differs')
        if row['kind'] == 'symlink':
            need(payload == row['target'].encode('utf-8'), 'retained link-target DATA differs')
        payloads[name] = payload
    total = ((offset + 1024 + 10239) // 10240) * 10240
    need(len(raw) == total and not any(raw[offset:]) and len(raw)-offset >= 1024, 'extra/truncated/noncanonical USTAR tail')
    return View(entries, payloads, root_mode)
