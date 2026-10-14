"""Held registered Source files; file bytes remain exact, directories use identity5."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType


def identity(node):
    return (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid,
            node.st_nlink, node.st_size, node.st_mtime_ns, node.st_ctime_ns)


def decode(raw):
    def unique(items):
        out = {}
        for key, value in items:
            if key in out: raise ValueError('registered-duplicate-json')
            out[key] = value
        return out
    def bad(value): raise ValueError('registered-nonfinite-json')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=bad)


class Sources:
    def __init__(self, root, rows, guard):
        self.root, self.rows, self.guard = Path(root), rows, guard
        self.nodes, self.slots, self.modules = {}, [], {}
        self.requested = 0
        self.uid = guard.call(os.getuid)
        if not self.root.is_absolute() or '..' in self.root.parts or type(rows) is not dict or len(rows) > 128:
            raise ValueError('registered-source-root')

    def file(self, name):
        self.guard.check()
        if name in self.nodes: self.verify_node(name); return self.nodes[name]['raw']
        if name not in self.rows or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('registered-unselected-source')
        expected = self.rows[name]; path = self.root / name
        ancestors = self.ancestors(path)
        before = self.guard.call(os.lstat, path)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_uid != self.uid or stat.S_IMODE(before.st_mode) != expected['mode'] or
            before.st_size != expected['bytes'] or not 0 <= before.st_size <= 8 * 1024**2):
            raise ValueError('registered-source-shape')
        slot = {'fd': None, 'name': name, 'attempted': False}; self.slots.append(slot)
        self.guard.check()
        slot['attempted'] = True
        slot['fd'] = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.guard.check()
        if identity(self.guard.call(os.fstat, slot['fd'])) != identity(before):
            raise ValueError('registered-open-drift')
        data = bytearray()
        while len(data) < before.st_size:
            size = min(65536, before.st_size - len(data)); self.requested += size
            if self.requested > 64 * 1024**2: raise ValueError('registered-source-read-cap')
            block = self.guard.call(os.pread, slot['fd'], size, len(data))
            if not block: raise ValueError('registered-source-short-read')
            data.extend(block)
        if self.guard.call(os.pread, slot['fd'], 1, len(data)): raise ValueError('registered-source-grew')
        raw = bytes(data)
        if hashlib.sha256(raw).hexdigest() != expected['sha256']: raise ValueError('registered-source-pin')
        self.nodes[name] = {'path': path, 'fd': slot['fd'], 'identity': identity(before),
                            'ancestors': ancestors, 'raw': raw}
        self.verify_node(name); return raw

    def ancestors(self, path, *, cleanup=False):
        values = []
        for parent in path.parents:
            node = self.guard.call(os.lstat, parent, cleanup=cleanup)
            if not stat.S_ISDIR(node.st_mode) or node.st_uid not in (0, self.uid) or node.st_mode & 0o022:
                raise ValueError('registered-source-ancestor')
            values.append((str(parent), identity(node)[:5]))
        return tuple(values)

    def verify_node(self, name, *, cleanup=False):
        node = self.nodes[name]
        if (identity(self.guard.call(os.fstat, node['fd'], cleanup=cleanup)) != node['identity'] or
            identity(self.guard.call(os.lstat, node['path'], cleanup=cleanup)) != node['identity'] or
            self.ancestors(node['path'], cleanup=cleanup) != node['ancestors']):
            raise ValueError('registered-source-identity-drift')

    def verify(self, *, cleanup=False):
        self.guard.check(cleanup=cleanup)
        for name in self.nodes: self.verify_node(name, cleanup=cleanup)
        return True

    def module(self, name, stem):
        raw = self.file(name); self.verify()
        if stem in sys.modules: raise ValueError('registered-source-module-collision')
        module = self.guard.call(ModuleType, stem)
        module.__file__ = str(self.root / name)
        sys.modules[stem] = module; self.modules[stem] = module
        code = self.guard.call(compile, raw, module.__file__, 'exec', dont_inherit=True)
        self.guard.call(exec, code, module.__dict__)
        self.verify(); return module

    def close(self):
        errors = []; first = None
        for slot in reversed(self.slots):
            if slot['fd'] is None:
                if slot.get('attempted') and not slot.get('closed'):
                    error = ValueError('SourceFDOutcomeUnknown')
                    primary = self.guard.record_failure(error, cleanup=True)
                    if first is None: first = primary
                    errors.append('SourceFDOutcomeUnknown')
                continue
            try:
                self.guard.check(cleanup=True); fd = slot['fd']; slot['fd'] = None
                slot['retiring_fd'] = fd
                os.close(fd); slot['closed'] = True; self.guard.check(cleanup=True)
            except BaseException as error:
                primary = self.guard.record_failure(error, cleanup=True)
                if first is None: first = primary
                errors.append(type(error).__name__)
        if first is not None: raise first
        return errors
