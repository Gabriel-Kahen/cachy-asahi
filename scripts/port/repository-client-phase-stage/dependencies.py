#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticate external predecessor/collector source before executing strings."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

ROOT = Path(__file__).resolve().parents[3]
COLLECTOR_MAP_SHA256 = '26eeddc56574c5475df67841c1ac8120900deabe1478f6d1fa7cd290f64f63a9'
COLLECTOR = {
    'entry.py': '5889e0358bd0a04122e6cfcb061337f1dc415b064ba92f46ae47893a5747e0c8',
    'worker.py': '9a513a59da3cbb58d54c236759e3299072e14194e4d297df911072daa241b060',
    'common.py': '92ca41005397c6cccfd70497646c0de1f2ac88a697e0fcbec4165bf5326cfc08',
    'base.py': '94a8e2898b062a0efd0f567d1f4f472bd04d6ff5a1573cd09f3bf8d1f556cddd',
    'provenance.py': '42d18ff6cfa68d7d0a704d0612cbf505f8652b5c24bf6ae69d833b43c08ad02b',
    'crypto.py': 'a3568741238738646593b2c972589f4ae92381611c88dea1c1c234c0e59a46f0',
    'orchestrator.py': '9323498b61d3cedbb0f99bd45564a3f26572ed7e560d75f260eef932c7f957ff',
}
PREDECESSORS = {
    'scripts/port/repository-client-stage/gate.py': 'fa39cfd6b5c1a3718f888d3f9fdb51f5bb8e38a7e57a98d1c4c8c570ea70af1e',
    'scripts/port/repository-client-stage/adapter.py': '69ad53b4bc041d37536ad15a4ced7efa4cb2d61bcd6cb4a62fdfce8a7dbd52ab',
    'scripts/release/release.py': '418c850e8a44ae71517e074f86f46f5999f5fe7433ca6798de945f318191a918',
    'scripts/client/client.py': '3025aa0e167c836e31c949e0915d4ee82a1007dc0fada598b4895240c82f5f97',
}
PREDECESSOR_MODES = {name: (0o755 if name == 'scripts/release/release.py' else 0o644)
                     for name in PREDECESSORS}
CACHE = {}


def source(path, expected, *, mode=0o644):
    """Bounded no-follow file/ancestor reads; no Python loader or PYC path."""
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('source parent traversal')
    fds, snapshots, fd = [], [], None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        current = Path('/')
        snapshots.append((current, os.fstat(fds[-1])))
        for part in path.parts[1:-1]:
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            current /= part; snapshots.append((current, os.fstat(fds[-1])))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024**2 or stat.S_IMODE(before.st_mode) != mode:
            raise ValueError('bounded source byte/mode contract')
        chunks, size = [], 0
        while chunk := os.read(fd, 65536):
            chunks.append(chunk); size += len(chunk)
            if size > 1024**2: raise ValueError('source bound')
        raw = b''.join(chunks)
        after, live = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != before.st_size or any(getattr(before, field) != getattr(after, field) or
                                            getattr(before, field) != getattr(live, field) for field in fields):
            raise ValueError('source identity drift')
        for ancestor, prior in snapshots:
            now = ancestor.lstat()
            if (now.st_dev, now.st_ino, now.st_mode) != (prior.st_dev, prior.st_ino, prior.st_mode):
                raise ValueError('source ancestor drift')
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('external source pin differs')
        return raw
    finally:
        if fd is not None: os.close(fd)
        for item in reversed(fds): os.close(item)


def load_collector(repo_root=ROOT):
    root = Path(repo_root).absolute()
    directory = root / 'scripts/port/repository-client-native'
    captures = {name: source(directory / name, pin) for name, pin in COLLECTOR.items()}
    observed = {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': 0o644} for name, raw in captures.items()}
    encoded = (json.dumps(observed, sort_keys=True, indent=2) + '\n').encode()
    if hashlib.sha256(encoded).hexdigest() != COLLECTOR_MAP_SHA256:
        raise ValueError('collector proposed source map differs')
    # Recheck each external byte pin even when returning an existing module set.
    if str(root) in CACHE:
        return CACHE[str(root)]
    modules, previous = {}, {}
    try:
        for name in ('common', 'base', 'provenance', 'crypto', 'orchestrator'):
            module = types.ModuleType(name)
            module.__file__ = str(directory / (name + '.py'))
            previous[name] = sys.modules.get(name)
            sys.modules[name] = module
            exec(compile(captures[name + '.py'], module.__file__, 'exec'), module.__dict__)
            modules[name] = module
    finally:
        for name, old in previous.items():
            if old is None: sys.modules.pop(name, None)
            else: sys.modules[name] = old
    CACHE[str(root)] = modules
    return modules


def predecessor(repo_root, name):
    return source(Path(repo_root) / name, PREDECESSORS[name], mode=PREDECESSOR_MODES[name])


def authenticate_all(repo_root=ROOT):
    load_collector(repo_root)
    return {name: predecessor(repo_root, name) for name in PREDECESSORS}
