#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Finite separate producer packet; no edits to initial/development packets."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/port/fdk-native-job/'
ADAPTER = 'scripts/port/fdk-native-stage/'
ADAPTER_SHA = 'fbc0b0bbf0f3765729adb9193331b09903ad5b8c99d00871ece79218a8b36483'
INPUTS_SHA = '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
RECIPES_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
EPOCH = 1791748800
NAMES = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
         'cachy-asahi-zsh-config', 'cachy-asahi-setup'}


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def relative(name):
    need(type(name) is str and name and '\\' not in name and
         all(32 <= ord(c) < 127 for c in name), 'packet-path')
    path = Path(name)
    need(not path.is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')), 'packet-path')
    return path


def read(path, limit=8 * 1024**2):
    path = Path(path).absolute()
    need('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'packet-parent')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'packet-file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino), 'packet-race')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        need(len(data) <= limit and (info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
             (path.lstat().st_dev, path.lstat().st_ino) == (info.st_dev, info.st_ino), 'packet-race')
        return data
    finally:
        os.close(fd)


def decode(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'packet-json-duplicate')
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique,
                        parse_constant=lambda _: need(False, 'packet-json-number'))
    need(type(result) is dict, 'packet-json-object')
    return result


def load(path, pin=None):
    data = read(path)
    if pin is not None:
        need(re.fullmatch('[0-9a-f]{64}', pin or '') and sha(data) == pin, 'packet-pin')
    return decode(data)


def save(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def closure(root):
    root = Path(root)
    adapter = load(root / (ADAPTER + 'stage.lock.json'), ADAPTER_SHA)
    recipes = load(root / 'scripts/ci/recipes.lock.json', RECIPES_SHA)
    inputs = load(root / 'scripts/ci/inputs.lock.json', INPUTS_SHA)
    need(inputs.get('source_date_epoch') == EPOCH and len(inputs.get('packages', [])) == 248 and
         {Path(name).name for name in recipes} == NAMES and len(recipes) == 4, 'producer-scope')
    files = set(adapter['files']) | {ADAPTER + 'stage.lock.json', 'scripts/ci/inputs.lock.json',
            'scripts/ci/recipes.lock.json', 'scripts/setup/setup.py', 'LICENSE', 'AGENTS.md'}
    for base, rows in recipes.items():
        relative(base)
        need(base.startswith(('packages/desktop/', 'packages/shells/', 'packages/settings/')) and
             type(rows) is dict, 'producer-recipe-path')
        for name in rows:
            relative(name)
            files.add(base + '/' + name)
    job = root / PREFIX
    visited = 0
    for path in job.rglob('*'):
        visited += 1
        need(visited <= 1024 and len(path.relative_to(job).parts) <= 16, 'packet-directory-bound')
        if '__pycache__' in path.parts:
            continue
        if path.is_dir() and not path.is_symlink():
            continue
        if path.name == 'packet.lock.json' and path.parent == job:
            continue
        need(stat.S_ISREG(path.lstat().st_mode), 'packet-own-file')
        files.add(str(path.relative_to(root)))
    need(len(files) <= 256, 'packet-file-count')
    return files, adapter, recipes


def verify(root, manifest_path, manifest_sha, commit, runner, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    need(re.fullmatch('[0-9a-f]{40}', commit or '') and not output.exists() and
         '..' not in root.parts and '..' not in output.parts and root == root.resolve() and
         not output.is_symlink() and not output.is_relative_to(root) and
         all(stat.S_ISDIR(p.lstat().st_mode) for p in (root, *root.parents, *output.parents)),
         'packet-commit-output')
    manifest = load(manifest_path, manifest_sha)
    need(set(manifest) == {'schema_version', 'files'} and manifest['schema_version'] == 1 and
         type(manifest['files']) is dict, 'packet-schema')
    expected, adapter, recipes = closure(root)
    need(set(manifest['files']) == expected, 'packet-complete-set')
    output.mkdir(mode=0o700)
    total = 0
    for name, row in manifest['files'].items():
        path = relative(name)
        need(type(row) is dict and set(row) == {'sha256', 'mode', 'bytes'} and
             type(row['mode']) is int and row['mode'] in (0o644, 0o755) and
             type(row['bytes']) is int and 0 <= row['bytes'] <= 8 * 1024**2 and
             re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'packet-row')
        data = read(root / path)
        total += len(data)
        need(total <= 32 * 1024**2 and len(data) == row['bytes'] and sha(data) == row['sha256'] and
             stat.S_IMODE((root / path).lstat().st_mode) == row['mode'], 'packet-byte-mode-pin')
        command = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                   '--no-optional-locks', '-C', str(root)]
        blob = runner.run(command + ['show', commit + ':' + name], timeout=10)
        mode = runner.run(command + ['ls-tree', '--format=%(objectmode)', commit, '--', name], timeout=10, limit=4096)
        need(blob.returncode == mode.returncode == 0 and blob.stdout == data and
             mode.stdout == ('100' + oct(row['mode'])[2:] + '\n').encode(), 'packet-Git-binding')
        destination = output / path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_bytes(data)
        destination.chmod(row['mode'])
    for name, row in manifest['files'].items():
        need(sha(read(root / name)) == sha(read(output / name)) == row['sha256'] and
             stat.S_IMODE((root / name).lstat().st_mode) == row['mode'] and
             stat.S_IMODE((output / name).lstat().st_mode) == row['mode'], 'packet-copy-race')
    for name, row in adapter['files'].items():
        need(manifest['files'][name]['sha256'] == row['sha256'] and
             manifest['files'][name]['mode'] == row['mode'], 'frozen-adapter-drift')
    for base, rows in recipes.items():
        need({n: manifest['files'][base + '/' + n]['sha256'] for n in rows} == rows, 'original-recipe-drift')
    return {'status': 'PASS', 'source_commit': commit, 'packet_sha256': manifest_sha,
            'files': len(expected), 'bytes': total, 'adapter_lock_sha256': ADAPTER_SHA,
            'inputs_sha256': INPUTS_SHA, 'recipes_sha256': RECIPES_SHA, 'source_date_epoch': EPOCH}
