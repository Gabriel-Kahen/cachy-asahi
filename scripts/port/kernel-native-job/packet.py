#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Bounded source closure for the original producer and frozen kernel controller."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PREFIX = 'scripts/port/kernel-native-job/'
KERNEL = 'scripts/port/kernel-native-stage/'
WORKFLOW = '.github/workflows/native-arm-kernel.yml'
DOCUMENT = 'docs/workstreams/kernel-native-job.md'
KERNEL_SHA = '485ca7f3fea921e83a6222973d5824a31ba8f0f21af5225542fbedc393bd1be3'
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
RECIPES_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
EPOCH = 1791748800
RECIPE_COUNT, KERNEL_COUNT = 71, 29
MAX_FILES, MAX_FILE, MAX_TOTAL = 256, 8 * 1024**2, 32 * 1024**2
RECIPE_BASES = {'packages/desktop/cachy-asahi-hyprland-settings',
                'packages/settings/cachy-asahi-setup',
                'packages/shells/cachy-asahi-fish-config',
                'packages/shells/cachy-asahi-zsh-config'}
# Audited build-mode closure: native_arm imports package_checks; build/compare
# import package_checks and build; build mounts container-entry. setup_sync reads
# canonical setup and its MIT license. Integration mode is deliberately absent.
HELPERS = {
    'scripts/ci/native_arm.py': ('a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898', 0o644),
    'scripts/checks/package_checks.py': ('e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8', 0o644),
    'scripts/build/build.py': ('e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45', 0o644),
    'scripts/build/compare.py': ('d75d9177cb741d7ae8e13466aa4b9e96587470b88749735ef2923f9a4446748d', 0o644),
    'scripts/build/container-entry.sh': ('89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24', 0o644),
    'scripts/setup/setup.py': ('a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2', 0o755),
    'LICENSE': ('51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 0o644),
    'AGENTS.md': ('a95eaf775ac935ebdfe6b9c89aad9382639671aecdaab91503e1453d4782a056', 0o644),
}

# Only these two Source-pinned donor buffers may be nested job inputs.
DONORS = {'donor/current-controller.py': 'bbe279edb9743f98e8feed8365859abc221b2665924658e600775c902e18299e', 'donor/current-packet.json': '9d5a7dc25fd44e127c457c72addb28272b1eb1f5391c4c5b8d5b0a226a3be048'}

def need(value, code):
    if not value:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def relative(name):
    need(type(name) is str and name and '\\' not in name and
         all(32 <= ord(c) < 127 for c in name), 'packet-path')
    need(not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')), 'packet-path')
    return Path(name)


def capture(path, limit=MAX_FILE):
    """Traverse directories without following links, hash/parse this one read."""
    path = Path(path).absolute()
    need('..' not in path.parts, 'packet-path')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             info.st_size <= limit and mode in (0o600, 0o644, 0o755), 'packet-file')
        data = bytearray()
        while block := os.read(fd, min(1024**2, limit + 1 - len(data))):
            data.extend(block)
            need(len(data) <= limit, 'packet-file-bound')
        after = os.fstat(fd)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
                              s.st_ctime_ns, s.st_mode, s.st_nlink)
        need(identity(info) == identity(after) == identity(current) and len(data) == info.st_size,
             'packet-race')
        return bytes(data), mode
    except OSError:
        raise ValueError('packet-file') from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def read(path, limit=MAX_FILE):
    return capture(path, limit)[0]


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
        need(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) and sha(data) == pin, 'packet-pin')
    return decode(data)


def walk(root, ignore_cache=False):
    """Finite regular-file inventory; no recursive symlink traversal."""
    files, visited = set(), 0
    for base, directories, names in os.walk(root, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)):
        need(len(Path(base).relative_to(root).parts) <= 16, 'packet-directory-bound')
        for name in directories + names:
            visited += 1
            need(visited <= 1024, 'packet-directory-bound')
            path = Path(base) / name
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'packet-own-file')
            if stat.S_ISREG(info.st_mode):
                files.add(path.relative_to(root).as_posix())
        if ignore_cache:
            directories[:] = [name for name in directories if name != '__pycache__']
    return files


def closure(root):
    root = Path(root)
    kernel = load(root / (KERNEL + 'stage.lock.json'), KERNEL_SHA)
    recipes = load(root / 'scripts/ci/recipes.lock.json', RECIPES_SHA)
    inputs = load(root / 'scripts/ci/inputs.lock.json', INPUTS_SHA)
    need(type(kernel.get('files')) is dict and len(kernel['files']) == KERNEL_COUNT and
         inputs.get('source_date_epoch') == EPOCH and len(inputs.get('packages', [])) == 248 and
         set(recipes) == RECIPE_BASES and sum(len(v) for v in recipes.values()) == RECIPE_COUNT,
         'producer-scope')
    files = set(kernel['files']) | set(HELPERS) | {KERNEL + 'stage.lock.json',
            'scripts/ci/inputs.lock.json', 'scripts/ci/recipes.lock.json', WORKFLOW, DOCUMENT}
    for base, rows in recipes.items():
        relative(base)
        need(type(rows) is dict and walk(root / base) == set(rows), 'producer-recipe-set')
        files.update(base + '/' + str(relative(name)) for name in rows)
    job_files = walk(root / PREFIX, ignore_cache=True)
    # The coordinator's external-pin map excludes itself. No other JSON/binary
    # can enter the executable closure through this directory.
    job_files.discard('packet.lock.json')
    need(set(DONORS) <= job_files and job_files and all(
        name in DONORS or name.endswith('.py') and '/' not in name for name in job_files), 'packet-own-file')
    for name, pin in DONORS.items():
        donor, mode = capture(root / PREFIX / relative(name), 2 * 1024**2)
        need(mode == 0o644 and sha(donor) == pin, 'packet-donor-pin')
    files.update(PREFIX + name for name in job_files)
    need(len(files) <= MAX_FILES, 'packet-file-count')
    for name in files:
        relative(name)
    return files, kernel, recipes


def row(data, mode):
    return {'sha256': sha(data), 'mode': mode, 'bytes': len(data)}


def frozen(rows, kernel, recipes):
    for name, expected in kernel['files'].items():
        need(rows[name]['sha256'] == expected['sha256'] and rows[name]['mode'] == expected['mode'],
             'frozen-kernel-drift')
    for name, (digest, mode) in HELPERS.items():
        need(rows[name]['sha256'] == digest and rows[name]['mode'] == mode, 'frozen-producer-drift')
    for base, expected in recipes.items():
        need({name: rows[base + '/' + name]['sha256'] for name in expected} == expected, 'original-recipe-drift')


def preview(root):
    """Return reviewable map only; never write or register a shared lock."""
    names, kernel, recipes = closure(root)
    rows = {name: row(*capture(Path(root) / name)) for name in sorted(names)}
    need(all(v['mode'] in (0o644, 0o755) for v in rows.values()), 'packet-source-mode')
    need(sum(v['bytes'] for v in rows.values()) <= MAX_TOTAL, 'packet-total-bound')
    frozen(rows, kernel, recipes)
    return {'schema_version': 1, 'files': rows}


def verify(root, manifest_path, manifest_sha, commit, runner, output, workflow_sha=None):
    root, output = Path(root).absolute(), Path(output).absolute()
    need(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit) and
         os.environ.get('GITHUB_SHA') == commit and
         (workflow_sha or os.environ.get('GITHUB_WORKFLOW_SHA')) == commit, 'packet-workflow-commit')
    need(root == root.resolve() and '..' not in output.parts and not output.exists() and
         not output.is_symlink() and all(stat.S_ISDIR(p.lstat().st_mode) for p in output.parents),
         'packet-commit-output')
    # Source snapshots inside the checkout are restricted to this new ignored
    # job's artifact root; never write over source or another controller's state.
    need(not output.is_relative_to(root) or output.is_relative_to(root / 'artifacts/kernel-native-job'),
         'packet-commit-output')
    manifest = load(manifest_path, manifest_sha)
    need(set(manifest) == {'schema_version', 'files'} and type(manifest['schema_version']) is int and
         manifest['schema_version'] == 1 and type(manifest['files']) is dict, 'packet-schema')
    names, kernel, recipes = closure(root)
    need(set(manifest['files']) == names, 'packet-complete-set')
    total = 0
    for name, value in manifest['files'].items():
        need(type(value) is dict and set(value) == {'sha256', 'mode', 'bytes'} and
             type(value['mode']) is int and value['mode'] in (0o644, 0o755) and
             type(value['bytes']) is int and 0 <= value['bytes'] <= MAX_FILE and
             type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'packet-row')
        total += value['bytes']
    need(total <= MAX_TOTAL, 'packet-total-bound')
    frozen(manifest['files'], kernel, recipes)
    command = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
               '--no-optional-locks', '-C', str(root)]
    head = runner.run(command + ['rev-parse', '--verify', 'HEAD'], timeout=10, limit=4096)
    need(head.returncode == 0 and head.stdout == (commit + '\n').encode(), 'packet-HEAD')
    output.mkdir(mode=0o700)
    for name, value in sorted(manifest['files'].items()):
        data, mode = capture(root / relative(name))
        need(row(data, mode) == value, 'packet-byte-mode-pin')
        blob = runner.run(command + ['show', commit + ':' + name], timeout=10, limit=MAX_FILE)
        git_mode = runner.run(command + ['ls-tree', '--format=%(objectmode)', commit, '--', name],
                              timeout=10, limit=4096)
        need(blob.returncode == git_mode.returncode == 0 and blob.stdout == data and
             git_mode.stdout == ('100' + oct(mode)[2:] + '\n').encode(), 'packet-Git-binding')
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
        destination.chmod(mode)
    for name, value in manifest['files'].items():
        need(row(*capture(root / name)) == row(*capture(output / name)) == value, 'packet-copy-race')
    need(closure(root)[0] == names, 'packet-closure-race')
    return {'status': 'PASS', 'source_commit': commit, 'packet_sha256': manifest_sha,
            'files': len(names), 'bytes': total, 'kernel_lock_sha256': KERNEL_SHA,
            'inputs_sha256': INPUTS_SHA, 'recipes_sha256': RECIPES_SHA,
            'source_date_epoch': EPOCH, 'files_map': manifest['files']}
