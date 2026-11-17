#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Reconstruct exact unissued Source339 and run original artifact-free controls."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEPENDENCIES = json.loads((HERE / 'dependencies.json').read_bytes())


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def git(*args):
    # Large full-history packs need finite mapping windows inside the same
    # address-space envelope as the source controls. No repository config edit.
    return subprocess.check_output(['git', '-c', 'core.packedGitWindowSize=16m',
                                    '-c', 'core.packedGitLimit=64m', '-C', str(ROOT), *args])


def module(name, path):
    spec = importlib.util.spec_from_file_location('source339_ci_' + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def snapshot(root):
    files = {}
    directories = set()
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'ordinary immutable source namespace')
        if path.is_dir():
            directories.add(path.relative_to(root).as_posix())
        else:
            info = path.stat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'ordinary single-link source leaf')
            files[path.relative_to(root).as_posix()] = dict(**pin(path.read_bytes()), mode=stat.S_IMODE(info.st_mode))
    expected = {p.as_posix() for name in files for p in Path(name).parents if str(p) != '.'}
    need(directories == expected, 'no additional empty source directories')
    return files


def original_families(work):
    roots = {}
    for name, family in DEPENDENCIES['families'].items():
        revision, prefix = family['revision'], family['path']
        git('merge-base', '--is-ancestor', revision, 'HEAD')
        # Check original published/merged Git bytes and modes, not a local artifact.
        rows = {}
        bodies = {}
        for line in git('ls-tree', '-r', revision, '--', prefix).decode().splitlines():
            metadata, full = line.split('\t')
            mode, kind, _ = metadata.split()
            need(mode in ('100644', '100755') and kind == 'blob', 'ordinary original Git leaves')
            relative = full.removeprefix(prefix + '/')
            need(relative != full, 'exact Git family prefix')
            raw = git('show', revision + ':' + full)
            rows[relative] = dict(**pin(raw), mode=int(mode, 8) & 0o777)
            bodies[relative] = raw
        need(rows == family['files'], 'exact original Git family bodies/modes: ' + name)
        if name == 'qualification':
            root = work / 'frozen-qualification'
            root.mkdir(mode=0o700)
            for relative, raw in bodies.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(rows[relative]['mode'])
        else:
            root = ROOT / prefix
        need(snapshot(root) == rows, 'unchanged complete family namespace: ' + name)
        roots[name] = root
    return roots


def source(root, number):
    expected = DEPENDENCIES['sources'][number]
    rows = snapshot(root)
    need(len(rows) == expected['files'] and sum(row['bytes'] for row in rows.values()) == expected['bytes'],
         'exact physical Source' + number + ' count and bytes')
    need(pin((root / 'source.lock.json').read_bytes()) == expected['lock'], 'exact physical Source' + number + ' lock')
    value = json.loads((root / 'source.lock.json').read_bytes())
    need(all(v is None for v in value['actual'].values()), 'unissued physical Source only')
    adapter = module('adapter_' + number, root / 'adapter.py')
    need(adapter.source(expected['lock']['sha256']) == expected['lock'], 'unchanged physical adapter acceptance')
    return expected['lock']


def build(work, roots):
    lifecycle = module('lifecycle', roots['lifecycle145'] / 'constructor.py')
    first = work / 'Source145'
    lifecycle.construct(roots['source65'], roots['qualification'], first)
    source(first, '145')
    constructor310 = module('constructor310', roots['constructor310'] / 'constructor.py')
    second = work / 'Source310'
    own310 = pin((roots['constructor310'] / 'source.lock.json').read_bytes())
    constructor310.construct(first, roots['cleanup'], roots['metadata'], second, own310)
    source(second, '310')
    constructor310.verify_export(second, DEPENDENCIES['sources']['310']['lock'], own310)
    constructor339 = module('constructor339', roots['constructor339'] / 'constructor.py')
    third = work / 'Source339'
    own339 = pin((roots['constructor339'] / 'source.lock.json').read_bytes())
    constructor339.construct(second, roots['guard'], roots['qmp'], third, own339)
    source(third, '339')
    result = constructor339.verify_export(third, DEPENDENCIES['sources']['339']['lock'], own339)
    need(result['files'] == 339 and result['closed_leaf_bytes'] == 3512147, 'complete efficient310 inverse replay')
    return first, second, third


def cli_controls(path, args, count):
    # The original CLI selects DATA operands. No actor/authority entry is called.
    tree = ast.parse(path.read_bytes(), filename=str(path))
    actual = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')
                 for node in ast.walk(tree))
    need(actual == count, 'explicit original control count')
    subprocess.run([sys.executable, '-I', '-B', '-Werror::ResourceWarning', str(path), *args, '-v'],
                   check=True, timeout=90)


def guard_controls(root, predecessor):
    # Exactly one local artifact operand is adapted in memory. Original test
    # files, proposals, constructors and their closed seals stay unchanged.
    path = root / 'test_proposal.py'
    tree = ast.parse(path.read_bytes(), filename=str(path))
    changed = 0
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'ACTUAL':
            node.value = ast.Call(func=ast.Name(id='Path', ctx=ast.Load()),
                                  args=[ast.Constant(str(predecessor))], keywords=[])
            changed += 1
    need(changed == 1, 'one exact original guard test Source310 operand')
    value = types.ModuleType('original_guard_source339_controls')
    value.__file__ = str(path)
    exec(compile(ast.fix_missing_locations(tree), str(path), 'exec'), value.__dict__)
    suite = unittest.defaultTestLoader.loadTestsFromModule(value)
    need(suite.countTestCases() == 14, 'fourteen original guard controls')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    need(result.wasSuccessful() and not result.skipped, 'guard controls pass without skips')


def fence(event, args):
    if event == 'open' and args and isinstance(args[0], (str, bytes)):
        name = os.fsdecode(args[0])
        need('/artifacts/development/' not in name and
             not name.endswith(('.raw', 'credentials.canonical.private.json', 'collection.lock')) and
             'private-keys-v1.d' not in name, 'no local artifacts, raw, credentials, private keys or lease')
    if event == 'subprocess.Popen':
        executable = os.fsdecode(args[0])
        need(executable in ('git', '/usr/bin/git', '/usr/bin/bash', sys.executable),
             'only Git, original Python controls and ordinary temporary-tree Bash')
    if event.startswith('socket.'):
        need(event == 'socket.__new__' and args[1] == socket.AF_UNIX,
             'only original local socketpair protocol controls; no network actor')
    need(event not in ('os.system', 'fcntl.flock', 'resource.setrlimit'), 'no actor, lease or runtime admission')


def main():
    need(all(value is None for value in DEPENDENCIES['actual'].values()), 'all actual grant/profile fields NULL')
    for tool in ('git', 'bash', 'getfattr', 'setfattr', 'stat', 'sha256sum', 'find'):
        need(shutil.which(tool) is not None, 'required ordinary control tool: ' + tool)
    sys.addaudithook(fence)
    with tempfile.TemporaryDirectory(prefix='perl-source339-ci-') as temporary:
        work = Path(temporary)
        roots = original_families(work)
        first, second, third = build(work, roots)
        cli_controls(roots['constructor310'] / 'test_constructor.py',
                     ['--predecessor', str(first), '--cleanup', str(roots['cleanup']), '--metadata', str(roots['metadata'])], 18)
        guard_controls(roots['guard'], second)
        cli_controls(roots['qmp'] / 'test_proposal.py', ['--source', str(second)], 12)
        cli_controls(roots['constructor339'] / 'test_constructor.py',
                     ['--predecessor', str(second), '--guard', str(roots['guard']), '--qmp', str(roots['qmp'])], 21)
        # All constructors and controls must leave original family bytes/modes intact.
        for name, root in roots.items():
            need(snapshot(root) == DEPENDENCIES['families'][name]['files'], 'immutable inputs after controls')
        source(first, '145'); source(second, '310'); source(third, '339')
    print(json.dumps(dict(status='PASS_65_ORIGINAL_SOURCE_AND_TEMPORARY_TREE_LOCAL_SOCKET_CONTROLS_ONLY',
                          controls=65, Source339=DEPENDENCIES['sources']['339'],
                          Root_authority=None, nonce=None, runtime_profile=None, VM=None, ALPM=None, M2=None, release=None),
                     sort_keys=True))


if __name__ == '__main__':
    main()
