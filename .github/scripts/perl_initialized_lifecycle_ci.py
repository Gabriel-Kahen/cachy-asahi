#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Run the unchanged sealed lifecycle controls with public, pinned operands."""
import ast
import hashlib
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FAMILY = ROOT / 'scripts/integration/arm16k_perl_initialized_lifecycle_vm'
LEGACY = ROOT / 'scripts/integration/arm16k_warm_control/source/arm16k_perl5423_vm'
PROOF = ROOT / '.github/fixtures/perl-initialized-lifecycle'
REVISION = 'ead107b0f904d72e61b262f77444e46abd80cd7f'
PREFIX = 'scripts/integration/arm16k_perl_initialized_vm/'
PINS = {
    'empty-closure.DATA.json': (7556, '135759471cc66dbcafcc0b14600a0c5fc1badcc2e1fc6e458199eb0269f731dc'),
    'empty-proof.DATA.json': (3757, '7a84225e2bbf3ed91fe6eb62d9d974399b01bbe30b2a82da19b94294388d253a'),
}


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def frozen_qualification(output):
    # This original commit is an ancestor of published Main. No local-only object
    # or substitute current qualification Source can satisfy the frozen seal.
    git('merge-base', '--is-ancestor', REVISION, 'HEAD')
    for line in git('ls-tree', '-r', REVISION, '--', PREFIX).decode().splitlines():
        metadata, name = line.split('\t')
        require(metadata.split()[:2] == ['100644', 'blob'], 'ordinary frozen Source leaf')
        relative = Path(name.removeprefix(PREFIX))
        require(relative.name == str(relative), 'flat frozen qualification family')
        (output / relative).write_bytes(git('show', REVISION + ':' + name))
        (output / relative).chmod(0o644)
    raw = (output / 'source.lock.json').read_bytes()
    require((len(raw), hashlib.sha256(raw).hexdigest()) ==
            (2188, 'f51c3110877cc9f8d4056c064a43c339af4f6d026b9f7055d5a1ea749ad7e55a'),
            'exact published frozen initialized Source lock')


def controls(name, paths, expected):
    path = FAMILY / name
    tree = ast.parse(path.read_bytes(), filename=str(path))
    replaced = set()
    # Adapt only test operand selection in memory. Sealed tests and every module
    # used by the constructor remain unchanged on disk and retain their seals.
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in paths:
                node.value = ast.Call(func=ast.Name(id='Path', ctx=ast.Load()),
                                      args=[ast.Constant(str(paths[target.id]))], keywords=[])
                replaced.add(target.id)
    require(replaced == set(paths), 'exact declared test operand assignments')
    module = types.ModuleType('portable_' + path.stem)
    module.__file__ = str(path)
    exec(compile(ast.fix_missing_locations(tree), str(path), 'exec'), module.__dict__)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    require(suite.countTestCases() == expected, 'explicit lifecycle control count')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    require(result.wasSuccessful() and not result.skipped, 'all controls pass without skips')


def main():
    for command in ('bash', 'getfattr', 'setfattr', 'stat', 'sha256sum', 'find'):
        require(shutil.which(command) is not None, 'required temporary-tree tool: ' + command)
    for name, pin in PINS.items():
        path = PROOF / name
        require(not path.is_symlink() and path.stat().st_nlink == 1, 'ordinary public DATA')
        body = path.read_bytes()
        require((len(body), hashlib.sha256(body).hexdigest()) == pin, 'exact public r74 DATA')
    with tempfile.TemporaryDirectory(prefix='perl-lifecycle-ci-') as tmp:
        initialized = Path(tmp) / 'initialized'
        initialized.mkdir(mode=0o700)
        frozen_qualification(initialized)
        operands = dict(LEGACY=LEGACY, INITIALIZED=initialized)
        controls('test_initialized_lifecycle.py', operands, 9)
        controls('test_guest.py', {}, 8)
        controls('test_empty_closure.py', dict(operands, PROOF=PROOF), 7)
    print('PASS: 24 actor-free controls; no Root, fixture, VM, native or M2 acceptance')


if __name__ == '__main__':
    main()
