#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise only emit's mkdir statements; never import or invoke the constructor."""
import sys


def deny_actors(event, args):
    if (event.startswith(('socket.', 'subprocess.', 'ctypes.', 'pty.'))
            or event in ('os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn')
            or event == 'import' and args[0].split('.')[0] in
            {'socket', 'subprocess', 'ctypes', 'multiprocessing'}):
        raise RuntimeError('actor denied: ' + event)


sys.addaudithook(deny_actors)

import ast
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

FACTORY = Path(__file__).resolve().parents[1]


def mkdir_program(raw):
    """Select the real directory prefix, stopping before the first file write."""
    module = ast.parse(raw)
    emit = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'emit')
    loops = [n for n in ast.walk(emit) if isinstance(n, ast.For)
             and ast.unparse(n.iter) == 'sorted(bodies.items())']
    if len(loops) != 1:
        raise ValueError('one output loop required')
    statements = []
    for node in loops[0].body:
        if isinstance(node, ast.With):
            break
        statements.append(node)
    # Keep the execution capability finite: assignment, path traversal and mkdir.
    for node in ast.walk(ast.Module(body=statements, type_ignores=[])):
        if isinstance(node, ast.Call) and not (isinstance(node.func, ast.Attribute)
                and node.func.attr in {'relative_to', 'mkdir'}):
            raise ValueError('non-directory call in output prefix')
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.With, ast.While, ast.Try)):
            raise ValueError('non-directory statement in output prefix')
    return compile(ast.fix_missing_locations(ast.Module(body=statements, type_ignores=[])),
                   '<maintained emit directory prefix>', 'exec')


def output_names():
    parent = json.loads((FACTORY / 'parent-profile.json').read_bytes())['files']
    full = json.loads((FACTORY / 'tests/fixtures/source-full-map.json').read_bytes())
    fields = ('bytes', 'sha256', 'mode', 'blob')
    changed = {n for n in parent.keys() | full.keys() if
               (None if n not in parent else {k: parent[n][k] for k in fields}) !=
               (None if n not in full else {k: full[n][k] for k in fields})}
    names = ({'source/' + n for n in full} | {'before05df/' + n for n in changed & parent.keys()}
             | {'stage.json', 'source-authorization.json', 'source-modes.json', 'git-blobs.json',
                'parent-commit.raw', 'parent-full-map.json', 'delta05df.json', 'selected-overlay.json'})
    if len(full) != 201 or len(changed) != 7 or len(names) != 214:
        raise ValueError('held Source201/214 namespace required')
    return sorted(names)


def exercise(program, names, mask):
    previous = os.umask(mask)
    try:
        with tempfile.TemporaryDirectory(prefix='platform-policy-mkdir-') as temporary:
            staged = Path(temporary) / 'output'
            staged.mkdir(mode=0o700)
            for name in names:
                exec(program, {'__builtins__': {}, 'staged': staged, 'name': name})
            return {p.relative_to(staged).as_posix(): stat.S_IMODE(p.stat().st_mode)
                    for p in staged.rglob('*')}
    finally:
        os.umask(previous)


class SourceDirectories(unittest.TestCase):
    def test_workflows_bind_current_checkout_and_historical_parent_tree(self):
        profile = json.loads((FACTORY / 'parent-profile.json').read_bytes())
        for name in ('platform-namespace-policy-host-data.yml',
                     'platform-namespace-policy-source-proposal.yml'):
            with self.subTest(workflow=name):
                text = (FACTORY.parents[2] / '.github/workflows' / name).read_text()
                self.assertEqual(text.count('          ref: 639e3f9b5176bf8ebe497fc0b247182af90904e7'), 1)
                self.assertIn('      EXPECTED_PARENT: 639e3f9b5176bf8ebe497fc0b247182af90904e7\n', text)
                self.assertIn('      HISTORICAL_PARENT: ' + profile['parent'] + '\n', text)
                self.assertIn('      EXPECTED_PARENT_TREE: ' + profile['parent_tree'] + '\n', text)
                self.assertIn('test "$(git -C "$basis" rev-parse HEAD)" = "$EXPECTED_PARENT"', text)
                self.assertIn('test "$(git -C "$basis" rev-parse HEAD^{tree})" = "$EXPECTED_PARENT_TREE"', text)
                self.assertNotIn('          ref: ' + profile['parent'], text)

    def test_real_emit_prefix_satisfies_held0700_checker_for_all214_paths(self):
        program = mkdir_program((FACTORY / 'prepare.py').read_bytes())
        names = output_names()
        wanted = {p.as_posix() for n in names for p in Path(n).parents if p != Path('.')}
        for mask in (0o022, 0o002, 0o077):
            with self.subTest(umask=oct(mask)):
                modes = exercise(program, names, mask)
                self.assertEqual(set(modes), wanted)
                self.assertEqual(set(modes.values()), {0o700})

    def test_original_mkdir_pattern_reproduces0755_intermediate_parents(self):
        # A minimal counterexample, not execution of historical constructor code.
        program = compile('target = staged / name\n'
                          'target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)\n',
                          '<mkdir parents counterexample>', 'exec')
        modes = exercise(program, output_names(), 0o022)
        self.assertEqual(modes['source'], 0o755)
        self.assertEqual(modes['source/.github'], 0o755)
        self.assertEqual(modes['source/.github/workflows'], 0o700)
        self.assertEqual(modes['before05df'], 0o755)
        self.assertEqual(modes['before05df/.github'], 0o755)

    def test_actor_guard_precedes_imports(self):
        for event in ('subprocess.Popen', 'socket.connect', 'ctypes.dlopen', 'os.system'):
            with self.subTest(event=event), self.assertRaises(RuntimeError):
                sys.audit(event)


if __name__ == '__main__':
    unittest.main()
