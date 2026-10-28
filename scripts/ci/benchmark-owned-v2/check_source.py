#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticate finite v2 source wiring without importing or executing workloads."""
import argparse
import ast
import fnmatch
import hashlib
import json
from pathlib import Path
import stat
import sys

PROFILE = 'scripts/ci/benchmark-owned-v2/source-profile.json'
PROFILE_SHA256 = '6abc639205e66d77d5ef3869437c897c7468cf91b576bc71ab7796eb39b8da09'


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, row):
    before = path.lstat()
    need(not any(p.is_symlink() for p in (path, *path.parents)) and
         stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         before.st_size == row['bytes'] and stat.S_IMODE(before.st_mode) == int(row['mode'], 8),
         'ordinary exact source file/mode required: ' + path.name)
    raw = path.read_bytes()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                             info.st_uid, info.st_gid, info.st_size,
                             info.st_mtime_ns, info.st_ctime_ns)
    need(identity(path.lstat()) == identity(before) and sha(raw) == row['sha256'],
         'source bytes changed: ' + path.name)
    return raw


def constant(tree, name):
    nodes = [n for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    need(len(nodes) == 1, 'one source constant required: ' + name)
    return ast.literal_eval(nodes[0].value)


def main(root):
    need(sys.version_info >= (3, 12), 'Python>=3.12 required')
    root = root.resolve(strict=True)
    profile_path = root / PROFILE
    raw = profile_path.read_bytes()
    need(sha(raw) == PROFILE_SHA256 and not profile_path.is_symlink(), 'exact finite source profile')
    profile = json.loads(raw)
    rows = profile['files']
    need(profile['schema_version'] == 1 and len(rows) == 18, 'finite18 source dependency closure')
    bodies, trees = {}, {}
    for name, row in rows.items():
        relative = Path(name)
        need(not relative.is_absolute() and all(p not in ('', '.', '..') for p in relative.parts),
             'canonical relative source path')
        bodies[name] = read(root / relative, row)
        if name.endswith('.py'):
            trees[name] = ast.parse(bodies[name], filename=name)
    prefix = 'scripts/benchmarks/'
    runner, adapter = prefix + 'benchmark_v2.py', prefix + 'benchmark_owned_retirement.py'
    controls = profile['controlled_entrypoint']
    need(controls == prefix + 'benchmark_v2_retirement_controls.py' and
         not fnmatch.fnmatch(Path(controls).name, 'test_*.py'), 'explicit namespace-only controls route')
    tests = [n.name for n in ast.walk(trees[controls]) if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
    need(len(tests) == len(set(tests)) == profile['qualified_controls'] == 12, 'all twelve controls declared')
    need(constant(trees[runner], 'OWNED_RETIREMENT_ADAPTER_SHA256') == rows[adapter]['sha256'] and
         constant(trees[adapter], 'OWNER_SHA256') == rows['scripts/virtual/owned_process.py']['sha256'],
         'runner to adapter to exact shared owner pins')
    need(constant(trees[runner], 'EXECUTION_LAYER') == constant(trees[adapter], 'SCHEMA') ==
         'benchmark-owned-retirement-v2', 'distinct versioned execution layer')
    sensors = [n for n in ast.walk(trees[adapter]) if isinstance(n, ast.Call) and
               isinstance(n.func, ast.Name) and n.func.id == 'sensors']
    need(len(sensors) == 1 and not sensors[0].args and not sensors[0].keywords, 'PID-free sensor callback')
    old = bodies[prefix + 'benchmark.py'].decode()
    new = bodies[runner].decode()
    for name, expected in profile['comparison_source_contracts']['byte_held_functions'].items():
        pieces = []
        for text in (old, new):
            nodes = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name]
            need(len(nodes) == 1, 'one comparison function: ' + name)
            pieces.append(ast.get_source_segment(text, nodes[0]).encode())
        need(pieces[0] == pieces[1] and sha(pieces[0]) == expected, 'held comparison source: ' + name)
    print(json.dumps(dict(status='PASS_BENCHMARK_V2_SOURCE_WIRING_ONLY',source_files=18,
                         declared_private_controls=12,executed_private_controls=0,
                         imports_or_workloads=0,host_sensor_or_census=False,native='NOT_RUN',
                         actual_paired_artifacts='NOT_RUN',performance='NOT_MEASURED'), sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    main(parser.parse_args().root)
