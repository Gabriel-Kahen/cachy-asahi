# SPDX-License-Identifier: MIT
"""Exact source-only reuse. Imports execute no build, container or guest actors."""
import functools
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = json.loads((HERE / 'dependencies.json').read_text())
CHECKER = 'scripts/checks/package_checks.py'
HELD_CHECKER = (Path('scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source')
                / 'scripts/ci/llhttp-reference-native-source/base/runtime' / CHECKER)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source(root, name):
    root = Path(root)
    row = POLICY['dependencies'][name]
    path = root / name
    if name == CHECKER and (root / HELD_CHECKER).parent.is_dir():
        # Older standalone source trees carry the same pin at the canonical path.
        path = root / HELD_CHECKER
    need(path.is_file() and not path.is_symlink(), 'source regular file required')
    data = path.read_bytes()
    need(len(data) == row['bytes'] and sha(data) == row['sha256'], 'source pin differs: ' + name)
    return path


@functools.lru_cache(None)
def load(root, name):
    path = source(root, name)
    spec = importlib.util.spec_from_file_location('audio16k_' + sha(name.encode())[:16], path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def closed_elf(data, generic):
    interpreter, needed, loads = generic.elf(data)
    need(loads and all(align >= 16384 and (va - offset) % 16384 == 0
                      for va, offset, _, align in loads), 'ELF not structurally 16KiB aligned')
    return interpreter, needed
