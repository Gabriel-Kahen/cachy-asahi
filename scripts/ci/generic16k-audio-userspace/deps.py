# SPDX-License-Identifier: MIT
"""Exact source-only reuse. Imports execute no build, container or guest actors."""
import functools
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = json.loads((HERE / 'dependencies.json').read_text())


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source(root, name):
    row = POLICY['dependencies'][name]
    path = Path(root) / name
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
