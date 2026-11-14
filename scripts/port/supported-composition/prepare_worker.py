#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded child for the existing private libalpm engine; DATA input only."""
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024**2, 32 * 1024**2))
ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('held_transaction', ROOT / 'scripts/platform/transaction.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)


def run(path):
    work = path.parent
    need = t.preview.need
    need(path.name == 'prepare-data.json' and work.name.startswith('private-supported-composition-'), 'private engine input path refused')
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024**2, 'bounded ordinary engine DATA required')
    value = t.tuple_audit.load_json(path.read_bytes())
    need(set(value) == {'image', 'protected', 'catalogs', 'targets'}, 'engine DATA fields refused')
    image, protected, catalogs, targets = (value[key] for key in ('image', 'protected', 'catalogs', 'targets'))
    t.preview.write_local(work / 'db/local', image)
    for name, rows in catalogs.items():
        t.write_catalog(work / 'db/sync' / (name + '.db'), rows)
    prepared = t.prepare(work, image, protected, catalogs, targets)
    final = dict(image)
    for row in prepared['remove']: final.pop(row['name'], None)
    for row in prepared['add']:
        metadata = catalogs[row['repo']][row['name']]
        need(metadata['VERSION'] == [row['version']], 'child addition/catalog mismatch')
        final[row['name']] = metadata
    audit = work / 'final-audit'; (audit / 'root').mkdir(parents=True, mode=0o700)
    t.preview.write_local(audit / 'db/local', final)
    relations, conflicts = t.preview.alpm_audit(audit, final)
    return {'prepare': prepared, 'dependencies': relations, 'conflicts': conflicts}


if __name__ == '__main__':
    result = run(Path(sys.argv[1]))
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
