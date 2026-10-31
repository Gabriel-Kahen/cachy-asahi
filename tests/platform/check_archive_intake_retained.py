#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit optional local integration. Missing evidence is NOT RUN, never PASS."""
import argparse
import json
from pathlib import Path
import types

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('selection', 'selection-sha256', 'authentication', 'authentication-sha256', 'output'):
        parser.add_argument('--' + field)
    args = parser.parse_args()
    if not all(vars(args).values()) or not all(Path(p).is_file() for p in (args.selection, args.authentication)):
        print(json.dumps(dict(status='NOT_RUN', reason='explicit-local-evidence-inputs-absent')))
        return 0
    source = ROOT / 'scripts/platform/archive_intake.py'
    adapter = types.ModuleType('explicit_local_intake')
    adapter.__file__ = str(source)
    exec(compile(source.read_bytes(), str(source), 'exec'), adapter.__dict__)
    selection = adapter.decode(adapter.pinned_file(args.selection, args.selection_sha256))
    authentication = adapter.decode(adapter.pinned_file(args.authentication, args.authentication_sha256))
    if not all(Path(row[key]['path']).is_file() for row in selection['packages'] for key in ('archive', 'signature')):
        print(json.dumps(dict(status='NOT_RUN', reason='exact-retained-archive-or-signature-absent')))
        return 0
    print(json.dumps(adapter.run(selection, authentication, args.output), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
