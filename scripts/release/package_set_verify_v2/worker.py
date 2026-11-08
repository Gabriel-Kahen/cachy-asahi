#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private resource-limited adapter to the unchanged current package validator."""
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import sys

MAX_REPORT = 32 * 1024 * 1024
MAX_MEMBERS = 131072


def main():
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPORT, MAX_REPORT))
    mode, operand, pin = sys.argv[1:]
    path = Path(__file__).resolve().parents[2] / 'checks/package_checks.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('current validator SHA-256 changed')
    spec = importlib.util.spec_from_file_location('package_set_validator_v2', path)
    checks = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), checks.__dict__)
    if mode == 'inspect':
        report = checks.package(Path(operand))
        if len(report['members']) > MAX_MEMBERS:
            raise ValueError('per-archive member budget exceeded')
        result = {key: report[key] for key in ('artifact', 'sha256', 'metadata', 'errors', 'review')}
        result['members'] = {name: {'type': row['type']} for name, row in report['members'].items()}
    elif mode == 'conflicts':
        with Path(operand).open() as stream:
            reports = [json.loads(line) for line in stream]
        result = checks.conflicts(reports)
    else:
        raise ValueError('unknown private worker mode')
    encoded = json.dumps(result, separators=(',', ':')).encode()
    if len(encoded) > MAX_REPORT:
        raise ValueError('worker report byte budget exceeded')
    sys.stdout.buffer.write(encoded)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error)[:500], file=sys.stderr)
        sys.exit(2)
