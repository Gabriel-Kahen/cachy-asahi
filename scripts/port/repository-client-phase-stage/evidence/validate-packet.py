#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run local tests from an exact private copy; retain the actual execution log."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).absolute().parents[4]
OWNED = Path('scripts/port/repository-client-phase-stage')
LOG = OWNED / 'evidence/full-suite.log'
RECORD = OWNED / 'evidence/full-suite-validation.json'
EXTERNAL = [Path('scripts/port/repository-client-native') / name for name in
            ('entry.py', 'worker.py', 'common.py', 'base.py', 'provenance.py', 'crypto.py', 'orchestrator.py', 'test_crypto.py')]
EXTERNAL += [Path(name) for name in (
    'scripts/port/repository-client-stage/gate.py', 'scripts/port/repository-client-stage/adapter.py',
    'scripts/port/repository-client-stage/test_gate.py', 'scripts/release/release.py', 'scripts/client/client.py',
    'scripts/ci/repository_projection.py', 'scripts/ci/lifecycle_inventory.py', 'scripts/ci/inputs.lock.json',
    'scripts/port/refreshed-desktop/proposed-builder-inventory.lock')]


def main():
    paths = sorted([path.relative_to(ROOT) for path in (ROOT / OWNED).rglob('*')
                    if path.is_file() and path.relative_to(ROOT) not in (LOG, RECORD)]
                   + [Path('docs/workstreams/repository-client-phase-stage.md')] + EXTERNAL)
    def rows(base):
        return {str(path): {'sha256': hashlib.sha256((base / path).read_bytes()).hexdigest(),
                           'mode': (base / path).stat().st_mode & 0o777, 'bytes': (base / path).stat().st_size}
                for path in paths}
    before = rows(ROOT); started = time.time()
    with tempfile.TemporaryDirectory(prefix='phase-stage-exact-source-packet-') as temporary:
        copied = Path(temporary)
        for path in paths:
            target = copied / path; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, target)
        assert rows(copied) == before
        command = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(OWNED), '-p', 'test_*.py', '-v']
        result = subprocess.run(command, cwd=copied, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        copied_stable, original_stable = rows(copied) == before, rows(ROOT) == before
        bytecode = list(copied.rglob('__pycache__'))
        (ROOT / LOG).write_bytes(result.stdout)
        value = {'schema_version': 1, 'purpose': 'exact-copied-local-test-validation',
            'status': 'PASS-local-tests' if result.returncode == 0 and copied_stable and original_stable and not bytecode else 'FAIL',
            'command': command, 'exit_code': result.returncode, 'elapsed_seconds': round(time.time() - started, 3),
            'copied_source_stable': copied_stable, 'original_source_stable': original_stable, 'bytecode_directories': len(bytecode),
            'copied_packet_removed_after_checks': True, 'native_admission': 'NOT RUN', 'hardware_validation': 'NOT RUN',
            'execution_log': {'path': str(LOG), 'sha256': hashlib.sha256(result.stdout).hexdigest(), 'bytes': len(result.stdout)},
            'exact_input_files': before,
            'fixture_boundary': 'native/base/provenance/installation observations modeled; original phases and fresh TEST signing/client commands real'}
        (ROOT / RECORD).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: item for key, item in value.items() if key not in ('exact_input_files', 'command', 'fixture_boundary')}, sort_keys=True))
    print(result.stdout.decode()[-1600:])
    return 0 if value['status'] == 'PASS-local-tests' else 1


if __name__ == '__main__': sys.exit(main())
