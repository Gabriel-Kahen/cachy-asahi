#!/usr/bin/env python3
"""Write explicit source pins and finite budgets; never launch native actors."""
import argparse
import hashlib
import json
from pathlib import Path

BEFORE = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
AFTER = 'dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def build(code, driver, scope):
    # Pin the available code/data tree, including transitive local imports. Tests
    # and this caller are not dependencies of the separately supervised driver.
    files = [p for name in ('update', 'install', 'client', 'release', 'checks', 'build')
             for p in (code / 'scripts' / name).glob('*')
             if p.suffix in ('.py', '.json', '.lock') and not p.name.startswith('test_')]
    composition = code / 'scripts/ci/full-development-composition'
    files += [composition / name for name in ('run.py', 'setup4_inputs.py', 'audio_aux.py',
                                              'expected-updater-v2.lock', 'expected-setup4-v2.lock')]
    files += [code / name for name in ('packages/tools/cachy-asahi-update/asahi-policy.py',
                                       'scripts/port/kernel-native-job/runtime.py')]
    pins = {p.relative_to(code).as_posix(): sha(p) for p in sorted(files)
            if p.is_file() and not p.is_symlink()}
    for name in ('root_upgrade.py', 'construct_repository.py'):
        pins['scripts/ci/full-root-upgrade/' + name] = sha(driver / name)
    return dict(schema_version=1, purpose='actual587-persistent-root-setup4-test', code_pins=pins,
        external_pins={'/setup4.py': 'aa9bcc4eff8208c9724de7d7f6490055404dc9e11979f6cbae372d98fd83d379',
                       # Mounted from fixed PREPARATION_SOURCE, independently of upgrade-code.
                       '/footprint.py': '78391cd0e009bdf165cffdb26ba911642f5fec81ec6bd7feab65654fcf776387',
                       '/persistent_scope.py': sha(scope)},
        stage_seconds=900, verify_seconds=600, copy_seconds=600, driver_seconds=1800,
        scale=dict(schema_version=1, purpose='disposable-bound-update-scale',
            before_lock_sha256=BEFORE, after_lock_sha256=AFTER, platform_mode='generic-development',
            limits=dict(root_nodes=200000, root_bytes=6*1024**3, file_bytes=1024**3,
                package_files=500000, archive_bytes=1024**2, archive_total_bytes=2*1024**2,
                decoded_bytes=16*1024**2, archive_members=1000, window_bytes=16*1024**2, seconds=1200),
            capacity=dict(root_reserve_bytes=256*1024**2, root_reserve_inodes=10000,
                          workspace_future_bytes=256*1024**2, workspace_future_inodes=20000)),
        release=dict(release_id='full-root-setup4-test-20261016', repo_name='cachy-asahi-test',
            namespace='cachy-asahi-full-root-test', sequence=1, issued_utc='2026-10-16T00:00:00Z',
            expires_utc='2026-10-18T00:00:00Z', supported_models=['m2-air-13', 'm2-air-15']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('code', 'driver', 'scope', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(build(args.code, args.driver, args.scope), indent=2, sort_keys=True) + '\n')
