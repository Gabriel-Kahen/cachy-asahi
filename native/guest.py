# SPDX-License-Identifier: MIT
"""Disposable original341 ALARM debugger consumer; no host attach or policy edits."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import input_contract, need, pin, read, save, verify_source


def run(root, output, map_hash):
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.getuid() == os.geteuid() != 0, 'actual unprivileged native ARM consumer required')
    verify_source(root, map_hash)
    _, _, expected = input_contract(root)
    need(read(Path('/builder-packages.lock')) == expected, 'actual exact341 ALARM inventory')
    need(not output.exists(), 'fresh consumer output'); output.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', architecture=platform.machine(), uid=os.getuid(),
                  page_size=os.sysconf('SC_PAGE_SIZE'), packages=pin(expected),
                  native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', system_install='NOT_RUN',
                  performance='NOT_MEASURED', release='NOT_ADMITTED')
    try:
        path = root / 'scripts/workflows/developer_debugger.py'
        spec = importlib.util.spec_from_file_location('_native_debugger', path)
        debugger = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(debugger)
        report['debugger'] = debugger.run(output / 'debugger', '/usr/bin', timeout=45, total=600)
        need(report['debugger']['status'] == 'PASS_LOCAL_DEBUGGER_COMPONENT'
             and set(report['debugger']['projects']) == {'c', 'cpp'}
             and all(r['status'] == 'PASS_REAL_GDB_WORKFLOW' for r in report['debugger']['projects'].values()),
             'both actual GDB source/local/stack/continue/edit/failure/recovery journeys required')
        report['status'] = 'PASS_NATIVE_DEBUGGER_COMPONENT_ONLY'
    finally:
        save(output / 'result.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--map-sha256', required=True)
    args = parser.parse_args()
    result = run(Path(__file__).resolve().parents[1], args.output, args.map_sha256)
    print(json.dumps(dict(status=result['status'])))
