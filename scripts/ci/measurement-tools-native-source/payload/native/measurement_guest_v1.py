# SPDX-License-Identifier: MIT
"""Future native measurement-tools consumer; export image-stage evidence as DATA."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import input_contract, need, pin, read, save, verify_source

STORE = Path('/opt/native-measurement-tools-alpm-v1/evidence')
OPERATION = 'measurement-tools-alpm-v1'
PASS = 'PASS_MEASUREMENT_TOOLS_NATIVE_ALPM_COMPONENT'


def module(root, relative, name):
    spec = importlib.util.spec_from_file_location(name, root / relative)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def run(root, output, map_hash):
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.getuid() == os.geteuid() != 0, 'actual unprivileged native ARM ALARM consumer required')
    verify_source(root, map_hash)
    _, _, expected = input_contract(root)
    need(read(Path('/builder-packages.lock')) == expected, 'actual exact349 ALARM package inventory')
    need(sys.version_info[:3] == (3, 14, 8), 'actual retained Python3.14.8 required')
    need(not output.exists(), 'fresh consumer output required')
    output.mkdir(mode=0o700)
    report = dict(schema=1, operation=OPERATION, status='FAIL', source_map_sha256=map_hash,
                  architecture=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'), packages=pin(expected),
                  native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN',
                  system_install='IMAGE_STAGE_ALPM_ONLY', performance='NOT_MEASURED', release='NOT_ADMITTED')
    phase = 'export-image-stage-measurement-tools-alpm-data'
    try:
        lifecycle = module(root, 'native/measurement_alpm_v1.py', '_native_measurement_alpm_v1')
        need(lifecycle.STORE == STORE, 'fixed original image-stage DATA store required')
        result = lifecycle.export(output / 'measurement-tools-alpm-v1', map_hash)
        report['measurement_alpm'] = result  # Retain failed original DATA before the outer PASS guard.
        need(type(result) is dict and result.get('schema_version') == 1
             and result.get('operation') == OPERATION and result.get('source_map_sha256') == map_hash
             and result.get('status') == PASS, 'actual image-stage measurement-tools ALPM evidence required')
        report['status'] = PASS
    except BaseException as error:
        report['failure'] = dict(phase=phase, type=type(error).__name__, message=str(error)[:2048])
        raise
    finally:
        report['phase'] = phase
        save(output / 'result.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--map-sha256', required=True)
    args = parser.parse_args()
    result = run(Path(__file__).resolve().parents[1], args.output, args.map_sha256)
    print(json.dumps(dict(status=result['status'])))
