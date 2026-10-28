# SPDX-License-Identifier: MIT
"""Future ALARM consumer. Source-only imports do not load or run feature code."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import sysconfig

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import input_contract, need, pin, read, save, verify_source


def module(root, relative, name):
    path = root / relative
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def run(root, output, map_hash):
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.getuid() == os.geteuid() != 0, 'actual unprivileged native ARM ALARM consumer required')
    verify_source(root, map_hash); profile, _, expected = input_contract(root)
    need(read(Path('/builder-packages.lock')) == expected, 'actual exact349 ALARM package inventory')
    need(not output.exists(), 'fresh consumer output required'); output.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', architecture=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'),
                  packages=pin(expected), native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN',
                  system_install='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
    phase = 'interpreter-and-header-identity'
    try:
        extension = module(root, 'scripts/workflows/python_extension.py', '_native_extension')
        need(sys.version_info[:3] == (3, 14, 8), 'actual selected Python version')
        identity = dict(implementation=sys.implementation.name, machine=platform.machine(),
                        include=sysconfig.get_path('include'), platinclude=sysconfig.get_path('platinclude'),
                        config={k: sysconfig.get_config_var(k) for k in ('EXT_SUFFIX', 'SOABI')})
        need(identity['config'] == {k: profile['retained_sysconfig']['selected'][k] for k in identity['config']}, 'actual interpreter ABI matches retained payload')
        for name, row in profile['cmake_ctest']['members'].items():
            need(pin(read(Path('/') / name)) == {k: row[k] for k in ('bytes', 'sha256')}, 'actual CMake/CTest payload identity')
        header_report, _ = extension.header_inputs(identity)
        expected_headers = {n.removeprefix('usr/include/python3.14/'): row
                            for n, row in profile['python_headers']['files'].items()}
        need(header_report['files'] == expected_headers, 'installed headers differ from pinned Python payload')
        report['headers'] = header_report
        phase = 'python-backend'
        python = module(root, 'native/python_backend.py', '_native_python_pep517')
        report['python'] = python.run(root, output / 'python')
        need(report['python']['status'] == 'PASS_LOCAL_PYTHON_PEP517_WORKFLOW', 'actual separately pinned PEP517 frontend/backend journey required')
        phase = 'compiled-extension'
        report['extension'] = extension.run(output / 'extension', '/usr/bin/python3',
            '/usr/bin/cmake', '/usr/bin/ninja', '/usr/bin/cc', '/usr/bin/ctest', timeout=45, total=600)
        need(report['extension']['status'] == 'PASS_LOCAL_COMPILED_PYTHON_WORKFLOW', 'real native extension journey')
        phase = 'build-systems'
        builds = module(root, 'scripts/workflows/developer_build_systems.py', '_native_builds')
        report['build_systems'] = builds.run(output / 'build-systems', '/usr/bin', timeout=45, total=600)
        need(report['build_systems']['status'] == 'PASS_AVAILABLE_LOCAL_WORKFLOWS'
             and {r['status'] for r in report['build_systems']['project_workflows'].values()} == {'PASS_REAL_PROJECT_WORKFLOW'}
             and set(report['build_systems']['project_workflows']) == {'cmake', 'meson'}, 'both actual CMake and Meson journeys required')
        report['status'] = 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY'
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
