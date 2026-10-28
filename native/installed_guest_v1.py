# SPDX-License-Identifier: MIT
"""Native installed/moved-prefix command consumer, separate from held184 guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import input_contract, need, pin, read, save, verify_source
from installed_tools_v1 import PREFIX, SDK, load_packaged_workflow


def run(root, output, map_hash, alpm_installed=False, installed_usr=False):
    need(not installed_usr or alpm_installed, "explicit ALPM-only /usr journeys")
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.getuid() == os.geteuid() != 0, 'actual unprivileged native ARM consumer required')
    verify_source(root, map_hash); _, _, expected = input_contract(root)
    need(sys.version_info[:3] == (3, 14, 8), 'held exact Python version required')
    if alpm_installed:
        from installed_alpm_v1 import git_policy
        _,dependencies=git_policy(root)
    else:dependencies=expected
    need(read(Path('/builder-dependency-packages.lock')) == dependencies, 'exact selected dependencies required')
    actual = read(Path('/builder-packages.lock'))
    wanted = b''.join(sorted(dependencies.splitlines(keepends=True)+[b'cachy-asahi-developer-tools 0.1.0-1\n'])) if alpm_installed else expected
    need(actual == wanted, 'exact349 or exact350 only while TEST package installed')
    need(not output.exists(), 'fresh installed consumer output required'); output.mkdir(mode=0o700)
    image = json.loads((PREFIX / 'image-package.json').read_text())
    contract = json.loads((PREFIX / 'installed-contract-v1.json').read_text())
    for row in contract['payload_files']:
        need(pin(read(SDK / row['path'])) == {k: row[k] for k in ('bytes', 'sha256')}, 'actual installed/moved prefix payload differs')
    save(output / 'package.json', image)
    W = load_packaged_workflow()
    control = output / 'control'; control.mkdir(mode=0o700)
    home = control / 'home'; home.mkdir(mode=0o700)
    commands = W.Commands(control, home, '/usr/bin:/bin', timeout=400, total=600, max_output=256*1024)
    report = dict(schema=1, status='FAIL', operation='installed-v1', architecture=platform.machine(),
        page_size=os.sysconf('SC_PAGE_SIZE'), packages=pin(expected), installed_inventory=pin(actual),
        installed_package=image, installed_prefix='/usr' if installed_usr else str(SDK), commands={}, native_16K='NOT_QUALIFIED',
        physical_M2='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED',
        source_mount='READ_ONLY_SOURCE184_STILL_MOUNTED; commands bind installed runtime paths, no hidden-checkout claim',
        python_backend_protocol='VERSIONED_WRAPPER_FORCES_EXISTING_PINNED_OFFLINE_PEP517; original v1 builtin label is not accepted as evidence')
    report['alpm_installed'] = alpm_installed
    phase = 'installed-verify'
    try:
        launcher = '/usr/bin/cachy-asahi-developer-tools' if installed_usr else str(SDK / 'bin/cachy-asahi-developer-tools')
        commands.run('installed-verify', [launcher, 'verify'], output)
        for name in ('workflow', 'build-systems', 'debugger', 'python'):
            phase = name
            argv = [launcher, name, '--output', str(output / name), '--command-timeout', '60', '--total-timeout', '360']
            if name == 'python':
                argv += ['--python', '/usr/bin/python3', '--uv', str(PREFIX / 'uv-v1')]
            else:
                argv += ['--tool-path', '/usr/bin:/bin']
            # Git is absent in the exact349 lock. The CLI must report missing
            # tools instead of pretending this repository/editor journey ran.
            commands.run('installed-' + name, argv, output, 2 if name == 'workflow' and not alpm_installed else 0)
            result = json.loads((output / name / 'result.json').read_text())
            if name == 'workflow' and alpm_installed:
                need(result['status']=='PASS_LOCAL_DEVELOPER_COMPONENT' and {r['status'] for r in result['project_workflows'].values()}=={'PASS_REAL_PROJECT_WORKFLOW'} and set(result['project_workflows'])=={'make','ninja'}, 'actual Git/editor/Make/Ninja journey required')
            elif name == 'workflow':
                need(result['status'] == 'MISSING_TOOLS' and result['missing_required'] == ['git'], 'exact known missing Git state required')
            elif name == 'build-systems':
                from build_summary import emit
                emit(output/name,result,map_hash,output)
                need(result['status'] == 'PASS_AVAILABLE_LOCAL_WORKFLOWS' and set(result['project_workflows']) == {'cmake', 'meson'}
                     and {v['status'] for v in result['project_workflows'].values()} == {'PASS_REAL_PROJECT_WORKFLOW'}, 'both installed build journeys required')
            else:
                need(result['status'] == {'debugger':'PASS_LOCAL_DEBUGGER_COMPONENT','python':'PASS_LOCAL_PYTHON_WORKFLOW'}[name], 'actual installed command journey required')
            report['commands'][name] = result
        backend = json.loads((output / 'backend-v1/result.json').read_text())
        need(backend['status'] == 'PASS_PINNED_INSTALLED_PEP517_ADAPTER_V1', 'actual separately pinned backend adapter required')
        report['backend'] = backend
        report['status'] = 'PASS_INSTALLED_TEST_ALPM_COMPONENTS_V1' if alpm_installed else 'INCOMPLETE_NATIVE_INSTALLED_DEVELOPER_TOOLS_V1'
        report['missing'] = {} if alpm_installed else dict(workflow=['git'])
    except BaseException as error:
        report['failure'] = dict(phase=phase, type=type(error).__name__, message=str(error)[:2048]); raise
    finally:
        report['phase'] = phase
        save(control / 'result.json', dict(status='INSTALLED_COMMAND_CUSTODY_V1', commands=commands.records))
        save(output / 'result.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--map-sha256', required=True)
    parser.add_argument('--alpm-installed', action='store_true')
    parser.add_argument('--installed-usr', action='store_true')
    args = parser.parse_args()
    print(json.dumps(dict(status=run(Path(__file__).resolve().parents[1], args.output, args.map_sha256, args.alpm_installed, args.installed_usr)['status'])))
