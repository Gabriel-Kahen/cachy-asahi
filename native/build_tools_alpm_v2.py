# SPDX-License-Identifier: MIT
"""Probe-only image RUN adapter; no package, service or policy operation."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_tools_tools_v2 as T
need = T.need
SOURCE, STORE = T.SOURCE, T.STORE
PASS = 'PASS_NAMESPACE_PREFLIGHT_NATIVE_DIAGNOSTIC'


def prepare(root, context, map_hash, own):
    from common import verify_source
    manifest = verify_source(root, map_hash)
    need(re.fullmatch('[0-9a-f]{24}', own['token']), 'owner-bound diagnostic token')
    target = Path(context) / T.OPERATION / 'source'
    target.mkdir(parents=True)
    for name in sorted(set(manifest['files']) | {'native/source-map.json'}):
        source = Path(root) / name; out = target / name
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, out); out.chmod(stat.S_IMODE(source.stat().st_mode))


def dockerfile(base, map_hash, own):
    ending = 'USER alarm\nWORKDIR /tmp\n'
    need(base.endswith(ending) and base.count(ending) == 1, 'exact original349 image suffix')
    T.arguments(T.CASES[0], map_hash, own['token'])
    script = ('test "$BASHPID" -eq 1 || exit 125; /usr/bin/python3 -I -B ' + str(SOURCE / 'native/build_tools_alpm_v2.py') +
              ' --inside-image --map-sha256 ' + map_hash + ' --token ' + own['token'] +
              ' & namespace_owner=$!; namespace_status=0; wait "$namespace_owner" || namespace_status=$?; exit "$namespace_status"')
    return (base[:-len(ending)] + 'COPY ' + T.OPERATION + '/source/ ' + str(SOURCE) + '/\n' +
            'RUN /usr/bin/mkdir -m 0755 ' + str(STORE) + ' && /usr/bin/chown alarm:alarm ' + str(STORE) + '\n' +
            ending + 'RUN ' + json.dumps(['/usr/bin/bash', '--noprofile', '--norc', '-p', '-c', script]) + '\n')


def retired(row):
    s = row.get('supervision')
    need(type(s) is dict and s.get('reaped') is True and s.get('ownership') == 'REAPED' and
         s.get('group_census') == 'EMPTY_TWICE' and s.get('output_complete') is True and
         s.get('timeout') is False and s.get('signals') == [] and s.get('error') is None and
         type(s.get('exit')) is int and 0 <= s['exit'] <= 255 and
         type(s.get('seconds')) in (int, float) and 0 <= s['seconds'] < 20,
         'complete natural namespace command retirement')
    need(row.get('success') is (s['exit'] == 0), 'actual zero expectation outcome retained')
    return s['exit']


def save(scope, report, records):
    report['commands'] = records
    for name, value in (('commands.json', records), ('result.json', report)):
        target = scope / name
        target.write_bytes(T.encoded(value)); target.chmod(0o644)


def inside(map_hash, token):
    from common import input_contract, verify_source
    verify_source(SOURCE, map_hash)
    _, _, baseline = input_contract(SOURCE)
    alarm = pwd.getpwnam('alarm')
    need(os.uname().machine == 'aarch64' and os.getuid() == os.geteuid() == alarm.pw_uid == 1000 and
         os.getgid() == os.getegid() == alarm.pw_gid == 1000 and os.getpid() > 1 and os.getppid() == 1 and
         Path.cwd() == Path('/tmp') and T.ordinary('/builder-packages.lock') == baseline,
         'native original349 USER alarm RUN direct child of Bash PID1')
    scope = STORE / 'journey' / T.OPERATION
    need(not (STORE / 'journey').exists(), 'fresh diagnostic evidence namespace')
    scope.mkdir(parents=True); scope.chmod(0o755)
    home = scope / 'home'; home.mkdir(mode=0o700)
    report = dict(schema_version=1, operation=T.OPERATION, status='FAIL', source_map_sha256=map_hash,
                  token=token, baseline=T.data_pin(baseline), execution='NORMAL_DOCKER_IMAGE_BUILD_RUN_USER_ALARM',
                  process_layout=dict(schema=1, contract='bash-pid1-direct-python-child-v1', python_pid=os.getpid(),
                    python_ppid=os.getppid(), status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'),
                  commands=[], outcomes={}, first_failure=None, cleanup=dict(home_absent=False),
                  package_build='NOT_RUN', package_install='NOT_RUN', services='NOT_RUN', GUI='NOT_RUN',
                  namespace_policy_cause='UNKNOWN', Doc315='NOT_ESTABLISHED', native_acceptance='NOT_ADMITTED',
                  physical_M2='NOT_RUN', release='NOT_ADMITTED')
    records = []; primary = None
    save(scope, report, records)
    try:
        import importlib.util
        path = SOURCE / 'scripts/workflows/developer_workflow.py'
        spec = importlib.util.spec_from_file_location('_namespace_held_commands', path)
        workflow = importlib.util.module_from_spec(spec); spec.loader.exec_module(workflow)
        commands = workflow.Commands(scope, home, '/usr/bin:/bin', timeout=20, total=60, max_output=65536)
        records = commands.records
        for case in T.CASES:
            before = len(records)
            try:
                raw = commands.run(case, T.wrapper(case, map_hash, token), Path('/tmp'), expected=0)
            except Exception:
                # A denied command is an observation only after independent owned retirement.
                need(len(records) == before + 1, 'launch/record failure cannot become a denial')
                need(not commands.cancelled, 'cancellation cannot become namespace denial')
                retired(records[-1])
                raw = T.ordinary(scope / records[-1]['log'], 65536)
            code = retired(records[-1])
            need(T.data_pin(raw) == records[-1]['log_pin'], 'actual complete supervised probe output')
            report['outcomes'][case] = T.namespace_outcome(raw, code, case, map_hash, token)
            save(scope, report, records)
        need(T.ordinary('/builder-packages.lock') == baseline, 'held baseline bytes after both probes')
        report['status'] = PASS
    except BaseException as error:
        primary = error
        report['first_failure'] = dict(type=type(error).__name__, message=str(error)[:1024])
    finally:
        try:
            need(not home.is_symlink() and home.stat().st_uid == 1000 and stat.S_IMODE(home.stat().st_mode) == 0o700,
                 'exact own diagnostic home')
            home.rmdir()
            report['cleanup'] = dict(home_absent=True)
        except BaseException as error:
            report['cleanup'] = dict(home_absent=False, failure=type(error).__name__)
            if primary is None: primary = error
        if primary is not None: report['status'] = 'FAIL'
        save(scope, report, records)
        for row in records: (scope / row['log']).chmod(0o644)
    # Preserve complete failure DATA in the disposable image; consumer refuses it.
    return report


def export(output, map_hash):
    from common import verify_source
    verify_source(Path(__file__).resolve().parents[1], map_hash)
    output = Path(output)
    need(os.getuid() == os.geteuid() != 0 and not os.path.lexists(output) and
         not any(p.is_symlink() for p in output.parents), 'unprivileged fresh fixed DATA export')
    scope = STORE / 'journey' / T.OPERATION
    raw = T.ordinary(scope / 'result.json', 262144); report = json.loads(raw)
    rows = json.loads(T.ordinary(scope / 'commands.json', 262144))
    need(report['commands'] == rows and len(rows) <= 2 and report['source_map_sha256'] == map_hash and
         report['operation'] == T.OPERATION, 'finite same-source observation index')
    files = {'result.json': raw, 'commands.json': T.encoded(rows)}
    for index, row in enumerate(rows):
        name = row['log']
        need(name == '%03d-%s.log' % (index, T.CASES[index]), 'exact diagnostic raw-log grammar')
        body = T.ordinary(scope / name, 65536)
        need(T.data_pin(body) == row['log_pin'], 'same original raw-log pin')
        files[name] = body
    output.mkdir(mode=0o700)
    for name, body in files.items():
        with (output / name).open('xb') as stream: stream.write(body)
        (output / name).chmod(0o600)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside-image', action='store_true', required=True)
    parser.add_argument('--map-sha256', required=True); parser.add_argument('--token', required=True)
    args = parser.parse_args()
    inside(args.map_sha256, args.token)
