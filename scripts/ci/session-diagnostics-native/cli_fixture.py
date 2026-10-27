#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Installed headless CLI and private controls; no host service probing."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

NAME = 'cachy-asahi-session-diagnostics'
CAP = 2 * 1024**2
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', LANG='C', TZ='UTC')
SCOPED_CHECKS = ('hyprland/version', 'hyprland/displays', 'renderer/wayland-gles-client',
    'user/graphical-session.target', 'user/pipewire.service', 'user/wireplumber.service',
    'user/xdg-desktop-portal-hyprland.service', 'system/speakersafetyd.service',
    'system/asahi-audio.service', 'session/logind', 'audio/graph', 'suspend/logind-capability')


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path required')
    return path


def packaged(cli):
    cli = ordinary(cli)
    need(cli.is_file() and cli.name == NAME and cli.stat().st_size <= 65536, 'bounded exact diagnostic launcher required')
    runtime = ordinary(cli.parents[1] / 'lib' / NAME / 'session_probe.py')
    need(runtime.is_file() and runtime.stat().st_size <= 65536 and
         {p.name for p in runtime.parent.iterdir()} == {'session_probe.py'}, 'exact single-module private runtime required')
    expected = re.findall(r"^RUNTIME_SHA256 = '([0-9a-f]{64})'$", cli.read_text(), re.M)
    need(len(expected) == 1 and pin(runtime.read_bytes())['sha256'] == expected[0], 'launcher/runtime source binding differs')
    spec = importlib.util.spec_from_file_location('installed_session_probe_fixture', runtime)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, runtime


def assert_headless(report, *, architecture=None, page_size=None):
    need(report.get('schema_version') == 1 and report.get('record_type') == 'session-observations', 'exact report schema required')
    need(report['identity']['architecture'] == (architecture or os.uname().machine) and
         report['identity']['page_size_bytes'] == (page_size or os.sysconf('SC_PAGE_SIZE')) and
         report['identity']['observed_model_id'] is None and
         report['identity']['execution_context'] == 'virtual', 'headless actual machine identity differs')
    need(set(report['physical_checks'].values()) == {'NOT RUN'}, 'physical checks must remain NOT RUN')
    rows = {row['check']: row for row in report['checks']}
    need(len(rows) == 15 and all(rows[name]['state'] == 'unavailable' and
         rows[name]['reason'] == 'local-endpoint-unavailable' and rows[name]['value'] is None and
         'returncode' not in rows[name] for name in SCOPED_CHECKS), 'headless endpoints must skip every service/tool launch')
    need(rows['hyprland/compositor-renderer']['state'] == 'unknown' and
         rows['hyprland/compositor-renderer']['value'] is None, 'unexposed compositor renderer must remain unknown')
    need(report['limits'] == dict(command_seconds=2, total_query_seconds=20,
         combined_output_bytes_per_command=524288, cleanup_seconds_per_command=1), 'fixed diagnostic budgets differ')
    return dict(status='PASS_HEADLESS_ENDPOINT_ABSENCE', unavailable_endpoint_checks=12,
        compositor_renderer='UNKNOWN', speaker_protection='NOT TESTED', physical='NOT_RUN',
        kernel_power_capabilities='OBSERVATION_ONLY', optional_tools_available=report['tools_available'])


def headless_guard():
    marker = Path('/tmp/session-diagnostics-fixture-context.json')
    need(Path('/.dockerenv').is_file() and os.uname().machine == 'aarch64' and os.getuid() > 0 and
         os.environ.get('CACHY_ASAHI_SESSION_DIAGNOSTICS_FIXTURE') == '1', 'owned native ARM ordinary-user fixture required')
    info = marker.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o644 and
         info.st_nlink == 1 and info.st_size <= 4096 and json.loads(marker.read_bytes()) ==
         dict(scope='OWNED_DISPOSABLE_HEADLESS_SESSION_DIAGNOSTICS', network='NONE', host_service_mounts='NONE'),
         'root-created dedicated headless fixture marker required')
    for root in (Path('/run/dbus'), Path('/run/user') / str(os.getuid())):
        need(not root.exists() or not any(stat.S_ISSOCK(p.lstat().st_mode) for p in root.rglob('*')),
             'service/session endpoint present; headless fixture refuses collection')


def missing_tool_control(module, work):
    """Injected endpoint selection, real exec ENOENT; never call any real tool."""
    absent = work / 'absent-optional-executables'
    absent.mkdir(mode=0o700)
    calls = []
    def missing(argv, seconds, env):
        replacement = absent / Path(argv[0]).name
        need(not replacement.exists(), 'missing executable fixture must stay absent')
        result = module.query([str(replacement), *argv[1:]], seconds, env)
        need(result == ('command-absent', None, b'', b''), 'real missing executable observation differs')
        calls.append(dict(requested_argv=argv, executed_argv=[str(replacement), *argv[1:]], reason=result[0]))
        return result
    context = {scope: (ENV, ()) for scope in ('local', 'hypr', 'wayland', 'user', 'system', 'audio')}
    value = module.collect(dict(execution_context='unknown'), run=missing, read=lambda _: None, environ={}, context=context)
    rows = {row['check']: row for row in value['checks']}
    need(len(calls) == 12 and all(rows[name]['state'] == 'unavailable' and
         rows[name]['reason'] == 'command-absent' for name in SCOPED_CHECKS), 'missing optional tools must remain unavailable')
    need(set(value['physical_checks'].values()) == {'NOT RUN'}, 'missing-tool control cannot establish hardware results')
    return dict(status='PASS_REAL_EXEC_ABSENCE', scope='INJECTED_ENDPOINT_CONTEXT_AND_PRIVATE_EXECUTABLE_MAPPING',
        service_queries='NONE', calls=calls, report=value,
        limitation='Exact installed module with injected endpoint context and mapped absent executables; real session integration remains untested.')


def retire_owned_children(children):
    """Confirm each unreaped direct child before signalling its numeric PID."""
    cleanup_ok = True
    for child in children:
        try:
            reservation = os.waitid(os.P_PID, child, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if reservation is not None and reservation.si_pid != child:
                raise ValueError('unexpected child reservation')
        except (OSError, ValueError):
            cleanup_ok = False
            continue
        # No wait/reap occurs between this ownership observation and the signal.
        if reservation is None:
            try:
                os.kill(child, signal.SIGKILL)
            except OSError:
                cleanup_ok = False
                continue
        end = time.monotonic() + 2
        while True:
            try:
                pid, _ = os.waitpid(child, os.WNOHANG)
            except OSError:
                cleanup_ok = False
                break
            if pid == child:break
            if time.monotonic() >= end:
                cleanup_ok = False
                break
            time.sleep(.01)
    need(cleanup_ok, 'owned fixture descendant cleanup-unverified')


def process_controls(module):
    """Keep orphan retirement observable by making only this fixture a subreaper."""
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'default fixture child policy required')
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    need(libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0 and previous.value == 0,
         'fresh Linux fixture subreaper state required')
    need(libc.prctl(36, 1, 0, 0, 0) == 0, 'private fixture subreaper setup failed')
    events, owned = [], []
    try:
        natural = module.query([sys.executable, '-I', '-B', '-c', 'import os;os.write(1,b"owned-natural")'], 2, ENV)
        need(natural == ('observed', 0, b'owned-natural', b''), 'natural installed child query differs')
        events.append(dict(case='natural', reason=natural[0], returncode=natural[1]))
        code = ('import os,time\nchild=os.fork()\n'
                'if child==0:time.sleep(60)\n'
                'else:os.write(1,(str(os.getpid())+" "+str(child)).encode());os._exit(0)')
        value = module.query([sys.executable, '-I', '-B', '-c', code], 1, ENV)
        need(value[0] == 'timeout' and value[1] == 0 and not value[3], 'inherited-pipe timeout differs')
        fields = value[2].decode().split()
        need(len(fields) == 2 and all(x.isdigit() for x in fields), 'owned leader and descendant PIDs required')
        leader, child = map(int, fields);owned.append(child)
        try:
            os.kill(leader, 0)
        except ProcessLookupError:
            pass
        else:
            raise ValueError('reaped diagnostic leader remains')
        end = time.monotonic() + 2
        while True:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid == child:
                owned.remove(child)
                need(os.waitstatus_to_exitcode(status) == -signal.SIGKILL, 'descendant not killed by owned group cleanup')
                break
            need(time.monotonic() < end, 'owned descendant retirement deadline')
            time.sleep(.01)
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            pass
        else:
            raise ValueError('retired diagnostic descendant remains')
        events.append(dict(case='leader-exit-inherited-pipe', reason=value[0], returncode=value[1],
            leader_absent=True, descendant_reaped=True, descendant_exit=-signal.SIGKILL))
        previous_signal = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            incompatible = module.query(['/private/never-launch'], 1, ENV)
        finally:
            signal.signal(signal.SIGCHLD, previous_signal)
        need(incompatible == ('reaping-policy-incompatible', None, b'', b''), 'incompatible SIGCHLD must skip launch')
        events.append(dict(case='SIGCHLD-ignored', reason=incompatible[0], returncode=None, launch='SKIPPED'))
        return dict(status='PASS_OWNED_INSTALLED_RUNTIME_CHILDREN', events=events, all_owned_children_reaped=True,
            subreaper_scope='THIS_FIXTURE_PROCESS_ONLY')
    finally:
        try:
            retire_owned_children(owned)
        finally:
            need(libc.prctl(36, previous.value, 0, 0, 0) == 0, 'fixture subreaper restoration failed')


def tamper_control(cli, runtime, work, command):
    stage = work / 'private-tamper-fixture'
    program = stage / 'usr/bin' / NAME
    private = stage / 'usr/lib' / NAME / 'session_probe.py'
    program.parent.mkdir(parents=True);private.parent.mkdir(parents=True)
    shutil.copyfile(cli, program);program.chmod(0o755)
    original = runtime.read_bytes()
    events = []
    for change in ('changed', 'missing', 'oversized', 'symlink'):
        if os.path.lexists(private):private.unlink()
        if change == 'changed':private.write_bytes(original + b'\n# private tamper control\n')
        elif change == 'oversized':private.write_bytes(b'x' * 65537)
        elif change == 'symlink':private.symlink_to(runtime)
        value = command(program, ['--help'], 'tamper-' + change, expected=2)
        need(value['stdout_bytes'] == 0 and 'runtime missing or changed' in value['stderr_text'], 'private tamper must refuse before probe')
        events.append(dict(case=change, returncode=value['returncode'], stdout_bytes=0, refusal_before_probe=True))
    private.unlink();private.write_bytes(original);private.chmod(0o644)
    good = command(program, ['--help'], 'tamper-restored', expected=0)
    need('--baseline-sha256' in good['stdout_text'], 'restored private fixture help failed')
    return dict(status='PASS_PRIVATE_TAMPER_REFUSAL', installed_runtime_modified=False, events=events, restored_help_exit=0)


def run(cli, work):
    cli, work = ordinary(cli), ordinary(work)
    info = work.stat()
    need(work.is_dir() and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700 and
         not list(work.iterdir()), 'owned empty 0700 work directory required')
    headless_guard()
    module, runtime = packaged(cli)
    before = {str(p): pin(p.read_bytes()) for p in (cli, runtime)}
    public = {}
    def save(name, value):
        path = work / name
        need(not path.exists() and not path.is_symlink(), 'fresh fixture evidence required')
        raw = value if type(value) is bytes else encoded(value)
        need(len(raw) <= CAP, 'bounded fixture output required')
        with path.open('xb') as stream:stream.write(raw)
        path.chmod(0o600);public[name] = pin(raw)
        return path
    unrelated = work / 'unrelated-cwd';unrelated.mkdir(mode=0o700)
    hostile = work / 'hostile-python';hostile.mkdir(mode=0o700)
    (hostile / 'sitecustomize.py').write_text('raise SystemExit("HOSTILE_PYTHONPATH_EXECUTED")\n')
    (hostile / 'session_probe.py').write_text('raise SystemExit("HOSTILE_PYTHONPATH_EXECUTED")\n')
    commands = []
    def command(program, args, label, expected):
        environment = dict(ENV, HOME='/nonexistent', PYTHONPATH=str(hostile), PYTHONHOME=str(hostile),
            XDG_RUNTIME_DIR='/nonexistent', WAYLAND_DISPLAY='', HYPRLAND_INSTANCE_SIGNATURE='', DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent')
        started = time.monotonic()
        result = subprocess.run([str(program), *args], cwd=unrelated, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        need(len(result.stdout) + len(result.stderr) <= CAP and result.returncode == expected,
            'bounded fixture command exit differs: ' + label)
        need(b'HOSTILE_PYTHONPATH_EXECUTED' not in result.stdout + result.stderr, 'user Python environment affected installed command')
        save(label + '.stdout', result.stdout);save(label + '.stderr', result.stderr)
        row = dict(case=label, argv=[str(program), *args], returncode=result.returncode,
            stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr), elapsed_seconds=time.monotonic()-started,
            cwd=str(unrelated), hostile_python_environment_ignored=True)
        commands.append(row)
        return dict(row, stdout_text=result.stdout.decode(), stderr_text=result.stderr.decode())
    help_result = command(cli, ['--help'], 'help', expected=0)
    need('--execution-context' in help_result['stdout_text'], 'installed help differs')
    actual = command(cli, ['--execution-context', 'virtual'], 'headless', expected=0)
    need(actual['stderr_bytes'] == 0, 'headless CLI emitted unexpected stderr')
    report = json.loads(actual['stdout_text']);checks = assert_headless(report)
    need(report['tool_sha256'] == before[str(runtime)]['sha256'], 'headless report runtime digest differs')
    missing = missing_tool_control(module, work);save('missing-tool-control.json', missing)
    owned = process_controls(module);save('owned-process-control.json', owned)
    tamper = tamper_control(cli, runtime, work, command)
    need(before == {str(p): pin(p.read_bytes()) for p in (cli, runtime)}, 'installed diagnostic payload changed')
    need(not list(runtime.parent.rglob('__pycache__')), 'fixture wrote bytecode under installed runtime')
    save('commands.json', commands)
    return dict(status='PASS_SESSION_DIAGNOSTICS_HEADLESS_CONTROLS', architecture=os.uname().machine,
        page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(), actual_cli_headless=True,
        actual_cli_report=dict(path='headless.stdout', **public['headless.stdout']), headless_checks=checks,
        missing_tool_control=missing, tamper_refusal=tamper, owned_process_cleanup=owned,
        installed_payload_preserved=True, unrelated_cwd=True, hostile_python_environment_ignored=True,
        report_capture='USER_OWNED_STDOUT_REDIRECTION_EQUIVALENT', public_evidence=public,
        physical='NOT_RUN', performance='NOT_MEASURED', service_queries='NONE')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli', type=Path, required=True);p.add_argument('--work', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True);a = p.parse_args()
    value = run(a.cli, a.work)
    report = ordinary(a.report)
    need(report.parent == a.work and not report.exists(), 'fresh work-local fixture report required')
    with report.open('xb') as stream:stream.write(encoded(value))
    report.chmod(0o600)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':main()
