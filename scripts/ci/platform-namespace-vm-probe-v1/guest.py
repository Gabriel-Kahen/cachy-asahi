# SPDX-License-Identifier: MIT
"""Marked diskless guest entry; never a host namespace probe."""
import base64
import ctypes
import os
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import witness as W
import owned_command as O


def proc(name, cap=8192):
    with open(name, 'rb') as stream:
        raw = stream.read(cap + 1)
    C.need(len(raw) <= cap, 'bounded fixed proc evidence')
    return raw.decode('ascii')


def guard(nonce, release, root=False, inner=False):
    C.need(re.fullmatch('[0-9a-f]{32}', nonce or '') and re.fullmatch('[A-Za-z0-9_.+-]{1,128}', release or ''),
           'literal guest identity')
    C.need(os.uname().machine == 'aarch64' and os.uname().release == release and
           os.sysconf('SC_PAGE_SIZE') == 16384 and os.getpid() != 1 and
           ('namespace_vm_probe_v1=' + nonce) in proc('/proc/cmdline').split(), 'marked actual generic16K guest only')
    if not inner:
        C.need(os.getuid() == os.geteuid() == (0 if root else 23001), 'fixed guest bootstrap or probe UID')


def observe():
    status = dict(line.split(':', 1) for line in proc('/proc/self/status').splitlines() if ':' in line)
    maps = {}
    for key in ('uid_map', 'gid_map'):
        lines = proc('/proc/self/' + key, 1024).splitlines()
        C.need(1 <= len(lines) <= 16 and all(re.fullmatch(r'\s*[0-9]+\s+[0-9]+\s+[0-9]+\s*', x) for x in lines),
               'complete actual ID maps')
        maps[key] = [list(map(int, x.split())) for x in lines]
    return dict(machine=os.uname().machine, kernel=os.uname().release, page_size=os.sysconf('SC_PAGE_SIZE'),
                uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(), groups=os.getgroups(),
                capabilities={k: int(status[k].strip(), 16) for k in C.CAPS},
                NoNewPrivs=int(status['NoNewPrivs'].strip()),
                namespaces={k: os.readlink('/proc/self/ns/' + k) for k in C.NAMESPACES},
                pid=os.getpid(), pgid=os.getpgid(0), sid=os.getsid(0), **maps)


def emit(kind, nonce, value):
    raw = C.encoded(value)
    C.need(len(raw) <= C.BOUNDS['report_bytes'], 'guest frame bound')
    print(kind + ' ' + nonce + ' ' + base64.b64encode(raw).decode('ascii'), flush=True)


def frame(raw, kind, nonce):
    prefix = (kind + ' ' + nonce + ' ').encode()
    lines = [x for x in raw.splitlines() if x.startswith((kind + ' ').encode())]
    C.need(len(lines) == 1 and lines[0].startswith(prefix), 'one exact nonce child frame')
    value = base64.b64decode(lines[0][len(prefix):], validate=True)
    C.need(len(value) <= C.BOUNDS['report_bytes'], 'child frame bound')
    return C.decode(value)


def drop_identity(work):
    work.mkdir(mode=0o700)
    os.chown(work, 23001, 23001)
    libc = ctypes.CDLL(None, use_errno=True)
    C.need(libc.prctl(38, 1, 0, 0, 0) == 0, 'set guest no-new-privileges')
    for bit in range(64):
        if libc.prctl(24, bit, 0, 0, 0) != 0:
            C.need(ctypes.get_errno() == 22, 'drop guest bounding capability')
    C.need(libc.prctl(47, 4, 0, 0, 0) == 0, 'clear guest ambient capabilities')
    os.setgroups([])
    os.setgid(23001)
    os.setuid(23001)


def main(nonce, release):
    guard(nonce, release, root=True)
    bootstrap = dict(uid=os.getuid(), gid=os.getgid(), groups=os.getgroups(), pid=os.getpid())
    helper = Path('/probe/runner.py')
    selection = C.decode(C.read(Path('/probe/selection.json')))
    C.need(C.pin(C.read(helper)) == selection['runner'], 'exact trusted guest supervisor')
    work = Path('/tmp/namespace-vm-probe')
    drop_identity(work)
    before = observe()
    C.context_valid(before, release)
    sender, receiver = W.channel()
    observation, observation_error = None, None
    try:
        try:
            row, out, err, failure = O.run_command(C.WRAPPER + [nonce, release], work, C.ENV,
                                                  C.BOUNDS['command_seconds'], C.BOUNDS['command_output_bytes'])
        finally:
            sender.close()
        try:
            observation = W.receive(receiver)
        except (ValueError, OSError, KeyError, TypeError) as error:
            observation_error = type(error).__name__
    finally:
        sender.close()
        receiver.close()
    report = dict(schema=1, operation=C.OPERATION, nonce=nonce, bootstrap=bootstrap, before=before,
                  after=observe(), command=row, bwrap_argv=C.BWRAP + [nonce, release], exec_context=None,
                  inside=None, inner_observation=observation, inner_observation_error=observation_error, command_error=None if failure is None else type(failure).__name__,
                  stderr=C.pin(err), stderr_preview=C.stderr_preview(err), bwrap=selection['bwrap'],
                  numeric_unshare_errno=None, generic_emulated_16K_only=True,
                  hardware='NOT_RUN', namespace_cause='UNKNOWN_NOT_INFERRED_FROM_TEXT')
    report['status'] = 'PROBE_EXECUTION_OR_RETIREMENT_FAILED'
    try:
        report['exec_context'] = frame(out, 'NSVM_EXEC_V1', nonce)
        C.context_valid(report['exec_context'], release)
        if failure is None and row['group_absence_verified']:
            if row['exit_code'] == 0:
                inside = frame(out, 'NSVM_INSIDE_V1', nonce)
                C.context_valid(inside, release, outer=False, evidence=observation, observer=before, nonce=nonce)
                report['inside'] = inside
                C.need(len(out.splitlines()) == 2 and out.splitlines()[0].startswith(b'NSVM_EXEC_V1 '),
                       'only exact exec then inside frames')
                report['status'] = 'OBSERVED_UNPRIVILEGED_BWRAP_SUCCESS'
            elif row['exit_code'] == 1:
                C.need(len(out.splitlines()) == 1, 'only exec frame for observed nonzero')
                report['status'] = 'OBSERVED_BWRAP_NONZERO'
    except (ValueError, KeyError, TypeError):
        report.update(inside=None, inner_observation=observation, inner_observation_error=observation_error, command_error='CHILD_FRAME_IDENTITY_OR_KERNEL_CREDENTIAL_REFUSED')
    removed = False
    if row['group_absence_verified']:
        C.need(not any(work.iterdir()), 'unexpected guest work retained')
        work.rmdir()
        removed = True
    report['cleanup'] = dict(group_absence_verified=row['group_absence_verified'], work_removed=removed,
                             PID1_shutdown='PENDING_OUTER_UART_AND_QEMU_JOIN')
    try:
        C.validate_report(report, nonce, release)
    except (ValueError, KeyError, TypeError):
        report.update(status='PROBE_EXECUTION_OR_RETIREMENT_FAILED', inside=None,
                      command_error='GUEST_REPORT_REFUSED')
    emit('NSVM_REPORT_V1', nonce, report)
    return 0 if report['status'].startswith('OBSERVED_') else 1


if __name__ == '__main__':
    C.need(len(sys.argv) == 3, 'two explicit guest selectors')
    raise SystemExit(main(*sys.argv[1:]))
