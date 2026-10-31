#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute one pinned v2 adopted-child control; ordinary supervisor PASS is insufficient."""
import argparse
import base64
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import stat
import subprocess
import sys
import threading
import time
import types

CAP, RETIREMENT, GRACE = 8.0, 2.0, .1
OUTPUT_CAP, RESULT_CAP = 4096, 128 * 1024


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def read_source(path, cap):
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical ordinary source path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap, 'bounded single-link source')
        body = bytearray()
        while len(body) <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(body) == before.st_size and key(before) == key(os.fstat(fd)) == key(path.lstat()), 'stable complete source bytes')
        return bytes(body)
    finally:
        os.close(fd)


def save(path, value):
    body = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(len(body) <= RESULT_CAP, 'bounded complete receipt; overflow never qualifies')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def qualify(row, ledger, leader, owner):
    need(type(row) is dict and row['passed'] is True and row['exit'] == 0 and row['reaped'] is True
         and row['ownership'] == 'REAPED' and row['timeout'] is False and row['signals'] == []
         and row['error'] is None and row['output_complete'] is True and 0 <= row['seconds'] < CAP
         and row['group_census'] == 'RESERVED_LEADER_ONLY', 'strict actual runtime completion required')
    need(ledger['schema'] == 1 and ledger['status'] == 'ONE_OWN_ZERO_ZOMBIE_LEFT_FOR_ADOPTION'
         and ledger['leader'] == leader and ledger['owner'] == owner and ledger['fixture_forks'] == 1
         and ledger['fixture_consuming_waits'] == 0, 'exact controlled one-fork fixture ledger')
    child = ledger['child']
    need(type(child['pid']) is int and child['pid'] not in (leader, owner) and child['pid'] > 0
         and type(child['start_ticks']) is int and child['start_ticks'] > 0
         and child['state'] == 'Z' and child['ppid'] == leader
         and child['group'] == child['session'] == leader, 'fixture-reserved zombie identity')
    need(ledger['fixture_waitid'] == dict(pid=child['pid'], code='CLD_EXITED', status=0), 'fixture kept its zero-exit child waitable')
    group = row['group_retirement']
    need(type(group) is dict and group['phase'] == 'PRE_REAP' and group['wait_owner_pid'] == owner
         and group['reserved_leader']['pid'] == leader and group['member_count'] == 1
         and group['truncated'] is False and len(group['members']) == 1, 'fresh final reserved-leader-only runtime census')
    only = group['members'][0]
    need(only['pid'] == only['group'] == only['session'] == leader and only['state'] == 'Z'
         and only['ppid'] == owner and only['parent_relation'] == 'WAIT_OWNER_PID'
         and only['start_ticks'] == group['reserved_leader']['start_ticks'], 'exact final leader PID/start/group/session/parent')
    # All following checks inspect returned DATA only. No process API is called.
    adopted = group.get('adopted_child')
    need(type(adopted) is dict, 'adopted branch NOT EXERCISED: ordinary success cannot pass')
    need(adopted['schema'] == 1 and adopted['status'] == 'QUALIFIED_ONE_ADOPTED_CHILD_REAPED'
         and adopted['initial_member_count'] == 2 and adopted['initial_scan_complete'] is True
         and adopted['refusal'] == 'NONE', 'actual one-adopted-child branch qualification')
    candidate = adopted['candidate']
    expected = dict(child, ppid=owner, parent_relation='WAIT_OWNER_PID')
    need(candidate == expected, 'same actual adopted PID/start/group/session and new owner PPID')
    need(adopted['waitid'] == dict(observed=True, pid=child['pid'], code='CLD_EXITED', status=0)
         and adopted['identity_reverified'] is True and adopted['leader_reserved_before_reap'] is True,
         'runtime actual WNOWAIT-zero/identity/leader reservation receipts')
    need(adopted['raw_reap'] == dict(attempted=True, pid=child['pid'], exit=0, status_matches=True)
         and adopted['ownership'] == 'REAPED' and adopted['target_queries_closed'] is True
         and adopted['before_leader_reap'] is True and adopted['final_scan_complete'] is True
         and adopted['final_census'] == 'RESERVED_LEADER_ONLY', 'actual raw-zero reap/authority closure/fresh final scan')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--runtime-sha256', required=True)
    parser.add_argument('--runtime-bytes', type=int, required=True)
    parser.add_argument('--source-label', required=True, help='External source provenance label; no Git operation is performed')
    parser.add_argument('--execution-context', choices=('host', 'native-runner'), required=True, help='Caller label; native/hardware provenance remains externally qualified')
    parser.add_argument('--output', type=Path, required=True, help='Fresh absolute output directory')
    args = parser.parse_args()
    need(__debug__ and threading.current_thread() is threading.main_thread() and threading.active_count() == 1, 'assertion-enabled exclusive main-thread owner')
    need(platform.system() == 'Linux' and hasattr(os, 'fork') and hasattr(os, 'WNOWAIT') and hasattr(os, 'memfd_create'), 'Linux fork/WNOWAIT/sealed-memfd prerequisites; no fallback')
    need(re.fullmatch('[0-9a-f]{64}', args.runtime_sha256) and 0 < args.runtime_bytes <= 128 * 1024, 'explicit bounded exact runtime pin')
    need(0 < len(args.source_label) <= 160 and all(32 <= ord(c) < 127 for c in args.source_label), 'finite caller source label')
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'exclusive default SIGCHLD required')
    raw = read_source(args.runtime, args.runtime_bytes)
    need(pin(raw) == dict(bytes=args.runtime_bytes, sha256=args.runtime_sha256), 'exact selected runtime source in memory')
    fixture_path = Path(__file__).resolve().with_name('owned_process_v2_adoption_fixture.py')
    fixture = read_source(fixture_path, 16 * 1024)
    output = args.output
    need(output.is_absolute() and output == output.resolve() and output.parent.is_dir()
         and not os.path.lexists(output) and not any(p.is_symlink() for p in output.parents), 'fresh canonical output directory; no replay')
    for protected in (args.runtime.parent, fixture_path.parent):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output), 'output outside runtime/control source roots')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    runtime = types.ModuleType('_exact_selected_v2_runtime')
    runtime.__file__ = str(args.runtime)
    result = None
    error = None
    ledger = None
    mask = None
    descriptor = None
    subreaper_changed = False
    previous = ctypes.c_int()
    started = time.monotonic()
    metadata = dict(runtime=pin(raw), runtime_path=str(args.runtime), fixture=pin(fixture),
                    source_label=args.source_label, caller_execution_context=args.execution_context,
                    context_provenance='EXTERNAL; CLI does not attest native/M2 provenance',
                    interpreter=dict(executable=sys.executable, version=sys.version, implementation=platform.python_implementation()),
                    architecture=platform.machine(), page_size=os.sysconf('SC_PAGESIZE'), owner=os.getpid(),
                    bounds=dict(runtime_seconds=CAP, retirement_seconds=RETIREMENT, grace_seconds=GRACE,
                                fixture_wait_seconds=2, output_bytes=OUTPUT_CAP, result_bytes=RESULT_CAP),
                    inherited_FSIZE=list(resource.getrlimit(resource.RLIMIT_FSIZE)))
    save(output / 'intent.json', dict(metadata, once=True, retry=False, acceptance=False))
    try:
        # Trusted caller-selected Source only; downloaded evidence is never imported.
        exec(compile(raw, str(args.runtime), 'exec'), runtime.__dict__)
        need(callable(runtime.prepare) and callable(runtime.supervise), 'existing prepare/supervise API required')
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        prctl.restype = ctypes.c_int
        need(prctl(37, ctypes.addressof(previous), 0, 0, 0) == 0 and previous.value == 0, 'fresh isolated owner must not already be subreaper')
        need(prctl(36, 1, 0, 0, 0) == 0, 'enable only this isolated control owner as subreaper')
        subreaper_changed = True
        observed = ctypes.c_int()
        need(prctl(37, ctypes.addressof(observed), 0, 0, 0) == 0 and observed.value == 1, 'actual subreaper prerequisite')
        descriptor = os.memfd_create('owned-v2-one-fork-fixture', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        need(os.write(descriptor, fixture) == len(fixture), 'whole explicit fixture Source')
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        runtime.prepare()
        # Preserve an atomic caller handoff against ordinary interrupts. The
        # trusted runtime's own8s cap remains active; no external child callback.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        def child_mask():
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        child = subprocess.Popen([str(Path(sys.executable).resolve()), '-I', '-B', '-S', '/proc/self/fd/' + str(descriptor)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, pass_fds=(descriptor,), preexec_fn=child_mask)
        leader = child.pid
        # Exact wait and pipe ownership transfers once. Never poll/wait/signal
        # this Popen or either numeric PID after this call, including on refusal.
        result = runtime.supervise(child, cap=CAP, retirement=RETIREMENT, grace=GRACE,
                                   group=True, streams=(child.stdout, child.stderr), max_output=OUTPUT_CAP)
        need(type(result) is dict and type(result.get('output')) is bytes and len(result['output']) <= OUTPUT_CAP, 'bounded original runtime output')
        body = result['output']
        ledger = json.loads(body)
        need(body == (json.dumps(ledger, sort_keys=True, separators=(',', ':')) + '\n').encode(), 'one canonical complete fixture ledger; no extra output')
        qualify(result, ledger, leader, metadata['owner'])
    except BaseException as exc:
        error = dict(type=type(exc).__name__, message=str(exc)[:1000])
    finally:
        # No target-PID operation follows transfer/consumption/ECHILD. Only local
        # descriptors, our own subreaper flag and returned DATA are handled here.
        if descriptor is not None:
            os.close(descriptor)
        restored = not subreaper_changed or prctl(36, previous.value, 0, 0, 0) == 0
        if not restored and error is None:
            error = dict(type='SubreaperRestoreError', message='own subreaper flag restoration failed')
        serial = None
        if result is not None:
            serial = dict(result)
            value = serial.get('output')
            if type(value) is bytes:
                serial['output'] = dict(encoding='base64', **pin(value), base64=base64.b64encode(value).decode('ascii'))
        try:
            encoded = (json.dumps(serial, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
            if len(encoded) > RESULT_CAP - 1024:
                error = dict(type='RuntimeResultOverflow', message='complete runtime result exceeds128KiB; no partial qualification')
                save(output / 'runtime-result.json', dict(status='REFUSED_OVERSIZE_RUNTIME_RESULT', complete_result_pin=pin(encoded)))
            else:
                # Compact complete encoding retains room for the small outer label.
                fd = os.open(output / 'runtime-result.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            outcome = dict(metadata, status='PASS_ACTUAL_RUNTIME_ADOPTED_ZERO_EXIT_CHILD_CONTROL' if error is None else 'FAIL_ACTUAL_RUNTIME_ADOPTED_ZERO_EXIT_CHILD_CONTROL',
                           fixture_ledger=ledger, runtime_result_pin=pin((output / 'runtime-result.json').read_bytes()),
                           error=error, subreaper_previous=previous.value, subreaper_restored=restored,
                           seconds=time.monotonic() - started, process_followups_after_transfer=0,
                           cleanup_authority='EXCLUSIVELY_SELECTED_RUNTIME; UNKNOWN_IF_ITS_RECEIPTS_REFUSE',
                           scope='CONTROL_PROCESS_ONLY; NO_NATIVE_COMPONENT_M2_PERFORMANCE_OR_RELEASE_ACCEPTANCE', acceptance=False)
            save(output / 'result.json', outcome)
            print(json.dumps(dict(status=outcome['status'], runtime=metadata['runtime'], output=str(output), error=error), sort_keys=True))
        finally:
            if mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    return int(error is not None)


if __name__ == '__main__':
    raise SystemExit(main())
