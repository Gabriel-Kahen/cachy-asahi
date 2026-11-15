#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep the owned session leader until fixed private GUI children retire naturally."""
import hashlib, importlib.util, json, os, subprocess, sys, time
from pathlib import Path

PRIVATE = Path('/home/builder/UI-runtime')

def argv():
    return ['/usr/bin/dbus-run-session', '--', '/usr/bin/xvfb-run', '-a', '-e',
            str(PRIVATE/'xvfb.log'), '-s',
            '-screen 0 1024x768x24 -nolisten tcp -extension GLX',
            '/usr/bin/python3', '-I', '-B', '/usr/local/libexec/ui-gui-probe.py']

def save(name, raw):
    assert name in ('session-lifecycle.json', 'session.stdout') and len(raw) <= 128*1024
    with (PRIVATE/name).open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(PRIVATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def settle(owned, leader, deadline, observations):
    """Read only; no signals, waits, helper changes or renewed deadline."""
    empty = 0
    while time.monotonic() < deadline:
        rows = owned._members(leader, deadline)
        mine = [r for r in rows if r[0] == leader]
        assert len(mine) == 1 and mine[0][2] not in (b'Z', b'X'), 'reserved session leader absent'
        if observations:
            assert mine[0][1] == observations[0]['leader_start_ticks'], 'session leader identity changed'
        other = sorted(r for r in rows if r[0] != leader)
        assert len(rows) <= 64, 'private GUI process count bound'
        sample = {'leader_start_ticks': mine[0][1],
                  'members': [{'pid': pid, 'start_ticks': ticks, 'state': state.decode('ascii')}
                              for pid, ticks, state in sorted(rows)]}
        # Retain each changed census plus the two final leader-only observations.
        if not observations or sample != observations[-1] or not other:
            assert len(observations) < 128, 'private GUI census receipt bound'
            observations.append(sample)
        empty = empty + 1 if not other else 0
        if empty == 2: return
        time.sleep(.01)
    raise TimeoutError('private GUI original group/session did not retire naturally')

def remaining(owned, leader):
    rows = owned._members(leader, time.monotonic()+1)
    assert len(rows) <= 64, 'private GUI process count bound'
    found = []
    for pid, ticks, state in sorted(rows):
        try:
            before = owned._stat(pid)
            with open('/proc/'+str(pid)+'/comm', 'rb') as stream: name = stream.read(65)
            after = owned._stat(pid)
        except (FileNotFoundError, ProcessLookupError): continue
        if before[0] != pid or before[2:4] != (leader, leader) or before[4] != ticks or before != after:
            continue
        assert len(name) <= 64, 'bounded process name required'
        found.append({'pid': pid, 'start_ticks': ticks, 'state': state.decode('ascii'),
                      'comm': name.decode('utf-8', errors='backslashreplace').rstrip('\n')})
    return found

def main():
    assert __debug__ and sys.flags.isolated and os.geteuid() == 1000
    assert os.getpid() == os.getpgrp() == os.getsid(0), 'fresh reserved session leader required'
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location('ui_owned_process', '/usr/local/libexec/ui-owned-process.py')
    owned = importlib.util.module_from_spec(spec); spec.loader.exec_module(owned); owned.prepare()
    report = {'status': 'HOLD', 'leader_pid': os.getpid(), 'argv': argv(),
              'scope': 'original process group/session only; no escaped-child absence claim',
              'censuses': []}
    output = b''
    try:
        # No new session here: the outer frozen supervisor owns this wrapper's
        # group. Direct wait ownership of the launcher is transferred only once.
        child = subprocess.Popen(argv(), cwd='/', env=dict(os.environ), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=None)
        report['launcher_pid'] = child.pid
        result = owned.supervise(child, cap=82, retirement=3, grace=.5,
                                 group=False, max_output=128*1024)
        output = result.pop('output'); report['launcher_retirement'] = result
        save('session.stdout', output)
        report['stdout'] = {'bytes': len(output), 'sha256': hashlib.sha256(output).hexdigest()}
        report['members_after_launcher_retirement'] = remaining(owned, os.getpid())
        assert result['passed'] and result['signals'] == [], 'private GUI launcher retirement refused'
        settle(owned, os.getpid(), time.monotonic()+3, report['censuses'])
        report.update(status='PASS_NATURAL_PRIVATE_GUI_SESSION_CLOSE', leader_only_twice=True)
    except BaseException as exc:
        report['failure'] = {'category': type(exc).__name__, 'message': str(exc)[:256]}
    finally:
        save('session-lifecycle.json', (json.dumps(report, sort_keys=True)+'\n').encode())
    if report['status'] != 'PASS_NATURAL_PRIVATE_GUI_SESSION_CLOSE': return 1
    sys.stdout.buffer.write(output); sys.stdout.buffer.flush()
    return 0

if __name__ == '__main__': raise SystemExit(main())
