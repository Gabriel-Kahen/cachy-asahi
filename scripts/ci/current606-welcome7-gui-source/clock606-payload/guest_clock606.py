# SPDX-License-Identifier: MIT
"""Seed and verify the disposable 16 KiB systemd clock from its controller."""
from datetime import datetime
import os
from pathlib import Path
import re
import stat
import sys
import time

SECOND = 1_000_000_000
SLACK = 5 * SECOND
MARKER = 'usr/lib/clock-epoch'
RECEIPT = 'usr/local/share/desktop574/guest-clock.txt'
ENV = 'CACHY_ASAHI_GUI_CLOCK_SEED'
EVENT = 'guest_clock_handoff_DATA'
BOOT = r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sample():
    start = time.monotonic_ns()
    wall = time.time_ns()
    end = time.monotonic_ns()
    need(0 <= end - start <= SECOND, 'bounded controller wall/monotonic sample')
    return dict(realtime_ns=wall, monotonic_ns=end)


def token(seed):
    need(type(seed) is dict and set(seed) == {'realtime_ns','monotonic_ns','nonce'}
         and all(type(seed[k]) is int for k in ('realtime_ns','monotonic_ns')), 'exact controller clock seed')
    value = f"{seed['realtime_ns']}:{seed['monotonic_ns']}:{seed['nonce']}"
    need(re.fullmatch(r'[1-8][0-9]{18}:[1-9][0-9]{0,18}:[a-f0-9]{32}',value),
         'bounded controller clock seed fields')
    return value


def untoken(value):
    parts = value.split(':')
    need(len(parts) == 3 and all(re.fullmatch('[0-9]{1,19}',x) for x in parts[:2]), 'clock seed token')
    seed = dict(realtime_ns=int(parts[0]),monotonic_ns=int(parts[1]),nonce=parts[2])
    need(token(seed) == value, 'canonical controller clock seed')
    return seed


def leaf(root,name):
    need(root.is_absolute() and root.is_dir() and root == root.resolve(), 'ordinary fixture root')
    path = root/name
    need(path.parent.is_dir() and path.parent.resolve() == path.parent, 'ordinary fixture clock path')
    return path


def stage(root,seed):
    """Add the systemd epoch marker inside the already guarded disposable image."""
    encoded = token(seed)
    epoch = seed['realtime_ns'] // SECOND
    marker, receipt = (leaf(root,n) for n in (MARKER,RECEIPT))
    need(not any(p.exists() or p.is_symlink() for p in (marker,receipt)), 'new fixture-only clock files')
    with marker.open('xb'):
        pass
    marker.chmod(0o644)
    os.utime(marker,ns=(epoch*SECOND,epoch*SECOND))
    with receipt.open('x') as out:
        out.write(encoded+'\n')
    receipt.chmod(0o644)


def guest(root,boot_id,clock=time,owner=0):
    """Read PID1's clock result in the guarded guest before runtime pacman."""
    marker, receipt = (leaf(root,n) for n in (MARKER,RECEIPT))
    for path,cap in ((marker,0),(receipt,96)):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == owner
             and stat.S_IMODE(info.st_mode) == 0o644 and info.st_size <= cap,
             'ordinary root-owned staged clock state')
    raw = receipt.read_text()
    need(raw.endswith('\n'), 'one complete fixture clock seed')
    seed = untoken(raw[:-1])
    epoch = seed['realtime_ns']//SECOND
    wall, mono = clock.time_ns(), clock.monotonic_ns()
    need(marker.stat().st_mtime_ns == epoch*SECOND and wall >= epoch*SECOND and mono > 0,
         'systemd must adopt the hosted clock floor before guest ALPM')
    need(re.fullmatch(BOOT,boot_id), 'same guest boot ID')
    return dict(seed=seed,marker_epoch=epoch,guest_realtime_ns=wall,guest_monotonic_ns=mono,boot_id=boot_id)


def join(seed,event,received):
    token(seed)
    need(type(event) is dict and set(event) == {'event','seed','marker_epoch','guest_realtime_ns',
                                              'guest_monotonic_ns','boot_id'}
         and event['event'] == EVENT and event['seed'] == seed, 'one same-fixture guest clock event')
    need(re.fullmatch(BOOT,event['boot_id']), 'guest clock boot ID')
    need(set(received) == {'realtime_ns','monotonic_ns'}
         and all(type(v) is int for v in (*received.values(),event['marker_epoch'],
                                         event['guest_realtime_ns'],event['guest_monotonic_ns'])),
         'exact integer clock observations')
    epoch = seed['realtime_ns']//SECOND
    controller_elapsed = received['monotonic_ns'] - seed['monotonic_ns']
    host_elapsed = received['realtime_ns'] - seed['realtime_ns']
    guest_elapsed = event['guest_realtime_ns'] - epoch*SECOND
    need(event['marker_epoch'] == epoch and controller_elapsed >= 0 and
         abs(host_elapsed - controller_elapsed) <= SLACK and
         0 <= guest_elapsed <= controller_elapsed + SLACK and
         0 < event['guest_monotonic_ns'] <= controller_elapsed + SLACK,
         'same-run controller wall/monotonic and guest boot clock bounds')
    return dict(seed=seed,received=received,observation=event)


def verify(report,own,run=None):
    events = report['events']
    rows = [row for row in events if row.get('event') == EVENT]
    probes = [row for row in events if row.get('event') == 'nomops_userspace']
    need(len(rows) == 1 and len(probes) == 2
         and all(row['boot_id'] == rows[0]['boot_id'] for row in probes)
         and events.index(rows[0]) < events.index(probes[0]), 'one boot clock event before root ALPM and joined NOMOPS')
    receipt = report['guest_clock_handoff']
    seed, received = receipt['seed'], receipt['received']
    need(receipt == join(seed,rows[0],received), 'original controller and guest clock receipt join')
    need(own['started_monotonic']*SECOND <= seed['monotonic_ns'] <= received['monotonic_ns']
         <= own['owner_deadline']*SECOND, 'clock observations inside the source-owned hosted monotonic window')
    if run is not None:
        def epoch(name):
            stamp = run[name]
            need(type(stamp) is str and stamp.endswith('Z'), 'original hosted UTC timestamp')
            return int(datetime.fromisoformat(stamp).timestamp())*SECOND
        need(epoch('run_started_at') <= seed['realtime_ns'] <= received['realtime_ns']
             < epoch('updated_at')+SECOND, 'clock handoff inside original hosted attempt UTC timestamps')
    return receipt


def apply(out,pin,once):
    """Patch the exact rendered generic16k runner before its whole-map seal."""
    changes = {}

    def edit(name,edits):
        path = out/name
        before = path.read_bytes()
        body = before.decode()
        for old,new in edits:
            body = once(body,old,new)
        after = body.encode()
        if name.endswith('.py'):
            compile(after,name,'exec')
        path.write_bytes(after)
        changes[name] = dict(before=pin(before),after=pin(after))

    edit('desktop574_fixture.sh', [
        ('allocated=$(du -sx --block-size=1 "$root" | cut -f1)',
         'cp /runner/guest_clock606.py "$root/usr/local/share/desktop574/"\n'
         'python3 -I -B /runner/guest_clock606.py "$root" "${CACHY_ASAHI_GUI_CLOCK_SEED:?}"\n'
         'allocated=$(du -sx --block-size=1 "$root" | cut -f1)')])

    edit('base_guest.py', [
        ("        current_nomops('root')\n        actual = command",
         """        import importlib.util
        clock_spec=importlib.util.spec_from_file_location('guest_clock606',SHARE/'guest_clock606.py')
        clock=importlib.util.module_from_spec(clock_spec)
        clock_spec.loader.exec_module(clock)
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        emit(clock.EVENT,**clock.guest(Path('/'),boot_id))
        current_nomops('root')
        actual = command""")])

    edit('desktop574_runtime.py', [
        ("        cmd[-2:-2] = ['--env=CACHY_DESKTOP574_FIXTURE=1']",
         """        clock = load('guest_clock606', runner/'guest_clock606.py')
        clock_seed = dict(clock.sample(), nonce=os.urandom(16).hex())
        cmd[-2:-2] = ['--env=CACHY_DESKTOP574_FIXTURE=1', '--env='+clock.ENV+'='+clock.token(clock_seed)]"""),
        ("                report['events'].append(event)\n                if event.get('event') == 'frame_ready':",
         """                report['events'].append(event)
                if event.get('event') == clock.EVENT:
                    require('guest_clock_handoff' not in report, 'one guest clock handoff only')
                    report['guest_clock_handoff'] = clock.join(clock_seed,event,clock.sample())
                if event.get('event') == 'frame_ready':""")])
    path = out/'guest_clock606.py'
    need(not path.exists(), 'fresh emitted guest clock helper')
    raw = Path(__file__).read_bytes()
    path.write_bytes(raw)
    changes[path.name] = dict(after=pin(raw))
    return changes


if __name__ == '__main__':
    need(len(sys.argv) == 3, 'one guarded staged fixture root and controller clock seed')
    stage(Path(sys.argv[1]),untoken(sys.argv[2]))
