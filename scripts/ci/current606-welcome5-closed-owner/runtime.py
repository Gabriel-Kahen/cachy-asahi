# SPDX-License-Identifier: MIT
"""Post-capture actors for the closed606 owner; no standalone admission route."""
import os
import re
import stat
import time
from pathlib import Path

CAPS = {
    'finalize': ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'SETFCAP'),
    'dispose': ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'SETFCAP'),
    'worker': ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'SETUID', 'SETGID', 'SYS_CHROOT', 'SETFCAP'),
}
SECONDS = {'finalize': 600, 'worker': 1800, 'dispose': 120}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute owned path required')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink in owned path')
    return path


def measurement_lease(path):
    """Called BEFORE capture changes ownership; keep this small lease in memory."""
    path = ordinary(path)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
         stat.S_IMODE(info.st_mode) == 0o700 and not any(path.iterdir()),
         'fresh caller-owned0700 measurement directory')
    return dict(identity=[info.st_dev, info.st_ino], uid=info.st_uid,
                gid=info.st_gid, mode=0o700)


def argv(role, image, nonce, paths):
    """The actual launch consumes these exact rows, also checked by worker guards."""
    need(role in CAPS and re.fullmatch('sha256:[0-9a-f]{64}', image or ''), 'fixed actor/image')
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'exact independent nonce')
    expected = {'runner', 'seed', 'proof', 'work', 'out'} if role == 'worker' else {'runner', 'measurement', 'selection', 'out'}
    need(type(paths) is dict and set(paths) == expected, 'finite phase mount sources')
    # Do not traverse root-owned measurement descendants from the ordinary host.
    # Their backing identity/maps are checked inside the actor. The host passes
    # only paths derived from its earlier measurement lease, never runtime data.
    for path in paths.values():
        need(isinstance(path, Path) and path.is_absolute() and '..' not in path.parts and
             not any(c in str(path) for c in ',\n\r'), 'literal absolute mount source')
    mounts = ([(paths['runner'], '/runner', True), (paths['seed'], '/seed', True),
               (paths['proof'], '/bridge-proof', True), (paths['work'], '/work', False),
               (paths['out'], '/out', False)] if role == 'worker' else
              [(paths['runner'], '/runner', True), (paths['measurement'], '/measurement', False),
               (paths['selection'], '/bridge-input', True), (paths['out'], '/out', False)])
    command = ['docker', 'run', '--name', 'cachy-asahi-welcome606-' + role + '-' + nonce,
               '--pull=never', '--platform=linux/arm64', '--network=none', '--cap-drop=ALL',
               '--security-opt=no-new-privileges', '--pids-limit=512', '--memory=8g',
               '--cpus=4', '--user=0:0', '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=2g',
               '--env=' + ('CAA_CURRENT606_WELCOME5_COPY=' if role == 'worker' else 'CAA_CURRENT606_BRIDGE=') + nonce]
    command += ['--cap-add=' + cap for cap in CAPS[role]]
    for source, target, readonly in mounts:
        command += ['--mount', 'type=bind,src=' + str(source) + ',dst=' + target + (',readonly' if readonly else '')]
    command += ['--entrypoint=/usr/bin/python3', image, '-B']
    if role == 'worker':
        command += ['/runner/scripts/ci/current606-welcome5-copy/worker.py',
                    '--selection', '/runner/selection.json', '--handoff', '/runner/handoff.json',
                    '--nonce', nonce, '--output', '/out/result.json']
    else:
        command += ['/runner/bridge/scripts/ci/current606-welcome5-source-bridge/bridge.py', role,
                    '--selection', '/bridge-input/selection.json', '--code', '/runner/bridge-code', '--nonce', nonce]
    return command


def group_absent(pid):
    need(type(pid) is int and pid > 1, 'recorded owned process group')
    try:
        os.killpg(pid, 0)  # Observation only; never signal a reaped numeric PID.
    except ProcessLookupError:
        return True
    raise ValueError('prior owned process group still present')


class AfterCapture:
    """Use held Containers/LoggedProcess APIs; preserve the original6600s owner.

    The enclosing source-pinned owner verifies its selection before constructing
    this object. This helper cannot authorize a source, create a producer, build
    packages or turn an actor report into native acceptance.
    """
    def __init__(self, *, owned, common, env, image, nonce, output, owner_deadline):
        need(owned.image == image and re.fullmatch('[0-9a-f]{32}', nonce or ''), 'owned image/nonce')
        need(time.monotonic() < owner_deadline, 'original outer deadline exhausted')
        self.owned, self.common, self.env = owned, common, env
        self.image, self.nonce, self.output = image, nonce, ordinary(output)
        self.deadline, self.phase, self.events = owner_deadline, 'captured', []

    def retire_original(self, active):
        need(self.phase == 'captured' and len(self.owned.rows) == 9,
             'four tools builders, four Welcome builders, one original consumer')
        need(type(active.process.returncode) is int, 'original606 direct child must be reaped')
        active.finish()
        group_absent(active.process.pid)
        self.owned.cleanup()  # Exact image/label/ID checks, reverse order, verified absence.
        need(all(row['status'] == 'PASS_ABSENCE_VERIFIED' for row in self.owned.rows), 'all original actors absent')
        receipt = dict(nonce=self.nonce, prior_consumers_absent=True,
                       process=dict(pid=active.process.pid, returncode=active.process.returncode, direct_child_reaped=True, group_absent=True),
                       containers=[dict(row) for row in self.owned.rows])
        self.events.append(dict(phase='retire-original', retirement=receipt))
        self.phase = 'retired' if active.process.returncode == 0 else 'failed-original-retired'
        return receipt

    def run(self, role, paths):
        expected = {'finalize': {'retired'}, 'worker': {'finalized'},
                    'dispose': {'retired', 'finalized', 'worker-retired', 'failed-original-retired'}}
        need(role in expected and self.phase in expected[role], 'exact finalize/worker/dispose order')
        seconds = min(SECONDS[role], self.deadline - time.monotonic())
        need(seconds > 0, 'original owner budget exhausted')
        command = self.owned.launch(argv(role, self.image, self.nonce, paths))
        active = None
        terminal = None
        error = None
        try:
            active = self.common.LoggedProcess(command, self.output / (role + '.log'),
                                              env=self.env, limit=16 * 1024**2, owner_signals_only=True)
            terminal = self.common.await_terminal(active.process, time.monotonic() + seconds)
        except BaseException as caught:
            error = caught
        finally:
            try:
                if active is not None:
                    # Reserve the child through the last group signal, then reap.
                    self.common.reap(active.process, timeout=10, verify_absence=True)
                    active.finish()
            finally:
                self.owned.cleanup()
        need(all(row['status'] == 'PASS_ABSENCE_VERIFIED' for row in self.owned.rows), 'phase container absence unknown')
        ok = terminal is not None and terminal.si_code == os.CLD_EXITED and terminal.si_status == 0 and error is None
        self.events.append(dict(phase=role, argv=command, pid=None if active is None else active.process.pid,
                                exit=0 if ok else 'FAILED', direct_child_reaped=True,
                                group_absent=True, containers_absent=True))
        # Failed finalizer/worker may authorize disposal ONLY after every actor
        # was verifiably retired; they never authorize the next functional phase.
        self.phase = ({'finalize': 'finalized', 'worker': 'worker-retired', 'dispose': 'disposed'}[role]
                      if ok else 'retired')
        if error is not None:
            raise error
        need(ok, 'phase failed; receipt cannot authorize continuation')
        return self.events[-1]

    def retirement_context(self):
        need(self.phase in {'retired', 'finalized', 'worker-retired', 'disposed', 'failed-original-retired'}, 'actors not retired')
        processes = [dict(self.events[0]['retirement']['process'], phase='original606')]
        for event in self.events[1:]:
            need(event['pid'] is not None, 'uncreated process is not a retirement witness')
            processes.append(dict(pid=event['pid'], phase=event['phase'], returncode=event['exit'],
                                  direct_child_reaped=True, group_absent=True))
        return dict(nonce=self.nonce, prior_consumers_absent=True, processes=processes,
                    containers=[dict(row) for row in self.owned.rows])

    def verify_disposal(self, measurement, lease):
        need(self.phase == 'disposed', 'disposer must retire before host readback')
        need(measurement_lease(measurement) == lease, 'original measurement identity/ownership/mode/emptiness not restored')
        return dict(status='POST_CAPTURE_ACTORS_RETIRED_AND_MEASUREMENT_RESTORED',
                    events=self.events, native_acceptance='NOT_GRANTED')
