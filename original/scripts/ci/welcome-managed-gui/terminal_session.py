# SPDX-License-Identifier: MIT
"""Owned visible terminal phase on the existing private generic ARM fixture."""
import importlib.util
import json
import os
from pathlib import Path
import time

spec = importlib.util.spec_from_file_location('terminal_session_contract', Path(__file__).with_name('terminal_workflow.py'))
T = importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
base = None
IPC_READ_TIMEOUT = "Hyprland IPC didn't respond in time\n\nCouldn't read (6)"


def startup_clients(env, logs, name):
    """Only the observed, fully retired IPC read timeout is a readiness retry."""
    probe = base.Logged(['/usr/bin/hyprctl', '-j', 'clients', '-a'], name, logs, env)
    first = None
    try:
        probe.process.wait(timeout=20)
    except BaseException as error:
        first = error
    finally:
        for cleanup in (lambda: base.terminate(probe.process), probe.finish):
            try:cleanup()
            except BaseException as error:
                if first is None:first = error
    if first is not None:raise first
    output = T.read(probe.paths[0]).decode()
    errors = T.read(probe.paths[1])
    if probe.process.returncode == 6 and output.strip() == IPC_READ_TIMEOUT and not errors:
        base.emit('readiness_retry', scope='initial-gui-window-mapping-only', probe=name,
                  reason='hyprctl-ipc-read-timeout', returncode=6)
        return None
    T.need(probe.process.returncode == 0, 'initial terminal clients query failed: ' + name)
    return json.loads(output)


def wait(probe, healthy, seconds, description):
    deadline = time.monotonic() + seconds
    while True:
        healthy();T.need(time.monotonic() < deadline, description + ' deadline')
        value = probe()
        healthy();T.need(time.monotonic() < deadline, description + ' deadline')
        if value is not None:return value
        time.sleep(.25)


def worker_identity(pid, parent, proc=Path('/proc')):
    text = T.read(proc / str(pid) / 'status', 65536).decode()
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    T.need(int(fields['PPid']) == parent and [int(v) for v in fields['Uid'].split()] == [23001]*4,
           'owned terminal worker process identity differs')
    return dict(pid=pid, parent_pid=parent, uid=23001)


def phase(stage, config, env, logs):
    compositor = terminal = None
    first = None
    selected = None
    sequence = 0
    nonce = os.urandom(16).hex()
    workspace = base.HOME / ('terminal-' + stage + '-' + nonce)
    before = T.snapshot(Path(env['XDG_CONFIG_HOME']))
    workspace.mkdir(mode=0o700)
    (workspace / 'alacritty.toml').write_text(T.ALACRITTY)

    def command(argv, label, timeout=20):
        nonlocal sequence
        sequence += 1
        return base.command(argv, selected, logs, stage + '-terminal-' + str(sequence) + '-' + label, timeout=timeout)

    def healthy():
        compositor.healthy();terminal.healthy()

    def clients(*, readiness=False):
        nonlocal sequence
        if readiness:
            sequence += 1
            return startup_clients(selected, logs, stage + '-terminal-' + str(sequence) + '-clients')
        return json.loads(command(['/usr/bin/hyprctl', '-j', 'clients', '-a'], 'clients'))

    try:
        T.need(not any(p.is_socket() for p in base.RUNTIME.glob('wayland-*')), 'stale Wayland socket')
        compositor = base.Logged(['/usr/bin/Hyprland', '--config', str(config)], stage, logs, env)
        selected = base.ipc(stage, compositor, env, logs)
        monitors = json.loads(command(['/usr/bin/hyprctl', '-j', 'monitors'], 'monitors'))
        T.need(len(monitors) == 1 and monitors[0].get('width') == 1024 and monitors[0].get('height') == 768
               and monitors[0].get('scale') == 1, 'fixed generic monitor required')
        sockets = [p for p in base.RUNTIME.glob('wayland-*') if p.is_socket()]
        T.need(len(sockets) == 1, 'one private Wayland socket required')
        selected['WAYLAND_DISPLAY'] = sockets[0].name
        terminal = base.Logged(['/usr/bin/alacritty', '--config-file', str(workspace / 'alacritty.toml'),
            '--class', T.APP_ID, '--title', T.TITLE, '--working-directory', str(workspace),
            '--command', '/usr/bin/python3', '-I', '-B', str(base.SHARE / 'worker.py'),
            '--workspace', str(workspace), '--nonce', nonce, '--stage', stage], stage + '-alacritty', logs, selected)
        def mapped():
            reply = clients(readiness=True)
            return T.window(reply, terminal.process.pid) if reply is not None else None

        wait(mapped, healthy, 90, 'visible owned Alacritty')
        T.publish(workspace / 'start.json', dict(nonce=nonce, terminal_pid=terminal.process.pid))

        def result_ready():
            path = workspace / 'result.json'
            return json.loads(T.read(path)) if path.exists() else None

        result = wait(result_ready, healthy, 180, 'terminal editor/build/clipboard result')
        raw = T.read(workspace / 'result.json')
        base.emit('terminal_workflow_result', stage=stage, proof=result, proof_sha256=T.sha(raw))
        T.validate_result(result, stage, nonce, terminal.process.pid)
        T.need(T.read(workspace / 'main.c', 4096) == T.EDITED and
               T.sha(T.read(workspace / 'probe', 1024**2)) == result['executable']['sha256'],
               'owned source/executable file proof differs')
        worker_identity(result['worker_pid'], terminal.process.pid)
        start = time.monotonic()
        while time.monotonic() - start < 5:
            healthy();time.sleep(.1)
        current = T.window(clients(), terminal.process.pid)
        T.need(current is not None, 'terminal disappeared before capture')
        identity = worker_identity(result['worker_pid'], terminal.process.pid)
        base.emit('frame_ready', stage=stage, terminal=current, terminal_pid=terminal.process.pid,
                  worker=identity, workflow_proof_sha256=T.sha(raw),
                  workflow_status=result['status'], monitors=monitors,
                  capture_after_ms=int((time.monotonic() - start) * 1000),
                  physical_keyboard='NOT_RUN', hardware='NOT_RUN')
        until = time.monotonic() + 8
        while time.monotonic() < until:
            healthy();time.sleep(.1)
        T.need(T.window(clients(), terminal.process.pid) is not None, 'terminal disappeared after capture')
        worker_identity(result['worker_pid'], terminal.process.pid)
        T.publish(workspace / 'release.json', dict(nonce=nonce))
        terminal.process.wait(timeout=15)
        T.need(terminal.process.returncode == 0, 'terminal/owned child did not exit cleanly')

        def gone():
            return True if not any(c.get('pid') == terminal.process.pid and
                (c.get('mapped') or c.get('visible')) for c in clients()) else None

        wait(gone, compositor.healthy, 15, 'terminal window retirement')
        reply = command(['/usr/bin/hyprctl', 'dispatch', 'hl.dsp.exit()'], 'exit', timeout=5)
        T.need(reply.strip() == 'ok', 'compositor exit dispatch differs')
        compositor.process.wait(timeout=10)
        T.need(compositor.process.returncode == 0, 'unclean compositor exit')
    except BaseException as error:
        first = error
    finally:
        for item in (terminal, compositor):
            if item:
                for cleanup in (lambda child=item: base.terminate(child.process), item.finish):
                    try:cleanup()
                    except BaseException as error:
                        if first is None:first = error
        try:T.need(T.snapshot(Path(env['XDG_CONFIG_HOME'])) == before, 'user configuration changed')
        except BaseException as error:
            if first is None:first = error
    if first is not None:raise first
    base.emit('phase_pass', stage=stage, terminal='PASS', vim_edit='PASS', native_c='PASS',
              unicode_clipboard='PASS', config_preserved=True, thunar='UNSELECTED_NOT_RUN',
              physical_keyboard='NOT_RUN', hardware='NOT_RUN')
