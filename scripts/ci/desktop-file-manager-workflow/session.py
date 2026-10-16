# SPDX-License-Identifier: MIT
"""Finite Thunar workflow on the guarded private generic ARM fixture."""
import importlib.util
import json
import os
from pathlib import Path
import re
import time

spec = importlib.util.spec_from_file_location('file_manager_contract', Path(__file__).with_name('file_manager.py'))
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
        base.emit('readiness_retry', scope='initial-thunar-mapping-only', probe=name,
                  reason='hyprctl-ipc-read-timeout', returncode=6)
        return None
    T.need(probe.process.returncode == 0, 'initial Thunar clients query failed: ' + name)
    return json.loads(output)




def wait(probe, healthy, seconds, label):
    deadline = time.monotonic() + seconds
    while True:
        healthy();T.need(time.monotonic() < deadline, label + ' deadline')
        value = probe()
        healthy();T.need(time.monotonic() < deadline, label + ' deadline')
        if value is not None:return value
        time.sleep(.25)


def phase(stage, config, env, logs):
    compositor = thunar = settings = None
    first = None
    selected = None
    sequence = 0
    nonce = os.urandom(16).hex()
    workspace = base.HOME / ('files-' + stage + '-' + nonce)
    before = T.snapshot(Path(env['XDG_CONFIG_HOME']))
    workspace.mkdir(mode=0o700)
    directory = workspace / 'Files';directory.mkdir()
    for name in ('config', 'data', 'cache'):(workspace / name).mkdir()
    seed = workspace / 'seed.txt';seed.write_bytes(T.CONTENT)
    outside = workspace / 'outside.txt';outside.write_bytes(b'preserve outside fixture\n')
    protected = T.sha(T.read(outside))
    created = directory / 'created.txt';renamed = directory / 'renamed.txt'
    apps = workspace / 'data/applications';apps.mkdir()
    handler = apps / 'cachy-file-probe.desktop'
    handler.write_text('[Desktop Entry]\nType=Application\nName=Private text launch receipt\n'
        'Exec=/usr/bin/python3 -I -B ' + str(base.SHARE / 'open_probe.py') + ' ' + str(workspace) +
        ' ' + nonce + ' %f\nTerminal=false\nMimeType=text/plain;\nNoDisplay=true\n')
    (workspace / 'config/mimeapps.list').write_text('[Default Applications]\ntext/plain=cachy-file-probe.desktop\n')

    def command(argv, label, timeout=20):
        nonlocal sequence
        sequence += 1
        return base.command(argv, selected, logs, stage + '-files-' + str(sequence) + '-' + label, timeout=timeout)

    def healthy():
        compositor.healthy()
        if settings:settings.healthy()
        if thunar:thunar.healthy()

    def call(interface, method, *args, dest=T.BUS, path=T.OBJECT):
        return command(['/usr/bin/gdbus', 'call', '--session', '--dest', dest,
            '--object-path', path, '--method', interface + '.' + method, *args], method)

    def owner():
        raw = call('org.freedesktop.DBus', 'GetConnectionUnixProcessID', T.BUS,
                   dest='org.freedesktop.DBus', path='/org/freedesktop/DBus')
        match = re.fullmatch(r'\(uint32 ([1-9][0-9]*),\)\s*', raw)
        T.need(match is not None and int(match[1]) == thunar.process.pid, 'Thunar D-Bus owner differs')
        return int(match[1])

    def clients():
        return json.loads(command(['/usr/bin/hyprctl', '-j', 'clients', '-a'], 'clients'))

    try:
        T.need(not any(p.is_socket() for p in base.RUNTIME.glob('wayland-*')), 'stale Wayland socket')
        compositor = base.Logged(['/usr/bin/Hyprland', '--config', str(config)], stage, logs, env)
        selected = base.ipc(stage, compositor, env, logs)
        monitors = json.loads(command(['/usr/bin/hyprctl', '-j', 'monitors'], 'monitors'))
        T.need(len(monitors) == 1 and monitors[0].get('width') == 1024 and
               monitors[0].get('height') == 768 and monitors[0].get('scale') == 1, 'fixed monitor required')
        sockets = [p for p in base.RUNTIME.glob('wayland-*') if p.is_socket()]
        T.need(len(sockets) == 1, 'one private Wayland socket required')
        selected.update(WAYLAND_DISPLAY=sockets[0].name, GDK_BACKEND='wayland',
            XDG_CONFIG_HOME=str(workspace / 'config'), XDG_DATA_HOME=str(workspace / 'data'),
            XDG_CACHE_HOME=str(workspace / 'cache'))
        # Own xfconfd before Thunar: bus activation must not write fixture-user config.
        settings = base.Logged(['/usr/lib/xfce4/xfconf/xfconfd'], stage + '-xfconfd', logs, selected)
        def settings_ready():
            reply = call('org.freedesktop.DBus', 'ListNames', dest='org.freedesktop.DBus', path='/org/freedesktop/DBus')
            return True if "'org.xfce.Xfconf'" in reply else None
        wait(settings_ready, healthy, 20, 'private xfconf')
        thunar = base.Logged(['/usr/bin/thunar', '--daemon'], stage + '-thunar', logs, selected)
        def ready():
            reply = call('org.freedesktop.DBus', 'ListNames', dest='org.freedesktop.DBus', path='/org/freedesktop/DBus')
            return True if "'" + T.BUS + "'" in reply else None
        wait(ready, healthy, 30, 'owned Thunar bus')
        owner_pid = owner()
        raw = command(['/usr/bin/gdbus', 'introspect', '--session', '--dest', T.BUS,
                       '--object-path', T.OBJECT, '--xml'], 'introspection')
        signatures = T.introspection(raw)
        call(T.BUS, 'DisplayFolder', directory.as_uri(), '', '')
        def mapped():
            nonlocal sequence
            sequence += 1
            reply = startup_clients(selected, logs, stage + '-files-' + str(sequence) + '-clients')
            return T.window(reply, thunar.process.pid, 'Files') if reply is not None else None
        wait(mapped, healthy, 90, 'visible owned Thunar')
        call(T.BUS, 'CopyTo', str(workspace), "['seed.txt']", "['Files/created.txt']", '', '')
        wait(lambda:True if created.exists() and T.read(created, 4096) == T.CONTENT else None,
             healthy, 30, 'Thunar copied file')
        command(['/usr/bin/gio', 'move', '--', str(created), str(renamed)], 'gio-rename')
        T.need(not created.exists() and T.read(renamed, 4096) == T.CONTENT, 'GIO rename differs')
        # Query the selected MIME handler before asking Thunar to launch the text file.
        mime = command(['/usr/bin/gio', 'mime', 'text/plain'], 'mime-handler')
        T.need('cachy-file-probe.desktop' in mime, 'private text handler unselected')
        call(T.BUS, 'LaunchFiles', str(directory), "['renamed.txt']", '', '')
        def opened():
            path = workspace / 'opened.json'
            return json.loads(T.read(path)) if path.exists() else None
        receipt = wait(opened, healthy, 30, 'Thunar text launch receipt')
        proof = dict(status='PASS_THUNAR_DBUS_COPY_LAUNCH_GIO_RENAME', stage=stage, nonce=nonce,
            thunar_pid=thunar.process.pid, bus_owner_pid=owner_pid, renamed_path=str(renamed),
            content_sha256=T.sha(T.read(renamed)), bytes=len(T.CONTENT), handler=receipt,
            original_preserved=T.read(seed) == T.CONTENT, outside_preserved=T.sha(T.read(outside)) == protected,
            copy='Thunar org.xfce.FileManager.CopyTo', rename='GIO move; Thunar rename UI NOT_RUN',
            open='Thunar LaunchFiles to private text handler; editor UI NOT_RUN', signatures=signatures)
        T.validate(proof, stage, thunar.process.pid)
        encoded = (json.dumps(proof, sort_keys=True, indent=2) + '\n').encode()
        base.emit('file_manager_result', stage=stage, proof=proof, proof_sha256=T.sha(encoded))
        start = time.monotonic()
        while time.monotonic() - start < 5:healthy();time.sleep(.1)
        current = T.window(clients(), thunar.process.pid, 'Files')
        T.need(current is not None and owner() == owner_pid, 'Thunar disappeared before capture')
        base.emit('frame_ready', stage=stage, thunar=current, thunar_pid=thunar.process.pid,
            workflow_proof_sha256=T.sha(encoded), monitors=monitors,
            capture_after_ms=int((time.monotonic()-start)*1000), physical_keyboard='NOT_RUN', hardware='NOT_RUN')
        until = time.monotonic() + 8
        while time.monotonic() < until:healthy();time.sleep(.1)
        T.need(T.window(clients(), thunar.process.pid, 'Files') is not None, 'Thunar disappeared after capture')
        command(['/usr/bin/thunar', '--quit'], 'quit')
        thunar.process.wait(timeout=15);T.need(thunar.process.returncode == 0, 'unclean Thunar exit')
        wait(lambda:True if not any(c.get('pid') == thunar.process.pid and c.get('mapped') for c in clients()) else None,
             compositor.healthy, 15, 'Thunar window retirement')
        T.need(T.read(seed) == T.CONTENT and T.sha(T.read(outside)) == protected and
               T.read(renamed) == T.CONTENT, 'final preservation differs')
        base.terminate(settings.process);settings.finish();settings = None
        reply = command(['/usr/bin/hyprctl', 'dispatch', 'hl.dsp.exit()'], 'exit', timeout=5)
        T.need(reply.strip() == 'ok', 'compositor exit dispatch differs')
        compositor.process.wait(timeout=10);T.need(compositor.process.returncode == 0, 'unclean compositor exit')
    except BaseException as error:first = error
    finally:
        for item in (thunar, settings, compositor):
            if item:
                for cleanup in (lambda child=item:base.terminate(child.process), item.finish):
                    try:cleanup()
                    except BaseException as error:
                        if first is None:first = error
        try:T.need(T.snapshot(Path(env['XDG_CONFIG_HOME'])) == before, 'fixture-user configuration changed')
        except BaseException as error:
            if first is None:first = error
    if first is not None:raise first
    base.emit('phase_pass', stage=stage, thunar='PASS', dbus_copy='PASS', gio_rename='PASS',
              text_launch='PASS', config_preserved=True, rename_ui='NOT_RUN', editor_ui='NOT_RUN', hardware='NOT_RUN')
