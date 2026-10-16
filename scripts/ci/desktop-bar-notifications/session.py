# SPDX-License-Identifier: MIT
"""Owned Waybar/Mako phase, called only by the disposable ARM guest adapter."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import time
import managed_session as managed

SUMMARY = 'Cachy Asahi desktop'
BODY = 'Waybar and Mako: generic ARM software check'
APP = 'cachy-asahi-smoke'
MAKO_NAMESPACE = 'notifications'  # Pinned Mako wayland.c, not its executable name.
TEMPLATES = Path('/usr/share/cachy-asahi/hyprland')
BUS = ['/usr/bin/busctl', '--user', '--auto-start=no', '--timeout=5s', 'call']
base = None  # Explicitly bound to the pinned guest helper by the adapter.


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def uint_reply(value):
    match = re.fullmatch(r'u ([0-9]+)\s*', value)
    need(match is not None and 0 < int(match[1]) < 2**32, 'invalid D-Bus uint reply')
    return int(match[1])


def notifications(value, identifier):
    need(type(value) is list and all(type(row) is dict for row in value), 'invalid notification list')
    found = [row for row in value if row.get('id') == identifier]
    need(len(found) == 1 and type(found[0].get('id')) is int, 'notification missing/ambiguous')
    row = found[0]
    need((row.get('app_name'), row.get('summary'), row.get('body')) == (APP, SUMMARY, BODY),
         'notification payload differs')
    return row


def layer_rows(value):
    need(type(value) is dict, 'invalid layer reply')
    rows = []
    for monitor, data in value.items():
        need(type(data) is dict and type(data.get('levels')) is dict, 'invalid layer levels')
        for level, entries in data['levels'].items():
            need(type(entries) is list and all(type(row) is dict for row in entries), 'invalid layer list')
            rows.extend(dict(row, monitor=monitor, level=level) for row in entries)
    return rows


def owned_layer(value, namespace, pid):
    found = [row for row in layer_rows(value) if row.get('namespace') == namespace]
    if not found:
        return None
    need(len(found) == 1, 'ambiguous ' + namespace + ' layers')
    row = found[0]
    need(type(row.get('pid')) is int and row['pid'] == pid, 'foreign ' + namespace + ' layer')
    need(all(type(row.get(key)) is int for key in ('x', 'y', 'w', 'h')), 'invalid layer geometry')
    need(row['level'] in ('2', '3') and type(row.get('alpha')) in (int, float) and
         math.isfinite(row['alpha']) and 0 <= row['alpha'] <= 1, 'invalid layer alpha/level')
    if row['alpha'] < .99 or row['w'] == 0 or row['h'] == 0:
        return None  # Transitional surfaces must become fully visible before capture.
    need(0 <= row['x'] < 1024 and 0 <= row['y'] < 768 and row['w'] > 0 and row['h'] > 0 and
         row['x'] + row['w'] <= 1024 and row['y'] + row['h'] <= 768, 'offscreen/empty layer')
    if namespace == 'waybar':
        need(row['x'] == row['y'] == 0 and row['w'] == 1024 and 15 <= row['h'] <= 100,
             'bar geometry differs')
    else:
        need(row['w'] >= 120 and row['h'] >= 30, 'notification geometry differs')
    return row


def snapshot(directory):
    """Bounded no-follow config observation; never copy, replace or remove it."""
    result = {}
    for path in sorted(directory.rglob('*')):
        need(len(result) < 128, 'configuration snapshot entry limit')
        info = path.lstat()
        row = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        if stat.S_ISLNK(info.st_mode):
            row.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            need(info.st_size <= 1024**2, 'configuration file too large')
            row.update(kind='file', sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            need(stat.S_ISDIR(info.st_mode), 'special configuration node')
            row.update(kind='directory')
        result[str(path.relative_to(directory))] = row
    return result


def wait_ready(probe, healthy, seconds, description):
    deadline = time.monotonic() + seconds
    while True:
        healthy()
        need(time.monotonic() < deadline, description + ' deadline')
        value = probe()
        healthy()
        need(time.monotonic() < deadline, description + ' deadline')
        if value is not None:
            return value
        time.sleep(.25)


def clean_stop(logged, sig):
    need(logged.process.poll() is None, 'client exited before owned stop')
    os.killpg(logged.process.pid, sig)
    logged.process.wait(timeout=10)
    need(logged.process.returncode == 0, 'client did not exit cleanly')


SESSION_ENV=('WAYLAND_DISPLAY','HYPRLAND_INSTANCE_SIGNATURE','XDG_SESSION_TYPE','XDG_CURRENT_DESKTOP')


def environment_values(selected):
    values={name:selected.get(name) for name in SESSION_ENV}
    need(all(type(v) is str for v in values.values()) and
         re.fullmatch(r'wayland-[0-9]{1,5}',values['WAYLAND_DISPLAY']) and
         re.fullmatch(r'[A-Za-z0-9_.-]{1,256}',values['HYPRLAND_INSTANCE_SIGNATURE']) and
         values['XDG_SESSION_TYPE']=='wayland' and values['XDG_CURRENT_DESKTOP']=='Hyprland',
         'explicit owned Wayland activation environment required')
    return values


def activate_environment(command,dbus,selected,manager_pid):
    values=environment_values(selected)
    command(['/usr/bin/systemctl','--user','set-environment',*[k+'='+v for k,v in values.items()]],'activation-set',timeout=5)
    reply=dbus('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',
        'UpdateActivationEnvironment','a{ss}',str(len(values)),*[x for pair in values.items() for x in pair])
    need(reply.strip()=='','D-Bus activation update reply differs')
    raw=command(['/usr/bin/systemctl','--user','show-environment'],'activation-read',timeout=5)
    found={}
    for line in raw.splitlines():
        name,separator,value=line.partition('=')
        if name in values:
            need(separator and name not in found,'duplicate activation environment value')
            found[name]=value
    need(found==values,'managed activation environment differs')
    return dict(values=values,manager_pid=manager_pid,systemd_verified=True,dbus_updated=True)


def phase(stage, config, env, logs):
    compositor = bar = mako = None
    first = None
    selected = None
    before = snapshot(Path(env['XDG_CONFIG_HOME']))
    sequence = 0

    def command(argv, label, timeout=20):
        nonlocal sequence
        sequence += 1
        return base.command(argv, selected, logs, stage + '-slice-' + str(sequence) + '-' + label, timeout=timeout)

    def dbus(destination, path, interface, method, *arguments):
        return command(BUS + [destination, path, interface, method, *arguments], 'dbus', timeout=7)

    def owner():
        return uint_reply(dbus('org.freedesktop.DBus', '/org/freedesktop/DBus',
            'org.freedesktop.DBus', 'GetConnectionUnixProcessID', 's', 'org.freedesktop.Notifications'))

    def healthy():
        for logged in (compositor, bar, mako):
            logged.healthy()

    def layers():
        return json.loads(command(['/usr/bin/hyprctl', '-j', 'layers'], 'layers'))

    def listing():
        return json.loads(command(['/usr/bin/makoctl', 'list', '-j'], 'list'))

    def managed_identity():
        need(selected.get('DBUS_SESSION_BUS_ADDRESS') == managed.ADDRESS and
             selected.get('XDG_RUNTIME_DIR') == str(managed.RUNTIME), 'managed capture endpoint differs')
        raw = os.environ.get('CACHY_MANAGED_MANAGER_PID', '')
        need(re.fullmatch('[1-9][0-9]{0,9}', raw) is not None, 'root-joined manager PID absent')
        return managed.bus_probe(lambda argv: command(argv, 'managed-capture', timeout=5), int(raw))

    try:
        need(not any(p.is_socket() for p in base.RUNTIME.glob('wayland-*')), 'stale Wayland socket')
        compositor = base.Logged(['/usr/bin/Hyprland', '--config', str(config)], stage, logs, env)
        selected = base.ipc(stage, compositor, env, logs)
        identity = managed_identity()
        monitors = json.loads(command(['/usr/bin/hyprctl', '-j', 'monitors'], 'monitors'))
        need(base.usable_monitors(monitors), 'no usable monitor')
        need(len(monitors) == 1 and monitors[0]['width'] == 1024 and monitors[0]['height'] == 768
             and monitors[0].get('scale') == 1, 'fixed generic smoke monitor required')
        sockets = [p for p in base.RUNTIME.glob('wayland-*') if p.is_socket()]
        need(len(sockets) == 1, 'one owned Wayland socket required')
        selected.update(WAYLAND_DISPLAY=sockets[0].name,XDG_SESSION_TYPE='wayland',XDG_CURRENT_DESKTOP='Hyprland')
        activation=activate_environment(command,dbus,selected,identity['manager_pid'])
        need(managed_identity()==identity,'managed identity changed during activation update')
        need(not any(r.get('namespace') in ('waybar', MAKO_NAMESPACE) for r in layer_rows(layers())),
             'preexisting bar/notification layer')
        has_owner = lambda: dbus('org.freedesktop.DBus', '/org/freedesktop/DBus',
            'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.Notifications').strip()
        need(has_owner() == 'b false', 'preexisting notification owner')
        bar = base.Logged(['/usr/bin/waybar', '--config', str(TEMPLATES / 'waybar.json'),
            '--style', str(TEMPLATES / 'waybar.css')], stage + '-waybar', logs, selected)
        mako = base.Logged(['/usr/bin/mako', '--config', str(TEMPLATES / 'mako.conf')],
            stage + '-mako', logs, selected)

        def bus_ready():
            value = has_owner()
            need(value in ('b true', 'b false'), 'invalid D-Bus owner reply')
            if value == 'b false':
                return None
            need(owner() == mako.process.pid, 'foreign notification owner')
            return True

        wait_ready(bus_ready, healthy, 30, 'Mako ownership')
        need(listing() == [], 'preexisting notifications')
        identifier = uint_reply(dbus('org.freedesktop.Notifications', '/org/freedesktop/Notifications',
            'org.freedesktop.Notifications', 'Notify', 'susssasa{sv}i', APP, '0', '', SUMMARY, BODY,
            '0', '0', '0'))  # No actions/hints; explicit non-expiring timeout.

        def visible():
            need(owner() == mako.process.pid, 'notification ownership changed')
            notice = notifications(listing(), identifier)
            value = layers()
            a = owned_layer(value, 'waybar', bar.process.pid)
            b = owned_layer(value, MAKO_NAMESPACE, mako.process.pid)
            return dict(bar=a, mako=b, notification=notice) if a and b else None

        wait_ready(visible, healthy, 60, 'visible bar and notification')
        start = time.monotonic()
        while time.monotonic() - start < 5:
            healthy()
            time.sleep(.1)
        current = visible()
        need(current is not None, 'clients disappeared before capture')
        need(managed_identity() == identity, 'managed identity changed before capture')
        base.emit('frame_ready', stage=stage, monitors=monitors, **current,
                  capture_after_ms=int((time.monotonic() - start) * 1000),
                  waybar_pid=bar.process.pid, mako_pid=mako.process.pid,
                  compositor_pid=compositor.process.pid, managed_identity=identity,
                  activation='normal-shipped-config-no-reload', notification_timeout_ms=0,activation_environment=activation)
        after = time.monotonic() + 8
        while time.monotonic() < after:
            healthy()
            time.sleep(.1)
        need(visible() is not None, 'clients disappeared after capture')
        need(managed_identity() == identity, 'managed identity changed after capture')
        dbus('org.freedesktop.Notifications', '/org/freedesktop/Notifications',
             'org.freedesktop.Notifications', 'CloseNotification', 'u', str(identifier))

        def dismissed():
            need(owner() == mako.process.pid, 'notification ownership changed')
            value = listing()
            need(type(value) is list, 'invalid notification list')
            return True if not value and owned_layer(layers(), MAKO_NAMESPACE, mako.process.pid) is None else None

        wait_ready(dismissed, healthy, 15, 'notification dismissal')
        clean_stop(bar, signal.SIGINT)
        clean_stop(mako, signal.SIGTERM)
        need(has_owner() == 'b false', 'notification name retained after stop')
        wait_ready(lambda: True if not any(r.get('namespace') in ('waybar', MAKO_NAMESPACE)
                   for r in layer_rows(layers())) else None, compositor.healthy, 15, 'layer retirement')
        reply = command(['/usr/bin/hyprctl', 'dispatch', 'hl.dsp.exit()'], 'exit', timeout=5)
        need(reply.strip() == 'ok', 'compositor exit dispatch differs')
        compositor.process.wait(timeout=10)
        need(compositor.process.returncode == 0, 'unclean compositor exit')
    except BaseException as error:
        first = error
    finally:
        for logged in (mako, bar, compositor):
            if logged is not None:
                for cleanup in (lambda item=logged: base.terminate(item.process), logged.finish):
                    try:
                        cleanup()
                    except BaseException as error:
                        if first is None:
                            first = error
        try:
            need(snapshot(Path(env['XDG_CONFIG_HOME'])) == before, 'user configuration changed')
        except BaseException as error:
            if first is None:
                first = error
    if first is not None:
        raise first
    base.emit('phase_pass', stage=stage, waybar='PASS', mako='PASS', config_preserved=True)
