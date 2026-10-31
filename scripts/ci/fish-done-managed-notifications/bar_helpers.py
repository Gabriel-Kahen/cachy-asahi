# SPDX-License-Identifier: MIT
"""Owned Waybar/Mako phase, called only by the disposable ARM guest adapter."""
import hashlib
import base64
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



OBSERVE_ENV=(*SESSION_ENV,'DISPLAY','GDK_BACKEND','GSETTINGS_BACKEND','GTK_USE_PORTAL','G_DBUS_DEBUG')


def process_observation(logged,expected,proc=Path('/proc')):
    """One bounded read of an already-owned unreaped child; no attach or signals."""
    pid=logged.process.pid
    need(type(pid) is int and pid>0 and logged.process.poll() is None,'owned live diagnostic child required')
    root=proc/str(pid)
    def read(path,cap):
        with path.open('rb') as stream:raw=stream.read(cap+1)
        need(len(raw)<=cap,'proc diagnostic field bound')
        return raw
    def identity():
        text=read(root/'stat',4096).decode();fields=text[text.rfind(')')+2:].split()
        need(len(fields)>=20 and text.startswith(str(pid)+' ('),'proc diagnostic stat identity')
        uid=next(line.split()[1:] for line in read(root/'status',8192).decode().splitlines() if line.startswith('Uid:'))
        need(uid==['23001']*4 and os.readlink(root/'exe')==expected,'foreign diagnostic process')
        return dict(pid=pid,starttime=int(fields[19]),uid=[23001]*4,executable=expected)
    before=identity();environment={}
    for row in read(root/'environ',65536).split(b'\0'):
        name,separator,value=row.partition(b'=')
        key=name.decode(errors='replace')
        if key in OBSERVE_ENV:
            need(separator and key not in environment and len(value)<=512,'diagnostic environment value bound')
            environment[key]=value.decode(errors='replace')
    fields={}
    for name,cap in (('wchan',256),('syscall',1024)):
        try:fields[name]=read(root/name,cap).decode(errors='replace')
        except (OSError,ValueError) as error:fields[name]=dict(unavailable=type(error).__name__)
    threads=[];tasks=sorted(int(p.name) for p in (root/'task').iterdir() if p.name.isdecimal())
    need(len(tasks)<=256,'diagnostic task count bound')
    for tid in tasks[:16]:
        row=dict(tid=tid)
        for name,cap in (('comm',256),('wchan',256),('syscall',1024),('stack',2048)):
            try:row[name]=read(root/'task'/str(tid)/name,cap).decode(errors='replace')
            except (OSError,ValueError) as error:row[name]=dict(unavailable=type(error).__name__)
        threads.append(row)
    after=identity();need(after==before and logged.process.poll() is None,'diagnostic process changed')
    return dict(identity=before,environment=environment,**fields,threads=threads,total_threads=len(tasks),
                threads_truncated=len(tasks)>16,scope='READ_ONLY_OWNED_CHILD_NO_ATTACH')


def failure_observation(stage,error,actors,command,selected,activation):
    """Observe once on failure before ordinary retirement; preserve the first error."""
    value=dict(stage=stage,error_type=type(error).__name__,reason=str(error)[:512],activation=activation,processes={})
    for name,logged,expected in actors:
        if logged is None:continue
        try:value['processes'][name]=process_observation(logged,expected)
        except BaseException as problem:value['processes'][name]=dict(unavailable=type(problem).__name__,reason=str(problem)[:128])
    if selected is not None:
        for key,argv in (
            ('activation_now',['/usr/bin/systemctl','--user','show-environment']),
            ('portal_units',['/usr/bin/systemctl','--user','show','xdg-desktop-portal.service','xdg-desktop-portal-gtk.service',
                '--property=Id,ActiveState,SubState,MainPID,Result,ExecMainStatus']),
            ('activation_journal',['/usr/bin/journalctl','--user','--no-pager','-b','-n','32','-o','short-monotonic',
                '-u','xdg-desktop-portal.service','-u','xdg-desktop-portal-gtk.service','-u','dbus.service'])):
            try:
                raw=command(argv,'diagnostic-'+key,timeout=5)
                if key=='activation_now':
                    raw='\n'.join(line for line in raw.splitlines() if line.partition('=')[0] in OBSERVE_ENV)
                need(len(raw.encode())<=8192,'diagnostic command response bound');value[key]=raw
            except BaseException as problem:value[key]=dict(unavailable=type(problem).__name__,reason=str(problem)[:128])
    need(len(json.dumps(value).encode())<=256*1024,'whole diagnostic receipt bound')
    base.emit('bar_phase_diagnostic',**value)



TRACE_MARKER='cachy_asahi_waybar_trace=1'


def trace_requested(command_line):
    values=[word for word in command_line.split() if word.startswith('cachy_asahi_waybar_trace=')]
    need(values in ([],[TRACE_MARKER]),'one explicit diagnostic trace marker required')
    return bool(values)


def trace_command(argv,enabled=False):
    need(type(enabled) is bool and type(argv) is list and argv and type(argv[-1]) is str,
         'explicit boolean Waybar trace option required')
    result=list(argv);marker='cachy_asahi_bar_notifications=1'
    need(result[-1].count(marker)==1 and 'cachy_asahi_waybar_trace=' not in result[-1],
         'one original unselected bar guest command required')
    if enabled:result[-1]=result[-1].replace(marker,marker+' '+TRACE_MARKER)
    return result


def waybar_environment(selected,trace_waybar=False):
    need(type(trace_waybar) is bool,'explicit boolean Waybar trace option required')
    result=dict(selected);result.pop('G_DBUS_DEBUG',None)
    if trace_waybar:result['G_DBUS_DEBUG']='call'
    return result


def retain_waybar_trace(stage,logged):
    """Called only after the original failure and completed owned log retirement."""
    need(logged.process.poll() is not None and not logged.errors and not logged.overflow and
         all(not thread.is_alive() for thread in logged.threads),'completed bounded Waybar logs required')
    rows=[]
    for path in logged.paths:
        info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and not any(p.is_symlink() for p in (path,*path.parents)) and
             info.st_size<=base.MAX_LOG,'ordinary existing-cap Waybar trace required')
        with path.open('rb') as stream:raw=stream.read(base.MAX_LOG+1)
        need(len(raw)==info.st_size and len(raw)<=base.MAX_LOG,'Waybar trace changed or exceeded existing log cap')
        rows.append(dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
            content_base64=base64.b64encode(raw).decode(),capture_complete=True))
    need(len(rows)==2,'exact Waybar stdout/stderr required')
    base.emit('waybar_call_trace',stage=stage,pid=logged.process.pid,returncode=logged.process.returncode,
        logging=dict(G_DBUS_DEBUG='call'),diagnostic_only=True,logs=rows)


def phase(stage, config, env, logs, *, trace_waybar=False):
    need(type(trace_waybar) is bool,'explicit boolean Waybar trace option required')
    compositor = bar = mako = None
    first = None
    selected = activation = None
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

    def finish_observed(logged):
        logged.finish()
        if logged is bar and first is not None and trace_waybar:
            retain_waybar_trace(stage,logged)

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
            '--style', str(TEMPLATES / 'waybar.css')], stage + '-waybar', logs, waybar_environment(selected,trace_waybar))
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
                  activation='normal-shipped-config-no-reload', notification_timeout_ms=0,activation_environment=activation,
                  trace_waybar=trace_waybar)
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
        try:
            failure_observation(stage,error,(('compositor',compositor,'/usr/bin/Hyprland'),
                ('waybar',bar,'/usr/bin/waybar'),('mako',mako,'/usr/bin/mako')),command,selected,activation)
        except BaseException:
            pass  # A diagnostic failure must never mask the original failure or retirement.
    finally:
        for logged in (mako, bar, compositor):
            if logged is not None:
                for cleanup in (lambda item=logged: base.terminate(item.process), lambda item=logged: finish_observed(item)):
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
