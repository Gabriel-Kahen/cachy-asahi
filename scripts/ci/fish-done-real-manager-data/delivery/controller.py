# SPDX-License-Identifier: MIT
"""Real Mako delivery and supported refusal cases in the constructor's namespaces."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import struct
import stat
import subprocess
import sys
import time

sys.path.insert(0, '/inputs')
import fish_terminal as F
import monitor
import observation as O
from run import installed, mapped_root

W = Path('/work')
E = dict(os.environ, LD_LIBRARY_PATH='/work/libs')
actors, cleanup, cases, errors = [], [], [], []
sequence = 0
term = observer = None
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_FSIZE, (64*1024**2, 64*1024**2))
bindings = json.loads((W/'bindings.json').read_bytes())
lock = json.loads(Path('/inputs/done-lock.json').read_bytes())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def command(argv, *, timeout=5, check=True):
    global sequence
    sequence += 1
    process = subprocess.Popen(argv, env=E, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
    except BaseException:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=2)
        raise
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        absent = True
    else:
        absent = False
    O.need(len(out)+len(err) <= 65536, 'bounded command output')
    (W/f'command-{sequence}.json').write_text(json.dumps(dict(argv=argv, pid=process.pid,
        exit=process.returncode, group_absent=absent, stdout=out.decode('utf8', 'replace'),
        stderr=err.decode('utf8', 'replace')), indent=2)+'\n')
    O.need(absent and (not check or process.returncode == 0), 'owned command failed: '+argv[0])
    return out.decode()


def actor(name, argv):
    with (W/(name+'.stdout')).open('xb') as out, (W/(name+'.stderr')).open('xb') as err:
        process = subprocess.Popen(argv, env=E, stdin=subprocess.DEVNULL,
            stdout=out, stderr=err, start_new_session=True)
    actors.append((name, process))
    return process


def stop(name, process, normal=True):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        absent = True
    else:
        absent = False
    cleanup.append(dict(name=name, pid=process.pid, exit=process.returncode, group_absent=absent))
    O.need(absent and (not normal or process.returncode == 0), 'owned actor retirement: '+name)


def healthy():
    for name, process in actors:
        O.need(process.poll() is None, 'owned actor exited: '+name)
        O.need(sum((W/(name+'.'+suffix)).stat().st_size for suffix in ('stdout', 'stderr'))
               <= 262144, 'actor output cap')
    if term is not None:
        O.need(term.process.poll() is None, 'Fish exited early')
        term.pump()
    if observer is not None:
        observer.rows()


def until(probe, seconds, why):
    end = time.monotonic()+seconds
    while True:
        healthy()
        result = probe()
        if result:
            return result
        O.need(time.monotonic() < end, why)
        time.sleep(.02)


def bus(method, *args):
    return command(['/usr/bin/busctl', '--address='+E['DBUS_SESSION_BUS_ADDRESS'],
        '--auto-start=no', '--timeout=2s', 'call', 'org.freedesktop.DBus',
        '/org/freedesktop/DBus', 'org.freedesktop.DBus', method, *args]).strip()


def listing():
    return json.loads(command(['/work/tools/makoctl', 'list', '-j']))


def capabilities(*, check=True):
    return command(['/usr/bin/busctl', '--address='+E['DBUS_SESSION_BUS_ADDRESS'],
        '--auto-start=no', '--timeout=2s', 'call', 'org.freedesktop.Notifications',
        '/org/freedesktop/Notifications', 'org.freedesktop.Notifications', 'GetCapabilities'],
        timeout=3, check=check)


def ready(service=True):
    """A real observed roundtrip, repeated only within the fixed readiness bound."""
    deadline, attempts = time.monotonic()+5, 0
    while time.monotonic() < deadline:
        capabilities(check=service)
        attempts += 1
        if any(row.get('member') == 'GetCapabilities' and row.get('type') == 'method_call'
               for row in observer.rows()):
            return dict(attempts=attempts, observed_real_call=True)
        healthy()
        time.sleep(.05)
    raise ValueError('private bus monitor readiness')


class Shell(F.Terminal):
    def __init__(self, env, *, preload='', activated=True):
        init = F.INIT.replace('/work/done/usr/share', env['DONE_SHARE_PREFIX'])
        # Prompt paints can repeat on job completion. Count actual postexec events.
        init = init.replace('set -g __fdm_prompt 0', 'set -g __fdm_prompt 1')
        init = init.replace('    set -g __fdm_prompt (math $__fdm_prompt + 1)\n', '')
        init += '\nfunction fixture_count --on-event fish_postexec; set -g __fdm_prompt (math $__fdm_prompt + 1); end\n'
        init = init.replace('source '+env['DONE_SHARE_PREFIX'], preload+'\nsource '+env['DONE_SHARE_PREFIX'], 1)
        if not activated:
            init = init.replace('functions --query __done_ended __done_notify caa_done_watch caa_done_disable; or exit 91',
                                'functions --query __done_notify; and exit 91')
        super().__init__(env, init=init)
        self.sequence = 1

    def run(self, text, outcome=0, seconds=12):
        self.sequence += 1
        self.send(text+'\n')
        self.wait(('FDM_PROMPT_'+str(self.sequence)+'_'+str(outcome)).encode(), seconds)


def wire_rows():
    return [r for r in observer.rows() if r.get('type') == 'method_call' and
            r.get('interface') == 'org.freedesktop.Notifications' and r.get('member') == 'Notify']


def delivered(owner, outcome, kind='Foreground command'):
    wire = until(lambda: O.notify(observer.rows(), owner, outcome, kind), 5, 'real Notify/reply required')
    actual = O.listing(listing(), wire)
    O.need(actual is not None, 'actual Mako list must contain exact wire payload')
    return dict(wire=wire, daemon_listing=actual)


def finish_case(row, *, service=True, expires=False):
    global term, observer
    # notify-send has returned before the Fish prompt. A benign daemon roundtrip
    # follows it before checking the complete monitor interval.
    capabilities(check=service)
    if expires:
        deadline = time.monotonic()+3.5
        while time.monotonic() < deadline:
            healthy()
            if O.closure_facts(bytes(observer.parts[0]), row['wire'])['matching_closed_signals']:
                break
            time.sleep(.02)
    row['fish'] = term.finish()
    term.close()
    term = None
    row['monitor'] = observer.finish()
    observer.close()
    observer = None
    raw = base64.b64decode(row['monitor']['raw_base64'])
    calls = [r for r in O.messages(raw) if r.get('type') == 'method_call' and r.get('member') == 'Notify']
    row['notify_calls'] = len(calls)
    if 'wire' in row:
        O.need(len(calls) == 1, 'exactly one real notification required')
        row['closed'] = O.closure_facts(raw, row['wire'])
        if expires:
            signals = row['closed']['matching_closed_signals']
            O.need(len(signals) == 1 and signals[0]['signal']['payload']['data'] == [row['wire']['id'], 1],
                   'one real Mako natural-expiry signal required')
            O.need(listing() == [], 'expired notification still listed')
    else:
        O.need(not calls, 'suppressed/refused case emitted Notify')
    row['status'] = 'PASS'


def new_case(name, *, preload='', activated=True, service=True, background=False):
    global term, observer
    row = dict(name=name)
    cases.append(row)
    observer = monitor.Monitor(E)
    row['monitor_readiness'] = ready(service)
    term = F.BackgroundTerminal(E) if background else Shell(E, preload=preload, activated=activated)
    return row


def runtime_cleanup():
    paths = list((W/'runtime').iterdir())
    O.need(len(paths) <= 32, 'bounded owned runtime node cleanup')
    for path in paths:
        mode = path.lstat().st_mode
        O.need(stat.S_ISSOCK(mode) or (stat.S_ISREG(mode) and re.fullmatch(r'wayland-[0-9]+\.lock', path.name)),
               'unexpected private runtime node')
        path.unlink()
    cleanup.append(dict(name='private-runtime-nodes', removed=[p.name for p in paths],
                        empty=not any((W/'runtime').iterdir())))


def payload_snapshot(prefix):
    result = {}
    for name, row in lock['payload'].items():
        p = Path(prefix)/name
        O.need(p.is_file() and not p.is_symlink() and sha(p.read_bytes()) == row['sha256'],
               'exact pkgrel2 payload required')
        result[name] = sha(p.read_bytes())
    return result


try:
    O.need(str(os.geteuid()) == E['CACHY_NATIVE_UID'] and os.geteuid() != 0 and
           not Path('/run/user').exists() and not Path('/dev/input').exists() and
           not Path('/dev/dri').exists(), 'ordinary CPU-only isolated context required')
    O.need(not any(E.get(k) for k in ('DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS',
           'HYPRLAND_INSTANCE_SIGNATURE', 'WAYLAND_DEBUG', 'G_DBUS_DEBUG')), 'inherited desktop environment refused')
    arch = bindings['native_arch']
    O.need(platform.machine() == arch['name'], 'actual native architecture differs')
    for entry in bindings['inside_tools'].values():
        raw = Path(entry['path']).read_bytes()
        O.need(sha(raw) == entry['sha256'] and raw[:6] == b'\x7fELF\x02\x01' and
               struct.unpack_from('<H', raw, 18)[0] == arch['elf_machine'], 'native executable drift')
    for name, digest in bindings['libraries'].items():
        O.need(sha((W/'libs'/name).read_bytes()) == digest, 'native library drift')
    for name, digest in bindings['diagnostic_sources'].items():
        O.need(sha((Path('/inputs')/name).read_bytes()) == digest, 'constructor source drift')
    prefix = '/' if bindings['package_context'] == 'alpm-installed' else '/work/done'
    E['DONE_SHARE_PREFIX'] = str(Path(prefix)/'usr/share')
    before = payload_snapshot(prefix)
    if bindings['package_context'] == 'alpm-installed':
        owners = (mapped_root('uid'), mapped_root('gid'))
        O.need(installed(command, lock, owners=owners) == bindings['installed'], 'installed context changed')
    (W/'home/config/fish').mkdir(parents=True)
    (W/'home/data/fish').mkdir(parents=True)
    sentinels = {W/'home/config/fish/config.fish': b'exit 99\n',
                 W/'home/data/fish/fish_history': b'private existing history\n'}
    for p, raw in sentinels.items():
        p.write_bytes(raw)
    E['XDG_DATA_HOME'] = '/work/home/data'
    E.update(WLR_BACKENDS='headless', WLR_HEADLESS_OUTPUTS='1', WLR_RENDERER='pixman')
    sway = actor('sway', ['/work/tools/sway', '--config', '/work/sway.conf'])
    socket = until(lambda: next((p for p in (W/'runtime').glob('wayland-*') if p.is_socket()), None),
                   15, 'private CPU Sway socket')
    E['WAYLAND_DISPLAY'] = socket.name
    bus_process = actor('bus', ['/usr/bin/dbus-daemon', '--nofork', '--nopidfile', '--nosyslog',
                               '--config-file=/work/bus.conf'])
    until(lambda: (W/'runtime/bus').is_socket(), 5, 'owned private bus socket')
    E['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=/work/runtime/bus'
    O.need(bus('NameHasOwner', 's', 'org.freedesktop.Notifications') == 'b false', 'preexisting service refused')
    mako = actor('mako', ['/work/tools/mako', '--config', '/work/mako.conf'])
    until(lambda: bus('NameHasOwner', 's', 'org.freedesktop.Notifications') == 'b true', 5, 'real Mako registration')
    owner = json.loads(bus('GetNameOwner', 's', 'org.freedesktop.Notifications')[2:])
    O.need(bus('GetConnectionUnixProcessID', 's', owner) == 'u '+str(mako.pid) and
           bus('GetConnectionUnixUser', 's', owner) == 'u '+str(os.getuid()), 'owned Mako bus identity differs')
    O.need(os.readlink('/proc/'+str(mako.pid)+'/exe') == '/work/tools/mako' and listing() == [],
           'real selected daemon executable/empty state required')
    daemon = dict(owner=owner, pid=mako.pid, uid=os.getuid(), executable='/work/tools/mako',
                  sha256=sha((W/'tools/mako').read_bytes()), source=bindings['inputs']['source_metadata']['mako'])
    for outcome in (0, 7):
        row = new_case('foreground-success' if outcome == 0 else 'foreground-exit7')
        term.run(F.COMMANDS[outcome], outcome)
        row.update(delivered(owner, outcome))
        term.run('__fdm_continue $status')
        O.need(('FDM_CONT_'+str(outcome)).encode() in term.output, 'actual caller status continuation')
        row['caller_status'] = outcome
        finish_case(row, expires=True)
    row = new_case('watched-success-duplicate-registration', background=True)
    term.start(0)
    row.update(until(lambda: delivered(owner, 0, 'Watched job') if wire_rows() else None,
                     15, 'watched real notification'))
    row['caller'] = term.continuation(0)
    finish_case(row, expires=True)
    row = new_case('short-and-watch-refusals')
    for text, outcome in [('command sleep .1', 0), ('caa_done_watch', 2),
                          ('caa_done_watch nope', 2), ('caa_done_watch $fish_pid', 1),
                          ('command sleep .2 | command sleep .2 &; caa_done_watch $last_pid', 1),
                          ('wait', 0)]:
        term.run(text, outcome)
    finish_case(row)
    row = new_case('excluded-command')
    term.run("set -g caa_done_exclude '^command sleep'")
    term.run('command sleep 5.25')
    finish_case(row)
    row = new_case('invalid-user-threshold')
    term.run('set -g caa_done_min_duration invalid')
    term.run('command sleep 5.25')
    finish_case(row)
    row = new_case('disabled-module')
    term.run('caa_done_disable')
    term.run('functions --query __done_notify; and exit 93; true')
    term.run('command sleep 5.25')
    finish_case(row)
    row = new_case('repeat-source-custom-bindings-unrelated-hook')
    term.run("function fixture_post --on-event fish_postexec; printf event >> /work/home/events; end; "
             "bind ctrl-g 'commandline --replace CUSTOM'; bind --all > /work/home/bindings-before; "
             "functions --handlers > /work/home/handlers-before")
    term.run('source '+E['DONE_SHARE_PREFIX']+'/cachy-asahi/fish-done/opt-in.fish; '
             'bind --all > /work/home/bindings-after; functions --handlers > /work/home/handlers-after')
    O.need((W/'home/bindings-before').read_bytes() == (W/'home/bindings-after').read_bytes() and
           (W/'home/handlers-before').read_bytes() == (W/'home/handlers-after').read_bytes(),
           'repeat source changed bindings/handlers')
    term.run('command sleep 5.25')
    row.update(delivered(owner, 0))
    O.need((W/'home/events').stat().st_size > 0, 'unrelated postexec hook disappeared')
    finish_case(row, expires=True)
    row = new_case('existing-namespace-yields', activated=False,
        preload="function __done_ended --on-event fish_postexec; printf kept >> /work/home/foreign-events; end")
    term.run('command sleep 5.25')
    O.need((W/'home/foreign-events').stat().st_size > 0, 'existing plugin hook lost')
    finish_case(row)
    row = new_case('missing-bus-variable', activated=False, preload='set -e DBUS_SESSION_BUS_ADDRESS')
    term.run('command sleep 5.25')
    finish_case(row)
    row = new_case('noninteractive-noop')
    result = command(['/usr/bin/fish', '--no-config', '--private', '-c',
        'source '+E['DONE_SHARE_PREFIX']+'/cachy-asahi/fish-done/opt-in.fish; '
        'functions --query __done_notify; and exit 94; command sleep 5.25'], timeout=8)
    O.need(not result, 'noninteractive output')
    finish_case(row)
    stop('mako', mako)
    actors.remove(('mako', mako))
    O.need(bus('NameHasOwner', 's', 'org.freedesktop.Notifications') == 'b false', 'Mako name remained')
    row = new_case('unavailable-manager-bounded-caller', service=False)
    started = time.monotonic()
    term.run('command sleep 5.25')
    row['command_elapsed_seconds'] = time.monotonic()-started
    O.need(row['command_elapsed_seconds'] < 9, 'product 2s+1s transport bound exceeded')
    term.run('__fdm_continue $status')
    O.need(b'FDM_CONT_0' in term.output, 'transport error changed caller status')
    finish_case(row, service=False)
    O.need(bus('NameHasOwner', 's', 'org.freedesktop.Notifications') == 'b false', 'unexpected daemon activation')
    O.need(payload_snapshot(prefix) == before and all(p.read_bytes() == raw for p, raw in sentinels.items()),
           'product/config/history changed')
    if bindings['package_context'] == 'alpm-installed':
        O.need(installed(command, lock, owners=owners) == bindings['installed'], 'installed preservation failed')
    stop('bus', bus_process); actors.remove(('bus', bus_process))
    stop('sway', sway); actors.remove(('sway', sway))
except BaseException as error:
    errors.append(type(error).__name__+': '+str(error))
    if term is not None:
        (W/'failure-fish-pty').write_bytes(bytes(term.output))
    if observer is not None:
        (W/'failure-bus-stdout').write_bytes(bytes(observer.parts[0]))
        (W/'failure-bus-stderr').write_bytes(bytes(observer.parts[1]))
finally:
    for item, name in ((term, 'fish'), (observer, 'monitor')):
        if item is not None:
            try:
                item.close()
                cleanup.append(dict(name=name, failure_cleanup='PASS'))
            except BaseException as error:
                errors.append('cleanup '+name+': '+str(error))
    for name, process in reversed(actors):
        try:
            stop(name, process, normal=False)
        except BaseException as error:
            errors.append('cleanup '+name+': '+str(error))
    try:
        runtime_cleanup()
    except BaseException as error:
        errors.append('cleanup runtime: '+str(error))
    result = dict(status='PASS_PRIVATE_REAL_MAKO_TRIAL' if not errors and len(cases) == 12 else 'FAIL_PRIVATE_REAL_MAKO_TRIAL',
        native_arch=bindings['native_arch'], package_context=bindings['package_context'],
        scope=bindings['scope'], errors=errors, cases=cases, cleanup=cleanup,
        daemon=locals().get('daemon'), visual_display='NOT_QUALIFIED',
        installed_owners=locals().get('owners'),
        page_size=os.sysconf('SC_PAGE_SIZE'),
        namespace_mapping={kind: Path('/proc/self/'+kind+'_map').read_text() for kind in ('uid', 'gid')},
        native_arm='NOT_RUN' if platform.machine() != 'aarch64' else 'ACTUAL_AARCH64_ONLY',
        hardware='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
    (W/'result.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(dict(status=result['status'], cases=len(cases), errors=errors)))
