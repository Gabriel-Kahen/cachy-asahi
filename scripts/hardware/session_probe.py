#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only current-session observations; never a physical validation result."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

MAX_OUTPUT = 524288
COMMAND_SECONDS = 2
TOTAL_SECONDS = 20
MODELS = {'apple,j413': 'MacBook Air 13-inch (M2)', 'apple,j415': 'MacBook Air 15-inch (M2)'}
SERVICE_PROPERTIES = ('LoadState', 'ActiveState', 'SubState')  # Doctor2 interface
USER_UNITS = ('graphical-session.target', 'pipewire.service', 'wireplumber.service',
              'xdg-desktop-portal-hyprland.service')
SYSTEM_UNITS = ('speakersafetyd.service', 'asahi-audio.service')
PHYSICAL_CHECKS = ('fresh_login_and_acceleration', 'brightness_keyboard_trackpad',
                   'speaker_protection_and_audibility', 'headset_and_microphone',
                   'lock_unlock', 'lid_suspend_resume_and_preserved_applications',
                   'external_display_reconnect', 'power_thermals_and_performance')


def read_fixed(path):
    try:
        with open(path, 'rb') as source:
            value = source.read(4097)
        return value if len(value) <= 4096 else None
    except OSError:
        return None


def query(argv, seconds, env):
    """Own child reaping in this single-threaded CLI or skip launch safely.

    SIG_IGN/custom handlers are incompatible. Reset an apparently default
    disposition to clear SA_NOCLDWAIT without changing the caller's signal mask.
    This is not an API for processes with independent/native child reapers.
    """
    if (threading.current_thread() is not threading.main_thread() or threading.active_count() != 1
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        return 'reaping-policy-incompatible', None, b'', b''
    try:
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    except (OSError, ValueError):
        return 'reaping-policy-unverified', None, b'', b''
    return query_owned(argv, seconds, env)


def query_owned(argv, seconds, env):
    """Combined output and whole-command deadline, including inherited open pipes.

    Keep the leader unreaped until signalling its group, avoiding PID reuse.
    This is cooperative Linux cleanup, not a hard real-time kernel guarantee.
    """
    end = time.monotonic() + seconds
    try:
        child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
    except FileNotFoundError:
        return 'command-absent', None, b'', b''
    except PermissionError:
        return 'query-denied', None, b'', b''
    except OSError:
        return 'launch-failed', None, b'', b''
    parts = [bytearray(), bytearray()]
    reason = 'observed'
    reservation = True
    code = None
    selector = None

    def observe_leader():
        nonlocal reservation, reason
        if not reservation:
            return False

        if child.returncode is not None:
            reservation = False
            reason = 'child-reservation-lost'
            return False
        try:
            status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None and status.si_pid != child.pid:
                raise ValueError('unexpected child observation')
            return status is not None
        except (OSError, ValueError) as error:
            reservation = False
            reason = ('child-reservation-lost' if isinstance(error, ChildProcessError)
                      or getattr(error, 'errno', None) == errno.ECHILD else 'child-reservation-unverified')
            return False

    def settle_popen():
        # Avoid Popen's finalizer warning for an externally reaped child. Its
        # ECHILD-to-zero fallback is deliberately never used as report evidence.
        try:
            child.wait(timeout=0)
        except (subprocess.TimeoutExpired, OSError):
            pass

    try:
        selector = selectors.DefaultSelector()
        for index, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        while True:
            exited = observe_leader()
            if not reservation or (exited and not selector.get_map()):
                break
            left = end - time.monotonic()
            if left <= 0:
                reason = 'timeout'
                break
            for key, _ in selector.select(min(.05, left)):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if sum(map(len, parts)) + len(chunk) > MAX_OUTPUT:
                    reason = 'output-limit'
                    break
                parts[key.data].extend(chunk)
            if reason != 'observed':
                break
    except (OSError, ValueError):
        reason = 'read-failed'
    finally:
        try:
            # Reconfirm the unreaped leader immediately before group signalling.
            # No wait/poll/reap is performed before the last possible signal.
            observe_leader()
            if reservation:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    reason = 'cleanup-incomplete'
                end_reap = time.monotonic() + 1
                while True:
                    try:
                        pid, status = os.waitpid(child.pid, os.WNOHANG)
                    except OSError as error:
                        reservation = False
                        reason = ('child-reservation-lost' if error.errno == errno.ECHILD
                                  else 'child-reservation-unverified')
                        settle_popen()
                        break
                    if pid == child.pid:
                        code = child.returncode = os.waitstatus_to_exitcode(status)
                        reservation = False
                        break
                    if time.monotonic() >= end_reap:
                        reason = 'cleanup-incomplete'
                        break
                    time.sleep(.01)
            else:
                # Popen maps ECHILD to an internal zero. Do not expose that as
                # an observed status or claim leader/descendant retirement.
                settle_popen()
        finally:
            if selector is not None:
                selector.close()
            child.stdout.close()
            child.stderr.close()
    out, err = map(bytes, parts)
    if reason == 'observed' and code != 0:
        reason = ('query-denied' if any(x in err.lower() for x in
                  (b'permission denied', b'access denied', b'not authorized', b'authentication required'))
                  else 'query-failed')
    if reason == 'observed' and err:
        reason = 'query-warning'
    return reason, code, out, err


def socket_snapshot(path, owner):
    """No symlink ancestors; private current-user runtime checked separately."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        return None
    fd = None
    identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_nlink)
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        ancestry = []
        for index, part in enumerate(path.parts[1:-1], 1):
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            if info.st_uid not in (0, owner) or stat.S_IMODE(info.st_mode) & 0o022:
                return None
            if Path(*path.parts[:index + 1]) == Path('/run/user') / str(owner):
                if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
                    return None
            ancestry.append(identity(info))
        info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner or info.st_nlink != 1:
            return None
        return tuple(ancestry), identity(info)
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)


def contexts(environ):
    uid = os.getuid()
    runtime = Path('/run/user') / str(uid)
    base = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0',
            'XDG_CONFIG_HOME': '/nonexistent', 'XDG_CACHE_HOME': '/nonexistent',
            'MESA_SHADER_CACHE_DISABLE': 'true'}
    result = {'local': (base, ())}
    system = Path('/run/dbus/system_bus_socket')
    if socket_snapshot(system, 0):
        result['system'] = (dict(base, DBUS_SYSTEM_BUS_ADDRESS='unix:path=' + str(system)), ((system, 0),))
    try:
        info = runtime.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            return result
    except OSError:
        return result
    env = dict(base, XDG_RUNTIME_DIR=str(runtime))
    for kind, name in (('user', 'bus'), ('audio', 'pipewire-0')):
        path = runtime / name
        if socket_snapshot(path, uid):
            extra = ({'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(path)} if kind == 'user' else
                     {'PIPEWIRE_RUNTIME_DIR': str(runtime), 'PIPEWIRE_REMOTE': 'pipewire-0',
                      'XDG_CONFIG_DIRS': '/etc/xdg'})
            result[kind] = (dict(env, **extra), ((path, uid),))
    signature = environ.get('HYPRLAND_INSTANCE_SIGNATURE', '')
    if re.fullmatch(r'[A-Za-z0-9_.-]{1,200}', signature) and signature not in ('.', '..'):
        path = runtime / 'hypr' / signature / '.socket.sock'
        if socket_snapshot(path, uid):
            result['hypr'] = (dict(env, HYPRLAND_INSTANCE_SIGNATURE=signature), ((path, uid),))
    display = environ.get('WAYLAND_DISPLAY', '')
    if re.fullmatch(r'[A-Za-z0-9_-]{1,100}', display):
        path = runtime / display
        if socket_snapshot(path, uid):
            result['wayland'] = (dict(env, WAYLAND_DISPLAY=display, EGL_LOG_LEVEL='fatal'), ((path, uid),))
    return result


def json_value(raw):
    def reject_constant(_):
        raise ValueError('nonfinite')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)


def text(value, maximum=160):
    if not isinstance(value, str) or not re.fullmatch(r'[ -~]{1,' + str(maximum) + '}', value):
        raise ValueError('invalid text')
    return value


def number(value, low, high):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError('invalid number')
    return value


def hypr_version(raw):
    value = json_value(raw)
    result = {'version': text(value['version'], 100), 'commit': text(value['commit'], 64)}
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', result['commit']):
        raise ValueError('invalid commit')
    return result


def monitors(raw):
    rows = json_value(raw)
    if not isinstance(rows, list) or len(rows) > 32:
        raise ValueError('invalid monitor list')
    result = []
    for index, row in enumerate(rows):
        # Do not report serial, make/model, connector name, workspace or window IDs.
        entry = {'index': index, 'width': number(row['width'], 1, 32768),
                 'height': number(row['height'], 1, 32768),
                 'refresh_hz': number(row['refreshRate'], 1, 2000),
                 'scale': number(row['scale'], .1, 10), 'transform': number(row['transform'], 0, 7)}
        for key in ('dpmsStatus', 'disabled', 'focused'):
            if key in row:
                if type(row[key]) is not bool:
                    raise ValueError('invalid boolean')
                entry[key] = row[key]
        result.append(entry)
    return result


def renderer(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        match = re.fullmatch(r'OpenGL ES profile (vendor|renderer|version)(?: string)?: (.+)', line.strip())
        if match:
            if match[1] in result:
                raise ValueError('ambiguous context')
            result[match[1]] = text(match[2], 240)
    if set(result) != {'vendor', 'renderer', 'version'}:
        raise ValueError('GLES renderer not reported')
    result['software_renderer_hint'] = any(x in result['renderer'].lower() for x in ('llvmpipe', 'softpipe', 'software rasterizer', 'swrast'))
    return result


def properties(raw, expected):
    result = {}
    for line in raw.decode('ascii').splitlines():
        key, value = line.split('=', 1)
        if key not in expected or key in result or not re.fullmatch(r'[a-z-]{1,64}', value):
            raise ValueError('invalid property')
        result[key] = value
    if set(result) != set(expected):
        raise ValueError('incomplete properties')
    return result


def audio_graph(raw):
    rows = json_value(raw)
    if not isinstance(rows, list) or len(rows) > 4096:
        raise ValueError('invalid graph')
    counts, states, asahi = Counter(), Counter(), set()
    classes = {'Audio/Sink', 'Audio/Source', 'Audio/Source/Virtual', 'Audio/Sink/Virtual'}
    links = Counter()
    for row in rows:
        kind = row['type']
        info = row.get('info') or {}
        if not isinstance(info, dict):
            raise ValueError('invalid object')
        if kind == 'PipeWire:Interface:Node':
            props = info.get('props', {})
            if not isinstance(props, dict):
                raise ValueError('invalid properties')
            media = props.get('media.class')
            if isinstance(media, str) and media in classes:
                counts[media] += 1
            state = info.get('state')
            if state in ('creating', 'suspended', 'idle', 'running', 'error'):
                states[state] += 1
            name = props.get('node.name')
            # Exact names from the existing pinned j413/j415 audio graphs only.
            if isinstance(name, str) and re.fullmatch(r'(audio_effect|effect_output)\.j(413|415)-(convolver|mic)', name):
                asahi.add(name)
        elif kind == 'PipeWire:Interface:Link':
            state = info.get('state')
            if state in ('error', 'unlinked', 'init', 'negotiating', 'allocating', 'paused', 'active'):
                links[state] += 1
    return {'media_class_counts': dict(sorted(counts.items())), 'node_state_counts': dict(sorted(states.items())),
            'link_state_counts': dict(sorted(links.items())), 'known_asahi_graph_nodes': sorted(asahi),
            'speaker_protection': 'NOT TESTED'}


def can_suspend(raw):
    match = re.fullmatch(rb's "(yes|no|challenge|na)"\n?', raw)
    if not match:
        raise ValueError('invalid capability')
    return {'logind_can_suspend': match[1].decode()}


def power_tokens(raw, allowed):
    tokens = raw.decode('ascii').strip().split()
    if not tokens or len(tokens) > 8 or any(x.strip('[]') not in allowed for x in tokens):
        raise ValueError('invalid power capability')
    if any(not re.fullmatch(r'\[?[a-z0-9-]+\]?', x) or ('[' in x) != (']' in x) for x in tokens):
        raise ValueError('invalid power tokens')
    return tokens


def collect(identity, *, run=query, read=read_fixed, environ=None, context=None, clock=time.monotonic):
    environ = os.environ if environ is None else environ
    context = contexts(environ) if context is None else context
    deadline = clock() + TOTAL_SECONDS
    checks = []

    def probe(name, argv, scope, parse, note):
        row = {'check': name, 'state': 'unknown', 'reason': 'total-deadline', 'value': None, 'note': note, 'argv': argv}
        left = deadline - clock()
        if left <= 0:
            checks.append(row)
            return
        if scope not in context:
            row.update(state='unavailable', reason='local-endpoint-unavailable')
        else:
            env, sockets = context[scope]
            before = [socket_snapshot(path, owner) for path, owner in sockets]
            if any(x is None for x in before):
                row.update(state='unavailable', reason='local-endpoint-unavailable')
            else:
                reason, code, out, _ = run(argv, min(left, COMMAND_SECONDS), env)
                row.update(reason=reason, returncode=code)
                if before != [socket_snapshot(path, owner) for path, owner in sockets]:
                    row['reason'] = 'local-endpoint-changed'
                elif reason == 'command-absent':
                    row['state'] = 'unavailable'
                elif reason == 'observed':
                    try:
                        row.update(value=parse(out), state='checked')
                    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, OverflowError, RecursionError):
                        row['reason'] = 'malformed-or-unsupported-output'
        checks.append(row)

    probe('hyprland/version', ['/usr/bin/hyprctl', '-j', 'version'], 'hypr', hypr_version,
          'Current compositor IPC version; no new compositor is launched.')
    probe('hyprland/displays', ['/usr/bin/hyprctl', '-j', 'monitors'], 'hypr', monitors,
          'Current active outputs in returned order; indices are not persistent display identities.')
    checks.append({'check': 'hyprland/compositor-renderer', 'state': 'unknown',
                   'reason': 'not-exposed-by-selected-interface', 'value': None,
                   'note': 'Version/monitor IPC does not expose the compositor renderer. Broad systeminfo and session logs are not collected; see the separate GLES client observation.'})
    probe('renderer/wayland-gles-client', ['/usr/bin/eglinfo', '-B', '-p', 'wayland', '-a', 'gles'], 'wayland', renderer,
          'Brief GLES context in this Wayland session with default system driver selection; not proof of compositor renderer, frame presentation or acceleration performance.')
    for scope, units in (('user', USER_UNITS), ('system', SYSTEM_UNITS)):
        for unit in units:
            probe(scope + '/' + unit,
                  ['/usr/bin/systemctl', '--' + scope, '--no-pager', '--no-ask-password', 'show', unit,
                   '--property=' + ','.join(SERVICE_PROPERTIES)], scope,
                  lambda raw: properties(raw, SERVICE_PROPERTIES),
                  'Doctor2 service properties only; active does not establish functionality or protection.')
    probe('session/logind', ['/usr/bin/loginctl', '--no-pager', '--no-ask-password', 'show-session', 'self',
          '--property=Type,Class,State,Active,Remote,LockedHint'], 'system',
          lambda raw: properties(raw, ('Type', 'Class', 'State', 'Active', 'Remote', 'LockedHint')),
          'Caller session only; absence can reflect how the desktop was launched.')
    probe('audio/graph', ['/usr/bin/pw-dump', '-r', 'pipewire-0'], 'audio', audio_graph,
          'Sanitized current graph counts and exact known Asahi nodes; no client/device names, IDs or routes retained. Presence does not prove protected playback.')
    probe('suspend/logind-capability', ['/usr/bin/busctl', '--system', '--no-pager', '--timeout=2', 'call',
          'org.freedesktop.login1', '/org/freedesktop/login1', 'org.freedesktop.login1.Manager', 'CanSuspend'],
          'system', can_suspend, 'Capability query only; no suspend, lock or inhibitor modification.')
    for name, allowed in (('state', {'freeze', 'standby', 'mem', 'disk'}), ('mem_sleep', {'s2idle', 'shallow', 'deep'})):
        raw = read('/sys/power/' + name)
        row = {'check': 'suspend/kernel-' + name, 'state': 'unavailable', 'reason': 'interface-unavailable', 'value': None,
               'note': 'Advertised kernel modes only; actual sleep, wake and drain remain NOT RUN.'}
        if raw is not None:
            try:
                row.update(state='checked', reason='observed', value=power_tokens(raw, allowed))
            except (UnicodeError, ValueError):
                row.update(state='unknown', reason='malformed-or-unsupported-output')
        checks.append(row)
    compatible = read('/proc/device-tree/compatible')
    observed = [] if compatible is None else [x.decode('ascii') for x in compatible.split(b'\0') if x in (b'apple,j413', b'apple,j415')]
    observed_model = observed[0] if len(set(observed)) == 1 and platform.machine() == 'aarch64' else None
    return {'schema_version': 1, 'record_type': 'session-observations',
            'collected_at': datetime.now(timezone.utc).isoformat(),
            'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'identity': dict(identity, architecture=platform.machine(), kernel=platform.release(),
                             page_size_bytes=os.sysconf('SC_PAGE_SIZE'), observed_model_id=observed_model,
                             declared_model_matches_observation=(identity.get('declared_model_id') == observed_model)
                             if identity.get('declared_model_id') and observed_model else None),
            'session_hints': {'session_type': environ.get('XDG_SESSION_TYPE') if environ.get('XDG_SESSION_TYPE') in ('wayland', 'x11', 'tty') else None,
                              'wayland_environment_present': bool(environ.get('WAYLAND_DISPLAY')),
                              'hyprland_environment_present': bool(environ.get('HYPRLAND_INSTANCE_SIGNATURE'))},
            'limits': {'command_seconds': COMMAND_SECONDS, 'total_query_seconds': TOTAL_SECONDS,
                       'combined_output_bytes_per_command': MAX_OUTPUT, 'cleanup_seconds_per_command': 1},
            'tools_available': {name: os.access('/usr/bin/' + name, os.X_OK) for name in
                                ('hyprctl', 'eglinfo', 'systemctl', 'loginctl', 'pw-dump', 'busctl')},
            'checks': checks, 'coverage': dict(Counter(row['state'] for row in checks)),
            'physical_checks': dict.fromkeys(PHYSICAL_CHECKS, 'NOT RUN'),
            'limitations': ['Supplied model, source revision, baseline hash and execution context are declarations, not authenticated provenance.',
                            'Known device-tree identifiers do not prove physical execution or compatibility.',
                            'No raw command output/errors, environment, network identifiers, monitor serials, application titles or unrelated process content are reported.',
                            'Local socket checks detect observed replacement, not hostile same-UID races or server identity.',
                            'Incompatible reaping policy skips command launch. Lost or unverified child reservation disables group signals and leaves retirement unverified.',
                            'Queries may cause ordinary IPC, graphics-context or service bookkeeping; no configuration, service, volume, brightness, locking or sleep changes are requested.',
                            'This report complements capture-baseline.py and Doctor2; it is not an acceptance or health certificate.']}


def digest(value):
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise argparse.ArgumentTypeError('expected 64 lowercase hex characters')
    return value


def revision(value):
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value):
        raise argparse.ArgumentTypeError('expected full lowercase Git object ID')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-id', choices=sorted(MODELS), help='Operator-declared exact model; independently observed when available')
    parser.add_argument('--source-revision', type=revision, help='Exact source revision under test (operator supplied)')
    parser.add_argument('--baseline-sha256', type=digest, help='SHA256 of separately retained baseline (operator supplied)')
    parser.add_argument('--execution-context', choices=('physical', 'virtual', 'emulated', 'unknown'), default='unknown')
    args = parser.parse_args(argv)
    identity = {'declared_model_id': args.model_id, 'source_revision': args.source_revision,
                'baseline_sha256': args.baseline_sha256, 'execution_context': args.execution_context}
    def interrupt(*_):
        raise KeyboardInterrupt()
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        print(json.dumps(collect(identity), indent=2, allow_nan=False))
    except KeyboardInterrupt:
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
