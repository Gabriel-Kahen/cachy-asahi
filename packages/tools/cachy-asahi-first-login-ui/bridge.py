# SPDX-License-Identifier: MIT
"""Finite first-login protocol client. No shell, elevation or automatic writes."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import threading
import time

COMPONENTS = ('fish', 'zsh', 'hyprland')
TEMPLATES = {'fish': 'fish/config.fish', 'zsh': 'zsh/config.zsh', 'hyprland': 'hyprland/hyprland.lua',
    **{name: name + '/opt-in.' + ('fish' if name.startswith('fish-') else 'zsh') for name in (
        'fish-bang-bang', 'fish-autopair', 'fish-done', 'zsh-autosuggestions',
        'zsh-syntax-highlighting', 'zsh-history-substring-search')}}
MAX_BYTES = 2 * 1024 * 1024


class Error(Exception):
    pass


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def nonconstant(_):
    raise ValueError('nonstandard JSON number')


def valid_report(data, operation, components, apply):
    expected = set(components or COMPONENTS)
    if (not isinstance(data, dict) or type(data.get('schema_version')) is not int
            or data['schema_version'] != 1 or data.get('operation') != operation
            or data.get('mode') not in ('read-only', 'preview', 'applied')
            or (not apply and data['mode'] == 'applied')
            or data.get('status') not in ('ready-to-select', 'attention-required', 'blocked',
                'activation-preview', 'activation-applied', 'recovery-required', 'recovery-preview', 'recovery-applied')):
        return False
    rows, status = data.get('components'), data.get('setup_status')
    if (not isinstance(rows, list) or len(rows) != len(expected)
            or any(not isinstance(r, dict) or r.get('component') not in expected
                   or type(r.get('available')) is not bool for r in rows)
            or {r['component'] for r in rows} != expected or not isinstance(status, dict)):
        return False
    if (status.get('schema_version') != 1 or status.get('operation') != 'status'
            or status.get('mode') != 'read-only' or not isinstance(status.get('state'), dict)
            or status['state'].get('status') not in ('missing', 'valid', 'unknown')
            or not isinstance(status.get('pending'), dict)
            or status['pending'].get('status') not in ('none', 'resumable', 'blocked', 'unknown', 'migration-owned')):
        return False
    for report in (status, data.get('setup_result', {'actions': []})):
        if not isinstance(report, dict) or not isinstance(report.get('actions'), list):
            return False
        if any(not isinstance(r, dict) or not isinstance(r.get('component'), str)
               or not isinstance(r.get('status'), str)
               or ('path' in r and not isinstance(r['path'], str)) for r in report['actions']):
            return False
    return True


def fingerprint(path, include_data=False):
    """Hash only finite ordinary files, opening each ancestor without symlinks."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise Error('Use absolute configuration paths without parent traversal.')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            for name in path.parts[1:-1]:
                new = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = new
            file = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return (None, None) if include_data else None
        with os.fdopen(file, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES:
                raise Error('A selected configuration/input is unsafe or too large; preserve it and inspect separately.')
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_uid, s.st_gid,
                                  s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
            if len(raw) > MAX_BYTES or identity(before) != identity(after):
                raise Error('Configuration changed while reading; preview again.')
            token = (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid,
                     before.st_mtime_ns, before.st_ctime_ns, hashlib.sha256(raw).hexdigest())
            return (token, raw) if include_data else token
    except OSError:
        raise Error('A selected configuration/input cannot be read safely; preserve it and inspect separately.') from None
    finally:
        os.close(fd)


class Bridge:
    def __init__(self, prefix, home=None, template_root=None, config_home=None, zdotdir=None, state_dir=None):
        if os.geteuid() == 0:
            raise Error('Open this application as your ordinary user, without sudo.')
        self.prefix = Path(prefix)
        explicit = home is not None
        self.home = Path(home) if explicit else Path.home()
        self.paths = {'home': self.home,
            'template_root': Path(template_root) if template_root else self.prefix / 'share/cachy-asahi',
            'config_home': Path(config_home or (os.environ.get('XDG_CONFIG_HOME') if not explicit else '') or self.home / '.config'),
            'zdotdir': Path(zdotdir or (os.environ.get('ZDOTDIR') if not explicit else '') or self.home),
            'state_dir': Path(state_dir or ((Path(os.environ['XDG_STATE_HOME']) / 'cachy-asahi/setup')
                if not explicit and os.environ.get('XDG_STATE_HOME') else self.home / '.local/state/cachy-asahi/setup'))}
        if any(not p.is_absolute() or '..' in p.parts or any(ord(c) < 32 or ord(c) == 127 for c in str(p))
               for p in (*self.paths.values(), self.prefix)):
            raise Error('Use absolute configuration paths without control characters or parent traversal.')
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.ticket = None

    def invalidate(self):
        self.ticket = None

    def argv(self, operation, components=(), apply=False):
        if operation not in ('inspect', 'activate', 'recover') or any(c not in COMPONENTS for c in components):
            raise Error('Unknown first-login operation or component.')
        if (operation == 'activate') != bool(components) or (operation == 'inspect' and apply):
            raise Error('Choose components before previewing activation.')
        argv = [str(self.prefix / 'bin/cachy-asahi-first-login'), operation,
                '--setup-helper', str(self.prefix / 'bin/cachy-asahi-setup')]
        if components:
            argv += ['--components', *components]
        for name, path in self.paths.items():
            argv += ['--' + name.replace('_', '-'), str(path)]
        return argv + (['--apply'] if apply else [])

    def invoke(self, operation, components=(), apply=False):
        command = self.argv(operation, components, apply)
        process = None
        output = bytearray()
        end = time.monotonic() + 15
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, close_fds=True, start_new_session=True,
                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if self.cancel.is_set() or time.monotonic() >= end:
                        raise Error('Operation stopped. Inspect again; an interrupted apply may need recovery.')
                    for _, _ in selector.select(0.05):
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(process.stdout)
                        output.extend(chunk)
                        if len(output) > MAX_BYTES:
                            raise Error('Helper report exceeds the supported size; inspect separately.')
                code = process.wait(timeout=max(0.01, end - time.monotonic()))
            data = json.loads(output, object_pairs_hook=pairs, parse_constant=nonconstant)
            if (code not in (0, 1, 2) or not valid_report(data, operation, components, apply)
                    or (apply and code == 0 and (data['mode'] != 'applied'
                        or data['status'] != ('activation-applied' if operation == 'activate' else 'recovery-applied')))):
                raise Error('First-login returned an incompatible report; inspect its CLI separately.')
            return data, code
        except (OSError, ValueError, RecursionError, subprocess.TimeoutExpired):
            raise Error('First-login is unavailable or returned invalid JSON. Check the installed prerequisites.') from None
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
                process.stdout.close()

    def snapshot(self):
        p = self.paths
        files = [p['config_home'] / 'fish/config.fish', p['config_home'] / 'cachy-asahi/hyprland.lua',
                 p['zdotdir'] / '.zshrc']
        files += [p['template_root'] / path for path in TEMPLATES.values()]
        observed = []
        for name in ('state.json', 'journal.json'):
            token, raw = fingerprint(p['state_dir'] / name, include_data=True)
            observed.append((name, token))
            if raw is None:
                continue
            try:
                data = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonconstant)
                if not isinstance(data, dict): raise ValueError()
                records = data.get('components', {}) if name == 'state.json' else data.get('new_state', {}).get('components', {})
                if not isinstance(records, dict) or len(records) > len(TEMPLATES): raise ValueError()
                for component, record in records.items():
                    if component not in TEMPLATES or not isinstance(record, dict): raise ValueError()
                    if 'source_root' in record:
                        files.append(Path(record['source_root']) / TEMPLATES[component])
                if name == 'journal.json' and 'template_root' in data:
                    files += [Path(data['template_root']) / path for path in TEMPLATES.values()]
            except (ValueError, TypeError, AttributeError, RecursionError):
                raise Error('Stored configuration metadata is unsupported. Preserve it and inspect the setup CLI separately.') from None
        files += [self.prefix / path for path in ('bin/cachy-asahi-first-login', 'bin/cachy-asahi-setup',
                  'lib/cachy-asahi/first-login/first_login.py')]
        return observed + [(str(path), fingerprint(path)) for path in sorted(set(files))]

    def preview(self, operation, components=()):
        self.invalidate()
        before = self.snapshot()
        report, code = self.invoke(operation, components)
        after = self.snapshot()
        if before != after:
            raise Error('Inputs changed during preview. Preserve edits and preview again.')
        allowed = ((operation == 'activate' and code == 0 and report.get('status') == 'activation-preview'
                    and report['setup_status'].get('pending', {}).get('status') == 'none'
                    and all(row['available'] for row in report['components']))
                   or (operation == 'recover' and code in (0, 2) and report.get('status') == 'recovery-preview'
                       and report['setup_status'].get('pending', {}).get('status') == 'resumable'))
        result = report.get('setup_result', {})
        if (allowed and report['setup_status'].get('state', {}).get('status') in ('missing', 'valid')
                and report.get('mode') == result.get('mode') == 'preview'
                and result.get('operation') == operation and not result.get('preserved_conflicts')):
            self.ticket = (operation, tuple(components), report, after, time.monotonic())
        return report, code

    def apply(self):
        ticket = self.ticket
        self.invalidate()
        if ticket is None or time.monotonic() - ticket[4] > 120:
            raise Error('Preview expired or is missing. Preview again before applying.')
        operation, components, old, files, _ = ticket
        if files != self.snapshot():
            raise Error('Files or templates changed since preview. Preserve edits and preview again.')
        fresh, code = self.preview(operation, components)
        fresh_ticket = self.ticket
        self.invalidate()
        if fresh_ticket is None or fresh != old or files != fresh_ticket[3]:
            raise Error('Preview is stale or conflicting. Review a fresh preview before applying.')
        return self.invoke(operation, components, True)

    def run(self, action, components=()):
        if not self.lock.acquire(blocking=False):
            raise Error('Another first-login action is still running.')
        try:
            if action == 'inspect':
                self.invalidate(); return self.invoke('inspect')
            if action == 'preview':
                return self.preview('activate', components)
            if action == 'recover-preview':
                return self.preview('recover')
            if action == 'apply':
                return self.apply()
            raise Error('Unknown application action.')
        except BaseException:
            self.invalidate(); raise
        finally:
            self.lock.release()
