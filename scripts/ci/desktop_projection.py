#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project only the two bound Hyprland verification logs to plain UTF-8.

No subprocesses or writes. The original receipt, result flags, and unknown logs
remain untouched. The caller must still apply the generic public export policy.
"""
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import unicodedata
from urllib.parse import unquote

LIMIT = 4 * 1024**2
SPEC = importlib.util.spec_from_file_location('desktop_public_policy', Path(__file__).with_name('integration_export.py'))
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
HEX = re.compile(r'[0-9a-f]{64}\Z')
DEFAULT = '/usr/share/cachy-asahi/hyprland/hyprland.lua'
OPTIONAL = re.compile(r'/tmp/cachy-asahi-desktop-verify-[A-Za-z0-9_-]{1,64}/optional-startup\.lua\Z')
SGR = re.compile(r'\x1b\[[0-9;]{0,64}m')
PAYLOAD = tuple(sorted({f'usr/share/cachy-asahi/hyprland/{name}' for name in
                       ('hyprland.lua', 'waybar.json', 'waybar.css', 'mako.conf')} |
                      {f'usr/share/{part}/cachy-asahi-hyprland-settings/{name}' for part, name in
                       (('doc', 'README.md'), ('licenses', 'NOTICE'), ('licenses', 'LICENSE'))}))
RECEIPT_KEYS = {'schema_version', 'record_type', 'status', 'container_arch', 'container_facts',
                'commands', 'checks', 'hardware_validation', 'graphics_acceleration',
                'portal_audio_session', 'optimization_acceptance', 'headless_compositor',
                'archive_sha256', 'runtime_lock_sha256', 'installed_payload_sha256', 'application_runtime'}


class Refused(ValueError):
    """Stable, bounded refusal without input content in diagnostics."""


def require(condition, code):
    if not condition:
        raise Refused('desktop-projection: ' + code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(root, relative):
    """Open every component without following links; bind before/after identity."""
    path = Path(root)
    require('..' not in path.parts, 'unsafe-root')
    path = Path(os.path.abspath(path)) / relative
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path.anchor, flags | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        before = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= LIMIT, 'unsafe-or-unbounded-file')
        file_fd = os.open(path.name, flags, dir_fd=fd)
        try:
            opened = os.fstat(file_fd)
            require(_identity(opened) == _identity(before), 'file-changed')
            chunks, size = [], 0
            while size <= LIMIT:
                chunk = os.read(file_fd, min(65536, LIMIT + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            require(size == before.st_size and size <= LIMIT and
                    _identity(os.fstat(file_fd)) == _identity(before) and
                    _identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)) == _identity(before),
                    'file-changed')
            return b''.join(chunks)
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: require(False, 'nonfinite-json'))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Refused('desktop-projection: invalid-receipt') from None


def _authority(value):
    require(type(value) is dict and set(value) == {'source_commit', 'image_id', 'nonce',
            'archive_sha256', 'runtime_lock_sha256'}, 'authority-schema')
    require(all(type(item) is str for item in value.values()), 'authority-types')
    require(re.fullmatch(r'[0-9a-f]{40}', value['source_commit']) and
            re.fullmatch(r'[0-9a-f]{32}', value['nonce']) and
            re.fullmatch(r'sha256:[0-9a-f]{64}', value['image_id']) and
            HEX.fullmatch(value['archive_sha256']) and HEX.fullmatch(value['runtime_lock_sha256']),
            'authority-values')


def _facts(facts, authority):
    require(type(facts) is dict and set(facts) == {'marker', 'arch', 'uid', 'mounts', 'capabilities',
            'no_new_privileges', 'interfaces', 'namespaces', 'nonce', 'image_id', 'marker_env', 'runner'},
            'container-schema')
    require(facts['marker'] is True and facts['arch'] == 'aarch64' and type(facts['uid']) is int and
            0 < facts['uid'] <= 2**32 - 1 and facts['marker_env'] == '1' and
            facts['runner'] == '/runner/desktop.py' and facts['interfaces'] == ['lo'] and
            facts['no_new_privileges'] == '1', 'container-isolation')
    require(facts['nonce'] == authority['nonce'] and facts['image_id'] == authority['image_id'], 'container-binding')
    caps = facts['capabilities']
    require(type(caps) is dict and set(caps) == {'CapEff', 'CapPrm', 'CapBnd'} and
            all(type(value) is int and value == 0 for value in caps.values()), 'container-capabilities')
    namespaces = facts['namespaces']
    require(type(namespaces) is dict and set(namespaces) == {'mnt', 'net', 'pid', 'user'} and
            all(type(value) is str and re.fullmatch(name + r':\[[0-9]+\]', value)
                for name, value in namespaces.items()), 'container-namespaces')
    mounts = facts['mounts']
    standard = {'/', '/proc', '/dev', '/dev/pts', '/sys', '/sys/fs/cgroup', '/dev/mqueue', '/dev/shm',
                '/tmp', '/inputs', '/runner', '/out', '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
                '/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger', '/proc/acpi',
                '/proc/scsi', '/sys/firmware', '/proc/interrupts', '/proc/kcore', '/proc/keys',
                '/proc/latency_stats', '/proc/timer_list', '/proc/asound', '/proc/timer_stats',
                '/proc/sched_debug', '/sys/devices/virtual/powercap'}
    require(type(mounts) is dict and set(mounts) <= standard and
            {'/', '/inputs', '/runner', '/out', '/tmp'} <= set(mounts), 'container-mounts')
    for name, entry in mounts.items():
        require(type(entry) is dict and set(entry) == {'flags', 'type'} and type(entry['type']) is str and
                type(entry['flags']) is list and all(type(flag) is str for flag in entry['flags']) and
                len(set(entry['flags'])) == len(entry['flags']), 'container-mount-schema')
        require(('ro' in entry['flags']) != ('rw' in entry['flags']), 'container-mount-mode')
    require(mounts['/']['type'] in ('overlay', 'fuse-overlayfs') and 'ro' in mounts['/']['flags'] and
            all('ro' in mounts[name]['flags'] for name in ('/inputs', '/runner')) and
            'rw' in mounts['/out']['flags'] and 'rw' in mounts['/tmp']['flags'] and
            mounts['/tmp']['type'] == 'tmpfs', 'container-required-mounts')


def _receipt(value, authority):
    require(type(value) is dict and set(value) == RECEIPT_KEYS and type(value['schema_version']) is int and
            value['schema_version'] == 1 and value['record_type'] == 'desktop-container-verification' and
            value['status'] == 'desktop-container-verifier-pass' and value['container_arch'] == 'aarch64',
            'receipt-schema-or-status')
    require(all(value[name] == authority[name] for name in ('archive_sha256', 'runtime_lock_sha256')), 'input-binding')
    _facts(value['container_facts'], authority)
    require(all(value[name] == 'NOT RUN' for name in ('hardware_validation', 'graphics_acceleration',
            'portal_audio_session', 'optimization_acceptance')), 'acceptance-flags')
    require(type(value['headless_compositor']) is dict and value['headless_compositor'].get('attempted') is False and
            value['headless_compositor'] == {'status': 'BLOCKED', 'attempted': False,
            'reason': 'pinned Aquamarine 0.15.1 requires a DRM-backed GBM allocator; /dev/dri is excluded'}, 'headless-status')
    checks = {name: 'PASS' for name in ('installed_payload', 'runtime_inventory', 'lua_syntax',
              'Hyprland_default_and_optional_verifier', 'waybar_strict_JSON_syntax_only', 'mako_source_audited_subset_only')}
    checks['GTK3_CSS_parser'] = {'status': 'PASS', 'parser': 'GTK3 CssProvider', 'display_created': False}
    require(value['checks'] == checks and type(value['checks']) is dict and
            value['checks']['GTK3_CSS_parser']['display_created'] is False, 'receipt-checks')
    apps = value['application_runtime']
    require(type(apps) is dict and set(apps) == {'waybar', 'mako'}, 'application-schema')
    for app in apps.values():
        require(type(app) is dict and set(app) == {'status', 'installed', 'reason'} and
                app['status'] == 'NOT RUN' and type(app['installed']) is bool and app['reason'] in
                ('no bar/notifier session launched; optional app not in frozen lock',
                 'syntax checks do not exercise the application session'), 'application-status')
    payload = value['installed_payload_sha256']
    require(type(payload) is dict and set(payload) == set(PAYLOAD) and
            all(type(item) is str and HEX.fullmatch(item) for item in payload.values()), 'payload-schema')
    commands = value['commands']
    require(type(commands) is list and len(commands) == 22, 'command-count')
    for row in commands:
        require(type(row) is dict and set(row) == {'argv', 'returncode', 'error', 'log_sha256', 'stdout'} and
                type(row['returncode']) is int and row['returncode'] == 0 and row['error'] is None and
                type(row['log_sha256']) is str and HEX.fullmatch(row['log_sha256']) and
                type(row['stdout']) is str and type(row['argv']) is list and
                all(type(arg) is str for arg in row['argv']), 'command-schema-or-status')
    archive = '/inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz'
    expected = [['/usr/bin/pacman', '-Q'], ['/usr/bin/bsdtar', '-xOf', archive, '.PKGINFO'],
                ['/usr/bin/bsdtar', '-tf', archive]]
    for path in PAYLOAD:
        expected.extend([['/usr/bin/bsdtar', '-xOf', archive, path], ['/usr/bin/pacman', '-Qoq', '/' + path]])
    optional = commands[20]['argv']
    require(len(optional) == 4 and OPTIONAL.fullmatch(optional[3]), 'optional-config-path')
    expected.extend([['/usr/bin/Hyprland', '--version'], ['/usr/bin/luac', '-p', DEFAULT],
                     ['/usr/bin/Hyprland', '--verify-config', '--config', DEFAULT],
                     ['/usr/bin/Hyprland', '--verify-config', '--config', optional[3]],
                     ['/usr/bin/python3', '/runner/desktop.py', '--gtk-css', '/usr/share/cachy-asahi/hyprland/waybar.css']])
    require([row['argv'] for row in commands] == expected, 'command-sequence')


def _private(text):
    """The generic credential rule also sees encoded spellings; never redact."""
    views = {text}
    for _ in range(3):
        expanded = set(views)
        for view in views:
            expanded.add(html.unescape(unquote(view)))
            expanded.add(re.sub(r'\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))',
                                lambda match: chr(int(match[1] or match[2], 16)), view))
        if expanded == views:
            break
        views = expanded
    require(all(not policy.PRIVATE_CONTENT.search(view) and not policy.PRIVATE_CONTENT.search(
                ''.join(char for char in SGR.sub('', view) if unicodedata.category(char) != 'Cf'))
                for view in views), 'private-content')


def _plain(data, config=None):
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        raise Refused('desktop-projection: invalid-utf8') from None
    _private(text)
    plain = SGR.sub('', text)
    require(all((ord(char) >= 32 and ord(char) != 127 and unicodedata.category(char) not in ('Cf', 'Cc'))
                or char in '\n\r\t' for char in plain), 'unreviewed-terminal-control')
    _private(plain)
    require('config ok' in plain.splitlines(), 'missing-config-success')
    if config is not None:
        require(plain.startswith("DEBUG ]: User-specified config location: '" + config + "'\n"), 'stdout-config-context')
    return plain.encode('utf-8')


def project(raw, authority):
    """Return (two plain log byte strings, public hash/binding index), or refuse."""
    _authority(authority)
    try:
        receipt_data = _read(raw, 'desktop/desktop.json')
        value = _json(receipt_data)
        _receipt(value, authority)
        projected, bindings = {}, []
        for command_index in (19, 20):
            relative = f'desktop/command-{command_index}.txt'
            data = _read(raw, relative)
            row = value['commands'][command_index]
            try:
                stdout = row['stdout'].encode('utf-8')
            except UnicodeError:
                raise Refused('desktop-projection: invalid-stdout') from None
            require(digest(data) == row['log_sha256'] and data == stdout, 'raw-log-binding')
            plain = _plain(data, row['argv'][3])
            projected[relative] = plain
            bindings.append({'path': relative, 'command_index': command_index, 'argv': list(row['argv']),
                             'returncode': 0, 'error': None, 'raw_sha256': digest(data), 'raw_bytes': len(data),
                             'public_sha256': digest(plain), 'public_bytes': len(plain)})
        index = {'schema_version': 1, 'record_type': 'desktop-terminal-projections',
                 'projection': 'Hyprland verify-config SGR presentation only',
                 'authority': dict(authority), 'receipt_path': 'desktop/desktop.json',
                 'receipt_sha256': digest(receipt_data), 'receipt_bytes': len(receipt_data),
                 'receipt_status': value['status'], 'container_arch': 'aarch64',
                 'hardware_validation': 'NOT RUN', 'graphics_acceleration': 'NOT RUN',
                 'portal_audio_session': 'NOT RUN', 'optimization_acceptance': 'NOT RUN',
                 'files': bindings}
        return projected, index
    except OSError:
        raise Refused('desktop-projection: filesystem-read') from None


def projections(raw, authority):
    return project(raw, authority)[0]


def projection_index(raw, authority):
    return project(raw, authority)[1]
