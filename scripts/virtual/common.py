#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed contracts for the disposable generic ARM guest proof."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
from contextlib import contextmanager

GIB = 1024 ** 3
MAX_LOG = 64 * 1024 ** 2
OVERLAYS = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
            'cachy-asahi-zsh-config', 'cachy-asahi-setup'}
SAFE_CAPS = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4)  # CHOWN/DAC_OVERRIDE/FOWNER/FSETID, fixture metadata only
IMAGE_SHA = '92445dac35421e6cba8ccf7b3e7de8fe8ca8914b69db26fce4a5162352f5dc0a'
KERNEL = '7.2.10-1-aarch64-ARCH'
QEMU_COMMIT = '4fc49f46dc95d4a27de2509e7fceb2931e91faeb'


class Refused(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def json_load(path):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise Refused('nonfinite JSON')
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs, parse_constant=constant)


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def relative(value):
    require(isinstance(value, str) and value and '\\' not in value and
            all(x not in ('', '.', '..') for x in value.split('/')) and
            not any(ord(x) < 32 or ord(x) == 127 for x in value), 'unsafe relative path')
    return value


def pinned(root, name, sha):
    path = Path(root) / relative(name)
    require(re.fullmatch('[0-9a-f]{64}', sha or ''), 'invalid digest')
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'symlink input')
    require(path.is_file() and path.stat().st_nlink == 1, 'regular singly linked input required')
    require(digest(path) == sha, f'input hash differs: {name}')
    return path


def inventory(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in result, 'invalid package inventory')
        result[fields[0]] = fields[1]
    require(result, 'empty inventory')
    return result


def mounts(text):
    result = {}
    for row in text.splitlines():
        before, after = row.split(' - ', 1)
        fields = before.split()
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        result[point] = {'flags': fields[5].split(','), 'type': after.split()[0]}
    return result


def facts():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    marker = Path('/.dockerenv')
    return {'uid': os.geteuid(), 'arch': platform.machine(),
            'docker': marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            'caps': {k: int(status[k].strip(), 16) for k in ('CapEff', 'CapPrm', 'CapBnd')},
            'nnp': status['NoNewPrivs'].strip(),
            'mounts': mounts(Path('/proc/self/mountinfo').read_text()),
            'interfaces': sorted(x.name for x in Path('/sys/class/net').iterdir()),
            'devices': any(Path(x).exists() for x in ('/dev/dri', '/dev/input', '/dev/snd', '/dev/kvm', '/dev/fuse', '/dev/mem')) or
                       any(stat.S_ISBLK(x.lstat().st_mode) for x in Path('/dev').rglob('*') if not x.is_symlink()),
            'docker_socket': any(Path(x).exists() for x in ('/run/docker.sock', '/var/run/docker.sock')),
            'nonce': os.getenv('CACHY_ASAHI_VIRTUAL_NONCE', ''),
            'image_id': os.getenv('CACHY_ASAHI_IMAGE_ID', ''),
            'marker': os.getenv('CACHY_ASAHI_DISPOSABLE_VIRTUAL', ''),
            'runner': str(Path(__file__).resolve().parent)}


def validate_environment(f, preparation=False):
    require(f['marker'] == '1' and f['docker'] and f['arch'] == 'aarch64', 'explicit disposable native ARM Docker required')
    require((f['uid'] == 0) == preparation, 'root is permitted only for fixture preparation')
    require(not preparation or f['caps']['CapEff'] == SAFE_CAPS, 'preparation requires exact metadata-only capabilities')
    require(f['nnp'] == '1' and not any(v & ~(SAFE_CAPS if preparation else 0) for v in f['caps'].values()), 'privileged capabilities refused')
    require(f['interfaces'] == ['lo'] and not f['devices'] and not f['docker_socket'], 'network/host-device/socket exposure refused')
    require(re.fullmatch('[0-9a-f]{32}', f['nonce']) and re.fullmatch('sha256:[0-9a-f]{64}', f['image_id']), 'nonce/immutable installed-image identity required')
    require(f['runner'] == '/runner/virtual', 'fixed read-only runner location required')
    table = f['mounts']
    for path, flag, kind in (('/', 'ro', None), ('/inputs', 'ro', None), ('/runner', 'ro', None), ('/out', 'rw', None), ('/tmp', 'rw', 'tmpfs')):
        entry = table.get(path, {})
        require(flag in entry.get('flags', []) and (not kind or entry.get('type') == kind), 'required isolated mount absent: ' + path)
    require(table['/']['type'] in ('overlay', 'fuse-overlayfs'), 'disposable overlay root required')
    for path in table:
        require(not any(path.startswith(x + '/') for x in ('/inputs', '/runner', '/out', '/tmp')), 'nested work/input mount refused')
        if any(path == x or path.startswith(x + '/') for x in ('/usr', '/etc', '/var', '/home', '/root', '/run', '/boot')):
            require(path in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'), 'host system-path mount refused')


def guard(preparation=False):
    f = facts()
    validate_environment(f, preparation)
    require(not any(os.getenv(x) for x in ('DISPLAY', 'WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'DBUS_SESSION_BUS_ADDRESS', 'PULSE_SERVER', 'PIPEWIRE_REMOTE')), 'inherited host connection refused')
    return f


def contract(path, sha, f):
    require(path.parent == Path('/inputs') and not path.is_symlink(), 'contract must be directly below /inputs')
    c = json_load(pinned('/inputs', path.name, sha))
    require(c.get('schema_version') == 1 and c.get('execution') == 'qemu-tcg-generic-aarch64', 'unsupported proof contract')
    require(c.get('nonce') == f['nonce'] and c.get('image_id') == f['image_id'], 'contract image/nonce differs')
    require(re.fullmatch('[0-9a-f]{40}', c.get('source_commit', '')), 'reviewed source commit required')
    require(isinstance(c.get('output_uid'), int) and isinstance(c.get('output_gid'), int) and
            1000 <= c['output_uid'] < 60000 and 1000 <= c['output_gid'] < 60000, 'bounded controller UID/GID required')
    rows = c.get('baseline')
    require(isinstance(rows, list) and len(rows) == 4 and {r.get('name') for r in rows} == OVERLAYS, 'all four original overlay archives required')
    for row in rows:
        require(isinstance(row.get('version'), str) and re.fullmatch('[A-Za-z0-9._+:~-]+', row['version']), 'invalid original version')
        pinned('/inputs', row['archive'], row['sha256'])
        require(isinstance(row.get('payload_sha256'), dict) and row['payload_sha256'], 'original complete payload map required')
        for name, value in row['payload_sha256'].items():
            require(relative(name).startswith('usr/') and re.fullmatch('[0-9a-f]{64}', value), 'invalid original payload map')
    receipt = json_load(pinned('/inputs', c['baseline_handoff'], c['baseline_handoff_sha256']))
    require(receipt.get('status') == 'PASS' and receipt.get('baseline_handoff_ready') is True,
            'successful original installed-image handoff required')
    require(receipt.get('handoff_package_versions') == {r['name']: r['version'] for r in rows} and
            receipt.get('handoff_payload_sha256') == {r['name']: r['payload_sha256'] for r in rows}, 'handoff originals differ')
    barrier_contract(c, Path('/inputs'))
    transaction_contract(c, Path('/inputs'))
    return c


BARRIER_PURPOSE = 'installer-barrier-only'
BARRIER_FRAME_LINES = {'SELECTED_WORKER': 1325, 'SELECTED_TEST': 1757, 'SELECTED_RUNTIME': 280, 'GUEST': 2048}
BARRIER_TEST = 'test_actual_isolate_keeps_host_readonly_and_only_evidence_persistent'
BARRIER_SOURCE = 'd4313163538f51d85bc03e6a4adfde0c850cbc30'
BARRIER_FILES = {
    'scripts/install/local_transaction.py': {'bytes': 82312, 'sha256': '966aedf602511bedfc8ee8e12c29f21a7ff6b79523e4c5800b2a22a2af826eca'},
    'scripts/install/test_local_transaction.py': {'bytes': 114659, 'sha256': 'ea5299f12b4d325035ebca1476feb2832e0d8e95980a456910ac302e845aefdb'},
    'scripts/port/kernel-native-job/runtime.py': {'bytes': 11345, 'sha256': '8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'},
}


def barrier_contract(c, root=None):
    purpose = c.get('purpose', 'desktop')
    require(purpose in ('desktop', BARRIER_PURPOSE, TRANSACTION_PURPOSE), 'unsupported virtual purpose')
    if purpose != BARRIER_PURPOSE:
        require('barrier_fixture' not in c, 'barrier fixture requires explicit purpose')
        return False
    expected = {'source_commit': BARRIER_SOURCE, 'test': BARRIER_TEST, 'files': BARRIER_FILES}
    require(json.dumps(c.get('barrier_fixture'), sort_keys=True) == json.dumps(expected, sort_keys=True),
            'exact selected barrier fixture required')
    if root is not None:
        for name, row in BARRIER_FILES.items():
            path = pinned(root, name, row['sha256'])
            require(path.stat().st_size == row['bytes'] and not path.stat().st_mode & 0o022,
                    'barrier fixture size/protection differs')
    return True


def barrier_event(event, nonce, selection):
    """One fixed result, never raw unittest failure text or a desktop claim."""
    keys = {'event', 'nonce', 'selection_sha256', 'fixture_source', 'uid', 'gid',
            'tests', 'failures', 'errors', 'skips', 'status', 'report', 'first_failure'}
    require(type(event) is dict and set(event) == keys and event['event'] == 'barrier_result' and
            event['nonce'] == nonce and event['selection_sha256'] == selection and
            event['fixture_source'] == BARRIER_SOURCE and
            type(event['uid']) is int and event['uid'] == 23001 and
            type(event['gid']) is int and event['gid'] == 23001,
            'barrier result identity differs')
    require(all(type(event[k]) is int and 0 <= event[k] <= 1 for k in ('tests', 'failures', 'errors', 'skips')),
            'invalid single test counts')
    failure = event['first_failure']
    if failure is not None:
        require(type(failure) is dict and set(failure) == {'exception', 'errno', 'frames', 'unshare_tool_error'},
                'invalid barrier failure')
        require(failure['exception'] in ('AssertionError', 'OSError', 'PermissionError', 'FileNotFoundError',
                'TimeoutExpired', 'ValueError', 'RuntimeError', 'KeyboardInterrupt', 'SystemExit', 'OTHER') and
                (failure['errno'] is None or type(failure['errno']) is int and 1 <= failure['errno'] <= 4095),
                'invalid barrier exception')
        require(type(failure['frames']) is list and len(failure['frames']) <= 8 and all(
                type(row) is dict and set(row) == {'source', 'line'} and
                row['source'] in BARRIER_FRAME_LINES and
                type(row['line']) is int and 1 <= row['line'] <= BARRIER_FRAME_LINES[row['source']] for row in failure['frames']),
                'invalid barrier source frame')
        tool = failure['unshare_tool_error']
        require(type(tool) is dict and set(tool) == {'stage', 'errno'} and
                tool['stage'] in ('PROC_MOUNT', 'ROOT_PROPAGATION', 'UNSHARE_CALL', 'UNRECOGNIZED_OR_ABSENT') and
                (tool['errno'] == 'UNAVAILABLE' or type(tool['errno']) is int and 1 <= tool['errno'] <= 4095),
                'invalid unshare suffix')
    if event['status'] == 'PASS_BARRIER_ONLY':
        expected = {'status': 'PASS-barrier-only', 'worker_sha256': BARRIER_FILES['scripts/install/local_transaction.py']['sha256'],
            'outside_errno': 30, 'uid': 0, 'namespace_changed': True,
            'denied_service_syscalls': {str(n): 1 for n in (203, 206, 211, 269, 425, 426, 427)},
            'capabilities': {'CapEff': 0x400cb, 'CapPrm': 0x400cb, 'CapBnd': 0x400cb, 'CapInh': 0, 'CapAmb': 0},
            'no_new_privileges': 1, 'libalpm_initialized': False, 'package_commit': False,
            'host_namespace_unchanged': True, 'outside_bytes_unchanged': True,
            'guest_file_absent_on_host': True, 'evidence_marker_persisted': True}
        # Canonical JSON also distinguishes booleans from integers in nested facts.
        require(event['tests'] == 1 and not any(event[k] for k in ('failures', 'errors', 'skips')) and
                failure is None and json.dumps(event['report'], sort_keys=True) == json.dumps(expected, sort_keys=True),
                'incomplete barrier proof')
    else:
        require(event['status'] == 'FAIL' and event['report'] is None and
                (failure is not None or event['skips'] == 1), 'invalid failed barrier result')
    return event


TRANSACTION_PURPOSE = 'installer-transaction-only'
TRANSACTION_FILES = {
    'scripts/install/local_transaction.py': {'bytes': 93752, 'sha256': '14381d049506b52770059bf7af415f7a079f69872543e74417aca11ce24ac3c5'},
    'scripts/install/test_local_transaction.py': {'bytes': 131063, 'sha256': '1987ed23821da917215e9e3366545810d565ece08406fafd429a8c3c772eb2cd'},
    'scripts/port/kernel-native-job/runtime.py': {'bytes': 11345, 'sha256': '8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'},
}
# Exact17 methods in original definition order; declared-after has its own closed refusal.
TRANSACTION_CASES = (
    ('SIGNED_PAIR', 'test_actual_signed_tiny_dependency_pair_commit', ('PAIR',)),
    ('MISSING_DEPENDENCY', 'test_actual_missing_dependency_refuses_before_commit', ('PREPARE',)),
    ('WRONG_SIGNER', 'test_actual_wrong_signer_refuses_before_commit', ('SIGNER',)),
    ('INVALID_SIGNATURE', 'test_actual_invalid_signature_refuses_before_commit', ('INVALID',)),
    ('SECRET_CERTIFICATE', 'test_actual_secret_certificate_refuses_before_commit', ('SECRET',)),
    ('SIGNATURE_SUBKEY', 'test_actual_signature_subkey_binds_primary_signer', ('ADD',)),
    ('INPUT_HARDLINK', 'test_actual_input_hardlink_refused_without_commit', ('SNAPSHOT',)),
    ('ESCAPING_ARCHIVE', 'test_actual_escaping_signed_archive_refused_without_escape', ('ESCAPE',)),
    ('EXTERNAL_ROOT_HARDLINK', 'test_actual_existing_root_external_hardlink_refused', ('SNAPSHOT',)),
    ('FILE_CONFLICT', 'test_actual_file_conflict_preserves_foreign_bytes', ('CONFLICT',)),
    ('DECLARED_AFTER', 'test_declared_after_mismatch_refuses_before_commit', ('DECLARED',)),
    ('PROTECTED_UPGRADE', 'test_actual_protected_upgrade_refuses_before_commit', ('ADD', 'REFUSED')),
    ('PROTECTED_REMOVAL', 'test_actual_protected_removal_refuses_before_commit', ('ADD', 'REFUSED')),
    ('SIGNED_SEED_REMOVAL', 'test_actual_signed_removal_uses_installed_seed', ('ADD', 'REMOVE')),
    ('UPGRADE', 'test_actual_upgrade_changes_installed_version_and_payload', ('ADD', 'UPGRADE')),
    ('PROTECTED_UNRELATED_ADD', 'test_actual_unrelated_add_preserves_protected_package_and_file', ('ADD', 'PROTECTED_ADD')),
    ('WRONG_BEFORE_INVENTORY', 'test_actual_wrong_before_inventory_refuses_before_commit', ('PREPARE',)),
)
TRANSACTION_TESTS = tuple(row[1] for row in TRANSACTION_CASES)
TRANSACTION_SELECTORS = tuple(row[0] for row in TRANSACTION_CASES)
TRANSACTION_FRAME_LINES = {'SELECTED_WORKER': 1450, 'SELECTED_TEST': 1958, 'SELECTED_RUNTIME': 280, 'GUEST': 2048}
TRANSACTION_PROFILE = {'path': '/usr/local/share/virtual-proof/tool-profile.json', 'size': 47593,
                       'sha256': 'b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8'}
TRANSACTION_LAUNCHER = {
    'aliases': {'/usr/bin/setpriv': '/usr/bin/setpriv', '/usr/lib/libcap-ng.so.0': '/usr/lib/libcap-ng.so.0.0.0',
                '/lib/ld-linux-aarch64.so.1': '/usr/lib/ld-linux-aarch64.so.1'},
    'files': {
        '/usr/bin/setpriv': {'bytes': 133344, 'sha256': '395f9244208ba1ca9941dafcf8881673095f2c3e7e5b177e559bd76048fac500'},
        '/usr/lib/libcap-ng.so.0.0.0': {'bytes': 67704, 'sha256': 'c62b668a9810af6a194d5808e9498b5bb59f3d1f350d4ea66f0017a177b945f0'},
        '/usr/lib/libc.so.6': {'bytes': 1853736, 'sha256': '6ab264fb4e8df9942b0fb75b48fcd5c30b2f081d8dfaa6c25d7be1d3fce5b2ab'},
        '/usr/lib/ld-linux-aarch64.so.1': {'bytes': 201832, 'sha256': 'b1f2738bdb51e6419d7062f96c8a44bd68853698dc5ac624fa6ca9f9b03d456d'},
    },
}

TRANSACTION_PROFILE_BYTES = b'{\n  "ABI": "actual observation NOT RUN",\n  "aliases": {\n    "/lib/ld-linux-aarch64.so.1": "/usr/lib/ld-linux-aarch64.so.1",\n    "/usr/bin/gpg": "/usr/bin/gpg",\n    "/usr/bin/gpg-agent": "/usr/bin/gpg-agent",\n    "/usr/bin/gpgconf": "/usr/bin/gpgconf",\n    "/usr/bin/python3": "/usr/bin/python3.14",\n    "/usr/bin/true": "/usr/bin/true",\n    "/usr/bin/unshare": "/usr/bin/unshare",\n    "/usr/lib/ld-linux-aarch64.so.1": "/usr/lib/ld-linux-aarch64.so.1",\n    "/usr/lib/libacl.so.1.2.2400": "/usr/lib/libacl.so.1.2.2400",\n    "/usr/lib/libalpm.so.16.0.1": "/usr/lib/libalpm.so.16.0.1",\n    "/usr/lib/libarchive.so.13.8.9": "/usr/lib/libarchive.so.13.8.9",\n    "/usr/lib/libassuan.so.9.0.0": "/usr/lib/libassuan.so.9.0.0",\n    "/usr/lib/libbrotlicommon.so.1.2.0": "/usr/lib/libbrotlicommon.so.1.2.0",\n    "/usr/lib/libbrotlidec.so.1.2.0": "/usr/lib/libbrotlidec.so.1.2.0",\n    "/usr/lib/libbrotlienc.so.1.2.0": "/usr/lib/libbrotlienc.so.1.2.0",\n    "/usr/lib/libbz2.so.1.0.8": "/usr/lib/libbz2.so.1.0.8",\n    "/usr/lib/libc.so.6": "/usr/lib/libc.so.6",\n    "/usr/lib/libcom_err.so.2.1": "/usr/lib/libcom_err.so.2.1",\n    "/usr/lib/libcrypto.so.3": "/usr/lib/libcrypto.so.3",\n    "/usr/lib/libcurl.so.4.8.0": "/usr/lib/libcurl.so.4.8.0",\n    "/usr/lib/libexpat.so.1.13.0": "/usr/lib/libexpat.so.1.13.0",\n    "/usr/lib/libffi.so.8.5.0": "/usr/lib/libffi.so.8.5.0",\n    "/usr/lib/libgcc_s.so.1": "/usr/lib/libgcc_s.so.1",\n    "/usr/lib/libgcrypt.so.20.8.9": "/usr/lib/libgcrypt.so.20.8.9",\n    "/usr/lib/libgdbm.so.6.0.0": "/usr/lib/libgdbm.so.6.0.0",\n    "/usr/lib/libgdbm_compat.so.4.0.0": "/usr/lib/libgdbm_compat.so.4.0.0",\n    "/usr/lib/libgpg-error.so.0.42.1": "/usr/lib/libgpg-error.so.0.42.1",\n    "/usr/lib/libgpgme.so.45.2.0": "/usr/lib/libgpgme.so.45.2.0",\n    "/usr/lib/libgssapi_krb5.so.2.2": "/usr/lib/libgssapi_krb5.so.2.2",\n    "/usr/lib/libicudata.so.78.3": "/usr/lib/libicudata.so.78.3",\n    "/usr/lib/libicuuc.so.78.3": "/usr/lib/libicuuc.so.78.3",\n    "/usr/lib/libidn2.so.0.4.0": "/usr/lib/libidn2.so.0.4.0",\n    "/usr/lib/libk5crypto.so.3.1": "/usr/lib/libk5crypto.so.3.1",\n    "/usr/lib/libkeyutils.so.1.10": "/usr/lib/libkeyutils.so.1.10",\n    "/usr/lib/libkrb5.so.3.3": "/usr/lib/libkrb5.so.3.3",\n    "/usr/lib/libkrb5support.so.0.1": "/usr/lib/libkrb5support.so.0.1",\n    "/usr/lib/liblz4.so.1.10.0": "/usr/lib/liblz4.so.1.10.0",\n    "/usr/lib/liblzma.so.5.8.4": "/usr/lib/liblzma.so.5.8.4",\n    "/usr/lib/libm.so.6": "/usr/lib/libm.so.6",\n    "/usr/lib/libmpdec.so.4.0.1": "/usr/lib/libmpdec.so.4.0.1",\n    "/usr/lib/libncursesw.so.6.6": "/usr/lib/libncursesw.so.6.6",\n    "/usr/lib/libnghttp2.so.14.29.5": "/usr/lib/libnghttp2.so.14.29.5",\n    "/usr/lib/libnghttp3.so.9.9.0": "/usr/lib/libnghttp3.so.9.9.0",\n    "/usr/lib/libngtcp2.so.16.11.0": "/usr/lib/libngtcp2.so.16.11.0",\n    "/usr/lib/libngtcp2_crypto_ossl.so.0.3.1": "/usr/lib/libngtcp2_crypto_ossl.so.0.3.1",\n    "/usr/lib/libnpth.so.0.3.0": "/usr/lib/libnpth.so.0.3.0",\n    "/usr/lib/libpanelw.so.6.6": "/usr/lib/libpanelw.so.6.6",\n    "/usr/lib/libpsl.so.5.3.5": "/usr/lib/libpsl.so.5.3.5",\n    "/usr/lib/libpython3.14.so.1.0": "/usr/lib/libpython3.14.so.1.0",\n    "/usr/lib/libreadline.so.8.3": "/usr/lib/libreadline.so.8.3",\n    "/usr/lib/libresolv.so.2": "/usr/lib/libresolv.so.2",\n    "/usr/lib/libseccomp.so.2.6.0": "/usr/lib/libseccomp.so.2.6.0",\n    "/usr/lib/libsqlite3.so.3.53.4": "/usr/lib/libsqlite3.so.3.53.4",\n    "/usr/lib/libssh2.so.1.0.1": "/usr/lib/libssh2.so.1.0.1",\n    "/usr/lib/libssl.so.3": "/usr/lib/libssl.so.3",\n    "/usr/lib/libstdc++.so.6.0.35": "/usr/lib/libstdc++.so.6.0.35",\n    "/usr/lib/libunistring.so.5.2.1": "/usr/lib/libunistring.so.5.2.1",\n    "/usr/lib/libuuid.so.1.3.0": "/usr/lib/libuuid.so.1.3.0",\n    "/usr/lib/libxml2.so.16.1.4": "/usr/lib/libxml2.so.16.1.4",\n    "/usr/lib/libz.so.1.3.2": "/usr/lib/libz.so.1.3.2",\n    "/usr/lib/libzstd.so.1.5.7": "/usr/lib/libzstd.so.1.5.7",\n    "/usr/lib/python3.14/lib-dynload/_asyncio.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_asyncio.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_bisect.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_bisect.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_blake2.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_blake2.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_bz2.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_bz2.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_codecs_cn.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_codecs_cn.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_codecs_hk.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_codecs_hk.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_codecs_iso2022.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_codecs_iso2022.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_codecs_jp.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_codecs_jp.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_codecs_kr.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_codecs_kr.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_codecs_tw.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_codecs_tw.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_csv.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_csv.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_ctypes.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_ctypes.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_ctypes_test.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_ctypes_test.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_curses.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_curses.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_curses_panel.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_curses_panel.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_dbm.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_dbm.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_decimal.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_decimal.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_elementtree.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_elementtree.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_gdbm.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_gdbm.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_heapq.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_heapq.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_hmac.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_hmac.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_interpchannels.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_interpchannels.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_interpqueues.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_interpqueues.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_interpreters.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_interpreters.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_json.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_json.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_lsprof.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_lsprof.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_lzma.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_lzma.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_md5.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_md5.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_multibytecodec.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_multibytecodec.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_multiprocessing.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_multiprocessing.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_pickle.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_pickle.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_posixshmem.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_posixshmem.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_posixsubprocess.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_posixsubprocess.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_queue.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_queue.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_random.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_random.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_remote_debugging.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_remote_debugging.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_sha1.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_sha1.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_sha2.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_sha2.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_sha3.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_sha3.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_socket.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_socket.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_sqlite3.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_sqlite3.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_ssl.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_ssl.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_statistics.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_statistics.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_struct.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_struct.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testbuffer.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testbuffer.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testcapi.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testcapi.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testclinic.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testclinic.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testclinic_limited.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testclinic_limited.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testimportmultiple.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testimportmultiple.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testinternalcapi.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testinternalcapi.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testlimitedcapi.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testlimitedcapi.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testmultiphase.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testmultiphase.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_testsinglephase.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_testsinglephase.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_uuid.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_uuid.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_xxtestfuzz.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_xxtestfuzz.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_zoneinfo.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_zoneinfo.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/_zstd.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/_zstd.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/array.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/array.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/binascii.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/binascii.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/cmath.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/cmath.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/fcntl.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/fcntl.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/grp.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/grp.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/math.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/math.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/mmap.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/mmap.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/pyexpat.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/pyexpat.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/readline.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/readline.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/resource.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/resource.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/select.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/select.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/syslog.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/syslog.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/termios.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/termios.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/unicodedata.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/unicodedata.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/xxlimited.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/xxlimited.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/xxlimited_35.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/xxlimited_35.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/xxsubtype.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/xxsubtype.cpython-314-aarch64-linux-gnu.so",\n    "/usr/lib/python3.14/lib-dynload/zlib.cpython-314-aarch64-linux-gnu.so": "/usr/lib/python3.14/lib-dynload/zlib.cpython-314-aarch64-linux-gnu.so"\n  },\n  "architecture": "aarch64",\n  "excluded_generic_missing": [\n    {\n      "candidates": [],\n      "needed": "libtk8.6.so",\n      "path": "usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-aarch64-linux-gnu.so"\n    },\n    {\n      "candidates": [],\n      "needed": "libtcl8.6.so",\n      "path": "usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-aarch64-linux-gnu.so"\n    }\n  ],\n  "excluded_optional_not_reachable_from_selected_role": [\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "0471153eef9038bf07567d91179b0e872c07867dde227214f0289c847ff98437",\n      "size": 134896\n    }\n  ],\n  "files": [\n    {\n      "owner": "gnupg 2.4.9-3",\n      "path": "/usr/bin/gpg",\n      "sha256": "cf42862f6127c4e4089261dd9286e798750f02f18dc6d9d09db8a6499342b414",\n      "size": 1397904\n    },\n    {\n      "owner": "gnupg 2.4.9-3",\n      "path": "/usr/bin/gpg-agent",\n      "sha256": "ad4f93e53499688d9d867a70e97be740327fad9c14424df61747db123858664e",\n      "size": 529760\n    },\n    {\n      "owner": "gnupg 2.4.9-3",\n      "path": "/usr/bin/gpgconf",\n      "sha256": "9d18d3e7f2d48bd93964c06064a125399c951751455d797e176524d89ee4e2e7",\n      "size": 204152\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/bin/python3.14",\n      "sha256": "d1f9615fa32814f0bb9149959a72450c2d45e14fa8fe1e9c5ce41dc40d659350",\n      "size": 67720\n    },\n    {\n      "owner": "coreutils 9.12-2",\n      "path": "/usr/bin/true",\n      "sha256": "188f60223e6f443dfc16deab009a5e425145a3aa7cf2d897e7444b22ded74b68",\n      "size": 68024\n    },\n    {\n      "owner": "util-linux 2.42.4-1",\n      "path": "/usr/bin/unshare",\n      "sha256": "4b36ec42b72b23f75e7eb4fec2fca4af93837e714135c6779d11d6087a806247",\n      "size": 133560\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/ld-linux-aarch64.so.1",\n      "sha256": "b1f2738bdb51e6419d7062f96c8a44bd68853698dc5ac624fa6ca9f9b03d456d",\n      "size": 201832\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libacl.so.1.2.2400",\n      "sha256": "976ae00af71340cf57b1502f45a657897dd5f8951b7ed1a18ecbf9739f751866",\n      "size": 67568\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libalpm.so.16.0.1",\n      "sha256": "94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902",\n      "size": 330416\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libarchive.so.13.8.9",\n      "sha256": "fb1d670516898b869eef8f468ee68cd4d6217eb33d375bf2fdfb4fbca466e601",\n      "size": 919544\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libassuan.so.9.0.0",\n      "sha256": "3e51b38189c734a5978d11b4658ae908086c5d76558b4965114c90454d8d276c",\n      "size": 133216\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libbrotlicommon.so.1.2.0",\n      "sha256": "93d374c121f516fe27c7f52f1ac75443bfc221979999cf931ac4145f51d03424",\n      "size": 198528\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libbrotlidec.so.1.2.0",\n      "sha256": "393cd16c4a9b5fc17961c8ac1f4bc5c7b0f3fe5b587bbbddd81f78a14b50462d",\n      "size": 67376\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libbrotlienc.so.1.2.0",\n      "sha256": "bebe45b1a9d93208788aec03c13a04350d8da5ad3870ebbbf864e943ce0c11e7",\n      "size": 854328\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libbz2.so.1.0.8",\n      "sha256": "973f0f527699d7eda3dc15cbc8b236d0c1d877492c4e471b94b15cb51190684a",\n      "size": 70504\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libc.so.6",\n      "sha256": "6ab264fb4e8df9942b0fb75b48fcd5c30b2f081d8dfaa6c25d7be1d3fce5b2ab",\n      "size": 1853736\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libcom_err.so.2.1",\n      "sha256": "e00d7e9f917da09261087bda0b421f1749c8f1536e9ee13f6f0361177243e788",\n      "size": 67576\n    },\n    {\n      "owner": "openssl 3.6.5-1",\n      "path": "/usr/lib/libcrypto.so.3",\n      "sha256": "f17e29025b7dbd0112849ff6e841df5fcc175dabee48cde004321468676bea5b",\n      "size": 6564088\n    },\n    {\n      "owner": "curl 8.22.0-1",\n      "path": "/usr/lib/libcurl.so.4.8.0",\n      "sha256": "5fe1afa1ca8300d325f8691d215630869f13b9e5fbb8469e6550df7fb5832329",\n      "size": 1185104\n    },\n    {\n      "owner": "expat 2.9.0-1",\n      "path": "/usr/lib/libexpat.so.1.13.0",\n      "sha256": "b5bcf7a8c7145d8115ad738ff909d387d35f9f1495cc1014dfc7796962f912ea",\n      "size": 198640\n    },\n    {\n      "owner": "libffi 3.8.0-1",\n      "path": "/usr/lib/libffi.so.8.5.0",\n      "sha256": "8be7610cc71df6b52d7ae8ad50ffd32fedbe47a64184efdb321c6789f84d1605",\n      "size": 67720\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libgcc_s.so.1",\n      "sha256": "ac598673a4bf67c0295b6609e46b1fafd0d4adf3f80a513d61ac49ecff772e48",\n      "size": 133352\n    },\n    {\n      "owner": "libgcrypt 1.12.4-1",\n      "path": "/usr/lib/libgcrypt.so.20.8.9",\n      "sha256": "6f5fd5839f5d3c74394100bfc4de59647a4f5cfe70c4058c17b22b8977f3d6bc",\n      "size": 1333264\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libgdbm.so.6.0.0",\n      "sha256": "68d129abd4f3d60b23819318b960d2c95e7e7074b7e683b538b637223709f7ff",\n      "size": 133152\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libgdbm_compat.so.4.0.0",\n      "sha256": "214aa82e163d4c49c51b99aafebdb602ee7de5a3d4ef71fe89930412d06bb439",\n      "size": 67376\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libgpg-error.so.0.42.1",\n      "sha256": "f673d5ca8f03998f31aa9b8db9da99fbee45f5b74439792ea60e4c5a69333f0e",\n      "size": 198792\n    },\n    {\n      "owner": "gpgme 2.2.0-1",\n      "path": "/usr/lib/libgpgme.so.45.2.0",\n      "sha256": "0d414a37be6eac5d5f8c3f05f752b3429b4866151b20a316b6652a6538bfbb12",\n      "size": 400160\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libgssapi_krb5.so.2.2",\n      "sha256": "4052b927a040e67a9a7716ea1f19cde350a3f3260bbe3e72624cfd9866c2f3c9",\n      "size": 397584\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libicudata.so.78.3",\n      "sha256": "2f624d6c2d92113a45906f245e0d50f4d28572cfe973ede09b25e8422460ba09",\n      "size": 33162960\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libicuuc.so.78.3",\n      "sha256": "76217efb5cf1c42284a1572e6b8f1b13147523b0072d3cc819458be5f657fe40",\n      "size": 2427016\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libidn2.so.0.4.0",\n      "sha256": "5dee65d8352d02fccc0513e25ebf30219ebe762fc94a3a25df8bcf36280a7109",\n      "size": 198680\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libk5crypto.so.3.1",\n      "sha256": "47639a505e412978bf76a92e2cc24e3bc6518f905d97724035b511ae4f123ed4",\n      "size": 198840\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libkeyutils.so.1.10",\n      "sha256": "e6a891119ae81f300411e51e41f450d89e518d572aaeef5f8c6de6bb45166d11",\n      "size": 67576\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libkrb5.so.3.3",\n      "sha256": "4ca6b2605d63224962dfb4db6887952849f64a2c46b1d18463613a99a8c9bd4b",\n      "size": 1054752\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libkrb5support.so.0.1",\n      "sha256": "9dd40bdbe926e0ed663e8c4f449d7f4a99ce2e648b2f0cd3dab7ed17081e4b91",\n      "size": 67824\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/liblz4.so.1.10.0",\n      "sha256": "abbc6d677888c05c812813032fb08f8990a5450124ff9d608c112e150220ba12",\n      "size": 198528\n    },\n    {\n      "owner": "xz 5.8.4-1",\n      "path": "/usr/lib/liblzma.so.5.8.4",\n      "sha256": "ee0801ca9ca614d92f21cd04bc14c31e0624d34c2409362b68971f3e9514b860",\n      "size": 198720\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libm.so.6",\n      "sha256": "71ed8de709c40acd4fd0177258fc71251a5acdb1d075122409ad42529d6c7a4e",\n      "size": 788960\n    },\n    {\n      "owner": "mpdecimal 4.0.1-3",\n      "path": "/usr/lib/libmpdec.so.4.0.1",\n      "sha256": "05e845eee39e758e7edef8c04c2b615f9a385a9d50a74578b74582beecc33049",\n      "size": 198976\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libncursesw.so.6.6",\n      "sha256": "893eea93d2c1011c1f9edee6393cd46475f115d9f2a788e3b55f34591020316b",\n      "size": 527568\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libnghttp2.so.14.29.5",\n      "sha256": "3e2fe8ca94248d8d159e86085be4f1e76c1b6742956a7e60a645c2670f57bfdc",\n      "size": 198712\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libnghttp3.so.9.9.0",\n      "sha256": "ffea4971ecf9ea9acdfff697b33a906022fd47c9b7864e567382af325cc50730",\n      "size": 205824\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libngtcp2.so.16.11.0",\n      "sha256": "b5d13800d86e5305318ea24c9841004129f169586481db6621a54f6200a2fb01",\n      "size": 395280\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libngtcp2_crypto_ossl.so.0.3.1",\n      "sha256": "1f065ec78dad91aa5e8656341f3ffae34216d03366ca574c58f03f5b9a0647f5",\n      "size": 67568\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libnpth.so.0.3.0",\n      "sha256": "56873bd3bce8aac9888cccdb9ad636880fd9165273b29b0295c9a13985c7f548",\n      "size": 67456\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libpanelw.so.6.6",\n      "sha256": "7dd2117e2c7d7e7b5623d522ee9095297bd5a6d48d6c9b4d8291d333d1b2df33",\n      "size": 67504\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libpsl.so.5.3.5",\n      "sha256": "8898566abb931fde7d4814a18d2d4ee1048208c3749fd0dfb00181eb6158e892",\n      "size": 132912\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/libpython3.14.so.1.0",\n      "sha256": "6d01ac24a706adc3d178321b786ab12629998cef33582b2c0d3d38546da75105",\n      "size": 6995416\n    },\n    {\n      "owner": "readline 8.3.6-1",\n      "path": "/usr/lib/libreadline.so.8.3",\n      "sha256": "c5a59b857c964ef34e9cea2499a0777f952938ffc4df2e3d4276f89ff4b31035",\n      "size": 416736\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libresolv.so.2",\n      "sha256": "40f2f2f1049378e1757c1f09813a8bea3a404dfcca73c9a4bbba4a28a713e68e",\n      "size": 67952\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libseccomp.so.2.6.0",\n      "sha256": "bb30f1c00ccfa041ada09a6276eb7d76e937ce58b27a9c7a02684b50a840f8a8",\n      "size": 198584\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libsqlite3.so.3.53.4",\n      "sha256": "2db449a85914b1fefa35388d205fa3a8dc946ee3e8ab289cb8a0bfbdc17f575f",\n      "size": 1657608\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libssh2.so.1.0.1",\n      "sha256": "d4f17dcf082edc006ba751dde368da76c584d2bc9ee81a579682c412e2436ff3",\n      "size": 330264\n    },\n    {\n      "owner": "openssl 3.6.5-1",\n      "path": "/usr/lib/libssl.so.3",\n      "sha256": "aa535edd19a77fccb28418158a69892d17b61ca94cfc8e6d4eeb340d34fb5a91",\n      "size": 1195992\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libstdc++.so.6.0.35",\n      "sha256": "abdf011833740a6f0ca1654876f18d9a5911a9ad08806a38d015e60e3e516ab8",\n      "size": 3017768\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libunistring.so.5.2.1",\n      "sha256": "ac7c4523c7a8567f6a0e3eeadc5999a9f9a70889c9d47e4c041655c9f3984509",\n      "size": 2033736\n    },\n    {\n      "owner": "util-linux-libs 2.42.4-1",\n      "path": "/usr/lib/libuuid.so.1.3.0",\n      "sha256": "98f5106993cd1523eff94cfb46380fd802071113eb6b4e4895042d3bd3c33dc8",\n      "size": 67792\n    },\n    {\n      "owner": "libxml2 2.15.4-1",\n      "path": "/usr/lib/libxml2.so.16.1.4",\n      "sha256": "4b35c8763ef09eb47d84eebe1eb1096388851ab75b1c5ad79f1ddf8e49a4aa47",\n      "size": 1379200\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libz.so.1.3.2",\n      "sha256": "f8d5729601ca8fb86a8d9d048eff241a0e349342da7a5cea11389d0e33ed0a43",\n      "size": 133128\n    },\n    {\n      "owner": "signed-rootfs",\n      "path": "/usr/lib/libzstd.so.1.5.7",\n      "sha256": "14d907be630eb1670d14fc104a0982cca01feac5bc75f1846e54f6278c5ee2e2",\n      "size": 854104\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_asyncio.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "608092221004f11bc21d63c3fd28a17fb741909e511d93c8b586bf1ea3a91bcd",\n      "size": 138072\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_bisect.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "7009c3276e744eb5bfc6bc15ca262b5ac9a876efc4eb6856e26bc6a49c4f27e9",\n      "size": 68184\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_blake2.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "055a0fa99dc7aad0f0d3da69f8967d45ddfc754ab364161cfaf8c098f7cbd249",\n      "size": 68520\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_bz2.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "91567b2a0302f9381836d0531adae8725d30206c3516e2c397abde10e449b3e2",\n      "size": 68400\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_codecs_cn.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "43621cce1c9c6562fad71d6c5c5f61921661b6d8f8a770f575cbcb066548eb3d",\n      "size": 198968\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_codecs_hk.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "2f99ca81480fa87e3e2c55447a32fbca1f43b129f979817d355940ab350d5acb",\n      "size": 198944\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_codecs_iso2022.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "1eb9ade7916512d4a962b62288391c7bcab526b4216b5ee026cff9f8eaa28056",\n      "size": 67800\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_codecs_jp.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "71ef031f63c0ffbf38a29950fe47ce290e127f1729e666d74de49f211c0f0e41",\n      "size": 330208\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_codecs_kr.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "ddbc4f24979f1bba7ad5defccd96de0d627b2fa81c376629f41a3b6c19ab4043",\n      "size": 198944\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_codecs_tw.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "078764f2ddaf56152ab0824fae478f4c8970d67141312167f25a12f787043906",\n      "size": 133384\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_csv.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "466873c80969b27ca7ef82dfa68e7307553a9aba519066e5ccd254e4115c4825",\n      "size": 69616\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_ctypes.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "c54d1c5a7cfa73fe837e8503a863d3d1fad5c82c730b348849629fd7ccfd74bc",\n      "size": 205744\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_ctypes_test.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "0b59a5d5eacd7b693d1b6a5db23537c209322d77a7509f87256a102a66e21e6d",\n      "size": 199080\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_curses.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "8d2c3f19ae9896f423a061ad21f4390adc66c8858f5d87c97df7094dad4e0f43",\n      "size": 204160\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_curses_panel.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "0a6986e48bcbc8daa3c6266319a49d616943979ebf04e2a540fbea42176ec54b",\n      "size": 68640\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_dbm.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "8b4d2074f1d4278feecbfc159808dcbe809e16da6a2b16dd8c0df1641352e06f",\n      "size": 68376\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_decimal.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "be2957bd861fa6ce4671caf8848823c425afedadecad2ce7e74687d4e0388670",\n      "size": 272344\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_elementtree.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "e637bda17a02f8c81a373671c573acfbe64184600ccc8b27838664a3f2a2d14e",\n      "size": 136712\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_gdbm.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "90bfd1a9952a684fe0359e744e46e4c3b2bbd17e97bec7adcc291264fa45a96a",\n      "size": 68448\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_hashlib.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "14967e0609ef9bdc34486f04a1b45432fe1b75f162d4757a853c38b89c90d22a",\n      "size": 71096\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_heapq.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "0370715970e8e2f705702fb27f0b3a41f4c0a66db8a1a4eef238de286f4d1a71",\n      "size": 67856\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_hmac.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "7f5e697411be2db7ea058361d3805d07ab96288e30d955ddab4c4e05192d1754",\n      "size": 199968\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_interpchannels.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "b2de05f669630f802f602dcd9af86fdbcd82ea89a231e7e334f458fc44222c99",\n      "size": 69264\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_interpqueues.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "84707bce975f31da57a50df6c99af7997942d5d723ffebfba61fb35c827ec952",\n      "size": 68320\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_interpreters.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "3eedd9513c7c5ce59442197e55c67f53ae0ae15a4cd17de13c0e610e9c88f0ba",\n      "size": 68848\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_json.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "b19b44be4e20348c1fec024d02861d8c06ca2acd8777eb75c5a7fd86ae1e0fd1",\n      "size": 68912\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_lsprof.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "24c6851a79fad35865ac32bb9c257d76c252e92b79486d2f947c08730e9ac4d3",\n      "size": 68608\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_lzma.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "8da13964ebcd29f951e9aefb5c2ed0248080afd37a35bf755d3676d7c6b585de",\n      "size": 68848\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_md5.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "e50960b73e692da21b6a7159adb2294d49339f6a0d482d42463ac541741a0015",\n      "size": 68304\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_multibytecodec.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "ff054393f78b1fb771b89544f9b2c1b8db8781022e16fcc7660fa0a757df4c6b",\n      "size": 70024\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_multiprocessing.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "dfccee5de7a15e5c3ab4ec07bfb390eafc1d71f0438256e280fe43ca45cf3f78",\n      "size": 68704\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_pickle.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "f0064fd39c5ae3051a57be2f31815148108340ec1d2edeece5781b9000918ddd",\n      "size": 135808\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_posixshmem.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "3234d58279a9863de2ed868353ec8f3a113856800717daf2d4de98f9654c6af5",\n      "size": 67784\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_posixsubprocess.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "fd9ec95a161ef621a8052b78a7f199f74efac18d3811740748c7deba51a002d3",\n      "size": 67712\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_queue.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "d631efb1abb619eb803b15ee5fce9b0de97848708b1390ed828e7f6103e5c2c2",\n      "size": 68448\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_random.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "85c9f59caf370ba6eeb9cc398aefcb8c081dccd9362d91d8acf44dc848148973",\n      "size": 67984\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_remote_debugging.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "274a7dabf6fb8fc6a6c760b051e916afad668c6c9938786a6434685494b2ef20",\n      "size": 134032\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_sha1.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "9adfa0576ec7bae4841202f9bac6cd17e03fd8ee333a1bd6a93ef3d0dd88eec8",\n      "size": 68304\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_sha2.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "473020303d5ba52d9475cbe7fd34c09f1c93cd956a1742d82f20f09237bb22e8",\n      "size": 69112\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_sha3.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "05dea4dfed08cbe0815bc612070d40f758dc585da936a8c7adcfec2a338a5773",\n      "size": 69792\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_socket.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "54e236d2259a257452f4a141772b89e2395e6646585ded906739be5ac14fbc21",\n      "size": 135832\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_sqlite3.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "89a011293b53aab4955ad434fbdf3c25b81d982f5c447b26d747b191957bf26f",\n      "size": 204048\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_ssl.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "bccbbd50bade97a1be9945115966c30c6ec995da19adc05e14c53e21eb41a7e8",\n      "size": 299152\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_statistics.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "efe364194176e1e5784aa2655bc78cd13ae8ece94332ed8f30f2237e4c0e8c25",\n      "size": 67712\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_struct.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "58e8eb56109354353e773770c9d28fefe5727cb02f8f6293f3c8d6ba1778b258",\n      "size": 70792\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testbuffer.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "fabf400fd387730a3d3d5130b9bb733eb199e1e8cb788c47413b43710ac97898",\n      "size": 69904\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testcapi.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "72a480ab6cfb9c2459d1640e41dc52fd4d051708d24f8559132dea13377e2cf7",\n      "size": 432616\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testclinic.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "bc1ee19b8770c3c4a159dab615af1bd7062bad39ce8a2865a4009b5b9118f176",\n      "size": 143984\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testclinic_limited.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "6a2c973e1a5efb1da3f383cc577bc880e1726f7433ea2a1d3c87c8f326760c33",\n      "size": 67664\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testimportmultiple.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "1fd357c6e1e485e469a71e083a8f99fd6ea9b3556a37d027a1d85dfbeb1d9507",\n      "size": 67696\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testinternalcapi.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "f66ce7236a24df630ededee3002731808f7192cdb6cef8f1a63eb4aaac91f0d8",\n      "size": 137808\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testlimitedcapi.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "de97b6d10c93899c3077c789d9e632f39b2460891205f0ee5bfe5c6519613272",\n      "size": 276544\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testmultiphase.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "94f90e3cf977acce5ff71d8f529ad4b32e00c16842a6a151e4106b603d0bfdb5",\n      "size": 71856\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_testsinglephase.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "2df624106cce0d29afe7fdfd1e9291596348234d9dbc80f786dd07da36b3f5d6",\n      "size": 68912\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_uuid.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "69e61938e1c4d8992c94f128a7e8acee24d4b6d8a29d3f24fcb4451314927c49",\n      "size": 67728\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_xxtestfuzz.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "c54f3a84d598e8681d1232750f282b2b456869196b7707685e43c4570bd48003",\n      "size": 67768\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_zoneinfo.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "89fb35353cdbe1388a764059048cf837c3f4c355f323bde6f440d02cf0d2f201",\n      "size": 68976\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/_zstd.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "0c5ce9ec200343845990faeba6acd66f606d46683d7fc4670d84e1bf7a0e239d",\n      "size": 69960\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/array.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "699a9e8c55efb6fb16a20d0527878758ff28ee7c9ee233b5ef501021e71074ff",\n      "size": 135312\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/binascii.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "96b5aedcb809abcfbbd8428e5f23afab907d07fee599fbe0995075fe516a3838",\n      "size": 68656\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/cmath.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "0224f1b9c36495331874cf0d12ff6f5c486272c83befcdb1800ff64471d017cc",\n      "size": 68576\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/fcntl.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "791ae1edf81321253776fcc0e819c67db4a396f594b26731b5f3e1914df0a970",\n      "size": 67824\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/grp.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "795673ba9488e3a2f58f55b2fecbbdb9f2ecca331b160942f8f40aecfd767907",\n      "size": 68120\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/math.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "bb2a63384556af0d6c1e2386adf918b422956ed07316e8f49dac7ed1e2be9c82",\n      "size": 135344\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/mmap.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "44a96103b2061880f07530997a1af13ad0d5a0b617eb74294cd37cf2b5ab215f",\n      "size": 68824\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/pyexpat.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "9edc925c52f59081b0f04ffbd8173b9eb23d8e366a70ec81d986269c154a4eaa",\n      "size": 139416\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/readline.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "c98224874e4c5a2236002cb1e93113acbf4ff3b206676ee685f105319eafff4b",\n      "size": 68504\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/resource.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "f0bda01b773e10b77d683fae0ddb0cad392325a4dd5f791a177972b35148906d",\n      "size": 68160\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/select.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "0054a71dbcd32f633c63313192825152abbb5e7b8956bcb218d9071157c81e19",\n      "size": 68976\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/syslog.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "bea4f171cf20df1ce96897a64c946a0a3df7618cf51301921a5b38f0191d1e00",\n      "size": 68032\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/termios.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "4d0c389395a2a6ea41993f484b65506f9d1f4b713520d51cff516a839e2d6e97",\n      "size": 71968\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/unicodedata.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "6ff240202b71a80951c78dc74cdf4ef3f25c4ea5592fcb67cd92bbbf7022b902",\n      "size": 792008\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/xxlimited.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "6e1f5e592d36ee846bd00564cacf8014bdc7c1df08cd98d107490b5a587b623f",\n      "size": 68160\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/xxlimited_35.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "2b63a38fb2bdee14aea96f52c97d436a1865477eb9ef9fbea4b154aca82f1204",\n      "size": 68144\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/xxsubtype.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "156a4e4e4680701fceb398c01c6970477c7b462940ffe5b784d3bc0660606057",\n      "size": 68976\n    },\n    {\n      "owner": "python 3.14.8-1",\n      "path": "/usr/lib/python3.14/lib-dynload/zlib.cpython-314-aarch64-linux-gnu.so",\n      "sha256": "9750314d1e0fcbbe77542a6f51d3d1f035b80dcc227cae82714fd8c3ebc6a32e",\n      "size": 69912\n    }\n  ],\n  "inputs_sha256": "3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650",\n  "libalpm_expected_abi": "16.0.1",\n  "role_notes": [\n    "GPG private software key generation requires pinned gpg-agent as an internal executable",\n    "All captured Python lib-dynload extensions except unused _tkinter are included conservatively",\n    "No complete optional Python feature claim; no package inventory trimmed"\n  ],\n  "roots": [\n    "usr/bin/python3",\n    "usr/bin/gpg",\n    "usr/bin/gpgconf",\n    "usr/bin/gpg-agent",\n    "usr/bin/unshare",\n    "usr/bin/true",\n    "usr/lib/libalpm.so.16.0.1"\n  ],\n  "schema": 1,\n  "status": "PASS required-role static tool closure; native ABI and execution NOTRUN"\n}\n'


def transaction_contract(c, root=None):
    if c.get('purpose', 'desktop') != TRANSACTION_PURPOSE:
        require('transaction_fixture' not in c and 'transaction_launcher' not in c, 'unselected transaction data')
        return False
    require('barrier_fixture' not in c and type(c.get('source_commit')) is str and
            re.fullmatch('[0-9a-f]{40}', c['source_commit']), 'explicit transaction Source required')
    expected = {'source_commit': c['source_commit'], 'sources': TRANSACTION_FILES, 'tool_profile': TRANSACTION_PROFILE}
    require(json.dumps(c.get('transaction_fixture'), sort_keys=True) == json.dumps(expected, sort_keys=True) and
            json.dumps(c.get('transaction_launcher'), sort_keys=True) == json.dumps(TRANSACTION_LAUNCHER, sort_keys=True),
            'exact reviewed transaction inputs required')
    require(len(TRANSACTION_PROFILE_BYTES) == TRANSACTION_PROFILE['size'] and
            hashlib.sha256(TRANSACTION_PROFILE_BYTES).hexdigest() == TRANSACTION_PROFILE['sha256'], 'fixed profile data differs')
    if root is not None:
        for name, row in TRANSACTION_FILES.items():
            path = pinned(root, name, row['sha256'])
            require(path.stat().st_size == row['bytes'] and not path.stat().st_mode & 0o022, 'transaction Source size/protection differs')
    return True


def transaction_launcher(root):
    """Archive-derived launcher closure, separate from the held worker profile."""
    root = Path(root).resolve(strict=True)
    for alias, target in TRANSACTION_LAUNCHER['aliases'].items():
        require((root / alias.lstrip('/')).resolve(strict=True) == root / target.lstrip('/'), 'launcher alias differs')
    require(not (root / 'etc/ld.so.preload').exists() and not (root / 'etc/ld.so.preload').is_symlink(), 'launcher preload refused')
    for name, row in TRANSACTION_LAUNCHER['files'].items():
        path = root / name.lstrip('/')
        require(all(not p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(root)), 'launcher source symlink')
        for parent in path.parents:
            if not parent.is_relative_to(root): break
            s = parent.stat()
            require(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022, 'launcher parent protection differs')
        before = path.stat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                not before.st_mode & 0o022 and before.st_size == row['bytes'], 'launcher file protection differs')
        pin = digest(path); after = path.stat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(pin == row['sha256'] and identity(before) == identity(after), 'launcher file bytes changed')
    return True


def transaction_call(row, pattern):
    keys = {'returncode','worker_status','phase','commit_started','committed'}
    require(type(row) is dict and set(row)==keys and type(row['returncode']) is int and
            0<=row['returncode']<=255 and type(row['commit_started']) is bool and type(row['committed']) is bool,
            'transaction hop fields differ')
    positive = pattern in ('PAIR','ADD','REMOVE','UPGRADE','PROTECTED_ADD')
    expected = ('complete',True,True) if positive else ('NOT_REPORTED',False,False) if pattern=='REFUSED' else ('declaration-after',False,False) if pattern=='DECLARED' else (
        'commit',True,False) if pattern=='CONFLICT' else ('snapshot',False,False) if pattern=='SNAPSHOT' else (
        'prepare',False,False) if pattern=='PREPARE' else ('isolated',False,False)
    require((row['phase'],row['commit_started'],row['committed'])==expected and
            row['worker_status']==('PASS-disposable-payload-transaction' if positive else 'REFUSED' if pattern in ('REFUSED','DECLARED') else 'FAIL') and
            (row['returncode']==0 if positive else row['returncode']!=0), 'selected transaction hop differs')
    return row


def transaction_method(row, index, *, complete=True):
    patterns=TRANSACTION_CASES[index][2]
    require(type(row) is dict and set(row)=={'method','calls'} and row['method']==TRANSACTION_SELECTORS[index] and
            type(row['calls']) is list and 1<=len(row['calls'])<=len(patterns) and
            (not complete or len(row['calls'])==len(patterns)), 'transaction method fields/count differ')
    for hop,call in enumerate(row['calls']): transaction_call(call,patterns[hop])
    return row


def transaction_event(event, nonce, selection, source):
    keys = {'event','nonce','selection_sha256','fixture_source','uid','gid','tests','failures','errors','skips',
            'status','methods','first_failure','class_cleanups_returned','cancelled'}
    require(type(event) is dict and set(event) == keys and event['event'] == 'transaction_result' and
            event['nonce'] == nonce and event['selection_sha256'] == selection and event['fixture_source'] == source and
            type(source) is str and re.fullmatch('[0-9a-f]{40}', source) and
            type(event['uid']) is int and event['uid'] == 23001 and type(event['gid']) is int and event['gid'] == 23001 and
            all(type(event[k]) is int and 0 <= event[k] <= (17 if k == 'tests' else 32) for k in ('tests','failures','errors','skips')) and
            type(event['class_cleanups_returned']) is bool and type(event['cancelled']) is bool,
            'transaction event identity/counts differ')
    require(type(event['methods']) is list and len(event['methods']) <= 17, 'bounded transaction methods required')
    for i,row in enumerate(event['methods']):
        transaction_method(row,i,complete=event['status']=='PASS_TRANSACTION_ONLY' or i<len(event['methods'])-1)
    failure = event['first_failure']
    if failure is not None:
        # Reuse the existing closed exception/errno/tool domain, with selected Source line bounds.
        proxy = dict(event='barrier_result', nonce=nonce, selection_sha256=selection, fixture_source=BARRIER_SOURCE,
                     uid=23001,gid=23001,tests=0,failures=0,errors=1,skips=0,status='FAIL',report=None,first_failure=failure)
        old_frames = failure.get('frames') if type(failure) is dict else None
        require(type(old_frames) is list and len(old_frames) <= 8 and all(type(row) is dict and set(row)=={'source','line'} and
                row['source'] in TRANSACTION_FRAME_LINES and type(row['line']) is int and
                1 <= row['line'] <= TRANSACTION_FRAME_LINES[row['source']] for row in old_frames), 'transaction failure frames differ')
        proxy['first_failure'] = failure | {'frames': []}
        barrier_event(proxy, nonce, selection)
    if event['status'] == 'PASS_TRANSACTION_ONLY':
        require(event['tests'] == 17 and not any(event[k] for k in ('failures','errors','skips')) and
                len(event['methods']) == 17 and sum(len(row['calls']) for row in event['methods']) == 22 and failure is None and event['class_cleanups_returned'] and not event['cancelled'],
                'incomplete transaction fixture proof')
    else:
        require(event['status'] == 'FAIL' and (failure is not None or event['skips'] > 0), 'invalid failed transaction fixture')
    require(len(json.dumps(event)) <= 8192, 'transaction event bound')
    return event


def check_runtime(c):
    base = inventory(pinned('/inputs', c['base_runtime_lock'], c['base_runtime_lock_sha256']).read_text())
    tooling = json_load(pinned('/inputs', c['tooling_lock'], c['tooling_lock_sha256']))
    require(len(base) == 341 and tooling.get('base_package_count') == 341 and tooling.get('expected_package_count') == 362 and
            tooling.get('qemu_source_commit') == QEMU_COMMIT, 'wrong frozen base/tooling extension')
    audit = json_load(pinned('/inputs', c['tooling_audit'], c['tooling_audit_sha256']))
    require(audit.get('status') == 'PASS' and audit.get('tooling_lock_sha256') == c['tooling_lock_sha256'] and
            set(audit.get('packages', {})) == {r['name'] for r in tooling['packages']}, 'authenticated tooling receipt required')
    expected = dict(base)
    for row in tooling['packages']:
        require(row['name'] not in expected, 'extension may not replace base packages')
        expected[row['name']] = row['version']
    for row in c['baseline']:
        expected[row['name']] = row['version']
    actual = inventory(subprocess.check_output(['/usr/bin/pacman', '-Q'], text=True, timeout=30))
    require(actual == expected, 'installed package inventory differs from full base + tooling + four originals')
    for row in c['baseline']:
        names = subprocess.check_output(['/usr/bin/bsdtar', '-tf', '/inputs/' + row['archive']], text=True, timeout=15).splitlines()
        require(len(names) == len(set(names)) and
                {n for n in names if not n.endswith('/') and n not in ('.PKGINFO', '.BUILDINFO', '.MTREE', '.Changelog')} == set(row['payload_sha256']),
                'original archive payload map is incomplete or contains extra files')
        for name in names:
            relative(name.rstrip('/'))
        metadata = subprocess.check_output(['/usr/bin/bsdtar', '-xOf', '/inputs/' + row['archive'], '.PKGINFO'], text=True, timeout=15)
        require('pkgname = ' + row['name'] + '\n' in metadata and 'pkgver = ' + row['version'] + '\n' in metadata, 'original archive metadata differs')
        for name, value in row['payload_sha256'].items():
            path = Path('/') / name
            require(not path.is_symlink() and path.is_file() and digest(path) == value, 'installed original payload differs: ' + name)
            owner = subprocess.check_output(['/usr/bin/pacman', '-Qqo', str(path)], text=True, timeout=15).strip()
            require(owner == row['name'], 'original installed-file owner differs')
            data = subprocess.check_output(['/usr/bin/bsdtar', '-xOf', '/inputs/' + row['archive'], name], timeout=15)
            require(hashlib.sha256(data).hexdigest() == value, 'original archive payload differs')
    require(digest('/boot/Image') == IMAGE_SHA, 'signed generic kernel Image differs')
    return actual


def allocated(path):
    return sum(x.lstat().st_blocks * 512 for x in Path(path).rglob('*'))


def free_bytes(path):
    s = os.statvfs(path)
    return s.f_bavail * s.f_frsize


@contextmanager
def registered_spawn():
    """Defer cancellation until the child handle is registered; never mask it in children."""
    import signal
    import threading
    require(threading.current_thread() is threading.main_thread(), 'process spawning requires main thread')
    pending, previous = [], {}
    def remember(sig, frame):
        pending.append((sig, frame))
    try:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            handler = signal.getsignal(sig)
            if handler != signal.SIG_IGN:
                previous[sig] = signal.signal(sig, remember)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        for sig, frame in pending:
            handler = previous[sig]
            if callable(handler):
                handler(sig, frame)
            else:
                # Raising permits the owner's finally to reap the child even when
                # the original disposition would terminate without Python cleanup.
                raise InterruptedError('cancelled during process registration: ' + str(sig))


def terminal(process):
    """Single owner only: observe without releasing the PID/PGID reservation."""
    require(hasattr(os, 'WNOWAIT') and hasattr(os, 'waitid'), 'WNOWAIT required')
    require(process.returncode is None, 'child already reaped; group ownership lost')
    try:
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise Refused('child reservation lost; cleanup uncertain') from error


def await_terminal(process, deadline):
    import time
    while (row := terminal(process)) is None:
        require(time.monotonic() < deadline, 'child terminal deadline')
        time.sleep(min(.01, max(0, deadline - time.monotonic())))
    return row


def reap(process, timeout=5, verify_absence=False):
    """Reserve through the LAST group signal, then reap; never signal after wait."""
    import signal
    import time
    deadline = time.monotonic() + timeout
    terminal(process)  # ECHILD/another waiter => no numeric mutating signal.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=max(.001, deadline - time.monotonic()))
    if verify_absence:
        while True:
            try:
                os.killpg(process.pid, 0)  # Nonmutating; reuse can only cause refusal.
            except ProcessLookupError:
                break
            require(time.monotonic() < deadline, 'owned group absence unverified')
            time.sleep(min(.01, max(0, deadline - time.monotonic())))
    return process.returncode


def bounded(argv, *, env=None, timeout=30, limit=1024 ** 2, log=None):
    """Stream a trusted process with a combined output cap and group cleanup."""
    import selectors
    import signal
    import time
    require(hasattr(os, 'WNOWAIT') and hasattr(os, 'waitid'), 'WNOWAIT required before spawn')
    process = None
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    total, error = 0, None
    start = time.monotonic()
    output = Path(log).open('xb') if log else None
    try:
        with registered_spawn():
            process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for name in streams:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() - start >= timeout:
                    error = 'timeout'
                    break
                for key, _ in selector.select(.05):
                    data = os.read(key.fd, min(65536, limit - total + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    take = min(len(data), limit - total)
                    streams[key.data].extend(data[:take])
                    if output:
                        output.write(data[:take])
                    total += take
                    if take < len(data):
                        error = 'output overflow'
                        break
                if error:
                    break
        if not error:
            try:
                await_terminal(process, start + timeout)
            except Refused:
                if time.monotonic() < start + timeout:
                    raise
                error = 'timeout'
    finally:
        import sys
        primary, faults = sys.exc_info()[1], []
        try:
            with registered_spawn():
                duties = ([lambda: reap(process), process.stdout.close, process.stderr.close] if process else [])
                if output:
                    duties.append(output.close)
                for duty in duties:
                    try:
                        duty()
                    except BaseException as exc:
                        faults.append(exc)
        except BaseException as exc:
            faults.append(exc)
        if faults:
            if primary is not None:
                primary.add_note('owned process cleanup uncertain: ' + type(faults[0]).__name__)
            elif error is not None:
                first = Refused(error)
                first.add_note('owned process cleanup uncertain: ' + type(faults[0]).__name__)
                raise first from faults[0]
            else:
                raise faults[0]
    return {'returncode': process.returncode, 'error': error,
            **{name: data.decode(errors='replace') for name, data in streams.items()}}


class LoggedProcess:
    """Immediately drain/cap a long-lived session's merged output to one log."""
    def __init__(self, argv, path, *, env=None, limit=1024 ** 2, stdin=None, owner_signals_only=False):
        import signal
        import threading
        require(not owner_signals_only or hasattr(os, 'WNOWAIT'), 'WNOWAIT required before spawn')
        self.error = None
        self.limit = limit
        self.process = self.thread = None
        output = Path(path).open('xb')
        def drain():
            written = 0
            try:
                with output as stream:
                    while data := self.process.stdout.read1(min(16384, limit - written + 1)):
                        take = min(len(data), limit - written)
                        stream.write(data[:take])
                        stream.flush()
                        written += take
                        if take < len(data):
                            self.error = 'output overflow'
                            break
            except Exception as exc:
                self.error = str(exc)
            finally:
                if self.error and not owner_signals_only:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.process.stdout.close()
        try:
            with registered_spawn():
                self.process = subprocess.Popen(argv, env=env, stdin=stdin, stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT, start_new_session=True)
                self.thread = threading.Thread(target=drain, daemon=True)
                self.thread.start()
        except BaseException as primary:
            faults = []
            try:
                with registered_spawn():
                    duties = []
                    if self.process is not None:
                        duties.extend((lambda: reap(self.process), self.process.stdout.close))
                    if self.thread is not None and self.thread.ident is not None:
                        duties.append(lambda: self.thread.join(timeout=5))
                    duties.append(output.close)
                    for duty in duties:
                        try:
                            duty()
                        except BaseException as exc:
                            faults.append(exc)
            except BaseException as exc:
                faults.append(exc)
            if faults:
                primary.add_note('logged process cleanup uncertain: ' + type(faults[0]).__name__)
            raise

    def finish(self):
        self.thread.join(timeout=5)
        require(not self.thread.is_alive(), 'log drain cleanup incomplete')
        require(self.error is None, 'session logging failed: ' + str(self.error))
