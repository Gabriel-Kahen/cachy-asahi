#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native-only controller for one private, bounded generic QEMU software trial.

--inside-tooling/--inside-verify are confined disposable-container entrypoints.
No host installation, host keyring, push, prune, KVM or Apple emulation exists.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import sys
import tempfile
import time
import types

import audit_tooling
from common import (GIB, IMAGE_SHA, OVERLAYS, SAFE_CAPS, allocated, bounded, digest,
                    facts, free_bytes, inventory, json_load, pinned, relative,
                    require, save, barrier_contract, barrier_event, BARRIER_PURPOSE, transaction_contract, transaction_event, TRANSACTION_PURPOSE,
                    TRANSACTION_FILES, TRANSACTION_LAUNCHER, TRANSACTION_PROFILE)

LOCK_PIN = 'c18afc5bde9868594d41bd576a956960a7b01b190d148ba03ca4c41d4394e1b0'
AUDIT_PIN = 'd3289a52f3269ba44f1437b69a112dcbd2086ee16ebe8d44658e65e7fb8e2095'
AUDITOR_PIN = '6677f391f2de23540bc147770148729fe4c993850b7bbed0b71fb7e48d296fdc'
CORE = {
    'common.py': 'aef2b4f09a91c4cfd66dd4504e69ef18396a94214c82ae0ec0a43c2716894a03',
    'guest.py': '1a642f3e6102d76fc4d2885eb0554a73e5b0bf8c122c4fb5376321d2a1233a93',
    'prepare.py': '5a9fbfbbafb56244b6a6c960fa40bbfc574bfd6bb4c3d5338e17082714c69488',
    'run.py': 'e96ec9b61dc26fa622702ef871bcdf9f53f3fd08ee12b5df03991163460d5766',
    'gbm_probe.c': 'fe0bb7b15df0bc93c4b5115543619e182ba3dac2ed22d0d8b1ab541d77a72efd',
    'image_decode_probe.c': 'e5857f60f664ccfeb8a2275396c4a4f8ed6412f14bb5237e71bd34582479ba3a',
    'image_decode_report.py': '377efb140ec7b5e50a18ae3c3d312f31f25676818f45942bde1c3acb5dceaacd',
}
CONFIG_FIELDS = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Labels', 'Volumes',
                 'ExposedPorts', 'StopSignal', 'Shell', 'Healthcheck', 'ArgsEscaped')
ALIASES = {'base_inputs_lock', 'base_lock', 'installed_lock', 'lifecycle_receipt', 'installed_image_receipt',
           'committed_config', 'committed_verification', 'commit_receipt', 'tooling_lock', 'tooling_audit'}
LIMIT = 8 * 1024 ** 2
CAPS = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID')
CANCELLED = False
OWNED_CONTAINERS = set()


def regular(path):
    require(path.is_absolute() and all(not x.is_symlink() for x in (path, *path.parents)), 'absolute non-symlink path required')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'singly linked regular input required')
    return info


def config(value):
    result = {key: value.get(key) for key in CONFIG_FIELDS}
    for key in ('Env', 'Entrypoint', 'Cmd', 'Shell'):
        result[key] = result[key] or []
    if result['Entrypoint'] == ['']:
        result['Entrypoint'] = []
    if result['Labels'] is None:
        result['Labels'] = {}
    result['WorkingDir'] = result['WorkingDir'] or '/'
    result['ArgsEscaped'] = bool(result['ArgsEscaped'])
    return result


def command(argv, *, timeout=60, log=None):
    outcome = bounded(argv, timeout=timeout, limit=LIMIT, log=log)
    require(outcome['error'] is None and outcome['returncode'] == 0, 'command failed: ' + argv[0])
    return outcome['stdout'].strip()


def native_guard():
    # Refuse x86/root before the first Docker CLI invocation.
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64' and 1000 <= os.getuid() < 60000 and 1000 <= os.getgid() < 60000,
            'native non-root Linux aarch64 controller required; no x86 Docker invocation')
    endpoints = ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
    require(os.getenv('DOCKER_HOST', endpoints[0]) in endpoints, 'remote Docker host refused')
    context = json.loads(command(['docker', 'context', 'inspect']))[0]
    endpoint = context['Endpoints']['docker']['Host']
    require(endpoint in endpoints, 'local Docker context required')
    info = json.loads(command(['docker', 'info', '--format', '{{json .}}']))
    require(info.get('Architecture') in ('aarch64', 'arm64') and info.get('OSType') == 'linux', 'native local ARM Docker daemon required')
    return {'os': 'Linux', 'architecture': 'aarch64', 'daemon_architecture': info['Architecture'],
            'docker_endpoint': endpoint, 'docker_server_version': info.get('ServerVersion'),
            'docker_root_dir': info.get('DockerRootDir'), 'uid': os.getuid(), 'gid': os.getgid()}


def accepted_base_inputs(actual, tooling_base):
    # Reviewed successor changes only vim/vim-runtime, outside the tooling closure.
    return actual == tooling_base or (
        tooling_base == '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
        and actual == 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')


def validate_input(c, root):
    require(c.get('schema_version') == 1 and c.get('execution') == 'native-aarch64-controller-qemu-tcg-guest', 'wrong controller contract')
    require(type(c.get('run_id')) is str and re.fullmatch('[1-9][0-9]{0,19}', c['run_id']) and
            type(c.get('run_attempt')) is str and re.fullmatch('[1-9][0-9]{0,9}', c['run_attempt']),
            'authenticated workflow run/attempt required')
    require(re.fullmatch('sha256:[0-9a-f]{64}', c.get('installed_image_id', '')) and
            re.fullmatch('[0-9a-f]{40}', c.get('source_commit', '')) and
            re.fullmatch('[0-9a-f]{40}', c.get('baseline_source_commit', '')), 'immutable installed image/source commit required')
    require(c.get('core_sha256') == CORE and c.get('audit_tooling_sha256') == AUDITOR_PIN and
            c.get('controller_sha256') == digest(Path(__file__)), 'reviewed exact controller/core/auditor source required')
    barrier_contract(c, root)
    transaction_contract(c, root)
    rows = c.get('baseline')
    require(isinstance(rows, list) and len(rows) == 4 and {r.get('name') for r in rows} == OVERLAYS, 'all four original overlays required')
    require(set(c.get('files', {})) == ALIASES, 'complete accepted handoff/lock receipts required')
    loaded, paths = {}, {}
    for alias, item in c['files'].items():
        path = pinned(root, item['path'], item['sha256'])
        require(path.stat().st_size <= LIMIT, 'oversized controller metadata')
        paths[alias] = path
        loaded[alias] = inventory(path.read_text()) if alias.endswith('_lock') and alias not in ('tooling_lock', 'base_inputs_lock') else json_load(path)
    base, installed = loaded['base_lock'], loaded['installed_lock']
    versions = {r['name']: r['version'] for r in rows}
    payload = {r['name']: r['payload_sha256'] for r in rows}
    require(len(base) == 341 and not OVERLAYS & set(base) and installed == base | versions, 'exact full 341+4 installed baseline required')
    life = loaded['lifecycle_receipt']
    require(life.get('status') == 'PASS' and life.get('baseline_handoff_ready') is True and
            life.get('source_commit') == c['baseline_source_commit'] and
            life.get('handoff_package_versions') == versions and life.get('handoff_payload_sha256') == payload,
            'PASS original lifecycle handoff required')
    image = loaded['installed_image_receipt']
    committed = loaded['committed_config']
    verified = loaded['committed_verification']
    receipt = loaded['commit_receipt']
    require(image.get('image_id') == c['installed_image_id'] and image.get('source_commit') == c['baseline_source_commit'] and
            image.get('lock_sha256') == c['files']['installed_lock']['sha256'] and
            image.get('commit_receipt_sha256') == c['files']['commit_receipt']['sha256'] and
            image.get('base_image') == receipt.get('image_id') == life.get('image_id'), 'installed-image provenance differs')
    require(committed.get('status') == 'PASS' and committed.get('image_id') == c['installed_image_id'] and
            committed.get('accepted_base_config') == committed.get('committed_config') and
            committed.get('test_identity_in_image_env') is False, 'baseline immutable Config verification required')
    require(verified.get('status') == 'PASS' and verified.get('image_id') == c['installed_image_id'] and
            verified.get('source_commit') == c['baseline_source_commit'] and verified.get('baseline') == rows and
            verified.get('installed_packages_sha256') == c['files']['installed_lock']['sha256'], 'fresh baseline read-side verification differs')
    require(receipt.get('status') == 'READY' and receipt.get('purpose') == 'sanitized-baseline-image-handoff' and
            receipt.get('source_commit') == c['baseline_source_commit'] and receipt.get('package_versions') == versions and
            receipt.get('payload_sha256') == payload and receipt.get('installed_package_count') == 345 and
            receipt.get('installed_packages_sha256') == c['files']['installed_lock']['sha256'] and
            receipt.get('base_packages_sha256') == c['files']['base_lock']['sha256'] and
            receipt.get('private_cleanup') == 'PASS; no private contents or hashes recorded', 'sanitized READY baseline receipt required')
    gates = {'successful-lifecycle-handoff', 'lifecycle-receipt-binding', 'exact-base-plus-originals-inventory',
             'complete-pacman-owned-payload', 'original-payload-hash', 'private-keyring-removed',
             'only-empty-alarm-home', 'system-gnupg-state-removed'}
    require(receipt.get('checks') and all(r.get('status') == 'PASS' for r in receipt['checks']) and
            gates <= {r.get('check') for r in receipt['checks']}, 'baseline handoff checks incomplete')
    require(c['files']['tooling_lock']['sha256'] == LOCK_PIN and c['files']['tooling_audit']['sha256'] == AUDIT_PIN,
            'unreviewed tooling closure/audit')
    lock, audit = loaded['tooling_lock'], loaded['tooling_audit']
    require(accepted_base_inputs(c['files']['base_inputs_lock']['sha256'], lock['base_inputs_lock_sha256']),
            'accepted native base input snapshot differs')
    upstream = loaded['base_inputs_lock']
    frozen_base = {r['name'][0]: r['version'][0] for r in upstream['rootfs_packages']}
    frozen_base.update({r['name']: r['version'] for r in upstream['packages']})
    require(base == frozen_base and len(frozen_base) == 341, 'installed base differs from authenticated native input snapshot')
    require(len(lock['packages']) == 21 and lock['base_package_count'] == 341 and lock['expected_package_count'] == 362 and
            {'qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci'} <= {r['name'] for r in lock['packages']} and
            audit['status'] == 'PASS' and audit['tooling_lock_sha256'] == LOCK_PIN and
            set(audit['packages']) == {r['name'] for r in lock['packages']}, 'complete authenticated 21-package extension required')
    require(not set(base) & {r['name'] for r in lock['packages']} and not OVERLAYS & {r['name'] for r in lock['packages']}, 'tooling may not replace existing packages')
    for row in rows:
        require(relative(row['archive']).startswith('baseline/') and row['archive'].endswith(('.pkg.tar.xz', '.pkg.tar.zst', '.pkg.tar.gz')), 'original archive must be under baseline/')
        pinned(root, row['archive'], row['sha256'])
        require(row['payload_sha256'] and all(relative(n).startswith('usr/') and re.fullmatch('[0-9a-f]{64}', d) for n, d in row['payload_sha256'].items()), 'complete safe original payload map required')
    cache = root / relative(c['cache_dir'])
    require(cache.is_dir() and not cache.is_symlink(), 'private original tooling cache directory required')
    downloads = lock['keyring_files'] + [item for r in lock['packages'] for item in (r, audit_tooling.signature(r))]
    for item in downloads:
        path = pinned(cache, item['filename'], item['sha256'])
        require(path.stat().st_size == item['size'], 'authenticated tooling/key size differs')
    for name, pin in CORE.items():
        require(digest(Path(__file__).parent / name) == pin, 'frozen core changed')
    require(digest(Path(audit_tooling.__file__)) == AUDITOR_PIN, 'auditor source changed')
    return loaded, paths, cache


def child_guard(writable):
    f = facts()
    require(f['marker'] == '1' and f['docker'] and f['arch'] == 'aarch64' and f['uid'] == 0 and
            f['nnp'] == '1' and f['interfaces'] == ['lo'] and not f['devices'] and not f['docker_socket'], 'isolated root native tooling container required')
    require(f['caps']['CapEff'] == (SAFE_CAPS if writable else 2) and
            all(not v & ~(SAFE_CAPS if writable else 2) for v in f['caps'].values()), 'exact tooling metadata-only capabilities required')
    require(f['runner'] == '/runner/virtual' and re.fullmatch('[0-9a-f]{32}', f['nonce']) and
            re.fullmatch('sha256:[0-9a-f]{64}', f['image_id']), 'source/nonce/image binding required')
    for path, flag in (('/', 'rw' if writable else 'ro'), ('/inputs', 'ro'), ('/runner', 'ro'), ('/out', 'rw')):
        require(flag in f['mounts'].get(path, {}).get('flags', []), 'required tooling mount missing')
    require(f['mounts']['/']['type'] in ('overlay', 'fuse-overlayfs'), 'disposable overlay root required')
    for point in f['mounts']:
        require(not any(point == p or point.startswith(p + '/') for p in ('/tmp', '/usr', '/var', '/home', '/root', '/run', '/boot')),
                'underlying image private/system view must be exposed without host mounts')
        require(not any(point.startswith(p + '/') for p in ('/inputs', '/runner', '/out')), 'nested tooling mounts refused')
        if point == '/etc' or point.startswith('/etc/'):
            require(point in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'), 'host etc mount refused')
    require(not any(os.getenv(k) for k in ('DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS', 'PULSE_SERVER', 'PIPEWIRE_REMOTE')), 'host connection refused')
    return f


def installed(expected, rows):
    actual = inventory(command(['/usr/bin/pacman', '-Q']))
    require(actual == expected, 'installed full package inventory differs')
    for row in rows:
        owned = {line.split(' ', 1)[1].lstrip('/') for line in command(['/usr/bin/pacman', '-Ql', row['name']]).splitlines() if not line.endswith('/')}
        require(owned == set(row['payload_sha256']), 'original owned payload map differs')
        names = command(['/usr/bin/bsdtar', '-tf', '/inputs/' + row['archive']]).splitlines()
        require(len(names) == len(set(names)) and {n for n in names if not n.endswith('/') and n not in ('.PKGINFO', '.BUILDINFO', '.MTREE', '.Changelog')} == owned, 'original archive map incomplete')
        for name, value in row['payload_sha256'].items():
            file = Path('/') / relative(name)
            require(file.is_file() and not file.is_symlink() and digest(file) == value and
                    command(['/usr/bin/pacman', '-Qqo', str(file)]) == row['name'], 'original payload/owner changed')
            data = bounded(['/usr/bin/bsdtar', '-xOf', '/inputs/' + row['archive'], name], timeout=15)
            require(data['error'] is None and data['returncode'] == 0 and hashlib.sha256(data['stdout'].encode()).hexdigest() == value, 'original archived payload changed')
    require(digest('/boot/Image') == IMAGE_SHA, 'generic signed kernel changed')
    return actual


def sanitized():
    for name in ('tmp', 'root', 'var/cache/pacman/pkg'):
        path = Path('/') / name
        require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()), 'private image directory not empty: ' + name)
    for name in ('etc/pacman.d/gnupg', 'var/lib/gnupg', 'var/log/pacman.log'):
        path = Path('/') / name
        require(not path.exists() and not path.is_symlink(), 'private state remains: ' + name)
    home = Path('/home/alarm')
    require(list(Path('/home').iterdir()) == [home] and home.is_dir() and not home.is_symlink() and not any(home.iterdir()), 'baseline homes not sanitized')


def inside(sha, writable):
    f = child_guard(writable)
    c = json_load(pinned('/inputs', 'tooling-contract.json', sha))
    require(c.get('schema_version') == 1, 'tooling child contract schema differs')
    require(c['image_id'] == f['image_id'] and c['nonce'] == f['nonce'] and c['controller_sha256'] == digest(Path(__file__)) and
            c['core_sha256'] == CORE, 'tooling contract/source/identity differs')
    lock = json_load(pinned('/inputs', 'tooling.lock.json', LOCK_PIN))
    for row in c['baseline']:
        pinned('/inputs', row['archive'], row['sha256'])
    expected = inventory(pinned('/inputs', 'base-packages.lock', c['base_lock_sha256']).read_text())
    require(len(expected) == 341, 'full frozen base required')
    expected |= {r['name']: r['version'] for r in c['baseline']}
    for item in lock['keyring_files'] + [i for r in lock['packages'] for i in (r, audit_tooling.signature(r))]:
        path = pinned('/inputs/tooling-cache', item['filename'], item['sha256'])
        require(path.stat().st_size == item['size'], 'private tooling input size differs')
    output = Path('/out/tooling.json')
    require(not output.exists(), 'fresh tooling receipt required')
    result = {'status': 'FAIL', 'image_id': c['image_id'], 'nonce': c['nonce'], 'source_commit': c['source_commit'],
              'contract_sha256': sha, 'tooling_lock_sha256': LOCK_PIN, 'hardware_validation': 'NOT RUN'}
    temporary = None
    try:
        if writable:
            sanitized()
            installed(expected, c['baseline'])
            temporary = Path(tempfile.mkdtemp(prefix='cachy-virtual-trust-', dir='/tmp'))
            keyring = temporary / 'keyring'
            conf = temporary / 'pacman.conf'
            hooks = temporary / 'hooks'; hooks.mkdir()
            for folder in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'):
                for path in Path(folder).glob('*.hook'):
                    require(re.fullmatch('[A-Za-z0-9._+-]+[.]hook', path.name), 'unsafe global hook name')
                    target = hooks / path.name
                    if not target.exists() and not target.is_symlink():
                        target.symlink_to('/dev/null')
            conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n' +
                            'HookDir = ' + str(hooks) + '\nGPGDir = ' + str(keyring) + '\n')
            # Only this private image creates a TEST local master; no host or stable keys.
            command(['/usr/bin/pacman-key', '--gpgdir', str(keyring), '--init'], timeout=120, log=Path('/out/key-init.log'))
            command(['/usr/bin/pacman-key', '--gpgdir', str(keyring), '--add', '/inputs/tooling-cache/archlinuxarm.gpg'], log=Path('/out/key-import.log'))
            command(['/usr/bin/pacman-key', '--gpgdir', str(keyring), '--lsign-key', lock['signer_fingerprint']], log=Path('/out/key-trust.log'))
            for row in lock['packages']:
                verified = command(['/usr/bin/gpg', '--batch', '--homedir', str(keyring), '--status-fd', '1', '--verify',
                                    '/inputs/tooling-cache/' + row['filename'] + '.sig', '/inputs/tooling-cache/' + row['filename']])
                audit_tooling.verify(verified, lock['signer_fingerprint'])
                audit = audit_tooling.inspect(Path('/inputs/tooling-cache') / row['filename'], row)
                require(not audit['hooks'], 'tooling package scripts/hooks are not accepted')
            command(['/usr/bin/pacman', '--config', str(conf), '--noconfirm', '--noscriptlet', '--logfile', str(temporary / 'pacman.log'),
                     '-U', *['/inputs/tooling-cache/' + r['filename'] for r in lock['packages']]], timeout=300, log=Path('/out/transaction.log'))
            command(['/usr/bin/ldconfig'], log=Path('/out/ldconfig.log'))
            command(['/usr/bin/gpgconf', '--homedir', str(keyring), '--kill', 'all'])
            shutil.rmtree(temporary); temporary = None
        expected |= {r['name']: r['version'] for r in lock['packages']}
        require(len(expected) == 366, 'exact 362+4 expected set required')
        result['packages'] = installed(expected, c['baseline'])
        sanitized()
        result.update(status='READY', private_cleanup='PASS; TEST local master/keyring removed before private commit',
                      package_count=366, scriptlets='DISABLED', hooks='MASKED; no package hooks accepted',
                      package_inventory_sha256=hashlib.sha256(''.join(k + ' ' + v + '\n' for k, v in sorted(expected.items())).encode()).hexdigest())
    except Exception as exc:
        result['error'] = str(exc)
        raise
    finally:
        if temporary is not None:
            try:
                command(['/usr/bin/gpgconf', '--homedir', str(temporary / 'keyring'), '--kill', 'all'])
            except Exception:
                result['status'] = 'FAIL'
                result['cleanup_error'] = 'private TEST trust-agent cleanup failed'
            finally:
                try:
                    shutil.rmtree(temporary)
                except OSError:
                    result['status'] = 'FAIL'
                    result['cleanup_error'] = 'private TEST trust-state removal failed'
        save(output, result)
        for path in Path('/out').iterdir():
            require(path.is_file() and not path.is_symlink(), 'unexpected tooling output')
            path.chmod(0o644)
            if writable:
                os.chown(path, c['output_uid'], c['output_gid'])


@contextmanager
def cleanup_signals():
    pending = []
    def remember(*_):
        global CANCELLED
        CANCELLED = True
        pending.append(True)
    old = {sig: signal.signal(sig, remember) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield pending
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def remove_container(name):
    require(re.fullmatch('cachy-virtual-[a-z0-9-]+', name) and name in OWNED_CONTAINERS, 'unowned cleanup name')
    with cleanup_signals():
        result = bounded(['docker', 'rm', '-f', name], timeout=15)
        observed = bounded(['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'], timeout=15)
    absent = observed['error'] is None and observed['returncode'] == 0 and not observed['stdout'].strip()
    if absent:
        OWNED_CONTAINERS.discard(name)
    return {'container': name, 'status': 'PASS' if absent else 'FAIL',
            'remove_exit': result['returncode'], 'absence_verified': absent}


def remove_private_tag(tag, image=None, uncertain=False):
    require(re.fullmatch('cachy-virtual-private-[0-9a-f]{32}:fixture', tag), 'unsafe owned private tag')
    with cleanup_signals():
        removed = bounded(['docker', 'image', 'rm', tag], timeout=30)
        observed = bounded(['docker', 'image', 'ls', '--no-trunc', '--quiet', '--filter', 'reference=' + tag], timeout=30)
        absent = observed['error'] is None and observed['returncode'] == 0 and not observed['stdout'].strip()
        if image:
            all_images = bounded(['docker', 'image', 'ls', '--no-trunc', '--quiet'], timeout=30)
            absent &= all_images['error'] is None and all_images['returncode'] == 0 and image not in all_images['stdout'].splitlines()
    return {'private_tag': tag, 'image_id': image, 'status': 'PASS' if absent and not uncertain else 'FAIL',
            'remove_exit': removed['returncode'], 'absence_verified': absent, 'commit_outcome_uncertain': uncertain}


def container_args(image, name, inputs, runner, out, root=False, writable=False, temporary=True):
    args = ['docker', 'create', '--pull=never', '--platform=linux/arm64', '--name', name, '--network=none',
            '--security-opt=no-new-privileges', '--cap-drop=ALL', '--pids-limit=256', '--memory=6g', '--memory-swap=6g', '--cpus=4',
            '--user', '0:0' if root else f'{os.getuid()}:{os.getgid()}']
    if root:
        for cap in (CAPS if writable or temporary else ('DAC_OVERRIDE',)):
            args += ['--cap-add=' + cap]
    if not writable:
        args += ['--read-only']
    if temporary:
        args += ['--tmpfs', f'/tmp:rw,nosuid,nodev,exec,size=64m,mode=0700,uid={0 if root else os.getuid()},gid={0 if root else os.getgid()}']
    for source, dest, ro in ((inputs, '/inputs', True), (runner, '/runner', True), (out, '/out', False)):
        require(source.is_absolute() and source.is_dir() and not source.is_symlink() and ',' not in str(source), 'safe existing private bind root required')
        args += ['--mount', f'type=bind,src={source},dst={dest}' + (',readonly' if ro else '')]
    return args + ['--entrypoint=/usr/bin/env', image]


def validate_container(observed, image, root, writable, temporary):
    require(observed['Image'] == image and observed['HostConfig']['NetworkMode'] == 'none' and
            observed['HostConfig']['Privileged'] is False and observed['HostConfig'].get('CapDrop') == ['ALL'], 'created container isolation differs')
    expected = (set(CAPS) if writable or temporary else {'DAC_OVERRIDE'}) if root else set()
    require({x.removeprefix('CAP_') for x in observed['HostConfig'].get('CapAdd') or []} == expected and not observed['HostConfig'].get('Devices') and
            not observed['HostConfig'].get('DeviceRequests') and observed['HostConfig']['ReadonlyRootfs'] == (not writable), 'created container capability/device/root differs')
    require(observed['Config']['User'] == ('0:0' if root else f'{os.getuid()}:{os.getgid()}'), 'created container UID differs')
    binds = [m for m in observed['Mounts'] if m['Type'] == 'bind']
    require({m['Destination']: m['RW'] for m in binds} == {'/inputs': False, '/runner': False, '/out': True}, 'created bind targets differ')
    require(set(observed['HostConfig'].get('Tmpfs') or {}) == ({'/tmp'} if temporary else set()), 'created tmpfs differs')
    require(observed['HostConfig'].get('Memory') == 6 * GIB and observed['HostConfig'].get('NanoCpus') == 4 * 10**9 and
            any(x in ('no-new-privileges', 'no-new-privileges=true', 'no-new-privileges:true') for x in observed['HostConfig'].get('SecurityOpt') or []) and
            observed['HostConfig'].get('MemorySwap') == 6 * GIB and observed['HostConfig'].get('PidsLimit') == 256, 'created resource/no-new-privileges limits differ')


def commit_args(name, base, tag=None):
    require(re.fullmatch('[A-Za-z0-9:_-]+', base.get('User', '')), 'accepted base USER required')
    workdir = base.get('WorkingDir') or '/'
    require(workdir.startswith('/') and '\n' not in workdir, 'accepted workdir required')
    # Moby 28.0.4 merge inherits runtime Cmd when both requested arrays are
    # empty. This exact sentinel blocks inheritance and create resets it.
    entrypoint = base.get('Entrypoint')
    if entrypoint in (None, [], ['']):
        entrypoint = ['']
    args = ['docker', 'commit', '--pause=true', '--change', 'USER ' + base['User'], '--change', 'WORKDIR ' + workdir,
            '--change', 'ENTRYPOINT ' + json.dumps(entrypoint), '--change', 'CMD ' + json.dumps(base.get('Cmd') or []), name]
    if tag is not None:
        require(re.fullmatch('cachy-virtual-private-[0-9a-f]{32}:fixture', tag), 'unsafe private commit tag')
        args.append(tag)
    return args


def run_container(args, log, image, root, writable, temporary, timeout, cleanups, keep=False):
    name = args[args.index('--name') + 1]
    require(not command(['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']), 'owned container name already exists')
    created = False
    try:
        OWNED_CONTAINERS.add(name)
        created = True  # Even a failed create may have allocated this owned name.
        command(args, timeout=60)
        observed = json.loads(command(['docker', 'container', 'inspect', name]))[0]
        validate_container(observed, image, root, writable, temporary)
        command(['docker', 'start', '-a', name], timeout=timeout, log=log)
        state = json.loads(command(['docker', 'container', 'inspect', name]))[0]
        require(state['State']['Status'] == 'exited' and state['State']['ExitCode'] == 0 and state['Image'] == image, 'container did not exit cleanly from accepted image')
    except BaseException:
        keep = False
        raise
    finally:
        if created and not keep:
            result = remove_container(name); cleanups.append(result)
            require(result['status'] == 'PASS', 'owned container removal was not verified')
    require(not CANCELLED, 'controller cancelled during container cleanup')


def reviewed_decode_run():
    """Load only the selected runtime/parser source for outer validation."""
    for name in ('run.py', 'image_decode_report.py'):
        source = Path(__file__).with_name(name); regular(source)
        require(name in CORE and digest(source) == CORE[name], 'image decode validation source differs')
    source = Path(__file__).with_name('run.py')
    module = types.ModuleType('_reviewed_virtual_decode_run'); module.__file__ = str(source)
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
    return module


def prepared_decode_authority(proof, prepared, proof_sha256, prepare_sha256):
    context = reviewed_decode_run().image_decode_context(proof, prepared, proof_sha256)
    require(type(prepare_sha256) is str and re.fullmatch('[0-9a-f]{64}', prepare_sha256),
            'preparation receipt pin required')
    row = {'schema_version': 1, 'helper_sha256': context['helper_sha256'],
           'guest_image_sha256': context['image_sha256'],
           'package_inventory_sha256': context['package_inventory_sha256'],
           'asset_sha256': context['asset_sha256'],
           'guest_contract_sha256': prepared['image_decode_build']['guest_contract_sha256'],
           'prepare_receipt_sha256': prepare_sha256}
    return context, row


def project(raw, target, report, *, image_decode_context=None):
    """Explicit guest records + matching public PPM; no generic private-tree exporter."""
    if not raw.exists():
        return
    result = json_load(raw / 'result.json') if (raw / 'result.json').is_file() else None
    capability_file = raw / 'capabilities.json'
    if capability_file.exists():
        require(regular(capability_file).st_size <= 16 * 1024, 'capability receipt exceeds bound')
        source = Path(__file__).with_name('run.py'); regular(source)
        data = source.read_bytes()
        require(hashlib.sha256(data).hexdigest() == CORE['run.py'], 'capability projector source differs')
        module = types.ModuleType('_reviewed_virtual_run'); module.__file__ = str(source)
        exec(compile(data, str(source), 'exec'), module.__dict__)
        rows = module.capability_projection(json_load(capability_file))
        require(result is None or result.get('capabilities') == rows, 'capability receipt/result differs')
        report['qemu_capabilities'] = rows
        report['qemu_capabilities_sha256'] = hashlib.sha256(
            (json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
    if result is not None:
        report['guest'] = {k: result.get(k) for k in ('status', 'execution', 'contract_sha256', 'prepare_receipt_sha256', 'image_id',
                          'nonce', 'software_compositor', 'software_session_ipc', 'frame_proof', 'hardware_validation',
                          'graphics_acceleration', 'm2_16k_pages', 'performance', 'elapsed_seconds', 'error', 'logging_error', 'logs',
                          'owned_group_retirement', 'cleanup_uncertain')}
        allowed = {'transaction_result', 'transaction_child_exit', 'barrier_result', 'barrier_child_exit', 'boot', 'gbm_pass', 'frame_ready', 'phase_pass', 'guest_pass', 'guest_failed', 'command', 'session_log', 'ipc_probe', 'process_state', 'image_decode_probe'}
        events = [e for e in result.get('events', []) if e.get('event') in allowed]
        if report.get('purpose') == TRANSACTION_PURPOSE:
            require(result.get('contract_sha256') == report['proof_contract_sha256'] and
                    result.get('prepare_receipt_sha256') == report['prepare_receipt_sha256'] and
                    result.get('nonce') == report['transaction_nonce'] and
                    result.get('image_id') == report['stages']['tooling']['image_id'], 'transaction result authority differs')
            rows = [e for e in events if e['event'] == 'transaction_result']
            require(len(rows) <= 1 and not result.get('frames'), 'unexpected transaction evidence')
            require(result.get('transaction_result') == (rows[0] if rows else None), 'transaction result/event differs')
            if rows:
                report['transaction_result'] = transaction_event(rows[0],result['nonce'],report['proof_contract_sha256'],report['source_commit'])
            if result['status'] == 'PASS_TRANSACTION_ONLY':
                reviewed_decode_run().validate_transaction_completion(events,result['nonce'],report['proof_contract_sha256'],report['source_commit'])
                require(result.get('owned_group_retirement') == 'PASS' and result.get('cleanup_uncertain') is False,
                        'transaction QEMU retirement incomplete')
        else:
            require(not any(e['event'].startswith('transaction_') for e in events), 'unselected transaction evidence')
        if report.get('purpose') == BARRIER_PURPOSE:
            require(result.get('contract_sha256') == report['proof_contract_sha256'] and
                    result.get('prepare_receipt_sha256') == report['prepare_receipt_sha256'] and
                    result.get('nonce') == report['barrier_nonce'] and
                    result.get('image_id') == report['stages']['tooling']['image_id'], 'barrier result authority differs')
            rows = [e for e in events if e['event'] == 'barrier_result']
            require(len(rows) <= 1 and not result.get('frames'), 'unexpected barrier evidence')
            require(result.get('barrier_result') == (rows[0] if rows else None), 'barrier result/event differs')
            if rows:
                report['barrier_result'] = barrier_event(rows[0], result['nonce'], report['proof_contract_sha256'])
            if result['status'] == 'PASS_BARRIER_ONLY':
                reviewed_decode_run().validate_barrier_completion(events, result['nonce'], report['proof_contract_sha256'])
                require(result.get('owned_group_retirement') == 'PASS' and result.get('cleanup_uncertain') is False,
                        'barrier QEMU retirement incomplete')
        else:
            require(not any(e['event'].startswith('barrier_') for e in events), 'unselected barrier evidence')
        decode_events = [e for e in events if e['event'] == 'image_decode_probe']
        require(len(decode_events) <= 1, 'duplicate image decode observation')
        if decode_events:
            require(image_decode_context is not None, 'independent image decode preparation authority required')
            observation = reviewed_decode_run().image_decode_observation(
                events, image_decode_context, result.get('nonce'), allow_failed=True)
            require(result.get('image_decode_observation') == observation, 'image decode result/event differs')
            if observation is not None:
                report['image_decode_observation'] = observation
            else:
                require(result.get('status') == 'FAILED', 'failed image decode transport cannot establish capture')
        else:
            require(result.get('image_decode_observation') is None and
                    result.get('status') != 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'image decode observation required before capture')
        encoded = json.dumps(events).encode()
        require(len(encoded) <= 16 * 1024 ** 2 and b'PRIVATE KEY' not in encoded, 'guest public evidence rejected')
        save(target / 'guest-events.json', events)
        report['guest_events_sha256'] = digest(target / 'guest-events.json')
        report['frames'] = {}
        for stage, row in result.get('frames', {}).items():
            require(stage in ('minimal', 'overlay') and row['filename'] == stage + '.ppm', 'unapproved frame artifact')
            path = raw / row['filename']; regular(path)
            require(path.stat().st_size <= LIMIT and digest(path) == row['sha256'], 'frame differs from captured receipt')
            shutil.copyfile(path, target / path.name)
            require(digest(target / path.name) == row['sha256'], 'frame changed during public projection')
            report['frames'][stage] = row
    # Failed starts need their exact bounded QEMU diagnostic, not an empty projection.
    log = raw / 'qemu.log'
    if log.is_file():
        require(regular(log).st_size <= 1024 ** 2 and b'PRIVATE KEY' not in log.read_bytes(), 'QEMU diagnostic rejected')
        shutil.copyfile(log, target / 'qemu.log')
        report['qemu_log_sha256'] = digest(target / 'qemu.log')


def save_final_report(path, report):
    """Late cancellation during projection/cleanup/receipt writing stays a failure."""
    if CANCELLED:
        report['status'] = 'FAIL'
        report['cancellation'] = 'controller interrupted during finalization'
    save(path, report)
    if CANCELLED and report['status'] != 'FAIL':
        report['status'] = 'FAIL'
        report['cancellation'] = 'controller interrupted during final receipt writing'
        save(path, report)


def main(argv=None):
    global CANCELLED
    CANCELLED = False
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--contract', type=Path)
    ap.add_argument('--contract-sha256', required=True)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--inside-tooling', action='store_true')
    ap.add_argument('--inside-verify', action='store_true')
    args = ap.parse_args(argv)
    if args.inside_tooling or args.inside_verify:
        require(args.inside_tooling != args.inside_verify, 'one explicit child stage required')
        return inside(args.contract_sha256, args.inside_tooling)
    host = native_guard()
    require(args.contract is not None and args.output is not None, 'host input/output paths required')
    regular(args.contract)
    require(digest(args.contract) == args.contract_sha256 and not args.output.exists() and not args.output.is_symlink(), 'pinned contract/fresh output required')
    c = json_load(args.contract)
    loaded, paths, cache = validate_input(c, args.contract.resolve().parent)
    output = args.output.resolve(); output.mkdir(mode=0o700)
    report = {'schema_version': 1, 'purpose': 'bounded-generic-arm-software-proof', 'status': 'FAIL', 'native_host': host,
              'execution': 'native-aarch64-controller; qemu-tcg-generic-aarch64-guest', 'hardware_validation': 'NOT RUN',
              'controller_contract_sha256': args.contract_sha256, 'source_commit': c['source_commit'],
              'run_id': c['run_id'], 'run_attempt': c['run_attempt'],
              'source_sha256': CORE | {'controller.py': c['controller_sha256'], 'audit_tooling.py': AUDITOR_PIN},
              'inputs': c['files'], 'baseline_image': c['installed_image_id'], 'cleanup': [], 'stages': {}, 'resources': {}}
    derived, name_tooling, private_tag = None, None, None
    commit_uncertain = False
    decode_context = None
    if barrier_contract(c) or transaction_contract(c):
        report['purpose'] = c['purpose']
    start = time.monotonic()
    def interrupted(*_):
        global CANCELLED
        CANCELLED = True
        raise ValueError('controller interrupted/deadline')
    old = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL, 3300)
    with tempfile.TemporaryDirectory(prefix='cachy-virtual-private-', dir=output.parent) as temporary:
        work = Path(temporary)
        inputs = work / 'inputs'; inputs.mkdir()
        runner = work / 'runner'; (runner / 'virtual').mkdir(parents=True)
        raw = work / 'raw'; raw.mkdir()
        try:
            report['resources']['free_before_bytes'] = free_bytes(work)
            report['resources']['tooling_cache_allocated_bytes'] = allocated(cache)
            require(free_bytes(work) >= GIB, 'less than 1 GiB space before tooling extension')
            base = json.loads(command(['docker', 'image', 'inspect', c['installed_image_id']]))[0]
            require(base['Id'] == c['installed_image_id'] and base['Architecture'] == 'arm64' and base['Os'] == 'linux' and
                    config(base['Config']) == loaded['committed_config']['committed_config'], 'actual immutable baseline architecture/Config differs')
            require(not base['Config'].get('Volumes') and not base['Config'].get('Healthcheck') and
                    not any(e.startswith(('CACHY_ASAHI_', 'DISPLAY=', 'WAYLAND_', 'DBUS_', 'PULSE_', 'PIPEWIRE_')) for e in base['Config'].get('Env') or []), 'unreviewed image volumes/healthcheck/connections/identity')
            report['baseline_config_sha256'] = hashlib.sha256(json.dumps(config(base['Config']), sort_keys=True).encode()).hexdigest()
            report['resources']['baseline_image_bytes'] = base['Size']
            mapping = {'base_lock': 'base-packages.lock', 'lifecycle_receipt': 'lifecycle.json', 'tooling_lock': 'tooling.lock.json', 'tooling_audit': 'tooling-audit.json'}
            for alias, name in mapping.items():
                shutil.copyfile(paths[alias], inputs / name)
                require(digest(inputs / name) == c['files'][alias]['sha256'], 'input copy changed')
            blobs = loaded['tooling_lock']['keyring_files'] + [i for r in loaded['tooling_lock']['packages'] for i in (r, audit_tooling.signature(r))]
            (inputs / 'tooling-cache').mkdir()
            for row in blobs:
                shutil.copyfile(cache / row['filename'], inputs / 'tooling-cache' / row['filename'])
                require(digest(inputs / 'tooling-cache' / row['filename']) == row['sha256'], 'tooling copy changed')
            root = args.contract.resolve().parent
            for row in c['baseline']:
                dest = inputs / relative(row['archive']); dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / row['archive'], dest)
                require(digest(dest) == row['sha256'], 'original archive copy changed')
            for name, sha in report['source_sha256'].items():
                shutil.copyfile(Path(__file__).parent / name, runner / 'virtual' / name)
                require(digest(runner / 'virtual' / name) == sha, 'runner source copy changed')
            nonce = os.urandom(16).hex()
            child = {'schema_version': 1, 'image_id': c['installed_image_id'], 'nonce': nonce, 'source_commit': c['source_commit'],
                     'controller_sha256': c['controller_sha256'], 'core_sha256': CORE, 'base_lock_sha256': c['files']['base_lock']['sha256'],
                     'baseline': c['baseline'], 'output_uid': os.getuid(), 'output_gid': os.getgid()}
            save(inputs / 'tooling-contract.json', child)
            name_tooling = 'cachy-virtual-tooling-' + nonce
            setup = raw / 'tooling'; setup.mkdir()
            identity = ['CACHY_ASAHI_DISPOSABLE_VIRTUAL=1', 'CACHY_ASAHI_VIRTUAL_NONCE=' + nonce,
                        'CACHY_ASAHI_IMAGE_ID=' + child['image_id'], 'HOME=/tmp', 'PYTHONDONTWRITEBYTECODE=1']
            argv = container_args(child['image_id'], name_tooling, inputs, runner, setup, root=True, writable=True, temporary=False)
            argv += identity + ['/usr/bin/python3', '-B', '/runner/virtual/controller.py', '--inside-tooling', '--contract-sha256', digest(inputs / 'tooling-contract.json')]
            run_container(argv, raw / 'tooling-container.log', child['image_id'], True, True, False, 650, report['cleanup'], keep=True)
            receipt = json_load(setup / 'tooling.json')
            require(receipt['status'] == 'READY' and receipt['package_count'] == 366 and receipt['contract_sha256'] == digest(inputs / 'tooling-contract.json') and
                    receipt['image_id'] == c['installed_image_id'] and receipt['nonce'] == nonce, 'clean exact tooling READY receipt required before commit')
            existing_images = set(command(['docker', 'image', 'ls', '--no-trunc', '--quiet']).splitlines())
            candidate_tag = 'cachy-virtual-private-' + nonce + ':fixture'
            require(not command(['docker', 'image', 'ls', '--no-trunc', '--quiet', '--filter', 'reference=' + candidate_tag]), 'private tag already exists')
            private_tag = candidate_tag
            commit_uncertain = True
            committed_id = command(commit_args(name_tooling, base['Config'], private_tag), timeout=120)
            require(re.fullmatch('sha256:[0-9a-f]{64}', committed_id) and committed_id != c['installed_image_id'] and committed_id not in existing_images, 'new immutable private tooling image required')
            derived = committed_id
            commit_uncertain = False
            observed = json.loads(command(['docker', 'image', 'inspect', derived]))[0]
            require(observed['Id'] == derived and observed['Architecture'] == 'arm64' and observed['Os'] == 'linux' and
                    config(observed['Config']) == config(base['Config']), 'tooling committed immutable Config differs')
            cleanup = remove_container(name_tooling); report['cleanup'].append(cleanup)
            require(cleanup['status'] == 'PASS', 'tooling container not removed')
            name_tooling = None
            child['image_id'] = derived; save(inputs / 'tooling-contract.json', child)
            verification = raw / 'verify'; verification.mkdir()
            argv = container_args(derived, 'cachy-virtual-verify-' + nonce, inputs, runner, verification, root=True, temporary=False)
            argv += ['CACHY_ASAHI_DISPOSABLE_VIRTUAL=1', 'CACHY_ASAHI_VIRTUAL_NONCE=' + nonce,
                     'CACHY_ASAHI_IMAGE_ID=' + derived, 'HOME=/tmp', 'PYTHONDONTWRITEBYTECODE=1',
                     '/usr/bin/python3', '-B', '/runner/virtual/controller.py', '--inside-verify', '--contract-sha256', digest(inputs / 'tooling-contract.json')]
            run_container(argv, raw / 'verify-container.log', derived, True, False, False, 180, report['cleanup'])
            verified = json_load(verification / 'tooling.json')
            require(verified['status'] == 'READY' and verified['packages'] == receipt['packages'] and verified['package_count'] == 366 and
                    verified['image_id'] == derived, 'fresh read-only tooling image verification failed')
            report['stages']['tooling'] = {'status': 'READY', 'image_id': derived, 'package_count': 366,
                                         'package_inventory_sha256': verified['package_inventory_sha256'],
                                         'private_cleanup': verified['private_cleanup'], 'committed_config_sha256': report['baseline_config_sha256']}
            proof = {'schema_version': 1, 'execution': 'qemu-tcg-generic-aarch64', 'nonce': nonce, 'image_id': derived,
                     'source_commit': c['source_commit'], 'output_uid': os.getuid(), 'output_gid': os.getgid(),
                     'baseline_image_id': c['installed_image_id'], 'run_id': c['run_id'], 'run_attempt': c['run_attempt'],
                     'baseline_handoff': 'lifecycle.json', 'baseline_handoff_sha256': c['files']['lifecycle_receipt']['sha256'],
                     'base_runtime_lock': 'base-packages.lock', 'base_runtime_lock_sha256': c['files']['base_lock']['sha256'],
                     'tooling_lock': 'tooling.lock.json', 'tooling_lock_sha256': LOCK_PIN,
                     'tooling_audit': 'tooling-audit.json', 'tooling_audit_sha256': AUDIT_PIN,
                     'baseline': c['baseline'], 'runner_sha256': CORE}
            if barrier_contract(c):
                proof.update(purpose=c['purpose'], barrier_fixture=c['barrier_fixture'])
                report['barrier_nonce'] = nonce
                for name, row in c['barrier_fixture']['files'].items():
                    source = pinned(root, name, row['sha256'])
                    dest = inputs / name; dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, dest)
                    require(digest(dest) == row['sha256'], 'barrier input copy changed')
            if transaction_contract(c):
                proof.update(purpose=c['purpose'], transaction_fixture=c['transaction_fixture'],transaction_launcher=c['transaction_launcher'])
                report['transaction_nonce'] = nonce
                for name,row in TRANSACTION_FILES.items():
                    source=pinned(root,name,row['sha256']);dest=inputs/name;dest.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(source,dest)
                    require(dest.stat().st_size==row['bytes'] and digest(dest)==row['sha256'], 'transaction input copy changed')
            save(inputs / 'virtual-contract.json', proof)
            report['proof_contract_sha256'] = digest(inputs / 'virtual-contract.json')
            identity = ['CACHY_ASAHI_DISPOSABLE_VIRTUAL=1', 'CACHY_ASAHI_VIRTUAL_NONCE=' + nonce,
                        'CACHY_ASAHI_IMAGE_ID=' + derived, 'HOME=/tmp', 'PYTHONDONTWRITEBYTECODE=1']
            preparation = raw / 'prepare'; preparation.mkdir()
            argv = container_args(derived, 'cachy-virtual-prepare-' + nonce, inputs, runner, preparation, root=True)
            argv += identity + ['/usr/bin/python3', '-B', '/runner/virtual/prepare.py', '--contract-sha256', report['proof_contract_sha256']]
            run_container(argv, raw / 'prepare-container.log', derived, True, False, True, 1260, report['cleanup'])
            prepared = json_load(preparation / 'prepared/prepare.json')
            require(prepared['status'] == 'PREPARED', 'preparation failed')
            require(prepared.get('package_inventory') == verified['packages'], 'prepared tooling inventory differs')
            report['stages']['preparation'] = {k: prepared.get(k) for k in ('status', 'resources', 'extended_attributes', 'elapsed_seconds', 'error')}
            report['prepare_receipt_sha256'] = digest(preparation / 'prepared/prepare.json')
            decode_context, report['image_decode_preparation'] = prepared_decode_authority(
                proof, prepared, report['proof_contract_sha256'], report['prepare_receipt_sha256'])
            shutil.move(str(preparation / 'prepared'), str(inputs / 'prepared'))
            runtime = raw / 'runtime'; runtime.mkdir()
            argv = container_args(derived, 'cachy-virtual-run-' + nonce, inputs, runner, runtime)
            argv += identity + ['/usr/bin/python3', '-B', '/runner/virtual/run.py', '--contract-sha256', report['proof_contract_sha256'],
                                '--prepare-receipt-sha256', report['prepare_receipt_sha256']]
            run_container(argv, raw / 'runtime-container.log', derived, False, False, True, 1260, report['cleanup'])
            result = json_load(runtime / 'proof/result.json')
            require(result['status'] == ('PASS_TRANSACTION_ONLY' if transaction_contract(c) else 'PASS_BARRIER_ONLY' if barrier_contract(c) else 'CAPTURED_REQUIRES_VISUAL_REVIEW'),
                    'software trial did not reach selected completion point')
            report['status'] = result['status']
        except BaseException as exc:
            report['status'] = 'FAIL'
            report['error'] = str(exc)
            report['error_type'] = type(exc).__name__
            raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            with cleanup_signals():
                for owned in sorted(OWNED_CONTAINERS):
                    report['cleanup'].append(remove_container(owned))
                if private_tag:
                    report['cleanup'].append(remove_private_tag(private_tag, derived, commit_uncertain))
                if CANCELLED or any(r['status'] != 'PASS' for r in report['cleanup']):
                    report['status'] = 'FAIL'; report['cleanup_error'] = 'owned container/image removal not verified'
                try:
                    project(raw / 'runtime/proof', output, report, image_decode_context=decode_context)
                except Exception as exc:
                    report['status'] = 'FAIL'
                    report['projection_error'] = str(exc)
                for stage in ('tooling', 'verify', 'prepare', 'runtime'):
                    log = raw / (stage + '-container.log')
                    if log.is_file():
                        data = log.read_bytes()
                        if regular(log).st_size <= LIMIT and b'PRIVATE KEY' not in data:
                            shutil.copyfile(log, output / (stage + '-container.log'))
                        else:
                            report['status'] = 'FAIL'
                            report.setdefault('rejected_diagnostics', []).append(stage + '-container.log')
                # Explicit phase errors and bounded logs stay sanitized, not key-init logs.
                for stage, file in (('tooling', raw / 'tooling/tooling.json'), ('preparation', raw / 'prepare/prepared/prepare.json')):
                    if file.is_file():
                        try:
                            data = json_load(file)
                            report['stages'].setdefault(stage, {k: data.get(k) for k in ('status', 'error', 'resources', 'elapsed_seconds')})
                        except Exception:
                            report['status'] = 'FAIL'
                            report.setdefault('rejected_diagnostics', []).append(stage + '-receipt')
                try:
                    report['resources']['private_workspace_allocated_bytes_before_cleanup'] = allocated(work)
                    shutil.rmtree(work)
                    require(not work.exists(), 'private workspace remains')
                    report['private_workspace_cleanup'] = 'PASS'
                except OSError as exc:
                    report['status'] = 'FAIL'
                    report['private_workspace_cleanup'] = 'FAIL'
                    report['workspace_cleanup_error'] = type(exc).__name__
                report['elapsed_seconds'] = round(time.monotonic() - start, 3)
                save_final_report(output / 'result.json', report)
            for sig, handler in old.items():
                signal.signal(sig, handler)
    save_final_report(output / 'result.json', report)
    return not CANCELLED and report['status'] in ('CAPTURED_REQUIRES_VISUAL_REVIEW', 'PASS_BARRIER_ONLY', 'PASS_TRANSACTION_ONLY')


if __name__ == '__main__':
    raise SystemExit(0 if main() is not False else 1)
