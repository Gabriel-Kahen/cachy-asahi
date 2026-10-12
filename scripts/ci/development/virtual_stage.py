#!/usr/bin/env python3
"""Bounded adapter for the reviewed owner of a private generic QEMU trial.

PASS means captured software evidence with verified owner cleanup. Visual review,
Apple hardware compatibility and performance acceptance remain NOT RUN.
"""
import ast
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import signal
import stat
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

from common import (base_prerequisite, command, copy_pinned, digest, read_json,
                    read_regular, require, save)

LIMIT = 4 * 1024**2
BLOB_LIMIT = 32 * 1024**2
ACQUISITION_SECONDS = 600
READ_TIMEOUT = 15
OWNER_TIMEOUT = 3420  # Owner's 3300-second trial plus bounded finalization.
PACKET_FILES = {'controller.py', 'audit_tooling.py', 'common.py', 'guest.py',
                'prepare.py', 'run.py', 'gbm_probe.c', 'tooling.lock.json', 'tooling-audit.json'}
ALIASES = {'base_inputs_lock', 'base_lock', 'installed_lock', 'lifecycle_receipt',
           'installed_image_receipt', 'committed_config', 'committed_verification',
           'commit_receipt', 'tooling_lock', 'tooling_audit'}
OVERLAYS = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
            'cachy-asahi-zsh-config', 'cachy-asahi-setup'}
PUBLIC_DIRS = ('result', 'events', 'minimal-frame', 'overlay-frame', 'qemu',
               'tooling-launch', 'verify-launch', 'prepare-launch', 'runtime-launch', 'launcher')
PUBLIC_FILES = {'result': 'result.json', 'events': 'guest-events.json', 'qemu': 'qemu.log',
                **{s + '-launch': s + '-container.log' for s in ('tooling', 'verify', 'prepare', 'runtime')}}
GATES = {'successful-lifecycle-handoff', 'lifecycle-receipt-binding', 'exact-base-plus-originals-inventory',
         'complete-pacman-owned-payload', 'original-payload-hash', 'private-keyring-removed',
         'only-empty-alarm-home', 'system-gnupg-state-removed'}
PIN = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9@._+\-]*\Z')
VERSION = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9:._+~\-]*\Z')


def relative(value):
    require(isinstance(value, str) and value and len(value) <= 255 and
            all(32 <= ord(c) < 127 for c in value) and '\\' not in value, 'unsafe-input-name')
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and
            all(p not in ('', '.', '..') for p in value.split('/')), 'unsafe-input-name')
    return value


def load_module(path, name):
    read_regular(path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory(path):
    rows = {}
    for line in read_regular(path).decode('utf-8').splitlines():
        fields = line.split()
        require(len(fields) == 2 and NAME.fullmatch(fields[0]) and VERSION.fullmatch(fields[1])
                and fields[0] not in rows, 'invalid-package-inventory')
        rows[fields[0]] = fields[1]
    require(rows, 'empty-package-inventory')
    return rows


def source_packet(controller, root):
    accepted = getattr(controller, 'virtual_packet_sha256', None)
    require(isinstance(accepted, dict) and set(accepted) == PACKET_FILES and
            all(isinstance(pin, str) and PIN.fullmatch(pin) for pin in accepted.values()),
            'virtual-source-packet-not-accepted')
    directory = root / 'scripts/virtual'
    require(all(digest(directory / name) == pin for name, pin in accepted.items()), 'virtual-source-packet-drift')
    # Do not import the owner: its bare common import must never resolve to this
    # adapter's common module. Only literal declarations are read here.
    declarations = {}
    for node in ast.parse(read_regular(directory / 'controller.py').decode()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ('LOCK_PIN', 'AUDIT_PIN', 'AUDITOR_PIN', 'CORE', 'ALIASES'):
                declarations[node.targets[0].id] = ast.literal_eval(node.value)
    require(declarations.get('ALIASES') == ALIASES and declarations.get('LOCK_PIN') == accepted['tooling.lock.json']
            and declarations.get('AUDIT_PIN') == accepted['tooling-audit.json']
            and declarations.get('AUDITOR_PIN') == accepted['audit_tooling.py'] and
            declarations.get('CORE') == {n: accepted[n] for n in ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c')},
            'virtual-owner-constants-differ')
    return accepted, declarations


def preflight(controller, root):
    accepted, constants = source_packet(controller, root)
    prerequisite = base_prerequisite(controller)
    require(controller.report.get('stages', {}).get('lifecycle', {}).get('status') == 'PASS', 'lifecycle-handoff-required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', controller.installed or ''), 'actual-installed-image-required')
    work = Path(controller.work)
    handoff = work / 'lifecycle-raw'
    paths = {'base_inputs_lock': Path(controller.native_out) / 'inputs.lock.json',
             'base_lock': Path(controller.native_out) / 'packages.lock',
             'installed_lock': handoff / 'installed-packages.lock',
             'lifecycle_receipt': handoff / 'lifecycle/result.json',
             'installed_image_receipt': handoff / 'installed-image.json',
             'committed_config': handoff / 'committed-config.json',
             'committed_verification': handoff / 'committed-image/result.json',
             'commit_receipt': handoff / 'commit-receipt.json',
             'tooling_lock': root / 'scripts/virtual/tooling.lock.json',
             'tooling_audit': root / 'scripts/virtual/tooling-audit.json'}
    hashes = {name: digest(path) for name, path in paths.items()}
    loaded = {name: inventory(path) if name in ('base_lock', 'installed_lock') else read_json(path)
              for name, path in paths.items()}
    rows = read_json(work / 'fixtures-raw/archives.json')['baseline']
    require(isinstance(rows, list) and len(rows) == 4 and all(isinstance(r, dict) for r in rows)
            and {r.get('name') for r in rows} == OVERLAYS, 'original-four-baseline-required')
    for row in rows:
        require(NAME.fullmatch(row['name']) and VERSION.fullmatch(row['version']) and
                PIN.fullmatch(row['sha256']) and relative(row['archive']).startswith('baseline/') and
                row['archive'].endswith(('.pkg.tar.xz', '.pkg.tar.zst', '.pkg.tar.gz')), 'original-archive-invalid')
        require(isinstance(row['payload_sha256'], dict) and row['payload_sha256'] and
                all(relative(name).startswith('usr/') and isinstance(pin, str) and PIN.fullmatch(pin)
                    for name, pin in row['payload_sha256'].items()), 'original-payload-invalid')
        require(digest(work / 'archive-inputs' / row['archive']) == row['sha256'], 'original-archive-drift')
    versions, payload = ({r['name']: r['version'] for r in rows}, {r['name']: r['payload_sha256'] for r in rows})
    base, installed = loaded['base_lock'], loaded['installed_lock']
    require(len(base) == 341 and not OVERLAYS & set(base) and installed == base | versions, 'exact-345-baseline-required')
    life, image, committed, verified, receipt = (loaded[n] for n in
        ('lifecycle_receipt', 'installed_image_receipt', 'committed_config', 'committed_verification', 'commit_receipt'))
    source = life.get('source_commit')
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{40}', source) and life.get('status') == 'PASS' and
            life.get('baseline_handoff_ready') is True and life.get('handoff_package_versions') == versions and
            life.get('handoff_payload_sha256') == payload, 'original-lifecycle-binding-refused')
    require(image.get('image_id') == controller.installed and image.get('source_commit') == source and
            image.get('lock_sha256') == hashes['installed_lock'] and image.get('commit_receipt_sha256') == hashes['commit_receipt']
            and image.get('base_image') == receipt.get('image_id') == life.get('image_id') == controller.image,
            'installed-image-binding-refused')
    require(committed.get('status') == 'PASS' and committed.get('image_id') == controller.installed and
            committed.get('accepted_base_config') == committed.get('committed_config') and
            committed.get('test_identity_in_image_env') is False, 'committed-config-binding-refused')
    require(verified.get('status') == 'PASS' and verified.get('image_id') == controller.installed and
            verified.get('source_commit') == source and verified.get('baseline') == rows and
            verified.get('installed_packages_sha256') == hashes['installed_lock'], 'committed-verification-binding-refused')
    require(receipt.get('status') == 'READY' and receipt.get('purpose') == 'sanitized-baseline-image-handoff' and
            receipt.get('source_commit') == source and receipt.get('package_versions') == versions and
            receipt.get('payload_sha256') == payload and receipt.get('installed_package_count') == 345 and
            receipt.get('installed_packages_sha256') == hashes['installed_lock'] and
            receipt.get('base_packages_sha256') == hashes['base_lock'] and
            receipt.get('private_cleanup') == 'PASS; no private contents or hashes recorded', 'clean-handoff-receipt-required')
    checks = receipt.get('checks')
    require(isinstance(checks, list) and checks and all(isinstance(r, dict) and r.get('status') == 'PASS' for r in checks)
            and GATES <= {r.get('check') for r in checks}, 'clean-handoff-gates-required')
    lock, audit, upstream = (loaded[n] for n in ('tooling_lock', 'tooling_audit', 'base_inputs_lock'))
    frozen = {r['name'][0]: r['version'][0] for r in upstream['rootfs_packages']}
    frozen.update({r['name']: r['version'] for r in upstream['packages']})
    require(base == frozen and hashes['base_inputs_lock'] == lock['base_inputs_lock_sha256'], 'authenticated-base-binding-refused')
    packages = lock['packages']
    require(len(packages) == 19 and len({r['name'] for r in packages}) == 19 and lock['base_package_count'] == 341
            and lock['expected_package_count'] == 360 and audit.get('status') == 'PASS' and
            audit.get('tooling_lock_sha256') == hashes['tooling_lock'] and
            set(audit['packages']) == {r['name'] for r in packages} and
            not (set(base) | OVERLAYS) & {r['name'] for r in packages}, 'reviewed-tooling-audit-required')
    blobs = list(lock['keyring_files'])
    require(len(blobs) == 3 and {r['filename'] for r in blobs} ==
            {'archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked'}, 'exact-key-inputs-required')
    for row in packages:
        blobs += [row, {'filename': row['filename'] + '.sig', 'url': row['url'] + '.sig',
                        'sha256': row['signature_sha256'], 'size': row['signature_size']}]
    require(len(blobs) == 41 and len({r['filename'] for r in blobs}) == 41, 'exact-tooling-inputs-required')
    for row in blobs:
        require('/' not in relative(row['filename']) and re.fullmatch(r'[A-Za-z0-9._+@:~\-]{1,255}', row['filename']) and
                isinstance(row['sha256'], str) and PIN.fullmatch(row['sha256']) and type(row['size']) is int and
                0 <= row['size'] <= BLOB_LIMIT and isinstance(row['url'], str) and row['url'].startswith('https://'),
                'tooling-input-invalid')
    require(sum(r['size'] for r in blobs) <= 128 * 1024**2, 'tooling-total-bound-exceeded')
    contract = {'schema_version': 1, 'execution': 'native-aarch64-controller-qemu-tcg-guest',
                'installed_image_id': controller.installed, 'source_commit': controller.commit,
                'baseline_source_commit': source, 'core_sha256': constants['CORE'],
                'audit_tooling_sha256': constants['AUDITOR_PIN'], 'controller_sha256': accepted['controller.py'],
                'baseline': rows, 'files': {n: {'path': 'metadata/' + n + paths[n].suffix, 'sha256': hashes[n]} for n in paths},
                'cache_dir': 'tooling-cache'}
    prerequisite.update(installed_image_id=controller.installed, installed_package_count=345,
                        baseline_source_commit=source, virtual_source_packet='PASS', tooling_audit='PASS')
    return prerequisite, contract, paths, blobs


class AcquisitionDeadline(ValueError):
    """Fixed acquisition timeout; no transport or source contents."""


def within(deadline):
    if time.monotonic() >= deadline:
        raise AcquisitionDeadline('tooling-acquisition-deadline')


@contextmanager
def acquisition_clock():
    """A wall-clock alarm also bounds slow headers and trickling buffered reads.

    Acquisition is sequential in the controller's main thread. Preserve an
    earlier enclosing job alarm and restore its remaining time afterward.
    """
    started = time.monotonic()
    previous = signal.getsignal(signal.SIGALRM)
    timer, interval = signal.getitimer(signal.ITIMER_REAL)
    enclosing = timer > 0 and timer <= ACQUISITION_SECONDS
    fired = False
    def expired(signum, frame):
        nonlocal fired
        fired = True
        if enclosing:
            if callable(previous):
                previous(signum, frame)
            raise KeyboardInterrupt()
        raise AcquisitionDeadline('tooling-acquisition-deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(timer, ACQUISITION_SECONDS) if enclosing else ACQUISITION_SECONDS)
    try:
        yield started + ACQUISITION_SECONDS
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if timer > 0 and not (enclosing and fired):
            signal.setitimer(signal.ITIMER_REAL, max(0.001, timer - (time.monotonic() - started)), interval)
        elif interval > 0:
            signal.setitimer(signal.ITIMER_REAL, interval, interval)


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        require(urlsplit(url).scheme == 'https', 'tooling-insecure-redirect')
        return super().redirect_request(request, response, code, message, headers, url)


def open_tooling(url, timeout):
    return urllib.request.build_opener(HTTPSRedirect()).open(url, timeout=timeout)


def fetch_blob(row, cache, deadline):
    """Exact bounded public inputs; no native.fetch mutation or host trust work."""
    within(deadline)
    target = cache / row['filename']
    if target.exists() or target.is_symlink():
        data = read_regular(target, BLOB_LIMIT)
        within(deadline)
        require(len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'tooling-cache-drift')
        return target
    descriptor, name = tempfile.mkstemp(prefix=row['filename'] + '.', suffix='.partial', dir=cache)
    partial = Path(name)
    try:
        checksum, size = hashlib.sha256(), 0
        with os.fdopen(descriptor, 'wb') as stream, open_tooling(row['url'], timeout=READ_TIMEOUT) as source:
            require(urlsplit(source.geturl()).scheme == 'https' and source.status == 200, 'tooling-origin-refused')
            length = source.headers.get('Content-Length')
            require(length is None or length == str(row['size']), 'tooling-size-differs')
            while True:
                within(deadline)
                # read1 returns after one buffered/socket read. The phase alarm
                # additionally covers HTTP header/chunk parsing and slow trickles.
                data = source.read1(min(65536, row['size'] + 1 - size))
                within(deadline)
                if not data:
                    break
                size += len(data)
                require(size <= row['size'], 'tooling-size-differs')
                stream.write(data); checksum.update(data)
        require(size == row['size'] and checksum.hexdigest() == row['sha256'], 'tooling-pin-differs')
        within(deadline)
        require(not target.exists() and not target.is_symlink(), 'tooling-cache-collision')
        partial.rename(target)
        return target
    finally:
        partial.unlink(missing_ok=True)


def acquire(root, cache, inputs, blobs, receipts):
    # No executor shutdown can hold cancellation hostage to background reads.
    # Every planned input receives an outcome, including pending/cancelled ones.
    cancelled = False
    try:
        with acquisition_clock() as deadline:
            require(cache.is_absolute() and '..' not in cache.parts and
                    all(stat.S_ISDIR(p.lstat().st_mode) for p in (cache, *cache.parents)), 'existing-safe-cache-required')
            for row in blobs:
                target = inputs / 'tooling-cache' / row['filename']
                existed = target.exists() or target.is_symlink()
                complete = False
                try:
                    within(deadline)
                    path = fetch_blob(row, cache, deadline)
                    within(deadline)
                    result = copy_pinned(path, target, row['sha256'], BLOB_LIMIT)
                    within(deadline)
                    require(result['bytes'] == row['size'], 'tooling-size-differs')
                    receipts.append({'filename': row['filename'], 'status': 'PIN_MATCH', **result})
                    complete = True
                except AcquisitionDeadline:
                    receipts.append({'filename': row['filename'], 'status': 'FAIL', 'error_code': 'tooling-acquisition-deadline'})
                except Exception:
                    receipts.append({'filename': row['filename'], 'status': 'FAIL', 'error_code': 'tooling-acquisition-failed'})
                finally:
                    if not complete and not existed:
                        target.unlink(missing_ok=True)
    except KeyboardInterrupt:
        cancelled = True
        raise
    finally:
        receipts.extend({'filename': row['filename'], 'status': 'FAIL',
                         'error_code': 'tooling-acquisition-cancelled' if cancelled else 'tooling-acquisition-incomplete'}
                        for row in blobs[len(receipts):])
    require(len(receipts) == 41 and all(r['status'] == 'PIN_MATCH' for r in receipts), 'tooling-acquisition-failed')


def public_paths(output):
    """Fixed retention allowlist, also usable after a raised cancellation."""
    paths = [output / 'adapter-status', *(output / 'virtual-public' / n for n in PUBLIC_DIRS)]
    return [str(p.absolute()) for p in paths if p.is_dir() and not p.is_symlink()]


def text_projection(exporter, source, target, selected, name=None):
    selected.mkdir(mode=0o700)
    # The generic exporter owns the complete content/private/control policy.
    copy_pinned(source, selected / (name or source.name), digest(source), 8 * 1024**2)
    result = exporter.export_evidence(selected, target)
    return result.get('evidence_export') == 'PASS'


def frame(path, row, stage):
    require(isinstance(row, dict) and row.get('filename') == stage + '.ppm' and
            isinstance(row.get('sha256'), str) and PIN.fullmatch(row['sha256']), 'frame-binding-refused')
    data = read_regular(path, 8 * 1024**2)
    require(hashlib.sha256(data).hexdigest() == row['sha256'], 'frame-binding-refused')
    header = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s', data)
    require(header is not None, 'frame-format-refused')
    width, height = map(int, header.groups())
    body = data[header.end():]
    require(0 < width <= 1920 and 0 < height <= 1200 and len(body) == width * height * 3 and
            row.get('width') == width and row.get('height') == height and
            len({body[i:i + 3] for i in range(0, len(body), 3)}) >= 8, 'frame-content-refused')
    return data


def read_events(path, policy):
    """Inspect the known encoded terminal records before any public copying."""
    data = read_regular(path, LIMIT)
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate-guest-event-field')
            result[key] = value
        return result
    events = json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                        parse_constant=lambda _: require(False, 'nonfinite-guest-event'))
    require(isinstance(events, list) and len(events) <= 2048 and all(isinstance(e, dict) for e in events),
            'bounded-guest-event-list-required')
    schemas = {
        'boot': {'event', 'nonce', 'arch', 'page_size', 'kernel', 'execution', 'hardware_validation'},
        'gbm_pass': {'event', 'nonce', 'probe'}, 'frame_ready': {'event', 'stage', 'monitors', 'clients'},
        'phase_pass': {'event', 'stage'},
        'guest_pass': {'event', 'nonce', 'software_session', 'hardware_validation', 'graphics_acceleration'},
        'guest_failed': {'event', 'error', 'hardware_validation'},
        'command': {'event', 'argv', 'returncode', 'error', 'stdout', 'stderr'},
        'session_log': {'event', 'stage', 'filename', 'sha256', 'base64'}}
    for event in events:
        require(isinstance(event.get('event'), str) and event['event'] in schemas and
                set(event) == schemas[event['event']], 'unknown-guest-event-fields-refused')
        if event.get('event') == 'session_log':
            require(set(event) == {'event', 'stage', 'filename', 'sha256', 'base64'} and event['stage'] in ('minimal', 'overlay') and
                    event['filename'] in (event['stage'] + '.log', event['stage'] + '-client.log') and
                    isinstance(event['sha256'], str) and PIN.fullmatch(event['sha256']) and isinstance(event['base64'], str),
                    'guest-session-log-event-refused')
            decoded = base64.b64decode(event['base64'], validate=True)
            require(len(decoded) <= 1024**2 and hashlib.sha256(decoded).hexdigest() == event['sha256'], 'guest-session-log-binding-refused')
            text = decoded.decode('utf-8', errors='replace')
            normalized = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
            normalized = ''.join(c for c in normalized if ord(c) >= 32 or c in '\n\r\t')
            require(not policy.PRIVATE_CONTENT.search(text) and not policy.PRIVATE_CONTENT.search(normalized),
                    'private-guest-session-log-refused')
    return events, hashlib.sha256(data).hexdigest()


def event_protocol(path, expected_sha256, nonce, policy):
    events, actual_sha256 = read_events(path, policy)
    require(actual_sha256 == expected_sha256, 'guest-events-binding-refused')
    require(len(events) >= 7, 'complete-guest-event-protocol-required')
    essential = []
    for event in events:
        require(isinstance(event, dict), 'guest-event-object-required')
        kind = event.get('event')
        require(kind in ('boot', 'gbm_pass', 'frame_ready', 'phase_pass', 'guest_pass', 'command', 'session_log'),
                'guest-event-kind-refused')
        require('nonce' not in event or event['nonce'] == nonce, 'guest-event-nonce-refused')
        if kind == 'boot':
            require(set(event) == {'event', 'nonce', 'arch', 'page_size', 'kernel', 'execution', 'hardware_validation'} and
                    event['nonce'] == nonce and event['arch'] == 'aarch64' and type(event['page_size']) is int and
                    event['page_size'] == 4096 and event['kernel'] == '7.2.10-1-aarch64-ARCH' and
                    event['execution'] == 'qemu-tcg-generic-aarch64' and event['hardware_validation'] == 'NOT RUN',
                    'guest-boot-identity-refused')
        elif kind == 'gbm_pass':
            require(set(event) == {'event', 'nonce', 'probe'} and event['nonce'] == nonce and
                    isinstance(event['probe'], dict), 'guest-gbm-identity-refused')
            probe = event['probe']
            require(probe.get('schema') == 1 and probe.get('status') == 'PASS' and
                    probe.get('scope') == 'guest_software_gbm_egl_only' and
                    isinstance(probe.get('renderer'), str) and probe['renderer'].startswith(('llvmpipe', 'softpipe')) and
                    probe.get('width') == probe.get('height') == 64 and probe.get('verified_pixels') == 4096 and
                    probe.get('expected_rgba') == [255, 0, 255, 255] and
                    all(probe.get(n) == 'NOT_RUN' for n in ('scanout', 'm2_hardware', 'performance')),
                    'guest-software-gbm-proof-refused')
        elif kind == 'frame_ready':
            require(set(event) == {'event', 'stage', 'monitors', 'clients'} and event['stage'] in ('minimal', 'overlay') and
                    isinstance(event['monitors'], list) and isinstance(event['clients'], list), 'guest-frame-event-refused')
            require(any(isinstance(m, dict) and type(m.get('width')) is int and type(m.get('height')) is int and
                        m['width'] > 0 and m['height'] > 0 for m in event['monitors']) and
                    any(isinstance(c, dict) and c.get('mapped') is True and type(c.get('pid')) is int and c['pid'] > 0 and
                        isinstance(c.get('size'), list) and len(c['size']) == 2 and
                        all(type(n) is int and n > 0 for n in c['size']) for c in event['clients']), 'guest-session-frame-proof-refused')
        elif kind == 'phase_pass':
            require(set(event) == {'event', 'stage'} and event['stage'] in ('minimal', 'overlay'), 'guest-phase-event-refused')
        elif kind == 'guest_pass':
            require(set(event) == {'event', 'nonce', 'software_session', 'hardware_validation', 'graphics_acceleration'} and
                    event['nonce'] == nonce and event['software_session'] == 'PASS' and
                    event['hardware_validation'] == event['graphics_acceleration'] == 'NOT RUN', 'guest-completion-event-refused')
        elif kind == 'command':
            require(set(event) == {'event', 'argv', 'returncode', 'error', 'stdout', 'stderr'} and
                    isinstance(event['argv'], list) and event['argv'] and all(isinstance(a, str) for a in event['argv']) and
                    event['argv'][0] in ('/usr/bin/modprobe', '/usr/bin/udevadm', '/usr/bin/dmesg', '/usr/bin/pacman', '/usr/local/bin/gbm-probe', '/usr/bin/hyprctl') and
                    event['returncode'] == 0 and event['error'] is None and
                    isinstance(event['stdout'], str) and isinstance(event['stderr'], str), 'guest-command-event-refused')
        if kind not in ('command', 'session_log'):
            essential.append((kind, event.get('stage')))
    require(essential == [('boot', None), ('gbm_pass', None), ('frame_ready', 'minimal'), ('phase_pass', 'minimal'),
                          ('frame_ready', 'overlay'), ('phase_pass', 'overlay'), ('guest_pass', None)],
            'guest-event-order-or-completeness-refused')


@contextmanager
def defer_finalization():
    events = []
    previous = {sig: signal.signal(sig, lambda *_: events.append(True)) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield events
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def receive(root, output, contract, code, result):
    owner = output / 'owner-public'
    exporter = load_module(root / 'scripts/ci/integration_export.py', 'development_virtual_exporter')
    public = output / 'virtual-public'; public.mkdir(mode=0o700, exist_ok=True)
    selected = output / 'selected'; selected.mkdir(mode=0o700, exist_ok=True)
    good = True
    for directory, name in PUBLIC_FILES.items():
        if directory == 'events':
            continue
        source = owner / name
        if source.exists() or source.is_symlink():
            try:
                good = text_projection(exporter, source, public / directory, selected / directory) and good
            except Exception:
                good = False
    launch = output / 'private-launcher.log'
    if launch.exists():
        try:
            good = text_projection(exporter, launch, public / 'launcher', selected / 'launcher', 'launcher.log') and good
        except Exception:
            good = False
    event_file = owner / 'guest-events.json'
    if event_file.exists() or event_file.is_symlink():
        try:
            read_events(event_file, exporter)
            good = text_projection(exporter, event_file, public / 'events', selected / 'events') and good
        except Exception:
            good = False
    receipt = read_json(owner / 'result.json', 8 * 1024**2)
    cleanup = receipt.get('cleanup')
    cleanup_ok = isinstance(cleanup, list) and bool(cleanup) and all(isinstance(r, dict) and
                 r.get('status') == 'PASS' and r.get('absence_verified') is True and
                 not r.get('commit_outcome_uncertain', False) for r in cleanup)
    result['owner_cleanup'] = {'status': 'PASS' if cleanup_ok else 'FAIL',
                              'records': len(cleanup) if isinstance(cleanup, list) else 0,
                              'private_workspace_cleanup': 'PASS' if receipt.get('private_workspace_cleanup') == 'PASS' else 'FAIL'}
    require(good, 'virtual-public-export-refused')
    require(receipt.get('schema_version') == 1 and receipt.get('purpose') == 'bounded-generic-arm-software-proof' and
            receipt.get('source_commit') == contract['source_commit'] and receipt.get('baseline_image') == contract['installed_image_id']
            and receipt.get('controller_contract_sha256') == digest(output / 'inputs/controller-contract.json') and
            receipt.get('source_sha256') == contract['core_sha256'] | {'controller.py': contract['controller_sha256'],
                'audit_tooling.py': contract['audit_tooling_sha256']} and receipt.get('inputs') == contract['files'], 'virtual-owner-binding-refused')
    require(code == 0 and receipt.get('status') == 'CAPTURED_REQUIRES_VISUAL_REVIEW' and cleanup_ok and
            receipt.get('private_workspace_cleanup') == 'PASS', 'virtual-owner-acceptance-failed')
    require(set(receipt.get('frames', {})) == {'minimal', 'overlay'} and
            digest(owner / 'guest-events.json') == receipt.get('guest_events_sha256') and
            (public / 'events/export-manifest.json').is_file() and (public / 'result/export-manifest.json').is_file(),
            'virtual-capture-evidence-required')
    require(receipt.get('stages', {}).get('tooling', {}).get('status') == 'READY' and
            receipt['stages']['tooling'].get('package_count') == 364 and
            receipt.get('stages', {}).get('preparation', {}).get('status') == 'PREPARED', 'virtual-stage-receipts-required')
    guest = receipt.get('guest', {})
    require(guest.get('status') == 'CAPTURED_REQUIRES_VISUAL_REVIEW' and
            guest.get('execution') == 'qemu-tcg-generic-aarch64' and
            guest.get('contract_sha256') == receipt.get('proof_contract_sha256') and
            isinstance(receipt.get('proof_contract_sha256'), str) and PIN.fullmatch(receipt['proof_contract_sha256']) and
            guest.get('prepare_receipt_sha256') == receipt.get('prepare_receipt_sha256') and
            isinstance(receipt.get('prepare_receipt_sha256'), str) and PIN.fullmatch(receipt['prepare_receipt_sha256']) and
            guest.get('image_id') == receipt['stages']['tooling'].get('image_id') and
            re.fullmatch(r'sha256:[0-9a-f]{64}', guest.get('image_id', '')) and
            re.fullmatch(r'[0-9a-f]{32}', guest.get('nonce', '')) and
            guest.get('software_session_ipc') == 'PASS' and guest.get('software_compositor') == 'REVIEW REQUIRED' and
            guest.get('frame_proof') == 'REVIEW REQUIRED' and all(guest.get(n) == 'NOT RUN' for n in
                ('hardware_validation', 'graphics_acceleration', 'm2_16k_pages', 'performance')),
            'virtual-guest-proof-binding-refused')
    nonce = guest['nonce']
    require(len(cleanup) == 5 and {r.get('container') for r in cleanup if 'container' in r} ==
            {'cachy-virtual-' + s + '-' + nonce for s in ('tooling', 'verify', 'prepare', 'run')} and
            len([r for r in cleanup if r.get('private_tag') == 'cachy-virtual-private-' + nonce + ':fixture'
                 and r.get('image_id') == guest['image_id']]) == 1, 'virtual-complete-owned-cleanup-required')
    event_protocol(owner / 'guest-events.json', receipt['guest_events_sha256'], nonce, exporter)
    # Binary publication requires the complete accepted capture binding. Text
    # failure diagnostics remain independently subject to the generic filter.
    frames = {stage: frame(owner / (stage + '.ppm'), receipt['frames'][stage], stage)
              for stage in ('minimal', 'overlay')}
    for stage, data in frames.items():
        row = receipt['frames'][stage]
        folder = selected / (stage + '-frame'); folder.mkdir(mode=0o700)
        (folder / (stage + '.ppm')).write_bytes(data)
        save(folder / 'receipt.json', {'filename': stage + '.ppm', 'sha256': hashlib.sha256(data).hexdigest(),
             'bytes': len(data), 'width': row['width'], 'height': row['height'], 'visual_review': 'NOT RUN'})
        require(read_regular(folder / (stage + '.ppm'), 8 * 1024**2) == data, 'frame-copy-drift')
        folder.rename(public / (stage + '-frame'))
    result.update(status='PASS', owner_status='CAPTURED_REQUIRES_VISUAL_REVIEW', visual_review='REQUIRED')


def run_virtual(controller, root, output, cache):
    root, output, cache = map(lambda p: Path(p).absolute(), (root, output, cache))
    require('..' not in output.parts and not output.exists() and not output.is_symlink() and
            all(not p.is_symlink() for p in output.parents), 'new-safe-output-required')
    for other in (root, Path(controller.native_out).absolute(), Path(controller.work).absolute(), cache):
        require(not output.is_relative_to(other) and not other.is_relative_to(output), 'output-boundary-overlap')
    output.mkdir(mode=0o700, parents=True)
    status = output / 'adapter-status'; status.mkdir(mode=0o700)
    result = {'status': 'NOT RUN', 'prerequisite': {}, 'public': [], 'hardware_validation': 'NOT RUN',
              'performance_acceptance': 'NOT RUN', 'visual_review': 'NOT RUN', 'selected_for_release': False}
    acquisitions, contract, launched = [], None, False
    try:
        if not getattr(controller, 'virtual_packet_sha256', None):
            result['error_code'] = 'virtual-source-packet-not-accepted'
            return result
        result['prerequisite'], contract, paths, blobs = preflight(controller, root)
        result['status'] = 'FAIL'
        inputs = output / 'inputs'; inputs.mkdir(mode=0o700)
        for alias, path in paths.items():
            item = contract['files'][alias]
            copy_pinned(path, inputs / item['path'], item['sha256'])
        for row in contract['baseline']:
            copy_pinned(Path(controller.work) / 'archive-inputs' / row['archive'], inputs / row['archive'], row['sha256'], BLOB_LIMIT)
        acquire(root, cache, inputs, blobs, acquisitions)
        save(inputs / 'controller-contract.json', contract)
        launched = True
        code = command([sys.executable, '-B', root / 'scripts/virtual/controller.py', '--contract',
                        inputs / 'controller-contract.json', '--contract-sha256', digest(inputs / 'controller-contract.json'),
                        '--output', output / 'owner-public'], output / 'private-launcher.log', OWNER_TIMEOUT)
        receive(root, output, contract, code, result)
    except KeyboardInterrupt:
        result.update(status='FAIL', error_code='cancelled')
        raise
    except Exception:
        result['error_code'] = 'virtual-prerequisite-refused' if result['status'] == 'NOT RUN' else 'virtual-stage-failed'
    finally:
        # Repeated TERM/INT cannot escape before cleanup/status evidence is sealed.
        with defer_finalization() as events:
            if launched and result['status'] != 'PASS' and not (output / 'virtual-public').exists():
                try:
                    receive(root, output, contract, None, result)
                except KeyboardInterrupt:
                    events.append(True)
                except Exception:
                    pass
            if events:
                result.update(status='FAIL', error_code='cancelled')
            result['public'] = public_paths(output)
            save(status / 'acquisition.json', {'status': 'PIN_MATCH' if len(acquisitions) == 41 and
                 all(r['status'] == 'PIN_MATCH' for r in acquisitions) else 'NOT COMPLETE', 'inputs': acquisitions,
                 'signature_authentication': 'Owner performs trust and signature verification inside its isolated container'})
            if events:
                result.update(status='FAIL', error_code='cancelled')
            save(status / 'result.json', {k: v for k, v in result.items() if k != 'public'})
            if events:
                result.update(status='FAIL', error_code='cancelled')
                save(status / 'result.json', {k: v for k, v in result.items() if k != 'public'})
        if events:
            raise KeyboardInterrupt()
    return result
