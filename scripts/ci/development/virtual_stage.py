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
import shutil
import sys
import signal
import stat
import tempfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit

from common import (base_prerequisite, command, copy_pinned, digest, read_json,
                    read_regular, require, save, check_deadline, CleanupFailure)

LIMIT = 4 * 1024**2
BLOB_LIMIT = 32 * 1024**2
ACQUISITION_SECONDS = 600
READ_TIMEOUT = 15
OWNER_TIMEOUT = 3420  # Owner's 3300-second trial plus bounded finalization.
PACKET_FILES = {'controller.py', 'audit_tooling.py', 'common.py', 'guest.py',
                'prepare.py', 'run.py', 'gbm_probe.c', 'image_decode_probe.c',
                'image_decode_report.py', 'tooling.lock.json', 'tooling-audit.json'}
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


DIAGNOSTIC_CODES = {
    'accepted-source-commit-required',
    'actual-bootstrap-binding-required',
    'actual-builder-required',
    'actual-installed-image-required',
    'authenticated-base-binding-refused',
    'bounded-guest-event-list-required',
    'clean-handoff-gates-required',
    'clean-handoff-receipt-required',
    'committed-config-binding-refused',
    'committed-verification-binding-refused',
    'complete-guest-event-protocol-required',
    'copy-changed',
    'copy-pin-differs',
    'duplicate-guest-event-field',
    'duplicate-json-field',
    'empty-package-inventory',
    'exact-345-baseline-required',
    'exact-authenticated-341-base-required',
    'exact-key-inputs-required',
    'exact-tooling-inputs-required',
    'existing-safe-cache-required',
    'finite-command-bounds-required',
    'frame-binding-refused',
    'frame-content-refused',
    'frame-copy-drift',
    'frame-format-refused',
    'full-pin-required',
    'guest-boot-identity-refused',
    'guest-command-event-refused',
    'guest-completion-event-refused',
    'guest-event-kind-refused',
    'guest-event-nonce-refused',
    'guest-event-object-required',
    'guest-event-order-or-completeness-refused',
    'guest-events-binding-refused',
    'guest-frame-event-refused',
    'guest-gbm-identity-refused',
    'guest-ipc-probe-event-refused',
    'guest-ipc-readiness-protocol-refused',
    'guest-image-decode-event-refused',
    'guest-image-decode-order-refused',
    'guest-image-decode-binding-refused',
    'authenticated-workflow-identity-required',
    'guest-phase-event-refused',
    'guest-process-state-event-refused',
    'guest-process-state-order-refused',
    'guest-session-frame-proof-refused',
    'guest-session-log-binding-refused',
    'guest-session-log-event-refused',
    'guest-software-gbm-proof-refused',
    'input-changed',
    'input-hash-bound-exceeded',
    'input-parent-invalid',
    'input-path-invalid',
    'input-pin-differs',
    'installed-image-binding-refused',
    'invalid-package-inventory',
    'json-object-required',
    'lifecycle-handoff-required',
    'native-original-builds-required',
    'new-safe-output-required',
    'nonfinite-guest-event',
    'nonfinite-json',
    'original-archive-drift',
    'original-archive-invalid',
    'original-four-baseline-required',
    'original-lifecycle-binding-refused',
    'original-payload-invalid',
    'output-boundary-overlap',
    'private-guest-session-log-refused',
    'private-guest-ipc-probe-refused',
    'qemu-capability-binding-refused',
    'qemu-capability-record-refused',
    'qemu-capability-source-refused',
    'qemu-capability-success-required',
    'qemu-guest-claim-refused',
    'virtual-public-copy-drift',
    'regular-bounded-input-required',
    'reviewed-tooling-audit-required',
    'signed-baseline-cached-signer-authority-required',
    'signed-baseline-cached-signer-receipt-refused',
    'signed-baseline-original-binding-refused',
    'signed-baseline-public-signature-required',
    'signed-baseline-required',
    'signed-baseline-signature-binding-refused',
    'signed-baseline-signature-pin-refused',
    'signed-baseline-signer-archive-binding-refused',
    'signed-baseline-signer-receipt-refused',
    'signed-baseline-signer-status-refused',
    'stage-deadline-exceeded',
    'stage-cleanup-failed',
    'stage-log-bound-exceeded',
    'tooling-acquisition-deadline',
    'tooling-acquisition-failed',
    'tooling-cache-collision',
    'tooling-cache-drift',
    'tooling-http-failed',
    'tooling-input-invalid',
    'tooling-insecure-redirect',
    'tooling-origin-refused',
    'tooling-pin-differs',
    'tooling-size-differs',
    'tooling-total-bound-exceeded',
    'tooling-transport-failed',
    'tooling-transport-timeout',
    'unknown-guest-event-fields-refused',
    'unsafe-input-name',
    'virtual-capture-evidence-required',
    'virtual-complete-owned-cleanup-required',
    'virtual-guest-proof-binding-refused',
    'virtual-input-unavailable',
    'virtual-owner-acceptance-failed',
    'virtual-owner-binding-refused',
    'virtual-owner-constants-differ',
    'virtual-public-export-refused',
    'virtual-source-packet-drift',
    'virtual-source-packet-not-accepted',
    'virtual-stage-receipts-required',
}


def diagnostic(error, fallback):
    """Only exact fixed codes survive; exception text is never a diagnostic."""
    if isinstance(error, urllib.error.HTTPError):
        return 'tooling-http-failed'
    if isinstance(error, TimeoutError):
        return 'tooling-transport-timeout'
    if isinstance(error, urllib.error.URLError):
        return 'tooling-transport-failed'
    if isinstance(error, OSError):
        return 'virtual-input-unavailable'
    if isinstance(error, ValueError) and len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0] in DIAGNOSTIC_CODES:
        return error.args[0]
    return fallback


def deadline_options(deadline):
    return {} if deadline is None else {'deadline': deadline}


def relative(value):
    require(isinstance(value, str) and value and len(value) <= 255 and
            all(32 <= ord(c) < 127 for c in value) and '\\' not in value, 'unsafe-input-name')
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and
            all(p not in ('', '.', '..') for p in value.split('/')), 'unsafe-input-name')
    return value


def load_module(path, name, *, deadline=None):
    check_deadline(deadline)
    read_regular(path, **deadline_options(deadline))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def image_decoder(root=None, expected_pin=None, *, deadline=None):
    """Load only the selected packet file, never an ambient module search path."""
    check_deadline(deadline)
    root = Path(__file__).resolve().parents[3] if root is None else Path(root)
    path = root / 'scripts/virtual/image_decode_report.py'
    source = read_regular(path, **deadline_options(deadline))
    if expected_pin is not None:
        require(type(expected_pin) is str and PIN.fullmatch(expected_pin) and
                hashlib.sha256(source).hexdigest() == expected_pin, 'virtual-source-packet-drift')
    spec = importlib.util.spec_from_file_location('development_virtual_image_decode_report', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def workflow_identity():
    values = {name: os.environ.get('GITHUB_' + name.upper()) for name in ('run_id', 'run_attempt')}
    require(all(type(values[key]) is str and re.fullmatch(r'[1-9][0-9]{0,' + str(maximum - 1) + '}', values[key])
                for key, maximum in (('run_id', 20), ('run_attempt', 10))), 'authenticated-workflow-identity-required')
    return values


def inventory(path, *, deadline=None):
    check_deadline(deadline)
    rows = {}
    for line in read_regular(path, **deadline_options(deadline)).decode('utf-8').splitlines():
        check_deadline(deadline)
        fields = line.split()
        require(len(fields) == 2 and NAME.fullmatch(fields[0]) and VERSION.fullmatch(fields[1])
                and fields[0] not in rows, 'invalid-package-inventory')
        rows[fields[0]] = fields[1]
    require(rows, 'empty-package-inventory')
    return rows


def source_packet(controller, root, *, deadline=None):
    check_deadline(deadline)
    accepted = getattr(controller, 'virtual_packet_sha256', None)
    require(isinstance(accepted, dict) and set(accepted) == PACKET_FILES and
            all(isinstance(pin, str) and PIN.fullmatch(pin) for pin in accepted.values()),
            'virtual-source-packet-not-accepted')
    directory = root / 'scripts/virtual'
    require(all(digest(directory / name, **deadline_options(deadline)) == pin for name, pin in accepted.items()), 'virtual-source-packet-drift')
    # Do not import the owner: its bare common import must never resolve to this
    # adapter's common module. Only literal declarations are read here.
    declarations = {}
    for node in ast.parse(read_regular(directory / 'controller.py', **deadline_options(deadline)).decode()).body:
        check_deadline(deadline)
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ('LOCK_PIN', 'AUDIT_PIN', 'AUDITOR_PIN', 'CORE', 'ALIASES'):
                declarations[node.targets[0].id] = ast.literal_eval(node.value)
    require(declarations.get('ALIASES') == ALIASES and declarations.get('LOCK_PIN') == accepted['tooling.lock.json']
            and declarations.get('AUDIT_PIN') == accepted['tooling-audit.json']
            and declarations.get('AUDITOR_PIN') == accepted['audit_tooling.py'] and
            declarations.get('CORE') == {n: accepted[n] for n in ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c',
                                                                  'image_decode_probe.c', 'image_decode_report.py')},
            'virtual-owner-constants-differ')
    return accepted, declarations


def signed_baseline(rows, observed, work, image, expected_receipt, *, deadline=None):
    """Accept only the lifecycle producer's verified signature annotation."""
    check_deadline(deadline)
    require(isinstance(expected_receipt, dict) and expected_receipt, 'signed-baseline-cached-signer-authority-required')
    receipt = read_json(Path(work) / 'signer-raw/test-signature-receipt.json', **deadline_options(deadline))
    require(receipt.get('status') == 'TEST-SIGNATURES PASS' and receipt.get('purpose') == 'TEST-ONLY-integration-signatures' and
            receipt.get('production_credentials_used') is False and receipt.get('hardware_status') == 'NOT RUN' and
            receipt.get('contract', {}).get('image_id') == image and
            isinstance(receipt.get('signatures'), dict) and len(receipt['signatures']) == 8 and
            re.fullmatch(r'[0-9A-F]{40}', receipt.get('fingerprint', '')),
            'signed-baseline-signer-receipt-refused')
    require(receipt == expected_receipt, 'signed-baseline-cached-signer-receipt-refused')
    core = {'name', 'version', 'archive', 'sha256', 'payload_sha256'}
    require(isinstance(observed, list) and len(observed) == len(rows) == 4, 'signed-baseline-required')
    for original, signed in zip(rows, observed):
        check_deadline(deadline)
        require(isinstance(original, dict) and set(original) == core and isinstance(signed, dict) and
                set(signed) == core | {'signature_sha256'} and {k: signed[k] for k in core} == original,
                'signed-baseline-original-binding-refused')
        pin = signed['signature_sha256']
        record = receipt['signatures'].get(original['archive'])
        require(isinstance(record, dict) and set(record) == {'archive_sha256', 'signature_sha256', 'status'} and
                record['archive_sha256'] == original['sha256'] and record['signature_sha256'] == pin and
                isinstance(record['status'], str), 'signed-baseline-signer-archive-binding-refused')
        statuses = [line.split()[1:] for line in record['status'].splitlines() if line.startswith('[GNUPG:] ')]
        valid = [r for r in statuses if r and r[0] == 'VALIDSIG']
        require(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == receipt['fingerprint'] and
                not any(r and r[0] in ('EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY') for r in statuses),
                'signed-baseline-signer-status-refused')
        require(isinstance(pin, str) and PIN.fullmatch(pin), 'signed-baseline-signature-pin-refused')
        path = Path(work) / 'lifecycle-inputs' / (relative(original['archive']) + '.sig')
        data = read_regular(path, 8192, **deadline_options(deadline))
        require(data and b'PRIVATE KEY' not in data and data[0] & 128 and
                (data[0] & 63 if data[0] & 64 else (data[0] >> 2) & 15) == 2,
                'signed-baseline-public-signature-required')
        require(hashlib.sha256(data).hexdigest() == pin, 'signed-baseline-signature-binding-refused')
    return observed


def preflight(controller, root, *, deadline=None):
    check_deadline(deadline)
    accepted, constants = source_packet(controller, root, **deadline_options(deadline))
    prerequisite = base_prerequisite(controller, **deadline_options(deadline))
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
    hashes = {name: digest(path, **deadline_options(deadline)) for name, path in paths.items()}
    loaded = {name: inventory(path, **deadline_options(deadline)) if name in ('base_lock', 'installed_lock') else read_json(path, **deadline_options(deadline))
              for name, path in paths.items()}
    rows = read_json(work / 'fixtures-raw/archives.json', **deadline_options(deadline))['baseline']
    require(isinstance(rows, list) and len(rows) == 4 and all(isinstance(r, dict) for r in rows)
            and {r.get('name') for r in rows} == OVERLAYS, 'original-four-baseline-required')
    for row in rows:
        check_deadline(deadline)
        require(NAME.fullmatch(row['name']) and VERSION.fullmatch(row['version']) and
                PIN.fullmatch(row['sha256']) and relative(row['archive']).startswith('baseline/') and
                row['archive'].endswith(('.pkg.tar.xz', '.pkg.tar.zst', '.pkg.tar.gz')), 'original-archive-invalid')
        require(isinstance(row['payload_sha256'], dict) and row['payload_sha256'] and
                all(relative(name).startswith('usr/') and isinstance(pin, str) and PIN.fullmatch(pin)
                    for name, pin in row['payload_sha256'].items()), 'original-payload-invalid')
        require(digest(work / 'archive-inputs' / row['archive'], **deadline_options(deadline)) == row['sha256'], 'original-archive-drift')
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
            verified.get('source_commit') == source and
            verified.get('installed_packages_sha256') == hashes['installed_lock'], 'committed-verification-binding-refused')
    signed_rows = signed_baseline(rows, verified.get('baseline'), work, controller.image, getattr(controller, 'sign_receipt', None), **deadline_options(deadline))
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
    require(len(packages) == 21 and len({r['name'] for r in packages}) == 21 and lock['base_package_count'] == 341
            and lock['expected_package_count'] == 362 and
            {'qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci'} <= {r['name'] for r in packages} and
            audit.get('status') == 'PASS' and
            audit.get('tooling_lock_sha256') == hashes['tooling_lock'] and
            set(audit['packages']) == {r['name'] for r in packages} and
            not (set(base) | OVERLAYS) & {r['name'] for r in packages}, 'reviewed-tooling-audit-required')
    blobs = list(lock['keyring_files'])
    require(len(blobs) == 3 and {r['filename'] for r in blobs} ==
            {'archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked'}, 'exact-key-inputs-required')
    for row in packages:
        check_deadline(deadline)
        blobs += [row, {'filename': row['filename'] + '.sig', 'url': row['url'] + '.sig',
                        'sha256': row['signature_sha256'], 'size': row['signature_size']}]
    require(len(blobs) == 45 and len({r['filename'] for r in blobs}) == 45, 'exact-tooling-inputs-required')
    for row in blobs:
        check_deadline(deadline)
        require('/' not in relative(row['filename']) and re.fullmatch(r'[A-Za-z0-9._+@:~\-]{1,255}', row['filename']) and
                isinstance(row['sha256'], str) and PIN.fullmatch(row['sha256']) and type(row['size']) is int and
                0 <= row['size'] <= BLOB_LIMIT and isinstance(row['url'], str) and row['url'].startswith('https://'),
                'tooling-input-invalid')
    require(sum(r['size'] for r in blobs) <= 128 * 1024**2, 'tooling-total-bound-exceeded')
    contract = {'schema_version': 1, 'execution': 'native-aarch64-controller-qemu-tcg-guest',
                'installed_image_id': controller.installed, 'source_commit': controller.commit,
                'baseline_source_commit': source, 'core_sha256': constants['CORE'],
                'audit_tooling_sha256': constants['AUDITOR_PIN'], 'controller_sha256': accepted['controller.py'],
                'baseline': signed_rows, 'files': {n: {'path': 'metadata/' + n + paths[n].suffix, 'sha256': hashes[n]} for n in paths},
                'cache_dir': 'tooling-cache'}
    contract.update(workflow_identity())
    prerequisite.update(installed_image_id=controller.installed, installed_package_count=345,
                        baseline_source_commit=source, virtual_source_packet='PASS', tooling_audit='PASS')
    return prerequisite, contract, paths, blobs


class AcquisitionDeadline(ValueError):
    """Fixed acquisition timeout; no transport or source contents."""


def within(deadline):
    if time.monotonic() >= deadline:
        raise AcquisitionDeadline('tooling-acquisition-deadline')


@contextmanager
def acquisition_clock(*, deadline=None):
    """A wall-clock alarm also bounds slow headers and trickling buffered reads.

    Acquisition is sequential in the controller's main thread. Preserve an
    earlier enclosing job alarm and restore its remaining time afterward.
    """
    check_deadline(deadline)
    started = time.monotonic()
    if deadline is not None:
        require(signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, set()), 'stage-deadline-exceeded')
    previous = signal.getsignal(signal.SIGALRM)
    timer, interval = signal.getitimer(signal.ITIMER_REAL)
    end = min(started + ACQUISITION_SECONDS, deadline) if deadline is not None else started + ACQUISITION_SECONDS
    if deadline is not None and timer > 0:
        end = min(end, started + timer)
    budget = end - started
    enclosing = timer > 0 and timer <= budget
    fired = False
    def expired(signum, frame):
        nonlocal fired
        fired = True
        if enclosing:
            if callable(previous):
                previous(signum, frame)
            raise KeyboardInterrupt()
        check_deadline(deadline)
        raise AcquisitionDeadline('tooling-acquisition-deadline')
    try:
        signal.signal(signal.SIGALRM, expired)
        remaining = budget if deadline is None else end - time.monotonic()
        require(remaining > 0, 'stage-deadline-exceeded')
        signal.setitimer(signal.ITIMER_REAL, min(timer, remaining) if enclosing else remaining)
        yield end
    finally:
        original, errors = sys.exc_info()[1], []
        def restore(call):
            try:
                call()
            except BaseException as error:
                errors.append(error)
        restore(lambda: signal.setitimer(signal.ITIMER_REAL, 0))
        restore(lambda: signal.signal(signal.SIGALRM, previous))
        if timer > 0 and not (enclosing and fired):
            restore(lambda: signal.setitimer(signal.ITIMER_REAL, max(0.001, timer - (time.monotonic() - started)), interval))
        elif interval > 0:
            restore(lambda: signal.setitimer(signal.ITIMER_REAL, interval, interval))
        if deadline is not None:
            restore(lambda: check_deadline(deadline))
        if errors and original is None:
            raise errors[0]


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        require(urlsplit(url).scheme == 'https', 'tooling-insecure-redirect')
        return super().redirect_request(request, response, code, message, headers, url)


def open_tooling(url, timeout):
    return urllib.request.build_opener(HTTPSRedirect()).open(url, timeout=timeout)


def fetch_blob(row, cache, deadline, *, job_deadline=None):
    """Exact bounded public inputs; no native.fetch mutation or host trust work."""
    check_deadline(job_deadline)
    within(deadline)
    target = cache / row['filename']
    if target.exists() or target.is_symlink():
        data = read_regular(target, BLOB_LIMIT, **deadline_options(job_deadline))
        within(deadline)
        require(len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'tooling-cache-drift')
        return target
    descriptor, partial, stream = None, None, None
    try:
        if job_deadline is None:
            descriptor, name = tempfile.mkstemp(prefix=row['filename'] + '.', suffix='.partial', dir=cache)
            partial = Path(name)
        else:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
            try:
                check_deadline(job_deadline)
                within(deadline)
                descriptor, name = tempfile.mkstemp(prefix=row['filename'] + '.', suffix='.partial', dir=cache)
                partial = Path(name)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        checksum, size = hashlib.sha256(), 0
        check_deadline(job_deadline)
        within(deadline)
        timeout = READ_TIMEOUT if job_deadline is None else min(READ_TIMEOUT, deadline - time.monotonic())
        if job_deadline is None:
            stream = os.fdopen(descriptor, 'wb')
            descriptor = None
        else:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
            try:
                stream = os.fdopen(descriptor, 'wb')
                descriptor = None
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        source = None
        try:
            url = row['url']
            check_deadline(job_deadline)
            within(deadline)
            if job_deadline is not None:
                timeout = min(READ_TIMEOUT, min(deadline, job_deadline) - time.monotonic())
                require(timeout > 0, 'stage-deadline-exceeded')
            source = open_tooling(url, timeout=timeout)
            require(urlsplit(source.geturl()).scheme == 'https' and source.status == 200, 'tooling-origin-refused')
            length = source.headers.get('Content-Length')
            require(length is None or length == str(row['size']), 'tooling-size-differs')
            while True:
                check_deadline(job_deadline)
                within(deadline)
                # read1 returns after one buffered/socket read. The phase alarm
                # additionally covers HTTP header/chunk parsing and slow trickles.
                data = source.read1(min(65536, row['size'] + 1 - size))
                check_deadline(job_deadline)
                within(deadline)
                if not data:
                    break
                size += len(data)
                require(size <= row['size'], 'tooling-size-differs')
                stream.write(data); checksum.update(data)
        finally:
            original, errors = sys.exc_info()[1], []
            for resource in (source, stream):
                if resource is not None:
                    try:
                        resource.close()
                        if resource is stream:
                            stream = None
                    except BaseException as error:
                        errors.append(error)
            if errors and original is None:
                if not isinstance(errors[0], Exception):
                    raise errors[0]
                raise CleanupFailure() from errors[0]
        require(size == row['size'] and checksum.hexdigest() == row['sha256'], 'tooling-pin-differs')
        within(deadline)
        require(not target.exists() and not target.is_symlink(), 'tooling-cache-collision')
        partial.rename(target)
        return target
    finally:
        original, errors = sys.exc_info()[1], []
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                errors.append(error)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                errors.append(error)
        if partial is not None:
            try:
                partial.unlink(missing_ok=True)
            except BaseException as error:
                errors.append(error)
        if errors and original is None:
            if not isinstance(errors[0], Exception):
                raise errors[0]
            raise CleanupFailure() from errors[0]


def acquire(root, cache, inputs, blobs, receipts, *, deadline=None):
    # No executor shutdown can hold cancellation hostage to background reads.
    # Every planned input receives an outcome, including pending/cancelled ones.
    check_deadline(deadline)
    cancelled = False
    try:
        with acquisition_clock(**deadline_options(deadline)) as phase_end:
            require(cache.is_absolute() and '..' not in cache.parts and
                    all(stat.S_ISDIR(p.lstat().st_mode) for p in (cache, *cache.parents)), 'existing-safe-cache-required')
            for row in blobs:
                check_deadline(deadline)
                target = inputs / 'tooling-cache' / row['filename']
                existed = target.exists() or target.is_symlink()
                complete = False
                try:
                    check_deadline(deadline)
                    within(phase_end)
                    path = fetch_blob(row, cache, phase_end, **({} if deadline is None else {'job_deadline': deadline}))
                    within(phase_end)
                    result = copy_pinned(path, target, row['sha256'], BLOB_LIMIT, **deadline_options(deadline))
                    within(phase_end)
                    require(result['bytes'] == row['size'], 'tooling-size-differs')
                    receipts.append({'filename': row['filename'], 'status': 'PIN_MATCH', **result})
                    complete = True
                except AcquisitionDeadline:
                    receipts.append({'filename': row['filename'], 'status': 'FAIL', 'error_code': 'tooling-acquisition-deadline'})
                except Exception as error:
                    if isinstance(error, urllib.error.HTTPError):
                        try:
                            error.close()
                        except OSError:
                            pass
                    code = diagnostic(error, 'tooling-acquisition-failed')
                    record = {'filename': row['filename'], 'status': 'FAIL', 'error_code': code}
                    if isinstance(error, urllib.error.HTTPError) and type(error.code) is int and 100 <= error.code <= 599:
                        record['http_status'] = error.code
                    receipts.append(record)
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
    require(len(receipts) == 45 and all(r['status'] == 'PIN_MATCH' for r in receipts), 'tooling-acquisition-failed')


def public_paths(output):
    """Fixed retention allowlist, also usable after a raised cancellation."""
    paths = [output / 'adapter-status', *(output / 'virtual-public' / n for n in PUBLIC_DIRS)]
    return [str(p.absolute()) for p in paths if p.is_dir() and not p.is_symlink()]


def text_projection(exporter, source, target, selected, name=None, data=None, *, deadline=None):
    check_deadline(deadline)
    selected.mkdir(mode=0o700)
    # The generic exporter owns the complete content/private/control policy.
    data = read_regular(source, 8 * 1024**2, **deadline_options(deadline)) if data is None else data
    require(type(data) is bytes and len(data) <= 8 * 1024**2, 'regular-bounded-input-required')
    name = name or source.name
    (selected / name).write_bytes(data)
    check_deadline(deadline)
    require(not target.exists() and not target.is_symlink(), 'new-safe-output-required')
    published = []

    def verify(folder, result):
        require(read_regular(folder / 'export-manifest.json', **deadline_options(deadline)) ==
                (json.dumps(result, sort_keys=True, indent=2) + '\n').encode(), 'virtual-public-copy-drift')
        names = {'export-manifest.json'}
        if result.get('evidence_export') == 'PASS':
            names.add(name)
            require(result.get('accepted') == [{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]
                    and read_regular(folder / name, 8 * 1024**2, **deadline_options(deadline)) == data, 'virtual-public-copy-drift')
        else:
            require(result.get('accepted') == [], 'virtual-public-copy-drift')
        require({p.name for p in folder.iterdir()} == names, 'virtual-public-copy-drift')

    try:
        with tempfile.TemporaryDirectory(prefix='virtual-text-export-', dir=selected.parent) as temporary:
            staged = Path(temporary) / 'public'
            result = exporter.export_evidence(selected, staged)
            check_deadline(deadline)
            require(read_regular(selected / name, 8 * 1024**2, **deadline_options(deadline)) == data, 'virtual-public-copy-drift')
            verify(staged, result)
            identity = staged.stat()
            with defer_finalization() as cancelled:
                staged.rename(target)
                published.append((target, selected / 'invalid-public', (identity.st_dev, identity.st_ino)))
            if cancelled:
                raise KeyboardInterrupt()
            verify(target, result)
        return result.get('evidence_export') == 'PASS'
    except BaseException as error:
        try:
            retract_publications(published, isinstance(error, KeyboardInterrupt), **deadline_options(deadline))
        except BaseException:
            if deadline is None:
                raise
        raise


def captured_json(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate-json-field'); result[key] = value
        return result
    value = json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                       parse_constant=lambda _: require(False, 'nonfinite-json'))
    require(type(value) is dict, 'json-object-required')
    return value


def frame(path, row, stage, *, deadline=None):
    check_deadline(deadline)
    require(isinstance(row, dict) and row.get('filename') == stage + '.ppm' and
            isinstance(row.get('sha256'), str) and PIN.fullmatch(row['sha256']), 'frame-binding-refused')
    data = read_regular(path, 8 * 1024**2, **deadline_options(deadline))
    require(hashlib.sha256(data).hexdigest() == row['sha256'], 'frame-binding-refused')
    header = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s', data)
    require(header is not None, 'frame-format-refused')
    width, height = map(int, header.groups())
    body = data[header.end():]
    require(0 < width <= 1920 and 0 < height <= 1200 and len(body) == width * height * 3 and
            row.get('width') == width and row.get('height') == height and
            len({body[i:i + 3] for i in range(0, len(body), 3)}) >= 8, 'frame-content-refused')
    return data


def no_reported_config_error_text(value):
    """Accept only the two empty-text reply shapes; upstream error counts are lossy."""
    return type(value) is list and (value == [] or
           len(value) == 1 and type(value[0]) is str and value[0] == '')


def image_decode_order(events, decoder, nonce=None, *, required=False):
    """The observation follows minimal readiness and precedes any client query."""
    seen, raw, awaiting, ready, monitor = False, None, None, False, False
    essential = []
    ipc_argv = ['/usr/bin/hyprctl', '-j', 'configerrors']
    for row in events:
        kind = row['event']
        if awaiting is not None:
            require(kind == 'command' and row.get('argv') == ipc_argv and
                    all(row.get(field) == awaiting[field] for field in ('returncode', 'error', 'stdout', 'stderr')),
                    'guest-ipc-readiness-protocol-refused')
            ready = awaiting['stage'] == 'minimal'
            awaiting = None
        if kind == 'ipc_probe' and row['returncode'] == 0:
            try:
                accepted = row['error'] is None and row['stderr'] == '' and no_reported_config_error_text(json.loads(row['stdout']))
            except (ValueError, TypeError):
                accepted = False
            if accepted:
                awaiting = row
        if kind == 'command' and row.get('argv') == ['/usr/bin/hyprctl', '-j', 'monitors']:
            try:
                values = json.loads(row['stdout'])
                monitor = ready and row['returncode'] == 0 and row['error'] is None and type(values) is list and any(
                    type(m) is dict and type(m.get('width')) is int and m['width'] > 0 and
                    type(m.get('height')) is int and m['height'] > 0 for m in values)
            except (ValueError, TypeError):
                monitor = False
        if kind == 'image_decode_probe':
            require(ready, 'guest-ipc-readiness-protocol-refused')
            require(not seen and monitor and essential == [('boot', None), ('gbm_pass', None)],
                    'guest-image-decode-order-refused')
            try:
                raw = decoder.validate_event(row, nonce if nonce is not None else row['nonce'])
            except (ValueError, TypeError, KeyError):
                require(False, 'guest-image-decode-event-refused')
            seen = True
        elif kind == 'command' and row.get('argv') == ['/usr/bin/hyprctl', '-j', 'clients']:
            require(seen and raw is not None, 'guest-image-decode-order-refused')
        if kind not in ('command', 'session_log', 'ipc_probe', 'process_state', 'image_decode_probe'):
            essential.append((kind, row.get('stage')))
    require(not required or seen and raw is not None, 'guest-image-decode-event-refused')
    return raw


def process_diagnostic_order(events):
    """Failure observations require their actual IPC/monitor prefix; never grant success."""
    if not any(row['event'] == 'process_state' for row in events):
        return
    ipc = {stage: {'attempt': 0, 'elapsed': 0, 'ready': False, 'valid': True,
                   'correlated': False, 'monitor': False} for stage in ('minimal', 'overlay')}
    awaiting, observed, completed = None, None, set()
    before = None
    essential = []
    argv = ['/usr/bin/hyprctl', '-j', 'configerrors']
    for row in events:
        kind = row['event']
        correlated = False
        if observed is not None:
            stage, boundary = observed
            if kind == 'process_state':
                require(boundary == 'before_cleanup' and row['boundary'] == 'after_cleanup' and
                        row['stage'] == stage, 'guest-process-state-order-refused')
                for role in ('client', 'compositor'):
                    prior, later = before[role], row[role]
                    require(prior['state'] != 'exited' or later['state'] == 'unavailable' or
                            later['state'] == 'exited' and later['returncode'] == prior['returncode'],
                            'guest-process-state-order-refused')
                    require(prior['logging'] not in ('output_overflow', 'drain_error') or later['logging'] != 'ok',
                            'guest-process-state-order-refused')
                observed = (stage, 'after_cleanup')
            else:
                require(kind == 'guest_failed' or kind == 'session_log' and row['stage'] == stage,
                        'guest-process-state-order-refused')
                # A delivered after snapshot immediately follows before; a partial failure may omit it.
                observed = (stage, 'terminal')
            continue
        if awaiting is not None:
            stage, reply = awaiting
            match = kind == 'command' and row['argv'] == argv and type(row['returncode']) is int and \
                    all(row[field] == reply[field] for field in ('returncode', 'error', 'stdout', 'stderr'))
            ipc[stage]['correlated'] = match
            ipc[stage]['valid'] = ipc[stage]['valid'] and match
            correlated = match
            awaiting = None
        if kind == 'ipc_probe':
            state = ipc[row['stage']]
            prefix = [('boot', None), ('gbm_pass', None)]
            if row['stage'] == 'overlay':
                prefix += [('frame_ready', 'minimal'), ('phase_pass', 'minimal')]
            state['valid'] = state['valid'] and essential == prefix and not state['ready'] and \
                    row['attempt'] == state['attempt'] + 1 and state['elapsed'] <= row['elapsed_ms'] < 180000
            state['attempt'], state['elapsed'] = row['attempt'], row['elapsed_ms']
            if row['returncode'] == 6:
                state['valid'] = state['valid'] and row['error'] is None and row['stderr'] == '' and \
                        row['stdout'] == "Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n"
            else:
                try:
                    ready = row['returncode'] == 0 and row['error'] is None and row['stderr'] == '' and \
                            no_reported_config_error_text(json.loads(row['stdout']))
                except (ValueError, TypeError):
                    ready = False
                state['valid'] = state['valid'] and ready
                state['ready'] = ready
                awaiting = (row['stage'], row)
        elif kind == 'command' and row['argv'] == argv:
            require(correlated, 'guest-process-state-order-refused')
        elif kind == 'command' and row['argv'] == ['/usr/bin/hyprctl', '-j', 'monitors']:
            for state in ipc.values():
                if state['correlated'] and state['valid']:
                    try:
                        monitors = json.loads(row['stdout'])
                        positive = type(monitors) is list and any(type(m) is dict and
                                   type(m.get('width')) is int and m['width'] > 0 and
                                   type(m.get('height')) is int and m['height'] > 0 for m in monitors)
                    except (ValueError, TypeError):
                        positive = False
                    state['monitor'] = type(row['returncode']) is int and row['returncode'] == 0 and \
                            row['error'] is None and type(row['stderr']) is str and positive
        elif kind == 'phase_pass':
            require(row['stage'] in ('minimal', 'overlay'), 'guest-process-state-order-refused')
            completed.add(row['stage'])
        elif kind == 'guest_failed':
            require(False, 'guest-process-state-order-refused')
        elif kind == 'process_state':
            state = ipc[row['stage']]
            require(row['boundary'] == 'before_cleanup' and state['valid'] and state['ready'] and
                    state['correlated'] and state['monitor'] and row['stage'] not in completed and
                    (row['stage'] == 'minimal' or 'minimal' in completed),
                    'guest-process-state-order-refused')
            observed = (row['stage'], row['boundary'])
            before = row
        if kind not in ('command', 'session_log', 'ipc_probe', 'process_state', 'image_decode_probe'):
            essential.append((kind, row.get('stage')))


def read_events(path, policy, *, data=None, decoder=None, nonce=None, deadline=None):
    """Inspect the known encoded terminal records before any public copying."""
    check_deadline(deadline)
    data = read_regular(path, LIMIT, **deadline_options(deadline)) if data is None else data
    require(type(data) is bytes and len(data) <= LIMIT, 'bounded-guest-event-list-required')
    def unique(rows):
        result = {}
        for key, value in rows:
            check_deadline(deadline)
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
        'ipc_probe': {'event', 'stage', 'attempt', 'elapsed_ms', 'returncode', 'error', 'stdout', 'stderr'},
        'process_state': {'event', 'stage', 'boundary', 'client', 'compositor'},
        'session_log': {'event', 'stage', 'filename', 'sha256', 'base64'},
        'image_decode_probe': {'event', 'nonce', 'stage', 'elapsed_ms', 'returncode', 'error', 'report_sha256', 'report_base64'}}
    for event in events:
        check_deadline(deadline)
        require(isinstance(event.get('event'), str) and event['event'] in schemas and
                set(event) == schemas[event['event']], 'unknown-guest-event-fields-refused')
        if event['event'] == 'image_decode_probe':
            try:
                raw = (decoder or image_decoder(**deadline_options(deadline))).validate_event(event, nonce if nonce is not None else event['nonce'])
            except (ValueError, TypeError, KeyError):
                require(False, 'guest-image-decode-event-refused')
            require(raw is None or not policy.PRIVATE_CONTENT.search(raw.decode('ascii')), 'guest-image-decode-event-refused')
        if event['event'] == 'process_state':
            require(event['stage'] in ('minimal', 'overlay') and
                    event['boundary'] in ('before_cleanup', 'after_cleanup'), 'guest-process-state-event-refused')
            for role in ('client', 'compositor'):
                check_deadline(deadline)
                row = event[role]
                require(type(row) is dict and set(row) == {'state', 'returncode', 'logging'} and
                        row['state'] in ('alive', 'exited', 'unavailable') and
                        row['logging'] in ('ok', 'output_overflow', 'drain_error', 'unavailable') and
                        (row['state'] == 'exited' and type(row['returncode']) is int and -64 <= row['returncode'] <= 255 or
                         row['state'] in ('alive', 'unavailable') and row['returncode'] is None),
                        'guest-process-state-event-refused')
        if event['event'] == 'ipc_probe':
            require(event['stage'] in ('minimal', 'overlay') and
                    type(event['attempt']) is int and 1 <= event['attempt'] <= 24 and
                    type(event['elapsed_ms']) is int and 0 <= event['elapsed_ms'] <= 600000 and
                    type(event['returncode']) is int and -64 <= event['returncode'] <= 255 and
                    (event['error'] is None or type(event['error']) is str and
                     event['error'] in ('timeout', 'output overflow')) and
                    type(event['stdout']) is str and type(event['stderr']) is str and
                    len(event['stdout'].encode('utf-8')) + len(event['stderr'].encode('utf-8')) <= 1024**2,
                    'guest-ipc-probe-event-refused')
            for text in (event['stdout'], event['stderr']):
                check_deadline(deadline)
                normalized = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
                normalized = ''.join(c for c in normalized if ord(c) >= 32 or c in '\n\r\t')
                require(not policy.PRIVATE_CONTENT.search(text) and not policy.PRIVATE_CONTENT.search(normalized),
                        'private-guest-ipc-probe-refused')
        if event.get('event') == 'session_log':
            require(set(event) == {'event', 'stage', 'filename', 'sha256', 'base64'} and event['stage'] in ('minimal', 'overlay') and
                    event['filename'] in (event['stage'] + '.log', event['stage'] + '-client.log',
                                          event['stage'] + '-compositor.log') and
                    isinstance(event['sha256'], str) and PIN.fullmatch(event['sha256']) and isinstance(event['base64'], str),
                    'guest-session-log-event-refused')
            decoded = base64.b64decode(event['base64'], validate=True)
            require(len(decoded) <= 1024**2 and hashlib.sha256(decoded).hexdigest() == event['sha256'], 'guest-session-log-binding-refused')
            text = decoded.decode('utf-8', errors='replace')
            normalized = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
            normalized = ''.join(c for c in normalized if ord(c) >= 32 or c in '\n\r\t')
            require(not policy.PRIVATE_CONTENT.search(text) and not policy.PRIVATE_CONTENT.search(normalized),
                    'private-guest-session-log-refused')
    # Historical early failures remain diagnostic-only without a probe. Any new
    # probe is fully ordered, even when a later application failure is retained.
    if any(row['event'] == 'image_decode_probe' for row in events):
        image_decode_order(events, decoder or image_decoder(**deadline_options(deadline)), nonce)
    process_diagnostic_order(events)
    return events, hashlib.sha256(data).hexdigest()


def event_protocol(path, expected_sha256, nonce, policy, *, data=None, decoder=None, deadline=None):
    check_deadline(deadline)
    decoder = decoder or image_decoder(**deadline_options(deadline))
    events, actual_sha256 = read_events(path, policy, data=data, decoder=decoder, nonce=nonce, **deadline_options(deadline))
    require(actual_sha256 == expected_sha256, 'guest-events-binding-refused')
    require(len(events) >= 7, 'complete-guest-event-protocol-required')
    image_decode_order(events, decoder, nonce, required=True)
    essential = []
    ipc = {stage: {'attempt': 0, 'elapsed_ms': 0, 'ready': False, 'correlated': False}
           for stage in ('minimal', 'overlay')}
    ipc_argv = ['/usr/bin/hyprctl', '-j', 'configerrors']
    awaiting = None
    for event in events:
        check_deadline(deadline)
        require(isinstance(event, dict), 'guest-event-object-required')
        kind = event.get('event')
        require(kind in ('boot', 'gbm_pass', 'frame_ready', 'phase_pass', 'guest_pass', 'command', 'session_log', 'ipc_probe', 'image_decode_probe'),
                'guest-event-kind-refused')
        require('nonce' not in event or event['nonce'] == nonce, 'guest-event-nonce-refused')
        correlated = awaiting is not None
        if correlated:
            require(kind == 'command' and event['argv'] == ipc_argv and
                    type(event['returncode']) is int and
                    all(event[field] == awaiting[field] for field in ('returncode', 'error', 'stdout', 'stderr')),
                    'guest-ipc-readiness-protocol-refused')
            ipc[awaiting['stage']]['correlated'] = True
            awaiting = None
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
            require(ipc[event['stage']]['correlated'], 'guest-ipc-readiness-protocol-refused')
            require(any(isinstance(m, dict) and type(m.get('width')) is int and type(m.get('height')) is int and
                        m['width'] > 0 and m['height'] > 0 for m in event['monitors']) and
                    any(isinstance(c, dict) and c.get('mapped') is True and type(c.get('pid')) is int and c['pid'] > 0 and
                        isinstance(c.get('size'), list) and len(c['size']) == 2 and
                        all(type(n) is int and n > 0 for n in c['size']) for c in event['clients']), 'guest-session-frame-proof-refused')
        elif kind == 'phase_pass':
            require(set(event) == {'event', 'stage'} and event['stage'] in ('minimal', 'overlay'), 'guest-phase-event-refused')
            require(ipc[event['stage']]['correlated'], 'guest-ipc-readiness-protocol-refused')
        elif kind == 'guest_pass':
            require(set(event) == {'event', 'nonce', 'software_session', 'hardware_validation', 'graphics_acceleration'} and
                    event['nonce'] == nonce and event['software_session'] == 'PASS' and
                    event['hardware_validation'] == event['graphics_acceleration'] == 'NOT RUN', 'guest-completion-event-refused')
        elif kind == 'command':
            require(set(event) == {'event', 'argv', 'returncode', 'error', 'stdout', 'stderr'} and
                    isinstance(event['argv'], list) and event['argv'] and all(isinstance(a, str) for a in event['argv']) and
                    event['argv'][0] in ('/usr/bin/modprobe', '/usr/bin/udevadm', '/usr/bin/dmesg', '/usr/bin/pacman', '/usr/local/bin/gbm-probe', '/usr/bin/hyprctl') and
                    type(event['returncode']) is int and event['returncode'] == 0 and event['error'] is None and
                    isinstance(event['stdout'], str) and isinstance(event['stderr'], str), 'guest-command-event-refused')
            require(event['argv'] != ipc_argv or correlated, 'guest-ipc-readiness-protocol-refused')
        elif kind == 'ipc_probe':
            stage = event['stage']; state = ipc[stage]
            prefix = [('boot', None), ('gbm_pass', None)]
            if stage == 'overlay':
                prefix += [('frame_ready', 'minimal'), ('phase_pass', 'minimal')]
            require(essential == prefix and not state['ready'] and
                    event['attempt'] == state['attempt'] + 1 and
                    state['elapsed_ms'] <= event['elapsed_ms'] < 180000,
                    'guest-ipc-readiness-protocol-refused')
            state['attempt'], state['elapsed_ms'] = event['attempt'], event['elapsed_ms']
            if event['returncode'] == 6:
                require(event['error'] is None and event['stderr'] == '' and
                        event['stdout'] == "Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n",
                        'guest-ipc-readiness-protocol-refused')
            else:
                require(event['returncode'] == 0 and event['error'] is None and event['stderr'] == '',
                        'guest-ipc-readiness-protocol-refused')
                try:
                    ready = no_reported_config_error_text(json.loads(event['stdout']))
                except (ValueError, TypeError):
                    ready = False
                require(ready, 'guest-ipc-readiness-protocol-refused')
                state['ready'] = True
                awaiting = event
        if kind not in ('command', 'session_log', 'ipc_probe', 'image_decode_probe'):
            essential.append((kind, event.get('stage')))
    require(awaiting is None and all(row['correlated'] for row in ipc.values()),
            'guest-ipc-readiness-protocol-refused')
    require(essential == [('boot', None), ('gbm_pass', None), ('frame_ready', 'minimal'), ('phase_pass', 'minimal'),
                          ('frame_ready', 'overlay'), ('phase_pass', 'overlay'), ('guest_pass', None)],
            'guest-event-order-or-completeness-refused')


@contextmanager
def defer_finalization():
    events = []
    signals = {signal.SIGINT, signal.SIGTERM}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    previous = {}
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, lambda *_: events.append(True))
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield events
    finally:
        original, errors = sys.exc_info()[1], []
        def restore(call):
            try:
                call()
            except BaseException as error:
                errors.append(error)
        restore(lambda: signal.pthread_sigmask(signal.SIG_BLOCK, signals))
        for sig, handler in previous.items():
            restore(lambda sig=sig, handler=handler: signal.signal(sig, handler))
        try:
            pending = (signal.sigpending() & signals) - mask
        except BaseException as error:
            errors.append(error)
            pending = set()
        for sig in pending:
            try:
                signal.sigwait({sig})
                events.append(True)
            except BaseException as error:
                errors.append(error)
        restore(lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
        if errors and original is None:
            raise errors[0]


def remove_publication(path, deadline):
    check_deadline(deadline)
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        for child in path.iterdir():
            remove_publication(child, deadline)
        path.rmdir()
    check_deadline(deadline)


def retract_publications(publications, interrupted=False, *, deadline=None):
    """Quarantine every owned target before deletion; preserve cancellation and foreign paths."""
    quarantines, errors = [], []
    with defer_finalization() as cancelled:
        for target, quarantine, identity in publications:
            try:
                observed = target.lstat()
                require((observed.st_dev, observed.st_ino) == identity and
                        not quarantine.exists() and not quarantine.is_symlink(), 'virtual-public-copy-drift')
                target.rename(quarantine)
                quarantines.append(quarantine)
            except (OSError, ValueError):
                errors.append(True)
        for quarantine in quarantines:
            try:
                if deadline is None:
                    shutil.rmtree(quarantine)
                else:
                    remove_publication(quarantine, deadline)
            except (OSError, ValueError):
                errors.append(True)
    if interrupted or cancelled:
        raise KeyboardInterrupt() from None
    if errors and deadline is not None:
        raise CleanupFailure()
    require(not errors, 'virtual-public-copy-drift')


def capability_validator(root, pin, *, deadline=None):
    """Compile only the captured authenticated data validator, never owner imports."""
    check_deadline(deadline)
    source = Path(root) / 'scripts/virtual/run.py'
    raw = read_regular(source, LIMIT, **deadline_options(deadline))
    require(type(pin) is str and PIN.fullmatch(pin) and hashlib.sha256(raw).hexdigest() == pin,
            'qemu-capability-source-refused')
    constants = {'CAPABILITIES', 'CAPABILITY_LIMIT', 'CAPABILITY_REASONS'}
    namespace = {'require': require, 're': re}
    functions = []
    for node in ast.parse(raw.decode('utf-8')).body:
        check_deadline(deadline)
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in constants:
                require(name not in namespace, 'qemu-capability-source-refused')
                value = node.value
                if name == 'CAPABILITY_LIMIT' and isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult):
                    left, right = ast.literal_eval(value.left), ast.literal_eval(value.right)
                    require(type(left) is int and type(right) is int, 'qemu-capability-source-refused')
                    namespace[name] = left * right
                else:
                    namespace[name] = ast.literal_eval(value)
        elif isinstance(node, ast.FunctionDef) and node.name == 'capability_projection':
            require(not node.decorator_list and not node.args.defaults and not node.args.kw_defaults and
                    node.returns is None and not node.args.posonlyargs and not node.args.kwonlyargs and
                    node.args.vararg is None and node.args.kwarg is None and len(node.args.args) == 1 and
                    node.args.args[0].arg == 'rows' and node.args.args[0].annotation is None and
                    not getattr(node, 'type_params', []),
                    'qemu-capability-source-refused')
            functions.append(node)
    require(constants <= namespace.keys() and len(functions) == 1, 'qemu-capability-source-refused')
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), namespace)
    return namespace['capability_projection']


def capability_receipt(root, contract, receipt, *, deadline=None):
    """Check diagnostics before any public copy; partial observations never grant capture."""
    check_deadline(deadline)
    pair = {'qemu_capabilities', 'qemu_capabilities_sha256'}
    fields = pair & receipt.keys()
    guest = receipt.get('guest', {})
    require(type(guest) is dict and type(receipt.get('frames', {})) is dict, 'qemu-guest-claim-refused')
    claims = {'status': {'FAILED', 'NOT RUN', 'PASS', 'CAPTURED_REQUIRES_VISUAL_REVIEW'},
              'software_compositor': {'NOT RUN', 'PASS', 'REVIEW REQUIRED'},
              'software_session_ipc': {'NOT RUN', 'PASS'},
              'frame_proof': {'NOT RUN', 'PASS', 'REVIEW REQUIRED'}}
    for name, values in claims.items():
        check_deadline(deadline)
        require(name not in guest or type(guest[name]) is str and guest[name] in values,
                'qemu-guest-claim-refused')
    captured = receipt.get('status') in ('PASS', 'CAPTURED_REQUIRES_VISUAL_REVIEW') or bool(receipt.get('frames')) or \
               guest.get('status') in ('PASS', 'CAPTURED_REQUIRES_VISUAL_REVIEW') or \
               any(guest.get(name) in ('PASS', 'REVIEW REQUIRED') for name in
                   ('software_compositor', 'software_session_ipc', 'frame_proof'))
    require(not fields or fields == pair, 'qemu-capability-binding-refused')
    if not fields:
        require(not captured, 'qemu-capability-success-required')
        return None
    rows, pin = receipt['qemu_capabilities'], receipt['qemu_capabilities_sha256']
    require(type(pin) is str and PIN.fullmatch(pin), 'qemu-capability-binding-refused')
    validate = capability_validator(root, contract['core_sha256']['run.py'], **deadline_options(deadline))
    try:
        projected = validate(rows)
    except (ValueError, TypeError, KeyError, IndexError):
        raise ValueError('qemu-capability-record-refused') from None
    require(projected == rows and hashlib.sha256((json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()).hexdigest() == pin,
            'qemu-capability-binding-refused')
    require(not captured or len(rows) == 4 and all(row['status'] == 'PASS' for row in rows),
            'qemu-capability-success-required')
    return projected


def image_decode_binding(contract, receipt, events, decoder):
    """Derive context from selected controller authority, never producer context."""
    require(all(type(contract.get(key)) is str and re.fullmatch(r'[1-9][0-9]{0,' + str(maximum - 1) + '}', contract[key]) and
                receipt.get(key) == contract[key] for key, maximum in (('run_id', 20), ('run_attempt', 10))),
            'guest-image-decode-binding-refused')
    attempts = [row for row in events if row['event'] == 'image_decode_probe']
    require(len(attempts) <= 1, 'guest-image-decode-order-refused')
    preparation = receipt.get('image_decode_preparation')
    observation = receipt.get('image_decode_observation')
    if preparation is None:
        require(not attempts and observation is None, 'guest-image-decode-binding-refused')
        return
    keys = {'schema_version', 'helper_sha256', 'guest_image_sha256', 'package_inventory_sha256',
            'asset_sha256', 'guest_contract_sha256', 'prepare_receipt_sha256'}
    require(type(preparation) is dict and set(preparation) == keys and type(preparation['schema_version']) is int and
            preparation['schema_version'] == 1 and all(type(preparation[key]) is str and PIN.fullmatch(preparation[key])
            for key in keys - {'schema_version'}) and preparation['asset_sha256'] == decoder.ASSET_SHA256 and
            preparation['prepare_receipt_sha256'] == receipt.get('prepare_receipt_sha256'),
            'guest-image-decode-binding-refused')
    tooling = receipt.get('stages', {}).get('tooling', {})
    guest = receipt.get('guest', {})
    require(type(tooling.get('image_id')) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', tooling['image_id']) and
            tooling.get('package_inventory_sha256') == preparation['package_inventory_sha256'] and
            ('prepare_receipt_sha256' not in guest or guest['prepare_receipt_sha256'] == preparation['prepare_receipt_sha256']),
            'guest-image-decode-binding-refused')
    if attempts:
        nonce = guest.get('nonce')
        require(type(nonce) is str and re.fullmatch(r'[0-9a-f]{32}', nonce), 'guest-image-decode-binding-refused')
        image_decode_order(events, decoder, nonce)
    if not attempts or attempts[0]['error'] is not None:
        require(observation is None, 'guest-image-decode-binding-refused')
        return
    raw = image_decode_order(events, decoder, nonce)
    expected = {'source_sha256': contract['core_sha256']['image_decode_probe.c'],
                'image_sha256': preparation['guest_image_sha256'], 'tooling_sha256': tooling['image_id'][7:],
                'guest_sha256': contract['core_sha256']['guest.py'], 'helper_sha256': preparation['helper_sha256'],
                'runtime_sha256': contract['core_sha256']['common.py'],
                'package_inventory_sha256': preparation['package_inventory_sha256'],
                'asset_sha256': preparation['asset_sha256'], 'run_id': contract['run_id'], 'run_attempt': contract['run_attempt']}
    require(type(observation) is dict and set(observation) == {'binding', 'observation'}, 'guest-image-decode-binding-refused')
    try:
        validated = decoder.parse_bound_report(raw, observation['binding'], expected,
                    expected_report_sha256=attempts[0]['report_sha256'])
    except (ValueError, TypeError, KeyError):
        require(False, 'guest-image-decode-binding-refused')
    require(validated == observation, 'guest-image-decode-binding-refused')


def receive(root, output, contract, code, result, *, deadline=None):
    check_deadline(deadline)
    owner = output / 'owner-public'
    receipt_bytes = read_regular(owner / 'result.json', 8 * 1024**2, **deadline_options(deadline))
    receipt = captured_json(receipt_bytes)
    cleanup = receipt.get('cleanup')
    cleanup_ok = isinstance(cleanup, list) and bool(cleanup) and all(isinstance(r, dict) and
                 r.get('status') == 'PASS' and r.get('absence_verified') is True and
                 not r.get('commit_outcome_uncertain', False) for r in cleanup)
    result['owner_cleanup'] = {'status': 'PASS' if cleanup_ok else 'FAIL',
                              'records': len(cleanup) if isinstance(cleanup, list) else 0,
                              'private_workspace_cleanup': 'PASS' if receipt.get('private_workspace_cleanup') == 'PASS' else 'FAIL'}
    capabilities = capability_receipt(root, contract, receipt, **deadline_options(deadline))
    require(receipt.get('schema_version') == 1 and receipt.get('purpose') == 'bounded-generic-arm-software-proof' and
            receipt.get('source_commit') == contract['source_commit'] and receipt.get('baseline_image') == contract['installed_image_id']
            and receipt.get('controller_contract_sha256') == digest(output / 'inputs/controller-contract.json', **deadline_options(deadline)) and
            receipt.get('source_sha256') == contract['core_sha256'] | {'controller.py': contract['controller_sha256'],
                'audit_tooling.py': contract['audit_tooling_sha256']} and receipt.get('inputs') == contract['files'], 'virtual-owner-binding-refused')
    decoder = image_decoder(root, contract['core_sha256']['image_decode_report.py'], **deadline_options(deadline))
    exporter = load_module(root / 'scripts/ci/integration_export.py', 'development_virtual_exporter', **deadline_options(deadline))
    event_file = owner / 'guest-events.json'
    event_bytes, event_sha256, events = None, None, []
    if event_file.exists() or event_file.is_symlink():
        event_bytes = read_regular(event_file, LIMIT, **deadline_options(deadline))
        events, event_sha256 = read_events(event_file, exporter, data=event_bytes, decoder=decoder,
                                         nonce=receipt.get('guest', {}).get('nonce'), **deadline_options(deadline))
        require(not any(event['event'] in ('boot', 'gbm_pass', 'frame_ready', 'phase_pass', 'guest_pass') for event in events)
                or capabilities is not None and len(capabilities) == 4 and
                all(row['status'] == 'PASS' for row in capabilities), 'qemu-capability-success-required')
    image_decode_binding(contract, receipt, events, decoder)
    public = output / 'virtual-public'; public.mkdir(mode=0o700, exist_ok=True)
    selected = output / 'selected'; selected.mkdir(mode=0o700, exist_ok=True)
    good = True
    for directory, name in PUBLIC_FILES.items():
        check_deadline(deadline)
        if directory == 'events':
            continue
        source = owner / name
        if directory == 'result' or source.exists() or source.is_symlink():
            try:
                good = text_projection(exporter, source, public / directory, selected / directory,
                                       data=receipt_bytes if directory == 'result' else None, **deadline_options(deadline)) and good
            except Exception:
                good = False
    launch = output / 'private-launcher.log'
    if launch.exists():
        try:
            good = text_projection(exporter, launch, public / 'launcher', selected / 'launcher', 'launcher.log', **deadline_options(deadline)) and good
        except Exception:
            good = False
    if event_bytes is not None:
        try:
            good = text_projection(exporter, event_file, public / 'events', selected / 'events', data=event_bytes, **deadline_options(deadline)) and good
        except Exception:
            good = False
    require(good, 'virtual-public-export-refused')
    require(code == 0 and receipt.get('status') == 'CAPTURED_REQUIRES_VISUAL_REVIEW' and cleanup_ok and
            receipt.get('private_workspace_cleanup') == 'PASS', 'virtual-owner-acceptance-failed')
    require(set(receipt.get('frames', {})) == {'minimal', 'overlay'} and
            event_sha256 == receipt.get('guest_events_sha256') and
            (public / 'events/export-manifest.json').is_file() and (public / 'result/export-manifest.json').is_file(),
            'virtual-capture-evidence-required')
    require(receipt.get('stages', {}).get('tooling', {}).get('status') == 'READY' and
            receipt['stages']['tooling'].get('package_count') == 366 and
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
    event_protocol(owner / 'guest-events.json', receipt['guest_events_sha256'], nonce, exporter, data=event_bytes, decoder=decoder, **deadline_options(deadline))
    # Binary publication requires the complete accepted capture binding. Text
    # failure diagnostics remain independently subject to the generic filter.
    frames = {stage: frame(owner / (stage + '.ppm'), receipt['frames'][stage], stage, **deadline_options(deadline))
              for stage in ('minimal', 'overlay')}
    published_frames = []
    try:
        for stage, data in frames.items():
            check_deadline(deadline)
            row = receipt['frames'][stage]
            folder = selected / (stage + '-frame'); folder.mkdir(mode=0o700)
            (folder / (stage + '.ppm')).write_bytes(data)
            binding = {'filename': stage + '.ppm', 'sha256': hashlib.sha256(data).hexdigest(),
                 'bytes': len(data), 'width': row['width'], 'height': row['height'], 'visual_review': 'NOT RUN'}
            binding_bytes = (json.dumps(binding, sort_keys=True, indent=2) + '\n').encode()
            save(folder / 'receipt.json', binding, **deadline_options(deadline))
            def verify_frame(path):
                require(read_regular(path / (stage + '.ppm'), 8 * 1024**2, **deadline_options(deadline)) == data and
                        read_regular(path / 'receipt.json', **deadline_options(deadline)) == binding_bytes and
                        {p.name for p in path.iterdir()} == {stage + '.ppm', 'receipt.json'}, 'frame-copy-drift')
            verify_frame(folder)
            identity = folder.stat()
            target = public / (stage + '-frame')
            with defer_finalization() as cancelled:
                folder.rename(target)
                published_frames.append((target, selected / (target.name + '-failed'), (identity.st_dev, identity.st_ino)))
            if cancelled:
                raise KeyboardInterrupt()
            verify_frame(target)
    except BaseException as error:
        try:
            retract_publications(published_frames, isinstance(error, KeyboardInterrupt), **deadline_options(deadline))
        except BaseException:
            if deadline is None:
                raise
        raise
    check_deadline(deadline)
    result.update(status='PASS', owner_status='CAPTURED_REQUIRES_VISUAL_REVIEW', visual_review='REQUIRED')


def finalize_virtual(root, output, status, result, acquisitions, contract, launched,
                     acquisition_started, first_failure, deadline):
    """Attempt each finite retention step without renewing the caller's deadline."""
    errors = []
    def attempt(call):
        try:
            call()
        except BaseException as error:
            errors.append(error)
            result.update(status='FAIL', finalization_failed=True,
                          finalization_error_code=diagnostic(errors[0], 'virtual-stage-failed'))
            if first_failure is None:
                result.setdefault('error_code', result['finalization_error_code'])
    def retain():
        with defer_finalization() as events:
            attempt(lambda: check_deadline(deadline))
            if launched and result['status'] != 'PASS' and not (output / 'virtual-public').exists():
                attempt(lambda: receive(root, output, contract, None, result, deadline=deadline))
            if events and first_failure is None:
                result.update(status='FAIL', error_code='cancelled')
            result['public'] = public_paths(output)
            attempt(lambda: save(status / 'acquisition.json', {
                'status': 'PIN_MATCH' if len(acquisitions) == 45 and
                    all(r['status'] == 'PIN_MATCH' for r in acquisitions) else 'NOT COMPLETE',
                'inputs': acquisitions, 'execution': 'ATTEMPTED' if acquisition_started else 'NOT RUN',
                'planned_inputs': 45 if contract is not None else 0,
                'signature_authentication': 'Owner performs trust and signature verification inside its isolated container'}, deadline=deadline))
            attempt(lambda: save(status / 'result.json', {k:v for k,v in result.items() if k != 'public'}, deadline=deadline))
            if events:
                if first_failure is None:
                    result.update(status='FAIL', error_code='cancelled')
                attempt(lambda: save(status / 'result.json', {k:v for k,v in result.items() if k != 'public'}, deadline=deadline))
                if first_failure is None:
                    raise KeyboardInterrupt()
    attempt(retain)
    attempt(lambda: check_deadline(deadline))
    if first_failure is None:
        control = next((e for e in errors if not isinstance(e, Exception)), None)
        if control is not None:
            raise control


def run_virtual(controller, root, output, cache, *, deadline=None):
    check_deadline(deadline)
    root, output, cache = map(lambda p: Path(p).absolute(), (root, output, cache))
    require('..' not in output.parts and not output.exists() and not output.is_symlink() and
            all(not p.is_symlink() for p in output.parents), 'new-safe-output-required')
    for other in (root, Path(controller.native_out).absolute(), Path(controller.work).absolute(), cache):
        check_deadline(deadline)
        require(not output.is_relative_to(other) and not other.is_relative_to(output), 'output-boundary-overlap')
    output.mkdir(mode=0o700, parents=True)
    status = output / 'adapter-status'; status.mkdir(mode=0o700)
    result = {'status': 'NOT RUN', 'phase': 'preflight', 'prerequisite': {}, 'public': [], 'hardware_validation': 'NOT RUN',
              'performance_acceptance': 'NOT RUN', 'visual_review': 'NOT RUN', 'selected_for_release': False}
    acquisitions, contract, launched, acquisition_started = [], None, False, False
    first_failure = None
    try:
        if not getattr(controller, 'virtual_packet_sha256', None):
            result['error_code'] = 'virtual-source-packet-not-accepted'
            return result
        result['prerequisite'], contract, paths, blobs = preflight(controller, root, **deadline_options(deadline))
        result.update(status='FAIL', phase='input-copy')
        inputs = output / 'inputs'; inputs.mkdir(mode=0o700)
        for alias, path in paths.items():
            check_deadline(deadline)
            item = contract['files'][alias]
            copy_pinned(path, inputs / item['path'], item['sha256'], **deadline_options(deadline))
        for row in contract['baseline']:
            check_deadline(deadline)
            copy_pinned(Path(controller.work) / 'archive-inputs' / row['archive'], inputs / row['archive'], row['sha256'], BLOB_LIMIT, **deadline_options(deadline))
        result['phase'] = 'acquisition'
        acquisition_started = True
        acquire(root, cache, inputs, blobs, acquisitions, **deadline_options(deadline))
        save(inputs / 'controller-contract.json', contract, **deadline_options(deadline))
        result['phase'] = 'owner-execution'
        launched = True
        code = command([sys.executable, '-B', root / 'scripts/virtual/controller.py', '--contract',
                        inputs / 'controller-contract.json', '--contract-sha256', digest(inputs / 'controller-contract.json', **deadline_options(deadline)),
                        '--output', output / 'owner-public'], output / 'private-launcher.log', OWNER_TIMEOUT, **deadline_options(deadline))
        result['phase'] = 'owner-receive'
        receive(root, output, contract, code, result, **deadline_options(deadline))
        result['phase'] = 'complete'
    except KeyboardInterrupt as error:
        first_failure = error
        result.update(status='FAIL', error_code='cancelled')
        raise
    except Exception as error:
        first_failure = error
        result['error_code'] = diagnostic(error, 'virtual-prerequisite-refused' if result['status'] == 'NOT RUN' else 'virtual-stage-failed')
    finally:
        if deadline is not None:
            finalize_virtual(root, output, status, result, acquisitions, contract, launched,
                             acquisition_started, first_failure, deadline)
        else:
            try:
                # Defer repeated TERM/INT while cleanup and status evidence is sealed.
                with defer_finalization() as events:
                    if launched and result['status'] != 'PASS' and not (output / 'virtual-public').exists():
                        try:
                            receive(root, output, contract, None, result, **deadline_options(deadline))
                        except KeyboardInterrupt:
                            events.append(True)
                        except Exception:
                            pass
                    if events:
                        result.update(status='FAIL', error_code='cancelled')
                    result['public'] = public_paths(output)
                    save(status / 'acquisition.json', {'status': 'PIN_MATCH' if len(acquisitions) == 45 and
                         all(r['status'] == 'PIN_MATCH' for r in acquisitions) else 'NOT COMPLETE', 'inputs': acquisitions,
                         'execution': 'ATTEMPTED' if acquisition_started else 'NOT RUN', 'planned_inputs': 45 if contract is not None else 0,
                         'signature_authentication': 'Owner performs trust and signature verification inside its isolated container'}, **deadline_options(deadline))
                    if events:
                        result.update(status='FAIL', error_code='cancelled')
                    save(status / 'result.json', {k: v for k, v in result.items() if k != 'public'}, **deadline_options(deadline))
                    if events:
                        result.update(status='FAIL', error_code='cancelled')
                        save(status / 'result.json', {k: v for k, v in result.items() if k != 'public'}, **deadline_options(deadline))
                if events:
                    raise KeyboardInterrupt()
            except KeyboardInterrupt:
                # A restored Python handler can interrupt the context's final unmask.
                with defer_finalization():
                    result.update(status='FAIL', error_code='cancelled')
                    result['public'] = public_paths(output)
                    save(status / 'result.json', {k: v for k, v in result.items() if k != 'public'}, **deadline_options(deadline))
                raise
    return result
