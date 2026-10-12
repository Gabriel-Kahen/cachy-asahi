# SPDX-License-Identifier: MIT
"""Scoped Docker proxy for unchanged native producer/build subprocess CLIs.

The parent supplies an accepted per-operation captured-ELF/socket/daemon backend.
No Docker subprocess is launched here. A serial main-thread RPC service delegates
only the finite original CLI grammar. Legacy build cache/intermediate resources
are NOT absence-verifiable by this interface and are an explicit acceptance limit.
"""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import threading
import time

REQUEST_LIMIT = 65536
RESPONSE_LIMIT = 8 * 1024**2
JOURNAL_LIMIT = 8 * 1024**2
LABEL = 'org.cachy-asahi.ksm-job'
CONTEXT_LABEL = 'org.cachy-asahi.ksm-context'
IMAGE_LABEL = 'org.cachy-asahi.ksm-image'
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
CID = re.compile(r'[0-9a-f]{64}\Z')
ORIGINALS = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
             'cachy-asahi-zsh-config', 'cachy-asahi-setup'}


class Cancelled(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def argv_check(argv):
    need(type(argv) is list and 0 < len(argv) <= 128 and all(type(x) is str and x and '\0' not in x
         and len(x) <= 8192 for x in argv), 'bounded-argv-required')
    need(len(json.dumps(argv).encode()) <= REQUEST_LIMIT, 'argv-byte-bound')


def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute-nofollow-directory-required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def node(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def parse_options(tokens, valued, flags, repeat=()):
    result, index = {}, 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith('--'):
            return result, tokens[index:]
        key, equal, value = token.partition('=')
        need(key in valued or key in flags, 'unsupported-docker-option')
        if key in flags:
            need(not equal, 'flag-value-refused')
            value = True
        elif not equal:
            index += 1
            need(index < len(tokens), 'missing-option-value')
            value = tokens[index]
        need(key not in result or key in repeat, 'duplicate-docker-option')
        result.setdefault(key, []).append(value)
        index += 1
    return result, []


def image_absence_outputs(image):
    """Finite exact CLI folded forms: diagnostic and optional standalone []."""
    need(type(image) is str and IMAGE.fullmatch(image), 'bound-absence-image-required')
    outputs = set()
    for separator in ('', ' '):
        diagnostic = ('Error response from daemon: No such image:' + separator + image).encode()
        for form in (diagnostic, b'[]\n' + diagnostic, diagnostic + b'\n[]'):
            outputs.update((form, form + b'\n'))
    return outputs


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def baseline_json(data):
    need(type(data) is bytes and len(data) <= 128 * 1024, 'baseline-inspection-bound')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'baseline-duplicate-field')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs,
                       parse_constant=lambda _: need(False, 'baseline-nonfinite-json'))
    nodes = 0
    def visit(item, depth=0):
        nonlocal nodes
        nodes += 1
        need(nodes <= 8192 and depth <= 16, 'baseline-json-bound')
        if type(item) is dict:
            for key, child in item.items(): visit(key, depth + 1); visit(child, depth + 1)
        elif type(item) is list:
            for child in item: visit(child, depth + 1)
        elif type(item) is str:
            need(len(item.encode()) <= 65536, 'baseline-json-string-bound')
        else:
            need(item is None or type(item) in (bool, int, float), 'baseline-json-type')
    visit(value); canonical(value)
    return value


class Baseline:
    """Private positive image/reference observations; inventory grants no ownership.

    The backend checks actual captured CLI/socket/daemon identity around each call.
    All observations are quiescent: no container is tolerated. New image IDs are
    unowned and unverified, including the legacy builder's internal cache.
    """
    STAGES = frozenset({'before_producer', 'after_producer', 'after_build_1', 'after_build_2',
        'before_lifecycle', 'after_lifecycle', 'before_cleanup', 'after_cleanup',
        'before-build', 'after-build', 'before-run', 'after-run',
        'before-image-removal', 'after-image-removal'})

    def __init__(self, backend, private, binding, nonce, *, deadline=None, cancelled=lambda: False,
                 clock=time.monotonic, on_inventory=None):
        need(type(binding) is dict and set(binding) == {'source_commit', 'packet_sha256', 'run_id',
             'run_attempt', 'uid', 'gid'}, 'baseline-job-binding-required')
        need(type(binding['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', binding['source_commit']) and
             type(binding['packet_sha256']) is str and re.fullmatch('[0-9a-f]{64}', binding['packet_sha256']) and
             all(type(binding[k]) is str and re.fullmatch('[1-9][0-9]{0,19}', binding[k]) for k in ('run_id', 'run_attempt')) and
             type(binding['uid']) is type(binding['gid']) is int and
             binding['uid'] == os.getuid() == os.geteuid() and 0 < binding['uid'] <= 65535 and
             binding['gid'] == os.getgid() == os.getegid() and 0 < binding['gid'] <= 65535 and
             type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'baseline-actual-job-required')
        need(backend.endpoint in {'unix:///run/docker.sock', 'unix:///var/run/docker.sock'} and
             type(backend.expected) is str and re.fullmatch('[A-Za-z0-9:-]{8,128}', backend.expected) and
             type(backend.cli_sha256) is str and re.fullmatch('[0-9a-f]{64}', backend.cli_sha256) and
             2 <= len(backend.socket_identity) <= 16 and all(type(x) is int and x >= 0 for x in backend.socket_identity) and
             backend.socket_identity[1] > 0,
             'baseline-captured-backend-required')
        self.backend, self.private, self.binding, self.nonce = backend, Path(private), dict(binding), nonce
        self.clock, self.cancelled, self.deadline = clock, cancelled, clock() + 8460 if deadline is None else deadline
        need(type(self.deadline) in (int, float) and math.isfinite(self.deadline), 'baseline-finite-deadline')
        self.operation_deadline, self.on_inventory = None, on_inventory
        self.pins = (backend.endpoint, backend.expected, backend.cli_sha256, tuple(backend.socket_identity))
        self.path = self.private / 'daemon-baseline.jsonl'
        self.fd, self.parent = None, None
        self.ready, self.failed, self.rows, self.data = False, False, None, b''
        self.ids, self.observations, self.last = frozenset(), 0, None
        self.initial_counts, self.unknown_count = {}, None
        self.preservation, self.observation_mode = 'UNVERIFIED', None
        self.thread = threading.get_ident()

    def check(self, cleanup=False):
        need(threading.get_ident() == self.thread and self.clock() < self.deadline,
             'baseline-thread-or-deadline')
        if self.operation_deadline is not None:
            need(type(self.operation_deadline) in (int, float) and math.isfinite(self.operation_deadline) and
                 self.clock() < self.operation_deadline, 'baseline-phase-deadline')
        cancelled = self.cancelled(); need(type(cancelled) is bool, 'baseline-boolean-cancellation')
        if cancelled and not cleanup: raise Cancelled('baseline-cancelled')
        need((self.backend.endpoint, self.backend.expected, self.backend.cli_sha256,
              tuple(self.backend.socket_identity)) == self.pins, 'baseline-backend-binding-drift')

    def call(self, args, cleanup=False):
        self.check(cleanup)
        end = min(self.deadline, self.operation_deadline or self.deadline)
        result = self.backend.call(['docker', '--host=' + self.backend.endpoint, *args],
                                   timeout=min(30, end - self.clock()))
        self.check(cleanup)
        need(isinstance(result, subprocess.CompletedProcess) and type(result.returncode) is int and
             type(result.stdout) is bytes and len(result.stdout) <= 128 * 1024 and result.stderr in (None, b''),
             'baseline-bounded-backend-response')
        return result

    def inventory(self, kind, cleanup=False, initial=False):
        result = self.call([kind, 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'], cleanup)
        if initial and self.on_inventory is not None: self.on_inventory(kind, result)
        need(result.returncode == 0, 'baseline-inventory-query')
        values = result.stdout.decode('ascii').splitlines()
        pattern = IMAGE if kind == 'image' else CID
        need(len(values) <= 256 and all(pattern.fullmatch(value) for value in values), 'baseline-inventory-bound')
        return frozenset(values)

    def image(self, target, cleanup=False):
        result = self.call(['image', 'inspect', target], cleanup)
        need(result.returncode == 0, 'baseline-image-query')
        rows = baseline_json(result.stdout)
        need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'baseline-one-image-required')
        return rows[0]

    def projection(self, cleanup=False, initial=False):
        if cleanup:
            need(self.ready, 'baseline-cleanup-requires-protected-set')
            images = self.ids
        else:
            containers = self.inventory('container', False, initial)
            if initial: self.initial_counts['container'] = len(containers)
            need(not containers, 'baseline-containers-present')
            images = self.inventory('image', False, initial)
            if initial: self.initial_counts['image'] = len(images)
            need(not self.ready or self.ids <= images, 'baseline-image-missing')
        selected, rows, references, total = (self.ids if self.ready else images), [], {}, 2
        for image in sorted(selected):
            row = self.image(image, cleanup)
            required = {'Id', 'Architecture', 'Os', 'Config', 'RootFS', 'Size', 'RepoTags', 'RepoDigests'}
            need(required <= set(row) and row['Id'] == image and
                 all(type(row[k]) is str and 0 < len(row[k].encode()) <= 64 for k in ('Architecture', 'Os')) and
                 type(row['Size']) is int and 0 <= row['Size'] <= 2**60 and
                 (row['Config'] is None or type(row['Config']) is dict), 'baseline-image-metadata')
            refs = {}
            for key in ('RepoTags', 'RepoDigests'):
                values = [] if row[key] is None else row[key]
                need(type(values) is list and len(values) <= 256 and all(type(v) is str and
                     0 < len(v.encode()) <= 512 and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._/:@+-]*', v) for v in values) and
                     len(set(values)) == len(values), 'baseline-reference-bound')
                refs[key] = sorted(values)
                for ref in values:
                    need(ref not in references or references[ref] == image, 'baseline-reference-collision')
                    references[ref] = image
                need(len(references) <= 256, 'baseline-reference-total-bound')
            rootfs, parent = row['RootFS'], row.get('Parent')
            if parent == '': parent = None
            need(type(rootfs) is dict and set(rootfs) <= {'Type', 'Layers'} and type(rootfs.get('Type')) is str and
                 0 < len(rootfs['Type'].encode()) <= 64 and type(rootfs.get('Layers', [])) is list and
                 len(rootfs.get('Layers', [])) <= 256 and all(type(v) is str and IMAGE.fullmatch(v) for v in rootfs.get('Layers', [])) and
                 (parent is None or type(parent) is str and IMAGE.fullmatch(parent)), 'baseline-rootfs-or-parent')
            projected = {key: row[key] for key in ('Id', 'Architecture', 'Os', 'Config', 'Size')}
            projected.update(refs, RootFS={'Type': rootfs['Type'], 'Layers': rootfs.get('Layers', [])}, Parent=parent)
            total += len(canonical(projected)) + bool(rows)
            need(total <= 4 * 1024**2, 'baseline-projection-byte-bound')
            rows.append(projected)
        if not cleanup:
            for reference, image in sorted(references.items()):
                need(self.image(reference).get('Id') == image, 'baseline-reference-rebound')
        return rows, images

    def capture(self, cleanup=False, initial=False):
        first, ids = self.projection(cleanup, initial)
        second, final = self.projection(cleanup)
        need(first == second and ids == final, 'baseline-capture-drift')
        return first, ids

    def verify(self):
        self.check(True)
        need(self.fd is not None and self.parent is not None, 'baseline-receipt-required')
        parent = directory(self.private)
        try:
            parent_info = os.fstat(parent)
            need(node(parent_info) == self.parent_identity and parent_info.st_uid == self.binding['uid'] and
                 parent_info.st_gid == self.binding['gid'] and stat.S_IMODE(parent_info.st_mode) == 0o700 and
                 node(os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)) == self.file_identity,
                 'baseline-receipt-namespace-drift')
        finally: os.close(parent)
        info = os.fstat(self.fd)
        captured = os.pread(self.fd, len(self.data) + 1, 0)
        after = os.fstat(self.fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(node(info) == self.file_identity and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             info.st_uid == self.binding['uid'] and info.st_gid == self.binding['gid'] and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(self.data) and
             all(getattr(info, k) == getattr(after, k) for k in fields) and captured == self.data and
             node(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)) == self.file_identity,
             'baseline-receipt-drift')

    def append(self, row):
        data = canonical(row) + b'\n'
        need(len(self.data) + len(data) <= JOURNAL_LIMIT and self.observations <= 64, 'baseline-receipt-bound')
        if self.data: self.verify()
        view = memoryview(data)
        while view:
            count = os.write(self.fd, view); need(count > 0, 'baseline-receipt-write'); view = view[count:]
        os.fsync(self.fd); self.data += data
        self.verify()

    def start(self):
        need(not self.ready and not self.failed and self.fd is None, 'baseline-already-started-or-failed')
        try:
            rows, images = self.capture(initial=True)
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                self.parent = directory(self.private)
                info = os.fstat(self.parent)
                need(info.st_uid == self.binding['uid'] and info.st_gid == self.binding['gid'] and
                     stat.S_IMODE(info.st_mode) == 0o700, 'baseline-private-parent-required')
                self.parent_identity = node(info)
                self.fd = os.open(self.path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=self.parent)
                os.fchmod(self.fd, 0o600); self.file_identity = node(os.fstat(self.fd))
            finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            self.rows, self.ids = canonical(rows), images
            self.identity_sha256 = hashlib.sha256(self.rows).hexdigest()
            self.append({'schema_version': 1, 'kind': 'protected-daemon-image-baseline', **self.binding,
                         'nonce': self.nonce, 'docker_endpoint': self.pins[0], 'daemon_id': self.pins[1],
                         'docker_sha256': self.pins[2], 'docker_socket_identity': list(self.pins[3]),
                         'containers': [], 'images': rows, 'identity_sha256': self.identity_sha256})
            os.fsync(self.parent); self.ready = True
            self.observe('before_producer')
            return self.summary()
        except BaseException:
            self.failed = True; self.close(); raise

    def protected(self):
        need(self.ready, 'baseline-not-established'); self.verify()
        return self.ids

    def observe(self, stage, cleanup=False):
        need(stage in self.STAGES and self.ready, 'baseline-observation-stage-required')
        try:
            self.verify(); rows, images = self.capture(cleanup)
            digest = hashlib.sha256(canonical(rows)).hexdigest()
            self.observations += 1; self.last = stage
            self.observation_mode = 'protected-image-metadata-only' if cleanup else 'inventory-and-reference'
            if not cleanup: self.unknown_count = len(images - self.ids)
            self.append({'kind': 'protected-baseline-observation', 'stage': stage,
                'mode': self.observation_mode, 'identity_sha256': digest,
                'image_id_count': None if cleanup else len(images), 'container_count': None if cleanup else 0,
                'unowned_image_id_count': self.unknown_count, 'monotonic_ns': int(self.clock() * 10**9)})
            need(digest == self.identity_sha256 and canonical(rows) == self.rows, 'baseline-changed')
            if stage == 'after_cleanup' and not cleanup and not self.failed: self.preservation = 'PASS'
            return self.summary()
        except BaseException:
            self.failed = True; self.preservation = 'FAIL'; raise

    def summary(self):
        return {'status': 'FAIL' if self.failed else 'PASS' if self.ready else 'NOT RUN',
                'preservation': self.preservation, 'observation_mode': self.observation_mode,
                'protected_image_count': len(self.ids) if self.ready else None,
                'initial_container_count': self.initial_counts.get('container'),
                'initial_image_id_count': self.initial_counts.get('image'),
                'identity_sha256': getattr(self, 'identity_sha256', None),
                'receipt_sha256': hashlib.sha256(self.data).hexdigest() if self.data else None,
                'observation_count': self.observations, 'last_stage': self.last,
                'unowned_image_id_count': self.unknown_count,
                'unowned_images': 'NOT VERIFIED', 'legacy_build_cache_absence': 'NOT ESTABLISHED'}

    def close(self):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            for name in ('fd', 'parent'):
                value = getattr(self, name)
                if value is not None: os.close(value); setattr(self, name, None)
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)


class Broker:
    """Main-thread owner of all reservations; clients cannot select phase/backend.

    backend.endpoint is one reviewed Unix endpoint; backend.call(canonical_argv,
    timeout=seconds) must check captured Docker ELF, socket inode and daemon ID
    before AND after EVERY operation, including all inspection/removal/absence.
    context_digest(context) validates producer input pins and returns their actual
    bounded context SHA256. A digest label alone is not image-payload proof.
    """
    def __init__(self, backend, journal_path, nonce, private_root, source_root, *,
                 context_digest, binding, deadline=None, daemon_id=None,
                 cancelled=lambda: False, clock=time.monotonic, baseline=None):
        need(re.fullmatch(r'[0-9a-f]{32}', nonce or ''), 'nonce-required')
        need(type(binding) is dict and set(binding) == {'source_commit', 'run_id', 'packet_sha256', 'uid', 'gid'}, 'exact-job-binding-required')
        binding = dict(binding)
        source_commit, run_id = binding['source_commit'], binding['run_id']
        need(type(binding['packet_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', binding['packet_sha256']), 'packet-binding-required')
        need(type(source_commit) is str and re.fullmatch(r'[0-9a-f]{40}', source_commit)
             and type(run_id) is str and re.fullmatch(r'[1-9][0-9]{0,19}', run_id), 'same-job-source-binding-required')
        need(backend.endpoint in {'unix:///run/docker.sock', 'unix:///var/run/docker.sock'}, 'local-backend-required')
        need(callable(context_digest), 'validated-context-digest-required')
        self.backend, self.nonce = backend, nonce
        self.baseline = baseline
        if baseline is not None:
            need(isinstance(baseline, Baseline) and baseline.backend is backend and baseline.private == Path(private_root) and
                 baseline.nonce == nonce and all(baseline.binding[k] == value for k, value in binding.items()),
                 'same-job-baseline-required')
            baseline.protected()
        self.daemon_id = daemon_id if daemon_id is not None else getattr(backend, 'expected', None)
        need(type(self.daemon_id) is str and re.fullmatch(r'[A-Za-z0-9:-]{8,128}', self.daemon_id), 'bound-daemon-id-required')
        self.private, self.source = Path(private_root), Path(source_root)
        self.uid, self.gid = binding['uid'], binding['gid']
        need(type(self.uid) is type(self.gid) is int and 0 < self.uid <= 65535 and 0 < self.gid <= 65535
             and self.uid == os.getuid() == os.geteuid() and self.gid == os.getgid() == os.getegid(),
             'actual-positive-uid-gid-required')
        need(self.private.is_absolute() and self.source.is_absolute() and '..' not in self.private.parts
             and '..' not in self.source.parts and not self.private.is_relative_to(self.source), 'private-outside-source-required')
        self.context_digest, self.clock, self.cancelled = context_digest, clock, cancelled
        self.deadline = clock() + 8460 if deadline is None else deadline
        self.operation_deadline = None  # Parent sets the current outer phase cutoff.
        self.thread = threading.get_ident()
        self.phase, self.image, self.image_reserved, self.image_removed = 'producer', None, False, False
        self.image_context = None
        self.containers, self.failed, self.events, self.bytes, self.requests = {}, False, [], 0, 0
        self.journal_path = Path(journal_path)
        need(self.journal_path.parent == self.private and self.journal_path.name not in {'', '.', '..'}, 'private-journal-path-required')
        parent = directory(self.private)
        self.journal_fd = None
        try:
            info = os.fstat(parent)
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private-journal-parent-required')
            self.private_identity = node(info)
            self.journal_fd = os.open(self.journal_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      0o600, dir_fd=parent)
            os.fchmod(self.journal_fd, 0o600)
            self.journal_identity = node(os.fstat(self.journal_fd))
            os.fsync(parent)
        except BaseException:
            if self.journal_fd is not None:
                os.close(self.journal_fd); self.journal_fd = None
            raise
        finally:
            os.close(parent)
        pins = {}
        if hasattr(backend, 'cli_sha256'): pins['docker_sha256'] = backend.cli_sha256
        if hasattr(backend, 'socket_identity'):
            pins.update(docker_socket_device=backend.socket_identity[0], docker_socket_inode=backend.socket_identity[1])
        try:
            self.record('opened', **binding, **pins, docker_endpoint=backend.endpoint, daemon_id=self.daemon_id,
                        legacy_build_cache_absence='NOT ESTABLISHED')
        except BaseException:
            self.close()
            raise

    def record(self, event, **fields):
        row = {'event': event, 'nonce': self.nonce, 'phase': self.phase, **fields}
        data = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
        need(len(data) <= REQUEST_LIMIT + 1024 and self.bytes + len(data) <= JOURNAL_LIMIT - REQUEST_LIMIT,
             'journal-byte-budget')
        parent = directory(self.private)
        try:
            parent_info = os.fstat(parent)
            need(node(parent_info) == self.private_identity and parent_info.st_uid == os.geteuid()
                 and stat.S_IMODE(parent_info.st_mode) == 0o700
                 and node(os.stat(self.journal_path.name, dir_fd=parent, follow_symlinks=False)) == self.journal_identity,
                 'journal-namespace-drift')
        finally:
            os.close(parent)
        info = os.fstat(self.journal_fd)
        need(node(info) == self.journal_identity and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'journal-identity-drift')
        view = memoryview(data)
        while view:
            count = os.write(self.journal_fd, view)
            need(count > 0, 'journal-write-failure')
            view = view[count:]
        os.fsync(self.journal_fd)
        self.events.append(row); self.bytes += len(data)

    def check(self, *, cleanup=False):
        need(threading.get_ident() == self.thread, 'serial-main-thread-required')
        need(self.phase in {'producer', 'ksm-1', 'ksm-2'}, 'parent-phase-required')
        need(cleanup or not self.failed, 'failed-broker-refuses-new-work')
        if self.baseline is not None:
            self.baseline.operation_deadline = self.operation_deadline
            need(cleanup or not self.baseline.failed, 'failed-baseline-refuses-new-work')
        value = self.cancelled()
        need(type(value) is bool, 'boolean-cancellation-required')
        if value and not cleanup:
            raise Cancelled('job-cancelled')
        need(self.clock() < self.deadline, 'aggregate-deadline')

    def observe_baseline(self, stage, cleanup=False):
        if self.baseline is not None:
            self.baseline.operation_deadline = self.operation_deadline
            self.baseline.observe(stage, cleanup=cleanup)

    def call(self, args, *, maximum=60, cleanup=False):
        self.check(cleanup=cleanup)
        remaining = self.deadline - self.clock() - (0 if cleanup else 180)
        if not cleanup and self.operation_deadline is not None:
            need(type(self.operation_deadline) in (int, float) and math.isfinite(self.operation_deadline),
                 'finite-operation-deadline-required')
            remaining = min(remaining, self.operation_deadline - self.clock())
        need(remaining > 0, 'phase-deadline-or-cleanup-time-reserve')
        argv = ['docker', '--host=' + self.backend.endpoint, *args]
        self.record('docker-operation-reserved', argv=argv)
        result = self.backend.call(argv, timeout=min(maximum, remaining))
        need(isinstance(result, subprocess.CompletedProcess) and type(result.returncode) is int
             and type(result.stdout) is bytes and len(result.stdout) <= RESPONSE_LIMIT
             and result.stderr in (None, b''), 'bounded-folded-backend-response-required')
        self.check(cleanup=cleanup)
        need(cleanup or self.operation_deadline is None or self.clock() < self.operation_deadline, 'operation-phase-deadline')
        self.record('docker-operation-completed', returncode=result.returncode, stdout_bytes=len(result.stdout),
                    stdout_sha256=hashlib.sha256(result.stdout).hexdigest())
        return result

    def success(self, args, **kwargs):
        result = self.call(args, **kwargs)
        need(result.returncode == 0, 'docker-operation-failed')
        return result.stdout

    def inspect(self, kind, target, *, cleanup=False):
        data = self.success([kind, 'inspect', target], cleanup=cleanup)
        rows = json.loads(data)
        need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'one-object-inspection-required')
        return rows[0]

    def owned_image(self, *, cleanup=False):
        need(self.image is not None and not self.image_removed, 'owned-image-required')
        if self.baseline is not None:
            need(self.image not in self.baseline.protected(), 'baseline-ID-collision')
        row = self.inspect('image', self.image, cleanup=cleanup)
        labels = row.get('Config', {}).get('Labels', {})
        need(row.get('Id') == self.image and row.get('Architecture') == 'arm64' and row.get('Os') == 'linux'
             and labels.get(LABEL) == self.nonce and labels.get(CONTEXT_LABEL) == self.image_context,
             'image-ownership-mismatch')
        return row

    def owned_container(self, name, record, *, cleanup=False):
        row = self.inspect('container', record['id'] or name, cleanup=cleanup)
        labels = row.get('Config', {}).get('Labels', {})
        need(CID.fullmatch(row.get('Id', '')) and row.get('Name') == '/' + name
             and row.get('Image') == self.image and labels.get(LABEL) == self.nonce
             and labels.get(IMAGE_LABEL) == self.image, 'container-ownership-mismatch')
        if record['id'] is not None:
            need(row['Id'] == record['id'], 'container-id-drift')
        return row

    def absent_container(self, name, cid):
        for selected in ('name=^/' + name + '$', 'id=' + cid):
            data = self.success(['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', selected], cleanup=True)
            need(not data.strip(), 'individual-container-absence-unconfirmed')

    def remove_container(self, name, record):
        row = self.owned_container(name, record, cleanup=True)
        record['id'] = row['Id']
        self.record('container-removal-reserved', name=name, id=row['Id'])
        self.success(['rm', '--force', '--volumes', row['Id']], cleanup=True)
        self.absent_container(name, row['Id'])
        record['absent'] = True
        self.record('container-absent', name=name, id=row['Id'])

    def build(self, argv):
        need(self.phase == 'producer' and not self.image_reserved, 'one-producer-image-build-only')
        self.observe_baseline('before-build')
        options, rest = parse_options(argv[2:], {'--network', '--pull', '--platform', '--iidfile'}, set())
        context, iidfile = self.private / 'producer/context', self.private / 'producer/image-id'
        need(options == {'--network': ['none'], '--pull': ['false'], '--platform': ['linux/arm64'], '--iidfile': [str(iidfile)]}
             and rest == [str(context)], 'exact-producer-build-required')
        digest = self.context_digest(context)
        need(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest), 'validated-context-hash-required')
        self.image_reserved = True
        self.record('image-reserved', context_sha256=digest, tag='ksm-native-' + self.nonce)
        for selection in ('reference=ksm-native-' + self.nonce, 'label=' + LABEL + '=' + self.nonce):
            need(not self.success(['image', 'ls', '--quiet', '--no-trunc', '--filter', selection]).strip(),
                 'image-reservation-already-present')
        command = ['build', '--network=none', '--pull=false', '--platform=linux/arm64',
                   '--memory=4g', '--memory-swap=4g', '--cpu-period=100000', '--cpu-quota=400000',
                   '--label', LABEL + '=' + self.nonce, '--label', CONTEXT_LABEL + '=' + digest,
                   '--tag', 'ksm-native-' + self.nonce, '--iidfile', str(iidfile), str(context)]
        result = self.call(command, maximum=1800)
        need(result.returncode == 0, 'producer-build-failed-commit-uncertain')
        parent = directory(iidfile.parent)
        fd = None
        try:
            fd = os.open(iidfile.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                 and 0 < info.st_size <= 128, 'bounded-iidfile-required')
            data = os.read(fd, 129)
            after = os.fstat(fd)
            need((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size,
                  info.st_mtime_ns, info.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size,
                  after.st_mtime_ns, after.st_ctime_ns) and len(data) == info.st_size, 'iidfile-drift')
        finally:
            if fd is not None: os.close(fd)
            os.close(parent)
        image = data.decode('ascii').strip()
        need(IMAGE.fullmatch(image), 'immutable-produced-image-required')
        if self.baseline is not None:
            need(image not in self.baseline.protected(), 'baseline-ID-collision')
        row = self.inspect('image', image)
        need(row.get('Id') == image and row.get('Architecture') == 'arm64' and row.get('Os') == 'linux'
             and row.get('Config', {}).get('Labels', {}).get(LABEL) == self.nonce
             and row.get('Config', {}).get('Labels', {}).get(CONTEXT_LABEL) == digest, 'image-ownership-mismatch')
        self.image, self.image_context = image, digest
        self.record('image-bound', id=image, context_sha256=digest)
        self.observe_baseline('after-build')
        return result

    def mount_policy(self, mounts):
        need(len(mounts) == 4, 'four-reviewed-builder-mounts-required')
        parsed = {}
        for value in mounts:
            parts = value.split(',')
            need(len(parts) in {3, 4} and parts[0] == 'type=bind' and parts[1].startswith('src=')
                 and parts[2].startswith('dst=') and (len(parts) == 3 or parts[3] == 'readonly'), 'exact-bind-mount-grammar')
            source, target = Path(parts[1][4:]), parts[2][4:]
            need(source.is_absolute() and '..' not in source.parts and target not in parsed, 'canonical-distinct-mounts-required')
            parsed[target] = (source, len(parts) == 4)
        need(set(parsed) == {'/inputs', '/out', '/builder-entry.sh', '/expected-packages.lock'}, 'reviewed-mount-targets-required')
        base = parsed['/inputs'][0].parent
        if self.phase == 'producer':
            need(base.parent == self.private / 'producer' and any(base.name == name + '-' + attempt
                 for name in ORIGINALS for attempt in ('1', '2')), 'original-build-snapshot-required')
        else:
            need(base == self.private / ('build-' + self.phase[-1]), 'ksm-build-snapshot-required')
        need(parsed == {'/inputs': (base / 'inputs', True), '/out': (base / 'artifacts', False),
                        '/builder-entry.sh': (self.source / 'scripts/build/container-entry.sh', True),
                        '/expected-packages.lock': (base / 'expected-packages.lock', True)}, 'reviewed-mount-sources-required')
        # Resolve through no-follow ancestors. Source bytes are separately frozen
        # by the parent; Docker mounts are not source-distribution authorization.
        for path, _ in parsed.values():
            parent = directory(path.parent)
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                need(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1), 'regular-mount-source-required')
            finally:
                os.close(parent)

    def run(self, argv):
        self.observe_baseline('before-run')
        valued = {'--name', '--pull', '--network', '--cap-drop', '--security-opt', '--entrypoint', '--platform',
                  '--user', '--pids-limit', '--memory', '--cpus', '--tmpfs', '--env', '--mount'}
        options, rest = parse_options(argv[2:], valued, {'--rm', '--read-only'}, {'--env', '--mount'})
        need(self.image is not None and not self.image_removed and len(rest) == 2 and rest[0] == self.image, 'owned-image-run-required')
        common = {'--rm': [True], '--pull': ['never'], '--network': ['none'], '--cap-drop': ['ALL'],
                  '--security-opt': ['no-new-privileges'], '--read-only': [True]}
        inventory = {**common, '--entrypoint': ['/bin/cat']}
        if options == inventory and rest[1] == '/builder-packages.lock':
            need(self.phase == 'producer', 'producer-inventory-only')
            name = 'ksm-inventory-' + self.nonce
        else:
            name = options.get('--name', [''])[0]
            epoch = options.get('--env', [])
            need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'original-distinct-container-name-required')
            need(len(epoch) == 2 and epoch[0] == 'CACHY_ASAHI_CONTAINER=1'
                 and re.fullmatch(r'SOURCE_DATE_EPOCH=[0-9]{1,12}', epoch[1]), 'reviewed-builder-env-required')
            expected = {**common, '--name': [name], '--platform': ['linux/arm64'], '--user': [f'{self.uid}:{self.gid}'],
                        '--pids-limit': ['512'], '--memory': ['4g'], '--cpus': ['4'],
                        '--tmpfs': ['/tmp:rw,nosuid,nodev,exec,size=4g'], '--env': epoch,
                        '--mount': options.get('--mount', []), '--entrypoint': ['/bin/bash']}
            need(options == expected and rest[1] == '/builder-entry.sh', 'exact-original-builder-run-required')
            self.mount_policy(options['--mount'])
        need(name not in self.containers and len(self.containers) < 14, 'distinct-container-reservation-budget')
        self.owned_image()
        record = {'id': None, 'absent': False, 'phase': self.phase}
        self.containers[name] = record
        self.record('container-reserved', name=name, image=self.image)
        command = ['create']
        for key, values in options.items():
            if key in {'--rm', '--name'}: continue
            for value in values:
                command += [key] if value is True else [key, value]
        command += ['--name', name, '--label', LABEL + '=' + self.nonce, '--label', IMAGE_LABEL + '=' + self.image,
                    '--memory-swap=4g']
        if options == inventory:
            command += ['--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=32', '--platform=linux/arm64']
            command.remove('--memory-swap=4g')
        command += rest
        created = self.success(command)
        cid = created.decode('ascii').strip()
        need(CID.fullmatch(cid), 'create-commit-uncertain')
        record['id'] = cid
        self.record('container-bound', name=name, id=cid)
        self.owned_container(name, record)
        self.record('container-start-reserved', name=name, id=cid)
        result = self.call(['start', '--attach', cid], maximum=300 if options != inventory else 60)
        row = self.owned_container(name, record)
        state = row.get('State', {})
        need(state.get('Status') == 'exited' and type(state.get('ExitCode')) is int and state.get('OOMKilled') is False,
             'container-exit-state-unconfirmed')
        need(result.returncode == state['ExitCode'], 'attached-exit-code-mismatch')
        self.record('container-exited', name=name, id=cid, status=state['Status'],
                    exit_code=state['ExitCode'], oom_killed=state['OOMKilled'])
        self.remove_container(name, record)
        self.observe_baseline('after-run')
        return result

    def request(self, argv):
        try:
            self.check(); argv_check(argv)
            need(argv[0] == 'docker', 'docker-only-request')
            self.requests += 1
            need(self.requests <= 256, 'request-count-bound')
            self.record('request', argv=argv)
            if argv[1:] in (['info', '--format', '{{.Architecture}}'], ['version']):
                return self.call(argv[1:])
            if argv[1:] == ['context', 'inspect']:
                result = self.call(['context', 'inspect'])
                need(result.returncode == 0, 'context-inspection-failed')
                def unique(pairs):
                    value = {}
                    for key, item in pairs:
                        need(key not in value, 'duplicate-context-field')
                        value[key] = item
                    return value
                rows = json.loads(result.stdout, object_pairs_hook=unique,
                                  parse_constant=lambda _: need(False, 'nonfinite-context-JSON'))
                need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
                     'one-actual-context-required')
                endpoints = rows[0].get('Endpoints')
                need(type(endpoints) is dict and type(endpoints.get('docker')) is dict
                     and type(endpoints['docker'].get('Host')) is str and endpoints['docker']['Host'] in {'unix:///run/docker.sock', 'unix:///var/run/docker.sock'},
                     'actual-local-context-required')
                return result
            if len(argv) == 4 and argv[1:3] == ['image', 'inspect']:
                need(self.image is not None and argv[3] == self.image and not self.image_removed, 'owned-image-inspect-only')
                row = self.owned_image()
                return subprocess.CompletedProcess(argv, 0, json.dumps([row]).encode())
            if len(argv) > 2 and argv[1] == 'build': return self.build(argv)
            if len(argv) > 2 and argv[1] == 'run': return self.run(argv)
            if len(argv) == 4 and argv[1:3] == ['rm', '-f']:
                name = argv[3]
                need(name in self.containers, 'unreserved-removal-refused')
                record = self.containers[name]
                if not record['absent']: self.remove_container(name, record)
                else: self.absent_container(name, record['id'])
                return subprocess.CompletedProcess(argv, 0, b'')
            raise ValueError('unsupported-docker-command')
        except BaseException as error:
            self.failed = True
            self.record('request-failed', classification='uncertain' if self.image_reserved or self.containers else 'refused',
                        error_type=type(error).__name__)
            raise

    def absent_image(self):
        for selection in ('reference=ksm-native-' + self.nonce, 'label=' + LABEL + '=' + self.nonce):
            need(not self.success(['image', 'ls', '--quiet', '--no-trunc', '--filter', selection], cleanup=True).strip(),
                 'owned-image-absence-unconfirmed')
        absent = self.call(['image', 'inspect', self.image], cleanup=True)
        need(absent.returncode == 1 and absent.stdout in image_absence_outputs(self.image),
             'individual-image-absence-unconfirmed')

    def cleanup_image(self):
        """Dispose the one known image only after accepted consumers finish."""
        self.check(cleanup=True)
        if not self.image_reserved:
            return
        if self.image_removed:
            self.absent_image()
            return
        need(self.image is not None, 'unbound-image-commit-uncertain')
        self.observe_baseline('before-image-removal', cleanup=True)
        self.owned_image(cleanup=True)
        self.record('image-removal-reserved', id=self.image)
        if self.baseline is not None:
            need(self.image not in self.baseline.protected(), 'baseline-ID-collision')
        self.success(['image', 'rm', '--no-prune', self.image], cleanup=True)
        self.absent_image()
        self.image_removed = True
        self.record('image-absent', id=self.image)
        self.observe_baseline('after-image-removal', cleanup=True)

    def cleanup(self):
        """Owned-ID cleanup only; unresolved reservations remain explicit FAIL."""
        try:
            self.check(cleanup=True)
            for name, record in self.containers.items():
                if not record['absent']:
                    self.remove_container(name, record)
                else:
                    self.absent_container(name, record['id'])
            self.cleanup_image()
            result = {'status': 'FAIL' if self.failed else 'PASS', 'containers_absent': True,
                      'owned_image_absent': not self.image_reserved or self.image_removed,
                      'legacy_build_cache_absence': 'NOT ESTABLISHED'}
        except BaseException as error:
            self.failed = True
            result = {'status': 'FAIL', 'containers_absent': False, 'owned_image_absent': False,
                      'legacy_build_cache_absence': 'NOT ESTABLISHED', 'error_type': type(error).__name__}
        self.record('cleanup-result', **result)
        return result

    def close(self):
        if self.journal_fd is not None:
            os.close(self.journal_fd); self.journal_fd = None


def receive(connection, maximum):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            block = connection.recv(min(65536, size - len(data)))
            need(block, 'truncated-rpc')
            data.extend(block)
        return bytes(data)
    size = struct.unpack('!I', exact(4))[0]
    need(0 < size <= maximum, 'rpc-byte-bound')
    return exact(size)


def send(connection, data, maximum):
    need(0 < len(data) <= maximum, 'rpc-byte-bound')
    connection.sendall(struct.pack('!I', len(data)) + data)


class Service:
    """Parent Runner's main-thread poll callback; never a broker worker thread."""
    def __init__(self, socket_path, broker, token):
        need(re.fullmatch(r'[0-9a-f]{64}', token or ''), 'rpc-token-required')
        self.path, self.broker, self.token = Path(socket_path), broker, token
        need(self.path.parent == broker.private and len(str(self.path).encode()) < 104, 'private-unix-socket-required')
        self.parent = directory(self.path.parent)
        self.busy = False
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.identity = None
        try:
            need(self.path.name not in os.listdir(self.parent), 'socket-must-be-absent')
            info = os.fstat(self.parent)
            need(node(info) == broker.private_identity and info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o700, 'private-rpc-parent-required')
            self.socket.bind(f'/proc/self/fd/{self.parent}/{self.path.name}')
            self.identity = node(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False))
            os.chmod(self.path.name, 0o600, dir_fd=self.parent, follow_symlinks=False)
            self.socket.listen(4); self.socket.setblocking(False)
        except BaseException:
            self.socket.close()
            try:
                if self.identity is not None:
                    need(node(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)) == self.identity,
                         'partial-rpc-socket-replacement-cleanup-refused')
                    os.unlink(self.path.name, dir_fd=self.parent); os.fsync(self.parent)
            finally:
                os.close(self.parent)
            raise

    def poll(self):
        self.broker.check()
        if self.busy:
            return
        need(node(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)) == self.identity, 'rpc-socket-identity-drift')
        try:
            connection, _ = self.socket.accept()
        except BlockingIOError:
            return
        self.busy = True
        try:
            self.handle(connection)
        finally:
            self.busy = False

    def handle(self, connection):
        with connection:
            connection.settimeout(5)
            try:
                peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(peer[1] == os.geteuid(), 'rpc-peer-owner-required')
                request = json.loads(receive(connection, REQUEST_LIMIT))
                need(type(request) is dict and set(request) == {'token', 'argv'} and request['token'] == self.token, 'rpc-request-refused')
                result = self.broker.request(['docker', *request['argv']])
                response = {'code': result.returncode, 'stdout': base64.b64encode(result.stdout).decode()}
            except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
                self.broker.failed = True
                self.broker.record('rpc-failed', error_type=type(error).__name__)
                response = {'code': 125, 'stdout': base64.b64encode(('scoped Docker request refused: ' + type(error).__name__ + '\n').encode()).decode()}
            send(connection, json.dumps(response).encode(), RESPONSE_LIMIT * 2)

    def close(self):
        self.socket.close()
        try:
            need(node(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)) == self.identity, 'rpc-socket-replacement-cleanup-refused')
            os.unlink(self.path.name, dir_fd=self.parent)
            os.fsync(self.parent)
        finally:
            os.close(self.parent)
