# SPDX-License-Identifier: MIT
"""Create-only, fsynced recovery journal; reading never authorizes a resume."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PHASES = ('CREATED', 'BASELINE_RECORDED', 'REFERENCE_READY', 'BASELINE_RESTORED',
          'NORMAL_EPISODE_PASSED', 'RECOVERY_BASELINE_RESTORED', 'PRIOR_INSTALLED',
          'INTERRUPT_INTENT', 'CHECKPOINT_VERIFIED',
          'INTERRUPTED_RETIRED', 'CLEANUP_INTENT', 'CLEANUP_COMPLETED',
          'RECOVERY_INSTALL_INTENT', 'RECOVERY_INSTALLED', 'RECOVERY_VERIFIED', 'FINALIZED')
COMMANDS = ('COMMAND_INTENT', 'COMMAND_COMPLETED')
LINE_CAP, FILE_CAP, RECORD_CAP = 65536, 1048576, 256


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def binding(value):
    need(type(value) is dict and set(value) == {'source', 'ref', 'run', 'attempt', 'map_sha256', 'token'},
         'exact recovery journal binding')
    need(type(value['source']) is str and re.fullmatch('[0-9a-f]{40}', value['source'])
         and type(value['map_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['map_sha256']), 'Source/map')
    need(type(value['ref']) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9._+/-]+', value['ref'])
         and all(p not in ('', '.', '..') for p in value['ref'].split('/')), 'future literal ref')
    need(type(value['run']) is str and re.fullmatch('[1-9][0-9]{0,19}', value['run'])
         and type(value['attempt']) is int and value['attempt'] == 1
         and type(value['token']) is str and re.fullmatch('[0-9a-f]{24,64}', value['token']), 'actual run/token')
    return json.loads(encoded(value))


def transition(phase, pending, event, data):
    need(type(data) is dict, 'journal DATA object')
    if event == 'FAILED':
        need(phase not in ('FINALIZED', 'FAILED'), 'terminal journal')
        return 'FAILED', pending
    need(phase not in ('FINALIZED', 'FAILED'), 'terminal journal')
    if event == 'COMMAND_INTENT':
        need(phase is not None and pending is None, 'one outstanding command only')
        need(type(data.get('step')) is str and re.fullmatch('[A-Za-z0-9_-]{1,80}', data['step']), 'command step')
        need(type(data.get('argv')) in (list, tuple) and 1 <= len(data['argv']) <= 128
             and all(type(v) is str and 0 < len(v) <= 4096 and '\0' not in v for v in data['argv']), 'bounded argv')
        need(type(data.get('seconds')) is int and 0 < data['seconds'] <= 1800
             and type(data.get('output_cap')) is int and 0 < data['output_cap'] <= 33554432, 'command caps')
        return phase, data['step']
    if event == 'COMMAND_COMPLETED':
        need(pending is not None and data.get('step') == pending, 'completion joins pending command')
        return phase, None
    need(event in PHASES and pending is None, 'unknown phase or unresolved command')
    expected = PHASES[0] if phase is None else PHASES[PHASES.index(phase) + 1]
    need(event == expected, 'exact forward recovery phase')
    return event, None


class Journal:
    @classmethod
    def create(cls, path, context):
        path = Path(path).absolute()
        need(path == path.resolve() and path.parent.is_dir() and not path.is_symlink(), 'ordinary journal path')
        parent = path.parent.stat()
        need(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700, 'private journal parent')
        obj = cls()
        obj.path, obj._binding = path, encoded(binding(context))
        obj.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(obj.fd, 0o600)
            obj.phase, obj.pending, obj.previous, obj.sequence, obj.bytes = None, None, '0' * 64, 0, 0
            obj.broken = False
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            obj.append('CREATED', {})
        except BaseException:
            obj.close()
            raise
        return obj

    @property
    def binding(self):
        return json.loads(self._binding)

    def append(self, event, data):
        need(self.fd is not None and not self.broken, 'closed/broken journal; never reopen')
        phase, pending = transition(self.phase, self.pending, event, data)
        payload = dict(schema=1, sequence=self.sequence, binding=self.binding,
                       previous=self.previous, event=event, data=data)
        body = encoded(payload)
        digest = hashlib.sha256(body).hexdigest()
        raw = encoded(dict(payload, sha256=digest)) + b'\n'
        need(len(raw) <= LINE_CAP and self.bytes + len(raw) <= FILE_CAP and self.sequence < RECORD_CAP,
             'journal limits')
        try:
            offset = 0
            while offset < len(raw):
                n = os.write(self.fd, raw[offset:])
                need(n > 0, 'journal short write')
                offset += n
            os.fsync(self.fd)
        except BaseException:
            self.broken = True
            raise
        self.phase, self.pending = phase, pending
        self.previous, self.sequence, self.bytes = digest, self.sequence + 1, self.bytes + len(raw)
        return dict(sequence=payload['sequence'], sha256=digest, phase=phase, pending=pending)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def load(path, expected_binding):
    """Passive verification only: even a complete journal cannot resume a writer."""
    context = binding(expected_binding)
    path = Path(path).absolute()
    need(path == path.resolve(), 'ordinary journal path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600
             and 0 < before.st_size <= FILE_CAP, 'bounded private journal')
        raw = os.read(fd, FILE_CAP + 1)
        after = os.fstat(fd)
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and key(before) == key(after) == key(path.lstat()), 'stable whole journal')
    finally:
        os.close(fd)
    need(raw.endswith(b'\n'), 'uncertain partial journal tail')
    records, phase, pending, previous = [], None, None, '0' * 64
    for i, line in enumerate(raw.splitlines()):
        need(i < RECORD_CAP and len(line) + 1 <= LINE_CAP, 'journal record bounds')
        record = json.loads(line)
        need(type(record) is dict and set(record) == {'schema', 'sequence', 'binding', 'previous', 'event', 'data', 'sha256'}, 'record fields')
        digest = record['sha256']
        payload = {k: v for k, v in record.items() if k != 'sha256'}
        need(type(record['schema']) is int and record['schema'] == 1
             and type(record['sequence']) is int and record['sequence'] == i
             and record['binding'] == context and record['previous'] == previous
             and hashlib.sha256(encoded(payload)).hexdigest() == digest
             and encoded(record) == line, 'canonical binding/hashchain')
        phase, pending = transition(phase, pending, record['event'], record['data'])
        records.append(record)
        previous = digest
    return dict(records=records, phase=phase, pending_command=pending, resume_allowed=False,
                complete=phase == 'FINALIZED', sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
