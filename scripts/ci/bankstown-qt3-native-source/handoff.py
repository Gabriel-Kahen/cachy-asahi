# SPDX-License-Identifier: MIT
"""Passive image/profile handoff checks. This module issues no authority."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

KIND = 'BANKSTOWN_QT3_IMAGE_DATA_V1'
FINAL = dict(Root_final_acceptance=None, independent_component_acceptance=False,
             hardware_acceptance=False, release_acceptance=False)
PROTECTED349 = dict(bytes=6800, sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453')
EXPECTED477 = dict(bytes=9102, sha256='64f9c67795bd16f4cf3704dc0a050d2d17d1baa6e42b4e4fa254507b15183c49')


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decoded(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 2 * 1024**2, 'HANDOFF_JSON_BOUND')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_HANDOFF_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE_HANDOFF'))


def whole(value, cap=16 * 1024**3):
    need(type(value) is dict and set(value) == {'bytes', 'sha256'}
         and type(value['bytes']) is int and 0 < value['bytes'] <= cap
         and type(value['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'WHOLE_HANDOFF_PIN')
    return value


def ordinary(value):
    need(type(value) is str and '\x00' not in value and '\n' not in value, 'HANDOFF_PATH')
    path = Path(value)
    need(path.is_absolute() and str(path) == value and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'UNALIASED_HANDOFF_PATH')
    return path


def identity(row):
    return tuple(getattr(row, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def verify_reference(row, *, cap=16 * 1024**3, deadline=None, body=False):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'HANDOFF_REFERENCE')
    expected = whole({k: row[k] for k in ('bytes', 'sha256')}, cap)
    path = ordinary(row['path'])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == expected['bytes'], 'ORDINARY_WHOLE_HANDOFF_FILE')
        digest, size, chunks = hashlib.sha256(), 0, []
        while True:
            need(deadline is None or time.monotonic() < deadline, 'HANDOFF_DEADLINE')
            part = os.read(fd, min(1024**2, expected['bytes'] + 1 - size))
            if not part:
                break
            size += len(part)
            need(size <= expected['bytes'], 'HANDOFF_FILE_GREW')
            digest.update(part)
            if body:
                chunks.append(part)
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and size == expected['bytes'] and digest.hexdigest() == expected['sha256'], 'HANDOFF_FILE_DIFFERS')
        return b''.join(chunks) if body else expected
    finally:
        os.close(fd)


def validate_image_receipt(raw, expected_sha256, *, now_monotonic=None, verify_files=True):
    """Require the caller's externally selected whole receipt and live lifetime.

    File verification is mandatory for a real handoff; False supports schema-only
    MODEL controls and grants no authority or filesystem qualification.
    """
    need(pin(raw)['sha256'] == expected_sha256, 'EXTERNAL_IMAGE_RECEIPT_PIN')
    value = decoded(raw)
    keys = {'schema', 'kind', 'status', 'source', 'binding', 'nonce', 'delegation_pin',
            'catalog', 'image', 'filesystem', 'executor', 'lifetime', 'legal', 'key_freshness'} | set(FINAL)
    need(type(value) is dict and set(value) == keys and type(value['schema']) is int
         and value['schema'] == 1 and value['kind'] == KIND
         and value['status'] == 'PASS_PRIVATE_IMAGE_DATA_ONLY', 'IMAGE_RECEIPT_SCHEMA')
    need(value['legal'] == value['key_freshness'] == 'HELD'
         and all(value[k] is expected for k, expected in FINAL.items()), 'HANDOFF_HOLDS_REQUIRED')
    source, binding = value['source'], value['binding']
    need(type(source) is dict and set(source) == {'root', 'commit', 'ref'}
         and re.fullmatch('[0-9a-f]{40}', source.get('commit', ''))
         and re.fullmatch(r'refs/heads/[A-Za-z0-9._+/-]+', source.get('ref', '')),
         'HANDOFF_SOURCE_IDENTITY')
    source_root = ordinary(source['root'])
    need(type(binding) is dict and set(binding) == {'source', 'ref', 'run', 'job', 'attempt', 'source_lock'}
         and binding['source'] == source['commit'] and binding['ref'] == source['ref']
         and type(binding['attempt']) is int and binding['attempt'] == 1
         and all(type(binding[k]) is str and re.fullmatch('[1-9][0-9]{0,19}', binding[k]) for k in ('run', 'job')),
         'ACTUAL_HANDOFF_BINDING')
    whole(binding['source_lock'], 2 * 1024**2)
    whole(value['delegation_pin'], 2 * 1024**2)
    need(type(value['nonce']) is str and re.fullmatch('[0-9a-f]{64}', value['nonce']), 'HANDOFF_NONCE')
    image, filesystem, executor, lifetime = (value[k] for k in ('image', 'filesystem', 'executor', 'lifetime'))
    need(type(image) is dict and set(image) == {'id', 'inventory', 'protected349'}
         and type(image['id']) is str and re.fullmatch('sha256:[0-9a-f]{64}', image['id'])
         and image['protected349'] == PROTECTED349, 'ACTUAL_PROTECTED_IMAGE')
    need(type(filesystem) is dict and set(filesystem) == {'root', 'image_id', 'archive'}
         and filesystem['image_id'] == image['id'], 'MATERIALIZED_IMAGE_IDENTITY')
    materialized_root = ordinary(filesystem['root'])
    need(materialized_root != source_root and not materialized_root.is_relative_to(source_root)
         and not source_root.is_relative_to(materialized_root), 'DISJOINT_IMAGE_ROOT')
    need(type(executor) is dict and set(executor) == {'code_pin', 'engine_id', 'docker_endpoint', 'owner_pid', 'daemon_pid'},
         'HANDOFF_EXECUTOR_SCHEMA')
    whole(executor['code_pin'], 128 * 1024)
    need(type(executor['engine_id']) is str and 0 < len(executor['engine_id']) <= 256
         and type(executor['docker_endpoint']) is str and executor['docker_endpoint'].startswith('unix:///')
         and value['nonce'] in executor['docker_endpoint']
         and all(type(executor[k]) is int and executor[k] > 0 for k in ('owner_pid', 'daemon_pid'))
         and executor['owner_pid'] != executor['daemon_pid'], 'ACTUAL_EXCLUSIVE_EXECUTOR')
    need(type(lifetime) is dict and set(lifetime) == {'observed_monotonic', 'work_deadline_monotonic'}, 'HANDOFF_LIFETIME')
    now = time.monotonic() if now_monotonic is None else now_monotonic
    need(all(type(t) in (int, float) and math.isfinite(t) and t > 0
             for t in (now, lifetime['observed_monotonic'], lifetime['work_deadline_monotonic']))
         and lifetime['observed_monotonic'] <= now < lifetime['work_deadline_monotonic'], 'LIVE_SAME_HOST_LIFETIME')
    for row, cap in ((value['catalog'], 64 * 1024**2), (image['inventory'], 2 * 1024**2),
                     (filesystem['archive'], 16 * 1024**3)):
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'HANDOFF_REFERENCE')
        ordinary(row['path'])
        whole({k: row[k] for k in ('bytes', 'sha256')}, cap)
    need({k: image['inventory'][k] for k in ('bytes', 'sha256')} == EXPECTED477, 'EXACT477_OBSERVED_INVENTORY_REQUIRED')
    if verify_files:
        need(source_root.is_dir() and materialized_root.is_dir(), 'ACTUAL_HANDOFF_ROOTS')
        deadline = lifetime['work_deadline_monotonic']
        for row in (value['catalog'], image['inventory'], filesystem['archive']):
            verify_reference(row, deadline=deadline)
    return value
