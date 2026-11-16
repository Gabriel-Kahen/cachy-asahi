# SPDX-License-Identifier: MIT
"""Finite BANKSTOWN_QT3_IMAGE_DATA_V1 consumer; no receipt or authority issuer."""
import math
import re
from pathlib import Path

EXPECTED477 = dict(bytes=9102, sha256='64f9c67795bd16f4cf3704dc0a050d2d17d1baa6e42b4e4fa254507b15183c49')


def validate(d, P, *, now):
    def exact(value, keys, code):
        P.need(type(value) is dict and set(value) == set(keys.split()), code)
    def text(value, pattern, code):
        P.need(type(value) is str and re.fullmatch(pattern, value), code)
    exact(d, 'schema kind status source binding nonce delegation_pin catalog image filesystem executor lifetime legal key_freshness Root_final_acceptance independent_component_acceptance hardware_acceptance release_acceptance', 'IMAGE_RECEIPT_SCHEMA')
    P.need(type(d['schema']) is int and d['schema'] == 1
           and d['kind'] == 'BANKSTOWN_QT3_IMAGE_DATA_V1'
           and d['status'] == 'PASS_PRIVATE_IMAGE_DATA_ONLY', 'ACTUAL_IMAGE_DATA_REQUIRED')
    P.need(d['Root_final_acceptance'] is None
           and all(d[k] is False for k in ('independent_component_acceptance', 'hardware_acceptance', 'release_acceptance'))
           and d['legal'] == d['key_freshness'] == 'HELD', 'ACCEPTANCE_MUST_REMAIN_HELD')
    exact(d['source'], 'root commit ref', 'SOURCE_SCHEMA')
    P.ordinary(d['source']['root'])
    text(d['source']['commit'], '[0-9a-f]{40}', 'SOURCE_COMMIT')
    text(d['source']['ref'], r'refs/heads/[A-Za-z0-9_./-]{1,200}', 'SOURCE_REF')
    P.need('..' not in d['source']['ref'], 'SOURCE_REF')
    b = d['binding']
    exact(b, 'source ref run job attempt source_lock', 'BINDING_SCHEMA')
    P.need(b['source'] == d['source']['commit'] and b['ref'] == d['source']['ref']
           and type(b['attempt']) is int and b['attempt'] == 1, 'SOURCE_BINDING_DIFFERS')
    for key in ('run', 'job'): text(b[key], '[1-9][0-9]{0,19}', 'FINITE_RUN_JOB')
    P.descriptor(b['source_lock'], 2 * 1024**2)
    P.sha(d['nonce']); P.descriptor(d['delegation_pin'], 2 * 1024**2)
    for row in (d['catalog'], d['image'].get('inventory') if type(d['image']) is dict else None):
        exact(row, 'path bytes sha256', 'PINNED_IMAGE_REF')
        P.ordinary(row['path']); P.descriptor({k: row[k] for k in ('bytes', 'sha256')})
    exact(d['image'], 'id inventory protected349', 'IMAGE_SCHEMA')
    text(d['image']['id'], 'sha256:[0-9a-f]{64}', 'ACTUAL_IID_REQUIRED')
    P.descriptor(d['image']['protected349'])
    P.need({k: d['image']['inventory'][k] for k in ('bytes', 'sha256')} == EXPECTED477, 'EXACT_OBSERVED477_PIN')
    e = d['executor']
    exact(e, 'code_pin engine_id docker_endpoint owner_pid daemon_pid', 'EXECUTOR_SCHEMA')
    P.descriptor(e['code_pin'], 128 * 1024)
    for key in ('owner_pid', 'daemon_pid'):
        P.need(type(e[key]) is int and 0 < e[key] < 2**31, 'FINITE_EXECUTOR_PID')
    text(e['docker_endpoint'], r'unix:///[A-Za-z0-9_./-]{1,240}', 'EXPLICIT_DAEMON_ENDPOINT')
    P.need('..' not in e['docker_endpoint'].split('/') and d['nonce'] in e['docker_endpoint']
           and e['owner_pid'] != e['daemon_pid'], 'EXCLUSIVE_DAEMON_NONCE_AND_PIDS')
    text(e['engine_id'], r'[^\s\x00-\x1f\x7f]{1,256}', 'ACTUAL_ENGINE_ID')
    f = d['filesystem']
    exact(f, 'root image_id archive', 'FILESYSTEM_SCHEMA')
    root = P.ordinary(f['root']); source = P.ordinary(d['source']['root'])
    P.need(root != source and not root.is_relative_to(source) and not source.is_relative_to(root), 'DISJOINT_IMAGE_ROOT')
    P.need(f['image_id'] == d['image']['id'], 'FILESYSTEM_IID_DIFFERS')
    exact(f['archive'], 'path bytes sha256', 'FILESYSTEM_ARCHIVE_REF')
    P.ordinary(f['archive']['path']); P.descriptor({k: f['archive'][k] for k in ('bytes', 'sha256')}, 16 * 1024**3)
    lifetime = d['lifetime']
    exact(lifetime, 'observed_monotonic work_deadline_monotonic', 'LIFETIME_SCHEMA')
    P.need(type(now) in (float, int) and math.isfinite(now), 'FINITE_NOW')
    for value in lifetime.values():
        P.need(type(value) in (float, int) and math.isfinite(value) and value > 0, 'FINITE_LIFETIME')
    P.need(lifetime['observed_monotonic'] <= now < lifetime['work_deadline_monotonic'], 'SAME_LIVE_LIFETIME_REQUIRED')
    return d
