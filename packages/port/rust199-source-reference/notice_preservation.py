#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve pinned upstream source notice contexts as DATA; no legal clearance."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

MAX_ARCHIVE = 512 * 1024**2
MAX_FILE = 1024**2
MAX_TOTAL = 16 * 1024**2
MAX_CATALOGUE = 1024**2
SCOPE = 'EXACT_SOURCE_FILES_CONTAINING_CATALOGUED_NOTICE_CONTEXTS_ONLY_NO_LEGAL_ACCEPTANCE'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def open_input(path, cap):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute input required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        source = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)
    stream = os.fdopen(source, 'rb')
    info = os.fstat(stream.fileno())
    if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= cap):
        stream.close()
        raise ValueError('bounded regular single-link input required')
    return stream, info


def catalogue(path, expected):
    with open_input(path, MAX_CATALOGUE)[0] as stream:
        raw = stream.read(MAX_CATALOGUE + 1)
    need(pin(raw)['sha256'] == expected, 'catalogue changed')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate catalogue key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    need(value['schema'] == 1 and value['scope'] == SCOPE and value['holds_preserved'] is True,
         'wrong catalogue scope')
    files = value['files']
    need(type(files) is dict and 0 < len(files) <= 512, 'finite notice file set required')
    for name, row in files.items():
        p = PurePosixPath(name)
        need(type(name) is str and len(name) <= 512 and '\\' not in name and p.as_posix() == name
             and p.parts[:2] == ('rustc-1.99.0-src', 'vendor') and len(p.parts) >= 4
             and all(part not in ('', '.', '..') for part in p.parts), 'unsafe notice member')
        need(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE
             and type(row['sha256']) is str and len(row['sha256']) == 64
             and all(c in '0123456789abcdef' for c in row['sha256']), 'invalid notice file pin')
    grants = value.get('retained_upstream_grant_bodies', {})
    need(type(grants) is dict and len(grants) <= 128, 'finite retained grant set required')
    for digest, row in grants.items():
        need(type(row['text']) is str and type(row.get('path', row.get('file'))) is str, 'retained grant text/provenance required')
        raw_grant = row['text'].encode('utf-8')
        need(0 < len(raw_grant) <= MAX_FILE and pin(raw_grant) == {k: row[k] for k in ('bytes', 'sha256')}
             and row['sha256'] == digest, 'retained grant bytes changed')
    referenced = {digest for component in value['components']
                  for digest in component.get('retained_exact_upstream_grant_bodies', [])}
    need(referenced == set(grants), 'complete retained grant component provenance required')
    need(sum(row['bytes'] for row in files.values()) + sum(row['bytes'] for row in grants.values()) <= MAX_TOTAL,
         'notice aggregate cap')
    return value, raw


def collect(archive, value):
    """Authenticate the whole archive, then read selected regular members without extraction."""
    stream, before = open_input(archive, MAX_ARCHIVE)
    with stream:
        h = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024**2), b''):
            h.update(chunk)
        need(dict(bytes=before.st_size, sha256=h.hexdigest()) == value['source_archive'], 'source archive changed')
        stream.seek(0)
        selected, total, count = {}, 0, 0
        with tarfile.open(fileobj=stream, mode='r|xz') as tar:
            for member in tar:
                count += 1
                need(count <= 1000000, 'archive member cap')
                if member.name not in value['files']:
                    continue
                need(member.name not in selected and member.isfile() and not member.issparse(), 'duplicate/nonregular notice member')
                row = value['files'][member.name]
                need(member.size == row['bytes'] <= MAX_FILE, 'notice member size changed')
                with tar.extractfile(member) as source:
                    raw = source.read(MAX_FILE + 1)
                need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'notice member changed')
                # Context lines are descriptive DATA; the entire authentic file is retained.
                for context in row['contexts']:
                    first, last = context['lines']
                    need(type(first) is int and type(last) is int and 1 <= first <= last,
                         'invalid context lines')
                    actual = b''.join(raw.splitlines(keepends=True)[first-1:last])
                    need(actual == context['text'].encode('utf-8'), 'catalogued context differs from source')
                selected[member.name] = raw
                total += len(raw)
                need(total <= MAX_TOTAL, 'notice aggregate cap')
        need(set(selected) == set(value['files']), 'notice member missing')
        need(identity(before) == identity(os.fstat(stream.fileno())), 'archive changed while reading')
    return selected


def stage(archive, catalogue_path, destination, expected):
    value, raw_catalogue = catalogue(catalogue_path, expected)
    selected = collect(archive, value)
    destination = Path(destination)
    need(destination.is_absolute() and destination.parent.resolve() == destination.parent
         and not os.path.lexists(destination), 'fresh canonical notice destination required')
    bodies = {hashlib.sha256(raw).hexdigest(): raw for raw in selected.values()}
    grants = value.get('retained_upstream_grant_bodies', {})
    for digest, row in grants.items():
        bodies[digest] = row['text'].encode('utf-8')
    # No source-provided name is used as an output path.
    destination.mkdir(mode=0o755)
    (destination / 'bodies').mkdir(mode=0o755)
    for digest, raw in sorted(bodies.items()):
        path = destination / 'bodies' / (digest + '.txt')
        path.write_bytes(raw)
        path.chmod(0o644)
    index = dict(scope=SCOPE, holds_preserved=True, source_archive=value['source_archive'],
                 catalogue_sha256=pin(raw_catalogue)['sha256'],
                 copyright_ownership_inferred=False, manifest_authors_are_owners=False,
                 retained_grants={digest: dict(bytes=row['bytes'], sha256=row['sha256'],
                     retained_evidence_path=row.get('path', row.get('file')),
                     retained_evidence={key: value for key, value in row.items() if key != 'text'},
                     body='bodies/' + digest + '.txt',
                     components=[component['component'] for component in sorted(value['components'], key=lambda c: c['component'])
                                 if digest in component.get('retained_exact_upstream_grant_bodies', [])],
                     scope=value['grant_scope']) for digest, row in sorted(grants.items())},
                 paths={name: dict(**pin(raw), body='bodies/' + pin(raw)['sha256'] + '.txt')
                        for name, raw in sorted(selected.items())})
    for name, raw in [('index.json', encode(index)), ('catalogue.DATA.json', raw_catalogue)]:
        path = destination / name
        path.write_bytes(raw)
        path.chmod(0o644)
    return index
