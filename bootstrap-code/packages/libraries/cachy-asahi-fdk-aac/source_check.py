#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Read-only verification of the exact grant-scoped codec source selection."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

HERE = Path(__file__).resolve().parent
COMMIT = 'a68a51aa45d86a43c7b228e3d45624af09dcdd8d'
PACKET = 'fdk-aac-3.0.0-selected-source.tar'
PACKET_SHA = '1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4'
PACKET_BYTES = 17387520
SELECTED_LIMIT = 20 * 1024 * 1024
MANIFEST_SHA = '3eb66e2e1632cf65044f9250c7460b1effe0de3217f83b573b4e23885772fc29'
PREFIX = 'fdk-aac-3.0.0/'
NOTICES = {'NOTICE.classic': ('NOTICE', '95ec80da40b4af12ad4c4f3158c9cfb80f2479f3246e4260cb600827cc8c7836'),
           'NOTICE.xhe-aac': ('xhe-aac/NOTICE', 'bf3e762249027586195def2b2e904901b42c8b7fab455fc66bf365f70d08de6d'),
           'COPYRIGHTS-and-LICENSES': (None, 'a0a52a99bef6dea5c370711f17ed1c02e8b0989a4c167f4e54a36368987428c0')}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_map(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate source map key')
            result[key] = value
        return result
    mapping = json.loads(data, object_pairs_hook=unique)
    if type(mapping) is not dict or not all(type(n) is str and len(safe_name(n)) == 1 and
            type(h) is str and re.fullmatch(r'[0-9a-f]{64}', h) for n, h in mapping.items()):
        raise ValueError('invalid source map')
    return mapping


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('input must be a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('input exceeds size limit')
        return data
    finally:
        os.close(fd)


def read_selected_packet(path):
    """Only the explicitly selected packet gets the larger finite storage cap."""
    data = read_regular(path, SELECTED_LIMIT)
    if len(data) != PACKET_BYTES or sha(data) != PACKET_SHA:
        raise ValueError('selected packet differs from reviewed bytes')
    return data


def repository_roots(base):
    """Recognize Git structure, including worktree gitdir/commondir pointers.

    A stray .git marker alone is not a worktree. No Git command/hook executes.
    """
    base = Path(base).resolve()
    roots = [base]
    for parent in base.parents:
        marker = parent / '.git'
        try:
            if marker.is_dir():
                gitdir = marker.resolve()
            elif marker.is_file():
                text = read_regular(marker, 4096).decode().strip()
                if not text.startswith('gitdir: '):
                    continue
                gitdir = (parent / text[8:]).resolve()
            else:
                continue
            head = read_regular(gitdir / 'HEAD', 4096).decode().strip()
            if not (re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', head) or
                    head.startswith('ref: refs/') and len(head) > 10 and
                    not any(c.isspace() for c in head[5:]) and '..' not in head):
                continue
            common = gitdir
            if (gitdir / 'commondir').is_file():
                common = (gitdir / read_regular(gitdir / 'commondir', 4096).decode().strip()).resolve()
            if (common / 'objects').is_dir() and (common / 'refs').is_dir():
                roots.append(parent)
        except (OSError, ValueError, UnicodeError):
            continue
    return roots


def safe_name(name):
    if not isinstance(name, str) or '\\' in name or any(ord(c) < 32 for c in name):
        raise ValueError('unsafe archive path')
    parts = name.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('unsafe archive path')
    return parts


def audit_members(archive, expected):
    """Inspect bytes without extracting or executing any archive member."""
    ancestors = {'fdk-aac-3.0.0'}
    for name in expected:
        parts = safe_name(name)
        ancestors.update('fdk-aac-3.0.0/' + '/'.join(parts[:i]) for i in range(1, len(parts)))
    seen, files, total = set(), set(), 0
    for member in archive:
        if len(seen) >= 4096:
            raise ValueError('too many archive members')
        name = member.name
        safe_name(name)
        if name in seen:
            raise ValueError('duplicate archive member')
        seen.add(name)
        if member.isdir():
            if name not in ancestors:
                raise ValueError('unexpected directory')
            continue
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not name.startswith(PREFIX):
            raise ValueError('only rooted regular source files/directories allowed')
        relative = name[len(PREFIX):]
        if relative not in expected:
            raise ValueError('unexpected source file')
        row = expected[relative]
        if member.size != row['bytes'] or not 0 <= member.size <= 8 * 1024 * 1024:
            raise ValueError('source member size mismatch')
        total += member.size
        if total > 32 * 1024 * 1024:
            raise ValueError('source packet exceeds expanded size limit')
        stream = archive.extractfile(member)
        with stream:
            data = stream.read(member.size + 1)
        if len(data) != member.size or sha(data) != row['sha256']:
            raise ValueError('source member digest mismatch')
        files.add(relative)
    if files != set(expected):
        raise ValueError('source file set incomplete')
    return {'files': len(files), 'bytes': total}


def verify_packet(path, manifest_path=HERE / 'selected-source-manifest.json'):
    manifest_bytes = read_regular(manifest_path, 1024 * 1024)
    if sha(manifest_bytes) != MANIFEST_SHA:
        raise ValueError('selected manifest differs from reviewed bytes')
    manifest = json.loads(manifest_bytes)
    if manifest['source_commit'] != COMMIT or manifest['codec_source_modifications']:
        raise ValueError('unexpected source revision/modifications')
    expected = manifest['included_files']
    if len(expected) != 900:
        raise ValueError('unexpected source inventory')
    for _, (source, checksum) in NOTICES.items():
        if source and expected[source]['sha256'] != checksum:
            raise ValueError('source grant differs from reviewed bytes')
    data = read_selected_packet(path)
    if len(data) != PACKET_BYTES or sha(data) != PACKET_SHA:
        raise ValueError('selected packet differs from reviewed bytes')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        report = audit_members(archive, expected)
    return {**report, 'source_commit': COMMIT, 'packet_sha256': PACKET_SHA,
            'status': 'source-packet-pass', 'native_build': 'NOT RUN',
            'source_rights_scope': 'recorded explicit grants for selected codec; private full archive excluded',
            'publication': 'NOT RUN', 'patent_clearance': 'NOT CLAIMED'}


def template_files(base=HERE):
    """Bind local assets to reviewed .SRCINFO without evaluating shell code."""
    base = Path(base)
    fields = {}
    for line in read_regular(base / '.SRCINFO', 65536).decode().splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*([a-zA-Z0-9_]+) = (.*)', line)
        if not match:
            raise ValueError('invalid metadata line')
        fields.setdefault(match[1], []).append(match[2])
    names, sums = fields.get('source', []), fields.get('sha256sums', [])
    if len(names) != len(sums) or len(set(names)) != len(names) or PACKET not in names:
        raise ValueError('invalid local source bindings')
    expected_names = set(names) | {'PKGBUILD', '.SRCINFO'}
    actual = {p.name for p in base.iterdir()}
    if actual not in (expected_names, expected_names - {PACKET}):
        raise ValueError('unexpected/missing template file set')
    result = {}
    for name in sorted(actual):
        if len(safe_name(name)) != 1:
            raise ValueError('flat local sources required')
        result[name] = read_selected_packet(base / name) if name == PACKET else read_regular(base / name, 8 * 1024 * 1024)
    for name, checksum in zip(names, sums):
        if not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise ValueError('source requires a fixed SHA256')
        if name == PACKET:
            if checksum != PACKET_SHA:
                raise ValueError('recipe does not pin reviewed packet')
        elif name not in result or sha(result[name]) != checksum:
            raise ValueError('local source changed: ' + name)
    for name, (_, checksum) in NOTICES.items():
        if sha(result[name]) != checksum:
            raise ValueError('binary grant changed: ' + name)
    if sha(result['selected-source-manifest.json']) != MANIFEST_SHA:
        raise ValueError('manifest changed')
    if PACKET in result and sha(result[PACKET]) != PACKET_SHA:
        raise ValueError('materialized archive changed')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify_packet(args.archive), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
