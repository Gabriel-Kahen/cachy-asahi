#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Create an exact grant-scoped codec packet; no extraction/build/publication."""
import argparse
import io
import json
from pathlib import Path
import tarfile
import urllib.request
from urllib.parse import urlparse
from source_check import HERE, NOTICES, PACKET_BYTES, PACKET_SHA, PREFIX, SELECTED_LIMIT, read_selected_packet, read_regular, repository_roots, safe_name, sha

PRIVATE_SHA = '1244e51941011bb63433b022f8bc247a28cf374749a2c3fb30f73fae42c88c49'
UPSTREAM_SHA = 'ac9682b35f6e5f75e1f008a5ba2636ba6c9c77c70b78377b53992559e8bda806'
UPSTREAM_URL = 'https://codeload.github.com/mstorsjo/fdk-aac/tar.gz/a68a51aa45d86a43c7b228e3d45624af09dcdd8d'
UPSTREAM_PREFIX = 'fdk-aac-a68a51aa45d86a43c7b228e3d45624af09dcdd8d/'
EPOCH = 1791748800


def fetch_upstream():
    request = urllib.request.Request(UPSTREAM_URL, headers={'User-Agent': 'cachy-asahi-source-check/1'})
    with urllib.request.urlopen(request, timeout=30) as response:
        target = urlparse(response.geturl())
        if target.scheme != 'https' or target.hostname != 'codeload.github.com':
            raise ValueError('upstream transport redirected outside the pinned source host')
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) != 4707099 or sha(data) != UPSTREAM_SHA:
        raise ValueError('fetched upstream bytes differ from fixed commit archive')
    return data


def selected_data(data):
    layout = json.loads(read_regular(HERE / 'build-layout.json', 1024 * 1024))
    expected = dict(layout['selected_implementation_files'])
    expected['NOTICE'] = {'bytes': 4447, 'sha256': NOTICES['NOTICE.classic'][1]}
    expected['xhe-aac/NOTICE'] = {'bytes': 4721, 'sha256': NOTICES['NOTICE.xhe-aac'][1]}
    if len(expected) != 900:
        raise ValueError('selected inventory must contain 898 implementation files and two grants')
    digest = sha(data)
    if digest not in {PRIVATE_SHA, PACKET_SHA, UPSTREAM_SHA}:
        raise ValueError('input is not a pinned upstream, private or selected source packet')
    if digest == PACKET_SHA:
        if len(data) != PACKET_BYTES:
            raise ValueError('selected packet length differs from reviewed bytes')
    elif len(data) > 8 * 1024 * 1024:
        raise ValueError('original source packet exceeds size limit')
    prefix = UPSTREAM_PREFIX if digest == UPSTREAM_SHA else PREFIX
    result, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:' if digest == PACKET_SHA else 'r:gz') as archive:
        for member in archive:
            safe_name(member.name)
            if len(seen) >= 4096:
                raise ValueError('too many source members')
            if member.name in seen:
                raise ValueError('duplicate source member')
            seen.add(member.name)
            if member.isdir():
                continue
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not member.name.startswith(prefix):
                raise ValueError('invalid source member')
            if not 0 <= member.size <= 8 * 1024 * 1024:
                raise ValueError('source member exceeds size limit')
            total += member.size
            if total > 32 * 1024 * 1024:
                raise ValueError('source exceeds expanded size limit')
            name = member.name[len(prefix):]
            if name not in expected:
                if digest in {PRIVATE_SHA, UPSTREAM_SHA}:
                    continue  # Never copy unselected private scaffolding/assets.
                raise ValueError('unselected file in selected packet')
            row = expected[name]
            if member.size != row['bytes'] or not 0 <= member.size <= 8 * 1024 * 1024:
                raise ValueError('selected member size mismatch: ' + name)
            with archive.extractfile(member) as stream:
                content = stream.read(member.size + 1)
            if len(content) != member.size or sha(content) != row['sha256']:
                raise ValueError('selected source bytes changed: ' + name)
            if name not in {'NOTICE', 'xhe-aac/NOTICE'} and (
                    b'Fraunhofer' not in content or
                    b'Redistribution and use in source and binary forms' not in content):
                raise ValueError('selected source grant absent: ' + name)
            result[name] = content
    if set(result) != set(expected):
        raise ValueError('selected source inventory incomplete')
    return result


def source_input(archive_path):
    # Large inputs can only enter as exact fixed-length/digest selected raw tar.
    path = Path(archive_path)
    if path.lstat().st_size > 8 * 1024 * 1024:
        if path.lstat().st_size != PACKET_BYTES:
            raise ValueError('original source packet exceeds size limit')
        return read_selected_packet(path)
    return read_regular(path, 8 * 1024 * 1024)


def selected_bytes(archive_path):
    return selected_data(source_input(archive_path))


def build_archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            safe_name(name)
            member = tarfile.TarInfo(PREFIX + name)
            member.size, member.mode, member.mtime = len(data), 0o644, EPOCH
            member.uid = member.gid = 0
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def create_codec_packet(private_archive, output):
    requested = Path(output)
    output = requested.resolve()
    roots = repository_roots(HERE)
    if any(output.is_relative_to(p) for p in roots) or output.exists() or requested.is_symlink():
        raise ValueError('output must be new and outside the repository')
    original = fetch_upstream() if private_archive is None else source_input(private_archive)
    files = selected_data(original)
    data = build_archive(files)
    if len(data) != PACKET_BYTES or len(data) > SELECTED_LIMIT or sha(data) != PACKET_SHA:
        raise ValueError('reconstructed packet differs from pinned selected digest')
    with output.open('xb') as stream:
        stream.write(data)
    return {'schema_version': 1, 'source_commit': 'a68a51aa45d86a43c7b228e3d45624af09dcdd8d',
            'files': len(files), 'packet_bytes': len(data), 'packet_sha256': sha(data),
            'producer_input_sha256': sha(original),
            'input_sha256': {n: {'bytes': len(b), 'sha256': sha(b)} for n, b in sorted(files.items())},
            'scope': 'selected codec implementation with recorded explicit grants; unchanged source bytes',
            'upstream_scaffold_copied': False, 'codec_source_modifications': [],
            'native_build': 'NOT RUN', 'publication': 'NOT RUN', 'patent_clearance': 'NOT CLAIMED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--input', type=Path)
    inputs.add_argument('--fetch-upstream', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(create_codec_packet(args.input, args.output), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
