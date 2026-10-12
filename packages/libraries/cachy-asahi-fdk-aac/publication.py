#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Pack/reconstruct complete selected corresponding-source inputs; no build/publish."""
import argparse
import gzip
import io
import json
from pathlib import Path
import shutil
import tarfile
from source_check import HERE, PACKET, load_map, read_regular, repository_roots, safe_name, sha, template_files, verify_packet

ROOT = 'cachy-asahi-fdk-aac-3.0.0-source/'
EPOCH = 1791748800


def external_new(output):
    requested = Path(output)
    output = requested.resolve()
    roots = repository_roots(HERE)
    if any(output.is_relative_to(p) for p in roots) or output.exists() or requested.is_symlink():
        raise ValueError('output must be new and outside the repository/template')
    return output


def pack(recipe, output, reviewed_inputs, reviewed_sha256):
    output = external_new(output)
    inputs = template_files(recipe)
    if PACKET not in inputs:
        raise ValueError('materialized selected source archive required')
    approved = read_regular(reviewed_inputs, 65536)
    if sha(approved) != reviewed_sha256 or load_map(approved) != {n: sha(b) for n, b in inputs.items()}:
        raise ValueError('complete recipe differs from independently reviewed source map')
    verify_packet(Path(recipe) / PACKET)
    entries = {ROOT + 'recipe/' + n: b for n, b in inputs.items()}
    entries[ROOT + 'SOURCE-MAP.json'] = approved
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=buf, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(entries.items()):
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(data), 0o644, EPOCH
                member.uid = member.gid = 0
                archive.addfile(member, io.BytesIO(data))
    data = buf.getvalue()
    with output.open('xb') as stream:
        stream.write(data)
    return {'schema_version': 1, 'packet_sha256': sha(data), 'packet_bytes': len(data),
            'source_map_sha256': sha(approved), 'recipe_files': len(inputs),
            'scope': 'complete selected two-library implementation + original project build/package/test/reconstruction inputs',
            'codec_files': 900, 'private_full_archive_included': False,
            'native_build': 'NOT RUN', 'publication': 'NOT RUN', 'patent_clearance': 'NOT CLAIMED'}


def read_bundle(path, packet_sha256, map_sha256):
    data = read_regular(path, 8 * 1024 * 1024)
    if sha(data) != packet_sha256:
        raise ValueError('publication packet differs from trusted digest')
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as compressed:
        unpacked = compressed.read(16 * 1024 * 1024 + 1)
    if len(unpacked) > 16 * 1024 * 1024:
        raise ValueError('publication tar exceeds expanded size bound')
    files, seen, total, approved = {}, set(), 0, None
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r:') as archive:
        for member in archive:
            safe_name(member.name)
            if member.name in seen or len(seen) >= 128:
                raise ValueError('duplicate/excess publication members')
            seen.add(member.name)
            if member.pax_headers or member.type != tarfile.REGTYPE or member.mode != 0o644 or member.uid != 0 or member.gid != 0:
                raise ValueError('publication members must be regular reviewed files')
            if not 0 <= member.size <= 8 * 1024 * 1024:
                raise ValueError('oversized publication member')
            total += member.size
            if total > 8 * 1024 * 1024:
                raise ValueError('publication packet exceeds expanded size bound')
            with archive.extractfile(member) as stream:
                content = stream.read(member.size + 1)
            if len(content) != member.size:
                raise ValueError('truncated publication member')
            if member.name == ROOT + 'SOURCE-MAP.json':
                if len(content) > 65536:
                    raise ValueError('oversized source map')
                approved = content
            elif member.name.startswith(ROOT + 'recipe/'):
                name = member.name.removeprefix(ROOT + 'recipe/')
                if len(safe_name(name)) != 1:
                    raise ValueError('flat recipe inputs required')
                files[name] = content
            else:
                raise ValueError('unexpected publication file')
    if approved is None or sha(approved) != map_sha256:
        raise ValueError('source map differs from trusted digest')
    mapping = load_map(approved)
    if mapping != {n: sha(b) for n, b in files.items()} or not {PACKET, 'PKGBUILD', '.SRCINFO'} <= set(files):
        raise ValueError('publication recipe incomplete or changed')
    return files


def reconstruct(path, output, packet_sha256, map_sha256):
    output = external_new(output)
    files = read_bundle(path, packet_sha256, map_sha256)
    output.mkdir(parents=True, exist_ok=False)
    try:
        for name, data in files.items():
            with (output / name).open('xb') as stream:
                stream.write(data)
            (output / name).chmod(0o644)
        if template_files(output) != files:
            raise ValueError('reconstructed source inputs differ')
        verify_packet(output / PACKET)
        return {'status': 'reconstructed-source-only', 'recipe': str(output),
                'input_sha256': {n: sha(b) for n, b in sorted(files.items())},
                'native_build': 'NOT RUN', 'installation': 'NOT RUN', 'publication': 'NOT RUN'}
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    pack_parser = sub.add_parser('pack')
    pack_parser.add_argument('--recipe', type=Path, required=True)
    pack_parser.add_argument('--output', type=Path, required=True)
    pack_parser.add_argument('--reviewed-inputs', type=Path, required=True)
    pack_parser.add_argument('--reviewed-inputs-sha256', required=True)
    reconstruct_parser = sub.add_parser('reconstruct')
    reconstruct_parser.add_argument('--archive', type=Path, required=True)
    reconstruct_parser.add_argument('--output', type=Path, required=True)
    reconstruct_parser.add_argument('--archive-sha256', required=True)
    reconstruct_parser.add_argument('--map-sha256', required=True)
    args = parser.parse_args()
    try:
        result = pack(args.recipe, args.output, args.reviewed_inputs, args.reviewed_inputs_sha256) if args.command == 'pack' else reconstruct(args.archive, args.output, args.archive_sha256, args.map_sha256)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
