#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently compare every serialized staging node to its bound manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

CHUNK = 65536


def need(value, reason):
    if not value:
        raise ValueError(reason)


def hashed(stream, size):
    count, digest = 0, hashlib.sha256()
    while True:
        raw = stream.read(CHUNK)
        if not raw:
            break
        count += len(raw)
        need(count <= size, 'body-overrun')
        digest.update(raw)
    need(count == size, 'body-size')
    return digest.hexdigest()


def verify(directory):
    directory = Path(directory)
    need(not (directory / 'INCOMPLETE.json').exists(), 'incomplete-run')
    receipt = json.loads((directory / 'receipt.json').read_bytes())
    need(receipt['status'] == 'PASS_EXACT_SELECTED_ARCHIVES_TO_STAGING_ONLY', 'receipt-status')
    raw_manifest = (directory / 'assembly.json').read_bytes()
    need(len(raw_manifest) <= 256 * 1024**2 and
         hashlib.sha256(raw_manifest).hexdigest() == receipt['manifest_sha256'], 'manifest-digest')
    manifest = json.loads(raw_manifest)
    nodes, seen, counts = manifest['output_nodes'], set(), {}
    epoch = manifest['source_date_epoch']
    need(len(nodes) <= 500000 and manifest['config_deltas'] == [], 'pristine-only-closure')
    need(manifest['archive_authentication'] == receipt['archive_authentication'] and
         manifest['inert_separation'] == receipt['separation'], 'separate-authority-binding')
    need(all(not path.startswith('.') for path in nodes), 'root-control-in-payload')
    need(set(manifest['output_ownership']) == set(nodes) and
         set(manifest['pristine']['nodes']) == set(nodes), 'ownership-path-closure')
    with (directory / 'staging.tar').open('rb') as source:
        need(hashed(source, receipt['bundle']['bytes']) == receipt['bundle']['sha256'], 'bundle-digest')
        source.seek(0)
        with tarfile.open(fileobj=source, mode='r|') as archive:
            for item in archive:
                name = item.name
                need(name not in seen and len(seen) <= 500003, 'duplicate-or-excess-member')
                seen.add(name)
                need(item.mtime == epoch and item.uname == item.gname == '', 'normalized-header')
                if name in ('rootfs', 'metadata'):
                    need(item.isdir() and (item.mode, item.uid, item.gid) == (0o755, 0, 0), 'root-header')
                    continue
                if name == 'metadata/assembly.json':
                    need(item.isfile() and (item.mode, item.uid, item.gid) == (0o644, 0, 0), 'manifest-header')
                    need(item.size == len(raw_manifest), 'embedded-manifest-size')
                    with archive.extractfile(item) as body:
                        need(hashed(body, item.size) == receipt['manifest_sha256'], 'embedded-manifest-binding')
                    continue
                need(name.startswith('rootfs/'), 'bundle-layout')
                path = name[len('rootfs/'):]
                need(path in nodes, 'unexpected-payload-path')
                node = nodes[path]
                kind = node['type']
                need((item.mode, item.uid, item.gid) == (node['mode'], node['uid'], node['gid']),
                     'payload-mode-owner')
                types = {'file': item.isfile, 'directory': item.isdir,
                         'symlink': item.issym, 'hardlink': item.islnk}
                need(types[kind](), 'payload-type')
                if kind == 'file':
                    need(item.size == node['bytes'], 'payload-size')
                    with archive.extractfile(item) as body:
                        need(hashed(body, item.size) == node['sha256'], 'payload-content')
                else:
                    need(item.size == 0, 'nonfile-body')
                    if kind in ('symlink', 'hardlink'):
                        prefix = 'rootfs/' if kind == 'hardlink' else ''
                        need(item.linkname == prefix + node['target'], 'payload-link')
                    if kind == 'hardlink':
                        target = nodes[node['target']]
                        need(target['type'] == 'file' and all(node[k] == target[k]
                             for k in ('mode', 'uid', 'gid')), 'hardlink-metadata')
                need(manifest['pristine']['nodes'][path] == node and
                     manifest['output_ownership'][path]['package_owners'] ==
                     manifest['pristine']['owners'][path], 'pristine-owner-binding')
                counts[kind] = counts.get(kind, 0) + 1
    need(seen == {'rootfs', 'metadata', 'metadata/assembly.json'} |
         {'rootfs/' + path for path in nodes}, 'serialized-path-closure')
    return dict(status='PASS_EVERY_SERIALIZED_NODE_AND_BODY', nodes=len(nodes), counts=counts,
                bundle=receipt['bundle'], manifest_sha256=receipt['manifest_sha256'],
                archive_bytes_reauthenticated_by_verifier=False, hardware_image_accepted=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), sort_keys=True))
