#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recheck held pins and dependency closure without package/native actors."""
import argparse
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
from contract import digest, verify_source

HERE = Path(__file__).resolve().parent


def check(source, cache=None):
    verify_source(source)
    proposal = json.loads((HERE / 'package-inputs.json').read_text())
    base = json.loads((source / proposal['base_lock']['path']).read_text())
    if digest(source / proposal['base_lock']['path']) != proposal['base_lock']['sha256']:
        raise ValueError('base pin differs')
    selected = {r['name']: r for r in base['packages']}
    if any(selected[r['name']] != r for r in proposal['closure_packages']):
        raise ValueError('closure pin differs')
    spec = importlib.util.spec_from_file_location('bar_preview', source / 'scripts/port/preview.py')
    preview = importlib.util.module_from_spec(spec);spec.loader.exec_module(preview)
    records = {r['name']: {'NAME': [r['name']], 'VERSION': [r['version']], 'ARCH': [r['arch']],
        'DEPENDS': r['depends'], 'PROVIDES': r['provides'], 'CONFLICTS': r['conflicts'],
        'REPLACES': r['replaces']} for r in selected.values()}
    with tempfile.TemporaryDirectory(dir=HERE) as directory:
        work = Path(directory);(work / 'root').mkdir()
        preview.write_local(work / 'db/local', records)
        edges, conflicts = preview.alpm_audit(work, records)
    if any(not e['provider'] for e in edges) or conflicts:
        raise ValueError('base dependency/version/conflict audit differs')
    byname = {n: [] for n in selected}
    for e in edges:
        byname[e['package']].append(e)
    queue = ['waybar', 'mako'];closure = set()
    while queue:
        name = queue.pop()
        if name not in closure:
            closure.add(name);queue.extend(e['provider'] for e in byname[name])
    if closure != {r['name'] for r in proposal['closure_packages']} or \
            [e for e in edges if e['package'] in closure] != proposal['dependency_edges']:
        raise ValueError('transitive dependency graph differs')
    evidence = proposal['signature_evidence']
    if digest(source / evidence['path']) != evidence['sha256']:
        raise ValueError('retained signature evidence differs')
    receipt = json.loads((source / evidence['path']).read_text())
    observations = {r['name']: r for r in receipt['packages']}
    for row in proposal['roots']:
        old = observations[row['name']]
        if old['archive_sha256'] != row['sha256'] or old['signature_sha256'] != row['signature_sha256'] \
                or old['gpg']['exit'] != 0:
            raise ValueError('root signature evidence differs')
        if cache is None:
            continue
        archive = cache / row['filename']
        for path, pin, size in ((archive, row['sha256'], row['size']),
                (cache / (row['filename'] + '.sig'), row['signature_sha256'], row['signature_size'])):
            if path.is_symlink() or path.stat().st_size != size or digest(path) != pin:
                raise ValueError('root bytes differ')
        with tarfile.open(archive) as package:
            fields = {}
            info = package.getmember('.PKGINFO')
            if info.size > 65536:
                raise ValueError('oversized package metadata')
            for line in package.extractfile(info).read().decode().splitlines():
                if not line.startswith('#') and ' = ' in line:
                    key, value = line.split(' = ', 1);fields.setdefault(key, []).append(value)
            if fields['pkgname'] != [row['name']] or fields['pkgver'] != [row['version']] \
                    or fields['arch'] != ['aarch64'] or fields['depend'] != row['depends']:
                raise ValueError('root package metadata differs')
            header = package.extractfile('usr/bin/' + row['name']).read(20)
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 183:
                raise ValueError('root executable is not AArch64 ELF')
    return dict(status='PASS_METADATA_AND_HELD_BYTES' if cache else 'PASS_METADATA',
                closure_packages=len(closure), dependency_edges=len(proposal['dependency_edges']),
                additive_packages=0, signatures='retained receipt matches; no new GPG execution',
                native_runtime='NOT_RUN', hardware='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.source.resolve(), args.cache.resolve() if args.cache else None), indent=2))
