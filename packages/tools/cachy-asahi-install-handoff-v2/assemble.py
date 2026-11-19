#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize the opt-in install-handoff 0.1.0-2 recipe from local Git objects."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile


ORIGINAL = '282364173f497f1052267c3901dda395dd59e03f'
SOURCE = '8f736cd4954b24b80fdb58c9d39ea5bea4407c54'
OLD_RECIPE = 'packages/tools/cachy-asahi-install-handoff/'
HERE = Path(__file__).resolve().parent
INPUTS = (
    'private-source.tar.gz', 'check-source.tar.gz', 'cachy-asahi-install-handoff',
    'test_package.py', 'check_sources.py', 'README.md', 'source-provenance.json',
    'payload-map.json', 'NOTICE', 'LICENSE',
)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return dict(size=len(raw), sha256=sha(raw))


def file_pin(raw, mode=0o644):
    return dict(bytes=len(raw), sha256=sha(raw), mode=mode)


def git_body(root, revision, name):
    return subprocess.check_output(
        ['git', '--no-replace-objects', '-C', str(root), 'show', revision + ':' + name],
        timeout=20,
    )


def replace_once(raw, old, new):
    if raw.count(old) != 1:
        raise ValueError('frozen recipe marker changed: ' + old.decode())
    return raw.replace(old, new, 1)


def archive(prefix, files):
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode='wb', mtime=0) as compressor:
        with tarfile.open(fileobj=compressor, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(files.items()):
                member = tarfile.TarInfo(prefix + '/' + name)
                member.mode = 0o644
                member.size = len(raw)
                tar.addfile(member, io.BytesIO(raw))
    return result.getvalue()


def snapshot(root, original):
    generated = {'source-lock.json', 'runtime.json'}
    runtime_roster, check_roster = set(original['runtime_files']), set(original['check_files'])
    source = {name: git_body(root, SOURCE, name) for name in sorted(check_roster - generated)}
    refs = {name: pin(source[name]) for name in original['interface_witnesses']}
    source['source-lock.json'] = encoded(dict(
        schema_version=1, purpose='fresh-handoff-owning-source-witnesses',
        source_commit=SOURCE, source_refs=refs,
    ))
    runtime = {name: source[name] for name in sorted(runtime_roster - {'runtime.json'})}
    source['runtime.json'] = runtime['runtime.json'] = encoded(dict(
        schema_version=1, purpose='finite-fresh-handoff-operator-runtime',
        source_commit=SOURCE, files={name: pin(raw) for name, raw in runtime.items()},
    ))
    return runtime, source


def recipe_files(root):
    def old(name):
        return git_body(root, ORIGINAL, OLD_RECIPE + name)

    original = json.loads(old('source-provenance.json'))
    runtime, checks = snapshot(root, original)
    out = {
        'private-source.tar.gz': archive('private', runtime),
        'check-source.tar.gz': archive('checks', checks),
        'cachy-asahi-install-handoff': old('cachy-asahi-install-handoff'),
        'test_package.py': old('test_package.py'),
        'check_sources.py': replace_once(old('check_sources.py'), original['source_revision'].encode(), SOURCE.encode()),
        'README.md': (HERE / 'README.md').read_bytes(),
        'NOTICE': old('NOTICE'),
        'LICENSE': runtime['LICENSE'],
    }
    provenance = dict(
        original, version='0.1.0-2', source_revision=SOURCE, recipe_predecessor=ORIGINAL,
        source_authority='Exact selected Git bodies plus generated source and runtime receipts',
        runtime_sha256=sha(runtime['runtime.json']),
        runtime_files={name: file_pin(raw) for name, raw in runtime.items()},
        check_files={name: file_pin(raw) for name, raw in checks.items()},
    )
    for role in ('source_archive', 'check_source_archive'):
        name = original[role]['path']
        provenance[role] = dict(path=name, bytes=len(out[name]), sha256=sha(out[name]))
    out['source-provenance.json'] = encoded(provenance)
    payload = json.loads(old('payload-map.json'))
    for name, mode in payload['files'].items():
        relative = name.removeprefix('usr/lib/cachy-asahi/install-handoff/')
        raw = runtime[relative] if relative != name else out[name.rsplit('/', 1)[-1]]
        payload['files'][name] = file_pin(raw, mode['mode'])
    out['payload-map.json'] = encoded(payload)
    for name, marker in (('PKGBUILD', b'pkgrel=1'), ('.SRCINFO', b'pkgrel = 1')):
        raw = replace_once(old(name), marker, marker[:-1] + b'2')
        for leaf in INPUTS:
            raw = replace_once(raw, sha(old(leaf)).encode(), sha(out[leaf]).encode())
        out[name] = raw
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.git_root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    if output.is_relative_to(root) or output.exists() or output.is_symlink():
        parser.error('fresh output outside the source checkout required')
    files = recipe_files(root)
    output.mkdir(mode=0o700)
    written = []
    try:
        for name, raw in files.items():
            path = output / name
            with path.open('xb') as stream:
                written.append(path)
                stream.write(raw)
    except BaseException:
        for path in written:
            path.unlink()
        output.rmdir()
        raise
    print(json.dumps(dict(output=str(output), version='0.1.0-2',
                          source=SOURCE, runtime_sha256=json.loads(files['source-provenance.json'])['runtime_sha256']),
                     sort_keys=True))


if __name__ == '__main__':
    main()
