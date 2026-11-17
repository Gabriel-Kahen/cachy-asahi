#!/usr/bin/env python3
"""Read-only offline validation of the two original source-provider materials."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

HERE = Path(__file__).resolve().parent


def validate(cache):
    results = []
    for name in ('llhttp', 'libgit2'):
        recipe = HERE.parent / f'cachy-asahi-{name}-reference'
        pin = json.loads((recipe / 'source.json').read_text())
        source = pin['source']
        archive = cache / source['filename']
        if archive.is_symlink() or not archive.is_file():
            raise ValueError(f'{name}: source must be a regular, non-symlink file')
        if archive.stat().st_size != source['bytes']:
            raise ValueError(f'{name}: source length differs')
        with archive.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != source['sha256']:
                raise ValueError(f'{name}: source checksum differs')
        prefix = source['archive_prefix']
        with tarfile.open(archive, 'r:gz') as bundle:
            members = bundle.getmembers()
            seen = set()
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or path.parts[0] != prefix:
                    raise ValueError(f'{name}: unsafe archive path')
                if member.name in seen:
                    raise ValueError(f'{name}: duplicate archive member')
                seen.add(member.name)
                if member.issym():
                    expected = f'{prefix}/tests/resources/testrepo-worktree/link_to_new.txt'
                    if name != 'libgit2' or member.name != expected or member.linkname != 'new.txt':
                        raise ValueError(f'{name}: unexpected source symlink')
                elif not (member.isdir() or member.isfile()):
                    raise ValueError(f'{name}: unsupported archive entry type')
            required = ('CMakeLists.txt', 'LICENSE-MIT', 'src/llhttp.c', 'src/http.c',
                        'src/api.c', 'include/llhttp.h') if name == 'llhttp' else (
                        'CMakeLists.txt', 'COPYING', 'AUTHORS', 'tests/clar/generate.py',
                        'tests/libgit2/CMakeLists.txt', 'cmake/SelectHTTPParser.cmake')
            for path in required:
                item = bundle.getmember(f'{prefix}/{path}')
                if not item.isfile() or not item.size:
                    raise ValueError(f'{name}: absent/empty required source {path}')
            if name == 'llhttp':
                header = bundle.extractfile(f'{prefix}/include/llhttp.h').read()
                for key, value in (('MAJOR', 9), ('MINOR', 3), ('PATCH', 1)):
                    if f'#define LLHTTP_VERSION_{key} {value}'.encode() not in header:
                        raise ValueError('llhttp: generated header version mismatch')
                if any(f'{prefix}/{path}' in seen for path in ('package.json', 'package-lock.json')):
                    raise ValueError('llhttp: expected generated C release, not npm generator tree')
        results.append({'package': name, 'sha256': source['sha256'],
                        'bytes': source['bytes'], 'members': len(members), 'status': 'PASS'})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps({'scope': 'source material only; no compilation, signature or hardware claim',
                          'results': validate(args.cache)}, indent=2))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(2, f'source validation failed: {error}\n')


if __name__ == '__main__':
    main()
