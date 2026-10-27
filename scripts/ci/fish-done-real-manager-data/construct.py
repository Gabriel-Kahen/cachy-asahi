#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only offline context constructor; never invokes a build or native actor."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

HERE = Path(__file__).resolve().parent
DELIVERY = 'artifacts/development/fish-done-real-notification-development-20261027/proposed/scripts/diagnostics/fish-done-real-notifications'
DONE = 'artifacts/development/expanded-candidate-inputs-20261016/payload/packages/cachy-asahi-fish-done-a/cachy-asahi-fish-done-0.1.0-2-any.pkg.tar.xz'
DONE_SHA = '9ce3c7ba89467f04660014c1b12056dce28bd0c4e69b4cab8a9c2c98e1cce54f'
STYLE = 'packages/desktop/cachy-asahi-hyprland-settings/mako.conf'
STYLE_SHA = 'c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()


def read(path, digest, limit):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'absolute non-symlink input required')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022 and
         before.st_size <= limit, 'bounded ordinary single-link input required')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'input replaced before open')
        raw = stream.read(limit+1)
    after = path.lstat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
         len(raw) == before.st_size and sha(raw) == digest, 'input hash or identity drift')
    return raw


def archive(raw, row, destination=None):
    """Strict plain-member extraction; preserved source bytes and MIT files."""
    result, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as stream:
        for member in stream:
            name = member.name
            path = PurePosixPath(name)
            need(name not in seen and name.rstrip('/') == path.as_posix() and
                 not path.is_absolute() and '..' not in path.parts and
                 path.parts[0] == row['strip_prefix'] and (member.isdir() or member.isfile()) and
                 not member.mode & 0o7000 and member.pax_headers == row.get('pax_headers', {}),
                 'unsafe/duplicate source archive member')
            need(member.isdir() or len(path.parts) > 1, 'source root must be a directory')
            seen.add(name)
            relative = Path(*path.parts[1:])
            need('.git' not in relative.parts, 'source repository metadata refused')
            if member.isdir():
                if destination is not None:
                    (destination/relative).mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            need(member.size <= 16*1024**2 and total <= 32*1024**2 and len(seen) <= 2048,
                 'source archive decoded cap')
            data = stream.extractfile(member).read(member.size+1)
            need(len(data) == member.size, 'source archive member length differs')
            result[str(relative)] = dict(bytes=len(data), sha256=sha(data))
            if destination is not None:
                target = destination/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    output.write(data)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    need(len(seen) == row['members'] and total == row['decoded_bytes'] and
         'meson.build' in result and 'LICENSE' in result, 'complete pinned source tree required')
    return result


def make(source, output, validate_only=False):
    source, output = Path(source), Path(output)
    need(source.is_absolute() and output.is_absolute() and not any(p.is_symlink() for p in (output, *output.parents)),
         'absolute non-symlink source/output required')
    need(not output.exists() and output.parent.is_dir() and output.parent.stat().st_uid == os.getuid() and
         not output.parent.stat().st_mode & 0o022, 'fresh output under owned non-public parent required')
    lock = json.loads((HERE/'build.lock.json').read_bytes())
    ledger = read(source/lock['base']['ledger'], lock['base']['ledger_sha256'], 4*1024**2)
    packages = json.loads(ledger)['packages']
    inventory = ''.join(r['name']+' '+r['version']+'\n' for r in sorted(packages, key=lambda r:r['name'])).encode()
    need(len(packages) == len({r['name'] for r in packages}) == 574 and
         sha(inventory) == lock['base']['inventory_sha256'] and
         inventory == (HERE/'inventory574.lock').read_bytes(), 'known574 base inventory differs')
    files, trees = {}, {}
    for name, row in lock['sources'].items():
        raw = read(source/row['retained_path'], row['sha256'], 8*1024**2)
        need(len(raw) == row['bytes'], 'source archive length differs')
        trees[name] = archive(raw, row)
        files[row['filename']] = raw
    files['done.pkg.tar.xz'] = read(source/DONE, DONE_SHA, 65536)
    files['mako.conf'] = read(source/STYLE, STYLE_SHA, 4096)
    for name, digest in lock['delivery_files'].items():
        need(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
             'unsafe delivery source name')
        files['delivery/'+name] = read(source/DELIVERY/name, digest, 131072)
    for name in ('native_build.py', 'construct.py', 'build.lock.json', 'inventory574.lock', 'no-git.native', 'reserved_process.py'):
        files[name] = (HERE/name).read_bytes()
    receipt = dict(schema_version=1, status='PASS_DATA_ONLY_NATIVE_BUILD_CONTEXT',
        base=lock['base'], source_trees=trees,
        files={name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in sorted(files.items())},
        build='NOT_RUN', native_runtime='NOT_RUN', installed_delivery='NOT_RUN')
    if validate_only:
        return receipt
    output.mkdir(mode=0o700)
    for name, raw in files.items():
        target = output/name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o444)
    (output/'context.json').write_bytes(encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    value = make(args.source, args.output, args.validate_only)
    print(json.dumps(dict(status=value['status'], context_files=len(value['files']),
                         build=value['build'], output_created=not args.validate_only)))


if __name__ == '__main__':
    main()
