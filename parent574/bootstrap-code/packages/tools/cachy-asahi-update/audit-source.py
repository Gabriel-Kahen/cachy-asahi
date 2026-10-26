#!/usr/bin/env python3
"""Create a deterministic, artwork-sanitized source input; never execute it."""
import argparse
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path, PurePosixPath

COMMIT = 'e2b1b7144be71cf392809f48d1440f8da1d9c81a'
ARCHIVE = 'b5e4ca8f2f779d1a877ab7a815cbb40a9a9cecf16ac59852eb7a3072fb3a261d'
LOCK = '0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753'
EPOCH = 1789753605
ROOT = 'cachy-update-' + COMMIT
ICONS = {f'cachy-update{state}-{style}{suffix}.svg' for style in ('blue', 'light', 'dark')
         for state, suffix in (('', ''), ('_updates-available', ''), ('_updates-available', '-cb'))}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect(data):
    files, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for count, member in enumerate(archive, 1):
            name = PurePosixPath(member.name.rstrip('/'))
            if (count > 1024 or name.is_absolute() or '..' in name.parts
                    or not name.parts or name.parts[0] != ROOT
                    or member.name in seen or not (member.isdir() or member.isfile())):
                raise ValueError('unsafe source archive member')
            seen.add(member.name)
            total += member.size
            if member.size > 8 * 1024 * 1024 or total > 32 * 1024 * 1024:
                raise ValueError('source archive size bound')
            if member.isfile():
                relative = str(name.relative_to(ROOT))
                if relative == '.':
                    raise ValueError('root must be a directory')
                files[relative] = (archive.extractfile(member).read(),
                                   0o755 if member.mode & 0o111 else 0o644)
    return files


def prepare(archive, package, output):
    raw = archive.read_bytes()
    if len(raw) > 1024 * 1024 or sha(raw) != ARCHIVE:
        raise ValueError('source archive differs from pin')
    files = inspect(raw)
    if sha(files['src/tray/Cargo.lock'][0]) != LOCK:
        raise ValueError('Cargo.lock differs from pin')
    if b'(or any later version of that license)' not in files['README.md'][0]:
        raise ValueError('explicit upstream software grant missing')
    excluded = {name: sha(data) for name, (data, _) in files.items()
                if name.startswith('res/icons/') and name.endswith('.svg')}
    if set(Path(name).name for name in excluded) != ICONS | {'cachy-update_app-icon.svg'}:
        raise ValueError('unexpected upstream artwork set')
    for name in excluded:
        del files[name]
    replacements = {}
    if {p.name for p in (package / 'icons').iterdir()} != ICONS:
        raise ValueError('original replacement icon set differs')
    for name in sorted(ICONS):
        data = (package / 'icons' / name).read_bytes()
        if b'SPDX-License-Identifier: MIT' not in data or b'Original geometric' not in data:
            raise ValueError('replacement artwork grant missing')
        files['res/icons/' + name] = (data, 0o644)
        replacements[name] = sha(data)
    for name in ('ICON-LICENSE', 'NOTICE'):
        files[name] = ((package / name).read_bytes(), 0o644)
    output.mkdir(parents=True, exist_ok=False)
    target = output / (ROOT + '-sanitized.tar.gz')
    with target.open('wb') as stream:
        with gzip.GzipFile(fileobj=stream, filename='', mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name, (data, mode) in sorted(files.items()):
                    item = tarfile.TarInfo(ROOT + '/' + name)
                    item.size, item.mode, item.mtime = len(data), mode, EPOCH
                    archive.addfile(item, io.BytesIO(data))
    report = {'schema_version': 1, 'source_commit': COMMIT, 'source_date_epoch': EPOCH,
              'upstream_archive_sha256': ARCHIVE, 'cargo_lock_sha256': LOCK,
              'software_grant': 'README explicit GPL-3.0-or-later plus source SPDX',
              'excluded_unresolved_artwork_sha256': excluded,
              'original_mit_replacement_sha256': replacements,
              'sanitized_source': target.name, 'sanitized_sha256': sha(target.read_bytes()),
              'files_sha256': {name: sha(data) for name, (data, _) in sorted(files.items())},
              'native_build': 'NOT RUN', 'apple_updater_acceptance': 'NOT RUN'}
    (output / 'source-audit.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = prepare(args.archive, Path(__file__).resolve().parent, args.output)
    print(json.dumps({k: report[k] for k in ('sanitized_source', 'sanitized_sha256', 'native_build')}))
