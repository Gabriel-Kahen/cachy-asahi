#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage current helpers with exactly pinned historical Welcome1 product inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

PREFIX = 'packages/tools/cachy-asahi-welcome/'
COMMIT = '09717a45388e5b90ca80fd3fef327444101c108f'
SCOPE = 'HISTORICAL_WELCOME0.1.0-1_NOT_CURRENT_ACCEPTANCE'
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 10000, 16 * 1024**2, 256 * 1024**2
EXCLUDED = {'.git', '.ci-inputs', 'artifacts'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def relative(name):
    require(isinstance(name, str) and name and not any(ord(c) < 32 for c in name), 'invalid relative path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name and all(p not in ('.', '..') for p in path.parts),
            'noncanonical relative path')
    return path


def absolute(path, exists=True):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute canonical path required')
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'path alias refused')
    require(path.resolve(strict=exists) == path, 'path alias refused')
    return path


def read(path):
    absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES, 'regular bounded file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(fd)
        require(len(raw) == info.st_size and len(raw) <= MAX_FILE_BYTES and
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed while reading')
        return raw
    finally:
        os.close(fd)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def source_lock(path):
    value = json.loads(read(path), object_pairs_hook=unique)
    require(value.get('schema_version') == 1 and value.get('source_commit') == COMMIT and value.get('scope') == SCOPE,
            'historical source identity differs')
    files = value.get('files')
    require(isinstance(files, dict) and len(files) == 16, 'exact16 historical files required')
    for name, row in files.items():
        relative(name)
        require(name.startswith(PREFIX) and '/' not in name[len(PREFIX):], 'historical product scope differs')
        require(isinstance(row, dict) and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and
                0 <= row['bytes'] <= MAX_FILE_BYTES and isinstance(row['sha256'], str) and
                re.fullmatch('[0-9a-f]{64}', row['sha256']), 'invalid historical source pin')
    return value


def tracked(root):
    result = subprocess.run(['/usr/bin/git', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
                             '-C', str(root), 'ls-files', '--stage', '-z'], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
                                 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'})
    require(len(result.stdout) <= 4 * 1024**2 and result.stdout.endswith(b'\0'), 'tracked index output bound')
    rows = []
    for raw in result.stdout[:-1].split(b'\0'):
        head, name = raw.split(b'\t', 1)
        mode, oid, stage_number = head.decode('ascii').split()
        require(stage_number == '0' and mode in ('100644', '100755') and re.fullmatch('[0-9a-f]{40,64}', oid),
                'unmerged, linked or nonregular index entry refused')
        rows.append((name.decode('utf-8'), int(mode, 8), oid))
    return rows


def stage(current, historical, output, entries, lock):
    """Explicit entries permit owned-temp controls without creating Git repositories."""
    current, historical = absolute(current), absolute(historical)
    output = absolute(output, exists=False)
    require(current.is_dir() and historical.is_dir() and not output.exists() and output.parent.is_dir(),
            'fresh output under an existing directory required')
    for root in (current, historical):
        require(not output.is_relative_to(root) and not root.is_relative_to(output), 'overlapping output refused')
    require(len(entries) <= MAX_FILES, 'tracked file count bound')
    planned, seen, total = {}, set(), 0
    for name, mode, oid in entries:
        path = relative(name)
        require(name not in seen and mode in (0o100644, 0o100755), 'duplicate/nonregular tracked entry')
        seen.add(name)
        if path.parts[0] in EXCLUDED or name.startswith(PREFIX):
            continue
        require(name != 'replay.json', 'reserved replay receipt path')
        raw = read(current / name)
        total += len(raw)
        require(total <= MAX_TOTAL_BYTES, 'staged source byte bound')
        planned[name] = dict(pin(raw), mode=0o755 if mode == 0o100755 else 0o644, origin='current', git_blob=oid)
    actual = historical / PREFIX
    require(actual.is_dir() and {p.name for p in actual.iterdir()} == {Path(n).name for n in lock['files']},
            'historical product file set differs')
    for name, expected in lock['files'].items():
        raw = read(historical / name)
        require(pin(raw) == expected, 'historical source pin differs: ' + name)
        total += len(raw)
        require(total <= MAX_TOTAL_BYTES, 'staged source byte bound')
        planned[name] = dict(expected, mode=0o644, origin='historical')
    require(len(planned) <= MAX_FILES and total <= MAX_TOTAL_BYTES, 'staged source bound')
    output.mkdir(mode=0o700)
    for name, row in sorted(planned.items()):
        raw = read((historical if row['origin'] == 'historical' else current) / name)
        require(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'source changed before copy: ' + name)
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(row['mode'])
    # A second comparison proves copied helpers still equal current inputs at completion.
    for name, row in planned.items():
        original = (historical if row['origin'] == 'historical' else current) / name
        require(pin(read(original)) == pin(read(output / name)) == {k: row[k] for k in ('bytes', 'sha256')},
                'post-copy source comparison failed: ' + name)
    receipt = dict(schema_version=1, scope=SCOPE, source_commit=COMMIT, historical_files=lock['files'],
                   current_root=str(current), historical_root=str(historical), files=planned,
                   current_files_match='PASS_EXACT_BYTES', current_acceptance=False,
                   file_count=len(planned), total_bytes=total)
    (output / 'replay.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('current-root', 'historical-root', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    lock = source_lock(Path(__file__).resolve().with_name('source.json'))
    receipt = stage(args.current_root, args.historical_root, args.output, tracked(absolute(args.current_root)), lock)
    print(json.dumps(dict(scope=SCOPE, file_count=receipt['file_count'], total_bytes=receipt['total_bytes'])))


if __name__ == '__main__':
    main()
