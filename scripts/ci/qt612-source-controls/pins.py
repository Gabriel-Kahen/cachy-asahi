# SPDX-License-Identifier: MIT
"""Read-only, bounded checks of frozen Qt source families. Never follow links."""
import hashlib
import os
from pathlib import Path
import re
import stat

MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 512, 2 * 1024**2, 16 * 1024**2
PRIVATE = {'.git', '.ssh', '.gnupg', '.aws', '.config', '.cache', '.codex'}
PASSIVE_LINKS = {f'recipe-inputs/{d}/LICENSES/0BSD.txt': '../LICENSE' for d in ('arch', 'alarm')}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def member(name):
    need(type(name) is str and 0 < len(name) <= 255 and len(name.split('/')) <= 12
         and all(re.fullmatch('[A-Za-z0-9._+@~-]+', part) and part not in ('.', '..')
                 and part.casefold() not in PRIVATE for part in name.split('/')), 'safe public source member required')
    return name


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path != Path('/') and str(path) == os.path.normpath(str(path))
         and not PRIVATE.intersection(p.casefold() for p in path.parts)
         and all(not p.is_symlink() for p in (path, *path.parents)), 'ordinary public absolute root required')
    return path


def identity(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid',
                                       'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def descriptor(name, row, files):
    member(name)
    need(type(row) is dict and row.get('kind') in ('file', 'symlink')
         and type(row.get('bytes')) is int and 0 <= row['bytes'] <= MAX_FILE_BYTES
         and type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
         and type(row.get('mode')) is int, 'finite source descriptor required')
    if row['kind'] == 'file':
        need(set(row) == {'kind', 'bytes', 'sha256', 'mode'} and row['mode'] == 0o644, 'ordinary source mode required')
    else:
        need(set(row) == {'kind', 'bytes', 'sha256', 'mode', 'target'} and name in PASSIVE_LINKS
             and row['target'] == PASSIVE_LINKS[name] and row['mode'] == 0o777, 'exact passive license link only')
        target = str(Path(name).parent.parent / 'LICENSE')
        need(target in files and type(files[target]) is dict and files[target].get('kind') == 'file',
             'independently pinned license target required')
        raw = row['target'].encode()
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'link descriptor differs')


def verify_family(root, files):
    root = ordinary(root)
    need(type(files) is dict and 0 < len(files) <= MAX_FILES, 'source file count cap')
    for name, row in files.items(): descriptor(name, row, files)
    need(sum(row['bytes'] for row in files.values()) <= MAX_TOTAL_BYTES, 'declared total source cap')
    wanted_dirs = {str(p) for name in files for p in Path(name).parents if str(p) != '.'}
    dirs, found = {}, {}
    def walk(name, parent_fd=None):
        fd = os.open(root if not name else name.rsplit('/', 1)[-1],
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(fd); dirs[name] = fd, identity(info)
        need(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022, 'unsafe source directory')
        with os.scandir(fd) as entries:
            for entry in entries:
                rel = name + '/' + entry.name if name else entry.name
                member(rel)
                need(len(dirs) + len(found) < 2 * MAX_FILES, 'source namespace cap')
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    need(rel in wanted_dirs, 'unexpected source directory')
                    walk(rel, fd)
                else:
                    need(rel in files, 'unexpected source file')
                    row = files[rel]
                    need(info.st_uid in (0, os.geteuid()) and info.st_nlink == 1
                         and stat.S_IMODE(info.st_mode) == row['mode'] and info.st_size == row['bytes'],
                         'source mode/size/ownership/link count differs')
                    need(stat.S_ISREG(info.st_mode) if row['kind'] == 'file' else stat.S_ISLNK(info.st_mode),
                         'source node type differs')
                    found[rel] = identity(info)
    try:
        walk('')
        need(set(found) == set(files), 'missing source file')
        need(sum(row[6] for row in found.values()) <= MAX_TOTAL_BYTES, 'actual total source cap')
        for name, row in files.items():
            parent, _, leaf = name.rpartition('/'); parent_fd = dirs[parent][0]
            if row['kind'] == 'symlink':
                raw = os.readlink(leaf, dir_fd=parent_fd).encode()
                need(raw.decode() == row['target'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'passive link changed')
                continue
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
            try:
                before = os.fstat(fd)
                need(identity(before) == found[name], 'source replaced before read')
                h, size = hashlib.sha256(), 0
                while block := os.read(fd, min(1024**2, before.st_size + 1 - size)):
                    size += len(block); need(size <= before.st_size, 'source grew')
                    h.update(block)
                need(size == row['bytes'] and h.hexdigest() == row['sha256']
                     and identity(os.fstat(fd)) == found[name], 'source whole body differs')
            finally: os.close(fd)
        need(all(identity(os.fstat(fd)) == previous == identity((root / name).lstat())
                 for name, (fd, previous) in dirs.items()), 'source directory changed')
        need(all(identity((root / name).lstat()) == previous for name, previous in found.items()), 'source leaf changed')
        return {'status': 'PASS_FROZEN_SOURCE_BYTES_ONLY', 'files': len(files),
                'bytes': sum(row['bytes'] for row in files.values()),
                'passive_symlinks': sum(row['kind'] == 'symlink' for row in files.values())}
    finally:
        for fd, _ in dirs.values(): os.close(fd)
