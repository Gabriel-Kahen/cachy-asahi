# SPDX-License-Identifier: MIT
"""Bounded passive byte custody; no actors or authority issuance."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

MIB = 1024**2
RECIPE_COMMIT = 'b05267833d497ef034576741bf31968019a526c3'
RECIPE_PATH = 'packages/port/qt612-gui-source-reference'
PACKAGE = 'cachy-asahi-qt612-gui-source-reference'
VERSION = '6.12.0-1'
FILENAME = PACKAGE + '-' + VERSION + '-aarch64.pkg.tar.xz'
MAP_PIN = dict(bytes=5976, sha256='a595ee503233867201704ab8a6aac88d3514b39067d1ef004f6c8f7ac10f1559')
CONTRACT_PIN = dict(bytes=14990, sha256='1896928865f4770908e0d00cd4f64dbdea5ba216b7e440c09fed2335fcfa15cf')
STAGE_PIN = dict(bytes=19545, sha256='291053598bd806eed9be622f495d51725aae5f579f5f3241a83111ded254cee5')


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw, cap=32*MIB):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    need(type(raw) is bytes and 0 < len(raw) <= cap, 'bounded JSON bytes')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def relative(value):
    need(type(value) is str and len(value) <= 1024 and value.isascii()
         and re.fullmatch(r'[A-Za-z0-9_./+@-]+', value)
         and not value.startswith('/') and str(PurePosixPath(value)) == value
         and all(p not in ('', '.', '..', '.gnupg', '.ssh', '.aws', '.config')
                 for p in value.split('/')), 'ordinary relative public reference')
    return value


def descriptor(row, cap=512*MIB):
    need(type(row) is dict and set(row) == {'bytes', 'sha256'}
         and type(row['bytes']) is int and 0 < row['bytes'] <= cap
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'bounded whole byte descriptor')
    return row


def reference(row, cap=512*MIB):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'whole relative reference')
    relative(row['path'])
    descriptor({k: row[k] for k in ('bytes', 'sha256')}, cap)
    return row


def canonical_root(value):
    root = Path(value)
    need(root.is_absolute() and str(value) == str(root) and root == root.resolve()
         and all(not p.is_symlink() for p in (root, *root.parents))
         and root.is_dir(), 'canonical ordinary retained input root')
    return root


def identity(s):
    return (s.st_dev, s.st_ino, s.st_nlink, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_ref(root, row, cap=512*MIB, collect=True):
    reference(row, cap)
    root = canonical_root(root)
    current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = row['path'].split('/')
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and not before.st_mode & 0o022 and before.st_size == row['bytes'],
                 'ordinary nonshared exact-size retained input')
            digest, blocks, total = hashlib.sha256(), [], 0
            while True:
                block = os.read(fd, min(65536, row['bytes'] + 1 - total))
                if not block:
                    break
                total += len(block)
                need(total <= row['bytes'], 'input grew during bounded read')
                digest.update(block)
                if collect:
                    blocks.append(block)
            need(total == row['bytes'] and digest.hexdigest() == row['sha256']
                 and identity(before) == identity(os.fstat(fd))
                 and identity(before) == identity(os.stat(parts[-1], dir_fd=current, follow_symlinks=False)),
                 'stable original whole input bytes')
            return b''.join(blocks) if collect else dict(bytes=total, sha256=digest.hexdigest())
        finally:
            os.close(fd)
    finally:
        os.close(current)


def inspect_recipe(root):
    root = canonical_root(root)
    map_path = RECIPE_PATH + '/recipe-files.lock.json'
    raw = read_ref(root, dict(path=map_path, **MAP_PIN), MIB)
    mapping = decode(raw, MIB)
    need(mapping['kind'] == 'QT612_GUI_COMPLETE_RECIPE_FILE_MAP_V1'
         and mapping['root'] == RECIPE_PATH and len(mapping['files']) == 35
         and mapping['Root_acceptance'] is None and mapping['native_acceptance'] is False,
         'exact b052 source-only file map')
    expected = set(mapping['files']) | {'recipe-files.lock.json'}
    base = root / RECIPE_PATH
    physical, count = set(), 0
    for directory, dirs, names in os.walk(base, followlinks=False):
        count += len(dirs) + len(names)
        need(count <= 128 and all(not (Path(directory)/n).is_symlink() for n in dirs),
             'finite ordinary GUI recipe namespace')
        for name in names:
            physical.add((Path(directory)/name).relative_to(base).as_posix())
    need(physical == expected, 'complete GUI recipe namespace with no extra files')
    for name, row in mapping['files'].items():
        relative(name)
        path = base / name
        need(stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'exact original recipe file mode')
        read_ref(root, dict(path=RECIPE_PATH+'/'+name,
                           **{k: row[k] for k in ('bytes', 'sha256')}), MIB, collect=False)
    contract = decode(read_ref(root, dict(path=RECIPE_PATH+'/BUILD-CONTRACT.json', **CONTRACT_PIN), MIB), MIB)
    need(contract['package']['name'] == PACKAGE and contract['package']['version'] == VERSION
         and contract['actual_native']['native_acceptance'] is False, 'fixed GUI18 recipe contract')
    return dict(recipe_commit=RECIPE_COMMIT, recipe_map=MAP_PIN, contract=contract,
                contract_pin=CONTRACT_PIN, stage_program_pin=STAGE_PIN,
                source_only=True, native_acceptance=False, Root_acceptance=None)
