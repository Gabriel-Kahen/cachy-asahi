# SPDX-License-Identifier: MIT
"""Closed candidate DATA pins and unchanged bounded lifecycle API loading."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

PROFILE_SHA = 'a7a20c44cabd6ba05dac8096906c0c133310c1d914a099d4fcfb5aab4ed7ebf5'
HOST_CONTRACT_SHA = 'c15bf77254ee4c857c31036004e7a663a5b3d7ec25f49e59c10a4ea3e1d942d6'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_JSON_KEY'); result[key] = value
        return result
    def invalid(_):
        raise ValueError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def read(path, maximum=32 * 1024**2):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'ALIASED_INPUT')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum, 'UNSAFE_OR_OVERSIZED_INPUT')
        raw = stream.read(maximum + 1)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), 'INPUT_CHANGED')
        return raw


def profile(directory):
    raw = read(directory / 'profile.json', 65536)
    need(digest(raw) == PROFILE_SHA, 'CANDIDATE_PROFILE_PIN')
    return decode(raw)


def host_contract(directory):
    raw = read(directory / 'host-contract-v2.json', 65536)
    need(digest(raw) == HOST_CONTRACT_SHA, 'HOST_SUCCESSOR_CONTRACT_PIN')
    return decode(raw)


def held(path, pin, name):
    raw = read(path, 128 * 1024)
    need(len(raw) == pin['bytes'] and digest(raw) == pin['sha256'], 'HELD_API_PIN')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def packet(root):
    """Bounded single-owner private tree snapshot; no archive/code execution."""
    root = Path(root).absolute()
    need('..' not in root.parts and root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)), 'ALIASED_PACKET')
    pending, result, total = [root], {}, 0
    while pending:
        path = pending.pop(); info = path.lstat()
        need(info.st_uid == os.geteuid(), 'PACKET_OWNER')
        relative = '.' if path == root else path.relative_to(root).as_posix()
        need('..' not in Path(relative).parts and '\\' not in relative, 'PACKET_PATH')
        if stat.S_ISDIR(info.st_mode):
            need(stat.S_IMODE(info.st_mode) == 0o700, 'PACKET_DIRECTORY_MODE')
            result[relative] = dict(kind='directory', mode=0o700)
            with os.scandir(path) as children:
                for child in children:
                    pending.append(Path(child.path))
                    need(len(result) + len(pending) <= 512, 'PACKET_NODE_LIMIT')
        else:
            need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, 'PACKET_FILE_TYPE_OR_MODE')
            total += info.st_size; need(total <= 128 * 1024**2, 'PACKET_TOTAL_LIMIT')
            raw = read(path)
            result[relative] = dict(kind='file', mode=0o600, bytes=len(raw), sha256=digest(raw))
    return result
