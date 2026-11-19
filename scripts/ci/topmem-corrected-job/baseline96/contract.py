"""Versioned standalone build contract; no historical consumer admission."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

ID = 'maintained-native-baseline-v1-vim-9.2.1178-1'
INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
INVENTORY = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
NATIVE = 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'
RECIPES = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
AUDIT = '1302243720fb2e621431fd9ed71f249aabad7979c8ea31b6990ae0f471087b8d'
MAX_SECONDS, RESERVE = 7200, 360


def need(value, reason):
    if not value:
        raise ValueError(reason)


def live(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline)
         and time.monotonic() < deadline, 'successor-deadline')


def relative(name):
    need(type(name) is str and name and '\\' not in name and not name.startswith('/')
         and all(p not in ('', '.', '..') for p in name.split('/'))
         and all(32 <= ord(c) < 127 for c in name), 'successor-source-path')
    return Path(name)


def read(path, limit=8 * 1024**2, deadline=None):
    if deadline is not None: live(deadline)
    path = Path(path).absolute()
    need('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'successor-input-parent')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit, 'successor-regular-input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        data = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
            if deadline is not None: live(deadline)
            data.extend(chunk); need(len(data) <= limit, 'successor-input-size')
        after = os.fstat(fd); named = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(data) == before.st_size and all(getattr(before, k) == getattr(opened, k)
             == getattr(after, k) == getattr(named, k) for k in fields), 'successor-input-drift')
        return bytes(data)
    finally:
        os.close(fd)


def decode(raw):
    def pairs(rows):
        value = {}
        for k, v in rows:
            need(k not in value, 'successor-json-duplicate'); value[k] = v
        return value
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: need(False, 'successor-json-number'))
    need(type(value) is dict, 'successor-json-object')
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(path, pin, deadline=None):
    need(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin), 'successor-full-pin')
    raw = read(path, deadline=deadline); need(sha(raw) == pin, 'successor-pin-mismatch')
    return raw


def verify(base, packet_pin, deadline=None):
    deadline = min(time.monotonic() + 30, deadline) if deadline is not None else time.monotonic() + 30
    live(deadline)
    base = Path(base).resolve()
    packet = decode(pinned(base / 'packet.json', packet_pin, deadline))
    need(packet['schema_version'] == 1 and type(packet['schema_version']) is int
         and packet['baseline_id'] == ID and packet['lineage'] == 'SUCCESSOR_NOT_HISTORICAL_ORIGINAL'
         and packet['audit_sha256'] == AUDIT and packet['inputs_sha256'] == INPUTS
         and packet['inventory_sha256'] == INVENTORY and packet['native_sha256'] == NATIVE
         and packet['recipes_sha256'] == RECIPES, 'successor-variant-binding')
    files = packet['files']
    need(type(files) is dict and 79 < len(files) <= 128, 'successor-source-count')
    actual, nodes = set(), [0]
    def walk(directory, depth):
        need(depth <= 12, 'successor-source-depth')
        with os.scandir(directory) as entries:
            for entry in entries:
                live(deadline); nodes[0] += 1
                need(nodes[0] <= 512, 'successor-source-node-bound')
                info = entry.stat(follow_symlinks=False); path = Path(entry.path)
                need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'successor-source-node-type')
                if stat.S_ISDIR(info.st_mode): walk(path, depth + 1)
                elif path != base / 'packet.json': actual.add(str(path.relative_to(base)))
    walk(base, 0)
    need(actual == set(files), 'successor-source-membership')
    total = 0
    for name, row in files.items():
        path = base / relative(name); raw = read(path, deadline=deadline); total += len(raw)
        need(total <= 16 * 1024**2, 'successor-source-byte-bound')
        need(set(row) == {'sha256', 'bytes', 'mode'} and len(raw) == row['bytes']
             and sha(raw) == row['sha256'] and stat.S_IMODE(path.stat().st_mode) == row['mode'], 'successor-source-binding')
    inputs = decode(pinned(base / 'locks/inputs-successor.lock.json', INPUTS, deadline))
    pinned(base / 'native/scripts/ci/native_arm.py', NATIVE, deadline)
    recipes = decode(pinned(base / 'native/scripts/ci/recipes.lock.json', RECIPES, deadline))
    names = {p + '/' + n for p, rows in recipes.items() for n in rows}
    need(len(recipes) == 4 and len(names) == 71 and len(inputs['packages']) == 248, 'successor-original-recipe-set')
    native_rows = {n.removeprefix('native/') for n in files if n.startswith('native/')}
    need(len(native_rows) == 79 and names <= native_rows, 'successor-native-closure')
    expected = {p['name'][0]: p['version'][0] for p in inputs['rootfs_packages']}
    expected.update({p['name']: p['version'] for p in inputs['packages']})
    inventory = pinned(base / 'locks/builder-successor.lock', INVENTORY, deadline)
    need(len(expected) == 341 and inventory == ''.join(f'{n} {v}\n' for n, v in sorted(expected.items())).encode(), 'successor-inventory-binding')
    live(deadline); return inputs, packet


def cache_items(inputs):
    items = list(inputs['keyring_files'])
    for row in [inputs['rootfs'], *inputs['packages']]:
        items += [row, {'filename': row['filename'] + '.sig', 'size': row['signature_size'], 'sha256': row['signature_sha256']}]
    need(len(items) == 501 and len({r['filename'] for r in items}) == 501, 'successor-cache-membership')
    need(sum(r['size'] for r in items) <= 4 * 1024**3, 'successor-cache-byte-bound')
    for row in items:
        need(type(row['filename']) is str and re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}', row['filename'])
             and row['filename'] not in ('.', '..') and type(row['size']) is int and 0 <= row['size'] <= 2 * 1024**3
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'successor-cache-entry')
        need(row['size'] > 0 or (row['filename'] == 'archlinuxarm-revoked' and row['sha256'] == sha(b'')), 'successor-empty-input')
    return items


def seed_cache(inputs, source, target, deadline, resource_check):
    source, target = Path(source).absolute(), Path(target).absolute()
    need(source != target and not source.is_relative_to(target), 'successor-cache-separation')
    need(all(stat.S_ISDIR(p.lstat().st_mode) for p in [source, *source.parents]), 'successor-cache-source-parent')
    items = cache_items(inputs)
    observed = set()
    with os.scandir(source) as entries:
        for entry in entries:
            live(deadline); need(len(observed) < 501, 'successor-offline-cache-count'); observed.add(entry.name)
    need(observed == {r['filename'] for r in items}, 'successor-offline-cache-exact-set')
    target.mkdir(mode=0o700)
    for row in items:
        live(deadline)
        path = source / row['filename']; before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['size'], 'successor-cache-regular')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        digest, count = hashlib.sha256(), 0
        try:
            with (target / row['filename']).open('xb') as out:
                os.fchmod(out.fileno(), 0o600)
                while chunk := os.read(fd, 1024**2):
                    live(deadline); resource_check(); count += len(chunk)
                    need(count <= row['size'], 'successor-cache-drift')
                    digest.update(chunk); out.write(chunk)
            opened, named = os.fstat(fd), path.lstat()
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(all(getattr(before, k) == getattr(opened, k) == getattr(named, k) for k in fields)
                 and count == row['size'] and digest.hexdigest() == row['sha256'], 'successor-cache-pin')
        finally:
            os.close(fd)
    live(deadline); resource_check()
    return {'objects': 501, 'signature_inputs': 249, 'pinned_bytes': sum(r['size'] for r in items)}


def publish(path, value, custody, deadline):
    """Create one status in its held parent, retaining inode identity on faults."""
    import secrets
    path = Path(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    custody.update(parent=path.parent, name=path.name, directory=os.fstat(fd), temporary=None, inode=None)
    target = None
    try:
        live(deadline)
        need((path.parent.lstat().st_dev, path.parent.lstat().st_ino) ==
             (custody['directory'].st_dev, custody['directory'].st_ino), 'successor-public-directory-drift')
        try: os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: need(False, 'successor-public-already-exists')
        name = '.status-' + secrets.token_hex(16)
        custody['temporary'] = name
        target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        info = os.fstat(target); custody['inode'] = (info.st_dev, info.st_ino)
        data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        need(len(data) <= 65536, 'successor-public-size')
        while data:
            live(deadline); count = os.write(target, data); need(count > 0, 'successor-public-write'); data = data[count:]
        os.fsync(target); live(deadline)
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(named.st_mode) and named.st_nlink == 1
             and (named.st_dev, named.st_ino) == custody['inode'], 'successor-public-temporary-drift')
        # An exclusive link commits without replacing a concurrently created name.
        os.link(name, path.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.unlink(name, dir_fd=fd)
        custody['temporary'] = None
        os.fsync(fd); live(deadline)
    finally:
        if target is not None: os.close(target)
        os.close(fd)


def retire(custody):
    """Unlink only our recorded inode; replacement or denial stays UNKNOWN."""
    if custody.get('inode') is None: return 'NO OWNED PUBLIC INODE'
    fd = os.open(custody['parent'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd); expected = custody['directory']
        need((info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino), 'successor-public-directory-drift')
        unknown = False
        for name in [custody['name'], custody.get('temporary')]:
            if name is None: continue
            try: current = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError: continue
            if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != custody['inode']:
                unknown = True; continue
            os.unlink(name, dir_fd=fd)
        os.fsync(fd)
        need(not unknown, 'successor-public-replacement')
        return 'OWNED PUBLIC INODE REMOVED'
    finally:
        os.close(fd)
