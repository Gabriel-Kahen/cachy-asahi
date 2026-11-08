# SPDX-License-Identifier: MIT
"""Bounded fd-relative recovery I/O; caller owns exclusive disposable-root custody.

No CLI, process retirement, signature verification or container claim lives here.
The caller must prove those prerequisites before cleanup. Directory removal and
unlink are not atomic identity-conditioned syscalls: a hostile concurrent writer
is outside this helper's contract. Every failure stops; there is no rollback or
retry after a partial cleanup.
"""
import hashlib
import json
import os
import stat

LOCAL = 'var/lib/pacman/local'
LOCK = 'var/lib/pacman/db.lck'
CANDIDATE = 'cachy-asahi-security-maintenance-0.1.0-2'
PRIOR = 'cachy-asahi-security-maintenance-0.1.0-1'
LEAF_CAP = 1024**2
TOTAL_CAP = 64 * 1024**2
NODE_CAP = 4096
DEPTH_CAP = 16
SNAPSHOT_CAP = 1024**2
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
           'st_size', 'st_mtime_ns', 'st_ctime_ns')


class Refusal(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refusal(reason)


def canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     allow_nan=False, ensure_ascii=True).encode('ascii')
    need(len(raw) <= SNAPSHOT_CAP, 'snapshot JSON cap')
    return raw


def snapshot_sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _parts(name):
    need(type(name) is str and 0 < len(name.encode('utf-8')) <= 512
         and not name.startswith('/') and '\0' not in name, 'relative bounded path')
    parts = name.split('/')
    need(len(parts) <= DEPTH_CAP and all(part not in ('', '.', '..')
         and len(part.encode('utf-8')) <= 255 for part in parts), 'safe path components')
    return parts


def _key(st):
    return tuple(getattr(st, field) for field in _FIELDS)


def _same(before, after):
    need(_key(before) == _key(after), 'filesystem identity or metadata changed')


def _owner(st, uid, gid):
    need(st.st_uid == uid and st.st_gid == gid, 'unexpected filesystem owner')


def _meta(st, kind):
    return dict(kind=kind, dev=st.st_dev, ino=st.st_ino,
                mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                nlink=st.st_nlink)


def _directory(parent, leaf, uid, gid):
    before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISDIR(before.st_mode), 'directory ancestor required')
    _owner(before, uid, gid)
    fd = os.open(leaf, _DIR_FLAGS, dir_fd=parent)
    try:
        _same(before, os.fstat(fd))
        _same(before, os.stat(leaf, dir_fd=parent, follow_symlinks=False))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _walk(root, parts, uid, gid):
    fd = os.dup(root)
    try:
        for part in parts:
            child = _directory(fd, part, uid, gid)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _bounded_names(directory):
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            names.append(entry.name)
            need(len(names) <= NODE_CAP, 'directory namespace node cap')
    return sorted(names)


def _entry(parent, leaf, uid, gid, budget, *, lock=False):
    before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    _owner(before, uid, gid)
    budget[0] += 1
    need(budget[0] <= NODE_CAP, 'snapshot node cap')
    if stat.S_ISDIR(before.st_mode):
        need(not lock, 'lock must be an ordinary file')
        fd = _directory(parent, leaf, uid, gid)
        try:
            _same(before, os.fstat(fd))
            return _meta(before, 'dir')
        finally:
            os.close(fd)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
         'ordinary single-link file required')
    need(0 <= before.st_size <= LEAF_CAP, 'snapshot file cap')
    budget[1] += before.st_size
    need(budget[1] <= TOTAL_CAP, 'snapshot aggregate byte cap')
    if lock:
        need(before.st_size == 0 and stat.S_IMODE(before.st_mode) == 0,
             'exact empty mode000 lock required')
        flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open(leaf, flags, dir_fd=parent)
    try:
        _same(before, os.fstat(fd))
        digest = hashlib.sha256()
        size = 0
        if not lock:
            while True:
                raw = os.read(fd, min(65536, before.st_size + 1 - size))
                if not raw:
                    break
                size += len(raw)
                need(size <= before.st_size, 'file grew during capture')
                digest.update(raw)
        need(size == before.st_size, 'complete file capture')
        _same(before, os.fstat(fd))
        _same(before, os.stat(leaf, dir_fd=parent, follow_symlinks=False))
        return dict(**_meta(before, 'file'), bytes=size, sha256=digest.hexdigest())
    finally:
        os.close(fd)


def read_regular(root_fd, relative, maximum=LEAF_CAP):
    """Read a bounded ordinary input beneath the trusted root fd, without links."""
    need(type(maximum) is int and 0 <= maximum <= LEAF_CAP, 'input file cap')
    root = os.fstat(root_fd)
    need(stat.S_ISDIR(root.st_mode), 'root fd must name a directory')
    parts = _parts(relative)
    parent = _walk(root_fd, parts[:-1], root.st_uid, root.st_gid)
    try:
        entry = _entry(parent, parts[-1], root.st_uid, root.st_gid, [0, 0])
        need(entry['kind'] == 'file' and entry['bytes'] <= maximum, 'bounded ordinary input')
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                     | os.O_NONBLOCK, dir_fd=parent)
        try:
            _same(before, os.fstat(fd))
            raw = b''
            while len(raw) <= maximum:
                piece = os.read(fd, min(65536, maximum + 1 - len(raw)))
                if not piece:
                    break
                raw += piece
            need(len(raw) <= maximum and dict(**_meta(before, 'file'),
                 bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) == entry,
                 'input changed between bounded reads')
            _same(before, os.fstat(fd))
            _same(before, os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
            return raw, entry
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def snapshot(root_fd, payload_names, *, owner_uid, owner_gid):
    """Capture local DB, declared paths beneath usr/, and the optional lock."""
    need(type(root_fd) is int and root_fd >= 0 and type(owner_uid) is int
         and type(owner_gid) is int and owner_uid >= 0 and owner_gid >= 0,
         'explicit root capability and owner')
    root = os.fstat(root_fd)
    need(stat.S_ISDIR(root.st_mode), 'root fd must name a directory')
    _owner(root, owner_uid, owner_gid)
    need(type(payload_names) in (tuple, list) and 0 < len(payload_names) <= 64
         and all(type(n) is str for n in payload_names)
         and len(set(payload_names)) == len(payload_names), 'finite distinct payload names')
    for name in payload_names:
        _parts(name)
    need(not any(a != b and b.startswith(a + '/') for a in payload_names
                 for b in payload_names), 'payload names cannot overlap ancestors')
    db, payload, budget = {}, {}, [0, 0]
    local = _walk(root_fd, _parts(LOCAL), owner_uid, owner_gid)
    try:
        def capture(directory, prefix='', depth=0):
            need(depth < DEPTH_CAP, 'snapshot depth cap')
            before = os.fstat(directory)
            names = _bounded_names(directory)
            for leaf in names:
                need(_parts(leaf) == [leaf], 'ordinary DB leaf name')
                name = prefix + leaf
                need(len(name.encode('utf-8')) <= 512, 'DB path cap')
                item = _entry(directory, leaf, owner_uid, owner_gid, budget)
                db[name] = item
                if item['kind'] == 'dir':
                    child = _directory(directory, leaf, owner_uid, owner_gid)
                    try:
                        capture(child, name + '/', depth + 1)
                    finally:
                        os.close(child)
            need(names == _bounded_names(directory), 'DB directory namespace changed')
            _same(before, os.fstat(directory))
        capture(local)
    finally:
        os.close(local)
    for name in sorted(payload_names):
        parts = _parts(name)
        parent = None
        try:
            parent = _walk(root_fd, ['usr'] + parts[:-1], owner_uid, owner_gid)
            payload[name] = _entry(parent, parts[-1], owner_uid, owner_gid, budget)
        except FileNotFoundError:
            payload[name] = None
        finally:
            if parent is not None:
                os.close(parent)
    parent = _walk(root_fd, _parts('var/lib/pacman'), owner_uid, owner_gid)
    try:
        try:
            lock = _entry(parent, 'db.lck', owner_uid, owner_gid, budget, lock=True)
        except FileNotFoundError:
            lock = None
    finally:
        os.close(parent)
    result = dict(db=db, payload=payload, lock=lock)
    canonical(result)
    return result


def cleanup(root_fd, payload_names, expected_snapshot, *, owner_uid, owner_gid):
    """Remove only an exact empty prepared DB dir, then its exact stale lock.

    Caller first verifies the recovery plan, signature, checkpoint and complete
    owned-process retirement. This helper does not authorize those facts.
    """
    expected = json.loads(canonical(expected_snapshot))
    need(set(expected) == {'db', 'payload', 'lock'} and type(expected['db']) is dict,
         'exact snapshot fields')
    directory, lock = expected['db'].get(CANDIDATE), expected['lock']
    need(type(directory) is dict and directory.get('kind') == 'dir'
         and directory.get('mode') == 0o755 and directory.get('uid') == owner_uid
         and directory.get('gid') == owner_gid, 'exact prepared candidate directory')
    need(PRIOR not in expected['db'] and not any(n.startswith(CANDIDATE + '/')
         for n in expected['db']), 'old DB absent and prepared directory empty')
    need(type(lock) is dict and lock.get('kind') == 'file' and lock.get('bytes') == 0
         and lock.get('mode') == 0 and lock.get('nlink') == 1
         and lock.get('uid') == owner_uid and lock.get('gid') == owner_gid
         and lock.get('sha256') == hashlib.sha256(b'').hexdigest(), 'exact stale owned lock')
    need(type(expected['payload']) is dict and all(v is None for v in expected['payload'].values()),
         'every declared package payload absent')
    def check(wanted):
        actual = snapshot(root_fd, payload_names, owner_uid=owner_uid, owner_gid=owner_gid)
        need(canonical(actual) == canonical(wanted), 'whole recovery snapshot changed')
        return actual
    before = check(expected)
    local = _walk(root_fd, _parts(LOCAL), owner_uid, owner_gid)
    try:
        need(_meta(os.stat(CANDIDATE, dir_fd=local, follow_symlinks=False), 'dir') == directory,
             'candidate identity changed immediately before rmdir')
        os.rmdir(CANDIDATE, dir_fd=local)
    finally:
        os.close(local)
    del expected['db'][CANDIDATE]
    after_directory = check(expected)
    parent = _walk(root_fd, _parts('var/lib/pacman'), owner_uid, owner_gid)
    try:
        current = _entry(parent, 'db.lck', owner_uid, owner_gid, [0, 0], lock=True)
        need(canonical(current) == canonical(lock), 'lock identity changed immediately before unlink')
        os.unlink('db.lck', dir_fd=parent)
    finally:
        os.close(parent)
    expected['lock'] = None
    after_unlock = check(expected)
    return dict(status='EXACT_EMPTY_DB_DIRECTORY_AND_STALE_LOCK_REMOVED',
                before_sha256=snapshot_sha256(before), after_directory=after_directory,
                after_directory_sha256=snapshot_sha256(after_directory),
                after_unlock=after_unlock, after_unlock_sha256=snapshot_sha256(after_unlock),
                mutations=[dict(operation='rmdir', path=LOCAL + '/' + CANDIDATE),
                           dict(operation='unlink', path=LOCK)], retry=False)
