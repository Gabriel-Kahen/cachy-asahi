# SPDX-License-Identifier: MIT
"""Read and restore the exact md4c donor Sources without importing their code."""
import base64
import hashlib
import json
from pathlib import Path
import stat

MAX_SOURCE = 2 * 1024**2
MAP = 'source-map.json'
MARKER = 'inner-public-retention-v6.json'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(), 'canonical absolute path required')
    return path


def read(path):
    path = ordinary(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         not before.st_mode & 0o022 and 0 < before.st_size < MAX_SOURCE,
         'bounded regular source leaf')
    with path.open('rb') as stream:
        body = stream.read(before.st_size + 1)
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid,
                          s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(body) == before.st_size and identity(before) == identity(after), 'stable complete source leaf')
    return body


def physical(root):
    root = ordinary(root)
    need(root.is_dir(), 'physical source directory required')
    bodies = {}
    directories = set()
    total = 0
    for path in root.rglob('*'):
        name = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            directories.add(name)
            need(len(directories) <= 256, 'bounded source directory namespace')
            continue
        need(stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o644 and len(bodies) < 95,
             'source leaves must be regular, mode 0644 and within the file limit')
        body = read(path)
        total += len(body)
        need(total < MAX_SOURCE, 'source exceeds the 2 MiB limit')
        bodies[name] = body
    expected = {p.as_posix() for name in bodies for p in Path(name).parents if p != Path('.')}
    need(directories == expected, 'complete source directory namespace')
    return bodies


def tree(bodies):
    def oid(kind, raw):
        return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()

    def walk(prefix):
        children = {name[len(prefix):].split('/')[0] for name in bodies if name.startswith(prefix)}
        rows = []
        for name in children:
            path = prefix + name
            if path in bodies:
                mode, digest, key = b'100644', oid(b'blob', bodies[path]), name
            else:
                mode, digest, key = b'40000', walk(path + '/'), name + '/'
            rows.append((key.encode(), mode + b' ' + name.encode() + b'\0' + digest))
        return oid(b'tree', b''.join(row for _, row in sorted(rows)))

    return walk('').hex()


def identity(bodies):
    return dict(files=len(bodies), bytes=sum(map(len, bodies.values())),
                tree=tree(bodies), map=pin(bodies[MAP]))


def validate(bodies, expected):
    need(identity(bodies) == expected, 'exact source census, tree and map required')
    mapping = json.loads(bodies[MAP])
    rows = {name: dict(pin(raw), mode=0o644) for name, raw in bodies.items() if name != MAP}
    need(rows == mapping['files'] and all(value is None for value in mapping['actual'].values()),
         'complete source body/mode map and unissued selectors required')


def restore(bodies, predecessors):
    """Restore each predecessor from its retained map and pinned before-bodies."""
    for index, expected in enumerate(predecessors):
        if index < 3:
            rows = json.loads(bodies[MARKER])['before']
            carried = {}
            for name, row in rows.items():
                body = base64.b64decode(row['body_base64'], validate=True)
                need(row['mode'] == 0o644 and pin(body) == row['pin'], 'exact retained before-body')
                carried[name] = body
        else:
            prefix = f'previous-v{7-index}/'
            carried = {name.removeprefix(prefix): raw for name, raw in bodies.items()
                       if name.startswith(prefix)}
        mapping = carried[MAP]
        need(pin(mapping) == expected['map'], 'exact retained predecessor map')
        included = json.loads(mapping)['files']
        need(set(carried) <= set(included) | {MAP}, 'unexpected retained predecessor leaf')
        bodies = {name: carried[name] if name in carried else bodies[name] for name in included}
        bodies[MAP] = mapping
        validate(bodies, expected)
    return bodies
