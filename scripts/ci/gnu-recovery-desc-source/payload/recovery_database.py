# SPDX-License-Identifier: MIT
"""Bounded raw held-glibc database evidence around an unchanged checkpoint.

C (and optionally R) is injected by the source-owned loader. Importing this
module performs no observation, transaction, or other actor operation.
"""
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import types

LOCAL = 'var/lib/pacman/local'
DESC_LIMIT = 65536
LOG_LIMIT = 256 * 1024
COMPRESSED_LIMIT = 64 * 1024**2
MAP_LIMIT = 256 * 1024**2
FAILURE = 'FAILURE_DIAGNOSTIC_NOT_ACCEPTANCE'
OPERATIONS = {'remove-interruption', 'candidate-extraction-interruption'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _root_owner(info):
    return info.st_uid == info.st_gid == 0


@contextlib.contextmanager
def parent_fd(path, *, mutation=False):
    """Pin every ordinary ancestor; refuse a changed path after the read."""
    path = Path(path)
    need(path.is_absolute() and path == Path(os.path.abspath(path)) and
         all(p not in ('.', '..') for p in path.parts), 'canonical absolute evidence path')
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    pins = []
    try:
        for name in path.parts[1:-1]:
            before = os.stat(name, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode), 'ordinary evidence ancestors')
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=fds[-1])
            need(identity(before) == identity(os.fstat(fd)), 'stable evidence ancestor')
            pins.append((fds[-1], name, identity(before), fd))
            fds.append(fd)
        yield fds[-1], path.name
        for parent, name, pin, fd in pins:
            current, linked = identity(os.fstat(fd)), identity(os.stat(
                name, dir_fd=parent, follow_symlinks=False))
            # Exclusive export adds one child to its final parent.
            size = 6 if mutation and fd == fds[-1] else 9
            need(pin[:size] == current[:size] == linked[:size], 'unchanged evidence ancestors')
    finally:
        for fd in reversed(fds):
            os.close(fd)


def read_plain(path, limit, *, descriptor=False):
    with parent_fd(path) as (parent, name):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             0 <= info.st_size <= limit, 'bounded single-link regular evidence file')
        if descriptor:
            need(_root_owner(info) and stat.S_IMODE(info.st_mode) == 0o644,
                 'root-owned mode0644 held descriptor')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        try:
            need(identity(info) == identity(os.fstat(fd)), 'same evidence FD')
            need(not os.listxattr(fd), 'plain evidence file without xattrs')
            raw = bytearray()
            while True:
                part = os.read(fd, min(65536, info.st_size + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
                need(len(raw) <= info.st_size, 'stable evidence extent')
            need(len(raw) == info.st_size and identity(info) == identity(os.fstat(fd))
                 == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) and
                 not os.listxattr(fd), 'whole unchanged evidence FD')
        finally:
            os.close(fd)
    node = dict(type='file', mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                gid=info.st_gid, bytes=len(raw), sha256=sha(raw))
    return bytes(raw), identity(info), node


def parse(raw):
    """Return exact fields and a skeleton replacing only INSTALLDATE digits."""
    need(type(raw) is bytes and 0 < len(raw) <= DESC_LIMIT, 'descriptor bound')
    need(not any(c < 32 and c not in (9, 10) or c == 127 for c in raw),
         'descriptor control byte')
    raw.decode('utf-8', errors='strict')
    need(raw.endswith(b'\n\n'), 'descriptor canonical final separator')
    position, fields, date_span = 0, {}, None
    for block in raw[:-2].split(b'\n\n'):
        lines = block.split(b'\n')
        header = lines[0]
        need(re.fullmatch(rb'%[A-Z][A-Z0-9_]*%', header) is not None and
             len(lines) >= 2 and all(lines[1:]), 'descriptor canonical field block')
        key = header[1:-1].decode('ascii')
        need(len(key) <= 64 and key not in fields and len(fields) < 128,
             'descriptor unique bounded fields')
        need(not any(re.fullmatch(rb'%[A-Z][A-Z0-9_]*%', value) for value in lines[1:]),
             'descriptor nested field header')
        body = b'\n'.join(lines[1:]) + b'\n'
        fields[key] = body
        if key == 'INSTALLDATE':
            need(len(lines) == 2 and re.fullmatch(rb'[0-9]{1,20}', lines[1]) is not None,
                 'descriptor ASCII install date')
            date = int(lines[1])
            need(date <= 2**63 - 1, 'descriptor install date range')
            date_span = (position + len(header) + 1, len(lines[1]), date)
        position += len(block) + 2
    need(date_span is not None, 'descriptor install date required')
    start, size, date = date_span
    normalized = raw[:start] + b'@INSTALLDATE@' + raw[start + size:]
    return fields, date, normalized


def capture(path, expected=None):
    raw, pin, node = read_plain(path, DESC_LIMIT, descriptor=True)
    if expected is not None:
        need(node == expected, 'descriptor bytes and full metadata join root observation')
    result = dict(raw_base64=base64.b64encode(raw).decode('ascii'), bytes=len(raw),
                  sha256=sha(raw), identity=pin, logical_node=node,
                  install_date=None, non_date_sha256=None, parse_error=None)
    try:
        _, result['install_date'], normalized = parse(raw)
        result['non_date_sha256'] = sha(normalized)
    except (ValueError, UnicodeError):
        result['parse_error'] = 'INVALID_CANONICAL_DESCRIPTOR'
    return result


def compare(before, after):
    result = dict(metadata_equal=False, field_order_equal=False,
                  field_values_equal_except_install_date=False,
                  normalized_bytes_equal=False, fields=[])
    if before is None or after is None:
        return result
    keys = ('type', 'mode', 'uid', 'gid')
    result['metadata_equal'] = all(before['logical_node'][k] == after['logical_node'][k]
                                   for k in keys)
    if before['parse_error'] is not None or after['parse_error'] is not None:
        return result
    a, _, an = parse(base64.b64decode(before['raw_base64'], validate=True))
    b, _, bn = parse(base64.b64decode(after['raw_base64'], validate=True))
    result['field_order_equal'] = list(a) == list(b)
    result['normalized_bytes_equal'] = an == bn
    result['field_values_equal_except_install_date'] = (
        {k: v for k, v in a.items() if k != 'INSTALLDATE'} ==
        {k: v for k, v in b.items() if k != 'INSTALLDATE'})
    result['fields'] = [dict(name=k, before_sha256=sha(a[k]) if k in a else None,
                             after_sha256=sha(b[k]) if k in b else None,
                             equal=k in a and k in b and a[k] == b[k])
                        for k in dict.fromkeys([*a, *b])]
    return result


def owned(lane, root, case):
    need(case in ('pristine', 'modified') and isinstance(root, Path) and
         root == lane.WORK / case / 'root' and root == root.resolve() and
         not any(p.is_symlink() for p in (root, *root.parents)),
         'exact existing disposable clone only')
    for path, mode in ((root, 0o755), (root.parent, 0o700)):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
             stat.S_IMODE(info.st_mode) == mode, 'owned clone and private parent')


def descriptor_path(base):
    version = base.get('glibc')
    need(type(version) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_:~@-]{0,127}',
                                             version) is not None,
         'bounded ordinary held glibc version')
    return LOCAL + '/glibc-' + version + '/desc'


def _pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, 'duplicate evidence JSON key')
        value[key] = item
    return value


def recovered_map(lane, case):
    path = lane.OUT / (case + '-recovered-held574-root.json.gz')
    compressed, _, _ = read_plain(path, COMPRESSED_LIMIT)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode='rb') as stream:
        raw = stream.read(MAP_LIMIT + 1)
        need(len(raw) <= MAP_LIMIT and not stream.read(1), 'original root map decoded bound')
    result = json.loads(raw, object_pairs_hook=_pairs,
                        parse_constant=lambda _: need(False, 'finite evidence JSON'))
    need(type(result) is dict and result.get('complete') is True and
         type(result.get('nodes')) is dict and
         type(result.get('unsupported_counts')) is dict and
         set(result['unsupported_counts']) <= {'absolute-symlink', 'auxiliary-present'} and
         type(result.get('security_capabilities')) is dict,
         'existing complete original recovered-held574 map')
    return result


def database_checks(lane, api, root, base, rows, before, recovered, desc):
    after_rows = lane.database(api, root)
    prefix = desc.rsplit('/', 1)[0]
    local = lambda nodes: {n: r for n, r in nodes.items()
                           if n == LOCAL or n.startswith(LOCAL + '/')}
    unrelated = lambda nodes: {n: r for n, r in local(nodes).items()
                               if n != prefix and not n.startswith(prefix + '/')}
    held = lambda nodes: {n: r for n, r in nodes.items()
                          if (n == prefix or n.startswith(prefix + '/')) and n != desc}
    user = lambda nodes: {n: r for n, r in nodes.items()
                          if n == lane.USER or n.startswith(lane.USER + '/')}
    configs = lambda nodes: {n: r for n, r in nodes.items() if n in lane.CONFIGS}
    a, b = before['nodes'], recovered['nodes']
    return dict(base_packages=len(base), before_rows=len(rows), after_rows=len(after_rows),
                before_rows_sha256=sha(canonical(rows)), after_rows_sha256=sha(canonical(after_rows)),
                rows_equal=rows == after_rows,
                inventory_equal=lane.inventory(rows) == lane.inventory(after_rows) == base,
                ownership_equal=lane.ownership(rows) == lane.ownership(after_rows),
                unrelated_db_equal=unrelated(a) == unrelated(b),
                held_other_db_equal=held(a) == held(b), configs_equal=configs(a) == configs(b),
                user_equal=user(a) == user(b),
                capabilities_equal=before['security_capabilities'] == recovered['security_capabilities'])


def export(lane, case, value, report):
    raw = canonical(value)
    need(len(raw) <= LOG_LIMIT, 'bounded descriptor evidence JSON')
    path = lane.OUT / (case + '-recovery-db-descriptors.log')
    with parent_fd(path, mutation=True) as (parent, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o644, dir_fd=parent)
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                need(stream.write(raw) == len(raw), 'complete descriptor evidence export')
                stream.flush()
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 stat.S_IMODE(info.st_mode) == 0o644 and info.st_size == len(raw),
                 'exclusive ordinary descriptor evidence export')
        finally:
            os.close(fd)
    report['recovery_database_evidence'] = dict(path=path.name, bytes=len(raw),
                                               sha256=sha(raw), status=value['status'])


def wrap(original_checkpoint_module, lifecycle_module, operation):
    """Clone one checkpoint namespace; call its original exercise unchanged."""
    need(operation in OPERATIONS and isinstance(original_checkpoint_module, types.ModuleType)
         and callable(original_checkpoint_module.exercise), 'known unchanged checkpoint operation')
    original = original_checkpoint_module.exercise
    clone = types.ModuleType(original_checkpoint_module.__name__ + '_raw_db_evidence')
    clone.__dict__.update(original_checkpoint_module.__dict__)

    def exercise(api, lane, root, index, base, new, old, before, case, report):
        need(lane is lifecycle_module, 'exact source lifecycle module')
        owned(lane, root, case)
        need(type(before) is dict and before.get('complete') is True and
             type(before.get('nodes')) is dict and
             type(before.get('security_capabilities')) is dict,
             'complete original before574 map')
        rows = lane.database(api, root)
        need(type(base) is dict and len(base) == len(rows) == 574 and
             lane.inventory(rows) == base, 'original574 ordinary inventory before checkpoint')
        desc = descriptor_path(base)
        need(desc in before['nodes'], 'before descriptor joins original574 observation')
        first = capture(root / desc, before['nodes'][desc])
        value = dict(schema=1, operation=operation, case=case, descriptor_path=desc,
                     before=first, after=None, comparison=compare(first, None),
                     database_checks=None, status=FAILURE, diagnostic=None)
        if first['parse_error'] is not None:
            value['diagnostic'] = 'BEFORE_DESCRIPTOR_GRAMMAR_REFUSED'
            export(lane, case, value, report)
            need(False, 'canonical before descriptor required before checkpoint')
        try:
            result = original(api, lane, root, index, base, new, old, before, case, report)
        except BaseException as error:
            # Diagnostic raw bytes never upgrade a failed original exercise.
            value['diagnostic'] = 'ORIGINAL_EXERCISE_FAILED'
            try:
                value['after'] = capture(root / desc)
                value['comparison'] = compare(first, value['after'])
            except (OSError, ValueError, UnicodeError):
                value['diagnostic'] = 'ORIGINAL_EXERCISE_FAILED_CURRENT_DESCRIPTOR_UNAVAILABLE'
            try:
                export(lane, case, value, report)
            except BaseException as secondary:
                error.add_note('Descriptor diagnostic export failed: ' + type(secondary).__name__)
            raise
        try:
            recovered = recovered_map(lane, case)
            need(desc in recovered['nodes'], 'after descriptor joins original recovered map')
            value['after'] = capture(root / desc, recovered['nodes'][desc])
            value['comparison'] = compare(first, value['after'])
            value['database_checks'] = database_checks(lane, api, root, base, rows,
                                                       before, recovered, desc)
            comparison = value['comparison']
            checks = value['database_checks']
            valid = (all(comparison[k] is True for k in ('metadata_equal', 'field_order_equal',
                     'field_values_equal_except_install_date', 'normalized_bytes_equal')) and
                     checks['base_packages'] == checks['before_rows'] == checks['after_rows'] == 574 and
                     all(v is True for k, v in checks.items() if k.endswith('_equal')))
            value['status'] = 'PASS' if valid else FAILURE
            value['diagnostic'] = None if valid else 'RAW_DESCRIPTOR_OR_DATABASE_POSTCONDITION_REFUSED'
        except BaseException as error:
            value['diagnostic'] = 'POSTCONDITION_OBSERVATION_FAILED'
            try:
                if value['after'] is None:
                    value['after'] = capture(root / desc)
                    value['comparison'] = compare(first, value['after'])
                export(lane, case, value, report)
            except BaseException as secondary:
                error.add_note('Descriptor diagnostic export failed: ' + type(secondary).__name__)
            raise
        # Retain both raw descriptions before asserting the strict comparison.
        export(lane, case, value, report)
        need(valid, 'recovered database must differ only in canonical INSTALLDATE digits')
        return result

    clone.exercise = exercise
    return clone
