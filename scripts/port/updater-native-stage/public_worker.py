#!/usr/bin/env python3
"""Authenticated local evidence operations; the caller bounds process lifetime."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
import uuid

MODULES = {
    'project': 'packages/tools/cachy-asahi-update/public-evidence.py',
    'guard': 'scripts/ci/integration_export.py',
    'bundle': 'scripts/ci/log_evidence.py',
}
MODULE_LIMIT = 4 * 1024**2
BUNDLE_LIMIT = 8 * 1024**2


def need(value):
    if not value:
        raise ValueError('public-operation-refused')


def absolute(value):
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts and str(path) == os.path.abspath(path))
    return path


def directory(path, root=None):
    """Open every component without following links; require owned inner paths."""
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = Path('/')
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd);fd = child;current /= part
            info = os.fstat(fd)
            if root is not None and (current == root or root in current.parents):
                need(info.st_uid == os.getuid() and not info.st_mode & 0o7022)
        return fd
    except BaseException:
        os.close(fd)
        raise


def module_bytes(path, expected, root):
    need(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected))
    parent = directory(path.parent, root)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
             and not before.st_mode & 0o7022 and before.st_size <= MODULE_LIMIT)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MODULE_LIMIT + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_nlink,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(after) and len(raw) == before.st_size
             and hashlib.sha256(raw).hexdigest() == expected)
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def atomic_bundle(rootfd, name, data):
    need(type(data) is bytes and len(data) <= BUNDLE_LIMIT)
    temporary = '.public-bundle-' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=rootfd)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            count = os.write(fd, view);need(count > 0);view = view[count:]
        os.fsync(fd)
        # link publishes atomically and refuses an existing destination.
        os.link(temporary, name, src_dir_fd=rootfd, dst_dir_fd=rootfd, follow_symlinks=False)
    finally:
        os.close(fd)
        os.unlink(temporary, dir_fd=rootfd)
    os.fsync(rootfd)


def public_tree(path, root):
    """Public inputs contain only bounded owned directories and single files."""
    fd = directory(path, root)
    count, size, device = 0, 0, os.fstat(fd).st_dev
    def walk(parent, depth):
        nonlocal count, size
        need(depth <= 32)
        with os.scandir(parent) as entries:
            for entry in entries:
                count += 1;need(count <= 2048)
                info = os.stat(entry.name, dir_fd=parent, follow_symlinks=False)
                need(info.st_uid == os.getuid() and info.st_dev == device and not info.st_mode & 0o7022)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    try:
                        opened = os.fstat(child)
                        need((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino))
                        walk(child, depth + 1)
                    finally:os.close(child)
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                    size += info.st_size;need(size <= 16 * 1024**2)
    try:walk(fd, 0)
    finally:os.close(fd)


@contextlib.contextmanager
def quiet():
    """Suppress Python and direct-fd diagnostics from authenticated helpers."""
    saved = []
    with open(os.devnull, 'w') as discard:
        try:
            sys.stdout.flush();sys.stderr.flush()
            for number in (1, 2):
                saved.append((number, os.dup(number)))
                os.dup2(discard.fileno(), number)
            with contextlib.redirect_stdout(discard), contextlib.redirect_stderr(discard):
                yield
        finally:
            for number, duplicate in saved:
                try:os.dup2(duplicate, number)
                finally:os.close(duplicate)


def execute(operation, module_path, module_sha256, input_path, output_path, stage_output, materialized=None):
    """Fixed project/guard/bundle ABI; the CLI emits only fixed status JSON."""
    sys.dont_write_bytecode = True
    need(operation in MODULES)
    root = absolute(stage_output)
    need(Path('/tmp') in root.parents and root != Path('/tmp'))
    rootfd = directory(root, root)
    try:
        info = os.fstat(rootfd);need(stat.S_IMODE(info.st_mode) == 0o700)
        module_path, input_path, output_path = map(absolute, (module_path, input_path, output_path))
        need(module_path == root / 'private/source' / MODULES[operation])
        allowed = {'project': (root/'private/native', root/'private/empty-raw'),
                   'guard': (root/'projected',), 'bundle': (root/'guarded',)}
        target = {'project': root/'projected', 'guard': root/'guarded', 'bundle': root/'public-evidence.tar.gz'}
        need(input_path in allowed[operation] and output_path == target[operation])
        fd = directory(input_path, root);os.close(fd)
        if operation != 'project':
            public_tree(input_path, root)
        need(not os.path.lexists(output_path))
        if materialized is not None:
            materialized = absolute(materialized)
            need(operation == 'project' and materialized == root/'private/materialized')
            fd = directory(materialized, root);os.close(fd)
        raw = module_bytes(module_path, module_sha256, root)
        imported = types.ModuleType('_authenticated_public_' + operation)
        imported.__file__ = str(module_path)
        imported.__package__ = None
        # Suppress even module-level Python diagnostics; public stdout is fixed.
        with quiet():
            exec(compile(raw, str(module_path), 'exec'), imported.__dict__)
            if operation == 'project':
                result = imported.project_evidence(input_path, output_path, materialized=materialized)
                need(type(result) is dict and result.get('projection') == 'PASS')
            elif operation == 'guard':
                result = imported.export_evidence(input_path, output_path)
                need(type(result) is dict and result.get('evidence_export') == 'PASS')
            else:
                atomic_bundle(rootfd, output_path.name, imported.bundle(input_path))
        if operation != 'bundle':
            public_tree(output_path, root)
        return {'status': 'PASS', 'operation': operation}
    finally:
        os.close(rootfd)


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError('public-operation-arguments')


def main(argv=None):
    operation = None
    try:
        parser = Parser(add_help=False)
        parser.add_argument('--operation', choices=tuple(MODULES), required=True)
        for name in ('module', 'module-sha256', 'input', 'output', 'stage-output'):
            parser.add_argument('--' + name, required=True)
        parser.add_argument('--materialized')
        args = parser.parse_args(argv)
        operation = args.operation
        result = execute(operation, args.module, args.module_sha256, args.input, args.output, args.stage_output, args.materialized)
    except BaseException:
        result = {'status': 'FAIL', 'operation': operation}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
