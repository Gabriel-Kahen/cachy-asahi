#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage/check a finite fresh-handoff operator runtime; no checkout fallback.

The caller supplies an external runtime.json SHA-256 before local helper imports.
The entry-point body itself must come from the trusted, reviewed delivery. This
transport inventory supplies byte identity, not release or key-owner trust.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
MANIFEST = 'runtime.json'
LOCK = 'source-lock.json'
ENTRY = 'scripts/install/fresh_handoff/handoff.py'
RUNTIME = (
    ENTRY, 'scripts/install/fresh_handoff/runtime.py',
    'scripts/release/recovery_bundle.py', 'scripts/release/offline_kit.py',
    'scripts/release/source_delivery.py', 'scripts/client/client.py',
    'scripts/platform/recovery_inputs.py', 'scripts/platform/authenticate_missing.py',
    'scripts/platform/archive_coverage.py', 'scripts/platform/capture.py',
    'scripts/platform/transaction.py', 'scripts/platform/tuple_audit.py',
    'scripts/port/authenticate.py', 'scripts/port/preview.py',
    'scripts/ci/native_arm.py', 'scripts/checks/package_checks.py',
    'scripts/integration/lifecycle.py',
)
INTERFACES = (
    'manifests/packages.toml', 'scripts/install/local_transaction.py',
    'scripts/install/native_preflight.py', 'scripts/install/first_login.py',
    'scripts/repository/enroll.py', 'scripts/release/offline_kit.py',
    'scripts/release/recovery_bundle.py', 'scripts/platform/recovery_preflight.py',
    'packages/tools/cachy-asahi-first-login/PKGBUILD',
    'packages/tools/cachy-asahi-setup8/PKGBUILD',
    'packages/tools/cachy-asahi-setup8/cachy-asahi-setup',
    'packages/tools/cachy-asahi-repository-enrollment-v3/PKGBUILD',
    'packages/shells/cachy-asahi-fish-config/config.fish',
    'packages/shells/cachy-asahi-zsh-config/config.zsh',
    'packages/desktop/cachy-asahi-hyprland-settings011/hyprland.lua',
)
FILES = frozenset((*RUNTIME, *INTERFACES, 'LICENSE', LOCK))
MAX_FILE, MAX_TOTAL = 4 * 1024**2, 32 * 1024**2
HEX = re.compile('[0-9a-f]{64}\\Z')


class Error(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Error(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate runtime JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise Error('runtime JSON floats/nonfinite refused')
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict, 'runtime JSON object required')
    return value


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path.anchor == '/', 'absolute runtime path required')
    return path


def directories(path):
    """No directory aliases when staging/checking selected roots."""
    path = absolute(path)
    for parent in (*reversed(path.parents), path):
        need(stat.S_ISDIR(parent.lstat().st_mode), 'runtime directory/symlink refused')
    return path


def read(root, name):
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and '..' not in path.parts, 'unsafe runtime member')
    directory = directories(Path(root) / path.parent)
    fd = os.open(directory / path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_FILE,
             'bounded single-link runtime file required: ' + name)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_FILE + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'runtime member changed')
        return raw
    finally:
        os.close(fd)


def descriptor(raw):
    return dict(size=len(raw), sha256=sha(raw))


def source_lock(commit, refs):
    need(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit), 'exact source commit required')
    need(type(refs) is dict and set(refs) == set(INTERFACES), 'exact owning-interface witness set required')
    for name, row in refs.items():
        need(type(row) is dict and set(row) == {'size', 'sha256'} and
             type(row['size']) is int and 0 < row['size'] <= MAX_FILE and
             type(row['sha256']) is str and HEX.fullmatch(row['sha256']), 'invalid source witness: ' + name)
    return dict(schema_version=1, purpose='fresh-handoff-owning-source-witnesses',
                source_commit=commit, source_refs=refs)


def inventory(root):
    directories(root)
    files, dirs = {}, set()
    for current, children, names in os.walk(root, followlinks=False):
        for name in children:
            path = Path(current) / name
            need(stat.S_ISDIR(path.lstat().st_mode), 'runtime directory alias refused')
            dirs.add(path.relative_to(root).as_posix())
        for name in names:
            relative = (Path(current) / name).relative_to(root).as_posix()
            need(relative in FILES | {MANIFEST}, 'foreign runtime member: ' + relative)
            files[relative] = descriptor(read(root, relative))
    parents = {p.as_posix() for name in files for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    need(dirs == parents, 'empty/foreign runtime directory refused')
    need(sum(row['size'] for row in files.values()) <= MAX_TOTAL, 'runtime total bound exceeded')
    return files


def verify(root, runtime_sha256):
    root = directories(root)
    need(type(runtime_sha256) is str and HEX.fullmatch(runtime_sha256), 'external runtime SHA-256 required')
    raw = read(root, MANIFEST)
    need(sha(raw) == runtime_sha256, 'external runtime inventory pin differs')
    receipt = decode(raw)
    need(set(receipt) == {'schema_version', 'purpose', 'source_commit', 'files'} and
         type(receipt['schema_version']) is int and receipt['schema_version'] == 1 and
         receipt['purpose'] == 'finite-fresh-handoff-operator-runtime', 'unsupported operator runtime')
    files = inventory(root)
    files.pop(MANIFEST, None)
    need(set(files) == FILES and receipt['files'] == files, 'runtime closure incomplete or changed')
    lock = decode(read(root, LOCK))
    need(set(lock) == {'schema_version', 'purpose', 'source_commit', 'source_refs'} and
         type(lock['schema_version']) is int and lock['schema_version'] == 1 and
         lock['purpose'] == 'fresh-handoff-owning-source-witnesses' and
         lock == source_lock(receipt['source_commit'], lock['source_refs']), 'owning-source lock differs')
    need(all(files[name] == row for name, row in lock['source_refs'].items()), 'owning-source witness differs')
    need(inventory(root) == {**files, MANIFEST: descriptor(raw)}, 'runtime changed during verification')
    return lock


def stage(source_root, output, source_commit, source_refs):
    """Copy only reviewed runtime bodies plus Git-checked interface witnesses.

    The composer obtains source_refs using its existing source/Git validation.
    This copies current trusted runtime source, binding it by SHA-256 rather
    than pretending new uncommitted bodies belong to an older Git commit.
    """
    source_root, output = directories(source_root), absolute(output)
    lock = source_lock(source_commit, source_refs)
    need(not output.exists() and not output.is_symlink(), 'fresh runtime output required')
    parent = directories(output.parent)
    info = parent.stat()
    need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'private caller-owned runtime output parent required')
    with tempfile.TemporaryDirectory(prefix='.fresh-handoff-runtime-', dir=parent) as temporary:
        target = Path(temporary) / 'runtime'
        target.mkdir(mode=0o700)
        for name in sorted(FILES):
            raw = encoded(lock) if name == LOCK else read(source_root, name)
            if name in source_refs:
                need(descriptor(raw) == source_refs[name], 'trusted source witness changed: ' + name)
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with destination.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            destination.chmod(0o400)
        receipt = dict(schema_version=1, purpose='finite-fresh-handoff-operator-runtime',
                       source_commit=source_commit, files=inventory(target))
        raw = encoded(receipt)
        path = target / MANIFEST
        path.write_bytes(raw)
        path.chmod(0o400)
        pin = sha(raw)
        verify(target, pin)
        # Reuse the existing no-replace publication helper after verifying every
        # module body. Its finite dependencies are already staged above.
        spec = importlib.util.spec_from_file_location('fresh_runtime_publish', target/'scripts/release/offline_kit.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fd = os.open(parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = target.stat()
            module.publish(target, fd, output, (info.st_dev, info.st_ino))
        finally:
            os.close(fd)
    return dict(path=str(output), runtime_sha256=pin, source_commit=source_commit,
                runtime_files=len(RUNTIME), payload_files=len(FILES) + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-sha256', required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER,
                        help='handoff arguments following --; runtime never discovers a checkout')
    args = parser.parse_args(argv)
    try:
        root = Path(__file__).resolve().parents[3]
        lock = verify(root, args.runtime_sha256)
        arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
        sys.argv = [str(root / ENTRY), *arguments]
        runpy.run_path(str(root / ENTRY), run_name='__main__', init_globals={'DELIVERED_SOURCE_LOCK': lock})
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError) as error:
        print('operator runtime refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
