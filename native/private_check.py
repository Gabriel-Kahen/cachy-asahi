#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private image export materialization and future exact external check proof."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile

MAX_BYTES = 8 * 1024**3
MAX_MEMBERS = 150000
OMIT = {'dev', 'proc', 'sys'}

def need(ok, message):
    if not ok: raise ValueError(message)

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def parts(name):
    need(type(name) is str and 0 < len(name) <= 4096 and '\0' not in name, 'bounded tar path')
    name = name.removeprefix('./').removesuffix('/')
    need(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')), 'relative canonical tar path')
    return tuple(name.split('/'))

def directory(path):
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd); raise

def parent_fd(root, names, modes):
    fd = os.dup(root)
    try:
        for index, name in enumerate(names):
            try: os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError: pass
            modes.setdefault('/'.join(names[:index + 1]), 0o755)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd); raise

def materialize(export_tar, target_root):
    """Read one <=8GiB raw export; write only a fresh private caller-owned root."""
    export_tar, target_root = Path(export_tar).absolute(), Path(target_root).absolute()
    source_parent = directory(export_tar.parent)
    try: source = os.open(export_tar.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_parent)
    finally: os.close(source_parent)
    try: parent = directory(target_root.parent)
    except BaseException:
        os.close(source); raise
    root = None; made = False
    try:
        before = os.fstat(source)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_BYTES, 'bounded named regular export')
        digest = hashlib.sha256(); size = 0
        with os.fdopen(source, 'rb', closefd=False) as stream:
            while block := stream.read(1024**2):
                size += len(block); need(size <= MAX_BYTES, 'export byte cap'); digest.update(block)
            need(size == before.st_size, 'complete export')
            stream.seek(0)
            os.mkdir(target_root.name, 0o700, dir_fd=parent); made = True
            root = os.open(target_root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            seen, regular, hardlinks, links, modes, directories = set(), {}, {}, {}, {}, {}
            expanded = omitted = count = 0; stripped = []
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                for item in archive:
                    count += 1; need(count <= MAX_MEMBERS, 'export member cap')
                    if item.name in ('.', './') and item.isdir():
                        need('' not in seen, 'duplicate export root'); seen.add(''); continue
                    names = parts(item.name); name = '/'.join(names)
                    need(name not in seen, 'duplicate export member'); seen.add(name)
                    if names[0] in OMIT: omitted += 1; continue
                    if item.mode & 0o6000: stripped.append(name)
                    mode = item.mode & 0o1777
                    if item.isdir():
                        fd = parent_fd(root, names, directories); os.close(fd)
                        directories[name] = mode
                    elif item.isfile():
                        need(not item.sparse and 0 <= item.size <= MAX_BYTES - expanded, 'bounded nonsparse regular member')
                        expanded += item.size
                        fd = parent_fd(root, names[:-1], directories)
                        try:
                            out = os.open(names[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                            with os.fdopen(out, 'wb') as target, archive.extractfile(item) as body:
                                remaining = item.size
                                while remaining:
                                    block = body.read(min(remaining, 1024**2)); need(block, 'complete regular tar body')
                                    target.write(block); remaining -= len(block)
                        finally: os.close(fd)
                        regular[name] = item.size; modes[name] = mode
                    elif item.islnk(): hardlinks[name] = '/'.join(parts(item.linkname))
                    elif item.issym():
                        need(type(item.linkname) is str and 0 < len(item.linkname) <= 4096 and '\0' not in item.linkname, 'bounded symlink target')
                        links[name] = item.linkname
                    else: raise ValueError('special export member outside dev/proc/sys')
            resolved = {}
            for destination in hardlinks:
                chain, positions, name = [], set(), destination
                while name not in regular and name not in resolved:
                    need(name in hardlinks and name not in positions and len(chain) < 256, 'safe acyclic regular hardlink target')
                    positions.add(name); chain.append(name); name = hardlinks[name]
                origin = resolved.get(name, name)
                need(origin in regular, 'hardlink cannot target symlink/special/missing member')
                for key in chain: resolved[key] = origin
            for name, origin in resolved.items():
                length = regular[origin]
                need(length <= MAX_BYTES - expanded, 'expanded hardlink copy byte cap'); expanded += length
                names, target_names = parts(name), parts(origin)
                dest_fd = parent_fd(root, names[:-1], directories)
                source_fd = parent_fd(root, target_names[:-1], directories)
                try:
                    src = os.open(target_names[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
                    try:
                        dst = os.open(names[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dest_fd)
                        with os.fdopen(dst, 'wb') as target:
                            remaining = length
                            while remaining:
                                block = os.read(src, min(remaining, 1024**2)); need(block, 'complete hardlink source copy')
                                target.write(block); remaining -= len(block)
                    finally: os.close(src)
                finally: os.close(dest_fd); os.close(source_fd)
                modes[name] = modes[origin]
            # All link objects are delayed until no archive body can traverse them.
            for name, link in links.items():
                names = parts(name); fd = parent_fd(root, names[:-1], directories)
                try: os.symlink(link, names[-1], dir_fd=fd)
                finally: os.close(fd)
            for name, mode in modes.items():
                names = parts(name); fd = parent_fd(root, names[:-1], directories)
                try:
                    out = os.open(names[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                    try: os.fchmod(out, mode)
                    finally: os.close(out)
                finally: os.close(fd)
            # Mount points contain no exported dev/proc/sys objects. Key masks are mandatory.
            mountpoints = ('dev', 'proc', 'sys', 'run', 'home', 'root', 'tmp', 'source', 'work', 'etc/pacman.d/gnupg')
            for name in mountpoints:
                fd = parent_fd(root, parts(name), directories); os.close(fd)
            for name, mode in sorted(directories.items(), key=lambda row: len(parts(row[0])), reverse=True):
                names = parts(name); fd = parent_fd(root, names[:-1], directories)
                try:
                    child = os.open(names[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try: os.fchmod(child, mode)
                    finally: os.close(child)
                finally: os.close(fd)
            after = os.fstat(source)
            stable = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_nlink)
            need(stable(before) == stable(after), 'export changed during materialization')
            return dict(schema=1, status='PASS_PRIVATE_ROOTFS_MATERIALIZATION_ONLY', export=dict(bytes=size, sha256=digest.hexdigest()),
                members=count, expanded_bytes=expanded, regular_files=len(regular), hardlinks_copied=len(resolved),
                symlinks_delayed=len(links), omitted_dev_proc_sys=omitted, suid_sgid_stripped=len(stripped),
                stripped_examples=stripped[:256], stripped_examples_truncated=len(stripped) > 256,
                generated_mountpoints=list(mountpoints), private_root_mode='0700', chown=False, executed=False,
                keys='PRIVATE_ROOT_ONLY_NOT_PUBLIC_DATA')
    except BaseException:
        if made:
            # fd-relative rmtree uses the platform's symlink-resistant implementation.
            shutil.rmtree(target_root.name, dir_fd=parent)
        raise
    finally:
        if root is not None: os.close(root)
        os.close(parent); os.close(source)

def proof_command(rootfs, source, work, recipe_root):
    paths = [Path(p).absolute() for p in (rootfs, source, work)]
    for path in paths:
        fd = directory(path); os.close(fd)
        need(path.stat().st_uid == os.getuid(), 'caller-owned proof paths')
    rootfs, source, work = paths
    need(not any(a == b or a.is_relative_to(b) for index, a in enumerate(paths) for j, b in enumerate(paths) if index != j), 'disjoint private proof paths')
    need(parts(recipe_root)[:2] == ('packages', 'tools'), 'reviewed relative recipe root')
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--ro-bind', str(rootfs), '/', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--tmpfs', '/home', '--tmpfs', '/run', '--tmpfs', '/sys',
        '--tmpfs', '/root', '--tmpfs', '/etc/pacman.d/gnupg',
        '--ro-bind', str(source), '/source', '--bind', str(work), '/work', '--chdir', '/work',
        '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C',
        '--setenv', 'HOME', '/tmp/proof-home', '--setenv', 'TMPDIR', '/tmp/proof-tmp', '--',
        '/usr/bin/python3', '-I', '-B', '/source/native/private_check.py', '--inner', '--recipe-root', recipe_root]

def inner(recipe_root):
    """Future native proof child. This function is never called by data controls."""
    import importlib.util
    import platform
    import subprocess
    import sys
    source, work = Path('/source'), Path('/work')
    sys.path.insert(0, '/source/native')
    from common import execution_selection, load, read, save, verify_source
    request = load(work / 'proof-input.json')
    need(request.get('schema') == 1 and request['recipe_root'] == recipe_root, 'exact proof input recipe')
    binding = request['binding']
    need(re.fullmatch('[0-9a-f]{40}', binding.get('source_sha') or '') and binding.get('attempt') == 1
         and re.fullmatch('[1-9][0-9]*', binding.get('run_id') or '') and binding.get('ref', '').startswith('refs/heads/codex/'), 'actual proof binding')
    need(re.fullmatch('sha256:[0-9a-f]{64}', request.get('image') or ''), 'immutable actual exported image')
    verify_source(source, request['source_map_sha256'])
    selected = execution_selection(source)['selected_package']
    recipe = source.joinpath(*parts(recipe_root))
    source_files = {name: row for name, row in selected['files'].items() if PurePosixPath(name).parent.as_posix() == recipe_root}
    need(len(source_files) == 17 and source_files == request['source_files'], 'exact sealed seventeen-file recipe')
    for name, row in source_files.items():
        path = source / name
        need(pin(read(path)) == {k: row[k] for k in ('bytes', 'sha256')}
             and stat.S_IMODE(path.stat().st_mode) == row['mode'], 'actual selected source bytes/modes')
    need(pin(read(recipe / 'PKGBUILD'))['sha256'] == selected['recipe_sha256'] == request['recipe_sha256'], 'exact selected check function recipe')
    original = read(source / 'native/original341.lock')
    need(pin(original)['sha256'] == request['original341_sha256'] and len(original.splitlines()) == 341, 'actual original341 inventory binding')
    need(platform.machine() == 'aarch64' and os.getuid() == os.geteuid() != 0, 'actual nonroot native ARM proof')
    need(Path('/usr/bin/bwrap').is_file() and os.access('/usr/bin/bwrap', os.X_OK), 'original341 nested bubblewrap required')
    need(all(not any(Path(name).iterdir()) for name in ('/home', '/run', '/sys', '/root', '/etc/pacman.d/gnupg')),
         'home/run/sys/root and both private keyring paths masked')
    test_module = next((name for name in source_files if name.endswith('/test_package.py')), None)
    need(test_module is not None, 'sealed package test source')
    import ast
    tree = ast.parse(read(source / test_module))
    methods = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    need(len(methods) == len(set(methods)) == 6, 'exact six sealed package methods')
    for path in (Path('/tmp/proof-home'), Path('/tmp/proof-tmp'), Path('/tmp/proof-work'), work / 'logs'):
        path.mkdir(mode=0o700)
    owned_path = source / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py'
    spec = importlib.util.spec_from_file_location('_support_private_check_owned', owned_path)
    owned = importlib.util.module_from_spec(spec); sys.modules[spec.name] = owned; spec.loader.exec_module(owned)
    commands = []
    def command(argv, log, timeout):
        state = {}; path = work / log
        with path.open('xb') as stream:
            result = owned.run(argv, cwd='/tmp/proof-work', env=dict(PATH='/usr/bin:/bin', LC_ALL='C', LANG='C', HOME='/tmp/proof-home', TMPDIR='/tmp/proof-tmp'),
                stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout,
                lifecycle=state, allowed_uids={os.getuid()})
        row = dict(argv=argv, log=log, log_pin=pin(read(path)), supervision=state, expected_exit=0, status='FAIL')
        commands.append(row)
        save(work / 'commands.json', commands)
        need(result.returncode == state.get('exit') == 0 and state.get('retirement') == 'REAPED'
             and state.get('natural_exit') is True and state.get('group_absent') is True
             and state.get('leader_held_until_group_inspection') is True and state.get('exit_observed_via_waitpid') is True
             and state.get('ownership_lost') is False and state.get('forced_cleanup') is False, 'actual natural proof retirement')
        row['status'] = 'PASS'
        save(work / 'commands.json', commands)
        return read(path)
    inventory = command(['/usr/bin/pacman', '-Q'], 'logs/inventory.log', 30)
    inventory = b''.join(sorted(inventory.splitlines(keepends=True)))
    need(inventory == original, 'actual exported original341 inventory')
    shell = 'set -euo pipefail\nsrcdir=$1\nstartdir=$1\nsource "$1/PKGBUILD"\ncheck\n'
    log = command(['/usr/bin/bash', '--noprofile', '--norc', '-c', shell, 'support-external-exact-check', str(recipe)], 'check.log', 900)
    lines = log.decode('utf-8').splitlines()
    for method in methods:
        need(sum(bool(re.fullmatch(re.escape(method) + r' \([^\n]+\) \.\.\. ok', line)) for line in lines) == 1, 'actual exact named check completion')
    need(sum(bool(re.fullmatch(r'Ran 6 tests in [0-9.]+s', line)) for line in lines) == 1
         and lines[-1] == 'OK' and not any('skipped' in line.lower() or line.startswith(('FAILED', 'ERROR:', 'FAIL:')) for line in lines), 'exact six completed checks with zero skips')
    result = dict(schema=1, status='PASS_EXTERNAL_EXACT_CHECK_FUNCTION', binding=binding,
        source_map_sha256=request['source_map_sha256'], image=request['image'], recipe_sha256=request['recipe_sha256'],
        source_files=source_files, architecture=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(), inventory=pin(inventory),
        checks=dict(count=6, skips=0, methods=methods, exit=0, log='check.log', log_pin=pin(log)), commands=commands)
    save(work / 'proof-result.json', result)
    return result

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inner', action='store_true', required=True)
    parser.add_argument('--recipe-root', required=True)
    args = parser.parse_args()
    print(json.dumps(inner(args.recipe_root), sort_keys=True))
