# SPDX-License-Identifier: MIT
"""Keep the packet's Python bytes in custody across the hosted process boundary."""
import base64
from contextlib import contextmanager
import ctypes
import fcntl
import json
import os
from pathlib import Path

import packet

ACQUISITION = packet.KERNEL + 'acquisition.py'
STAGE = packet.KERNEL + 'stage.py'
PRODUCER = 'scripts/ci/native_arm.py'
BUILD = 'scripts/build/build.py'
BUILD_ENTRY = 'scripts/build/container-entry.sh'
COMPARE = 'scripts/build/compare.py'
CHECKER = 'scripts/checks/package_checks.py'
HARNESS = 'scripts/port/kernel-candidates/harness.py'
COMMIT = 'scripts/ci/commit_image.py'

MODULES = {
    ACQUISITION: {'common': packet.KERNEL + 'common.py', 'package_checks': CHECKER},
    STAGE: {name: packet.KERNEL + name + '.py'
            for name in ('common', 'runtime', 'broker', 'evidence', 'image', 'inner_result')},
    PRODUCER: {'package_checks': CHECKER, 'build': BUILD},
}
LIMIT = 1024**2
# Linux UAPI constants for Python builds compiled without the relevant headers.
ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
GET_SEALS = getattr(fcntl, 'F_GET_SEALS', 1034)
SEALS = 0x0F  # F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
MEMFD_FLAGS = 0x03  # MFD_CLOEXEC | MFD_ALLOW_SEALING
PYTHON = ('/usr/bin/python3', '-I', '-B', '-S', '-c')

# Run with no application filesystem import paths. The payload contains verified
# bytes, their logical filenames and the exact delayed imports used by the child.
LAUNCHER = (f"add_seals, get_seals, seals, memfd_flags = {ADD_SEALS}, {GET_SEALS}, {SEALS}, {MEMFD_FLAGS}\n"
            f"recipes_lock = {packet.RECIPES_LOCK!r}\n") + """\
import base64
import fcntl
import hashlib
from importlib.machinery import BuiltinImporter, FrozenImporter, ModuleSpec, PathFinder
from importlib.util import module_from_spec
import json
import os
from pathlib import Path
import subprocess
import sys

fd, entry, *args = sys.argv[1:]
fd = int(fd)
size = os.fstat(fd).st_size
if fcntl.fcntl(fd, get_seals) & seals != seals or not 0 < size <= 1024**2:
    raise ValueError('unsealed child source')
bodies, modules, aliases, producer, stage, drivers = json.loads(os.pread(fd, size, 0))
if entry == producer:
    os.set_inheritable(fd, False)
else:
    os.close(fd)
bodies = {path: base64.b64decode(data, validate=True) for path, data in bodies.items()}
paths = tuple(sys.path)

class HeldModules:
    def find_spec(self, name, path=None, target=None):
        if name in modules:
            return ModuleSpec(name, self, origin=modules[name])
        # Package submodule searches also stay within the interpreter paths.
        search = paths if path is None else tuple(
            item for item in path if any(item.startswith(base + '/') for base in paths)
        )
        return PathFinder.find_spec(name, search)

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = module.__spec__.origin
        exec(compile(bodies[module.__file__], module.__file__, 'exec'), vars(module))

loader = HeldModules()
if modules.keys() & sys.modules.keys():
    raise ValueError('child import collision')
sys.meta_path = [BuiltinImporter, FrozenImporter, loader]

def load(name, filename, body):
    value = module_from_spec(ModuleSpec(name, loader, origin=filename))
    value.__file__ = filename
    sys.modules[name] = value
    exec(compile(body, filename, 'exec'), vars(value))
    return value

if aliases:
    import common

    def load_alias(name, path):
        filename, source = aliases[name]
        if str(path) != filename:
            raise ValueError('unbound child import: ' + name)
        return load(name, filename, bodies[source])

    common.module = load_alias

sys.argv = [entry, *args]
if entry == producer:
    value = load('kernel_held_producer', entry, bodies[entry])
    original_run, original_sha = value.run, value.sha
    prefix = sys.orig_argv[:6]

    def run(command, log=None, timeout=1800):
        if command[0] != sys.executable:
            return original_run(command, log, timeout)
        if command[1] not in drivers:
            raise ValueError('unbound producer Python driver')
        with log.open('w') as stream:
            result = subprocess.run([*prefix, str(fd), *command[1:]], pass_fds=(fd,),
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise ValueError(f'command failed ({result.returncode}); see {log}')

    value.run = run
    value.sha = lambda path: (hashlib.sha256(bodies[entry]).hexdigest()
                              if path == Path(entry) else original_sha(path))
    raise SystemExit(value.main())
if entry == stage:
    value = load('kernel_held_stage', entry, bodies[entry])
    original_runner = value.Runner

    def runner(seconds, env, log_dir):
        return original_runner(seconds, dict(env, GIT_NO_REPLACE_OBJECTS='1'), log_dir)

    value.Runner = runner
    raise SystemExit(value.main())
if drivers and entry == drivers[0]:
    root = Path(entry).parents[2]
    approved = json.loads(bodies[str(root / recipes_lock)])
    try:
        recipe = Path(args[0]).relative_to(root).as_posix()
        review = approved[recipe]
        option = args.index('--reviewed-inputs')
        if (args[0] != str(root / recipe) or args.count('--reviewed-inputs') != 1
                or not args[option + 1] or args[option + 1].startswith('-')):
            raise ValueError('review argument')
    except (IndexError, KeyError, ValueError):
        raise ValueError('unbound builder reviewed inputs') from None

    # The producer's review file is retained for evidence. The builder reads
    # only the map authorized by the sealed recipe lock.
    import ctypes
    create = ctypes.CDLL(None, use_errno=True).memfd_create
    create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    create.restype = ctypes.c_int
    review_fd = create(b'kernel-reviewed-inputs', memfd_flags)
    if review_fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    with os.fdopen(review_fd, 'wb') as stream:
        stream.write((json.dumps(review, indent=2, sort_keys=True) + '\\n').encode('utf-8'))
        stream.flush()
        fcntl.fcntl(review_fd, add_seals, seals)
        sys.argv = [entry, *args[:option], *args[option + 2:],
                    '--reviewed-inputs', f'/proc/self/fd/{review_fd}']
        value = load('kernel_held_build', entry, bodies[entry])
        entry_script = str(Path(entry).with_name('container-entry.sh'))
        raise SystemExit(value.main(entry_script=bodies[entry_script]))
load('__main__', entry, bodies[entry])
"""


def memfd():
    name = 'kernel-child-source'
    if hasattr(os, 'memfd_create'):
        return os.memfd_create(name, MEMFD_FLAGS)
    create = ctypes.CDLL(None, use_errno=True).memfd_create
    create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    create.restype = ctypes.c_int
    fd = create(name.encode('ascii'), MEMFD_FLAGS)
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return fd


@contextmanager
def bind(root, entry, command, rows):
    """Check local bytes and mode, then hold both entry and imports until reaped."""
    filename = str(root / entry)
    packet.need(command[:4] == [*PYTHON[:3], filename], 'child-source-command')
    modules = MODULES[entry]
    aliases = {}
    drivers = ()
    if entry == ACQUISITION:
        aliases = {'kernel_acquisition_native': (root / PRODUCER, PRODUCER),
                   'kernel_acquisition_harness': (root / HARNESS, HARNESS)}
    elif entry == STAGE:
        output = Path(command[command.index('--output') + 1])
        aliases = {'kernel_commit_config': (output / 'private/code' / COMMIT, COMMIT)}
    elif entry == PRODUCER:
        drivers = (BUILD, COMPARE)

    paths = {entry, *modules.values(), *(source for _, source in aliases.values()), *drivers}
    if drivers:
        paths.update((BUILD_ENTRY, packet.RECIPES_LOCK))
        for flag, expected in (('--recipes', str(root / packet.RECIPES_LOCK)),
                               ('--recipes-sha256', packet.RECIPES_SHA)):
            packet.need(command.count(flag) == 1, 'child-recipe-review-pin')
            index = command.index(flag) + 1
            packet.need(command[index:index + 1] == [expected], 'child-recipe-review-pin')
    packet.need(paths <= rows.keys(), 'child-source-pin')
    packet.need(sum(rows[name]['bytes'] for name in paths) <= LIMIT * 3 // 4, 'child-source-bound')
    bodies = {}
    for name in sorted(paths):
        path = root / name
        raw, mode = packet.capture(path, rows[name]['bytes'])
        packet.need(rows[name] == packet.row(raw, mode), 'child-source-pin')
        if name == packet.RECIPES_LOCK:
            packet.need(packet.sha(raw) == packet.RECIPES_SHA, 'child-recipe-review-pin')
        bodies[str(path)] = base64.b64encode(raw).decode('ascii')

    payload = json.dumps([bodies, {name: str(root / path) for name, path in modules.items()},
                          {name: (str(path), str(root / source)) for name, (path, source) in aliases.items()},
                          filename if entry == PRODUCER else None, filename if entry == STAGE else None,
                          [str(root / name) for name in drivers]], separators=(',', ':')).encode()
    packet.need(len(payload) <= LIMIT, 'child-source-bound')
    fd = memfd()
    with os.fdopen(fd, 'wb') as stream:
        stream.write(payload)
        stream.flush()
        fcntl.fcntl(fd, ADD_SEALS, SEALS)
        yield [*PYTHON, LAUNCHER, str(fd), filename, *command[4:]], (fd,)
