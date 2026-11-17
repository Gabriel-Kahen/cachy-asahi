# SPDX-License-Identifier: MIT
"""Source-suite I/O policy: pinned public reads, owned MODEL writes, no actors."""
import os
from contextvars import ContextVar
from pathlib import Path
import sys


def install(workspace, scratch, allowed_files, wrapper_actor_fence):
    workspace, scratch = Path(workspace), Path(scratch)
    allowed = {workspace / name for name in allowed_files}
    allowed_dirs = {parent for file in allowed for parent in file.parents if parent.is_relative_to(workspace)}
    libraries = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
    seen = set()
    opening = ContextVar('qt612_model_open_target', default=None)

    def path(value, directory=None):
        if type(value) is int: return None
        value = Path(os.fsdecode(value))
        if not value.is_absolute():
            base = Path(os.readlink('/proc/self/fd/' + str(directory))) if directory not in (None, -1) else Path.cwd()
            value = base / value
        return Path(os.path.normpath(value))

    def owned(value, directory=None):
        selected = path(value, directory)
        if selected is not None and not selected.resolve().is_relative_to(scratch):
            raise PermissionError('SOURCE_MODEL_WRITE_OUTSIDE_OWNED_SCRATCH')

    def readable(selected, directory=False):
        resolved = selected.resolve()
        if resolved.is_relative_to(scratch): return
        if selected == Path('/proc/self/status') or selected == Path('/dev/null'): return
        if selected.is_relative_to(workspace):
            if resolved == selected and directory and selected in allowed_dirs: return
            if resolved == selected and selected in allowed:
                seen.add(selected.relative_to(workspace).as_posix()); return
        elif any(resolved.is_relative_to(lib) for lib in libraries): return
        raise PermissionError('SOURCE_CI_UNPINNED_OR_PRIVATE_READ:' + str(selected))

    def guard(event, args):
        if wrapper_actor_fence and (event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec',
                                                      'os.fork', 'os.posix_spawn')) or event in {
                'os.system', 'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit'}):
            raise ValueError('SOURCE_CI_NO_ACTORS_OR_KERNEL_CUSTODY')
        if event == 'open':
            name, mode, flags = args
            selected = opening.get() or path(name)
            if selected is None: return
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                owned(selected); return
            readable(selected, bool(flags & os.O_DIRECTORY)); return
        if event in ('os.scandir', 'os.listdir'):
            selected = Path(os.readlink('/proc/self/fd/' + str(args[0]))) if type(args[0]) is int else path(args[0] or '.')
            readable(selected, True)
        if event in ('os.remove', 'os.rmdir'):
            owned(args[0], args[1])
        elif event in ('os.mkdir', 'os.chmod'):
            owned(args[0], args[2])
        elif event in ('os.rename', 'os.link'):
            owned(args[0], args[2]); owned(args[1], args[3])
        elif event == 'os.symlink':
            # Negative MODEL links may name foreign targets; only their new leaf is owned.
            selected = path(args[1], args[2])
            if not selected.parent.resolve().is_relative_to(scratch):
                raise PermissionError('SOURCE_MODEL_LINK_OUTSIDE_OWNED_SCRATCH')
        elif event == 'os.truncate':
            owned(args[0])
    original_open = os.open
    def checked_open(file, flags, mode=0o777, *, dir_fd=None):
        # Audit 'open' omits dir_fd. Carry its real target through the unchanged
        # descriptor-relative syscall so reads/writes cannot masquerade as CWD I/O.
        token = opening.set(path(file, dir_fd))
        try: return original_open(file, flags, mode, dir_fd=dir_fd)
        finally: opening.reset(token)
    sys.addaudithook(guard)
    os.open = checked_open
    return seen
