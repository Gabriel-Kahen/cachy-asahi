#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the maintained Native ARM Build lane to its pinned recipe maps."""
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

import native_arm


# Linux UAPI values also cover Python distributions built without these headers.
MEMFD_FLAGS = 0x03  # MFD_CLOEXEC | MFD_ALLOW_SEALING
ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
SEALS = 0x0F  # F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE


def review_descriptor():
    if hasattr(os, 'memfd_create'):
        return os.memfd_create('native-reviewed-inputs', MEMFD_FLAGS)
    create = ctypes.CDLL(None, use_errno=True).memfd_create
    create.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    create.restype = ctypes.c_int
    fd = create(b'native-reviewed-inputs', MEMFD_FLAGS)
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return fd


def bound_runner(original_run, reviewed):
    builder = [sys.executable, str(native_arm.ROOT / 'scripts/build/build.py')]
    approved = {str(native_arm.ROOT / path): hashes for path, hashes in reviewed.items()}

    def run(command, log=None, timeout=1800):
        if command[:2] != builder:
            return original_run(command, log, timeout)
        try:
            hashes = approved[command[2]]
            option = command.index('--reviewed-inputs')
            if (command.count('--reviewed-inputs') != 1 or not command[option + 1]
                    or command[option + 1].startswith('-') or log is None):
                raise ValueError('review argument')
        except (IndexError, KeyError, ValueError):
            raise ValueError('unbound build recipe review') from None

        fd = review_descriptor()
        with os.fdopen(fd, 'wb') as review:
            review.write((json.dumps(hashes, indent=2, sort_keys=True) + '\n').encode('utf-8'))
            review.flush()
            fcntl.fcntl(fd, ADD_SEALS, SEALS)
            argv = [*command[:option], *command[option + 2:], '--reviewed-inputs', f'/proc/self/fd/{fd}']
            with log.open('w') as stream:
                result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT,
                                        timeout=timeout, pass_fds=(fd,))
            if result.returncode:
                raise ValueError(f'command failed ({result.returncode}); see {log}')

    return run


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('build',))
    parser.add_argument('--recipes', type=Path, required=True)
    parser.add_argument('--recipes-sha256', required=True)
    selected, _ = parser.parse_known_args(args)
    try:
        reviewed = native_arm.load_pinned(selected.recipes, selected.recipes_sha256)
        if not isinstance(reviewed, dict):
            raise ValueError('reviewed recipe lock must be an object')
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1

    original_run = native_arm.run
    native_arm.run = bound_runner(original_run, reviewed)
    try:
        return native_arm.main(args)
    finally:
        native_arm.run = original_run


if __name__ == '__main__':
    sys.exit(main())
