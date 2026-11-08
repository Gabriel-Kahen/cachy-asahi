# SPDX-License-Identifier: MIT
"""One marked diskless guest bootstrap; no BusyBox mount/mkdir dependency."""
import ctypes
import os
from pathlib import Path
import re
import sys


def need(value, reason):
    if not value:
        raise ValueError(reason)


def guard(nonce, release):
    need(re.fullmatch('[0-9a-f]{32}', nonce or '') and
         re.fullmatch('[A-Za-z0-9_.+-]{1,128}', release or ''), 'literal bootstrap identity')
    need(os.uname().machine == 'aarch64' and os.uname().release == release and
         os.sysconf('SC_PAGE_SIZE') == 16384 and os.getuid() == os.geteuid() == 0 and
         os.getgid() == os.getegid() == 0 and os.getppid() == 1 and os.getpid() != 1,
         'fresh root generic16K guest bootstrap only')
    proc = Path('/proc')
    need(proc.is_dir() and not proc.is_symlink() and not any(proc.iterdir()),
         'fresh empty harness proc mountpoint; refuse host/already mounted proc')


def mount(libc, source, target, kind, flags):
    if libc.mount(source, target, kind, flags, None) != 0:
        code = ctypes.get_errno()
        raise OSError(code, 'guest bootstrap mount failed: ' + target.decode('ascii'))


def main(nonce, release):
    guard(nonce, release)  # Refuse host/unmarked input before loading libc or changing paths.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    mount(libc, b'proc', b'/proc', b'proc', 2 | 4 | 8)  # NOSUID | NODEV | NOEXEC
    with open('/proc/cmdline', 'rb') as stream:
        cmdline = stream.read(8193)
    need(len(cmdline) <= 8192 and ('namespace_vm_probe_v1=' + nonce).encode() in cmdline.split(),
         'exact marked guest command line after mounting proc')
    for name in ('/dev', '/tmp', '/home', '/var/lib/pacman'):
        os.makedirs(name, mode=0o755, exist_ok=True)
        need(Path(name).is_dir() and not Path(name).is_symlink(), 'ordinary guest bootstrap directory')
    mount(libc, b'devtmpfs', b'/dev', b'devtmpfs', 2)  # NOSUID; device nodes remain usable.
    print('NSVM_BOOT_READY_V1 ' + nonce, flush=True)
    return 0


if __name__ == '__main__':
    need(len(sys.argv) == 3, 'explicit bootstrap nonce/release')
    raise SystemExit(main(*sys.argv[1:]))
