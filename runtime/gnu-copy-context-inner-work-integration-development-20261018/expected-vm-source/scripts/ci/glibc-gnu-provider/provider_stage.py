#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finalize only a disposable makepkg pkgdir; never run installed libc code."""
import argparse
import json
import os
from pathlib import Path
import stat
import struct

NAME = 'cachy-asahi-glibc-gnu-provider'
DROP = ('usr/bin/tzselect', 'usr/bin/zdump', 'usr/bin/zic', 'var/db/Makefile')
CACHE = ('etc/ld.so.cache', 'etc/ld.so.cache~')
LOCALE = ('LC_ADDRESS', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION',
          'LC_MEASUREMENT', 'LC_MESSAGES/SYS_LC_MESSAGES', 'LC_MONETARY',
          'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME')
REQUIRED = ('etc/gai.conf', 'etc/rpc', 'usr/lib/libc.so.6', 'usr/lib/libm.so.6',
            'usr/lib/ld-linux-aarch64.so.1', 'usr/lib/gconv/ISO8859-1.so',
            *('usr/lib/locale/C.utf8/' + n for n in LOCALE),
            *('usr/share/licenses/' + NAME + '/' + n
              for n in ('COPYINGv2', 'COPYING.LESSERv2', 'LICENSES')))


def need(ok, why):
    if not ok:
        raise ValueError(why)


def inventory(root):
    root = Path(root).absolute()
    need(str(root) == os.path.normpath(root) and root != Path('/') and
         root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)),
         'ordinary non-root pkgdir required')
    entries = {}; total = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(parent) / name
            mode = p.lstat().st_mode
            need(not mode & 0o7000 and (stat.S_ISDIR(mode) or stat.S_ISREG(mode) or
                                      stat.S_ISLNK(mode)), 'ordinary package entry required')
            n = p.relative_to(root).as_posix()
            entries[n] = p
            total += p.lstat().st_size if stat.S_ISREG(mode) else 0
            need(len(entries) <= 60000 and total <= 512 * 1024**2,
                 'package member/byte bound')
            if p.is_symlink():
                target = os.readlink(p)
                need(not target.startswith('/') and '\x00' not in target,
                     'relative package link required')
                need(p.resolve().is_relative_to(root) and p.resolve().is_file(),
                     'package link escapes, loops or dangles')
    return root, entries


def elf(data):
    """Read ELF64 LE program headers and dynsym; no loader or subprocess."""
    need(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01' and
         struct.unpack_from('<H', data, 18)[0] == 183, 'AArch64 ELF64 required')
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
    need(phnum <= 1024 and shnum <= 65534 and phsize in (0, 56) and
         shsize in (0, 64) and (not phnum or phsize == 56) and
         (not shnum or shsize == 64) and phoff + phnum * phsize <= len(data) and
         shoff + shnum * shsize <= len(data), 'bounded ELF tables required')
    loads = []; dirname = []
    for i in range(phnum):
        p = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        if p[0] == 1:
            loads.append(p)
            need(p[7] >= 16384 and p[7] & (p[7] - 1) == 0 and
                 p[2] % p[7] == p[3] % p[7] and p[6] >= p[5] and
                 p[2] + p[5] <= len(data),
                 '16K PT_LOAD alignment/file bounds required')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
                for i in range(shnum)]
    for s in sections:
        if s[1] != 11:
            continue
        need(s[9] == 24 and s[5] % 24 == 0 and s[5] <= 100000 * 24 and
             s[4] + s[5] <= len(data) and s[6] < len(sections), 'bounded dynsym required')
        strings = sections[s[6]]
        need(strings[1] == 3 and strings[5] <= 8 * 1024**2 and
             strings[4] + strings[5] <= len(data), 'dynstr bounds')
        table = data[strings[4]:strings[4] + strings[5]]
        for off in range(s[4], s[4] + s[5], 24):
            name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', data, off)
            end = table.find(b'\0', name, name + 4096)
            need(name < len(table) and end != -1, 'dynsym string bounds')
            if table[name:end] == b'_nl_default_dirname' and index:
                spans = [p for p in loads if p[3] <= value and value + size <= p[3] + p[5]]
                need(len(spans) == 1, 'locale dirname must have one file-backed LOAD mapping')
                offset = spans[0][2] + value - spans[0][3]
                need(data[offset:offset + size] == b'/usr/share/locale\0',
                     'conventional locale dirname bytes required')
                dirname.append((info & 15, size))
    return len(loads), dirname


def finish(root):
    root, entries = inventory(root)
    # The held tzdata owns these commands. The upstream var/db Makefile is an
    # example database regeneration makefile, not runtime state for this package.
    for name in DROP:
        need(name in entries and entries[name].is_file() and
             not entries[name].is_symlink(), 'expected upstream removable file absent: ' + name)
    for name in CACHE:
        if name in entries:
            need(entries[name].is_file() and not entries[name].is_symlink(),
                 'cache must be an ordinary staged file')
    for name in DROP + CACHE:
        if name in entries:
            entries[name].unlink()
    for name in ('var/db', 'var'):
        p = root / name
        if p.exists():
            p.rmdir()  # Unexpected staged state is fatal, never recursively removed.
    return audit(root)


def audit(root):
    root, entries = inventory(root)
    need(all(n == 'etc' or n in ('etc/gai.conf', 'etc/rpc') or
             n == 'usr' or n in ('usr/bin', 'usr/include', 'usr/lib', 'usr/share') or
             n.startswith(('usr/bin/', 'usr/include/', 'usr/lib/', 'usr/share/'))
             for n in entries), 'unexpected conventional provider path')
    need(not any(n in entries for n in DROP + CACHE), 'excluded staged path present')
    need(all(n in entries and entries[n].is_file() and not entries[n].is_symlink()
             for n in REQUIRED), 'required provider/config/license/locale file absent')
    need(entries.get('usr/bin/ld.so') is not None and
         entries['usr/bin/ld.so'].is_symlink() and
         os.readlink(entries['usr/bin/ld.so']) == '../lib/ld-linux-aarch64.so.1',
         'conventional ld.so link required')
    elves = 0; loadable = 0; dirname = []
    for name, path in entries.items():
        if path.is_symlink() or not path.is_file():
            continue
        need(path.stat().st_size <= 64 * 1024**2, 'package file byte bound')
        data = path.read_bytes()
        need(b'/opt/caa/g243a1' not in data, 'private candidate path leaked into provider')
        if name in ('usr/lib/libc.so.6', 'usr/lib/libm.so.6',
                    'usr/lib/ld-linux-aarch64.so.1', 'usr/lib/gconv/ISO8859-1.so'):
            need(data.startswith(b'\x7fELF'), 'required provider file must be ELF')
        if data.startswith(b'\x7fELF'):
            loads, symbols = elf(data); elves += 1; loadable += bool(loads)
            if name == 'usr/lib/libc.so.6':
                need(loads > 0, 'libc must be loadable')
                dirname = symbols
    need(dirname == [(1, 18)], 'exact 18-byte _nl_default_dirname OBJECT required')
    need(elves >= 4 and loadable >= 4, 'required provider ELF files absent')
    return dict(status='PASS_INERT_PROVIDER_STAGING', entries=len(entries),
                elf_files=elves, loadable_files=loadable, dirname_object_bytes=18,
                scope='staged layout and static ELF checks only; no build/runtime/admission credit')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pkgdir', type=Path, required=True)
    parser.add_argument('--audit-only', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps((audit if args.audit_only else finish)(args.pkgdir), sort_keys=True))
    except (ValueError, OSError, RuntimeError, struct.error) as error:
        parser.exit(1, str(error) + '\n')
