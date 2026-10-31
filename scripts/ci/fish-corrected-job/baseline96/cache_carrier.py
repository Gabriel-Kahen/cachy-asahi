#!/usr/bin/env python3
"""Receive an exact private 501-file cache carrier; never extract archive paths."""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import time
import zipfile

BASE = Path(__file__).resolve().parent
# Bind the bootstrap contract from source bytes before any project import.
import types
_contract_path = BASE / 'contract.py'
_contract_info = _contract_path.lstat()
if not stat.S_ISREG(_contract_info.st_mode) or _contract_info.st_nlink != 1 or _contract_info.st_size > 65536:
    raise ValueError('successor-bootstrap-contract-type')
_contract_fd = os.open(_contract_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    _contract_raw = os.read(_contract_fd, 65537)
finally:
    os.close(_contract_fd)
if hashlib.sha256(_contract_raw).hexdigest() != 'c84168539130394f9fe51bf440d036f44813ff2b923c1e9d77748f97f755c922':
    raise ValueError('successor-bootstrap-contract-pin')
c = types.ModuleType('contract')
c.__file__ = str(_contract_path)
exec(compile(_contract_raw, str(_contract_path), 'exec'), c.__dict__)


def receive(archive, target, inputs, deadline):
    items = {row['filename']: row for row in c.cache_items(inputs)}
    archive, target = Path(archive).absolute(), Path(target).absolute()
    c.need(not target.exists() and not target.is_symlink()
           and all(stat.S_ISDIR(p.lstat().st_mode) for p in target.parents), 'successor-fresh-cache-carrier')
    c.need(all(stat.S_ISDIR(p.lstat().st_mode) for p in archive.parents), 'successor-cache-carrier-parent')
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    directory = None
    try:
        before = os.fstat(fd)
        c.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
               and 0 < before.st_size <= 2 * 1024**3, 'successor-cache-carrier-size')
        c.live(deadline)
        tail = os.pread(fd, min(before.st_size, 65557), max(0, before.st_size - 65557))
        offset = tail.rfind(b'PK\x05\x06')
        c.need(offset >= 0 and len(tail) - offset >= 22, 'successor-cache-carrier-directory')
        _, disk, start_disk, disk_rows, total_rows, cd_size, cd_offset, comment = struct.unpack('<4s4H2LH', tail[offset:offset+22])
        end_offset = before.st_size - len(tail) + offset
        c.need(os.pread(fd, 4, max(0, end_offset - 20)) != b'PK\x06\x07', 'successor-cache-carrier-zip64-refused')
        c.need(disk == start_disk == 0 and disk_rows == total_rows == 501
               and 0 < cd_size <= 512 * 1024 and cd_offset + cd_size == end_offset
               and offset + 22 + comment == len(tail), 'successor-cache-carrier-directory-bound')
        # The exact 501-object, <2GiB carrier requires no ZIP64 or split archive.
        c.live(deadline)
        with os.fdopen(fd, 'rb', closefd=False) as stream, zipfile.ZipFile(stream) as zipped:
            rows = zipped.infolist()
            c.need(len(rows) == 501 and len({r.filename for r in rows}) == 501
                   and {r.filename for r in rows} == set(items), 'successor-cache-carrier-membership')
            target.mkdir(mode=0o700)
            directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            owned = os.fstat(directory)
            c.need(owned.st_uid == os.getuid() and stat.S_IMODE(owned.st_mode) == 0o700, 'successor-cache-carrier-owner')
            for row in rows:
                c.live(deadline)
                current = target.lstat()
                c.need((current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino), 'successor-cache-carrier-target-drift')
                available = os.fstatvfs(directory)
                c.need(available.f_bavail * available.f_frsize >= 8 * 1024**3, 'successor-cache-carrier-free-reserve')
                expected = items[row.filename]
                mode = row.external_attr >> 16
                c.need(not row.is_dir() and (not mode or stat.S_IFMT(mode) in (0, stat.S_IFREG))
                       and row.file_size == expected['size'] and not row.flag_bits & 1,
                       'successor-cache-carrier-member')
                digest, size = hashlib.sha256(), 0
                output_fd = os.open(row.filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                with os.fdopen(output_fd, 'wb') as out, zipped.open(row) as source:
                    os.fchmod(out.fileno(), 0o600)
                    while chunk := source.read(1024**2):
                        c.live(deadline); size += len(chunk)
                        current = target.lstat()
                        c.need((current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino), 'successor-cache-carrier-target-drift')
                        c.need(size <= expected['size'], 'successor-cache-carrier-overflow')
                        digest.update(chunk); out.write(chunk)
                c.need(size == expected['size'] and digest.hexdigest() == expected['sha256'], 'successor-cache-carrier-pin')
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            after, named = os.fstat(fd), archive.lstat()
            c.need(all(getattr(before, k) == getattr(after, k) == getattr(named, k) for k in fields), 'successor-cache-carrier-drift')
        c.live(deadline)
        return {'objects': 501, 'status': 'PINNED PRIVATE CACHE RECEIVED; CRYPTO/NATIVE NOT RUN'}
    finally:
        if directory is not None: os.close(directory)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        inputs, _ = c.verify(BASE, args.packet_sha256)
        receive(args.archive, args.output, inputs, time.monotonic() + 300)
        return 0
    except Exception:
        print('successor-cache-carrier-refused', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
