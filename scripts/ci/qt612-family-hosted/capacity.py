# SPDX-License-Identifier: MIT
"""Read-only capacity evidence for the existing owned storage setup."""

import os
from pathlib import Path
import stat
import time

GIB = 1024**3
STORAGE_BYTES = 12 * GIB
RESERVE_BYTES = 2 * GIB
MINIMUM_BYTES = STORAGE_BYTES + RESERVE_BYTES
TRANSFER_SLACK_BYTES = 64 * 1024**2


def observe(path):
    """Record the kernel's available bytes, device and mount ID for one path."""
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("Capacity evidence needs one ordinary absolute directory")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        fs = os.fstatvfs(fd)
        with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
            rows = stream.read(8193).splitlines()
        mount, = (int(row.split()[1]) for row in rows if row.startswith("mnt_id:"))
        return dict(path=str(path), device=st.st_dev, inode=st.st_ino, mount=mount,
                    free_bytes=fs.f_bavail * fs.f_frsize, fragment_bytes=fs.f_frsize,
                    readonly=bool(fs.f_flag & os.ST_RDONLY), observed_monotonic_ns=time.monotonic_ns())
    finally:
        os.close(fd)


def require_before(output):
    result = observe(output)
    if result["readonly"] or result["free_bytes"] < MINIMUM_BYTES:
        raise ValueError("Owned host filesystem needs 14 GiB available before allocation")
    if os.path.lexists(Path(output) / "storage.img"):
        raise ValueError("Owned storage reservation must be fresh")
    return result


def require_after(output, before):
    """Read back the same outer directory and the exact fully allocated file."""
    current = observe(output)
    if (any(current[key] != before[key] for key in ("path", "device", "inode", "mount"))
            or current["readonly"] or current["observed_monotonic_ns"] <= before["observed_monotonic_ns"]
            or current["free_bytes"] < RESERVE_BYTES):
        raise ValueError("Same outer filesystem needs 2 GiB available after allocation")
    image = Path(output) / "storage.img"
    info = image.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_dev != current["device"] or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size != STORAGE_BYTES or info.st_blocks * 512 < STORAGE_BYTES):
        raise ValueError("Expected one fully allocated private 12 GiB storage image")
    return dict(host=current, reservation=dict(path=str(image), device=info.st_dev, inode=info.st_ino,
                 bytes=info.st_size, allocated_bytes=info.st_blocks*512))


def require_transfer_volume(output, after, logical_bytes):
    """Check a finite two-copy transfer budget inside the new private volume."""
    if type(logical_bytes) is not int or logical_bytes < 1:
        raise ValueError("Expected whole pinned transfer byte count")
    host = after["host"]
    if host["path"] != str(output) or host["free_bytes"] < RESERVE_BYTES:
        raise ValueError("Retain the same verified outer reserve before transfer")
    volume = observe(Path(output) / "volume")
    work = observe(Path(output) / "volume/work")
    minimum = 2 * logical_bytes + TRANSFER_SLACK_BYTES
    if (volume["device"] == host["device"] or volume["mount"] == host["mount"]
            or volume["observed_monotonic_ns"] <= host["observed_monotonic_ns"]
            or volume["device"] != work["device"] or volume["mount"] != work["mount"]
            or volume["readonly"] or work["readonly"] or min(volume["free_bytes"], work["free_bytes"]) < minimum):
        raise ValueError("Bulk transfer needs sufficient space on the verified owned loop mount")
    return dict(volume=volume, work=work, logical_bytes=logical_bytes, minimum_free_bytes=minimum)
