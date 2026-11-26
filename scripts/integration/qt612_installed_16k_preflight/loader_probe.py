# SPDX-License-Identifier: MIT
"""Report the standard loader's file-backed mappings after one Qt SONAME load."""

import ctypes
import json
import os
from pathlib import Path
import re
import sys


SONAME = re.compile(r"libQt6[A-Za-z0-9]+\.so\.6")
MAP_CAP = 1 << 20
MAX_MAPPINGS = 512


def file_maps(raw):
    if not 0 < len(raw) <= MAP_CAP:
        raise ValueError("Bounded original /proc maps required")
    mapped = {}
    for line in raw.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not fields[5].startswith(b"/usr/lib/"):
            continue
        _, mode, _, device, inode, raw_path = fields
        if b"x" not in mode:
            continue
        path = raw_path.decode("ascii")
        if not re.fullmatch(r"/usr/lib/[A-Za-z0-9_+./-]{1,1015}", path) or Path(path).as_posix() != path:
            raise ValueError("Noncanonical or deleted loader mapping")
        major, minor = (int(part, 16) for part in device.split(b":"))
        identity = [major, minor, int(inode)]
        if identity[2] <= 0 or (path in mapped and mapped[path] != identity):
            raise ValueError("Conflicting loader mapping identity")
        mapped[path] = identity
        if len(mapped) > MAX_MAPPINGS:
            raise ValueError("Too many executable library mappings")
    return mapped


class LinkMap(ctypes.Structure):
    _fields_ = (("address", ctypes.c_void_p), ("name", ctypes.c_char_p))


def process_maps():
    with Path("/proc/self/maps").open("rb") as stream:
        return file_maps(stream.read(MAP_CAP + 1))


def probe(name):
    before = process_maps()
    try:
        lib = ctypes.CDLL(name, mode=os.RTLD_NOW | os.RTLD_LOCAL)
    except OSError as error:
        if str(error).startswith(name + ": cannot open shared object file: No such file or directory"):
            return {"soname": name, "path": None, "maps": {}, "loaded": []}
        raise
    dlinfo = ctypes.CDLL(None).dlinfo
    dlinfo.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(LinkMap)))
    dlinfo.restype = ctypes.c_int
    link = ctypes.POINTER(LinkMap)()
    if dlinfo(lib._handle, 2, ctypes.byref(link)) != 0 or not link or not link.contents.name:
        raise ValueError("Original loaded SONAME link map missing")
    name_in_loader = Path(os.fsdecode(link.contents.name))
    if not name_in_loader.is_absolute():
        raise ValueError("Loader returned a nonabsolute installed library")
    path = str(name_in_loader.resolve(strict=True))
    maps = process_maps()
    if path not in maps:
        raise ValueError("Selected SONAME is missing from its actual loader maps")
    return {"soname": name, "path": path, "maps": maps, "loaded": sorted(maps.keys() - before.keys())}


def main():
    if (len(sys.argv) != 2 or not SONAME.fullmatch(sys.argv[1]) or not sys.flags.isolated
            or not sys.dont_write_bytecode or os.uname().machine != "aarch64"
            or os.sysconf("SC_PAGE_SIZE") != 16384 or any(key.startswith("LD_") for key in os.environ)):
        raise ValueError("Exact standard ARM16K loader probe required")
    print(json.dumps(probe(sys.argv[1]), sort_keys=True))


if __name__ == "__main__":
    main()
