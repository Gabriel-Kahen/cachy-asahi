#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the installed llhttp SONAME inside the admitted scratch target."""

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys

SONAME = "libllhttp.so.9.3"
REAL = Path("/usr/lib/libllhttp.so.9.3.1")


def parse(lib):
    signatures = {
        "llhttp_init": ([ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p], None),
        "llhttp_settings_init": ([ctypes.c_void_p], None),
        "llhttp_execute": ([ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t], ctypes.c_int),
        "llhttp_finish": ([ctypes.c_void_p], ctypes.c_int),
        "llhttp_errno_name": ([ctypes.c_int], ctypes.c_char_p),
        "llhttp_get_method": ([ctypes.c_void_p], ctypes.c_uint8),
        "llhttp_method_name": ([ctypes.c_int], ctypes.c_char_p),
    }
    for name, (arguments, result) in signatures.items():
        method = getattr(lib, name)
        method.argtypes, method.restype = arguments, result

    def execute(parts, finish):
        # Both exact 9.3.1 public structs (header pinned by operands.py)
        # fit in these 256-byte, 8-byte-aligned buffers on AArch64.
        parser = (ctypes.c_uint64*32)()
        settings = (ctypes.c_uint64*32)()
        lib.llhttp_settings_init(settings)
        lib.llhttp_init(parser, 1, settings)  # llhttp_type_t.HTTP_REQUEST.
        codes = [lib.llhttp_execute(parser, part, len(part)) for part in parts]
        if finish:
            codes.append(lib.llhttp_finish(parser))
        return [lib.llhttp_errno_name(code).decode("ascii") for code in codes], lib.llhttp_method_name(
            lib.llhttp_get_method(parser)).decode("ascii")

    complete, method = execute([b"POST /fixture HTTP/1.1\r\nHost: test.invalid\r\nContent-Length: 5\r\n\r\nhe",
                                b"llo"], True)
    invalid, _ = execute([b"POST /fixture HTTP/1.1\r\nContent-Length: z\r\n\r\n"], False)
    incomplete, _ = execute([b"POST /fixture HTTP/1.1\r\nContent-Length: 5\r\n\r\nhe"], True)
    if complete != ["HPE_OK"]*3 or method != "POST" or invalid != ["HPE_INVALID_CONTENT_LENGTH"] or incomplete != [
            "HPE_OK", "HPE_INVALID_EOF_STATE"]:
        raise ValueError("llhttp parser outcomes differ")
    return dict(split_request=complete, method=method, invalid_length=invalid, incomplete_body=incomplete)


def main(mode, digest, nonce):
    if (not sys.flags.isolated or not sys.dont_write_bytecode or os.uname().machine != "aarch64"
            or os.sysconf("SC_PAGE_SIZE") != 16384 or not re.fullmatch("[a-f0-9]{64}", digest)
            or not re.fullmatch("[a-f0-9]{32}", nonce)
            or Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce="+nonce) != 1
            or any(name.startswith("LD_") for name in os.environ)):
        raise ValueError("Exact offline ARM16K probe boundary required")
    try:
        lib = ctypes.CDLL(SONAME, mode=os.RTLD_NOW | os.RTLD_LOCAL)
    except OSError as exc:
        if mode != "absent" or "No such file or directory" not in str(exc) or REAL.exists():
            raise
        return dict(soname=SONAME, loaded=False, page_size=16384)
    if mode != "present":
        raise ValueError("An unexpected llhttp provider remains visible")
    mappings = [line.split(None,5)[-1] for line in Path("/proc/self/maps").read_text().splitlines()
                if "/libllhttp.so" in line]
    actual=sha256(REAL.read_bytes()).hexdigest()
    if Path("/usr/lib",SONAME).resolve()!=REAL or not mappings or set(mappings)!={str(REAL)} or actual!=digest:
        raise ValueError("The standard loader did not map the exact installed llhttp library")
    return dict(soname=SONAME, loaded=True, page_size=16384, mapped=str(REAL), sha256=actual, **parse(lib))


if __name__ == "__main__":
    print(json.dumps(main(*sys.argv[1:]),sort_keys=True))
