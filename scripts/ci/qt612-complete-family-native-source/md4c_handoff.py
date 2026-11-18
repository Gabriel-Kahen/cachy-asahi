# SPDX-License-Identifier: MIT
"""Bind independently selected md4c package and signature bytes for Qt intake."""

import argparse
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qt612_md4c_handoff_common", HERE / "common.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
M, P = C.M, C.P

NAME = "md4c"
VERSION = "0.5.3-1"
ARCH = "aarch64"
PACKAGE = f"{NAME}-{VERSION}-{ARCH}.pkg.tar.xz"


def build_reference(*, archive, archive_pin, signature, signature_pin):
    """Return the existing producer input shape after a local whole-byte check."""
    archive, signature = M.ordinary(archive), M.ordinary(signature)
    C.need(archive.name == PACKAGE and signature.name == PACKAGE + ".sig",
           "Expected the exact md4c 0.5.3-1 archive and detached signature names")

    observed = {}
    for path, pin, limit in ((archive, archive_pin, 4 * 1024**2),
                             (signature, signature_pin, 1024**2)):
        M.descriptor(pin, limit)
        C.need(pin["bytes"] > 0, "Nonempty package and signature bytes required")
        M.stream(path, pin, observed, cap=limit)

    metadata = P.pkginfo(archive)
    expected = dict(pkgname=[NAME], pkgver=[VERSION], arch=[ARCH], depend=["glibc"])
    C.need(all(metadata.get(key) == value for key, value in expected.items()),
           "Expected the exact md4c 0.5.3-1 package identity and glibc dependency")
    C.need(not any(metadata.get(key) for key in ("install", "replaces", "conflict", "provides")),
           "Unexpected md4c install or provider relations")
    M.unchanged(observed)

    return dict(name=NAME, version=VERSION, arch=ARCH, filename=PACKAGE,
                archive=dict(path=str(archive), **archive_pin),
                signature=dict(path=str(signature), **signature_pin))


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Use whole-byte pins selected independently of the input paths. "
               "Detached-signature authentication is supplied separately.",
    )
    for role in ("archive", "signature"):
        parser.add_argument("--" + role, required=True)
        parser.add_argument("--" + role + "-bytes", type=int, required=True)
        parser.add_argument("--" + role + "-sha256", required=True)
    args = parser.parse_args()
    sys.addaudithook(M.fence)
    reference = build_reference(
        archive=args.archive, archive_pin=dict(bytes=args.archive_bytes, sha256=args.archive_sha256),
        signature=args.signature, signature_pin=dict(bytes=args.signature_bytes, sha256=args.signature_sha256),
    )
    sys.stdout.buffer.write(C.encoded(reference))


if __name__ == "__main__":
    main()
