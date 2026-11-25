#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the exact packaging-only Qtbase provider metadata successor."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


PACKAGE = "cachy-asahi-qt612-gui-server-source-reference"
VERSION = "6.12.0-2"
RECIPE_PINS = {
    (6145, "121f2ec8f25a8c935be16136cd3dc036603679fdaea2f1b95e45a7a2201f852b"):
        ("canonical", (6153, "df567ae1927ef84e6b45d9d2a2766d9b1cbdbfc65d30060d8d5c9cab850a2e65")),
    (6232, "b8ab08950fc2e5729e00bc066e13897163ae52362105aa90d58569f603e07296"):
        ("q3", (6240, "32debaeea9895337aa93309ff22e31f30a849e0b9d8579063a58db1d73c9a1e9")),
}
SRCINFO_INPUT = (3856, "9c132b1d743040efcfad23401efee5879270fab91d71877fe0972d6501bdb445")
SRCINFO_OUTPUT = (3858, "d6ce3f256bbdab09b98f03bb7163b637635d5e820ed3a09492da7399225070b8")


def pin(body):
    return len(body), hashlib.sha256(body).hexdigest()


def describe(body):
    size, digest = pin(body)
    return dict(bytes=size, sha256=digest)


def successor(recipe, srcinfo):
    selected = RECIPE_PINS.get(pin(recipe))
    if selected is None or pin(srcinfo) != SRCINFO_INPUT:
        raise ValueError("Expected exact canonical or Q3 Qtbase recipe and SRCINFO")
    profile, expected = selected
    # Use the complete version. libalpm compares without pkgrel when either
    # side omits it, which would also satisfy an official -3 exact dependency.
    projected = recipe.replace(b"\npkgrel=1\n", b"\npkgrel=2\n").replace(
        b'provides=("qt6-base=$pkgver" ', b'provides=("qt6-base=$pkgver-$pkgrel" ')
    projected_info = srcinfo.replace(b"\tpkgrel = 1\n", b"\tpkgrel = 2\n").replace(
        b"\tprovides = qt6-base=6.12.0\n", b"\tprovides = qt6-base=6.12.0-2\n")
    if pin(projected) != expected or pin(projected_info) != SRCINFO_OUTPUT:
        raise ValueError("Exact Qtbase packaging-only projection required")
    inputs = {"PKGBUILD": recipe, ".SRCINFO": srcinfo}
    outputs = {"PKGBUILD": projected, ".SRCINFO": projected_info}
    receipt = dict(kind="QTBASE_PROVIDER_METADATA_PROJECTION_V1", profile=profile,
                   package=PACKAGE, version=VERSION, provides="qt6-base=" + VERSION,
                   inputs={name: describe(body) for name, body in inputs.items()},
                   outputs={name: describe(body) for name, body in outputs.items()},
                   packaging="NOT_RUN", installation="NOT_RUN", authority=None)
    return outputs | {"receipt": (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()}


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 8192:
            raise ValueError("Expected a bounded ordinary Qtbase recipe file")
        return stream.read(info.st_size + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe-dir", type=Path, required=True)
    parser.add_argument("--emit", choices=("PKGBUILD", ".SRCINFO", "receipt"), default="receipt")
    args = parser.parse_args()
    try:
        recipe = read(args.recipe_dir / "PKGBUILD")
        srcinfo = read(args.recipe_dir / ".SRCINFO")
        sys.stdout.buffer.write(successor(recipe, srcinfo)[args.emit])
    except (OSError, ValueError) as error:
        sys.exit(str(error) if isinstance(error, ValueError) else "Cannot read the selected Qtbase recipe")


if __name__ == "__main__":
    main()
