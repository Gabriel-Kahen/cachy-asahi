#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project the unissued Qtbase 6.12.0-4 Asahi629 parity recipe."""

import argparse
import json
from pathlib import Path
import re
from runpy import run_path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BASE = run_path(str(HERE / "prepare.py"))
describe, read, source_hashes, substitute = (
    BASE[name] for name in ("describe", "read", "source_hashes", "substitute")
)
BASE_SHA256 = "b3b46a27d6bb5e93bf411de9a23bf238c36230f268206af09637c9d66f0ce41a"
FEATURES = ("accessibility_atspi_bridge", "cups", "egl_x11", "xcb_egl_plugin")
DESCRIPTION = b"Independent Qt 6.12 Asahi629 accessibility, printing and XCB EGL TEST candidate"
ATSPI_OPTDEP = b"at-spi2-core: desktop accessibility bus and registry"
PARITY_INPUTS = {
    "libcups-2:2.4.20-1-aarch64.pkg.tar.xz": {
        "bytes": 257476, "sha256": "f280995b8d7426dc9f40c70ca8d19dead27aa8a116cfeb94afa0149028709e66",
        "signature": {"bytes": 566, "sha256": "db214904615d2428f3c93556b6abe1e01fcb446d32c370c2765b2006a885c506"},
    },
    "at-spi2-core-2.62.1-1-aarch64.pkg.tar.xz": {
        "bytes": 547452, "sha256": "71efadc123171229c74281323db4b04c594c5e31ee0d7dfcb680bf5d8d98c74b",
        "signature": {"bytes": 566, "sha256": "3386365fb23b962a5ce9612f8f5349c7cec9abee430bee2668334465e9ffd9c3"},
    },
}


def project(files):
    profile = files["configure.cmake"]
    for feature in FEATURES:
        old = f'set(FEATURE_{feature} OFF CACHE BOOL "" FORCE)\n'.encode()
        profile = substitute(profile, old, old.replace(b" OFF ", b" ON "))
    files = files | {"configure.cmake": profile, "check_parity.py": (HERE / "check_parity.py").read_bytes()}

    recipe = files["PKGBUILD"]
    srcinfo = files[".SRCINFO"]
    recipe = substitute(recipe, b"\npkgrel=3\n", b"\npkgrel=4\n")
    srcinfo = substitute(srcinfo, b"\tpkgrel = 3\n", b"\tpkgrel = 4\n")
    description = b"Independent Qt 6.12 Vulkan and md4c 0.6 TEST candidate"
    recipe = substitute(recipe, description, DESCRIPTION)
    srcinfo = substitute(srcinfo, description, DESCRIPTION)
    recipe = substitute(recipe, b"'libwayland-server.so=0-64')", b"'libwayland-server.so=0-64' 'libcups')")
    recipe = substitute(recipe, b"'vulkan-headers=1:1.4.363.0-1')\n",
                        b"'vulkan-headers=1:1.4.363.0-1' 'at-spi2-core')\noptdepends=('" + ATSPI_OPTDEP + b"')\n")
    srcinfo = substitute(srcinfo, b"\tmakedepends = vulkan-headers=1:1.4.363.0-1\n",
                         b"\tmakedepends = vulkan-headers=1:1.4.363.0-1\n\tmakedepends = at-spi2-core\n")
    srcinfo = substitute(srcinfo, b"\tdepends = libwayland-server.so=0-64\n",
                         b"\tdepends = libwayland-server.so=0-64\n\tdepends = libcups\n\toptdepends = " + ATSPI_OPTDEP + b"\n")
    recipe = substitute(recipe, b"        'check_gui.py'\n", b"        'check_gui.py'\n        'check_parity.py'\n")
    srcinfo = substitute(srcinfo, b"\tsource = check_gui.py\n", b"\tsource = check_gui.py\n\tsource = check_parity.py\n")
    recipe = substitute(recipe, b'> "$srcdir/vulkan-md4c-elf.json" || return\n',
                        b'> "$srcdir/vulkan-md4c-elf.json" || return\n'
                        b'  python "$srcdir/check_parity.py" "$srcdir/stage-contract.json" || return\n')

    checksums = source_hashes(srcinfo, files)
    recipe_hashes = re.search(rb"^sha256sums=\(.*?\)\n", recipe, re.MULTILINE | re.DOTALL)[0]
    srcinfo_hashes = re.search(rb"(?:^\tsha256sums = [\da-f]{64}\n)+", srcinfo, re.MULTILINE)[0]
    recipe = substitute(recipe, recipe_hashes, b"sha256sums=('" + b"'\n            '".join(checksums) + b"')\n")
    srcinfo = substitute(srcinfo, srcinfo_hashes, b"".join(b"\tsha256sums = " + digest + b"\n" for digest in checksums))
    return files | {"PKGBUILD": recipe, ".SRCINFO": srcinfo}


def prepare_parity(output):
    with tempfile.TemporaryDirectory(dir=output.parent) as workspace:
        base = Path(workspace) / "base"
        receipt = BASE["prepare"](base)
        if describe((base / "SUCCESSOR.UNISSUED.json").read_bytes())["sha256"] != BASE_SHA256:
            raise ValueError("Qtbase 6.12.0-3 recipe differs from the Asahi629 input")
        files = project({name: read(base / name, pin) for name, pin in receipt["files"].items()})

    result = receipt | {
        "artifact_version": "6.12.0-4",
        "base_recipe_sha256": BASE_SHA256,
        "features_enabled": list(FEATURES),
        "official_inputs": receipt["official_inputs"] | PARITY_INPUTS,
        "files": {name: describe(body) for name, body in files.items()},
    }
    output.mkdir(mode=0o700)
    for name, body in files.items():
        (output / name).write_bytes(body)
    (output / "PARITY.UNISSUED.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    try:
        print(json.dumps(prepare_parity(parser.parse_args().output), sort_keys=True))
    except (OSError, ValueError) as error:
        sys.exit(str(error))
