#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the unissued Qtbase Vulkan/md4c 0.6 successor recipe."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REFERENCE = ROOT / "packages/port/qt612-gui-server-source-reference"
PROJECTION = HERE.parent / "qt612_full_16k_preflight/package_metadata.py"
PATCH = "032643f99e090e0304ef935c2ee11c109d55c8a1.patch"
PATCH_PATH = ROOT / "packages/port/qt612-source-reference/recipe-inputs/qt-cherry-pick-inputs" / PATCH
ARCHIVE_SHA256 = "a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307"
PROFILE_SHA256 = "5d9696e5fadd0d84a1ce659432ce48020cda5e7c3f67e7dbe4c0e21e9e02b4db"
LAST_PATCH = b"CVE-2026-105943-qtbase-6.12.diff"
OLD_DESC = b"Independent Qt6.12 GUI18 server-enabled candidate; TEST-only and unselected"
DESCRIPTION = b"Independent Qt 6.12 Vulkan and md4c 0.6 TEST candidate"
BUILD_DEPS = (
    "binutils",
    "vulkan-headers=1:1.4.363.0-1",
)
RUNTIME_DEP = "md4c=0.6.0-2"
NOTICE_SHA256 = (
    (b"d30937367d5413e7eaa218b1640b8946ff76fd34d97152f6979fd96169d5d0fc",
     b"e547c9a66c120b19f9838a1f7c2f51137f5c71ba27b70c3611b673f2cdb4e02e"),
    (b"7b2bc7be22e4be2a2984119ce3d0bfc210ddd0d8ef6193d66e8479d4c22af4ba",
     b"f5e9ca33ff2ca3e1bd7e8540255e1209f82b993bc7a3a57c1b2c8c5231e44d32"),
)
OFFICIAL_INPUTS = {
    "fingerprint": "68B3537F39A313B3E574D06777193F152BDBE6A6",
    "public_key": {"bytes": 3098, "sha256": "6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f"},
    "md4c-0.6.0-2-aarch64.pkg.tar.xz": {
        "bytes": 80764, "sha256": "14cc79f8a7f0b4c913068cd808717f8db2f6adb097738ade3b2e89b15caccf98",
        "signature": {"bytes": 566, "sha256": "aa5a0215b7b4082dc3216c6b3b7a2a025a4be908eb3074a9f0e2e7acceda514e"},
    },
    "vulkan-headers-1:1.4.363.0-1-any.pkg.tar.xz": {
        "bytes": 2046076, "sha256": "a9a8b1226aad787e8a3931da08cadc6b459d6efa73f86cc585de20aae1e45dab",
        "signature": {"bytes": 566, "sha256": "7750c9302c3180cb6a63d53d9423f50adb69419b3425192510c411eecc849be9"},
    },
}


def describe(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def read(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected["bytes"]:
        raise ValueError(f"unexpected recipe input: {path.name}")
    body = path.read_bytes()
    if describe(body) != expected:
        raise ValueError(f"changed recipe input: {path.name}")
    return body


def substitute(body, old, new):
    if body.count(old) != 1:
        raise ValueError(f"expected one recipe preimage: {old[:100]!r}")
    return body.replace(old, new)


def source_hashes(srcinfo, files):
    items = re.findall(rb"^\tsource = (.+)$", srcinfo, re.MULTILINE)
    if not items or not items[0].startswith(b"https://download.qt.io/archive/qt/"):
        raise ValueError("expected exact Qt primary source archive")
    return [ARCHIVE_SHA256.encode()] + [describe(files[name.decode()])["sha256"].encode() for name in items[1:]]


def project(recipe, srcinfo, files):
    profile = substitute(files["configure.cmake"], b'set(FEATURE_vulkan OFF CACHE BOOL "" FORCE)\n',
                         b'set(FEATURE_vulkan ON CACHE BOOL "" FORCE)\n'
                         b'set(FEATURE_vkkhrdisplay OFF CACHE BOOL "" FORCE)\n')
    if describe(profile)["sha256"] != PROFILE_SHA256:
        raise ValueError("projected configuration differs from the audited successor")
    notices = files["source-notices.json"]
    for before, after in NOTICE_SHA256:
        notices = substitute(notices, before, after)
    policy_sha = describe(notices)["sha256"].encode()
    checker = substitute(files["check_stage.py"],
                         b"3651e4bca7846caee61183c2bc55bf4988c6f4f2a56af81f3948afe03d41cfda", policy_sha)
    files = files | {"configure.cmake": profile, "source-notices.json": notices, "check_stage.py": checker}

    for before, after in (
        (b"\npkgrel=2\n", b"\npkgrel=3\n"),
        (OLD_DESC, DESCRIPTION),
        (b"'md4c>=0.5.3' 'md4c<0.6'", b"'" + RUNTIME_DEP.encode() + b"'"),
        (b"'perl' 'patch')", b"'perl' 'patch' " + b" ".join(b"'" + dep.encode() + b"'" for dep in BUILD_DEPS) + b")"),
        (b'provides=("qt6-base=$pkgver-$pkgrel" ', b"provides=('qt6-base' "),
        (b"        'check_stage.py'\n", b"        'check_stage.py'\n        'check_gui.py'\n"),
        (b"        '" + LAST_PATCH + b"'\n)", b"        '" + LAST_PATCH + b"'\n        '" + PATCH.encode() + b"'\n)"),
        (b'  done\n  python "$srcdir/source.py" verify',
         b'  done\n  patch --batch --forward --fuzz=0 -d "$srcdir/qtbase-everywhere-src-$pkgver" \\\n'
         b'    -p1 -i "$srcdir/' + PATCH.encode() + b'" || return\n  python "$srcdir/source.py" verify'),
        (b'> "$srcdir/stage-contract.json" || return\n}', b'> "$srcdir/stage-contract.json" || return\n'
         b'  python "$srcdir/check_gui.py" "$pkgdir/usr/lib/libQt6Gui.so.$pkgver" \\\n'
         b'    > "$srcdir/vulkan-md4c-elf.json" || return\n}'),
    ):
        recipe = substitute(recipe, before, after)

    for before, after in (
        (b"\tpkgrel = 2\n", b"\tpkgrel = 3\n"),
        (OLD_DESC, DESCRIPTION),
        (b"\tdepends = md4c>=0.5.3\n\tdepends = md4c<0.6\n", b"\tdepends = " + RUNTIME_DEP.encode() + b"\n"),
        (b"\tmakedepends = patch\n", b"\tmakedepends = patch\n" +
         b"".join(b"\tmakedepends = " + dep.encode() + b"\n" for dep in BUILD_DEPS)),
        (b"\tprovides = qt6-base=6.12.0-2\n", b"\tprovides = qt6-base\n"),
        (b"\tsource = check_stage.py\n", b"\tsource = check_stage.py\n\tsource = check_gui.py\n"),
        (b"\tsource = " + LAST_PATCH + b"\n", b"\tsource = " + LAST_PATCH + b"\n\tsource = " + PATCH.encode() + b"\n"),
    ):
        srcinfo = substitute(srcinfo, before, after)
    hashes = source_hashes(srcinfo, files)
    recipe_hashes = re.search(rb"^sha256sums=\(.*?\)\n", recipe, re.MULTILINE | re.DOTALL)
    metadata_hashes = re.search(rb"(?:^\tsha256sums = [\da-f]{64}\n)+", srcinfo, re.MULTILINE)
    if not recipe_hashes or not metadata_hashes:
        raise ValueError("expected both recipe checksum blocks")
    recipe = substitute(recipe, recipe_hashes[0], b"sha256sums=('" +
                        b"'\n            '".join(hashes) + b"')\n")
    srcinfo = substitute(srcinfo, metadata_hashes[0], b"".join(b"\tsha256sums = " + digest + b"\n" for digest in hashes))
    return files | {"PKGBUILD": recipe, ".SRCINFO": srcinfo}


def prepare(output):
    lock = json.loads(read(REFERENCE / "recipe-files.lock.json",
                           {"bytes": 6887, "sha256": "738801a88ef047ede41e2826f0c27e8613482f2c92225ad028cd2d7baabd1ce0"}))
    read(PROJECTION, {"bytes": 5601, "sha256": "41d9290c313f1032e2cab46f7ef3efa4c71a3e84d89fa03d7d2b0deb06f6f20e"})
    ref = {name: read(REFERENCE / name, {key: lock["files"][name][key] for key in ("bytes", "sha256")})
           for name in ("PKGBUILD", ".SRCINFO")}
    base = runpy.run_path(str(PROJECTION))["successor"](ref["PKGBUILD"], ref[".SRCINFO"])
    names = re.findall(rb"^\tsource = (.+)$", base[".SRCINFO"], re.MULTILINE)[1:]
    files = {name: read(REFERENCE / name, {key: lock["files"][name][key] for key in ("bytes", "sha256")})
             for name in (item.decode() for item in names)}
    files[PATCH] = read(PATCH_PATH, {
        "bytes": 196774, "sha256": "85f937ff9d68d3f74680988515eefe40498a75fa69cb422a1bc368f5f6b2a247"})
    files["check_gui.py"] = (HERE / "check_gui.py").read_bytes()
    result = project(base["PKGBUILD"], base[".SRCINFO"], files)
    receipt = dict(status="UNISSUED_RECIPE_ONLY", artifact_version="6.12.0-3", authority=None,
                   build="NOT_RUN", installation="NOT_RUN", qt_source={"bytes": 51220268, "sha256": ARCHIVE_SHA256},
                   official_inputs=OFFICIAL_INPUTS, files={name: describe(body) for name, body in result.items()})
    output.mkdir(mode=0o700)
    for name, body in result.items():
        (output / name).write_bytes(body)
    (output / "SUCCESSOR.UNISSUED.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    try:
        print(json.dumps(prepare(parser.parse_args().output), sort_keys=True))
    except (OSError, ValueError, KeyError) as error:
        sys.exit(str(error))
