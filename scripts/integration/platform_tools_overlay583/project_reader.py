#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project the independent Platform Tools v2 inventory check into the sealed Overlay583 Reader."""

import argparse
from compression import zstd
from io import BytesIO
import os
from pathlib import Path
import sys
import tarfile

SCRIPTS = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SCRIPTS / "checks"), str(SCRIPTS / "install/overlay583_trial")]

from package_checks import metadata
from trial import canonical_lock, decode, encoded, need, ordinary, pin, read, sorted_rows, unchanged

NAME = "cachy-asahi-platform-tools"
VERSION = "0.2.0-1"
ARCH = "any"
ARCHIVE = f"{NAME}-{VERSION}-{ARCH}.pkg.tar.zst"
RECIPE_COMMIT = "ee4916ec0b1d04fc879ed5afa33e27f4d4783ec3"
PKGBUILD_SHA256 = "0fa2a014d1e56a130e8e828d9998a26248ebc8b0e9db552b552b6c975c0180c7"
HANDOFF = "OVERLAY583_PLATFORM_TOOLS_V2_ROOT_OPERANDS_ONLY_V1"
SUPPLEMENT = "PLATFORM_TOOLS_V2_OVERLAY583_TEST_SUPPLEMENT_V1"

OLD_PACKAGE = 'PACKAGE = b"cachy-asahi-first-login 0.1.0-2\\n"'
OLD_EXCLUSION = '    need(b"cachy-asahi-first-login" not in inventory(target), "Fresh base must exclude FirstLogin")'
LOCK_RESULT = "    return exact\n\n\ndef load"
SIGNED_JOIN = '''    need(data["first_login"]["after"] == pin(installed),
         "Exact signed supplement must join the independent installed inventory")
'''


def package_row(raw):
    """Read the identity and recipe provenance inside the already selected archive."""
    with zstd.ZstdFile(BytesIO(raw)) as stream:
        cap = 2 * 1024**2
        expanded = stream.read(cap + 1)
    need(len(expanded) <= cap, "Platform Tools archive expands beyond its bound")
    fields = {}
    with tarfile.open(fileobj=BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            if name not in {".PKGINFO", ".BUILDINFO"}:
                continue
            need(name not in fields and member.isfile() and 0 < member.size <= 64 * 1024,
                 "Expected one bounded regular copy of each package metadata member")
            with archive.extractfile(member) as stream:
                fields[name] = metadata(stream.read().decode("utf-8"))
    need(fields.keys() == {".PKGINFO", ".BUILDINFO"}, "Package identity and build provenance required")
    pkg, build = fields[".PKGINFO"], fields[".BUILDINFO"]
    need(all(pkg.get(key) == [value] for key, value in
             (("pkgname", NAME), ("pkgver", VERSION), ("arch", ARCH))),
         "Wrong Platform Tools package identity")
    need(all(build.get(key) == [value] for key, value in
             (("pkgname", NAME), ("pkgver", VERSION), ("pkgarch", ARCH),
              ("pkgbuild_sha256sum", PKGBUILD_SHA256))),
         "Wrong Platform Tools build provenance")
    return f"{pkg['pkgname'][0]} {pkg['pkgver'][0]}\n".encode("ascii")


def render_reader(original, row):
    text = original.decode("utf-8")
    for old, new in (
        (OLD_PACKAGE, f"PACKAGE = {row!r}"),
        (OLD_EXCLUSION, '    need(PACKAGE.split(b" ",1)[0] not in inventory(target), '
                        '"Fresh base must exclude Platform Tools v2")'),
        (LOCK_RESULT, SIGNED_JOIN + LOCK_RESULT),
    ):
        need(text.count(old) == 1, "Expected exact uncorrected Overlay583 Reader seam")
        text = text.replace(old, new, 1)
    compile(text, "readback.py", "exec")
    return text.encode("utf-8")


def project(stage, *, handoff_sha256, reader_sha256):
    stage = ordinary(stage)
    observations = {}
    handoff = read(stage / "HANDOFF.DATA.json", cap=128 * 1024, observed=observations)
    data = decode(handoff)
    need(pin(handoff)["sha256"] == handoff_sha256 and data["kind"] == HANDOFF,
         "Exact sealed Platform Tools handoff required")
    first = data["first_login"]
    supplement_root = stage / "first-login"
    supplement = decode(read(supplement_root / "supplement.json", first["receipt"],
                             cap=64 * 1024, observed=observations))
    provenance = data["provenance"]
    archive = provenance["origin_archive"]
    before = data["expected_inventories"]["before"]
    before_pin = {key: before[key] for key in ("bytes", "sha256")}
    need(supplement["kind"] == SUPPLEMENT and supplement["provenance"] == provenance
         and supplement["files"] == first["files"] and supplement["rehearsal"] == first["rehearsal"]
         and supplement["overlay_before"] == before_pin
         and supplement["overlay_after"] == first["after"]
         and provenance["recipe_commit"] == RECIPE_COMMIT and provenance["package_arch"] == ARCH
         and provenance["production_trust"] is False and first["rehearsal"]["test_only"] is True
         and first["files"].get(ARCHIVE) == archive and ARCHIVE + ".sig" in first["files"],
         "Signed supplement must match the sealed Platform Tools package, provenance and inventory pins")
    package = read(supplement_root / ARCHIVE, archive, cap=256 * 1024, observed=observations)
    row = package_row(package)

    base = read(Path(data["staging"]) / "target.lock", before_pin, cap=64 * 1024, observed=observations)
    need(NAME not in canonical_lock(base, 583), "Platform Tools must be absent from the 583-package base")
    installed = sorted_rows(base + row)
    canonical_lock(installed, 584)
    expected = dict(before=dict(count=583, **pin(base)), installed=dict(count=584, **pin(installed)),
                    after_removal=dict(count=583, **pin(base)))
    need(first["after"] == pin(installed), "Signed supplement inventory differs from the package projection")
    need(data["expected_inventories"] == expected, "Different independent 583/584/583 projection")

    original = read(stage / "readback.py", cap=128 * 1024, observed=observations)
    need(pin(original)["sha256"] == reader_sha256, "Exact selected uncorrected Reader required")
    result = render_reader(original, row)
    unchanged(observations)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--handoff-sha256", required=True)
    parser.add_argument("--reader-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = ordinary(args.output)
    need(not output.is_relative_to(ordinary(args.stage)), "Reader output must be outside the sealed stage")
    result = project(args.stage, handoff_sha256=args.handoff_sha256, reader_sha256=args.reader_sha256)
    with output.open("xb") as stream:
        stream.write(result)
        os.fchmod(stream.fileno(), 0o400)
    print(encoded(pin(result)).decode(), end="")


if __name__ == "__main__":
    main()
