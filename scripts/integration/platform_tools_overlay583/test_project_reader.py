#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced controls for the Platform Tools addon Reader projection."""

from compression import zstd
from io import BytesIO
from pathlib import Path
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import project_reader as projection


# The frozen Reader's three seams, with the same independent lock checks.
LEGACY = f'''{projection.OLD_PACKAGE}

def lock_bodies(data):
    target = data["target"]
{projection.OLD_EXCLUSION}
    installed = sorted_rows(target + PACKAGE)
    exact = dict(before=target, installed=installed, after_removal=target)
    need({{name:dict(count=len(inventory(body)), **pin(body)) for name,body in exact.items()}}
         == data["expected_inventories"], "Different independent 583/584/583 projection")
{projection.LOCK_RESULT}(digest):
    return digest
'''.encode()


def archive(version, build_hash):
    package = f"pkgname = {projection.NAME}\npkgver = {version}\n"
    entries = {
        ".PKGINFO": package + "arch = any\n",
        ".BUILDINFO": package + f"pkgarch = any\npkgbuild_sha256sum = {build_hash}\n",
    }
    data = BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tar:
        for name, body in entries.items():
            raw = body.encode()
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            tar.addfile(member, BytesIO(raw))
    return zstd.compress(data.getvalue())


def stage(root, *, version=projection.VERSION, build_hash=projection.PKGBUILD_SHA256,
          already_installed=False, stale=False):
    addon = root / "first-login"
    addon.mkdir()
    body = archive(version, build_hash)
    (addon / projection.ARCHIVE).write_bytes(body)
    before = projection.sorted_rows(b"".join(f"base-{n:03} 1-1\n".encode() for n in range(583)))
    if already_installed:
        before = projection.sorted_rows(before.split(b"\n", 1)[1] + b"cachy-asahi-platform-tools 0.1.0-1\n")
    (root / "target.lock").write_bytes(before)
    installed = projection.sorted_rows(before + b"cachy-asahi-platform-tools 0.2.0-1\n")
    stale_lock = projection.sorted_rows(before + b"cachy-asahi-first-login 0.1.0-2\n")
    inventories = dict(before=dict(count=583, **projection.pin(before)),
                       installed=dict(count=584, **projection.pin(installed)),
                       after_removal=dict(count=583, **projection.pin(before)))
    files = {projection.ARCHIVE: projection.pin(body), projection.ARCHIVE + ".sig": projection.pin(b"fixture")}
    provenance = dict(origin_archive=projection.pin(body), recipe_commit=projection.RECIPE_COMMIT,
                      package_arch=projection.ARCH, production_trust=False)
    rehearsal = dict(test_only=True)
    after = projection.pin(stale_lock if stale else installed)
    receipt = projection.encoded(dict(kind=projection.SUPPLEMENT, provenance=provenance,
                                     files=files, rehearsal=rehearsal,
                                     overlay_before=projection.pin(before), overlay_after=after))
    (addon / "supplement.json").write_bytes(receipt)
    data = dict(kind=projection.HANDOFF, staging=str(root), expected_inventories=inventories, provenance=provenance,
                first_login=dict(after=after, files=files, rehearsal=rehearsal, receipt=projection.pin(receipt)))
    handoff = projection.encoded(data)
    (root / "HANDOFF.DATA.json").write_bytes(handoff)
    (root / "readback.py").write_bytes(LEGACY)
    return dict(handoff_sha256=projection.pin(handoff)["sha256"], reader_sha256=projection.pin(LEGACY)["sha256"]), (
        dict(data, target=before), before, installed)


def locks(source, data):
    namespace = dict(need=projection.need, pin=projection.pin, sorted_rows=projection.sorted_rows,
                     inventory=lambda body: projection.canonical_lock(body, len(body.splitlines())))
    exec(compile(source, "readback.py", "exec"), namespace)
    return namespace["lock_bodies"](data)


class ReaderProjection(unittest.TestCase):
    def test_legacy_row_refuses_and_projected_reader_restores_exact_base(self):
        with TemporaryDirectory() as location:
            root = Path(location)
            args, (data, before, installed) = stage(root)
            with self.assertRaisesRegex(ValueError, "Different independent"):
                locks(LEGACY, data)
            updated = projection.project(root, **args)
            self.assertEqual(locks(updated, data), dict(before=before, installed=installed, after_removal=before))
            self.assertEqual((root / "readback.py").read_bytes(), LEGACY)

    def test_wrong_package_and_rebuilt_recipe_refuse_even_with_matching_archive_pin(self):
        for values, reason in ((dict(version="0.1.0-1"), "package identity"),
                               (dict(build_hash="0" * 64), "build provenance")):
            with self.subTest(values=values), TemporaryDirectory() as location:
                root = Path(location)
                args, _ = stage(root, **values)
                with self.assertRaisesRegex(ValueError, reason):
                    projection.project(root, **args)

    def test_stale_supplement_and_candidate_in_base_refuse(self):
        for values, reason in ((dict(stale=True), "supplement inventory differs"),
                               (dict(already_installed=True), "must be absent")):
            with self.subTest(values=values), TemporaryDirectory() as location:
                root = Path(location)
                args, _ = stage(root, **values)
                with self.assertRaisesRegex(ValueError, reason):
                    projection.project(root, **args)


def fence(event, _):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.posix_spawn", "os.fork", "os.system")):
        raise AssertionError("Reader projection must remain offline: " + event)


if __name__ == "__main__":
    sys.addaudithook(fence)
    unittest.main(verbosity=2)
