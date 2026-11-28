#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test the passive audit's inventory, archive and ELF refusal paths."""

import io
from pathlib import Path
from runpy import run_path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


LANE = Path(__file__).resolve().parent
GUEST_LANE = Path("/trial-code/jbig-tiff")
I = run_path(str(LANE / "inputs.py"))
TIFF = """
 0x0000000000000001 (NEEDED)             Shared library: [libtiff.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [libanother.so.1]
    8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND TIFFOpen@LIBTIFF_4.0 (4)
    9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND Other@OTHER_4.0 (5)
Version needs section '.gnu.version_r' contains 2 entries:
  000000: Version: 1  File: libtiff.so.6  Cnt: 1
  0x0010:   Name: LIBTIFF_4.0  Flags: none  Version: 4
  0x0020: Version: 1  File: libanother.so.1  Cnt: 1
  0x0030:   Name: OTHER_4.0  Flags: none  Version: 5
"""
PROJECT_TIFF = """
 0x0000000000000001 (NEEDED)             Shared library: [libjbig.so.2.2]
 0x0000000000000001 (NEEDED)             Shared library: [libjpeg.so.8]
 0x000000000000000e (SONAME)             Library soname: [libtiff.so.6]
   18: 0000000000000000    64 FUNC    GLOBAL DEFAULT   14 TIFFOpen@@LIBTIFF_4.0
"""
PIPEWIRE = " 0x0000000000000001 (NEEDED) Shared library: [libspandsp.so.2]"


def archive(*members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as output:
        for name, raw in members:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            output.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def lock(rows):
    return "".join(f"{key} {value}\n" for key, value in sorted(rows.items())).encode("ascii")


def guest_module(file):
    # Preserve the shallow guest __file__ values without mounting or writing the host root.
    path = Path(file)
    if path.parent != GUEST_LANE or path.name not in {"inputs.py", "jpeg_recipe.py"}:
        raise AssertionError(f"Unexpected guest source path: {path}")
    scope = {"__file__": str(path), "__name__": "guest_fixture"}
    exec(compile((LANE / path.name).read_bytes(), str(path), "exec"), scope)
    scope["run_path"] = guest_module
    return scope


class AuditTest(unittest.TestCase):
    def test_inventory_projection(self):
        rows = {f"unchanged-{number:03}": "1:2.3-4" for number in range(627)}
        original = lock(rows | I["OFFICIAL"])
        expected = lock(rows | I["PROJECT"])
        implementation = I["project"]
        with patch.dict(implementation.__globals__, dict(BASELINE=I["body_pin"](original),
                                                         REPLACEMENT=I["body_pin"](expected))):
            self.assertEqual(implementation(original), (expected, original))
            with self.assertRaisesRegex(ValueError, "rollback lock pin"):
                implementation(original.replace(b"jbigkit 2.1-8", b"jbigkit 2.1-9"))

    def test_inventory_refuses_duplicate_names(self):
        raw = lock({f"test-{number:03}": "1-1" for number in range(628)})
        with self.assertRaisesRegex(ValueError, "Duplicate inventory"):
            I["inventory"](b"test-000 1-1\n" + raw)

    def test_pinned_file_rejects_symlink_or_wrong_bytes(self):
        with TemporaryDirectory() as folder:
            base = Path(folder)
            file = base / "file"
            link = base / "link"
            file.write_bytes(b"expected")
            link.symlink_to(file)
            self.assertEqual(I["read"](file, I["body_pin"](b"expected")), b"expected")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                I["read"](file, I["body_pin"](b"mismatch"))
            with self.assertRaises(OSError):
                I["read"](link, I["body_pin"](b"expected"))

    def test_archive_member_pins_and_parity_gap(self):
        wanted = {"usr/bin/exact": I["body_pin"](b"data")}
        read_members = I["selected_members"]
        self.assertEqual(read_members(archive(("./usr/bin/exact", b"data")), wanted), {"usr/bin/exact": b"data"})
        for body, failure in (
            (archive(("usr/bin/exact", b"nope")), "Member digest"),
            (archive(("usr/bin/decoy", b"data")), "Missing archive"),
            (archive(("usr/bin/exact", b"data"), ("./usr/bin/exact", b"data")), "unique bounded"),
        ):
            with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, failure):
                read_members(body, wanted)
        with self.assertRaisesRegex(ValueError, "Unexpected packaged member"):
            read_members(archive(("usr/bin/exact", b"data"), ("./usr/bin/tiffgt", b"old")), wanted,
                         forbidden=(I["TIFFGT"],))

    def test_transport_key_joins_armored_and_binary_pins(self):
        armor = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nZXhhbXBsZQ==\n=A1b2\n-----END PGP PUBLIC KEY BLOCK-----\n"
        check = I["alarm_key"]
        with TemporaryDirectory() as folder:
            stage = Path(folder)
            key = stage / "keys/alarm.gpg"
            key.parent.mkdir()
            key.write_bytes(armor)
            wire_pin = I["body_pin"](armor)
            manifest = {"files": {"keys/alarm.gpg": wire_pin}}
            with patch.dict(check.__globals__, dict(ALARM_TRANSPORT_KEY=wire_pin, ALARM_KEY=I["body_pin"](b"example"))):
                self.assertEqual(check(stage, manifest, None), b"example")
                with self.assertRaisesRegex(ValueError, "Retained ALARM key pin differs"):
                    check(stage, {"files": {"keys/alarm.gpg": {}}}, None)
            with patch.dict(check.__globals__, dict(ALARM_TRANSPORT_KEY=wire_pin, ALARM_KEY=I["body_pin"](b"wrong"))):
                with self.assertRaisesRegex(ValueError, "Dearmored ALARM public key pin differs"):
                    check(stage, manifest, None)

    def test_readelf_associates_imports_with_soname_index(self):
        needed, imports = I["tiff_imports"](TIFF)
        self.assertEqual(needed, {"libtiff.so.6", "libanother.so.1"})
        self.assertEqual(imports, [("TIFFOpen", "LIBTIFF_4.0")])
        _, imports = I["tiff_imports"](TIFF.replace("TIFFOpen@LIBTIFF_4.0 (4)", "TIFFOpen@LIBTIFF_4.0 (5)"))
        self.assertEqual(imports, [])

    def test_abi_refuses_missing_export_or_indirect_edge(self):
        abi = I["check_abi"]
        example = {
            "usr/bin/example": dict(package="consumer", version="1-1", pin=I["body_pin"](b"example"),
                                    tiff_imports=1),
            I["PIPEWIRE"]: I["CONSUMERS"][I["PIPEWIRE"]],
        }
        objects = {"usr/bin/example": TIFF, I["PIPEWIRE"]: PIPEWIRE}
        with patch.dict(abi.__globals__, dict(CONSUMERS=example, elf=lambda content: content)):
            self.assertEqual(abi(objects, PROJECT_TIFF)["usr/bin/example"]["tiff_imports"],
                             [["TIFFOpen", "LIBTIFF_4.0"]])
            with self.assertRaisesRegex(ValueError, "unresolved TIFF imports"):
                abi(objects, PROJECT_TIFF.replace("TIFFOpen@@", "TIFFClose@@"))
            with self.assertRaisesRegex(ValueError, "PipeWire plugin"):
                abi(objects | {I["PIPEWIRE"]: PIPEWIRE.replace("libspandsp", "libunrelated")}, PROJECT_TIFF)
            with self.assertRaisesRegex(ValueError, "project TIFF linkage"):
                abi(objects, PROJECT_TIFF.replace("libjbig.so.2.2", "libjbig.so.2.1"))
            with self.assertRaisesRegex(ValueError, "project TIFF linkage"):
                abi(objects, PROJECT_TIFF.replace("libjpeg.so.8", "libjpeg.so.7"))
            for retired in I["RETIRING_JBIG"]:
                with self.subTest(retired=retired), self.assertRaisesRegex(ValueError, "direct ELF dependency"):
                    abi(objects | {"usr/bin/example": TIFF.replace("libanother.so.1", retired)}, PROJECT_TIFF)

    def test_jpeg_correction_requires_new_release_dependency_and_recipe_identity(self):
        guest = guest_module(GUEST_LANE / "inputs.py")
        recipe = guest["jpeg_recipe"]()
        self.assertEqual(recipe["HERE"], GUEST_LANE)
        metadata = (b"pkgname = cachy-asahi-libtiff\npkgver = 4.7.2-1.2\narch = aarch64\n"
                    b"depend = libjpeg-turbo\ndepend = libjpeg.so=8-64\n")
        buildinfo = f'pkgbuild_sha256sum = {recipe["PKGBUILD_PIN"]["sha256"]}\n'.encode()
        verifier = guest["require_qualified_tiff"]
        with TemporaryDirectory() as folder:
            path = Path(folder) / "cachy-asahi-libtiff-4.7.2-1.2-aarch64.pkg.tar.xz"
            with patch.dict(verifier.__globals__, {"PROVIDERS": I["HISTORICAL_PROVIDERS"]}):
                with self.assertRaisesRegex(ValueError, "awaits an audited pin"):
                    verifier(path)
            for info, build, failure in (
                (metadata, buildinfo, None),
                (metadata.replace(b"4.7.2-1.2", b"4.7.2-1.1"), buildinfo, "identity"),
                (metadata.replace(b"aarch64", b"x86_64"), buildinfo, "identity"),
                (metadata.replace(b"8-64", b"7-64"), buildinfo, "exact libjpeg"),
                (metadata + b"depend = libjpeg.so=8-64\n", buildinfo, "exact libjpeg"),
                (metadata, b"pkgbuild_sha256sum = wrong\n", "different recipe"),
            ):
                with self.subTest(failure=failure):
                    body = archive((".PKGINFO", info), (".BUILDINFO", build))
                    path.write_bytes(body)
                    selection = I["PROVIDERS"] | {I["PROJECT_TIFF"]: dict(
                        version=recipe["VERSION"], filename=path.name, archive=I["body_pin"](body), signature=None)}
                    with patch.dict(verifier.__globals__, {"PROVIDERS": selection}):
                        if failure:
                            with self.assertRaisesRegex(ValueError, failure):
                                verifier(path)
                        else:
                            self.assertEqual(verifier(path), dict(version=recipe["VERSION"],
                                                                  dependency=recipe["JPEG_DEPENDENCY"],
                                                                  recipe=recipe["PKGBUILD_PIN"]))
                            with self.assertRaisesRegex(ValueError, "archive name"):
                                verifier(path.with_name("unselected.pkg.tar.xz"))
                            path.write_bytes(body[:-1] + bytes([body[-1] ^ 1]))
                            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                                verifier(path)

    def test_selected_jpeg_provider_requires_provision_on_exact_installed_version(self):
        raw = (b"%NAME%\nlibjpeg-turbo\n\n%VERSION%\n3.2.0-2\n\n"
               b"%PROVIDES%\nlibjpeg.so=8-64\nlibturbojpeg.so=0-64\n\n")
        self.assertEqual(I["jpeg_provider"](raw, "libjpeg.so=8-64"),
                         dict(package="libjpeg-turbo", version="3.2.0-2", provides="libjpeg.so=8-64"))
        for changed in (raw.replace(b"3.2.0-2", b"3.2.0-3"), raw.replace(b"%PROVIDES%", b"%DEPENDS%")):
            with self.assertRaisesRegex(ValueError, "provider metadata differs"):
                I["jpeg_provider"](changed, "libjpeg.so=8-64")

    def test_static_census(self):
        refs = [row["tiff_imports"] for row in I["CONSUMERS"].values()]
        self.assertEqual((len(refs), sum(bool(count) for count in refs), sum(refs)), (8, 7, 84))
        self.assertIn(I["TIFFGT"], I["PROVIDER_FILES"]["libtiff"])
        self.assertNotIn(I["TIFFGT"], I["PROVIDER_FILES"]["cachy-asahi-libtiff"])
        self.assertTrue(all(I["PROVIDERS"][name]["signature"] for name in I["OFFICIAL"]))
        self.assertTrue(all(I["PROVIDERS"][name]["signature"] is None for name in I["PROJECT"]))


if __name__ == "__main__":
    unittest.main()
