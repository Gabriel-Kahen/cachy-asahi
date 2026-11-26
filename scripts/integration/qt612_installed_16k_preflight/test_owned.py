# SPDX-License-Identifier: MIT
"""Offline controls for the installed site adapter and exact sealed source."""

from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
S = SimpleNamespace(**run_path(str(HERE / "site.py")))
H, C = S.H, S.C
NONCE, SIBLING = "a" * 32, "b" * 32
SHA = "c" * 64


class Owned(unittest.TestCase):
    def test_each_role_keeps_the_original_raw_backing_and_exact_boot_case(self):
        for case, clone in (("main", NONCE), ("tampered_signature", SIBLING), ("unknown_key", "d" * 32)):
            with self.subTest(case=case):
                role = H.role(NONCE, case, clone, SHA, SHA, SHA, SHA, 1800000000)
                argv = role["qemu_argv"]
                command = argv[argv.index("-append") + 1].split()
                self.assertEqual(command[0], "root=PARTUUID=" + clone[:8] + "-01")
                self.assertIn("cachy_qt_install_nonce=" + NONCE, command)
                self.assertIn("cachy_qt_install_clone=" + clone, command)
                self.assertIn("cachy_qt_install_case=" + case, command)
                self.assertIn("arm16k_rtc_host_epoch=1800000000", command)
                self.assertEqual(argv[argv.index("-nic") + 1], "none")
                self.assertIn("if=none,id=operands,file=/inputs/operands.raw,format=raw,readonly=on", argv)
        with self.assertRaisesRegex(ValueError, "case-specific"):
            H.role(NONCE, "unknown_key", NONCE, SHA, SHA, SHA, SHA, 1800000000)
        raw = ("QTBASE_INSTALLED16K_TERMINAL " + SIBLING + " PASS\r\n").encode()
        self.assertEqual(H.terminal(raw, SIBLING), "PASS")
        with self.assertRaises(ValueError):
            H.terminal(raw + raw, SIBLING)
        with self.assertRaises(ValueError):
            H.terminal(raw, NONCE)

    def test_owned_site_reuses_exact_attach_and_retirement_with_separate_scope(self):
        package, owner = S.owner_modules(Path("/sealed/control"), SHA)
        original = run_path(str(H.PACKAGE / "package_site.py"))["package_owner"](Path("/sealed/control"), SHA)
        self.assertEqual(owner.execute_owned.__code__, original.execute_owned.__code__)
        self.assertEqual(owner.recover_lost_create.__code__, original.recover_lost_create.__code__)
        self.assertEqual(package.CLAIM, H.CLAIM)
        self.assertEqual(owner.SCOPE, H.P.SCOPE)
        self.assertEqual(original.SCOPE, H.M.W.SCOPE)
        selected = SimpleNamespace(owner=owner, role={"nonce": NONCE, "selection": {"sha256": SHA}},
                                   media={"runner": {"actor_image": H.F.P.QEMU_ACTOR_IMAGE}, "plan": {"sha256": SHA}},
                                   root=Path("/sealed"), media_sha=SHA, site_sha=SHA)
        group = "/user.slice/user-1000.slice/user@1000.service/app.slice/" + H.P.SCOPE
        meta = S.meta(selected, group)
        argv = owner.create_args(Path("/sealed") / H.CLAIM, meta)
        self.assertIn("caa-qtbase16k-installed-" + NONCE, argv)
        self.assertIn("type=bind,source=/sealed/control,target=/stage,readonly", argv)
        self.assertIn("type=bind,source=/sealed/inputs,target=/inputs,readonly", argv)
        self.assertIn(S.ACTOR, argv)
        self.assertIn("--network=none", argv)
        self.assertIn("--cap-drop=ALL", argv)

    def test_authority_binds_exact_media_case_clone_and_time(self):
        media = {"case": "unknown_key", "clone": SIBLING}
        row = dict(kind=H.AUTH_KIND, issuer="Root", approved=True, scope=H.P.SCOPE, case=media["case"],
                   clone=SIBLING, media_sha256=SHA, created_utc=1000, expires_utc=1600)
        raw = C.wire(row)
        pin = C.pin(raw)["sha256"]
        self.assertEqual(H.read_authority(raw, pin, media, SHA, now=1400), row)
        for wrong, now in ((media | {"case": "main"}, 1400), (media | {"clone": NONCE}, 1400), (media, 1600)):
            with self.assertRaises(ValueError):
                H.read_authority(raw, pin, wrong, SHA, now=now)

    def test_assembled_source_tree_can_import_both_real_entry_points(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            records = {}
            for name in sorted(H.SOURCE_FILES):
                raw = (H.P.ROOT / name).read_bytes()
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                records[name] = C.pin(raw)
            H.verify_source(root, records)
            installed = root / "scripts/integration/qt612_installed_16k_preflight"
            for leaf in ("actor.py", "guest.py"):
                process = subprocess.run([sys.executable, "-I", "-B", str(installed / leaf), "--help"],
                                         capture_output=True, timeout=6)
                self.assertEqual(process.returncode, 0, process.stderr.decode())
            (root / "extra").touch()
            with self.assertRaises(ValueError):
                H.verify_source(root, records)

    def test_installed_pid1_checks_its_boot_manifest_with_original_helpers(self):
        package_media = run_path(str(HERE / "media.py"))
        files = package_media["boot_payload"]({"inert": C.pin(b"fixture")}, ["/etc/pacman.conf"])
        digest = C.pin(files["MANIFEST.sha256"])["sha256"]
        role = H.role(NONCE, "main", NONCE, digest, SHA, SHA, SHA, 1800000000)
        argv = role["qemu_argv"]
        tokens = argv[argv.index("-append") + 1].split()
        with TemporaryDirectory() as folder:
            root = Path(folder)
            for name, body in files.items():
                (root / name).write_bytes(body)
            shell = ('source "$1"; boot=$2; shift 2; read_cmdline "$@"; verify_sources; '
                     'source "$boot/root-helpers.sh"; declare -F installed_finish verify_boot >/dev/null')
            command = ["/usr/bin/bash", "--noprofile", "--norc", "-c", shell, "fixture",
                       str(HERE / "owned-guest-init.sh"), str(root), *tokens]
            result = subprocess.run(command, capture_output=True, timeout=6)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            (root / "protect.list").write_text("/different\n")
            self.assertNotEqual(subprocess.run(command, capture_output=True, timeout=6).returncode, 0)

    def test_offline_negative_readback_requires_original_diagnostic_and_database(self):
        review = run_path(str(HERE / "readback.py"))["review_case"]
        case = "unknown_key"
        database, stderr = b"same database\n", b"error: required key missing from keyring\n"
        archive, signature = C.pin(b"archive"), C.pin(b"signature")
        argv = H.P.PACMAN + ["--noconfirm", "-U", "--", H.P.ARCHIVE]
        plan = {"nonce": NONCE, "negative_trials": {case: {"command": argv}}}
        selection = {"inputs": {"archive": archive, "signature": signature}}
        media = dict(case=case, clone=SIBLING, plan={"sha256": SHA}, selection={"sha256": SHA}, signature=signature)
        report = dict(kind="QTBASE16K_INSTALLED_NEGATIVE_RESULT_V1", status="SIGNATURE_REFUSAL_VERIFIED_ONLY",
                      case=case, nonce=NONCE, clone=SIBLING, plan_sha256=SHA, selection_sha256=SHA,
                      inventory_before=H.P.Q3_INVENTORY, inventory_after=H.P.Q3_INVENTORY, scratch=H.P.Q3_SCRATCH,
                      configuration=C.pin(H.P.CONFIG.encode()), archive=archive, signature=signature, argv=argv,
                      exit_code=1, natural=True, group_empty=True, database_before=C.pin(database),
                      database_after=C.pin(database), stderr=C.pin(stderr))
        files = {"evidence/result.json": C.wire(report), "evidence/database-before.json": database,
                 "evidence/database-after.json": database, "evidence/commands/signature-refusal.stderr": stderr}
        self.assertEqual(review(media, plan, selection, lambda name, _cap: files[name]), C.pin(database))
        files["evidence/commands/signature-refusal.stderr"] = b"substitution\n"
        with self.assertRaisesRegex(ValueError, "evidence differs"):
            review(media, plan, selection, lambda name, _cap: files[name])


if __name__ == "__main__":
    unittest.main()
