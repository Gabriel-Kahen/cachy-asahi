# SPDX-License-Identifier: MIT
"""Offline controls for the installed site adapter and exact sealed source."""

from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
S = SimpleNamespace(**run_path(str(HERE / "site.py")))
H, C = S.H, S.C
NONCE, SIBLING = "a" * 32, "b" * 32
SHA = "c" * 64
SITE_SHA, CID = (digit * 64 for digit in "de")


def inspect_fixture(owner, attempt, meta, status):
    args = owner.actor_args(meta["handoff_sha256"], meta["authority_sha256"])
    return C.wire([dict(
        Id=CID, Name="/" + meta["name"], Image=meta["image"], Path="/usr/bin/python3", Args=args,
        Config=dict(Entrypoint=["/usr/bin/python3"], Cmd=args, User="", WorkingDir="/",
                    Labels={owner.NONCE_LABEL: meta["nonce"]}, Env=list(owner.ROLE_FLAGS)),
        HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False, Init=False, AutoRemove=False,
                        CapDrop=["ALL"], Memory=H.ACTOR_BYTES, MemorySwap=H.ACTOR_BYTES, NanoCpus=4_000_000_000,
                        PidsLimit=256, SecurityOpt=["no-new-privileges"], CgroupnsMode="private", IpcMode="private",
                        RestartPolicy=dict(Name="no", MaximumRetryCount=0), Runtime="runc",
                        LogConfig={"Type": "json-file", "Config": {"max-size": "2m", "max-file": "1"}},
                        Tmpfs={"/tmp": "rw,nodev,nosuid,noexec,size=32m"}, OomKillDisable=False, OomScoreAdj=0),
        Mounts=[dict(Type="bind", Source=source, Destination=target, RW=writable, Propagation="rprivate")
                for source, target, writable in owner.mounts_for(attempt)],
        State=dict(Status=status, Running=False, OOMKilled=False, Pid=0, Error="", ExitCode=0),
    )])


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

    def test_authority_binds_exact_media_site_case_clone_and_time(self):
        media = {"case": "unknown_key", "clone": SIBLING}
        row = dict(kind=H.AUTH_KIND, issuer="Root", approved=True, scope=H.P.SCOPE, case=media["case"],
                   clone=SIBLING, media_sha256=SHA, site_sha256=SITE_SHA, created_utc=1000, expires_utc=1600)
        raw = C.wire(row)
        pin = C.pin(raw)["sha256"]
        self.assertEqual(H.read_authority(raw, pin, media, SHA, site_sha=SITE_SHA, now=1400), row)
        with self.assertRaisesRegex(ValueError, "exact installed guest authority"):
            H.read_authority(raw, pin, media, SHA, site_sha=SHA, now=1400)
        for wrong, now in ((media | {"case": "main"}, 1400), (media | {"clone": NONCE}, 1400), (media, 1600)):
            with self.assertRaises(ValueError):
                H.read_authority(raw, pin, wrong, SHA, now=now)

    def site_fixture(self):
        base = Path(self.enterContext(TemporaryDirectory())).resolve()
        root = base / "original"
        stage, templates = root / "control", root / "templates"
        root.mkdir(mode=0o700)
        stage.mkdir(mode=0o700)
        templates.mkdir()
        template = templates / "result.raw"
        template_body = b"inert template"
        template.write_bytes(template_body)
        template.chmod(0o444)
        contract = HERE / "owned.py"
        medium = dict(case="main", clone=NONCE, plan={"sha256": SHA}, boot_payload={},
                      source={str(contract.relative_to(H.P.ROOT)): C.pin(contract.read_bytes())},
                      result=C.pin(template_body), runner={"actor_image": H.F.P.QEMU_ACTOR_IMAGE})
        media_body = C.wire(medium)
        media_sha = C.pin(media_body)["sha256"]
        (root / H.MEDIA_NAME).write_bytes(media_body)
        self.enterContext(patch.object(H, "load_media", return_value=medium))

        site = base / "site.json"
        site_body = C.wire(S.describe_site(root, media_sha))
        site_sha = C.pin(site_body)["sha256"]
        site.write_bytes(site_body)
        authority = base / "root-authority.json"
        authority_body = C.wire(dict(kind=H.AUTH_KIND, issuer="Root", approved=True, scope=H.P.SCOPE,
                                     case="main", clone=NONCE, media_sha256=media_sha, site_sha256=site_sha,
                                     created_utc=1000, expires_utc=1600))
        authority.write_bytes(authority_body)
        return root, media_sha, site, site_sha, authority, C.pin(authority_body)["sha256"]

    def test_original_authority_refuses_copied_root_and_recreated_control(self):
        root, media_sha, site, site_sha, authority, authority_sha = self.site_fixture()
        copy = root.with_name("copied")
        copy.mkdir(mode=0o700)
        (copy / "control").mkdir(mode=0o700)
        (copy / H.MEDIA_NAME).write_bytes((root / H.MEDIA_NAME).read_bytes())
        with patch.object(H, "verify_controls", side_effect=AssertionError("Entered original controls")):
            with self.assertRaisesRegex(ValueError, "original installed media and control identities"):
                S.replay_host(copy, media_sha, site, site_sha, authority, authority_sha)
            replacement = C.wire(S.describe_site(copy, media_sha))
            site.write_bytes(replacement)
            with self.assertRaisesRegex(ValueError, "exact installed guest authority"):
                S.replay_host(copy, media_sha, site, C.pin(replacement)["sha256"], authority, authority_sha)

            site.write_bytes(C.wire(S.describe_site(root, media_sha)))
            (root / "control").rename(root / "retained-control")
            (root / "control").mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "original installed media and control identities"):
                S.replay_host(root, media_sha, site, site_sha, authority, authority_sha)

    def test_original_host_replay_refuses_changed_receipts_without_client(self):
        operands = self.site_fixture()
        root = operands[0]
        lifecycle, owner = S.owner_modules(root / "control", SHA)
        prior = ("previous.scope", "f" * 64, b"fixture predecessor\n")
        self.enterContext(patch.object(H, "verify_controls", return_value=({}, prior)))
        self.enterContext(patch.object(H, "verify_source"))
        self.enterContext(patch.object(H, "verify_carriers"))
        self.enterContext(patch.object(H.M, "verify_result"))
        self.enterContext(patch.dict(S.replay_host.__globals__, owner_modules=lambda *_: (lifecycle, owner)))
        self.enterContext(patch.object(owner, "client_for", side_effect=AssertionError("Opened Docker client")))
        self.enterContext(patch.object(owner, "predecessors_absent", side_effect=AssertionError("Probed live scope")))
        _, selected = S.selected_site(*operands, live=False, connect=False)
        attempt = root / H.CLAIM
        attempt.mkdir(mode=0o700)
        (attempt / "output").mkdir(mode=0o700)
        group = "/user.slice/user-1000.slice/user@1000.service/app.slice/" + H.P.SCOPE
        expected = S.meta(selected, group)
        files = {"attempt.json": C.wire(expected), "selection.json": selected.raw_selection,
                 "prior-full-closure.json": prior[2], "run.cid": (CID + "\n").encode(),
                 "run.create.stdout": (CID + "\n").encode(), "run.attach-exit": b"0\n",
                 "run.stdout": b"fixture stdout\n", "run.stderr": b"fixture stderr\n",
                 "run.absence-1": b"", "run.absence-2": b"", "output/actor-result.json": b"{}\n"}
        for status in ("created", "exited"):
            files[f"run.{status}.inspect.json"] = inspect_fixture(owner, attempt, expected, status)
        for name, body in files.items():
            (attempt / name).write_bytes(body)
        host_body = C.wire(owner.host_result(attempt, expected, CID, 0))
        (attempt / "host-result.json").write_bytes(host_body)
        report = S.replay_host(*operands)
        self.assertEqual(report["host_result"], C.pin(host_body))
        self.assertEqual(report["actor_result"], C.pin(files["output/actor-result.json"]))
        self.assertEqual((report["cid"], report["exit_code"], report["site_sha256"]), (CID, 0, operands[3]))
        self.assertNotIn("observations", report)

        for name in ("run.stderr", "run.attach-exit", "run.exited.inspect.json", "prior-full-closure.json",
                     "output/actor-result.json"):
            with self.subTest(name=name):
                path = attempt / name
                path.write_bytes(b"substitution\n")
                with self.assertRaises(ValueError):
                    S.replay_host(*operands)
                path.write_bytes(files[name])

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

if __name__ == "__main__":
    unittest.main()
