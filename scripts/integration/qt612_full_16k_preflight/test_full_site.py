# SPDX-License-Identifier: MIT
"""Inert host launcher and once-claim controls for the Qtbase full target."""

import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
with patch.object(sys, "path", [str(HERE), *sys.path]):
    import full_site as S


_fixture_active = False


def no_actor(event, _args):
    if _fixture_active and event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Host launcher fixture performed live execution")


sys.addaudithook(no_actor)
CID, FOREIGN_CID = "a" * 64, "b" * 64
HANDOFF_SHA, AUTHORITY_SHA, SITE_SHA = (digit * 64 for digit in "456")
NONCE = "7" * 32
GROUP = f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service/app.slice/{S.SCOPE}"


def set_fixture_active(value):
    global _fixture_active
    _fixture_active = value


class Daemon:
    """Model create, the reviewed inspect states, attach, and owned retirement."""

    def __init__(self, attempt, row, exit_code=2):
        self.attempt, self.row, self.exit_code = attempt, row, exit_code
        self.created = self.attached = self.removed = False
        self.claimed_cid, self.create_stdout = CID, CID
        self.timeout = self.oom = self.running = False
        self.foreign_present = False
        self.calls = []

    def docker(self, operation, action, *args):
        self.calls.append((operation, action, *args))
        if (operation, action) == ("container", "ls"):
            return b""
        if (operation, action) == ("container", "create"):
            self.created = True
            self.save("run.cid", (self.claimed_cid + "\n").encode())
            return (self.create_stdout + "\n").encode()
        if (operation, action) == ("container", "inspect"):
            if args == (FOREIGN_CID,) and self.foreign_present:
                foreign = copy.deepcopy(self.row)
                foreign.update(Id=FOREIGN_CID, Name="/unrelated-build")
                return S.C.wire([foreign])
            if args != (CID,):
                raise AssertionError("Fixture asked to inspect a foreign container")
            row = copy.deepcopy(self.row)
            if self.attached:
                row["State"].update(Status="exited", ExitCode=self.exit_code, OOMKilled=self.oom)
                row["HostConfig"].update(OomKillDisable=None, OomScoreAdj=200)
            if self.running:
                row["State"].update(Status="running", Running=True, Pid=2345)
            return S.C.wire([row])
        if (operation, action) == ("container", "stop") and args[-1] == CID and self.running:
            self.running = False
            return (CID + "\n").encode()
        if (operation, action) == ("container", "rm") and args == (CID,):
            self.removed = True
            return (CID + "\n").encode()
        raise AssertionError(f"Unexpected daemon operation {operation, action, args!r}")

    def attach(self, attempt, cid):
        if attempt != self.attempt or cid != CID:
            raise AssertionError("Fixture received a foreign attempt or CID")
        self.calls.append(("attach", cid))
        self.attached = True
        self.save("run.stdout", b"fixture stdout\n")
        self.save("run.stderr", b"fixture stderr\n")
        if self.timeout:
            self.running = True
            raise subprocess.TimeoutExpired("inert fixture", 1)
        return self.exit_code

    def absent(self, cid):
        self.calls.append(("absence", cid))
        present = (cid == CID and self.created and not self.removed
                   or cid == FOREIGN_CID and self.foreign_present)
        return (cid + "\n").encode() if present else b""

    def save(self, name, data):
        path = self.attempt / name
        path.write_bytes(data)
        path.chmod(0o600)

    def verify_daemon(self):
        self.calls.append(("verified-daemon",))


class FullSiteTests(unittest.TestCase):
    def setUp(self):
        set_fixture_active(True)
        self.addCleanup(set_fixture_active, False)
        self.stage = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.stage).resolve() / "capsule"
        self.root.mkdir(mode=0o700)
        self.attempt = self.root / S.CLAIM
        self.plan = dict(nonce=NONCE, limits=S.F.DEFAULT_LIMITS.copy(), attach_seconds=51600)
        self.handoff = dict(plan=dict(sha256="2" * 64),
                            runner=dict(actor_image="sha256:" + "1" * 64, vcpus=4))
        info = self.root.stat()
        self.site = dict(kind=S.SITE_KIND, scope=S.SCOPE, nonce=NONCE,
                         capsule=dict(path=str(self.root), device=info.st_dev, inode=info.st_ino,
                                      handoff_sha256=HANDOFF_SHA),
                         qtgui_handoff=str(self.root.parent / "qtgui-handoff"),
                         qtgui_retirement=str(self.root.parent / "qtgui-retirement"),
                         plan_sha256=self.handoff["plan"]["sha256"])
        self.meta = S.attempt_meta(self.site, self.handoff, self.plan, GROUP, self.attempt,
                                   AUTHORITY_SHA, SITE_SHA)

    def inspect(self):
        args = S.actor_args(HANDOFF_SHA, AUTHORITY_SHA)
        return dict(
            Id=CID, Name="/" + self.meta["name"], Image=self.meta["image"], Path="/usr/bin/python3", Args=args,
            Config=dict(Entrypoint=["/usr/bin/python3"], Cmd=args, User="", WorkingDir="/",
                        Labels={S.NONCE_LABEL: NONCE}, Env=list(S.ROLE_FLAGS)),
            HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False, Init=False, AutoRemove=False,
                            CapDrop=["ALL"], CapAdd=None, Devices=[], Memory=8 << 30, MemorySwap=8 << 30,
                            NanoCpus=4_000_000_000, PidsLimit=256, SecurityOpt=["no-new-privileges"],
                            CgroupnsMode="private", IpcMode="private", RestartPolicy=dict(Name="no", MaximumRetryCount=0),
                            Runtime="runc", LogConfig={"Type": "json-file",
                                                       "Config": {"max-size": "2m", "max-file": "1"}},
                            Tmpfs={"/tmp": "rw,nodev,nosuid,noexec,size=32m"}, OomKillDisable=False, OomScoreAdj=0),
            Mounts=[dict(Type="bind", Source=source, Destination=target, RW=rw, Propagation="rprivate")
                    for source, target, rw in S.mounts_for(self.attempt)],
            State=dict(Status="created", Running=False, OOMKilled=False, Pid=0, Error="", ExitCode=0),
        )

    def fake_daemon(self, exit_code=2):
        self.attempt.mkdir(mode=0o700)
        (self.attempt / "output").mkdir(mode=0o700)
        return Daemon(self.attempt, self.inspect(), exit_code)

    def selection(self, start, end):
        authority = self.root.parent / "selection"
        binding = S.F.unsupplied_selection(self.handoff, self.plan, HANDOFF_SHA)
        body = S.C.wire(binding | dict(issuer="Root", approved=True, created_utc=start, expires_utc=end))
        authority.write_bytes(body)
        return authority, S.C.pin(body)["sha256"]

    def test_create_binds_one_writable_output_and_exact_actor_limits(self):
        command = S.create_args(self.attempt, self.meta)
        mounts = [value for flag, value in zip(command, command[1:]) if flag == "--mount"]
        self.assertEqual(len(mounts), 6)
        self.assertEqual([row for row in mounts if not row.endswith(",readonly")],
                         [f"type=bind,source={self.attempt / 'output'},target=/out"])
        self.assertEqual(command[-8:], S.actor_args(HANDOFF_SHA, AUTHORITY_SHA))
        self.assertTrue(command[-5].endswith("/qt612_full_16k_preflight/full_actor.py"))
        for option in ("--pull=never", "--read-only", "--network=none", "--cap-drop=ALL", "--cpus=4",
                       f"--memory={8 << 30}", f"--memory-swap={8 << 30}", "--pids-limit=256",
                       "--security-opt=no-new-privileges", "--cgroupns=private", "--ipc=private", "--restart=no",
                       "--runtime=runc", "--log-driver=json-file", "--log-opt=max-size=2m", "--log-opt=max-file=1"):
            self.assertIn(option, command)

    def test_inspect_rejects_mount_and_isolation_drift(self):
        original = self.inspect()
        S.inspect_row(S.C.wire([original]), self.attempt, self.meta, CID)
        changes = (
            ("HostConfig", "NetworkMode", "bridge"), ("HostConfig", "MemorySwap", 9 << 30),
            ("HostConfig", "NanoCpus", 3_000_000_000), ("HostConfig", "DeviceRequests", [{"Driver": "gpu"}]),
            ("HostConfig", "ReadonlyRootfs", False), ("HostConfig", "SecurityOpt", []),
            ("HostConfig", "CgroupnsMode", "host"), ("HostConfig", "IpcMode", "host"),
            ("HostConfig", "RestartPolicy", {"Name": "always", "MaximumRetryCount": 0}),
            ("HostConfig", "Runtime", "unchecked"),
            ("HostConfig", "LogConfig", {"Type": "json-file", "Config": {}}),
            ("HostConfig", "CapAdd", ["SYS_ADMIN"]), ("Config", "Env", ["CACHY_ASAHI_QTBASE16K_ACTOR=1"]),
        )
        for section, key, value in changes:
            with self.subTest(section=section, key=key):
                row = copy.deepcopy(original)
                row[section][key] = value
                with self.assertRaises(ValueError):
                    S.inspect_row(S.C.wire([row]), self.attempt, self.meta, CID)
        for key, value in (("RW", True), ("Source", str(self.root.parent / "foreign/source"))):
            with self.subTest(key=key):
                row = copy.deepcopy(original)
                row["Mounts"][0][key] = value
                with self.assertRaises(ValueError):
                    S.inspect_row(S.C.wire([row]), self.attempt, self.meta, CID)

    def test_natural_hold_retains_original_exit_and_retirement(self):
        client = self.fake_daemon()
        self.assertEqual(S.execute_owned(client, self.attempt, self.meta, lambda: None), 2)
        self.assertTrue(client.attached and client.removed)
        self.assertEqual(client.calls[-2:], [("absence", CID)] * 2)
        report = S.C.json_body((self.attempt / "host-result.json").read_bytes(), canonical=True)
        self.assertTrue(report["natural"])
        self.assertEqual((report["cid"], report["exit_code"]), (CID, 2))
        self.assertEqual((self.attempt / "run.attach-exit").read_bytes(), b"2\n")
        self.assertEqual((self.attempt / "run.stderr").read_bytes(), b"fixture stderr\n")
        self.assertEqual((self.attempt / "run.create.stdout").read_bytes(), (CID + "\n").encode())
        self.assertEqual(report["receipts"]["run.stderr"], S.C.pin(b"fixture stderr\n"))

    def test_mismatched_create_cid_never_attaches_or_removes_foreign_actor(self):
        client = self.fake_daemon()
        client.claimed_cid = FOREIGN_CID
        client.foreign_present = True
        with self.assertRaises(ValueError):
            S.execute_owned(client, self.attempt, self.meta, lambda: None)
        self.assertFalse(client.attached)
        self.assertTrue(client.foreign_present)
        self.assertFalse(any(call[:2] in (("container", "rm"), ("container", "stop"), ("container", "kill"))
                             and FOREIGN_CID in call for call in client.calls))
        self.assertFalse((self.attempt / "host-result.json").exists())

    def test_expiry_before_create_is_non_mutating(self):
        client = self.fake_daemon()

        def expired():
            raise ValueError("entry window closed")

        with self.assertRaisesRegex(ValueError, "entry window closed"):
            S.execute_owned(client, self.attempt, self.meta, expired)
        self.assertFalse(client.created or client.attached)

    def test_oom_exit_cannot_be_natural(self):
        client = self.fake_daemon(exit_code=137)
        client.oom = True
        with self.assertRaises(ValueError):
            S.execute_owned(client, self.attempt, self.meta, lambda: None)
        self.assertEqual((self.attempt / "run.attach-exit").read_bytes(), b"137\n")
        self.assertFalse((self.attempt / "host-result.json").exists())
        self.assertTrue(client.removed)

    def test_attach_uses_reviewed_process_ceiling_and_separate_streams(self):
        client = SimpleNamespace(attach_seconds=self.plan["attach_seconds"],
                                 argv=lambda args: ["/fixture/docker", *args], check=lambda: None)
        self.attempt.mkdir(mode=0o700)

        def fake_start(argv, **options):
            self.assertEqual(argv, ["/fixture/docker", "container", "start", "--attach", CID])
            self.assertEqual(options["timeout"], self.plan["attach_seconds"])
            self.assertIs(options["preexec_fn"], S.OLD.bound_output)
            options["stdout"].write(b"fixture stdout\n")
            options["stderr"].write(b"fixture stderr\n")
            return SimpleNamespace(returncode=2)

        with patch.object(subprocess, "run", fake_start):
            self.assertEqual(S.OLD.Client.attach(client, self.attempt, CID), 2)
        self.assertEqual((self.attempt / "run.stdout").read_bytes(), b"fixture stdout\n")
        self.assertEqual((self.attempt / "run.stderr").read_bytes(), b"fixture stderr\n")

    def test_timeout_stops_only_owned_actor_without_natural_receipt(self):
        client = self.fake_daemon()
        client.timeout = True
        with self.assertRaises((subprocess.TimeoutExpired, ValueError)):
            S.execute_owned(client, self.attempt, self.meta, lambda: None)
        self.assertTrue(client.removed)
        self.assertTrue(any(call[:2] == ("container", "stop") and call[-1] == CID for call in client.calls))
        self.assertFalse((self.attempt / "host-result.json").exists())

    def test_stale_selection_refuses_before_claim(self):
        now = int(time.time())
        with self.assertRaisesRegex(ValueError, "entry window"):
            S.run(self.site, self.handoff, self.plan, SITE_SHA, *self.selection(now - 100, now - 10))
        self.assertFalse(self.attempt.exists())

    def test_bound_root_refuses_copy_and_replacement_at_same_path(self):
        descriptor = self.root.parent / "site.json"
        body = S.C.wire(self.site)
        descriptor.write_bytes(body)
        digest = S.C.pin(body)["sha256"]
        replacement = self.root.parent / "replacement"
        replacement.mkdir(mode=0o700)
        with patch.object(S, "site_descriptor") as describe:
            with self.assertRaisesRegex(ValueError, "capsule root differ"):
                S.load_site(descriptor, digest, replacement)
            self.root.rename(self.root.parent / "original")
            replacement.rename(self.root)
            with self.assertRaisesRegex(ValueError, "capsule root differ"):
                S.load_site(descriptor, digest, self.root)
        describe.assert_not_called()

    def test_existing_claim_refuses_even_if_only_a_dangling_alias(self):
        self.attempt.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(ValueError, "(?:claim|attempt)"):
            S.run(self.site, self.handoff, self.plan, SITE_SHA, self.root / "missing", AUTHORITY_SHA)
        self.assertTrue(self.attempt.is_symlink())

    def test_wrong_scope_group_refuses_before_create(self):
        with self.assertRaisesRegex(ValueError, "scope"):
            S.attempt_meta(self.site, self.handoff, self.plan, "/user.slice/other.scope", self.attempt,
                           AUTHORITY_SHA, SITE_SHA)

    def test_result_clone_is_private_distinct_and_reverified(self):
        (self.root / "templates").mkdir(mode=0o700)
        template = self.root / "templates/result.raw"
        template.write_bytes(b"pinned empty result")
        template.chmod(0o444)
        self.fake_daemon()
        target = self.attempt / "output/result.raw"
        pin = S.C.pin(template.read_bytes())
        plan = self.plan | {"inputs": {"result.raw": pin}}

        def clone(source, result, selected):
            self.assertEqual((source, result, selected), (template, target, pin))
            with result.open("xb") as stream:
                stream.write(source.read_bytes())

        with (patch.object(S.F.K, "clone", side_effect=clone),
              patch.object(S.F, "verify_result_template") as verify):
            S.clone_result(self.root, self.attempt, plan)
        verify.assert_called_once_with(target, plan)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(template.stat().st_mode & 0o777, 0o444)
        self.assertFalse(template.samefile(target))

    def test_run_claims_once_and_post_scope_reopens_original_receipts(self):
        now = int(time.time())
        authority = self.selection(now - 1, now + 120)
        previous = {label: (f"{label}.scope", digit * 64, label.encode())
                    for label, digit in zip(("q3", "r4", "core", "gui"), "1234")}
        client = Daemon(self.attempt, self.inspect())
        client.row["Args"] = client.row["Config"]["Cmd"] = S.actor_args(HANDOFF_SHA, authority[1])
        capacity = {"fits": True, "free_bytes": 1 << 40}
        preflight = {"capacity": capacity}
        with (patch.object(S, "owning_group", return_value=GROUP),
              patch.object(S.F, "preflight", return_value=preflight),
              patch.object(S.F, "capacity", return_value=capacity),
              patch.object(S, "client_for", return_value=client),
              patch.object(S, "predecessors", return_value=previous),
              patch.object(S.OLD, "scope_listing", return_value=b"") as scopes,
              patch.object(S, "clone_result") as clone):
            self.assertEqual(S.run(self.site, self.handoff, self.plan, SITE_SHA, *authority), 2)
            clone.assert_called_once_with(self.root, self.attempt, self.plan)
            with self.assertRaisesRegex(ValueError, "already claimed"):
                S.run(self.site, self.handoff, self.plan, SITE_SHA, *authority)
            observed = S.observe(self.site, self.handoff, self.plan, SITE_SHA)
            self.assertEqual(observed["observations"], [{"container_absent": True, "scope_absent": True}] * 2)
            self.assertEqual(observed["exit_code"], 2)
            self.assertEqual(scopes.call_count, 10)
            scopes.return_value = b"full scope remains"
            with self.assertRaisesRegex(ValueError, "scope or container remains"):
                S.observe(self.site, self.handoff, self.plan, SITE_SHA)
            (self.attempt / "run.stderr").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "retained original"):
                S.observe(self.site, self.handoff, self.plan, SITE_SHA)
        self.assertEqual(sum(call[:2] == ("container", "create") for call in client.calls), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
