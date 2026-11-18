# SPDX-License-Identifier: MIT
"""Inert controls for QtCore host selection, limits and ownership."""

import copy
import json
import os
from pathlib import Path
from runpy import run_path
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
T = SimpleNamespace(**run_path(str(HERE.parents[1] / "install/overlay583_trial/trial.py")))
C = SimpleNamespace(T=T, SCOPE="cachy-asahi-qtbase16k-qtcore-link.scope", IMAGE="sha256:" + "1" * 64,
                    ACTOR_PATH="/src/scripts/integration/qt612_base_16k_link_preflight/actor.py")
with patch.dict(sys.modules, capsule=C):
    S = SimpleNamespace(**run_path(str(HERE / "site.py")))
sys.addaudithook(S.fence)


class HostControls(unittest.TestCase):
    def setUp(self):
        self.root = Path("/fixture/capsule")
        self.attempt = self.root / "issued.fixture"
        self.handoff = dict(plan=dict(sha256="2" * 64))
        self.plan = dict(nonce="3" * 32)
        self.handoff_sha, self.authority_sha, self.cid = (value * 64 for value in "456")
        self.group = "/user.slice/user-1000.slice/" + C.SCOPE
        self.meta = S.attempt_meta(self.handoff, self.plan, self.handoff_sha, self.authority_sha,
                                   self.group, self.attempt)

    def row(self, attempt=None, phase="created", exit_code=0):
        args = S.actor_args(self.handoff_sha, self.authority_sha)
        return dict(Id=self.cid, Name="/" + self.meta["name"], Image=C.IMAGE, Path="/usr/bin/python3", Args=args,
                    Config=dict(Entrypoint=["/usr/bin/python3"], Cmd=args, User="", WorkingDir="/",
                                Labels={S.NONCE_LABEL: self.plan["nonce"]}, Env=list(S.ROLE_FLAGS)),
                    HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False,
                                    Init=False, AutoRemove=False, CapDrop=["ALL"], CapAdd=None, Devices=[],
                                    Memory=6 << 30, MemorySwap=6 << 30, NanoCpus=4_000_000_000, PidsLimit=256,
                                    SecurityOpt=["no-new-privileges"],
                                    Tmpfs={"/tmp": "rw,nodev,nosuid,noexec,size=32m"},
                                    OomKillDisable=False, OomScoreAdj=0),
                    Mounts=[dict(Type="bind", Source=source, Destination=target, RW=rw, Propagation="rprivate")
                            for source, target, rw in S.mounts_for(attempt or self.attempt)],
                    State=dict(Status=phase, Running=False, OOMKilled=False, Pid=0, Error="", ExitCode=exit_code))

    def test_only_attempt_output_is_writable(self):
        command = S.create_args(self.attempt, self.meta)
        mounts = [command[index + 1] for index, word in enumerate(command) if word == "--mount"]
        self.assertEqual(len(mounts), 6)
        self.assertEqual([mount for mount in mounts if not mount.endswith(",readonly")],
                         [f"type=bind,source={self.attempt / 'output'},target=/out"])
        self.assertEqual(command[-8:], S.actor_args(self.handoff_sha, self.authority_sha))
        self.assertIn("--pull=never", command)
        self.assertIn("--network=none", command)

    def test_wrong_inspect_effective_limits_refused(self):
        original = self.row()
        S.inspect_row(T.encoded([original]), self.attempt, self.meta, self.cid)
        changes = (("NetworkMode", "bridge"), ("MemorySwap", 7 << 30), ("CapAdd", ["SYS_ADMIN"]),
                   ("DeviceRequests", [{"Driver": "gpu"}]), ("ReadonlyRootfs", False))
        for key, value in changes:
            with self.subTest(key=key):
                row = copy.deepcopy(original)
                row["HostConfig"][key] = value
                with self.assertRaisesRegex(ValueError, "offline read-only"):
                    S.inspect_row(T.encoded([row]), self.attempt, self.meta, self.cid)
        for section, key, value, message in (("Mounts", "RW", True, "sole writable"),
                                              ("Config", "User", "1234", "actor args")):
            with self.subTest(section=section):
                row = copy.deepcopy(original)
                target = row[section][0] if section == "Mounts" else row[section]
                target[key] = value
                with self.assertRaisesRegex(ValueError, message):
                    S.inspect_row(T.encoded([row]), self.attempt, self.meta, self.cid)

    def test_exact_rootless_defaults_and_natural_hold(self):
        before, after = self.row(), self.row(phase="exited", exit_code=2)
        after["HostConfig"].update(OomKillDisable=None, OomScoreAdj=200)
        S.matching_inspects(T.encoded([before]), T.encoded([after]), self.attempt, self.meta, self.cid, 2)
        after["HostConfig"]["OomScoreAdj"] = 201
        with self.assertRaisesRegex(ValueError, "allowed rootless Docker defaults"):
            S.matching_inspects(T.encoded([before]), T.encoded([after]), self.attempt, self.meta, self.cid, 2)

    def test_previous_claim_refuses_before_authority_or_actor(self):
        with tempfile.TemporaryDirectory() as stage:
            root = Path(stage)
            (root / "root-run.claim").symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "original QtCore attempt already claimed"):
                S.run(root, self.handoff, self.plan, self.handoff_sha, root / "authority", self.authority_sha)

    def test_capacity_refuses_before_claim_or_actor(self):
        with tempfile.TemporaryDirectory() as stage:
            root = Path(stage)
            authority = root / "authority"
            authority.write_bytes(b"inert candidate\n")
            with patch.object(C, "verify_selection", create=True, return_value={}), \
                 patch.object(C, "preflight_root", create=True, return_value={"fits": False}), \
                 self.assertRaisesRegex(ValueError, "below the sealed limits"):
                S.run(root, self.handoff, self.plan, self.handoff_sha, authority, self.authority_sha)
            self.assertFalse((root / "root-run.claim").exists())

    def test_owned_lifecycle_retains_original_hold_and_two_empty_censuses(self):
        with tempfile.TemporaryDirectory() as stage:
            attempt = Path(stage)
            before, after = self.row(attempt), self.row(attempt, phase="exited", exit_code=2)
            calls = []
            cid_body = (self.cid + "\n").encode()

            def inspect_docker(operation, action, *args):
                calls.append((operation, action))
                if action == "create":
                    (attempt / "run.cid").write_bytes(cid_body)
                    return cid_body
                if action == "inspect":
                    self.assertEqual(args, (self.cid,))
                    return T.encoded([next(inspections)])
                self.assertEqual((action, args), ("rm", (self.cid,)))
                return cid_body

            def fake_attach(path, cid):
                self.assertEqual((path, cid), (attempt, self.cid))
                calls.append(("container", "attach"))
                return 2

            def absent(cid):
                self.assertEqual(cid, self.cid)
                calls.append(("container", "absent"))
                return b""

            inspections = iter((before, after, after))
            client = SimpleNamespace(docker=inspect_docker, attach=fake_attach, absent=absent)
            with patch.object(signal, "signal"), patch.object(signal, "pthread_sigmask"):
                self.assertEqual(S.execute_owned(client, attempt, self.meta), 2)
            self.assertEqual(calls, [("container", action) for action in
                            ("create", "inspect", "attach", "inspect", "inspect", "rm", "absent", "absent")])
            self.assertEqual(json.loads((attempt / "host-result.json").read_bytes()), S.host_result(self.meta, self.cid, 2))
            self.assertTrue(all((attempt / f"run.absence-{n}").read_bytes() == b"" for n in (1, 2)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
