#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert controls for Qt629 selection, actor substitution and retirement."""

import json
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
L = run_path(str(HERE / "launch.py"))
C, H, M, R = (L[name] for name in ("C", "H", "M", "R"))
NONCE, CID = "a" * 32, "b" * 64


class LaunchSelectionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.path = self.root / "authority.json"
        self.paths = {key: str(self.root / key) for key in L["PATHS"]}
        self.authority = dict(kind=L["KIND"], issuer="Root", scope=L["SCOPE"], nonce=NONCE,
                              launcher=C.pin((HERE / "launch.py").read_bytes()), paths=self.paths,
                              receipt=C.pin((HERE / "receipt.py").read_bytes()),
                              preparation=dict(path=str(self.root / "preparation.json"), **C.pin(b"selection")))

    def test_exact_root_authority_and_launcher_pin(self):
        raw = C.wire(self.authority)
        self.path.write_bytes(raw)
        self.assertEqual(L["selected"](self.path, C.pin(raw)["sha256"]), (self.authority, C.pin(raw)))
        with self.assertRaisesRegex(ValueError, "External digest differs"):
            L["selected"](self.path, "c" * 64)
        for modified in ({"issuer": None}, {"scope": "production"}, {"launcher": C.pin(b"some other launcher")},
                         {"receipt": C.pin(b"some other assembler")}):
            raw = C.wire(self.authority | modified)
            self.path.write_bytes(raw)
            with self.assertRaises(ValueError):
                L["selected"](self.path, C.pin(raw)["sha256"])

    def test_draft_preparation_cannot_be_launched(self):
        ref = self.root / "preparation.json"
        raw = C.wire(dict(kind=M["KIND"], authority=None, preparation="FIXED_BYTES_STAGED"))
        ref.write_bytes(raw)
        row = self.authority | {"preparation": dict(path=str(ref), **C.pin(raw))}
        with self.assertRaisesRegex(ValueError, "Completed fresh unissued"):
            L["prepared"](row, ref, self.root / "stage", self.root / "source")

    def test_completed_preparation_rechecks_bytes_without_requiring_a_new_window_after_run(self):
        repo, stage = HERE.parents[2], self.root / "stage"
        code = {name: (repo / name).read_bytes() for name in H["GUEST_ENTRY"]["SOURCES"]}
        code.update({name: b"retained test worker" for name in H["BASE"]})
        names = M["FIXED_MEDIA"].keys() | M["TEST_MEDIA"] | M["WESTON_MEDIA"]
        media = {"qt-replacement/" + name: b"operand " + name.encode() for name in names}
        code_pins, media_pins = ({name: C.pin(body) for name, body in group.items()} for group in (code, media))
        preview = {"keys": {"preview-test": {"fingerprint": "A" * 40, "not_before": 1, "not_after": 8000}}}
        review = dict(fingerprint="B" * 40, not_before=1, not_after=8000,
                      certificate=media_pins["qt-replacement/test-certificate.gpg"],
                      signature=media_pins["qt-replacement/" + M["P"]["PROJECT_NAME"] + ".sig"])
        plan = dict(kind=H["KIND"], nonce=NONCE, manifest=C.pin(C.wire(preview)), media=preview,
                    code=code_pins, qt_media=media_pins,
                    qt_replacement={"wayland_socket": M["DISPLAY_SOCKET"], "project_review": review})
        overlay = {"code/" + name: body for name, body in code.items()} | {"inputs/" + name: body for name, body in media.items()}
        overlay["code/plan.json"] = C.wire(plan)
        for name, body in overlay.items():
            M["put"](stage / name, body)
        init = M["put"](stage / "guest-init.sh", b"test pid1")
        source = {name: C.pin((HERE / name).read_bytes()) for name in ("controller.py", "host_stage.py", "export.py", "readback.py")}
        packet = dict(kind=M["KIND"], authority=None, preparation="GUEST_FRAGMENT_STAGED", pending=[], nonce=NONCE,
                      predecessor_nonce="c" * 32, retained={"actor_image": L["ACTOR_IMAGE"]}, source=source,
                      qt_source={name: code_pins[name] for name in H["GUEST_ENTRY"]["SOURCES"]},
                      preview={"manifest": plan["manifest"]}, staged=dict(kind="QT629_HOST_STAGE_UNISSUED_V1",
                      authority=None, path=str(stage), plan=C.pin(overlay["code/plan.json"]), init=init,
                      worker=code_pins["asahi-guest.py"], files={name: C.pin(body) for name, body in overlay.items()}))
        ref = self.root / "preparation.json"
        pin = M["put"](ref, C.wire(packet))
        authority = self.authority | {"preparation": dict(path=str(ref), **pin)}
        with patch.object(L["time"], "time", return_value=100):
            self.assertEqual(L["prepared"](authority, ref, stage, repo), (packet, plan))
        with patch.object(L["time"], "time", return_value=7000):
            with self.assertRaisesRegex(ValueError, "retained run allowance"):
                L["prepared"](authority, ref, stage, repo)
            self.assertEqual(L["prepared"](authority, ref, stage, repo, current=False), (packet, plan))
        P = M["P"]
        parity = dict(kind=P["PARITY_KIND"], official_version=P["VERSION"], project_version=P["PARITY_PROJECT_VERSION"],
                      recipe=P["PARITY_RECIPE"], test_review=review,
                      **{name: C.pin(name.encode()) for name in P["PARITY_INPUT_CAPS"]})
        changed = self.root / "parity-preparation.json"
        pin = M["put"](changed, C.wire(packet | {"parity_profile": parity}))
        selected = authority | {"preparation": dict(path=str(changed), **pin)}
        with self.assertRaisesRegex(ValueError, "Staged Qt profile differs"):
            L["prepared"](selected, changed, stage, repo, current=False)

    def test_runner_hooks_replace_names_without_modifying_legacy_globals(self):
        namespace = {"init_bytes": lambda: b"old", "copy_transport": lambda: {"old": True}}
        exec("def rehearse(): return init_bytes(), copy_transport()", namespace)
        run = L["adapted"](namespace["rehearse"], init_bytes=lambda: b"new", copy_transport=lambda: {"qt": True})
        self.assertEqual(run(), (b"new", {"qt": True}))
        self.assertEqual(namespace["rehearse"](), (b"old", {"old": True}))

    def test_detached_signature_refusal_precedes_launch_claim(self):
        paths = self.paths | {"source": str(HERE.parents[2])}
        preview = self.root / "preview"
        preview.mkdir()
        Path(paths["seed"]).write_bytes(b"seed")
        packet = {"preview": {"path": str(preview)},
                  "originals": {"owned_terminal": {"path": str(Path(paths["retained"]) / "terminal.json")}}}
        review = {"fingerprint": "C" * 40}
        plan = {"media": {"keys": {"preview-test": {"fingerprint": "A" * 40}}},
                "qt_replacement": {"project_review": review}}
        control, boot = ({"receipt": C.pin(body)} for body in (b"control", b"boot"))
        preceding = {"control": control, "control_boot": boot, "references": {"seed": C.pin(b"seed")}}
        legacy = {"O": SimpleNamespace(rehash=lambda *_: None, HISTORICAL_TEST=set()), "T": object(),
                  "control_refs": lambda *_: (control, {}), "cold_boot_refs": lambda *_: boot,
                  "transaction_kernel_refs": lambda *_: {}}
        docker, put = Mock(), Mock()
        verify = Mock(side_effect=ValueError("Detached signature refused"))
        with (patch.dict(L["owner"].__globals__, selected=lambda *_: (self.authority | {"paths": paths}, {}),
                         host_scope=lambda *_: {}, prepared=lambda *_: (packet, plan),
                         verify_derivation=lambda *_: None, mount_roles=lambda *_: {}, Docker=docker),
              patch.dict(M, retained_controller=lambda *_: (legacy, preceding, None), put=put),
              patch.dict(H, verify_qt_test=verify)):
            with self.assertRaisesRegex(ValueError, "Detached signature refused"):
                L["owner"](self.path, "b" * 64)
        verify.assert_called_once_with(self.root / "stage/inputs/qt-replacement", review)
        docker.assert_not_called()
        put.assert_not_called()
        self.assertFalse(Path(paths["output"]).exists())

    def test_actor_uses_selected_stage_and_observes_runtime_return(self):
        calls = []
        stage = {"plan": C.pin(b"plan"), "init": C.pin(b"init"), "worker": C.pin(b"worker")}
        plan = dict(nonce=NONCE)
        common = dict.fromkeys(("actor_image", "tools", "source", "references"), "fixture")
        prior = common | {"control": {"receipt": C.pin(b"control")}, "control_boot": {"receipt": C.pin(b"boot")}}
        namespace = dict(events=calls)
        exec('''
class Base:
    def __init__(self, authority):
        self.authority = authority
        self.runtime = type("Runtime", (), {"command": staticmethod(lambda *a: events.append("waited"))})()
    def run_asahi629(self, authority_path, digest):
        actual, plan = binding()
        return self.rehearse(actual, plan, authority_path, digest)
    def rehearse(self, actual, plan, path, sha):
        assert actual == self.authority
        assert init_bytes() == b"new pid1"
        assert copy_transport("preview", plan, "tree") == "manifest"
        self.runtime.command([], "out", "qemu")
        export(None, "disk", "asahi", held=True)
        return {"status": "legacy-pass"}
''', namespace)
        legacy = dict(Controller=namespace["Base"], C=SimpleNamespace(actor_boundary=lambda *_: calls.append("boundary")),
                      G=SimpleNamespace(PASS="legacy-pass"), binding=lambda **_: (prior, {"base": True}))
        authority = dict(nonce=NONCE)
        packet = dict(staged=stage, preview={"manifest": C.pin(b"preview")}, display={})
        with (patch.dict(L["actor"].__globals__, selected=lambda *_: (authority, {}), legacy_actor=lambda: (legacy, prior),
                         prepared=lambda *_: (packet, plan), verify_derivation=lambda *_: calls.append("derivation")),
              patch.dict(L["os"].environ, CACHY_ASAHI_QT629_ACTOR="1"),
              patch.dict(M, pack_inputs=lambda *_a, **_k: (plan, "manifest"),
                         require_result_uuid=lambda *args: calls.append(args),
                         put=lambda _p, raw: calls.append(C.json_body(raw))),
              patch.dict(H, export_result=lambda *_a, **kwargs: calls.append(("export", kwargs["expected_nonce"]))),
              patch.object(C, "read", side_effect=((b"new pid1", stage["init"]), (None, C.pin(b"disk")))),
              patch.object(L["time"], "time_ns", side_effect=(100, 200))):
            self.assertEqual(L["actor"](L["AUTHORITY"], "b" * 64), ({"status": "legacy-pass"}, 0))
        self.assertEqual(calls, ["boundary", "derivation", "waited",
                                 {"nonce": NONCE, "inputs_verified_at_ns": 100, "vm_exited_at_ns": 200},
                                 ("disk", C.pin(b"disk"), NONCE), ("export", NONCE)])


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.name, self.labels = L["name_labels"](NONCE)
        self.args = L["actor_args"]("c" * 64)
        self.roles = {Path("/src"): (self.root / "source", False), Path("/out"): (self.root / "output", True)}
        self.state = {"Status": "created", "Running": False}

    def container(self):
        return dict(Id=CID, Name="/" + self.name, Image=L["ACTOR_IMAGE"], State=self.state,
                    Config=dict(Entrypoint=["/usr/bin/python3"], Cmd=self.args, Labels=self.labels,
                                Env=[f"CACHY_ASAHI_{name}_ACTOR=1" for name in ("OVERLAY583", "629", "QT629")]),
                    HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, CapDrop=["ALL"], Init=False,
                                    CapAdd=[], Privileged=False, Devices=[], Memory=6 << 30, MemorySwap=6 << 30,
                                    NanoCpus=4_000_000_000, PidsLimit=256, SecurityOpt=["no-new-privileges"],
                                    Tmpfs={"/tmp": "rw,nodev,nosuid,noexec,size=32m"}),
                    Mounts=[dict(Type="bind", Destination=str(dst), Source=str(src), RW=rw)
                            for dst, (src, rw) in self.roles.items()])

    def inspect(self, row):
        return L["owned_container"](json.dumps([row]).encode(), CID, self.name, self.labels, self.roles, self.args)

    def test_container_configuration_and_wrong_mount_or_capability(self):
        args = L["create_args"](self.name, self.labels, self.roles, self.args, self.root / "cid")
        for literal in ("--pull=never", "--read-only", "--network=none", "--cap-drop=ALL"):
            self.assertIn(literal, args)
        self.assertEqual(self.inspect(self.container()), self.state)
        row = self.container()
        row["Mounts"][0]["RW"] = True
        with self.assertRaisesRegex(ValueError, "mount census"):
            self.inspect(row)
        row = self.container()
        row["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
        with self.assertRaisesRegex(ValueError, "confinement"):
            self.inspect(row)

    def test_retirement_checks_owned_cid_before_stop_then_observes_absence_twice(self):
        commands, states = [], {"listed": True, "running": True}
        cidfile = self.root / "cid"

        def call(*args, **_kwargs):
            commands.append(args)
            if args[:2] == ("container", "ls"):
                return (CID + "\n").encode() if states["listed"] else b""
            if args[1] == "stop":
                states["running"] = False
            if args[1] == "rm":
                states["listed"] = False
            return b""

        def inspect(cid, **_kwargs):
            self.assertEqual(cid, CID)
            return {"Running": states["running"]}

        d = SimpleNamespace(call=call)
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            L["retire"](d, self.name, "c" * 64, inspect, cidfile=cidfile)
        self.assertTrue(all(row[1] == "ls" for row in commands))
        commands.clear()
        with patch.object(L["time"], "sleep"), patch.object(L["time"], "time_ns", side_effect=(100, 200)):
            self.assertEqual(L["retire"](d, self.name, CID, inspect, cidfile=cidfile),
                             (CID, [100, 200], {"Running": False}))
        self.assertEqual([row[1] for row in commands if row[1] != "ls"], ["stop", "rm"])
        self.assertEqual([row[1] for row in commands[-4:]], ["ls", "ls", "ls", "ls"])

    def test_cancelled_start_race_reconciles_saved_cid_and_retries_removal(self):
        cidfile = self.root / "cid"
        cidfile.write_text(CID + "\n")
        actions, status = [], "created"

        def call(*args, **_kwargs):
            nonlocal status
            action = args[1]
            if action == "ls":
                # The saved CID remains discoverable even when the name lookup misses it.
                return CID.encode() if args[5] == "id=" + CID and status != "removed" else b""
            actions.append((action, args[-1]))
            if action == "rm" and status == "created":
                status = "running"
                raise L["DockerCommandError"]("container started while removal was requested")
            status = "exited" if action == "stop" else "removed"
            return b""

        def inspect(cid, **_kwargs):
            self.assertEqual(cid, CID)
            return dict(Status=status, Running=status == "running", ExitCode=143)

        d = SimpleNamespace(call=call)
        with patch.object(L["time"], "sleep"), patch.object(L["time"], "time_ns", side_effect=(300, 400)):
            self.assertEqual(L["retire"](d, self.name, None, inspect, cidfile=cidfile),
                             (CID, [300, 400], dict(Status="exited", Running=False, ExitCode=143)))
        self.assertEqual(actions, [("rm", CID), ("stop", CID), ("rm", CID)])

    def test_uncertain_create_retires_owned_actor_first_listed_after_six_seconds(self):
        cidfile = self.root / "cid"
        cidfile.touch()
        clock, removed = [0.0], []

        def call(*args, **_kwargs):
            if args[1] == "ls":
                return CID.encode() if clock[0] >= 6 and not removed else b""
            self.assertEqual(args[:2], ("container", "rm"))
            removed.append(args[-1])
            return b""

        with (patch.object(L["time"], "monotonic", side_effect=lambda: clock[0]),
              patch.object(L["time"], "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)),
              patch.object(L["time"], "time_ns", side_effect=lambda: round(1000 * clock[0]))):
            inspected = Mock(return_value={"Status": "created", "Running": False})
            claimed, absence, state = L["retire"](SimpleNamespace(call=call), self.name, None, inspected,
                                                  cidfile=cidfile, create_uncertain=True)
        self.assertEqual(claimed, CID)
        self.assertEqual(state, {"Status": "created", "Running": False})
        self.assertEqual(len(absence), 2)
        self.assertGreater(absence[1], absence[0])
        self.assertGreater(absence[0], 6000)
        inspected.assert_called_once()
        self.assertEqual(inspected.call_args.args, (CID,))
        self.assertEqual(removed, [CID])

    def test_uncertain_create_without_daemon_outcome_refuses_at_deadline(self):
        clock = [0.0]
        docker = SimpleNamespace(call=Mock(return_value=b""))
        inspect = Mock()
        with (patch.dict(L["retire"].__globals__, RETIRE_TIMEOUT=7),
              patch.object(L["time"], "monotonic", side_effect=lambda: clock[0]),
              patch.object(L["time"], "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)),
              patch.object(L["time"], "time_ns") as observe):
            with self.assertRaisesRegex(ValueError, "create outcome remains unresolved at the bounded retirement deadline"):
                L["retire"](docker, self.name, None, inspect, cidfile=self.root / "cid", create_uncertain=True)
        self.assertEqual(clock[0], 7)
        self.assertTrue(all(row.args[:2] == ("container", "ls") for row in docker.call.call_args_list))
        inspect.assert_not_called()
        observe.assert_not_called()

    def test_retirement_retries_respect_one_deadline(self):
        cidfile = self.root / "cid"
        attempts, clock = [], [0.0]

        def refusing(*args, timeout):
            self.assertLessEqual(timeout, 1.0 - clock[0])
            if args[1] == "ls":
                return CID.encode()
            attempts.append(args[1])
            raise L["DockerCommandError"]("transient stop failure")

        with (patch.dict(L["retire"].__globals__, RETIRE_TIMEOUT=1),
              patch.object(L["time"], "monotonic", side_effect=lambda: clock[0]),
              patch.object(L["time"], "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay))):
            with self.assertRaisesRegex(ValueError, "bounded deadline"):
                L["retire"](SimpleNamespace(call=refusing), self.name, CID,
                             lambda *_a, **_k: {"Running": True}, cidfile=cidfile)
        self.assertEqual(attempts, ["stop"] * 5)


class ObservationsTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.actor = self.root / "actor/qt629"
        self.actor.mkdir(parents=True)
        self.qemu = ["/usr/bin/qemu-system-aarch64", "-name", "overlay583-" + NONCE]
        self.exited = dict(Status="exited", ExitCode=1, Running=False)
        row = dict(argv=self.qemu, reaped=True, ownership="REAPED", group_census="EMPTY_TWICE", exit=1,
                   output_complete=True, timeout=False, signals=[])
        (self.actor / "qemu.json").write_bytes(C.wire(row))
        (self.actor / "vm-observation.json").write_bytes(C.wire(dict(nonce=NONCE, inputs_verified_at_ns=100, vm_exited_at_ns=200)))
        (self.actor / "result.raw").write_bytes(b"synthetic stopped result body")
        leaf = "inputs/qt-replacement/"
        self.packet = {"originals": {}, "staged": {"files": {leaf + "test-certificate.gpg": C.pin(b"public test fixture"),
                        leaf + M["P"]["PROJECT_NAME"] + ".sig": C.pin(b"test fixture signature")}}}

    def test_held_export_seals_actual_four_observations_and_retirement(self):
        calls = []
        with patch.dict(M, export_stopped=lambda **args: calls.append(args) or dict(held=True)):
            output = L["export_after_retirement"](self.root, NONCE, self.packet, self.root / "stage", CID,
                                                 self.exited, [300, 400], True, self.qemu)
        self.assertTrue(output["held"])
        raw = (self.root / "stopped-result.json").read_bytes()
        self.assertEqual(output["stopped_observation"], C.pin(raw))
        stop = C.json_body(raw, canonical=True)
        self.assertEqual(stop["host_times"], {"inputs-verified": 100, "vm-exited": 200, "absence-first": 300, "absence-second": 400})
        self.assertEqual(stop["retirement"]["outer_container"], dict(id=CID, exit=1, removed=True))
        self.assertIsNone(stop["retirement"]["keyrings"])
        self.assertEqual(calls[0]["nonce"], NONCE)

    def test_refuses_rebound_qemu_and_out_of_order_absence(self):
        for argv, sample in ((["wrong"], [300, 400]), (self.qemu, [300, 250])):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                L["export_after_retirement"](self.root, NONCE, self.packet, self.root / "stage", CID,
                                             self.exited, sample, True, argv)
        self.assertFalse((self.root / "stopped-result.json").exists())

    def test_created_state_cannot_supply_a_stopped_receipt_exit(self):
        with self.assertRaisesRegex(ValueError, "outer terminal state"):
            L["export_after_retirement"](self.root, NONCE, self.packet, self.root / "stage", CID,
                                         {"Status": "created", "ExitCode": 0, "Running": False}, [300, 400], True, self.qemu)
        self.assertFalse((self.root / "stopped-result.json").exists())

    def test_completed_export_calls_independent_assembler_with_digest_selected_observation(self):
        calls = []
        disk = self.actor / "result.raw"
        with disk.open("wb") as stream:
            stream.truncate(H["E"]["RESULT_BYTES"])
        _, selected_pin = C.read(disk, H["E"]["RESULT_BYTES"], collect=False)
        with patch.dict(L["ASSEMBLER"], assemble=lambda **args: calls.append(args) or dict(receipt="independent")):
            result = L["export_after_retirement"](self.root, NONCE, self.packet, self.root / "stage", CID,
                                                 self.exited | {"ExitCode": 0}, [300, 400], False, self.qemu, selected_pin)
        self.assertEqual(result, {"receipt": "independent"})
        call, = calls
        raw = call["observation"].read_bytes()
        self.assertEqual(call["observation_sha"], C.pin(raw)["sha256"])
        self.assertEqual(call["nonce"], NONCE)
        row = C.json_body(raw, canonical=True)
        self.assertEqual(row["kind"], L["ASSEMBLER"]["STOPPED"])
        self.assertFalse(row["held"])
        self.assertEqual(list(sorted(row["host_times"].values())), [100, 200, 300, 400])


if __name__ == "__main__":
    unittest.main()
