# SPDX-License-Identifier: MIT
"""Inert launcher controls. No Docker, network, mounts or signer actors."""

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import capacity
import executor
import launch

HERE = Path(__file__).resolve().parent
BASE = "sha256:" + "1"*64
STAGE = "sha256:" + "2"*64
NONCE = "3"*32
FINGERPRINT = "B2"*20


class LaunchTests(unittest.TestCase):
    def test_retire_only_pinned_superseded_transfer_files(self):
        R = executor.load(HERE.parent/"qt612-complete-family-native-source/runner_inputs.py",
                          "qt612_test_transfer_retirement")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            acquired, bound = work/"acquired", work/"bound"
            roles = ["operands/qt-upstream/archive.tar.xz", "framework/group/recipe",
                     "operands/base-materials/rootfs.tar.gz", "operands/dependencies/md4c.pkg"]
            payload = b"bounded synthetic exact operand"
            for name in roles:
                path = acquired/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            projected = {"archives/one/archive.tar.xz": "archive.tar.xz", "code/recipe": "group/recipe"}
            files = {name: R.C.pin(payload) for name in projected}
            for name in files:
                path = bound/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            args = (R, acquired, bound, {"new_source_map": {"sha256":"a"*64}}, work.stat().st_dev)
            second = acquired/roles[1]
            with patch.object(R.C, "read_source", return_value={"files":files}), \
                    patch.object(R, "mapped_archive_paths", return_value={list(projected)[0]: "archive.tar.xz"}), \
                    patch.object(R, "mapped_git_paths", return_value={"code/recipe": "group/recipe"}):
                second.write_bytes(b"x"*len(payload))
                with self.assertRaisesRegex(ValueError, "STABLE_WHOLE_FILE_PIN"):
                    launch.retire_transfer_duplicates(*args)
                self.assertTrue((acquired/roles[0]).is_file())
                second.write_bytes(payload)
                foreign = second.with_name("unselected")
                foreign.write_bytes(b"held")
                with self.assertRaisesRegex(ValueError, "finite superseded transfer namespace"):
                    launch.retire_transfer_duplicates(*args)
                self.assertTrue(foreign.is_file())
                foreign.unlink()
                actual = launch.retire_transfer_duplicates(*args)
            self.assertEqual((actual["files"], actual["bytes"]), (2, 2*len(payload)))
            self.assertFalse(any((acquired/name).exists() for name in roles[:2]))
            self.assertTrue(all((acquired/name).read_bytes() == payload for name in roles[2:]))
            self.assertTrue(all((bound/name).read_bytes() == payload for name in files))

    def test_known_controller_projects_only_owned_unit_duration(self):
        class Controller:
            def __init__(self, root, out, policy, nonce, uid, gid):
                self.policy = policy

            def run(self, argv, seconds):
                return argv, seconds

        module = SimpleNamespace(Controller=Controller, D=SimpleNamespace(
            unit=lambda nonce, kind: f"cachy-llhttp-reference-{nonce}-{kind}.service"))
        old = dict(pair_seconds=1200, controller_work_seconds=1650,
                   controller_scope_seconds=1740, cleanup_seconds=90, unrelated="fixed")
        control = launch.first_stage_controller(dict(controller=module, policy=old),
            "/retained", "/next", NONCE, 1001, 1001)
        self.assertEqual(control.policy["unrelated"], "fixed")
        self.assertEqual(control.policy["controller_scope_seconds"], 21030)
        self.assertEqual(old["pair_seconds"], 1200)
        unit = f"--unit=cachy-llhttp-reference-{NONCE}-daemon.service"
        args = ["/usr/bin/systemd-run", unit, "--property=RuntimeMaxSec=1290s", "--", "/usr/bin/dockerd"]
        self.assertEqual(control.run(args, 20), (args[:2]+["--property=RuntimeMaxSec=21030s"]+args[3:], 20))
        args[1] = "--unit=foreign.service"
        with self.assertRaisesRegex(ValueError, "Only one current owner"):
            control.run(args, 20)

    def test_exact_operation_order_and_mount_for_bind(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)
        image = output/"storage.img"
        events = []
        stages = []
        model = SimpleNamespace(out=output, policy={
            "minimum_disk_bytes":capacity.MINIMUM_BYTES, "storage_bytes":capacity.STORAGE_BYTES,
            "host_reserve_bytes":capacity.RESERVE_BYTES, "minimum_available_bytes":10*capacity.GIB})
        model.tool = lambda name: "/usr/bin/" + name
        model.run = lambda argv, _: events.append(("allocate", argv))

        def setup():
            fd = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            events.append("exclusive-create")
            model.run(["/usr/bin/fallocate", "--length", str(capacity.STORAGE_BYTES), "--",
                       str(image)], 60)
            events.append("mounted")
            return {"pid":5}, 15, 12

        model.setup = setup

        @contextmanager
        def workspace(path, device, inode, mount):
            events.append(("workspace", path, device, inode, mount))
            yield path
            events.append("workspace-reread")

        def transfer(**paths):
            events.append(("transfer", paths))
            return dict(status="ACQUIRED_QT_RUNNER_INPUT_BYTES_ONLY", selection_sha256="a"*64,
                        GPG="NOT_RUN", Root_acceptance=None)

        def bind(*args):
            events.append(("bind", args))
            return dict(status="BOUND_RUNNER_SOURCE_DATA_ONLY", base_roles=517, packages=7, GPG="NOT_RUN")

        inputs = SimpleNamespace(owned_workspace=workspace, bind_inputs=bind)
        info = output.stat()
        original_lstat = Path.lstat

        def model_file(path):
            row = original_lstat(path)
            if path != image:
                return row
            fields = ("st_mode", "st_dev", "st_ino", "st_nlink", "st_size", "st_blocks")
            return SimpleNamespace(st_uid=0, **{name:getattr(row,name) for name in fields})

        def census(_):
            events.append("allocation-admission" if image.exists() else "fresh")
            return dict(path=str(output), device=info.st_dev, inode=info.st_ino, mount=6,
                        readonly=False, free_bytes=capacity.MINIMUM_BYTES)

        with patch("os.getuid", return_value=0), patch("os.geteuid", return_value=0), \
                patch.object(capacity, "observe", side_effect=census), patch.object(Path, "lstat", model_file), \
                patch.object(capacity, "require_after", side_effect=lambda *_: events.append("after") or {}), \
                patch.object(capacity, "require_transfer_volume", return_value={"volume":{
                    "device":2, "inode":5, "mount":7}}), \
                patch.object(launch, "retire_transfer_duplicates",
                             side_effect=lambda *_: events.append("retire-duplicates") or {"files":35}), \
                patch.object(launch, "expose_readonly_tree") as expose, patch.object(Path, "chmod"):
            result = launch.reserve_and_bind(model, inputs, transfer, selection_sha256="a"*64,
                                             logical_bytes=180, stage=stages.append)
        self.assertEqual([e[0] if isinstance(e, tuple) else e for e in events],
                         ["fresh", "exclusive-create", "allocation-admission", "allocate", "after", "mounted",
                          "workspace", "transfer", "bind", "retire-duplicates", "workspace-reread"])
        self.assertEqual(stages, ["STORAGE_FRESHNESS", "OWNED_HOST_SETUP", "STORAGE_ALLOCATION_ADMISSION",
                                  "STORAGE_ALLOCATION", "STORAGE_ALLOCATION_READBACK", "OWNED_HOST_SETUP",
                                  "OWNED_VOLUME_JOIN", "INPUT_ACQUISITION", "INPUT_BINDING", "INPUT_TRANSFER_RETIREMENT", "INPUT_EXPOSURE"])
        self.assertEqual(events[6], ("workspace", output/"volume", 2, 5, 7))
        self.assertEqual(events[7][1], dict(owned_workspace=output/"volume", device=2, inode=5, mount_id=7,
                                             portable=output/"volume/work/portable", output=output/"volume/work/acquired"))
        self.assertEqual(events[8][1], (output/"volume/work/portable", "a"*64, output/"volume/work/acquired/operands",
                         output/"volume/work/acquired/framework", output/"volume/work/bound", output/"volume"))
        self.assertEqual(result["source"], output/"volume/work/bound/Source-DATA")
        self.assertEqual([c.args[0] for c in expose.call_args_list],
                         [result["source"], result["operands"], output/"volume/work/acquired/trust"])

    def test_rejects_weakened_host_policy_before_any_setup(self):
        model = SimpleNamespace(out="/owned", setup=Mock(), policy={"minimum_disk_bytes":0})
        stage = Mock()
        with patch("os.getuid", return_value=0), patch("os.geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "Unchanged native"):
                launch.reserve_and_bind(model, None, None, selection_sha256="a"*64, logical_bytes=180, stage=stage)
        model.setup.assert_not_called()
        stage.assert_not_called()


class Signed349AssemblyFailureTests(unittest.TestCase):
    def test_exact_owned_cleanup_after_create_start_and_commit_failures(self):
        adapter = launch.signed349_bind
        fixture = (HERE.parent/"llhttp-minimal-native-source-data/fixtures/Source95/held-source/scripts/ci"
                   /"llhttp-reference-native-source/base/runtime/reference_controller.py")
        self.assertEqual(sha256(fixture.read_bytes()).hexdigest(),
                         "e7c8935f342d4b36bb6f8f24c0b48c3b8aa04be9807f62c3f8141aeaf26819fc")
        owner = executor.load(fixture, "qt612_cleanup_retained_owner")
        installer = "4"*64
        label = adapter.IMAGE_LABEL
        for failed, expected in (("create", ["create", "remove"]),
                                 ("start", ["create", "start", "force"]),
                                 ("commit", ["create", "start", "commit", "remove"]),
                                 ("commit-after-effect", ["create", "start", "commit", "remove", "retire-image"])):
            with self.subTest(stage=failed), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                plan = adapter.Plan(out/"context", out/"iid", out/"cid", BASE, "private:"+NONCE,
                                    "signed349-"+NONCE, NONCE, "fixture only")
                state = SimpleNamespace(container=None, image=None, cleaning=False)
                actions = []
                absent = {"scoped": 0, "all": 0, "images": 0}
                import_cleanup = Mock()

                @contextmanager
                def retirement():
                    self.assertFalse(state.cleaning)
                    state.cleaning = True
                    try:
                        yield
                    finally:
                        state.cleaning = False

                def run(argv, cap, *, check=True):
                    self.assertEqual(argv[0], adapter.DOCKER)
                    if argv == plan.create():
                        actions.append("create")
                        state.container = "created"
                        if failed != "create":
                            plan.cidfile.write_text(installer+"\n")
                        status = int(failed == "create")
                        body = b"" if status else (installer+"\n").encode()
                    elif argv[1:] == ["container", "start", "--attach", installer]:
                        actions.append("start")
                        state.container = "running" if failed == "start" else "exited"
                        status, body = int(failed == "start"), b""
                    elif argv == plan.commit(installer):
                        self.assertEqual(state.container, "exited")
                        actions.append("commit")
                        # The daemon may commit before the client loses the reply.
                        if failed == "commit-after-effect":
                            state.image = STAGE
                            raise ValueError("natural owned command retirement required")
                        status, body = 1, b""
                    elif argv[1:3] == ["container", "ls"]:
                        scoped = "--filter" in argv
                        if state.container is None:
                            absent["scoped" if scoped else "all"] += 1
                        body = (installer+" "+plan.name+"\n").encode() if state.container else b""
                        status = 0
                    elif argv[1:] == ["container", "inspect", installer]:
                        host = dict(NetworkMode="none", CgroupnsMode="private", ReadonlyRootfs=False,
                                    Privileged=False, RestartPolicy={"Name":"no"}, CapDrop=["ALL"],
                                    CapAdd=list(adapter.CAPS), SecurityOpt=["no-new-privileges"],
                                    Memory=adapter.MEMORY, MemorySwap=adapter.MEMORY, NanoCpus=2*10**9,
                                    PidsLimit=256)
                        config = dict(Labels={adapter.BASE_LABEL:NONCE}, User="0:0", WorkingDir="/",
                                      Cmd=["/bin/sh", "-ec", plan.command])
                        mount = dict(Type="bind", Source=str(plan.context), Destination="/mnt", RW=False,
                                     Propagation="rprivate")
                        status, body = 0, json.dumps([dict(Id=installer, Name="/"+plan.name, Image=BASE,
                            Config=config, HostConfig=host, Mounts=[mount], State=dict(Status=state.container,
                            ExitCode=0, Running=state.container=="running", OOMKilled=False, Error=""))]).encode()
                    elif argv[1:3] == ["container", "rm"]:
                        self.assertTrue(state.cleaning)
                        flags = ["--force"] if state.container=="running" else []
                        self.assertEqual(argv[3:], flags+[installer])
                        actions.append("force" if flags else "remove")
                        state.container = None
                        status, body = 0, b""
                    elif argv[1:3] == ["image", "ls"]:
                        self.assertEqual(argv[-1], "label="+label+"="+NONCE)
                        if state.image is None:
                            absent["images"] += 1
                        status, body = 0, ((state.image+"\n").encode() if state.image else b"")
                    elif argv[1:] == ["image", "inspect", STAGE]:
                        self.assertIsNone(state.container)
                        status, body = 0, json.dumps([dict(Id=STAGE, Config={"Labels":{label:NONCE}},
                                                          RepoTags=[plan.tag])]).encode()
                    elif argv[1:] == ["image", "rm", STAGE]:
                        self.assertIsNone(state.container)
                        actions.append("retire-image")
                        state.image = None
                        status, body = 0, b""
                    else:
                        self.fail(f"Unexpected MODEL Docker command {argv}")
                    return subprocess.CompletedProcess(argv, status, body, b"no space left on device" if status else b"")

                baseline = launch.SignedBase(pipeline=SimpleNamespace(C=None), entry=SimpleNamespace(LABEL=label),
                    carrier=None, rootfs=SimpleNamespace(ROOTFS_DIFF_ID=BASE), native=None, container_runtime=owner,
                    runner=run, source=None, source_map_sha256=None, output=out, nonce=NONCE)
                baseline.imported = SimpleNamespace(submitted=True, labels={adapter.BASE_LABEL:NONCE},
                                                    image=BASE, cleanup=import_cleanup)
                baseline.tag = plan.tag
                supervisor, dependencies = Mock(), Mock()
                stages = []
                reason = ("IMAGE_BUILD_RETIREMENT" if failed == "commit-after-effect"
                          else "IMAGE_BUILD_NO_SPACE")
                temp = out/"tmp"
                temp.mkdir()
                pinned = dict(bytes=1, sha256="5"*64)
                cert = out/"TEST-not-executed"
                prepared = dict(work=out, source=out/"unopened-MODEL-source",
                                input_test_certificate=cert, acquisition={"md4c_public_certificate":pinned},
                                input_receipt={"new_source_map":pinned})

                def construct(stage):
                    adapter.assemble(baseline, [], 1800, out=out, handoff=None, stage=stage,
                                     classify=launch.signed349_build_reason, retirement=retirement)

                with (patch.object(baseline, "construct", side_effect=construct),
                      patch.object(launch, "SignedBase", return_value=baseline),
                      patch.object(launch, "SignedDependencies", return_value=dependencies),
                      patch.object(launch, "scoped_runner", return_value=run),
                      patch.object(adapter, "make_plan", return_value=plan),
                      patch.object(adapter, "read_metadata", return_value=b"MODEL"),
                      patch.object(adapter, "audit_context", return_value=b"MODEL"),
                      patch.object(subprocess, "Popen", side_effect=AssertionError("MODEL cannot start a process")),
                      patch.dict(os.environ)):
                    with self.assertRaises(BaseExceptionGroup) as failure:
                        launch.run_owned_payload(pipeline=SimpleNamespace(POLICY={}), family_source=None,
                            bootstrap={}, supervisor=supervisor, commands=None, prepared=prepared,
                            socket=out/"unopened-MODEL-socket", nonce=NONCE,
                            auth={"certificate":dict(pinned,path=str(cert))}, stage_mode="pair-only",
                            stage=stages.append)
                    self.assertEqual([str(error) for error in failure.exception.exceptions], [reason])
                    self.assertIsNone(state.container)
                    self.assertGreaterEqual(absent["scoped"], 3)  # Before create and twice after removal.
                    self.assertFalse(plan.iidfile.exists())
                    dependencies.construct.assert_not_called()
                    dependencies.retire.assert_called_once_with()
                    supervisor.retain_owner_evidence.assert_called_once_with(work=out, commands=None)
                self.assertEqual(actions, expected)
                self.assertIsNone(state.image)
                self.assertGreaterEqual(absent["all"], 2)
                self.assertGreaterEqual(absent["images"], 2)
                self.assertEqual(stages, ["SIGNED349_BUILD", "SIGNED349_IMAGE_BUILD"])
                import_cleanup.assert_called_once_with()


class SignedDependenciesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.pipeline = executor.load(HERE.parent/"qt612-complete-family-native-source/pipeline.py",
                                      "qt612_hosted_test_family_pipeline")
        C = self.pipeline.C
        deps = {}
        for name in ("double-conversion", "libb2", "libice", "libsm", "md4c", "xcb-util-cursor", "xdg-utils"):
            deps[name] = {"filename":name+"-0.5.3-1-aarch64.pkg.tar.xz", "version":"0.5.3"}
        plan = C.P.dependency_image_plan(BASE, {"files":517, "inventory":{i:i for i in range(349)}},
                {"complete":True, "packages":dict(deps,md4c=dict(deps["md4c"],version="0.5.3-1"))},
                builder_uid=os.getuid(), builder_gid=os.getgid())
        refs = {}
        for name in plan["archives"]:
            for suffix in ("", ".sig"):
                refs[name+suffix] = self.file(name+suffix, (name+suffix).encode())
        self.inventory = "".join(f"p{i:03} 1-1\n" for i in range(356)).encode()
        self.plan = dict(plan, signed_context=refs, expected_inventory=self.inventory.decode(),
                         inventory_pin=C.pin(self.inventory))
        md4c = deps["md4c"]["filename"]
        key = self.file("test.gpg", b"opaque inert fixture")
        self.auth = dict(certificate=key, fingerprint=FINGERPRINT, expires_epoch=int(time.time())+600,
                         archive=C.pin(Path(refs[md4c]["path"]).read_bytes()),
                         signature=C.pin(Path(refs[md4c+".sig"]["path"]).read_bytes()), root_evidence={})
        self.checked = Mock()
        self.rows = []
        self.built = self.removed = False
        self.inventory_probe = self.inventory
        self.runtime = launch.SignedDependencies(SimpleNamespace(C=C, builder_image_plan=lambda **_: self.plan),
                                                   self.runner, NONCE, self.root/"signed356")

    def file(self, name, body):
        path = self.root/name
        path.write_bytes(body)
        return dict(path=str(path), **self.pipeline.C.pin(body))

    def runner(self, argv, seconds):
        self.rows.append((argv, seconds))
        args = argv[1:]
        body = b""
        if args[0] == "build":
            self.built = True
            Path(args[args.index("--iidfile")+1]).write_text(STAGE+"\n")
        if args[:2] == ["image", "inspect"]:
            body = json.dumps([dict(Id=STAGE, Architecture="arm64", Os="linux", RepoTags=[self.runtime.tag],
                Config=dict(User=f"{os.getuid()}:{os.getgid()}", Labels={executor.LABEL:NONCE}))]).encode()
        if args[:2] == ["image", "ls"] and self.built and not self.removed:
            body = STAGE.encode()+b"\n"
        if args[0] == "run":
            body = self.inventory_probe
        if args[:2] == ["image", "rm"]:
            self.removed = True
        return subprocess.CompletedProcess(argv, 0, body, b"")

    def construct(self):
        actual = dict(image=BASE, input_count=517, official_signature_count=257, shell={"status":"SHELL_PASS"})
        return self.runtime.construct(source=self.root/"Source-DATA", source_map_sha256="d"*64, baseline=actual,
                                      auth=self.auth, authenticate=self.checked)

    def test_builds_from_exact_local_image_then_reopens_356(self):
        result = self.construct()
        self.assertEqual(result["image"], STAGE)
        self.checked.assert_called_once_with(self.auth)
        recipe = (self.root/"signed356/context/Dockerfile").read_text()
        self.assertTrue(recipe.startswith("FROM "+BASE.removeprefix("sha256:")+"\n"))
        self.assertIn(" --lsign-key "+FINGERPRINT+" &&", recipe)
        self.assertIn(" --populate archlinuxarm ", recipe)
        self.assertIn("pacman --config /qt612.pacman.conf -U", recipe)
        config = (self.root/"signed356/context/qt612.pacman.conf").read_text()
        self.assertIn("SigLevel = Required TrustedOnly\n", config)
        self.assertIn("GPGDir = "+launch.GPGDIR+"\n", config)
        argv, seconds = next((argv, seconds) for argv, seconds in self.rows if argv[1] == "build")
        self.assertIn("--pull=false", argv)
        self.assertIn("--network=none", argv)
        self.assertEqual(seconds, 600)
        self.runtime.retire()
        self.assertIn(([executor.DOCKER,"image","rm",STAGE],30), self.rows)

    def test_wrong_signed_md4c_or_stale_key_stops_before_docker(self):
        old = self.auth["archive"]
        self.auth["archive"] = {}
        with self.assertRaisesRegex(ValueError, "exact TEST md4c"):
            self.construct()
        self.runtime.retire()
        self.auth["archive"] = old
        self.auth["expires_epoch"] = 1
        with self.assertRaisesRegex(ValueError, "Current selected TEST signer"):
            self.construct()
        self.assertEqual(self.rows, [])

    def test_actual_ordinary_inventory_must_be_exact(self):
        self.inventory_probe = self.inventory.replace(b"p000 1-1", b"p000 2-1", 1)
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.construct()
        self.runtime.retire()
        self.assertTrue(self.removed)


if __name__ == "__main__":
    unittest.main()
