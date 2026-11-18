# SPDX-License-Identifier: MIT

from contextlib import ExitStack
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("upgrade", HERE / "upgrade.py")
U = importlib.util.module_from_spec(spec)
spec.loader.exec_module(U)

controller_spec = importlib.util.spec_from_file_location(
    "overlay583_controller", HERE.parent / "overlay583_trial/controller.py"
)
C = importlib.util.module_from_spec(controller_spec)
controller_spec.loader.exec_module(C)

NONCE = "1" * 32
LOG = (
    b"[2026-11-17T23:00:00+0000] [ALPM] installed cachy-asahi-setup (0.1.0-7)\n"
    b"[2026-11-17T23:01:00+0000] [ALPM] upgraded cachy-asahi-setup (0.1.0-7 -> 0.3.0-1)\n"
)


class Upgrade(unittest.TestCase):
    def setUp(self):
        area = tempfile.TemporaryDirectory(prefix="overlay583-upgrade-fixture-")
        self.addCleanup(area.cleanup)
        self.root = Path(area.name)
        self.lock = "".join(sorted([f"{U.PACKAGE} {U.NEW}\n",
                                    *(f"package-{n:03d} 1-1\n" for n in range(582))])).encode("ascii")
        self.log = b"".join(
            f"[2026-11-17T22:59:00+0000] [ALPM] installed package-{n:03d} (1-1)\n".encode()
            for n in range(582)
        ) + LOG
        self.before = self.lock.replace(f"{U.PACKAGE} {U.NEW}\n".encode(),f"{U.PACKAGE} {U.OLD}\n".encode())
        names = U.T.canonical_lock(self.lock,583)
        rows = {name:dict(repo=U.T.BASE_REPO,version=version) for name,version in names.items()}
        rows[U.PACKAGE]["repo"] = U.T.OVERLAY_REPO
        successor = U.T.REPOS[U.T.OVERLAY_REPO] + f"/{U.PACKAGE}-{U.NEW}-any.pkg.tar.xz"
        self.packet = dict(preflight={"test":True},target=U.T.pin(self.lock),packages=rows,
                           files={successor:U.SUCCESSOR},signers=["A"*40,"B"*40,"C"*40])
        self.staging = self.root / U.PREDECESSOR
        self.staging.mkdir()
        for name in (U.ARCHIVE,U.SIGNATURE,U.PUBLIC):
            (self.staging/name).write_bytes(name.encode("ascii"))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(U,"PREVIOUS",U.T.pin(U.ARCHIVE.encode("ascii"))))
        self.stack.enter_context(patch.object(U,"TARGET",U.T.pin(self.lock)))
        raw = U.T.encoded(U.staged_tree(self.staging,"D"*40,U.ARTIFACT))
        (self.staging/U.RECEIPT).write_bytes(raw)
        self.predecessor = U.check_stage(self.staging,U.T.pin(raw))

    def test_one_changed_version_and_distinct_old_and_new_pacman_operands(self):
        value = U.plan(self.packet,self.lock,self.predecessor,NONCE)
        expected = U.expected_output(value,self.lock)
        self.assertEqual(len(expected["query-without-setup"][0].splitlines()),582)
        self.assertEqual(expected["query-before"][0],self.before)
        self.assertEqual(expected["query-after"][0],self.lock)
        argv = {role:args for role,args,_ in value["operations"]}
        self.assertNotIn(U.T.OVERLAY_REPO+"/"+U.PACKAGE,argv["install-base-and-shells"])
        self.assertEqual(argv["install-predecessor"][-1],str(U.T.IN/U.PREDECESSOR/U.ARCHIVE))
        self.assertEqual(argv["upgrade"][-1],U.T.OVERLAY_REPO+"/"+U.PACKAGE)
        self.assertEqual(argv["upgrade"][argv["upgrade"].index("--cachedir")+1],str(U.CACHE))
        self.assertTrue(all(flag not in argv["upgrade"] for flag in ("--nodeps","--overwrite","--assume-installed")))

    def test_wrong_current_version_archive_nonselected_row_or_reused_trust_fails(self):
        for invalid in (
            dict(self.packet,files={}),
            dict(self.packet,signers=[self.predecessor["signer"],*self.packet["signers"][1:]]),
            dict(self.packet,packages=self.packet["packages"] | {"package-000":{"version":"9-1","repo":U.T.BASE_REPO}}),
        ):
            with self.subTest(invalid=invalid.keys()), self.assertRaises(ValueError):
                U.plan(invalid,self.lock,self.predecessor,NONCE)

    def test_mutated_signature_or_external_receipt_pin_refused(self):
        pin = self.predecessor["receipt"]
        with self.assertRaises(ValueError):
            U.check_stage(self.staging,dict(pin,sha256="0"*64))
        (self.staging/U.SIGNATURE).write_bytes(b"x" * (self.staging/U.SIGNATURE).stat().st_size)
        with self.assertRaises(ValueError):
            U.check_stage(self.staging,pin)

    def test_stage_refuses_wrong_artifact_and_existing_output(self):
        bad = self.root/"bad.zip"
        bad.write_bytes(b"wrong original")
        with self.assertRaises(ValueError):
            U.stage(bad,self.root/"fresh")
        self.assertFalse((self.root/"fresh").exists())
        with patch.object(U,"previous_archive",return_value=b"unused"), self.assertRaises(FileExistsError):
            U.stage(bad,self.staging)

    def test_real_alpm_messages_require_exact_single_version_change(self):
        U.confirm_transaction(self.log,self.before)
        for body in (self.log.replace(b"upgraded",b"downgraded"), self.log.rsplit(b"\n",2)[0]+b"\n",
                     self.log+LOG, self.log+b"[x] [ALPM] reinstalled cachy-asahi-setup (0.3.0-1)\n",
                     self.log.replace(b"0.1.0-7 ->",b"0.1.0-6 ->"),
                     self.log.replace(b"installed package-000",b"downgraded package-000")):
            with self.assertRaises(ValueError):
                U.confirm_transaction(body,self.before)

    def test_host_refusal_precedes_command_or_write(self):
        value = U.plan(self.packet,self.lock,self.predecessor,NONCE)
        with patch.object(U.os,"sysconf",return_value=4096), self.assertRaises(ValueError):
            U.execute(value,self.lock,lambda *args:self.fail("actor called"),{},b"")

    def evidence(self):
        value = U.plan(self.packet,self.lock,self.predecessor,NONCE)
        out = self.root / "evidence"
        out.mkdir()
        for name in U.evidence_names(value):
            (out/name).touch()
        for role,(body,snapshot) in U.expected_output(value,self.lock).items():
            (out/(role+".stdout")).write_bytes(body)
            if snapshot:
                (out/snapshot).write_bytes(body)
        (out/"pacman.log").write_bytes(self.log)
        gpg = ["/usr/bin/gpg","--batch","--no-options"]
        trust = [(f"import-{idx}",[*gpg,"--import"]) for idx in range(3)]
        trust += [("ownertrust",[*gpg,"--import-ownertrust"]),("import-predecessor",[*gpg,"--import"]),
                  ("trust-predecessor",[*gpg,"--import-ownertrust"])]
        commands = [dict(role=role,argv=args,exit=0)
                    for role,args in trust+[(role,args) for role,args,_ in value["operations"]]]
        (out/"result.json").write_bytes(U.T.encoded(dict(
            status="PASS_DISPOSABLE_OVERLAY583_SETUP_UPGRADE_ONLY",nonce=NONCE,
            plan=U.T.pin(U.T.encoded(value)),installed_lock=U.TARGET,Root_acceptance=None,commands=commands
        )))
        return out, value

    def test_independent_reader_rejects_snapshot_drift_and_failed_hook(self):
        out, value = self.evidence()
        self.assertEqual(set(U.readback(out,value,self.lock)),U.evidence_names(value))
        stderr = out/"upgrade.stderr"
        stderr.write_bytes(b"error: command failed to execute\n")
        with self.assertRaises(ValueError):
            U.readback(out,value,self.lock)
        stderr.write_bytes(b"")
        (out/"before-upgrade.lock").write_bytes(self.lock)
        with self.assertRaises(ValueError):
            U.readback(out,value,self.lock)

    def test_independent_reader_rejects_missing_logs_and_unexpected_operand(self):
        out,value = self.evidence()
        (out/"upgrade.stdout").unlink()
        with self.assertRaises(ValueError):
            U.readback(out,value,self.lock)
        (out/"upgrade.stdout").touch()
        (out/"late-operand").touch()
        with self.assertRaises(ValueError):
            U.readback(out,value,self.lock)


    def test_controller_packs_only_the_selected_predecessor_and_worker(self):
        staging = self.root/"staging"
        staging.mkdir()
        worker = self.root/"worker.py"
        worker.write_bytes(b"worker")
        (staging/"target.lock").write_bytes(self.lock)
        packet = dict(self.packet, aliases={},trust={})
        for path in packet["files"]:
            destination = staging/path
            destination.parent.mkdir(parents=True)
            destination.write_bytes(b"mock successor")
        with patch.object(C.T,"upgrade_module",return_value=U), \
             patch.object(C,"runtime_payload",return_value={}), \
             patch.object(U,"SUCCESSOR",U.T.pin(b"mock successor")):
            for name in packet["files"]:
                packet["files"][name] = U.SUCCESSOR
            value = C.T.selected_plan(packet,NONCE,predecessor=self.staging,predecessor_pin=self.predecessor["receipt"])
            with self.assertRaises(ValueError):
                C.T.selected_plan(packet,NONCE,signature_recovery=True,predecessor=self.staging,
                                  predecessor_pin=self.predecessor["receipt"])
            files,_,_ = C.input_tree(staging,worker,U.T.pin(b"worker"),U.T.encoded(value),
                                     self.root/"packed",predecessor=self.staging)
            prefix = "inputs/"+U.PREDECESSOR+"/"
            self.assertEqual({name for name in files if name.startswith(prefix)},
                             {prefix+name for name in (U.ARCHIVE,U.SIGNATURE,U.PUBLIC,U.RECEIPT)})
            self.assertEqual(files["code/upgrade.py"],value["upgrade_worker"])
            (self.staging/U.SIGNATURE).unlink()
            with self.assertRaises(ValueError):
                C.input_tree(staging,worker,U.T.pin(b"worker"),U.T.encoded(value),
                             self.root/"bad",predecessor=self.staging)

    def test_guest_route_holds_native_upgrade_failure_without_relabeling(self):
        trial = C.T
        work = self.root/"work"
        work.mkdir()
        for relative in trial.GPG_PATHS:
            path = self.root/relative
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b"synthetic public key")
        packet = dict(self.packet,trust={name:U.T.pin(b"synthetic public key") for name in trial.GPG_PATHS})
        chosen = U.plan(packet,self.lock,self.predecessor,NONCE)
        def refuse(*args):
            raise ValueError("modeled upgrade refused")

        fail = SimpleNamespace(execute=refuse,PASS=U.PASS)
        with patch.multiple(trial,WORK=work,OUTPUT=work/"evidence",CONFIG=work/"config",TARGET=work/"target",IN=self.root), \
             patch.object(trial.subprocess,"run",return_value=SimpleNamespace(returncode=0)):
            code = trial.execute_guest(chosen,self.lock,{},trial.time.monotonic()+10,upgrade=fail)
            self.assertEqual(code,trial.LIFECYCLE_HOLD_EXIT)
            raw = (work/"evidence/result.json").read_bytes()
            self.assertEqual(U.T.decode(raw)["status"],U.HOLD)
            with patch.object(trial,"upgrade_module",return_value=U):
                report = trial.read_result(work/"evidence",chosen,held=True)
        self.assertEqual(report["phase"],"upgrade-setup")
        self.assertIsNone(report["installed_lock"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
