# SPDX-License-Identifier: MIT
"""Inert source and receipt controls for the disposable install adapter."""

import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in ("os.system", "os.exec", "os.fork", "os.posix_spawn"):
        raise AssertionError("Test fixtures cannot start actors")


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("overlay583_trial",HERE/"trial.py")
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


def model_inputs():
    packages = {f"model-{i:03d}":dict(version="1-1",repo=T.BASE_REPO if i<574 else T.OVERLAY_REPO) for i in range(583)}
    raw = "".join(f"{name} 1-1\n" for name in packages).encode()
    fake = T.pin(b"inert fixture")
    packet = dict(target=T.pin(raw),packages=packages,kit=fake,release=fake,base_lock=fake,
                  base_receipt=fake,signers=["A"*40,"B"*40,"C"*40],release_declares_synthetic_fixture=True,preflight=None)
    receipt = dict(status="verified-offline-install-preflight",base_archives_authenticated=True,
                   base_rootfs_authenticated=True,synthetic=True,pacman_siglevel="Required TrustedOnly",
                   packages_installed=False,transaction_authorized=False,kit_sha256=fake["sha256"],
                   release_sha256=fake["sha256"],target_lock_sha256=packet["target"]["sha256"],
                   base_lock_sha256=fake["sha256"],base_receipt_sha256=fake["sha256"],base_signer="B"*40,
                   base_package_signer="C"*40,target_package_count=583,base_package_count=574,
                   overlay_package_count=9,pacman_plan_sha256=T.pin(T.pacman_plan(packet))["sha256"],
                   signer=dict(primary_fingerprint="A"*40))
    packet["authenticated_preflight"] = T.pin(T.encoded(receipt))
    return packet,receipt,raw


class Trial(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="overlay583-MODEL-")
        self.addCleanup(scratch.cleanup)
        self.out = Path(scratch.name)
        self.packet,self.receipt,self.raw = model_inputs()

    def plan(self):
        raw = T.encoded(self.receipt)
        admitted = T.admit(self.packet,raw,T.pin(raw))
        return T.guest_plan(admitted,"1"*32)

    def test_plan_keeps_normal_pacman_transaction_and_pinned_origins(self):
        plan=self.plan()
        self.assertEqual([row[0] for row in plan["operations"]],["refresh","resolve","install","query","check"])
        install=plan["operations"][2][1]
        self.assertEqual(len(install[install.index("--")+1:]),583)
        self.assertTrue(install[-1].startswith(T.OVERLAY_REPO+"/"))
        for argv in (row[1] for row in plan["operations"]):
            self.assertNotIn("--nodeps",argv)
            self.assertNotIn("--overwrite",argv)
            self.assertNotIn("--sysupgrade",argv)
            self.assertEqual(argv[argv.index("--root")+1], str(T.TARGET))
            self.assertEqual(argv[argv.index("--gpgdir")+1],str(T.WORK/"trust"))

    def test_reject_preflight_plan_and_signer_drift_even_when_repinned(self):
        for field in ("pacman_plan_sha256","base_package_signer","base_receipt_sha256"):
            changed=dict(self.receipt,**{field:"0"*64})
            raw=T.encoded(changed)
            with self.assertRaisesRegex(ValueError,field):
                T.admit(dict(self.packet,authenticated_preflight=T.pin(raw)),raw,T.pin(raw))

    def test_refuses_unissued_preflight_or_wrong_raw_receipt_pin(self):
        with self.assertRaises(ValueError):
            T.guest_plan(self.packet,"1"*32)
        with self.assertRaises(ValueError):
            T.admit(self.packet,T.encoded(self.receipt),T.pin(b"wrong bytes"))

    def fill_output(self,plan):
        gpg=["/usr/bin/gpg","--batch","--no-options"]
        commands=[("import-"+str(i),[*gpg,"--import"]) for i in range(3)]
        commands += [("ownertrust",[*gpg,"--import-ownertrust"])]
        commands += [(role,argv) for role,argv,_ in plan["operations"]]
        for role,_ in commands:
            (self.out/(role+".stdout")).write_bytes(b"")
            (self.out/(role+".stderr")).write_bytes(b"")
        (self.out/"installed.lock").write_bytes(self.raw)
        (self.out/"query.stdout").write_bytes(self.raw)
        (self.out/"resolve.stdout").write_bytes(T.pacman_plan(plan["packet"]))
        (self.out/"pacman.log").write_bytes(b"MODEL transaction log\n")
        (self.out/"result.json").write_bytes(T.encoded(dict(status="PASS_DISPOSABLE_PACMAN_TRANSACTION_ONLY",
            nonce=plan["nonce"],plan=T.pin(T.encoded(plan)),installed_lock=plan["packet"]["target"],
            commands=[dict(role=role,argv=argv,exit=0) for role,argv in commands],Root_acceptance=None)))

    def test_reader_joins_current_bytes_and_refuses_same_count_wrong_version(self):
        plan=self.plan();self.fill_output(plan)
        result=T.read_result(self.out,plan)
        self.assertEqual(result["package_count"],583)
        self.assertIsNone(result["Root_acceptance"])
        (self.out/"query.stdout").write_bytes(self.raw.replace(b"model-006 1-1",b"model-006 1-2"))
        with self.assertRaisesRegex(ValueError,"Original pacman plan or installed inventory differs"):
            T.read_result(self.out,plan)

    def test_reader_rejects_extra_files_and_stale_disposable_nonce(self):
        plan=self.plan();self.fill_output(plan)
        with self.assertRaisesRegex(ValueError,"Unbound guest"):
            T.read_result(self.out,dict(plan,nonce="2"*32))
        (self.out/"alien").write_bytes(b"inert")
        with self.assertRaisesRegex(ValueError,"extra guest evidence"):
            T.read_result(self.out,plan)

    def test_repository_alias_cannot_redirect(self):
        for repo in T.REPOS.values():
            (self.out/repo).mkdir(parents=True)
        key=T.BASE+"/repo/test.db"
        path=self.out/key;path.symlink_to("test.db.tar.gz")
        T.check_repos(self.out,{}, {key:"test.db.tar.gz"})
        path.unlink();path.symlink_to("../foreign")
        with self.assertRaisesRegex(ValueError,"Repository alias differs"):
            T.check_repos(self.out,{}, {key:"test.db.tar.gz"})

    def test_guest_gate_requires_live_selected_mount(self):
        T.mount_mode("/trial-inputs","ro",["66 41 0:99 / /trial-inputs ro - ext4 /dev/vdx ro"])
        with self.assertRaises(ValueError):
            T.mount_mode("/trial-inputs","ro",["66 41 0:99 / /trial-inputs rw - ext4 /dev/vdx rw"])

    def test_owned_process_bridge_requires_owned_natural_exit(self):
        events=[]
        def supervise(child,**kw):
            self.assertEqual(child,"MODEL child")
            self.assertEqual(kw["cap"],T.TIMEOUT)
            events.append("supervise")
            return dict(passed=True,reaped=True,ownership="REAPED",group_census="EMPTY_TWICE",
                        signals=[],timeout=False,exit=0,output_complete=True)
        actor=SimpleNamespace(prepare=lambda:events.append("prepare"),supervise=supervise)
        def launch(**_request):
            events.append("launch")
            return "MODEL child"
        def export(_observation):
            events.append("export")
            return self.out
        vm=T.OwnedVMAdapter(actor,authenticate=None,launch=launch,export=export,absent_twice=None)
        result=vm.run_guest(timeout=T.TIMEOUT)
        self.assertEqual(events,["prepare","launch","supervise","export"])
        self.assertEqual(result["evidence"],self.out)
        actor.supervise=lambda *_a,**_kw:dict(passed=True,reaped=False)
        with self.assertRaises(ValueError):
            vm.run_guest(timeout=T.TIMEOUT)
        self.assertEqual(events.count("export"),1)

    def test_owned_handoff_authenticates_before_launch_and_confirms_retirement(self):
        receipt = self.out/"preflight.json"
        receipt.write_bytes(T.encoded(self.receipt))
        evidence = self.out/"readback"
        evidence.mkdir()
        nonce = "1"*32
        events = []

        def authenticate(selection, **binding):
            self.assertEqual(selection, "MODEL authority")
            self.assertEqual(binding["nonce"], nonce)
            self.assertEqual(binding["plan_sha256"], T.pin(T.encoded(self.plan()))["sha256"])
            events.append("authenticate")

        def run_guest(**request):
            self.assertEqual(request["staging"], self.out)
            self.assertEqual(request["kernel_argument"], "cachy_overlay583_nonce="+nonce)
            self.assertEqual(request["argv"][-2], T.pin(request["plan"])["sha256"])
            self.assertEqual(request["argv"][-1], request["worker_pin"]["sha256"])
            events.append("launch")
            return dict(exit=0,natural=True,reaped=True,output_complete=True,evidence=evidence)

        def check_absence(check_nonce):
            self.assertEqual(check_nonce, nonce)
            events.append("retired")

        owner = SimpleNamespace(API=T.OwnedVMAdapter.API,authenticate=authenticate,
                                run_guest=run_guest,require_absent_twice=check_absence)
        args = dict(staging=self.out,preflight=receipt,preflight_pin=T.pin(receipt.read_bytes()),
                    nonce=nonce,selection="MODEL authority")
        with patch.object(T,"choose",return_value=self.packet) as select, \
             patch.object(T,"read_result",return_value="MODEL readback") as result:
            self.assertEqual(T.run_owned(owner, **args), "MODEL readback")
            self.assertEqual(events, ["authenticate","launch","retired"])
            self.assertEqual(select.call_count, 2)
            result.assert_called_once_with(evidence, self.plan())
            owner.authenticate = lambda *_args, **_kw: self.fail("authority refused")
            with self.assertRaisesRegex(AssertionError, "authority refused"):
                T.run_owned(owner, **args)
            self.assertEqual(events, ["authenticate","launch","retired"])


if __name__ == "__main__":
    unittest.main()
