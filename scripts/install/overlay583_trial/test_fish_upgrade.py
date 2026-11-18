# SPDX-License-Identifier: MIT
"""Portable Fish selection, readonly media, and held command controls."""

from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_controller as controller_checks
import test_trial as trial_checks

C=controller_checks.C
T=trial_checks.T
G=T.fish_upgrade_module("guest.py")
O=T.fish_upgrade_module("operands.py")
NONCE="8"*32
FPR="29"*20


class FishUpgradeIntegration(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="overlay583-fish-fenced-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.stage=self.root/"fish"
        self.stage.mkdir()
        (self.stage/"supplement.json").write_bytes(b"fixture manifest")
        files={}
        for name,path in T.fish_upgrade_sources().items():
            src=path.read_bytes()
            (self.stage/name).write_bytes(src)
            files[name]=T.pin(src)
        now=int(time.time())
        self.supplement=dict(receipt=T.pin(b"fixture manifest"),files=files,
                             rehearsal=dict(fingerprint=FPR,created=now-30,expires=now+86400))
        self.digest=self.supplement["receipt"]["sha256"]
        self.packet,receipt,self.base=trial_checks.model_inputs()
        self.preflight=T.encoded(receipt)
        self.admitted=T.admit(self.packet,self.preflight,T.pin(self.preflight))
        self.plan=dict(T.guest_plan(self.admitted,NONCE),kind=T.FISH_UPGRADE_KIND,fish_upgrade=self.supplement)
        fence=patch.object(T.subprocess,"Popen",side_effect=AssertionError("No actor in this fixture"))
        fence.start()
        self.addCleanup(fence.stop)

    def bind_args(self):
        paths={name:str(self.root/name) for name in ("staging","preflight","kernel","config","baseline","output")}
        return dict(paths,nonce=NONCE,fish_upgrade=str(self.stage),fish_upgrade_sha256=self.digest)

    def test_ambiguous_or_incomplete_mode_refused_before_supplement_read(self):
        args=self.bind_args()
        with patch.object(C.T,"fish_upgrade_selection") as read:
            for other in (dict(lifecycle=True),dict(signature_recovery=True),
                          dict(predecessor=str(self.root/"prior"),predecessor_sha256="a"*64),
                          dict(first_login=str(self.root/"first"),first_login_sha256="a"*64),
                          dict(llhttp=str(self.root/"llhttp"),llhttp_sha256="a"*64)):
                with self.subTest(other=other), self.assertRaisesRegex(ValueError,"only one"):
                    C.binding(**args,**other)
            with self.assertRaisesRegex(ValueError,"digest required together"):
                C.binding(**dict(args,fish_upgrade_sha256=None))
            read.assert_not_called()
        for other in (dict(first_login={}),dict(llhttp={}),dict(lifecycle=True),dict(signature_recovery=True),
                      dict(predecessor=self.root),dict(predecessor_pin={})):
            with self.subTest(other=other),self.assertRaisesRegex(ValueError,"only one"):
                T.selected_plan(self.admitted,NONCE,fish_upgrade=self.supplement,**other)

    def test_passive_controller_fish_plan_and_source_pin(self):
        args=self.bind_args()
        Path(args["preflight"]).write_bytes(self.preflight)
        with (
            patch.object(C,"pinned"),
            patch.object(C,"tool_pins",return_value={}),
            patch.object(C.T,"choose",return_value=self.packet),
            patch.object(C.T,"fish_upgrade_plan",return_value=self.plan) as plan,
            patch.object(C.T,"fish_upgrade_selection",return_value=self.supplement) as validate,
        ):
            selected=C.binding(**args)
            validate.assert_called_once_with(self.stage,self.digest)
            plan.assert_called_once_with(self.admitted,NONCE,self.supplement)
        self.assertIsNone(selected["issuer"])
        self.assertEqual(selected["fish_upgrade"],self.supplement["receipt"])
        self.assertEqual(selected["plan"],T.pin(T.encoded(self.plan)))
        additions=set(C.source_pins(fish_upgrade=True))-set(C.source_pins())
        self.assertEqual(additions,{"scripts/integration/fish_config_overlay583/"+key for key in self.supplement["files"]})

    def test_pack_places_exact_only_readonly_fish_code(self):
        staging=self.root/"staging"
        staging.mkdir()
        (staging/"target.lock").write_bytes(self.base)
        worker=self.root/"worker"
        worker.write_bytes(b"fixture guest worker")
        packed=self.root/"packed"
        projected=dict(self.plan,packet=dict(self.admitted,files={},trust={},aliases={}))
        with (
            patch.object(C,"runtime_payload",return_value={}),
            patch.object(C.T,"fish_upgrade_selection",return_value=self.supplement) as validate,
        ):
            files,aliases,dirs=C.input_tree(staging,worker,T.pin(worker.read_bytes()),T.encoded(projected),
                                           packed,fish_upgrade=self.stage)
        validate.assert_called_once_with(self.stage,self.digest)
        actual={name.removeprefix("code/fish-upgrade/") for name in files if name.startswith("code/fish-upgrade/")}
        self.assertEqual(actual,set(self.supplement["files"])|{"supplement.json"})
        self.assertEqual({name for name in files if name.startswith("inputs/")},{"inputs/target.lock"})
        self.assertIn("code/fish-upgrade",dirs)
        self.assertEqual(aliases,{})
        for name in actual:
            self.assertEqual((packed/"code/fish-upgrade"/name).stat().st_mode&0o777,0o444)

    def execute(self,failure):
        inputs=self.root/"inputs"
        work=self.root/"work"
        work.mkdir()
        trust={}
        for name in T.GPG_PATHS:
            path=inputs/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(name.encode())
            trust[name]=T.pin(name.encode())
        plan=dict(self.plan,packet=dict(self.admitted,trust=trust,files={},aliases={}))
        output=work/"evidence"
        roles=[]
        def addon(trial,**data):
            for role,argv in G.command_plan(trial,O,T.fish_upgrade_module("probe.py")).items():
                data["command"](role,argv+["--foreign"] if failure=="argv" else argv,30)
            self.fail("Expected a modeled guest refusal")
        shim=SimpleNamespace(command_plan=G.command_plan,run=addon,evidence=G.evidence)
        def command(argv,**kwargs):
            if argv[0]=="/usr/bin/gpgconf":
                return SimpleNamespace(returncode=0)
            role=Path(kwargs["stdout"].name).name.removesuffix(".stdout")
            roles.append(role)
            if role=="resolve":
                kwargs["stdout"].write(T.pacman_plan(plan["packet"]))
            elif role=="query":
                kwargs["stdout"].write(self.base)
            elif role=="install":
                (output/"pacman.log").write_bytes(b"fixture base")
            elif role=="fish-upgrade" and failure=="hook":
                kwargs["stderr"].write(b"error: command failed\n")
            if role=="fish-verify-successor" and failure=="signature":
                kwargs["stderr"].write(b"model signature refusal\n")
                return SimpleNamespace(returncode=7)
            return SimpleNamespace(returncode=0)
        with (
            patch.multiple(T,WORK=work,IN=inputs,TARGET=work/"target",CONFIG=work/"pacman.conf",OUTPUT=output),
            patch.object(T,"check_repos"),patch.object(T,"target_api_mounts"),
            patch.object(T.subprocess,"run",side_effect=command),patch.dict(sys.modules,{T.__name__:T}),
        ):
            code=T.execute_guest(plan,self.base,{},time.monotonic()+15,fish_upgrade=shim)
            result=T.read_result(output,plan,held=True)
            raw=T.decode((output/"fish-upgrade.json").read_bytes())
        return code,result,roles,raw

    def test_signature_failure_holds_before_trust_or_package_command(self):
        code,result,roles,raw=self.execute("signature")
        self.assertEqual(code,T.LIFECYCLE_HOLD_EXIT)
        self.assertEqual((result["status"],result["phase"]),(T.FISH_UPGRADE_HOLD,"fish-verify-successor"))
        self.assertEqual(raw["commands"][-1]["exit"],7)
        self.assertNotIn("fish-trust-test",roles)
        self.assertNotIn("fish-upgrade",roles)

    def test_foreign_arguments_refused_before_any_fish_command(self):
        code,result,roles,raw=self.execute("argv")
        self.assertEqual(code,T.LIFECYCLE_HOLD_EXIT)
        self.assertEqual(result["status"],T.FISH_UPGRADE_HOLD)
        self.assertFalse(any(name.startswith("fish-") for name in roles))
        self.assertEqual(raw["commands"],[])

    def test_failed_upgrade_hook_holds_before_the_next_probe(self):
        code,result,roles,raw=self.execute("hook")
        self.assertEqual(code,T.LIFECYCLE_HOLD_EXIT)
        self.assertEqual((result["status"],result["phase"]),(T.FISH_UPGRADE_HOLD,"fish-upgrade"))
        self.assertEqual(raw["commands"][-1]["role"],"fish-upgrade")
        self.assertNotIn("fish-upgraded",roles)
        self.assertNotIn("fish-restore",roles)

    def test_exact_later_pair_binding_and_held_receipt_refusal_are_portable(self):
        logs=[b"PASS: model Fish CDPATH-independent checks\n"]*2
        archive=T.pin(b"model matching files")
        closure=dict(issuer="Root",native_pair="PASS",source="c"*40,run=123,
              package=O.SUCCESSOR,package_archive=archive,builds=2,build="PASS_BOTH_NATIVE_AARCH64",
              comparison="PASS_BYTE_IDENTICAL",original_custody_pass=True,owned_storage_absent=True,
              controller_empty_twice=True)
        data=dict(kind=O.PAIR_KIND,issuer="Root",status="PASS",source=closure["source"],run=closure["run"],
                  architecture="aarch64",package_architecture="any",closure=T.pin(T.encoded(closure)),
                  builds=[dict(build=i,archive=archive,clean=True,checks="PASS",check_log=T.pin(body))
                          for i,body in enumerate(logs,1)])
        self.assertEqual(O.qualification(T,T.encoded(data),archive,T.encoded(closure),logs),data)
        hold=T.encoded(dict(closure,native_pair="HOLD",required_missing=["original build 2 check"]))
        with self.assertRaisesRegex(ValueError,"Independent closed PASS"):
            O.qualification(T,T.encoded(dict(data,closure=T.pin(hold))),archive,hold,logs)
        with self.assertRaisesRegex(ValueError,"original successful Fish semantic check"):
            O.qualification(T,T.encoded(data),archive,T.encoded(closure),[logs[0],b""])
        with self.assertRaisesRegex(ValueError,"original Fish archives and checks"):
            O.qualification(T,T.encoded(data),archive,T.encoded(closure),[logs[0],logs[1]+b"changed"])


if __name__=="__main__":
    unittest.main(verbosity=2)
