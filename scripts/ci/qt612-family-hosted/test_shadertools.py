# SPDX-License-Identifier: MIT
"""Offline MODELS for the independently owned ShaderTools continuation."""

import os
from pathlib import Path
from subprocess import CompletedProcess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import shadertools as S
P = S.OWNER.load(HERE.parent/"qt612-complete-family-native-source/pipeline.py", "shader_stage_model_pipeline")
L = P.C.local("lifecycle")
BASE, IMAGE = "sha256:"+"1"*64, "sha256:"+"2"*64
NONCE = "3"*32
LAYERS = ["sha256:"+"4"*64, "sha256:"+"5"*64]


def fence(event, _):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.fork", "fcntl.flock")):
        raise AssertionError("Offline ShaderTools controls must not run a native, signer, or network actor")


class ModelCommands:
    def __init__(self, before, after):
        self.rows = []
        self.env = []
        self.before, self.after = before, after
        self.derived_layers = LAYERS

    def __call__(self, argv, seconds, env=None):
        if argv[2:4] == ["image", "inspect"]:
            image = argv[-1]
            layers = LAYERS[:1] if image == BASE else self.derived_layers
            raw = P.C.encoded([dict(Id=image, Architecture="arm64", Os="linux", RootFS=dict(Type="layers", Layers=layers),
                                    Config=dict(Labels={S.OWNER.LABEL: NONCE}))])
        elif argv[2:4] == ["container", "ls"]:
            raw = b""
        elif argv[2] == "run":
            if argv[-1] == "pacman -Q | LC_ALL=C sort":
                raw = self.before if BASE in argv else self.after
            else:
                raw = P.C.encoded(dict(kind="MODEL ShaderTools qualification"))
        else:
            raw = b'{"stage": "MODEL command only"}\n'
        self.env.append(env)
        self.rows.append(dict(argv=argv, retirement=dict(exit=0, reaped=True, ownership="REAPED",
            group_census="EMPTY_TWICE", output_complete=True, signals=[], timeout=False, error=None)))
        return CompletedProcess(argv, 0, raw, b"")


class Controls(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="shadertools-owner-MODEL-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root/"source"
        self.output = self.root/"output"
        self.source.mkdir()
        self.output.mkdir()
        packages = {f"base{i:03}": "1.0-1" for i in range(356)}
        sorted_bytes = lambda rows:"".join(f"{key} {value}\n" for key,value in sorted(rows.items())).encode()
        self.before = sorted_bytes(packages)
        self.gui = P.C.load_lock()["components"]["gui_server"]
        self.shaders = P.C.load_lock()["components"][S.COMPONENT]
        self.after = sorted_bytes(packages | {self.gui["package"]:"6.12.0-1"})
        (self.source/"expected356.lock").write_bytes(self.before)
        self.commands = ModelCommands(self.before, self.after)
        self.supervisor = Mock()
        self.supervisor.authenticate_shadertools_continuation.return_value = True
        self.credential = Mock(API=S.OWNER.CREDENTIAL_API)
        self.seed = dict(image=BASE, inventory=P.C.pin(self.before), signature_policy=S.SIGNATURE_POLICY,
            base_image="sha256:"+"0"*64, md4c_archive=P.C.pin(b"MODEL md4c"), md4c_signature=P.C.pin(b"MODEL md4c sig"))
        self.ref = dict(image=IMAGE, inventory=P.C.pin(self.after))
        self.plan = dict(component=S.COMPONENT, serial=True, source_map_sha256="6"*64, nonce=NONCE, image=IMAGE,
            inventory_pin=self.ref["inventory"], builds=[dict(
                argv=["/usr/bin/python3","-I","-B",str(self.source/"runtime/shadertools/scripts/build/build_family.py"),
                      "--output",str(self.output/f"build-{i}")],env=dict(CACHY_QT612_REFERENCE_ATTEMPT=str(i))) for i in (1,2)],
            compare=["/usr/bin/python3","-I","-B","MODEL compare"],inventory_path=str(self.source/"expected357.lock"),
            entry_pin={"sha256":"7"*64}, source_date_epoch=1792021458)
        self.stage = dict(component=S.COMPONENT, image=IMAGE, inventory_pin=self.ref["inventory"])
        self.enterContext(patch.dict(os.environ, {key:"MODEL" for key in (
            "GITHUB_REPOSITORY","GITHUB_EVENT_NAME","GITHUB_SHA","GITHUB_REF","GITHUB_RUN_ID","GITHUB_RUN_ATTEMPT",
            "UNRELATED_SECRET")}, clear=True))
        self.enterContext(patch.object(S.OWNER,"private_socket",return_value=(Path("/MODEL/volume/docker.sock"),(9,4))))

    def ref_file(self, name, body):
        path=self.root/name
        path.write_bytes(body)
        return dict(path=str(path),**P.C.pin(body))

    def owner(self):
        return S.ShaderToolsExecutor(P,self.plan,self.commands,self.supervisor,socket="/MODEL/volume/docker.sock",
            source=self.source,binding="/MODEL/binding",binding_sha256="a"*64,lifecycle_credential=self.credential,
            signed356=self.seed,signed357=self.ref,inventory356=self.before,inventory357=self.after,runner={"MODEL":True})

    def authenticate(self, owner):
        owner.authenticate_Root_stage_binding(self.stage)
        owner.require_domain(P.POLICY)
        owner.require_signed_inventory(component=S.COMPONENT,image=IMAGE,inventory_pin=self.ref["inventory"],
            signature_policy=S.SIGNATURE_POLICY,previous_providers=["gui_server"])

    def test_pinned_gui_projection_remains_unmodified(self):
        raw=(HERE/"executor.py").read_bytes()
        self.assertEqual(S.HOSTED_OWNER_SHA256,S.hashlib.sha256(raw).hexdigest())
        projected=S._project_owner(raw)
        self.assertIn(b'COMPONENT = "shadertools"',projected)
        self.assertIn(b'COMPONENT = "gui_server"',raw)
        self.assertIn(b'expected["previous_providers"] == ["gui_server"]',projected)
        with self.assertRaisesRegex(ValueError,"Exact retained"):
            S._project_owner(raw+b"\n")

    def test_image_selection_requires_exact_gui_carryover_and_md4c_pins(self):
        name=self.gui["filename"]
        selected={key:dict(path=f"/MODEL/{key}") for key in ("qualification","archive","signature","carryover")}
        for key in selected:
            selected[key].update(P.C.pin(key.encode()))
        md4c="md4c-0.5.3-1-aarch64.pkg.tar.xz"
        planned=dict(expected_packages=357,normal_signature_policy=S.SIGNATURE_POLICY,
            carried_provider_acceptance={"gui_server":selected["carryover"]},inventory_pin=self.ref["inventory"],
            archives=[md4c],signed_context={name:selected["archive"],name+".sig":selected["signature"],
                md4c:self.seed["md4c_archive"],md4c+".sig":self.seed["md4c_signature"]})
        mapping=dict(files={"expected356.lock":P.C.pin(self.before)})
        with (patch.object(P.C,"read_source",return_value=mapping),
              patch.object(P,"builder_image_plan",return_value=planned) as builder):
            _, scope, _=S.image_selection(P,source=self.source,source_map_sha256="6"*64,
                signed356=self.seed,prior_gui=selected,uid=1000,gid=1000)
            self.assertEqual(scope["base_image"],BASE)
            self.assertEqual(builder.call_args.kwargs["previous"],{"gui_server":selected})
            wrong=dict(self.seed,md4c_signature=P.C.pin(b"MODEL wrong signature"))
            with self.assertRaisesRegex(ValueError,"unchanged signed356 inputs"):
                S.image_selection(P,source=self.source,source_map_sha256="6"*64,
                    signed356=wrong,prior_gui=selected,uid=1000,gid=1000)

    def test_serial_child_and_native_inventory_observation(self):
        owner=self.owner()
        self.authenticate(owner)
        self.assertEqual(set(owner.inventory_evidence),{"356","357"})
        images=[row["argv"] for row in self.commands.rows if row["argv"][2]=="run"]
        self.assertEqual(len(images),2)
        self.assertTrue(all("--network=none" in argv and "--read-only" in argv for argv in images))
        first,second=self.plan["builds"]
        owner.run(first["argv"],P.BUILD_SECONDS,env=first["env"])
        self.assertIn(str(HERE/"shadertools.py"),self.commands.rows[-1]["argv"])
        self.assertNotIn("UNRELATED_SECRET",self.commands.env[-1])
        with self.assertRaisesRegex(ValueError,"confirm retirement"):
            owner.run(second["argv"],P.BUILD_SECONDS,env=second["env"])
        owner.require_absent_twice("cachy-qt612-family-"+NONCE+"-shadertools-1")
        owner.run(second["argv"],P.BUILD_SECONDS,env=second["env"])
        owner.require_absent_twice("cachy-qt612-family-"+NONCE+"-shadertools-2")
        owner.run(self.plan["compare"],P.COMPARE_SECONDS,env={},stdout=str(self.output/"comparison.json"))
        self.assertTrue(owner.compared)
        self.commands.derived_layers=["sha256:"+"b"*64,*LAYERS]
        with self.assertRaisesRegex(ValueError,"signed356 parent layers"):
            self.authenticate(self.owner())

    def test_entry_forces_lifecycle_and_refuses_a_pair_only_result(self):
        runner = HERE/"shadertools.py"
        runner_ref = dict(path=str(runner),**P.C.pin(runner.read_bytes()))
        env = {"QT612_FAMILY_SOURCE_ROOT":str(self.source),
               "QT612_FAMILY_SOURCE_MAP_SHA256":"6"*64,
               "QT612_FAMILY_BINDING_PATH":"/MODEL/binding",
               "QT612_FAMILY_BINDING_SHA256":"a"*64}
        planned = dict(inventory_pin=self.ref["inventory"],expected_inventory=self.after.decode())
        with (patch.dict(os.environ,env), patch.object(S.os,"access",return_value=False),
              patch.object(S,"image_selection",return_value=(planned,{"inventory":self.ref["inventory"]},self.before)),
              patch.object(P,"stage_commands",return_value=self.plan),
              patch.object(P,"run_stage",return_value=dict(
                  status="PASS_QT612_FAMILY_COMPONENT_PAIR_ONLY",lifecycle=None)) as stage):
            with self.assertRaisesRegex(ValueError,"Natural ShaderTools lifecycle"):
                S.run_shadertools_pair(trusted_pipeline=P,owner_commands=self.commands,supervisor=self.supervisor,
                    source=self.source,source_map_sha256="6"*64,signed356=self.seed,signed357=self.ref,prior_gui={},
                    inventory=self.plan["inventory_path"],output=self.output,cache=self.root/"cache",nonce=NONCE,
                    work=self.root/"qualifier",failure_output=self.root/"hold",socket="/MODEL/volume/docker.sock",
                    binding="/MODEL/binding",binding_sha256="a"*64,lifecycle_credential=self.credential,runner=runner_ref)
        self.assertIs(stage.call_args.kwargs["pair_only"],False)
        self.assertFalse((self.output/"owned-pair.json").exists())

    def test_scoped_signature_and_exact_install_rollback_ledger_required(self):
        owner=self.owner()
        self.authenticate(owner)
        filename=self.shaders["filename"]
        archive=self.ref_file(filename,b"MODEL qualified archive bytes")
        signature=self.ref_file(filename+".sig",b"MODEL separately selected signature")
        archive_pin=S._whole(archive)
        qualified=dict(filename=filename,observations=[dict(archive=archive_pin) for _ in (1,2)])
        qualification=P.C.pin(P.C.encoded(qualified))
        self.credential.select_signed_archive.return_value=dict(archive=archive,signature=signature,
            qualification=qualification)
        plan=L.command_plan(self.shaders,self.after,qualification,archive_pin)

        def receipt(**request):
            commands=[dict(role=step["role"],argv=step["argv"],exit=0,natural=True,reaped=True,output_complete=True,
                stdout=step["exact_stdout"] if step["exact_stdout"] is not None else "qsb 6.12.0\n") for step in plan["steps"]]
            return dict(plan_pin=P.C.pin(P.C.encoded(plan)),signature_policy=S.SIGNATURE_POLICY,
                archive_pin=archive_pin,signature_pin=S._whole(signature),configuration_unchanged=True,
                host_state_unchanged=True,scope=request["scope"],commands=commands)

        request=dict(component=S.COMPONENT,qualified=qualified,plan=plan,timeout=P.LIFECYCLE_SECONDS,
                     output_json=str(self.output/"lifecycle.json"))
        with self.assertRaisesRegex(ValueError,"required before lifecycle"):
            owner.lifecycle(**request)
        owner.compared,owner.executions=True,[{}]*4
        self.supervisor.lifecycle.side_effect=receipt
        final=owner.lifecycle(**request)
        L.validate_receipt(plan,final,canonical_pin=lambda value:P.C.pin(P.C.encoded(value)))
        self.assertEqual(len(owner.absence["lifecycle"]),2)
        self.assertEqual(final["scope"]["network"],"none")
        self.assertEqual(final["commands"][-1]["stdout"],self.after.decode())
        missing=[row for row in final["commands"] if row["role"]!="rollback-to-base"]
        with self.assertRaisesRegex(ValueError,"Complete ordered lifecycle"):
            L.validate_receipt(plan,dict(final,commands=missing),canonical_pin=lambda value:P.C.pin(P.C.encoded(value)))
        owner.lifecycle_operands=None
        self.supervisor.lifecycle.side_effect=lambda **kw:dict(receipt(**kw),signature_pin=P.C.pin(b"MODEL wrong"))
        with self.assertRaisesRegex(ValueError,"same exact signature"):
            owner.lifecycle(**request)

        owner.lifecycle_operands=None
        def overwrite_rollback(**kwargs):
            kwargs["plan"]["steps"].pop()
            return receipt(**kwargs)

        self.supervisor.lifecycle.side_effect=overwrite_rollback
        with self.assertRaisesRegex(ValueError,"preserve the exact transaction ledger"):
            owner.lifecycle(**request)


if __name__ == "__main__":
    sys.addaudithook(fence)
    unittest.main(verbosity=2)
