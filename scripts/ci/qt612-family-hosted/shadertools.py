# SPDX-License-Identifier: MIT
"""Owned ShaderTools continuation with a carried GUI pair and mandatory lifecycle."""

import hashlib
import json
import os
from pathlib import Path
import re
from types import ModuleType

HERE = Path(__file__).resolve().parent
COMPONENT = "shadertools"
HOSTED_OWNER_SHA256 = "d91457ba75dd5d61c1bae9cc09ac468d5e05de049f87409669dd769efe7b4ba6"
SIGNATURE_POLICY = "Required TrustedOnly"


def _need(value, reason):
    if not value:
        raise ValueError(reason)


def _project_owner(raw):
    """Reuse the pinned serial driver and limits with only ShaderTools roles changed."""
    _need(hashlib.sha256(raw).hexdigest() == HOSTED_OWNER_SHA256, "Exact retained GUI owner source required")
    changes = (
        (b'COMPONENT = "gui_server"', b'COMPONENT = "shadertools"', 1),
        (b'"runtime/gui_server/scripts/build/build_family.py"', b'"runtime/shadertools/scripts/build/build_family.py"', 1),
        (b'"-gui_server-"', b'"-shadertools-"', 2),
        (b'expected["previous_providers"] == []', b'expected["previous_providers"] == ["gui_server"]', 1),
        (b'str(HERE / "executor.py")', b'str(HERE / "shadertools.py")', 1),
    )
    projected = raw
    for before, after, count in changes:
        _need(projected.count(before) == count and after not in projected, "Exact ShaderTools projection seams required")
        projected = projected.replace(before, after)
    inverse = projected
    for before, after, _ in reversed(changes):
        inverse = inverse.replace(after, before)
    _need(inverse == raw, "Whole reversible ShaderTools projection required")
    return projected


def _owner():
    path = HERE / "executor.py"
    raw = path.read_bytes()
    module = ModuleType("qt612_shadertools_owned_driver")
    module.__file__ = str(path)
    exec(compile(_project_owner(raw), str(path), "exec"), module.__dict__)
    return module


OWNER = _owner()


def _whole(ref):
    return {key: ref[key] for key in ("bytes", "sha256")}


def image_selection(pipeline, *, source, source_map_sha256, signed356, prior_gui, uid, gid):
    """Rejoin the signed356 plan and the one accepted GUI carryover before the new stage."""
    C, M = pipeline.C, pipeline.C.M
    _need(set(signed356) == {"image", "inventory", "signature_policy", "base_image", "md4c_archive", "md4c_signature"}
          and re.fullmatch(r"sha256:[0-9a-f]{64}", signed356["image"])
          and signed356["signature_policy"] == SIGNATURE_POLICY
          and set(prior_gui) == {"qualification", "archive", "signature", "carryover"},
          "Only an exact signed356 parent and independently selected GUI carryover are allowed")
    mapping = C.read_source(source, source_map_sha256)
    raw356 = M.stream(Path(source)/"expected356.lock", _whole(mapping["files"]["expected356.lock"]), {}, collect=True)
    _need(len(raw356.splitlines()) == 356 and C.pin(raw356) == signed356["inventory"],
          "Signed356 parent must retain the complete frozen inventory")
    planned = pipeline.builder_image_plan(source=source, source_map_sha256=source_map_sha256,
        component=COMPONENT, baseline_image=signed356["base_image"], previous={"gui_server": prior_gui}, uid=uid, gid=gid)
    archive = C.load_lock()["components"]["gui_server"]["filename"]
    md4c, = [name for name in planned["archives"] if name.startswith("md4c-")]
    refs = planned["signed_context"]
    _need(planned["expected_packages"] == 357 and planned["normal_signature_policy"] == SIGNATURE_POLICY
          and planned["carried_provider_acceptance"] == {"gui_server": prior_gui["carryover"]}
          and refs[archive] == prior_gui["archive"] and refs[archive+".sig"] == prior_gui["signature"]
          and _whole(refs[md4c]) == signed356["md4c_archive"] and _whole(refs[md4c+".sig"]) == signed356["md4c_signature"],
          "Exact accepted GUI package and unchanged signed356 inputs required")
    expected = dict(component=COMPONENT, source_map_sha256=source_map_sha256, base_image=signed356["image"],
                    inventory=planned["inventory_pin"], signature_policy=SIGNATURE_POLICY,
                    gui_archive=_whole(prior_gui["archive"]), gui_signature=_whole(prior_gui["signature"]),
                    gui_acceptance=_whole(prior_gui["carryover"]))
    return planned, expected, raw356


class ShaderToolsExecutor(OWNER.FirstPairExecutor):
    """Use an independently authenticated stage image and a separate signed lifecycle selection."""

    def __init__(self, *args, signed356, signed357, inventory356, inventory357, runner, **kwargs):
        super().__init__(*args, **kwargs)
        self.signed356 = signed356
        self.signed357 = signed357
        self.inventory356 = inventory356
        self.inventory357 = inventory357
        self.runner = runner
        self.inventory_evidence = {}
        self.lifecycle_operands = None
        _need(getattr(self.lifecycle_credential, "API", None) == OWNER.CREDENTIAL_API
              and callable(getattr(self.lifecycle_credential, "select_signed_archive", None)),
              "Separate scoped ShaderTools lifecycle credential required")

    def authenticate_Root_stage_binding(self, binding):
        _need(binding["component"] == COMPONENT and binding["image"] == self.signed357["image"]
              and binding["inventory_pin"] == self.signed357["inventory"],
              "Exact owned ShaderTools stage binding required")
        _need(self.supervisor.authenticate_shadertools_continuation(
              binding=binding, signed356=self.signed356, signed357=self.signed357, runner=self.runner) is True,
              "Separate Root authorization of the exact ShaderTools continuation required")
        super().authenticate_Root_stage_binding(binding)

    def require_signed_inventory(self, **expected):
        super().require_signed_inventory(**expected)
        base, selected = (self._inspect(image) for image in (self.signed356["image"], self.signed357["image"]))
        before, after = base["RootFS"]["Layers"], selected["RootFS"]["Layers"]
        _need(before and all(re.fullmatch(r"sha256:[0-9a-f]{64}", layer) for layer in after)
              and len(after)>len(before) and after[:len(before)]==before,
              "Exact derived image must retain the signed356 parent layers")
        for count, image, raw in ((356, self.signed356["image"], self.inventory356),
                                  (357, self.signed357["image"], self.inventory357)):
            self.require_no_containers()
            result = self.docker(*inventory_command(image, self.plan["nonce"], count), seconds=30)
            receipt = self.retired(result, result.args)
            _need(result.stdout == raw and not result.stderr, "Complete observed signed inventory differs")
            self.inventory_evidence[str(count)] = dict(readback=receipt, absence=[self.require_no_containers() for _ in range(2)])

    def _inspect(self, image):
        result = self.docker("image", "inspect", image)
        self.retired(result, result.args)
        rows = json.loads(result.stdout)
        _need(len(rows) == 1 and rows[0]["Id"] == image and rows[0]["Architecture"] == "arm64"
              and rows[0]["Os"] == "linux" and rows[0]["RootFS"]["Type"] == "layers",
              "Exact local native image identity required")
        return rows[0]

    def lifecycle(self, **request):
        _need(self.compared and len(self.executions) == 4 and self.lifecycle_operands is None
              and request["component"] == COMPONENT, "Current exact ShaderTools pair required before lifecycle")
        C, P = self.pipeline.C, self.pipeline.P
        qualified, plan = request["qualified"], request["plan"]
        qpin = C.pin(C.encoded(qualified))
        filename = C.load_lock()["components"][COMPONENT]["filename"]
        selected = self.lifecycle_credential.select_signed_archive(binding=self.binding, qualification=qpin)
        _need(set(selected) == {"qualification", "archive", "signature"} and selected["qualification"] == qpin
              and qpin == plan["qualification_pin"] and qualified["filename"] == filename
              and Path(selected["archive"]["path"]).name == filename
              and Path(selected["signature"]["path"]).name == filename+".sig"
              and _whole(selected["archive"]) == plan["archive_pin"]
              and 0 < selected["signature"]["bytes"] <= 1024**2
              and len(qualified["observations"]) == 2
              and all(row["archive"] == plan["archive_pin"] for row in qualified["observations"]),
              "Exact separately selected ShaderTools archive, pair and stage signature required")
        observed = {}
        P.reference(selected["archive"], observed, cap=512*1024**2)
        P.reference(selected["signature"], observed, cap=1024**2)
        self.lifecycle_operands = selected
        plan_pin = C.pin(C.encoded(plan))
        selected_pin = C.pin(C.encoded(selected))
        signature_pin = _whole(selected["signature"])
        scope = dict(component=COMPONENT, image=self.plan["image"], network="none", platform="linux/arm64",
                     container=f"cachy-qt612-shadertools-{self.plan['nonce']}-lifecycle")
        self.require_no_containers()
        receipt = self.supervisor.lifecycle(credential=self.lifecycle_credential, selected_signed=selected,
                                            scope=dict(scope), **request)
        _need(C.pin(C.encoded(plan)) == plan_pin and C.pin(C.encoded(selected)) == selected_pin,
              "Lifecycle must preserve the exact transaction ledger and signed selection")
        _need(receipt["signature_pin"] == signature_pin and receipt["scope"] == scope,
              "Lifecycle must authenticate the same exact signature in the selected offline image")
        self.absence["lifecycle"] = [self.require_no_containers() for _ in range(2)]
        C.M.unchanged(observed)
        return receipt


def inventory_command(image, nonce, count):
    _need(re.fullmatch(r"sha256:[0-9a-f]{64}", image) and re.fullmatch(r"[0-9a-f]{32}", nonce)
          and count in (356, 357), "Exact signed inventory readback identity")
    return ["run", "--rm", "--pull=never", "--platform=linux/arm64", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cpus=1", "--memory=512m",
            "--memory-swap=512m", "--pids-limit=32", "--name", f"cachy-qt612-shadertools-{nonce}-inventory{count}",
            "--entrypoint=/bin/sh", image, "-ec", "pacman -Q | LC_ALL=C sort"]


def run_shadertools_pair(*, trusted_pipeline, owner_commands, supervisor, source, source_map_sha256,
                         signed356, signed357, prior_gui, inventory, output, cache, nonce, work,
                         failure_output, socket, binding, binding_sha256, lifecycle_credential, runner):
    """Run only on an already owned, externally supervised ShaderTools stage."""
    p = trusted_pipeline
    C, M = p.C, p.C.M
    source, output = map(M.ordinary, (source, output))
    _need(callable(getattr(supervisor, "authenticate_shadertools_continuation", None))
          and getattr(lifecycle_credential, "API", None) == OWNER.CREDENTIAL_API,
          "Separate Root supervisor and new archive lifecycle custody required")
    for name, value in (("QT612_FAMILY_SOURCE_ROOT", str(source)),
                        ("QT612_FAMILY_SOURCE_MAP_SHA256", source_map_sha256),
                        ("QT612_FAMILY_BINDING_PATH", str(binding)),
                        ("QT612_FAMILY_BINDING_SHA256", binding_sha256)):
        _need(os.environ.get(name) == value, "Exact bound ShaderTools environment required")
    _need(runner["path"] == str(HERE/"shadertools.py")
          and all(not os.access(path, os.W_OK) for path in (source, HERE, HERE/"shadertools.py", HERE/"executor.py")),
          "Exact protected scoped ShaderTools code and Source required")
    runner_identity = {}
    p.P.reference(runner, runner_identity, cap=64*1024)
    planned, expected, base = image_selection(p, source=source, source_map_sha256=source_map_sha256,
        signed356=signed356, prior_gui=prior_gui, uid=os.getuid(), gid=os.getgid())
    image = signed357["image"]
    _need(signed357 == dict(expected, image=image) and image != signed356["image"],
          "Exact authenticated signed357 observation required")
    plan = p.stage_commands(source=source, source_map_sha256=source_map_sha256, component=COMPONENT,
                            output=output, image=image, inventory=inventory, cache=cache, nonce=nonce)
    _need(plan["inventory_pin"] == planned["inventory_pin"] and not (output/"owned-pair.json").exists(),
          "Exact signed357 operating inventory and fresh ShaderTools witness required")
    owner = ShaderToolsExecutor(p, plan, owner_commands, supervisor, socket=socket, source=source,
        binding=binding, binding_sha256=binding_sha256, lifecycle_credential=lifecycle_credential,
        signed356=signed356, signed357=signed357, inventory356=base,
        inventory357=planned["expected_inventory"].encode("ascii"), runner=runner)
    result = p.run_stage(plan, owner, source=source, source_map_sha256=source_map_sha256,
                         output=output, work=work, failure_output=failure_output, pair_only=False)
    _need(result["status"] == "PASS_COMPONENT_CALLBACK_AND_BYTE_JOINS_ONLY"
          and owner.lifecycle_operands is not None and result["lifecycle"] is not None
          and len(owner.absence["lifecycle"]) == 2,
          "Natural ShaderTools lifecycle must complete before witness retention")
    M.unchanged(runner_identity)
    witness = dict(kind="QT612_HOSTED_OWNED_PAIR_WITNESS_V1", mode="signed-lifecycle",
        component=COMPONENT, nonce=nonce, source_map_sha256=source_map_sha256,
        stage_binding_sha256=binding_sha256, image=image, inventory_pin=plan["inventory_pin"],
        dispatch={key:owner.binding[key] for key in ("source", "ref", "run", "job", "attempt")},
        commands=owner.executions, absence=owner.absence, installed_inputs=owner.inventory_evidence,
        qualification=C.pin(C.encoded(result["qualification"])),
        lifecycle=C.pin(C.encoded(result["lifecycle"])),
        gui_acceptance=expected["gui_acceptance"], signed_archive=_whole(owner.lifecycle_operands["archive"]),
        signature=_whole(owner.lifecycle_operands["signature"]))
    OWNER.write_fresh(output/"owned-pair.json", C.encoded(witness))
    return result


if __name__ == "__main__":
    raise SystemExit(OWNER.build_child())
