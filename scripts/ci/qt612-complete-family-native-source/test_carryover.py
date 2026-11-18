# SPDX-License-Identifier: MIT
"""Offline MODELS for accepted GUI carryover across a fresh runner Source map."""

import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qt_family_carryover_model", HERE / "pipeline.py")
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)
C, M = N.C, N.M


def fence(event, _):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.posix_spawn", "os.fork", "fcntl.flock")):
        raise AssertionError("passive carryover MODEL must never enter an actor")


if __name__ == '__main__':
    sys.addaudithook(fence)


class Carryover(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="qt-gui-carryover-MODEL-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        lock = C.load_lock()
        self.row = lock["components"]["gui_server"]
        self.dependencies = {}
        for key in ("double-conversion", "libb2", "libice", "libsm", "md4c", "xcb-util-cursor", "xdg-utils"):
            version = "0.5.3-1" if key == "md4c" else "1.0-1"
            filename = f"{key}-{version}-aarch64.pkg.tar.xz"
            self.dependencies[key] = dict(name=key, version=version, arch="aarch64", filename=filename,
                archive=self.write(filename, b"MODEL bits: " + key.encode()),
                signature=self.write(filename+".sig", b"MODEL signature: "+key.encode()))

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        return dict(path=str(path), **C.pin(raw))

    def record(self, name, value):
        return self.write(name, C.encoded(value))

    def source(self):
        base = dict(kind="QT612_COMPLETE517_INPUT_DATA_ONLY", files=517,
                    inventory={f"base{i:03}": "1.0-1" for i in range(349)})
        versions = base["inventory"] | {key: row["version"] for key,row in self.dependencies.items()}
        inventory = "".join(f"{key} {value}\n" for key,value in sorted(versions.items())).encode()
        root = self.root/"future-bound-source"
        writer = M.Writer(root)
        inputs = dict(base_provider=self.write("MODEL-new-base.json", b"MODEL new paths"),
                      dependencies=dict(packages=self.dependencies, complete=True))
        try:
            bodies={
              "expected356.lock":inventory,
              "family-inputs.DATA.json":C.encoded(inputs),
              "scripts/ci/qt612-complete-family-native-source/pipeline.py":(HERE/"pipeline.py").read_bytes(),
              "recipes/gui_server/PKGBUILD":b"MODEL frozen recipe",
            }
            rows={name:writer.put(name,raw=raw) for name,raw in bodies.items()}
            mapping=dict(schema=1,kind="QT612_COMPLETE_FAMILY_SOURCE_DATA_V1",files=rows,
                         components={},input_plan_complete=True,desktop_consumer=None,
                         actual=dict.fromkeys(M.ACTUAL),Root_acceptance=None)
            raw=C.encoded(mapping)
            writer.put("source-map.json",raw=raw)
        finally:
            writer.close()
        return root, C.pin(raw)["sha256"], mapping, base

    def selected(self, mapping, successor, *, drift=None, mutate_terminal=None, mutate_archive=None):
        inventory=N._whole(mapping["files"]["expected356.lock"])
        row=self.row
        original=dict(mapping,files=dict(mapping["files"], **{
            "family-inputs.DATA.json":dict(mode=0o644,**C.pin(b"MODEL previous runner paths")),
            "scripts/ci/qt612-complete-family-native-source/pipeline.py":dict(mode=0o644,**C.pin(b"MODEL original program")),
        }))
        if drift is not None:
            original["files"][drift]=dict(mode=0o644,**C.pin(b"MODEL wrong frozen source bytes"))
        original_ref=self.record("MODEL-original-build-map.json",original)
        pkg = io.BytesIO()
        with tarfile.open(fileobj=pkg,mode="w:xz") as stream:
            raw=f"pkgname = {row['package']}\npkgver = 6.12.0-1\narch = aarch64\n".encode()
            leaf=tarfile.TarInfo(".PKGINFO")
            leaf.size=len(raw)
            stream.addfile(leaf,io.BytesIO(raw))
        filename=row["filename"]
        archive=self.write(filename,pkg.getvalue())
        signature=self.write(filename+".sig",b"MODEL externally selected detached signature")
        qualification=self.record("MODEL-qualification.json",
            dict(status="PASS_QT612_FAMILY_COMPONENT_PAIR_CURRENT_BYTES_ONLY",component="gui_server",
                 filename=filename,recipe_commit=row["commit"],source_map_sha256=original_ref["sha256"],
                 inventory_pin=inventory,image="sha256:"+"d"*64,
                 observations=[dict(archive=N._whole(archive)) for _ in (1,2)]))
        dispatch=dict(source="a"*40,ref="refs/heads/main",run="901",job="902",attempt="1")
        hashes={f"build-{i}/artifacts/{filename}":N._whole(archive) for i in (1,2)}
        if mutate_archive is not None:
            hashes[f"build-2/artifacts/{filename}"]=C.pin(mutate_archive)
        manifest=self.record("MODEL-manifest.json",dict(kind="QT612_HOSTED_PAIR_EXACT_EXPORT_V1",
            selected=dict(dispatch=dispatch,stage_binding_sha256="c"*64,source_map=N._whole(original_ref),
                          qualification=N._whole(qualification)),
            lifecycle_status="NOT_RUN",native_acceptance=None,Root_acceptance=None,
            files={"qualification.json":N._whole(qualification),"source-map.json":N._whole(original_ref),**hashes}))
        lock=N.P.selected(N.C.PARENT/"dependency-candidates.lock.json",N.P.DEPENDENCIES,{})
        original_selection=self.record("MODEL-original-selection.json",dict(
            original_source_map=C.pin(b"MODEL unbound original"),kind="QT612_PATHLESS_RUNNER_INPUTS_DATA_V1",schema=1,
            Root_acceptance=None,official_dependency_lock=N.P.DEPENDENCIES,
            base_metadata={key:lock[role] for key,role in (("base_lock","baseline_input_lock"),
              ("baseline_inventory","baseline_inventory"),("bootstrap_profile","bootstrap_profile"))},
            dependencies={key:dict(item,archive=N._whole(item["archive"]),signature=N._whole(item["signature"]))
                          for key,item in self.dependencies.items()}))
        runtime=self.record("MODEL-original-runtime-map.json",dict(kind="QT612_GUI_PAIR_WORKFLOW_SOURCE_V1",schema=1,
            files={"portable/source-map.json":C.pin(b"MODEL unbound original"),
                   "portable/selection.DATA.json":N._whole(original_selection)}))
        result=dict(status="INDEPENDENT_EXACT_NATIVE_PAIR_READBACK_ONLY",conclusion="success",attempt=1,run=901,job=902,
            workflow_id=422506968,workflow_sha=dispatch["source"],live_ref=dispatch["ref"],artifact=dict(id=903,name=f"qt612-gui-server-pair-{dispatch['source']}-901-1"),
            artifact_archive=C.pin(b"MODEL ZIP"),runtime_source=dict(map=N._whole(runtime)),
            native_acceptance=None,Root_acceptance=None,lifecycle_status="NOT_RUN",
            independent_pair=dict(manifest=N._whole(manifest),stage_binding=dict(sha256="c"*64),
                signed356=dict(image="sha256:"+"d"*64,inventory=inventory),
                replay=dict(status="PASS_QT612_HOSTED_PAIR_EXACT_READBACK_ONLY",lifecycle_status="NOT_RUN",Root_acceptance=None)))
        if mutate_terminal is not None:
            result.update(mutate_terminal)
        terminal=self.record("MODEL-terminal.json",result)
        acceptance=self.record("MODEL-acceptance.json",dict(kind="ROOT_QT612_GUI_PAIR_PROVIDER_CARRYOVER_V1",
            issuer="Root",accepted=True,continuation_source_map_sha256=successor,readback=terminal,manifest=manifest,
            build_source_map=original_ref,runtime_map=runtime,portable_selection=original_selection))
        return dict(qualification=qualification,archive=archive,signature=signature,carryover=acceptance)

    def plan(self, source, digest, base, selected):
        with patch.object(N.P,"validate_base_provider",return_value=base):
            return N.builder_image_plan(source=source,source_map_sha256=digest,component="shadertools",
                baseline_image="sha256:"+"f"*64,previous={"gui_server":selected},uid=1000,gid=1000)

    def test_fresh_runner_map_accepts_exact_original_gui_only_via_root_decision(self):
        source,digest,mapping,base=self.source()
        chosen=self.selected(mapping,digest)
        without_carryover={key:value for key,value in chosen.items() if key!="carryover"}
        with self.assertRaisesRegex(ValueError,"MATCHING_SELECTED_PRIOR_PAIR"):
            self.plan(source,digest,base,without_carryover)
        plan=self.plan(source,digest,base,chosen)
        self.assertEqual(plan["expected_packages"],357)
        self.assertEqual(plan["carried_provider_acceptance"],{"gui_server":chosen["carryover"]})
        self.assertEqual(plan["signed_context"][self.row["filename"]],chosen["archive"])
        self.assertEqual(plan["signed_context"][self.row["filename"]+".sig"],chosen["signature"])
        self.assertIn("LocalFileSigLevel = Required TrustedOnly",plan["pacman_config"])
        self.assertIn("pacman --config /qt612.pacman.conf -U --noconfirm --noscriptlet /qt612-deps/"+self.row["filename"],plan["dockerfile"])
        self.assertIs(plan["pair_evidence_is_authentication"],False)
        self.assertIsNone(plan["Root_acceptance"])

    def test_refuses_wrong_recipe_terminal_or_original_archive(self):
        source,digest,mapping,base=self.source()
        for patch_args,reason in (
            (dict(drift="recipes/gui_server/PKGBUILD"),"UNCHANGED_FAMILY_RECIPES"),
            (dict(mutate_terminal=dict(conclusion="failure")),"ORIGINAL_INDEPENDENT_NATIVE_GUI_PAIR_READBACK"),
            (dict(mutate_archive=b"MODEL different first or second package"),"EXACT_GUI_PROVIDER"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError,reason):
                self.plan(source,digest,base,self.selected(mapping,digest,**patch_args))

    def test_md4c_signature_bytes_and_new_source_map_remain_bound(self):
        source,digest,mapping,base=self.source()
        chosen=self.selected(mapping,digest)
        self.dependencies["md4c"]["signature"]=self.write("MODEL-wrong-md4c.sig",b"MODEL replacement signature")
        # A separately read model successor uses the same inventory but changes its signed operand.
        incoming=M.decode((source/"family-inputs.DATA.json").read_bytes())
        incoming["dependencies"]["packages"]=self.dependencies
        raw=C.encoded(incoming)
        (source/"family-inputs.DATA.json").write_bytes(raw)
        mapping["files"]["family-inputs.DATA.json"]=dict(mode=0o644,**C.pin(raw))
        raw=C.encoded(mapping)
        (source/"source-map.json").write_bytes(raw)
        new_sha=C.pin(raw)["sha256"]
        with self.assertRaisesRegex(ValueError,"EXACT_ROOT_SELECTED_GUI_CARRYOVER"):
            self.plan(source,new_sha,base,chosen)
        accept=M.decode(Path(chosen["carryover"]["path"]).read_bytes())
        chosen["carryover"]=self.record("MODEL-rebound-decision.json",dict(accept,continuation_source_map_sha256=new_sha))
        with self.assertRaisesRegex(ValueError,"UNCHANGED_BASELINE_AND_ALL_SEVEN_SIGNED_DEPENDENCIES"):
            self.plan(source,new_sha,base,chosen)


if __name__ == "__main__":
    unittest.main(verbosity=2)
