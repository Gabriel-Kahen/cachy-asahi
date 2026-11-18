# SPDX-License-Identifier: MIT
"""Finite passive export controls with intentionally inert package bodies."""

from pathlib import Path
import tempfile
import unittest

import evidence
import executor


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source, self.stage, self.commands = (self.root/name for name in ("source", "stage", "commands"))
        pipeline = executor.load(Path(__file__).resolve().parents[1]/"qt612-complete-family-native-source/pipeline.py",
                                 "qt612_hosted_test_export_pipeline")
        C = self.C = pipeline.C
        frozen = C.load_lock()["components"]["gui_server"]
        self.filename = frozen["filename"]
        recipe = b"MODEL recipe"
        inventory = b"MODEL signed356 inventory"
        self.write(self.source/"expected356.lock", inventory)
        mapping = dict(kind="QT612_COMPLETE_FAMILY_SOURCE_DATA_V1", input_plan_complete=True, Root_acceptance=None,
                       files={"expected356.lock": C.pin(inventory), "recipes/gui_server/PKGBUILD": C.pin(recipe)})
        map_pin = self.write_json(self.source/"source-map.json", mapping)
        image, nonce = "sha256:"+"1"*64, "2"*32
        dispatch = dict(source="3"*40, ref="refs/heads/codex/model", run="100", job="200", attempt="1")
        comparison = self.write_json(self.stage/"comparison.json", {})
        archive = b"inert identical package fixture"
        cert = C.encoded({"model":"inert"})
        check_log = b"MODEL check"
        artifacts = {}
        for index in (1, 2):
            base = self.stage/f"build-{index}"
            files = {
                "build.log": b"MODEL build", "validation.json": b"{}", "expected-packages.lock": inventory,
                "artifacts/packages.lock": inventory, "artifacts/"+self.filename: archive,
                "artifacts/"+self.filename.removesuffix(".pkg.tar.xz")+"-check.log": check_log,
                **{f"artifacts/{name}":cert for name in ("environment.txt", "config.sha256", "generated.SRCINFO",
                    "makepkg.conf", "pacman.conf", "family-stage.json", "family-configuration.json",
                    "family-notices.json", "family-dependencies.missing", "family-build-proof.json")}
            }
            for relative, raw in files.items():
                self.write(base/relative, raw)
            self.write(base/"inputs/PKGBUILD", recipe)
            artifacts[f"build-{index}"] = self.write_json(base/"provenance.json",
                dict(image_id=image, artifacts={self.filename:C.pin(archive)["sha256"]},
                     recipe_inputs={"PKGBUILD":C.pin(recipe)["sha256"]},
                     files={name:C.pin(raw)["sha256"] for name,raw in files.items()}))
        observation = dict(archive=C.pin(archive), check_log=C.pin(check_log), build_proof=C.pin(cert),
                           stage=C.pin(cert), configuration=C.pin(cert), notices=C.pin(cert))
        values = dict(image=image, nonce=nonce, inventory_pin=C.pin(inventory), entry_pin=C.pin(b"entry"),
                      source_date_epoch=1792021458)
        qualification = dict(status="PASS_QT612_FAMILY_COMPONENT_PAIR_CURRENT_BYTES_ONLY", component="gui_server",
            source_map_sha256=map_pin["sha256"], recipe_commit=frozen["commit"], filename=self.filename,
            native_acceptance=None, Root_acceptance=None, M2="NOT_RUN", GPG="NOT_RUN",
            observations=[observation, observation], provenance_pins=artifacts, comparison=comparison, **values)
        qual = self.write_json(self.stage/"qualification.json", qualification)
        first, second = "/example/build-1", "/example/build-2"
        request = self.write_json(self.stage/"qualifier-input/request.json",
            dict(kind="QT612_FAMILY_PAIR_QUALIFICATION_REQUEST_V1", component="gui_server",
                 source_map_sha256=map_pin["sha256"], first=first, second=second, expected=values))
        docker = ["/usr/bin/docker", "--host=unix:///example/volume/docker.sock"]
        empty = [*docker, "container", "ls", "-a", "--no-trunc", "--quiet"]
        build = ["/usr/bin/python3", "-I", "-B", "/app/executor.py", "/source/build_family.py",
                 "--network", "none", "--mode", "native", "--image", image, "--output"]
        commands = [
            self.event(3, [*build, first]),
            self.event(6, [*build, second]),
            self.event(9, ["/usr/bin/python3", "compare_v2.py", first, second, "--require-bytes"],
                       (self.stage/"comparison.json").read_bytes()),
            self.event(10, [*docker, "run", "--memory=2g", "--memory-swap=2g", "--cpus=1", "--network=none",
                       "--read-only", "cachy-qt612-qualify-"+nonce, request["sha256"]],
                       (self.stage/"qualification.json").read_bytes()),
        ]
        absence = {}
        for number, start in ((1,4),(2,7)):
            query = [*empty,"--filter", "name=^/cachy-qt612-family-"+nonce+f"-gui_server-{number}$"]
            absence[f"build-{number}"] = [self.event(i,query) for i in (start,start+1)]
        absence["qualifier"] = [self.event(i,empty) for i in (11,12)]
        binding = "4"*64
        owner = self.write_json(self.stage/"owned-pair.json", dict(kind="QT612_HOSTED_OWNED_PAIR_WITNESS_V1",
            mode="pair-only", dispatch=dispatch, stage_binding_sha256=binding, qualification=qual, component="gui_server",
            source_map_sha256=map_pin["sha256"], image=image, nonce=nonce, inventory_pin=C.pin(inventory),
            commands=commands, absence=absence))
        self.selected = dict(source_map=map_pin, qualification=qual, owner=owner,
                             stage_binding_sha256=binding, dispatch=dispatch)

    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return self.C.pin(raw)

    def write_json(self, path, value):
        return self.write(path, self.C.encoded(value))

    def event(self, index, argv, stdout=b""):
        label = f"{index:03}"
        pin = self.write(self.commands/(label+".stdout"), stdout)
        stderr = self.write(self.commands/(label+".stderr"),b"")
        row = dict(argv=argv, retirement=dict(exit=0, reaped=True, ownership="REAPED", group_census="EMPTY_TWICE",
                   output_complete=True, signals=[], timeout=False, error=None), stdout=pin, stderr=stderr)
        self.write_json(self.commands/(label+".json"),row)
        return dict(index=index, **row)

    def export(self, name="export"):
        return evidence.export_pair(self.C, stage=self.stage, source=self.source, commands=self.commands,
                                    output=self.root/name, selected=self.selected)

    def test_whole_export_readback_and_unapproved_extra_member(self):
        pin = self.export()
        root = self.root/"export"
        report = evidence.verify_export(self.C, root=root, manifest_pin=pin, selected=self.selected)
        self.assertEqual(report["lifecycle_status"],"NOT_RUN")
        self.assertTrue((root/"build-2/artifacts"/self.filename).is_file())
        self.write(root/"lifecycle.json",b"{}")
        with self.assertRaisesRegex(ValueError,"Unexpected raw pair export"):
            evidence.verify_export(self.C, root=root, manifest_pin=pin, selected=self.selected)

    def test_tampered_original_raw_command_output_is_held(self):
        self.write(self.commands/"009.stdout",b"modified command output")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse((self.root/"export").exists())

    def test_mismatched_archive_and_dispatch_are_held(self):
        old = self.selected["dispatch"]
        self.selected["dispatch"] = dict(old,job="wrong")
        with self.assertRaisesRegex(ValueError,"already-qualified"):
            self.export()
        self.selected["dispatch"] = old
        self.write(self.stage/"build-2/artifacts"/self.filename,b"swapped package")
        with self.assertRaises(ValueError):
            self.export()


if __name__ == "__main__":
    unittest.main()
