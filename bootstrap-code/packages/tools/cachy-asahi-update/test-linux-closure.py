#!/usr/bin/env python3
"""Mocked Cargo metadata and temporary inert source fixtures; no Cargo execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("closure", Path(__file__).with_name("linux-closure.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
CFG = b'unix\ntarget_arch="aarch64"\ntarget_os="linux"\ntarget_env="gnu"\ntarget_family="unix"\ntarget_pointer_width="64"\ntarget_endian="little"\ntarget_vendor="unknown"\ntarget_has_atomic="64"\n'


class Fixture:
    def __init__(self, path):
        self.vendor = path / "vendor"
        self.vendor.mkdir()
        definitions = {
            "arch-update-tray": ("4.4.2", '[dependencies]\nlocale_config="0.3"\nuser-named={package="data",version="1",features=["derive"]}\n[build-dependencies]\ntool="1"\n'),
            "locale_config": ("0.3.0", '[target.\'cfg(target_os = "macos")\'.dependencies]\nobjc_id="0.1"\n'),
            "data": ("1.0.0", '[lib]\nname="runtime"\n[dependencies]\noptional={version="1",optional=true}\nmacro={version="1",optional=true}\n[features]\ndefault=["dep:optional", "optional?/extra"]\nderive=["dep:macro"]\n'),
            "tool": ("1.0.0", '[dependencies]\nhelper="1"\n'),
            "macro": ("1.0.0", '[lib]\nproc-macro=true\n[dependencies]\nhelper="1"\n'),
            "optional": ("1.0.0", '[features]\nextra=[]\n'),
            "helper": ("1.0.0", ""),
            "objc_id": ("0.1.1", ""),
        }
        self.manifests, self.ids, rows, lockrows = {}, {}, [], []
        for name, (version, suffix) in definitions.items():
            text = f'[package]\nname="{name}"\nversion="{version}"\nlicense="MIT"\n' + suffix
            data = text.encode()
            manifest = C.tomllib.loads(text)
            self.manifests[name] = manifest
            is_root = name == "arch-update-tray"
            self.ids[name] = "root" if is_root else C.REGISTRY + "#" + name + "@" + version
            checksum = C.digest((name + version).encode())
            if is_root:
                self.manifest = data
            else:
                directory = self.vendor / (name + "-" + version)
                directory.mkdir()
                payloads = {"Cargo.toml": data, "LICENSE": b"fixture MIT grant", "src/lib.rs": b"// inert fixture"}
                hashes = {p: C.digest(d) for p, d in payloads.items()}
                for p, d in payloads.items():
                    output = directory / p
                    output.parent.mkdir(exist_ok=True)
                    output.write_bytes(d)
                (directory / ".cargo-checksum.json").write_bytes(C.canonical({"package": checksum, "files": hashes}))
                rows.append({"name": name, "version": version, "registry": C.REGISTRY, "checksum": "PASS",
                             "archive_sha256": checksum, "source_files_sha256": C.digest(C.canonical(hashes)),
                             "normalized_manifest_sha256": C.digest(data),
                             "license_evidence_blockers": ["missing historical notice"] if name == "objc_id" else []})
            deps = C.declarations(manifest)
            lock_deps = sorted({row["name"] for row in deps})
            rowtext = f'[[package]]\nname="{name}"\nversion="{version}"\n'
            if not is_root:
                rowtext += f'source="{C.REGISTRY}"\nchecksum="{checksum}"\n'
            if lock_deps:
                rowtext += "dependencies=" + json.dumps(lock_deps) + "\n"
            lockrows.append(rowtext)
        self.lock = ("version=4\n" + "\n".join(lockrows)).encode()
        self.audit = C.canonical({"registry_sources": rows, "cargo_lock_sha256": C.digest(self.lock),
                                  "locked_packages": 8, "registry_packages": 7})
        self.pins = {"manifest": C.digest(self.manifest), "lock": C.digest(self.lock), "audit": C.digest(self.audit)}
        packages = []
        for name, manifest in self.manifests.items():
            deps = C.declarations(manifest)
            dependency_rows = [{"name": r["name"], "rename": r["alias"] if r["alias"] != r["name"] else None,
                                "source": C.REGISTRY, "req": C.normalized_req(r["version"]), "kind": r["kind"],
                                "target": r["target"], "optional": r["optional"], "uses_default_features": r["default"],
                                "features": r["features"], "registry": None} for r in deps]
            proc = manifest.get("lib", {}).get("proc-macro", False)
            packages.append({"id": self.ids[name], "name": name, "version": manifest["package"]["version"],
                             "source": None if name == "arch-update-tray" else C.REGISTRY,
                             "manifest_path": "/worker/src/Cargo.toml" if name == "arch-update-tray" else "/vendor/" + name + "/Cargo.toml",
                             "dependencies": dependency_rows, "features": C.features(manifest, deps),
                             "targets": [{"name": manifest.get("lib", {}).get("name", name.replace("-", "_")),
                                          "kind": ["proc-macro" if proc else "lib"]}]})
        self.metadata = {"version": 1, "packages": packages, "workspace_members": ["root"],
                         "workspace_default_members": ["root"], "resolve": {"root": "root", "nodes": []}}
        graph = {"arch-update-tray": [("locale_config", "locale_config", None), ("user_named", "data", None), ("tool", "tool", "build")],
                 "data": [("optional", "optional", None), ("macro", "macro", None)],
                 "tool": [("helper", "helper", None)], "macro": [("helper", "helper", None)],
                 "locale_config": [], "optional": [], "helper": []}
        enabled = {"data": ["default", "derive"], "optional": ["extra"]}
        for name, children in graph.items():
            typed = [{"name": alias, "pkg": self.ids[child], "dep_kinds": [{"kind": kind, "target": None}]}
                     for alias, child, kind in children]
            self.metadata["resolve"]["nodes"].append({"id": self.ids[name], "dependencies": [x["pkg"] for x in typed],
                                                       "deps": typed, "features": enabled.get(name, [])})
        self.worker = {"schema_version": 1, "host": C.TARGET, "target": C.TARGET,
                       "image_id": "sha256:" + "a" * 64, "manifest_path": "/worker/src/Cargo.toml"}
        self.worker["metadata_argv"] = ["/usr/bin/cargo", "metadata", "--format-version", "1", "--offline", "--locked",
                                        "--filter-platform", C.TARGET, "--manifest-path", self.worker["manifest_path"]]

    def refresh_manifest(self, name, text):
        data = text.encode()
        manifest = C.tomllib.loads(text)
        self.manifests[name] = manifest
        package = self.package(name)
        deps = C.declarations(manifest)
        package["features"] = C.features(manifest, deps)
        package["dependencies"] = [{"name": r["name"], "rename": r["alias"] if r["alias"] != r["name"] else None,
                                    "source": C.REGISTRY, "req": C.normalized_req(r["version"]), "kind": r["kind"],
                                    "target": r["target"], "optional": r["optional"], "uses_default_features": r["default"],
                                    "features": r["features"], "registry": None} for r in deps]
        if name == "arch-update-tray":
            self.manifest = data
            self.pins["manifest"] = C.digest(data)
        else:
            directory = self.vendor / (name + "-" + package["version"])
            (directory / "Cargo.toml").write_bytes(data)
            checksum_path = directory / ".cargo-checksum.json"
            checksum = C.load(checksum_path.read_bytes())
            checksum["files"]["Cargo.toml"] = C.digest(data)
            checksum_path.write_bytes(C.canonical(checksum))
            audit = C.load(self.audit)
            row = next(r for r in audit["registry_sources"] if r["name"] == name)
            row["normalized_manifest_sha256"] = C.digest(data)
            row["source_files_sha256"] = C.digest(C.canonical(checksum["files"]))
            self.audit = C.canonical(audit)
            self.pins["audit"] = C.digest(self.audit)

    def node(self, name):
        return next(x for x in self.metadata["resolve"]["nodes"] if x["id"] == self.ids[name])

    def package(self, name):
        return next(x for x in self.metadata["packages"] if x["name"] == name)

    def validate(self):
        data = C.canonical(self.metadata)
        worker = copy.deepcopy(self.worker)
        worker["sha256"] = dict(self.pins, metadata=C.digest(data), cfg=C.digest(CFG))
        return C.validate(data, worker, self.manifest, self.lock, self.audit, CFG, self.vendor,
                          pins=self.pins, expected_count=8)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cachy-linux-closure-test-")
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(Path(self.tmp.name))

    def refused(self, pattern):
        with self.assertRaisesRegex(C.ClosureError, pattern):
            self.f.validate()

    def test_filtered_packages_can_contain_unselected_notice_blocker(self):
        report, sources = self.f.validate()
        self.assertEqual(len(sources), 6)
        self.assertNotIn(("objc_id", "0.1.1"), sources)
        self.assertEqual(report["native_compilation"], "NOT RUN")
        self.assertEqual(report["license_compatibility"], "NOT ACCEPTED")

    def test_build_proc_macro_and_transitive_host_sources_retained(self):
        report, _ = self.f.validate()
        host = {x["name"] for x in report["selected_nodes"] if x["host_dependency"]}
        self.assertEqual(host, {"tool", "macro", "helper"})

    def test_linux_subset_retains_original_evidence_and_inert_data(self):
        report, sources = self.f.validate()
        destination = Path(self.tmp.name) / "result"
        C.retain(destination, report, sources, {"Cargo.lock": self.f.lock, "cargo-audit-all-target.json": self.f.audit})
        self.assertEqual((destination / "Cargo.lock").read_bytes(), self.f.lock)
        self.assertEqual((destination / "cargo-audit-all-target.json").read_bytes(), self.f.audit)
        self.assertFalse(any(p.stat().st_mode & 0o111 for p in destination.rglob("*") if p.is_file()))
        self.assertFalse((destination / "vendor/objc_id-0.1.1").exists())
        with self.assertRaisesRegex(C.ClosureError, "exist"):
            C.retain(destination, report, sources, {})

    def test_missing_resolve(self):
        self.f.metadata["resolve"] = None
        self.refused("missing resolve")

    def test_missing_node(self):
        self.f.metadata["resolve"]["nodes"] = [n for n in self.f.metadata["resolve"]["nodes"] if n["id"] != self.f.ids["tool"]]
        self.refused("missing node")

    def test_extra_unreachable_node(self):
        self.f.metadata["resolve"]["nodes"].append({"id": self.f.ids["objc_id"], "dependencies": [], "deps": [], "features": []})
        self.refused("unreachable")

    def test_missing_edge(self):
        node = self.f.node("arch-update-tray")
        node["deps"] = node["deps"][:-1]
        node["dependencies"] = node["dependencies"][:-1]
        self.refused("missing active|unreachable")

    def test_legacy_edge_disagreement(self):
        self.f.node("arch-update-tray")["dependencies"].pop()
        self.refused("disagreement")

    def test_wrong_dependency_kind(self):
        self.f.node("arch-update-tray")["deps"][-1]["dep_kinds"][0]["kind"] = None
        self.refused("extra/ambiguous")

    def test_wrong_target_platform(self):
        self.f.node("arch-update-tray")["deps"][0]["dep_kinds"][0]["target"] = "cfg(windows)"
        self.refused("extra/ambiguous")

    def test_selected_historical_notice_blocker_refused(self):
        node = self.f.node("locale_config")
        node["dependencies"] = [self.f.ids["objc_id"]]
        node["deps"] = [{"name": "objc_id", "pkg": self.f.ids["objc_id"],
                         "dep_kinds": [{"kind": None, "target": 'cfg(target_os = "macos")'}]}]
        self.f.metadata["resolve"]["nodes"].append({"id": self.f.ids["objc_id"], "dependencies": [], "deps": [], "features": []})
        self.refused("historical notice")

    def test_unknown_unreachable_source_refused(self):
        self.f.package("objc_id")["source"] = "git+https://bad.example/"
        self.refused("source drift")

    def test_duplicate_package(self):
        self.f.metadata["packages"].append(copy.deepcopy(self.f.package("data")))
        self.refused("duplicate")

    def test_duplicate_kind(self):
        edge = self.f.node("arch-update-tray")["deps"][0]
        edge["dep_kinds"].append(copy.deepcopy(edge["dep_kinds"][0]))
        self.refused("duplicate edge")

    def test_feature_declaration_drift(self):
        self.f.package("data")["features"]["surprise"] = []
        self.refused("feature declaration drift")

    def test_missing_feature_forwarding(self):
        self.f.node("optional")["features"] = []
        self.refused("feature activation")

    def test_unknown_selected_feature(self):
        self.f.node("data")["features"].append("surprise")
        self.refused("unknown selected")

    def test_host_cross_build_refused(self):
        self.f.worker["host"] = "x86_64-unknown-linux-gnu"
        self.refused("native host")

    def test_changed_command_features_refused(self):
        self.f.worker["metadata_argv"].extend(["--all-features"])
        self.refused("wrong metadata command")

    def test_checksum_ledger_pin_refused(self):
        self.f.audit += b" "
        self.refused("pin mismatch")

    def test_vendor_extra_file_refused(self):
        (self.f.vendor / "data-1.0.0/extra").write_text("unlocked input")
        self.refused("extra drift")

    def test_vendor_missing_file_refused(self):
        (self.f.vendor / "data-1.0.0/LICENSE").unlink()
        self.refused("missing vendor")

    def test_vendor_changed_file_refused(self):
        (self.f.vendor / "data-1.0.0/LICENSE").write_text("changed")
        self.refused("hash/extra")

    def test_vendor_hardlink_refused(self):
        path = self.f.vendor / "data-1.0.0/LICENSE"
        os.link(path, Path(self.tmp.name) / "linked")
        self.refused("hardlinked")

    def test_vendor_symlink_refused(self):
        path = self.f.vendor / "data-1.0.0/LICENSE"
        path.unlink()
        path.symlink_to("Cargo.toml")
        self.refused("symlink")

    def test_duplicate_json_key_refused(self):
        with self.assertRaisesRegex(C.ClosureError, "duplicate JSON"):
            C.load(b'{"resolve":null,"resolve":{}}')

    def test_cfg_nested_and_negative_platforms(self):
        values = C.cfg_values(CFG.decode())
        self.assertTrue(C.platform('cfg(all(unix,not(windows),any(target_os="linux",target_os="macos")))', values))
        self.assertFalse(C.platform('cfg(target_os = "macos")', values))
        self.assertFalse(C.platform("cfg(any())", values))
        self.assertFalse(C.platform("x86_64-unknown-linux-gnu", values))
        with self.assertRaises(C.ClosureError):
            C.platform("cfg(feature=\"extra\")", values)

    def test_unexpected_build_target_refused(self):
        self.f.package("tool")["targets"].append({"name": "build-script-build", "kind": ["custom-build"]})
        self.refused("build script target drift")

    def test_missing_build_target_refused(self):
        audit = C.load(self.f.audit)
        row = next(x for x in audit["registry_sources"] if x["name"] == "tool")
        row["build_scripts"] = [{"path": "src/lib.rs", "sha256": C.digest(b"// inert fixture")}]
        self.f.audit = C.canonical(audit)
        self.f.pins["audit"] = C.digest(self.f.audit)
        self.refused("build script target drift")

    def test_invalid_cfg_refused(self):
        for predicate in ("cfg(", "cfg(unix", "cfg(all(unix)", "cfg(unknown(unix))", "cfg(not(unix,windows))"):
            with self.subTest(predicate=predicate), self.assertRaises(C.ClosureError):
                C.platform(predicate, C.cfg_values(CFG.decode()))
        with self.assertRaisesRegex(C.ClosureError, "wrong native"):
            C.cfg_values(CFG.decode().replace('target_arch="aarch64"', 'target_arch="x86_64"'))

    def test_worker_metadata_hash_not_self_declared_pass(self):
        data = C.canonical(self.f.metadata)
        record = copy.deepcopy(self.f.worker)
        record["sha256"] = dict(self.f.pins, metadata="0" * 64, cfg=C.digest(CFG))
        with self.assertRaisesRegex(C.ClosureError, "hash binding"):
            C.validate(data, record, self.f.manifest, self.f.lock, self.f.audit, CFG, self.f.vendor,
                       pins=self.f.pins, expected_count=8)

    def test_wrong_selected_version_refused(self):
        self.assertFalse(C.version_matches("2.0.0", "1"))
        self.f.package("data")["version"] = "2.0.0"
        self.refused("outside original lock")

    def test_cargo_cfg_whitespace_normalization(self):
        self.f.package("locale_config")["dependencies"][0]["target"] = 'cfg(target_os="macos")'
        self.f.validate()
        with self.assertRaisesRegex(C.ClosureError, "invalid cfg"):
            C.canonical_platform('cfg(unix)#')

    def test_inactive_declared_kind_on_surviving_edge(self):
        text = self.f.manifest.decode() + '[target.\'cfg(target_os="macos")\'.dependencies]\nuser-named={package="data",version="1"}\n'
        self.f.refresh_manifest("arch-update-tray", text)
        edge = next(e for e in self.f.node("arch-update-tray")["deps"] if e["pkg"] == self.f.ids["data"])
        edge["dep_kinds"].append({"kind": None, "target": 'cfg(target_os = "macos")'})
        report, _ = self.f.validate()
        inactive = [e for e in report["selected_edges"] if e["target"] == 'cfg(target_os = "macos")']
        self.assertEqual(len(inactive), 1)
        self.assertFalse(inactive[0]["platform_active"])
        self.assertFalse(inactive[0]["feature_active"])

    def test_conservative_optional_metadata_edge_not_compile_activation(self):
        path = self.f.vendor / 'tool-1.0.0/Cargo.toml'
        text = path.read_text().replace('helper="1"', 'helper={version="1",optional=true}')
        self.f.refresh_manifest("tool", text)
        report, _ = self.f.validate()
        edges = [e for e in report["selected_edges"] if e["from"] == self.f.ids["tool"]]
        self.assertEqual(len(edges), 1)
        self.assertTrue(edges[0]["platform_active"])
        self.assertFalse(edges[0]["feature_active"])
        self.assertEqual(report["native_compilation"], "NOT RUN")

    def supplemental_fixture(self):
        key = ("defmt-parser", "1.0.0")
        files = {"Cargo.toml": b"fixture pinned manifest", "README.md": b"fixture declared grant"}
        notices = Path(self.tmp.name) / "notices"
        (notices / key[0]).mkdir(parents=True)
        text = b"fixture full notice bytes"
        (notices / key[0] / "LICENSE-MIT").write_bytes(text)
        row = {"archive_sha256": "a" * 64, "declared_spdx": "MIT OR Apache-2.0",
               "normalized_manifest_sha256": C.digest(files["Cargo.toml"])}
        entry = {"name": key[0], "version": key[1], "notice_status": "COMPLETE SOURCE EVIDENCE", "blockers": [],
                 "registry_source_archive_sha256": row["archive_sha256"], "declared_spdx": row["declared_spdx"],
                 "retained_declarations": [{"path": path, "sha256": C.digest(data)} for path, data in files.items()],
                 "source_comparison": {"different_source_bytes": [], "missing_source_paths": [],
                       "manifest": {"registry_manifest_sha256": row["normalized_manifest_sha256"],
                                    "version_matches": True, "declared_license_matches": True}},
                 "notices": [{"upstream_path": "LICENSE-MIT", "sha256": C.digest(text), "bytes": len(text)}]}
        entries = [entry] + [{"name": n, "version": v, "notice_status": "COMPLETE SOURCE EVIDENCE"}
                             for n, v in C.SUPPLEMENTAL_ALLOWED - {key}]
        data = C.canonical({"cargo_lock_sha256": C.PINS["lock"], "entries": entries})
        return key, row, files, data, notices

    def test_supplemental_notice_requires_pinned_source_and_actual_bytes(self):
        key, row, files, data, notices = self.supplemental_fixture()
        result = C.supplemental_notice(key, row, files, data, notices, pin=C.digest(data))
        self.assertEqual(result[0]["sha256"], C.digest(b"fixture full notice bytes"))
        with self.assertRaisesRegex(C.ClosureError, "pin mismatch"):
            C.supplemental_notice(key, row, files, data, notices)
        (notices / key[0] / "LICENSE-MIT").write_bytes(b"altered")
        with self.assertRaisesRegex(C.ClosureError, "bytes drift"):
            C.supplemental_notice(key, row, files, data, notices, pin=C.digest(data))

    def test_supplemental_does_not_invent_grants_or_relicense_other_sources(self):
        key, row, files, data, notices = self.supplemental_fixture()
        with self.assertRaisesRegex(C.ClosureError, "evidence missing"):
            C.supplemental_notice(("objc_id", "0.1.1"), row, files, data, notices, pin=C.digest(data))
        row["archive_sha256"] = "b" * 64
        with self.assertRaisesRegex(C.ClosureError, "source/license binding"):
            C.supplemental_notice(key, row, files, data, notices, pin=C.digest(data))

    def test_semver_constraints(self):
        for version, req, result in [("0.61.2", ">=0.52, <0.62", True), ("0.62.0", ">=0.52, <0.62", False),
                                     ("1.2.3", "1.2", True), ("2.0.0", "1.2", False), ("0.3.2", "~0.3", True),
                                     ("0.4.0", "~0.3", False), ("0.0.6", "^0.0.6", True), ("0.0.7", "^0.0.6", False),
                                     ("0.61.2", "<=0.61.*", True), ("1.1.6+spec-1.1.0", "1.1", True)]:
            with self.subTest(version=version, req=req):
                self.assertEqual(C.version_matches(version, req), result)
        with self.assertRaisesRegex(C.ClosureError, "unreviewed"):
            C.version_matches("0.1.0-beta.1", "=0.1.0-beta.1")


if __name__ == "__main__":
    unittest.main()
