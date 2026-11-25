#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Synthetic unit/integration tests. No native build or hardware evidence."""
import argparse
import base64
import copy
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class RepoAddCapabilityTests(unittest.TestCase):
    def test_known_versions_and_advertised_option_construct_one_command(self):
        for version, help_text, include in [
                (b"6.0.2", b"  --sign\n", False),
                (b"6.0.2", b"  --include-sigs  include signatures\n", True),
                (b"6.0.2", b"  --include-sigs-foreign\n", False),
                (b"6.1.0", b"  --sign\n", True),
                (b"7.0.0", b"  --sign\n", True),
                (b"7.1.0", b"  --sign\n", True),
                (b"7.1.0.r9.g54d9411", b"  --include-sigs\n", True)]:
            with self.subTest(version=version, help=help_text):
                env = {"GNUPGHOME": "fixture", "LC_ALL": "fixture"}
                with mock.patch.object(r, "run", side_effect=[b"repo-add (pacman) " + version + b"\n", help_text, b""]) as run:
                    r.add_database("fixture.db.tar.gz", ["fixture.pkg.tar.gz"], "fixture-key", env)
                expected = ["repo-add", *(["--include-sigs"] if include else []), "--sign", "--key",
                            "fixture-key", "fixture.db.tar.gz", "fixture.pkg.tar.gz"]
                self.assertEqual(run.call_args_list, [
                    mock.call(["repo-add", "--version"], env={**env, "LC_ALL": "C"}),
                    mock.call(["repo-add", "--help"], env={**env, "LC_ALL": "C"}),
                    mock.call(expected, env=env)])

    def test_unknown_version_refuses_before_database_command(self):
        for version in (b"", b"repo-add (pacman) unknown\n", b"repo-add (pacman) 8.0.0\n",
                        b"foreign-tool 6.0.2\n", b"repo-add (pacman) 6.0\n"):
            with self.subTest(version=version), mock.patch.object(r, "run", return_value=version) as run:
                with self.assertRaises(r.Error):r.add_database("fixture.db.tar.gz", [], "key", {})
                self.assertEqual(run.call_count, 1)

    def test_probe_and_database_errors_preserve_first_error_without_retry(self):
        for preceding in ([], [b"repo-add (pacman) 6.0.2\n"],
                          [b"repo-add (pacman) 7.1.0\n", b"  --sign\n"]):
            error = r.Error("first command failure")
            with self.subTest(phase=len(preceding)), mock.patch.object(r, "run", side_effect=[*preceding, error]) as run:
                with self.assertRaises(r.Error) as caught:r.add_database("fixture.db.tar.gz", [], "key", {})
                self.assertIs(caught.exception, error)
                self.assertEqual(run.call_count, len(preceding) + 1)


@unittest.skipUnless(shutil.which("bsdtar"), "bsdtar is required")
class DatabaseDescriptorTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.database = Path(work.name) / "fixture.db.tar.gz"

    def archive(self, entries, mode="w:"):
        with tarfile.open(self.database, mode) as archive:
            for name, kind, data in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                    member.linkname = "fixture-1-1/files"
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def test_tar_compressions_keep_exact_descriptor_bytes_and_order(self):
        long_name = "a" * 120 + "-2:1-1/desc"
        rows = [(long_name, tarfile.REGTYPE, b"first\r\n" * 180),
                ("./fixture-1-1/", tarfile.DIRTYPE, b""),
                ("./fixture-1-1/files", tarfile.REGTYPE, b"ignored"),
                ("./fixture-1-1/desc", tarfile.REGTYPE, b"second\n")]
        expected = [(long_name, rows[0][2]), ("fixture-1-1/desc", rows[-1][2])]
        for mode, option in (("w:", None), ("w:gz", None), ("w:bz2", None), ("w:xz", None),
                             ("w:", "--zstd"), ("w:", "-Z")):
            with self.subTest(mode=mode, option=option):
                self.archive(rows, mode)
                if option:
                    original = self.database.with_suffix(".tar")
                    self.database.replace(original)
                    r.run(["bsdtar", "-cf", self.database, option, f"@{original}"])
                original_reads = [(name, r.run(["bsdtar", "-xOf", self.database, member]))
                                  for name, member in r.archive_members(self.database).items()
                                  if name.endswith("/desc")]
                self.assertEqual(original_reads, expected)
                self.assertEqual(list(r.database_descriptors(self.database)), expected)

    def test_rejects_unsafe_duplicate_and_out_of_order_members(self):
        first = ("fixture-1-1/desc", tarfile.REGTYPE, b"fixture")
        for name, error in (("../outside/files", "unsafe archive entry"),
                            ("fixture-1-1//desc", "unsafe archive entry"),
                            ("./fixture-1-1/desc", "duplicate archive entries")):
            with self.subTest(name=name):
                self.archive([first, (name, tarfile.REGTYPE, b"other")])
                with self.assertRaisesRegex(r.Error, error):
                    list(r.database_descriptors(self.database))
        self.archive([first, ("other-1-1/desc", tarfile.REGTYPE, b"other")])
        listed = r.archive_members(self.database)
        with mock.patch.object(r, "archive_members", return_value=dict(reversed(listed.items()))):
            with self.assertRaisesRegex(r.Error, "descriptor members changed or out of order"):
                list(r.database_descriptors(self.database))
        with mock.patch.object(r, "archive_members", return_value={**listed, "absent/desc": "absent/desc"}):
            with self.assertRaisesRegex(r.Error, "descriptor members missing"):
                list(r.database_descriptors(self.database))
        with self.assertRaisesRegex(r.Error, "repository database package count mismatch"):
            r.database_check(self.database.parent, "fixture", [])

    def test_rejects_non_regular_and_truncated_descriptors(self):
        name = "fixture-1-1/desc"
        for kind in (tarfile.DIRTYPE, tarfile.LNKTYPE, tarfile.SYMTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                self.archive([("fixture-1-1/files", tarfile.REGTYPE, b"fixture"), (name, kind, b"")])
                with self.assertRaisesRegex(r.Error, "descriptor is not a regular file"):
                    list(r.database_descriptors(self.database))
        member = tarfile.TarInfo(name)
        member.size = 4096
        self.database.write_bytes(member.tobuf() + b"short")
        with self.assertRaises(r.Error):
            list(r.database_descriptors(self.database))


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [x for x in ("gpg", "gpgconf", "repo-add", "bsdtar", "vercmp") if not shutil.which(x)]
        if missing:
            raise unittest.SkipTest(f"installed system tools unavailable: {missing}")
        cls.key_temp = tempfile.TemporaryDirectory(prefix="synthetic-release-gpg-")
        cls.home = Path(cls.key_temp.name)
        cls.home.chmod(0o700)
        env = dict(os.environ, GNUPGHOME=str(cls.home))
        r.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
               "Synthetic release test <fixture@invalid>", "ed25519", "sign", "1d"], env=env)
        listing = r.run(["gpg", "--batch", "--with-colons", "--list-keys"], env=env).decode()
        cls.key = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "key_temp"):
            subprocess.run(["gpgconf", "--homedir", str(cls.home), "--kill", "all"], capture_output=True)
            cls.key_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-release-case-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.root = self.base / "repository"
        self.root.mkdir()
        self.env = r.gpg_env(self.home, self.root)
        self.archive = self.inputs / "fixture-1.0-1-any.pkg.tar.gz"
        metadata = "\n".join(["pkgname = fixture", "pkgver = 1.0-1", "pkgdesc = Synthetic fixture",
                              "url = https://invalid.example/fixture", "builddate = 1700000000",
                              "packager = Synthetic test", "size = 8", "arch = any", "license = MIT",
                              "depend = virtual-runtime>=2"]) + "\n"
        with tarfile.open(self.archive, "w:gz") as tar:
            for name, data in {".PKGINFO": metadata.encode(), "usr/share/fixture/config": b"fixture\n"}.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        self.digest = r.sha(self.archive)
        base = {"schema_version": 1, "snapshot_id": "synthetic-snapshot", "target_arch": "aarch64",
                "kind": "complete-target-transaction", "packages": [
                    {"name": "linux-asahi", "version": "1", "arch": "aarch64", "depend": [],
                     "provides": [], "conflict": [], "files": ["boot/asahi-fixture"]},
                    {"name": "runtime", "version": "2", "arch": "aarch64", "depend": [],
                     "provides": ["virtual-runtime=2"], "conflict": [], "files": ["usr/lib/fixture.so"]}]}
        self.put("base.json", base)
        self.put("provenance.json", {"schema_version": 1, "artifact_sha256": self.digest,
             "package": {"name": "fixture", "version": "1.0-1", "arch": "any"},
             "source_commit": "a" * 40, "recipe_sha256": "b" * 64, "licenses": ["MIT"],
             "sources": [{"url": "https://invalid.example/source", "sha256": "c" * 64}],
             "build": {"execution": "synthetic", "architecture": "aarch64", "environment": "synthetic-fixture",
                       "snapshot_id": "synthetic-snapshot"}})
        (self.inputs / "LICENSE.fixture").write_text("Synthetic license fixture; not a project license selection.\n")
        self.release_spec = {"schema_version": 1, "release_id": "fixture-1", "synthetic": True,
            "target_arch": "aarch64", "repo_name": "fixture", "source_commit": "a" * 40,
            "base": dict(self.ref("base.json"), snapshot_id="synthetic-snapshot"),
            "packages": [{"artifact": self.ref(self.archive.name), "provenance": self.ref("provenance.json")}],
            "policy": {"supported_models": ["m2-air-13"], "selected_packages": ["fixture"],
                       "protected_packages": ["linux-asahi"],
                       "coordinated_sets": [{"name": "synthetic-runtime", "versions": {"runtime": "2"}}]},
            "project_license": dict(self.ref("LICENSE.fixture"), spdx="MIT"), "evidence": []}
        self.spec_path = self.inputs / "spec.json"
        self.save_spec()

    def put(self, name, value):
        r.write(self.inputs / name, value)

    def ref(self, name):
        return {"path": name, "sha256": r.sha(self.inputs / name)}

    def save_spec(self):
        self.put("spec.json", self.release_spec)

    def stage(self):
        self.save_spec()
        result = r.stage(argparse.Namespace(spec=str(self.spec_path)), self.root, self.key, self.env)
        self.directory = Path(result["path"])
        return result

    def verify(self):
        return r.verify_release(self.directory, self.key, self.env)

    def complete_modeled_evidence(self):
        """Model schema completion only. These records are fabricated test inputs."""
        build_snapshot = r.load(self.inputs / "provenance.json")["build"]["snapshot_id"]
        def add(eid, value):
            if isinstance(value, str):
                (self.inputs / eid).write_text(value)
            else:
                self.put(eid, value)
            self.release_spec["evidence"].append(dict(self.ref(eid), id=eid))
        for eid in ("build-1.log", "build-2.log", "inspect.txt", "hardware.log", "baseline.txt", "repro.log", "previous.json"):
            add(eid, "SYNTHETIC TEST DATA; no commands executed on a native builder or M2.\n")
        shutil.copyfile(self.archive, self.inputs / "second.pkg.tar.gz")
        self.release_spec["evidence"].append(dict(self.ref("second.pkg.tar.gz"), id="second.pkg.tar.gz"))
        add("lock.json", {"schema_version": 1, "snapshot_id": build_snapshot,
            "packages": [{"name": "runtime", "version": "2", "sha256": "d" * 64}],
            "retrievable_inputs": [{"uri": "fixture://synthetic", "sha256": "e" * 64}]})
        add("contract.json", {"sleep_wake_repetitions": 3})
        add("packages.lock", "runtime 2\n")
        add("PKGBUILD.fixture", "# Synthetic fixture recipe; no build executed.\n")
        add("validation.json", {"artifacts": [], "errors": [], "synthetic": True})
        add("machine.json", {"model": "m2-air-13", "machine_id": "synthetic-machine", "soc": "M2",
            "execution": "physical", "base_sha256": self.release_spec["base"]["sha256"],
            "package_sha256": {"fixture": self.digest}, "platform_versions": {"kernel": "synthetic"},
            "baseline": "baseline.txt", "acceptance_contract": "contract.json"})
        provenance = r.load(self.inputs / "provenance.json")
        provenance["build"]["execution"] = "native"  # fabricated schema-test assertion
        provenance["recipe_sha256"] = r.sha(self.inputs / "PKGBUILD.fixture")
        self.put("provenance.json", provenance)
        self.release_spec["packages"][0]["provenance"] = self.ref("provenance.json")
        records = []
        def record(kind, logs, **kw):
            records.append(dict(kind=kind, result="PASS", operator="synthetic-test", date_utc="2026-10-11",
                                commands=["synthetic modeled command; NOT RUN"], logs=logs, **kw))
        for n in (1, 2):
            add(f"build-{n}.json", {"schema_version": 1, "status": "built-package-static-pass", "mode": "native",
                "builder_host_arch": "aarch64", "image": "sha256:" + "f" * 64, "image_id": "sha256:" + "f" * 64,
                "clean_environment_id": f"synthetic-clean-{n}", "exit_code": 0,
                "command": ["synthetic-builder", "NOT-RUN"],
                "artifacts": {self.archive.name: self.digest},
                "recipe_inputs": {"PKGBUILD": r.sha(self.inputs / "PKGBUILD.fixture")},
                "files": {"build.log": r.sha(self.inputs / f"build-{n}.log"),
                          "validation.json": r.sha(self.inputs / "validation.json"),
                          f"artifacts/{self.archive.name}": self.digest},
                "expected_packages_sha256": r.sha(self.inputs / "packages.lock")})
            record("native-build", [f"build-{n}.log"], package="fixture", attempt=n, execution="native",
                   architecture="aarch64", artifact_sha256=self.digest, snapshot_id=build_snapshot,
                   environment_digest="sha256:" + "f" * 64, clean_environment_id=f"synthetic-clean-{n}",
                   dependency_lock="lock.json", build_record=f"build-{n}.json", builder_package_lock="packages.lock",
                   file_bindings={"build.log": f"build-{n}.log", "validation.json": "validation.json",
                                  f"artifacts/{self.archive.name}": "second.pkg.tar.gz"},
                   recipe_bindings={"PKGBUILD": "PKGBUILD.fixture"})
        record("release-review", ["inspect.txt"], custodian="synthetic-custodian", alternate_custodian="synthetic-alternate",
               hardware_owner="synthetic-hardware-owner", release_notes="inspect.txt", retained_base_inputs="lock.json",
               recovery_plan="inspect.txt", license_review="inspect.txt")
        record("package-review", ["inspect.txt"], package="fixture", inspection_report="inspect.txt",
               checks={k: "PASS" for k in ("licenses", "source-pins", "files-ownership", "hooks", "config-preservation", "protected-platform", "16k-pages")})
        records[-1]["operator"] = "synthetic-independent-reviewer"
        record("reproducibility", ["repro.log"], package="fixture", method="byte-identical",
               artifact_sha256=[self.digest, self.digest], second_artifact="second.pkg.tar.gz")
        for kind, checks in (("functional", r.FUNCTIONAL), ("install-removal", r.LIFECYCLE), ("upgrade-recovery", r.RECOVERY)):
            extra = {"sleep_wake_completed": 3} if kind == "functional" else {}
            if kind == "upgrade-recovery":
                extra.update(previous_release_id="fixture-0", previous_release_record="previous.json")
            record(kind, ["hardware.log"], model="m2-air-13", machine_id="synthetic-machine", machine_record="machine.json",
                   checks={c: {"result": "PASS", "evidence": "hardware.log"} for c in checks}, **extra)
        return {"schema_version": 1, "release_id": "fixture-1", "synthetic": True, "source_commit": "a" * 40,
            "base_sha256": self.release_spec["base"]["sha256"], "project_license_sha256": self.release_spec["project_license"]["sha256"],
            "package_sha256": {"fixture": self.digest}, "records": records}

    def source_delivery_fixture(self):
        """Tiny original source/materials; attestation is synthetic, never a legal grant."""
        source = self.inputs / 'source-inputs'; source.mkdir()
        recipe = b'# Original synthetic fixture recipe; no build executed.\n'
        (source / 'PKGBUILD.fixture').write_bytes(recipe)
        (source / 'NOTICE.fixture').write_bytes(b'Original synthetic MIT notice; fixture only.\n')
        code = b'/* Original synthetic source; never compiled. */\n'
        with tarfile.open(source / 'fixture-source.tar.gz', 'w:gz') as archive:
            item = tarfile.TarInfo('fixture/source.c'); item.size = len(code)
            archive.addfile(item, io.BytesIO(code))
        r.write(source / 'source-map.json', {'PKGBUILD': r.sha(source / 'PKGBUILD.fixture'),
                                          'src/source.c': hashlib.sha256(code).hexdigest()})
        def material(name, eid):
            path = source / name
            return dict(id=eid, path='source-inputs/' + name, sha256=r.sha(path), bytes=path.stat().st_size)
        package = dict(name='fixture', version='1.0-1', arch='any', sha256=self.digest)
        record = dict(package=package, review_status='REVIEWED_SOURCE_ONLY',
                      bundle=material('fixture-source.tar.gz', 'fixture-source.tar.gz'),
                      notices=[material('NOTICE.fixture', 'fixture-NOTICE')],
                      source_map=material('source-map.json', 'fixture-source-map.json'),
                      recipe=material('PKGBUILD.fixture', 'fixture-PKGBUILD'), recipe_key='PKGBUILD')
        # Reuse opaque existing review data; do not mint a new approval boolean/schema.
        (source / 'package-review.txt').write_bytes(
            b'Existing synthetic package review: REVIEWED_SOURCE_ONLY. No real completeness or legal result.\n')
        record['authorization'] = material('package-review.txt', 'fixture-package-review.txt')
        self.source_index = dict(schema_version=1, purpose='release-source-delivery', synthetic=True, packages=[record])
        self.source_record = record
        self.save_source_index()
        provenance = r.load(self.inputs / 'provenance.json')
        provenance['recipe_sha256'] = record['recipe']['sha256']
        self.put('provenance.json', provenance)
        self.release_spec['packages'][0]['provenance'] = self.ref('provenance.json')
        return record

    def save_source_index(self):
        self.put('source-delivery-v1.json', self.source_index)
        self.release_spec['source_delivery'] = dict(schema_version=1,
            index=dict(id='source-delivery-v1.json', **self.ref('source-delivery-v1.json')))

    def test_source_delivery_assembles_stages_and_verifies_retained_materials(self):
        record = self.source_delivery_fixture()
        result = self.stage()
        manifest, spec = self.verify()
        self.assertEqual(result['source_delivery'], 'CHECKED_DECLARED_ASSOCIATIONS')
        self.assertFalse(result['source_completeness_accepted'])
        ids = {m['id'] for m in [record['bundle'], *record['notices'], record['source_map'], record['recipe'], record['authorization']]}
        self.assertEqual({x['id'] for x in spec['evidence']}, ids | {'source-delivery-v1.json'})
        for material in [record['bundle'], *record['notices'], record['source_map'], record['recipe'], record['authorization']]:
            retained = self.directory / 'evidence' / material['id']
            self.assertEqual(retained.read_bytes(), (self.inputs / material['path']).read_bytes())
            self.assertEqual(manifest['files']['evidence/' + material['id']], material['sha256'])
        self.assertNotIn('release_sha256', r.load(self.directory / 'evidence/source-delivery-v1.json'))

    def test_source_delivery_missing_input_stops_before_signing(self):
        record = self.source_delivery_fixture()
        (self.inputs / record['bundle']['path']).unlink()
        with mock.patch.object(r, 'sign') as sign, self.assertRaises((r.Error, ValueError, OSError)):
            self.stage()
        sign.assert_not_called()
        self.assertFalse((self.root / 'staging/fixture-1').exists())

    def test_source_delivery_complete_identity_and_duplicate_set_required_before_signing(self):
        self.source_delivery_fixture()
        original = copy.deepcopy(self.source_index)
        cases = [[], [copy.deepcopy(original['packages'][0]), copy.deepcopy(original['packages'][0])]]
        for field, value in [('name', 'foreign'), ('version', '2-1'), ('arch', 'aarch64'), ('sha256', 'f'*64)]:
            row = copy.deepcopy(original['packages'][0]); row['package'][field] = value; cases.append([row])
        for rows in cases:
            self.source_index = {**original, 'packages':rows}; self.save_source_index()
            with self.subTest(rows=rows), mock.patch.object(r, 'sign') as sign, self.assertRaises((r.Error, ValueError)):
                self.stage()
            sign.assert_not_called()
            self.assertFalse((self.root / 'staging/fixture-1').exists())

    def test_source_delivery_recipe_must_join_existing_provenance(self):
        self.source_delivery_fixture()
        provenance = r.load(self.inputs / 'provenance.json'); provenance['recipe_sha256'] = 'b'*64
        self.put('provenance.json', provenance)
        self.release_spec['packages'][0]['provenance'] = self.ref('provenance.json')
        with mock.patch.object(r, 'sign') as sign, self.assertRaises((r.Error, ValueError)):
            self.stage()
        sign.assert_not_called()

    def test_source_delivery_resigned_payload_still_requires_recipe_map_binding(self):
        record = self.source_delivery_fixture(); self.stage()
        recipe = self.directory / 'evidence' / record['recipe']['id']
        recipe.write_bytes(b'# Different synthetic recipe outside the existing source map.\n')
        index_path = self.directory / 'evidence/source-delivery-v1.json'
        index = r.load(index_path); index['packages'][0]['recipe'].update(sha256=r.sha(recipe), bytes=recipe.stat().st_size)
        r.write(index_path, index)
        spec = r.load(self.directory / 'spec.json')
        for item in spec['evidence']:
            if item['id'] == record['recipe']['id']: item['sha256'] = r.sha(recipe)
            if item['id'] == 'source-delivery-v1.json': item['sha256'] = r.sha(index_path)
        spec['source_delivery']['index']['sha256'] = r.sha(index_path)
        r.write(self.directory / 'spec.json', spec)
        manifest = r.load(self.directory / 'release.json'); manifest['files'] = r.payload_files(self.directory)
        r.write(self.directory / 'release.json', manifest)
        (self.directory / 'release.json.sig').unlink()  # Replace only this owned synthetic signature.
        r.sign(self.directory / 'release.json', self.key, self.env)
        with self.assertRaisesRegex(r.Error, 'source delivery'):
            self.verify()

    def test_source_delivery_retains_incomplete_existing_review_without_approval_claim(self):
        self.source_delivery_fixture()
        self.source_index['packages'][0]['review_status'] = 'INCOMPLETE'
        self.save_source_index()
        result = self.stage()
        self.verify()
        self.assertFalse(result['source_completeness_accepted'])
        index = r.load(self.directory / 'evidence/source-delivery-v1.json')
        self.assertEqual(index['packages'][0]['review_status'], 'INCOMPLETE')
        self.assertIn(b'Existing synthetic package review',
                      (self.directory / 'evidence/fixture-package-review.txt').read_bytes())

    def test_signed_stage_and_verify(self):
        result = self.stage()
        self.assertEqual(result["status"], "local-staging")
        self.assertEqual(result["source_delivery"], "NOT_DECLARED")
        self.assertFalse(result["source_completeness_accepted"])
        self.verify()
        self.assertTrue((self.directory / "repo/fixture.db").is_symlink())
        self.assertTrue((self.directory / "repo/fixture.files.tar.gz.sig").is_file())

    def test_builder_snapshot_is_independent_and_build_evidence_stays_bound(self):
        provenance = r.load(self.inputs / "provenance.json")
        provenance["build"]["snapshot_id"] = "synthetic-builder-341"
        self.put("provenance.json", provenance)
        self.release_spec["packages"][0]["provenance"] = self.ref("provenance.json")
        gates = self.complete_modeled_evidence()
        wrong_lock = r.load(self.inputs / "lock.json")
        wrong_lock["snapshot_id"] = self.release_spec["base"]["snapshot_id"]
        self.put("wrong-lock.json", wrong_lock)
        self.release_spec["evidence"].append(dict(self.ref("wrong-lock.json"), id="wrong-lock.json"))
        self.stage()
        manifest, specification = self.verify()
        self.assertEqual(specification["base"]["snapshot_id"], "synthetic-snapshot")
        self.assertEqual(r.load(self.directory / manifest["packages"][0]["provenance"])["build"]["snapshot_id"],
                         "synthetic-builder-341")
        gates["release_sha256"] = r.sha(self.directory / "release.json")
        # Fabricated gate inputs exercise matching only; the signed fixture stays synthetic.
        specification["synthetic"] = gates["synthetic"] = False
        gate_path = self.inputs / "gates.json"
        r.write(gate_path, gates)
        r.gates_check(self.directory, manifest, specification, gate_path)
        for field, value, error in (("snapshot_id", "synthetic-snapshot", "build checksum/snapshot"),
                                    ("dependency_lock", "wrong-lock.json", "dependency lock/input")):
            changed = copy.deepcopy(gates)
            next(row for row in changed["records"] if row["kind"] == "native-build")[field] = value
            r.write(gate_path, changed)
            with self.subTest(field=field), self.assertRaisesRegex(r.Error, error):
                r.gates_check(self.directory, manifest, specification, gate_path)

    def test_signed_package_digest_must_match_the_observed_archive_digest(self):
        self.stage()
        document = self.directory / "release.json"
        manifest = r.load(document)
        package = manifest["packages"][0]
        name = f"repo/{package['filename']}"
        self.assertEqual(manifest["files"][name], package["sha256"])
        # Model an observed archive with a different digest while keeping the
        # test package, its signature and its build provenance intact.
        manifest["files"][name] = "0" * 64
        r.write(document, manifest)
        document.with_suffix(".json.sig").unlink()
        r.sign(document, self.key, self.env)
        with mock.patch.object(r, "payload_files", return_value=manifest["files"]):
            with self.assertRaisesRegex(r.Error, "artifact digest differs from signed file map"):
                self.verify()

    def test_resigned_database_requires_exact_detached_package_signature(self):
        self.stage()
        db = self.directory / "repo/fixture.db.tar.gz"
        original = db.read_bytes()
        package = self.directory / "repo" / self.archive.name
        expected = base64.b64encode(Path(str(package) + ".sig").read_bytes()).decode("ascii")
        # A real, valid signature of different material still cannot identify this package.
        foreign = base64.b64encode(Path(str(db) + ".sig").read_bytes()).decode("ascii")
        self.assertNotEqual(expected, foreign)
        variants = {"missing": "", "changed": base64.b64encode(b"altered detached signature").decode("ascii"),
                    "foreign-valid": foreign, "duplicate": expected + "\n" + expected}
        for name, value in variants.items():
            with self.subTest(variant=name):
                with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as source:
                    rows = [(member, source.extractfile(member).read() if member.isfile() else None)
                            for member in source.getmembers()]
                with tarfile.open(db, "w:gz") as output:
                    for member, data in rows:
                        if member.name.endswith("/desc"):
                            data = re.sub(rb"%PGPSIG%\n[^%]*", b"%PGPSIG%\n" + value.encode() + b"\n\n", data)
                            member.size = len(data)
                        output.addfile(member, io.BytesIO(data) if data is not None else None)
                Path(str(db) + ".sig").unlink()  # Replace only this owned synthetic signature.
                r.sign(db, self.key, self.env)
                manifest = r.load(self.directory / "release.json")
                manifest["files"] = r.payload_files(self.directory)
                r.write(self.directory / "release.json", manifest)
                (self.directory / "release.json.sig").unlink()
                r.sign(self.directory / "release.json", self.key, self.env)
                r.verify_signature(db, self.key, self.env)
                r.verify_signature(self.directory / "release.json", self.key, self.env)
                r.verify_signature(package, self.key, self.env)
                with self.assertRaisesRegex(r.Error, "database package signature mismatch"):
                    self.verify()

    def test_resigned_database_rejects_duplicate_and_malformed_field_headers(self):
        self.stage()
        db = self.directory / "repo/fixture.db.tar.gz"
        original = db.read_bytes()
        package = self.directory / "repo" / self.archive.name
        foreign = base64.b64encode(Path(str(db) + ".sig").read_bytes())
        variants = []
        for field, wrong in [(b"PGPSIG", foreign), (b"NAME", b"foreign"), (b"SHA256SUM", b"0" * 64)]:
            for order in ("before", "after"):
                variants.append((field, order, wrong, "duplicate repository database field"))
        variants.append((b"UNUSED_1", "extra-duplicate", b"fixture", "duplicate repository database field"))
        for alias in (b"%%PGPSIG%%", b"%PGPSIG%%", b"%%PGPSIG%", b"%pgpsig%",
                      b"%PGPSIG-%", b"%%NAME%%"):
            variants.append((b"NAME" if alias == b"%%NAME%%" else b"PGPSIG", "alias", alias,
                             "malformed repository database field header"))
        # Leading '%' without a closing '%' is an ordinary descriptor value.
        for value in (b"% savings", b"%PGPSIG"):
            variants.append((b"DESC", "ordinary-value", value, None))
        for field, kind, value, refusal in variants:
            with self.subTest(field=field, variant=kind, value=value):
                with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as source:
                    rows = [(member, source.extractfile(member).read() if member.isfile() else None)
                            for member in source.getmembers()]
                with tarfile.open(db, "w:gz") as output:
                    for member, data in rows:
                        if member.name.endswith("/desc"):
                            header = b"%" + field + b"%"
                            if kind == "alias":
                                self.assertEqual(data.count(header + b"\n"), 1)
                                data = data.replace(header + b"\n", value + b"\n")
                            elif kind == "extra-duplicate":
                                data += b"\n" + header + b"\nfirst\n\n" + header + b"\nsecond\n\n"
                            elif kind == "ordinary-value":
                                data = re.sub(re.escape(header) + rb"\n[^%]*", header + b"\n" + value + b"\n\n", data)
                            else:
                                block = re.search(re.escape(header) + rb"\n[^%]*", data).group()
                                duplicate = header + b"\n" + value + b"\n\n"
                                data = data.replace(block, duplicate + block if kind == "before" else block + duplicate)
                            member.size = len(data)
                        output.addfile(member, io.BytesIO(data) if data is not None else None)
                Path(str(db) + ".sig").unlink()  # Only these disposable fixture signatures are replaced.
                r.sign(db, self.key, self.env)
                manifest = r.load(self.directory / "release.json")
                manifest["files"] = r.payload_files(self.directory)
                r.write(self.directory / "release.json", manifest)
                (self.directory / "release.json.sig").unlink()
                r.sign(self.directory / "release.json", self.key, self.env)
                for signed in (db, self.directory / "release.json", package):
                    r.verify_signature(signed, self.key, self.env)
                if refusal is None:
                    self.verify()
                else:
                    with self.assertRaisesRegex(r.Error, refusal):self.verify()

    def test_artifact_tamper(self):
        self.stage()
        with (self.directory / "repo" / self.archive.name).open("ab") as f:
            f.write(b"tamper")
        with self.assertRaisesRegex(r.Error, "payload changed"):
            self.verify()

    def test_wrong_signer_and_manifest_tamper(self):
        self.stage()
        with self.assertRaisesRegex(r.Error, "pinned fingerprint"):
            r.verify_release(self.directory, "0" * 40, self.env)
        with (self.directory / "release.json").open("a") as f:
            f.write(" ")
        with self.assertRaisesRegex(r.Error, "command failed"):
            self.verify()

    def test_symlink_tamper(self):
        self.stage()
        link = self.directory / "repo/fixture.db"
        link.unlink()
        link.symlink_to("../../outside")
        with self.assertRaisesRegex(r.Error, "symlink"):
            self.verify()

    def test_dependency_version_conflict_and_file_ownership(self):
        base = r.load(self.inputs / "base.json")
        package = r.pkginfo(self.archive)
        base["packages"][1]["provides"] = ["virtual-runtime"]
        with self.assertRaisesRegex(r.Error, "unsatisfied dependency"):
            r.dependency_check(self.release_spec, [package], base)
        base["packages"][1]["provides"] = ["virtual-runtime=2"]
        base["packages"][1]["conflict"] = ["fixture"]
        with self.assertRaisesRegex(r.Error, "package conflict"):
            r.dependency_check(self.release_spec, [package], base)
        base["packages"][1]["conflict"] = []
        base["packages"][1]["files"] = ["usr/share/fixture/config"]
        with self.assertRaisesRegex(r.Error, "file conflict"):
            r.dependency_check(self.release_spec, [package], base)

    def test_protected_packages_and_selected_scope(self):
        base = r.load(self.inputs / "base.json")
        package = r.pkginfo(self.archive)
        package["provides"] = ["linux-asahi"]
        with self.assertRaisesRegex(r.Error, "protected"):
            r.dependency_check(self.release_spec, [package], base)
        package["provides"] = []
        self.release_spec["policy"]["selected_packages"] = ["missing"]
        with self.assertRaisesRegex(r.Error, "selected package"):
            r.dependency_check(self.release_spec, [package], base)

    def test_input_checksum_and_symlink_rejected(self):
        bad = self.ref("base.json")
        bad["sha256"] = "0" * 64
        with self.assertRaisesRegex(r.Error, "checksum mismatch"):
            r.file_ref(self.inputs, bad)
        (self.inputs / "linked.json").symlink_to("base.json")
        with self.assertRaisesRegex(r.Error, "symlink"):
            r.file_ref(self.inputs, {"path": "linked.json", "sha256": r.sha(self.inputs / "base.json")})

    def test_synthetic_never_promotes(self):
        gates = self.complete_modeled_evidence()
        self.stage()
        gates["release_sha256"] = r.sha(self.directory / "release.json")
        gate_path = self.inputs / "gates.json"
        r.write(gate_path, gates)
        with self.assertRaisesRegex(r.Error, "synthetic"):
            r.promote(argparse.Namespace(release_id="fixture-1", gates=str(gate_path)), self.root, self.key, self.env)
        self.assertFalse((self.root / "stable").exists())

    def test_gate_schema_and_missing_evidence(self):
        gates = self.complete_modeled_evidence()
        self.stage()
        manifest, specification = self.verify()
        gates["release_sha256"] = r.sha(self.directory / "release.json")
        # Only test the gate validator's modeled success; stored signed fixture stays synthetic.
        specification["synthetic"] = False
        gates["synthetic"] = False
        gate_path = self.inputs / "gates.json"
        r.write(gate_path, gates)
        r.gates_check(self.directory, manifest, specification, gate_path)
        missing = copy.deepcopy(gates)
        missing["records"] = [x for x in missing["records"] if x["kind"] != "upgrade-recovery"]
        r.write(gate_path, missing)
        with self.assertRaisesRegex(r.Error, "upgrade-recovery"):
            r.gates_check(self.directory, manifest, specification, gate_path)
        r.write(gate_path, gates)
        no_license = copy.deepcopy(specification)
        no_license.pop("project_license")
        with self.assertRaisesRegex(r.Error, "project license missing"):
            r.gates_check(self.directory, manifest, no_license, gate_path)
        no_license = copy.deepcopy(specification)
        no_license["policy"]["supported_models"] = ["m2-air-15"]
        with self.assertRaisesRegex(r.Error, "functional"):
            r.gates_check(self.directory, manifest, no_license, gate_path)

    def test_withdraw_retains_signed_artifacts(self):
        self.stage()
        (self.inputs / "incident.txt").write_text("Synthetic withdrawal drill.\n")
        result = r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(self.inputs / "incident.txt")), self.root, self.key, self.env)
        self.assertEqual(result["status"], "withdrawn-locally")
        self.assertTrue((self.directory / "repo" / self.archive.name).exists())
        r.verify_signature(self.root / "withdrawals/fixture-1.json", self.key, self.env)
        with self.assertRaisesRegex(r.Error, "already withdrawn"):
            r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(self.inputs / "incident.txt")), self.root, self.key, self.env)

    def test_vercmp_epoch_and_versioned_provide(self):
        self.assertTrue(r.satisfies("pkg>2", {"name": "pkg", "version": "1:1-1"}))
        self.assertFalse(r.satisfies("virtual>=2", {"name": "pkg", "version": "10", "provides": ["virtual"]}))
        self.assertTrue(r.satisfies("virtual>=2", {"name": "pkg", "version": "1", "provides": ["virtual=2"]}))

    def test_expired_key_rejected_by_real_gpg(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-expired-key-") as tmp:
            home = Path(tmp)
            home.chmod(0o700)
            env = dict(os.environ, GNUPGHOME=tmp)
            try:
                r.run(["gpg", "--batch", "--faked-system-time", "1700000000", "--pinentry-mode", "loopback",
                       "--passphrase", "", "--quick-generate-key", "Expired test <expired@invalid>", "ed25519", "sign", "1d"], env=env)
                listing = r.run(["gpg", "--with-colons", "--list-keys"], env=env).decode()
                key = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
                path = home / "fixture.txt"
                path.write_text("Synthetic historical signature.\n")
                r.run(["gpg", "--batch", "--faked-system-time", "1700000100", "--local-user", key, "--digest-algo", "SHA256",
                       "--detach-sign", path], env=env)
                # GPG itself exits zero and reports EXPKEYSIG; our verifier must reject it.
                raw = r.run(["gpg", "--batch", "--status-fd", "1", "--verify", str(path) + ".sig", path], env=env)
                self.assertIn(b"EXPKEYSIG", raw)
                with self.assertRaisesRegex(r.Error, "signature/key status"):
                    r.verify_signature(path, key, env)
                unsigned = home / "new.txt"
                unsigned.write_text("Synthetic signing rejection.\n")
                with self.assertRaises(r.Error):
                    r.sign(unsigned, key, env)
            finally:
                subprocess.run(["gpgconf", "--homedir", tmp, "--kill", "all"], capture_output=True)

    def test_revoked_key_rejected_by_real_gpg(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-revoked-key-") as tmp:
            home = Path(tmp)
            home.chmod(0o700)
            env = dict(os.environ, GNUPGHOME=tmp)
            try:
                r.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
                       "Revoked test <revoked@invalid>", "ed25519", "sign", "1d"], env=env)
                listing = r.run(["gpg", "--with-colons", "--list-keys"], env=env).decode()
                key = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
                path = home / "fixture.txt"
                path.write_text("Synthetic revocation test.\n")
                r.sign(path, key, env)
                certificate = (home / "openpgp-revocs.d" / f"{key}.rev").read_text()
                certificate = certificate[certificate.index(":-----BEGIN"):].replace(":-----BEGIN", "-----BEGIN", 1)
                revoked = home / "revoked.asc"
                revoked.write_text(certificate)
                r.run(["gpg", "--batch", "--import", revoked], env=env)
                with self.assertRaises(r.Error):
                    r.verify_signature(path, key, env)
                unsigned = home / "new.txt"
                unsigned.write_text("Synthetic signing rejection.\n")
                with self.assertRaises(r.Error):
                    r.sign(unsigned, key, env)
            finally:
                subprocess.run(["gpgconf", "--homedir", tmp, "--kill", "all"], capture_output=True)

    def test_storage_symlink_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.root / "withdrawals").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(r.Error, "storage path is a symlink"):
            self.stage()
        self.assertFalse(list(outside.iterdir()))

    def test_hardware_gates_bind_one_version_record(self):
        gates = self.complete_modeled_evidence()
        alternate = r.load(self.inputs / "machine.json")
        alternate["platform_versions"] = {"kernel": "different-synthetic-version"}
        self.put("machine-alternate.json", alternate)
        self.release_spec["evidence"].append(dict(self.ref("machine-alternate.json"), id="machine-alternate.json"))
        self.stage()
        manifest, specification = self.verify()
        gates["release_sha256"] = r.sha(self.directory / "release.json")
        gates["synthetic"] = specification["synthetic"] = False  # isolated schema test only
        next(x for x in gates["records"] if x["kind"] == "install-removal")["machine_record"] = "machine-alternate.json"
        gate_path = self.inputs / "gates.json"
        r.write(gate_path, gates)
        with self.assertRaisesRegex(r.Error, "identities/version records"):
            r.gates_check(self.directory, manifest, specification, gate_path)

    def test_cli_signed_stage_and_withdrawal_verification(self):
        command = [sys.executable, str(Path(__file__).with_name("release.py")), "--root", str(self.root),
                   "--gpg-home", str(self.home), "--key", self.key]
        staged = json.loads(r.run(command + ["stage", "--spec", str(self.spec_path)]))
        self.assertEqual(staged["status"], "local-staging")
        verified = json.loads(r.run(command + ["verify", "--release-id", "fixture-1"]))
        self.assertEqual(verified["status"], "verified-locally")
        (self.inputs / "incident.txt").write_text("Synthetic CLI withdrawal drill.\n")
        r.run(command + ["withdraw", "--release-id", "fixture-1", "--reason", str(self.inputs / "incident.txt")])
        rejected = subprocess.run(command + ["verify", "--release-id", "fixture-1"], capture_output=True, text=True)
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("release withdrawn", rejected.stderr)

    def test_noncanonical_file_paths_rejected(self):
        base = r.load(self.inputs / "base.json")
        base["packages"][1]["files"] = ["usr//share/fixture/config"]
        with self.assertRaisesRegex(r.Error, "noncanonical"):
            r.dependency_check(self.release_spec, [r.pkginfo(self.archive)], base)

    def test_nested_release_filename_is_hashed(self):
        (self.inputs / "release.json").write_text("Synthetic evidence, not the root manifest.\n")
        self.release_spec["evidence"].append(dict(self.ref("release.json"), id="release.json"))
        self.stage()
        (self.directory / "evidence/release.json").write_text("changed\n")
        with self.assertRaisesRegex(r.Error, "payload changed"):
            self.verify()

    def test_atomic_activation_and_frozen_gate_object(self):
        """Mock gates only to exercise storage mechanics; no real stable gate is asserted."""
        self.stage()
        gate_path = self.inputs / "gates.json"
        original = {"schema_version": 1, "synthetic": True, "marker": "validated synthetic plumbing fixture"}
        r.write(gate_path, original)
        calls = []
        def modeled_check(directory, manifest, specification, path):
            data = r.load(path)
            calls.append(data)
            if len(calls) == 1:
                r.write(gate_path, {"marker": "changed after first validation"})
            return data
        with mock.patch.object(r, "gates_check", side_effect=modeled_check):
            r.promote(argparse.Namespace(release_id="fixture-1", gates=str(gate_path)), self.root, self.key, self.env)
        self.assertEqual(calls, [original, original])
        promotion = self.root / "promotions/fixture-1.json"
        self.assertEqual(r.load(promotion)["gates"], original)
        r.verify_signature(promotion, self.key, self.env)
        self.assertEqual(os.readlink(self.root / "stable/current"), "fixture-1")
        self.assertTrue(self.directory.exists())
        (self.inputs / "incident.txt").write_text("Synthetic activation/withdrawal drill.\n")
        r.withdraw(argparse.Namespace(release_id="fixture-1", reason=str(self.inputs / "incident.txt")), self.root, self.key, self.env)
        self.assertFalse((self.root / "stable/current").exists())
        self.assertTrue((self.root / "stable/fixture-1/release.json").exists())

    def modeled_promotion(self, rid="fixture-1"):
        self.release_spec["release_id"] = rid
        self.stage()
        self.put(f"{rid}-gates.json", {"schema_version": 1, "synthetic": True, "release_id": rid,
                                      "release_sha256": r.sha(self.directory / "release.json")})
        return argparse.Namespace(release_id=rid, gates=str(self.inputs / f"{rid}-gates.json"))

    def promote_model(self, args, *, activation_fails=False):
        with r.locked(self.root), mock.patch.object(r, "gates_check", side_effect=lambda *a: r.load(a[-1])):
            if activation_fails:
                with mock.patch.object(r.os, "replace", side_effect=OSError("activation interrupted")) as replace:
                    with self.assertRaisesRegex(OSError, "activation interrupted"):
                        r.promote(args, self.root, self.key, self.env)
                link = replace.call_args.args[0]
                self.assertNotEqual(link.parent, self.root / "stable")
                self.assertFalse(link.parent.exists())
            else:
                return r.promote(args, self.root, self.key, self.env)

    def test_verify_refuses_requested_id_different_from_signed_bundle(self):
        self.promote_model(self.modeled_promotion())
        rid, alias = "fixture-1", "fixture-alias"
        command = [sys.executable, Path(__file__).with_name("release.py"), "--root", self.root,
                   "--gpg-home", self.home, "--key", self.key, "verify"]
        staged = json.loads(r.run([*command, "--release-id", rid, "--channel", "staging"]))
        self.assertEqual(staged["release_id"], rid)
        with self.assertRaisesRegex(r.Error, "synthetic fixtures cannot enter stable"):
            r.run([*command, "--release-id", rid, "--channel", "stable"])
        for channel in ("staging", "stable"):
            shutil.copytree(self.root / channel / rid, self.root / channel / alias, symlinks=True)
        history = self.root / "promotions"
        for suffix in (".json", ".json.sig"):
            shutil.copyfile(history / (rid + suffix), history / (alias + suffix))
        for channel in ("staging", "stable"):
            with self.subTest(channel=channel), self.assertRaisesRegex(r.Error, "path/release identity mismatch"):
                r.run([*command, "--release-id", alias, "--channel", channel])

    def test_verify_stable_refuses_signed_promotion_for_another_id(self):
        self.promote_model(self.modeled_promotion())
        record = self.root / "promotions/fixture-1.json"
        saved = r.load(record)
        r.write(record, dict(saved, release_id="different-release"))
        record.with_suffix(".json.sig").unlink()
        r.sign(record, self.key, self.env)
        command = [sys.executable, Path(__file__).with_name("release.py"), "--root", self.root,
                   "--gpg-home", self.home, "--key", self.key, "verify",
                   "--release-id", "fixture-1", "--channel", "stable"]
        with self.assertRaisesRegex(r.Error, "promotion record is not bound to this release"):
            r.run(command)

    def test_promotion_retry_authenticates_exact_inputs_and_preserves_history(self):
        self.promote_model(self.modeled_promotion("previous"))
        args = self.modeled_promotion()
        self.promote_model(args, activation_fails=True)
        current = self.root / "stable/current"
        self.assertEqual(os.readlink(current), "previous")
        legacy = current.with_name(".current-next")
        legacy.symlink_to("fixture-1")
        promotion = self.root / "promotions/fixture-1.json"
        signature = promotion.with_suffix(".json.sig")
        originals = {path: path.read_bytes() for path in (promotion, signature)}
        gate_path = Path(args.gates)
        original_gates = r.load(gate_path)
        r.write(gate_path, dict(original_gates, synthetic=1))
        with self.assertRaisesRegex(r.Error, "gates differ"):
            self.promote_model(args)
        r.write(gate_path, original_gates)
        with r.locked(self.root), self.assertRaisesRegex(r.Error, "synthetic fixtures"):
            r.promote(args, self.root, self.key, self.env)
        staging = self.directory / "release.json"
        staged_sig = staging.with_suffix(".json.sig")
        staged_original, staged_signature = staging.read_bytes(), staged_sig.read_bytes()
        r.write(staging, dict(json.loads(staged_original), created_utc="2026-01-01T00:00:00+00:00"))
        staged_sig.unlink()
        r.sign(staging, self.key, self.env)
        with self.assertRaisesRegex(r.Error, "release differs from staging"):
            self.promote_model(args)
        staging.write_bytes(staged_original)
        staged_sig.write_bytes(staged_signature)
        signature.write_bytes(b"corrupt signature")
        with self.assertRaisesRegex(r.Error, "command failed: gpg"):
            self.promote_model(args)
        signature.write_bytes(originals[signature])
        self.assertEqual(os.readlink(current), "previous")
        with mock.patch.object(r, "sign", side_effect=AssertionError("retry must not sign")):
            self.assertEqual(self.promote_model(args)["status"], "local-stable")
        self.assertEqual(os.readlink(current), "fixture-1")
        self.assertEqual(os.readlink(legacy), "fixture-1")
        self.assertEqual({path: path.read_bytes() for path in originals}, originals)

    def test_promotion_retry_rejects_future_time_and_superseded_promotion(self):
        args = self.modeled_promotion()
        self.promote_model(args, activation_fails=True)
        current = self.root / "stable/current"
        promotion = self.root / "promotions/fixture-1.json"
        signature = promotion.with_suffix(".json.sig")
        original, original_signature = promotion.read_bytes(), signature.read_bytes()
        for timestamp in ("9999-01-01T00:00:00+00:00", "2026-01-01T12:00:00"):
            with self.subTest(timestamp=timestamp):
                r.write(promotion, dict(json.loads(original), promoted_utc=timestamp))
                signature.unlink()
                r.sign(promotion, self.key, self.env)
                with self.assertRaisesRegex(r.Error, "invalid promoted_utc timestamp"):
                    self.promote_model(args)
                self.assertFalse(current.is_symlink())
        promotion.write_bytes(original)
        signature.write_bytes(original_signature)
        self.promote_model(self.modeled_promotion("successor"))
        reason = self.inputs / "incident.txt"
        reason.write_text("Synthetic successor withdrawal.\n")
        with r.locked(self.root):
            r.withdraw(argparse.Namespace(release_id="successor", reason=str(reason)), self.root, self.key, self.env)
        with self.assertRaisesRegex(r.Error, "not newer than stable history"):
            self.promote_model(args)
        self.assertFalse(current.is_symlink())

    def test_withdrawal_retry_authenticates_exact_reason_and_unblocks_export(self):
        self.promote_model(self.modeled_promotion())
        reason = self.inputs / "incident.txt"
        reason.write_bytes(b"Synthetic withdrawal.\r\n")
        args = argparse.Namespace(release_id="fixture-1", reason=str(reason))
        current = self.root / "stable/current"
        unlink = Path.unlink

        def interrupt(path, *a, **kw):
            if path == current:
                raise OSError("withdrawal interrupted")
            return unlink(path, *a, **kw)

        with r.locked(self.root), mock.patch.object(Path, "unlink", interrupt):
            with self.assertRaisesRegex(OSError, "withdrawal interrupted"):
                r.withdraw(args, self.root, self.key, self.env)
        record = self.root / "withdrawals/fixture-1.json"
        signature = record.with_suffix(".json.sig")
        originals = {path: path.read_bytes() for path in (record, signature)}
        endpoint = self.base / "endpoint"
        endpoint.mkdir()
        export = [sys.executable, Path(__file__).with_name("export_repository.py"), "--root", self.root,
                  "--endpoint", endpoint, "--gpg-home", self.home, "--key", self.key]
        with self.assertRaisesRegex(r.Error, "selected release is withdrawn"):
            r.run(export)
        reason.write_bytes(b"Synthetic withdrawal.\n")
        with r.locked(self.root), self.assertRaisesRegex(r.Error, "withdrawal differs"):
            r.withdraw(args, self.root, self.key, self.env)
        reason.write_bytes(b"Synthetic withdrawal.\r\n")
        signature.write_bytes(b"corrupt signature")
        with r.locked(self.root), self.assertRaisesRegex(r.Error, "command failed: gpg"):
            r.withdraw(args, self.root, self.key, self.env)
        signature.write_bytes(originals[signature])
        self.assertEqual(os.readlink(current), "fixture-1")
        with r.locked(self.root), mock.patch.object(r, "sign", side_effect=AssertionError("retry must not sign")):
            self.assertEqual(r.withdraw(args, self.root, self.key, self.env)["status"], "withdrawn-locally")
        self.assertFalse(current.is_symlink())
        self.assertEqual({path: path.read_bytes() for path in originals}, originals)
        self.assertIsNone(json.loads(r.run(export))["selected_release"])

    def kill_record_publication(self, operation, flag, args, destination):
        code = """
import argparse
import os
from pathlib import Path
import signal
import sys
from unittest import mock
from test_release import r

root, home, key, operation, flag, rid, input_path, destination = sys.argv[1:]
root = Path(root)
rename = r.rename_noreplace

def interrupt(source, target):
    if target == Path(destination) or (destination == "completed" and target.name == destination):
        os.kill(os.getpid(), signal.SIGKILL)
    rename(source, target)

args = argparse.Namespace(release_id=rid, **{flag: input_path})
with r.locked(root), mock.patch.object(r, "gates_check", side_effect=lambda *args: r.load(args[-1])):
    r.rename_noreplace = interrupt
    getattr(r, operation)(args, root, key, r.gpg_env(home, root))
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, str(self.root), str(self.home), self.key,
             operation, flag, args.release_id, getattr(args, flag), str(destination)],
            cwd=Path(__file__).resolve().parent, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr.decode())

    def test_promotion_resumes_partial_journal_without_replacing_colliding_history(self):
        self.root.chmod(0o2700)
        args = self.modeled_promotion()
        destination = self.root / "stable/fixture-1"
        promotion = self.root / "promotions/fixture-1.json"
        rename = r.rename_noreplace

        def collision(source, target):
            if target == destination:
                destination.mkdir()
            rename(source, target)

        with mock.patch.object(r, "rename_noreplace", collision), self.assertRaises(FileExistsError) as caught:
            self.promote_model(args)
        self.assertEqual(caught.exception.errno, errno.EEXIST)
        self.assertEqual(list(destination.iterdir()), [])
        destination.rmdir()

        self.kill_record_publication("promote", "gates", args, promotion)
        signature = promotion.with_suffix(".json.sig")
        original = signature.read_bytes()
        pending = self.root / ".promotion-pending/fixture-1"
        journal = pending / "record.json"
        self.assertEqual(journal.with_suffix(".json.sig").read_bytes(), original)
        self.assertTrue(destination.is_dir())
        self.assertFalse((destination.parent / "current").is_symlink())
        signature.write_bytes(b"foreign record")
        with self.assertRaisesRegex(r.Error, "retained signed record differs"):
            self.promote_model(args)
        self.assertEqual(signature.read_bytes(), b"foreign record")
        signature.write_bytes(original)
        journal.chmod(0o666)
        with self.assertRaisesRegex(r.Error, "unsafe pending signed record member"):
            self.promote_model(args)
        journal.chmod(0o600)
        gate_path = Path(args.gates)
        original_gates = r.load(gate_path)
        r.write(gate_path, dict(original_gates, foreign=True))
        with self.assertRaisesRegex(r.Error, "gates differ"):
            self.promote_model(args)
        r.write(gate_path, original_gates)
        retained = pending.with_name("preserved-test-journal")
        pending.rename(retained)
        with self.assertRaisesRegex(r.Error, "incomplete or unsafe signed record"):
            self.promote_model(args)
        retained.rename(pending)
        self.assertFalse(promotion.exists())
        raw = journal.read_bytes()
        self.kill_record_publication("promote", "gates", args, "completed")
        self.assertEqual(promotion.read_bytes(), raw)
        self.assertFalse((destination.parent / "current").is_symlink())
        with mock.patch.object(r, "sign", side_effect=AssertionError("retry must not sign")):
            self.assertEqual(self.promote_model(args)["status"], "local-stable")
        self.assertEqual(promotion.read_bytes(), raw)
        self.assertEqual(signature.read_bytes(), original)
        self.assertEqual(os.readlink(destination.parent / "current"), "fixture-1")
        self.assertFalse(pending.exists())

    def test_withdrawal_resumes_partial_journal_with_exact_reason_and_signature(self):
        self.root.chmod(0o2700)
        promotion = self.modeled_promotion()
        self.promote_model(promotion)
        reason = self.inputs / "incident.txt"
        reason.write_bytes(b"Synthetic partial withdrawal.\r\n")
        args = argparse.Namespace(release_id="fixture-1", reason=str(reason))
        record = self.root / "withdrawals/fixture-1.json"
        self.kill_record_publication("withdraw", "reason", args, record)
        signature = record.with_suffix(".json.sig")
        original = signature.read_bytes()
        pending = self.root / ".withdrawal-pending/fixture-1"
        journal = pending / "record.json"
        self.assertEqual(journal.with_suffix(".json.sig").read_bytes(), original)
        raw = journal.read_bytes()
        current = self.root / "stable/current"
        self.assertEqual(os.readlink(current), "fixture-1")
        verify = [sys.executable, Path(__file__).with_name("release.py"), "--root", self.root,
                  "--gpg-home", self.home, "--key", self.key, "verify", "--release-id", "fixture-1"]
        with self.assertRaisesRegex(r.Error, "withdrawal incomplete"):
            r.run(verify)
        with self.assertRaisesRegex(r.Error, "withdrawal incomplete"):
            self.promote_model(promotion)
        reason.write_bytes(b"Synthetic partial withdrawal.\n")
        with r.locked(self.root), self.assertRaisesRegex(r.Error, "withdrawal differs"):
            r.withdraw(args, self.root, self.key, self.env)
        reason.write_bytes(b"Synthetic partial withdrawal.\r\n")
        journal.write_bytes(raw + b"\n")
        with r.locked(self.root), self.assertRaisesRegex(r.Error, "command failed: gpg"):
            r.withdraw(args, self.root, self.key, self.env)
        journal.write_bytes(raw)
        retained = pending.with_name("preserved-test-journal")
        pending.rename(retained)
        with r.locked(self.root), self.assertRaisesRegex(r.Error, "incomplete or unsafe signed record"):
            r.withdraw(args, self.root, self.key, self.env)
        retained.rename(pending)
        self.assertEqual(signature.read_bytes(), original)
        self.assertFalse(record.exists())
        self.kill_record_publication("withdraw", "reason", args, "completed")
        self.assertEqual(record.read_bytes(), raw)
        self.assertEqual(os.readlink(current), "fixture-1")
        with r.locked(self.root), mock.patch.object(r, "sign", side_effect=AssertionError("retry must not sign")):
            self.assertEqual(r.withdraw(args, self.root, self.key, self.env)["status"], "withdrawn-locally")
        self.assertFalse(current.is_symlink())
        self.assertFalse(pending.exists())
        self.assertEqual(record.read_bytes(), raw)
        self.assertEqual(signature.read_bytes(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
