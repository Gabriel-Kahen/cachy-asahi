# SPDX-License-Identifier: MIT
"""Actor-fenced Source207 readback, route projection, and replay controls."""

import argparse
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(HERE))
import checkpoint as P
import terminal as T
import test_contract as M
import test_terminal as terminal_model

C = P.C
S = C.S207
reader_model = P.load("source207_reader_model", HERE.parent / "test_reader.py")
R = P.load("source207_main_reader", ROOT / S.READER["member"])
SOURCE_205_READER = ROOT / C.READER
SOURCE_206_READER = ROOT / C.S.READER["member"]


class Source207Reader(unittest.TestCase):

    def test_versioned_reader_and_historical_bytes(self):
        self.assertEqual(C.pin((ROOT / S.READER["member"]).read_bytes()), R.whole(S.READER))
        self.assertEqual(C.pin(SOURCE_205_READER.read_bytes()), T.READER)
        self.assertEqual(C.pin(SOURCE_206_READER.read_bytes()), R.whole(C.S.READER))
        self.assertEqual((R.SOURCE207_CID, R.SOURCE207_REF, R.SOURCE207), (S.CID, S.REF, S.SOURCE))
        self.assertEqual(set(R.SOURCE207_DOWNLOAD_ROUTES), S.DIRECT_DOWNLOAD_FILENAMES)
        self.assertEqual(R.SELECTED_TEST_FINGERPRINT, S.TEST_FINGERPRINT)
        R.helper_inverse()

    def test_child_pin_binds_url_original_whole_digest_and_empty_aliases(self):
        name = "cmake-4.4.4-1-aarch64.pkg.tar.xz"
        original, selected = R.SOURCE207_DOWNLOAD_ROUTES[name]
        whole = R.SOURCE207_ROUTE_PINS[name]
        cache, out, root = "/MODEL/cache", "/MODEL/out", "/MODEL/source"
        authority, programs, child = {}, {}, ["MODEL-child"]
        image = dict(base_lock={"body": "MODEL"}, bootstrap_profile={"body": "MODEL2"})
        operands = dict(pins={name: whole}, urls={name: selected}, downloads=[name])
        row = dict(authority=authority, source_root=root, programs=programs, **image, cache=cache,
                   filename=name, url=selected, redirect_urls=[], expected=whole, output=f"{cache}/{name}")
        expected = C.pin(C.encoded(row))["sha256"]
        commands = R.material_download_commands(operands, authority, root, programs, image, cache, {name: []}, child, out)
        self.assertEqual(list(commands), [
            ([*child, "download", "--request", f"{out}/download-{name}.json", "--request-sha256", expected], 90)
        ])
        self.assertNotEqual(expected, C.pin(C.encoded(dict(row, url=original)))["sha256"])
        self.assertNotEqual(expected, C.pin(C.encoded(dict(row, redirect_urls=[selected])))["sha256"])
        self.assertNotEqual(expected, C.pin(C.encoded(dict(row, expected=C.pin(b"foreign archive"))))["sha256"])

    def tearDown(self):
        self.assertEqual(M.ACTORS, [])
        self.assertEqual(reader_model.ACTORS, [])


def model_case(profile, prepared):
    """Create synthetic checks of exact pinned DATA without issuing authority."""
    values = M.model_case(profile)
    case = values["case"]
    selected = prepared["root_case"]
    now = S.TEST_ROLE_EXPIRES - 690
    case.update(kind=S.CASE_KIND, workflow_id=S.WORKFLOW_ID, source=selected["source"], main=selected["main"],
                issued_epoch=now - 10, expires_epoch=S.TEST_ROLE_EXPIRES, resources=selected["resources"])
    for role in ("admission", "runtime", "registration", "readback", "once"):
        values[role]["binding"] = C.binding(case)
    for role in ("admission", "runtime"):
        values[role].update(issued_epoch=now - 8, expires_epoch=case["expires_epoch"])
    values["admission"]["resources"] = case["resources"]
    for role in ("registration", "readback", "once"):
        values[role]["observed_epoch"] = now - 2
    for index, sweep in enumerate(values["runtime"]["sweeps"]):
        sweep["observed_epoch"] = now - 5 + index
    values["registration"]["workflow_id"] = S.WORKFLOW_ID
    values["readback"].update(source=case["source"], main=case["main"], profile_pin=S.PROFILE)
    values["request"]["launcher"] = case["main"]["launcher"]

    def delegation(row):
        row.update(policy=S.POLICY, issued_epoch=case["issued_epoch"], expires_epoch=case["expires_epoch"])
        row["binding"].update(source=S.CID, ref=S.REF, source_lock=S.SOURCE["source_map"])
        row["hosted"].update(workflow_ref=f"{C.REPOSITORY}/{C.WORKFLOW}@{S.REF}", workflow_sha=S.CID)

    M.change_request(values, "delegation", delegation)
    M.change_request(values, "grant", lambda row: row.update(
        source=S.CID, ref=S.REF, source_lock=S.SOURCE["source_map"], issued_epoch=case["issued_epoch"],
        expires_epoch=case["expires_epoch"], policy=R.whole(S.POLICY),
        redirect_urls={name: [] for name in S.DOWNLOAD_FILENAMES}))
    certificate = dict(path="/MODEL/source/" + S.TEST_PUBLIC_KEY["member"], **R.whole(S.TEST_PUBLIC_KEY))
    approval = C.encoded(dict(issuer="Root", approved=True, scope="CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY",
                             public_key=certificate, fingerprint=S.TEST_FINGERPRINT,
                             issued_epoch=case["issued_epoch"], expires_epoch=case["expires_epoch"]))
    M.change_request(values, "assembler", lambda row: row.update(test_trust=dict(
        fingerprint=S.TEST_FINGERPRINT, public_key=dict(S.TEST_PUBLIC_KEY),
        Root_admission=dict(json=approval.decode(), pin=C.pin(approval)))))
    return now, values


def exact_profile(files):
    program = C.decode(files[S.PROGRAM["path"]])
    materials = C.decode(files["inputs/delegated-materials-v4.json"])["materials"]
    profile = C.encoded(dict(
        schema=7, kind="UNISSUED_CURRENT_ONBOARDING_TRANSPORT_SOURCE_PROFILE_V7", operation=C.OPERATION,
        files=S.SOURCE["files"], bytes=S.SOURCE["bytes"], prospective_tree=S.SOURCE["tree"],
        source_map=S.SOURCE["source_map"], program=S.PROGRAM, delegation_programs=program["delegation_programs"],
        staging_materials=program["staging_materials"], materials=materials, transport_commit=P.R.CONSTRUCTOR,
        actual=dict.fromkeys(P.R.ACTUAL_KEYS), **P.R.BASES,
    ))
    if C.pin(profile) != S.PROFILE:
        raise ValueError("Source207 exact profile join")
    return profile


def genuine_controls(source_root, profile_path, publication_path):
    class GenuineSource207(unittest.TestCase):

        @classmethod
        def setUpClass(cls):
            cls.files = reader_model.read_source(source_root, S.SOURCE)
            cls.profile = exact_profile(cls.files)
            if profile_path and profile_path.read_bytes() != cls.profile:
                raise ValueError("Source207 retained profile equality")
            if publication_path:
                cls.publication = publication_path.read_bytes()
            else:
                # CI exercises the readback structure without asserting an actual Root observation.
                cls.publication = C.encoded(dict(status="PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY",
                    fixture="MODEL_ONLY", issuer="Root", source=S.CID, ref=S.REF, public_clone_complete=True,
                    public_blob_tree_join=True, Root_independent_fresh_ref_commit_recheck=True,
                    Root_independent_whole_file_mode_recheck=True, native="NOT RUN",
                    source_map_sha256=S.SOURCE["source_map"]["sha256"],
                    **{key: S.SOURCE[key] for key in ("tree", "files", "bytes")}))
                cls.enterClassContext(patch.object(S, "PUBLICATION", C.pin(cls.publication)))
            cls.core = cls.files[C.LAUNCHER]
            cls.reader = (ROOT / S.READER["member"]).read_bytes()
            cls.selection = dict(source=dict(cid=S.CID, ref=S.REF), main=dict(cid="b" * 40, tree="d" * 40),
                                 workflow_id=S.WORKFLOW_ID)
            cls.operands = dict(
                publication=cls.publication,
                source196_close=C.encoded(dict(status=P.SOURCE196_HOLD, Source=P.R.SOURCE196, issuer="Root",
                    run=1, job=2, attempt=1, retry=False, native_acceptance=False,
                    underlying_child_cause="UNKNOWN_NOT_RETAINED")),
                profile=cls.profile, launcher=cls.core, provenance_operand=M.CORE_RAW, reader=cls.reader,
                registration=C.encoded(dict(id=S.WORKFLOW_ID, path=C.WORKFLOW, state="active",
                                             name="Current onboarding delegated private v3")),
                workflow=(ROOT / C.WORKFLOW).read_bytes(),
            )
            cls.prepared = cls.checkpoint()

        @classmethod
        def checkpoint(cls, **changed):
            operands = dict(cls.operands, **changed)
            return P.prepare(cls.selection, operands, {role: C.pin(raw) for role, raw in operands.items()},
                             source_version=207)

        def qualify(self, values, now, **changed):
            operands, pins = M.pack(values)
            checkpoint = C.encoded(self.prepared)
            options = dict(now=now, core_raw=self.core, profile_raw=self.profile)
            options.update(changed)
            return P.qualify_backend(checkpoint, C.pin(checkpoint), operands, pins, **options)

        def test_checkpoint_requires_exact_selected_publication_core_and_reader(self):
            self.assertEqual(C.pin(self.operands["publication"]), S.PUBLICATION)
            self.assertEqual(C.pin(self.core), S.CORE)
            self.assertEqual(self.files[C.WORKFLOW], self.operands["workflow"])
            self.assertEqual(self.prepared["kind"], "SOURCE207_BACKEND_CHECKPOINT_UNISSUED_V1")
            self.assertIsNone(self.prepared["authority"])
            self.assertEqual(self.prepared["POSTs"], 0)
            self.assertEqual(self.prepared["root_case"]["main"]["launcher"], dict(member=C.LAUNCHER, **S.CORE))
            self.assertEqual(self.prepared["request_plan"]["main"]["provenance_operand"],
                             dict(member=P.R.OPERAND, **C.CORE))
            with self.assertRaisesRegex(ValueError, "HOLD_EXACT_CANONICAL_MAIN_ADOPTION"):
                self.checkpoint(launcher=M.CORE_RAW)
            with self.assertRaisesRegex(ValueError, "HOLD_EXACT_SOURCE207_MAIN_READER"):
                self.checkpoint(reader=SOURCE_206_READER.read_bytes())
            with self.assertRaisesRegex(ValueError, "HOLD_PUBLISHED_SOURCE207_SELECTOR"):
                self.checkpoint(publication=self.operands["publication"] + b" ")

        def test_real_source_inverse_bodies_and_historical_reader_boundary(self):
            expected = reader_model.selection(self.files, R.TRANSPORT_PREFIX)
            expected.update(fingerprint=R.SELECTED_TEST_FINGERPRINT, reader_pin=C.pin(self.reader))
            expected["resources"] = R.frozen_resources(R.receipt(self.files[S.POLICY["member"]]))
            with patch.object(Path, "read_bytes", side_effect=AssertionError("source inverse reads supplied bytes only")):
                _, program, policy = R.source_data(expected, self.files, delegated=True)
                change = dict(self.files)
                member = R.SOURCE206_INVERSE["member"]
                change[member] += b" "
                with self.assertRaises(ValueError):
                    R.source_data(expected, change, delegated=True)
            self.assertEqual(program["delegation_programs"], C.decode(self.profile)["delegation_programs"])
            self.assertEqual(policy["private_stage"]["test"]["fingerprint"], S.TEST_FINGERPRINT)
            old = R.rebound_source_inverse(
                self.files, R.SOURCE206, R.SOURCE206_INVERSE, 206, R.SOURCE206_CID,
                {row["member"] for row in R.SOURCE207_REPLACEMENTS.values()} | {S.PROGRAM["path"], "source-map.json"},
            )
            historical = P.load("source206_historical_reader", SOURCE_206_READER)
            preceding_case = reader_model.selection(old, R.TRANSPORT_PREFIX)
            with self.assertRaisesRegex(ValueError, "HOLD_EXACT_TRANSPORT_SOURCE205"):
                historical.source_data(preceding_case, old, delegated=True)

        def test_frozen_517_materials_and_exact_four_effective_urls(self):
            profile = C.decode(self.profile)
            materials = profile["staging_materials"]
            root, cache = "/MODEL/source", "/MODEL/cache"
            image = {}
            for role, key in (("staging_base_lock", "base_lock"), ("staging_bootstrap_profile", "bootstrap_profile")):
                row = materials[role]
                image[key] = dict(path=f"{root}/{row['member']}", **R.whole(row))
            lock = C.decode(self.files[materials["staging_base_lock"]["member"]])
            supplemental = C.decode(self.files[materials["staging_bootstrap_profile"]["member"]])
            originals = {}
            for role, rows, signed in (("base_materials", [lock["rootfs"], *lock["packages"]], True),
                    ("supplemental_materials", supplemental["additions"]["rows"], True),
                    ("keyring_materials", lock["keyring_files"], False)):
                items = image[role] = {}
                for row in rows:
                    name = row["filename"]
                    items[name] = dict(path=f"{cache}/{name}", bytes=row["size"], sha256=row["sha256"])
                    originals[name] = row["url"]
                    if signed:
                        name += ".sig"
                        items[name] = dict(path=f"{cache}/{name}", bytes=row["signature_size"], sha256=row["signature_sha256"])
                        originals[name] = row["url"] + ".sig"
            d = dict(materials=materials, binding=dict(source_lock=S.SOURCE["source_map"]))
            args = (self.files, d, dict(source_root=root), dict(image_inputs=image), cache)
            output = R.material_operand_data(*args)
            self.assertEqual(set(output["downloads"]), S.DOWNLOAD_FILENAMES)
            self.assertEqual(len(output["pins"]), 517)
            self.assertEqual({name for name in originals if originals[name] != output["urls"][name]},
                             S.DIRECT_DOWNLOAD_FILENAMES)
            for name in S.DIRECT_DOWNLOAD_FILENAMES:
                self.assertEqual(output["urls"][name], R.SOURCE207_RETAINED_ORIGIN + name)
                self.assertEqual(output["pins"][name], R.SOURCE207_ROUTE_PINS[name])
            d["binding"]["source_lock"] = C.S.SOURCE["source_map"]
            with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_EXACT_DOWNLOAD_OVERLAY"):
                R.material_operand_data(*args)

        def test_qualification_rejects_redirect_for_four_and_wrong_roster(self):
            now, values = model_case(C.decode(self.profile), self.prepared)
            result = self.qualify(values, now)
            self.assertEqual(result["POSTs"], 0)
            self.assertEqual(result["binding"]["source"], S.CID)
            with self.assertRaisesRegex(ValueError, "HOLD_CORE_BODY"):
                self.qualify(values, now, core_raw=M.CORE_RAW)
            with self.assertRaisesRegex(ValueError, "HOLD_AUTHORITY_TIME"):
                self.qualify(values, S.TEST_ROLE_EXPIRES)

            def modify(row):
                name = "cmake-4.4.4-1-aarch64.pkg.tar.xz"
                row["redirect_urls"][name] = [R.SOURCE207_LEGACY_ORIGIN + name]

            M.change_request(values, "grant", modify)
            with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_FIXED_DOWNLOAD_ROUTES"):
                self.qualify(values, now)

            def rename(row):
                redirects = row["redirect_urls"]
                redirects["other-archive.pkg.tar.xz"] = redirects.pop("archlinuxarm.gpg")

            M.change_request(values, "grant", rename)
            with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_FIXED_DOWNLOAD_ROUTES"):
                self.qualify(values, now)

        def test_terminal_replay_demands_explicit_version_and_exact_reader_core(self):
            fixture = terminal_model.Terminal()
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            _, values = model_case(C.decode(self.profile), self.prepared)
            operands, pins = M.pack(values)
            branch = S.REF.removeprefix("refs/heads/")
            fixture.run.update(head_sha=S.CID, head_branch=branch, workflow_id=S.WORKFLOW_ID)
            fixture.job.update(head_sha=S.CID)
            fixture.artifact["workflow_run"].update(head_sha=S.CID, head_branch=branch)
            fixture.entries = {"launcher-report.json": dict(status="HOLD", request_pin=pins["request"],
                failure=dict(phase="git_source", reason="VALIDATION_REFUSED"), **C.FINAL)}
            archive = fixture.archive()
            fixture.artifact.update(size_in_bytes=len(archive), digest="sha256:" + C.pin(archive)["sha256"])
            files = dict(case=operands["case"], request=operands["request"], run=C.encoded(fixture.run),
                         jobs=C.encoded(fixture.jobs), artifacts=C.encoded(fixture.artifacts), archive=archive)
            pins = {name: C.pin(raw) for name, raw in files.items()}

            def verify(**changed):
                options = dict(ids=terminal_model.IDS, core_raw=self.core, profile_raw=self.profile,
                               reader_raw=self.reader, source_version=207)
                return T.verify(files, pins, **(options | changed))

            self.assertEqual(verify()["status"], T.UNRETAINED)
            for version in (205, 206):
                with self.assertRaisesRegex(ValueError, "HOLD_TERMINAL_CASE"):
                    verify(source_version=version)
            with self.assertRaisesRegex(ValueError, "HOLD_TERMINAL_READER"):
                verify(reader_raw=SOURCE_206_READER.read_bytes())
            with self.assertRaisesRegex(ValueError, "HOLD_CORE_BODY"):
                verify(core_raw=M.CORE_RAW)

        def tearDown(self):
            self.assertEqual(M.ACTORS, [])
            self.assertEqual(reader_model.ACTORS, [])

    return GenuineSource207


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--publication", type=Path)
    args, unittest_args = parser.parse_known_args()
    if args.source_root:
        GenuineSource207 = genuine_controls(args.source_root, args.profile, args.publication)
    elif args.profile or args.publication:
        parser.error("provide --source-root with the optional profile and publication readbacks")
    unittest.main(argv=[sys.argv[0], *unittest_args])
