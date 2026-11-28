#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert refusal and byte-exact rollback controls for the Qt input handoff."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


P = run_path(str(Path(__file__).with_name("prepare.py")))
C = P["C"]
OWNERS = P["OFFICIAL"], P["PROJECT"]
VERSION = P["VERSION"]


def inventory(provider):
    rows = [f"fixture-{i:04d} 1:2.1-1\n" for i in range(628)] + [f"{provider} {VERSION}\n"]
    return "".join(sorted(rows)).encode("ascii")


class HandoffTests(unittest.TestCase):
    def test_profile_requires_independent_digest_and_complete_actual_input_pins(self):
        review = dict(fingerprint="C" * 40, signature=C.pin(b"new signature"),
                      certificate=C.pin(b"new certificate"), not_before=100, not_after=200)
        profile = dict(kind=P["PARITY_KIND"], official_version=VERSION, project_version=P["PARITY_PROJECT_VERSION"],
                       recipe=P["PARITY_RECIPE"], test_review=review,
                       **{name: C.pin(name.encode()) for name in P["PARITY_INPUT_CAPS"]})
        with TemporaryDirectory() as directory:
            path = Path(directory) / "review.json"
            body = C.wire(profile)
            path.write_bytes(body)
            self.assertEqual(P["load_profile"](path, C.pin(body)["sha256"]), profile)
            with self.assertRaisesRegex(ValueError, "independent SHA-256"):
                P["load_profile"](path, None)
            with self.assertRaisesRegex(ValueError, "External digest differs"):
                P["load_profile"](path, C.pin(b"wrong")["sha256"])
            for name in ("project_archive", "build_receipt", "test_review"):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Exact reviewed Qt629 parity profile"):
                    P["checked_profile"]({key: value for key, value in profile.items() if key != name})

    def test_projected_swap_touches_one_package_and_restores_exact_bytes(self):
        baseline = inventory(OWNERS[0])
        replacement, restored = P["project"](baseline)
        self.assertEqual(replacement, inventory(OWNERS[1]))
        self.assertEqual(restored, baseline)
        self.assertEqual(len(replacement.splitlines()), 629)

    def test_parity_projects_only_the_project_version_and_restores_original_bytes(self):
        official, candidate = OWNERS
        baseline = inventory(official)
        parity = P["PARITY_PROJECT_VERSION"]
        replacement, restored = P["project"](baseline, project_version=parity)
        self.assertEqual(set(baseline.splitlines()) - set(replacement.splitlines()),
                         {f"{official} {VERSION}".encode()})
        self.assertEqual(set(replacement.splitlines()) - set(baseline.splitlines()),
                         {f"{candidate} {parity}".encode()})
        self.assertEqual(restored, baseline)
        reverse = P["step"](replacement, restored, candidate, official, "official_archive", project_version=parity)
        self.assertEqual(reverse["remove"], [dict(name=candidate, version=parity)])
        self.assertEqual(reverse["add"], [dict(name=official, version=VERSION, archive_input="official_archive")])
        with self.assertRaisesRegex(ValueError, "installed provider"):
            P["project"](baseline.replace(f"{official} {VERSION}".encode(), f"{official} {parity}".encode()),
                         project_version=parity)
        with self.assertRaisesRegex(ValueError, "exact Qt project provider version"):
            P["project"](baseline, project_version="6.12.0-5")

    def test_refuses_wrong_owner_version_duplicate_or_noncanonical_rows(self):
        baseline = inventory(OWNERS[0])
        rows = baseline.splitlines(keepends=True)
        altered = baseline.replace(f"{OWNERS[0]} {VERSION}".encode(), f"{OWNERS[0]} 6.12.0-4".encode())
        for invalid in (inventory(OWNERS[1]), altered, b"".join(rows[1:] + rows[-1:]),
                        b"".join(reversed(rows)), baseline[:-1], baseline.replace(b"\n", b"\r\n")):
            with self.subTest(head=invalid[:48]), self.assertRaises(ValueError):
                P["project"](invalid)

    def test_reverse_refuses_a_second_qt_provider(self):
        replacement = inventory(OWNERS[1])
        rows = replacement.splitlines(keepends=True)
        rows[-1] = f"{OWNERS[0]} {VERSION}\n".encode()
        with self.assertRaisesRegex(ValueError, "Expected only the selected installed provider"):
            P["projected_swap"](b"".join(sorted(rows)), OWNERS[1], OWNERS[0])

    def test_byte_pins_refuse_modified_equal_length_files_and_symlinks(self):
        original = b"original"
        with TemporaryDirectory() as directory, patch.dict(P["PINS"], rollback_lock=C.pin(original)):
            root = Path(directory)
            selected = root / "rollback.lock"
            selected.write_bytes(original)
            self.assertEqual(P["read"]("rollback_lock", selected), original)
            symlink = root / "other.lock"
            symlink.symlink_to(selected)
            for altered in (symlink, root / "absent.lock"):
                with self.subTest(path=altered.name), self.assertRaisesRegex(ValueError, "rollback_lock"):
                    P["read"]("rollback_lock", altered)
            selected.write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "Exact original file pin"):
                P["read"]("rollback_lock", selected)

    def test_rollback_receipt_must_bind_the_exact_lock_and_retired_result(self):
        result = dict(status=P["PASS629"], nonce="a" * 32, inventory=dict(rollback=P["PINS"]["rollback_lock"]))
        terminal = dict(status=P["OWNED_SUCCESS"], nonce=result["nonce"], outer_container_absent_twice=True,
                        inputs_reverified_after=True, controller_result=dict(status=P["PASS629"]),
                        retained_result_files={"evidence/result.json": P["PINS"]["rollback_result"]})
        P["verify_predecessor"](result, terminal)
        for changed in (dict(nonce="b" * 32), dict(outer_container_absent_twice=False),
                        dict(retained_result_files={"evidence/result.json": C.pin(b"foreign")})):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                P["verify_predecessor"](result, terminal | changed)
        with self.assertRaises(ValueError):
            P["verify_predecessor"](result | dict(inventory=dict(rollback=C.pin(b"wrong lock"))), terminal)


if __name__ == "__main__":
    unittest.main()
