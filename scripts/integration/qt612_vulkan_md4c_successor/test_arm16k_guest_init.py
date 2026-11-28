#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise boot-side comparisons without booting a guest."""

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest


INIT = Path(__file__).resolve().with_name("arm16k-guest-init.sh")
FUNCTIONS = r'''
set -Eeuo pipefail
boot_functions=$(source "$1"; declare -f same_bytes final_inventory_matches retain)
eval "$boot_functions"
ROOT=$2/root EVIDENCE=/collected EXPORT=$2/export PACKAGE=unused
PATH=$2/bin
export LC_ALL=C
census_version=$3 census_status=$4
timeout() {
    [[ $* == "60 chroot $ROOT /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/pacman -Q" ]] || return 89
    printf '%s\n' 'zeta 1-1' "alpha $census_version"
    return "$census_status"
}
'''


class GuestInitTests(unittest.TestCase):
    def setUp(self):
        work = Path(self.enterContext(TemporaryDirectory()))
        self.work = work
        self.collected = work / "root/collected/setup"
        self.retained = work / "export/evidence"
        self.collected.mkdir(parents=True)
        self.retained.mkdir(parents=True)
        (work / "bin").mkdir()
        for name in ("sha256sum", "sort", "stat", "install"):
            (work / "bin" / name).symlink_to(Path("/usr/bin") / name)
        (self.collected / "after.lock").write_bytes(b"alpha 1-1\nzeta 1-1\n")

    def invoke(self, body, version="1-1", producer_status=0):
        result = subprocess.run(
            ["/usr/bin/bash", "-c", FUNCTIONS + body, "guest-init-test", INIT, self.work,
             version, str(producer_status)],
            text=True, capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(result.stderr, "")
        return result

    def test_final_census_accepts_same_sorted_bytes(self):
        self.assertEqual(self.invoke("final_inventory_matches").returncode, 0)

    def test_final_census_refuses_changed_bytes(self):
        self.assertEqual(self.invoke("final_inventory_matches", version="2-1").returncode, 1)

    def test_final_census_refuses_failed_producer_even_with_same_bytes(self):
        self.assertEqual(self.invoke("final_inventory_matches", producer_status=23).returncode, 23)

    def test_emergency_retention_preserves_identical_existing_bytes(self):
        payload = b"binary\0content\n\n"
        (self.collected / "checkpoint").write_bytes(payload)
        existing = self.retained / "checkpoint"
        existing.write_bytes(payload)
        inode = existing.stat().st_ino
        self.assertEqual(self.invoke("set +e; retain setup HOLD checkpoint").returncode, 0)
        self.assertEqual(existing.read_bytes(), payload)
        self.assertEqual(existing.stat().st_ino, inode)

    def test_emergency_retention_refuses_mismatch_but_keeps_other_evidence(self):
        (self.collected / "checkpoint").write_bytes(b"new\n")
        (self.collected / "transcript").write_bytes(b"evidence\n")
        existing = self.retained / "checkpoint"
        existing.write_bytes(b"old\n")
        self.assertEqual(self.invoke("set +e; retain setup HOLD checkpoint transcript").returncode, 1)
        self.assertEqual(existing.read_bytes(), b"old\n")
        self.assertEqual((self.retained / "transcript").read_bytes(), b"evidence\n")

    def test_emergency_retention_refuses_hash_failure_even_with_matching_output(self):
        (self.retained / "after.lock").write_bytes((self.collected / "after.lock").read_bytes())
        result = self.invoke(r'''
sha256sum() { /usr/bin/sha256sum; return 42; }
set +e
retain setup HOLD after.lock
''')
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
