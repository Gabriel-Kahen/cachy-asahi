#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check passive ext4 extraction and the exact three inventory phases."""

import hashlib
import importlib.util
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import zipfile

spec = importlib.util.spec_from_file_location(
    "maintenance_guest_fixture", Path(__file__).with_name("prepare_maintenance_guest.py"))
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class Controls(unittest.TestCase):
    def test_root_seed_extract_reuse_and_changed_bytes(self):
        payload = bytearray(16 * 1024)
        for offset, number in ((4, 4), (12, 1), (24, 2)):
            struct.pack_into("<I", payload, 1024 + offset, number)
        payload[1080:1084] = b"\x53\xef\x01\x00"
        expected_uuid = "725346d2-f127-47bc-b464-9dd46155e8d6"
        payload[1128:1144] = uuid.UUID(expected_uuid).bytes
        with tempfile.TemporaryDirectory(prefix="asahi-passive-fixture-") as directory:
            root = Path(directory)
            archive = root / "asahi-base.zip"
            member = zipfile.ZipInfo("root.img")
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(member, payload)
            archive_ref = dict(path=str(archive), size=archive.stat().st_size,
                               sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
            root_pin = dict(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(), zip_member="root.img")
            seed = root / "seed-root.img"
            required = G.C.RESERVE + len(payload)
            with patch.object(G.shutil, "disk_usage", return_value=SimpleNamespace(free=required - 1)):
                with self.assertRaisesRegex(ValueError, "insufficient passive staging reserve"):
                    G.root_seed(archive_ref, root_pin, seed, {})
            self.assertFalse(seed.exists())
            with patch.object(G.shutil, "disk_usage", return_value=SimpleNamespace(free=required)):
                got, geometry = G.root_seed(archive_ref, root_pin, seed, {})
            self.assertEqual(seed.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(seed.stat().st_mode), 0o444)
            self.assertEqual(geometry, dict(block_size=4096, bytes=16384, free_bytes=4096, uuid=expected_uuid))
            self.assertEqual(G.existing_root_seed(seed, root_pin, {}), (got, geometry))
            seed.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "same read-only file"):
                G.existing_root_seed(seed, root_pin, {})
            payload[-1] = 1
            seed.write_bytes(payload)
            seed.chmod(0o444)
            with self.assertRaisesRegex(ValueError, "Changed pinned bytes"):
                G.existing_root_seed(seed, root_pin, {})

    def test_three_update_rollback_preserves_additions_and_restores_all_protected_versions(self):
        old = {f"base{i:03}": "1-1" for i in range(258)}
        old.update({name: change[0] for name, change in G.CHANGES.items()})
        baseline = dict(packages=[{"metadata": {"NAME": [name], "VERSION": [version]}}
                                  for name, version in old.items()])
        original = dict(protected=[dict(name=name, expected=old[name])
                                  for name in sorted(old)[:200] + ["python"]])
        proposal = {name: dict(name=name, version=version, repo="observed-Asahi-base") for name, version in old.items()}
        proposal.update({name: dict(name=name, version=after, repo=repo)
                         for name, (_, after, repo) in G.CHANGES.items()})
        proposal.update({f"new{i:03}": dict(name=f"new{i:03}", version="2-1", repo="extra") for i in range(365)})
        prepared = dict(add=[row for name, row in proposal.items() if old.get(name) != row["version"]], remove=[])
        locks, additions = G.phase_locks(baseline, original, proposal, prepared)
        self.assertEqual(len(additions), 368)
        self.assertEqual(G.T.canonical_lock(locks["baseline"], 261), old)
        self.assertEqual(len(G.T.canonical_lock(locks["forward"], 626)), 626)
        rollback = G.T.canonical_lock(locks["rollback"], 626)
        self.assertEqual({name: rollback[name] for name in old}, old)
        self.assertEqual(rollback["new364"], "2-1")
        proposal["base025"]["version"] = "9-1"
        with self.assertRaisesRegex(ValueError, "unexpected change"):
            G.phase_locks(baseline, original, proposal, prepared)


if __name__ == "__main__":
    unittest.main()
