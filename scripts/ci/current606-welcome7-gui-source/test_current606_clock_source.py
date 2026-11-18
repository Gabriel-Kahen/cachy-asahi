# SPDX-License-Identifier: MIT
"""Offline controls for the exact Current606 clock source transform."""

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("clock606_source", HERE / "clock606_source.py")
SOURCE = importlib.util.module_from_spec(SPEC)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--parent", type=Path)
    parser.add_argument("--reference", type=Path)
    OPTIONS, UNITTEST_ARGS = parser.parse_known_args()
    if OPTIONS.reference and not OPTIONS.parent:
        parser.error("--reference requires --parent")
else:
    OPTIONS = argparse.Namespace(parent=None, reference=None)

EXACT_DELTA = {
    "admission.py",
    "factory/factory.py",
    "factory/guest_clock606.py",
    "factory/service_capacity.py",
    "native.py",
    "source-manifest.json",
}


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn",
                         "os.fork", "os.system", "os.kill")):
        raise AssertionError("Source-only test attempted an actor operation: " + event)


def body(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        return stream.read()


def snapshot(root):
    result = {}
    for path in root.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise AssertionError("Unexpected nonregular fixture member: " + str(path))
        result[path.relative_to(root).as_posix()] = (stat.S_IMODE(info.st_mode), body(path))
    return result


def materialize(tree, output, timestamp=None):
    output.mkdir()
    for name, (mode, content) in tree.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        if timestamp is not None:
            os.utime(path, ns=(timestamp, timestamp))


class InertControls(unittest.TestCase):
    def test_missing_parent_rejected(self):
        with self.assertRaises(ValueError):
            SOURCE.transform({})

    def test_forged_manifest_rejected_without_reading_other_sources(self):
        rows = {"source-manifest.json": b'{"files":{}}\n', "admission.py": b"synthetic\n"}
        with self.assertRaises(ValueError):
            SOURCE.transform(rows)
        self.assertEqual(rows["source-manifest.json"], b'{"files":{}}\n')


@unittest.skipUnless(OPTIONS.parent, "supply --parent to test the exact parent fixture")
class ExactSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = OPTIONS.parent.resolve(strict=True)
        cls.tree = snapshot(cls.parent)
        if len(cls.tree) != 591:
            raise AssertionError("Expected 591 parent leaves")

    def test_in_memory_transform_preserves_original_body_map(self):
        parent = {name: content for name, (_, content) in self.tree.items()}
        remembered = parent.copy()
        successor = SOURCE.transform(parent)
        self.assertEqual(parent, remembered)
        self.assertEqual({name for name in parent | successor if parent.get(name) != successor.get(name)},
                         EXACT_DELTA)

    def test_exact_candidate_and_only_the_six_published_changes(self):
        with tempfile.TemporaryDirectory(prefix="current606-clock-output-") as folder:
            output = Path(folder) / "candidate"
            SOURCE.emit(self.parent, output)
            actual = snapshot(output)
            self.assertEqual(len(actual), 592)
            self.assertEqual(set(actual) - set(self.tree), {"factory/guest_clock606.py"})
            self.assertEqual({name for name in self.tree | actual if self.tree.get(name) != actual.get(name)},
                             EXACT_DELTA)
            self.assertTrue(all(mode == 0o644 for mode, _ in actual.values()))
            if OPTIONS.reference is not None:
                self.assertEqual(actual, snapshot(OPTIONS.reference.resolve(strict=True)))

    def test_fresh_copy_with_different_timestamps_and_restrictive_umask(self):
        with tempfile.TemporaryDirectory(prefix="current606-clock-copy-") as folder:
            work = Path(folder)
            copied = work / "copy"
            timestamp = 1_234_567_890_000_000_000
            materialize(self.tree, copied, timestamp)
            leaf = "source-manifest.json"
            self.assertEqual((copied / leaf).stat().st_mtime_ns, timestamp)
            self.assertFalse((copied / leaf).samefile(self.parent / leaf))
            direct, fresh = work / "direct", work / "fresh"
            SOURCE.emit(self.parent, direct)
            previous = os.umask(0o077)
            try:
                SOURCE.emit(copied, fresh)
            finally:
                os.umask(previous)
            self.assertEqual(snapshot(direct), snapshot(fresh))

    def test_body_mode_and_link_drift_leave_no_output(self):
        with tempfile.TemporaryDirectory(prefix="current606-clock-drift-") as folder:
            work = Path(folder)
            copied, output = work / "copy", work / "output"
            materialize(self.tree, copied)
            name = "factory/service_capacity.py"
            leaf = copied / name
            original = self.tree[name][1]
            leaf.write_bytes(original + b"# altered\n")
            with self.assertRaises(ValueError):
                SOURCE.emit(copied, output)
            self.assertFalse(output.exists())
            leaf.write_bytes(original)
            leaf.chmod(0o600)
            with self.assertRaises(ValueError):
                SOURCE.emit(copied, output)
            self.assertFalse(output.exists())
            leaf.unlink()
            leaf.symlink_to(self.parent / name)
            with self.assertRaises(ValueError):
                SOURCE.emit(copied, output)
            self.assertFalse(output.exists())

    def test_extra_leaf_and_existing_destination_are_refused(self):
        with tempfile.TemporaryDirectory(prefix="current606-clock-namespace-") as folder:
            work = Path(folder)
            copied, output = work / "copy", work / "output"
            materialize(self.tree, copied)
            extra = copied / "extra.txt"
            extra.write_bytes(b"untracked\n")
            with self.assertRaises(ValueError):
                SOURCE.emit(copied, output)
            self.assertFalse(output.exists())
            extra.unlink()
            output.mkdir()
            sentinel = output / "sentinel.txt"
            sentinel.write_bytes(b"keep\n")
            with self.assertRaises(ValueError):
                SOURCE.emit(copied, output)
            self.assertEqual(sentinel.read_bytes(), b"keep\n")
            self.assertEqual(list(output.iterdir()), [sentinel])


if __name__ == "__main__":
    sys.addaudithook(fence)
SPEC.loader.exec_module(SOURCE)

if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *UNITTEST_ARGS], verbosity=2)
