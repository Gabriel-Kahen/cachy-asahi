# SPDX-License-Identifier: MIT
"""Offline controls for the exact Current606 scoped report-focus Source."""

import argparse
from contextlib import contextmanager
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import target_focus606_source as source

REPOSITORY = None
R4_DRIVER = None


@contextmanager
def actor_fence():
    fenced = True

    def audit(event, _):
        if fenced and event.startswith(("subprocess.", "socket.", "os.exec", "os.fork",
                                        "os.posix_spawn", "os.system", "os.kill")):
            raise RuntimeError("Source control forbids process and network access")

    sys.addaudithook(audit)
    try:
        yield
    finally:
        fenced = False


class Controls(unittest.TestCase):
    def test_missing_or_forged_manifest_refuses_under_actor_fence(self):
        with actor_fence():
            for bodies in ({}, {source.MANIFEST: b'{"files":{}}'}):
                with self.assertRaisesRegex(ValueError, "Exact R4 source manifest"):
                    source.transform(bodies)

    def test_exact_public_git_replay(self):
        if REPOSITORY is None:
            self.skipTest("supply --repository containing the published R5 ancestry")
        peer, clock = source.peer, source.clock
        parent = peer.committed_tree(REPOSITORY, source.PARENT, source.PARENT_TREE, source.PARENT_BYTES)
        reference = peer.committed_tree(REPOSITORY, source.CANDIDATE, source.CANDIDATE_TREE,
                                        source.CANDIDATE_BYTES)
        with actor_fence():
            for name in (source.EXTENSION, source.INVERSE, "fresh-test/selection.json"):
                tampered = parent | {name: parent[name] + b"\n"}
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Exact R4 source body closure"):
                    source.transform(tampered)
            candidate = source.transform(parent)
        self.assertEqual(candidate, reference)
        self.assertEqual({name for name in candidate if candidate[name] != parent[name]}, set(source.CHANGED))
        with TemporaryDirectory(prefix="target-focus606-export-") as directory:
            output = Path(directory) / "source"
            self.assertIsNone(source.emit(REPOSITORY, output)["actual"])
            pins = {name: clock.pin(body) for name, body in reference.items()}
            self.assertEqual(clock.read_tree(output, pins), reference)
            with self.assertRaisesRegex(ValueError, "Fresh canonical output"):
                source.emit(REPOSITORY, output)
            self.assertEqual(clock.read_tree(output, pins), reference)

    def test_wrong_local_git_refuses_without_output(self):
        with TemporaryDirectory(prefix="target-focus606-no-git-") as directory:
            root = Path(directory)
            nonrepo = root / "ordinary"
            nonrepo.mkdir()
            output = root / "source"
            with self.assertRaisesRegex(ValueError, "already be available in local Git"):
                source.emit(nonrepo, output)
            self.assertFalse(output.exists())

    def test_exact_emitted_driver_and_strict_focus_seams(self):
        if R4_DRIVER is None:
            self.skipTest("supply --r4-driver containing the retained R4 emitted driver")
        raw = R4_DRIVER.read_bytes()
        self.assertEqual(source.clock.pin(raw)["sha256"],
                         "6dc58945e71994b0dc38daf35a47d0398a305a04e0d84a231402234e5f0e14fc")
        old = raw.decode()
        with actor_fence():
            new = source.settle_target_focus(old)
            for bad in ("", new, old + "\nstatic void ensure_visible(guint pid)"):
                with self.assertRaisesRegex(ValueError, "Exact single source transformation seam"):
                    source.settle_target_focus(bad)
        self.assertEqual(source.clock.pin(new.encode())["sha256"],
                         "fdcead3c6f4dce5a3da09cd3123fbbc01bf73d057bcf4036dda810dabc6ad891")
        self.assertEqual(old.count("atspi_component_grab_focus("), new.count("atspi_component_grab_focus("))
        self.assertEqual(old.split("int main(", 1)[1], new.split("int main(", 1)[1])
        self.assertIn('check(!focus_called || focused || report_focused, "actual focused control required");', new)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repository", type=lambda value: Path(value).resolve(strict=True))
    parser.add_argument("--r4-driver", type=lambda value: Path(value).resolve(strict=True))
    options, rest = parser.parse_known_args()
    REPOSITORY, R4_DRIVER = options.repository, options.r4_driver
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
