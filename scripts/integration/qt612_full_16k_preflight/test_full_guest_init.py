# SPDX-License-Identifier: MIT
"""Source-only controls for the full Qtbase guest init's passive contracts."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

GUEST = Path(__file__).with_name("full-guest-init.sh").resolve()
PREFIX = """
source "$1"
shift
mount() { exit 97; }
umount() { exit 97; }
systemctl() { exit 97; }
timeout() { exit 97; }
chroot() { exit 97; }
blkid() { exit 97; }
blockdev() { exit 97; }
mknod() { exit 97; }
"""
SCRATCH = "ed56022f-4e82-f6e3-fbde-502489347154"
LIBS = ("libQt6Core.so.6.12.0", "libQt6Gui.so.6.12.0")
CAPS = "\n".join(["50 16 32", "build.log 16", "result.json 16", *(f"{lib} 32" for lib in LIBS)])


def model(code, *args, cwd=None):
    return subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c", PREFIX + code,
                           "test", str(GUEST), *map(str, args)], cwd=cwd, stdin=subprocess.DEVNULL,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, capture_output=True, timeout=5)


def command_line(**updates):
    fields = dict(nonce="a" * 32, manifest="b" * 64, guest_plan="c" * 64, scratch_uuid=SCRATCH,
                  result_uuid="12345678-9012-4abc-acbd-123456789012", result_bytes=128 << 20,
                  guest_deadline=50400)
    fields.update(updates)
    return [f"cachy_qt_full_{name}={value}" for name, value in fields.items()]


def sha(data):
    return hashlib.sha256(data).hexdigest()


class GuestInitControls(unittest.TestCase):
    def test_cmdline_refuses_unknown_fields_wrong_media_or_geometry(self):
        code = 'parse_cmdline "$@"; printf "%s %s %s\\n" "$nonce" "$result_bytes" "$guest_deadline"'
        valid = model(code, "quiet", *command_line())
        self.assertEqual(valid.stdout, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 134217728 50400\n")
        self.assertEqual(valid.returncode, 0)
        for invalid in (command_line()[:-1], command_line() + command_line()[:1],
                        command_line() + ["cachy_qt_full_extra=1"],
                        command_line(result_uuid=SCRATCH), command_line(result_bytes=(128 << 20) + 1),
                        command_line(result_bytes=8 << 30), command_line(guest_deadline=90001)):
            with self.subTest(invalid=invalid):
                self.assertEqual(model(code, *invalid).returncode, 1)

    def test_manifest_requires_sorted_exact_four_pinned_leaves(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "media"
            root.mkdir()
            names = ("FULL-GUEST-PLAN.json", "full_guest.py", "guest-init.sh", "guest_link.py")
            for name in names:
                (root / name).write_text(name + " inert\n")
            lines = [f"{sha((root / name).read_bytes())}  {name}\n" for name in names]
            expected = sha((root / names[0]).read_bytes())
            code = 'manifest=$1; guest_plan=$2; verify_payload'
            manifest = root / "MANIFEST.sha256"
            raw = "".join(lines).encode()
            manifest.write_bytes(raw)
            self.assertEqual(model(code, sha(raw), expected, cwd=root).returncode, 0)
            self.assertEqual(model(code, sha(raw), "e" * 64, cwd=root).returncode, 1)
            swapped = "".join(reversed(lines)).encode()
            manifest.write_bytes(swapped)
            self.assertEqual(model(code, sha(swapped), expected, cwd=root).returncode, 1)
            manifest.write_bytes(raw)
            (root / ".extra").touch()
            self.assertEqual(model(code, sha(raw), expected, cwd=root).returncode, 1)
            (root / ".extra").unlink()
            member = root / names[-1]
            external = root.parent / "data"
            member.rename(external)
            member.symlink_to(external)
            self.assertEqual(model(code, sha(raw), expected, cwd=root).returncode, 1)

    def test_result_root_refuses_stale_or_hidden_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = 'fresh_result_root "$1"'
            self.assertEqual(model(code, root).returncode, 0)
            (root / ".previous").touch()
            self.assertEqual(model(code, root).returncode, 1)
            (root / ".previous").unlink()
            (root / "lost+found").symlink_to(root, target_is_directory=True)
            self.assertEqual(model(code, root).returncode, 1)

    def test_evidence_caps_require_all_original_leaves_on_pass(self):
        code = 'result_bytes=67108864 guest_deadline=60; parse_caps "$1"; retain "$2" "$3" "$4"'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            bodies = {"build.log": b"worker log", "result.json": b"original", **dict.fromkeys(LIBS, b"A" * 16)}
            for name, raw in bodies.items():
                (source / name).write_bytes(raw)
            self.assertEqual(model(code, CAPS, source, target, "PASS").returncode, 0)
            self.assertEqual({file.name: file.read_bytes() for file in target.iterdir()}, bodies)
            self.assertTrue(all(file.stat().st_mode & 0o777 == 0o600 for file in target.iterdir()))
            self.assertEqual(model(code, CAPS + "\nresult.json 16", source, target, "PASS").returncode, 1)
            for file in target.iterdir():
                file.unlink()
            (source / LIBS[0]).unlink()
            self.assertEqual(model(code, CAPS, source, target, "PASS").returncode, 1)

    def test_hold_limits_aggregate_bytes_and_ignores_aliased_or_unknown_leaves(self):
        code = 'result_bytes=67108864 guest_deadline=60; parse_caps "$1"; retain "$2" "$3" HOLD'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            (source / "build.log").write_bytes(b"worker log")
            self.assertEqual(model(code, CAPS, source, target).returncode, 0)
            for lib in LIBS:
                (source / lib).write_bytes(b"A" * 17)
            os.link(source / "build.log", source / ".hardlink")
            (source / "result.json").symlink_to(source / "build.log")
            (target / "build.log").unlink()
            self.assertEqual(model(code, CAPS, source, target).returncode, 1)
            self.assertEqual([file.name for file in target.iterdir()], [LIBS[0]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
