# SPDX-License-Identifier: MIT
"""Inert controls for the QtGui PID 1 boot and original evidence selection."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


GUEST = Path(__file__).with_name("guest-init.sh").resolve()
BASH = "/usr/bin/bash"
NAMES = ("GUI-GUEST-PLAN.json", "guest-init.sh", "guest_link.py")
OUTPUTS = ("inventory.before", "inventory.after", "core.commands", "gui.commands", "gui.link-command",
           "core-dry-run.log", "gui-dry-run.log", "build.log", "metrics.json", "aliases.txt",
           "libQt6Gui.so.6.12.0", "libQt6DBus.so.6.12.0", "libmd4c.so.0.5.3", "result.json")
PREFIX = """
guest=$1
shift
source "$guest"
mount() { exit 97; }
umount() { exit 97; }
systemctl() { exit 97; }
timeout() { exit 97; }
chroot() { exit 97; }
blkid() { exit 97; }
blockdev() { exit 97; }
mknod() { exit 97; }
"""


def fence(event, args):
    if event in {"subprocess.Popen", "os.posix_spawn"}:
        executable, argv, *_ = args
        if executable != BASH or argv[:3] != [BASH, "--noprofile", "--norc"]:
            raise AssertionError("Only the inert Bash fixture may spawn")
    if event.startswith(("socket.", "ctypes.")) or event in {"os.system", "os.exec"}:
        raise AssertionError("Passive guest controls forbid an actor or connection")


sys.addaudithook(fence)


def model(code, *args, cwd=None):
    return subprocess.run([BASH, "--noprofile", "--norc", "-c", PREFIX + code, "test", str(GUEST), *map(str, args)],
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=5)


def pin(raw):
    return hashlib.sha256(raw).hexdigest()


def command_line(**changed):
    fields = dict(nonce="a" * 32, manifest="b" * 64, guest_plan="c" * 64,
                  scratch_uuid="ed56022f-4e82-f6e3-fbde-502489347154",
                  result_uuid="12345678-9012-4abc-acbd-123456789012", result_bytes=128 << 20,
                  guest_deadline=10101)
    fields.update(changed)
    return [f"cachy_qt_gui_{name}={value}" for name, value in fields.items()]


class GuestInitControls(unittest.TestCase):
    def test_cmdline_is_exact_and_accepts_external_geometry_and_deadline(self):
        code = 'parse_cmdline "$@"; printf "%s %s %s\\n" "$nonce" "$result_bytes" "$guest_deadline"'
        valid = model(code, "quiet", *command_line())
        self.assertEqual((valid.returncode, valid.stdout), (0, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 134217728 10101\n"))
        for invalid in (command_line()[:-1],
                        command_line() + [command_line()[0]],
                        command_line() + ["cachy_qt_gui_extra=1"],
                        command_line(result_bytes=(128 << 20) + 1),
                        command_line(result_bytes=8 << 30),
                        command_line(result_uuid="ed56022f-4e82-f6e3-fbde-502489347154"),
                        command_line(guest_deadline="00010"),
                        command_line(guest_deadline=90001)):
            with self.subTest(invalid=invalid):
                self.assertEqual(model(code, *invalid).returncode, 1)

    def test_payload_requires_exact_three_rows_and_separate_plan_pin(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in NAMES:
                (root / name).write_bytes(name.encode("ascii") + b" inert\n")
            raw = "".join(f"{pin((root / name).read_bytes())}  {name}\n" for name in NAMES).encode()
            (root / "MANIFEST.sha256").write_bytes(raw)
            guest_plan = pin((root / NAMES[0]).read_bytes())
            code = 'manifest=$1; guest_plan=$2; verify_payload'
            self.assertEqual(model(code, pin(raw), guest_plan, cwd=root).returncode, 0)
            self.assertEqual(model(code, pin(raw), "e" * 64, cwd=root).returncode, 1)
            amended = raw + f"{'a' * 64}  ../other\n".encode()
            (root / "MANIFEST.sha256").write_bytes(amended)
            self.assertEqual(model(code, pin(amended), guest_plan, cwd=root).returncode, 1)
            (root / "MANIFEST.sha256").write_bytes(raw)
            worker = root / NAMES[-1]
            worker.rename(root / "extra.py")
            worker.symlink_to(root / "extra.py")
            self.assertEqual(model(code, pin(raw), guest_plan, cwd=root).returncode, 1)

    def test_pass_copies_each_exact_worker_byte_and_needs_every_leaf(self):
        code = 'log_cap=1000; artifact_cap=1000; retain "$1" "$2" PASS'
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            for label in OUTPUTS:
                (source / label).write_bytes(label.encode("ascii") + b" original\n")
            self.assertEqual(model(code, source, target).returncode, 0)
            self.assertEqual({p.name for p in target.iterdir()}, set(OUTPUTS))
            for label in OUTPUTS:
                self.assertEqual((target / label).read_bytes(), (source / label).read_bytes())
                self.assertEqual((target / label).stat().st_mode & 0o777, 0o600)
            (source / "result.json").unlink()
            for entry in target.iterdir():
                entry.unlink()
            self.assertEqual(model(code, source, target).returncode, 1)
            self.assertFalse((target / "result.json").exists())

    def test_hold_preserves_bounded_prefix_and_refuses_extra_or_aliased_leaf(self):
        code = 'log_cap=10; artifact_cap=30; retain "$1" "$2" HOLD'
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            (source / "inventory.before.raw").write_bytes(b"original hold\n")
            (source / "build.log").write_bytes(b"some log")
            self.assertEqual(model(code, source, target).returncode, 0)
            (source / "build.log").write_bytes(b"too many bytes")
            (source / "unreviewed").write_bytes(b"stray")
            os.link(source / "inventory.before.raw", source / "gui.commands.after")
            for entry in target.iterdir():
                entry.unlink()
            self.assertEqual(model(code, source, target).returncode, 1)
            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
