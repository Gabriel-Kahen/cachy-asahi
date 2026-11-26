# SPDX-License-Identifier: MIT
"""Exercise the guest callback adapter with inert commands and capture fixtures."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
G = SimpleNamespace(**run_path(str(HERE / "guest.py")))
W, T = G.W, G.T
APP = "/qt-install-work/consumer/qt612-smoke"


class GuestRunner(unittest.TestCase):
    def test_ordinary_launch_sets_diagnostic_only_at_final_exec(self):
        command = G.Runner(None, Path("/unused"), 200, {
            "run": [APP], "environment": {"HOME": "/qt-install-work/home"},
        })
        args = command.command_argv("install-consumer-run", [APP], {"HOME": "/qt-install-work/home", "LD_DEBUG": "files"})
        self.assertEqual(args, G.DROP + ["/usr/bin/env", "-i", "HOME=/qt-install-work/home", "LD_DEBUG=files", APP])
        soname = ["/usr/bin/python3", "-I", "-B", G.O.PROBE, "libQt6Core.so.6"]
        self.assertEqual(command.command_argv("baseline-observe-soname-0", soname, W.NORMAL_ENV)[:len(G.DROP)], G.DROP)
        with self.assertRaisesRegex(ValueError, "consumer command"):
            command.command_argv("install-consumer-run", [APP], {"LD_DEBUG": "all"})
        with self.assertRaisesRegex(ValueError, "loader probe"):
            command.command_argv("baseline-observe-soname-0", ["/usr/bin/bash"], W.NORMAL_ENV)

    def test_owned_recorder_retains_real_naturally_reaped_nonzero_with_streams(self):
        runtime = G.runtime_module()
        with TemporaryDirectory() as temp:
            output = Path(temp)
            runner = G.Runner(runtime, output, time.monotonic() + 45, {})
            argv = ["/usr/bin/python3", "-I", "-B", "-c",
                    "import sys; assert sys.stdin.buffer.read() == b''; "
                    "print('mock exact dependency'); print('stderr', file=sys.stderr); sys.exit(127)"]
            row = runner("installed-official-version", argv, timeout=10, stdin=None, env=W.NORMAL_ENV)
            self.assertEqual(row, dict(exit_code=127, stdout=b"mock exact dependency\n", stderr=b"stderr\n",
                                       natural=True, group_empty=True, overflow=False))
            self.assertEqual((output / "installed-official-version.stdout").read_bytes(), row["stdout"])
            self.assertEqual((output / "installed-official-version.stderr").read_bytes(), row["stderr"])
            self.assertEqual(runtime.receipt(output / "installed-official-version.json")["group_census"], "EMPTY_TWICE")

    def test_only_exact_ownertrust_command_retains_and_receives_input(self):
        fake = Mock()
        with TemporaryDirectory() as temp:
            output = Path(temp)
            runner = G.Runner(fake, output, 300, {})
            argv = W.GPG + ["--import-ownertrust"]
            ownertrust = b"A" * 40 + b":6:\n"
            saved = output / "key-trust.stdin"
            for invalid in (None, ownertrust.lower(), ownertrust + b"\n", ownertrust.replace(b":6:", b":5:")):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "public TEST ownertrust"):
                    runner("key-trust", argv, timeout=10, stdin=invalid, env=W.NORMAL_ENV)
            with self.assertRaisesRegex(ValueError, "public TEST ownertrust"):
                runner("key-trust", W.GPG + ["--list-keys"], timeout=10, stdin=ownertrust, env=W.NORMAL_ENV)
            with self.assertRaisesRegex(ValueError, "Only key-trust"):
                runner("key-import", W.GPG + ["--import"], timeout=10, stdin=b"", env=W.NORMAL_ENV)
            fake.command.assert_not_called()
            self.assertFalse(saved.exists())

            def run(wrapped, root, role, *, input_file, **kwargs):
                self.assertEqual((root, role), (output, "key-trust"))
                self.assertEqual(saved.read_bytes(), input_file.read())
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
                fake.receipt.return_value = {"argv": wrapped, "exit": 0}
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            fake.command.side_effect = run
            fake._retired.return_value = True
            runner("key-trust", argv, timeout=10, stdin=ownertrust, env=W.NORMAL_ENV)
            fake.receipt.assert_called_once_with(output / "key-trust.json")
            self.assertEqual(saved.read_bytes(), ownertrust)

    def test_deadline_reserves_existing_cleanup_and_original_receipt_required(self):
        fake = Mock()
        fake.command.return_value = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        fake.receipt.return_value = {"argv": ["different"], "exit": 0}
        fake._retired.return_value = True
        with TemporaryDirectory() as temp:
            runner = G.Runner(fake, Path(temp), 300, {})
            for role, deadline in (("install-mutation", 270), ("trust-retirement", 300)):
                with self.assertRaisesRegex(ValueError, "natural-retirement receipt"):
                    runner(role, ["/usr/bin/true"], timeout=10, stdin=None, env=W.NORMAL_ENV)
                self.assertEqual(fake.command.call_args.kwargs["deadline"], deadline)

    def test_q3_mounts_exclude_bound_foreign_package_database(self):
        role = {"root": "/qtwork/root"}
        rows = ["1 0 253:1 /root / rw,nosuid - ext4 /dev/vdb rw",
                "2 1 253:2 /selected /qt-install-inputs ro,nosuid - ext4 /dev/vda ro",
                "3 1 253:2 /source /qt-source ro,nosuid - ext4 /dev/vda ro",
                "4 1 0:1 / /proc ro,nosuid - proc proc rw"]
        source, media = Path("/qt-source"), Path("/qt-install-inputs")
        G.verify_mounts(rows, source, media, role)
        with self.assertRaisesRegex(ValueError, "local package database"):
            G.verify_mounts(rows + ["5 1 253:6 /foreign /var/lib rw,nosuid - ext4 /dev/vde rw"], source, media, role)
        with self.assertRaisesRegex(ValueError, "Q3 ext4 root"):
            G.verify_mounts([rows[0].replace("/root /", "/ /"), *rows[1:]], source, media, role)
        with self.assertRaisesRegex(ValueError, "Expected isolated mount"):
            G.verify_mounts([rows[0], rows[1].replace(" ro,nosuid", " rw,nosuid"), *rows[2:]], source, media, role)
        with self.assertRaisesRegex(ValueError, "mount trees"):
            G.verify_mounts(rows + ["5 3 253:6 /foreign /qt-source/scripts rw - ext4 /dev/vde rw"], source, media, role)

    def test_execute_joins_original_worker_to_observer_callbacks_after_checks(self):
        pins = {"archive": T.pin(b"archive"), "certificate": T.pin(b"cert"), "signature": T.pin(b"sig")}
        sight = dict(input_pins=pins, config_raw=G.P.CONFIG.encode(),
                     certificate_raw=b"cert", signature_raw=b"sig")
        with TemporaryDirectory() as temp:
            base = Path(temp)
            media, work = base / "media", base / "work"
            media.mkdir()
            (media / "consumer").mkdir()
            work.mkdir()
            (work / "evidence").mkdir()
            sample = b"consumer fixture"
            (media / "consumer" / "smoke.cpp").write_bytes(sample)
            (media / "loader_probe.py").write_bytes((HERE / "loader_probe.py").read_bytes())
            plan = dict(nonce="a" * 32, guest={"model": True}, consumer={"files": {"smoke.cpp": T.pin(sample)}})
            selection = {"inputs": pins}
            protected = (Path("/etc/pacman.conf"),)
            boundary, runtime = Mock(return_value=True), Mock()
            prepare, observer = Mock(return_value=work / "evidence" / "commands"), Mock()
            view = dict(database=b"model database", protected=b"model protected", payload={})
            observer.observe.return_value = view

            def perform(*args, **kwargs):
                self.assertIs(kwargs["observe"]("baseline"), view)
                return {"status": "model callback receipt"}

            with (patch.dict(G.execute.__globals__, MEDIA=media, WORK=work, verify_boundary=boundary,
                             runtime_module=Mock(return_value=runtime), prepare_work=prepare),
                  patch.object(W, "read_plan", return_value=plan), patch.object(W, "read_selection", return_value=selection),
                  patch.object(G.O, "input_evidence", return_value=sight), patch.object(G.O, "Observer", return_value=observer) as adapter,
                  patch.object(W, "exercise", side_effect=perform) as exercise):
                G.execute(b"plan", "a" * 64, b"inventory", b"selection", "b" * 64,
                          now=1, deadline=time.monotonic() + 120, protected=protected)
                actual_plan, actual_selection, runner, paths = adapter.call_args.args
                self.assertEqual((actual_plan, actual_selection, paths), (plan, selection, protected))
                self.assertIs(runner.runtime, runtime)
                kwargs = exercise.call_args.kwargs
                self.assertTrue(callable(kwargs.pop("observe")))
                self.assertEqual(kwargs, dict(now=1, **sight, verify_boundary=boundary, run=observer.run))
                boundary.assert_called_once_with(plan["nonce"], plan["guest"])
                observer.observe.assert_called_once_with("baseline")
                self.assertEqual(T.decode((work / "evidence" / "result.json").read_bytes()),
                                 {"status": "model callback receipt"})
                self.assertEqual((work / "evidence" / "baseline-database.json").read_bytes(), view["database"])
                self.assertEqual((work / "evidence" / "baseline-protected.json").read_bytes(), view["protected"])
                self.assertEqual(T.decode((work / "evidence" / "baseline-observed.json").read_bytes()),
                                 dict(database=T.pin(view["database"]), protected=T.pin(view["protected"]), payload={}))
                (media / "consumer" / "smoke.cpp").write_bytes(b"changed")
                prepare.reset_mock()
                with self.assertRaises(ValueError):
                    G.execute(b"plan", "a" * 64, b"inventory", b"selection", "b" * 64,
                              now=1, deadline=time.monotonic() + 120, protected=protected)
                prepare.assert_not_called()
