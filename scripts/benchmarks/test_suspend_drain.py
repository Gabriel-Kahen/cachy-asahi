# SPDX-License-Identifier: MIT
"""Read-only suspend-window controls with synthetic sensor and clock changes."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("suspend_drain", Path(__file__).with_name("suspend_drain.py"))
drain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(drain)
metrics = drain.metrics
SECOND = 10**9


class SuspendDrainTests(unittest.TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.battery = self.root / "battery"
        self.battery.mkdir()
        for key, value in dict(type="Battery", status="Discharging", present="1", energy_now="54000000").items():
            (self.battery / key).write_text(value + "\n")
        first = self.capture("before", 100 * SECOND, 200 * SECOND, 1000 * SECOND)
        (self.battery / "energy_now").write_text("53900000\n")
        second = self.capture("after", 102 * SECOND, 3802 * SECOND, 900 * SECOND)
        self.endpoints = first, second

    def capture(self, phase, monotonic, boottime, realtime):
        sensor = drain.energy_sensor(self.battery)
        sample = metrics.snapshot({"sensors": [sensor]}, 0)
        sensor["directory"] = "/sys/class/power_supply/macsmc-battery"
        sensor["id"] = sample["readings"][0]["id"] = sensor["directory"] + "/energy_now"
        # The real raw reader was used above. Only timing and the fixture path
        # are projected to the shape of a later hardware capture.
        sample["start"] = dict(monotonic_ns=monotonic, boottime_ns=boottime, realtime_ns=realtime)
        sample["end"] = {key: value + 1000 for key, value in sample["start"].items()}
        reading = sample["readings"][0]
        for row in [reading["reading"], *reading["context_before"].values(), *reading["context_after"].values()]:
            row.update(monotonic_start_ns=monotonic+100, monotonic_end_ns=monotonic+900)
        return dict(schema=drain.ENDPOINT, phase=phase, baseline=dict(bytes=32, sha256="1"*64),
                    collector=drain.collector(),
                    trial=dict(machine_id="m2-" + "2"*32, trial_id="trial-01", battery="macsmc-battery",
                               execution_context="physical", minimum_suspended_seconds=3599),
                    machine=dict(model="apple,j413", architecture="aarch64", page_size_bytes=16384,
                                 kernel="asahi", boot_id_sha256="3"*64),
                    sensor=sensor, sample=sample)

    def compare(self):
        return drain.compare(*self.endpoints, pins={})

    def test_long_window_keeps_awake_time_and_acceptance_separate(self):
        result = self.compare()
        self.assertEqual(result["status"], "OBSERVED_WINDOW")
        self.assertEqual(result["elapsed_ns"], {"lower": 3602*SECOND-1000, "upper": 3602*SECOND+1000})
        self.assertEqual(result["awake_ns"], {"lower": 2*SECOND-1000, "upper": 2*SECOND+1000})
        self.assertEqual(result["kernel_suspended_ns"], {"lower": 3600*SECOND-2000, "upper": 3600*SECOND+2000})
        self.assertEqual(result["energy_lost_uwh"], 100_000)
        self.assertAlmostEqual(result["window_average_w"]["lower"], 360 / 3602, places=7)
        self.assertEqual(result["hardware_validation"], "NOT RUN")

    def test_reboot_different_baseline_and_reversed_endpoint_order_refused(self):
        for key, leaf in (("machine", "boot_id_sha256"), ("baseline", "sha256"), ("trial", "trial_id")):
            with self.subTest(key=key):
                before, after = copy.deepcopy(self.endpoints)
                after[key][leaf] = "4"*64 if key != "trial" else "other"
                with self.assertRaisesRegex(ValueError, "different trial"):
                    drain.compare(before, after, pins={})
        with self.assertRaisesRegex(ValueError, "phase"):
            drain.compare(*reversed(self.endpoints), pins={})

    def test_insufficient_sleep_is_not_drain_evidence(self):
        for endpoint in self.endpoints:
            endpoint["trial"]["minimum_suspended_seconds"] = 3600
        result = self.compare()
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("lower bound", result["reason"])
        self.assertIsNone(result["energy_lost_uwh"])

    def test_lost_sensor_charging_increase_and_no_resolved_change(self):
        before = self.endpoints[0]
        for energy, status, reason in (
            (None, "Discharging", "missing or unreadable"),
            ("53900000", "Charging", "state transition"),
            ("55000000", "Discharging", "increased"),
            ("54000000", "Discharging", "did not resolve"),
        ):
            with self.subTest(energy=energy, status=status):
                leaf = self.battery / "energy_now"
                if energy is None:
                    leaf.unlink()
                else:
                    leaf.write_text(energy + "\n")
                (self.battery / "status").write_text(status + "\n")
                after = self.capture("after", 102*SECOND, 3802*SECOND, 1500*SECOND)
                result = drain.compare(before, after, pins={})
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertIn(reason, result["reason"])
                self.assertIsNone(result["window_average_w"])
                self.assertEqual(result["energy_lost_uwh"], 0 if energy == "54000000" else None)

    def test_offline_cli_checks_exact_pins_and_preserves_output(self):
        flags = []
        for endpoint in self.endpoints:
            phase = endpoint["phase"]
            path = self.root / f"{phase}.json"
            raw = metrics.encoded(endpoint)
            path.write_bytes(raw)
            flags.extend([f"--{phase}", str(path), f"--{phase}-sha256", metrics.pin_bytes(raw)["sha256"]])
        result = self.root / "result.json"
        with patch("sys.stdout", new=io.StringIO()) as printed, patch("sys.stderr", new=io.StringIO()) as errors:
            self.assertEqual(drain.main(["compare", *flags, "--output", str(result)]), 0)
            expected = result.read_bytes()
            self.assertEqual(json.loads(printed.getvalue()), metrics.pin_bytes(expected))
            self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
            self.assertEqual(drain.main(["compare", *flags, "--output", str(result)]), 1)
            self.assertEqual(result.read_bytes(), expected)
            wrong = self.root / "wrong.json"
            self.assertEqual(drain.main(["compare", *flags[:-1], "0"*64, "--output", str(wrong)]), 1)
            self.assertIn("input SHA-256", errors.getvalue())
            self.assertFalse(wrong.exists())


if __name__ == "__main__":
    unittest.main()
