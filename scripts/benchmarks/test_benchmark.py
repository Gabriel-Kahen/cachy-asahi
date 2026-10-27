"""Portable source-framework tests; synthetic/x86 runs are never M2 acceptance."""
import copy
import base64
import gzip
import hashlib
from datetime import timedelta
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import signal
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("benchmark", Path(__file__).with_name("benchmark.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.driver = self.root / "workload.py"
        self.driver.write_text("import sys\nprint(repr(sys.argv[1:]))\n")
        self.state = self.root / "baseline.json"
        self.record = {"architecture": "x86_64", "execution_context": "unknown", "kernel": "synthetic",
                       "page_size_bytes": 4096, "packages": {"returncode": 1}, "repositories": {"sync_databases": []}}
        self.state.write_text(json.dumps(self.record))
        self.config = {"experiment_id": "synthetic-smoke", "machine_id": "fake-x86", "base_id": "fake-base",
                       "workload_id": "argv-check", "execution_context": "unknown",
                       "change": {"variable": "synthetic", "baseline": "A", "candidate": "B", "rationale": "test only"},
                       "argv": [sys.executable, str(self.driver), "literal;$(touch SHOULD_NOT_EXIST)"],
                       "inputs": [sys.executable, str(self.driver)], "order": ["baseline", "candidate", "candidate", "baseline"] * 3,
                       "minimum_trials": 5, "timeout_seconds": 2, "sample_seconds": .02,
                       "controls": {"power_source": "AC", "display_config": "fixed", "brightness": "fixed",
                                    "cache_mode": "warm", "background_load": "none", "warmup": "one pre-run",
                                    "ambient_C": [19, 21], "thermal_start_C": [30, 35], "battery_soc_percent": [40, 60]},
                       "thresholds": {"minimum_elapsed_improvement_pct": 1, "maximum_elapsed_range_pct": 100}}
        self.conditions = self.root / "conditions.json"
        self.observed = self.config["controls"] | {"ambient_C": 20, "thermal_start_C": 32, "battery_soc_percent": 50,
                                                  "operator": "test", "notes": "synthetic controls"}
        self.conditions.write_text(json.dumps(self.observed))
        self.config_path = self.root / "config.json"
        self.plan = self.root / "plan.json"

    def freeze(self):
        self.config_path.write_text(json.dumps(self.config))
        b.freeze(self.config_path, self.state, self.state, self.plan)
        return b.load_plan(self.plan)

    def synthetic_trials(self):
        plan = self.freeze()
        declared = b.utc_timestamp(plan["frozen_at"])
        directories = []
        for slot, variant in enumerate(self.config["order"]):
            directory = self.root / f"trial-{slot}"
            directory.mkdir()
            (directory / "stdout.txt").write_text("workload result\n")
            (directory / "stderr.txt").write_text("")
            elapsed = 1_000_000_000 if variant == "baseline" else 900_000_000
            start = slot * 3_000_000_000
            sample = {"memory": {"root_rss_kib": 10, "lifecycle": "live"}, "thermal": [], "power": [], "monotonic_ns": start + 1}
            (directory / "telemetry.jsonl").write_text(json.dumps(sample) + "\n")
            trial = {"record_type": "benchmark-trial", "plan_sha256": b.digest(self.plan), "slot": slot, "variant": variant,
                     "machine_id": self.config["machine_id"], "base_id": self.config["base_id"],
                     "workload_id": self.config["workload_id"], "argv": self.config["argv"], "state": plan["states"][variant],
                     "state_after": plan["states"][variant], "conditions": self.observed,
                     "valid": True, "returncode": 0, "error": None, "hostname": "synthetic", "environment_sha256": "same",
                     "sampling_status": {"worker_stopped": True, "workload_reaped": True, "error": None, "dropped_samples": 0},
                     "comparable_environment_sha256": "same", "declared_environment": self.config.get("env", {}) |
                     self.config.get("variant_env", {}).get(variant, {}),
                     "elapsed_ns": elapsed, "monotonic_start_ns": start, "monotonic_end_ns": start + elapsed,
                     "started_at": (declared + timedelta(seconds=slot * 2 + 1)).isoformat(),
                     "finished_at": (declared + timedelta(seconds=slot * 2 + 2)).isoformat(), "metrics": b.metrics([sample]),
                     "raw_sha256": {name: b.digest(directory / name) for name in ("stdout.txt", "stderr.txt", "telemetry.jsonl")}}
            b.write_json(directory / "trial.json", trial)
            directories.append(directory)
        return directories

    def modify(self, directory, key, value):
        path = directory / "trial.json"
        trial = b.read_json(path)
        trial[key] = value
        path.write_text(json.dumps(trial))

    def replace_samples(self, directory, samples):
        trial = b.read_json(directory / "trial.json")
        (directory / "telemetry.jsonl").write_text("".join(json.dumps(s) + "\n" for s in samples))
        trial.update({"sample_count": len(samples), "metrics": b.metrics(samples)})
        trial["raw_sha256"]["telemetry.jsonl"] = b.digest(directory / "telemetry.jsonl")
        (directory / "trial.json").write_text(json.dumps(trial))

    def test_insufficient_or_grouped_trials_refused(self):
        for order in (["baseline", "candidate"] * 4, ["baseline"] * 6 + ["candidate"] * 6):
            with self.subTest(order=order):
                config = copy.deepcopy(self.config)
                config["order"] = order
                with self.assertRaises(b.Invalid):
                    b.validate_config(config)

    def test_invalid_numerics_and_privilege_refused(self):
        for value in (True, float("nan"), float("inf"), -1):
            with self.subTest(value=value), self.assertRaises(b.Invalid):
                config = copy.deepcopy(self.config)
                config["sample_seconds"] = value
                b.validate_config(config)
        self.config["argv"][0] = "/usr/bin/sudo"
        with self.assertRaisesRegex(b.Invalid, "privilege"):
            b.validate_config(self.config)

    def test_workload_drift_and_overwrite_refused(self):
        self.freeze()
        with self.assertRaises(FileExistsError):
            b.freeze(self.config_path, self.state, self.state, self.plan)
        self.driver.write_text("changed")
        with self.assertRaisesRegex(b.Invalid, "input changed"):
            b.load_plan(self.plan)

    def test_base_machine_difference_refused(self):
        other = self.root / "candidate.json"
        other.write_text(json.dumps(self.record | {"architecture": "aarch64"}))
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(b.Invalid, "state differences"):
            b.freeze(self.config_path, self.state, other, self.plan)

    def test_physical_claim_without_gate_and_exact_model_refused(self):
        self.config["execution_context"] = "physical"
        with self.assertRaisesRegex(b.Invalid, "recovery evidence"):
            self.freeze()
        gate = self.root / "gates.json"
        gate.write_text(json.dumps({"machine_id": self.config["machine_id"], "base_id": self.config["base_id"],
                                    "baseline_functional": "PASS", "recovery": "PASS", "reviewer": "synthetic",
                                    "evidence": "synthetic declaration, not real hardware evidence"}))
        self.config["hardware_gate_evidence"] = str(gate)
        self.record.update({"execution_context": "physical", "m2_air_size": "13-inch",
                            "device_tree_compatible": "apple,j413", "packages": {"returncode": 0, "stdout": "fake 1"}})
        self.state.write_text(json.dumps(self.record))
        with self.assertRaisesRegex(b.Invalid, "exact M2 Air"):
            self.freeze()  # A claimed size/device tree cannot turn x86 into a target.

    def test_missing_sensors_and_process_rss_are_not_zero(self):
        data = b.telemetry(999, self.root / "nosys", self.root / "noproc")
        self.assertEqual(data["missing"], ["thermal", "power", "battery"])
        self.assertIsNone(data["memory"]["root_rss_kib"])
        self.assertIsNone(b.metrics([data])["root_rss_kib"])

    def test_sensor_units_and_partial_coverage(self):
        supply = self.root / "class/power_supply/BAT0"
        supply.mkdir(parents=True)
        (supply / "type").write_text("Battery")
        (supply / "temp").write_text("270")
        (supply / "energy_now").write_text("1234")
        thermal = self.root / "class/thermal/thermal_zone0"
        thermal.mkdir(parents=True)
        (thermal / "temp").write_text("42000")
        first = b.telemetry(123, self.root, self.root / "noproc")
        readings = {r["path"].split("/")[-1]: r for r in first["battery"][0]["readings"]}
        self.assertEqual(readings["temp"]["unit"], "tenths_C")
        self.assertEqual(readings["energy_now"]["unit"], "uWh")
        self.assertEqual(first["thermal"][0]["unit"], "mC")
        (thermal / "temp").write_text("unreadable")
        second = b.telemetry(123, self.root, self.root / "noproc")
        self.assertIsNone(b.metrics([first, second])["thermal"][str(thermal / "temp")])

    def test_argv_is_literal_and_failure_retained(self):
        directory = self.root / "literal"
        directory.mkdir()
        result = b.execute(self.config["argv"], self.root, os.environ.copy(), directory, 2, .02)
        self.assertEqual(result["returncode"], 0)
        self.assertIn("$(touch SHOULD_NOT_EXIST)", (directory / "stdout.txt").read_text())
        self.assertFalse((self.root / "SHOULD_NOT_EXIST").exists())
        directory = self.root / "failure"
        directory.mkdir()
        result = b.execute([sys.executable, "-c", "import sys;sys.exit(7)"], self.root, os.environ.copy(), directory, 2, .02)
        self.assertEqual(result["returncode"], 7)

    def test_timeout_cleans_descendants(self):
        directory = self.root / "timeout"
        directory.mkdir()
        code = ("import subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
                "print(p.pid,flush=True);time.sleep(30)")
        result = b.execute([sys.executable, "-c", code], self.root, os.environ.copy(), directory, .2, .02)
        self.assertEqual(result["error"], "timeout")
        pid = int((directory / "stdout.txt").read_text().strip())
        # A killed orphan can briefly remain a zombie; neither state performs work.
        status = b.text_file(Path("/proc") / str(pid) / "status")
        self.assertTrue(status is None or "State:\tZ" in status)

    def test_live_drift_prevents_execution(self):
        self.freeze()
        with patch.object(b.os, "geteuid", return_value=1000), patch.object(b, "live_identity", return_value={}):
            with self.assertRaisesRegex(b.Invalid, "live machine"):
                b.run(self.plan, 0, self.state, self.conditions, self.root, self.root / "no-run")
        self.assertFalse((self.root / "no-run").exists())

    def test_root_execution_is_refused(self):
        with patch.object(b.os, "geteuid", return_value=0), self.assertRaisesRegex(b.Invalid, "root"):
            b.run(self.plan, 0, self.state, self.conditions, self.root, self.root / "no-root-run")
        self.assertFalse((self.root / "no-root-run").exists())

    def test_successful_comparison_never_accepts_optimization(self):
        directories = self.synthetic_trials()
        output = self.root / "compare.json"
        self.assertEqual(b.compare(self.plan, directories, output), 0)
        result = b.read_json(output)
        self.assertAlmostEqual(result["median_elapsed_improvement_pct"], 10)
        self.assertEqual(result["optimization_acceptance"], "NOT RUN")
        self.assertEqual(result["preliminary_result"], "MEETS_TIMING_RULE_ONLY")

    def test_missing_guardrail_is_incomplete(self):
        self.config["thresholds"]["maximum_regression"] = {"power_raw_uW_pct": 2}
        directories = self.synthetic_trials()
        output = self.root / "compare.json"
        self.assertEqual(b.compare(self.plan, directories, output), 2)
        self.assertEqual(b.read_json(output)["preliminary_result"], "INCOMPLETE")

    def test_each_comparison_binding_and_control_is_checked(self):
        directories = self.synthetic_trials()
        original = (directories[0] / "trial.json").read_text()
        bad = {"machine_id": "other", "base_id": "other", "workload_id": "other", "argv": ["other"],
               "comparable_environment_sha256": "other", "valid": False, "returncode": 1,
               "conditions": self.observed | {"power_source": "Battery"},
               "elapsed_ns": 0, "monotonic_end_ns": 5, "declared_environment": {"EXTRA": "1"},
               "sampling_status": {"worker_stopped": False},
               "metrics": {"root_rss_kib": 0}, "plan_sha256": "other",
               "finished_at": "2026-10-11T00:05:00+00:00"}
        for key, value in bad.items():
            with self.subTest(key=key):
                self.modify(directories[0], key, value)
                with self.assertRaises(b.Invalid):
                    b.compare(self.plan, directories, self.root / "compare.json")
                (directories[0] / "trial.json").write_text(original)

    def test_missing_duplicate_or_modified_raw_trials_refused(self):
        directories = self.synthetic_trials()
        for runs in (directories[:-1], directories + [directories[0]]):
            with self.assertRaisesRegex(b.Invalid, "trials"):
                b.compare(self.plan, runs, self.root / "compare.json")
        (directories[0] / "stdout.txt").write_text("changed")
        with self.assertRaisesRegex(b.Invalid, "raw output"):
            b.compare(self.plan, directories, self.root / "compare.json")

    def synthetic_sensor_cli(self):
        # Test-only entry; production telemetry and comparison stay unchanged.
        # Empty sensor identity matches the production no-snapshot fallback too.
        entry = self.root / "synthetic_sensor_cli.py"
        entry.write_text("""import importlib.util,os,sys,threading,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('synthetic_sensor_benchmark',sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
release=threading.Event();calls=0
original_killpg=b.os.killpg;original_queue=b.queue.Queue
ready=Path(sys.argv[sys.argv.index('--cwd')+1])/'sample-ready' if 'run' in sys.argv else None
def synthetic_telemetry(pid):
    global calls
    if calls and not release.wait(timeout=5):
        raise RuntimeError('synthetic sampler cleanup acknowledgement missing')
    calls+=1
    return dict(monotonic_ns=time.monotonic_ns(),thermal=[],power=[],battery=[],
                memory=dict(root_rss_kib=None,lifecycle='unknown'),
                missing=['thermal','power','battery','memory'],
                reason='EXPLICIT_SYNTHETIC_UNAVAILABLE_SENSORS_NOT_HARDWARE')
def cleanup(pid,sig):
    try:return original_killpg(pid,sig)
    finally:release.set()
class AcknowledgedQueue(original_queue):
    def put_nowait(self,row):
        super().put_nowait(row)
        ready.write_text('snapshot queued')
b.telemetry=synthetic_telemetry
b.os.killpg=cleanup
b.queue.Queue=AcknowledgedQueue
sys.argv=[sys.argv[0],*sys.argv[2:]]
raise SystemExit(b.main())
""")
        self.config["inputs"].append(str(entry))
        return [sys.executable, "-B", str(entry), str(Path(b.__file__))]

    def invalid_cli_packet(self, result, directory):
        paths = [self.config_path, self.plan, self.state, self.driver, self.root / "synthetic_sensor_cli.py"]
        paths += [directory / name for name in ("started.json", "trial.json", "stdout.txt", "stderr.txt", "telemetry.jsonl")]
        files, total = {}, 0
        for path in paths:
            if not path.is_file():
                continue
            raw = path.read_bytes()
            total += len(raw)
            self.assertLessEqual(total, 4 * 1024**2, "failure packet byte cap; no full-packet claim")
            files[str(path.relative_to(self.root))] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                                                     "base64": base64.b64encode(raw).decode()}
        body = json.dumps({"status": "INVALID_TRIAL_NOT_PERFORMANCE_EVIDENCE", "files": files,
                           "command": {"argv": result.args, "returncode": result.returncode,
                                       "stdout": result.stdout, "stderr": result.stderr}}, sort_keys=True).encode()
        compressed = gzip.compress(body, mtime=0)
        self.assertLessEqual(len(compressed), 256 * 1024, "failure packet log cap; no full-packet claim")
        (self.root / "cli-failure.json.gz").write_bytes(compressed)
        return "BENCHMARK_CLI_FAILURE_GZIP_BASE64 " + base64.b64encode(compressed).decode()

    def require_valid_cli_trial(self, result, directory):
        # run exit2 is INVALID evidence, never a negative timing verdict.
        path = directory / "trial.json"
        trial = b.read_json(path) if path.is_file() else {}
        diagnostic = {"cli_returncode": result.returncode, "cli_stderr": result.stderr,
                      "trial": {k: trial.get(k) for k in ("slot", "valid", "returncode", "error", "sampling_status")},
                      "state_changed": trial.get("state_after") != trial.get("state"),
                      "raw": {p.name: {"sha256": b.digest(p), "tail": p.read_text(errors="replace")[-4096:]}
                              for p in (directory / "stdout.txt", directory / "stderr.txt", directory / "telemetry.jsonl")
                              if p.is_file()}}
        message = json.dumps(diagnostic, sort_keys=True)
        if result.returncode != 0:
            # Assertion text survives CI even when TemporaryDirectory removes raw files.
            (self.root / "cli-invalid-trial.json").write_text(message + "\n")
            message += "\n" + self.invalid_cli_packet(result, directory)
        self.assertEqual(result.returncode, 0, message)
        self.assertTrue(trial.get("valid"), message)
        self.assertEqual(trial.get("returncode"), 0, message)
        self.assertIsNone(trial.get("error"), message)

    def require_cli_comparison(self, result, directories, output):
        self.assertTrue(output.is_file(), "comparison refused: " + result.stderr)
        report = b.read_json(output)
        # Replay unchanged production validation of raw hashes, conditions, cleanup,
        # complete trial graph and all budgets before accepting any CLI verdict.
        with tempfile.TemporaryDirectory(dir=self.root) as work:
            replay = Path(work) / "comparison.json"
            code = b.compare(self.plan, directories, replay)
            self.assertEqual(report, b.read_json(replay))
        verdict = "FAIL" if report["failures"] else "INCOMPLETE" if report["missing_guardrail_telemetry"] else "MEETS_TIMING_RULE_ONLY"
        self.assertEqual(report["preliminary_result"], verdict)
        self.assertEqual(result.returncode, code)
        self.assertEqual(code, 0 if verdict == "MEETS_TIMING_RULE_ONLY" else 2)
        self.assertEqual(report["record_type"], "preliminary-comparison")
        self.assertEqual(report["plan_sha256"], b.digest(self.plan))
        self.assertEqual(report["optimization_acceptance"], "NOT RUN")

    @unittest.skipIf(os.geteuid() == 0, "root workload execution intentionally refused")
    def test_actual_cli_roundtrip_is_nonacceptance_smoke(self):
        # Real workload/CLI/timing; explicitly synthetic unavailable sensors.
        # This portable protocol test establishes no physical sensor/M2 result.
        self.driver.write_text("import os,time\nfrom pathlib import Path\n"
                               "while not Path('sample-ready').exists():time.sleep(.001)\n"
                               "time.sleep(.05)\nprint('nonacceptance smoke',os.environ['SMOKE_VARIANT'])\n")
        self.config["change"]["environment_key"] = "SMOKE_VARIANT"
        self.config["variant_env"] = {"baseline": {"SMOKE_VARIANT": "A"}, "candidate": {"SMOKE_VARIANT": "B"}}
        live = b.live_identity("unknown")
        record = {key: value for key, value in live.items() if key not in ("packages", "repositories")}
        record["packages"] = {"returncode": 0 if live["packages"] is not None else 1, "stdout": live["packages"]}
        record["repositories"] = {"sync_databases": live["repositories"]}
        self.state.write_text(json.dumps(record))
        cli = self.synthetic_sensor_cli()
        self.config_path.write_text(json.dumps(self.config))
        prepared = subprocess.run(cli + ["prepare-plan", "--config", str(self.config_path), "--baseline", str(self.state),
                                        "--candidate-state", str(self.state), "--output", str(self.plan)], capture_output=True, text=True)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        directories = []
        for slot in range(len(self.config["order"])):
            directory = self.root / f"actual-{slot}"
            (self.root / "sample-ready").unlink(missing_ok=True)
            result = subprocess.run(cli + ["run", "--plan", str(self.plan), "--slot", str(slot), "--state", str(self.state),
                                          "--conditions", str(self.conditions), "--cwd", str(self.root), "--output", str(directory)],
                                    capture_output=True, text=True)
            self.require_valid_cli_trial(result, directory)
            self.assertIn("nonacceptance smoke", b.read_json(directory / "trial.json")["execution_label"])
            tag = self.config["change"][self.config["order"][slot]]
            self.assertIn(f"nonacceptance smoke {tag}", (directory / "stdout.txt").read_text())
            for sample in (directory / "telemetry.jsonl").read_text().splitlines():
                view = json.loads(sample)
                self.assertEqual(b.sensor_identity(view), {"thermal": [], "power": []})
                self.assertIsNone(view["memory"]["root_rss_kib"])
                self.assertIn("memory", view["missing"])
            directories.append(str(directory))
        output = self.root / "comparison.json"
        result = subprocess.run(cli + ["compare", "--plan", str(self.plan), "--runs", *directories, "--output", str(output)],
                                capture_output=True, text=True)
        self.require_cli_comparison(result, directories, output)

    def test_cli_complete_negative_and_incomplete_verdicts_are_preserved(self):
        for verdict in ("FAIL", "INCOMPLETE", "MEETS_TIMING_RULE_ONLY"):
            with self.subTest(verdict=verdict):
                control = BenchmarkTests()
                control.setUp()
                try:
                    if verdict == "FAIL":
                        control.config["thresholds"]["minimum_elapsed_improvement_pct"] = 90
                    elif verdict == "INCOMPLETE":
                        control.config["thresholds"]["maximum_regression"] = {"thermal_raw_mC": 1}
                    directories = control.synthetic_trials()
                    output = control.root / "actual-comparison.json"
                    command = [sys.executable, "-B", str(Path(b.__file__)), "compare", "--plan", str(control.plan),
                               "--runs", *map(str, directories), "--output", str(output)]
                    result = subprocess.run(command, capture_output=True, text=True)
                    control.require_cli_comparison(result, directories, output)
                    self.assertEqual(b.read_json(output)["preliminary_result"], verdict)
                    # A genuine report cannot justify the wrong exit code.
                    wrong = subprocess.CompletedProcess(command, 2 if result.returncode == 0 else 0, result.stdout, result.stderr)
                    with self.assertRaises(AssertionError):
                        control.require_cli_comparison(wrong, directories, output)
                finally:
                    control.doCleanups()

    def test_cli_refused_raw_data_is_not_a_negative_timing_verdict(self):
        directories = self.synthetic_trials()
        (directories[0] / "stdout.txt").write_text("changed after measurement")
        output = self.root / "refused-comparison.json"
        result = subprocess.run([sys.executable, "-B", str(Path(b.__file__)), "compare", "--plan", str(self.plan),
                                 "--runs", *map(str, directories), "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("raw output changed", result.stderr)
        with self.assertRaises(AssertionError):
            self.require_cli_comparison(result, directories, output)
        self.assertFalse(output.exists())

    def test_invalid_run_is_rejected_with_full_raw_diagnostics(self):
        directories = self.synthetic_trials()
        directory = directories[0]
        trial = b.read_json(directory / "trial.json")
        trial.update(valid=False, error="telemetry/cleanup incomplete")
        trial["sampling_status"]["dropped_samples"] = 1
        (directory / "trial.json").write_text(json.dumps(trial))
        result = subprocess.CompletedProcess(["explicit-invalid-run-control"], 2, "", "")
        with self.assertRaisesRegex(AssertionError, "dropped_samples"):
            self.require_valid_cli_trial(result, directory)
        packet = json.loads(gzip.decompress((self.root / "cli-failure.json.gz").read_bytes()))
        self.assertEqual(packet["status"], "INVALID_TRIAL_NOT_PERFORMANCE_EVIDENCE")
        for name, row in packet["files"].items():
            raw = base64.b64decode(row["base64"], validate=True)
            self.assertEqual(raw, (self.root / name).read_bytes())
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"])
        self.assertIn("trial-0/trial.json", packet["files"])
        self.assertIn("trial-0/telemetry.jsonl", packet["files"])

    def test_baseline_record_drift_invalidates_comparison(self):
        directories = self.synthetic_trials()
        self.state.write_text(json.dumps(self.record | {"kernel": "different"}))
        with self.assertRaisesRegex(b.Invalid, "state file changed"):
            b.compare(self.plan, directories, self.root / "comparison.json")

    def test_slow_sampling_does_not_bypass_timeout(self):
        directory = self.root / "slow-sample"
        directory.mkdir()
        original = b.telemetry
        def slow(pid):
            b.time.sleep(.1)
            return original(pid)
        with patch.object(b, "telemetry", side_effect=slow):
            result = b.execute([sys.executable, "-c", "import time;time.sleep(.2)"], self.root, os.environ.copy(), directory, .05, .02)
        self.assertEqual(result["error"], "timeout")

    def test_variant_environment_is_bounded_to_one_key(self):
        self.config["change"] = {"variable": "compiler flag", "baseline": "-O2", "candidate": "-O3",
                                 "rationale": "test-only", "environment_key": "CFLAGS"}
        self.config["variant_env"] = {"baseline": {"CFLAGS": "-O2"}, "candidate": {"CFLAGS": "-O3"}}
        self.config["variant_inputs"] = {"baseline": [str(self.driver)], "candidate": [str(self.driver)]}
        directories = self.synthetic_trials()
        self.assertEqual(b.compare(self.plan, directories, self.root / "comparison.json"), 0)
        self.config["variant_env"]["candidate"]["UNRELATED"] = "1"
        with self.assertRaisesRegex(b.Invalid, "only the declared key"):
            b.validate_config(self.config)

    def test_unrelated_package_update_is_rejected(self):
        self.record["packages"] = {"returncode": 0, "stdout": "target 1\nprotected 1"}
        self.state.write_text(json.dumps(self.record))
        candidate = self.root / "candidate.json"
        candidate.write_text(json.dumps(self.record | {"packages": {"returncode": 0, "stdout": "target 2\nprotected 2"}}))
        evidence = self.root / "change-review.txt"
        evidence.write_text("synthetic one-variable source-test evidence")
        self.config.update({"allowed_state_changes": ["packages"], "changed_packages": ["target"],
                            "state_change_evidence": str(evidence)})
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(b.Invalid, "unrelated/missing package"):
            b.freeze(self.config_path, self.state, candidate, self.plan)
        candidate.write_text(json.dumps(self.record | {"packages": {"returncode": 0, "stdout": "target 2\nprotected 1"}}))
        b.freeze(self.config_path, self.state, candidate, self.plan)
        self.assertEqual(b.load_plan(self.plan)["states"]["candidate"]["packages"], "target 2\nprotected 1")

    def test_telemetry_regressions_fail_and_partial_coverage_is_incomplete(self):
        self.config["thresholds"]["maximum_regression"] = {
            "root_rss_kib_pct": 10, "thermal_raw_mC": 1000, "power_raw_uW_pct": 5}
        self.config["power_domains"] = {"/synthetic/power": {"chip_name": "test", "channel_label": "CPU", "device": None,
                                      "domain": "synthetic CPU", "reviewer": "fixture", "evidence": "synthetic-only source test"}}
        directories = self.synthetic_trials()
        for directory in directories:
            trial = b.read_json(directory / "trial.json")
            candidate = trial["variant"] == "candidate"
            sample = {"monotonic_ns": trial["monotonic_start_ns"] + 1,
                      "memory": {"root_rss_kib": 120 if candidate else 100, "lifecycle": "live"},
                      "thermal": [{"path": "/synthetic/temp", "label": "test", "unit": "mC", "value": 42000 if candidate else 40000}],
                      "power": [{"path": "/synthetic/power", "chip_name": "test", "channel_label": "CPU", "device": None,
                                 "unit": "uW", "value": 1200000 if candidate else 1000000}]}
            (directory / "telemetry.jsonl").write_text(json.dumps(sample) + "\n")
            trial["metrics"] = b.metrics([sample])
            trial["raw_sha256"]["telemetry.jsonl"] = b.digest(directory / "telemetry.jsonl")
            (directory / "trial.json").write_text(json.dumps(trial))
        output = self.root / "regression.json"
        self.assertEqual(b.compare(self.plan, directories, output), 2)
        result = b.read_json(output)
        self.assertEqual(result["preliminary_result"], "FAIL")
        self.assertEqual(len(result["failures"]), 3)
        directory = directories[1]
        trial = b.read_json(directory / "trial.json")
        sample = json.loads((directory / "telemetry.jsonl").read_text())
        sample["power"][0]["value"] = None
        (directory / "telemetry.jsonl").write_text(json.dumps(sample) + "\n")
        trial["metrics"] = b.metrics([sample])
        trial["raw_sha256"]["telemetry.jsonl"] = b.digest(directory / "telemetry.jsonl")
        (directory / "trial.json").write_text(json.dumps(trial))
        output = self.root / "partial.json"
        b.compare(self.plan, directories, output)
        self.assertIn("power_raw_uW_pct:/synthetic/power", b.read_json(output)["missing_guardrail_telemetry"])

    def test_retargeted_input_symlink_is_rejected(self):
        link = self.root / "driver-link.py"
        other = self.root / "other-driver.py"
        other.write_text("changed\n")
        link.symlink_to(self.driver)
        self.config["inputs"].append(str(link))
        self.freeze()
        link.unlink()
        link.symlink_to(other)
        with self.assertRaisesRegex(b.Invalid, "input changed"):
            b.load_plan(self.plan)
        other.write_bytes(self.driver.read_bytes())
        with self.assertRaisesRegex(b.Invalid, "input changed"):
            b.load_plan(self.plan)  # Resolution identity changes even for equal contents.

    def test_blocked_sensor_does_not_block_deadline_or_allow_next_workload(self):
        directory = self.root / "blocked-sensor"
        directory.mkdir()
        release = threading.Event()
        entered = threading.Event()
        original = b.telemetry
        def blocked(pid):
            entered.set()
            release.wait(timeout=2)  # Self-expiring synthetic block, not real driver I/O.
            return original(pid)
        try:
            started = time.monotonic()
            code = "import os,time;print(os.getpid(),flush=True);time.sleep(.8)"
            with patch.object(b, "telemetry", side_effect=blocked), patch.object(b, "CLEANUP_SECONDS", .05):
                result = b.execute([sys.executable, "-c", code], self.root, os.environ.copy(), directory, .05, .02)
            self.assertTrue(entered.is_set())
            self.assertLess(time.monotonic() - started, .4)
            self.assertEqual(result["error"], "timeout")
            self.assertFalse(result["sampling_status"]["worker_stopped"])
            self.assertTrue(result["sampling_status"]["workload_reaped"])
            pid = int((directory / "stdout.txt").read_text().strip())
            self.assertIsNone(b.text_file(Path("/proc") / str(pid) / "status"))
            with self.assertRaisesRegex(b.Invalid, "previous telemetry sampler"):
                b.execute([sys.executable, "-c", "pass"], self.root, os.environ.copy(), self.root / "second", .1, .02)
        finally:
            release.set()
            if b._active_sampler is not None:
                b._active_sampler.join(timeout=1)

    def test_sigterm_records_interruption_and_reaps_workload(self):
        directory = self.root / "sigterm"
        directory.mkdir()
        code = """import importlib.util,json,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('benchmark',sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
work=[sys.executable,'-c','import os,time;print(os.getpid(),flush=True);time.sleep(.8)']
result=b.execute(work,Path(sys.argv[2]),os.environ.copy(),Path(sys.argv[2]),.6,.02)
Path(sys.argv[2],'result.json').write_text(json.dumps(result))
"""
        wrapper = subprocess.Popen([sys.executable, "-c", code, str(Path(b.__file__).resolve()), str(directory)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pid = None
        try:
            deadline = time.monotonic() + .5
            while time.monotonic() < deadline:
                text = b.text_file(directory / "stdout.txt")
                if text:
                    pid = int(text)
                    break
                time.sleep(.005)
            self.assertIsNotNone(pid, "bounded child did not reach its PID marker")
            wrapper.terminate()
            stdout, stderr = wrapper.communicate(timeout=1)
            self.assertEqual(wrapper.returncode, 0, stdout + stderr)
            result = b.read_json(directory / "result.json")
            self.assertEqual(result["error"], "interrupted by SIGTERM")
            self.assertTrue(result["sampling_status"]["workload_reaped"])
            self.assertNotEqual(result["returncode"], 0)
            self.assertIsNone(b.text_file(Path("/proc") / str(pid) / "status"))
        finally:
            if pid is not None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if wrapper.poll() is None:
                wrapper.kill()
            wrapper.communicate(timeout=1)

    def test_power_channel_labels_are_preserved_and_drift_is_rejected(self):
        chip = self.root / "class/hwmon/hwmon0"
        chip.mkdir(parents=True)
        (chip / "name").write_text("fixture-chip")
        (chip / "power1_input").write_text("100")
        (chip / "power1_label").write_text("CPU")
        first = b.telemetry(999, self.root, self.root / "no-proc")
        (chip / "power1_label").write_text("GPU")
        second = b.telemetry(999, self.root, self.root / "no-proc")
        self.assertEqual(first["power"][0]["chip_name"], "fixture-chip")
        self.assertEqual(first["power"][0]["channel_label"], "CPU")
        self.assertEqual(second["power"][0]["channel_label"], "GPU")
        self.assertIsNone(first["power"][0]["device"])
        directories = self.synthetic_trials()
        for directory in directories:
            trial = b.read_json(directory / "trial.json")
            sample = json.loads((directory / "telemetry.jsonl").read_text())
            sample["power"] = first["power"] if trial["variant"] == "baseline" else second["power"]
            self.replace_samples(directory, [sample])
        with self.assertRaisesRegex(b.Invalid, "sensor source/chip/channel"):
            b.compare(self.plan, directories, self.root / "identity.json")

    def test_missing_to_identified_sensor_is_refused_within_and_between_trials(self):
        # Actual strict comparator, valid raw hashes/metrics, no sensor values invented.
        directories = self.synthetic_trials()
        for location in ("within", "between"):
            with self.subTest(location=location):
                for directory in directories:
                    trial = b.read_json(directory / "trial.json")
                    sample = {"monotonic_ns": trial["monotonic_start_ns"] + 1,
                              "memory": {"root_rss_kib": None, "lifecycle": "unknown"},
                              "thermal": [], "power": [], "missing": ["memory", "thermal", "power"]}
                    self.replace_samples(directory, [sample])
                changed = directories[0 if location == "within" else 1]
                sample = json.loads((changed / "telemetry.jsonl").read_text())
                identified = copy.deepcopy(sample)
                identified["monotonic_ns"] += 1
                identified["power"] = [{"path": "/synthetic/identity-only", "unit": "uW", "value": None,
                                        "status": "unavailable", "chip_name": "SYNTHETIC_ONLY",
                                        "channel_label": "NO_MEASUREMENT", "device": None}]
                self.replace_samples(changed, [sample, identified] if location == "within" else [identified])
                output = self.root / ("refused-" + location + ".json")
                with self.assertRaisesRegex(b.Invalid, "sensor source/chip/channel/device/unit"):
                    b.compare(self.plan, directories, output)
                self.assertFalse(output.exists())

    def test_unreviewed_power_domain_is_incomplete(self):
        self.config["thresholds"]["maximum_regression"] = {"power_raw_uW_pct": 0}
        directories = self.synthetic_trials()
        for directory in directories:
            sample = json.loads((directory / "telemetry.jsonl").read_text())
            sample["power"] = [{"path": "/synthetic/power", "unit": "uW", "value": 100,
                                "chip_name": "fixture", "channel_label": "CPU", "device": None}]
            self.replace_samples(directory, [sample])
        output = self.root / "domain.json"
        self.assertEqual(b.compare(self.plan, directories, output), 2)
        result = b.read_json(output)
        self.assertEqual(result["preliminary_result"], "INCOMPLETE")
        self.assertIn("unreviewed/mismatched power domain", result["missing_guardrail_telemetry"][0])

    def test_rss_live_missing_and_unknown_are_incomplete_but_exit_is_excluded(self):
        self.config["thresholds"]["maximum_regression"] = {"root_rss_kib_pct": 0}
        directories = self.synthetic_trials()
        for lifecycle, expected in (("live", "INCOMPLETE"), ("unknown", "INCOMPLETE"), ("exited", "MEETS_TIMING_RULE_ONLY")):
            for directory in directories:
                original = json.loads((directory / "telemetry.jsonl").read_text().splitlines()[0])
                missing = copy.deepcopy(original)
                missing["monotonic_ns"] += 1
                missing["memory"] = {"root_rss_kib": None, "lifecycle": lifecycle}
                self.replace_samples(directory, [original, missing])
            output = self.root / f"rss-{lifecycle}.json"
            b.compare(self.plan, directories, output)
            result = b.read_json(output)
            self.assertEqual(result["preliminary_result"], expected)
        self.assertEqual(b.read_json(directories[0] / "trial.json")["metrics"]["rss_coverage"],
                         {"live_samples": 1, "missing_live_samples": 0, "excluded_exited_samples": 1, "unknown_lifecycle_samples": 0})

    def test_pre_freeze_trial_and_naive_clock_are_rejected(self):
        directories = self.synthetic_trials()
        declared = b.utc_timestamp(b.read_json(self.plan)["frozen_at"])
        self.modify(directories[0], "started_at", (declared - timedelta(seconds=1)).isoformat())
        with self.assertRaisesRegex(b.Invalid, "predates frozen plan"):
            b.compare(self.plan, directories, self.root / "retroactive.json")
        self.modify(directories[0], "started_at", declared.replace(tzinfo=None).isoformat())
        with self.assertRaisesRegex(b.Invalid, "timezone-aware"):
            b.compare(self.plan, directories, self.root / "naive-clock.json")


if __name__ == "__main__":
    unittest.main()
