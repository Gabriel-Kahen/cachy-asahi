"""Exercise v2 plan validation with synthetic files and no workload execution."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("benchmark_v2", Path(__file__).with_name("benchmark_v2.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.baseline = self.root / "baseline.json"
        self.candidate = self.root / "candidate.json"
        self.config_path = self.root / "config.json"
        self.plan_path = self.root / "plan.json"
        self.gates_path = self.root / "gates.json"
        self.record = {
            "schema_version": 1, "record_type": "environment-baseline", "validation_result": "NOT RUN",
            "architecture": "aarch64", "execution_context": "physical", "kernel": "synthetic",
            "page_size_bytes": 16384, "m2_air_size": "13-inch", "device_tree_compatible": "apple,j413\napple,t8112",
            "packages": {"command": ["pacman", "-Q"], "returncode": 0, "stdout": "fixture 1\nunrelated 1"},
            "repositories": {"sync_databases": []},
        }
        self.config = {
            "experiment_id": "fixture", "machine_id": "fixture-air", "base_id": "fixture-base",
            "workload_id": "unexecuted", "execution_context": "physical",
            "change": {"variable": "fixture", "baseline": "old", "candidate": "new", "rationale": "synthetic"},
            "argv": [sys.executable], "inputs": [sys.executable],
            "order": ["baseline", "candidate", "candidate", "baseline"] * 3, "minimum_trials": 5,
            "timeout_seconds": 1, "sample_seconds": .5, "hardware_gate_evidence": str(self.gates_path),
            "controls": dict.fromkeys(("power_source", "display_config", "brightness", "cache_mode",
                                       "background_load", "warmup"), "synthetic") |
            dict.fromkeys(("ambient_C", "thermal_start_C", "battery_soc_percent"), [0, 1]),
            "thresholds": {"minimum_elapsed_improvement_pct": 1, "maximum_elapsed_range_pct": 100},
        }
        self.write(self.gates_path, {"machine_id": "fixture-air", "base_id": "fixture-base",
                                     "baseline_functional": "PASS", "recovery": "PASS",
                                     "evidence": "synthetic fixture", "reviewer": "fixture reviewer"})

    def write(self, path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def freeze(self, baseline=None, candidate=None):
        self.write(self.baseline, self.record if baseline is None else baseline)
        self.write(self.candidate, self.record if candidate is None else candidate)
        self.write(self.config_path, self.config)
        runner.freeze(self.config_path, self.baseline, self.candidate, self.plan_path)

    def test_requires_exact_16k_device_tree_for_both_states(self):
        for change in ({"page_size_bytes": 4096}, {"architecture": "x86_64"}, {"m2_air_size": "15-inch"},
                       {"device_tree_compatible": "apple,j413"},
                       {"device_tree_compatible": "apple,j413\napple,j415\napple,t8112"},
                       {"device_tree_compatible": "apple,j413\napple,t8112\napple,t8112"},
                       {"device_tree_compatible": "apple,j413\n\napple,t8112"}):
            with self.subTest(change=change):
                record = self.record | change
                with self.assertRaisesRegex(runner.Invalid, "exact M2 Air"):
                    self.freeze(record, record)
                self.assertFalse(self.plan_path.exists())

    def test_valid_both_sizes_and_package_change(self):
        self.config.update(allowed_state_changes=["packages"], changed_packages=["fixture"],
                           state_change_evidence=str(self.gates_path))
        for size, identifier in (("13-inch", "apple,j413"), ("15-inch", "apple,j415")):
            with self.subTest(size=size):
                old = self.record | {"device_tree_compatible": identifier + "\napple,t8112", "m2_air_size": size}
                new = old | {"packages": old["packages"] | {"stdout": "fixture 2\nunrelated 1"}}
                self.freeze(old, new)
                plan = runner.load_plan(self.plan_path)
                self.assertEqual(plan["states"]["baseline"]["m2_air_size"], size)
                self.assertEqual(plan["states"]["candidate"]["packages"], "fixture 2\nunrelated 1")
                self.assertEqual(plan["optimization_acceptance"], "NOT RUN")
                self.plan_path.unlink()

    def test_inventory_must_be_nonempty_well_formed_and_unique(self):
        for stdout in ("", "fixture", "fixture 1\nfixture 1", "unrelated hidden\nfixture 1\nunrelated 1"):
            with self.subTest(stdout=stdout), self.assertRaisesRegex(runner.Invalid, "package inventor"):
                malformed = self.record | {"packages": self.record["packages"] | {"stdout": stdout}}
                self.freeze(malformed, malformed)
        self.config.update(allowed_state_changes=["packages"], changed_packages=["fixture"],
                           state_change_evidence=str(self.gates_path))
        hidden_change = self.record | {"packages": self.record["packages"] |
                                      {"stdout": "unrelated hidden\nfixture 2\nunrelated 1"}}
        with self.assertRaisesRegex(runner.Invalid, "package inventor"):
            self.freeze(self.record, hidden_change)

    def test_loading_rederives_both_capture_identities(self):
        self.freeze()
        original = self.plan_path.read_text()
        for variant in ("baseline", "candidate"):
            with self.subTest(variant=variant):
                plan = json.loads(original)
                plan["states"][variant]["kernel"] = "unbound"
                self.write(self.plan_path, plan)
                with self.assertRaisesRegex(runner.Invalid, "pinned captures"):
                    runner.load_plan(self.plan_path)
        self.plan_path.write_text(original)
        self.write(self.candidate, self.record | {"kernel": "changed on disk"})
        with self.assertRaisesRegex(runner.Invalid, "candidate state file changed"):
            runner.load_plan(self.plan_path)

    def test_loading_requires_bound_and_valid_hardware_gate(self):
        self.freeze()
        plan = runner.read_json(self.plan_path)
        original_pins = plan["inputs"]
        plan["inputs"] = [pin for pin in original_pins if pin["path"] != str(self.gates_path)]
        self.write(self.plan_path, plan)
        with self.assertRaisesRegex(runner.Invalid, "input lacks.*pin"):
            runner.load_plan(self.plan_path)
        gates = runner.read_json(self.gates_path)
        self.write(self.gates_path, gates | {"recovery": "NOT RUN"})
        plan["inputs"].append(runner.pin_file(self.gates_path))
        self.write(self.plan_path, plan)
        with self.assertRaisesRegex(runner.Invalid, "gate.*reviewed PASS"):
            runner.load_plan(self.plan_path)


if __name__ == "__main__":
    unittest.main()
