"""Exercise v2 plan validation with synthetic files and no workload execution."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


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

    def test_relative_inputs_are_bound_to_the_declaration_directory(self):
        self.config["hardware_gate_evidence"] = self.gates_path.name
        self.config["inputs"].append("fixture.txt")
        (self.root / "fixture.txt").write_text("pinned input")
        original = Path.cwd()
        try:
            os.chdir(self.root)
            self.freeze()
        finally:
            os.chdir(original)
        plan = runner.load_plan(self.plan_path)
        self.assertEqual(plan["declared_from"], str(self.root))

    def relative_workload_trial(self, *, explicit=False):
        declared = self.root / "declaration"
        work = self.root / "work"
        for path in (declared, work):
            path.mkdir()
            (path / "driver.py").write_text(str(path))
            (path / "data.bin").write_text(str(path))
        self.config["inputs"].append("driver.py")
        self.config["variant_inputs"] = {"baseline": ["data.bin"]}
        self.config["argv"] += ["./driver.py", "--data=data.bin", "--output", "result.bin"]
        if explicit:
            (declared / "fast").write_text("unrelated pinned file")
            self.config["inputs"].append("fast")
            self.config["argv"] += ["--mode=fast", "fast"]
            self.config["argv_file_operands"] = [1, 2]
        original = Path.cwd()
        try:
            os.chdir(declared)
            self.freeze()
        finally:
            os.chdir(original)
        conditions = self.root / "conditions.json"
        self.write(conditions, self.config["controls"] |
                   dict.fromkeys(("ambient_C", "thermal_start_C", "battery_soc_percent"), 0) |
                   {"operator": "fixture", "notes": "mocked workload"})
        output = self.root / "trial"
        identity = runner.load_plan(self.plan_path)["states"]["baseline"]
        with (patch.object(runner.os, "geteuid", return_value=1000),
              patch.object(runner, "live_identity", return_value=identity),
              patch.object(runner, "execute", return_value={"error": None, "returncode": 0}) as execute):
            self.assertEqual(runner.run(self.plan_path, 0, self.baseline, conditions, work, output), 0)
        return declared, work, output, execute.call_args.args

    def test_run_passes_and_records_pinned_paths_from_a_different_cwd(self):
        declared, work, output, call = self.relative_workload_trial()
        expected = [sys.executable, str(declared / "driver.py"), "--data=" + str(declared / "data.bin"),
                    "--output", "result.bin"]
        self.assertEqual(call[:2], (expected, work))
        for name in ("started.json", "trial.json"):
            self.assertEqual(runner.read_json(output / name)["argv"], expected)

    def test_compare_refuses_record_of_unbound_arguments(self):
        _, _, output, _ = self.relative_workload_trial()
        record = runner.read_json(output / "trial.json")
        record["argv"] = self.config["argv"]
        self.write(output / "trial.json", record)
        with self.assertRaisesRegex(runner.Invalid, "differing argv"):
            runner.compare(self.plan_path, [output], self.root / "comparison.json")

    def test_explicit_file_operands_leave_colliding_literals_unchanged(self):
        declared, work, output, call = self.relative_workload_trial(explicit=True)
        expected = [sys.executable, str(declared / "driver.py"), "--data=" + str(declared / "data.bin"),
                    "--output", "result.bin", "--mode=fast", "fast"]
        self.assertEqual(call[:2], (expected, work))
        self.assertEqual(runner.read_json(output / "trial.json")["argv"], expected)
        record = runner.read_json(output / "trial.json")
        record["argv"][-2] = "--mode=" + str(declared / "fast")
        self.write(output / "trial.json", record)
        with self.assertRaisesRegex(runner.Invalid, "differing argv"):
            runner.compare(self.plan_path, [output], self.root / "comparison.json")

    def test_explicit_empty_file_operands_leave_all_arguments_literal(self):
        config = self.config | {"inputs": [sys.executable, "fast"], "argv": [sys.executable, "--mode=fast", "fast"],
                                "argv_file_operands": []}
        runner.validate_config(config)
        self.assertEqual(runner.workload_argv({"config": config, "declared_from": str(self.root)}), config["argv"])

    def test_invalid_file_operand_indexes_and_unpinned_paths_fail_freeze(self):
        self.config["argv"].append("--data=missing")
        for indexes in (None, [0], [True], [-1], [2], [1, 1]):
            with self.subTest(indexes=indexes):
                self.config["argv_file_operands"] = indexes
                with self.assertRaisesRegex(runner.Invalid, "unique argument indexes"):
                    self.freeze()
        self.config["argv_file_operands"] = [1]
        with self.assertRaisesRegex(runner.Invalid, "must name a pinned input path"):
            self.freeze()
        self.assertFalse(self.plan_path.exists())

    def test_loading_refuses_added_file_operand_for_literal_option(self):
        self.config["argv"].append("--literal")
        self.config["argv_file_operands"] = []
        self.freeze()
        plan = runner.read_json(self.plan_path)
        plan["config"]["argv_file_operands"] = [1]
        self.write(self.plan_path, plan)
        with self.assertRaisesRegex(runner.Invalid, "must name a pinned input path"):
            runner.load_plan(self.plan_path)


if __name__ == "__main__":
    unittest.main()
