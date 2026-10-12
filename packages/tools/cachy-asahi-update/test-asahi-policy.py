#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic data and private mocked shell integration, never hardware evidence."""

import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


policy_module = module("asahi_policy", "asahi-policy.py")
upstream = module("upstream", "test-upstream.py")
BEHAVIOR_SHA = "08a781eeae66881359207ed93cbe808f3fdff884de646ec09c9bc640ad527db6"
APPLE_SHA = "8201ed41b9790cbb004f3ce62d80ce1e9f25d314e7ef685ffea44d2f1594b783"
FULL_SHA = "103c965d6d7b86b558b3fc686975a3a649de3cc2e0b94f7dee608c7bdaeaef0a"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture(change=None, phase="post-transaction"):
    # Names/versions/module releases are synthetic; no target policy is shipped.
    roles = {
        "boot": ["fixture-boot"], "kernel": ["fixture-asahi-kernel"],
        "firmware": ["fixture-firmware"], "graphics": ["fixture-graphics"],
        "audio": ["asahi-audio", "speakersafetyd"],
    }
    before = {name: "1-1" for names in roles.values() for name in names}
    before["fixture-asahi-kernel"] = "900-1"  # Deliberately unlike uname/module release.
    old, new = "6.99.synthetic-asahi", "6.99.synthetic-asahi"
    after = dict(before)
    if change == "kernel":
        after["fixture-asahi-kernel"] = "901-1"
        new = "7.00.synthetic-asahi"
    elif change == "platform":
        after["asahi-audio"] = "2-1"
    transition = {
        "id": "synthetic-transition", "model": "apple,j413",
        "before_versions": dict(before), "after_versions": dict(after),
        "before_kernel_releases": {"fixture-asahi-kernel": [old]},
        "after_kernel_releases": {"fixture-asahi-kernel": [new]},
        "target_kernel_release": new,
        "evidence_sha256": {"release_manifest": digest(b"synthetic manifest"),
                            "transition_validation": digest(b"synthetic validation, NOT hardware")},
    }
    policy = {
        "schema_version": 1, "purpose": "cachy-asahi-apple-update-policy",
        "release_id": "synthetic-test-only", "compatible_models": ["apple,j413"],
        "platform_roles": roles,
        "protected_units": {scope: sorted(units) for scope, units in policy_module.REQUIRED_UNITS.items()},
        "generic_restart_units": {"system": ["sshd.service"], "user": ["fixture-agent.service"]},
        "permitted_operations": ["repository-update", "orphan-removal", "package-cache-removal"],
        "transitions": [transition],
    }
    observation = {
        "schema_version": 1, "phase": phase, "model": "apple,j413",
        "running_kernel_release": old, "before_versions": before, "after_versions": after,
        "before_kernel_files": {"fixture-asahi-kernel": [f"/usr/lib/modules/{old}/kernel/fixture.ko.zst"]},
        "after_kernel_files": {"fixture-asahi-kernel": [f"/usr/lib/modules/{new}/kernel/fixture.ko.zst"]},
    }
    return policy, observation


class PurePolicy(unittest.TestCase):
    def decision(self, policy, observation, **kwargs):
        return policy_module.evaluate(policy, observation, **kwargs)["decision"]

    def test_identity_uses_owned_module_release_not_package_version(self):
        self.assertEqual(self.decision(*fixture()), "no-kernel-change")

    def test_validated_new_module_release_requires_reboot(self):
        self.assertEqual(self.decision(*fixture("kernel")), "reboot-required")

    def test_platform_changed_kernel_unchanged_needs_coordination(self):
        result = policy_module.evaluate(*fixture("platform"))
        self.assertEqual(result["decision"], "coordination-required")
        self.assertEqual(result["reason"], "protected-platform-changed")

    def test_projected_platform_change_blocks_preflight(self):
        self.assertEqual(self.decision(*fixture("platform", "pre-transaction"), action="transaction"),
                         "coordination-required")

    def test_kernel_only_projected_transition_can_pass_data_preflight(self):
        self.assertEqual(self.decision(*fixture("kernel", "pre-transaction"), action="transaction"),
                         "transaction-allowed")

    def test_optional_operation_needs_explicit_policy_declaration(self):
        p, o = fixture(phase="pre-transaction")
        for operation in ("aur-update", "flatpak-update", "flatpak-unused-removal"):
            self.assertEqual(self.decision(p, o, action="transaction", operation=operation), "coordination-required")
            p["permitted_operations"].append(operation)
            self.assertEqual(self.decision(p, o, action="transaction", operation=operation), "transaction-allowed")

    def test_wrong_phase_cannot_reuse_post_snapshot_for_preflight(self):
        self.assertEqual(self.decision(*fixture(), action="transaction"), "coordination-required")

    def test_unknown_running_module_owner_is_not_no_change(self):
        p, o = fixture()
        o["running_kernel_release"] = "unowned-synthetic-kernel"
        self.assertEqual(self.decision(p, o), "coordination-required")

    def test_unknown_transition_is_not_authorized(self):
        p, o = fixture()
        o["after_versions"]["fixture-graphics"] = "unreviewed-1"
        self.assertEqual(self.decision(p, o), "coordination-required")

    def test_duplicate_matching_transitions_cannot_choose_arbitrarily(self):
        p, o = fixture()
        other = deepcopy(p["transitions"][0]); other["id"] = "second"
        p["transitions"].append(other)
        self.assertEqual(self.decision(p, o), "coordination-required")

    def test_same_module_release_changed_kernel_package_is_ambiguous(self):
        p, o = fixture()
        o["after_versions"]["fixture-asahi-kernel"] = "902-1"
        p["transitions"][0]["after_versions"] = dict(o["after_versions"])
        self.assertEqual(self.decision(p, o), "coordination-required")

    def test_package_owned_vmlinuz_cannot_substitute_for_modules(self):
        p, o = fixture()
        o["after_kernel_files"]["fixture-asahi-kernel"] = ["/usr/lib/modules/6.99.synthetic-asahi/vmlinuz"]
        with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_missing_protected_inventory_entry_is_invalid(self):
        p, o = fixture(); del o["before_versions"]["speakersafetyd"]
        with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_missing_critical_role_is_invalid(self):
        p, o = fixture(); del p["platform_roles"]["firmware"]
        with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_kernel_role_cannot_swallow_audio_package_changes(self):
        p, o = fixture(); p["platform_roles"]["kernel"].append("asahi-audio")
        with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_no_pass_boolean_or_unknown_schema_fields(self):
        for mutate in (lambda p: p.update(PASS=True), lambda p: p.update(schema_version=True),
                       lambda p: p["transitions"][0]["evidence_sha256"].update(transition_validation=True)):
            p, o = fixture(); mutate(p)
            with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_model_scope_is_exact(self):
        p, o = fixture(); o["model"] = "apple,j415"
        with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_second_air_model_needs_its_own_transition(self):
        p, o = fixture()
        p["compatible_models"] = ["apple,j415"]
        p["transitions"][0]["model"] = "apple,j415"
        o["model"] = "apple,j415"
        self.assertEqual(self.decision(p, o), "no-kernel-change")

    def test_ambiguous_target_module_ownership_is_invalid(self):
        p, o = fixture()
        p["platform_roles"]["kernel"].append("fixture-second-kernel")
        transition = p["transitions"][0]
        for value in (o["before_versions"], o["after_versions"], transition["before_versions"], transition["after_versions"]):
            value["fixture-second-kernel"] = "1-1"
        for field in ("before_kernel_files", "after_kernel_files"):
            o[field]["fixture-second-kernel"] = list(o[field]["fixture-asahi-kernel"])
        for field in ("before_kernel_releases", "after_kernel_releases"):
            transition[field]["fixture-second-kernel"] = list(transition[field]["fixture-asahi-kernel"])
        with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_protected_system_and_user_audio_units_never_generic_restart(self):
        p, o = fixture()
        for unit in ("speakersafetyd.service", "asahi-audio.service", "pipewire.service",
                     "wireplumber.service", "pipewire@session.service", "speakersafetyd@device.service"):
            self.assertEqual(self.decision(p, o, scope="system", unit=unit), "coordination-required")

    def test_reviewed_generic_service_is_allowed_in_its_scope(self):
        p, o = fixture()
        self.assertEqual(self.decision(p, o, scope="system", unit="sshd.service"), "restart-allowed")
        self.assertEqual(self.decision(p, o, scope="user", unit="sshd.service"), "coordination-required")

    def test_protected_service_cannot_be_added_to_generic_allowlist(self):
        for unit in ("speakersafetyd.service", "wireplumber.service", "asahi-audio-extra.service"):
            p, o = fixture(); p["generic_restart_units"]["system"].append(unit)
            with self.assertRaises(policy_module.Invalid): self.decision(p, o)

    def test_service_argument_injection_is_invalid(self):
        p, o = fixture()
        for unit in ("--all.service", "sshd.service unsafe.service", "../../sshd.service", "sshd;reboot.service"):
            with self.assertRaises(policy_module.Invalid): self.decision(p, o, scope="system", unit=unit)

    def test_pin_duplicate_json_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory(prefix="asahi-policy-data-") as tmp:
            path = Path(tmp) / "data.json"
            data = b'{"schema_version":1,"schema_version":true}'
            path.write_bytes(data)
            with self.assertRaises(policy_module.Invalid): policy_module.load_pinned(path, digest(data), 1024)
            with self.assertRaises(policy_module.Invalid): policy_module.load_pinned(path, "0" * 64, 1024)
            link = Path(tmp) / "link.json"; link.symlink_to(path)
            with self.assertRaises(OSError): policy_module.load_pinned(link, digest(data), 1024)


class ShellIntegration(unittest.TestCase):
    def setUp(self):
        self.h = upstream.UpstreamBehavior(methodName="runTest")
        self.h.setUp(); self.addCleanup(self.h.doCleanups)
        full = (upstream.SOURCE / "src/lib/full_upgrade.sh").read_bytes()
        self.assertEqual(digest(full), FULL_SHA)
        (self.h.lib / "full_upgrade.sh").write_bytes(full)
        for filename, expected in (("behavior.patch", BEHAVIOR_SHA), ("apple-policy.patch", APPLE_SHA)):
            patch = HERE / filename
            self.assertEqual(digest(patch.read_bytes()), expected)
            applied = subprocess.run([shutil.which("patch"), "--batch", "--fuzz=0", "-p3", "-i", str(patch)],
                                     cwd=self.h.lib, capture_output=True, text=True, timeout=5)
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        for name in ("kernel_reboot", "restart_services", "update", "full_upgrade"):
            syntax = subprocess.run([upstream.BASH, "-n", str(self.h.lib / f"{name}.sh")],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.helper = self.h.root / "policy-helper"
        self.helper.write_text(f'#!{sys.executable}\nimport runpy\nrunpy.run_path({str(HERE / "asahi-policy.py")!r}, run_name="__main__")\n')
        self.helper.chmod(0o700)
        self.env = {"CACHY_ASAHI_POLICY_HELPER": str(self.helper)}
        self.configure()
        for name in ("stat", "realpath"):
            (self.h.bin / name).symlink_to(shutil.which(name))
        runtime = self.h.root / "runtime"
        runtime.chmod(0o700)
        (runtime / "arch-update").mkdir()

    def pinned(self, name, data):
        raw = json.dumps(data, sort_keys=True).encode()
        path = self.h.root / name; path.write_bytes(raw)
        return str(path), digest(raw)

    def configure(self, change=None):
        p, post = fixture(change)
        pre = deepcopy(post); pre["phase"] = "pre-transaction"
        path, sha = self.pinned("policy.json", p)
        self.env.update(CACHY_ASAHI_POLICY_FILE=path, CACHY_ASAHI_POLICY_SHA256=sha)
        for phase, o in (("PRE", pre), ("POST", post)):
            path, sha = self.pinned(f"{phase}.json", o)
            self.env[f"CACHY_ASAHI_{phase}_OBSERVATION_FILE"] = path
            self.env[f"CACHY_ASAHI_{phase}_OBSERVATION_SHA256"] = sha

    def run_lib(self, name, before="", **extra):
        env = dict(self.env); env.update(extra)
        return self.h.run_lib(name, before, **env)

    def services(self, report, answer="", **extra):
        return self.run_lib("restart_services", '''
elevate() {
    record elevate "$@"
    if [[ "$1" == checkservices ]]; then printf '%s\\n' "$MOCK_REPORT"; return "${DISCOVERY_EXIT:-0}";
    else return 0; fi
}
''', MOCK_REPORT=report, ANSWER=answer, **extra)

    def full_upgrade(self, before="", **extra):
        # Mock downstream discovery/cache dependencies, not the preflight or
        # post-update policy hooks. All package/service commands stay mocks.
        (self.h.lib / "list_packages.sh").write_text("record list_packages\n")
        (self.h.lib / "packages_cache.sh").write_text("record packages_cache\n")
        return self.run_lib("full_upgrade", '''
tmpdir="$XDG_RUNTIME_DIR/arch-update"
pacman() { record pacman "$@"; }
systemd-detect-virt() { record systemd-detect-virt "$@"; return 0; }
''' + before, **extra)

    def test_full_upgrade_missing_policy_blocks_empty_packages_before_all_stages(self):
        result = self.full_upgrade('packages=""; aur_helper=fixture_aur; flatpak_support=fixture_flatpak',
                                   CACHY_ASAHI_POLICY_FILE="")
        self.assertEqual(result.returncode, 21)
        self.assertEqual(self.h.logs(), [])
        self.assertFalse((self.h.root / "runtime/arch-update/upgrade.lock").exists())

    def test_full_upgrade_missing_aur_permission_blocks_before_discovery(self):
        result = self.full_upgrade('aur_helper=fixture_aur')
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs(), [])

    def test_full_upgrade_missing_flatpak_permission_blocks_before_discovery(self):
        result = self.full_upgrade('flatpak_support=fixture_flatpak')
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs(), [])

    def test_full_upgrade_cache_or_orphan_removal_needs_permission_before_stages(self):
        p, _ = fixture(); p["permitted_operations"] = ["repository-update"]
        path, sha = self.pinned("limited-policy.json", p)
        result = self.full_upgrade(CACHY_ASAHI_POLICY_FILE=path, CACHY_ASAHI_POLICY_SHA256=sha)
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs(), [])

    def test_full_upgrade_checks_post_policy_even_when_container_or_module_hook_would_skip(self):
        p, _ = fixture()
        platform, post = fixture("platform")
        platform["transitions"][0]["id"] = "synthetic-platform-transition"
        p["transitions"].append(platform["transitions"][0])
        path, sha = self.pinned("post-check-policy.json", p)
        post_path, post_sha = self.pinned("changed-post.json", post)
        result = self.full_upgrade(CACHY_ASAHI_POLICY_FILE=path, CACHY_ASAHI_POLICY_SHA256=sha,
                                   CACHY_ASAHI_POST_OBSERVATION_FILE=post_path,
                                   CACHY_ASAHI_POST_OBSERVATION_SHA256=post_sha)
        self.assertEqual(result.returncode, 22)
        self.assertIn("list_packages", self.h.logs())
        self.assertIn("packages_cache", self.h.logs())
        self.assertFalse(any("kernel-modules-hook" in call or "systemd-detect-virt" in call for call in self.h.logs()))

    def test_missing_policy_blocks_pacman_before_mutation(self):
        result = self.run_lib("update", 'packages=fixture', CACHY_ASAHI_POLICY_FILE="")
        self.assertEqual(result.returncode, 21)
        self.assertEqual(self.h.logs(), [])

    def test_uninstalled_helper_blocks_pacman(self):
        result = self.run_lib("update", 'packages=fixture', CACHY_ASAHI_POLICY_HELPER=str(self.h.root / "absent"))
        self.assertEqual(result.returncode, 21)
        self.assertEqual(self.h.logs(), [])

    def test_unpinned_policy_blocks_pacman(self):
        result = self.run_lib("update", 'packages=fixture', CACHY_ASAHI_POLICY_SHA256="0" * 64)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(self.h.logs(), [])

    def test_platform_transition_requires_coordinator_before_pacman(self):
        self.configure("platform")
        result = self.run_lib("update", 'packages=fixture')
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs(), [])

    def test_synthetic_reviewed_preflight_allows_mock_repository_transaction(self):
        result = self.run_lib("update", 'packages=fixture')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.h.logs(), ["elevate\tpacman\t--color\tnever\t-Syu"])

    def test_direct_aur_path_is_blocked_without_operation_permission(self):
        result = self.run_lib("update", 'aur_packages=fixture; aur_helper=fixture_aur')
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs(), [])

    def test_direct_flatpak_path_is_blocked_without_operation_permission(self):
        result = self.run_lib("update", 'flatpak_packages=fixture')
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs(), [])

    def test_declared_synthetic_aur_permission_keeps_real_updater_branch(self):
        p, _ = fixture(); p["permitted_operations"].append("aur-update")
        path, sha = self.pinned("aur-policy.json", p)
        result = self.run_lib("update", '''
aur_packages=fixture; aur_helper=fixture_aur
pacman() { record pacman "$@"; }
fixture_aur() { record fixture_aur "$@"; }
''', CACHY_ASAHI_POLICY_FILE=path, CACHY_ASAHI_POLICY_SHA256=sha)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.h.logs(), ["pacman\t-Qtdq", "fixture_aur\t--color\tnever\t-Syu"])

    def test_missing_policy_does_not_claim_no_reboot(self):
        result = self.run_lib("kernel_reboot", CACHY_ASAHI_POLICY_FILE="")
        self.assertEqual(result.returncode, 21)
        self.assertEqual(self.h.logs(), [])

    def test_unowned_running_module_release_refuses_reboot(self):
        p, o = fixture("kernel"); o["running_kernel_release"] = "unknown-kernel"
        path, sha = self.pinned("unowned.json", o)
        result = self.run_lib("kernel_reboot", CACHY_ASAHI_POST_OBSERVATION_FILE=path,
                              CACHY_ASAHI_POST_OBSERVATION_SHA256=sha)
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs(), [])

    def test_reboot_requires_opt_in_after_reviewed_module_transition(self):
        self.configure("kernel")
        result = self.run_lib("kernel_reboot", ANSWER="n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.h.logs(), ["ask"])

    def test_reboot_opt_in_reaches_only_mock_systemctl(self):
        self.configure("kernel")
        result = self.run_lib("kernel_reboot", '''
systemctl() { record systemctl "$@"; }; sleep() { :; }; tput() { :; }
''', ANSWER="y")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.h.logs(), ["ask", "systemctl\treboot"])

    def test_missing_service_policy_stops_before_discovery(self):
        result = self.services("restart 'sshd.service'", CACHY_ASAHI_POLICY_FILE="")
        self.assertEqual(result.returncode, 21)
        self.assertEqual(self.h.logs(), [])

    def test_protected_services_cannot_be_selected_even_with_zero(self):
        result = self.services("restart 'speakersafetyd.service'\nrestart 'pipewire.service'", answer="0")
        self.assertEqual(result.returncode, 22)
        self.assertEqual(len(self.h.logs()), 1)
        self.assertTrue(self.h.logs()[0].startswith("elevate\tcheckservices"))

    def test_mixed_requests_restart_only_reviewed_generic_unit(self):
        result = self.services("restart 'sshd.service'\nrestart 'speakersafetyd.service'", answer="0")
        self.assertEqual(result.returncode, 22)
        self.assertEqual(self.h.logs()[-1], "elevate\tsystemctl\trestart\t--\tsshd.service")

    def test_generic_restart_decline_leaves_systemctl_uncalled(self):
        result = self.services("restart 'sshd.service'", answer="")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("systemctl", "\n".join(self.h.logs()))

    def test_invalid_unit_argument_aborts_before_prompt_and_restart(self):
        result = self.services("restart '--all.service'", answer="0")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(self.h.logs()[-1], "error")
        self.assertNotIn("ask_array", self.h.logs())

    def test_discovery_failure_cannot_report_no_services(self):
        result = self.services("", DISCOVERY_EXIT="1")
        self.assertEqual(result.returncode, 11)
        self.assertEqual(self.h.logs()[-1], "error")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    upstream.SOURCE = args.source.resolve(strict=True)
    print("Synthetic policies only; private mocked commands; hardware/update acceptance NOT RUN")
    unittest.main(argv=[__file__, *remaining])
