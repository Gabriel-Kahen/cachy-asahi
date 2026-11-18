#!/usr/bin/env python3
"""Apply behavior.patch to pinned private copies and test real modified libraries.

Reuses the frozen upstream fixture harness; commands touching system services,
packages, Flatpak and notifications are mocks. The upgrade-lock tests use actual
flock only on private temporary files and mock later orchestration dependencies.
No build, installed updater, host session bus or system update is exercised.
"""

import argparse
import fcntl
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "test-upstream.py"
HARNESS_SHA = "8e499516cbf77f8c8d5f272e20865acf5f1e979f3890af04d4705ba153c464f3"
PATCH = HERE / "behavior.patch"
PATCH_SHA = "29fb848c84049f62d07cbf96cbe01f55e473ed6d790b045fda5ece539e57e29e"
FULL_UPGRADE_SHA = "103c965d6d7b86b558b3fc686975a3a649de3cc2e0b94f7dee608c7bdaeaef0a"
if hashlib.sha256(HARNESS.read_bytes()).hexdigest() != HARNESS_SHA:
    raise SystemExit("Frozen upstream harness changed")
spec = importlib.util.spec_from_file_location("upstream", HARNESS)
upstream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upstream)


class PatchedBehavior(upstream.UpstreamBehavior):
    # Replace the three upstream defect characterizations with fixed behavior.
    test_notification_launch_interpolates_desktop_path_into_shell = None
    test_check_enable_failure_is_not_propagated_upstream = None
    test_flatpak_cleanup_invokes_uninstall_before_own_confirmation = None

    def setUp(self):
        super().setUp()
        data = (upstream.SOURCE / "src/lib/full_upgrade.sh").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), FULL_UPGRADE_SHA)
        (self.lib / "full_upgrade.sh").write_bytes(data)
        patch = PATCH.read_bytes()
        self.assertEqual(hashlib.sha256(patch).hexdigest(), PATCH_SHA)
        destinations = [line[6:] for line in patch.decode().splitlines()
                        if line.startswith("+++ b/")]
        self.assertEqual(set(destinations), {
            "src/lib/notification.sh", "src/lib/check.sh",
            "src/lib/flatpak_unused_packages.sh", "src/lib/full_upgrade.sh",
        })
        result = subprocess.run(
            [shutil.which("patch"), "--batch", "--forward", "--fuzz=0", "-p3", "-i", str(PATCH)],
            cwd=self.lib, capture_output=True, text=True, timeout=5,
            env={"PATH": str(self.bin), "LC_ALL": "C"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in ("stat", "realpath"):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, name)
            (self.bin / name).symlink_to(executable)
        self.runtime = self.root / "runtime"
        self.runtime.chmod(0o700)
        self.private = self.runtime / "arch-update"
        self.private.mkdir()
        # Dependencies reached after lock acquisition, not the update backend.
        (self.lib / "list_packages.sh").write_text("record list_packages\n")
        (self.lib / "packages_cache.sh").write_text("record packages_cache\n")
        for name in destinations:
            syntax = subprocess.run([upstream.BASH, "-n", str(self.lib / Path(name).name)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_notification_launch_preserves_path_as_one_argument(self):
        # Override the original characterization: now one preserved argv value.
        data = self.root / "data with spaces; fixture"
        (data / "applications").mkdir(parents=True)
        desktop = data / "applications/arch-update.desktop"
        desktop.write_text("fixture desktop\n")
        (self.bin / "gettext.sh").write_text('eval_gettext() { printf "%s" "$1"; }\n')
        result = self.run_lib("notification", '''
update_number=1; tray_icon_style=blue
notify-send() { record notify-send "$@"; printf '42\\nrun\\n'; }
systemd-run() { record systemd-run "$@"; }
''', XDG_DATA_HOME=str(data))
        self.assertEqual(result.returncode, 0, result.stderr)
        launch = self.logs()[1].split("\t")
        self.assertEqual(launch[-3:], ["gio", "launch", str(desktop)])
        self.assertNotIn("/bin/bash", launch)
        self.assertNotIn("-c", launch)

    def test_notification_launch_failure_returns_eighteen(self):
        data = self.root / "data/applications"
        data.mkdir()
        (data / "arch-update.desktop").write_text("fixture desktop\n")
        (self.bin / "gettext.sh").write_text('eval_gettext() { printf "%s" "$1"; }\n')
        result = self.run_lib("notification", '''
update_number=1
notify-send() { printf '42\\nrun\\n'; }
systemd-run() { record systemd-run "$@"; return 1; }
''')
        self.assertEqual(result.returncode, 18)

    def test_check_enable_failure_stops_before_success_message(self):
        # Override original behavior: activation failure now stops before success.
        result = self.run_lib("check", '''
set -- --check --enable
systemctl() { record systemctl "$@"; return 1; }
info_msg() { record success_message; }
''')
        self.assertEqual(result.returncode, 19)
        self.assertEqual(self.logs(), ["systemctl\t--user\tenable\t--now\tarch-update.timer", "error"])

    def test_timer_success_reports_success_after_command(self):
        result = self.run_lib("check", '''
set -- --check --enable
systemctl() { record systemctl "$@"; }
info_msg() { record success_message; }
''')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.logs(), ["systemctl\t--user\tenable\t--now\tarch-update.timer", "success_message"])

    def run_repository_check(self, status=0, output="fixture-package 1 -> 2\n", no_version=""):
        return self.run_lib("check", '''
checkupdates_db_tmpdir_prefix="$XDG_RUNTIME_DIR/checkupdates-"
checkupdates() {
    record checkupdates "$@"
    [[ -d "$CHECKUPDATES_DB" ]] || return 99
    printf '%s' "$CHECK_OUTPUT"
    return "$CHECK_EXIT"
}
''', CHECK_EXIT=str(status), CHECK_OUTPUT=output, no_version=no_version)

    def test_repository_check_pending_preserves_versions_and_optional_results(self):
        result = self.run_repository_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["checkupdates"])
        self.assertEqual((self.state / "last_updates_check_packages").read_text(), "fixture-package 1 -> 2\n")
        self.assertEqual((self.state / "last_updates_check").read_text(),
                         "fixture-package 1 -> 2\naur pending\nflatpak pending\n")
        self.assertEqual((self.state / "tray_icon").read_text(), "updates-available\n")
        self.assertTrue((self.state / "last_updates_check_time").read_text().splitlines()[0].isdigit())

    def test_repository_check_no_version_formats_only_after_success(self):
        result = self.run_repository_check(no_version="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["checkupdates"])
        self.assertEqual((self.state / "last_updates_check_packages").read_text(), "fixture-package\n")

    def test_repository_check_no_updates_is_success_with_either_version_setting(self):
        for no_version in ("", "true"):
            with self.subTest(no_version=no_version):
                for path in self.state.iterdir():
                    path.unlink()
                result = self.run_repository_check(status=2, output="", no_version=no_version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.state / "last_updates_check_packages").read_bytes(), b"")
                self.assertEqual((self.state / "last_updates_check").read_text().strip(), "")
                self.assertEqual((self.state / "tray_icon").read_text(), "up-to-date\n")
                self.assertTrue((self.state / "last_updates_check_time").exists())

    def test_repository_check_failure_preserves_all_state_and_returns_twenty(self):
        for name in ("last_updates_check", "current_updates_check", "tray_icon", "last_updates_check_time"):
            (self.state / name).write_text("previous " + name + "\n")
        before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.state.iterdir()}
        for status in (1, 7, 127):
            for no_version in ("", "true"):
                with self.subTest(status=status, no_version=no_version):
                    self.calls.write_text("")
                    result = self.run_repository_check(status=status, output="incomplete result\n", no_version=no_version)
                    self.assertEqual(result.returncode, 20, result.stderr)
                    self.assertEqual(self.logs(), ["checkupdates", "error"])
                    after = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.state.iterdir()}
                    self.assertEqual(after, before)

    def test_repository_check_failure_creates_no_state_on_first_run(self):
        for path in self.state.iterdir():
            path.unlink()
        for no_version in ("", "true"):
            with self.subTest(no_version=no_version):
                result = self.run_repository_check(status=1, no_version=no_version)
                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertEqual(list(self.state.iterdir()), [])

    def test_repository_check_database_creation_failure_stops_before_helper_or_state(self):
        for name in ("last_updates_check", "tray_icon", "last_updates_check_time"):
            (self.state / name).write_text("previous " + name + "\n")
        before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.state.iterdir()}
        result = self.run_lib("check", '''
mktemp() { return 1; }
checkupdates() { record checkupdates; printf 'unexpected fallback result\\n'; }
''')
        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertEqual(self.logs(), ["error"])
        self.assertEqual({path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                          for path in self.state.iterdir()}, before)

    def test_flatpak_decline_calls_no_uninstall(self):
        # Override original behavior: declining makes no Flatpak command call.
        result = self.run_lib("flatpak_unused_packages", ANSWER="n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.logs(), ["ask"])

    def test_flatpak_accept_preserves_interactive_discovery_and_removal(self):
        result = self.run_lib("flatpak_unused_packages", '''
flatpak() { record flatpak "$@"; }
''', ANSWER="y")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.logs(), ["ask", "flatpak\tuninstall\t--unused"])

    def test_flatpak_failure_propagates_after_opt_in(self):
        result = self.run_lib("flatpak_unused_packages", '''
flatpak() { record flatpak "$@"; return 1; }
''', ANSWER="y")
        self.assertEqual(result.returncode, 20)
        self.assertEqual(self.logs(), ["ask", "flatpak\tuninstall\t--unused", "error"])

    def full_upgrade(self, before="", **extra):
        return self.run_lib("full_upgrade", '''
tmpdir="$XDG_RUNTIME_DIR/arch-update"
pacman() { record pacman "$@"; }
''' + before, **extra)

    def assert_refused_before_update(self, before="", **extra):
        result = self.full_upgrade(before, **extra)
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(self.logs(), ["error"])

    def test_lock_creation_is_private_and_acquisition_allows_stages(self):
        result = self.full_upgrade()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.private / "upgrade.lock").stat().st_mode & 0o777, 0o600)
        self.assertIn("list_packages", self.logs())
        self.assertIn("packages_cache", self.logs())

    def test_lock_append_does_not_truncate_existing_contents(self):
        lock = self.private / "upgrade.lock"
        lock.write_text("private marker\n")
        lock.chmod(0o600)
        self.assertEqual(self.full_upgrade().returncode, 0)
        self.assertEqual(lock.read_text(), "private marker\n")

    def test_concurrent_lock_cannot_be_bypassed_by_yes_answer(self):
        lock = self.private / "upgrade.lock"
        lock.touch(mode=0o600)
        with lock.open("a") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_refused_before_update(ANSWER="y")

    def test_lock_is_released_when_process_exits(self):
        self.assertEqual(self.full_upgrade().returncode, 0)
        self.calls.write_text("")
        self.assertEqual(self.full_upgrade().returncode, 0)
        self.assertIn("list_packages", self.logs())

    def test_shared_runtime_directory_is_refused(self):
        self.runtime.chmod(0o755)
        self.assert_refused_before_update()

    def test_writable_updater_directory_is_refused(self):
        self.private.chmod(0o777)
        self.assert_refused_before_update()

    def test_runtime_symlink_is_refused(self):
        alias = self.root / "runtime-alias"
        alias.symlink_to(self.runtime, target_is_directory=True)
        self.assert_refused_before_update(XDG_RUNTIME_DIR=str(alias))

    def test_runtime_ancestor_symlink_is_refused(self):
        alias = self.root / "root-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assert_refused_before_update(XDG_RUNTIME_DIR=str(alias / "runtime"))

    def test_writable_nonsticky_runtime_ancestor_is_refused(self):
        parent = self.root / "shared-parent"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        runtime = parent / "runtime"
        runtime.mkdir(mode=0o700)
        (runtime / "arch-update").mkdir()
        self.assert_refused_before_update(XDG_RUNTIME_DIR=str(runtime))

    def test_updater_subdirectory_symlink_is_refused(self):
        self.private.rmdir()
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        self.private.symlink_to(outside, target_is_directory=True)
        self.assert_refused_before_update()
        self.assertEqual(list(outside.iterdir()), [])

    def test_lock_symlink_does_not_open_or_change_target(self):
        target = self.root / "user-file"
        target.write_text("user bytes\n")
        (self.private / "upgrade.lock").symlink_to(target)
        self.assert_refused_before_update()
        self.assertEqual(target.read_text(), "user bytes\n")

    def test_dangling_lock_symlink_does_not_create_target(self):
        target = self.root / "absent-user-file"
        (self.private / "upgrade.lock").symlink_to(target)
        self.assert_refused_before_update()
        self.assertFalse(target.exists())

    def test_hardlinked_lock_is_refused(self):
        target = self.root / "user-file"
        target.write_text("user bytes\n")
        target.chmod(0o600)
        (self.private / "upgrade.lock").hardlink_to(target)
        self.assert_refused_before_update()
        self.assertEqual(target.read_text(), "user bytes\n")

    def test_nonregular_lock_is_refused(self):
        (self.private / "upgrade.lock").mkdir()
        self.assert_refused_before_update()

    def test_foreign_runtime_owner_is_refused_by_policy(self):
        # Mock only the ownership observation; never chown or create host users.
        self.assert_refused_before_update('''
stat() {
    if [[ "$2" == %u:%a ]]; then printf '999999:700';
    else command stat "$@"; fi
}
''')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    upstream.SOURCE = args.source.resolve(strict=True)
    if not upstream.BASH or not shutil.which("patch"):
        parser.error("bash and patch are required")
    print("Patched pinned source; private fixture locks; system endpoints mocked; D-Bus NOT RUN")
    unittest.main(argv=[__file__, *remaining])
