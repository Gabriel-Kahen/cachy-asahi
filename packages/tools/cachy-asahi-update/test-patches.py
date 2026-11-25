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
PATCH_SHA = "a002527c1ca4643d75815c6ddd002e314b2939a644f91740edaed3701eb4b819"
FULL_UPGRADE_SHA = "103c965d6d7b86b558b3fc686975a3a649de3cc2e0b94f7dee608c7bdaeaef0a"
COMMON_SHA = "3d3de36e22e509c2be638eb128c98ee90328dc2c93fe881e6a2a72093be347d9"
ENTRY_SHA = "b8857c72cf720c97361537dd13a5ae76bf2177e31eeef08f30aa4f6ff1eef010"
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
        for path, digest in (("lib/full_upgrade.sh", FULL_UPGRADE_SHA), ("lib/common.sh", COMMON_SHA)):
            data = (upstream.SOURCE / "src" / path).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            (self.lib / Path(path).name).write_bytes(data)
        patch = PATCH.read_bytes()
        self.assertEqual(hashlib.sha256(patch).hexdigest(), PATCH_SHA)
        destinations = [line[6:] for line in patch.decode().splitlines()
                        if line.startswith("+++ b/")]
        self.assertEqual(set(destinations), {
            "src/lib/notification.sh", "src/lib/check.sh",
            "src/lib/flatpak_unused_packages.sh", "src/lib/full_upgrade.sh",
            "src/lib/common.sh",
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

    def run_repository_check(self, status=0, output="fixture-package 1 -> 2\n", no_version="",
                             optional_mocks="", entry="check", **extra):
        return self.run_lib(entry, '''
checkupdates_db_tmpdir_prefix="$XDG_RUNTIME_DIR/checkupdates-"
checkupdates() {
    record checkupdates "$@"
    [[ -d "$CHECKUPDATES_DB" ]] || return 99
    printf '%s' "$CHECK_OUTPUT"
    return "$CHECK_EXIT"
}
''' + optional_mocks, CHECK_EXIT=str(status), CHECK_OUTPUT=output, no_version=no_version, **extra)

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

    def run_optional_check(self, **extra):
        return self.run_repository_check(status=2, output="", optional_mocks=r'''
set -- --check
aur_fixture() {
    record "$1" "$2" "$LC_ALL"
    printf '%s' "${AUR_OUTPUT:-}"
    printf '%s' "${AUR_ERROR:-}" >&2
    if [[ ${AUR_EXIT:-0} == signal ]]; then kill -TERM "$BASHPID"; fi
    return "${AUR_EXIT:-0}"
}
paru() { aur_fixture paru "$@"; }
yay() { aur_fixture yay "$@"; }
pikaur() { aur_fixture pikaur "$@"; }
flatpak() {
    record flatpak "$@"
    case "$*" in
        'list --user') printf '%s' "${FLATPAK_USER_APPS-fixture user app}" ;;
        'list --system') printf '%s' "${FLATPAK_SYSTEM_APPS:-}" ;;
        'update --appstream') ;;
        'mask') printf '%s' "${MASKS:-}" ;;
        'remote-ls --updates --columns=application,version' | \
        'remote-ls --updates --columns=name,version' | \
        'remote-ls --updates --columns=name') printf '%s' "${FLATPAK_OUTPUT:-}" ;;
        'list --columns=application,name') printf '%s' "${FLATPAK_NAMES:-}" ;;
        *) blocked flatpak "$@" ;;
    esac
    if [[ "$1" == "${FAIL_FLATPAK:-}" || "$*" == "${FAIL_FLATPAK:-}" ]]; then
        if [[ ${FLATPAK_EXIT:-1} == signal ]]; then (kill -TERM "$BASHPID"); return $?; fi
        return "${FLATPAK_EXIT:-1}"
    fi
}
''', **extra)

    def check_state(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.state.iterdir()}

    def assert_optional_failure_preserves_state(self, **extra):
        for name in ("last_updates_check", "current_updates_check", "tray_icon", "last_updates_check_time"):
            (self.state / name).write_text("previous " + name + "\n")
        before = self.check_state()
        self.calls.write_text("")
        result = self.run_optional_check(**extra)
        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertEqual(self.logs()[-1], "error")
        self.assertEqual(self.check_state(), before)

    def test_aur_check_failure_or_interruption_preserves_previous_state(self):
        for helper, status, output, error in (
            ("pikaur", "1", "", ""),
            ("paru", "1", "", "request failed\n"),
            ("yay", "1", "partial 1 -> 2\n", ""),
            ("paru", "127", "", ""),
            ("yay", "signal", "partial 1 -> 2\n", ""),
        ):
            with self.subTest(helper=helper, status=status):
                self.assert_optional_failure_preserves_state(
                    aur_helper=helper, AUR_EXIT=status, AUR_OUTPUT=output, AUR_ERROR=error)
                self.assertEqual(self.logs(), ["checkupdates", f"{helper}\t-Qua\tC", "error"])

    def test_flatpak_check_failure_or_interruption_preserves_previous_state(self):
        for step, masked, status in (
            ("list --user", False, "1"), ("list --system", False, "1"),
            ("update", False, "1"), ("mask", False, "1"),
            ("remote-ls", False, "1"), ("remote-ls", True, "1"),
            ("list", True, "1"), ("remote-ls", True, "signal"),
        ):
            with self.subTest(step=step, masked=masked, status=status):
                self.assert_optional_failure_preserves_state(
                    FAIL_FLATPAK=step, FLATPAK_EXIT=status, flatpak_support="flatpak",
                    MASKS="org.fixture.Masked*\n" if masked else "",
                    FLATPAK_OUTPUT="org.fixture.Pending\t2\n" if masked else "",
                    FLATPAK_NAMES="org.fixture.Pending Pending App\n",
                    aur_helper="pikaur", AUR_OUTPUT="new-aur 1 -> 2\n")
                self.assertTrue(self.logs()[-2].startswith("flatpak\t" + step.replace(" ", "\t")))

    def test_first_run_optional_failure_creates_no_state(self):
        for path in self.state.iterdir():
            path.unlink()
        for extra in ({"aur_helper": "pikaur", "AUR_EXIT": "1"},
                      {"flatpak_support": "flatpak", "FAIL_FLATPAK": "remote-ls"}):
            with self.subTest(extra=extra):
                self.assertEqual(self.run_optional_check(**extra).returncode, 20)
                self.assertEqual(list(self.state.iterdir()), [])

    def test_disabled_optional_sources_are_skipped(self):
        result = self.run_optional_check(aur_helper="paru", flatpak_support="flatpak",
                                         no_aur="true", no_flatpak="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["checkupdates"])
        self.assertEqual((self.state / "last_updates_check").read_text(), "aur pending\nflatpak pending\n")

    def test_flatpak_without_installed_apps_skips_update_query(self):
        result = self.run_optional_check(flatpak_support="flatpak", FLATPAK_USER_APPS="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["checkupdates", "flatpak\tlist\t--user", "flatpak\tlist\t--system"])

    def test_check_entry_preserves_state_when_flatpak_discovery_fails(self):
        data = (upstream.SOURCE / "src/arch-update.sh").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), ENTRY_SHA)
        (self.lib / "arch-update.sh").write_bytes(data)
        (self.bin / "gettext.sh").write_text('eval_gettext() { printf "%s" "$1"; }\n')
        (self.bin / "rm").symlink_to(shutil.which("rm"))
        config = self.root / "config/arch-update"
        config.mkdir()
        (config / "arch-update.conf").write_text("NoAUR\nNoColor\nNoNotification\n")
        state = self.state / "arch-update"
        state.mkdir()
        for path in self.state.glob("last_updates_check_*"):
            path.rename(state / path.name)
        self.state = state
        before = self.check_state()
        result = self.run_optional_check(entry="arch-update", FAIL_FLATPAK="list --system",
                                         FLATPAK_USER_APPS="", ARCH_UPDATE_LIBDIR=str(self.lib))
        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn("previous check state has been preserved", result.stderr)
        self.assertEqual(self.logs(), ["checkupdates", "flatpak\tlist\t--user", "flatpak\tlist\t--system"])
        self.assertEqual(self.check_state(), before)

    def test_empty_optional_success_clears_previous_pending_state(self):
        for helper, status, output, error in (
            ("paru", "1", "", ""), ("yay", "1", "", ""),
            ("pikaur", "0", "", "reading metadata\n"),
            ("paru", "0", "ignored-fixture 1 -> 2 [ignored]\n", ""),
        ):
            with self.subTest(helper=helper, output=output):
                for kind in ("aur", "flatpak"):
                    (self.state / f"last_updates_check_{kind}").write_text(kind + " pending\n")
                result = self.run_optional_check(aur_helper=helper, AUR_EXIT=status, AUR_OUTPUT=output,
                                                 AUR_ERROR=error, flatpak_support="flatpak")
                self.assertEqual(result.returncode, 0, result.stderr)
                for kind in ("aur", "flatpak"):
                    self.assertEqual((self.state / f"last_updates_check_{kind}").read_bytes(), b"")
                self.assertEqual((self.state / "tray_icon").read_text(), "up-to-date\n")

    def test_optional_check_success_preserves_format_masks_and_no_version(self):
        for masked in (False, True):
            for no_version in ("", "true"):
                with self.subTest(masked=masked, no_version=no_version):
                    self.calls.write_text("")
                    result = self.run_optional_check(
                        aur_helper="paru", AUR_OUTPUT="  fixture-aur   1 -> 2\nignored 1 -> 2 [ignored]\n",
                        flatpak_support="flatpak", no_version=no_version,
                        MASKS=" org.fixture.Masked*\n" if masked else "",
                        FLATPAK_NAMES="org.fixture.App Fixture App\n",
                        FLATPAK_OUTPUT=("org.fixture.MaskedOne\t1\norg.fixture.App\t2\norg.fixture.Fallback\t3\n"
                                        if masked else "Fixture App\n" if no_version else "Fixture App\t2\n"))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    aur = "fixture-aur\n" if no_version else "fixture-aur 1 -> 2\n"
                    flatpak = "Fixture App\n" if no_version else "Fixture App 2\n"
                    if masked:
                        flatpak += "org.fixture.Fallback\n" if no_version else "org.fixture.Fallback 3\n"
                    self.assertEqual((self.state / "last_updates_check").read_text(), aur + flatpak)
                    self.assertEqual((self.state / "tray_icon").read_text(), "updates-available\n")
                    columns = "application,version" if masked else "name" if no_version else "name,version"
                    calls = ["checkupdates", "paru\t-Qua\tC", "flatpak\tlist\t--user", "flatpak\tlist\t--system",
                             "flatpak\tupdate\t--appstream", "flatpak\tmask",
                             f"flatpak\tremote-ls\t--updates\t--columns={columns}"]
                    if masked:
                        calls.append("flatpak\tlist\t--columns=application,name")
                    self.assertEqual(self.logs(), calls)

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
