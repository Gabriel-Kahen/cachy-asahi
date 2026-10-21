#!/usr/bin/env python3
"""Pinned upstream shell behavior tests; no build, real updater or D-Bus calls.

Usage: python test-upstream.py --source /path/to/cachy-update-e2b1b714...
Only audited, hash-matching libraries are copied into private temporary fixtures.
System commands are shell mocks; PATH contains only selected data/file utilities.
Passing these tests does not accept upstream Apple update/reboot semantics.
"""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

COMMIT = "e2b1b7144be71cf392809f48d1440f8da1d9c81a"
PINS = {
    "update": "dff781d52c387417967a325226e21f29e746f8cdc5d66b65718619a7981189c4",
    "kernel_reboot": "ffa8a469792290959bede1204ac110e5cb8cea67c2197c67d6abb07c40e8aef2",
    "restart_services": "f30f2315c3994286858630fc932b87c4370ce68d18e7665a4b6f50986b41b3d4",
    "tray": "f0f23c27f223f3223fbd73241f9681298fb95271f08ad389b2608507312828ee",
    "config": "2be9e0a6b68f0c4f6774e7c47f4d71584518f6fcbf244549da8b279b41126e13",
    "orphan_packages": "ec74737d6eaa0c7c9362448075259059c406cb938b98a0321cfc149222efe8db",
    "flatpak_unused_packages": "a7e4e6dcad6216eac1a8faffec45e8ff6b175d7b06fce44da45493cf6cf8e078",
    "check": "9b927bbda9e67bbdf086fb7efbf70ce92d0a45ad3c9fe9e8e51008bd4540fc85",
    "notification": "78bd890c6b20604c88afab5d9cd8722ec84d5febfc7967ecc54fedee3baf08c2",
}
SOURCE = None
BASH = shutil.which("bash")

PRELUDE = r'''
record() {
    printf '%s' "$1" >> "$CALLS"
    shift
    if (( $# )); then printf '\t%s' "$@" >> "$CALLS"; fi
    printf '\n' >> "$CALLS"
}
blocked() { record BLOCKED "$@"; exit 97; }
for cmd in pacman sudo sudo-rs doas run0 systemctl checkservices flatpak paru yay \
           pikaur arch-update systemd-run xdg-open gio tput sleep uname setsid; do
    eval "$cmd() { blocked $cmd \"\$@\"; }"
done
eval_gettext() { printf '%s' "$1"; }
main_msg() { :; }; info_msg() { :; }; warning_msg() { :; }; quit_msg() { :; }
error_msg() { record error; }
ask_msg() { record ask; answer="$ANSWER"; }
ask_msg_array() { record ask_array; read -r -a answer_array <<< "$ANSWER"; }
icon_up-to-date() { printf 'up-to-date\n' > "$statedir/tray_icon"; }
icon_updates-available() { printf 'updates-available\n' > "$statedir/tray_icon"; }
name=arch-update; _name=Arch-Update; su_cmd=elevate; pacman_color_opt=never
elevate() { record elevate "$@"; return "${MOCK_EXIT:-0}"; }
'''


class UpstreamBehavior(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cachy-update-mocked-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lib = self.root / "lib"
        self.lib.mkdir()
        for name, digest in PINS.items():
            data = (SOURCE / "src/lib" / f"{name}.sh").read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)
            (self.lib / f"{name}.sh").write_bytes(data)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("cat", "sed", "grep", "wc", "cut", "awk", "mkdir", "cp",
                     "touch", "flock", "mktemp", "mv", "date", "tr"):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, name)
            (self.bin / name).symlink_to(executable)
        self.calls = self.root / "calls"
        self.calls.touch()
        self.state = self.root / "state"
        self.state.mkdir()
        for kind in ("packages", "aur", "flatpak"):
            (self.state / f"last_updates_check_{kind}").write_text(kind + " pending\n")
        for name in ("home", "runtime", "config", "data"):
            (self.root / name).mkdir()

    def run_lib(self, name, before="", after="", **extra):
        env = {
            "PATH": str(self.bin), "HOME": str(self.root / "home"),
            "XDG_RUNTIME_DIR": str(self.root / "runtime"),
            "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_DATA_HOME": str(self.root / "data"), "XDG_DATA_DIRS": str(self.root / "data"),
            "XDG_STATE_HOME": str(self.root / "state"), "LC_ALL": "C",
            "CALLS": str(self.calls), "statedir": str(self.state),
            "tmpdir": str(self.root / "runtime"), "libdir": str(self.lib),
            "AUDITED_LIB": str(self.lib / f"{name}.sh"), "ANSWER": "n",
        }
        env.update(extra)
        result = subprocess.run(
            [BASH, "--noprofile", "--norc", "-c",
             PRELUDE + before + '\nsource "$AUDITED_LIB"\n' + after],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=5,
        )
        self.assertNotIn("BLOCKED", self.calls.read_text(), result.stderr)
        return result

    def logs(self):
        return self.calls.read_text().splitlines()

    def test_repository_update_success_updates_only_its_state(self):
        result = self.run_lib("update", 'packages="fixture pending"',
                              '[[ "$packages_updated" == true ]]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["elevate\tpacman\t--color\tnever\t-Syu"])
        self.assertEqual((self.state / "last_updates_check_packages").read_text(), "")
        self.assertEqual((self.state / "last_updates_check").read_text(),
                         "aur pending\nflatpak pending\n")

    def test_repository_failure_exits_before_state_clear(self):
        result = self.run_lib("update", 'packages="fixture pending"', MOCK_EXIT="1")
        self.assertEqual(result.returncode, 5)
        self.assertEqual((self.state / "last_updates_check_packages").read_text(), "packages pending\n")
        self.assertFalse((self.state / "tray_icon").exists())

    def test_optional_flatpak_failure_keeps_state_and_suppresses_success_icon(self):
        result = self.run_lib("update", '''
flatpak_packages=fixture
flatpak() { record flatpak "$@"; return 1; }
''', '[[ "$error_during_update" == true ]]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["flatpak\tupdate"])
        self.assertEqual((self.state / "last_updates_check_flatpak").read_text(), "flatpak pending\n")
        self.assertFalse((self.state / "tray_icon").exists())

    def test_aur_failure_runs_orphan_query_but_keeps_aur_state(self):
        result = self.run_lib("update", '''
aur_packages=fixture; aur_helper=fixture_aur; devel_flag=(--devel)
pacman() { record pacman "$@"; }
fixture_aur() { record fixture_aur "$@"; return 1; }
''', '[[ "$error_during_update" == true ]]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["pacman\t-Qtdq", "fixture_aur\t--color\tnever\t--devel\t-Syu"])
        self.assertEqual((self.state / "last_updates_check_aur").read_text(), "aur pending\n")
        self.assertFalse((self.state / "tray_icon").exists())

    def test_kernel_missing_decline_does_not_reboot(self):
        result = self.run_lib("kernel_reboot", self.kernel_mocks(), ANSWER="n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["ask"])

    def test_kernel_missing_accept_calls_reboot(self):
        result = self.run_lib("kernel_reboot", self.kernel_mocks(), ANSWER="y")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), ["ask", "systemctl\treboot"])

    def test_kernel_present_has_no_prompt(self):
        result = self.run_lib("kernel_reboot", self.kernel_mocks(), MOCK_PRESENT="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), [])

    def test_reboot_failure_returns_six(self):
        result = self.run_lib("kernel_reboot", self.kernel_mocks(), ANSWER="y", MOCK_EXIT="1")
        self.assertEqual(result.returncode, 6)
        self.assertEqual(self.logs(), ["ask", "systemctl\treboot", "error"])

    @staticmethod
    def kernel_mocks():
        # Override the exact hardcoded path test: no host module path is read.
        return r'''
uname() { printf fixture-kernel; }
[() {
    if [[ "$#" == 3 && "$1" == -f && "$2" == /usr/lib/modules/fixture-kernel/vmlinuz ]]; then
        builtin test "${MOCK_PRESENT:-false}" = true
    else builtin test "$@"; fi
}
systemctl() { record systemctl "$@"; return "${MOCK_EXIT:-0}"; }
sleep() { :; }; tput() { :; }
'''

    def services(self, answer, exit_code="0"):
        return self.run_lib("restart_services", r'''
elevate() {
    record elevate "$@"
    if [[ "$1" == checkservices ]]; then
        printf "restart 'fixture-a.service'\nrestart 'fixture-b.service'\n"
    else return "${MOCK_EXIT:-0}"; fi
}
''', ANSWER=answer, MOCK_EXIT=exit_code)

    def test_services_decline_has_no_restart(self):
        self.assertEqual(self.services("").returncode, 0)
        self.assertEqual(len(self.logs()), 2)
        self.assertTrue(self.logs()[0].startswith("elevate\tcheckservices\t-F\t-P\t-R"))
        self.assertEqual(self.logs()[1], "ask_array")

    def test_services_zero_restarts_all(self):
        self.assertEqual(self.services("0").returncode, 0)
        self.assertEqual(self.logs()[-1], "elevate\tsystemctl\trestart\tfixture-a.service\tfixture-b.service")

    def test_services_selection_deduplicates(self):
        self.assertEqual(self.services("2 2").returncode, 0)
        self.assertEqual(self.logs()[2:], ["elevate\tsystemctl\trestart\tfixture-b.service"])

    def test_service_failure_returns_eleven(self):
        self.assertEqual(self.services("1", "1").returncode, 11)
        self.assertEqual(self.logs()[-2:], ["error", "error"])

    def tray(self, enable=False):
        applications = self.root / "data/applications"
        applications.mkdir(exist_ok=True)
        (applications / "arch-update-tray.desktop").write_text("fixture desktop\n")
        return self.run_lib("tray", '''
ARCH_UPDATE_TRAY_BIN=fixture-tray
setsid() { record setsid "$@" "$ARCH_UPDATE_TRAY_UPDATES_PER_PAGE" "$ARCH_UPDATE_SHOW_TRAY_WHEN_RELEVANT"; }
tray_updates_per_page=4; show_tray_when_relevant=true
''' + ("set -- --tray --enable\n" if enable else "set -- --tray\n"))

    def test_tray_default_does_not_create_autostart(self):
        self.assertEqual(self.tray().returncode, 0)
        self.assertFalse((self.root / "config/autostart").exists())
        self.assertEqual(self.logs(), ["setsid\tfixture-tray\t4\ttrue"])

    def test_tray_enable_is_private_opt_in_and_refuses_overwrite(self):
        self.assertEqual(self.tray(True).returncode, 0)
        autostart = self.root / "config/autostart/arch-update-tray.desktop"
        self.assertEqual(autostart.read_text(), "fixture desktop\n")
        autostart.write_text("user edit\n")
        self.assertEqual(self.tray(True).returncode, 10)
        self.assertEqual(autostart.read_text(), "user edit\n")

    def test_check_enable_calls_user_timer_only_when_explicit(self):
        result = self.run_lib("check", '''
set -- --check --enable
systemctl() { record systemctl "$@"; }
''')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.logs(), ["systemctl\t--user\tenable\t--now\tarch-update.timer"])

    def test_check_enable_failure_is_not_propagated_upstream(self):
        # Records another unresolved behavior: upstream reports success even
        # when mocked systemctl fails. This is not an acceptable activation gate.
        result = self.run_lib("check", '''
set -- --check --enable
systemctl() { record systemctl "$@"; return 1; }
''')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.logs(), ["systemctl\t--user\tenable\t--now\tarch-update.timer"])

    def test_flatpak_cleanup_invokes_uninstall_before_own_confirmation(self):
        # Characterizes a risk, not accepted semantics: the first command can
        # prompt/remove packages before this library asks its own question.
        result = self.run_lib("flatpak_unused_packages", r'''
flatpak() { record flatpak "$@"; printf ' 1. fixture-id\nfooter end\n'; }
''', ANSWER="n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.logs(), ["flatpak\tuninstall\t--unused", "ask"])

    def test_notification_launch_interpolates_desktop_path_into_shell(self):
        # This is risk evidence, not approval: spaces/metacharacters are passed
        # in a shell command string. The systemd-run mock never executes it.
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
        self.assertTrue(self.logs()[0].startswith("notify-send\t-p\t-a\tCachy-Update"))
        self.assertTrue(self.logs()[1].startswith("systemd-run\t--user\t--scope"))
        self.assertTrue(self.logs()[1].endswith(f"\t/bin/bash\t-c\tgio launch {desktop}"))

    def test_config_private_xdg_path_and_invalid_values_fall_back(self):
        config = self.root / "config/arch-update"
        config.mkdir()
        (config / "arch-update.conf").write_text(
            "NoAUR\nNoFlatpak\nTrayUpdatesPerPage=4\nPrivilegeElevationCommand=evil\n"
            "TrayIconStyle=invalid\nUpdateCheckTimeout=bad\n")
        result = self.run_lib("config", after='''
[[ "$no_aur" == true && "$no_flatpak" == true && "$tray_updates_per_page" == 4 &&
   -z "$su_cmd" && "$tray_icon_style" == blue && "$update_check_timeout" == 30 ]]
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs(), [])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    SOURCE = args.source.resolve(strict=True)
    if not BASH:
        parser.error("bash is required")
    print(f"Unmodified pinned shell source {COMMIT}; mocked commands only; D-Bus NOT RUN")
    unittest.main(argv=[__file__, *remaining])
