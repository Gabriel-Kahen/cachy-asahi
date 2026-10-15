#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Execute ONLY inside the disposable runtime container, as its unprivileged user.
set -euo pipefail
[[ $EUID != 0 && $# == 1 && $1 == /* && -x $1 ]]
[[ $(pacman -Q cachy-asahi-update) == 'cachy-asahi-update 4.4.2-1' ]]
[[ $(pacman -Qoq /usr/lib/arch-update/arch-update-tray) == cachy-asahi-update ]]
fixture=$1
session=$(mktemp -d /tmp/updater-tray.XXXXXXXX)
trap 'rm -rf -- "$session"' EXIT
chmod 700 "$session"
mkdir -m700 "$session/home" "$session/runtime" "$session/bin"
home=$session/home
mkdir -p "$home/state/arch-update" "$home/config" "$home/data"
for suffix in '' _packages _aur _flatpak; do
    : > "$home/state/arch-update/last_updates_check$suffix"
done
printf 'fixture-package 1 -> 2\n' > "$home/state/arch-update/last_updates_check"
cp "$home/state/arch-update/last_updates_check" "$home/state/arch-update/last_updates_check_packages"
date +%s > "$home/state/arch-update/last_updates_check_time"
printf 'arch-update\n' > "$home/state/arch-update/tray_icon"
# This endpoint records only the exact tray action. It never invokes the updater.
cat > "$session/bin/arch-update" <<'SH'
#!/usr/bin/bash
set -euo pipefail
[[ $# == 1 && $1 == --check ]]
[[ ! -e $HOME/check-action ]]
printf '%s\n' "$1" > "$HOME/check-action"
SH
chmod 700 "$session/bin/arch-update"
env -i HOME="$home" USER=tray-test LOGNAME=tray-test LANG=C LC_ALL=C \
    XDG_RUNTIME_DIR="$session/runtime" XDG_STATE_HOME="$home/state" \
    XDG_CONFIG_HOME="$home/config" XDG_DATA_HOME="$home/data" \
    XDG_DATA_DIRS=/usr/share PATH="$session/bin:/usr/bin:/bin" \
    timeout --kill-after=2s 35s dbus-run-session -- "$fixture"
