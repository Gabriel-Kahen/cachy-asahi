#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -eu
nonce=$(cat /etc/tcg-reference-nonce)
[[ "$nonce" =~ ^[0-9a-f]{32}$ ]]
grep -qw "tcg_reference_nonce=$nonce" /proc/cmdline
[[ $(id -u) == 1000 && $(id -un) == builder ]]
[[ $(cat /proc/1/comm) == systemd ]]
[[ -n ${XDG_SESSION_ID:-} ]]
printf '\nTCG_LOGIN_BEGIN %s\n' "$nonce"
printf 'UID=%s\nUSERNAME=%s\nPID1=systemd\nXDG_SESSION_ID=%s\n' "$(id -u)" "$(id -un)" "$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" --no-pager -p Id -p Name -p User -p Active -p State -p Class -p Remote -p Type -p Service -p Leader
systemctl is-active --quiet systemd-logind.service
systemctl is-active --quiet dbus.service
printf 'LOGIND=active\nDBUS=active\n'
printf 'TCG_LOGIN_END %s\n' "$nonce"
