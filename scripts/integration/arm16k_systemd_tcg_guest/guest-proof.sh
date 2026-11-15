#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -eu
nonce=$(cat /etc/arm16k-systemd-nonce)
[[ "$nonce" =~ ^[0-9a-f]{32}$ ]]
grep -qw "arm16k_systemd_nonce=$nonce" /proc/cmdline
[[ $(id -u) == 1000 && $(id -un) == builder && $(id -G) == 1000 ]]
[[ $(cat /proc/1/comm) == systemd && $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
[[ -n ${XDG_SESSION_ID:-} ]]
printf '\nTCG_LOGIN_BEGIN %s\n' "$nonce"
printf 'UID=1000\nUSERNAME=builder\nPID1=systemd\nARCH=aarch64\nPAGESIZE=16384\nXDG_SESSION_ID=%s\n' "$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" --no-pager -p Id -p Name -p User -p Active -p State -p Class -p Remote -p Type -p Service -p Leader
systemctl is-active --quiet systemd-logind.service
systemctl is-active --quiet dbus.service
printf 'LOGIND=active\nDBUS=active\n'
printf 'TCG_LOGIN_END %s\n' "$nonce"
