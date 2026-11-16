#!/bin/bash
# SPDX-License-Identifier: MIT
# Serial-only public directory metadata. No directory walk or file-body reads.
set -euo pipefail
export LC_ALL=C TZ=UTC0
[[ $# == 2 && $2 =~ ^[0-9a-f]{32}$ ]]
case "$1" in after_login|before_logout) ;; *) exit 2;; esac
[[ $(id -u) == 1000 && $(id -un) == builder ]]
printf '\nARM16K_NO_PACKAGE_META_BEGIN %s %s\n' "$2" "$1"
for p in /root /etc /etc/audit /etc/udev /usr /usr/bin /usr/lib /usr/share /var /var/cache /var/cache/ldconfig /var/lib /var/lib/pacman /var/lib/pacman/local /var/log;do
 parent=${p%/*};parent=${parent:-/}
 [[ -d $parent && -x $parent && ! -L $parent && $(readlink -f -- "$parent") == "$parent" ]]
 if [[ ! -e $p && ! -L $p ]];then
  printf '%s|ABSENT\n' "${p#/}"
 else
  [[ -d $p && ! -L $p && $(readlink -f -- "$p") == "$p" ]]
  printf '%s|' "${p#/}"
  stat --format='%i|%h|%a|%u|%g|%s|%x|%y' -- "$p"
 fi
done
printf 'ARM16K_NO_PACKAGE_META_END %s %s\n' "$2" "$1"
