#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Root-owned fixed fixture only; original signatures/hooks, no host/system use.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin LANG=C LC_ALL=C
D=/var/lib/arm16k-virtio-seat
. "$D/bytes.sh"
. "$D/rtc-clock.sh"
capture() {
 local label=$1;shift
 local -a statuses
 set +e
 "$@" 2>&1 | head -c 1048577 > "$D/receipts/$label.log"
 statuses=("${PIPESTATUS[@]}")
 set -e
 [[ ${statuses[0]} == 0 && ${statuses[1]} == 0 && $(stat -c %s "$D/receipts/$label.log") -le 1048576 ]]
}
phase=guard
finish() {
 local rc=$?
 trap - ERR EXIT
 if [[ $rc != 0 ]];then printf 'STATUS=HOLD\nFAILED_PHASE=%s\n' "$phase" > "$D/summary.env";fi
 for f in "$D"/receipts/* "$D/summary.env";do
  [[ -f $f && ! -L $f && $(stat -c %s "$f") -le 1048577 ]] || continue
  if ! sync -f "$f";then rc=1;phase=durability;fi
 done
 if ! sync -f "$D";then rc=1;phase=durability;fi
 if [[ $rc != 0 ]];then
  printf 'STATUS=HOLD\nFAILED_PHASE=%s\n' "$phase" > "$D/summary.env"
  sync -f "$D" || :
  if [[ ${nonce:-} =~ ^[0-9a-f]{32}$ ]];then
   printf '\nSEAT_HOLD %s {"status":"HOLD","failure":{"category":"GuestInstallFailure","phase":"%s"}}\n' "$nonce" "$phase" > /dev/ttyAMA0
  fi
 fi
 exit "$rc"
}
trap finish EXIT
[[ $# == 0 && $EUID == 0 && $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(cat /proc/1/comm) == systemd ]]
for tool in base64 bash cat cut date getconf gpg grep head install pacman sha256sum sleep sort stat sync systemctl timeout uname wc;do [[ $(type -P "$tool") == /usr/bin/"$tool" && -x /usr/bin/$tool ]];done
IFS= read -r nonce < /etc/arm16k-virtio-seat-nonce
[[ $nonce =~ ^[0-9a-f]{32}$ ]];grep -qw "arm16k_virtio_seat_nonce=$nonce" /proc/cmdline
[[ ! -e $D/consumed ]];(set -o noclobber;printf '%s\n' "$nonce" > "$D/consumed")
install -d -m700 "$D/receipts" "$D/trust" "$D/cache"
phase=clock
rtc_clock_guard
phase=baseline
pacman -Q | sort > "$D/receipts/before.lock"
same_bytes "$D/expected-before.lock" "$D/receipts/before.lock"
[[ $(wc -l < "$D/receipts/before.lock") == 111 ]]
phase=trust
cd "$D/materials"
sha256sum -c "$D/materials.sha256" > "$D/receipts/material-hashes.log"
capture key-import timeout --signal=TERM --kill-after=3s 30 gpg --no-options --batch --homedir "$D/trust" --import ./archlinuxarm.gpg
# Fixed audited original public fingerprints only, not an arbitrary trust request.
capture ownertrust timeout --signal=TERM --kill-after=3s 30 gpg --no-options --batch --homedir "$D/trust" --import-ownertrust < "$D/ownertrust.lock"
phase=install
archives=()
while IFS= read -r file;do [[ $file =~ ^[A-Za-z0-9@._+:-]+\.pkg\.tar\.xz$ && -f $file && ! -L $file ]];archives+=("$D/materials/$file");done < "$D/archive-names.lock"
[[ ${#archives[@]} -ge 4 && ${#archives[@]} -le 96 ]]
capture pacman-install timeout --signal=TERM --kill-after=3s 150 pacman --config "$D/pacman.conf" --noconfirm -U "${archives[@]}"
pacman -Q | sort > "$D/receipts/installed.lock"
same_bytes "$D/expected-after.lock" "$D/receipts/installed.lock"
pacman -T python python-gobject polkit networkmanager > "$D/receipts/dependencies.log"
phase=original-policy
sha256sum -c "$D/original-files.sha256" > "$D/receipts/original-policy.log"
pacman -Qo /usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy > "$D/receipts/policy-owner.log"
[[ $(pacman -Qoq /usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy) == networkmanager ]]
for tool in python3 pkaction udevadm loginctl journalctl;do [[ $(type -P "$tool") == /usr/bin/"$tool" && -x /usr/bin/$tool ]];done
/usr/bin/python3 -I -B "$D/namespace-check.py" > "$D/receipts/namespace.log"
phase=services
systemctl daemon-reload
systemctl start polkit.service
[[ $(systemctl is-enabled NetworkManager.service) == masked ]]
printf 'STATUS=PASS\nNONCE=%s\nBASELINE_PACKAGES=111\nINSTALLED_PACKAGES=%s\nTRUSTED_ALPM=Required_TrustedOnly\nHOOKS_SCRIPTLETS=unsuppressed\nPOLICY_OWNER=networkmanager\nCLOCK_SETTING=none\n' "$nonce" "$(wc -l < "$D/receipts/installed.lock")" > "$D/summary.env"
# Bound complete fixed receipts before terminal visibility; excessive logs HOLD.
for f in "$D"/receipts/*;do [[ -f $f && ! -L $f && $(stat -c %s "$f") -le 1048576 ]];done
sync -f "$D"
