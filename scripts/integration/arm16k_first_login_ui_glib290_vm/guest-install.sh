#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Fresh owned emulated guest only. Normal signatures/scriptlets/hooks retained.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin LANG=C LC_ALL=C
D=/var/lib/arm16k-virtio-seat
. "$D/bytes.sh"
. "$D/rtc-clock.sh"
phase=guard
finish() {
 local rc=$? sync_failed=0
 trap - ERR EXIT
 set +e
 if [[ $rc != 0 ]];then
  printf 'STATUS=HOLD\nFAILED_PHASE=%s\n' "$phase" > "$D/summary.env"
  sync -f "$D"
  printf '\nUI_HOLD %s {"stage":"install","category":"shell-stage-refusal","phase":"%s"}\n' "$nonce" "$phase" > /dev/ttyAMA0
 fi
 for f in "$D"/receipts/* "$D/summary.env";do if [[ -f $f && ! -L $f && $(stat -c %s "$f") -le 1048576 ]];then sync -f "$f" || sync_failed=1;fi;done
 sync -f "$D" || sync_failed=1
 if [[ $sync_failed != 0 ]];then rc=1;printf 'STATUS=HOLD\nFAILED_PHASE=syncfs\n' > "$D/summary.env";printf '\nUI_HOLD %s {"stage":"install","category":"syncfs-refusal"}\n' "$nonce" > /dev/ttyAMA0;fi
 exit "$rc"
}
nonce=unread
trap finish EXIT
[[ $# == 0 && $EUID == 0 && $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(cat /proc/1/comm) == systemd ]]
IFS= read -r nonce < /etc/arm16k-virtio-seat-nonce
[[ $nonce =~ ^[0-9a-f]{32}$ ]];grep -qw "arm16k_virtio_seat_nonce=$nonce" /proc/cmdline
[[ ! -e $D/consumed ]];(set -o noclobber;printf '%s\n' "$nonce" > "$D/consumed")
install -d -m700 "$D/receipts" "$D/trust" "$D/cache"
phase=clock;rtc_clock_guard
phase=baseline
pacman -Q | sort > "$D/receipts/before.lock"
same_bytes "$D/expected-before.lock" "$D/receipts/before.lock"
[[ $(wc -l < "$D/receipts/before.lock") == 111 ]]
sha256sum -c "$D/baseline-files.sha256" > "$D/receipts/baseline-files.log"
printf '{"/etc/passwd":"%s","/etc/group":"%s","/etc/shadow":"%s","/etc/gshadow":"%s"}\n' "$(sha256sum /etc/passwd | cut -d' ' -f1)" "$(sha256sum /etc/group | cut -d' ' -f1)" "$(sha256sum /etc/shadow | cut -d' ' -f1)" "$(sha256sum /etc/gshadow | cut -d' ' -f1)" > "$D/accounts-before.json"
phase=trust
cd "$D/materials"
sha256sum -c "$D/materials.sha256" > "$D/receipts/material-hashes.log"
for key in official-public.gpg project-public.gpg;do
 timeout --signal=TERM --kill-after=3s 30 gpg --no-options --batch --no-auto-key-retrieve --auto-key-locate clear --no-autostart --homedir "$D/trust" --import "$key" >> "$D/receipts/key-import.log" 2>&1
done
timeout --signal=TERM --kill-after=3s 30 gpg --no-options --batch --no-autostart --homedir "$D/trust" --import-ownertrust < "$D/ownertrust.lock" > "$D/receipts/ownertrust.log" 2>&1
gpg --no-options --batch --no-autostart --homedir "$D/trust" --with-colons --list-secret-keys > "$D/receipts/secret-key-check.log"
[[ ! -s $D/receipts/secret-key-check.log ]]
phase=install
archives=()
while IFS= read -r file;do [[ $file =~ ^[A-Za-z0-9@._+:-]+\.pkg\.tar\.(xz|zst)$ && -f $file && ! -L $file ]];archives+=("$D/materials/$file");done < "$D/archive-names.lock"
[[ ${#archives[@]} == 173 ]]
timeout --signal=TERM --kill-after=3s 180 pacman --config "$D/pacman.conf" --noconfirm -U "${archives[@]}" > "$D/receipts/pacman-install.log" 2>&1
pacman -Q | sort > "$D/receipts/installed.lock"
same_bytes "$D/expected-after.lock" "$D/receipts/installed.lock"
pacman -Dk > "$D/receipts/dependencies.log"
phase=original-policy
sha256sum -c "$D/original-files.sha256" > "$D/receipts/original-policy.log"
[[ $(pacman -Qoq /usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy) == networkmanager ]]
phase=services
systemctl daemon-reload
systemctl start polkit.service
[[ $(systemctl is-enabled NetworkManager.service) == masked ]]
printf 'STATUS=PASS\nNONCE=%s\nBASELINE_PACKAGES=111\nINSTALLED_PACKAGES=283\nTRUSTED_ALPM=Required_TrustedOnly\nHOOKS_SCRIPTLETS=unsuppressed\nPOLICY_OWNER=networkmanager\nCLOCK_SETTING=none\n' "$nonce" > "$D/summary.env"
for f in "$D"/receipts/*;do [[ -f $f && ! -L $f && $(stat -c %s "$f") -le 1048576 ]];done
sync -f "$D"
