# SPDX-License-Identifier: MIT
# Separate public-only scratch trust for the exact official db5.3 transaction.
official_policy_file() {
 local kind=$1 path=$2 signer=$3 line fingerprint level
 while IFS= read -r line || [[ -n $line ]];do
  line=${line%%#*};[[ -n $line ]] || continue
  [[ $line =~ ^([0-9A-F]{40})(:([1-6]):?)?$ ]] || return 2
  fingerprint=${BASH_REMATCH[1]};level=${BASH_REMATCH[3]:-}
  if [[ $kind == trusted ]];then
   [[ -n $level ]] || return 2
   [[ $fingerprint != "$signer" || $level == 4 || $level == 5 || $level == 6 ]] || return 2
  elif [[ $kind == revoked ]];then [[ $fingerprint != "$signer" ]] || return 2
  else return 2;fi
 done < "$path"
}
official_gpg() (
 local home=$1 label=$2;shift 2
 [[ $home == "$O/official-import" || $home == "$O/official-trust" ]]
 ulimit -f 8192
 bounded "$gpg_seconds" "$S/$label.log" gpg --no-options --homedir "$home" --batch --no-tty --no-auto-key-retrieve --no-autostart "$@"
)
official_single_primary() {
 local kind a b c d e f g h i rest pubs=0 primary= want=0
 while IFS=: read -r kind a b c d e f g h i rest;do
  case "$kind" in pub) pubs=$((pubs+1));want=1;;fpr) if [[ $want == 1 ]];then primary=$i;want=0;fi;;esac
 done < "$1"
 [[ $pubs == 1 && $primary == "$official_signer" ]]
}
official_init() {
 local path bytes hash mode owner version extra count=0
 [[ ! -e /etc/pacman.d/gnupg && ! -L /etc/pacman.d/gnupg ]]
 official_signer=$(cat "$D/official-signer")
 [[ $official_signer == 68B3537F39A313B3E574D06777193F152BDBE6A6 ]]
 : > "$S/official-public-observation.tsv"
 while IFS=$'\t' read -r path bytes hash mode owner version extra;do
  [[ -z $extra && $path == /usr/share/pacman/keyrings/archlinuxarm* && $bytes =~ ^[0-9]+$ && $bytes -le 4194304 && $hash =~ ^[0-9a-f]{64}$ && $mode == 644 && $owner == archlinuxarm-keyring ]]
  [[ -f $path && ! -L $path && $(readlink -f -- "$path") == "$path" && $(stat -c '%s:%a:%u:%g' -- "$path") == "$bytes:$mode:0:0" && $(file_sha "$path") == "$hash" ]]
  [[ $(pacman -Qoq -- "$path") == "$owner" && $(pacman -Q "$owner") == "$owner $version" ]]
  case "$path" in
   /usr/share/pacman/keyrings/archlinuxarm.gpg) (( bytes > 0 ));;
   /usr/share/pacman/keyrings/archlinuxarm-trusted) official_policy_file trusted "$path" "$official_signer";;
   /usr/share/pacman/keyrings/archlinuxarm-revoked) official_policy_file revoked "$path" "$official_signer";;
   *) return 2;;
  esac
  printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$bytes" "$hash" "$owner" "$version" >> "$S/official-public-observation.tsv"
  count=$((count+1))
 done < "$D/official-public-files.tsv"
 [[ $count == 3 && ! -e $O/official-import && ! -L $O/official-import && ! -e $O/official-trust && ! -L $O/official-trust ]]
 install -d -m700 "$O/official-import" "$O/official-trust"
 # Import the unchanged baseline public ring only into disposable scratch,
 # export the sole admitted primary, then admit exactly that public key.
 official_gpg "$O/official-import" official-source-import --import-options import-minimal --import /usr/share/pacman/keyrings/archlinuxarm.gpg
 official_gpg "$O/official-import" official-selected-export --output "$O/official-trust/selected-public.gpg" --export "$official_signer"
 [[ -f $O/official-trust/selected-public.gpg && ! -L $O/official-trust/selected-public.gpg && $(stat -c '%s' "$O/official-trust/selected-public.gpg") -gt 0 ]]
 bounded "$gpg_seconds" "$S/official-import-stop.log" gpgconf --homedir "$O/official-import" --kill all
 rm -rf -- "$O/official-import"
 official_gpg "$O/official-trust" official-import --import "$O/official-trust/selected-public.gpg"
 official_gpg "$O/official-trust" official-secret --with-colons --list-secret-keys
 ! grep -Eq '^(sec|ssb):' "$S/official-secret.log"
 official_gpg "$O/official-trust" official-keys --with-colons --fingerprint --list-keys
 official_single_primary "$S/official-keys.log"
 printf '%s:6:\n' "$official_signer" > "$S/official-ownertrust"
 official_gpg "$O/official-trust" official-ownertrust --import-ownertrust "$S/official-ownertrust"
 clock_valid
 official_gpg "$O/official-trust" official-signature --status-fd 1 --verify "$D/db5.3-5.3.28-7-aarch64.pkg.tar.xz.sig" "$D/db5.3-5.3.28-7-aarch64.pkg.tar.xz"
 local line marker code rest signing valids=0 trusted=0
 while IFS= read -r line;do
  [[ $line == '[GNUPG:] '* ]] || continue
  read -r marker code rest <<< "$line"
  case "$code" in
   VALIDSIG) read -r signing rest <<< "$rest";[[ $signing == "$official_signer" || ${rest##* } == "$official_signer" ]];valids=$((valids+1));;
   TRUST_ULTIMATE) trusted=$((trusted+1));;
   NEWSIG|KEY_CONSIDERED|SIG_ID|GOODSIG) ;;
   *) return 2;;
  esac
 done < "$S/official-signature.log"
 [[ $valids == 1 && $trusted == 1 && ! -e /etc/pacman.d/gnupg && ! -L /etc/pacman.d/gnupg ]]
}
official_finish() {
 bounded "$gpg_seconds" "$S/official-stop.log" gpgconf --homedir "$O/official-trust" --kill all
 rm -rf -- "$O/official-trust"
 [[ ! -e $O/official-trust && ! -L $O/official-trust && ! -e $O/official-import && ! -L $O/official-import && ! -e /etc/pacman.d/gnupg && ! -L /etc/pacman.d/gnupg ]]
}
