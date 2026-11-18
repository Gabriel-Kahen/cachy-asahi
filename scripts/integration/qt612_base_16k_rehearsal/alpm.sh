#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Execute only in the selected disposable ARM16K chroot.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C HOME=/root
unset GNUPGHOME GPG_AGENT_INFO
shopt -s nullglob dotglob

media=/qtmedia
private=/run/qtbase-alpm
keyring=$private/alpm
official=68B3537F39A313B3E574D06777193F152BDBE6A6
md4c=md4c-0.5.3-1-aarch64.pkg.tar.xz

fail() { printf '%s\n' "$*" >&2; exit 1; }
bounded() { timeout --signal=TERM --kill-after=15s "$@"; }

[[ $# == 1 && $1 == /* && $EUID == 0 &&
   $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]] ||
    fail 'Guest root on AArch64 with 16 KiB pages required'
evidence=$1
[[ $evidence != / && -d $evidence && ! -L $evidence && $(realpath -e -- "$evidence") == "$evidence" &&
   $evidence != "$media" && $evidence != "$media/"* ]] || fail 'Ordinary private evidence directory required'
awk -v path="$media" '$5 == path { n++; if ($6 ~ /(^|,)ro(,|$)/) ro++ } END { exit !(n == 1 && ro == 1) }' /proc/self/mountinfo ||
    fail 'Read-only sealed media mount required'
[[ -d /sys/class/net && $(ls -A /sys/class/net) == lo ]] || fail 'Offline guest required'
[[ ! -e $private && ! -L $private ]] || fail 'Fresh guest ALPM scratch directory required'
existing=("$evidence"/alpm-*)
[[ ${#existing[@]} == 0 ]] || fail 'Fresh guest ALPM evidence required'

mapfile -t selectors < "$media/md4c-signer"
[[ ${#selectors[@]} == 1 && ${selectors[0]} =~ ^[A-F0-9]{40}$ &&
   ${selectors[0]} != "$official" ]] || fail 'Separate selected TEST fingerprint required'
test_signer=${selectors[0]}
[[ $(cat "$media/official/archlinuxarm-trusted") == "$official:4:" &&
   -f $media/official/archlinuxarm-revoked && ! -s $media/official/archlinuxarm-revoked ]] ||
    fail 'Pinned official signer policy differs'

mkdir -m 0700 -- "$private"
cleanup() {
    local result=$? retired=0 home
    trap - EXIT
    for home in "$private"/{official,test,alpm}; do
        if [[ -d $home ]]; then
            bounded 30s gpgconf --homedir "$home" --kill all >> "$evidence/alpm-cleanup.log" 2>&1 || retired=1
        fi
    done
    if (( retired == 0 )); then
        rm -rf --one-file-system -- "$private" || retired=1
    fi
    if (( retired == 0 )) && [[ ! -e $private && ! -L $private ]]; then
        printf 'PRIVATE_ALPM_KEYRINGS_RETIRED\n' >> "$evidence/alpm-cleanup.log"
    else
        printf 'PRIVATE_ALPM_KEYRING_RETIREMENT_HOLD\n' >> "$evidence/alpm-cleanup.log"
        if (( result == 0 )); then result=1; fi
    fi
    exit "$result"
}
trap cleanup EXIT

mkdir -m 0700 -- "$private"/{official,test,alpm,hooks}
printf '%s\n' '[options]' 'Architecture = aarch64'     'SigLevel = Required TrustedOnly' 'LocalFileSigLevel = Required TrustedOnly'     "GPGDir = $keyring" "HookDir = $private/hooks" > "$private/pacman.conf"
cat "$private/pacman.conf" > "$evidence/alpm-pacman.conf"

while IFS= read -r hook || [[ -n $hook ]]; do
    [[ $hook =~ ^[A-Za-z0-9_.@+-]+\.hook$ && ! -e $private/hooks/$hook && ! -L $private/hooks/$hook ]] ||
        fail 'Safe unique hook-mask names required'
    ln -s /dev/null "$private/hooks/$hook"
done < "$media/disabled-hooks.list"
[[ -L $private/hooks/20-systemd-sysusers.hook ]] || fail 'Complete hook-mask allowlist required'

gpg_public=(gpg --batch --no-tty --no-options --no-auto-key-retrieve --no-autostart)
bounded 60s "${gpg_public[@]}" --homedir "$private/official" --import \
    "$media/official/archlinuxarm.gpg" > "$evidence/alpm-keys.log" 2>&1
bounded 60s "${gpg_public[@]}" --homedir "$private/official" --output "$private/official/selected.gpg" \
    --export "$official" >> "$evidence/alpm-keys.log" 2>&1
[[ -s $private/official/selected.gpg ]] || fail 'Pinned ALARM public primary required'
cp -- "$media/md4c-TEST-public.gpg" "$private/test/selected.gpg"
bounded 60s "${gpg_public[@]}" --homedir "$private/test" --with-colons --fingerprint \
    --show-keys "$private/test/selected.gpg" > "$private/test/metadata" 2>> "$evidence/alpm-keys.log"
awk -F: -v fp="$test_signer" -v now="$(date +%s)" '
    $1 == "pub" { pubs++; if ($2 ~ /[er]/ || $6 !~ /^[0-9]+$/ || $7 !~ /^[0-9]+$/ ||
                             $6 > now || now >= $7 || $7 - $6 > 86400) bad=1 }
    $1 == "fpr" { fprs++; if ($10 != fp) bad=1 }
    $1 == "uid" { uids++; if ($10 !~ /TEST.*md4c/) bad=1 }
    $1 ~ /^(sec|ssb|sub)$/ { bad=1 }
    END { exit !(pubs == 1 && fprs == 1 && uids == 1 && !bad) }
' "$private/test/metadata" || fail 'One current public md4c TEST key required'

verify_archive() {
    local archive=$1 scope=$2 expected=$3 record="$private/gpgv.status" status="$evidence/alpm-gpgv-$4.log"
    [[ -f $archive && ! -L $archive && -s $archive.sig && -f $archive.sig && ! -L $archive.sig &&
       $(stat -c %s -- "$archive.sig") -le 8192 ]] || fail 'Ordinary archive and adjacent detached signature required'
    printf '%s\n' "${archive##*/}" >> "$status"
    if ! bounded 60s gpgv --homedir "$private/$scope" --keyring "$private/$scope/selected.gpg" \
        --status-fd 1 -- "$archive.sig" "$archive" > "$record" 2>> "$status"; then
        cat "$record" >> "$status"
        fail "Detached signature verification failed for ${archive##*/}"
    fi
    cat "$record" >> "$status"
    awk -v fp="$expected" '
        $1 == "[GNUPG:]" && $2 == "VALIDSIG" { valid++; if (NF != 12 || $3 != fp || $NF != fp) bad=1 }
        $1 == "[GNUPG:]" && $2 ~ /^(EXPSIG|EXPKEYSIG|KEYEXPIRED|SIGEXPIRED|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY)$/ { bad=1 }
        END { exit !(valid == 1 && !bad) }
    ' "$record" || fail "Unexpected signer for ${archive##*/}"
    printf '%s\t%s\t%s\n' "$4" "${archive##*/}" "$expected" >> "$evidence/alpm-signatures.tsv"
}

base=("$media/alpm-base/"*.pkg.tar.xz)
add=("$media/alpm-add/"*.pkg.tar.xz)
base_leaves=("$media/alpm-base/"*)
add_leaves=("$media/alpm-add/"*)
[[ ${#base[@]} == 256 && ${#base_leaves[@]} == 512 &&
   ${#add[@]} == 7 && ${#add_leaves[@]} == 14 && -f $media/alpm-add/$md4c ]] ||
    fail 'Exact 256 baseline and seven Qt archive/signature pairs required'
for archive in "${base[@]}"; do verify_archive "$archive" official "$official" base; done
for archive in "${add[@]}"; do
    if [[ ${archive##*/} == "$md4c" ]]; then
        verify_archive "$archive" test "$test_signer" add
    else
        verify_archive "$archive" official "$official" add
    fi
done

trust_public() {
    local role=$1 fp=$2
    bounded 60s "${gpg_public[@]}" --homedir "$keyring" --import \
        "$private/$role/selected.gpg" >> "$evidence/alpm-keys.log" 2>&1
    printf '%s:6:\n' "$fp" | bounded 60s "${gpg_public[@]}" --homedir "$keyring" \
        --import-ownertrust >> "$evidence/alpm-keys.log" 2>&1
}

pacman_cmd=(pacman --config "$private/pacman.conf" --logfile "$evidence/alpm-pacman.log")
readback() {
    local name=$1 expected=$2
    bounded 90s "${pacman_cmd[@]}" -Q | LC_ALL=C sort > "$evidence/alpm-$name.lock"
    cmp -s -- "$evidence/alpm-$name.lock" "$media/$expected" || fail "Installed inventory differs at $name"
}
transact() {
    local label=$1; shift
    bounded 1800s "${pacman_cmd[@]}" -U --noconfirm --noscriptlet "$@" \
        > "$evidence/alpm-$label.stdout" 2> "$evidence/alpm-$label.stderr"
    bounded 60s ldconfig >> "$evidence/alpm-$label.stdout" 2>> "$evidence/alpm-$label.stderr"
}

readback rootfs rootfs.expected.lock
trust_public official "$official"
transact base "${base[@]}"
readback 349 expected349.lock
trust_public test "$test_signer"
transact add "${add[@]}"
readback 356 expected356.lock
bounded 90s "${pacman_cmd[@]}" -Dk > "$evidence/alpm-db-check.log" 2>&1
bounded 90s "${pacman_cmd[@]}" -Qk md4c > "$evidence/alpm-md4c-check.log" 2>&1
printf 'ALPM_EXACT_349_TO_356_PASS\n' > "$evidence/alpm-result"
