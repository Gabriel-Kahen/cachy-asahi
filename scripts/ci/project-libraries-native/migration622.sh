#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run inside the owned, offline Minimal206 root with /migration mounted read-only.
set -euo pipefail
[[ ${CACHY_ASAHI_MIGRATION:-0} == 1 && $(id -u) == 0 && $(uname -m) == aarch64 ]]
[[ -f /.dockerenv || -f /run/.containerenv ]]
umask 022
export LC_ALL=C
test "$(grep -Fxc 'SigLevel = Required' /etc/pacman.conf)" = 1
test "$(grep -Fxc 'LocalFileSigLevel = Required' /etc/pacman.conf)" = 1
test "$(grep -Fxc 'HookDir = /builder-disabled-hooks' /etc/pacman.conf)" = 1
cd /migration
sha256sum --check --strict --quiet SHA256SUMS
read -r profile < profile
[[ $profile == native-tiff || $profile == emulated-tiff ]]
scratch=$(mktemp -d /tmp/project-libraries-migration.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT

inventory() {
    pacman -Q | sort > "$scratch/inventory"
    diff -u "$1" "$scratch/inventory"
    pacman -Dk
    sha256sum "$scratch/inventory"
}

owns() {
    test "$(pacman -Qoq "$1")" = "$2"
}

absent() {
    [[ ! -e $1 && ! -L $1 ]]
}

prove_provider() {
    local role=$1 jbig=$2 tiff=$3 soname=$4 stale=$5
    inventory "$role.lock"
    pacman -Qk "$jbig" "$tiff" lcms2
    owns "/usr/lib/libjbig.so.$soname" "$jbig"
    owns "/usr/lib/libjbig85.so.$soname" "$jbig"
    owns /usr/lib/libtiff.so.6 "$tiff"
    owns /usr/lib/libtiffxx.so.6 "$tiff"
    owns /usr/bin/tificc lcms2
    printf '%s\n' '3a37c49bdb26c46f87543d3feff4328823485a19e0f57f3958296ae4bff37a58  /usr/bin/tificc' | sha256sum -c
    absent "/usr/lib/libjbig.so.$stale"
    absent "/usr/lib/libjbig85.so.$stale"
    sha256sum "/usr/lib/libjbig.so.$soname" "/usr/lib/libjbig85.so.$soname" \
        /usr/lib/libtiff.so.6 /usr/lib/libtiffxx.so.6 /usr/bin/tificc > "$scratch/provider-files"
    if [[ -e $scratch/$role.files ]]; then
        cmp "$scratch/$role.files" "$scratch/provider-files"
    else
        mv "$scratch/provider-files" "$scratch/$role.files"
    fi
    if [[ $role == project ]]; then
        sha256sum --check <<'SUMS'
6889273144dd76d0e00516a971bac18363e98746dde99a079ae26c2a44d95d6c  /usr/lib/libjbig.so.2.2
448c9393e65bd855749d3007d707c9ebf760413e7543cb3aa97378b86bff7479  /usr/lib/libjbig85.so.2.2
1c11df5fcd30e0b8ad285083bff41f7d017670e8f6f94750b70147884141ace4  /usr/lib/libtiff.so.6
6f38e390028607be4d3482ae49ba772ba5eceb78554529ce947e79414838bb73  /usr/lib/libtiffxx.so.6
SUMS
    fi
    ldd /usr/bin/tificc > "$scratch/loader"
    grep -Eq '^[[:space:]]+libtiff[.]so[.]6 => /(usr/)?lib/libtiff[.]so[.]6[[:space:]]' "$scratch/loader"
    grep -Eq "^[[:space:]]+libjbig[.]so[.]${soname/./[.]} => /(usr/)?lib/libjbig[.]so[.]${soname/./[.]}[[:space:]]" "$scratch/loader"
    ! grep -Fq 'not found' "$scratch/loader" || return 1
    gcc -Wall -Wextra -Werror /migration/roundtrip.c -ltiff -o "$scratch/roundtrip"
    "$scratch/roundtrip" "$scratch/roundtrip.tif"
    tiffinfo "$scratch/roundtrip.tif" > "$scratch/roundtrip-info"
    grep -Eq '^  Image Width: 32 Image Length: 4$' "$scratch/roundtrip-info"
    grep -Fq 'Compression Scheme: ISO JBIG' "$scratch/roundtrip-info"

    # Run the unchanged reverse consumer on a separate RGB image.
    printf 'P6\n2 2\n255\n\377\000\000\000\377\000\000\000\377\100\200\377' > "$scratch/rgb.ppm"
    ppm2tiff "$scratch/rgb.ppm" "$scratch/rgb.tif"
    tificc "$scratch/rgb.tif" "$scratch/converted.tif"
    tiffinfo "$scratch/converted.tif" > "$scratch/converted-info"
    grep -Eq '^  Image Width: 2 Image Length: 2$' "$scratch/converted-info"
    rm -- "$scratch/roundtrip.tif" "$scratch/rgb.tif" "$scratch/converted.tif"
    printf '%s\n' "$role provider and unchanged tificc passed"
}

inventory base.lock
read -r signer < test-fingerprint
[[ $signer =~ ^[A-F0-9]{40}$ ]]
pacman-key --add TEST-public.gpg
pacman-key --lsign-key "$signer"
historical=(jbigkit-2.1-8-aarch64.pkg.tar.xz libtiff-4.7.2-1-aarch64.pkg.tar.xz)
project=(cachy-asahi-jbigkit-2.2-1.1-aarch64.pkg.tar.xz cachy-asahi-libtiff-4.7.2-1.1-aarch64.pkg.tar.xz)
common=(lcms2-2.19.1-1-aarch64.pkg.tar.xz libdeflate-1.26-1-aarch64.pkg.tar.xz
        libjpeg-turbo-3.2.1-1-aarch64.pkg.tar.xz libwebp-1.6.0-2-aarch64.pkg.tar.xz)
pacman -U --noconfirm --noscriptlet "${common[@]}" "${historical[@]}"
ldconfig
prove_provider historical jbigkit libtiff 2.1 2.2

# ALPM_QUESTION_CONFLICT_PKG (1 << 2) allows the conflicting pair to be
# removed in the same transaction. The exact whole-inventory checks bind both ends.
pacman -U --noconfirm --noscriptlet --ask 4 "${project[@]}"
ldconfig
prove_provider project cachy-asahi-jbigkit cachy-asahi-libtiff 2.2 2.1

pacman -U --noconfirm --noscriptlet --ask 4 "${historical[@]}"
ldconfig
prove_provider historical jbigkit libtiff 2.1 2.2
absent /usr/share/doc/cachy-asahi-jbigkit/source/PKGBUILD
absent /usr/share/cachy-asahi-libtiff/corresponding-source/inventory.json
gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent
printf 'MIGRATION622_PASSED %s\n' "$profile"
