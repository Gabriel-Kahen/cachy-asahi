#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 022
export LC_ALL=C.UTF-8 TZ=UTC
test "$(uname -m)" = aarch64
test "$(getconf PAGESIZE)" = 4096
test "$(id -u)" = 0

inventory() { pacman -Q | LC_ALL=C sort; }
if [[ ${1:?expected provision or build} == provision ]]; then
    mkdir /work
    cat > /work/bootstrap-pacman.conf <<'EOF'
[options]
Architecture = aarch64
SigLevel = Required
LocalFileSigLevel = Required
EOF
    (cd /seed && sha256sum --check supplement.sha256)
    pacman-key --init
    pacman-key --populate archlinuxarm
    pacman --config /work/bootstrap-pacman.conf -U --noconfirm \
        /seed/fish-4.9.3-1-aarch64.pkg.tar.xz /seed/zsh-5.9.2-1-aarch64.pkg.tar.xz
    test "$(pacman -Q fish zsh)" = $'fish 4.9.3-1\nzsh 5.9.2-1'
    pacman -T 'python>=3.11' fish zsh gnupg patch fakeroot debugedit xz
    if pacman -Q cachy-asahi-setup || pacman -Q cachy-asahi-first-login; then
        echo 'Candidate package already present in the clean build image' >&2
        exit 1
    fi
    useradd --uid 2000 --create-home lane-builder
    inventory > /work/base-packages.txt
    exit
fi

test "$1" = build
test ! -e /work/result
inventory | cmp /work/base-packages.txt -
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH="$(cat /input/source-date-epoch)"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]{10}$ ]]
cat /etc/makepkg.conf > /work/makepkg.conf
cat >> /work/makepkg.conf <<'EOF'
MAKEFLAGS="-j1"
COMPRESSXZ=(xz -c -z -T1 -)
BUILDENV=(!distcc !color !ccache check !sign)
PACKAGER="Cachy-Asahi unsigned native build pair"
EOF
chmod 0644 /work/makepkg.conf
install -d -o lane-builder /work/result /work/build /work/result/packages
cp -- /work/base-packages.txt /work/result/before-setup.txt
cp -r -- /input/packages/tools/cachy-asahi-setup8-v3 /work/setup
cp -r -- /input/packages/tools/cachy-asahi-first-login-v4 /work/first-login
chown -R lane-builder /work/setup /work/first-login
readonly setup_archive=/work/result/packages/cachy-asahi-setup-0.3.1-2-any.pkg.tar.xz
readonly first_archive=/work/result/packages/cachy-asahi-first-login-0.1.0-4-any.pkg.tar.xz

builder_makepkg() {
    local recipe=$1
    shift
    (
        cd -- "/work/$recipe"
        runuser -u lane-builder -- env SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
            BUILDDIR=/work/build PKGDEST=/work/result/packages PKGEXT=.pkg.tar.xz \
            makepkg --config /work/makepkg.conf --nocolor "$@"
    )
}

build_recipe() {
    local recipe=$1
    builder_makepkg "$recipe" --printsrcinfo | cmp "/work/$recipe/.SRCINFO" -
    builder_makepkg "$recipe" --verifysource --noconfirm 2>&1 | tee "/work/result/$recipe-source.log"
    builder_makepkg "$recipe" --cleanbuild --check --nosign --noconfirm 2>&1 | tee "/work/result/$recipe-build.log"
}

build_recipe setup
test -f "$setup_archive"
bsdtar -xOf "$setup_archive" usr/bin/cachy-asahi-setup | cmp /input/packages/tools/cachy-asahi-first-login-v4/setup8-fixture.py -
sha256sum "$setup_archive" > /work/result/installed-build-dependency.sha256

# This separate configuration applies to one unsigned local build dependency.
# Additional repository packages are absent from this pacman transaction.
cat > /work/local-pacman.conf <<'EOF'
[options]
Architecture = aarch64
SigLevel = Required
LocalFileSigLevel = Never
EOF
test "$(pacman --config /work/local-pacman.conf -Qp "$setup_archive")" = 'cachy-asahi-setup 0.3.1-2'
pacman --config /work/local-pacman.conf -U --noconfirm --asdeps "$setup_archive" 2>&1 |
    tee /work/result/install-build-dependency.log
test "$(pacman -Q cachy-asahi-setup)" = 'cachy-asahi-setup 0.3.1-2'
pacman -T 'cachy-asahi-setup>=0.3.1-2'
cmp /usr/bin/cachy-asahi-setup /input/packages/tools/cachy-asahi-first-login-v4/setup8-fixture.py
inventory > /work/result/before-first-login.txt
{ cat /work/base-packages.txt; echo 'cachy-asahi-setup 0.3.1-2'; } | LC_ALL=C sort |
    cmp /work/result/before-first-login.txt -

build_recipe first-login
test -f "$first_archive"
inventory | cmp /work/result/before-first-login.txt -
printf 'architecture=aarch64\npage_size=4096\nbuilder_uid=2000\nsource_date_epoch=%s\n' \
    "$SOURCE_DATE_EPOCH" > /work/result/runtime.txt
