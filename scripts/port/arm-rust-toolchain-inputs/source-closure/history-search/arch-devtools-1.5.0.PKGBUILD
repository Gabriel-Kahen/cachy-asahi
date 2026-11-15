# Maintainer: Levente Polyak <anthraxx[at]archlinux[dot]org>
# Maintainer: Christian Heusel <gromit@archlinux.org>
# Contributor: Pierre Schmitz <pierre@archlinux.de>

pkgname=devtools
epoch=1
pkgver=1.5.0
pkgrel=1
pkgdesc='Tools for Arch Linux package maintainers'
arch=('any')
license=('GPL-3.0-or-later')
url='https://gitlab.archlinux.org/archlinux/devtools'
depends=(
  arch-install-scripts
  awk
  bash
  binutils
  coreutils
  curl
  diffutils
  expac
  fakeroot
  findutils
  glow
  grep
  gum
  jq
  openssh
  parallel
  reuse
  rsync
  sed
  util-linux
  sudo
  breezy
  git
  mercurial
  subversion
)
makedepends=(
  asciidoctor
)
checkdepends=(
  bats
)
optdepends=(
  'btrfs-progs: btrfs support'
  'bat: pretty printing for pkgctl search'
  'nvchecker: pkgctl version subcommand'
)
source=(https://gitlab.archlinux.org/archlinux/devtools/-/releases/v${pkgver}/downloads/devtools-${pkgver}.tar.gz{,.sig})
validpgpkeys=(
  'E240B57E2C4630BA768E2F26FC1B547C8D8172C8' # Levente Polyak <anthraxx@archlinux.org>
  'F00B96D15228013FFC9C9D0393B11DAA4C197E3D' # Christian Heusel (gromit packager key) <gromit@archlinux.org>
)
sha256sums=('e196cc3cb055f07da9542cd2a9db543178a57eeb3a1df0be4c81952c122b5f37'
            'SKIP')
b2sums=('cc9e05b6bf2cf40d1e76dcd3f0ac04fbccf926c00fa972451c3555f36897aff3677848a7ed1acec69962730896690ccfbef6750b1274d561d60c7d16714a5437'
        'SKIP')

build() {
  cd ${pkgname}-${pkgver}
  make BUILDTOOLVER="${epoch}:${pkgver}-${pkgrel}-${arch}" PREFIX=/usr
}

check() {
  cd ${pkgname}-${pkgver}
  make PREFIX=/usr test
}

package() {
  cd ${pkgname}-${pkgver}
  make PREFIX=/usr DESTDIR="${pkgdir}" install
}

# vim: ts=2 sw=2 et:
