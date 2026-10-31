# SPDX-License-Identifier: MIT
# Byte-exact project helpers, a private import tree, and an isolated CLI.
pkgname=cachy-asahi-maintenance
pkgver=0.1.0
pkgrel=2
pkgdesc='Offline signed-release health and held rebuild-planning review'
arch=('any')
url='https://github.com/Gabriel-Kahen/cachy-asahi'
license=('MIT')
depends=('python>=3.11' 'gnupg' 'libarchive' 'pacman')
source=('cachy-asahi-maintenance' 'check_source_pins.py' 'compare_releases.py' 'health.py' 'rebuild_plan.py' 'release.py' 'security_advisories.py' 'signing_expiry.py' 'source_delivery.py' 'update_plan.py' 'payload-pins.json' 'test_package.py' 'check_source.py' 'README.md' 'health-inputs.md' 'source-provenance.json' 'NOTICE' 'LICENSE')
sha256sums=(
    '4c0fe954900fb4bbda0b816d59a831a563f9497aa057e4e4f6a5d8c7d30c83be'
    '9b78c348e2d567f44f656285f6a562220cadead7025f1e0db2eb9a53d9f09ea3'
    '27086c7b0af74a1226deae7a6a71245882b82608a1fa9d33b68e657979c7d83c'
    '6809526f7553e76f4a6c8d24cbde2688abe8cfd1139b92b88a51847e7a7acadf'
    '472f9bb621d78f79f5016a662b7f72eb03e995dae787c7846bc1f947ff21313c'
    'e4ab44f7cc020ae1d705b64362e8b1b05fa0c29c19ce64d886116055619c0435'
    'f018ff4ac0265217213f749bf59afa08b61b24e4054973c0dcde110e57a0a2cb'
    'dd6ef397ea47cf14bb31f6ae6f7ca388d68bdb15e7fa3d20c36eb01f901b2c98'
    '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'
    '21af73923ca4bfff244d653e1f0046015d429a582548b2a60f1e0feb5b2a687e'
    '235ddbb11910b29bb5ea57e111094c0ddccd89a7da966f93843510ab3b8fe3e4'
    '68f4a91a32eb5073524c019c8721a4775b3af1a71b2b6c602cc26849a079583f'
    '8e0df4bcb8759f819eac03792c43d8c17c52d33e46f48bf9b194d44cd5f71c27'
    '0b476d0188373df5fc02fb27523c36347cf9a6fe01076ff45238433203443eeb'
    'fa9ad03e43b75fc8bdeba2ee06dc09c06973a85bbcca17f708c92d4f78f0557f'
    'b3ac2eab0236f8817501b38d47c5f1f5e883ee37cb533c2a9be46e2164c21058'
    'b6dffb613c2a3b709756cbdce9b0f40c2fe69a4133c1b050f69ccb618f2ee17a'
    '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'
)

check() {
    python -I -B "$srcdir/check_source.py" --recipe-root "$startdir" || return
    python -I -B -Werror::ResourceWarning "$srcdir/test_package.py" --recipe-root "$startdir"
}

package() {
    [[ -n $pkgdir && $pkgdir != / ]] || return 1
    local base="$pkgdir/usr/lib/cachy-asahi/maintenance"
    local file
    install -Dm755 "$srcdir/cachy-asahi-maintenance" "$pkgdir/usr/bin/cachy-asahi-maintenance" || return
    for file in health update_plan rebuild_plan signing_expiry security_advisories; do
        install -Dm644 "$srcdir/$file.py" "$base/scripts/maintenance/$file.py" || return
    done
    for file in check_source_pins compare_releases release source_delivery; do
        install -Dm644 "$srcdir/$file.py" "$base/scripts/release/$file.py" || return
    done
    for file in README.md health-inputs.md source-provenance.json payload-pins.json; do
        install -Dm644 "$srcdir/$file" "$pkgdir/usr/share/doc/$pkgname/$file" || return
    done
    for file in NOTICE LICENSE; do
        install -Dm644 "$srcdir/$file" "$pkgdir/usr/share/licenses/$pkgname/$file" || return
    done
}
