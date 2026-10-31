# SPDX-License-Identifier: MIT
# Original opt-in diagnostic; development candidate, not release-selected.
pkgname=cachy-asahi-session-diagnostics
pkgver=0.1.0
pkgrel=3
pkgdesc='Read-only current-session observations for cachy-asahi'
arch=('any')
url='https://github.com/Gabriel-Kahen/cachy-asahi'
license=('MIT')
depends=('python>=3.11')
optdepends=('hyprland: current compositor version and display observations'
            'mesa-utils: current Wayland GLES client renderer observation'
            'pipewire: current sanitized audio graph observation'
            'systemd: current session, unit states and suspend capability queries')
options=('!strip' '!debug')
source=('cachy-asahi-session-diagnostics' 'session_probe.py' 'test_session_probe.py' 'check_package.py' 'test_package.py' 'README.md' 'session-probe.md' 'source-provenance.json' 'NOTICE' 'LICENSE')
sha256sums=(
    '2b6700180210cc686f3e19f3c294f58ce5182dee2ae01e5406039bb1a0d3af7a'
    '9c5c41899cd991b0de4bf8d30bad6f5452b4592ea9440df0f0b4a7b54bc66984'
    'f598bf4ea38f753c1ffe31fb55e636d64722c32139230bd5485564d7f2332d2f'
    'ddf4119a1ecad917af69f3e670e469281e48662b08e20d2abdf17efc807df86d'
    '7134c5da0d1c96b2bb02fcdf7dc161821b31badf533a26b192e3b0e1f5b98879'
    '4a88ceecb9b844c7b1fbc261dd6e0788640b6c4320eb62db4f394d566dc71dd4'
    '2d8125214150de5b6426692758525b0636fcbb53c45539a139d7fc5bf4f804e1'
    '51cc74ecc32e47e740f39dcf86b30e0819ed6be4707ea40c398976dc2b637a76'
    'dad09067890027d4674c6f5861462966f190e527e7d4524360fbc175c68e0511'
    '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'
)

check() {
    python -I -B "$srcdir/check_package.py" --recipe-root "$startdir" || return
    python -I -B -Werror::ResourceWarning "$srcdir/test_session_probe.py" || return
    python -I -B -Werror::ResourceWarning "$srcdir/test_package.py"
}

package() {
    [[ -n ${pkgdir:-} && $pkgdir != / ]] || return 1
    install -Dm755 "$srcdir/cachy-asahi-session-diagnostics" "$pkgdir/usr/bin/cachy-asahi-session-diagnostics" || return
    install -Dm644 "$srcdir/session_probe.py" "$pkgdir/usr/lib/$pkgname/session_probe.py" || return
    local file
    for file in README.md session-probe.md source-provenance.json; do
        install -Dm644 "$srcdir/$file" "$pkgdir/usr/share/doc/$pkgname/$file" || return
    done
    for file in NOTICE LICENSE; do
        install -Dm644 "$srcdir/$file" "$pkgdir/usr/share/licenses/$pkgname/$file" || return
    done
}
