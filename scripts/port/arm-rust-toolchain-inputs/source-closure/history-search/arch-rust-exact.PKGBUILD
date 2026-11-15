# Maintainer: Johannes Löthberg <johannes@kyriasis.com>
# Maintainer: Jan Alexander Steffens (heftig) <heftig@archlinux.org>
# Contributor: Alexander F Rødseth <xyproto@archlinux.org>
# Contributor: Daniel Micay <danielmicay@gmail.com>
# Contributor: userwithuid <userwithuid@gmail.com>

pkgbase=rust
pkgname=(
  rust
  rust-musl
  rust-src
  rust-wasm

  # x86_64 only
  lib32-rust-libs

  # cross targets
  rust-aarch64-gnu
  rust-aarch64-musl
)
pkgver=1.99.0
pkgrel=1
epoch=1
pkgdesc="Systems programming language focused on safety, speed and concurrency"
url=https://www.rust-lang.org/
arch=(
  aarch64
  loong64
  riscv64
  x86_64
)
license=("Apache-2.0 OR MIT")
_llvmver=23.1.1
depends=(
  "compiler-rt=$_llvmver"
  "lld=$_llvmver"
  "llvm-libs=$_llvmver"
  bash
  curl
  gcc
  glibc
  libgcc
  libgit2
  libssh2
  libstdc++
  openssl
  sqlite
  zlib
)
makedepends=(
  "clang=$_llvmver"
  "llvm=$_llvmver"
  cmake
  libffi
  musl
  ninja
  perl
  python
  rust
  wasi-libc
  wasm-component-ld
)
makedepends_loong64=(
  aarch64-linux-gnu-gcc
  aarch64-linux-gnu-glibc
  musl-aarch64
  musl-x86_64
)
makedepends_riscv64=(
  aarch64-linux-gnu-gcc
  aarch64-linux-gnu-glibc
  musl-aarch64
  musl-x86_64
)
makedepends_x86_64=(
  aarch64-linux-gnu-gcc
  aarch64-linux-gnu-glibc
  lib32-gcc-libs
  lib32-glibc
  musl-aarch64
)
checkdepends=(
  gdb
  procps-ng
)
options=(
  !emptydirs
  !lto
)
source=(
  "https://static.rust-lang.org/dist/rustc-$pkgver-src.tar.xz"{,.asc}
  "https://github.com/llvm/llvm-project/releases/download/llvmorg-$_llvmver/llvm-project-$_llvmver.src.tar.xz"

  # Patch bootstrap so that rust-analyzer-proc-macro-srv
  # is in /usr/lib instead of /usr/libexec
  0001-bootstrap-Change-libexec-dir.patch

  # Put bash completions where they belong
  0002-bootstrap-Change-bash-completion-dir.patch

  # Fix build with system rustc
  # https://github.com/rust-lang/rust/issues/143735
  0003-bootstrap-Workaround-for-system-stage0.patch

  # Use our *-pc-linux-gnu targets, making LTO with clang simpler
  0004-compiler-Change-LLVM-targets.patch

  # Use our ld.lld
  0005-compiler-Use-ld.lld-by-default.patch

  # Use our target-specific GCCs, like aarch64-linux-gnu-gcc
  0006-compiler-Use-target-specific-GCC-linkers.patch

  # Make the riscv64 musl target behave like the x86_64 musl target
  0007-compiler-Link-riscv64-musl-statically.patch

  # Prefer "lib" over "lib64"
  0008-compiler-Swap-primary-and-secondary-lib-dirs.patch
)
source_aarch64=(bootstrap.aarch64.toml)
source_loong64=(bootstrap.loong64.toml)
source_riscv64=(bootstrap.riscv64.toml)
source_x86_64=(bootstrap.x86_64.toml)
b2sums=('f4e2d97047c42067d11c31484d320f9daaaf881c78d22473b7f9ac2289a8f5979de6e75c277c49a0e3e33cd80f18aecace39f25ae78645976945798f3e512f16'
        'SKIP'
        '31d0ad202f4ad38d001baaf638a756508b164229b02a6e41b9689508a33b3a7baecaa10398e20f3661cacb712663fe379eeb94e50e017e40ae546a7e7de8049d'
        '3736aa3f6f891cb94dbe549d5b2c74bc56e9d484a1598c2a446fbfd4db10a90a34f2e371c65743cf01e1266470fd6fe2fc52cbc365564c62ba61e20ea11c8e22'
        'eb57683802be1114452d0864bdabd1f2a42f83c0c45532ff968c693cb98dd5cf61342880bd75e731e91fde318b0f61cc30183374348a56db883ba32c900a4949'
        'd39a31a9260ba1e60e34f2481a4ef19ce18178736539450e57df19b9a3364a35f23b9055eecb36175de0e01a154b04f86c2645cffc7d637aab8b38dbf2eb0832'
        '8a5238d5807673d498ca330b8d1d7c3c14d12be1bd0dec361613b09fd04527060a7f661acd9205f6a03586e2ea4a650c890d2549eed2e207fc03cce3bdb1cf03'
        'd36a29127349f02fdd3327a36ebfe57b1ce7f64bb24de2bb85369b377e362ee389662b5a5f281bc2a82b7fca2eee234ca6de5a923f5030e3570ab1203653fdb2'
        '859806770bed41dca2c48e7ac01f0fe31b9c4811e76eab173a9cac254a8cdfda0c85ae4a01dd7238fa0018d06721bf3bda5d74348e5c296a19ec534c1b8763c9'
        '9e51e3442da85211165afce6c6eef3a89e5ce8d2b026d373a19c533b3ad99efdb7cc60668580536c2e52e8dc58c1a96cd8d2733ffa6f1b438db5df8d495042b6'
        'd5fcda00c46e1e1ea9ed1d269d3ef549d4ad96148d7d0744acd673de802b3bf3747ceec1fa506d3e7c128cdff742410b1e69218d59ef20a5f246755c1bd02694')
b2sums_aarch64=('f5af2c5dfaf46968544f96e729a30f66fd37284ca11ed81b198b146040078c564326917a563e0a5478ab9d43dec5c2b952e8b8497e23b0194fa08b47565b6160')
b2sums_loong64=('a96f553d5939457b7bcead77b849ebab3228107eb98b79a3714603442c71b6ec3e021e40ce0ffe80e95ffa30c10c336cdf07345d06178d56febc5affcaead0d4')
b2sums_riscv64=('c3770ab4ace070790829e54a436e43edec2cacf489d17912c82049d509d168fee1bd6bece758b805692edad10381233525035c8738a4253cb5f1a969e2d191a2')
b2sums_x86_64=('b696e650765ada0a54a83fca558b24cc2b9c9aeef18c1a9f2888ad9771051543de377b59b519c1545d3b353edd065024bebce282b622b1bfe4b1d679ba3398c1')
validpgpkeys=(
  108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE  # Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>
)

# Make sure the duplication in rust-wasm is found
COMPRESSZST+=(--long)

prepare() {
  cd rustc-$pkgver-src

  local src
  for src in "${source[@]}"; do
    src="${src%%::*}"
    src="${src##*/}"
    src="${src%.zst}"
    [[ $src = *.patch ]] || continue
    echo "Applying patch $src..."
    patch -Np1 < "../$src"
  done

  rm -rf src/llvm-project
  ln -sr "$srcdir/llvm-project-$_llvmver.src" src/llvm-project

  local clangdir
  clangdir="$(clang -print-resource-dir)"
  sed -e "s|%description%|Arch Linux $pkgbase $epoch:$pkgver-$pkgrel|g" \
      -e "s|%clangdir%|$clangdir|g" \
      "$srcdir/bootstrap.${CARCH}.toml" > bootstrap.toml
}

_pick() {
  local p="$1" f d; shift
  for f; do
    d="$srcdir/$p/${f#$pkgdir/}"
    mkdir -p "$(dirname "$d")"
    mv "$f" "$d"
    rmdir -p --ignore-fail-on-non-empty "$(dirname "$f")"
  done
}

build() {
  cd rustc-$pkgver-src

  export LIBGIT2_NO_VENDOR=1
  export LIBSSH2_SYS_USE_PKG_CONFIG=1
  export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
  export RUST_BACKTRACE=1
  unset CFLAGS CXXFLAGS LDFLAGS

  local xpy_options=(
    -j "$(nproc)"
  )

  local host_tuple do_pgo=0
  case $CARCH in
    aarch64|x86_64) host_tuple=$CARCH-unknown-linux-gnu; do_pgo=1 ;;
    loong64) host_tuple=loongarch64-unknown-linux-gnu ;;
    riscv64) host_tuple=riscv64gc-unknown-linux-gnu ;;
    *) host_tuple=$CARCH-unknown-linux-gnu ;;
  esac

  if (( do_pgo )); then
    local profraw="$PWD/build/profiles"
    mkdir -p "$profraw"

    cp bootstrap.toml bootstrap.toml.nopgo
    cat >bootstrap.toml bootstrap.toml.nopgo - <<END
[pgo]
rustc.generate = "$profraw"
END

    echo "Building instrumented compiler..."
    python ./x.py build sysroot "${xpy_options[@]}"

    # Building cargo is our workload for profiling
    echo "Profiling instrumented compiler..."
    local stage2="$PWD/build/$host_tuple/stage2"
    LLVM_PROFILE_FILE="$profraw/default_%m_%p.profraw" \
      LD_LIBRARY_PATH="$stage2/lib" RUSTC="$stage2/bin/rustc" \
      cargo build --manifest-path=src/tools/cargo/Cargo.toml

    # Merge the profile data
    local profdata="$PWD/build/rustc.profdata"
    llvm-profdata merge -o "$profdata" "$profraw"

    stat -c "Profile data found (%s bytes)" "$profdata"
    test -s "$profdata"

    # Clean up profraw and instrumented stage2 artifacts
    echo "Removing instrumented compiler..."
    rm -r "$profraw" "$stage2"*/

    cat >bootstrap.toml bootstrap.toml.nopgo - <<END
[pgo]
rustc.use = "$profdata"
END
    rm bootstrap.toml.nopgo
  fi

  echo "Building optimized compiler..."
  DESTDIR="$srcdir/dest-rust" python ./x.py install "${xpy_options[@]}"

  cd ../dest-rust

  # delete unnecessary files, e.g. files only used for the uninstall script
  rm -v etc/target-spec-json-schema.json
  rm -v usr/lib/rustlib/{components,install.log,rust-installer-version,uninstall.sh}
  rm -v usr/lib/rustlib/manifest-*

  # licenses for main rust package
  local ldir="usr/share/licenses/rust" f d
  mkdir -p "$ldir"
  for f in usr/share/doc/*/{COPYRIGHT,LICENSE}*; do
    d="$(dirname "$f")"
    case $f in
      */LICENSE-APACHE) rm -v "$f" ;;
      *) mv -v "$f" "$ldir/${f##*/}.${d##*/}" ;;
    esac
    rmdir -p --ignore-fail-on-non-empty "$d"
  done

  # rustbuild always installs copies of the shared libraries to /usr/lib,
  # overwrite them with symlinks to the per-architecture versions
  ln -srvft usr/lib usr/lib/rustlib/$host_tuple/lib/*.so

  # Symlink the "self-contained" linker to our system lld
  mkdir -pv usr/lib/rustlib/$host_tuple/bin/gcc-ld
  ln -srvf  usr/bin/lld          usr/lib/rustlib/$host_tuple/bin/rust-lld
  ln -srvf  usr/bin/llvm-objcopy usr/lib/rustlib/$host_tuple/bin/rust-objcopy
  ln -srvft usr/lib/rustlib/$host_tuple/bin/gcc-ld usr/bin/{ld.lld,ld64.lld,lld-link,wasm-ld}

  _pick dest-musl usr/lib/rustlib/${host_tuple/gnu/musl}
  _pick dest-wasm usr/lib/rustlib/wasm32{,v1}-*
  _pick dest-src  usr/lib/rustlib/src

  case $CARCH in
    x86_64)
      _pick dest-i686 usr/lib/rustlib/i686-unknown-linux-gnu
      _pick dest-aarch64-gnu usr/lib/rustlib/aarch64-unknown-linux-gnu
      _pick dest-aarch64-musl usr/lib/rustlib/aarch64-unknown-linux-musl
      ;;
    loong64|riscv64)
      _pick dest-aarch64-gnu usr/lib/rustlib/aarch64-unknown-linux-gnu
      _pick dest-aarch64-musl usr/lib/rustlib/aarch64-unknown-linux-musl
      ;;
  esac
}

_install_licenses() {
  install -Dt "$pkgdir/usr/share/licenses/$pkgname" -m644 \
    rustc-$pkgver-src/{COPYRIGHT,LICENSE-MIT}
}

package_rust() {
  depends+=(
    libcurl.so
    libgcc_s.so
    libgit2.so
    libsqlite3.so
    libssh2.so
    libssl.so
  )
  optdepends=(
    'gdb: rust-gdb script'
    'lldb: rust-lldb script'
  )
  provides=(
    cargo
    rustfmt
  )
  conflicts=(
    cargo
    'rust-docs<1:1.56.1-3'
    rustfmt
  )
  replaces=(
    cargo
    cargo-tree
    'rust-docs<1:1.56.1-3'
    rustfmt
  )

  cp -a dest-rust/* "$pkgdir"
}

package_rust-musl() {
  pkgdesc="Musl target for Rust"
  depends=(rust)

  cp -a dest-musl/* "$pkgdir"
  _install_licenses
}

package_rust-src() {
  pkgdesc="Source code for the Rust standard library"
  depends=(rust)

  cp -a dest-src/* "$pkgdir"
  _install_licenses
}

package_rust-wasm() {
  pkgdesc="WebAssembly targets for Rust"
  depends=(
    rust
    wasm-component-ld
  )

  cp -a dest-wasm/* "$pkgdir"
  _install_licenses
}

package_lib32-rust-libs() {
  pkgdesc="32-bit target and libraries for Rust"
  arch=(x86_64)
  depends=(
    lib32-gcc-libs
    lib32-glibc
    rust
  )
  provides=(lib32-rust)
  conflicts=(lib32-rust)
  replaces=(lib32-rust)

  cp -a dest-i686/* "$pkgdir"
  _install_licenses

  cd "$pkgdir"
  mkdir -pv usr/lib32
  ln -srvft usr/lib32 usr/lib/rustlib/i686-unknown-linux-gnu/lib/*.so
}

package_rust-aarch64-gnu() {
  pkgdesc="AArch64 GNU target for Rust"
  arch=(
    loong64
    riscv64
    x86_64
  )
  depends=(
    aarch64-linux-gnu-gcc
    aarch64-linux-gnu-glibc
    rust
  )

  cp -a dest-aarch64-gnu/* "$pkgdir"
  _install_licenses
}

package_rust-aarch64-musl() {
  pkgdesc="AArch64 Musl target for Rust"
  arch=(
    loong64
    riscv64
    x86_64
  )
  depends=(
    aarch64-linux-gnu-gcc
    rust
  )

  cp -a dest-aarch64-musl/* "$pkgdir"
  _install_licenses
}

# vim:set ts=2 sw=2 et:
