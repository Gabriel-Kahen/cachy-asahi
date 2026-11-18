# First Login 0.1.0-2 hosted native pair

The unchanged recipe builds the same version and six installed files exercised
in the signed disposable ARM16K install/remove rehearsal. Its Python tests run
as the normal `makepkg check()`. The earlier x86_64 assembly used `--nodeps`.
The hosted pair must use normal dependency resolution against the preinstalled
builder package set. The retained rehearsal archive was host-assembled as Zstd.
The hosted AArch64 Fish r12 builder already sets `PKGEXT='.pkg.tar.xz'` in its
captured makepkg configuration. Neither recipe needs an edit.

The proposed builder reuses the proven Fish r12 offline ARM64 environment and
adds one package. The matching `cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz` is the
33,900-byte archive independently qualified from native run 40490674681 and
used as the signed R2 overlay dependency. The r12 341-package builder already
includes Python, GnuPG, pacman, Fish, and Zsh. The fresh expected 342-package
lock contains the same packages plus Setup8, SHA-256
`50adb6e881a2b717de486ce487e0f1bfcdecce36e028313566a2a1d10c6b34b3`.

## Prepare exact operands without building

Supply the current recipe directory, the exact unpacked public Fish r12 tree,
the retained Overlay583 `offline-overlay-kit` directory, and a fresh absolute
output path. The `FISH` and `OVERLAY` variables below are these two existing
paths.

```sh
python3 -I -B scripts/ci/first-login-v2-native-pair/pair.py prepare \
  --recipe "$PWD/packages/tools/cachy-asahi-first-login" \
  --original-lock "$FISH/scripts/ci/fish-config02-native-source/successor_v2/expected341.lock" \
  --fish-tools "$FISH/held-source32/scripts/ci/fish-config02-native-source/runtime/scripts/build" \
  --overlay "$OVERLAY" --output "$OUTPUT"
```

The output contains the complete reviewed recipe hash map, a byte-for-byte
recipe snapshot, the exact Setup8 archive and detached signature, and two
compiler-checked projections of r12's tools. The projections replace only the
exact archive basename and preserve container identity, isolation, resource
limits, the XZ gate, and the existing comparison. The setup certificate is an
external public operand with its whole pin recorded in `plan.DATA.json`.
The passive CLI does not read a key, call a signature verifier, launch a
container or use a package manager. The retained overlay development manifest
declares `2026-11-23T22:47:40Z` expiry. Fresh authority must confirm the actual
public certificate and signature are valid for the hosted operation.

## Hosted integration and review

Bind `bootstrap.bind(native, original_native_arm_bytes, dependency_dir,
public_certificate_path, pair)` after the existing audit and context handoff
configuration and before the existing admitted `native.build` call. It
projects only the held build function and preserves the exact audit. In that
private offline bootstrap, the added ALPM transaction must pass both exact
detached GnuPG verification and the existing Required pacman signature policy.
The bootstrap adds the scoped TEST certificate, installs the one exact
dependency, then deletes its trust. The host never installs the dependency
and the builder inherits the exact new inventory.

Use the projected builder and comparator leaves in the private runtime beside
the original generic helpers. Keep the existing owned pair's two build calls,
normal checks, no-network mode, comparison with `--require-bytes`, and owned
retirement unchanged. Both builds must use the staged `recipe`,
`reviewed-inputs.json` and `expected342.lock`. The First Login finisher accepts
the real `cachy-asahi-first-login-0.1.0-2-aarch64-check.log` from each build,
requires all 11 First Login and three package-delivery cases by name, and joins
the exact inventory and ordinary `-any.pkg.tar.xz` archive to the strict
comparison of contents, PKGINFO, BUILDINFO, and whole bytes. Its result still
requires the independent Root hosted terminal and owned cleanup join.

The r12 allowlist needs the First Login archive and original AArch64 check log
under both build directories. The r12 complete Source is 2,093,900 bytes of its
2 MiB cap. The 85,874-byte recipe and 34,019-byte dependency pair alone exceed
the residual budget. The next step is an independently pinned and bounded
First Login package carrier projection with its own operation identity, exact
policy and public retention map. Raw addition to that existing Fish Source
would fail its immutable namespace and size checks. This packet contains no
dispatch or signing authority and the hosted build pair remains unrun.
