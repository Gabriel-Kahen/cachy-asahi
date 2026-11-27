# Qtbase Vulkan and md4c 0.6 recipe

This unissued source recipe targets both failures in the
[R132 official-provider comparison](../qt612_installed_16k_preflight/README.md#official-provider-replacement-on-r132).
It derives a separate makepkg directory from the pinned GUI-server recipe
and the existing packaging projection for the retired 6.12.0-2 archive.
The stage includes matching package metadata and a receipt with recipe,
source and signed dependency pins.

The recipe applies the four inherited patches followed by Qt's
032643f99e090e0304ef935c2ee11c109d55c8a1 md4c patch. Both changed bundled
notice records receive new pins. The configured build uses system
md4c 0.6.0-2 and enables Vulkan. It explicitly disables the standalone
VK_KHR_display platform plugin to retain the existing plugin scope.
Vulkan headers 1:1.4.363.0-1 are an exact build dependency. Package
staging checks the six versioned QtGui Vulkan exports required by the
retained Qt Quick consumers and the dynamic md_parse relocation.

The staged package has project version 6.12.0-3 and provides the bare
qt6-base name required by the five R132 dependents. An exact dependency
on the official qt6-base 6.12.0-3 still refuses this replacement.

Run the projection from this directory and inspect its receipt.

    python3 -I -B prepare.py --output "$NEW_RECIPE"
    cd "$NEW_RECIPE"
    makepkg --printsrcinfo | cmp - .SRCINFO

For offline source preparation, place the pinned Qt source archive in
an owned SRCDEST and select a private BUILDDIR. The following runs the
checksums and recipe prepare phase on a development host.

    makepkg --nobuild --nodeps --ignorearch --holdver

The November 26 source preparation verified all five patches and 173 notice
records. `makepkg --printsrcinfo` matched the generated `.SRCINFO` byte for
byte. On the retained R132 metadata with this replacement, `pacman -T`
accepted all 811 runtime dependency expressions. Adding an exact dependency
on the official Qt version failed as intended. The metadata-only check
receipt has SHA-256
`0cc007ca96d59dd9b0d32c187a0f7ee6b99991a161fea9e2cbe959aca809e536`.

Normal CMake and Ninja linked an x86_64 QtGui that passed the six-export and
external md4c readback. Its SHA-256 is
`afacaf47b181d16d967a55f0a9f1bdf878d771060a3cef78ac21d49469124c1f`.
Five cross-compiled AArch64 objects verified the matching source definitions
and import. The prepared recipe receipt SHA-256 is
`b3b46a27d6bb5e93bf411de9a23bf238c36230f268206af09637c9d66f0ce41a`.

A normal ARM64 makepkg build needs a fresh isolated 16 KiB environment
with the exact dependencies in the receipt, including the original signed
ALARM inputs. The prior Q3 graph and package receipts bind its md4c
0.5.3-1 input and configured QtGui bytes. The successor needs its own
configure and full-build evidence, staged package readback, scoped TEST
signing and a separate R132-equivalent installation and restoration.
