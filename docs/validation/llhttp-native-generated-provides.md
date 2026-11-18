# llhttp 9.3.1 native package metadata

The r19 builder compiled and ran the package smoke check. Its artifact gate
rejected the package because the recipe's `.SRCINFO` declares `libllhttp.so`
and makepkg writes `libllhttp.so=9.3-64` to `.PKGINFO`. The archive's
`usr/lib/libllhttp.so.9.3.1` is an AArch64 ELF64 shared object with
`DT_SONAME=libllhttp.so.9.3`. [R124](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44230852682)

The r20 Source `4b2aae4de42adc8ad0ad501dc9089c3b58751c1b` passed two
separate native ARM builds and byte comparison. Both XZ packages were
30,828 bytes with SHA-256
`7fe05d7bfaf4545c7ae225dc75441ad0edaab493e7bb90bd47062864a84368a2`.
Both smoke checks passed. [R125](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44233343958)

The [llhttp source constructor](../../scripts/ci/llhttp-reference-native-source/prepare.py)
now puts the same package-specific metadata check into the generated builder and
comparator. They read the ELF from the exact archive, verify its identity against
the package report, and require makepkg's generated provider. The existing
metadata checker still verifies the other package fields and the PKGBUILD hash.
Pass `--historical-source` to reproduce Source62 for the historical successor
constructors. The default export is prospective and still requires Root admission.

The maintained constructor's generated commands were checked locally against the
retained R124 and R125 packages. Native execution of this export, package signing
and installation, native 16 KiB execution, and M2 validation remain separate gates.
