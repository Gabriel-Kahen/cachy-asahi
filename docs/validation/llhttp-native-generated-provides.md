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

## Installed llhttp on emulated ARM16K

A fresh offline AArch64 QEMU guest with 16 KiB pages installed one exact
`cachy-asahi-llhttp-reference 9.3.1-1` archive from the verified native pair.
A scoped TEST signature authenticated both original pair members. Each
archive was 30,828 bytes with SHA-256
`7fe05d7bfaf4545c7ae225dc75441ad0edaab493e7bb90bd47062864a84368a2`.
[Hosted build pair](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44233343958)

The standard loader resolved `libllhttp.so.9.3` to the exact packaged
`/usr/lib/libllhttp.so.9.3.1`. The installed library accepted a POST split over
three inputs and rejected an invalid Content-Length and an incomplete body
with their expected parser errors. Loader checks before installation and after
removal reported the library absent.

The signed install changed the exact 583-package base to 584 packages. Removal
restored the original inventory and a byte-identical local ALPM database
fingerprint. Independent readback verified all 22 retained evidence files
and observed that the scope and both containers had retired twice.

| Evidence | SHA-256 |
| --- | --- |
| Complete native build-pair receipt | `d70808ca5de9523a199f6a6efa705a1473187679fd41688b56feba37d84d4abe` |
| Installed 584-package inventory | `87f8c4f8358bae369d3ffddb482f7a955cd4345d284dbefcf4f6943c7e9dfa3e` |
| Restored local ALPM database fingerprint | `1de57a82d6047b262c3a9a0e06fe2bfbe086efea80f25ac01286c921bc3294ea` |
| Independent guest terminal receipt | `7a69a3077be36b141bc9c31e9640f9886c6bcbf9cde56c4e485df19ab7622030` |

The exercised guest source is `e9544ca6`. Native 16 KiB hardware, the full Asahi
transaction, and physical M2 testing remain open.
[llhttp guest trial](../../scripts/integration/llhttp_overlay583/README.md)
