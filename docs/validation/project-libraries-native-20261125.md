# #622 native JBIG and TIFF build pairs and fresh signed lifecycle

On November 25, 2026, the hosted lane at
`ea225d8e9b0aee46ae2b93aca022b5a94b6d0956`, attempt 1, passed both
native build pairs and the fresh TEST-signed lifecycle. Four clean offline
build containers ran on one GitHub-hosted Linux AArch64 runner with
4,096-byte pages. [Run 45706276628](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45706276628)
· [Pair job and bounded result](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45706276628/job/139528975636)

## Inputs and build evidence

The job verified all 417 pinned Minimal206 objects, 207 detached signatures
and the signed rootfs layout at r12 producer
`1604862d09fb04e471da03df2e2a98a5c05a77bf`. The input lock SHA-256 is
`629ef92976d17f13443897b0711a54ecb3e404eea4d0d997447407d76a9baf16`,
and the observed 206-package inventory SHA-256 is
`303cb32db7378e2cdd5d7645df1dc1f5e7a30fc9ea588f0d2867eede21127e66`.
All three official codec signature checks passed against ALARM signer
`68B3537F39A313B3E574D06777193F152BDBE6A6`. Two materializations matched
all 27 recipe files at tree `8cf292a311f6abccbb6de51963fd4751b13bcd5c`
and plan SHA-256
`892b271cd5dc8ff22f103b875adcca87b75ce8b98a2b35ca5b258225ca17923f`.

| Package | Bytes per archive | SHA-256 of both byte-identical archives |
| --- | ---: | --- |
| `cachy-asahi-jbigkit 2.2-1.1` | 143,352 | `98636579a9653b64987646ab2066fb0e4d9763ae44d52984c7d4677827a2af97` |
| `cachy-asahi-libtiff 4.7.2-1.1` | 862,056 | `93e380ec45bc69059c643968f84fd3328a654e532bff0cf5f58e6362e62eb27f` |

Both pairs produced successful makepkg check phases. Passive package
inspection verified the package metadata, structural 16 KiB ELF alignment,
corresponding-source bundles and notices, and the SONAMEs
`libjbig.so.2.2`, `libjbig85.so.2.2`, `libtiff.so.6` and
`libtiffxx.so.6`. The TIFF library declares `DT_NEEDED` on
`libjbig.so.2.2`. The public job result records the individual build and
check log hashes and the ELF payload hashes.

The TIFF builder installed the exact passing JBIG archive and the three
official codecs with signature policy `Required`. Its independent
210-package inventory readback has SHA-256
`20fef180b8649bc9162fc3092b228f232b28562dc3c633e70fcbdddd2d37c2e3`.
The disposable signer is `D06F7C9C278D30FAE117CCA1CDB6383B87DBEADD`.
Its JBIG signature SHA-256 is
`b81d91072e4a7a7112e17eb0f16fd6642a29e1f66784cb40d283e8a723521296`.

## Fresh signed lifecycle and cleanup

The disposable test began on unextended Minimal206 with neither previous
provider installed. Pacman refused the unsigned TIFF archive and preserved
the 206-package inventory. The exact signed pair and three official codecs
then followed the inventory sequence `206 → 211 → 206 → 211 → 206`.
Both 211-package checkpoints checked ownership and loader resolution,
compiled and ran the installed 32×4 TIFF/JBIG roundtrip, and verified the
dimensions and ISO JBIG compression using installed `tiffinfo`. Both
removals checked that the package-owned files were absent. The 211-package
inventory SHA-256 is
`3293e438f049763a200dbc4016beaae00a778518946d99ef280c40e5af686a4e`.
The TIFF TEST signature SHA-256 is
`13061a9050a8894776d9a32d9303cbf1410d46619a04ae3951913c497ea8819e`,
and the lifecycle log SHA-256 is
`d093bb2708ff1b7c9d72729648e6dae35ab9d695c051da77b73e981062a885eb`.

Cleanup verified absence of the job-owned containers and tagged builder
images, including the imported rootfs image. The separate step retired the
private runner cache. Docker daemon build-cache retirement is unverified.
The run published bounded metadata and hashes in its job log and uploaded
zero Actions artifacts.

## Historical providers on a reduced emulated fixture

A separate local, offline AArch64 QEMU user-mode fixture ran with 4,096-byte
pages. It authenticated the original ALARM signatures on `jbigkit 2.1-8`,
`libtiff 4.7.2-1` and `lcms2 2.19.1-1` from the retained Overlay583 inputs.
The 206-package builder plus those three packages and the three pinned
official codecs formed the 212-package historical inventory. Pacman used
Required signatures with scriptlets disabled and the builder hook masks
in place.

The project JBIG archive matched the hosted archive byte for byte. The
local TIFF rebuild used the same reviewed recipe and 210-package build
inventory. Its 861,864-byte archive has SHA-256
`085e8293b170ef5fa30febd3f7d4079da69b4b104c0e91733a30640e2e3f8875`.
The hosted archive was 862,056 bytes and had the different digest above.
Both TIFF shared libraries matched the hosted ELF hashes byte for byte.
The local package metadata matched the reviewed recipe, including the
PKGBUILD hash, and all 210 BUILDINFO package entries matched the hosted
inventory lock. Both inspections counted 15 corresponding-source members.
The hosted receipt exposes archive and ELF hashes and the builder
inventory hash. Raw hosted PKGINFO and BUILDINFO bytes were unavailable for
a direct metadata comparison.

| Checkpoint | Packages | SHA-256 of sorted inventory |
| --- | ---: | --- |
| Minimal206 | 206 | `303cb32db7378e2cdd5d7645df1dc1f5e7a30fc9ea588f0d2867eede21127e66` |
| Historical providers and consumer | 212 | `9203a23bef9d2a8ba4eb9135536d146ae8a8d89b936072e89851c91afde6cd87` |
| Project providers and unchanged consumer | 212 | `abbc68dd92b0324962fb309f848bad485f745368fd769516fcf4300aef0283e4` |
| Historical providers restored | 212 | `9203a23bef9d2a8ba4eb9135536d146ae8a8d89b936072e89851c91afde6cd87` |

One signed transaction replaced both original providers together. A second
transaction restored both. All three provider checkpoints passed the
package database and file checks, loader resolution, the 32×4 TIFF/JBIG
codec roundtrip and a 2×2 RGB TIFF conversion with the unchanged
`lcms2` `tificc`. The four installed project shared libraries matched
the hosted ELF hashes. After restoration, the original library and
consumer file hashes matched the first checkpoint, and stale project
SONAMEs and source bundle entry points were absent.
[Disposable migration driver](../../scripts/ci/project-libraries-native/migration622.sh)

## Remaining qualification

The native migration option needs the newly rebuilt, exact hosted TIFF
archive in the same job that runs the transaction. The original providers
and representative consumer are available through the separate pinned
historical carrier. The emulated fixture qualifies the exact historical
provider pair against the recorded local TIFF archive on the reduced
inventory. Qualification on the intended maintenance composition still
depends on reviewing that composition and its installed consumers before
running the replacement and restoration there.
[Historical reverse-consumer evidence](../workstreams/maintained-reverse-consumer-migration-impact.md)

Native 16 KiB execution, physical M2 Air testing, production trust, and
distribution review remain open.
