# #622 native JBIG and TIFF builds and signed lifecycle

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

## Historical provider replacement and restoration on native ARM64

On November 25, 2026, attempt 1 of the hosted migration lane completed
successfully at selected caller and reusable-workflow revision
`3baa5a9054201ca68580fa889ecbdcb3147ac6b6`. The
`project-libraries-migration` dispatch selected `native-migration` and
skipped the unrelated native job. One GitHub-hosted Linux AArch64 runner
with 4,096-byte pages ran both offline build pairs, repeated the fresh
signed lifecycle, and performed the historical transaction in a separate
offline Minimal206 container.
[Run 45711465597](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45711465597)
· [Pair and migration job 139550733936](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45711465597/job/139550733936)

The job reverified the same Minimal206 producer and inputs, three official
codec signatures, and exact recipe tree recorded above. Both native pairs
were byte-identical and matched the archive sizes and SHA-256 hashes above.
The migration staged those exact archives from the same job and signed
them with disposable TEST signer
`A3FD2561711389C71E9C0B77D310A1AA285B41F6`.
The historical carrier ref `refs/heads/native622-historical-r1` pinned
parentless commit `564f5c74b11b73eb43fe6b1879412c82ade3e6be` and tree
`96812687497a5f7674136b187a6a56300781bbe7`. It contained exactly the
three original archives and their detached signatures. The job verified
all three with the pinned ALARM keyring. Independent local verification
extracted those six blobs from the pinned Git commit, hashed them, and
confirmed all three signatures with `gpgv` against the pinned keyring
and primary signer `68B3537F39A313B3E574D06777193F152BDBE6A6`.

| Original ALARM package | Archive SHA-256 | Detached signature SHA-256 |
| --- | --- | --- |
| `jbigkit 2.1-8` | `ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db` | `f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f` |
| `libtiff 4.7.2-1` | `02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd` | `8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa` |
| `lcms2 2.19.1-1` | `5f93d01820b4e1a463f3cb11e19916bb3761b4faca20d4e1f0854329ba3f46f8` | `3e35d43d7cd15dc360e2c250b32610f97330b239ba30d2917d6998c1d337dd5c` |

Pacman required package signatures, skipped scriptlets, and ran with the
builder hook masks in place. One transaction replaced both original
providers and one transaction restored them with `lcms2` installed
throughout. All four exact inventory and database checks passed. The
independent observer recomputed the four hashes from the selected
revision's Minimal206 lock and the explicit historical and project package
sets. The hashes matched both the native receipt and the emulated fixture.

| Checkpoint | Packages | SHA-256 of sorted inventory |
| --- | ---: | --- |
| Minimal206 | 206 | `303cb32db7378e2cdd5d7645df1dc1f5e7a30fc9ea588f0d2867eede21127e66` |
| Historical providers and consumer | 212 | `9203a23bef9d2a8ba4eb9135536d146ae8a8d89b936072e89851c91afde6cd87` |
| Project providers and unchanged consumer | 212 | `abbc68dd92b0324962fb309f848bad485f745368fd769516fcf4300aef0283e4` |
| Historical providers restored | 212 | `9203a23bef9d2a8ba4eb9135536d146ae8a8d89b936072e89851c91afde6cd87` |

All three provider checkpoints passed ownership, SONAME and loader
checks, a 32×4 JBIG/TIFF roundtrip, and a 2×2 RGB TIFF conversion with the
unchanged `tificc`. All four installed project library hashes matched
the hosted payload receipts. The restored original library and consumer
hashes matched the first historical checkpoint, and project-only SONAMEs
and source bundle entry points were absent.
[Disposable migration driver](../../scripts/ci/project-libraries-native/migration622.sh)

The terminal receipt reports `NATIVE_BUILD_PAIRS_AND_HISTORICAL_MIGRATION_PASSED`
and migration log SHA-256
`36552de4f8393e7f4a0d171cb3f1eac4d49fe343efb86bfbb93a21f2e1aa708f`.
Both private runner caches were retired. The job verified absence of its
scoped containers and builder images, including the imported rootfs
image. Docker daemon build-cache retirement remains unverified. The
independent observer watched the run to successful completion and verified
both retirement acknowledgments and zero uploaded Actions artifacts.
The local signature check removed its temporary extracted archives,
signatures, and dearmored keyring. The retained public job log has SHA-256
`881f8f269ea095e3e08fb9f4cd2f8d0ca298b434b1d98baa600803de813d743b`.

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

The emulated transaction and restoration passed the same four inventories
listed above. All three provider checkpoints passed database and file
checks, loader resolution, the TIFF/JBIG roundtrip, and the unchanged
`tificc` conversion. The four installed project library hashes matched
the hosted ELF hashes. On restoration, the original library and consumer
hashes matched their initial values and project-only paths were absent.

## Reviewed maintained baseline on November 26, 2026

Native AArch64 run 45822448301 passed at
`f113b1347ae4ac1cd0f976e6206bbff70497b777` with 4,096-byte pages. The
same-head input audit verified 501 pinned baseline objects, 249 original
signatures, and five additional signed build dependencies. The public
input receipt SHA-256 is
`c6da130b61bae37fec62f0ff560c0d6968af94138ae2c929ecb57831bf5e798e`.
The native job independently verified those inputs and read back the
exact 341-package producer inventory. Both recipe materializations matched
across all 27 files.
[Hosted input audit](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45822018823)
· [Native builds and migration](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45822448301)

Both clean builds per package ran their makepkg checks and returned
byte-identical archives. BUILDINFO matched the complete 341-package
JBIG build inventory and the private 346-package TIFF build inventory.
The latter installed the same-job TEST-signed JBIG archive and five
pinned CMake dependencies with Required signature verification.

| Package | Bytes per archive | SHA-256 of both byte-identical archives |
| --- | ---: | --- |
| `cachy-asahi-jbigkit 2.2-1.1` | 144,384 | `fa97ca68d1c7474fdbd17ce59ab2f99a164a2eae8b762f65980b738a791af97c` |
| `cachy-asahi-libtiff 4.7.2-1.1` | 863,116 | `30444dd49066f88d247cee6f6259eb9f5ebdba7f68752fc7c3672e0f64718590` |

A separate offline 341-package container replaced both original
providers in one signed transaction and restored them together. The
original and restored inventory hash was
`fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.
The inventory with the two project providers was
`b5905bc7da08ca7ee6f7fe1d9d8df8f98c3de924f014ce293a3290c3e22ef346`.
All three checkpoints passed package database, loader, ownership, payload
hash and TIFF/JBIG roundtrip checks. The unchanged `tificc` executable
and its ALPM metadata matched their originals at all three checkpoints.
The passive scan of the maintained userspace found it was the only direct
TIFF consumer outside the replaced packages. ALPM also accepted the
original TIFF pkgrel expression through the release-less virtual provide.

The earlier native attempt stopped at the original producer exit.
The launcher inherited a private umask that made the producer's copied
pacman configuration unreadable to the unprivileged builder. The
corrected launch scopes `022` to the producer and preserves the private
parent directory. The first failed command in the earlier run remains
unavailable. The corrected run verified owned image and container absence,
both private cache retirements and preservation of all six pre-existing
Docker images. The bounded native receipt SHA-256 is
`bb53b22faa8e0be66bfb3d9dd2fbb5f45baf3d4afa5b14f295db764f837dd52d`.
The workflow published status and hashes, with zero Actions artifacts.
Docker build-cache retirement remains unverified.
[Earlier producer hold](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45820480303)

## Remaining qualification

The maintained result covers the reviewed 341-package ARM baseline and
its unchanged direct TIFF consumer. The supported Asahi installation and
its indirect consumers, native 16 KiB execution, both physical M2 Air
models, production trust, and distribution review remain open.
[Historical reverse-consumer evidence](../workstreams/maintained-reverse-consumer-migration-impact.md)
