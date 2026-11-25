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

## Remaining qualification

Provider replacement and restoration remain unrun. The next installed
qualification depends on a reviewed maintenance composition with pinned
signed archives for both original providers and representative installed
consumers. Replace and restore both providers together, verify the installed
inventory and ownership at each checkpoint, and run the dependent loader
and application checks. In the historical comparison, `libtiff 4.7.2-1`
from the original provider pair links to `libjbig.so.2.1` from
`jbigkit 2.1-8`. `lcms2`'s `tificc` is a recorded direct TIFF consumer. [Historical reverse-consumer evidence](../workstreams/maintained-reverse-consumer-migration-impact.md)

Native 16 KiB execution, physical M2 Air testing, production trust, and
distribution review remain open.
