# First Login 0.1.0-2 native AArch64 build pair

November 18, 2026. Two clean builds on the same hosted AArch64 runner with
4,096-byte pages produced byte-identical unsigned
`cachy-asahi-first-login-0.1.0-2-any.pkg.tar.xz` archives. Each is 10,764
bytes with SHA-256
`0e7b995347f9ae7ea04fc9ece42f5f8a1bbdeb86e5c9d6b1ceb4e480eedd2a51`.
The archive remains architecture-independent. The build ran from Source
`6b3e2fa44618a0eefc6bda3bc2d9b4f7c4411cf8` on workflow 422474129.
[Hosted run 44310776063](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44310776063)
· [Attempt 1, pair job 134824045309](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44310776063/job/134824045309)

Both network-disabled build containers used the same verified 342-package
inventory with `cachy-asahi-setup 0.3.0-1`. The lock SHA-256 is
`50adb6e881a2b717de486ce487e0f1bfcdecce36e028313566a2a1d10c6b34b3`.
The reader verified all 501 bootstrap acquisitions and 249 detached
signature results. The normal makepkg 7.1.0 checks passed 11 First Login
cases and three package-delivery cases in each build. They cover preview
without writes, repeat activation preserving edits, interrupted setup
recovery, incompatible helper refusal, and launcher relocation.

The independent offline reader rehashed all 882 files listed in the inner
evidence manifest and replayed the package comparison and both check-log
gates. It matched the six installed files and their modes to the pinned
recipe, verified the package metadata and recorded builder inventory,
and confirmed the owned containers, images and storage were removed.
The hosted controller scope was empty on two successive checks.

| Retained evidence | SHA-256 |
| --- | --- |
| Original job log, 1,894,965 bytes | `96744fbe0c82d55c9fb5830ce35660b1beea0499469304dd93c6d46328e7bee8` |
| Evidence archive decoded from that log | `faa7ad394d1507d1408e47f844dab7a536ad9444e3ec8b8329c2be0e0d3d88af` |
| Independent readback, `PASS_EXACT_FIRST_LOGIN_V2_NATIVE_PAIR_DATA` | `9ac7be4151c30e1ce58d8e95aa8b38af07c50c8906dc7d76ece47ed57bad967a` |

## Comparison with the installed rehearsal archive

The archived x86_64 host build was 19,471 bytes, used Zstandard compression
and had SHA-256
`d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839`.
All six installed files have the same bytes and modes in the
host and native archives. Both record version `0.1.0-2`, package
architecture `any`, dependencies `python>=3.11` and
`cachy-asahi-setup>=0.3.0`, and the same PKGBUILD digest. The archives
have different whole bytes and different `.PKGINFO`, `.BUILDINFO` and
`.MTREE` records. The existing signed Overlay583 install and removal
evidence covers the x86_64-built archive on an emulated 16 KiB AArch64
guest. [Host assembly](first-login-actual-shells-host-20261114.md)
· [Overlay583 First Login lifecycle](offline-overlay583-emulated-install-20261117.md#installed-shell-first-login-and-interrupted-setup-recovery)

Signing and installation of the new native archive, native 16 KiB execution,
the supported Asahi transaction, graphical login, physical M2 testing and
release acceptance remain open. The build evidence covers the retained
`0.1.0-2` recipe. The maintained `0.1.0-3` candidate has its own evidence
requirements.
