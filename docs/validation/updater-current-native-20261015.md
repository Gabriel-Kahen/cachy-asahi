# Current updater native build pair — 2026-10-15

[Workflow run 38761623120](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38761623120) completed successfully. Its retained final result records `updater_workflow=PASS`, `native_stage=PASS` and `recovery=PASS`. This establishes the private native package pair and the cleanup results below for exact Source `1aea667aec50a62ba0ab2dad44be24a4dc3bd098`.

| Input or result | Identity |
| --- | --- |
| Workflow | `native-arm-updater.yml` |
| Tested Source | `1aea667aec50a62ba0ab2dad44be24a4dc3bd098` |
| Upstream updater Source | `e2b1b7144be71cf392809f48d1440f8da1d9c81a` |
| PKGBUILD SHA-256 | `2281359ce075a4144991995b8ae4ef0092a6a29d8ef2c8c5e8a8ab2db2801daf` |
| Package | `cachy-asahi-update`, version `4.4.2-1`, architecture `aarch64` |
| Package SHA-256, both builds | `5902153ed1a7798ca533ad1e8cdab124c6355549797048982193fbe4cabfa968` |
| Compiled tray SHA-256, both builds | `04f52d9c37eb71718613fc21703aa761887bdf6754205da7bfe17bd68d943857` |
| Native builder image | `sha256:95b1dac7aa501b1dcfae7ada895099c4c56e027c0b9ed73d0086c95c53a242bd` |
| Verified 354-package worker inventory SHA-256 | `5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee` |

Both build statuses record `PASS-private-native-package-static-checks`, worker exit 0, no failure code, completed container removal and verified container absence. Both package validations report `artifact-static-pass` with zero errors. The comparison records identical package bytes, installed contents and package metadata, with zero errors. The native pair result is finalized with no failed stage. These are two clean container launches using one authenticated image and daemon; reproduction on an independent machine was not tested.

Both compile results record actual native compilation PASS. Each retains 148 emitted Cargo artifact records and 21 build-script execution records. The worker metadata identifies host and target as `aarch64-unknown-linux-gnu`. The packaged tray is AArch64 ELF with four LOAD segments and no static validation errors. Static 16 KiB segment geometry passed; the loader and physical 16 KiB execution were NOT RUN. The earlier metadata-only worker record's `native_compilation=NOT RUN` is preflight scope; the separate completed compiler and package records establish the later build result.

The two retained 67-row recipe input maps are equal. All 65 repository-file hashes match the tested Source; the remaining two rows are the generated sanitized upstream and vendor archives, whose digests match the recipe pins. At this report's comparison, against the canonical package directory, 50 retained rows match and 15 repository files differ; the two generated archives are absent locally. Differences are `.SRCINFO`, `PKGBUILD`, `build-gate.py`, `build-policy.json`, `native-entry.py`, `public-evidence.py`, `runner-inputs.lock.json`, `runner-ready-pins.json`, `test-native.py`, `test-public-evidence.py`, `test-recipe-gate.py`, `test-worker-build.py`, `updater-native.py`, `worker-build.py`, `worker-diagnostic.py`. In particular, canonical PKGBUILD SHA-256 is `c191226dba5eaeb3b12bbf11dcad4662a92640a8fc46a51fee340ca15f9befef`, which differs from the tested recipe above. Therefore this is an actual historical Source 1aea667 result; **current canonical native_build must remain NOT RUN until the tested product changes are integrated or the current bytes are built**. The run does not validate those differing files or establish integration into another branch. The recorded package and tray hashes come from retained build metadata; their private binaries were removed and were not rehashed locally for this note.

The exact Source runs network-disabled worker builds with `makepkg --nodeps`; it keeps declared package dependencies intact. Its worker omits the declared runtime roots `htmlq`, `pacman-contrib`, `archlinux-contrib` and `xdg-utils`. Build success therefore does not establish a complete target dependency transaction. The package's source/behavior/policy checks run within its build recipe, but this retained projection does not provide separate test-count results or a real tray/menu session.

The finalized terminal records `PASS PRIVATE NATIVE PAIR`, `private_native_pair_verified=true` and elapsed time 613 seconds. Process, Docker, GPG and private-data cleanup all report PASS; private data was removed, raw retention stayed within budget, no storage limit latched and there were no cleanup reasons. `daemon_disposal_status` remains `NOT ATTESTED`.

The separate recovery terminal also finalized PASS with cleanup PASS and private data removed. It explicitly records `native_compilation=NOT ATTESTED BY RECOVERY`: this is owned-resource cleanup/recovery confirmation, not another compilation or an updater rollback/boot recovery test.

Evidence was read offline from the existing [workflow log ZIP](../../artifacts/development/updater-run38761623120/logs.zip), without recollection or extraction of private state. These three curated frames passed their declared compressed size and SHA-256 checks:

| Frame | Bytes | SHA-256 |
| --- | ---: | --- |
| `guarded` | 54,419 | `c9537582ae3366170938ec1c39c2f782eed831a5c91cb41b5eeeed584f4a0daa` |
| `terminal-public` | 1,179 | `9a85d08aa43027d892b1c225b4f21c496d8e7f87d635002260b42aa1d941d115` |
| `recovery-terminal-public` | 852 | `f095ad2c2cb3fdf76d86d904f704d14bca16255042d8dd062d062a3b765faa70` |

The guarded manifest reports 26 accepted files with matching lengths/hashes and no rejections; both terminal export manifests report PASS. No native work was rerun for this documentation.

Publication remains NOT ACCEPTED and hardware remains NOT RUN. Actual target installation/update/removal, a complete signed dependency transaction, protected Asahi platform updates, a real tray/private-D-Bus session, target failure/rollback/boot recovery, both M2 Air sizes and performance remain unverified. This result advances native build evidence; Root owns source integration, inventory reconciliation, Git publication and release selection.
